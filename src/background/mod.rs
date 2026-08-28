use crate::config::Config;
use crate::debug_fill::{self, FillAttemptReport, FillMethod};
use crate::models::{Account, AppSettings, LogEntry, LogLevel, WorkerStatus};
use crate::monitor::{AppMonitor, MonitorObservation, MonitorStatus};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::Sender as StdSender;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::sleep;
use tracing::{debug, info, trace, warn};

#[derive(Debug, Clone)]
pub(crate) enum WorkerCommand {
    Start,
    Stop,
    Quiesce {
        request_id: u64,
        acknowledgement: StdSender<WorkerQuiescenceAck>,
    },
    #[cfg(test)]
    ApplyConfig {
        settings: AppSettings,
        accounts: Vec<Account>,
        refresh_passwords: bool,
    },
    ApplyConfigAndReleasePause {
        settings: AppSettings,
        accounts: Vec<Account>,
        refresh_passwords: bool,
        start_monitor: bool,
        pause_epoch: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WorkerQuiescenceAck {
    pub(crate) request_id: u64,
}

#[derive(Debug, Clone)]
pub(crate) enum WorkerEvent {
    StatusChanged(WorkerStatus),
    Log(LogEntry),
    FillAttemptReport(FillAttemptReport),
}

#[derive(Clone)]
pub(crate) struct WorkerInvalidator {
    generation: Arc<AtomicU64>,
}

impl WorkerInvalidator {
    pub(crate) fn new() -> Self {
        Self {
            generation: Arc::new(AtomicU64::new(0)),
        }
    }

    pub(crate) fn invalidate(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
    }

    pub(crate) fn pause_latch(&self) -> WorkerPauseLatch {
        WorkerPauseLatch {
            pause_state: Arc::new(AtomicU64::new(0)),
            generation: self.generation.clone(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct WorkerPauseLatch {
    // Packed as `(epoch << 1) | paused`. Keeping both values in one atomic
    // lets a release compare-and-swap the exact epoch without a mutex and
    // prevents an older release from reopening a newer safety pause.
    pause_state: Arc<AtomicU64>,
    generation: Arc<AtomicU64>,
}

impl WorkerPauseLatch {
    pub(crate) fn pause(&self) {
        self.pause_with_epoch();
    }

    pub(crate) fn pause_with_epoch(&self) -> u64 {
        const MAX_PAUSE_EPOCH: u64 = u64::MAX >> 1;
        // Publishing `paused` is itself enough to reject every automation
        // guard. Generation is advanced immediately before a successful
        // release so no observer can ever see an open latch with a stale
        // attempt generation.
        loop {
            let current = self.pause_state.load(Ordering::SeqCst);
            let current_epoch = current >> 1;
            // Never wrap: reusing an epoch would let a years-old release pass
            // an ABA check. Exhaustion is a terminal fail-closed pause.
            if current_epoch == MAX_PAUSE_EPOCH {
                let terminal = (MAX_PAUSE_EPOCH << 1) | 1;
                let _ = self.pause_state.compare_exchange(
                    current,
                    terminal,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                );
                break MAX_PAUSE_EPOCH;
            }
            let next_epoch = current_epoch + 1;
            let next = (next_epoch << 1) | 1;
            if self
                .pause_state
                .compare_exchange(current, next, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                break next_epoch;
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn current_epoch(&self) -> u64 {
        self.pause_state.load(Ordering::SeqCst) >> 1
    }

    pub(crate) fn resume_if_epoch(&self, expected_epoch: u64) -> bool {
        let expected = (expected_epoch << 1) | 1;
        const MAX_PAUSE_EPOCH: u64 = u64::MAX >> 1;
        if expected_epoch == 0
            || expected_epoch == MAX_PAUSE_EPOCH
            || self.pause_state.load(Ordering::SeqCst) != expected
        {
            return false;
        }
        self.generation.fetch_add(1, Ordering::SeqCst);
        self.pause_state
            .compare_exchange(expected, expected - 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    pub(crate) fn owns_pause(&self, expected_epoch: u64) -> bool {
        expected_epoch != 0 && self.pause_state.load(Ordering::SeqCst) == (expected_epoch << 1) | 1
    }

    pub(crate) fn apply_config_command(
        &self,
        pause_epoch: u64,
        settings: AppSettings,
        accounts: Vec<Account>,
        refresh_passwords: bool,
        start_monitor: bool,
    ) -> WorkerCommand {
        WorkerCommand::ApplyConfigAndReleasePause {
            settings,
            accounts,
            refresh_passwords,
            start_monitor,
            pause_epoch,
        }
    }

    pub(crate) fn is_paused(&self) -> bool {
        self.pause_state.load(Ordering::SeqCst) & 1 == 1
    }

    fn stable_unpaused_generation(&self) -> Option<u64> {
        if self.is_paused() {
            return None;
        }
        let generation = self.generation.load(Ordering::SeqCst);
        if self.is_paused() {
            return None;
        }
        let confirmed_generation = self.generation.load(Ordering::SeqCst);
        // pause_with_epoch publishes `paused = true` before advancing the
        // generation. Rechecking the latch after the snapshot rejects both a
        // completed pause and one racing this admission read. Requiring two
        // equal generation reads also rejects an independent invalidation.
        (!self.is_paused() && generation == confirmed_generation).then_some(generation)
    }

    fn ensure_attempt_current(
        &self,
        expected_generation: u64,
        reason: &'static str,
    ) -> anyhow::Result<()> {
        if self.is_paused() {
            anyhow::bail!(reason);
        }
        ensure_generation_current(&self.generation, expected_generation, reason)?;
        if self.is_paused() {
            anyhow::bail!(reason);
        }
        ensure_generation_current(&self.generation, expected_generation, reason)?;
        if self.is_paused() {
            anyhow::bail!(reason);
        }
        Ok(())
    }
}

const IDLE_SLEEP: Duration = Duration::from_millis(500);
const AUTOMATION_SLEEP: Duration = Duration::from_millis(250);
const PROMPT_STATUS_POLL_INTERVAL: Duration = Duration::from_secs(1);
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const MACOS_FALLBACK_PROMPT_PROBE_INTERVAL: Duration = Duration::from_secs(1);
const MACOS_RETRY_REARM_NO_PROMPT_OBSERVATIONS: u8 = 3;
const MACOS_RETRY_REARM_PROCESS_EXIT_OBSERVATIONS: u8 = 2;
const MACOS_RETRY_REARM_SHEET_EXIT_OBSERVATIONS: u8 = 3;
const CONNECTED_POLL_BACKOFF_MAX: Duration = Duration::from_secs(5);
const UNKNOWN_POLL_BACKOFF_MAX: Duration = Duration::from_secs(3);
const PRE_PASSWORD_REPORT_PERSIST_INTERVAL: Duration = Duration::from_secs(5 * 60);

struct FlagGuard {
    flag: Arc<AtomicBool>,
}

#[derive(Clone)]
struct WorkerActivityTracker {
    state: Arc<Mutex<WorkerActivityState>>,
}

struct WorkerActivityState {
    accepting_attempts: bool,
    active_attempts: usize,
    quiescence_waiters: Vec<WorkerQuiescenceWaiter>,
}

struct WorkerQuiescenceWaiter {
    request_id: u64,
    acknowledgement: StdSender<WorkerQuiescenceAck>,
}

struct WorkerActivityGuard {
    tracker: WorkerActivityTracker,
}

impl Default for WorkerActivityTracker {
    fn default() -> Self {
        Self {
            state: Arc::new(Mutex::new(WorkerActivityState {
                accepting_attempts: true,
                active_attempts: 0,
                quiescence_waiters: Vec::new(),
            })),
        }
    }
}

impl WorkerActivityTracker {
    fn begin_attempt(&self) -> Option<WorkerActivityGuard> {
        let Ok(mut state) = self.state.lock() else {
            return None;
        };
        if !state.accepting_attempts {
            return None;
        }
        state.active_attempts = state.active_attempts.checked_add(1)?;
        Some(WorkerActivityGuard {
            tracker: self.clone(),
        })
    }

    fn acknowledge_when_quiescent(
        &self,
        request_id: u64,
        acknowledgement: StdSender<WorkerQuiescenceAck>,
    ) {
        let Ok(mut state) = self.state.lock() else {
            warn!(
                request_id,
                "Worker activity state is unavailable; quiescence will not be acknowledged"
            );
            return;
        };
        // Closing the gate and observing the activity count under one mutex is
        // the linearization point: no attempt can register after this request
        // and escape the acknowledgement barrier.
        state.accepting_attempts = false;
        if state.active_attempts == 0 {
            drop(state);
            let _ = acknowledgement.send(WorkerQuiescenceAck { request_id });
            return;
        }
        state.quiescence_waiters.push(WorkerQuiescenceWaiter {
            request_id,
            acknowledgement,
        });
    }

    fn reopen_after_fresh_release(&self) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        if state.active_attempts != 0 || !state.quiescence_waiters.is_empty() {
            return false;
        }
        state.accepting_attempts = true;
        true
    }
}

impl Drop for WorkerActivityGuard {
    fn drop(&mut self) {
        let waiters = {
            let Ok(mut state) = self.tracker.state.lock() else {
                warn!("Worker activity state is unavailable; quiescence will not be acknowledged");
                return;
            };
            let Some(remaining) = state.active_attempts.checked_sub(1) else {
                warn!(
                    "Worker activity accounting underflowed; quiescence will not be acknowledged"
                );
                return;
            };
            state.active_attempts = remaining;
            if remaining == 0 {
                std::mem::take(&mut state.quiescence_waiters)
            } else {
                Vec::new()
            }
        };
        for waiter in waiters {
            let _ = waiter.acknowledgement.send(WorkerQuiescenceAck {
                request_id: waiter.request_id,
            });
        }
    }
}

impl FlagGuard {
    fn acquire(flag: &Arc<AtomicBool>) -> Option<Self> {
        if flag.swap(true, Ordering::SeqCst) {
            None
        } else {
            Some(Self {
                flag: Arc::clone(flag),
            })
        }
    }
}

impl Drop for FlagGuard {
    fn drop(&mut self) {
        self.flag.store(false, Ordering::SeqCst);
    }
}

fn log_event(level: LogLevel, message: impl Into<String>) -> WorkerEvent {
    WorkerEvent::Log(LogEntry {
        timestamp: chrono::Local::now().format("%H:%M:%S").to_string(),
        level,
        message: message.into(),
    })
}

fn safe_status_name(status: &MonitorStatus) -> &'static str {
    match status {
        MonitorStatus::Connected => "connected",
        MonitorStatus::ProcessNotFound => "process_not_found",
        MonitorStatus::LoginWindowDetected { .. } => "login_window_detected",
        MonitorStatus::Unknown => "unknown",
    }
}

fn runtime_config(_settings: &AppSettings) -> Arc<Config> {
    Arc::new(Config {
        macos_app_name: crate::config::TARGET_APP_NAME.to_string(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FillTrigger {
    Automatic,
}

impl FillTrigger {
    fn label(self) -> &'static str {
        match self {
            Self::Automatic => "automatic fill",
        }
    }
}

struct CurrentPromptAttempt {
    trigger: FillTrigger,
    settings: AppSettings,
    accounts: Vec<Account>,
    event_tx: Sender<WorkerEvent>,
    automation_in_progress: Arc<AtomicBool>,
    pause_latch: WorkerPauseLatch,
    expected_generation: u64,
    prompt_context: Option<debug_fill::VerifiedPromptContext>,
    prompt_retry_suppression: Option<PromptRetrySuppression>,
    activity_tracker: WorkerActivityTracker,
}

struct PromptRetrySuppression {
    recent_prompt_attempts: Arc<Mutex<HashMap<LoginPromptKey, Instant>>>,
    prompt_key: LoginPromptKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct LoginPromptKey {
    account_id: String,
    process_id: i32,
    window_handle: isize,
    window_title: String,
    prompt_email: String,
    prompt_origin: String,
}

impl LoginPromptKey {
    fn new(
        account_id: String,
        process_id: i32,
        window_handle: isize,
        window_title: String,
        prompt_email: String,
        prompt_origin: String,
    ) -> Self {
        Self {
            account_id: canonical_prompt_component(&account_id),
            process_id,
            window_handle,
            window_title: canonical_prompt_component(&window_title),
            prompt_email: canonical_prompt_component(&prompt_email),
            prompt_origin: canonical_prompt_component(&prompt_origin),
        }
    }

    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    fn from_verified_context(context: &debug_fill::VerifiedPromptContext) -> Self {
        Self::new(
            context.account_id.clone(),
            context.process_id,
            #[cfg(target_os = "windows")]
            context.window_handle,
            #[cfg(not(target_os = "windows"))]
            0,
            context.window_title.clone(),
            context.prompt_email.clone(),
            context.prompt_origin.clone(),
        )
    }
}

fn canonical_prompt_component(value: &str) -> String {
    value.trim().to_lowercase()
}

#[derive(Debug, PartialEq)]
enum PromptAccountDecision<'a> {
    Allow(&'a Account),
    MissingEmail,
    NoEnabledMatch,
    Ambiguous,
}

fn account_for_visible_prompt_email<'a>(
    accounts: &'a [Account],
    prompt_email: Option<&str>,
) -> PromptAccountDecision<'a> {
    let Some(prompt_email) = prompt_email
        .map(str::trim)
        .filter(|email| !email.is_empty())
    else {
        return PromptAccountDecision::MissingEmail;
    };

    let matching_accounts = accounts
        .iter()
        .filter(|account| {
            account.enabled && account.has_saved_password && !account.username.trim().is_empty()
        })
        .filter(|account| account.username.trim().eq_ignore_ascii_case(prompt_email))
        .collect::<Vec<_>>();

    if matching_accounts.is_empty() {
        return PromptAccountDecision::NoEnabledMatch;
    }

    let matching_accounts = matching_accounts.into_iter().take(2).collect::<Vec<_>>();

    match matching_accounts.as_slice() {
        [account] => PromptAccountDecision::Allow(account),
        [] => PromptAccountDecision::NoEnabledMatch,
        _ => PromptAccountDecision::Ambiguous,
    }
}

#[cfg_attr(not(test), allow(dead_code))]
fn prompt_retry_is_suppressed(
    recent_prompt_attempts: &HashMap<LoginPromptKey, Instant>,
    prompt_key: &LoginPromptKey,
) -> bool {
    // PID/HWND/title/origin are observations of one account identity and must
    // not create extra attempts. Keep older identities in the episode map so
    // an A -> B -> A config sequence cannot re-arm A by deleting its history.
    recent_prompt_attempts.keys().any(|attempted| {
        attempted.account_id == prompt_key.account_id
            && attempted.prompt_email == prompt_key.prompt_email
    })
}

fn reserve_prompt_retry_suppression(suppression: Option<&PromptRetrySuppression>) -> bool {
    let Some(suppression) = suppression else {
        return true;
    };
    let now = Instant::now();
    let Ok(mut prompts) = suppression.recent_prompt_attempts.lock() else {
        return false;
    };
    prompts.insert(suppression.prompt_key.clone(), now);
    true
}

fn release_prompt_retry_suppression_after_authenticated_success(
    suppression: Option<&PromptRetrySuppression>,
    report: &FillAttemptReport,
) -> bool {
    if !report.success || report.field("post_check_state") != Some("authenticated") {
        return true;
    }
    let Some(suppression) = suppression else {
        return true;
    };
    let Ok(mut prompts) = suppression.recent_prompt_attempts.lock() else {
        return false;
    };

    // Suppression is checked account-wide for one visible prompt identity,
    // not by the transient PID/window observations stored in the map key.
    // Release that same account/email identity after authentication so a
    // future connection can start a fresh retry episode.
    prompts.retain(|attempted, _| {
        attempted.account_id != suppression.prompt_key.account_id
            || attempted.prompt_email != suppression.prompt_key.prompt_email
    });
    true
}

fn ensure_generation_current(
    generation: &AtomicU64,
    expected_generation: u64,
    reason: &'static str,
) -> anyhow::Result<()> {
    if generation.load(Ordering::SeqCst) == expected_generation {
        Ok(())
    } else {
        anyhow::bail!(reason)
    }
}

#[derive(Default)]
struct PollCadence {
    last_stable_status: Option<&'static str>,
    stable_status_count: u32,
}

impl PollCadence {
    fn next_delay(&mut self, _settings: &AppSettings, status: &MonitorStatus) -> Duration {
        let base_delay = fixed_poll_interval();
        let Some(max_delay) = stable_status_backoff_max(status) else {
            self.last_stable_status = None;
            self.stable_status_count = 0;
            return base_delay;
        };

        let status_name = safe_status_name(status);
        if self.last_stable_status == Some(status_name) {
            self.stable_status_count = self.stable_status_count.saturating_add(1);
        } else {
            self.last_stable_status = Some(status_name);
            self.stable_status_count = 1;
        }

        let multiplier = 1_u32.checked_shl(self.stable_status_count.saturating_sub(1).min(3));
        let delay = base_delay.saturating_mul(multiplier.unwrap_or(8));
        delay.min(max_delay)
    }
}

fn fixed_poll_interval() -> Duration {
    Duration::from_secs(crate::models::FIXED_POLL_INTERVAL_SECS)
}

fn remaining_tick_delay(tick_start: Instant, target_delay: Duration) -> Duration {
    target_delay.saturating_sub(tick_start.elapsed())
}

fn stable_status_backoff_max(status: &MonitorStatus) -> Option<Duration> {
    match status {
        MonitorStatus::Connected => Some(CONNECTED_POLL_BACKOFF_MAX),
        MonitorStatus::Unknown => Some(UNKNOWN_POLL_BACKOFF_MAX),
        MonitorStatus::ProcessNotFound | MonitorStatus::LoginWindowDetected { .. } => None,
    }
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn should_run_macos_fallback_prompt_probe(
    prompt_attempt_started: bool,
    monitor_snapshot_available: bool,
    status_allows_probe: bool,
    prompt_probe_due: bool,
) -> bool {
    !prompt_attempt_started
        && !monitor_snapshot_available
        && status_allows_probe
        && prompt_probe_due
}

fn clear_recent_prompt_attempts(
    recent_prompt_attempts: &Arc<Mutex<HashMap<LoginPromptKey, Instant>>>,
) {
    if let Ok(mut prompts) = recent_prompt_attempts.lock() {
        prompts.clear();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrustedProcessPresence {
    Present,
    Absent,
    Indeterminate,
}

#[derive(Debug, Default)]
struct DefinitiveProcessExitTracker {
    consecutive_absence_by_pid: HashMap<i32, u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SuppressedSheetEpisode {
    process_id: i32,
    parent_window_title: String,
}

impl SuppressedSheetEpisode {
    fn from_prompt_key(prompt_key: &LoginPromptKey) -> Option<Self> {
        (prompt_key.prompt_origin == "sheet" && prompt_key.process_id > 0).then(|| Self {
            process_id: prompt_key.process_id,
            parent_window_title: prompt_key.window_title.clone(),
        })
    }
}

#[derive(Debug, Default)]
struct DefinitiveSheetExitTracker {
    consecutive_absence_by_episode: HashMap<SuppressedSheetEpisode, u8>,
}

impl DefinitiveSheetExitTracker {
    fn reset(&mut self) {
        self.consecutive_absence_by_episode.clear();
    }

    fn begin_tick(&mut self, suppressed_episodes: &[SuppressedSheetEpisode]) {
        self.consecutive_absence_by_episode
            .retain(|episode, _| suppressed_episodes.contains(episode));
    }

    fn observe(
        &mut self,
        episode: &SuppressedSheetEpisode,
        presence: TrustedProcessPresence,
        recent_prompt_attempts: &Arc<Mutex<HashMap<LoginPromptKey, Instant>>>,
    ) -> bool {
        match presence {
            TrustedProcessPresence::Present | TrustedProcessPresence::Indeterminate => {
                self.consecutive_absence_by_episode.remove(episode);
                false
            }
            TrustedProcessPresence::Absent => {
                let consecutive_absence = self
                    .consecutive_absence_by_episode
                    .entry(episode.clone())
                    .or_default();
                *consecutive_absence = consecutive_absence.saturating_add(1);
                if *consecutive_absence < MACOS_RETRY_REARM_SHEET_EXIT_OBSERVATIONS {
                    return false;
                }

                self.consecutive_absence_by_episode.remove(episode);
                clear_recent_prompt_attempts_for_sheet_episode(recent_prompt_attempts, episode)
            }
        }
    }
}

impl DefinitiveProcessExitTracker {
    fn reset(&mut self) {
        self.consecutive_absence_by_pid.clear();
    }

    fn begin_tick(&mut self, suppressed_process_ids: &[i32]) {
        // Dropping evidence for PIDs no longer represented in the suppression
        // map prevents a later PID reuse from inheriting an older episode.
        self.consecutive_absence_by_pid
            .retain(|process_id, _| suppressed_process_ids.contains(process_id));
    }

    fn observe(
        &mut self,
        process_id: i32,
        presence: TrustedProcessPresence,
        recent_prompt_attempts: &Arc<Mutex<HashMap<LoginPromptKey, Instant>>>,
    ) -> bool {
        match presence {
            TrustedProcessPresence::Present | TrustedProcessPresence::Indeterminate => {
                self.consecutive_absence_by_pid.remove(&process_id);
                false
            }
            TrustedProcessPresence::Absent => {
                let consecutive_absence = self
                    .consecutive_absence_by_pid
                    .entry(process_id)
                    .or_default();
                *consecutive_absence = consecutive_absence.saturating_add(1);
                if *consecutive_absence < MACOS_RETRY_REARM_PROCESS_EXIT_OBSERVATIONS {
                    return false;
                }

                self.consecutive_absence_by_pid.remove(&process_id);
                clear_recent_prompt_attempts_for_process_id(recent_prompt_attempts, process_id)
            }
        }
    }
}

fn clear_recent_prompt_attempts_for_process_id(
    recent_prompt_attempts: &Arc<Mutex<HashMap<LoginPromptKey, Instant>>>,
    process_id: i32,
) -> bool {
    let Ok(mut prompts) = recent_prompt_attempts.lock() else {
        return false;
    };
    let previous_len = prompts.len();
    prompts.retain(|attempted, _| attempted.process_id != process_id);
    prompts.len() != previous_len
}

fn clear_recent_prompt_attempts_for_sheet_episode(
    recent_prompt_attempts: &Arc<Mutex<HashMap<LoginPromptKey, Instant>>>,
    episode: &SuppressedSheetEpisode,
) -> bool {
    let Ok(mut prompts) = recent_prompt_attempts.lock() else {
        return false;
    };
    let previous_len = prompts.len();
    prompts.retain(|attempted, _| {
        attempted.process_id != episode.process_id
            || attempted.window_title != episode.parent_window_title
            || attempted.prompt_origin != "sheet"
    });
    prompts.len() != previous_len
}

#[cfg(target_os = "macos")]
fn suppressed_prompt_keys(
    recent_prompt_attempts: &Arc<Mutex<HashMap<LoginPromptKey, Instant>>>,
) -> anyhow::Result<Vec<LoginPromptKey>> {
    let prompts = recent_prompt_attempts
        .lock()
        .map_err(|_| anyhow::anyhow!("prompt retry suppression lock is poisoned"))?;
    Ok(prompts.keys().cloned().collect())
}

#[cfg(target_os = "macos")]
fn observe_suppressed_macos_episode_exits(
    process_exit_tracker: &mut DefinitiveProcessExitTracker,
    sheet_exit_tracker: &mut DefinitiveSheetExitTracker,
    recent_prompt_attempts: &Arc<Mutex<HashMap<LoginPromptKey, Instant>>>,
    guard: impl Fn() -> anyhow::Result<()>,
) -> anyhow::Result<(usize, usize)> {
    guard()?;
    // Snapshot under the mutex, then release it before any native identity
    // probe. One sorted/deduplicated snapshot guarantees one probe per PID in
    // this worker tick even if multiple prompt identities reference it.
    let prompt_keys = suppressed_prompt_keys(recent_prompt_attempts)?;
    let mut process_ids = prompt_keys
        .iter()
        .map(|attempted| attempted.process_id)
        .filter(|process_id| *process_id > 0)
        .collect::<Vec<_>>();
    process_ids.sort_unstable();
    process_ids.dedup();
    let mut sheet_episodes = prompt_keys
        .iter()
        .filter_map(SuppressedSheetEpisode::from_prompt_key)
        .collect::<Vec<_>>();
    sheet_episodes.sort_by(|left, right| {
        left.process_id
            .cmp(&right.process_id)
            .then_with(|| left.parent_window_title.cmp(&right.parent_window_title))
    });
    sheet_episodes.dedup();
    process_exit_tracker.begin_tick(&process_ids);
    sheet_exit_tracker.begin_tick(&sheet_episodes);

    let mut released_processes = 0;
    let mut released_sheet_episodes = 0;
    for process_id in process_ids {
        guard()?;
        let (process_presence, trusted_process) =
            match crate::macos_identity::trusted_process_info_for_pid(
                crate::config::TARGET_APP_NAME,
                process_id,
            ) {
                Ok(Some(trusted_process)) => {
                    (TrustedProcessPresence::Present, Some(trusted_process))
                }
                Ok(None) => (TrustedProcessPresence::Absent, None),
                Err(error) => {
                    debug!(
                        process_id,
                        reason = %error,
                        "macOS suppressed-process identity probe was indeterminate"
                    );
                    (TrustedProcessPresence::Indeterminate, None)
                }
            };
        // A pause or generation change while the native probe was running
        // invalidates the observation before it can affect retry state.
        guard()?;
        if process_exit_tracker.observe(process_id, process_presence, recent_prompt_attempts) {
            released_processes += 1;
        }

        for episode in sheet_episodes
            .iter()
            .filter(|episode| episode.process_id == process_id)
        {
            let sheet_presence = if let Some(trusted_process) = &trusted_process {
                guard()?;
                let result = crate::macos_ax::suppressed_sheet_episode_has_visible_direct_sheet(
                    trusted_process,
                    &episode.parent_window_title,
                );
                guard()?;
                match result {
                    Ok(true) => TrustedProcessPresence::Present,
                    Ok(false) => TrustedProcessPresence::Absent,
                    Err(error) => {
                        debug!(
                            process_id,
                            parent_window_title = %episode.parent_window_title,
                            reason = %error,
                            "macOS suppressed-sheet observation was indeterminate"
                        );
                        TrustedProcessPresence::Indeterminate
                    }
                }
            } else {
                TrustedProcessPresence::Indeterminate
            };
            if sheet_exit_tracker.observe(episode, sheet_presence, recent_prompt_attempts) {
                released_sheet_episodes += 1;
            }
        }
    }

    Ok((released_processes, released_sheet_episodes))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MacosForegroundNoPromptEvidence {
    process_id: i32,
    window_title: String,
}

impl MacosForegroundNoPromptEvidence {
    fn new(process_id: i32, window_title: &str) -> Self {
        Self {
            process_id,
            window_title: canonical_prompt_component(window_title),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct MacosNoPromptSnapshot<'a> {
    process_found: bool,
    target_process_id: Option<i32>,
    target_window_title: Option<&'a str>,
    target_frontmost: Option<bool>,
    target_window_observed: bool,
    selected_prompt_present: bool,
    prompt_candidate_count: usize,
}

fn macos_foreground_no_prompt_evidence(
    snapshot: MacosNoPromptSnapshot<'_>,
) -> Option<MacosForegroundNoPromptEvidence> {
    if !snapshot.process_found
        || snapshot.target_frontmost != Some(true)
        || !snapshot.target_window_observed
        || snapshot.selected_prompt_present
        || snapshot.prompt_candidate_count != 0
    {
        return None;
    }

    let process_id = snapshot
        .target_process_id
        .filter(|process_id| *process_id > 0)?;
    Some(MacosForegroundNoPromptEvidence::new(
        process_id,
        snapshot.target_window_title?,
    ))
}

#[cfg(target_os = "macos")]
fn macos_foreground_no_prompt_evidence_from_monitor_snapshot(
    snapshot: &crate::monitor::MacosMonitorSnapshot,
) -> Option<MacosForegroundNoPromptEvidence> {
    macos_foreground_no_prompt_evidence(MacosNoPromptSnapshot {
        process_found: snapshot.process_found,
        target_process_id: snapshot.target_process_id,
        target_window_title: snapshot.target_window_title.as_deref(),
        target_frontmost: snapshot.target_frontmost,
        target_window_observed: snapshot.target_window_observed,
        selected_prompt_present: snapshot.selected_prompt_present,
        prompt_candidate_count: snapshot.prompt_candidate_count,
    })
}

fn clear_recent_prompt_attempts_for_macos_foreground_window(
    recent_prompt_attempts: &Arc<Mutex<HashMap<LoginPromptKey, Instant>>>,
    evidence: &MacosForegroundNoPromptEvidence,
) -> bool {
    let Ok(mut prompts) = recent_prompt_attempts.lock() else {
        return false;
    };
    // First bind the foreground no-prompt proof to a reserved prompt from the
    // same trusted process and parent window. Then release that prompt's
    // account/email identity across transient window observations, matching
    // the account-wide suppression predicate.
    let identities = prompts
        .keys()
        .filter(|attempted| {
            attempted.process_id == evidence.process_id
                && attempted.window_title == evidence.window_title
        })
        .map(|attempted| (attempted.account_id.clone(), attempted.prompt_email.clone()))
        .collect::<Vec<_>>();
    if identities.is_empty() {
        return false;
    }

    let previous_len = prompts.len();
    prompts.retain(|attempted, _| {
        !identities.iter().any(|(account_id, prompt_email)| {
            attempted.account_id == *account_id && attempted.prompt_email == *prompt_email
        })
    });
    prompts.len() != previous_len
}

#[derive(Debug, Default)]
struct DefinitiveNoPromptTracker {
    consecutive_polls: u8,
    macos_foreground_evidence: Option<MacosForegroundNoPromptEvidence>,
}

impl DefinitiveNoPromptTracker {
    fn reset(&mut self) {
        self.consecutive_polls = 0;
        self.macos_foreground_evidence = None;
    }

    fn observe_prompt(&mut self) {
        self.reset();
    }

    fn observe_indeterminate(&mut self) {
        self.reset();
    }

    fn observe_definitive_no_prompt(
        &mut self,
        recent_prompt_attempts: &Arc<Mutex<HashMap<LoginPromptKey, Instant>>>,
    ) -> bool {
        if self.macos_foreground_evidence.is_some() {
            self.reset();
        }
        self.consecutive_polls = self.consecutive_polls.saturating_add(1);
        if self.consecutive_polls < 2 {
            return false;
        }
        clear_recent_prompt_attempts(recent_prompt_attempts);
        self.reset();
        true
    }

    fn observe_macos_foreground_no_prompt(
        &mut self,
        evidence: MacosForegroundNoPromptEvidence,
        recent_prompt_attempts: &Arc<Mutex<HashMap<LoginPromptKey, Instant>>>,
    ) -> bool {
        if self.macos_foreground_evidence.as_ref() != Some(&evidence) {
            self.reset();
            self.macos_foreground_evidence = Some(evidence.clone());
        }
        self.consecutive_polls = self.consecutive_polls.saturating_add(1);
        if self.consecutive_polls < MACOS_RETRY_REARM_NO_PROMPT_OBSERVATIONS {
            return false;
        }

        let released = clear_recent_prompt_attempts_for_macos_foreground_window(
            recent_prompt_attempts,
            &evidence,
        );
        self.reset();
        released
    }
}

#[derive(Default)]
struct PrePasswordReportPersistence {
    last_attempted_at_by_key: HashMap<String, Instant>,
    observed_this_tick: bool,
    persisted_this_tick: bool,
}

fn pre_password_persistence_key(reason: &str) -> &str {
    match reason {
        // The monitor cannot distinguish "no enabled account" from "matching
        // account has no saved password", while the macOS fallback can. Both
        // describe the same stable pre-password state and must not alternate
        // writes on every poll tick.
        "visible_prompt_email_matches_no_enabled_account"
        | "visible_prompt_email_matches_no_saved_password" => {
            "visible_prompt_email_has_no_usable_saved_password"
        }
        reason if reason.starts_with("prompt_detection_failed_") => "prompt_detection_failed",
        reason if reason.starts_with("attempt_cancelled_") => "attempt_cancelled",
        _ => reason,
    }
}

impl PrePasswordReportPersistence {
    fn should_persist(
        &mut self,
        reason: &str,
        _fields: &[(&'static str, String)],
        now: Instant,
    ) -> bool {
        self.observed_this_tick = true;
        let key = pre_password_persistence_key(reason);
        self.last_attempted_at_by_key.retain(|_, attempted_at| {
            now.saturating_duration_since(*attempted_at) < PRE_PASSWORD_REPORT_PERSIST_INTERVAL
        });
        if self.persisted_this_tick
            || self.last_attempted_at_by_key.get(key).is_some_and(|last| {
                now.saturating_duration_since(*last) < PRE_PASSWORD_REPORT_PERSIST_INTERVAL
            })
        {
            return false;
        }

        self.last_attempted_at_by_key.insert(key.to_string(), now);
        self.persisted_this_tick = true;
        true
    }

    fn begin_poll_tick(&mut self) {
        self.observed_this_tick = false;
        self.persisted_this_tick = false;
    }

    fn observe_monitor_status(&mut self, definitive_no_prompt: bool) {
        if definitive_no_prompt {
            self.observe_no_prompt();
        }
    }

    fn observe_no_prompt(&mut self) {
        if !self.observed_this_tick {
            self.last_attempted_at_by_key.clear();
        }
    }

    fn reset_observed_state(&mut self) {
        self.last_attempted_at_by_key.clear();
        self.observed_this_tick = false;
        self.persisted_this_tick = false;
    }
}

fn emit_pre_password_skip_report(
    event_tx: &Sender<WorkerEvent>,
    persistence: &mut PrePasswordReportPersistence,
    reason: impl Into<String>,
    fields: &[(&'static str, String)],
) {
    let reason = reason.into();
    let should_persist = persistence.should_persist(&reason, fields, Instant::now());
    let report = debug_fill::pre_password_skip_report(reason, fields);
    if should_persist {
        if let Err(e) = debug_fill::write_last_fill_attempt_report(&report) {
            warn!("Could not persist pre-password skip report: {e}");
        }
    }
    let _ = event_tx.try_send(WorkerEvent::FillAttemptReport(report));
}

fn monitor_prompt_fields(
    process_id: i32,
    prompt_email: Option<&str>,
    prompt_origin: &str,
) -> Vec<(&'static str, String)> {
    let mut fields = vec![
        (
            "prompt_context_source",
            "monitor_snapshot_preflight".to_string(),
        ),
        ("prompt_detected", "true".to_string()),
        ("windows_app_pid", process_id.to_string()),
        ("prompt_origin", prompt_origin.to_string()),
    ];
    if let Some(email) = prompt_email {
        fields.push(("detected_email_redacted", debug_fill::redacted_email(email)));
    }
    fields
}

#[allow(clippy::too_many_arguments)]
async fn handle_command(
    cmd: WorkerCommand,
    event_tx: &Sender<WorkerEvent>,
    running: &mut bool,
    settings: &mut AppSettings,
    accounts: &mut Vec<Account>,
    generation: &Arc<AtomicU64>,
    pause_latch: &WorkerPauseLatch,
    activity_tracker: &WorkerActivityTracker,
) {
    match cmd {
        WorkerCommand::Start => {
            if pause_latch.is_paused() {
                enforce_pause(event_tx, running, generation).await;
                warn!("Background worker start ignored while automation pause latch is active");
                return;
            }
            if *running {
                return;
            }
            *running = true;
            generation.fetch_add(1, Ordering::SeqCst);
            let _ = event_tx
                .send(WorkerEvent::StatusChanged(WorkerStatus::Running))
                .await;
            info!("Background worker started");
        }
        WorkerCommand::Stop => {
            if !*running {
                return;
            }
            *running = false;
            generation.fetch_add(1, Ordering::SeqCst);
            let _ = event_tx
                .send(WorkerEvent::StatusChanged(WorkerStatus::Idle))
                .await;
            info!("Background worker stopped");
        }
        WorkerCommand::Quiesce {
            request_id,
            acknowledgement,
        } => {
            activity_tracker.acknowledge_when_quiescent(request_id, acknowledgement);
        }
        #[cfg(test)]
        WorkerCommand::ApplyConfig {
            settings: next_settings,
            accounts: next_accounts,
            refresh_passwords,
        } => {
            apply_config(
                settings,
                accounts,
                generation,
                next_settings,
                next_accounts,
                refresh_passwords,
            );
        }
        WorkerCommand::ApplyConfigAndReleasePause {
            settings: next_settings,
            accounts: next_accounts,
            refresh_passwords,
            start_monitor,
            pause_epoch,
        } => {
            if !pause_latch.owns_pause(pause_epoch) {
                warn!("Stale worker config and pause release ignored after a newer safety event");
                return;
            }
            apply_config(
                settings,
                accounts,
                generation,
                next_settings,
                next_accounts,
                refresh_passwords,
            );
            if !start_monitor && *running {
                *running = false;
                generation.fetch_add(1, Ordering::SeqCst);
                let _ = event_tx
                    .send(WorkerEvent::StatusChanged(WorkerStatus::Idle))
                    .await;
                info!("Background worker stopped by atomic config apply");
            }
            if !pause_latch.resume_if_epoch(pause_epoch) {
                warn!("Stale worker pause release ignored after a newer safety event");
                return;
            }
            if !activity_tracker.reopen_after_fresh_release() {
                pause_latch.pause();
                warn!("Worker activity gate could not be reopened safely; pause remains active");
                return;
            }
            info!("Background worker pause released after fresh config was applied");
            if start_monitor && !*running {
                *running = true;
                generation.fetch_add(1, Ordering::SeqCst);
                let _ = event_tx
                    .send(WorkerEvent::StatusChanged(WorkerStatus::Running))
                    .await;
                info!("Background worker resumed after fresh config was applied");
            }
        }
    }
}

fn apply_config(
    settings: &mut AppSettings,
    accounts: &mut Vec<Account>,
    generation: &Arc<AtomicU64>,
    next_settings: AppSettings,
    next_accounts: Vec<Account>,
    refresh_passwords: bool,
) {
    let settings_changed = *settings != next_settings;
    let accounts_changed = *accounts != next_accounts;
    if settings_changed {
        *settings = next_settings;
    }
    if accounts_changed {
        *accounts = next_accounts;
    }
    if settings_changed || accounts_changed || refresh_passwords {
        generation.fetch_add(1, Ordering::SeqCst);
        info!(
            "Worker config applied: settings_changed={} accounts_changed={} account(s)={} refresh_passwords={}",
            settings_changed,
            accounts_changed,
            accounts.len(),
            refresh_passwords
        );
    }
}

async fn enforce_pause(
    event_tx: &Sender<WorkerEvent>,
    running: &mut bool,
    generation: &Arc<AtomicU64>,
) {
    if !*running {
        return;
    }
    *running = false;
    generation.fetch_add(1, Ordering::SeqCst);
    let _ = event_tx
        .send(WorkerEvent::StatusChanged(WorkerStatus::Idle))
        .await;
    info!("Background worker paused by supervisor latch");
}

#[allow(clippy::too_many_arguments)]
async fn drain_commands(
    cmd_rx: &mut Receiver<WorkerCommand>,
    event_tx: &Sender<WorkerEvent>,
    running: &mut bool,
    settings: &mut AppSettings,
    accounts: &mut Vec<Account>,
    generation: &Arc<AtomicU64>,
    pause_latch: &WorkerPauseLatch,
    activity_tracker: &WorkerActivityTracker,
) {
    while let Ok(cmd) = cmd_rx.try_recv() {
        handle_command(
            cmd,
            event_tx,
            running,
            settings,
            accounts,
            generation,
            pause_latch,
            activity_tracker,
        )
        .await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn wait_or_handle_command(
    duration: Duration,
    cmd_rx: &mut Receiver<WorkerCommand>,
    event_tx: &Sender<WorkerEvent>,
    running: &mut bool,
    settings: &mut AppSettings,
    accounts: &mut Vec<Account>,
    generation: &Arc<AtomicU64>,
    pause_latch: &WorkerPauseLatch,
    activity_tracker: &WorkerActivityTracker,
) -> bool {
    tokio::select! {
        _ = sleep(duration) => true,
        maybe_cmd = cmd_rx.recv() => {
            let Some(cmd) = maybe_cmd else {
                return false;
            };
            handle_command(
                cmd,
                event_tx,
                running,
                settings,
                accounts,
                generation,
                pause_latch,
                activity_tracker,
            )
            .await;
            drain_commands(
                cmd_rx,
                event_tx,
                running,
                settings,
                accounts,
                generation,
                pause_latch,
                activity_tracker,
            )
            .await;
            true
        }
    }
}

fn spawn_current_prompt_attempt(job: CurrentPromptAttempt) -> bool {
    if job
        .pause_latch
        .ensure_attempt_current(job.expected_generation, "worker paused or config changed")
        .is_err()
    {
        debug!("Fill current prompt skipped; worker is paused or config changed");
        return false;
    }
    let Some(automation_guard) = FlagGuard::acquire(&job.automation_in_progress) else {
        debug!("Fill current prompt skipped; UI automation is busy");
        let _ = job.event_tx.try_send(log_event(
            LogLevel::Warn,
            format!("{} skipped: UI automation is busy", job.trigger.label()),
        ));
        return false;
    };
    let Some(activity_guard) = job.activity_tracker.begin_attempt() else {
        warn!("Fill current prompt skipped; worker activity gate is closed or unavailable");
        let _ = job.event_tx.try_send(log_event(
            LogLevel::Warn,
            format!(
                "{} skipped: worker activity gate is closed or unavailable",
                job.trigger.label()
            ),
        ));
        return false;
    };

    // Recheck after both admission locks and immediately before reserving the
    // prompt identity. A pause already published while admission was waiting
    // must neither start automation nor consume this prompt's retry episode.
    if job
        .pause_latch
        .ensure_attempt_current(job.expected_generation, "worker paused or config changed")
        .is_err()
    {
        debug!("Fill current prompt skipped; worker paused during attempt admission");
        return false;
    }

    // Reserve the stable prompt identity before the worker thread starts. A
    // crash, cancellation, rejected credential, or storage failure must not
    // turn into an unbounded automatic retry loop against the same prompt.
    if !reserve_prompt_retry_suppression(job.prompt_retry_suppression.as_ref()) {
        warn!("Fill current prompt skipped; retry-suppression state is unavailable");
        let _ = job.event_tx.try_send(log_event(
            LogLevel::Warn,
            format!(
                "{} skipped: retry-suppression state is unavailable",
                job.trigger.label()
            ),
        ));
        return false;
    }

    std::thread::spawn(move || {
        // This outer guard drops only after every password, storage, UI, report,
        // and event-send local in the inner scope has been destroyed.
        let _activity_guard = activity_guard;
        {
            let CurrentPromptAttempt {
                trigger,
                settings,
                accounts,
                event_tx,
                pause_latch,
                expected_generation,
                prompt_context,
                prompt_retry_suppression,
                activity_tracker: _,
                ..
            } = job;
            let _automation_guard = automation_guard;
            let report = debug_fill::fill_current_prompt_once_guarded_with_context(
                &settings,
                &accounts,
                FillMethod::Keyboard,
                prompt_context,
                || {
                    pause_latch
                        .ensure_attempt_current(expected_generation, "accounts/settings changed")
                },
            );
            if !release_prompt_retry_suppression_after_authenticated_success(
                prompt_retry_suppression.as_ref(),
                &report,
            ) {
                warn!("Could not release retry suppression after authenticated fill attempt");
            }
            if let Err(e) = debug_fill::write_last_fill_attempt_report(&report) {
                warn!("Could not persist fill attempt report: {e}");
            }
            let level = if report.success {
                LogLevel::Info
            } else {
                LogLevel::Warn
            };
            let should_log = report.success
                || report.field("prompt_detected") == Some("true")
                || report.field("prompt_context_present") == Some("true");
            if should_log {
                let _ = event_tx.try_send(log_event(
                    level,
                    format!("{}: {}", trigger.label(), report.summary_line()),
                ));
            }
            let _ = event_tx.try_send(WorkerEvent::FillAttemptReport(report));
        }
    });
    true
}

pub(crate) fn spawn(
    mut cmd_rx: Receiver<WorkerCommand>,
    event_tx: Sender<WorkerEvent>,
    initial_settings: AppSettings,
    initial_accounts: Vec<Account>,
    invalidator: WorkerInvalidator,
    pause_latch: WorkerPauseLatch,
) {
    tokio::spawn(async move {
        let mut settings = initial_settings;
        let mut accounts = initial_accounts;
        let mut running = false;
        let recent_prompt_attempts =
            Arc::new(Mutex::new(HashMap::<LoginPromptKey, Instant>::new()));
        let automation_in_progress = Arc::new(AtomicBool::new(false));
        let activity_tracker = WorkerActivityTracker::default();
        let generation = invalidator.generation;
        #[cfg(target_os = "macos")]
        let mut last_macos_prompt_probe: Option<Instant> = None;
        let mut poll_cadence = PollCadence::default();
        let mut no_prompt_tracker = DefinitiveNoPromptTracker::default();
        #[cfg(target_os = "macos")]
        let mut process_exit_tracker = DefinitiveProcessExitTracker::default();
        #[cfg(target_os = "macos")]
        let mut sheet_exit_tracker = DefinitiveSheetExitTracker::default();
        let mut pre_password_report_persistence = PrePasswordReportPersistence::default();
        let mut pre_password_generation = generation.load(Ordering::SeqCst);

        loop {
            drain_commands(
                &mut cmd_rx,
                &event_tx,
                &mut running,
                &mut settings,
                &mut accounts,
                &generation,
                &pause_latch,
                &activity_tracker,
            )
            .await;

            if pause_latch.is_paused() {
                enforce_pause(&event_tx, &mut running, &generation).await;
            }

            if !running {
                no_prompt_tracker.reset();
                #[cfg(target_os = "macos")]
                {
                    process_exit_tracker.reset();
                    sheet_exit_tracker.reset();
                }
                pre_password_report_persistence.reset_observed_state();
                if !wait_or_handle_command(
                    IDLE_SLEEP,
                    &mut cmd_rx,
                    &event_tx,
                    &mut running,
                    &mut settings,
                    &mut accounts,
                    &generation,
                    &pause_latch,
                    &activity_tracker,
                )
                .await
                {
                    break;
                }
                continue;
            }

            let Some(current_generation) = pause_latch.stable_unpaused_generation() else {
                enforce_pause(&event_tx, &mut running, &generation).await;
                continue;
            };
            if current_generation != pre_password_generation {
                no_prompt_tracker.reset();
                #[cfg(target_os = "macos")]
                {
                    process_exit_tracker.reset();
                    sheet_exit_tracker.reset();
                }
                pre_password_report_persistence.reset_observed_state();
                pre_password_generation = current_generation;
            }

            if automation_in_progress.load(Ordering::SeqCst) {
                poll_cadence = PollCadence::default();
                if !wait_or_handle_command(
                    AUTOMATION_SLEEP,
                    &mut cmd_rx,
                    &event_tx,
                    &mut running,
                    &mut settings,
                    &mut accounts,
                    &generation,
                    &pause_latch,
                    &activity_tracker,
                )
                .await
                {
                    break;
                }
                continue;
            }

            let has_enabled_account = accounts.iter().any(|account| {
                account.enabled && account.has_saved_password && !account.username.trim().is_empty()
            });

            if !has_enabled_account {
                pre_password_report_persistence.reset_observed_state();
                if !wait_or_handle_command(
                    fixed_poll_interval(),
                    &mut cmd_rx,
                    &event_tx,
                    &mut running,
                    &mut settings,
                    &mut accounts,
                    &generation,
                    &pause_latch,
                    &activity_tracker,
                )
                .await
                {
                    break;
                }
                continue;
            }

            let monitor = AppMonitor::new(runtime_config(&settings));
            let tick_start = Instant::now();
            #[cfg(target_os = "macos")]
            match observe_suppressed_macos_episode_exits(
                &mut process_exit_tracker,
                &mut sheet_exit_tracker,
                &recent_prompt_attempts,
                || {
                    pause_latch.ensure_attempt_current(
                        current_generation,
                        "accounts/settings changed during suppressed-process probe",
                    )
                },
            ) {
                Ok((released_processes, released_sheet_episodes))
                    if released_processes > 0 || released_sheet_episodes > 0 =>
                {
                    debug!(
                        released_processes,
                        released_sheet_episodes,
                        "macOS prompt retry suppression re-armed after confirmed episode exit"
                    );
                }
                Ok(_) => {}
                Err(reason) => {
                    process_exit_tracker.reset();
                    sheet_exit_tracker.reset();
                    debug!(
                        reason = %reason,
                        "macOS suppressed-process probe was cancelled"
                    );
                    continue;
                }
            }
            #[cfg(target_os = "windows")]
            let status_check_start = Instant::now();
            #[cfg(target_os = "macos")]
            let (monitor_observation, macos_monitor_snapshot_this_tick) =
                monitor.check_status_with_snapshot();
            #[cfg(target_os = "macos")]
            if let Err(reason) = pause_latch.ensure_attempt_current(
                current_generation,
                "accounts/settings changed during macOS monitor inspection",
            ) {
                no_prompt_tracker.reset();
                debug!(
                    reason = %reason,
                    "macOS monitor snapshot was cancelled before it could affect automation state"
                );
                continue;
            }
            #[cfg(not(target_os = "macos"))]
            let monitor_observation = monitor.check_status();
            let MonitorObservation {
                status,
                definitive_no_prompt,
            } = monitor_observation;
            #[cfg(target_os = "windows")]
            let monitor_check_ms = status_check_start.elapsed().as_millis();
            let status_poll_delay = poll_cadence.next_delay(&settings, &status);
            let next_poll_delay = status_poll_delay.min(PROMPT_STATUS_POLL_INTERVAL);
            trace!(
                worker_tick_ms = tick_start.elapsed().as_millis(),
                worker_state = if running { "running" } else { "idle" },
                windows_app_running = !matches!(status, MonitorStatus::ProcessNotFound),
                prompt_candidate_visible =
                    matches!(status, MonitorStatus::LoginWindowDetected { .. }),
                suppression_active = false,
                suppression_reason = "",
                suppression_until_ms = 0_u64,
                backoff_ms = status_poll_delay.as_millis(),
                next_attempt_in_ms = if matches!(
                    status,
                    MonitorStatus::LoginWindowDetected { .. } | MonitorStatus::Unknown
                ) {
                    0
                } else {
                    next_poll_delay.as_millis()
                },
                last_attempt_failure_reason = "",
                "Monitor status: {}",
                safe_status_name(&status)
            );

            #[cfg(target_os = "macos")]
            let status_allows_macos_probe = matches!(status, MonitorStatus::Unknown);
            #[cfg(target_os = "macos")]
            let mut prompt_attempt_started = false;
            pre_password_report_persistence.begin_poll_tick();
            pre_password_report_persistence.observe_monitor_status(definitive_no_prompt);
            #[cfg_attr(not(target_os = "macos"), allow(unused_mut))]
            let mut definitive_no_prompt_this_tick = definitive_no_prompt;
            let mut prompt_observed_this_tick = false;
            #[cfg(target_os = "macos")]
            let macos_foreground_no_prompt_evidence_this_tick = macos_monitor_snapshot_this_tick
                .as_ref()
                .and_then(macos_foreground_no_prompt_evidence_from_monitor_snapshot);
            #[cfg(not(target_os = "macos"))]
            let macos_foreground_no_prompt_evidence_this_tick = None;

            #[cfg(target_os = "macos")]
            if macos_monitor_snapshot_this_tick
                .as_ref()
                .is_some_and(|snapshot| snapshot.prompt_candidate_count == 0)
            {
                // This is the same complete prompt-negative observation that
                // the old fallback probe reported, now reused without another
                // process/signature/AX traversal.
                pre_password_report_persistence.observe_no_prompt();
            }

            match status {
                MonitorStatus::Connected => {}
                // Unknown includes any failed or incomplete UI Automation
                // traversal and can never prove that a submitted prompt is
                // gone. Only a complete Connected inspection or process exit
                // may advance the two-observation re-arm tracker on Windows.
                MonitorStatus::Unknown => {}
                MonitorStatus::ProcessNotFound => {}
                MonitorStatus::LoginWindowDetected {
                    process_id,
                    window_handle,
                    window_title,
                    prompt_email,
                    prompt_origin,
                } => {
                    prompt_observed_this_tick = true;
                    no_prompt_tracker.observe_prompt();
                    let account_decision =
                        account_for_visible_prompt_email(&accounts, prompt_email.as_deref());

                    match account_decision {
                        PromptAccountDecision::Allow(account) => {
                            let prompt_email = prompt_email.unwrap_or_default();
                            let prompt_key = LoginPromptKey::new(
                                account.id.clone(),
                                process_id,
                                window_handle,
                                window_title.clone(),
                                prompt_email.clone(),
                                prompt_origin.clone(),
                            );
                            let suppressed = recent_prompt_attempts
                                .lock()
                                .map(|prompts| prompt_retry_is_suppressed(&prompts, &prompt_key))
                                .unwrap_or(true);
                            if suppressed {
                                debug!("Login prompt retry suppressed for recent prompt");
                                let mut fields = monitor_prompt_fields(
                                    process_id,
                                    Some(&prompt_email),
                                    &prompt_origin,
                                );
                                fields.push(("selected_account_id", account.id.clone()));
                                emit_pre_password_skip_report(
                                    &event_tx,
                                    &mut pre_password_report_persistence,
                                    "prompt_retry_suppressed",
                                    &fields,
                                );
                            } else {
                                let prompt_context = debug_fill::VerifiedPromptContext {
                                    account_id: account.id.clone(),
                                    process_id,
                                    #[cfg(target_os = "windows")]
                                    window_handle,
                                    window_title: window_title.clone(),
                                    prompt_email,
                                    prompt_origin,
                                    detected_at: Instant::now(),
                                    #[cfg(target_os = "windows")]
                                    monitor_check_ms,
                                };
                                pre_password_report_persistence.reset_observed_state();
                                let started = spawn_current_prompt_attempt(CurrentPromptAttempt {
                                    trigger: FillTrigger::Automatic,
                                    settings: settings.clone(),
                                    accounts: accounts.clone(),
                                    event_tx: event_tx.clone(),
                                    automation_in_progress: automation_in_progress.clone(),
                                    pause_latch: pause_latch.clone(),
                                    expected_generation: current_generation,
                                    prompt_context: Some(prompt_context),
                                    prompt_retry_suppression: Some(PromptRetrySuppression {
                                        recent_prompt_attempts: recent_prompt_attempts.clone(),
                                        prompt_key,
                                    }),
                                    activity_tracker: activity_tracker.clone(),
                                });
                                if started {
                                    #[cfg(target_os = "macos")]
                                    {
                                        prompt_attempt_started = true;
                                    }
                                    let _ = event_tx.try_send(log_event(
                                        LogLevel::Info,
                                        "Login window detected",
                                    ));
                                }
                            }
                        }
                        PromptAccountDecision::MissingEmail => {
                            debug!(
                                "Login window detected but no email was visible; skipping password load"
                            );
                            let fields = monitor_prompt_fields(process_id, None, &prompt_origin);
                            emit_pre_password_skip_report(
                                &event_tx,
                                &mut pre_password_report_persistence,
                                "visible_prompt_email_missing",
                                &fields,
                            );
                        }
                        PromptAccountDecision::NoEnabledMatch => {
                            warn!(
                                "Login window email does not match any enabled account with a saved password"
                            );
                            let fields = monitor_prompt_fields(
                                process_id,
                                prompt_email.as_deref(),
                                &prompt_origin,
                            );
                            emit_pre_password_skip_report(
                                &event_tx,
                                &mut pre_password_report_persistence,
                                "visible_prompt_email_matches_no_saved_password",
                                &fields,
                            );
                        }
                        PromptAccountDecision::Ambiguous => {
                            warn!(
                                "Login window email matches multiple enabled accounts with saved passwords; skipping ambiguous login"
                            );
                            let fields = monitor_prompt_fields(
                                process_id,
                                prompt_email.as_deref(),
                                &prompt_origin,
                            );
                            emit_pre_password_skip_report(
                                &event_tx,
                                &mut pre_password_report_persistence,
                                "visible_prompt_email_matches_multiple_enabled_accounts",
                                &fields,
                            );
                        }
                    }
                }
            }

            #[cfg(target_os = "macos")]
            {
                let prompt_probe_due = last_macos_prompt_probe
                    .map(|attempt| attempt.elapsed() >= MACOS_FALLBACK_PROMPT_PROBE_INTERVAL)
                    .unwrap_or(true);
                if should_run_macos_fallback_prompt_probe(
                    prompt_attempt_started,
                    macos_monitor_snapshot_this_tick.is_some(),
                    status_allows_macos_probe,
                    prompt_probe_due,
                ) {
                    let now = Instant::now();
                    last_macos_prompt_probe = Some(now);
                    let prompt_probe_result =
                        debug_fill::detect_current_prompt_context(&accounts, || {
                            pause_latch.ensure_attempt_current(
                                current_generation,
                                "accounts/settings changed",
                            )
                        });
                    if let Err(reason) = pause_latch.ensure_attempt_current(
                        current_generation,
                        "accounts/settings changed during macOS fallback prompt inspection",
                    ) {
                        no_prompt_tracker.reset();
                        debug!(
                            reason = %reason,
                            "macOS fallback prompt snapshot was cancelled before it could affect automation state"
                        );
                        continue;
                    }
                    match prompt_probe_result {
                        Ok(Some(prompt_context)) => {
                            prompt_observed_this_tick = true;
                            definitive_no_prompt_this_tick = false;
                            no_prompt_tracker.observe_prompt();
                            let prompt_key = LoginPromptKey::from_verified_context(&prompt_context);
                            let suppressed = recent_prompt_attempts
                                .lock()
                                .map(|prompts| prompt_retry_is_suppressed(&prompts, &prompt_key))
                                .unwrap_or(true);
                            if suppressed {
                                debug!("macOS fallback prompt retry suppressed for recent prompt");
                                emit_pre_password_skip_report(
                                    &event_tx,
                                    &mut pre_password_report_persistence,
                                    "prompt_retry_suppressed",
                                    &[
                                        (
                                            "prompt_context_source",
                                            "macos_fallback_preflight".to_string(),
                                        ),
                                        ("prompt_detected", "true".to_string()),
                                        ("windows_app_pid", prompt_context.process_id.to_string()),
                                        (
                                            "detected_email_redacted",
                                            debug_fill::redacted_email(
                                                &prompt_context.prompt_email,
                                            ),
                                        ),
                                        ("selected_account_id", prompt_context.account_id.clone()),
                                    ],
                                );
                            } else {
                                pre_password_report_persistence.reset_observed_state();
                                let started = spawn_current_prompt_attempt(CurrentPromptAttempt {
                                    trigger: FillTrigger::Automatic,
                                    settings: settings.clone(),
                                    accounts: accounts.clone(),
                                    event_tx: event_tx.clone(),
                                    automation_in_progress: automation_in_progress.clone(),
                                    pause_latch: pause_latch.clone(),
                                    expected_generation: current_generation,
                                    prompt_context: Some(prompt_context),
                                    prompt_retry_suppression: Some(PromptRetrySuppression {
                                        recent_prompt_attempts: recent_prompt_attempts.clone(),
                                        prompt_key,
                                    }),
                                    activity_tracker: activity_tracker.clone(),
                                });
                                if started {
                                    if !wait_or_handle_command(
                                        AUTOMATION_SLEEP,
                                        &mut cmd_rx,
                                        &event_tx,
                                        &mut running,
                                        &mut settings,
                                        &mut accounts,
                                        &generation,
                                        &pause_latch,
                                        &activity_tracker,
                                    )
                                    .await
                                    {
                                        break;
                                    }
                                    continue;
                                }
                            }
                        }
                        Ok(None) => {
                            pre_password_report_persistence.observe_no_prompt();
                            definitive_no_prompt_this_tick = false;
                            trace!(
                                "macOS fallback found no prompt after the monitor inspection failed; observation remains indeterminate"
                            );
                        }
                        Err(reason) => {
                            definitive_no_prompt_this_tick = false;
                            debug!(reason = %reason, "macOS fallback prompt preflight skipped");
                            emit_pre_password_skip_report(
                                &event_tx,
                                &mut pre_password_report_persistence,
                                reason,
                                &[(
                                    "prompt_context_source",
                                    "macos_fallback_preflight".to_string(),
                                )],
                            );
                        }
                    }
                }
            }

            if prompt_observed_this_tick {
                no_prompt_tracker.observe_prompt();
            } else if let Some(evidence) = macos_foreground_no_prompt_evidence_this_tick {
                if no_prompt_tracker
                    .observe_macos_foreground_no_prompt(evidence, &recent_prompt_attempts)
                {
                    debug!(
                        "macOS prompt retry suppression re-armed after repeated foreground no-prompt observations"
                    );
                }
            } else if definitive_no_prompt_this_tick {
                no_prompt_tracker.observe_definitive_no_prompt(&recent_prompt_attempts);
            } else {
                no_prompt_tracker.observe_indeterminate();
            }

            #[cfg(target_os = "macos")]
            if prompt_attempt_started {
                if !wait_or_handle_command(
                    AUTOMATION_SLEEP,
                    &mut cmd_rx,
                    &event_tx,
                    &mut running,
                    &mut settings,
                    &mut accounts,
                    &generation,
                    &pause_latch,
                    &activity_tracker,
                )
                .await
                {
                    break;
                }
                continue;
            }

            if !wait_or_handle_command(
                remaining_tick_delay(tick_start, next_poll_delay),
                &mut cmd_rx,
                &event_tx,
                &mut running,
                &mut settings,
                &mut accounts,
                &generation,
                &pause_latch,
                &activity_tracker,
            )
            .await
            {
                break;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::{
        account_for_visible_prompt_email, ensure_generation_current, handle_command,
        macos_foreground_no_prompt_evidence, prompt_retry_is_suppressed,
        release_prompt_retry_suppression_after_authenticated_success,
        reserve_prompt_retry_suppression, should_run_macos_fallback_prompt_probe,
        wait_or_handle_command, DefinitiveNoPromptTracker, DefinitiveProcessExitTracker,
        DefinitiveSheetExitTracker, LoginPromptKey, MacosForegroundNoPromptEvidence,
        MacosNoPromptSnapshot, MonitorStatus, PollCadence, PrePasswordReportPersistence,
        PromptAccountDecision, PromptRetrySuppression, SuppressedSheetEpisode,
        TrustedProcessPresence, WorkerActivityTracker, WorkerCommand, WorkerEvent,
        WorkerInvalidator, WorkerPauseLatch, WorkerQuiescenceAck,
        MACOS_FALLBACK_PROMPT_PROBE_INTERVAL, MACOS_RETRY_REARM_NO_PROMPT_OBSERVATIONS,
        MACOS_RETRY_REARM_PROCESS_EXIT_OBSERVATIONS, MACOS_RETRY_REARM_SHEET_EXIT_OBSERVATIONS,
        PRE_PASSWORD_REPORT_PERSIST_INTERVAL, PROMPT_STATUS_POLL_INTERVAL,
    };
    use crate::debug_fill;
    use crate::models::{Account, AppSettings, WorkerStatus};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    use tokio::sync::mpsc;

    fn pause_latch_for_generation(generation: &Arc<AtomicU64>) -> WorkerPauseLatch {
        WorkerInvalidator {
            generation: generation.clone(),
        }
        .pause_latch()
    }

    #[test]
    fn poll_cadence_backs_off_for_stable_statuses_but_keeps_prompts_fast() {
        let settings = AppSettings {
            poll_interval_secs: 60,
            ..AppSettings::default()
        };
        let mut cadence = PollCadence::default();
        let prompt = MonitorStatus::LoginWindowDetected {
            process_id: 42,
            window_handle: 7,
            window_title: "Sign in".to_string(),
            prompt_email: Some("user@example.com".to_string()),
            prompt_origin: "window".to_string(),
        };

        assert_eq!(
            cadence.next_delay(&settings, &MonitorStatus::Connected),
            Duration::from_secs(1)
        );
        assert_eq!(
            cadence.next_delay(&settings, &MonitorStatus::Connected),
            Duration::from_secs(2)
        );
        assert_eq!(
            cadence.next_delay(&settings, &MonitorStatus::Connected),
            Duration::from_secs(4)
        );
        assert_eq!(
            cadence.next_delay(&settings, &MonitorStatus::Connected),
            Duration::from_secs(5)
        );
        assert_eq!(
            cadence.next_delay(&settings, &prompt),
            Duration::from_secs(1)
        );
        assert_eq!(
            cadence.next_delay(&settings, &prompt),
            Duration::from_secs(1)
        );

        assert_eq!(
            cadence.next_delay(&settings, &MonitorStatus::Unknown),
            Duration::from_secs(1)
        );
        assert_eq!(
            cadence.next_delay(&settings, &MonitorStatus::Unknown),
            Duration::from_secs(2)
        );
        assert_eq!(
            cadence.next_delay(&settings, &MonitorStatus::Unknown),
            Duration::from_secs(3)
        );

        assert_eq!(PROMPT_STATUS_POLL_INTERVAL, Duration::from_secs(1));
        assert_eq!(
            MACOS_FALLBACK_PROMPT_PROBE_INTERVAL,
            PROMPT_STATUS_POLL_INTERVAL
        );
    }

    #[test]
    fn macos_successful_monitor_snapshot_prevents_redundant_fallback_probe() {
        assert!(!should_run_macos_fallback_prompt_probe(
            false, true, true, true
        ));
        assert!(should_run_macos_fallback_prompt_probe(
            false, false, true, true
        ));
        assert!(!should_run_macos_fallback_prompt_probe(
            true, false, true, true
        ));
        assert!(!should_run_macos_fallback_prompt_probe(
            false, false, false, true
        ));
        assert!(!should_run_macos_fallback_prompt_probe(
            false, false, true, false
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_monitor_snapshot_rearms_only_complete_unambiguous_no_prompt() {
        let mut snapshot = crate::monitor::MacosMonitorSnapshot {
            process_found: true,
            target_process_id: Some(42),
            target_window_title: Some("Sign in".to_string()),
            target_frontmost: Some(true),
            target_window_observed: true,
            selected_prompt_present: false,
            prompt_candidate_count: 0,
        };

        assert_eq!(
            super::macos_foreground_no_prompt_evidence_from_monitor_snapshot(&snapshot),
            Some(MacosForegroundNoPromptEvidence::new(42, "Sign in"))
        );

        snapshot.prompt_candidate_count = 2;
        assert_eq!(
            super::macos_foreground_no_prompt_evidence_from_monitor_snapshot(&snapshot),
            None
        );
    }

    #[test]
    fn macos_worker_reuses_monitor_snapshot_for_no_prompt_evidence() {
        let implementation = include_str!("mod.rs")
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .unwrap();

        assert_eq!(
            implementation
                .matches("monitor.check_status_with_snapshot()")
                .count(),
            1
        );
        assert!(
            implementation.contains("macos_foreground_no_prompt_evidence_from_monitor_snapshot")
        );
        assert!(!implementation.contains("complete_macos_foreground_no_prompt_evidence"));
        assert!(!implementation.contains("crate::macos_ax::inspect("));
    }

    #[test]
    fn pre_password_reports_are_deduplicated_and_rate_limited() {
        let mut persistence = PrePasswordReportPersistence::default();
        let now = Instant::now();
        let first_fields = [("prompt_context_source", "monitor".to_string())];
        let second_fields = [("prompt_context_source", "fallback".to_string())];

        persistence.begin_poll_tick();
        assert!(persistence.should_persist("first_reason", &first_fields, now));
        persistence.begin_poll_tick();
        assert!(!persistence.should_persist(
            "first_reason",
            &first_fields,
            now + PRE_PASSWORD_REPORT_PERSIST_INTERVAL - Duration::from_millis(1),
        ));
        persistence.begin_poll_tick();
        assert!(persistence.should_persist(
            "first_reason",
            &first_fields,
            now + PRE_PASSWORD_REPORT_PERSIST_INTERVAL,
        ));
        persistence.begin_poll_tick();
        assert!(persistence.should_persist(
            "second_reason",
            &second_fields,
            now + PRE_PASSWORD_REPORT_PERSIST_INTERVAL + Duration::from_millis(1),
        ));

        persistence.reset_observed_state();
        persistence.begin_poll_tick();
        assert!(persistence.should_persist(
            "second_reason",
            &second_fields,
            now + PRE_PASSWORD_REPORT_PERSIST_INTERVAL + Duration::from_millis(2),
        ));
    }

    #[test]
    fn alternating_skip_states_are_rate_limited_per_key_and_once_per_tick() {
        let mut persistence = PrePasswordReportPersistence::default();
        let now = Instant::now();
        let fields = [("prompt_context_source", "monitor".to_string())];

        persistence.begin_poll_tick();
        assert!(persistence.should_persist("reason_a", &fields, now));
        assert!(!persistence.should_persist(
            "prompt_detection_failed_first detail",
            &fields,
            now + Duration::from_millis(1),
        ));

        persistence.begin_poll_tick();
        assert!(!persistence.should_persist("reason_a", &fields, now + Duration::from_secs(1),));
        assert!(persistence.should_persist(
            "prompt_detection_failed_second detail",
            &fields,
            now + Duration::from_secs(1) + Duration::from_millis(1),
        ));

        persistence.begin_poll_tick();
        assert!(!persistence.should_persist("reason_a", &fields, now + Duration::from_secs(2),));
        assert!(!persistence.should_persist(
            "prompt_detection_failed_third detail",
            &fields,
            now + Duration::from_secs(2) + Duration::from_millis(1),
        ));
    }

    #[test]
    fn equivalent_account_miss_reasons_cannot_alternate_persisted_reports() {
        let mut persistence = PrePasswordReportPersistence::default();
        let now = Instant::now();
        let monitor_fields = [("prompt_context_source", "monitor".to_string())];
        let fallback_fields = [("prompt_context_source", "fallback".to_string())];

        persistence.begin_poll_tick();
        assert!(persistence.should_persist(
            "visible_prompt_email_matches_no_saved_password",
            &monitor_fields,
            now,
        ));
        assert!(!persistence.should_persist(
            "visible_prompt_email_matches_no_enabled_account",
            &fallback_fields,
            now + Duration::from_millis(1),
        ));

        persistence.begin_poll_tick();
        assert!(!persistence.should_persist(
            "visible_prompt_email_matches_no_saved_password",
            &monitor_fields,
            now + Duration::from_secs(1),
        ));
        assert!(!persistence.should_persist(
            "visible_prompt_email_matches_no_enabled_account",
            &fallback_fields,
            now + Duration::from_secs(1) + Duration::from_millis(1),
        ));

        persistence.begin_poll_tick();
        assert!(persistence.should_persist(
            "visible_prompt_email_matches_no_enabled_account",
            &fallback_fields,
            now + PRE_PASSWORD_REPORT_PERSIST_INTERVAL,
        ));
    }

    #[test]
    fn no_prompt_resets_only_when_the_tick_had_no_skip_state() {
        let mut persistence = PrePasswordReportPersistence::default();
        let now = Instant::now();
        let fields = [("prompt_context_source", "monitor".to_string())];

        persistence.begin_poll_tick();
        assert!(persistence.should_persist("missing_email", &fields, now));
        persistence.observe_no_prompt();
        persistence.begin_poll_tick();
        assert!(!persistence.should_persist(
            "missing_email",
            &fields,
            now + Duration::from_secs(1),
        ));

        persistence.begin_poll_tick();
        persistence.observe_no_prompt();
        persistence.begin_poll_tick();
        assert!(persistence.should_persist("missing_email", &fields, now + Duration::from_secs(2),));
    }

    #[test]
    fn explicit_no_prompt_status_makes_reappearing_failure_reportable() {
        let mut persistence = PrePasswordReportPersistence::default();
        let now = Instant::now();
        let fields = [("prompt_context_source", "monitor".to_string())];

        persistence.begin_poll_tick();
        assert!(persistence.should_persist("missing_email", &fields, now));

        persistence.begin_poll_tick();
        persistence.observe_monitor_status(true);

        persistence.begin_poll_tick();
        assert!(persistence.should_persist("missing_email", &fields, now + Duration::from_secs(2),));

        persistence.begin_poll_tick();
        persistence.observe_monitor_status(true);

        persistence.begin_poll_tick();
        assert!(persistence.should_persist("missing_email", &fields, now + Duration::from_secs(4),));

        persistence.begin_poll_tick();
        persistence.observe_monitor_status(false);
        persistence.begin_poll_tick();
        assert!(!persistence.should_persist(
            "missing_email",
            &fields,
            now + Duration::from_secs(5),
        ));
    }

    #[test]
    fn visible_prompt_email_matching_enabled_account_allows_password_load() {
        let account = account("account-1", "user@example.com", true);
        let accounts = [account];

        let decision = account_for_visible_prompt_email(&accounts, Some(" USER@example.com "));

        match decision {
            PromptAccountDecision::Allow(account) => assert_eq!(account.id, "account-1"),
            other => panic!("expected allowed account, got {other:?}"),
        }
    }

    #[test]
    fn visible_prompt_email_mismatch_is_not_allowed() {
        let account = account("account-1", "user@example.com", true);
        let accounts = [account];

        let decision = account_for_visible_prompt_email(&accounts, Some("other@example.com"));

        assert!(matches!(decision, PromptAccountDecision::NoEnabledMatch));
    }

    #[test]
    fn missing_visible_prompt_email_is_not_allowed() {
        let account = account("account-1", "user@example.com", true);

        assert!(matches!(
            account_for_visible_prompt_email(std::slice::from_ref(&account), None),
            PromptAccountDecision::MissingEmail
        ));
        assert!(matches!(
            account_for_visible_prompt_email(&[account], Some("   ")),
            PromptAccountDecision::MissingEmail
        ));
    }

    #[test]
    fn disabled_account_match_is_not_allowed() {
        let account = account("account-1", "user@example.com", false);
        let accounts = [account];

        let decision = account_for_visible_prompt_email(&accounts, Some("user@example.com"));

        assert!(matches!(decision, PromptAccountDecision::NoEnabledMatch));
    }

    #[test]
    fn passwordless_account_match_is_not_allowed() {
        let mut account = account("account-1", "user@example.com", true);
        account.has_saved_password = false;
        let accounts = [account];

        let decision = account_for_visible_prompt_email(&accounts, Some("user@example.com"));

        assert!(matches!(decision, PromptAccountDecision::NoEnabledMatch));
    }

    #[test]
    fn duplicate_enabled_account_matches_are_ambiguous_without_target_disambiguation() {
        for accounts in [
            vec![
                account("account-1", "user@example.com", true),
                account("account-2", " USER@example.com ", true),
            ],
            vec![
                account("account-1", "user@example.com", true),
                account("account-2", " USER@example.com ", true),
                account("account-3", "other@example.com", true),
            ],
            vec![
                account("account-1", "user@example.com", true),
                account("account-2", "user@example.com", true),
                account("account-3", "USER@example.com", true),
            ],
        ] {
            let decision = account_for_visible_prompt_email(&accounts, Some("user@example.com"));
            assert!(matches!(decision, PromptAccountDecision::Ambiguous));
        }
    }

    #[test]
    fn prompt_retry_suppression_is_account_wide_within_identity_and_remembers_a_b_a() {
        let now = std::time::Instant::now();
        let prompt_key = make_prompt_key("account-1", 42, "Sign in", "user@example.com");
        let mut attempts = HashMap::from([(prompt_key.clone(), now)]);

        assert!(prompt_retry_is_suppressed(&attempts, &prompt_key));
        assert!(prompt_retry_is_suppressed(
            &attempts,
            &make_prompt_key("account-1", 43, "Sign in", "user@example.com"),
        ));
        assert!(prompt_retry_is_suppressed(
            &attempts,
            &LoginPromptKey::new(
                " ACCOUNT-1 ".to_string(),
                999,
                999,
                " SIGN IN ".to_string(),
                " USER@EXAMPLE.COM ".to_string(),
                " WINDOW ".to_string(),
            ),
        ));
        assert!(!prompt_retry_is_suppressed(
            &attempts,
            &make_prompt_key("account-2", 43, "Sign in", "other@example.com"),
        ));
        let replacement_identity =
            make_prompt_key("account-1", 44, "Sign in", "replacement@example.com");
        assert!(!prompt_retry_is_suppressed(
            &attempts,
            &replacement_identity,
        ));
        assert_eq!(attempts.len(), 1);

        attempts.insert(replacement_identity.clone(), now);
        assert!(prompt_retry_is_suppressed(&attempts, &replacement_identity,));
        assert!(prompt_retry_is_suppressed(&attempts, &prompt_key));

        let context = verified_context("account-1", 42, "Sign in", "user@example.com", now);
        let verified_prompt_key = LoginPromptKey::from_verified_context(&context);
        attempts.insert(verified_prompt_key.clone(), now);

        assert!(prompt_retry_is_suppressed(&attempts, &verified_prompt_key));
    }

    #[test]
    fn macos_replacement_prompt_rearms_after_original_process_exit() {
        assert_eq!(MACOS_RETRY_REARM_PROCESS_EXIT_OBSERVATIONS, 2);
        let original_key = make_prompt_key("account-1", 42, "Sign in", "user@example.com");
        let replacement_key = make_prompt_key("account-1", 84, "Replacement", "user@example.com");
        let attempts = Arc::new(Mutex::new(HashMap::from([(
            original_key.clone(),
            Instant::now(),
        )])));
        let mut tracker = DefinitiveProcessExitTracker::default();

        tracker.begin_tick(&[42]);
        assert!(!tracker.observe(42, TrustedProcessPresence::Absent, &attempts));
        assert!(prompt_retry_is_suppressed(
            &attempts.lock().unwrap(),
            &replacement_key,
        ));

        // Merely observing the replacement prompt does not reset exit
        // evidence for the original process episode.
        assert!(prompt_retry_is_suppressed(
            &attempts.lock().unwrap(),
            &replacement_key,
        ));
        tracker.begin_tick(&[42]);
        assert!(tracker.observe(42, TrustedProcessPresence::Absent, &attempts));

        let attempts = attempts.lock().unwrap();
        assert!(!attempts.contains_key(&original_key));
        assert!(!prompt_retry_is_suppressed(&attempts, &replacement_key));
    }

    #[test]
    fn macos_indeterminate_process_presence_resets_exit_evidence() {
        let original_key = make_prompt_key("account-1", 42, "Sign in", "user@example.com");
        let attempts = Arc::new(Mutex::new(HashMap::from([(
            original_key.clone(),
            Instant::now(),
        )])));
        let mut tracker = DefinitiveProcessExitTracker::default();

        tracker.begin_tick(&[42]);
        assert!(!tracker.observe(42, TrustedProcessPresence::Absent, &attempts));
        tracker.begin_tick(&[42]);
        assert!(!tracker.observe(42, TrustedProcessPresence::Indeterminate, &attempts));
        tracker.begin_tick(&[42]);
        assert!(!tracker.observe(42, TrustedProcessPresence::Absent, &attempts));
        assert!(attempts.lock().unwrap().contains_key(&original_key));

        tracker.begin_tick(&[42]);
        assert!(tracker.observe(42, TrustedProcessPresence::Absent, &attempts));
        assert!(attempts.lock().unwrap().is_empty());
    }

    #[test]
    fn macos_exited_pid_release_preserves_live_same_identity_suppression() {
        let exited_key = make_prompt_key("account-1", 42, "Old", "user@example.com");
        let live_key = make_prompt_key("account-1", 84, "Current", "user@example.com");
        let attempts = Arc::new(Mutex::new(HashMap::from([
            (exited_key.clone(), Instant::now()),
            (live_key.clone(), Instant::now()),
        ])));
        let mut tracker = DefinitiveProcessExitTracker::default();

        tracker.begin_tick(&[42, 84]);
        assert!(!tracker.observe(42, TrustedProcessPresence::Absent, &attempts));
        assert!(!tracker.observe(84, TrustedProcessPresence::Present, &attempts));
        tracker.begin_tick(&[42, 84]);
        assert!(tracker.observe(42, TrustedProcessPresence::Absent, &attempts));
        assert!(!tracker.observe(84, TrustedProcessPresence::Present, &attempts));

        let attempts = attempts.lock().unwrap();
        assert!(!attempts.contains_key(&exited_key));
        assert!(attempts.contains_key(&live_key));
        assert!(prompt_retry_is_suppressed(&attempts, &live_key));
    }

    #[test]
    fn macos_same_pid_replacement_prompt_rearms_after_original_sheet_exit() {
        assert_eq!(MACOS_RETRY_REARM_SHEET_EXIT_OBSERVATIONS, 3);
        let original_key =
            make_sheet_prompt_key("account-1", 42, "Original resource", "user@example.com");
        let replacement_key =
            make_sheet_prompt_key("account-1", 42, "Other resource", "user@example.com");
        let attempts = Arc::new(Mutex::new(HashMap::from([(
            original_key.clone(),
            Instant::now(),
        )])));
        let original_episode = SuppressedSheetEpisode::from_prompt_key(&original_key).unwrap();
        let mut tracker = DefinitiveSheetExitTracker::default();

        for _ in 1..MACOS_RETRY_REARM_SHEET_EXIT_OBSERVATIONS {
            tracker.begin_tick(std::slice::from_ref(&original_episode));
            assert!(!tracker.observe(&original_episode, TrustedProcessPresence::Absent, &attempts,));
            // A prompt on another foreground parent in the same live PID must
            // not reset absence evidence for the original attached sheet.
            assert!(prompt_retry_is_suppressed(
                &attempts.lock().unwrap(),
                &replacement_key,
            ));
        }

        tracker.begin_tick(std::slice::from_ref(&original_episode));
        assert!(tracker.observe(&original_episode, TrustedProcessPresence::Absent, &attempts,));
        let attempts = attempts.lock().unwrap();
        assert!(!attempts.contains_key(&original_key));
        assert!(!prompt_retry_is_suppressed(&attempts, &replacement_key));
    }

    #[test]
    fn macos_visible_or_ambiguous_original_sheet_never_releases_suppression() {
        let original_key =
            make_sheet_prompt_key("account-1", 42, "Original resource", "user@example.com");
        let attempts = Arc::new(Mutex::new(HashMap::from([(
            original_key.clone(),
            Instant::now(),
        )])));
        let episode = SuppressedSheetEpisode::from_prompt_key(&original_key).unwrap();
        let mut tracker = DefinitiveSheetExitTracker::default();

        for presence in [
            TrustedProcessPresence::Absent,
            TrustedProcessPresence::Absent,
            TrustedProcessPresence::Present,
            TrustedProcessPresence::Absent,
            TrustedProcessPresence::Absent,
            TrustedProcessPresence::Indeterminate,
        ] {
            tracker.begin_tick(std::slice::from_ref(&episode));
            assert!(!tracker.observe(&episode, presence, &attempts));
        }

        assert!(attempts.lock().unwrap().contains_key(&original_key));
    }

    #[test]
    fn suppression_rearms_only_after_two_definitive_no_prompt_polls() {
        let key = make_prompt_key("account-1", 42, "Sign in", "user@example.com");
        let attempts = Arc::new(Mutex::new(HashMap::from([(key.clone(), Instant::now())])));
        let mut tracker = DefinitiveNoPromptTracker::default();

        assert!(!tracker.observe_definitive_no_prompt(&attempts));
        assert!(attempts.lock().unwrap().contains_key(&key));

        tracker.observe_indeterminate();
        assert!(!tracker.observe_definitive_no_prompt(&attempts));
        assert!(attempts.lock().unwrap().contains_key(&key));

        assert!(tracker.observe_definitive_no_prompt(&attempts));
        assert!(attempts.lock().unwrap().is_empty());
    }

    #[test]
    fn windows_closed_session_rearms_a_new_same_account_prompt_after_complete_no_prompt_polls() {
        let original_key = make_prompt_key("account-1", 42, "Sign in", "user@example.com");
        let next_connection_key = make_prompt_key("account-1", 84, "Sign in", "user@example.com");
        let attempts = Arc::new(Mutex::new(HashMap::from([(original_key, Instant::now())])));
        let mut tracker = DefinitiveNoPromptTracker::default();

        assert!(prompt_retry_is_suppressed(
            &attempts.lock().unwrap(),
            &next_connection_key
        ));
        assert!(!tracker.observe_definitive_no_prompt(&attempts));
        assert!(prompt_retry_is_suppressed(
            &attempts.lock().unwrap(),
            &next_connection_key
        ));
        assert!(tracker.observe_definitive_no_prompt(&attempts));
        assert!(!prompt_retry_is_suppressed(
            &attempts.lock().unwrap(),
            &next_connection_key
        ));
    }

    #[test]
    fn macos_no_prompt_evidence_requires_complete_foreground_snapshot() {
        let complete = MacosNoPromptSnapshot {
            process_found: true,
            target_process_id: Some(42),
            target_window_title: Some("Sign in"),
            target_frontmost: Some(true),
            target_window_observed: true,
            selected_prompt_present: false,
            prompt_candidate_count: 0,
        };

        assert_eq!(
            macos_foreground_no_prompt_evidence(complete),
            Some(MacosForegroundNoPromptEvidence::new(42, "Sign in"))
        );

        for incomplete in [
            MacosNoPromptSnapshot {
                process_found: false,
                ..complete
            },
            MacosNoPromptSnapshot {
                target_process_id: None,
                ..complete
            },
            MacosNoPromptSnapshot {
                target_process_id: Some(0),
                ..complete
            },
            MacosNoPromptSnapshot {
                target_window_title: None,
                ..complete
            },
            MacosNoPromptSnapshot {
                target_frontmost: None,
                ..complete
            },
            MacosNoPromptSnapshot {
                target_frontmost: Some(false),
                ..complete
            },
            MacosNoPromptSnapshot {
                target_window_observed: false,
                ..complete
            },
            MacosNoPromptSnapshot {
                selected_prompt_present: true,
                ..complete
            },
            MacosNoPromptSnapshot {
                prompt_candidate_count: 1,
                ..complete
            },
        ] {
            assert_eq!(macos_foreground_no_prompt_evidence(incomplete), None);
        }
    }

    #[test]
    fn macos_suppression_rearms_after_three_same_foreground_no_prompt_observations() {
        assert_eq!(MACOS_RETRY_REARM_NO_PROMPT_OBSERVATIONS, 3);
        let prompt_key = make_prompt_key("account-1", 42, "Sign in", "user@example.com");
        let same_identity_transient_window =
            make_prompt_key("account-1", 84, "Other", "user@example.com");
        let unrelated_key = make_prompt_key("account-2", 99, "Other", "other@example.com");
        let attempts = Arc::new(Mutex::new(HashMap::from([
            (prompt_key.clone(), Instant::now()),
            (same_identity_transient_window, Instant::now()),
            (unrelated_key.clone(), Instant::now()),
        ])));
        let evidence = MacosForegroundNoPromptEvidence::new(42, " SIGN IN ");
        let mut tracker = DefinitiveNoPromptTracker::default();

        assert!(!tracker.observe_macos_foreground_no_prompt(evidence.clone(), &attempts));
        assert!(!tracker.observe_macos_foreground_no_prompt(evidence.clone(), &attempts));
        assert!(prompt_retry_is_suppressed(
            &attempts.lock().unwrap(),
            &prompt_key
        ));

        assert!(tracker.observe_macos_foreground_no_prompt(evidence, &attempts));
        let attempts = attempts.lock().unwrap();
        assert!(!prompt_retry_is_suppressed(&attempts, &prompt_key));
        assert!(attempts.contains_key(&unrelated_key));
        assert_eq!(attempts.len(), 1);
    }

    #[test]
    fn macos_suppression_evidence_resets_on_indeterminate_prompt_or_window_change() {
        let prompt_key = make_prompt_key("account-1", 42, "Sign in", "user@example.com");
        let attempts = Arc::new(Mutex::new(HashMap::from([(
            prompt_key.clone(),
            Instant::now(),
        )])));
        let original_window = MacosForegroundNoPromptEvidence::new(42, "Sign in");
        let other_window = MacosForegroundNoPromptEvidence::new(42, "Devices");
        let mut tracker = DefinitiveNoPromptTracker::default();

        assert!(!tracker.observe_macos_foreground_no_prompt(original_window.clone(), &attempts));
        assert!(!tracker.observe_macos_foreground_no_prompt(original_window.clone(), &attempts));
        assert!(!tracker.observe_macos_foreground_no_prompt(other_window, &attempts));
        assert!(!tracker.observe_macos_foreground_no_prompt(original_window.clone(), &attempts));
        tracker.observe_indeterminate();
        assert!(!tracker.observe_macos_foreground_no_prompt(original_window.clone(), &attempts));
        tracker.observe_prompt();
        assert!(!tracker.observe_macos_foreground_no_prompt(original_window.clone(), &attempts));
        assert!(!tracker.observe_macos_foreground_no_prompt(original_window.clone(), &attempts));
        assert!(prompt_retry_is_suppressed(
            &attempts.lock().unwrap(),
            &prompt_key
        ));

        assert!(tracker.observe_macos_foreground_no_prompt(original_window, &attempts));
        assert!(attempts.lock().unwrap().is_empty());
    }

    #[test]
    fn macos_no_prompt_from_different_window_never_releases_reserved_identity() {
        let prompt_key = make_prompt_key("account-1", 42, "Sign in", "user@example.com");
        let attempts = Arc::new(Mutex::new(HashMap::from([(
            prompt_key.clone(),
            Instant::now(),
        )])));
        let other_window = MacosForegroundNoPromptEvidence::new(42, "Devices");
        let mut tracker = DefinitiveNoPromptTracker::default();

        for _ in 0..MACOS_RETRY_REARM_NO_PROMPT_OBSERVATIONS {
            tracker.observe_macos_foreground_no_prompt(other_window.clone(), &attempts);
        }

        assert!(prompt_retry_is_suppressed(
            &attempts.lock().unwrap(),
            &prompt_key
        ));
    }

    #[test]
    fn prompt_retry_suppression_reserves_before_attempt_start() {
        let prompt_key = make_prompt_key("account-1", 42, "Sign in", "user@example.com");
        let attempts = Arc::new(Mutex::new(HashMap::new()));
        let suppression = PromptRetrySuppression {
            recent_prompt_attempts: attempts.clone(),
            prompt_key: prompt_key.clone(),
        };

        assert!(reserve_prompt_retry_suppression(Some(&suppression)));
        assert!(attempts.lock().unwrap().contains_key(&prompt_key));
    }

    #[test]
    fn authenticated_success_releases_the_reserved_prompt_identity() {
        let prompt_key = make_prompt_key("account-1", 42, "Sign in", "user@example.com");
        let same_identity_other_window =
            make_prompt_key("account-1", 84, "Other desktop", "user@example.com");
        let unrelated_key = make_prompt_key("account-2", 43, "Sign in", "other@example.com");
        let attempts = Arc::new(Mutex::new(HashMap::from([
            (prompt_key.clone(), Instant::now()),
            (same_identity_other_window, Instant::now()),
            (unrelated_key.clone(), Instant::now()),
        ])));
        let suppression = PromptRetrySuppression {
            recent_prompt_attempts: attempts.clone(),
            prompt_key: prompt_key.clone(),
        };
        let report = debug_fill::FillAttemptReport {
            fields: vec![("post_check_state".to_string(), "authenticated".to_string())],
            success: true,
            failure_reason: None,
        };

        assert!(
            release_prompt_retry_suppression_after_authenticated_success(
                Some(&suppression),
                &report,
            )
        );
        let attempts = attempts.lock().unwrap();
        assert!(!prompt_retry_is_suppressed(&attempts, &prompt_key));
        assert!(attempts.contains_key(&unrelated_key));
        assert_eq!(attempts.len(), 1);
    }

    #[test]
    fn failed_or_unauthenticated_reports_retain_prompt_retry_suppression() {
        for report in [
            debug_fill::FillAttemptReport {
                fields: vec![("post_check_state".to_string(), "authenticated".to_string())],
                success: false,
                failure_reason: Some("submit_failed".to_string()),
            },
            debug_fill::FillAttemptReport {
                fields: vec![("post_check_state".to_string(), "still_prompt".to_string())],
                success: true,
                failure_reason: None,
            },
            debug_fill::FillAttemptReport {
                fields: vec![(
                    "post_check_state".to_string(),
                    "prompt_replaced".to_string(),
                )],
                success: false,
                failure_reason: Some("credential_prompt_replaced_after_submit".to_string()),
            },
        ] {
            let prompt_key = make_prompt_key("account-1", 42, "Sign in", "user@example.com");
            let attempts = Arc::new(Mutex::new(HashMap::from([(
                prompt_key.clone(),
                Instant::now(),
            )])));
            let suppression = PromptRetrySuppression {
                recent_prompt_attempts: attempts.clone(),
                prompt_key: prompt_key.clone(),
            };

            assert!(
                release_prompt_retry_suppression_after_authenticated_success(
                    Some(&suppression),
                    &report,
                )
            );
            assert!(prompt_retry_is_suppressed(
                &attempts.lock().unwrap(),
                &prompt_key,
            ));
        }
    }

    #[test]
    fn generation_change_rejects_in_flight_login_guard() {
        let generation = AtomicU64::new(7);

        assert!(ensure_generation_current(&generation, 7, "cancelled").is_ok());

        generation.fetch_add(1, Ordering::SeqCst);
        let error = ensure_generation_current(&generation, 7, "cancelled").unwrap_err();

        assert_eq!(error.to_string(), "cancelled");
    }

    #[test]
    fn post_pause_generation_is_never_an_unpaused_attempt_generation() {
        let generation = Arc::new(AtomicU64::new(7));
        let pause_latch = pause_latch_for_generation(&generation);

        assert_eq!(pause_latch.stable_unpaused_generation(), Some(7));
        // Reproduce the original interleaving deterministically: the worker
        // observed an unpaused latch, pause then published a new generation,
        // and the worker captured that post-pause value.
        assert!(!pause_latch.is_paused());
        pause_latch.pause();
        let post_pause_generation = generation.load(Ordering::SeqCst);
        assert!(ensure_generation_current(&generation, post_pause_generation, "cancelled").is_ok());

        assert_eq!(pause_latch.stable_unpaused_generation(), None);
        assert!(pause_latch
            .ensure_attempt_current(post_pause_generation, "cancelled")
            .is_err());
    }

    #[test]
    fn post_pause_generation_cannot_admit_or_reserve_a_prompt_attempt() {
        let generation = Arc::new(AtomicU64::new(11));
        let pause_latch = pause_latch_for_generation(&generation);
        pause_latch.pause();
        let post_pause_generation = generation.load(Ordering::SeqCst);
        let prompt_key = LoginPromptKey::new(
            "account-1".to_string(),
            42,
            0,
            "Sign in".to_string(),
            "user@example.com".to_string(),
            "sheet".to_string(),
        );
        let recent_prompt_attempts = Arc::new(Mutex::new(HashMap::new()));
        let (event_tx, _event_rx) = mpsc::channel(1);

        let started = super::spawn_current_prompt_attempt(super::CurrentPromptAttempt {
            trigger: super::FillTrigger::Automatic,
            settings: AppSettings::default(),
            accounts: Vec::new(),
            event_tx,
            automation_in_progress: Arc::new(AtomicBool::new(false)),
            pause_latch,
            expected_generation: post_pause_generation,
            prompt_context: None,
            prompt_retry_suppression: Some(PromptRetrySuppression {
                recent_prompt_attempts: recent_prompt_attempts.clone(),
                prompt_key,
            }),
            activity_tracker: WorkerActivityTracker::default(),
        });

        assert!(!started);
        assert!(recent_prompt_attempts.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn quiesce_command_withholds_ack_until_active_attempt_finishes() {
        let tracker = WorkerActivityTracker::default();
        let activity = tracker.begin_attempt().unwrap();
        let (acknowledgement, receiver) = std::sync::mpsc::channel();
        let (event_tx, _event_rx) = mpsc::channel::<WorkerEvent>(1);
        let generation = Arc::new(AtomicU64::new(1));
        let pause_latch = pause_latch_for_generation(&generation);
        let mut running = false;
        let mut settings = AppSettings::default();
        let mut accounts = Vec::new();

        handle_command(
            WorkerCommand::Quiesce {
                request_id: 41,
                acknowledgement,
            },
            &event_tx,
            &mut running,
            &mut settings,
            &mut accounts,
            &generation,
            &pause_latch,
            &tracker,
        )
        .await;

        assert!(matches!(
            receiver.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        assert!(tracker.begin_attempt().is_none());
        drop(activity);
        assert_eq!(
            receiver.recv().unwrap(),
            WorkerQuiescenceAck { request_id: 41 }
        );
    }

    #[test]
    fn quiescence_ack_waits_for_final_activity_guard() {
        let tracker = WorkerActivityTracker::default();
        let first = tracker.begin_attempt().unwrap();
        let second = tracker.begin_attempt().unwrap();
        let (acknowledgement, receiver) = std::sync::mpsc::channel();

        tracker.acknowledge_when_quiescent(73, acknowledgement);
        drop(first);
        assert!(matches!(
            receiver.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        drop(second);
        assert_eq!(
            receiver.recv().unwrap(),
            WorkerQuiescenceAck { request_id: 73 }
        );
    }

    #[test]
    fn immediate_quiescence_ack_closes_registration_gate() {
        let tracker = WorkerActivityTracker::default();
        let (acknowledgement, receiver) = std::sync::mpsc::channel();

        tracker.acknowledge_when_quiescent(91, acknowledgement);

        assert_eq!(
            receiver.recv().unwrap(),
            WorkerQuiescenceAck { request_id: 91 }
        );
        assert!(tracker.begin_attempt().is_none());
    }

    #[tokio::test]
    async fn only_fresh_pause_release_reopens_quiesced_registration_gate() {
        let tracker = WorkerActivityTracker::default();
        let (acknowledgement, receiver) = std::sync::mpsc::channel();
        tracker.acknowledge_when_quiescent(101, acknowledgement);
        assert_eq!(
            receiver.recv().unwrap(),
            WorkerQuiescenceAck { request_id: 101 }
        );
        assert!(tracker.begin_attempt().is_none());

        let (event_tx, _event_rx) = mpsc::channel::<WorkerEvent>(2);
        let generation = Arc::new(AtomicU64::new(5));
        let pause_latch = pause_latch_for_generation(&generation);
        let fresh_epoch = pause_latch.pause_with_epoch();
        let mut running = false;
        let mut settings = AppSettings::default();
        let mut accounts = Vec::new();
        handle_command(
            WorkerCommand::ApplyConfigAndReleasePause {
                settings: settings.clone(),
                accounts: accounts.clone(),
                refresh_passwords: false,
                start_monitor: false,
                pause_epoch: fresh_epoch,
            },
            &event_tx,
            &mut running,
            &mut settings,
            &mut accounts,
            &generation,
            &pause_latch,
            &tracker,
        )
        .await;
        drop(
            tracker
                .begin_attempt()
                .expect("fresh release must reopen gate"),
        );

        let (acknowledgement, receiver) = std::sync::mpsc::channel();
        tracker.acknowledge_when_quiescent(102, acknowledgement);
        assert_eq!(
            receiver.recv().unwrap(),
            WorkerQuiescenceAck { request_id: 102 }
        );
        let stale_epoch = pause_latch.pause_with_epoch();
        let newer_epoch = pause_latch.pause_with_epoch();
        assert!(newer_epoch > stale_epoch);
        handle_command(
            WorkerCommand::ApplyConfigAndReleasePause {
                settings: settings.clone(),
                accounts: accounts.clone(),
                refresh_passwords: false,
                start_monitor: true,
                pause_epoch: stale_epoch,
            },
            &event_tx,
            &mut running,
            &mut settings,
            &mut accounts,
            &generation,
            &pause_latch,
            &tracker,
        )
        .await;

        assert!(pause_latch.is_paused());
        assert!(tracker.begin_attempt().is_none());
        assert!(!running);
    }

    #[tokio::test]
    async fn apply_config_change_advances_generation_so_in_flight_attempts_cancel() {
        let (event_tx, mut event_rx) = mpsc::channel::<WorkerEvent>(1);
        let generation = std::sync::Arc::new(AtomicU64::new(3));
        let mut running = true;
        let mut settings = AppSettings::default();
        let mut accounts = vec![account("account-1", "user@example.com", true)];
        let expected_generation = generation.load(Ordering::SeqCst);
        let mut new_settings = settings.clone();
        new_settings.start_minimized = !settings.start_minimized;

        handle_command(
            WorkerCommand::ApplyConfig {
                settings: new_settings,
                accounts: accounts.clone(),
                refresh_passwords: false,
            },
            &event_tx,
            &mut running,
            &mut settings,
            &mut accounts,
            &generation,
            &pause_latch_for_generation(&generation),
            &WorkerActivityTracker::default(),
        )
        .await;

        assert!(event_rx.try_recv().is_err());
        assert!(ensure_generation_current(
            &generation,
            expected_generation,
            "Login attempt cancelled because accounts/settings changed",
        )
        .is_err());
    }

    #[tokio::test]
    async fn apply_config_refresh_advances_generation_for_password_only_change() {
        let (event_tx, mut event_rx) = mpsc::channel::<WorkerEvent>(1);
        let generation = std::sync::Arc::new(AtomicU64::new(11));
        let mut running = true;
        let mut settings = AppSettings::default();
        let mut accounts = vec![account("account-1", "user@example.com", true)];
        let expected_generation = generation.load(Ordering::SeqCst);

        handle_command(
            WorkerCommand::ApplyConfig {
                settings: settings.clone(),
                accounts: accounts.clone(),
                refresh_passwords: true,
            },
            &event_tx,
            &mut running,
            &mut settings,
            &mut accounts,
            &generation,
            &pause_latch_for_generation(&generation),
            &WorkerActivityTracker::default(),
        )
        .await;

        assert!(event_rx.try_recv().is_err());
        assert!(ensure_generation_current(
            &generation,
            expected_generation,
            "Login attempt cancelled because credentials changed",
        )
        .is_err());
    }

    #[tokio::test]
    async fn pause_latch_neutralizes_start_from_a_full_command_queue() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<WorkerCommand>(1);
        let (event_tx, mut event_rx) = mpsc::channel::<WorkerEvent>(2);
        let generation = Arc::new(AtomicU64::new(17));
        let pause_latch = pause_latch_for_generation(&generation);
        let mut running = false;
        let mut settings = AppSettings::default();
        let mut accounts = vec![account("account-1", "user@example.com", true)];

        cmd_tx.try_send(WorkerCommand::Start).unwrap();
        assert_eq!(cmd_tx.capacity(), 0);
        pause_latch.pause();

        assert!(
            wait_or_handle_command(
                Duration::from_secs(60),
                &mut cmd_rx,
                &event_tx,
                &mut running,
                &mut settings,
                &mut accounts,
                &generation,
                &pause_latch,
                &WorkerActivityTracker::default(),
            )
            .await
        );

        assert!(!running);
        assert_eq!(generation.load(Ordering::SeqCst), 17);
        assert!(event_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn pause_latch_forces_stale_running_worker_idle_without_stop_command() {
        let (event_tx, mut event_rx) = mpsc::channel::<WorkerEvent>(1);
        let generation = Arc::new(AtomicU64::new(23));
        let pause_latch = pause_latch_for_generation(&generation);
        let mut running = true;

        pause_latch.pause();
        if pause_latch.is_paused() {
            super::enforce_pause(&event_tx, &mut running, &generation).await;
        }

        assert!(!running);
        assert_eq!(generation.load(Ordering::SeqCst), 24);
        assert!(matches!(
            event_rx.try_recv(),
            Ok(WorkerEvent::StatusChanged(WorkerStatus::Idle))
        ));
    }

    #[tokio::test]
    async fn fresh_config_release_and_monitor_resume_are_one_atomic_command() {
        let (event_tx, mut event_rx) = mpsc::channel::<WorkerEvent>(1);
        let generation = Arc::new(AtomicU64::new(29));
        let pause_latch = pause_latch_for_generation(&generation);
        let pause_epoch = pause_latch.pause_with_epoch();
        let mut running = false;
        let mut settings = AppSettings::default();
        let mut accounts = Vec::new();
        let mut next_settings = settings.clone();
        next_settings.use_keyring = false;
        let next_accounts = vec![account("account-1", "user@example.com", true)];

        handle_command(
            WorkerCommand::ApplyConfigAndReleasePause {
                settings: next_settings.clone(),
                accounts: next_accounts.clone(),
                refresh_passwords: true,
                start_monitor: true,
                pause_epoch,
            },
            &event_tx,
            &mut running,
            &mut settings,
            &mut accounts,
            &generation,
            &pause_latch,
            &WorkerActivityTracker::default(),
        )
        .await;

        assert_eq!(settings, next_settings);
        assert_eq!(accounts, next_accounts);
        assert!(!pause_latch.is_paused());
        assert!(running);
        assert_eq!(generation.load(Ordering::SeqCst), 32);
        assert_eq!(pause_latch.stable_unpaused_generation(), Some(32));
        assert!(matches!(
            event_rx.try_recv(),
            Ok(WorkerEvent::StatusChanged(WorkerStatus::Running))
        ));
    }

    #[tokio::test]
    async fn fresh_config_release_with_stop_intent_forces_stale_running_worker_idle() {
        let (event_tx, mut event_rx) = mpsc::channel::<WorkerEvent>(1);
        let generation = Arc::new(AtomicU64::new(31));
        let pause_latch = pause_latch_for_generation(&generation);
        let pause_epoch = pause_latch.pause_with_epoch();
        let mut running = true;
        let mut settings = AppSettings::default();
        let mut accounts = Vec::new();

        handle_command(
            WorkerCommand::ApplyConfigAndReleasePause {
                settings: settings.clone(),
                accounts: accounts.clone(),
                refresh_passwords: false,
                start_monitor: false,
                pause_epoch,
            },
            &event_tx,
            &mut running,
            &mut settings,
            &mut accounts,
            &generation,
            &pause_latch,
            &WorkerActivityTracker::default(),
        )
        .await;

        assert!(!running);
        assert!(!pause_latch.is_paused());
        assert!(matches!(
            event_rx.try_recv(),
            Ok(WorkerEvent::StatusChanged(WorkerStatus::Idle))
        ));
    }

    #[tokio::test]
    async fn newer_pause_epoch_rejects_stale_config_release_and_start() {
        let (event_tx, mut event_rx) = mpsc::channel::<WorkerEvent>(1);
        let generation = Arc::new(AtomicU64::new(37));
        let pause_latch = pause_latch_for_generation(&generation);
        let stale_epoch = pause_latch.pause_with_epoch();
        let fresh_epoch = pause_latch.pause_with_epoch();
        assert!(fresh_epoch > stale_epoch);
        let mut running = false;
        let mut settings = AppSettings::default();
        let original_settings = settings.clone();
        let mut accounts = Vec::new();
        let mut stale_settings = settings.clone();
        stale_settings.use_keyring = false;

        handle_command(
            WorkerCommand::ApplyConfigAndReleasePause {
                settings: stale_settings,
                accounts: vec![account("account-1", "user@example.com", true)],
                refresh_passwords: true,
                start_monitor: true,
                pause_epoch: stale_epoch,
            },
            &event_tx,
            &mut running,
            &mut settings,
            &mut accounts,
            &generation,
            &pause_latch,
            &WorkerActivityTracker::default(),
        )
        .await;

        assert_eq!(settings, original_settings);
        assert!(accounts.is_empty());
        assert!(pause_latch.is_paused());
        assert!(!running);
        assert_eq!(generation.load(Ordering::SeqCst), 37);
        assert!(event_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn repeated_start_is_idempotent_and_preserves_recent_prompt_suppression() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<WorkerCommand>(1);
        let (event_tx, mut event_rx) = mpsc::channel::<WorkerEvent>(1);
        let generation = std::sync::Arc::new(AtomicU64::new(13));
        let prompt_key = make_prompt_key("account-1", 42, "Sign in", "user@example.com");
        let recent_prompt_attempts = Arc::new(Mutex::new(HashMap::from([(
            prompt_key.clone(),
            Instant::now(),
        )])));
        let mut running = true;
        let mut settings = AppSettings::default();
        let mut accounts = vec![account("account-1", "user@example.com", true)];

        cmd_tx.send(WorkerCommand::Start).await.unwrap();

        assert!(
            wait_or_handle_command(
                Duration::from_secs(60),
                &mut cmd_rx,
                &event_tx,
                &mut running,
                &mut settings,
                &mut accounts,
                &generation,
                &pause_latch_for_generation(&generation),
                &WorkerActivityTracker::default(),
            )
            .await
        );

        assert!(running);
        assert_eq!(generation.load(Ordering::SeqCst), 13);
        assert!(event_rx.try_recv().is_err());
        assert!(recent_prompt_attempts
            .lock()
            .unwrap()
            .contains_key(&prompt_key));
    }

    #[tokio::test]
    async fn wait_or_handle_command_handles_stop_without_rearming_suppression() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<WorkerCommand>(1);
        let (event_tx, mut event_rx) = mpsc::channel::<WorkerEvent>(1);
        let generation = std::sync::Arc::new(AtomicU64::new(5));
        let prompt_key = make_prompt_key("account-1", 42, "Sign in", "user@example.com");
        let recent_prompt_attempts = Arc::new(Mutex::new(HashMap::from([(
            prompt_key.clone(),
            Instant::now(),
        )])));
        let mut running = true;
        let mut settings = AppSettings::default();
        let mut accounts = vec![account("account-1", "user@example.com", true)];

        cmd_tx.send(WorkerCommand::Stop).await.unwrap();

        assert!(
            wait_or_handle_command(
                Duration::from_secs(60),
                &mut cmd_rx,
                &event_tx,
                &mut running,
                &mut settings,
                &mut accounts,
                &generation,
                &pause_latch_for_generation(&generation),
                &WorkerActivityTracker::default(),
            )
            .await
        );

        assert!(!running);
        assert_eq!(generation.load(Ordering::SeqCst), 6);
        assert!(recent_prompt_attempts
            .lock()
            .unwrap()
            .contains_key(&prompt_key));
        match event_rx.try_recv().unwrap() {
            WorkerEvent::StatusChanged(WorkerStatus::Idle) => {}
            other => panic!("expected idle status, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unscoped_password_refresh_invalidates_generation_but_preserves_suppression() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<WorkerCommand>(1);
        let (event_tx, mut event_rx) = mpsc::channel::<WorkerEvent>(1);
        let generation = std::sync::Arc::new(AtomicU64::new(9));
        let prompt_key = make_prompt_key("account-1", 42, "Sign in", "user@example.com");
        let recent_prompt_attempts = Arc::new(Mutex::new(HashMap::from([(
            prompt_key.clone(),
            Instant::now(),
        )])));
        let mut running = true;
        let mut settings = AppSettings::default();
        let mut accounts = vec![account("account-1", "user@example.com", true)];
        let next_settings = settings.clone();
        let next_accounts = accounts.clone();

        cmd_tx
            .send(WorkerCommand::ApplyConfig {
                settings: next_settings.clone(),
                accounts: next_accounts.clone(),
                refresh_passwords: true,
            })
            .await
            .unwrap();

        assert!(
            wait_or_handle_command(
                Duration::from_secs(60),
                &mut cmd_rx,
                &event_tx,
                &mut running,
                &mut settings,
                &mut accounts,
                &generation,
                &pause_latch_for_generation(&generation),
                &WorkerActivityTracker::default(),
            )
            .await
        );

        assert!(running);
        assert_eq!(settings, next_settings);
        assert_eq!(accounts, next_accounts);
        assert_eq!(generation.load(Ordering::SeqCst), 10);
        assert!(recent_prompt_attempts
            .lock()
            .unwrap()
            .contains_key(&prompt_key));
        assert!(event_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn unrelated_settings_change_preserves_prompt_suppression() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<WorkerCommand>(1);
        let (event_tx, mut event_rx) = mpsc::channel::<WorkerEvent>(1);
        let generation = std::sync::Arc::new(AtomicU64::new(21));
        let prompt_key = make_prompt_key("account-1", 42, "Sign in", "user@example.com");
        let recent_prompt_attempts = Arc::new(Mutex::new(HashMap::from([(
            prompt_key.clone(),
            Instant::now(),
        )])));
        let mut running = true;
        let mut settings = AppSettings::default();
        let mut accounts = vec![account("account-1", "user@example.com", true)];
        let mut next_settings = settings.clone();
        next_settings.start_minimized = !settings.start_minimized;

        cmd_tx
            .send(WorkerCommand::ApplyConfig {
                settings: next_settings.clone(),
                accounts: accounts.clone(),
                refresh_passwords: false,
            })
            .await
            .unwrap();

        assert!(
            wait_or_handle_command(
                Duration::from_secs(60),
                &mut cmd_rx,
                &event_tx,
                &mut running,
                &mut settings,
                &mut accounts,
                &generation,
                &pause_latch_for_generation(&generation),
                &WorkerActivityTracker::default(),
            )
            .await
        );

        assert_eq!(settings, next_settings);
        assert_eq!(generation.load(Ordering::SeqCst), 22);
        assert!(recent_prompt_attempts
            .lock()
            .unwrap()
            .contains_key(&prompt_key));
        assert!(event_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn account_identity_change_rearms_new_identity_without_forgetting_old_identity() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<WorkerCommand>(1);
        let (event_tx, mut event_rx) = mpsc::channel::<WorkerEvent>(1);
        let generation = std::sync::Arc::new(AtomicU64::new(31));
        let unchanged_key = make_prompt_key("account-1", 42, "Sign in", "one@example.com");
        let changed_key = make_prompt_key("account-2", 43, "Sign in", "two@example.com");
        let recent_prompt_attempts = Arc::new(Mutex::new(HashMap::from([
            (unchanged_key.clone(), Instant::now()),
            (changed_key.clone(), Instant::now()),
        ])));
        let mut running = true;
        let mut settings = AppSettings::default();
        let mut accounts = vec![
            account("account-1", "one@example.com", true),
            account("account-2", "two@example.com", true),
        ];
        let next_accounts = vec![
            account("account-1", "one@example.com", true),
            account("account-2", "replacement@example.com", true),
        ];

        cmd_tx
            .send(WorkerCommand::ApplyConfig {
                settings: settings.clone(),
                accounts: next_accounts.clone(),
                refresh_passwords: true,
            })
            .await
            .unwrap();

        assert!(
            wait_or_handle_command(
                Duration::from_secs(60),
                &mut cmd_rx,
                &event_tx,
                &mut running,
                &mut settings,
                &mut accounts,
                &generation,
                &pause_latch_for_generation(&generation),
                &WorkerActivityTracker::default(),
            )
            .await
        );

        assert_eq!(accounts, next_accounts);
        assert_eq!(generation.load(Ordering::SeqCst), 32);
        let replacement_key =
            make_prompt_key("account-2", 44, "Sign in", "replacement@example.com");
        let mut attempts = recent_prompt_attempts.lock().unwrap();
        assert!(attempts.contains_key(&unchanged_key));
        assert!(attempts.contains_key(&changed_key));
        assert!(!prompt_retry_is_suppressed(&attempts, &replacement_key));

        attempts.insert(replacement_key.clone(), Instant::now());
        assert!(prompt_retry_is_suppressed(&attempts, &replacement_key));
        assert!(prompt_retry_is_suppressed(&attempts, &changed_key));
        assert!(event_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn batched_account_a_b_a_changes_preserve_original_suppression() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<WorkerCommand>(2);
        let (event_tx, mut event_rx) = mpsc::channel::<WorkerEvent>(1);
        let generation = std::sync::Arc::new(AtomicU64::new(41));
        let original_key = make_prompt_key("account-1", 42, "Sign in", "a@example.com");
        let recent_prompt_attempts = Arc::new(Mutex::new(HashMap::from([(
            original_key.clone(),
            Instant::now(),
        )])));
        let mut running = true;
        let mut settings = AppSettings::default();
        let original_accounts = vec![account("account-1", "a@example.com", true)];
        let replacement_accounts = vec![account("account-1", "b@example.com", true)];
        let mut accounts = original_accounts.clone();

        cmd_tx
            .send(WorkerCommand::ApplyConfig {
                settings: settings.clone(),
                accounts: replacement_accounts,
                refresh_passwords: true,
            })
            .await
            .unwrap();
        cmd_tx
            .send(WorkerCommand::ApplyConfig {
                settings: settings.clone(),
                accounts: original_accounts.clone(),
                refresh_passwords: true,
            })
            .await
            .unwrap();

        assert!(
            wait_or_handle_command(
                Duration::from_secs(60),
                &mut cmd_rx,
                &event_tx,
                &mut running,
                &mut settings,
                &mut accounts,
                &generation,
                &pause_latch_for_generation(&generation),
                &WorkerActivityTracker::default(),
            )
            .await
        );

        assert_eq!(accounts, original_accounts);
        assert_eq!(generation.load(Ordering::SeqCst), 43);
        let attempts = recent_prompt_attempts.lock().unwrap();
        assert!(attempts.contains_key(&original_key));
        assert!(prompt_retry_is_suppressed(&attempts, &original_key));
        assert!(event_rx.try_recv().is_err());
    }

    #[test]
    fn exact_pause_release_advances_generation_once_and_rejects_duplicates() {
        let generation = Arc::new(AtomicU64::new(101));
        let pause_latch = pause_latch_for_generation(&generation);
        let pause_epoch = pause_latch.pause_with_epoch();

        assert!(pause_latch.owns_pause(pause_epoch));
        assert_eq!(generation.load(Ordering::SeqCst), 101);
        assert!(pause_latch.resume_if_epoch(pause_epoch));
        assert!(!pause_latch.is_paused());
        assert_eq!(generation.load(Ordering::SeqCst), 102);
        assert!(!pause_latch.resume_if_epoch(pause_epoch));
        assert_eq!(generation.load(Ordering::SeqCst), 102);
    }

    #[test]
    fn newer_pause_cannot_be_opened_by_a_stale_release() {
        let generation = Arc::new(AtomicU64::new(211));
        let pause_latch = pause_latch_for_generation(&generation);
        let stale_epoch = pause_latch.pause_with_epoch();
        let fresh_epoch = pause_latch.pause_with_epoch();

        assert!(!pause_latch.owns_pause(stale_epoch));
        assert!(pause_latch.owns_pause(fresh_epoch));
        assert!(!pause_latch.resume_if_epoch(stale_epoch));
        assert!(pause_latch.owns_pause(fresh_epoch));
        assert_eq!(generation.load(Ordering::SeqCst), 211);
        assert!(pause_latch.resume_if_epoch(fresh_epoch));
        assert_eq!(generation.load(Ordering::SeqCst), 212);
    }

    #[test]
    fn exhausted_pause_epoch_is_terminal_fail_closed_without_aba_wrap() {
        let generation = Arc::new(AtomicU64::new(307));
        let pause_latch = pause_latch_for_generation(&generation);
        let terminal_epoch = u64::MAX >> 1;
        pause_latch
            .pause_state
            .store((terminal_epoch - 1) << 1, Ordering::SeqCst);

        assert_eq!(pause_latch.pause_with_epoch(), terminal_epoch);
        assert!(pause_latch.owns_pause(terminal_epoch));
        assert!(!pause_latch.resume_if_epoch(terminal_epoch));
        assert!(pause_latch.is_paused());
        assert_eq!(generation.load(Ordering::SeqCst), 307);
        assert_eq!(pause_latch.pause_with_epoch(), terminal_epoch);
        assert!(pause_latch.owns_pause(terminal_epoch));
    }

    fn account(id: &str, username: &str, enabled: bool) -> Account {
        Account {
            id: id.to_string(),
            username: username.to_string(),
            has_saved_password: true,
            enabled,
        }
    }

    fn make_prompt_key(
        account_id: &str,
        process_id: i32,
        window_title: &str,
        prompt_email: &str,
    ) -> LoginPromptKey {
        LoginPromptKey::new(
            account_id.to_string(),
            process_id,
            process_id as isize,
            window_title.to_string(),
            prompt_email.to_string(),
            "window".to_string(),
        )
    }

    fn make_sheet_prompt_key(
        account_id: &str,
        process_id: i32,
        window_title: &str,
        prompt_email: &str,
    ) -> LoginPromptKey {
        LoginPromptKey::new(
            account_id.to_string(),
            process_id,
            process_id as isize,
            window_title.to_string(),
            prompt_email.to_string(),
            "sheet".to_string(),
        )
    }

    fn verified_context(
        account_id: &str,
        process_id: i32,
        window_title: &str,
        prompt_email: &str,
        detected_at: std::time::Instant,
    ) -> debug_fill::VerifiedPromptContext {
        debug_fill::VerifiedPromptContext {
            account_id: account_id.to_string(),
            process_id,
            #[cfg(target_os = "windows")]
            window_handle: process_id as isize,
            window_title: window_title.to_string(),
            prompt_email: prompt_email.to_string(),
            prompt_origin: "window".to_string(),
            detected_at,
            #[cfg(target_os = "windows")]
            monitor_check_ms: 0,
        }
    }
}
