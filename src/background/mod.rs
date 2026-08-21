use crate::config::Config;
use crate::debug_fill::{self, FillAttemptReport, FillMethod};
use crate::models::{Account, AppSettings, LogEntry, LogLevel, WorkerStatus};
use crate::monitor::{AppMonitor, MonitorStatus};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::sleep;
use tracing::{debug, info, trace, warn};

#[derive(Debug, Clone)]
pub(crate) enum WorkerCommand {
    Start,
    Stop,
    ApplyConfig {
        settings: AppSettings,
        accounts: Vec<Account>,
        refresh_passwords: bool,
    },
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
}

const IDLE_SLEEP: Duration = Duration::from_millis(500);
const AUTOMATION_SLEEP: Duration = Duration::from_millis(250);
const PROMPT_STATUS_POLL_INTERVAL: Duration = Duration::from_secs(1);
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const MACOS_FALLBACK_PROMPT_PROBE_INTERVAL: Duration = Duration::from_secs(1);
const CONNECTED_POLL_BACKOFF_MAX: Duration = Duration::from_secs(5);
const UNKNOWN_POLL_BACKOFF_MAX: Duration = Duration::from_secs(3);
const PRE_PASSWORD_REPORT_PERSIST_INTERVAL: Duration = Duration::from_secs(5 * 60);

struct FlagGuard {
    flag: Arc<AtomicBool>,
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
    generation: Arc<AtomicU64>,
    expected_generation: u64,
    prompt_context: Option<debug_fill::VerifiedPromptContext>,
    prompt_retry_suppression: Option<PromptRetrySuppression>,
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
fn prompt_account_decision_allows_macos_probe(decision: &PromptAccountDecision<'_>) -> bool {
    matches!(
        decision,
        PromptAccountDecision::MissingEmail
            | PromptAccountDecision::NoEnabledMatch
            | PromptAccountDecision::Ambiguous
    )
}

fn clear_recent_prompt_attempts(
    recent_prompt_attempts: &Arc<Mutex<HashMap<LoginPromptKey, Instant>>>,
) {
    if let Ok(mut prompts) = recent_prompt_attempts.lock() {
        prompts.clear();
    }
}

#[derive(Debug, Default)]
struct DefinitiveNoPromptTracker {
    consecutive_polls: u8,
}

impl DefinitiveNoPromptTracker {
    fn observe_prompt(&mut self) {
        self.consecutive_polls = 0;
    }

    fn observe_indeterminate(&mut self) {
        self.consecutive_polls = 0;
    }

    fn observe_definitive_no_prompt(
        &mut self,
        recent_prompt_attempts: &Arc<Mutex<HashMap<LoginPromptKey, Instant>>>,
    ) -> bool {
        self.consecutive_polls = self.consecutive_polls.saturating_add(1);
        if self.consecutive_polls < 2 {
            return false;
        }
        clear_recent_prompt_attempts(recent_prompt_attempts);
        self.consecutive_polls = 0;
        true
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

    fn observe_monitor_status(&mut self, status: &MonitorStatus, connected_is_definitive: bool) {
        if matches!(status, MonitorStatus::ProcessNotFound)
            || (connected_is_definitive && matches!(status, MonitorStatus::Connected))
        {
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

async fn handle_command(
    cmd: WorkerCommand,
    event_tx: &Sender<WorkerEvent>,
    running: &mut bool,
    settings: &mut AppSettings,
    accounts: &mut Vec<Account>,
    generation: &Arc<AtomicU64>,
) {
    match cmd {
        WorkerCommand::Start => {
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
        WorkerCommand::ApplyConfig {
            settings: next_settings,
            accounts: next_accounts,
            refresh_passwords,
        } => {
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
    }
}

async fn drain_commands(
    cmd_rx: &mut Receiver<WorkerCommand>,
    event_tx: &Sender<WorkerEvent>,
    running: &mut bool,
    settings: &mut AppSettings,
    accounts: &mut Vec<Account>,
    generation: &Arc<AtomicU64>,
) {
    while let Ok(cmd) = cmd_rx.try_recv() {
        handle_command(cmd, event_tx, running, settings, accounts, generation).await;
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
) -> bool {
    tokio::select! {
        _ = sleep(duration) => true,
        maybe_cmd = cmd_rx.recv() => {
            let Some(cmd) = maybe_cmd else {
                return false;
            };
            handle_command(cmd, event_tx, running, settings, accounts, generation).await;
            drain_commands(
                cmd_rx,
                event_tx,
                running,
                settings,
                accounts,
                generation,
            )
            .await;
            true
        }
    }
}

fn spawn_current_prompt_attempt(job: CurrentPromptAttempt) -> bool {
    let Some(automation_guard) = FlagGuard::acquire(&job.automation_in_progress) else {
        debug!("Fill current prompt skipped; UI automation is busy");
        let _ = job.event_tx.try_send(log_event(
            LogLevel::Warn,
            format!("{} skipped: UI automation is busy", job.trigger.label()),
        ));
        return false;
    };

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
        let CurrentPromptAttempt {
            trigger,
            settings,
            accounts,
            event_tx,
            generation,
            expected_generation,
            prompt_context,
            prompt_retry_suppression: _,
            ..
        } = job;
        let _automation_guard = automation_guard;
        let guard_generation = generation.clone();
        let report = debug_fill::fill_current_prompt_once_guarded_with_context(
            &settings,
            &accounts,
            FillMethod::Keyboard,
            prompt_context,
            || {
                ensure_generation_current(
                    &guard_generation,
                    expected_generation,
                    "accounts/settings changed",
                )
            },
        );
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
    });
    true
}

pub(crate) fn spawn(
    mut cmd_rx: Receiver<WorkerCommand>,
    event_tx: Sender<WorkerEvent>,
    initial_settings: AppSettings,
    initial_accounts: Vec<Account>,
    invalidator: WorkerInvalidator,
) {
    tokio::spawn(async move {
        let mut settings = initial_settings;
        let mut accounts = initial_accounts;
        let mut running = false;
        let recent_prompt_attempts =
            Arc::new(Mutex::new(HashMap::<LoginPromptKey, Instant>::new()));
        let automation_in_progress = Arc::new(AtomicBool::new(false));
        let generation = invalidator.generation;
        #[cfg(target_os = "macos")]
        let mut last_macos_prompt_probe: Option<Instant> = None;
        let mut poll_cadence = PollCadence::default();
        let mut no_prompt_tracker = DefinitiveNoPromptTracker::default();
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
            )
            .await;

            if !running {
                no_prompt_tracker.consecutive_polls = 0;
                pre_password_report_persistence.reset_observed_state();
                if !wait_or_handle_command(
                    IDLE_SLEEP,
                    &mut cmd_rx,
                    &event_tx,
                    &mut running,
                    &mut settings,
                    &mut accounts,
                    &generation,
                )
                .await
                {
                    break;
                }
                continue;
            }

            let current_generation = generation.load(Ordering::SeqCst);
            if current_generation != pre_password_generation {
                no_prompt_tracker.consecutive_polls = 0;
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
                )
                .await
                {
                    break;
                }
                continue;
            }

            let monitor = AppMonitor::new(runtime_config(&settings));
            let tick_start = Instant::now();
            #[cfg(target_os = "windows")]
            let status_check_start = Instant::now();
            let status = monitor.check_status();
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
            let mut status_allows_macos_probe = !matches!(status, MonitorStatus::ProcessNotFound);
            #[cfg(target_os = "macos")]
            let mut force_macos_prompt_probe = false;
            #[cfg(target_os = "macos")]
            let mut prompt_attempt_started = false;
            pre_password_report_persistence.begin_poll_tick();
            pre_password_report_persistence
                .observe_monitor_status(&status, cfg!(not(target_os = "macos")));
            let mut definitive_no_prompt_this_tick = false;
            let mut prompt_observed_this_tick = false;

            match status {
                MonitorStatus::Connected => {
                    definitive_no_prompt_this_tick = true;
                }
                MonitorStatus::Unknown => {
                    // Distinguish an indeterminate UIA failure from a
                    // successful no-prompt inspection. A single successful
                    // inspection is still insufficient to re-arm automation.
                    #[cfg(target_os = "windows")]
                    if crate::windows_ui::inspect(crate::config::TARGET_APP_NAME)
                        .is_ok_and(|inspection| inspection.prompt.is_none())
                    {
                        definitive_no_prompt_this_tick = true;
                    }
                }
                MonitorStatus::ProcessNotFound => {
                    definitive_no_prompt_this_tick = true;
                }
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
                    #[cfg(target_os = "macos")]
                    if prompt_account_decision_allows_macos_probe(&account_decision) {
                        status_allows_macos_probe = true;
                        force_macos_prompt_probe = true;
                    }

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
                                    generation: generation.clone(),
                                    expected_generation: current_generation,
                                    prompt_context: Some(prompt_context),
                                    prompt_retry_suppression: Some(PromptRetrySuppression {
                                        recent_prompt_attempts: recent_prompt_attempts.clone(),
                                        prompt_key,
                                    }),
                                });
                                if started {
                                    #[cfg(target_os = "macos")]
                                    {
                                        prompt_attempt_started = true;
                                        last_macos_prompt_probe = Some(Instant::now());
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
                if !prompt_attempt_started
                    && status_allows_macos_probe
                    && (prompt_probe_due || force_macos_prompt_probe)
                {
                    let now = Instant::now();
                    last_macos_prompt_probe = Some(now);
                    let detect_generation = generation.clone();
                    match debug_fill::detect_current_prompt_context(&accounts, || {
                        ensure_generation_current(
                            &detect_generation,
                            current_generation,
                            "accounts/settings changed",
                        )
                    }) {
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
                                    generation: generation.clone(),
                                    expected_generation: current_generation,
                                    prompt_context: Some(prompt_context),
                                    prompt_retry_suppression: Some(PromptRetrySuppression {
                                        recent_prompt_attempts: recent_prompt_attempts.clone(),
                                        prompt_key,
                                    }),
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
                            if !prompt_observed_this_tick {
                                definitive_no_prompt_this_tick = true;
                            }
                            pre_password_report_persistence.observe_no_prompt();
                            trace!("macOS fallback preflight found no credential prompt");
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
        prompt_account_decision_allows_macos_probe, prompt_retry_is_suppressed,
        reserve_prompt_retry_suppression, wait_or_handle_command, DefinitiveNoPromptTracker,
        LoginPromptKey, MonitorStatus, PollCadence, PrePasswordReportPersistence,
        PromptAccountDecision, PromptRetrySuppression, WorkerCommand, WorkerEvent,
        MACOS_FALLBACK_PROMPT_PROBE_INTERVAL, PRE_PASSWORD_REPORT_PERSIST_INTERVAL,
        PROMPT_STATUS_POLL_INTERVAL,
    };
    use crate::debug_fill;
    use crate::models::{Account, AppSettings, WorkerStatus};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    use tokio::sync::mpsc;

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
    fn macos_probe_fallback_rechecks_monitor_account_eligibility_misses() {
        let account = account("account-1", "user@example.com", true);

        assert!(!prompt_account_decision_allows_macos_probe(
            &PromptAccountDecision::Allow(&account)
        ));
        assert!(prompt_account_decision_allows_macos_probe(
            &PromptAccountDecision::MissingEmail
        ));
        assert!(prompt_account_decision_allows_macos_probe(
            &PromptAccountDecision::NoEnabledMatch
        ));
        assert!(prompt_account_decision_allows_macos_probe(
            &PromptAccountDecision::Ambiguous
        ));
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
        persistence.observe_monitor_status(&MonitorStatus::ProcessNotFound, false);

        persistence.begin_poll_tick();
        assert!(persistence.should_persist("missing_email", &fields, now + Duration::from_secs(2),));

        persistence.begin_poll_tick();
        persistence.observe_monitor_status(&MonitorStatus::Connected, true);

        persistence.begin_poll_tick();
        assert!(persistence.should_persist("missing_email", &fields, now + Duration::from_secs(4),));

        persistence.begin_poll_tick();
        persistence.observe_monitor_status(&MonitorStatus::Connected, false);
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
    fn generation_change_rejects_in_flight_login_guard() {
        let generation = AtomicU64::new(7);

        assert!(ensure_generation_current(&generation, 7, "cancelled").is_ok());

        generation.fetch_add(1, Ordering::SeqCst);
        let error = ensure_generation_current(&generation, 7, "cancelled").unwrap_err();

        assert_eq!(error.to_string(), "cancelled");
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
