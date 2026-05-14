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
const MAX_RECENT_PROMPT_ATTEMPTS: usize = 32;
const PROMPT_ATTEMPT_RETENTION: Duration = Duration::from_secs(3);

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
    window_title: String,
    prompt_email: String,
    prompt_origin: String,
}

impl LoginPromptKey {
    fn new(
        account_id: String,
        process_id: i32,
        window_title: String,
        prompt_email: String,
        prompt_origin: String,
    ) -> Self {
        Self {
            account_id,
            process_id,
            window_title,
            prompt_email,
            prompt_origin,
        }
    }

    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    fn from_verified_context(context: &debug_fill::VerifiedPromptContext) -> Self {
        Self::new(
            context.account_id.clone(),
            context.process_id,
            context.window_title.clone(),
            context.prompt_email.clone(),
            context.prompt_origin.clone(),
        )
    }
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
    recent_prompt_attempts: &mut HashMap<LoginPromptKey, Instant>,
    prompt_key: &LoginPromptKey,
    now: Instant,
    cooldown: Duration,
) -> bool {
    prune_recent_prompt_attempts(recent_prompt_attempts, now, cooldown);
    recent_prompt_attempts
        .get(prompt_key)
        .is_some_and(|attempted_at| now.duration_since(*attempted_at) < cooldown)
}

fn prune_recent_prompt_attempts(
    recent_prompt_attempts: &mut HashMap<LoginPromptKey, Instant>,
    now: Instant,
    retention: Duration,
) {
    recent_prompt_attempts.retain(|_, attempted_at| now.duration_since(*attempted_at) < retention);

    while recent_prompt_attempts.len() > MAX_RECENT_PROMPT_ATTEMPTS {
        let Some(oldest_key) = recent_prompt_attempts
            .iter()
            .min_by_key(|(_, attempted_at)| **attempted_at)
            .map(|(key, _)| key.clone())
        else {
            break;
        };
        recent_prompt_attempts.remove(&oldest_key);
    }
}

#[cfg_attr(not(test), allow(dead_code))]
fn fill_attempt_should_suppress_same_prompt_retry(report: &FillAttemptReport) -> bool {
    report.success
        || report_bool_field(report, "password_loaded")
        || report_bool_field(report, "fill_attempted")
        || report_bool_field(report, "submit_attempted")
}

#[cfg_attr(not(test), allow(dead_code))]
fn report_bool_field(report: &FillAttemptReport, field: &str) -> bool {
    report.field(field) == Some("true")
}

fn record_prompt_retry_suppression(
    suppression: Option<PromptRetrySuppression>,
    report: &FillAttemptReport,
) {
    if !fill_attempt_should_suppress_same_prompt_retry(report) {
        return;
    }
    let Some(suppression) = suppression else {
        return;
    };
    let now = Instant::now();
    if let Ok(mut prompts) = suppression.recent_prompt_attempts.lock() {
        prompts.insert(suppression.prompt_key, now);
        prune_recent_prompt_attempts(&mut prompts, now, PROMPT_ATTEMPT_RETENTION);
    };
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

fn emit_pre_password_skip_report(
    event_tx: &Sender<WorkerEvent>,
    reason: impl Into<String>,
    fields: &[(&'static str, String)],
) {
    let report = debug_fill::pre_password_skip_report(reason, fields);
    if let Err(e) = debug_fill::write_last_fill_attempt_report(&report) {
        warn!("Could not persist pre-password skip report: {e}");
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
) -> bool {
    match cmd {
        WorkerCommand::Start => {
            if *running {
                return false;
            }
            *running = true;
            generation.fetch_add(1, Ordering::SeqCst);
            let _ = event_tx
                .send(WorkerEvent::StatusChanged(WorkerStatus::Running))
                .await;
            info!("Background worker started");
            false
        }
        WorkerCommand::Stop => {
            if !*running {
                return false;
            }
            *running = false;
            generation.fetch_add(1, Ordering::SeqCst);
            let _ = event_tx
                .send(WorkerEvent::StatusChanged(WorkerStatus::Idle))
                .await;
            info!("Background worker stopped");
            true
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
                true
            } else {
                false
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
    recent_prompt_attempts: &Arc<Mutex<HashMap<LoginPromptKey, Instant>>>,
) {
    let mut should_clear_recent_prompts = false;
    while let Ok(cmd) = cmd_rx.try_recv() {
        should_clear_recent_prompts |=
            handle_command(cmd, event_tx, running, settings, accounts, generation).await;
    }
    if should_clear_recent_prompts {
        clear_recent_prompt_attempts(recent_prompt_attempts);
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
    recent_prompt_attempts: &Arc<Mutex<HashMap<LoginPromptKey, Instant>>>,
) -> bool {
    tokio::select! {
        _ = sleep(duration) => true,
        maybe_cmd = cmd_rx.recv() => {
            let Some(cmd) = maybe_cmd else {
                return false;
            };
            let should_clear_recent_prompts =
                handle_command(cmd, event_tx, running, settings, accounts, generation).await;
            if should_clear_recent_prompts {
                clear_recent_prompt_attempts(recent_prompt_attempts);
            }
            drain_commands(
                cmd_rx,
                event_tx,
                running,
                settings,
                accounts,
                generation,
                recent_prompt_attempts,
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

    std::thread::spawn(move || {
        let CurrentPromptAttempt {
            trigger,
            settings,
            accounts,
            event_tx,
            generation,
            expected_generation,
            prompt_context,
            prompt_retry_suppression,
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
        record_prompt_retry_suppression(prompt_retry_suppression, &report);
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

        loop {
            drain_commands(
                &mut cmd_rx,
                &event_tx,
                &mut running,
                &mut settings,
                &mut accounts,
                &generation,
                &recent_prompt_attempts,
            )
            .await;

            if !running {
                if !wait_or_handle_command(
                    IDLE_SLEEP,
                    &mut cmd_rx,
                    &event_tx,
                    &mut running,
                    &mut settings,
                    &mut accounts,
                    &generation,
                    &recent_prompt_attempts,
                )
                .await
                {
                    break;
                }
                continue;
            }

            let current_generation = generation.load(Ordering::SeqCst);

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
                    &recent_prompt_attempts,
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
                if !wait_or_handle_command(
                    fixed_poll_interval(),
                    &mut cmd_rx,
                    &event_tx,
                    &mut running,
                    &mut settings,
                    &mut accounts,
                    &generation,
                    &recent_prompt_attempts,
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

            match status {
                MonitorStatus::Connected => {
                    if let Ok(mut prompts) = recent_prompt_attempts.lock() {
                        prompts.clear();
                    }
                }
                MonitorStatus::Unknown => {}
                MonitorStatus::ProcessNotFound => {
                    if let Ok(mut prompts) = recent_prompt_attempts.lock() {
                        prompts.clear();
                    }
                }
                MonitorStatus::LoginWindowDetected {
                    process_id,
                    window_title,
                    prompt_email,
                    prompt_origin,
                } => {
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
                                window_title.clone(),
                                prompt_email.clone(),
                                prompt_origin.clone(),
                            );
                            let now = Instant::now();
                            let suppressed = recent_prompt_attempts
                                .lock()
                                .map(|mut prompts| {
                                    prompt_retry_is_suppressed(
                                        &mut prompts,
                                        &prompt_key,
                                        now,
                                        PROMPT_ATTEMPT_RETENTION,
                                    )
                                })
                                .unwrap_or(false);
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
                                    "prompt_retry_suppressed",
                                    &fields,
                                );
                            } else {
                                let prompt_context = debug_fill::VerifiedPromptContext {
                                    account_id: account.id.clone(),
                                    process_id,
                                    window_title: window_title.clone(),
                                    prompt_email,
                                    prompt_origin,
                                    detected_at: Instant::now(),
                                    #[cfg(target_os = "windows")]
                                    monitor_check_ms,
                                };
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
                            let prompt_key = LoginPromptKey::from_verified_context(&prompt_context);
                            let suppressed = recent_prompt_attempts
                                .lock()
                                .map(|mut prompts| {
                                    prompt_retry_is_suppressed(
                                        &mut prompts,
                                        &prompt_key,
                                        now,
                                        PROMPT_ATTEMPT_RETENTION,
                                    )
                                })
                                .unwrap_or(false);
                            if suppressed {
                                debug!("macOS fallback prompt retry suppressed for recent prompt");
                                emit_pre_password_skip_report(
                                    &event_tx,
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
                                        &recent_prompt_attempts,
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
                            emit_pre_password_skip_report(
                                &event_tx,
                                "visible_credential_prompt_not_detected",
                                &[(
                                    "prompt_context_source",
                                    "macos_fallback_preflight".to_string(),
                                )],
                            );
                        }
                        Err(reason) => {
                            debug!(reason = %reason, "macOS fallback prompt preflight skipped");
                            emit_pre_password_skip_report(
                                &event_tx,
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
                    &recent_prompt_attempts,
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
                &recent_prompt_attempts,
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
        account_for_visible_prompt_email, ensure_generation_current,
        fill_attempt_should_suppress_same_prompt_retry, handle_command,
        prompt_account_decision_allows_macos_probe, prompt_retry_is_suppressed,
        record_prompt_retry_suppression, wait_or_handle_command, LoginPromptKey, MonitorStatus,
        PollCadence, PromptAccountDecision, PromptRetrySuppression, WorkerCommand, WorkerEvent,
        MACOS_FALLBACK_PROMPT_PROBE_INTERVAL, MAX_RECENT_PROMPT_ATTEMPTS, PROMPT_ATTEMPT_RETENTION,
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
    fn poll_cadence_backs_off_only_for_stable_statuses() {
        let settings = AppSettings {
            poll_interval_secs: 60,
            ..AppSettings::default()
        };
        let mut cadence = PollCadence::default();

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
            cadence.next_delay(
                &settings,
                &MonitorStatus::LoginWindowDetected {
                    process_id: 42,
                    window_title: "Sign in".to_string(),
                    prompt_email: Some("user@example.com".to_string()),
                    prompt_origin: "window".to_string(),
                },
            ),
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
    }

    #[test]
    fn prompt_status_poll_wakes_up_after_one_second_even_with_status_backoff() {
        let settings = AppSettings {
            poll_interval_secs: 1,
            ..AppSettings::default()
        };
        let mut cadence = PollCadence::default();

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

        assert_eq!(PROMPT_STATUS_POLL_INTERVAL, Duration::from_secs(1));
        assert_eq!(
            Duration::from_secs(4).min(PROMPT_STATUS_POLL_INTERVAL),
            Duration::from_secs(1)
        );
    }

    #[test]
    fn macos_fallback_prompt_probe_uses_prompt_poll_interval() {
        assert_eq!(
            MACOS_FALLBACK_PROMPT_PROBE_INTERVAL,
            PROMPT_STATUS_POLL_INTERVAL
        );
    }

    #[test]
    fn credential_prompt_poll_cadence_stays_one_second_after_stable_backoff() {
        let settings = AppSettings {
            poll_interval_secs: 1,
            ..AppSettings::default()
        };
        let mut cadence = PollCadence::default();

        for _ in 0..4 {
            let _ = cadence.next_delay(&settings, &MonitorStatus::Connected);
        }

        let prompt = MonitorStatus::LoginWindowDetected {
            process_id: 42,
            window_title: "Windows Security".to_string(),
            prompt_email: Some("user@example.com".to_string()),
            prompt_origin: "window".to_string(),
        };

        assert_eq!(
            cadence.next_delay(&settings, &prompt),
            Duration::from_secs(1)
        );
        assert_eq!(
            cadence.next_delay(&settings, &prompt),
            Duration::from_secs(1)
        );
        assert_eq!(
            cadence.next_delay(&settings, &prompt),
            Duration::from_secs(1)
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
    fn duplicate_enabled_account_match_is_not_allowed() {
        let accounts = [
            account("account-1", "user@example.com", true),
            account("account-2", " USER@example.com ", true),
        ];

        let decision = account_for_visible_prompt_email(&accounts, Some("user@example.com"));

        assert!(matches!(decision, PromptAccountDecision::Ambiguous));
    }

    #[test]
    fn same_email_matches_are_ambiguous_without_target_disambiguation() {
        let accounts = [
            account("account-1", "user@example.com", true),
            account("account-2", " USER@example.com ", true),
            account("account-3", "other@example.com", true),
        ];

        let decision = account_for_visible_prompt_email(&accounts, Some("user@example.com"));

        assert!(matches!(decision, PromptAccountDecision::Ambiguous));
    }

    #[test]
    fn three_same_email_matches_are_ambiguous_without_target_disambiguation() {
        let accounts = [
            account("account-1", "user@example.com", true),
            account("account-2", "user@example.com", true),
            account("account-3", "USER@example.com", true),
        ];

        let decision = account_for_visible_prompt_email(&accounts, Some("user@example.com"));

        assert!(matches!(decision, PromptAccountDecision::Ambiguous));
    }

    #[test]
    fn stale_prompt_suppression_expires_and_allows_retry_after_ttl() {
        let now = std::time::Instant::now();
        let cooldown = Duration::from_secs(20);
        let prompt_key = make_prompt_key("account-1", 42, "Sign in", "user@example.com");
        let stale_key = make_prompt_key("account-2", 77, "Old sign in", "old@example.com");
        let mut attempts = HashMap::from([
            (prompt_key.clone(), now - Duration::from_secs(19)),
            (stale_key.clone(), now - Duration::from_secs(21)),
        ]);

        assert!(prompt_retry_is_suppressed(
            &mut attempts,
            &prompt_key,
            now,
            cooldown
        ));
        assert!(!attempts.contains_key(&stale_key));

        let retry_time = now + Duration::from_secs(2);
        assert!(!prompt_retry_is_suppressed(
            &mut attempts,
            &prompt_key,
            retry_time,
            cooldown
        ));
    }

    #[test]
    fn verified_context_uses_same_key_for_unknown_fallback_suppression() {
        let now = std::time::Instant::now();
        let context = verified_context("account-1", 42, "Sign in", "user@example.com", now);
        let prompt_key = LoginPromptKey::from_verified_context(&context);
        let mut attempts = HashMap::new();
        attempts.insert(prompt_key.clone(), now);

        assert!(prompt_retry_is_suppressed(
            &mut attempts,
            &prompt_key,
            now + Duration::from_secs(1),
            PROMPT_ATTEMPT_RETENTION,
        ));
    }

    #[test]
    fn verified_context_suppression_expires_for_unknown_fallback() {
        let now = std::time::Instant::now();
        let context = verified_context("account-1", 42, "Sign in", "user@example.com", now);
        let prompt_key = LoginPromptKey::from_verified_context(&context);
        let mut attempts = HashMap::from([(prompt_key.clone(), now)]);

        assert!(!prompt_retry_is_suppressed(
            &mut attempts,
            &prompt_key,
            now + PROMPT_ATTEMPT_RETENTION + Duration::from_millis(1),
            PROMPT_ATTEMPT_RETENTION,
        ));
    }

    #[test]
    fn different_prompt_key_bypasses_recent_suppression() {
        let now = std::time::Instant::now();
        let prompt_key = make_prompt_key("account-1", 42, "Sign in", "user@example.com");
        let different_prompt = make_prompt_key("account-1", 43, "Sign in", "user@example.com");
        let mut attempts = HashMap::from([(prompt_key, now)]);

        assert!(!prompt_retry_is_suppressed(
            &mut attempts,
            &different_prompt,
            now,
            Duration::from_secs(20),
        ));
    }

    #[test]
    fn recent_prompt_attempts_are_bounded_to_newest_entries() {
        let now = std::time::Instant::now();
        let newest_key = make_prompt_key(
            "newest-account",
            999,
            "Newest Sign in",
            "newest@example.com",
        );
        let mut attempts = HashMap::new();
        for index in 0..(MAX_RECENT_PROMPT_ATTEMPTS + 8) {
            let key = make_prompt_key(
                &format!("account-{index}"),
                index as i32,
                "Sign in",
                &format!("user-{index}@example.com"),
            );
            attempts.insert(key, now - Duration::from_secs((index + 1) as u64));
        }
        attempts.insert(newest_key.clone(), now);

        let missing_key =
            make_prompt_key("missing-account", 1000, "Sign in", "missing@example.com");

        assert!(!prompt_retry_is_suppressed(
            &mut attempts,
            &missing_key,
            now,
            Duration::from_secs(120),
        ));

        assert!(attempts.len() <= MAX_RECENT_PROMPT_ATTEMPTS);
        assert!(attempts.contains_key(&newest_key));
    }

    #[test]
    fn fill_attempt_suppression_requires_success_or_secret_bearing_attempt() {
        assert!(fill_attempt_should_suppress_same_prompt_retry(
            &fill_report(true, &[])
        ));
        assert!(!fill_attempt_should_suppress_same_prompt_retry(
            &fill_report(false, &[("post_check_state", "prompt_gone_unknown")])
        ));

        assert!(!fill_attempt_should_suppress_same_prompt_retry(
            &fill_report(false, &[("password_load_attempted", "true")])
        ));
        assert!(fill_attempt_should_suppress_same_prompt_retry(
            &fill_report(
                false,
                &[
                    ("password_load_attempted", "true"),
                    ("password_loaded", "true")
                ]
            )
        ));
        assert!(!fill_attempt_should_suppress_same_prompt_retry(
            &fill_report_with_failure(
                false,
                &[("password_load_attempted", "true")],
                Some("password_load_failed_for_selected_account")
            )
        ));
        assert!(fill_attempt_should_suppress_same_prompt_retry(
            &fill_report(false, &[("submit_attempted", "true")])
        ));
        assert!(fill_attempt_should_suppress_same_prompt_retry(
            &fill_report(false, &[("fill_attempted", "true"), ("fill_status", "ok")])
        ));
        assert!(!fill_attempt_should_suppress_same_prompt_retry(
            &fill_report_with_failure(false, &[], Some("fill_failed"))
        ));
        assert!(fill_attempt_should_suppress_same_prompt_retry(
            &fill_report_with_failure(
                false,
                &[("password_loaded", "true")],
                Some("fill_script_failed")
            )
        ));
        assert!(fill_attempt_should_suppress_same_prompt_retry(
            &fill_report_with_failure(
                false,
                &[("password_loaded", "true")],
                Some("attempt_cancelled_after_password_load_accounts_settings_changed")
            )
        ));
        assert!(fill_attempt_should_suppress_same_prompt_retry(
            &fill_report(
                false,
                &[("fill_attempted", "true"), ("fill_status", "not_found")]
            )
        ));
        assert!(!fill_attempt_should_suppress_same_prompt_retry(
            &fill_report(false, &[("prompt_context_revalidation_result", "stale")])
        ));
    }

    #[test]
    fn prompt_retry_suppression_is_recorded_only_for_suppressible_outcome() {
        let prompt_key = make_prompt_key("account-1", 42, "Sign in", "user@example.com");
        let attempts = Arc::new(Mutex::new(HashMap::new()));

        record_prompt_retry_suppression(
            Some(PromptRetrySuppression {
                recent_prompt_attempts: attempts.clone(),
                prompt_key: prompt_key.clone(),
            }),
            &fill_report(false, &[("password_load_attempted", "true")]),
        );
        assert!(attempts.lock().unwrap().is_empty());

        record_prompt_retry_suppression(
            Some(PromptRetrySuppression {
                recent_prompt_attempts: attempts.clone(),
                prompt_key: prompt_key.clone(),
            }),
            &fill_report(
                false,
                &[
                    ("password_load_attempted", "true"),
                    ("password_loaded", "true"),
                ],
            ),
        );

        assert!(attempts.lock().unwrap().contains_key(&prompt_key));
        attempts.lock().unwrap().clear();

        record_prompt_retry_suppression(
            Some(PromptRetrySuppression {
                recent_prompt_attempts: attempts.clone(),
                prompt_key: prompt_key.clone(),
            }),
            &fill_report(true, &[]),
        );

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
                &recent_prompt_attempts,
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
    async fn wait_or_handle_command_handles_stop_and_clears_recent_prompts() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<WorkerCommand>(1);
        let (event_tx, mut event_rx) = mpsc::channel::<WorkerEvent>(1);
        let generation = std::sync::Arc::new(AtomicU64::new(5));
        let recent_prompt_attempts = Arc::new(Mutex::new(HashMap::from([(
            make_prompt_key("account-1", 42, "Sign in", "user@example.com"),
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
                &recent_prompt_attempts,
            )
            .await
        );

        assert!(!running);
        assert_eq!(generation.load(Ordering::SeqCst), 6);
        assert!(recent_prompt_attempts.lock().unwrap().is_empty());
        match event_rx.try_recv().unwrap() {
            WorkerEvent::StatusChanged(WorkerStatus::Idle) => {}
            other => panic!("expected idle status, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn wait_or_handle_command_apply_config_refresh_clears_recent_prompts() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<WorkerCommand>(1);
        let (event_tx, mut event_rx) = mpsc::channel::<WorkerEvent>(1);
        let generation = std::sync::Arc::new(AtomicU64::new(9));
        let recent_prompt_attempts = Arc::new(Mutex::new(HashMap::from([(
            make_prompt_key("account-1", 42, "Sign in", "user@example.com"),
            Instant::now(),
        )])));
        let mut running = true;
        let mut settings = AppSettings::default();
        let mut accounts = vec![account("account-1", "user@example.com", true)];
        let mut next_settings = settings.clone();
        next_settings.start_minimized = !settings.start_minimized;
        let next_accounts = vec![account("account-2", "other@example.com", true)];

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
                &recent_prompt_attempts,
            )
            .await
        );

        assert!(running);
        assert_eq!(settings, next_settings);
        assert_eq!(accounts, next_accounts);
        assert_eq!(generation.load(Ordering::SeqCst), 10);
        assert!(recent_prompt_attempts.lock().unwrap().is_empty());
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
            window_title: window_title.to_string(),
            prompt_email: prompt_email.to_string(),
            prompt_origin: "window".to_string(),
            detected_at,
            #[cfg(target_os = "windows")]
            monitor_check_ms: 0,
        }
    }

    fn fill_report(success: bool, fields: &[(&str, &str)]) -> debug_fill::FillAttemptReport {
        fill_report_with_failure(success, fields, (!success).then_some("test_failure"))
    }

    fn fill_report_with_failure(
        success: bool,
        fields: &[(&str, &str)],
        failure_reason: Option<&str>,
    ) -> debug_fill::FillAttemptReport {
        debug_fill::FillAttemptReport {
            fields: fields
                .iter()
                .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
                .collect(),
            success,
            failure_reason: failure_reason.map(str::to_string),
        }
    }
}
