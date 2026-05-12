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
    UpdateSettings(AppSettings),
    UpdateAccounts(Vec<Account>),
    RefreshPasswords,
}

#[derive(Debug, Clone)]
pub(crate) enum WorkerEvent {
    StatusChanged(WorkerStatus),
    Log(LogEntry),
    FillAttemptReport(FillAttemptReport),
}

const IDLE_SLEEP: Duration = Duration::from_millis(500);
const AUTOMATION_SLEEP: Duration = Duration::from_millis(250);
const CONNECTED_POLL_BACKOFF_MAX: Duration = Duration::from_secs(5);
const UNKNOWN_POLL_BACKOFF_MAX: Duration = Duration::from_secs(3);
const MAX_RECENT_PROMPT_ATTEMPTS: usize = 32;
const PROMPT_ATTEMPT_RETENTION: Duration = Duration::from_secs(60);

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

fn runtime_config(settings: &AppSettings) -> Arc<Config> {
    Arc::new(Config {
        macos_app_name: settings.macos_app_name.clone(),
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
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct LoginPromptKey {
    account_id: String,
    process_id: i32,
    window_title: String,
    prompt_email: String,
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
        .filter(|account| account.enabled && !account.username.trim().is_empty())
        .filter(|account| account.username.trim().eq_ignore_ascii_case(prompt_email))
        .take(2)
        .collect::<Vec<_>>();

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
    fn next_delay(&mut self, settings: &AppSettings, status: &MonitorStatus) -> Duration {
        let base_delay = Duration::from_secs(settings.poll_interval_secs.max(1));
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

fn stable_status_backoff_max(status: &MonitorStatus) -> Option<Duration> {
    match status {
        MonitorStatus::Connected => Some(CONNECTED_POLL_BACKOFF_MAX),
        MonitorStatus::Unknown => Some(UNKNOWN_POLL_BACKOFF_MAX),
        MonitorStatus::ProcessNotFound | MonitorStatus::LoginWindowDetected { .. } => None,
    }
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
        WorkerCommand::UpdateSettings(s) => {
            if *settings == s {
                return;
            }
            *settings = s;
            generation.fetch_add(1, Ordering::SeqCst);
            info!("Settings updated");
        }
        WorkerCommand::UpdateAccounts(a) => {
            if *accounts == a {
                return;
            }
            *accounts = a;
            generation.fetch_add(1, Ordering::SeqCst);
            info!("Accounts updated: {} account(s)", accounts.len());
        }
        WorkerCommand::RefreshPasswords => {
            generation.fetch_add(1, Ordering::SeqCst);
            info!("Credential refresh requested");
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
            drain_commands(cmd_rx, event_tx, running, settings, accounts, generation).await;
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
            ..
        } = job;
        let _automation_guard = automation_guard;
        let guard_generation = generation.clone();
        let report = debug_fill::fill_current_prompt_once_guarded(
            &settings,
            &accounts,
            FillMethod::Keyboard,
            || {
                ensure_generation_current(
                    &guard_generation,
                    expected_generation,
                    "accounts/settings changed",
                )
            },
        );
        let level = if report.success {
            LogLevel::Info
        } else {
            LogLevel::Warn
        };
        let should_log = report.success || report.field("prompt_detected") == Some("true");
        if should_log {
            let _ = event_tx.try_send(log_event(
                level,
                format!("{}: {}", trigger.label(), report.summary_line()),
            ));
        }
        if should_log {
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
) {
    tokio::spawn(async move {
        let mut settings = initial_settings;
        let mut accounts = initial_accounts;
        let mut running = false;
        let recent_prompt_attempts =
            Arc::new(Mutex::new(HashMap::<LoginPromptKey, Instant>::new()));
        let automation_in_progress = Arc::new(AtomicBool::new(false));
        let generation = Arc::new(AtomicU64::new(0));
        let mut last_auto_fill_attempt: Option<Instant> = None;
        let mut poll_cadence = PollCadence::default();

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

            let has_enabled_account = accounts
                .iter()
                .any(|account| account.enabled && !account.username.trim().is_empty());

            if !has_enabled_account {
                if !wait_or_handle_command(
                    Duration::from_secs(settings.poll_interval_secs.max(1)),
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

            let auto_probe_due = last_auto_fill_attempt
                .map(|attempt| attempt.elapsed() >= Duration::from_secs(1))
                .unwrap_or(true);
            if auto_probe_due {
                let started = spawn_current_prompt_attempt(CurrentPromptAttempt {
                    trigger: FillTrigger::Automatic,
                    settings: settings.clone(),
                    accounts: accounts.clone(),
                    event_tx: event_tx.clone(),
                    automation_in_progress: automation_in_progress.clone(),
                    generation: generation.clone(),
                    expected_generation: current_generation,
                });
                if started {
                    last_auto_fill_attempt = Some(Instant::now());
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

            let monitor = AppMonitor::new(runtime_config(&settings));
            let tick_start = Instant::now();
            let status = monitor.check_status();
            let next_poll_delay = poll_cadence.next_delay(&settings, &status);
            trace!(
                worker_tick_ms = tick_start.elapsed().as_millis(),
                worker_state = if running { "running" } else { "idle" },
                windows_app_running = !matches!(status, MonitorStatus::ProcessNotFound),
                prompt_candidate_visible =
                    matches!(status, MonitorStatus::LoginWindowDetected { .. }),
                suppression_active = false,
                suppression_reason = "",
                suppression_until_ms = 0_u64,
                backoff_ms = next_poll_delay.as_millis(),
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

            match status {
                MonitorStatus::Connected => {
                    if let Ok(mut prompts) = recent_prompt_attempts.lock() {
                        prompts.clear();
                    }
                }
                MonitorStatus::Unknown => {
                    let prompt_retry_ok = last_auto_fill_attempt
                        .map(|attempt| attempt.elapsed() >= Duration::from_secs(1))
                        .unwrap_or(true);
                    if prompt_retry_ok {
                        let started = spawn_current_prompt_attempt(CurrentPromptAttempt {
                            trigger: FillTrigger::Automatic,
                            settings: settings.clone(),
                            accounts: accounts.clone(),
                            event_tx: event_tx.clone(),
                            automation_in_progress: automation_in_progress.clone(),
                            generation: generation.clone(),
                            expected_generation: current_generation,
                        });
                        if started {
                            last_auto_fill_attempt = Some(Instant::now());
                        }
                    }
                }
                MonitorStatus::ProcessNotFound => {
                    if let Ok(mut prompts) = recent_prompt_attempts.lock() {
                        prompts.clear();
                    }
                }
                MonitorStatus::LoginWindowDetected {
                    process_id,
                    window_title,
                    prompt_email,
                } => match account_for_visible_prompt_email(&accounts, prompt_email.as_deref()) {
                    PromptAccountDecision::Allow(account) => {
                        let prompt_key = LoginPromptKey {
                            account_id: account.id.clone(),
                            process_id,
                            window_title: window_title.clone(),
                            prompt_email: prompt_email.unwrap_or_default(),
                        };
                        if let Ok(mut prompts) = recent_prompt_attempts.lock() {
                            let now = Instant::now();
                            prompts.insert(prompt_key, now);
                            prune_recent_prompt_attempts(
                                &mut prompts,
                                now,
                                PROMPT_ATTEMPT_RETENTION,
                            );
                        }
                        let started = spawn_current_prompt_attempt(CurrentPromptAttempt {
                            trigger: FillTrigger::Automatic,
                            settings: settings.clone(),
                            accounts: accounts.clone(),
                            event_tx: event_tx.clone(),
                            automation_in_progress: automation_in_progress.clone(),
                            generation: generation.clone(),
                            expected_generation: current_generation,
                        });
                        if started {
                            last_auto_fill_attempt = Some(Instant::now());
                            let _ = event_tx
                                .try_send(log_event(LogLevel::Info, "Login window detected"));
                        }
                    }
                    PromptAccountDecision::MissingEmail => {
                        debug!(
                                "Login window detected but no email was visible; skipping password load"
                            );
                    }
                    PromptAccountDecision::NoEnabledMatch => {
                        warn!("Login window email does not match any enabled account");
                    }
                    PromptAccountDecision::Ambiguous => {
                        warn!(
                                "Login window email matches multiple enabled accounts; skipping ambiguous login"
                            );
                    }
                },
            }

            if !wait_or_handle_command(
                next_poll_delay,
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
        prompt_retry_is_suppressed, LoginPromptKey, MonitorStatus, PollCadence,
        PromptAccountDecision, WorkerCommand, WorkerEvent, MAX_RECENT_PROMPT_ATTEMPTS,
    };
    use crate::models::{Account, AppSettings};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;
    use tokio::sync::mpsc;

    #[test]
    fn poll_cadence_backs_off_only_for_stable_statuses() {
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
    fn duplicate_enabled_account_match_is_not_allowed() {
        let accounts = [
            account("account-1", "user@example.com", true),
            account("account-2", " USER@example.com ", true),
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
    fn generation_change_rejects_in_flight_login_guard() {
        let generation = AtomicU64::new(7);

        assert!(ensure_generation_current(&generation, 7, "cancelled").is_ok());

        generation.fetch_add(1, Ordering::SeqCst);
        let error = ensure_generation_current(&generation, 7, "cancelled").unwrap_err();

        assert_eq!(error.to_string(), "cancelled");
    }

    #[tokio::test]
    async fn settings_change_advances_generation_so_in_flight_attempts_cancel() {
        let (event_tx, mut event_rx) = mpsc::channel::<WorkerEvent>(1);
        let generation = std::sync::Arc::new(AtomicU64::new(3));
        let mut running = true;
        let mut settings = AppSettings::default();
        let mut accounts = vec![account("account-1", "user@example.com", true)];
        let expected_generation = generation.load(Ordering::SeqCst);
        let mut new_settings = settings.clone();
        new_settings.poll_interval_secs = settings.poll_interval_secs + 1;

        handle_command(
            WorkerCommand::UpdateSettings(new_settings),
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
        LoginPromptKey {
            account_id: account_id.to_string(),
            process_id,
            window_title: window_title.to_string(),
            prompt_email: prompt_email.to_string(),
        }
    }
}
