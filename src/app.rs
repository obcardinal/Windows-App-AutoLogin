use crate::autologin::{
    accessibility_status, open_accessibility_settings, request_accessibility_access_prompt,
    AccessibilityStatus,
};
use crate::background::{WorkerCommand, WorkerEvent, WorkerPauseLatch};
#[cfg(feature = "diagnostics-ui")]
use crate::debug_fill;
use crate::debug_fill::FillAttemptReport;
use crate::models::{
    Account, AccountId, AppConfig, AppSettings, LogEntry, LogLevel, MonitorControlState, Tab,
    WorkerStatus,
};
use crate::single_instance::{self, MonitorControlCommand};
use crate::tray::TrayCommand;
use crate::ui::theme;
use eframe::egui;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};
use tokio::sync::mpsc::Sender as TokioSender;
use zeroize::Zeroizing;

const MAX_LOG_ENTRIES: usize = 200;
const APP_VERSION_LABEL: &str = concat!("v", env!("CARGO_PKG_VERSION"));
const ACCESSIBILITY_REQUEST_BUTTON_SIZE: [f32; 2] = [278.0, 34.0];
const ACCESSIBILITY_SETTINGS_BUTTON_SIZE: [f32; 2] = [248.0, 34.0];
const ACCESSIBILITY_SETTINGS_INSTRUCTIONS: &str =
    "Enable Windows App AutoLogin, then return here. If its switch is already on but this screen remains, select the old Windows App AutoLogin entry and click the minus (−) button. Then click the plus (+) button, add Windows App AutoLogin again, and enable it. The app checks again every second.";
const BRIDGED_UI_STATUS_POLL_INTERVAL: Duration = Duration::from_millis(500);
const STORAGE_RECOVERY_SIGNAL_RETRY_INTERVAL: Duration = Duration::from_secs(1);
const LOCAL_CONFIG_MUTATION_QUIESCENCE_TIMEOUT: Duration = Duration::from_secs(15);
const BACKGROUND_MUTATION_QUEUE_CAPACITY: usize = 1;
const MONITOR_CONTROL_QUEUE_CAPACITY: usize = 1;
const MONITOR_CONTROL_COMPLETION_POLL_INTERVAL: Duration = Duration::from_millis(25);
const MONITOR_CONTROL_SAFETY_STOP_RETRY_INITIAL_INTERVAL: Duration = Duration::from_millis(100);
const MONITOR_CONTROL_SAFETY_STOP_RETRY_MAX_INTERVAL: Duration = Duration::from_secs(2);
pub(crate) const CONFIG_MUTATION_RECOVERY_REASON: &str =
    "Configuration controls are unavailable until password storage recovery completes after restart.";
const BACKGROUND_MUTATION_EXECUTOR_UNAVAILABLE_REASON: &str =
    "Configuration controls are unavailable because the background update service could not start. Restart the app to try again.";
pub(crate) const LOCAL_CONFIG_RELEASE_FAILED_REASON: &str =
    "Configuration controls are unavailable because the monitor could not confirm the current configuration. Restart the app before changing settings again.";
pub(crate) const SETTINGS_WINDOW_CLOSING_REASON: &str =
    "Settings cannot be changed while this window is closing.";

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum SettingsMutationPhase {
    BeginPending = 0,
    Abortable = 1,
    FailClosed = 2,
    Finished = 3,
}

pub(crate) struct SettingsMutationGuard {
    phase: Arc<AtomicU8>,
    cancel: Option<Box<dyn FnOnce() -> anyhow::Result<()> + Send>>,
}

impl SettingsMutationGuard {
    pub(crate) fn mark_begin_acknowledged(&mut self) {
        let _ = self.phase.compare_exchange(
            SettingsMutationPhase::BeginPending as u8,
            SettingsMutationPhase::Abortable as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    /// Prevents Drop from resuming the supervisor with stale configuration.
    /// A background settings transaction enters this state before its first
    /// filesystem or credential mutation. Only a verified clean abort may
    /// explicitly cancel it afterwards.
    pub(crate) fn mark_fail_closed(&mut self) {
        let _ = self.phase.compare_exchange(
            SettingsMutationPhase::Abortable as u8,
            SettingsMutationPhase::FailClosed as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    pub(crate) fn mark_commit_started(&mut self) {
        self.mark_fail_closed();
        self.cancel = None;
    }

    pub(crate) fn cancel_verified_abort(&mut self) -> anyhow::Result<()> {
        let previous = self
            .phase
            .swap(SettingsMutationPhase::Finished as u8, Ordering::AcqRel);
        if previous == SettingsMutationPhase::BeginPending as u8 {
            anyhow::bail!("settings mutation begin was not acknowledged");
        }
        let Some(cancel) = self.cancel.take() else {
            return Ok(());
        };
        cancel()
    }

    pub(crate) fn finish_unacknowledged_begin(&mut self) {
        self.phase
            .store(SettingsMutationPhase::Finished as u8, Ordering::Release);
        self.cancel = None;
    }
}

impl Drop for SettingsMutationGuard {
    fn drop(&mut self) {
        let phase = self
            .phase
            .swap(SettingsMutationPhase::Finished as u8, Ordering::AcqRel);
        if phase != SettingsMutationPhase::Abortable as u8 {
            return;
        }
        let Some(cancel) = self.cancel.take() else {
            return;
        };
        if let Err(error) = cancel() {
            tracing::warn!(%error, "Could not cancel an aborted settings mutation; supervisor remains fail-closed");
        }
    }
}

/// Prepared on the UI owner thread and consumed by a background mutation
/// worker. Preparing a local begin closes the synchronous automation gate;
/// only `wait_for_quiescence` may block, and it always runs on the std worker.
pub(crate) enum BackgroundSettingsMutationBegin {
    Supervisor,
    Local {
        worker_tx: TokioSender<WorkerCommand>,
        worker_pause_latch: WorkerPauseLatch,
        pause_epoch: u64,
    },
}

impl BackgroundSettingsMutationBegin {
    pub(crate) fn wait_for_quiescence(self) -> anyhow::Result<()> {
        match self {
            Self::Supervisor => single_instance::request_settings_mutation_begin(),
            Self::Local {
                worker_tx,
                worker_pause_latch,
                pause_epoch,
            } => {
                ensure_local_pause_epoch(&worker_pause_latch, pause_epoch)?;
                let (acknowledgement, acknowledgement_receiver) = std::sync::mpsc::channel();
                worker_tx
                    .try_send(WorkerCommand::Quiesce {
                        request_id: pause_epoch,
                        acknowledgement,
                    })
                    .map_err(|error| {
                        anyhow::anyhow!(
                            "could not queue local settings mutation quiescence: {error}"
                        )
                    })?;
                let acknowledgement = acknowledgement_receiver
                    .recv_timeout(LOCAL_CONFIG_MUTATION_QUIESCENCE_TIMEOUT)
                    .map_err(|error| {
                        anyhow::anyhow!(
                            "local settings mutation quiescence was not acknowledged: {error}"
                        )
                    })?;
                if acknowledgement.request_id != pause_epoch {
                    anyhow::bail!(
                        "local settings mutation quiescence acknowledgement mismatch (expected {pause_epoch}, received {})",
                        acknowledgement.request_id
                    );
                }
                ensure_local_pause_epoch(&worker_pause_latch, pause_epoch)
            }
        }
    }
}

fn ensure_local_pause_epoch(
    worker_pause_latch: &WorkerPauseLatch,
    expected_epoch: u64,
) -> anyhow::Result<()> {
    if !worker_pause_latch.owns_pause(expected_epoch) {
        anyhow::bail!("the local settings mutation pause epoch is no longer current");
    }
    Ok(())
}

struct BridgedUiStatusSnapshot {
    generation: u64,
    monitor_control_state: Option<MonitorControlState>,
    accessibility_status: AccessibilityStatus,
    #[cfg(feature = "diagnostics-ui")]
    last_fill_report: Option<FillAttemptReport>,
}

struct BridgedUiStatusPoller {
    receiver: std::sync::mpsc::Receiver<BridgedUiStatusSnapshot>,
    generation: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
}

impl BridgedUiStatusPoller {
    #[cfg_attr(test, allow(dead_code))]
    fn spawn(settings_window_mode: bool) -> Option<Self> {
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let generation = Arc::new(AtomicU64::new(0));
        let worker_generation = generation.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        if let Err(error) = std::thread::Builder::new()
            .name("ui-status-poll".to_string())
            .spawn(move || {
                while !worker_stop.load(Ordering::Acquire) {
                    let snapshot = BridgedUiStatusSnapshot {
                        generation: worker_generation.load(Ordering::Acquire),
                        monitor_control_state: if settings_window_mode {
                            bridged_monitor_control_state()
                        } else {
                            None
                        },
                        accessibility_status: accessibility_status(),
                        #[cfg(feature = "diagnostics-ui")]
                        last_fill_report: debug_fill::read_last_fill_attempt_report()
                            .ok()
                            .flatten(),
                    };
                    match sender.try_send(snapshot) {
                        Ok(()) | Err(std::sync::mpsc::TrySendError::Full(_)) => {}
                        Err(std::sync::mpsc::TrySendError::Disconnected(_)) => break,
                    }
                    // Check the stop latch in short increments so closing the
                    // UI does not leave a detached poller alive for a full
                    // polling interval.
                    for _ in 0..10 {
                        if worker_stop.load(Ordering::Acquire) {
                            return;
                        }
                        std::thread::sleep(BRIDGED_UI_STATUS_POLL_INTERVAL / 10);
                    }
                }
            })
        {
            tracing::warn!(%error, "Could not start the non-blocking UI status poller");
            return None;
        }
        Some(Self {
            receiver,
            generation,
            stop,
        })
    }

    fn take_latest(&self) -> Option<BridgedUiStatusSnapshot> {
        let current_generation = self.generation.load(Ordering::Acquire);
        self.receiver
            .try_iter()
            .filter(|snapshot| snapshot.generation == current_generation)
            .last()
    }

    fn invalidate_in_flight_snapshot(&self) {
        self.generation.fetch_add(1, Ordering::AcqRel);
    }
}

impl Drop for BridgedUiStatusPoller {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
    }
}

type BackgroundMutationTask = Box<dyn FnOnce() + Send + 'static>;

/// A per-window, prestarted executor for durable configuration mutations.
///
/// Checkbox handlers may prepare small owned snapshots and enqueue a task, but
/// they must never create an operating-system thread or wait for a worker. A
/// bounded `try_send` keeps submission non-blocking even if the executor is
/// unexpectedly busy; the existing fail-closed paths handle a rejected task.
#[derive(Clone)]
pub(crate) struct BackgroundMutationExecutor {
    sender: std::sync::mpsc::SyncSender<BackgroundMutationTask>,
}

impl BackgroundMutationExecutor {
    fn spawn() -> std::io::Result<Self> {
        let (sender, receiver) = std::sync::mpsc::sync_channel::<BackgroundMutationTask>(
            BACKGROUND_MUTATION_QUEUE_CAPACITY,
        );
        std::thread::Builder::new()
            .name("config-mutation".to_string())
            .spawn(move || {
                while let Ok(task) = receiver.recv() {
                    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(task)).is_err() {
                        tracing::error!(
                            "A background configuration mutation panicked; its owner will fail closed"
                        );
                        break;
                    }
                }
            })?;
        Ok(Self { sender })
    }

    pub(crate) fn try_submit(&self, task: impl FnOnce() + Send + 'static) -> std::io::Result<()> {
        self.sender.try_send(Box::new(task)).map_err(|error| {
            let (kind, message) = match error {
                std::sync::mpsc::TrySendError::Full(_) => (
                    std::io::ErrorKind::WouldBlock,
                    "background configuration queue is full",
                ),
                std::sync::mpsc::TrySendError::Disconnected(_) => (
                    std::io::ErrorKind::BrokenPipe,
                    "background configuration executor is unavailable",
                ),
            };
            std::io::Error::new(kind, message)
        })
    }
}

type MonitorControlTask = Box<dyn FnOnce() + Send + 'static>;

/// A dedicated, prestarted executor for Start/Stop IPC.
///
/// Monitor control must not share the durable configuration executor: a
/// Keychain migration or fsync may occupy that worker for seconds. The egui
/// owner only performs a bounded `try_send`; socket/pipe authentication and
/// acknowledgement waits always execute on this dedicated thread.
#[derive(Clone)]
struct MonitorControlExecutor {
    sender: std::sync::mpsc::SyncSender<MonitorControlTask>,
}

impl MonitorControlExecutor {
    fn spawn() -> std::io::Result<Self> {
        let (sender, receiver) =
            std::sync::mpsc::sync_channel::<MonitorControlTask>(MONITOR_CONTROL_QUEUE_CAPACITY);
        std::thread::Builder::new()
            .name("monitor-control".to_string())
            .spawn(move || {
                while let Ok(task) = receiver.recv() {
                    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(task)).is_err() {
                        tracing::error!(
                            "A background monitor control request panicked; its owner will treat the acknowledgement as ambiguous"
                        );
                    }
                }
            })?;
        Ok(Self { sender })
    }

    fn try_submit(&self, task: impl FnOnce() + Send + 'static) -> std::io::Result<()> {
        self.sender.try_send(Box::new(task)).map_err(|error| {
            let (kind, message) = match error {
                std::sync::mpsc::TrySendError::Full(_) => (
                    std::io::ErrorKind::WouldBlock,
                    "background monitor control queue is full",
                ),
                std::sync::mpsc::TrySendError::Disconnected(_) => (
                    std::io::ErrorKind::BrokenPipe,
                    "background monitor control executor is unavailable",
                ),
            };
            std::io::Error::new(kind, message)
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MonitorControlIntent {
    sequence: u64,
    command: MonitorControlCommand,
}

impl MonitorControlIntent {
    fn projected_state(self) -> MonitorControlState {
        match self.command {
            MonitorControlCommand::Start => MonitorControlState::PausedWithStartIntent,
            MonitorControlCommand::Stop | MonitorControlCommand::StorageRecoveryBlocked => {
                MonitorControlState::Stopped
            }
            #[cfg(not(target_os = "macos"))]
            MonitorControlCommand::ReloadConfig => MonitorControlState::Stopped,
        }
    }
}

struct PendingMonitorControl {
    receiver: std::sync::mpsc::Receiver<MonitorControlCompletion>,
    active_intent: MonitorControlIntent,
    latest_intent: MonitorControlIntent,
    projected_state: MonitorControlState,
}

#[derive(Debug, Clone, Copy)]
struct MonitorSafetyStopRecovery {
    next_retry_at: Option<Instant>,
    next_backoff: Duration,
}

#[derive(Debug, PartialEq, Eq)]
enum MonitorControlCompletion {
    Acknowledged(MonitorControlIntent),
    Ambiguous {
        intent: MonitorControlIntent,
        error: String,
        safety_stop_error: Option<String>,
    },
}

fn submit_monitor_control_worker<J>(
    executor: MonitorControlExecutor,
    job: J,
    repaint: egui::Context,
) -> std::io::Result<std::sync::mpsc::Receiver<MonitorControlCompletion>>
where
    J: FnOnce() -> MonitorControlCompletion + Send + 'static,
{
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    executor.try_submit(move || {
        let completion = job();
        let _ = sender.try_send(completion);
        repaint.request_repaint();
    })?;
    Ok(receiver)
}

fn run_monitor_control_request<R>(
    intent: MonitorControlIntent,
    mut request: R,
) -> MonitorControlCompletion
where
    R: FnMut(MonitorControlCommand) -> anyhow::Result<()>,
{
    debug_assert!(matches!(
        intent.command,
        MonitorControlCommand::Start | MonitorControlCommand::Stop
    ));
    match request(intent.command) {
        Ok(()) => MonitorControlCompletion::Acknowledged(intent),
        Err(error) => {
            // The supervisor commits before writing its ACK. A timeout or
            // broken connection is therefore ambiguous: the requested Start
            // may already be live. Issue a Stop on this same background thread
            // and treat the state as safely stopped only if that Stop receives
            // its own acknowledgement.
            let safety_stop_error = request(MonitorControlCommand::Stop)
                .err()
                .map(|error| error.to_string());
            MonitorControlCompletion::Ambiguous {
                intent,
                error: error.to_string(),
                safety_stop_error,
            }
        }
    }
}

pub(crate) struct AutoLoginApp {
    pub(crate) config: AppConfig,
    pub(crate) selected_tab: Tab,
    pub(crate) logs: VecDeque<LogEntry>,
    pub(crate) worker_status: WorkerStatus,
    bridged_monitor_control_state: MonitorControlState,
    bridged_ui_status_poller: Option<BridgedUiStatusPoller>,
    bridged_ui_status_initialized: bool,
    pub(crate) worker_tx: TokioSender<WorkerCommand>,
    worker_pause_latch: WorkerPauseLatch,
    background_mutation_executor: Option<BackgroundMutationExecutor>,
    monitor_control_executor: Option<MonitorControlExecutor>,
    pending_monitor_control: Option<PendingMonitorControl>,
    monitor_safety_stop_recovery: Option<MonitorSafetyStopRecovery>,
    next_monitor_control_intent_sequence: u64,
    pub(crate) tray_rx: std::sync::mpsc::Receiver<TrayCommand>,
    pub(crate) worker_event_rx: tokio::sync::mpsc::Receiver<WorkerEvent>,

    pub(crate) editing_account: Option<Account>,
    pub(crate) confirm_delete_account: Option<AccountId>,
    pub(crate) settings_draft: AppSettings,
    pub(crate) temp_password: Zeroizing<String>,
    pub(crate) show_password: bool,
    pub(crate) status_message: Option<(String, f64)>,
    pub(crate) last_fill_report: Option<FillAttemptReport>,
    storage_recovery_blocked: bool,
    quit_requested: bool,

    #[cfg(feature = "diagnostics-ui")]
    pub(crate) diagnose_running: bool,
    #[cfg(feature = "diagnostics-ui")]
    pub(crate) diagnose_result: String,
    #[cfg(feature = "diagnostics-ui")]
    pub(crate) diagnose_rx: Option<std::sync::mpsc::Receiver<String>>,
    #[cfg(feature = "diagnostics-ui")]
    pub(crate) runtime_status_running: bool,
    #[cfg(feature = "diagnostics-ui")]
    pub(crate) runtime_status_report: Option<FillAttemptReport>,
    #[cfg(feature = "diagnostics-ui")]
    pub(crate) runtime_status_rx: Option<std::sync::mpsc::Receiver<FillAttemptReport>>,
    settings_window_mode: bool,
    active_settings_mutation: Option<Weak<AtomicU8>>,
    active_local_config_mutation_pause_epoch: Option<u64>,
    active_local_config_mutation_start_monitor: Option<bool>,
    pub(crate) pending_settings_save: Option<crate::ui::settings::PendingSettingsSave>,
    pub(crate) pending_account_toggle: Option<crate::ui::accounts::PendingAccountToggle>,
    pub(crate) queued_account_toggles: Vec<crate::ui::accounts::AccountToggleIntent>,
    pub(crate) pending_account_transaction: Option<crate::ui::accounts::PendingAccountTransaction>,
    pub(crate) queued_account_transactions: VecDeque<crate::ui::accounts::AccountTransactionIntent>,
    pub(crate) next_account_toggle_intent_sequence: u64,
    pub(crate) account_toggle_start_retry_at: Option<Instant>,
    pub(crate) account_toggle_failure_status_sequence: Option<u64>,
    pending_storage_recovery_signal: Option<std::sync::mpsc::Receiver<Result<(), String>>>,
    storage_recovery_signal_retry_at: Option<Instant>,
    settings_changes_blocked_reason: Option<String>,
    close_settings_window_after_sync: bool,
    close_settings_window_after_pending_save: bool,
    keep_settings_window_open_through_ui_pass: bool,

    pub(crate) accessibility_status: AccessibilityStatus,
    accessibility_last_missing_log: Option<Instant>,
}

impl AutoLoginApp {
    pub(crate) fn new(
        worker_tx: TokioSender<WorkerCommand>,
        worker_pause_latch: WorkerPauseLatch,
        tray_rx: std::sync::mpsc::Receiver<TrayCommand>,
        worker_event_rx: tokio::sync::mpsc::Receiver<WorkerEvent>,
        config: AppConfig,
        settings_window_mode: bool,
        initial_tab: Tab,
    ) -> Self {
        // Status files are polled by a dedicated background reader. Starting
        // from the safe stopped state avoids filesystem I/O in the egui app
        // creator; the first snapshot is produced immediately by the poller.
        let bridged_monitor_control_state = MonitorControlState::Stopped;
        let worker_status = bridged_monitor_control_state.worker_status();
        let settings_draft = config.settings.clone();
        let accessibility_status = accessibility_status();
        let (background_mutation_executor, background_mutation_executor_error) =
            match BackgroundMutationExecutor::spawn() {
                Ok(executor) => (Some(executor), None),
                Err(error) => (None, Some(error)),
            };
        if let Some(error) = background_mutation_executor_error.as_ref() {
            tracing::error!(%error, "Could not start the background configuration executor");
        }
        let monitor_control_executor = if settings_window_mode {
            match MonitorControlExecutor::spawn() {
                Ok(executor) => Some(executor),
                Err(error) => {
                    tracing::error!(%error, "Could not start the background monitor control executor");
                    None
                }
            }
        } else {
            None
        };

        #[cfg(not(test))]
        let bridged_ui_status_poller = BridgedUiStatusPoller::spawn(settings_window_mode);
        #[cfg(test)]
        let bridged_ui_status_poller = None;

        let mut app = Self {
            config,
            selected_tab: initial_tab,
            logs: VecDeque::with_capacity(MAX_LOG_ENTRIES),
            worker_status,
            bridged_monitor_control_state,
            bridged_ui_status_poller,
            bridged_ui_status_initialized: false,
            worker_tx,
            worker_pause_latch,
            background_mutation_executor,
            monitor_control_executor,
            pending_monitor_control: None,
            monitor_safety_stop_recovery: None,
            next_monitor_control_intent_sequence: 0,
            tray_rx,
            worker_event_rx,
            editing_account: None,
            confirm_delete_account: None,
            settings_draft,
            temp_password: Zeroizing::new(String::new()),
            show_password: false,
            status_message: None,
            last_fill_report: None,
            // Startup performs recovery before constructing the UI and passes
            // the result through `with_storage_recovery_state`. Keep the
            // constructor itself free of filesystem work so creating or
            // repainting the window cannot stall on recovery metadata.
            storage_recovery_blocked: false,
            quit_requested: false,
            #[cfg(feature = "diagnostics-ui")]
            diagnose_running: false,
            #[cfg(feature = "diagnostics-ui")]
            diagnose_result: String::new(),
            #[cfg(feature = "diagnostics-ui")]
            diagnose_rx: None,
            #[cfg(feature = "diagnostics-ui")]
            runtime_status_running: false,
            #[cfg(feature = "diagnostics-ui")]
            runtime_status_report: None,
            #[cfg(feature = "diagnostics-ui")]
            runtime_status_rx: None,
            settings_window_mode,
            active_settings_mutation: None,
            active_local_config_mutation_pause_epoch: None,
            active_local_config_mutation_start_monitor: None,
            pending_settings_save: None,
            pending_account_toggle: None,
            queued_account_toggles: Vec::new(),
            pending_account_transaction: None,
            queued_account_transactions: VecDeque::new(),
            next_account_toggle_intent_sequence: 0,
            account_toggle_start_retry_at: None,
            account_toggle_failure_status_sequence: None,
            pending_storage_recovery_signal: None,
            storage_recovery_signal_retry_at: None,
            settings_changes_blocked_reason: background_mutation_executor_error
                .map(|_| BACKGROUND_MUTATION_EXECUTOR_UNAVAILABLE_REASON.to_string()),
            close_settings_window_after_sync: false,
            close_settings_window_after_pending_save: false,
            keep_settings_window_open_through_ui_pass: false,
            accessibility_status,
            accessibility_last_missing_log: None,
        };

        if app.storage_recovery_blocked {
            app.worker_pause_latch.pause();
        }

        app.log_accessibility_event(
            "accessibility_check_result",
            if app.accessibility_status.trusted {
                LogLevel::Info
            } else {
                LogLevel::Warn
            },
        );
        if !app.accessibility_status.trusted {
            app.status_message = Some((
                "Accessibility permission is required for this exact app".to_string(),
                10.0f64,
            ));
        }
        app
    }

    pub(crate) fn with_storage_recovery_state(mut self, recovery_ready: bool) -> Self {
        if !recovery_ready {
            self.storage_recovery_blocked = true;
            self.worker_pause_latch.pause();
        }
        self
    }

    pub(crate) fn account_mutations_ready(&self) -> bool {
        self.config_mutations_disabled_reason().is_none()
    }

    pub(crate) fn background_mutation_executor(
        &self,
    ) -> std::io::Result<BackgroundMutationExecutor> {
        self.background_mutation_executor.clone().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "background configuration executor is unavailable",
            )
        })
    }

    pub(crate) fn reject_background_mutation_submission(
        &mut self,
        authoritative_local_sync_required: bool,
        refresh_passwords_required: bool,
    ) {
        // The rejected task has already been dropped, so its BeginPending
        // guard cannot perform any IPC or durable work. Never retry through a
        // broken/full executor: revert optimistic state and disable further
        // mutations until restart.
        self.background_mutation_executor = None;
        self.active_settings_mutation = None;

        let local_release_succeeded = if self.settings_window_mode {
            true
        } else if authoritative_local_sync_required {
            // A predecessor in this same pause lease already committed. Rawly
            // opening the latch would resume the stale worker configuration;
            // apply the authoritative config and release the exact epoch as
            // one worker command instead.
            self.sync_background_saved_config_to_local_worker(refresh_passwords_required)
        } else {
            let Some(pause_epoch) = self.active_local_config_mutation_pause_epoch.take() else {
                self.fail_local_config_release(
                    "The rejected background mutation had no local pause lease to release.",
                );
                return;
            };
            let Some(_start_monitor) = self.active_local_config_mutation_start_monitor.take()
            else {
                self.fail_local_config_release(
                    "The rejected background mutation had no desired monitor state to release.",
                );
                return;
            };
            if self.worker_pause_latch.resume_if_epoch(pause_epoch) {
                true
            } else {
                self.fail_local_config_release(
                    "The rejected background mutation could not release its exact local pause epoch.",
                );
                false
            }
        };

        if local_release_succeeded && self.settings_save_fail_closed_reason().is_none() {
            self.set_settings_changes_blocked_reason(Some(
                BACKGROUND_MUTATION_EXECUTOR_UNAVAILABLE_REASON.to_string(),
            ));
        }
    }

    pub(crate) fn config_mutations_disabled_reason(&self) -> Option<&str> {
        self.window_closing_mutations_disabled_reason()
            .or_else(|| self.settings_save_fail_closed_reason())
    }

    /// Settings checkboxes are coalescible while a background save is active.
    /// Only a fail-closed, recovery, or already-closing state makes them
    /// unavailable.
    pub(crate) fn settings_mutations_disabled_reason(&self) -> Option<&str> {
        self.window_closing_mutations_disabled_reason()
            .or_else(|| self.settings_save_fail_closed_reason())
    }

    fn window_closing_mutations_disabled_reason(&self) -> Option<&str> {
        if self.quit_requested
            || (self.settings_window_mode
                && (self.close_settings_window_after_sync
                    || self.close_settings_window_after_pending_save))
        {
            return Some(SETTINGS_WINDOW_CLOSING_REASON);
        }
        None
    }

    pub(crate) fn settings_save_fail_closed_reason(&self) -> Option<&str> {
        if let Some(reason) = self.settings_changes_blocked_reason.as_deref() {
            return Some(reason);
        }
        if self.storage_recovery_blocked {
            return Some(CONFIG_MUTATION_RECOVERY_REASON);
        }
        None
    }

    pub(crate) fn settings_save_in_progress(&self) -> bool {
        self.pending_settings_save.is_some()
            || self.pending_account_toggle.is_some()
            || !self.queued_account_toggles.is_empty()
            || self.pending_account_transaction.is_some()
            || !self.queued_account_transactions.is_empty()
            || self.pending_storage_recovery_signal.is_some()
            || self.storage_recovery_signal_retry_at.is_some()
    }

    pub(crate) fn account_toggle_in_progress(&self) -> bool {
        self.pending_account_toggle.is_some()
            || !self.queued_account_toggles.is_empty()
            || self.pending_account_transaction.is_some()
            || !self.queued_account_transactions.is_empty()
    }

    pub(crate) fn account_transaction_ready(&self) -> bool {
        // Save/Delete clicks are accepted while another durable mutation is
        // active and are serialized by the background account transaction
        // queue. Only a genuine fail-closed/recovery/closing state makes the
        // controls unavailable.
        self.config_mutations_disabled_reason().is_none()
    }

    pub(crate) fn set_settings_changes_blocked_reason(&mut self, reason: Option<String>) {
        if reason.is_some() {
            // Every blocked state is terminal for the active local mutation.
            // Discard its desired-start intent together with the epoch so no
            // later completion can revive a fail-closed monitor.
            self.active_local_config_mutation_pause_epoch = None;
            self.active_local_config_mutation_start_monitor = None;
        }
        self.settings_changes_blocked_reason = reason;
    }

    pub(crate) fn settings_window_mode(&self) -> bool {
        self.settings_window_mode
    }

    pub(crate) fn keep_window_open_for_pending_settings_save(&mut self, ctx: &egui::Context) {
        if self.settings_save_in_progress() && ctx.input(|input| input.viewport().close_requested())
        {
            // `present_tab` already cancelled this delivered Close and made
            // the existing child visible/focused. Do not reinterpret the same
            // raw event later in the pass as a fresh manual close request.
            if self.keep_settings_window_open_through_ui_pass {
                return;
            }
            if self.settings_window_mode && !self.quit_requested {
                self.close_settings_window_after_pending_save = true;
            }
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
        }
    }

    fn automation_start_ready(&self) -> bool {
        !self.storage_recovery_blocked && !self.worker_pause_latch.is_paused()
    }

    fn add_log(&mut self, entry: LogEntry) {
        push_bounded_log(&mut self.logs, entry);
    }

    pub(crate) fn set_status(&mut self, msg: impl Into<String>) {
        self.account_toggle_failure_status_sequence = None;
        self.status_message = Some((msg.into(), 3.0));
    }

    fn append_status_warning(&mut self, warning: impl Into<String>) {
        let warning = warning.into();
        let (message, remaining) = match self.status_message.take() {
            Some((existing, remaining)) if !existing.trim().is_empty() => {
                let existing = existing.trim_end();
                let separator = match existing.chars().last() {
                    Some('.' | '!' | '?') => " ",
                    _ => ". ",
                };
                (
                    format!("{existing}{separator}{warning}"),
                    remaining.max(8.0),
                )
            }
            _ => (warning, 8.0),
        };
        self.status_message = Some((message, remaining));
    }

    #[cfg(test)]
    fn begin_settings_mutation_with<B, C>(
        &mut self,
        begin: B,
        cancel: C,
    ) -> Option<SettingsMutationGuard>
    where
        B: FnOnce() -> anyhow::Result<()>,
        C: FnOnce() -> anyhow::Result<()> + Send + 'static,
    {
        let cancel = self
            .settings_window_mode
            .then(|| Box::new(cancel) as Box<dyn FnOnce() -> anyhow::Result<()> + Send>);
        let mut guard = self.reserve_settings_mutation(cancel)?;
        if self.settings_window_mode {
            if let Err(error) = begin() {
                guard.finish_unacknowledged_begin();
                self.append_status_warning(format!(
                    "The monitor could not pause safely before saving: {error}. Restart the app before trying again."
                ));
                return None;
            }
        }
        guard.mark_begin_acknowledged();
        Some(guard)
    }

    pub(crate) fn reserve_background_settings_mutation(&mut self) -> Option<SettingsMutationGuard> {
        let cancel = self.settings_window_mode.then(|| {
            Box::new(single_instance::request_settings_mutation_cancel)
                as Box<dyn FnOnce() -> anyhow::Result<()> + Send>
        });
        self.reserve_settings_mutation(cancel)
    }

    /// Reserves the begin operation for a background settings/account job.
    /// In local mode this synchronously closes the latch exactly once for the
    /// entire coalesced chain. Successors receive handles for the same epoch.
    pub(crate) fn prepare_background_settings_mutation_begin(
        &mut self,
    ) -> BackgroundSettingsMutationBegin {
        if self.settings_window_mode {
            return BackgroundSettingsMutationBegin::Supervisor;
        }

        let pause_epoch = match self.active_local_config_mutation_pause_epoch {
            Some(pause_epoch) => {
                debug_assert!(self.active_local_config_mutation_start_monitor.is_some());
                pause_epoch
            }
            None => {
                // Preserve the user's desired running state before the worker
                // observes the pause and reports its incidental Idle state.
                // Every successor in this coalesced mutation chain reuses the
                // same intent together with the same exact pause epoch.
                let start_monitor = self.worker_status == WorkerStatus::Running;
                let pause_epoch = self.worker_pause_latch.pause_with_epoch();
                self.active_local_config_mutation_pause_epoch = Some(pause_epoch);
                self.active_local_config_mutation_start_monitor = Some(start_monitor);
                pause_epoch
            }
        };
        BackgroundSettingsMutationBegin::Local {
            worker_tx: self.worker_tx.clone(),
            worker_pause_latch: self.worker_pause_latch.clone(),
            pause_epoch,
        }
    }

    #[cfg(test)]
    pub(crate) fn reserve_background_settings_mutation_with_cancel(
        &mut self,
        cancel: impl FnOnce() -> anyhow::Result<()> + Send + 'static,
    ) -> Option<SettingsMutationGuard> {
        self.reserve_settings_mutation(Some(Box::new(cancel)))
    }

    fn reserve_settings_mutation(
        &mut self,
        cancel: Option<Box<dyn FnOnce() -> anyhow::Result<()> + Send>>,
    ) -> Option<SettingsMutationGuard> {
        if self.pending_settings_save.is_some()
            || self.pending_account_toggle.is_some()
            || self.pending_account_transaction.is_some()
            || self.settings_changes_blocked_reason.is_some()
            || self
                .active_settings_mutation
                .as_ref()
                .and_then(Weak::upgrade)
                .is_some_and(|phase| {
                    phase.load(Ordering::Acquire) != SettingsMutationPhase::Finished as u8
                })
        {
            self.append_status_warning("A settings save is already in progress.");
            return None;
        }

        let phase = Arc::new(AtomicU8::new(SettingsMutationPhase::BeginPending as u8));
        self.active_settings_mutation = Some(Arc::downgrade(&phase));
        Some(SettingsMutationGuard { phase, cancel })
    }

    fn mark_settings_mutation_commit_started(&mut self) {
        if let Some(phase) = self
            .active_settings_mutation
            .as_ref()
            .and_then(Weak::upgrade)
        {
            let _ = phase.compare_exchange(
                SettingsMutationPhase::Abortable as u8,
                SettingsMutationPhase::FailClosed as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
        }
    }

    pub(crate) fn send_worker_command(&mut self, cmd: WorkerCommand) {
        if self.settings_window_mode {
            return;
        }
        if matches!(cmd, WorkerCommand::Start) && !self.automation_start_ready() {
            self.worker_status = WorkerStatus::Idle;
            self.set_status(
                "Monitor remains stopped until password storage recovery completes after restart.",
            );
            return;
        }
        if let Err(e) = self.worker_tx.try_send(cmd) {
            self.set_status(format!("Monitor command failed: {}", e));
        }
    }

    #[cfg(any(test, not(target_os = "macos")))]
    pub(crate) fn sync_saved_config_to_worker(&mut self, refresh_passwords: bool) -> bool {
        self.sync_saved_config_to_worker_with_window_policy(refresh_passwords, false)
    }

    pub(crate) fn sync_background_saved_config_to_local_worker(
        &mut self,
        refresh_passwords: bool,
    ) -> bool {
        self.sync_background_saved_config_to_local_worker_with_recovery_state(
            refresh_passwords,
            !self.storage_recovery_blocked,
        )
    }

    fn sync_background_saved_config_to_local_worker_with_recovery_state(
        &mut self,
        refresh_passwords: bool,
        storage_recovery_is_clear: bool,
    ) -> bool {
        if self.settings_window_mode {
            return true;
        }
        self.mark_settings_mutation_commit_started();
        if !self.prepare_config_sync(storage_recovery_is_clear) {
            self.active_local_config_mutation_pause_epoch = None;
            self.active_local_config_mutation_start_monitor = None;
            self.append_status_warning(
                "Password storage recovery could not be verified. Auto-login will stay stopped until restart.",
            );
            self.stop_monitor_for_pending_storage_recovery();
            return false;
        }

        let Some(pause_epoch) = self.active_local_config_mutation_pause_epoch.take() else {
            self.fail_local_config_release(
                "The local configuration mutation pause lease was missing at final release.",
            );
            return false;
        };
        let Some(start_monitor) = self.active_local_config_mutation_start_monitor.take() else {
            self.fail_local_config_release(
                "The local configuration mutation pause lease had no desired monitor state.",
            );
            return false;
        };
        if let Err(error) = ensure_local_pause_epoch(&self.worker_pause_latch, pause_epoch) {
            self.fail_local_config_release(format!(
                "The saved configuration could not release its original monitor pause: {error}"
            ));
            return false;
        }

        let apply_command = self.worker_pause_latch.apply_config_command(
            pause_epoch,
            self.config.settings.clone(),
            self.config.accounts.clone(),
            refresh_passwords,
            start_monitor,
        );
        if let Err(error) = self.worker_tx.try_send(apply_command) {
            self.fail_local_config_release(format!(
                "The saved configuration could not be queued for the monitor: {error}"
            ));
            return false;
        }
        true
    }

    fn fail_local_config_release(&mut self, detail: impl Into<String>) {
        tracing::warn!(detail = %detail.into(), "The local monitor remains paused after a configuration mutation");
        self.active_local_config_mutation_pause_epoch = None;
        self.active_local_config_mutation_start_monitor = None;
        self.worker_status = WorkerStatus::Idle;
        self.set_settings_changes_blocked_reason(Some(
            LOCAL_CONFIG_RELEASE_FAILED_REASON.to_string(),
        ));
        self.append_status_warning(
            "The monitor could not reload the saved configuration safely. Restart the app before changing settings again.",
        );
    }

    #[cfg(any(test, not(target_os = "macos")))]
    fn sync_saved_config_to_worker_with_window_policy(
        &mut self,
        refresh_passwords: bool,
        close_settings_window_after_sync: bool,
    ) -> bool {
        self.sync_saved_config_to_worker_with(
            refresh_passwords,
            close_settings_window_after_sync,
            !self.storage_recovery_blocked,
            single_instance::request_config_reload,
        )
    }

    #[cfg(any(test, not(target_os = "macos")))]
    fn sync_saved_config_to_worker_with<R>(
        &mut self,
        refresh_passwords: bool,
        close_settings_window_after_sync: bool,
        storage_recovery_is_clear: bool,
        request_config_reload: R,
    ) -> bool
    where
        R: FnOnce() -> anyhow::Result<()>,
    {
        // Every caller reaches this point only after its durable mutation has
        // committed. Disarm Drop-cancel before any reload delivery attempt so
        // an ACK timeout can never resume the supervisor's stale config.
        self.mark_settings_mutation_commit_started();
        if !self.prepare_config_sync(storage_recovery_is_clear) {
            self.append_status_warning(
                "Password storage recovery could not be verified. Auto-login will stay stopped until restart.",
            );
            self.stop_monitor_for_pending_storage_recovery();
            return false;
        }
        if self.settings_window_mode {
            if let Err(e) = request_config_reload() {
                self.append_status_warning(format!(
                    "The supervisor could not reload the saved changes: {e}"
                ));
            } else {
                // The supervisor keeps automation quiesced only for the
                // acknowledged mutation. Close only after the durable mutation
                // is clean and its reload request was accepted.
                // An explicit presentation in this same app pass wins over a
                // Save click processed later by the UI. Otherwise the child
                // could acknowledge Focus and then immediately re-arm Close.
                self.close_settings_window_after_sync = close_settings_window_after_sync
                    && !self.keep_settings_window_open_through_ui_pass;
                return true;
            }
            return false;
        }

        let start_monitor = self.worker_status == WorkerStatus::Running;
        let pause_epoch = self.worker_pause_latch.pause_with_epoch();
        let apply_command = self.worker_pause_latch.apply_config_command(
            pause_epoch,
            self.config.settings.clone(),
            self.config.accounts.clone(),
            refresh_passwords,
            start_monitor,
        );
        if let Err(e) = self.worker_tx.try_send(apply_command) {
            self.worker_status = WorkerStatus::Idle;
            self.set_status(format!(
                "Saved, but monitor was stopped because it could not reload safely: {e}"
            ));
            return false;
        }
        true
    }

    fn prepare_config_sync(&mut self, storage_recovery_is_clear: bool) -> bool {
        // A later failed or recovery-blocked mutation must never inherit a
        // close scheduled by an earlier request in the same UI frame.
        self.close_settings_window_after_sync = false;
        !self.storage_recovery_blocked && storage_recovery_is_clear
    }

    pub(crate) fn stop_monitor_for_pending_storage_recovery(&mut self) {
        // Sticky for this UI process. A failed journal unlink/directory fsync
        // can make the pathname temporarily disappear even though power loss
        // may restore it, so only a fresh startup recovery may clear this gate.
        self.mark_settings_mutation_commit_started();
        self.storage_recovery_blocked = true;
        self.active_local_config_mutation_pause_epoch = None;
        self.active_local_config_mutation_start_monitor = None;
        self.close_settings_window_after_sync = false;
        self.worker_pause_latch.pause();
        self.worker_status = WorkerStatus::Idle;
        #[cfg(not(test))]
        {
            if let Err(error) = crate::storage::mark_storage_recovery_blocked() {
                tracing::error!(
                    error = %error,
                    "Password storage recovery block could not be persisted; process-local pause remains active"
                );
            }
        }
        if self.settings_window_mode {
            if let Err(stop_error) = single_instance::request_monitor_command(
                MonitorControlCommand::StorageRecoveryBlocked,
            ) {
                tracing::error!(
                    error = %stop_error,
                    "Password storage recovery is pending, but the supervisor recovery-block request failed"
                );
            }
            return;
        }
        if let Err(e) = self.worker_tx.try_send(WorkerCommand::Stop) {
            tracing::error!(
                error = %e,
                "Password storage recovery is pending, but the local monitor stop could not be queued"
            );
        }
    }

    /// Applies recovery state already persisted and, for a settings child,
    /// already delivered to the supervisor by a background settings job.
    /// This owner-thread step performs no filesystem work or blocking IPC.
    pub(crate) fn apply_background_storage_recovery_block(&mut self) {
        self.mark_settings_mutation_commit_started();
        self.storage_recovery_blocked = true;
        self.active_local_config_mutation_pause_epoch = None;
        self.active_local_config_mutation_start_monitor = None;
        self.close_settings_window_after_sync = false;
        self.worker_pause_latch.pause();
        self.worker_status = WorkerStatus::Idle;
        if self.settings_window_mode {
            return;
        }
        if let Err(error) = self.worker_tx.try_send(WorkerCommand::Stop) {
            tracing::error!(
                %error,
                "Password storage recovery is pending, but the local monitor stop could not be queued"
            );
        }
    }

    /// Fail-closed fallback for a background mutation whose result can no
    /// longer be trusted. The owner thread applies the process-local pause
    /// immediately, while persistence and supervisor IPC stay off the UI
    /// thread. The receiver remains tracked so close/quit cannot terminate the
    /// child in the middle of establishing the durable recovery block. If the
    /// release process aborts before this worker can report, the supervisor's
    /// active-mutation-at-child-exit check establishes the same sticky block.
    pub(crate) fn start_background_storage_recovery_signal(&mut self, ctx: &egui::Context) {
        let settings_window_mode = self.settings_window_mode;
        self.start_background_storage_recovery_signal_with(ctx, move || {
            let persist_result = crate::storage::mark_storage_recovery_blocked();
            let signal_result = if settings_window_mode {
                single_instance::request_monitor_command(
                    MonitorControlCommand::StorageRecoveryBlocked,
                )
            } else {
                Ok(())
            };
            persist_result.and(signal_result)
        });
    }

    fn start_background_storage_recovery_signal_with<J>(&mut self, ctx: &egui::Context, job: J)
    where
        J: FnOnce() -> anyhow::Result<()> + Send + 'static,
    {
        self.apply_background_storage_recovery_block();
        if self.pending_storage_recovery_signal.is_some() {
            ctx.request_repaint_after(Duration::from_millis(50));
            return;
        }
        self.storage_recovery_signal_retry_at = None;

        let executor = match self.background_mutation_executor() {
            Ok(executor) => executor,
            Err(error) => {
                tracing::error!(%error, "Could not queue the background storage recovery signal");
                self.storage_recovery_signal_retry_at =
                    Some(Instant::now() + STORAGE_RECOVERY_SIGNAL_RETRY_INTERVAL);
                ctx.request_repaint_after(STORAGE_RECOVERY_SIGNAL_RETRY_INTERVAL);
                return;
            }
        };
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let repaint = ctx.clone();
        match executor.try_submit(move || {
            let result = job().map_err(|error| error.to_string());
            let _ = sender.try_send(result);
            repaint.request_repaint();
        }) {
            Ok(_) => {
                self.pending_storage_recovery_signal = Some(receiver);
                ctx.request_repaint_after(Duration::from_millis(50));
            }
            Err(error) => {
                tracing::error!(%error, "Could not queue the background storage recovery signal");
                self.storage_recovery_signal_retry_at =
                    Some(Instant::now() + STORAGE_RECOVERY_SIGNAL_RETRY_INTERVAL);
                ctx.request_repaint_after(STORAGE_RECOVERY_SIGNAL_RETRY_INTERVAL);
            }
        }
    }

    fn poll_background_storage_recovery_signal(&mut self, ctx: &egui::Context) {
        if self.pending_storage_recovery_signal.is_none() {
            let Some(retry_at) = self.storage_recovery_signal_retry_at else {
                return;
            };
            let now = Instant::now();
            if now < retry_at {
                ctx.request_repaint_after(retry_at.saturating_duration_since(now));
                return;
            }
            self.storage_recovery_signal_retry_at = None;
            self.start_background_storage_recovery_signal(ctx);
            return;
        }

        let result = match self
            .pending_storage_recovery_signal
            .as_ref()
            .map(|receiver| receiver.try_recv())
        {
            None => return,
            Some(Err(std::sync::mpsc::TryRecvError::Empty)) => {
                ctx.request_repaint_after(Duration::from_millis(50));
                return;
            }
            Some(Err(std::sync::mpsc::TryRecvError::Disconnected)) => None,
            Some(Ok(result)) => Some(result),
        };
        self.pending_storage_recovery_signal = None;

        match result {
            Some(Ok(())) => {
                self.storage_recovery_signal_retry_at = None;
            }
            Some(Err(error)) => {
                tracing::error!(%error, "The background storage recovery signal failed");
                self.storage_recovery_signal_retry_at =
                    Some(Instant::now() + STORAGE_RECOVERY_SIGNAL_RETRY_INTERVAL);
                ctx.request_repaint_after(STORAGE_RECOVERY_SIGNAL_RETRY_INTERVAL);
            }
            None => {
                tracing::error!("The background storage recovery signal disconnected");
                self.storage_recovery_signal_retry_at =
                    Some(Instant::now() + STORAGE_RECOVERY_SIGNAL_RETRY_INTERVAL);
                ctx.request_repaint_after(STORAGE_RECOVERY_SIGNAL_RETRY_INTERVAL);
            }
        }
    }

    fn send_local_monitor_control_command(&mut self, command: MonitorControlCommand) {
        if command == MonitorControlCommand::Start && !self.automation_start_ready() {
            self.worker_status = WorkerStatus::Idle;
            self.set_status(
                "Monitor remains stopped until password storage recovery completes after restart.",
            );
            return;
        }
        if self.settings_window_mode {
            tracing::error!(
                ?command,
                "Rejected a synchronous monitor control request from the settings window"
            );
            self.set_status("Monitor command could not be queued. Restart the app to try again.");
            return;
        }

        match command {
            MonitorControlCommand::Start => self.send_worker_command(WorkerCommand::Start),
            MonitorControlCommand::Stop => self.send_worker_command(WorkerCommand::Stop),
            MonitorControlCommand::StorageRecoveryBlocked => {
                self.stop_monitor_for_pending_storage_recovery()
            }
            #[cfg(not(target_os = "macos"))]
            MonitorControlCommand::ReloadConfig => {
                self.sync_saved_config_to_worker(true);
            }
        }
    }

    fn next_monitor_control_intent(
        &mut self,
        command: MonitorControlCommand,
    ) -> MonitorControlIntent {
        self.next_monitor_control_intent_sequence =
            self.next_monitor_control_intent_sequence.wrapping_add(1);
        if self.next_monitor_control_intent_sequence == 0 {
            self.next_monitor_control_intent_sequence = 1;
        }
        MonitorControlIntent {
            sequence: self.next_monitor_control_intent_sequence,
            command,
        }
    }

    fn queue_background_monitor_control(
        &mut self,
        ctx: &egui::Context,
        command: MonitorControlCommand,
    ) {
        debug_assert!(matches!(
            command,
            MonitorControlCommand::Start | MonitorControlCommand::Stop
        ));
        if command == MonitorControlCommand::Start && !self.automation_start_ready() {
            self.bridged_monitor_control_state = MonitorControlState::Stopped;
            self.worker_status = WorkerStatus::Idle;
            self.set_status(
                "Monitor remains stopped until password storage recovery completes after restart.",
            );
            return;
        }

        let intent = self.next_monitor_control_intent(command);
        if let Some(pending) = self.pending_monitor_control.as_mut() {
            // The active IPC request cannot be cancelled after it is written.
            // Keep only the latest desired state; its successor is submitted
            // after the active acknowledgement reaches a terminal result.
            pending.latest_intent = intent;
            pending.projected_state = intent.projected_state();
            ctx.request_repaint();
            return;
        }

        let _ = self.start_background_monitor_control_intent(ctx, intent);
    }

    fn start_background_monitor_control_intent(
        &mut self,
        ctx: &egui::Context,
        intent: MonitorControlIntent,
    ) -> bool {
        let executor = self.monitor_control_executor.clone();
        self.start_background_monitor_control_intent_with(ctx, intent, move |job, repaint| {
            let executor = executor.ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "background monitor control executor is unavailable",
                )
            })?;
            submit_monitor_control_worker(executor, job, repaint)
        })
    }

    fn start_background_monitor_control_intent_with<S>(
        &mut self,
        ctx: &egui::Context,
        intent: MonitorControlIntent,
        spawn_worker: S,
    ) -> bool
    where
        S: FnOnce(
            Box<dyn FnOnce() -> MonitorControlCompletion + Send>,
            egui::Context,
        ) -> std::io::Result<std::sync::mpsc::Receiver<MonitorControlCompletion>>,
    {
        if self.pending_monitor_control.is_some() {
            return false;
        }
        let repaint = ctx.clone();
        let receiver = match spawn_worker(
            Box::new(move || {
                run_monitor_control_request(intent, single_instance::request_monitor_command)
            }),
            repaint,
        ) {
            Ok(receiver) => receiver,
            Err(error) => {
                tracing::warn!(%error, "Could not submit the background monitor control request");
                self.set_status(
                    "Monitor command could not be queued. Restart the app to try again.",
                );
                ctx.request_repaint();
                return false;
            }
        };

        self.pending_monitor_control = Some(PendingMonitorControl {
            receiver,
            active_intent: intent,
            latest_intent: intent,
            projected_state: intent.projected_state(),
        });
        ctx.request_repaint();
        true
    }

    fn poll_background_monitor_control(&mut self, ctx: &egui::Context) {
        self.poll_background_monitor_control_with(
            ctx,
            AutoLoginApp::start_background_monitor_control_intent,
        );
    }

    fn poll_background_monitor_control_with<S>(&mut self, ctx: &egui::Context, start_successor: S)
    where
        S: FnMut(&mut AutoLoginApp, &egui::Context, MonitorControlIntent) -> bool,
    {
        self.poll_background_monitor_control_at_with(ctx, Instant::now(), start_successor);
    }

    fn poll_background_monitor_control_at_with<S>(
        &mut self,
        ctx: &egui::Context,
        now: Instant,
        mut start_successor: S,
    ) where
        S: FnMut(&mut AutoLoginApp, &egui::Context, MonitorControlIntent) -> bool,
    {
        if self.pending_monitor_control.is_none() {
            let next_retry_at = self
                .monitor_safety_stop_recovery
                .as_ref()
                .and_then(|recovery| recovery.next_retry_at);
            if let Some(next_retry_at) = next_retry_at {
                let retry_wait = next_retry_at.saturating_duration_since(now);
                if !retry_wait.is_zero() {
                    ctx.request_repaint_after(retry_wait);
                    return;
                }
                if let Some(recovery) = self.monitor_safety_stop_recovery.as_mut() {
                    recovery.next_retry_at = None;
                }
                let retry_intent = self.next_monitor_control_intent(MonitorControlCommand::Stop);
                if !start_successor(self, ctx, retry_intent) {
                    self.schedule_monitor_safety_stop_retry(ctx, now);
                    return;
                }
            }
        }

        let completion = match self
            .pending_monitor_control
            .as_ref()
            .map(|pending| pending.receiver.try_recv())
        {
            None => return,
            Some(Err(std::sync::mpsc::TryRecvError::Empty)) => {
                ctx.request_repaint_after(MONITOR_CONTROL_COMPLETION_POLL_INTERVAL);
                return;
            }
            Some(Err(std::sync::mpsc::TryRecvError::Disconnected)) => None,
            Some(Ok(completion)) => Some(completion),
        };
        let pending = self
            .pending_monitor_control
            .take()
            .expect("a completed monitor control request must still be pending");

        let Some(completion) = completion else {
            self.apply_ambiguous_monitor_control_result(
                "the background monitor control request disconnected".to_string(),
                Some("the safety stop could not be submitted".to_string()),
            );
            self.schedule_monitor_safety_stop_retry(ctx, now);
            return;
        };

        match completion {
            MonitorControlCompletion::Acknowledged(intent) if intent == pending.active_intent => {
                self.apply_acknowledged_monitor_command(intent.command);
                if pending.latest_intent.sequence > intent.sequence
                    && pending.latest_intent.command != intent.command
                {
                    let successor = pending.latest_intent;
                    if !start_successor(self, ctx, successor)
                        && successor.command == MonitorControlCommand::Stop
                    {
                        self.schedule_monitor_safety_stop_retry(ctx, now);
                    }
                }
            }
            MonitorControlCompletion::Acknowledged(intent) => {
                tracing::error!(
                    expected_sequence = pending.active_intent.sequence,
                    received_sequence = intent.sequence,
                    "Monitor control completion did not match its active request"
                );
                self.apply_ambiguous_monitor_control_result(
                    "monitor control completion mismatch".to_string(),
                    Some("the safety stop was not confirmed".to_string()),
                );
                self.schedule_monitor_safety_stop_retry(ctx, now);
            }
            MonitorControlCompletion::Ambiguous {
                intent,
                error,
                safety_stop_error,
            } if intent == pending.active_intent => {
                let safety_stop_failed = safety_stop_error.is_some();
                self.apply_ambiguous_monitor_control_result(error, safety_stop_error);
                // A queued Start is deliberately discarded: after an ambiguous
                // acknowledgement only a confirmed Stop may expose Start again.
                // A newer explicit Stop may be submitted immediately; otherwise
                // the automatic bounded-backoff retry starts on a later pass.
                if safety_stop_failed
                    && pending.latest_intent.sequence > intent.sequence
                    && pending.latest_intent.command == MonitorControlCommand::Stop
                {
                    self.ensure_monitor_safety_stop_recovery();
                    if !start_successor(self, ctx, pending.latest_intent) {
                        self.schedule_monitor_safety_stop_retry(ctx, now);
                    }
                } else if safety_stop_failed {
                    self.schedule_monitor_safety_stop_retry(ctx, now);
                }
            }
            MonitorControlCompletion::Ambiguous {
                error,
                safety_stop_error,
                ..
            } => {
                let safety_stop_failed = safety_stop_error.is_some();
                self.apply_ambiguous_monitor_control_result(error, safety_stop_error);
                if safety_stop_failed {
                    self.schedule_monitor_safety_stop_retry(ctx, now);
                }
            }
        }
        ctx.request_repaint();
    }

    fn ensure_monitor_safety_stop_recovery(&mut self) {
        self.monitor_safety_stop_recovery
            .get_or_insert(MonitorSafetyStopRecovery {
                next_retry_at: None,
                next_backoff: MONITOR_CONTROL_SAFETY_STOP_RETRY_INITIAL_INTERVAL,
            });
    }

    fn schedule_monitor_safety_stop_retry(&mut self, ctx: &egui::Context, now: Instant) {
        self.ensure_monitor_safety_stop_recovery();
        let recovery = self
            .monitor_safety_stop_recovery
            .as_mut()
            .expect("safety Stop recovery must exist before scheduling a retry");
        if let Some(next_retry_at) = recovery.next_retry_at {
            ctx.request_repaint_after(next_retry_at.saturating_duration_since(now));
            return;
        }

        let retry_delay = recovery
            .next_backoff
            .min(MONITOR_CONTROL_SAFETY_STOP_RETRY_MAX_INTERVAL);
        recovery.next_retry_at = Some(now.checked_add(retry_delay).unwrap_or(now));
        recovery.next_backoff = retry_delay
            .saturating_mul(2)
            .min(MONITOR_CONTROL_SAFETY_STOP_RETRY_MAX_INTERVAL);
        ctx.request_repaint_after(retry_delay);
    }

    fn apply_ambiguous_monitor_control_result(
        &mut self,
        error: String,
        safety_stop_error: Option<String>,
    ) {
        if let Some(poller) = &self.bridged_ui_status_poller {
            poller.invalidate_in_flight_snapshot();
        }
        tracing::warn!(%error, ?safety_stop_error, "Monitor control acknowledgement was ambiguous");
        if safety_stop_error.is_none() {
            self.monitor_safety_stop_recovery = None;
            self.bridged_monitor_control_state = MonitorControlState::Stopped;
            self.worker_status = WorkerStatus::Idle;
            self.set_status(
                "Monitor command was not acknowledged. The monitor was stopped safely.",
            );
        } else {
            // Do not expose Start while the supervisor may still be running.
            // The next fresh status snapshot can prove Stopped; until then the
            // only available toggle action remains Stop.
            self.bridged_monitor_control_state = MonitorControlState::PausedWithStartIntent;
            self.worker_status = WorkerStatus::Idle;
            self.set_status(
                "Monitor command was not acknowledged, and a safety stop could not be confirmed. Try Stop Monitor again.",
            );
        }
    }

    fn toggle_monitor_from_ui(&mut self, ctx: &egui::Context) {
        let command = monitor_control_command(self.monitor_control_state());
        if command == MonitorControlCommand::Start && !self.accessibility_ready() {
            self.block_for_accessibility("starting the monitor");
        } else if self.settings_window_mode {
            self.queue_background_monitor_control(ctx, command);
        } else {
            self.send_local_monitor_control_command(command);
        }
    }

    pub(crate) fn accessibility_ready(&self) -> bool {
        self.accessibility_status.trusted
    }

    fn log_accessibility_event(&mut self, event: &str, level: LogLevel) {
        let status = &self.accessibility_status;
        self.add_log(LogEntry {
            timestamp: chrono::Local::now().format("%H:%M:%S").to_string(),
            level,
            message: accessibility_log_message(event, status),
        });
    }

    fn block_for_accessibility(&mut self, action: &str) {
        self.log_accessibility_event("accessibility_still_missing", LogLevel::Warn);
        self.status_message = Some((
            format!("Accessibility permission is required before {action}"),
            6.0,
        ));
        self.selected_tab = Tab::Accounts;
    }

    pub(crate) fn request_accessibility_access(&mut self) {
        self.log_accessibility_event("accessibility_prompt_requested", LogLevel::Info);
        // Prompting is only a request to macOS. Make every decision from one
        // complete status snapshot taken after that request; combining two
        // point-in-time booleans could otherwise report a grant that no longer
        // exists.
        let _ = request_accessibility_access_prompt();
        if !self.apply_accessibility_granted_status(accessibility_status()) {
            self.log_accessibility_event("accessibility_still_missing", LogLevel::Warn);
            self.status_message = Some((
                "macOS did not grant Accessibility yet. Enable this exact app in System Settings."
                    .to_string(),
                8.0,
            ));
        }
    }

    pub(crate) fn open_accessibility_settings(&mut self) {
        self.log_accessibility_event("accessibility_settings_opened", LogLevel::Info);
        if let Err(e) = open_accessibility_settings() {
            self.set_status(format!("Could not open Accessibility settings: {e}"));
        }
    }

    fn apply_accessibility_granted_status(&mut self, status: AccessibilityStatus) -> bool {
        let status = fail_closed_accessibility_status(status);
        self.accessibility_status = status;
        if !self.accessibility_status.trusted {
            return false;
        }

        self.accessibility_last_missing_log = None;
        self.log_accessibility_event("accessibility_granted", LogLevel::Info);
        if self.settings_window_mode {
            // The supervisor owns desired monitor intent. Its independent
            // Accessibility poll will start only when no later explicit Stop
            // has cancelled that intent; a child must not resurrect it.
            self.status_message = Some(("Accessibility permission granted.".to_string(), 5.0));
        } else if self.worker_status == WorkerStatus::Idle {
            self.status_message = Some((
                "Accessibility permission granted. Starting monitor.".to_string(),
                5.0,
            ));
            self.send_local_monitor_control_command(MonitorControlCommand::Start);
        }
        true
    }

    fn apply_polled_accessibility_status(&mut self, status: AccessibilityStatus) {
        let previous = self.accessibility_status.trusted;
        let status = fail_closed_accessibility_status(status);
        if status.trusted {
            if !previous {
                let _ = self.apply_accessibility_granted_status(status);
            } else {
                self.accessibility_status = status;
            }
            return;
        }
        self.accessibility_status = status;

        if self.worker_status == WorkerStatus::Running {
            self.send_worker_command(WorkerCommand::Stop);
        }
        let should_log = previous
            || self
                .accessibility_last_missing_log
                .is_none_or(|logged| logged.elapsed() >= Duration::from_secs(30));
        if should_log {
            self.log_accessibility_event(
                if previous {
                    "accessibility_permission_lost"
                } else {
                    "accessibility_still_missing"
                },
                LogLevel::Warn,
            );
            self.accessibility_last_missing_log = Some(Instant::now());
        }
    }

    fn process_tray_commands(&mut self, ctx: &egui::Context) {
        while let Ok(cmd) = self.tray_rx.try_recv() {
            match cmd {
                TrayCommand::OpenAccounts => self.present_tab(ctx, Tab::Accounts, || {}),
                TrayCommand::OpenSettings => self.present_tab(ctx, Tab::Settings, || {}),
                TrayCommand::PresentAccounts(acknowledgement) => {
                    self.present_tab(ctx, Tab::Accounts, move || {
                        let _ = acknowledgement.send(());
                    });
                }
                TrayCommand::PresentSettings(acknowledgement) => {
                    self.present_tab(ctx, Tab::Settings, move || {
                        let _ = acknowledgement.send(());
                    });
                }
                TrayCommand::ToggleMonitor => self.toggle_monitor_from_ui(ctx),
                TrayCommand::RequestAccessibilityAccess => {
                    self.request_accessibility_access();
                }
                TrayCommand::OpenAccessibilitySettings => {
                    self.open_accessibility_settings();
                }
                TrayCommand::Exit => {
                    self.quit_requested = true;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            }
        }
    }

    fn present_tab(&mut self, ctx: &egui::Context, tab: Tab, acknowledge: impl FnOnce()) {
        // An explicit presentation request wins over a close that was
        // deferred from the previous UI pass. The control-reader receives its
        // acknowledgement only after this cancellation and all viewport
        // commands have been ordered in the same UI owner.
        self.close_settings_window_after_sync = false;
        self.close_settings_window_after_pending_save = false;
        self.keep_settings_window_open_through_ui_pass = true;
        self.selected_tab = tab;
        // `Close` is delivered as raw input on a later frame. Clearing the
        // deferred flag alone cannot cancel that already-delivered request;
        // eframe exits after the frame unless it sees `CancelClose`.
        if ctx.input(|input| input.viewport().close_requested()) {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
        }
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
        acknowledge();
    }

    fn process_worker_events(&mut self) {
        while let Ok(event) = self.worker_event_rx.try_recv() {
            match event {
                WorkerEvent::StatusChanged(status) => {
                    self.worker_status = status;
                }
                WorkerEvent::Log(entry) => {
                    self.add_log(entry);
                }
                WorkerEvent::FillAttemptReport(report) => {
                    self.last_fill_report = Some(report);
                }
            }
        }
    }

    fn monitor_control_state(&self) -> MonitorControlState {
        if self.settings_window_mode {
            if self.monitor_safety_stop_recovery.is_some() {
                return MonitorControlState::PausedWithStartIntent;
            }
            self.pending_monitor_control
                .as_ref()
                .map_or(self.bridged_monitor_control_state, |pending| {
                    pending.projected_state
                })
        } else {
            MonitorControlState::from_worker_and_intent(
                self.worker_status,
                self.worker_status == WorkerStatus::Running,
            )
        }
    }

    fn apply_acknowledged_monitor_command(&mut self, command: MonitorControlCommand) {
        // A snapshot may have been read before the supervisor acknowledged
        // this command but not yet consumed by egui. Keep that stale sample
        // from reverting the optimistic Start/Stop state on the next frame.
        if let Some(poller) = &self.bridged_ui_status_poller {
            poller.invalidate_in_flight_snapshot();
        }
        let state = match command {
            // The acknowledgement commits desired start intent. The worker
            // may still be paused briefly, so use the state whose button
            // semantics are already `Stop`; the background snapshot will
            // refine it to Running when appropriate.
            MonitorControlCommand::Start => MonitorControlState::PausedWithStartIntent,
            MonitorControlCommand::Stop | MonitorControlCommand::StorageRecoveryBlocked => {
                MonitorControlState::Stopped
            }
            #[cfg(not(target_os = "macos"))]
            MonitorControlCommand::ReloadConfig => self.bridged_monitor_control_state,
        };
        if command == MonitorControlCommand::Stop {
            self.monitor_safety_stop_recovery = None;
        }
        self.bridged_monitor_control_state = state;
        self.worker_status = state.worker_status();
    }

    fn poll_bridged_ui_status(&mut self, ctx: &egui::Context) {
        ctx.request_repaint_after(if self.bridged_ui_status_initialized {
            BRIDGED_UI_STATUS_POLL_INTERVAL
        } else {
            Duration::from_millis(25)
        });
        let Some(snapshot) = self
            .bridged_ui_status_poller
            .as_ref()
            .and_then(BridgedUiStatusPoller::take_latest)
        else {
            return;
        };
        if self.pending_monitor_control.is_none() {
            if let Some(state) = snapshot.monitor_control_state {
                self.bridged_monitor_control_state = state;
                self.worker_status = state.worker_status();
            }
        }
        self.apply_polled_accessibility_status(snapshot.accessibility_status);
        self.bridged_ui_status_initialized = true;
        #[cfg(feature = "diagnostics-ui")]
        if let Some(report) = snapshot.last_fill_report {
            let next_attempt = report.field("attempt_id");
            let current_attempt = self
                .last_fill_report
                .as_ref()
                .and_then(|report| report.field("attempt_id"));
            if next_attempt != current_attempt {
                self.last_fill_report = Some(report);
            }
        }
    }

    fn close_settings_window_after_successful_sync(&mut self, ctx: &egui::Context) {
        if self.settings_save_in_progress() {
            return;
        }
        // Drain both independent latches even when both are armed. A
        // short-circuiting `||` would leave the manual-close latch sticky
        // whenever the internal close policy was also true.
        let should_close = std::mem::take(&mut self.close_settings_window_after_sync)
            | std::mem::take(&mut self.close_settings_window_after_pending_save);
        if !self.settings_window_mode || !should_close {
            return;
        }
        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
    }

    fn close_after_quit_when_settings_saves_are_drained(&self, ctx: &egui::Context) {
        if self.quit_requested && !self.settings_save_in_progress() {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
    }
}

fn redact_sensitive_log_text(message: &str) -> String {
    redact_path_assignments(&redact_secret_assignments(&redact_email_addresses(message)))
}

fn accessibility_log_message(
    event: &str,
    status: &crate::autologin::AccessibilityStatus,
) -> String {
    format!(
        "{event} trusted={} raw_trusted={} identity_trusted={} current_process_path_redacted={} app_bundle_path_redacted={}",
        status.trusted,
        status.raw_trusted,
        status.identity_trusted,
        crate::user_paths::redacted_path(&status.current_process_path),
        crate::user_paths::redacted_path(&status.app_bundle_path)
    )
}

fn fail_closed_accessibility_status(mut status: AccessibilityStatus) -> AccessibilityStatus {
    // `trusted` is derived from the two lower-level checks in production, but
    // keep every state-application boundary defensive. An inconsistent or
    // partially populated snapshot must never unlock automation.
    status.trusted = status.trusted && status.raw_trusted && status.identity_trusted;
    status
}

fn redact_email_addresses(message: &str) -> String {
    let chars: Vec<char> = message.chars().collect();
    let mut out = String::new();
    let mut idx = 0;

    while idx < chars.len() {
        if chars[idx] == '@' {
            let mut start = idx;
            while start > 0 && is_email_char(chars[start - 1]) {
                start -= 1;
            }
            let mut end = idx + 1;
            while end < chars.len() && is_email_char(chars[end]) {
                end += 1;
            }

            let candidate: String = chars[start..end].iter().collect();
            if looks_like_email(&candidate) {
                let keep_chars = out.chars().count().saturating_sub(idx - start);
                out = out.chars().take(keep_chars).collect();
                out.push_str("[email]");
                idx = end;
                continue;
            }
        }

        out.push(chars[idx]);
        idx += 1;
    }

    out
}

fn redact_secret_assignments(message: &str) -> String {
    let chars: Vec<char> = message.chars().collect();
    let mut out = String::new();
    let mut idx = 0;

    while idx < chars.len() {
        if let Some((prefix, value_end)) = secret_assignment_at(&chars, idx) {
            out.push_str(&prefix);
            out.push_str("[redacted]");
            idx = value_end;
            continue;
        }

        out.push(chars[idx]);
        idx += 1;
    }

    out
}

fn redact_path_assignments(message: &str) -> String {
    let chars: Vec<char> = message.chars().collect();
    let mut out = String::new();
    let mut idx = 0;

    while idx < chars.len() {
        if let Some((prefix, value, value_end)) = path_assignment_at(&chars, idx) {
            out.push_str(&prefix);
            out.push_str(&crate::user_paths::redacted_path(&value));
            idx = value_end;
            continue;
        }

        out.push(chars[idx]);
        idx += 1;
    }

    out
}

fn path_assignment_at(chars: &[char], idx: usize) -> Option<(String, String, usize)> {
    if idx > 0 && (chars[idx - 1].is_ascii_alphanumeric() || chars[idx - 1] == '_') {
        return None;
    }

    let key_len = path_key_len_at(chars, idx)?;
    let mut cursor = idx + key_len;
    while cursor < chars.len() && chars[cursor].is_whitespace() {
        cursor += 1;
    }
    if cursor >= chars.len() || !matches!(chars[cursor], '=' | ':') {
        return None;
    }
    cursor += 1;
    while cursor < chars.len() && chars[cursor].is_whitespace() {
        cursor += 1;
    }
    if cursor >= chars.len() || value_delimiter(chars[cursor]) {
        return None;
    }

    let value_start = cursor;
    if chars[cursor] == '"' || chars[cursor] == char::from(39) {
        let quote = chars[cursor];
        cursor += 1;
        while cursor < chars.len() {
            let current = chars[cursor];
            cursor += 1;
            if current == quote {
                break;
            }
        }
    } else {
        while cursor < chars.len() && !path_value_delimiter_at(chars, cursor) {
            cursor += 1;
        }
    }

    Some((
        chars[idx..value_start].iter().collect(),
        chars[value_start..cursor]
            .iter()
            .collect::<String>()
            .trim_matches(['"', '\''])
            .trim()
            .to_string(),
        cursor,
    ))
}

fn path_value_delimiter_at(chars: &[char], idx: usize) -> bool {
    if matches!(chars[idx], ',' | ';') {
        return true;
    }
    if !chars[idx].is_whitespace() {
        return false;
    }

    let mut next = idx;
    while next < chars.len() && chars[next].is_whitespace() {
        next += 1;
    }
    if next >= chars.len() {
        return true;
    }

    assignment_starts_at(chars, next)
}

fn assignment_starts_at(chars: &[char], idx: usize) -> bool {
    if idx > 0 && (chars[idx - 1].is_ascii_alphanumeric() || chars[idx - 1] == '_') {
        return false;
    }

    let Some(key_len) = path_key_len_at(chars, idx).or_else(|| secret_key_len_at(chars, idx))
    else {
        return false;
    };
    let mut cursor = idx + key_len;
    while cursor < chars.len() && chars[cursor].is_whitespace() {
        cursor += 1;
    }

    cursor < chars.len() && matches!(chars[cursor], '=' | ':')
}

fn path_key_len_at(chars: &[char], idx: usize) -> Option<usize> {
    [
        "current_process_path",
        "app_bundle_path",
        "executable_path",
        "windows_app_path",
        "keychain_process_path",
    ]
    .iter()
    .find_map(|key| {
        let key_chars = key.chars().collect::<Vec<_>>();
        if idx + key_chars.len() > chars.len() {
            return None;
        }
        let matches = key_chars
            .iter()
            .enumerate()
            .all(|(offset, expected)| chars[idx + offset] == *expected);
        matches.then_some(key_chars.len())
    })
}

fn secret_assignment_at(chars: &[char], idx: usize) -> Option<(String, usize)> {
    if idx > 0 && (chars[idx - 1].is_ascii_alphanumeric() || chars[idx - 1] == '_') {
        return None;
    }

    let key_len = secret_key_len_at(chars, idx)?;
    let mut cursor = idx + key_len;
    while cursor < chars.len() && chars[cursor].is_whitespace() {
        cursor += 1;
    }
    if cursor >= chars.len() || !matches!(chars[cursor], '=' | ':') {
        return None;
    }
    cursor += 1;
    while cursor < chars.len() && chars[cursor].is_whitespace() {
        cursor += 1;
    }
    if cursor >= chars.len() || value_delimiter(chars[cursor]) {
        return None;
    }

    let value_start = cursor;
    if chars[cursor] == '"' || chars[cursor] == char::from(39) {
        let quote = chars[cursor];
        cursor += 1;
        while cursor < chars.len() {
            let current = chars[cursor];
            cursor += 1;
            if current == quote {
                break;
            }
        }
    } else {
        while cursor < chars.len() && !value_delimiter(chars[cursor]) {
            cursor += 1;
        }
    }

    Some((chars[idx..value_start].iter().collect(), cursor))
}

fn secret_key_len_at(chars: &[char], idx: usize) -> Option<usize> {
    ["password", "passcode", "token", "secret"]
        .iter()
        .find_map(|key| {
            let key_chars = key.chars().collect::<Vec<_>>();
            if idx + key_chars.len() > chars.len() {
                return None;
            }
            let matches = key_chars
                .iter()
                .enumerate()
                .all(|(offset, expected)| chars[idx + offset].to_ascii_lowercase() == *expected);
            matches.then_some(key_chars.len())
        })
}

fn value_delimiter(c: char) -> bool {
    c.is_whitespace() || matches!(c, ',' | ';')
}

fn looks_like_email(value: &str) -> bool {
    let mut parts = value.split('@');
    let local = parts.next().unwrap_or_default();
    let domain = parts.next().unwrap_or_default();
    parts.next().is_none()
        && !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
}

fn is_email_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '%' | '+' | '-' | '@')
}

fn bridged_monitor_control_state() -> Option<MonitorControlState> {
    single_instance::read_monitor_control_state()
}

fn monitor_control_command(state: MonitorControlState) -> MonitorControlCommand {
    if state.toggle_requests_stop() {
        MonitorControlCommand::Stop
    } else {
        MonitorControlCommand::Start
    }
}

impl eframe::App for AutoLoginApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.process_tray_commands(ctx);
        self.process_worker_events();
        self.poll_background_monitor_control(ctx);
        self.poll_bridged_ui_status(ctx);
        crate::ui::accounts::poll_background_account_toggle(self, ctx);
        crate::ui::settings::poll_background_save(self, ctx);
        crate::ui::accounts::poll_background_account_transaction(self, ctx);
        self.poll_background_storage_recovery_signal(ctx);
        self.close_settings_window_after_successful_sync(ctx);
        #[cfg(feature = "diagnostics-ui")]
        crate::ui::diagnose::poll_diagnosis(self);
        #[cfg(feature = "diagnostics-ui")]
        crate::ui::diagnose::poll_runtime_status(self);
        self.close_after_quit_when_settings_saves_are_drained(ctx);
        self.keep_window_open_for_pending_settings_save(ctx);
        if !self.settings_window_mode
            && !self.quit_requested
            && ctx.input(|input| input.viewport().close_requested())
        {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        }
        ctx.request_repaint_after(Duration::from_millis(500));
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        let accessibility_ready = self.accessibility_ready();
        let monitor_control_state = self.monitor_control_state();

        if let Some((_, ref mut remaining)) = self.status_message {
            *remaining -= ctx.input(|i| i.stable_dt) as f64;
            if *remaining <= 0.0 {
                self.status_message = None;
            } else {
                ctx.request_repaint_after(Duration::from_millis(100));
            }
        }

        egui::Panel::top("top_panel")
            .frame(theme::top_bar_frame())
            .show_inside(ui, |ui| {
                ui.horizontal(|ui| {
                    if accessibility_ready {
                        ui.spacing_mut().item_spacing.x = 6.0;
                        let previous_button_padding = ui.spacing().button_padding;
                        ui.spacing_mut().button_padding = egui::vec2(8.0, 4.0);
                        for (tab, label) in [
                            (Tab::Accounts, "Accounts"),
                            (Tab::Settings, "Settings"),
                            #[cfg(feature = "diagnostics-ui")]
                            (Tab::Diagnose, "Diagnose"),
                        ] {
                            let selected = self.selected_tab == tab;
                            if ui
                                .add(
                                    egui::Button::selectable(
                                        selected,
                                        egui::RichText::new(label).strong(),
                                    )
                                    .corner_radius(egui::CornerRadius::same(8))
                                    .min_size(egui::vec2(0.0, 30.0)),
                                )
                                .clicked()
                            {
                                self.selected_tab = tab;
                            }
                        }
                        ui.spacing_mut().button_padding = previous_button_padding;
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.allocate_ui_with_layout(
                            egui::vec2(68.0, 30.0),
                            egui::Layout::centered_and_justified(egui::Direction::LeftToRight),
                            |ui| {
                                ui.label(theme::version_label(APP_VERSION_LABEL));
                            },
                        );

                        if accessibility_ready {
                            if monitor_control_state.toggle_requests_stop() {
                                if ui
                                    .add_sized(
                                        [140.0, 30.0],
                                        theme::secondary_button(
                                            monitor_control_state.toggle_label(),
                                        ),
                                    )
                                    .clicked()
                                {
                                    self.toggle_monitor_from_ui(ui.ctx());
                                }
                            } else if ui
                                .add_sized(
                                    [140.0, 30.0],
                                    theme::primary_button(monitor_control_state.toggle_label()),
                                )
                                .clicked()
                            {
                                self.toggle_monitor_from_ui(ui.ctx());
                            }
                        }
                    });
                });

                if accessibility_ready {
                    if let Some((msg, _)) = &self.status_message {
                        ui.add_space(7.0);
                        ui.label(theme::status_text(msg.as_str()));
                    }
                }
            });

        egui::CentralPanel::default()
            .frame(theme::content_frame())
            .show_inside(ui, |ui| {
                if !accessibility_ready {
                    show_accessibility_onboarding(ui, self);
                    return;
                }
                match self.selected_tab {
                    Tab::Accounts => crate::ui::accounts::show(ui, self),
                    Tab::Settings => crate::ui::settings::show(ui, self),
                    #[cfg(feature = "diagnostics-ui")]
                    Tab::Diagnose => crate::ui::diagnose::show(ui, self),
                }
            });

        // `logic` runs before `ui`. Keep a presentation request visible for
        // this entire UI pass so a simultaneous Save cannot schedule Close,
        // then release the guard for ordinary saves in later passes.
        self.keep_settings_window_open_through_ui_pass = false;
    }
}

fn push_bounded_log(logs: &mut VecDeque<LogEntry>, mut entry: LogEntry) {
    entry.message = redact_sensitive_log_text(&entry.message);
    logs.push_back(entry);
    while logs.len() > MAX_LOG_ENTRIES {
        logs.pop_front();
    }
}

fn show_accessibility_onboarding(ui: &mut egui::Ui, app: &mut AutoLoginApp) {
    theme::glass_frame().show(ui, |ui| {
        ui.heading("Accessibility permission is required");
        ui.add_space(8.0);
        ui.add(egui::Label::new(theme::muted(
            "Windows App AutoLogin can only detect and fill the visible credential prompt after macOS allows this exact app to use Accessibility.",
        )).wrap());
        ui.add_space(14.0);
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_sized(
                    ACCESSIBILITY_REQUEST_BUTTON_SIZE,
                    theme::primary_button("Request Accessibility Access"),
                )
                .clicked()
            {
                app.request_accessibility_access();
            }
            if ui
                .add_sized(
                    ACCESSIBILITY_SETTINGS_BUTTON_SIZE,
                    theme::secondary_button("Open Accessibility Settings"),
                )
                .clicked()
            {
                app.open_accessibility_settings();
            }
        });
    });
    ui.add_space(12.0);

    theme::glass_frame().show(ui, |ui| {
        ui.label(theme::muted(
            "System Settings -> Privacy & Security -> Accessibility",
        ));
        ui.add_space(8.0);
        ui.add(egui::Label::new(theme::muted(ACCESSIBILITY_SETTINGS_INSTRUCTIONS)).wrap());
    });
}

#[cfg(test)]
mod tests {
    use super::{
        accessibility_log_message, monitor_control_command, push_bounded_log,
        redact_sensitive_log_text, run_monitor_control_request, show_accessibility_onboarding,
        submit_monitor_control_worker, AutoLoginApp, BackgroundMutationExecutor,
        BridgedUiStatusPoller, BridgedUiStatusSnapshot, MonitorControlCompletion,
        MonitorControlExecutor, MonitorControlIntent, PendingMonitorControl, WorkerCommand,
        ACCESSIBILITY_SETTINGS_INSTRUCTIONS, LOCAL_CONFIG_RELEASE_FAILED_REASON, MAX_LOG_ENTRIES,
        MONITOR_CONTROL_SAFETY_STOP_RETRY_INITIAL_INTERVAL,
        MONITOR_CONTROL_SAFETY_STOP_RETRY_MAX_INTERVAL, SETTINGS_WINDOW_CLOSING_REASON,
    };
    use crate::autologin::AccessibilityStatus;
    use crate::background::{
        WorkerEvent, WorkerInvalidator, WorkerPauseLatch, WorkerQuiescenceAck,
    };
    use crate::models::{AppConfig, LogEntry, LogLevel, MonitorControlState, Tab, WorkerStatus};
    use crate::single_instance::MonitorControlCommand;
    use crate::tray::TrayCommand;
    use eframe::egui;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering as AtomicOrdering};
    use std::sync::mpsc::{channel as std_channel, sync_channel};
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tokio::sync::mpsc::channel as tokio_channel;

    fn test_pause_latch() -> WorkerPauseLatch {
        WorkerInvalidator::new().pause_latch()
    }

    fn mutation_test_app(settings_window_mode: bool) -> AutoLoginApp {
        let (worker_tx, _worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (_tray_tx, tray_rx) = std_channel();
        AutoLoginApp::new(
            worker_tx,
            test_pause_latch(),
            tray_rx,
            worker_event_rx,
            AppConfig::default(),
            settings_window_mode,
            Tab::Accounts,
        )
    }

    #[test]
    fn settings_mutation_begin_failure_does_not_cancel() {
        let mut app = mutation_test_app(true);
        let cancel_count = Arc::new(AtomicUsize::new(0));
        let cancel_count_for_request = cancel_count.clone();

        let guard = app.begin_settings_mutation_with(
            || anyhow::bail!("test begin failure"),
            move || {
                cancel_count_for_request.fetch_add(1, AtomicOrdering::SeqCst);
                Ok(())
            },
        );

        assert!(guard.is_none());
        assert_eq!(cancel_count.load(AtomicOrdering::SeqCst), 0);
    }

    #[test]
    fn aborted_settings_mutation_drop_sends_exactly_one_cancel() {
        let mut app = mutation_test_app(true);
        let cancel_count = Arc::new(AtomicUsize::new(0));
        let cancel_count_for_request = cancel_count.clone();

        let guard = app
            .begin_settings_mutation_with(
                || Ok(()),
                move || {
                    cancel_count_for_request.fetch_add(1, AtomicOrdering::SeqCst);
                    Ok(())
                },
            )
            .expect("successful begin must return a guard");
        drop(guard);

        assert_eq!(cancel_count.load(AtomicOrdering::SeqCst), 1);
    }

    #[test]
    fn terminal_settings_mutation_drop_does_not_cancel() {
        let mut app = mutation_test_app(true);
        let cancel_count = Arc::new(AtomicUsize::new(0));
        let cancel_count_for_request = cancel_count.clone();

        let mut guard = app
            .begin_settings_mutation_with(
                || Ok(()),
                move || {
                    cancel_count_for_request.fetch_add(1, AtomicOrdering::SeqCst);
                    Ok(())
                },
            )
            .expect("successful begin must return a guard");
        guard.mark_commit_started();
        drop(guard);

        assert_eq!(cancel_count.load(AtomicOrdering::SeqCst), 0);
    }

    #[test]
    fn nested_settings_mutation_begin_is_rejected() {
        let mut app = mutation_test_app(true);
        let first_cancel_count = Arc::new(AtomicUsize::new(0));
        let first_cancel_count_for_request = first_cancel_count.clone();
        let first_guard = app
            .begin_settings_mutation_with(
                || Ok(()),
                move || {
                    first_cancel_count_for_request.fetch_add(1, AtomicOrdering::SeqCst);
                    Ok(())
                },
            )
            .expect("first begin must return a guard");
        let nested_begin_count = Arc::new(AtomicUsize::new(0));
        let nested_begin_count_for_request = nested_begin_count.clone();

        let nested_guard = app.begin_settings_mutation_with(
            move || {
                nested_begin_count_for_request.fetch_add(1, AtomicOrdering::SeqCst);
                Ok(())
            },
            || Ok(()),
        );

        assert!(nested_guard.is_none());
        assert_eq!(nested_begin_count.load(AtomicOrdering::SeqCst), 0);
        drop(first_guard);
        assert_eq!(first_cancel_count.load(AtomicOrdering::SeqCst), 1);
    }

    #[test]
    fn local_settings_mutation_guard_uses_no_ipc() {
        let mut app = mutation_test_app(false);
        let begin_count = Arc::new(AtomicUsize::new(0));
        let begin_count_for_request = begin_count.clone();
        let cancel_count = Arc::new(AtomicUsize::new(0));
        let cancel_count_for_request = cancel_count.clone();

        let guard = app
            .begin_settings_mutation_with(
                move || {
                    begin_count_for_request.fetch_add(1, AtomicOrdering::SeqCst);
                    Ok(())
                },
                move || {
                    cancel_count_for_request.fetch_add(1, AtomicOrdering::SeqCst);
                    Ok(())
                },
            )
            .expect("local mutation must use a no-op guard");
        drop(guard);

        assert_eq!(begin_count.load(AtomicOrdering::SeqCst), 0);
        assert_eq!(cancel_count.load(AtomicOrdering::SeqCst), 0);
    }

    #[test]
    fn local_background_mutation_closes_latch_before_waiting_off_owner_thread() {
        let (worker_tx, mut worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (_tray_tx, tray_rx) = std_channel();
        let pause_latch = test_pause_latch();
        let mut app = AutoLoginApp::new(
            worker_tx,
            pause_latch.clone(),
            tray_rx,
            worker_event_rx,
            AppConfig::default(),
            false,
            Tab::Settings,
        );
        let owner_thread = std::thread::current().id();

        let begin = app.prepare_background_settings_mutation_begin();
        let pause_epoch = pause_latch.current_epoch();

        assert!(pause_latch.is_paused());
        assert_eq!(
            app.active_local_config_mutation_pause_epoch,
            Some(pause_epoch)
        );

        let (finished_tx, finished_rx) = std_channel();
        std::thread::spawn(move || {
            finished_tx
                .send((std::thread::current().id(), begin.wait_for_quiescence()))
                .unwrap();
        });

        let WorkerCommand::Quiesce {
            request_id,
            acknowledgement,
        } = worker_rx
            .blocking_recv()
            .expect("quiescence must be queued")
        else {
            panic!("expected local worker quiescence request");
        };
        assert_eq!(request_id, pause_epoch);
        assert!(finished_rx.try_recv().is_err());
        acknowledgement
            .send(WorkerQuiescenceAck { request_id })
            .unwrap();
        let (worker_thread, result) = finished_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("quiescence wait must finish after acknowledgement");
        assert_ne!(worker_thread, owner_thread);
        result.unwrap();
    }

    #[test]
    fn local_background_chain_reuses_and_releases_exact_pause_epoch_once() {
        let (worker_tx, mut worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (_tray_tx, tray_rx) = std_channel();
        let pause_latch = test_pause_latch();
        let mut app = AutoLoginApp::new(
            worker_tx,
            pause_latch.clone(),
            tray_rx,
            worker_event_rx,
            AppConfig::default(),
            false,
            Tab::Settings,
        );
        app.worker_status = WorkerStatus::Running;

        let first_begin = app.prepare_background_settings_mutation_begin();
        let pause_epoch = pause_latch.current_epoch();
        assert_eq!(app.active_local_config_mutation_start_monitor, Some(true));
        drop(first_begin);
        let successor_begin = app.prepare_background_settings_mutation_begin();

        assert_eq!(pause_latch.current_epoch(), pause_epoch);
        drop(successor_begin);
        app.config.settings.start_minimized = true;
        assert!(app.sync_background_saved_config_to_local_worker(true));

        match worker_rx.try_recv().expect("one final release is required") {
            WorkerCommand::ApplyConfigAndReleasePause {
                settings,
                accounts,
                refresh_passwords,
                start_monitor,
                pause_epoch: released_epoch,
            } => {
                assert_eq!(released_epoch, pause_epoch);
                assert_eq!(settings, app.config.settings);
                assert_eq!(accounts, app.config.accounts);
                assert!(refresh_passwords);
                assert!(start_monitor);
            }
            other => panic!("expected one atomic final config release, got {other:?}"),
        }
        assert!(worker_rx.try_recv().is_err());
        assert!(app.active_local_config_mutation_pause_epoch.is_none());
        assert!(app.active_local_config_mutation_start_monitor.is_none());
    }

    #[test]
    fn local_background_release_preserves_start_intent_after_pause_reports_idle() {
        let (worker_tx, mut worker_rx) = tokio_channel(8);
        let (worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (_tray_tx, tray_rx) = std_channel();
        let pause_latch = test_pause_latch();
        let mut app = AutoLoginApp::new(
            worker_tx,
            pause_latch.clone(),
            tray_rx,
            worker_event_rx,
            AppConfig::default(),
            false,
            Tab::Settings,
        );
        app.worker_status = WorkerStatus::Running;

        let begin = app.prepare_background_settings_mutation_begin();
        let pause_epoch = pause_latch.current_epoch();
        assert_eq!(app.active_local_config_mutation_start_monitor, Some(true));

        worker_event_tx
            .try_send(WorkerEvent::StatusChanged(WorkerStatus::Idle))
            .unwrap();
        app.process_worker_events();
        assert_eq!(app.worker_status, WorkerStatus::Idle);
        drop(begin);

        assert!(app.sync_background_saved_config_to_local_worker(false));
        match worker_rx.try_recv().expect("one final release is required") {
            WorkerCommand::ApplyConfigAndReleasePause {
                start_monitor,
                pause_epoch: released_epoch,
                ..
            } => {
                assert!(start_monitor);
                assert_eq!(released_epoch, pause_epoch);
            }
            other => panic!("expected one atomic final config release, got {other:?}"),
        }
        assert!(app.active_local_config_mutation_pause_epoch.is_none());
        assert!(app.active_local_config_mutation_start_monitor.is_none());
    }

    #[test]
    fn fail_closed_reason_discards_active_local_start_intent() {
        let (worker_tx, _worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (_tray_tx, tray_rx) = std_channel();
        let pause_latch = test_pause_latch();
        let mut app = AutoLoginApp::new(
            worker_tx,
            pause_latch.clone(),
            tray_rx,
            worker_event_rx,
            AppConfig::default(),
            false,
            Tab::Settings,
        );
        app.worker_status = WorkerStatus::Running;

        let begin = app.prepare_background_settings_mutation_begin();
        assert_eq!(app.active_local_config_mutation_start_monitor, Some(true));
        drop(begin);

        app.set_settings_changes_blocked_reason(Some(
            LOCAL_CONFIG_RELEASE_FAILED_REASON.to_string(),
        ));

        assert!(pause_latch.is_paused());
        assert!(app.active_local_config_mutation_pause_epoch.is_none());
        assert!(app.active_local_config_mutation_start_monitor.is_none());
    }

    #[test]
    fn newer_safety_pause_prevents_stale_local_chain_release() {
        let (worker_tx, mut worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (_tray_tx, tray_rx) = std_channel();
        let pause_latch = test_pause_latch();
        let mut app = AutoLoginApp::new(
            worker_tx,
            pause_latch.clone(),
            tray_rx,
            worker_event_rx,
            AppConfig::default(),
            false,
            Tab::Settings,
        );
        let begin = app.prepare_background_settings_mutation_begin();
        let mutation_epoch = pause_latch.current_epoch();
        drop(begin);

        let newer_epoch = pause_latch.pause_with_epoch();
        assert_ne!(newer_epoch, mutation_epoch);
        assert!(!app.sync_background_saved_config_to_local_worker(false));

        assert!(pause_latch.is_paused());
        assert_eq!(pause_latch.current_epoch(), newer_epoch);
        assert!(worker_rx.try_recv().is_err());
        assert_eq!(
            app.settings_save_fail_closed_reason(),
            Some(LOCAL_CONFIG_RELEASE_FAILED_REASON)
        );
    }

    #[test]
    fn full_ui_monitor_action_matches_the_supervisor_control_state() {
        for (state, expected_command, expected_label) in [
            (
                MonitorControlState::Running,
                MonitorControlCommand::Stop,
                "Stop Monitor",
            ),
            (
                MonitorControlState::PausedWithStartIntent,
                MonitorControlCommand::Stop,
                "Stop Monitor",
            ),
            (
                MonitorControlState::Stopped,
                MonitorControlCommand::Start,
                "Start Monitor",
            ),
        ] {
            assert_eq!(monitor_control_command(state), expected_command);
            assert_eq!(state.toggle_label(), expected_label);
        }
    }

    #[test]
    fn monitor_control_ipc_runs_on_the_prestarted_executor() {
        let owner_thread = std::thread::current().id();
        let executor = MonitorControlExecutor::spawn().unwrap();
        let (started_tx, started_rx) = std_channel();
        let (release_tx, release_rx) = std_channel();
        let intent = MonitorControlIntent {
            sequence: 1,
            command: MonitorControlCommand::Start,
        };

        let completion = submit_monitor_control_worker(
            executor,
            move || {
                run_monitor_control_request(intent, move |command| {
                    started_tx
                        .send((std::thread::current().id(), command))
                        .unwrap();
                    release_rx.recv_timeout(Duration::from_secs(1)).unwrap();
                    Ok(())
                })
            },
            egui::Context::default(),
        )
        .expect("bounded submission must not wait for IPC");

        let (request_thread, command) = started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("the prestarted executor must begin the request");
        assert_ne!(request_thread, owner_thread);
        assert_eq!(command, MonitorControlCommand::Start);
        assert!(completion.try_recv().is_err());

        release_tx.send(()).unwrap();
        assert_eq!(
            completion.recv_timeout(Duration::from_secs(1)).unwrap(),
            MonitorControlCompletion::Acknowledged(intent)
        );
    }

    #[test]
    fn rapid_monitor_clicks_use_and_coalesce_the_latest_projected_state() {
        let mut app = mutation_test_app(true);
        app.accessibility_status.trusted = true;
        app.bridged_monitor_control_state = MonitorControlState::Stopped;
        let active_intent = MonitorControlIntent {
            sequence: 1,
            command: MonitorControlCommand::Start,
        };
        app.next_monitor_control_intent_sequence = active_intent.sequence;
        let (completion_tx, completion_rx) = sync_channel(1);
        app.pending_monitor_control = Some(PendingMonitorControl {
            receiver: completion_rx,
            active_intent,
            latest_intent: active_intent,
            projected_state: active_intent.projected_state(),
        });
        let ctx = egui::Context::default();

        assert_eq!(
            app.monitor_control_state(),
            MonitorControlState::PausedWithStartIntent
        );
        app.toggle_monitor_from_ui(&ctx);
        assert_eq!(app.monitor_control_state(), MonitorControlState::Stopped);
        assert_eq!(
            app.pending_monitor_control
                .as_ref()
                .unwrap()
                .latest_intent
                .command,
            MonitorControlCommand::Stop
        );

        app.toggle_monitor_from_ui(&ctx);
        assert_eq!(
            app.monitor_control_state(),
            MonitorControlState::PausedWithStartIntent
        );
        assert_eq!(
            app.pending_monitor_control
                .as_ref()
                .unwrap()
                .latest_intent
                .command,
            MonitorControlCommand::Start
        );

        completion_tx
            .send(MonitorControlCompletion::Acknowledged(active_intent))
            .unwrap();
        app.poll_background_monitor_control_with(&ctx, |_, _, _| {
            panic!("a latest intent equal to the acknowledged command must be coalesced")
        });

        assert!(app.pending_monitor_control.is_none());
        assert_eq!(
            app.monitor_control_state(),
            MonitorControlState::PausedWithStartIntent
        );
    }

    #[test]
    fn acknowledged_monitor_command_starts_only_the_latest_opposite_successor() {
        let mut app = mutation_test_app(true);
        let active_intent = MonitorControlIntent {
            sequence: 1,
            command: MonitorControlCommand::Start,
        };
        app.next_monitor_control_intent_sequence = active_intent.sequence;
        let (completion_tx, completion_rx) = sync_channel(1);
        app.pending_monitor_control = Some(PendingMonitorControl {
            receiver: completion_rx,
            active_intent,
            latest_intent: active_intent,
            projected_state: active_intent.projected_state(),
        });
        let ctx = egui::Context::default();
        app.toggle_monitor_from_ui(&ctx);
        let expected_successor = app.pending_monitor_control.as_ref().unwrap().latest_intent;
        completion_tx
            .send(MonitorControlCompletion::Acknowledged(active_intent))
            .unwrap();
        let successor_count = std::cell::Cell::new(0);

        app.poll_background_monitor_control_with(&ctx, |app, _, intent| {
            successor_count.set(successor_count.get() + 1);
            assert_eq!(intent, expected_successor);
            let (sender, receiver) = sync_channel(1);
            std::mem::forget(sender);
            app.pending_monitor_control = Some(PendingMonitorControl {
                receiver,
                active_intent: intent,
                latest_intent: intent,
                projected_state: intent.projected_state(),
            });
            true
        });

        assert_eq!(successor_count.get(), 1);
        assert_eq!(app.monitor_control_state(), MonitorControlState::Stopped);
        assert_eq!(
            app.pending_monitor_control
                .as_ref()
                .unwrap()
                .active_intent
                .command,
            MonitorControlCommand::Stop
        );
    }

    #[test]
    fn pending_monitor_intent_ignores_stale_bridged_status_snapshot() {
        let mut app = mutation_test_app(true);
        app.bridged_monitor_control_state = MonitorControlState::Running;
        let active_intent = MonitorControlIntent {
            sequence: 1,
            command: MonitorControlCommand::Stop,
        };
        let (completion_sender, completion_receiver) = sync_channel(1);
        std::mem::forget(completion_sender);
        app.pending_monitor_control = Some(PendingMonitorControl {
            receiver: completion_receiver,
            active_intent,
            latest_intent: active_intent,
            projected_state: MonitorControlState::Stopped,
        });
        let (snapshot_sender, snapshot_receiver) = sync_channel(1);
        app.bridged_ui_status_poller = Some(BridgedUiStatusPoller {
            receiver: snapshot_receiver,
            generation: Arc::new(AtomicU64::new(0)),
            stop: Arc::new(AtomicBool::new(false)),
        });
        snapshot_sender
            .send(BridgedUiStatusSnapshot {
                generation: 0,
                monitor_control_state: Some(MonitorControlState::Running),
                accessibility_status: app.accessibility_status.clone(),
                #[cfg(feature = "diagnostics-ui")]
                last_fill_report: None,
            })
            .unwrap();

        app.poll_bridged_ui_status(&egui::Context::default());

        assert_eq!(app.monitor_control_state(), MonitorControlState::Stopped);
        assert_eq!(
            app.pending_monitor_control.as_ref().unwrap().latest_intent,
            active_intent
        );
    }

    #[test]
    fn ambiguous_start_ack_uses_acknowledged_safety_stop_and_discards_queued_start() {
        let intent = MonitorControlIntent {
            sequence: 1,
            command: MonitorControlCommand::Start,
        };
        let commands = std::cell::RefCell::new(Vec::new());
        let completion = run_monitor_control_request(intent, |command| {
            commands.borrow_mut().push(command);
            if command == MonitorControlCommand::Start {
                anyhow::bail!("synthetic ambiguous acknowledgement")
            }
            Ok(())
        });
        assert_eq!(
            commands.into_inner(),
            vec![MonitorControlCommand::Start, MonitorControlCommand::Stop]
        );
        assert!(matches!(
            &completion,
            MonitorControlCompletion::Ambiguous {
                safety_stop_error: None,
                ..
            }
        ));

        let mut app = mutation_test_app(true);
        let queued_start = MonitorControlIntent {
            sequence: 3,
            command: MonitorControlCommand::Start,
        };
        let (sender, receiver) = sync_channel(1);
        sender.send(completion).unwrap();
        app.pending_monitor_control = Some(PendingMonitorControl {
            receiver,
            active_intent: intent,
            latest_intent: queued_start,
            projected_state: queued_start.projected_state(),
        });

        app.poll_background_monitor_control_with(&egui::Context::default(), |_, _, _| {
            panic!("an ambiguous acknowledgement must discard a queued Start")
        });

        assert!(app.pending_monitor_control.is_none());
        assert_eq!(app.monitor_control_state(), MonitorControlState::Stopped);
        assert!(app
            .status_message
            .as_ref()
            .is_some_and(|(message, _)| message.contains("stopped safely")));
    }

    #[test]
    fn unconfirmed_safety_stop_never_exposes_start_action() {
        let intent = MonitorControlIntent {
            sequence: 1,
            command: MonitorControlCommand::Start,
        };
        let completion = run_monitor_control_request(intent, |_| {
            anyhow::bail!("synthetic acknowledgement failure")
        });
        let (sender, receiver) = sync_channel(1);
        sender.send(completion).unwrap();
        let mut app = mutation_test_app(true);
        app.pending_monitor_control = Some(PendingMonitorControl {
            receiver,
            active_intent: intent,
            latest_intent: intent,
            projected_state: intent.projected_state(),
        });

        app.poll_background_monitor_control_with(&egui::Context::default(), |_, _, _| false);

        assert_eq!(
            app.monitor_control_state(),
            MonitorControlState::PausedWithStartIntent
        );
        assert_eq!(app.monitor_control_state().toggle_label(), "Stop Monitor");
        assert!(app
            .status_message
            .as_ref()
            .is_some_and(|(message, _)| message.contains("could not be confirmed")));
    }

    #[test]
    fn disconnected_monitor_completion_automatically_retries_stop() {
        let mut app = mutation_test_app(true);
        let active_intent = MonitorControlIntent {
            sequence: 1,
            command: MonitorControlCommand::Start,
        };
        app.next_monitor_control_intent_sequence = active_intent.sequence;
        let (completion_sender, completion_receiver) = sync_channel(1);
        drop(completion_sender);
        app.pending_monitor_control = Some(PendingMonitorControl {
            receiver: completion_receiver,
            active_intent,
            latest_intent: active_intent,
            projected_state: active_intent.projected_state(),
        });
        let ctx = egui::Context::default();
        let now = Instant::now();

        app.poll_background_monitor_control_at_with(&ctx, now, |_, _, _| {
            panic!("a disconnected completion must use bounded backoff before retrying Stop")
        });

        let retry_at = app
            .monitor_safety_stop_recovery
            .as_ref()
            .and_then(|recovery| recovery.next_retry_at)
            .expect("a disconnected request must schedule an automatic safety Stop");
        assert_eq!(
            retry_at.saturating_duration_since(now),
            MONITOR_CONTROL_SAFETY_STOP_RETRY_INITIAL_INTERVAL
        );
        assert!(app.pending_monitor_control.is_none());
        assert_eq!(app.monitor_control_state().toggle_label(), "Stop Monitor");

        let retried_command = std::cell::Cell::new(None);
        app.poll_background_monitor_control_at_with(&ctx, retry_at, |app, _, retry_intent| {
            retried_command.set(Some(retry_intent.command));
            let (sender, receiver) = sync_channel(1);
            sender
                .send(MonitorControlCompletion::Acknowledged(retry_intent))
                .unwrap();
            app.pending_monitor_control = Some(PendingMonitorControl {
                receiver,
                active_intent: retry_intent,
                latest_intent: retry_intent,
                projected_state: retry_intent.projected_state(),
            });
            true
        });

        assert_eq!(retried_command.get(), Some(MonitorControlCommand::Stop));
        assert!(app.monitor_safety_stop_recovery.is_none());
        assert!(app.pending_monitor_control.is_none());
        assert_eq!(app.monitor_control_state(), MonitorControlState::Stopped);
    }

    #[test]
    fn failed_safety_stop_retries_with_bounded_backoff_and_discards_queued_start() {
        let mut app = mutation_test_app(true);
        let active_intent = MonitorControlIntent {
            sequence: 1,
            command: MonitorControlCommand::Start,
        };
        let queued_start = MonitorControlIntent {
            sequence: 2,
            command: MonitorControlCommand::Start,
        };
        app.next_monitor_control_intent_sequence = queued_start.sequence;
        let (sender, receiver) = sync_channel(1);
        sender
            .send(MonitorControlCompletion::Ambiguous {
                intent: active_intent,
                error: "synthetic Start acknowledgement failure".to_string(),
                safety_stop_error: Some("synthetic safety Stop failure".to_string()),
            })
            .unwrap();
        app.pending_monitor_control = Some(PendingMonitorControl {
            receiver,
            active_intent,
            latest_intent: queued_start,
            projected_state: queued_start.projected_state(),
        });
        let ctx = egui::Context::default();
        let now = Instant::now();

        app.poll_background_monitor_control_at_with(&ctx, now, |_, _, _| {
            panic!("a queued Start must be discarded after an ambiguous acknowledgement")
        });

        let first_retry_at = app
            .monitor_safety_stop_recovery
            .as_ref()
            .and_then(|recovery| recovery.next_retry_at)
            .expect("a failed safety Stop must schedule a retry");
        assert_eq!(app.monitor_control_state().toggle_label(), "Stop Monitor");
        assert!(app.pending_monitor_control.is_none());

        let rejected_retry = std::cell::Cell::new(None);
        app.poll_background_monitor_control_at_with(&ctx, first_retry_at, |_, _, retry_intent| {
            rejected_retry.set(Some(retry_intent.command));
            false
        });

        assert_eq!(rejected_retry.get(), Some(MonitorControlCommand::Stop));
        let recovery = app
            .monitor_safety_stop_recovery
            .as_ref()
            .expect("a rejected retry submission must remain fail-closed");
        let second_retry_at = recovery
            .next_retry_at
            .expect("a rejected retry submission must be rescheduled");
        assert_eq!(
            second_retry_at.saturating_duration_since(first_retry_at),
            MONITOR_CONTROL_SAFETY_STOP_RETRY_INITIAL_INTERVAL.saturating_mul(2)
        );
        assert!(recovery.next_backoff <= MONITOR_CONTROL_SAFETY_STOP_RETRY_MAX_INTERVAL);
        assert_eq!(app.monitor_control_state().toggle_label(), "Stop Monitor");

        app.poll_background_monitor_control_at_with(
            &ctx,
            second_retry_at,
            |app, _, retry_intent| {
                assert_eq!(retry_intent.command, MonitorControlCommand::Stop);
                let (sender, receiver) = sync_channel(1);
                sender
                    .send(MonitorControlCompletion::Acknowledged(retry_intent))
                    .unwrap();
                app.pending_monitor_control = Some(PendingMonitorControl {
                    receiver,
                    active_intent: retry_intent,
                    latest_intent: retry_intent,
                    projected_state: retry_intent.projected_state(),
                });
                true
            },
        );

        assert!(app.monitor_safety_stop_recovery.is_none());
        assert_eq!(app.monitor_control_state(), MonitorControlState::Stopped);
    }

    #[test]
    fn safety_stop_retry_backoff_is_capped() {
        let mut app = mutation_test_app(true);
        let ctx = egui::Context::default();
        let mut previous_attempt_at = Instant::now();
        app.schedule_monitor_safety_stop_retry(&ctx, previous_attempt_at);

        for _ in 0..10 {
            let retry_at = app
                .monitor_safety_stop_recovery
                .as_ref()
                .and_then(|recovery| recovery.next_retry_at)
                .expect("every rejected safety Stop submission must remain scheduled");
            assert!(
                retry_at.saturating_duration_since(previous_attempt_at)
                    <= MONITOR_CONTROL_SAFETY_STOP_RETRY_MAX_INTERVAL
            );
            app.poll_background_monitor_control_at_with(&ctx, retry_at, |_, _, retry_intent| {
                assert_eq!(retry_intent.command, MonitorControlCommand::Stop);
                false
            });
            assert_eq!(app.monitor_control_state().toggle_label(), "Stop Monitor");
            previous_attempt_at = retry_at;
        }

        assert_eq!(
            app.monitor_safety_stop_recovery
                .as_ref()
                .expect("safety Stop recovery must remain active")
                .next_backoff,
            MONITOR_CONTROL_SAFETY_STOP_RETRY_MAX_INTERVAL
        );
    }

    #[test]
    fn rejected_stop_successor_after_acknowledged_start_enters_safety_retry() {
        let mut app = mutation_test_app(true);
        let active_start = MonitorControlIntent {
            sequence: 1,
            command: MonitorControlCommand::Start,
        };
        let queued_stop = MonitorControlIntent {
            sequence: 2,
            command: MonitorControlCommand::Stop,
        };
        let (sender, receiver) = sync_channel(1);
        sender
            .send(MonitorControlCompletion::Acknowledged(active_start))
            .unwrap();
        app.pending_monitor_control = Some(PendingMonitorControl {
            receiver,
            active_intent: active_start,
            latest_intent: queued_stop,
            projected_state: queued_stop.projected_state(),
        });
        let now = Instant::now();

        app.poll_background_monitor_control_at_with(
            &egui::Context::default(),
            now,
            |_, _, successor| {
                assert_eq!(successor, queued_stop);
                false
            },
        );

        let retry_at = app
            .monitor_safety_stop_recovery
            .as_ref()
            .and_then(|recovery| recovery.next_retry_at)
            .expect("a rejected queued Stop must be retried automatically");
        assert_eq!(
            retry_at.saturating_duration_since(now),
            MONITOR_CONTROL_SAFETY_STOP_RETRY_INITIAL_INTERVAL
        );
        assert_eq!(app.monitor_control_state().toggle_label(), "Stop Monitor");
    }

    #[test]
    fn pending_monitor_control_does_not_block_settings_close() {
        let mut app = mutation_test_app(true);
        let active_intent = MonitorControlIntent {
            sequence: 1,
            command: MonitorControlCommand::Start,
        };
        let (sender, receiver) = sync_channel(1);
        std::mem::forget(sender);
        app.pending_monitor_control = Some(PendingMonitorControl {
            receiver,
            active_intent,
            latest_intent: active_intent,
            projected_state: active_intent.projected_state(),
        });
        assert!(!app.settings_save_in_progress());
        assert!(app.settings_mutations_disabled_reason().is_none());
        assert!(app.config_mutations_disabled_reason().is_none());
        assert!(app.account_mutations_ready());
        assert!(app.account_transaction_ready());

        let ctx = egui::Context::default();
        let mut input = egui::RawInput::default();
        input
            .viewports
            .get_mut(&egui::ViewportId::ROOT)
            .expect("default raw input must contain the root viewport")
            .events
            .push(egui::ViewportEvent::Close);
        ctx.begin_pass(input);
        app.keep_window_open_for_pending_settings_save(&ctx);
        let output = ctx.end_pass();

        assert!(output.viewport_output[&egui::ViewportId::ROOT]
            .commands
            .is_empty());
        assert!(!app.close_settings_window_after_pending_save);
    }

    #[test]
    fn accepted_close_or_quit_disables_every_configuration_mutation_with_one_reason() {
        let mut settings_child = mutation_test_app(true);
        settings_child.close_settings_window_after_pending_save = true;

        assert_eq!(
            settings_child.settings_mutations_disabled_reason(),
            Some(SETTINGS_WINDOW_CLOSING_REASON)
        );
        assert_eq!(
            settings_child.config_mutations_disabled_reason(),
            Some(SETTINGS_WINDOW_CLOSING_REASON)
        );
        assert!(!settings_child.account_mutations_ready());
        assert!(!settings_child.account_transaction_ready());

        let mut primary_window = mutation_test_app(false);
        primary_window.quit_requested = true;
        assert_eq!(
            primary_window.settings_mutations_disabled_reason(),
            Some(SETTINGS_WINDOW_CLOSING_REASON)
        );
        assert_eq!(
            primary_window.config_mutations_disabled_reason(),
            Some(SETTINGS_WINDOW_CLOSING_REASON)
        );
        assert!(!primary_window.account_mutations_ready());
        assert!(!primary_window.account_transaction_ready());
    }

    #[test]
    fn monitor_toggle_owner_path_has_no_blocking_ipc_source() {
        let source = include_str!("app.rs");
        let handler = source
            .split_once("fn toggle_monitor_from_ui(")
            .and_then(|(_, tail)| tail.split_once("pub(crate) fn accessibility_ready"))
            .map(|(body, _)| body)
            .expect("monitor toggle handler must remain inspectable");
        assert!(handler.contains("queue_background_monitor_control"));
        assert!(!handler.contains("request_monitor_command"));
        assert!(!handler.contains("recv"));
        assert!(!handler.contains("sleep"));

        let logic = source
            .split_once("fn logic(&mut self")
            .and_then(|(_, tail)| tail.split_once("fn ui(&mut self"))
            .map(|(body, _)| body)
            .expect("egui logic path must remain inspectable");
        assert!(logic.contains("poll_background_monitor_control(ctx)"));

        let retry_poll = source
            .split_once("fn poll_background_monitor_control_at_with")
            .and_then(|(_, tail)| tail.split_once("fn ensure_monitor_safety_stop_recovery"))
            .map(|(body, _)| body)
            .expect("monitor safety retry owner path must remain inspectable");
        assert!(retry_poll.contains("try_recv"));
        assert!(!retry_poll.contains("request_monitor_command"));
        assert!(!retry_poll.contains("recv_timeout"));
        assert!(!retry_poll.contains(".recv("));
        assert!(!retry_poll.contains("sleep"));

        let monitor_buttons = source
            .split_once("if monitor_control_state.toggle_requests_stop()")
            .and_then(|(_, tail)| tail.split_once("egui::CentralPanel::default()"))
            .map(|(body, _)| body)
            .expect("monitor buttons must remain inspectable");
        assert!(!monitor_buttons.contains("add_enabled"));
    }

    #[test]
    fn stale_background_status_cannot_revert_an_acknowledged_monitor_command() {
        let mut app = mutation_test_app(true);
        let (sender, receiver) = sync_channel(1);
        app.bridged_ui_status_poller = Some(BridgedUiStatusPoller {
            receiver,
            generation: Arc::new(AtomicU64::new(0)),
            stop: Arc::new(AtomicBool::new(false)),
        });
        sender
            .send(BridgedUiStatusSnapshot {
                generation: 0,
                monitor_control_state: Some(MonitorControlState::Stopped),
                accessibility_status: app.accessibility_status.clone(),
                #[cfg(feature = "diagnostics-ui")]
                last_fill_report: None,
            })
            .unwrap();

        app.apply_acknowledged_monitor_command(MonitorControlCommand::Start);
        app.poll_bridged_ui_status(&egui::Context::default());

        assert_eq!(
            app.monitor_control_state(),
            MonitorControlState::PausedWithStartIntent
        );
        assert_eq!(app.worker_status, WorkerStatus::Idle);

        sender
            .send(BridgedUiStatusSnapshot {
                generation: 1,
                monitor_control_state: Some(MonitorControlState::Running),
                accessibility_status: app.accessibility_status.clone(),
                #[cfg(feature = "diagnostics-ui")]
                last_fill_report: None,
            })
            .unwrap();
        app.poll_bridged_ui_status(&egui::Context::default());

        assert_eq!(app.monitor_control_state(), MonitorControlState::Running);
        assert_eq!(app.worker_status, WorkerStatus::Running);
    }

    fn assert_repeated_open_command(command: TrayCommand, opposite_tab: Tab, expected_tab: Tab) {
        let (worker_tx, mut worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (tray_tx, tray_rx) = std_channel();
        let mut config = AppConfig::default();
        config.settings.auto_start = true;
        config.settings.start_minimized = true;
        let mut app = AutoLoginApp::new(
            worker_tx,
            test_pause_latch(),
            tray_rx,
            worker_event_rx,
            config,
            true,
            opposite_tab,
        );
        app.settings_draft.auto_start = false;
        app.settings_draft.start_minimized = false;
        app.settings_draft.use_keyring = false;
        let original_config = app.config.clone();
        let original_draft = app.settings_draft.clone();
        let ctx = egui::Context::default();

        for activation in 1..=2 {
            app.selected_tab = opposite_tab;
            tray_tx.send(command.clone()).unwrap();

            ctx.begin_pass(Default::default());
            app.process_tray_commands(&ctx);
            let output = ctx.end_pass();

            assert_eq!(
                app.selected_tab, expected_tab,
                "activation {activation} did not select the requested tab"
            );
            assert_eq!(
                app.config, original_config,
                "activation {activation} mutated saved configuration"
            );
            assert_eq!(
                app.settings_draft, original_draft,
                "activation {activation} mutated the settings draft"
            );
            assert_eq!(
                output.viewport_output[&egui::ViewportId::ROOT].commands,
                vec![
                    egui::ViewportCommand::Visible(true),
                    egui::ViewportCommand::Minimized(false),
                    egui::ViewportCommand::Focus,
                ],
                "activation {activation} emitted unexpected viewport commands"
            );
            assert!(
                worker_rx.try_recv().is_err(),
                "activation {activation} queued a worker command"
            );
        }
    }

    #[test]
    fn repeated_open_accounts_selects_and_focuses_existing_window_without_side_effects() {
        assert_repeated_open_command(TrayCommand::OpenAccounts, Tab::Settings, Tab::Accounts);
    }

    #[test]
    fn repeated_open_settings_selects_and_focuses_existing_window_without_side_effects() {
        assert_repeated_open_command(TrayCommand::OpenSettings, Tab::Accounts, Tab::Settings);
    }

    #[test]
    fn successful_supervised_sync_emits_exactly_one_close() {
        let (worker_tx, mut worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (_tray_tx, tray_rx) = std_channel();
        let mut app = AutoLoginApp::new(
            worker_tx,
            test_pause_latch(),
            tray_rx,
            worker_event_rx,
            AppConfig::default(),
            true,
            Tab::Accounts,
        );
        let reload_requests = std::cell::Cell::new(0);

        app.sync_saved_config_to_worker_with(false, true, true, || {
            reload_requests.set(reload_requests.get() + 1);
            Ok(())
        });
        app.close_settings_window_after_pending_save = true;

        assert_eq!(reload_requests.get(), 1);
        assert!(worker_rx.try_recv().is_err());

        let ctx = egui::Context::default();
        ctx.begin_pass(Default::default());
        app.close_settings_window_after_successful_sync(&ctx);
        let output = ctx.end_pass();
        assert_eq!(
            output.viewport_output[&egui::ViewportId::ROOT].commands,
            vec![egui::ViewportCommand::Close]
        );
        assert!(!app.close_settings_window_after_sync);
        assert!(!app.close_settings_window_after_pending_save);

        ctx.begin_pass(Default::default());
        app.close_settings_window_after_successful_sync(&ctx);
        let output = ctx.end_pass();
        assert!(output.viewport_output[&egui::ViewportId::ROOT]
            .commands
            .is_empty());
    }

    #[test]
    fn settings_checkbox_sync_keeps_the_settings_window_open() {
        let (worker_tx, _worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (_tray_tx, tray_rx) = std_channel();
        let mut app = AutoLoginApp::new(
            worker_tx,
            test_pause_latch(),
            tray_rx,
            worker_event_rx,
            AppConfig::default(),
            true,
            Tab::Settings,
        );
        let reload_requested = std::cell::Cell::new(false);

        app.sync_saved_config_to_worker_with(false, false, true, || {
            reload_requested.set(true);
            Ok(())
        });

        assert!(reload_requested.get());
        let ctx = egui::Context::default();
        ctx.begin_pass(Default::default());
        app.close_settings_window_after_successful_sync(&ctx);
        let output = ctx.end_pass();
        assert!(output.viewport_output[&egui::ViewportId::ROOT]
            .commands
            .is_empty());
    }

    #[test]
    fn account_sync_keeps_the_accounts_window_open() {
        let (worker_tx, _worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (_tray_tx, tray_rx) = std_channel();
        let mut app = AutoLoginApp::new(
            worker_tx,
            test_pause_latch(),
            tray_rx,
            worker_event_rx,
            AppConfig::default(),
            true,
            Tab::Accounts,
        );
        let reload_requested = std::cell::Cell::new(false);

        app.sync_saved_config_to_worker_with(false, false, true, || {
            reload_requested.set(true);
            Ok(())
        });

        assert!(reload_requested.get());
        let ctx = egui::Context::default();
        ctx.begin_pass(Default::default());
        app.close_settings_window_after_successful_sync(&ctx);
        let output = ctx.end_pass();
        assert!(output.viewport_output[&egui::ViewportId::ROOT]
            .commands
            .is_empty());
    }

    #[test]
    fn explicit_presentation_cancels_an_already_delivered_close_before_acknowledging() {
        for tab in [Tab::Accounts, Tab::Settings] {
            let (worker_tx, _worker_rx) = tokio_channel(8);
            let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
            let (tray_tx, tray_rx) = std_channel();
            let (acknowledgement_tx, acknowledgement_rx) = std_channel();
            let mut app = AutoLoginApp::new(
                worker_tx,
                test_pause_latch(),
                tray_rx,
                worker_event_rx,
                AppConfig::default(),
                true,
                Tab::Accounts,
            );
            app.sync_saved_config_to_worker_with(false, true, true, || Ok(()));
            let command = match tab {
                Tab::Accounts => TrayCommand::PresentAccounts(acknowledgement_tx),
                Tab::Settings => TrayCommand::PresentSettings(acknowledgement_tx),
                #[cfg(feature = "diagnostics-ui")]
                Tab::Diagnose => unreachable!("diagnostics has no presentation command"),
            };
            tray_tx.send(command).unwrap();

            let ctx = egui::Context::default();
            let mut input = egui::RawInput::default();
            input
                .viewports
                .entry(egui::ViewportId::ROOT)
                .or_default()
                .events
                .push(egui::ViewportEvent::Close);
            ctx.begin_pass(input);
            assert!(ctx.input(|input| input.viewport().close_requested()));
            app.process_tray_commands(&ctx);
            app.close_settings_window_after_successful_sync(&ctx);
            let output = ctx.end_pass();

            assert!(acknowledgement_rx.try_recv().is_ok());
            assert_eq!(
                output.viewport_output[&egui::ViewportId::ROOT].commands,
                vec![
                    egui::ViewportCommand::CancelClose,
                    egui::ViewportCommand::Visible(true),
                    egui::ViewportCommand::Minimized(false),
                    egui::ViewportCommand::Focus,
                ]
            );
        }
    }

    #[test]
    fn explicit_presentation_during_pending_save_does_not_rearm_the_delivered_close() {
        for tab in [Tab::Accounts, Tab::Settings] {
            let (worker_tx, _worker_rx) = tokio_channel(8);
            let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
            let (tray_tx, tray_rx) = std_channel();
            let (acknowledgement_tx, acknowledgement_rx) = std_channel();
            let mut app = AutoLoginApp::new(
                worker_tx,
                test_pause_latch(),
                tray_rx,
                worker_event_rx,
                AppConfig::default(),
                true,
                Tab::Accounts,
            );
            app.pending_settings_save =
                Some(crate::ui::settings::PendingSettingsSave::inert_for_test());
            let command = match tab {
                Tab::Accounts => TrayCommand::PresentAccounts(acknowledgement_tx),
                Tab::Settings => TrayCommand::PresentSettings(acknowledgement_tx),
                #[cfg(feature = "diagnostics-ui")]
                Tab::Diagnose => unreachable!("diagnostics has no presentation command"),
            };
            tray_tx.send(command).unwrap();

            let ctx = egui::Context::default();
            let mut input = egui::RawInput::default();
            input
                .viewports
                .entry(egui::ViewportId::ROOT)
                .or_default()
                .events
                .push(egui::ViewportEvent::Close);
            ctx.begin_pass(input);
            app.process_tray_commands(&ctx);
            app.keep_window_open_for_pending_settings_save(&ctx);
            let output = ctx.end_pass();

            assert!(acknowledgement_rx.try_recv().is_ok());
            assert!(!app.close_settings_window_after_pending_save);
            assert_eq!(
                output.viewport_output[&egui::ViewportId::ROOT].commands,
                vec![
                    egui::ViewportCommand::CancelClose,
                    egui::ViewportCommand::Visible(true),
                    egui::ViewportCommand::Minimized(false),
                    egui::ViewportCommand::Focus,
                ]
            );

            app.pending_settings_save = None;
            ctx.begin_pass(Default::default());
            app.close_settings_window_after_successful_sync(&ctx);
            let output = ctx.end_pass();
            assert!(output.viewport_output[&egui::ViewportId::ROOT]
                .commands
                .is_empty());
        }
    }

    #[test]
    fn pending_settings_save_defers_close_until_the_entire_chain_drains() {
        let mut app = mutation_test_app(true);
        app.pending_settings_save =
            Some(crate::ui::settings::PendingSettingsSave::inert_for_test());
        let ctx = egui::Context::default();
        let mut input = egui::RawInput::default();
        input
            .viewports
            .get_mut(&egui::ViewportId::ROOT)
            .expect("default raw input must contain the root viewport")
            .events
            .push(egui::ViewportEvent::Close);

        ctx.begin_pass(input);
        app.keep_window_open_for_pending_settings_save(&ctx);
        let output = ctx.end_pass();

        assert_eq!(
            output.viewport_output[&egui::ViewportId::ROOT].commands,
            vec![egui::ViewportCommand::CancelClose]
        );
        assert!(app.close_settings_window_after_pending_save);
        assert_eq!(
            app.settings_mutations_disabled_reason(),
            Some(SETTINGS_WINDOW_CLOSING_REASON)
        );

        ctx.begin_pass(Default::default());
        app.close_settings_window_after_successful_sync(&ctx);
        let output = ctx.end_pass();
        assert!(output.viewport_output[&egui::ViewportId::ROOT]
            .commands
            .is_empty());
        assert!(app.close_settings_window_after_pending_save);

        app.pending_settings_save = None;
        ctx.begin_pass(Default::default());
        app.close_settings_window_after_successful_sync(&ctx);
        let output = ctx.end_pass();
        assert_eq!(
            output.viewport_output[&egui::ViewportId::ROOT].commands,
            vec![egui::ViewportCommand::Close]
        );
        assert!(!app.close_settings_window_after_pending_save);
    }

    #[test]
    fn pending_account_toggle_defers_manual_close_until_it_drains() {
        let mut app = mutation_test_app(true);
        app.pending_account_toggle = Some(
            crate::ui::accounts::PendingAccountToggle::inert_for_test(app.config.clone()),
        );
        let ctx = egui::Context::default();
        let mut input = egui::RawInput::default();
        input
            .viewports
            .get_mut(&egui::ViewportId::ROOT)
            .expect("default raw input must contain the root viewport")
            .events
            .push(egui::ViewportEvent::Close);

        ctx.begin_pass(input);
        app.keep_window_open_for_pending_settings_save(&ctx);
        let output = ctx.end_pass();

        assert_eq!(
            output.viewport_output[&egui::ViewportId::ROOT].commands,
            vec![egui::ViewportCommand::CancelClose]
        );
        assert!(app.close_settings_window_after_pending_save);

        ctx.begin_pass(Default::default());
        app.close_settings_window_after_successful_sync(&ctx);
        let output = ctx.end_pass();
        assert!(output.viewport_output[&egui::ViewportId::ROOT]
            .commands
            .is_empty());

        app.pending_account_toggle = None;
        ctx.begin_pass(Default::default());
        app.close_settings_window_after_successful_sync(&ctx);
        let output = ctx.end_pass();
        assert_eq!(
            output.viewport_output[&egui::ViewportId::ROOT].commands,
            vec![egui::ViewportCommand::Close]
        );
    }

    #[test]
    fn pending_and_queued_account_transactions_block_close_until_fully_drained() {
        let mut app = mutation_test_app(true);
        app.pending_account_transaction = Some(
            crate::ui::accounts::PendingAccountTransaction::inert_for_test(app.config.clone()),
        );
        app.queued_account_transactions.push_back(
            crate::ui::accounts::AccountTransactionIntent::Delete {
                sequence: 2,
                account_id: "queued-account".to_string(),
            },
        );
        let ctx = egui::Context::default();
        let mut input = egui::RawInput::default();
        input
            .viewports
            .get_mut(&egui::ViewportId::ROOT)
            .expect("default raw input must contain the root viewport")
            .events
            .push(egui::ViewportEvent::Close);

        ctx.begin_pass(input);
        app.keep_window_open_for_pending_settings_save(&ctx);
        let output = ctx.end_pass();
        assert_eq!(
            output.viewport_output[&egui::ViewportId::ROOT].commands,
            vec![egui::ViewportCommand::CancelClose]
        );
        assert!(app.close_settings_window_after_pending_save);

        app.pending_account_transaction = None;
        ctx.begin_pass(Default::default());
        app.close_settings_window_after_successful_sync(&ctx);
        let output = ctx.end_pass();
        assert!(output.viewport_output[&egui::ViewportId::ROOT]
            .commands
            .is_empty());

        app.queued_account_transactions.clear();
        ctx.begin_pass(Default::default());
        app.close_settings_window_after_successful_sync(&ctx);
        let output = ctx.end_pass();
        assert_eq!(
            output.viewport_output[&egui::ViewportId::ROOT].commands,
            vec![egui::ViewportCommand::Close]
        );
    }

    #[test]
    fn quit_waits_for_pending_account_toggle_to_drain() {
        let mut app = mutation_test_app(true);
        app.pending_account_toggle = Some(
            crate::ui::accounts::PendingAccountToggle::inert_for_test(app.config.clone()),
        );
        app.quit_requested = true;
        let ctx = egui::Context::default();

        ctx.begin_pass(Default::default());
        app.close_after_quit_when_settings_saves_are_drained(&ctx);
        let output = ctx.end_pass();
        assert!(output.viewport_output[&egui::ViewportId::ROOT]
            .commands
            .is_empty());

        app.pending_account_toggle = None;
        ctx.begin_pass(Default::default());
        app.close_after_quit_when_settings_saves_are_drained(&ctx);
        let output = ctx.end_pass();
        assert_eq!(
            output.viewport_output[&egui::ViewportId::ROOT].commands,
            vec![egui::ViewportCommand::Close]
        );
    }

    #[test]
    fn background_recovery_signal_uses_prestarted_executor_and_is_tracked_until_completion() {
        let mut app = mutation_test_app(true);
        let owner_thread = std::thread::current().id();
        let executor = app.background_mutation_executor().unwrap();
        let (executor_thread_tx, executor_thread_rx) = std_channel();
        executor
            .try_submit(move || {
                executor_thread_tx
                    .send(std::thread::current().id())
                    .unwrap();
            })
            .unwrap();
        let executor_thread = executor_thread_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("prestarted background mutation executor must run");
        let (started_tx, started_rx) = std_channel();
        let (release_tx, release_rx) = std_channel();
        let ctx = egui::Context::default();

        app.start_background_storage_recovery_signal_with(&ctx, move || {
            started_tx.send(std::thread::current().id()).unwrap();
            release_rx.recv().unwrap();
            Ok(())
        });

        let worker_thread = started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("background recovery signal must start");
        assert_ne!(worker_thread, owner_thread);
        assert_eq!(worker_thread, executor_thread);
        assert!(app.settings_save_in_progress());
        assert!(app.storage_recovery_blocked);

        release_tx.send(()).unwrap();
        for _ in 0..100 {
            app.poll_background_storage_recovery_signal(&ctx);
            if !app.settings_save_in_progress() {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }

        assert!(!app.settings_save_in_progress());
        assert!(app
            .status_message
            .as_ref()
            .is_none_or(|(message, _)| { !message.contains("recovery safety marker could not") }));
    }

    #[test]
    fn saturated_executor_defers_recovery_signal_without_running_it_on_owner_thread() {
        let mut app = mutation_test_app(true);
        let executor = app.background_mutation_executor().unwrap();
        let (started_tx, started_rx) = std_channel();
        let (release_tx, release_rx) = std_channel();
        executor
            .try_submit(move || {
                started_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            })
            .unwrap();
        started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("executor must be occupied before saturating its queue");
        for _ in 0..super::BACKGROUND_MUTATION_QUEUE_CAPACITY {
            executor.try_submit(|| {}).unwrap();
        }

        let job_ran = Arc::new(AtomicBool::new(false));
        let job_ran_from_worker = job_ran.clone();
        let ctx = egui::Context::default();
        app.start_background_storage_recovery_signal_with(&ctx, move || {
            job_ran_from_worker.store(true, AtomicOrdering::Release);
            Ok(())
        });

        assert!(app.pending_storage_recovery_signal.is_none());
        assert!(app.storage_recovery_signal_retry_at.is_some());
        assert!(app.storage_recovery_blocked);
        assert!(!job_ran.load(AtomicOrdering::Acquire));
        release_tx.send(()).unwrap();
    }

    #[test]
    fn recovery_signal_owner_path_has_no_thread_creation_or_waiting_channel_operation() {
        let source = include_str!("app.rs");
        let body = source
            .split_once("fn start_background_storage_recovery_signal_with<J>")
            .expect("recovery submission function must exist")
            .1
            .split_once("fn poll_background_storage_recovery_signal")
            .expect("recovery submission function boundary must exist")
            .0;

        assert!(body.contains("executor.try_submit"));
        assert!(!body.contains("thread::Builder"));
        assert!(!body.contains(".spawn("));
        assert!(!body.contains(".recv("));
        assert!(!body.contains(".send("));
    }

    #[test]
    fn failed_recovery_signal_remains_pending_for_retry_and_blocks_close() {
        let mut app = mutation_test_app(true);
        app.status_message = None;
        let ctx = egui::Context::default();

        app.start_background_storage_recovery_signal_with(&ctx, || {
            anyhow::bail!("low-level recovery detail")
        });
        for _ in 0..100 {
            app.poll_background_storage_recovery_signal(&ctx);
            if app.pending_storage_recovery_signal.is_none()
                && app.storage_recovery_signal_retry_at.is_some()
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }

        assert!(app.pending_storage_recovery_signal.is_none());
        assert!(app.storage_recovery_signal_retry_at.is_some());
        assert!(app.settings_save_in_progress());
        assert!(app.status_message.is_none());

        ctx.begin_pass(Default::default());
        app.close_settings_window_after_successful_sync(&ctx);
        let output = ctx.end_pass();
        assert!(output.viewport_output[&egui::ViewportId::ROOT]
            .commands
            .is_empty());
    }

    #[test]
    fn supervisor_quit_keeps_pending_settings_save_alive_until_it_drains() {
        let (worker_tx, _worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (tray_tx, tray_rx) = std_channel();
        let mut app = AutoLoginApp::new(
            worker_tx,
            test_pause_latch(),
            tray_rx,
            worker_event_rx,
            AppConfig::default(),
            true,
            Tab::Settings,
        );
        app.pending_settings_save =
            Some(crate::ui::settings::PendingSettingsSave::inert_for_test());
        tray_tx.send(TrayCommand::Exit).unwrap();
        let ctx = egui::Context::default();

        ctx.begin_pass(Default::default());
        app.process_tray_commands(&ctx);
        app.close_after_quit_when_settings_saves_are_drained(&ctx);
        let output = ctx.end_pass();
        assert!(app.quit_requested);
        assert!(app.pending_settings_save.is_some());
        assert_eq!(
            output.viewport_output[&egui::ViewportId::ROOT].commands,
            vec![egui::ViewportCommand::Close]
        );

        let mut input = egui::RawInput::default();
        input
            .viewports
            .get_mut(&egui::ViewportId::ROOT)
            .expect("default raw input must contain the root viewport")
            .events
            .push(egui::ViewportEvent::Close);
        ctx.begin_pass(input);
        app.keep_window_open_for_pending_settings_save(&ctx);
        app.close_after_quit_when_settings_saves_are_drained(&ctx);
        let output = ctx.end_pass();
        assert_eq!(
            output.viewport_output[&egui::ViewportId::ROOT].commands,
            vec![egui::ViewportCommand::CancelClose]
        );

        app.pending_settings_save = None;
        ctx.begin_pass(Default::default());
        app.close_after_quit_when_settings_saves_are_drained(&ctx);
        let output = ctx.end_pass();
        assert_eq!(
            output.viewport_output[&egui::ViewportId::ROOT].commands,
            vec![egui::ViewportCommand::Close]
        );
    }

    #[test]
    fn manual_close_during_pending_save_survives_recovery_and_emits_exactly_one_close() {
        let mut app = mutation_test_app(true);
        app.pending_settings_save =
            Some(crate::ui::settings::PendingSettingsSave::inert_for_test());
        let ctx = egui::Context::default();
        let mut input = egui::RawInput::default();
        input
            .viewports
            .get_mut(&egui::ViewportId::ROOT)
            .expect("default raw input must contain the root viewport")
            .events
            .push(egui::ViewportEvent::Close);

        ctx.begin_pass(input);
        app.keep_window_open_for_pending_settings_save(&ctx);
        app.apply_background_storage_recovery_block();
        let output = ctx.end_pass();

        assert_eq!(
            output.viewport_output[&egui::ViewportId::ROOT].commands,
            vec![egui::ViewportCommand::CancelClose]
        );
        assert!(!app.close_settings_window_after_sync);
        assert!(app.close_settings_window_after_pending_save);

        app.pending_settings_save = None;
        ctx.begin_pass(Default::default());
        app.close_settings_window_after_successful_sync(&ctx);
        let output = ctx.end_pass();
        assert_eq!(
            output.viewport_output[&egui::ViewportId::ROOT].commands,
            vec![egui::ViewportCommand::Close]
        );

        ctx.begin_pass(Default::default());
        app.close_settings_window_after_successful_sync(&ctx);
        let output = ctx.end_pass();
        assert!(output.viewport_output[&egui::ViewportId::ROOT]
            .commands
            .is_empty());
    }

    #[test]
    fn presentation_and_save_in_the_same_ui_pass_keep_the_presented_window_open() {
        let (worker_tx, _worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (_tray_tx, tray_rx) = std_channel();
        let mut app = AutoLoginApp::new(
            worker_tx,
            test_pause_latch(),
            tray_rx,
            worker_event_rx,
            AppConfig::default(),
            true,
            Tab::Settings,
        );
        let ctx = egui::Context::default();
        let acknowledgement_sent = std::cell::Cell::new(false);

        let _ = ctx.run_ui(Default::default(), |ui| {
            app.present_tab(ui.ctx(), Tab::Accounts, || {
                acknowledgement_sent.set(true);
            });
            app.sync_saved_config_to_worker_with(false, true, true, || Ok(()));
        });

        assert!(acknowledgement_sent.get());
        assert_eq!(app.selected_tab, Tab::Accounts);
        assert!(app.keep_settings_window_open_through_ui_pass);
        assert!(!app.close_settings_window_after_sync);

        // The guard is pass-scoped, not sticky: an ordinary later save still
        // gets the requested auto-close behavior.
        app.keep_settings_window_open_through_ui_pass = false;
        app.sync_saved_config_to_worker_with(false, true, true, || Ok(()));
        assert!(app.close_settings_window_after_sync);
    }

    #[test]
    fn close_cancellation_and_focus_are_queued_before_the_internal_ack() {
        for tab in [Tab::Accounts, Tab::Settings] {
            let (worker_tx, _worker_rx) = tokio_channel(8);
            let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
            let (_tray_tx, tray_rx) = std_channel();
            let mut app = AutoLoginApp::new(
                worker_tx,
                test_pause_latch(),
                tray_rx,
                worker_event_rx,
                AppConfig::default(),
                true,
                Tab::Accounts,
            );
            let ctx = egui::Context::default();
            let commands_at_ack = std::cell::RefCell::new(None);
            let mut input = egui::RawInput::default();
            input
                .viewports
                .get_mut(&egui::ViewportId::ROOT)
                .expect("default raw input must contain the root viewport")
                .events
                .push(egui::ViewportEvent::Close);

            let output = ctx.run_ui(input, |ui| {
                app.present_tab(ui.ctx(), tab, || {
                    commands_at_ack.replace(Some(
                        ui.ctx().viewport_for(egui::ViewportId::ROOT, |viewport| {
                            viewport.commands.clone()
                        }),
                    ));
                });
            });
            let expected = vec![
                egui::ViewportCommand::CancelClose,
                egui::ViewportCommand::Visible(true),
                egui::ViewportCommand::Minimized(false),
                egui::ViewportCommand::Focus,
            ];

            assert_eq!(
                commands_at_ack.into_inner().unwrap(),
                expected,
                "internal ACK ran before cancellation and focus were queued"
            );
            assert_eq!(
                output.viewport_output[&egui::ViewportId::ROOT].commands,
                expected
            );
        }
    }

    #[test]
    fn local_sync_does_not_close_the_primary_window() {
        let (worker_tx, mut worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (_tray_tx, tray_rx) = std_channel();
        let mut app = AutoLoginApp::new(
            worker_tx,
            test_pause_latch(),
            tray_rx,
            worker_event_rx,
            AppConfig::default(),
            false,
            Tab::Accounts,
        );

        app.sync_saved_config_to_worker_with(false, true, true, || {
            panic!("local sync must not request a supervisor reload")
        });

        assert!(matches!(
            worker_rx.try_recv(),
            Ok(WorkerCommand::ApplyConfigAndReleasePause { .. })
        ));
        let ctx = egui::Context::default();
        ctx.begin_pass(Default::default());
        app.close_settings_window_after_successful_sync(&ctx);
        let output = ctx.end_pass();
        assert!(output.viewport_output[&egui::ViewportId::ROOT]
            .commands
            .is_empty());
    }

    #[test]
    fn background_local_sync_rechecks_recovery_before_releasing_worker() {
        let (worker_tx, mut worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (_tray_tx, tray_rx) = std_channel();
        let mut app = AutoLoginApp::new(
            worker_tx,
            test_pause_latch(),
            tray_rx,
            worker_event_rx,
            AppConfig::default(),
            false,
            Tab::Settings,
        );

        assert!(!app.sync_background_saved_config_to_local_worker_with_recovery_state(false, false));
        assert!(app.storage_recovery_blocked);
        assert!(matches!(worker_rx.try_recv(), Ok(WorkerCommand::Stop)));
        assert!(worker_rx.try_recv().is_err());
    }

    #[test]
    fn blocked_or_failed_supervised_sync_never_schedules_close() {
        let (worker_tx, _worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (_tray_tx, tray_rx) = std_channel();
        let mut app = AutoLoginApp::new(
            worker_tx,
            test_pause_latch(),
            tray_rx,
            worker_event_rx,
            AppConfig::default(),
            true,
            Tab::Accounts,
        );

        app.set_status("Account saved");
        let reload_requested = std::cell::Cell::new(false);
        app.sync_saved_config_to_worker_with(false, true, false, || {
            reload_requested.set(true);
            Ok(())
        });
        assert!(!reload_requested.get());
        assert!(app.storage_recovery_blocked);
        assert!(!app.close_settings_window_after_sync);
        let recovery_status = &app.status_message.as_ref().unwrap().0;
        assert!(recovery_status.contains("Account saved"));
        assert!(recovery_status.contains("recovery could not be verified"));

        app.storage_recovery_blocked = false;
        app.set_status("Account deleted. Old fallback key cleanup failed");
        app.sync_saved_config_to_worker_with(false, true, true, || {
            anyhow::bail!("reload unavailable")
        });
        assert!(!app.close_settings_window_after_sync);
        let reload_status = &app.status_message.as_ref().unwrap().0;
        assert!(reload_status.contains("Old fallback key cleanup failed"));
        assert!(reload_status.contains("could not reload the saved changes"));
        assert!(reload_status.contains("reload unavailable"));
    }

    #[test]
    fn log_redaction_removes_email_addresses_and_secret_assignments() {
        let redacted = redact_sensitive_log_text(
            "failed for user@example.com password=super-secret token: abc123; secret = value",
        );

        assert!(redacted.contains("[email]"));
        assert!(redacted.contains("password=[redacted]"));
        assert!(redacted.contains("token: [redacted];"));
        assert!(redacted.contains("secret = [redacted]"));
        assert!(!redacted.contains("user@example.com"));
        assert!(!redacted.contains("super-secret"));
        assert!(!redacted.contains("abc123"));
        assert!(!redacted.contains(" value"));
    }

    #[test]
    fn log_redaction_does_not_rewrite_plain_password_words() {
        let redacted = redact_sensitive_log_text("password was not loaded for prompt");

        assert_eq!(redacted, "password was not loaded for prompt");
    }

    #[test]
    fn log_redaction_handles_quoted_and_uppercase_secret_assignments() {
        let redacted = redact_sensitive_log_text(
            "PASSWORD=\"secret with spaces\" PASSCODE: 123456 token='abc def'",
        );

        assert!(redacted.contains("PASSWORD=[redacted]"));
        assert!(redacted.contains("PASSCODE: [redacted]"));
        assert!(redacted.contains("token=[redacted]"));
        assert!(!redacted.contains("secret with spaces"));
        assert!(!redacted.contains("123456"));
        assert!(!redacted.contains("abc def"));
    }

    #[test]
    fn log_buffer_caps_entries_and_keeps_recent_events() {
        let mut logs = VecDeque::new();
        for idx in 0..(MAX_LOG_ENTRIES + 7) {
            push_bounded_log(
                &mut logs,
                LogEntry {
                    timestamp: format!("{idx:02}"),
                    level: LogLevel::Info,
                    message: format!("event {idx}"),
                },
            );
        }

        assert_eq!(logs.len(), MAX_LOG_ENTRIES);
        assert_eq!(
            logs.front().map(|entry| entry.message.as_str()),
            Some("event 7")
        );
        let expected_last = format!("event {}", MAX_LOG_ENTRIES + 6);
        assert_eq!(
            logs.back().map(|entry| entry.message.as_str()),
            Some(expected_last.as_str())
        );
    }

    #[test]
    fn log_buffer_redacts_before_retaining_message() {
        let mut logs = VecDeque::new();
        push_bounded_log(
            &mut logs,
            LogEntry {
                timestamp: "00:00".to_string(),
                level: LogLevel::Warn,
                message: "user@example.com password=super-secret token=abc".to_string(),
            },
        );

        let message = &logs[0].message;
        assert!(message.contains("[email]"));
        assert!(message.contains("password=[redacted]"));
        assert!(message.contains("token=[redacted]"));
        assert!(!message.contains("user@example.com"));
        assert!(!message.contains("super-secret"));
    }

    #[test]
    fn log_buffer_redacts_path_assignments_before_retaining_message() {
        let mut logs = VecDeque::new();
        push_bounded_log(
            &mut logs,
            LogEntry {
                timestamp: "00:00".to_string(),
                level: LogLevel::Warn,
                message: "current_process_path=/Users/alice/Private Projects/target/debug/windows-app-autologin app_bundle_path=/Users/alice/Applications/Windows App AutoLogin.app".to_string(),
            },
        );

        let message = &logs[0].message;
        assert!(message.contains("current_process_path=[path]"));
        assert!(message.contains("app_bundle_path=[path]"));
        assert!(!message.contains("windows-app-autologin"));
        assert!(!message.contains("Windows App AutoLogin.app"));
        assert!(!message.contains("/Users/alice"));
        assert!(!message.contains("Private Projects"));
        assert!(!message.contains("Applications"));
    }

    #[test]
    fn accessibility_event_log_redacts_paths_with_spaces_before_retaining_message() {
        let status = AccessibilityStatus {
            trusted: false,
            raw_trusted: true,
            identity_trusted: false,
            current_process_path:
                "/Applications/Windows App AutoLogin.app/Contents/MacOS/windows-app-autologin"
                    .to_string(),
            app_bundle_path: "/Applications/Windows App AutoLogin.app".to_string(),
        };

        let mut logs = VecDeque::new();
        push_bounded_log(
            &mut logs,
            LogEntry {
                timestamp: "00:00".to_string(),
                level: LogLevel::Warn,
                message: accessibility_log_message("accessibility_still_missing", &status),
            },
        );

        let message = &logs[0].message;
        assert!(message.contains(" trusted=false raw_trusted=true identity_trusted=false "));
        assert!(!message.contains("ax_trusted_for_current_process"));
        assert!(message.contains("current_process_path_redacted=[path]"));
        assert!(message.contains("app_bundle_path_redacted=[path]"));
        assert!(!message.contains("windows-app-autologin"));
        assert!(!message.contains("Windows App AutoLogin.app"));
        assert!(!message.contains("/Applications"));
        assert!(!message.contains("Contents/MacOS"));
        assert!(!message.contains("current_process_path=/"));
        assert!(!message.contains("app_bundle_path=/"));
    }

    #[test]
    fn accessibility_onboarding_copy_is_user_facing() {
        fn collect_text(shape: &egui::Shape, rendered_text: &mut String) {
            match shape {
                egui::Shape::Text(text) => {
                    rendered_text.push_str(text.galley.text());
                    rendered_text.push('\n');
                }
                egui::Shape::Vec(shapes) => {
                    for shape in shapes {
                        collect_text(shape, rendered_text);
                    }
                }
                _ => {}
            }
        }

        let mut app = mutation_test_app(false);
        app.accessibility_status = AccessibilityStatus {
            trusted: false,
            raw_trusted: false,
            identity_trusted: true,
            current_process_path:
                "/Users/test/Private Builds/SENTINEL.app/Contents/MacOS/windows-app-autologin"
                    .to_string(),
            app_bundle_path: "/Users/test/Private Builds/SENTINEL.app".to_string(),
        };
        let ctx = egui::Context::default();
        let output = ctx.run_ui(Default::default(), |ui| {
            show_accessibility_onboarding(ui, &mut app);
        });
        let mut rendered_text = String::new();
        for clipped_shape in &output.shapes {
            collect_text(&clipped_shape.shape, &mut rendered_text);
        }
        let rendered_text_lowercase = rendered_text.to_lowercase();

        assert!(rendered_text.contains(ACCESSIBILITY_SETTINGS_INSTRUCTIONS));
        assert!(rendered_text.contains("Windows App AutoLogin"));
        assert!(!rendered_text_lowercase.contains("exact app bundle"));
        assert!(!rendered_text_lowercase.contains("bundle to allow"));
        assert!(!rendered_text_lowercase.contains("sentinel"));
        assert!(!rendered_text_lowercase.contains("/users/"));
        assert!(!rendered_text_lowercase.contains("/applications/"));
        assert!(!rendered_text_lowercase.contains("/private/"));
        assert!(!rendered_text_lowercase.contains("contents/macos"));
    }

    #[test]
    fn inconsistent_or_untrusted_grant_snapshot_is_fail_closed() {
        let (worker_tx, mut worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (_tray_tx, tray_rx) = std_channel();
        let mut app = AutoLoginApp::new(
            worker_tx,
            test_pause_latch(),
            tray_rx,
            worker_event_rx,
            AppConfig::default(),
            false,
            Tab::Accounts,
        );
        app.worker_status = WorkerStatus::Idle;

        for (trusted, raw_trusted, identity_trusted) in [
            (false, true, true),
            (true, false, true),
            (true, true, false),
        ] {
            app.logs.clear();
            app.status_message = None;

            assert!(
                !app.apply_accessibility_granted_status(AccessibilityStatus {
                    trusted,
                    raw_trusted,
                    identity_trusted,
                    current_process_path: "/snapshot/current-executable".to_string(),
                    app_bundle_path: "/snapshot/WindowsAppAutoLogin.app".to_string(),
                })
            );
            assert!(!app.accessibility_status.trusted);
            assert!(app.status_message.is_none());
            assert!(!app
                .logs
                .iter()
                .any(|entry| entry.message.contains("accessibility_granted")));
            assert!(worker_rx.try_recv().is_err());
        }
    }

    #[test]
    fn accessibility_poll_detects_permission_loss_and_stops_the_worker() {
        let (worker_tx, mut worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (_tray_tx, tray_rx) = std_channel();
        let mut app = AutoLoginApp::new(
            worker_tx,
            test_pause_latch(),
            tray_rx,
            worker_event_rx,
            AppConfig::default(),
            false,
            Tab::Accounts,
        );
        app.accessibility_status = AccessibilityStatus {
            trusted: true,
            raw_trusted: true,
            identity_trusted: true,
            current_process_path: "/old/current-executable".to_string(),
            app_bundle_path: "/old/WindowsAppAutoLogin.app".to_string(),
        };
        app.accessibility_last_missing_log = Some(std::time::Instant::now());
        app.worker_status = WorkerStatus::Running;
        app.logs.clear();

        app.apply_polled_accessibility_status(AccessibilityStatus {
            trusted: false,
            raw_trusted: false,
            identity_trusted: true,
            current_process_path: "/current/current-executable".to_string(),
            app_bundle_path: "/current/WindowsAppAutoLogin.app".to_string(),
        });

        assert!(!app.accessibility_status.trusted);
        assert_eq!(
            app.accessibility_status.app_bundle_path,
            "/current/WindowsAppAutoLogin.app"
        );
        assert!(app
            .logs
            .iter()
            .any(|entry| entry.message.contains("accessibility_permission_lost")));
        assert!(matches!(worker_rx.try_recv(), Ok(WorkerCommand::Stop)));
        assert!(worker_rx.try_recv().is_err());
    }

    #[test]
    fn accessibility_poll_applies_one_granted_snapshot_and_starts_idle_worker() {
        let (worker_tx, mut worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (_tray_tx, tray_rx) = std_channel();
        let mut app = AutoLoginApp::new(
            worker_tx,
            test_pause_latch(),
            tray_rx,
            worker_event_rx,
            AppConfig::default(),
            false,
            Tab::Accounts,
        );
        app.accessibility_status = AccessibilityStatus {
            trusted: false,
            raw_trusted: false,
            identity_trusted: true,
            current_process_path: "/old/current-executable".to_string(),
            app_bundle_path: "/old/WindowsAppAutoLogin.app".to_string(),
        };
        app.worker_status = WorkerStatus::Idle;

        app.apply_polled_accessibility_status(AccessibilityStatus {
            trusted: true,
            raw_trusted: true,
            identity_trusted: true,
            current_process_path:
                "/snapshot/WindowsAppAutoLogin.app/Contents/MacOS/windows-app-autologin"
                    .to_string(),
            app_bundle_path: "/snapshot/WindowsAppAutoLogin.app".to_string(),
        });

        assert!(app.accessibility_status.trusted);
        assert_eq!(
            app.accessibility_status.app_bundle_path,
            "/snapshot/WindowsAppAutoLogin.app"
        );
        assert!(app.status_message.as_ref().is_some_and(
            |(message, _)| message == "Accessibility permission granted. Starting monitor."
        ));
        match worker_rx.try_recv().unwrap() {
            WorkerCommand::Start => {}
            other => panic!("expected Start, got {other:?}"),
        }
    }

    #[test]
    fn steady_trusted_poll_updates_snapshot_without_restarting_monitor() {
        let (worker_tx, mut worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (_tray_tx, tray_rx) = std_channel();
        let mut app = AutoLoginApp::new(
            worker_tx,
            test_pause_latch(),
            tray_rx,
            worker_event_rx,
            AppConfig::default(),
            false,
            Tab::Accounts,
        );
        app.accessibility_status = AccessibilityStatus {
            trusted: true,
            raw_trusted: true,
            identity_trusted: true,
            current_process_path: "/first/current-executable".to_string(),
            app_bundle_path: "/first/WindowsAppAutoLogin.app".to_string(),
        };
        app.worker_status = WorkerStatus::Idle;
        app.logs.clear();
        app.status_message = None;

        app.apply_polled_accessibility_status(AccessibilityStatus {
            trusted: true,
            raw_trusted: true,
            identity_trusted: true,
            current_process_path: "/second/current-executable".to_string(),
            app_bundle_path: "/second/WindowsAppAutoLogin.app".to_string(),
        });

        assert_eq!(
            app.accessibility_status.app_bundle_path,
            "/second/WindowsAppAutoLogin.app"
        );
        assert!(app.status_message.is_none());
        assert!(!app
            .logs
            .iter()
            .any(|entry| entry.message.contains("accessibility_granted")));
        assert!(worker_rx.try_recv().is_err());
    }

    #[test]
    fn settings_child_accessibility_grant_does_not_override_supervisor_stop_intent() {
        let (worker_tx, mut worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (_tray_tx, tray_rx) = std_channel();
        let mut app = AutoLoginApp::new(
            worker_tx,
            test_pause_latch(),
            tray_rx,
            worker_event_rx,
            AppConfig::default(),
            true,
            Tab::Accounts,
        );
        app.worker_status = WorkerStatus::Idle;

        assert!(app.apply_accessibility_granted_status(AccessibilityStatus {
            trusted: true,
            raw_trusted: true,
            identity_trusted: true,
            current_process_path: "/Applications/WindowsAppAutoLogin.app".to_string(),
            app_bundle_path: "/Applications/WindowsAppAutoLogin.app".to_string(),
        }));

        assert!(app.accessibility_status.trusted);
        assert!(app
            .status_message
            .as_ref()
            .is_some_and(|(message, _)| message == "Accessibility permission granted."));
        assert!(worker_rx.try_recv().is_err());
    }

    #[test]
    fn pending_storage_recovery_queues_stop_even_when_cached_status_is_idle() {
        let (worker_tx, mut worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (_tray_tx, tray_rx) = std_channel();
        let pause_latch = test_pause_latch();
        let mut app = AutoLoginApp::new(
            worker_tx,
            pause_latch.clone(),
            tray_rx,
            worker_event_rx,
            AppConfig::default(),
            false,
            Tab::Accounts,
        );
        app.worker_status = WorkerStatus::Idle;

        app.stop_monitor_for_pending_storage_recovery();

        assert!(!app.account_mutations_ready());
        assert!(pause_latch.is_paused());
        match worker_rx.try_recv().unwrap() {
            WorkerCommand::Stop => {}
            other => panic!("expected Stop, got {other:?}"),
        }
        assert_eq!(app.worker_status, WorkerStatus::Idle);
    }

    #[test]
    fn pending_storage_recovery_rejects_every_local_start_path() {
        let (worker_tx, mut worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (_tray_tx, tray_rx) = std_channel();
        let pause_latch = test_pause_latch();
        let mut app = AutoLoginApp::new(
            worker_tx,
            pause_latch.clone(),
            tray_rx,
            worker_event_rx,
            AppConfig::default(),
            false,
            Tab::Accounts,
        )
        .with_storage_recovery_state(false);

        assert!(app.apply_accessibility_granted_status(AccessibilityStatus {
            trusted: true,
            raw_trusted: true,
            identity_trusted: true,
            current_process_path: "/Applications/WindowsAppAutoLogin.app".to_string(),
            app_bundle_path: "/Applications/WindowsAppAutoLogin.app".to_string(),
        }));
        app.send_worker_command(WorkerCommand::Start);

        assert!(pause_latch.is_paused());
        assert_eq!(app.worker_status, WorkerStatus::Idle);
        assert!(worker_rx.try_recv().is_err());
    }

    #[test]
    fn full_apply_queue_leaves_worker_synchronously_paused() {
        let (worker_tx, mut worker_rx) = tokio_channel(1);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (_tray_tx, tray_rx) = std_channel();
        let pause_latch = test_pause_latch();
        worker_tx.try_send(WorkerCommand::Start).unwrap();
        let mut app = AutoLoginApp::new(
            worker_tx,
            pause_latch.clone(),
            tray_rx,
            worker_event_rx,
            AppConfig::default(),
            false,
            Tab::Accounts,
        );
        app.worker_status = WorkerStatus::Running;

        app.sync_saved_config_to_worker(true);

        assert!(pause_latch.is_paused());
        assert_eq!(app.worker_status, WorkerStatus::Idle);
        assert!(matches!(worker_rx.try_recv(), Ok(WorkerCommand::Start)));
        assert!(worker_rx.try_recv().is_err());
    }

    #[test]
    fn sticky_recovery_never_queues_a_config_release() {
        let (worker_tx, mut worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (_tray_tx, tray_rx) = std_channel();
        let pause_latch = test_pause_latch();
        let mut app = AutoLoginApp::new(
            worker_tx,
            pause_latch.clone(),
            tray_rx,
            worker_event_rx,
            AppConfig::default(),
            false,
            Tab::Accounts,
        )
        .with_storage_recovery_state(false);
        app.worker_status = WorkerStatus::Running;

        app.sync_saved_config_to_worker(true);

        assert!(pause_latch.is_paused());
        assert!(matches!(worker_rx.try_recv(), Ok(WorkerCommand::Stop)));
        assert!(worker_rx.try_recv().is_err());
    }

    #[test]
    fn successful_local_apply_releases_only_its_pause_epoch() {
        let (worker_tx, mut worker_rx) = tokio_channel(2);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (_tray_tx, tray_rx) = std_channel();
        let pause_latch = test_pause_latch();
        let mut app = AutoLoginApp::new(
            worker_tx,
            pause_latch.clone(),
            tray_rx,
            worker_event_rx,
            AppConfig::default(),
            false,
            Tab::Accounts,
        );
        app.worker_status = WorkerStatus::Running;

        app.sync_saved_config_to_worker(true);

        assert!(pause_latch.is_paused());
        match worker_rx.try_recv().unwrap() {
            WorkerCommand::ApplyConfigAndReleasePause {
                refresh_passwords,
                start_monitor,
                pause_epoch,
                ..
            } => {
                assert!(refresh_passwords);
                assert!(start_monitor);
                assert_eq!(pause_epoch, pause_latch.current_epoch());
            }
            other => panic!("expected atomic config apply, got {other:?}"),
        }
    }

    #[test]
    fn startup_recovery_failure_keeps_account_mutations_sticky_blocked() {
        let (worker_tx, _worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (_tray_tx, tray_rx) = std_channel();
        let app = AutoLoginApp::new(
            worker_tx,
            test_pause_latch(),
            tray_rx,
            worker_event_rx,
            AppConfig::default(),
            false,
            Tab::Accounts,
        )
        .with_storage_recovery_state(false);

        assert!(!app.account_mutations_ready());
    }

    #[test]
    fn background_mutation_executor_is_prestarted_fifo_and_never_waits_when_full() {
        let executor = BackgroundMutationExecutor::spawn().unwrap();
        let owner_thread = std::thread::current().id();
        let (started_tx, started_rx) = std_channel();
        let (release_tx, release_rx) = std_channel();
        let (events_tx, events_rx) = std_channel();

        let first_events = events_tx.clone();
        executor
            .try_submit(move || {
                started_tx.send(std::thread::current().id()).unwrap();
                release_rx.recv().unwrap();
                first_events.send(1_u8).unwrap();
            })
            .unwrap();
        let executor_thread = started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_ne!(executor_thread, owner_thread);

        executor
            .try_submit(move || {
                events_tx.send(2_u8).unwrap();
            })
            .unwrap();
        let rejection_started = std::time::Instant::now();
        let error = executor.try_submit(|| {}).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
        assert!(rejection_started.elapsed() < Duration::from_millis(50));

        release_tx.send(()).unwrap();
        assert_eq!(events_rx.recv_timeout(Duration::from_secs(1)).unwrap(), 1);
        assert_eq!(events_rx.recv_timeout(Duration::from_secs(1)).unwrap(), 2);
    }

    #[test]
    fn background_mutation_executor_stops_after_an_ambiguous_panic() {
        let executor = BackgroundMutationExecutor::spawn().unwrap();
        let (started_tx, started_rx) = std_channel();
        let (panic_tx, panic_rx) = std_channel();
        let (queued_ran_tx, queued_ran_rx) = std_channel();

        executor
            .try_submit(move || {
                started_tx.send(()).unwrap();
                panic_rx.recv().unwrap();
                panic!("synthetic background mutation panic");
            })
            .unwrap();
        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        executor
            .try_submit(move || {
                let _ = queued_ran_tx.send(());
            })
            .unwrap();
        panic_tx.send(()).unwrap();

        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        loop {
            if executor
                .try_submit(|| {})
                .is_err_and(|error| error.kind() == std::io::ErrorKind::BrokenPipe)
            {
                break;
            }
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(executor
            .try_submit(|| {})
            .is_err_and(|error| { error.kind() == std::io::ErrorKind::BrokenPipe }));
        assert!(queued_ran_rx
            .recv_timeout(Duration::from_millis(50))
            .is_err());
    }

    #[test]
    fn rejected_first_local_submission_releases_exact_pause_without_worker_command() {
        let (worker_tx, mut worker_rx) = tokio_channel(2);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(2);
        let (_tray_tx, tray_rx) = std_channel();
        let pause_latch = test_pause_latch();
        let mut app = AutoLoginApp::new(
            worker_tx,
            pause_latch.clone(),
            tray_rx,
            worker_event_rx,
            AppConfig::default(),
            false,
            Tab::Accounts,
        );
        let guard = app.reserve_background_settings_mutation().unwrap();
        let _begin = app.prepare_background_settings_mutation_begin();
        let pause_epoch = pause_latch.current_epoch();
        drop(guard);

        app.reject_background_mutation_submission(false, false);

        assert!(!pause_latch.is_paused());
        assert_eq!(pause_latch.current_epoch(), pause_epoch);
        assert!(worker_rx.try_recv().is_err());
        assert_eq!(
            app.settings_save_fail_closed_reason(),
            Some(super::BACKGROUND_MUTATION_EXECUTOR_UNAVAILABLE_REASON)
        );
    }

    #[test]
    fn rejected_follow_up_submission_applies_authoritative_config_before_release() {
        let (worker_tx, mut worker_rx) = tokio_channel(2);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(2);
        let (_tray_tx, tray_rx) = std_channel();
        let pause_latch = test_pause_latch();
        let mut config = AppConfig::default();
        config.settings.start_minimized = true;
        let mut app = AutoLoginApp::new(
            worker_tx,
            pause_latch.clone(),
            tray_rx,
            worker_event_rx,
            config.clone(),
            false,
            Tab::Settings,
        );
        let guard = app.reserve_background_settings_mutation().unwrap();
        let _begin = app.prepare_background_settings_mutation_begin();
        let pause_epoch = pause_latch.current_epoch();
        drop(guard);

        app.reject_background_mutation_submission(true, true);

        assert!(pause_latch.is_paused());
        match worker_rx.try_recv().unwrap() {
            WorkerCommand::ApplyConfigAndReleasePause {
                settings,
                accounts,
                refresh_passwords,
                pause_epoch: released_epoch,
                ..
            } => {
                assert_eq!(settings, config.settings);
                assert_eq!(accounts, config.accounts);
                assert!(refresh_passwords);
                assert_eq!(released_epoch, pause_epoch);
            }
            other => panic!("expected authoritative atomic release, got {other:?}"),
        }
        assert!(worker_rx.try_recv().is_err());
    }

    #[test]
    fn rejected_submission_never_opens_a_newer_safety_pause() {
        let (worker_tx, mut worker_rx) = tokio_channel(2);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(2);
        let (_tray_tx, tray_rx) = std_channel();
        let pause_latch = test_pause_latch();
        let mut app = AutoLoginApp::new(
            worker_tx,
            pause_latch.clone(),
            tray_rx,
            worker_event_rx,
            AppConfig::default(),
            false,
            Tab::Accounts,
        );
        let guard = app.reserve_background_settings_mutation().unwrap();
        let _begin = app.prepare_background_settings_mutation_begin();
        let stale_epoch = pause_latch.current_epoch();
        let fresh_epoch = pause_latch.pause_with_epoch();
        assert!(fresh_epoch > stale_epoch);
        drop(guard);

        app.reject_background_mutation_submission(false, false);

        assert!(pause_latch.owns_pause(fresh_epoch));
        assert!(worker_rx.try_recv().is_err());
        assert_eq!(
            app.settings_save_fail_closed_reason(),
            Some(LOCAL_CONFIG_RELEASE_FAILED_REASON)
        );
    }
}
