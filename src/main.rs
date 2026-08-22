#![cfg_attr(
    all(target_os = "windows", not(debug_assertions)),
    windows_subsystem = "windows"
)]
#[cfg(all(waal_release_profile, debug_assertions))]
compile_error!(
    "release profile must not enable debug assertions; --debug-fill-once is development-only"
);
#[cfg(all(
    feature = "diagnostics-ui",
    not(debug_assertions),
    not(feature = "release-diagnostics")
))]
compile_error!(
    "diagnostics-ui is development-only in release builds; enable release-diagnostics only for intentional support artifacts"
);

mod app;
mod app_identity;
mod autologin;
mod autostart;
mod background;
mod config;
mod debug_fill;
#[cfg(target_os = "macos")]
mod macos_ax;
mod macos_identity;
mod models;
mod monitor;
mod private_permissions;
mod single_instance;
mod storage;
mod tray;
mod ui;
mod user_paths;
#[cfg(target_os = "windows")]
mod windows_ui;

#[cfg(any(target_os = "macos", target_os = "windows"))]
include!(concat!(env!("OUT_DIR"), "/waal_build_metadata.rs"));

use eframe::egui;
use std::process::{Child, Command};
use std::sync::mpsc::{channel as std_channel, Receiver as StdReceiver, Sender as StdSender};
use std::time::{Duration, Instant};
use tokio::runtime::Runtime;
use tokio::sync::mpsc::{
    channel as tokio_channel, Receiver as TokioReceiver, Sender as TokioSender,
};
use winit::application::ApplicationHandler;
use winit::event::{StartCause, WindowEvent};
use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop};
use winit::window::WindowId;

const _ICON_ASSET_FINGERPRINT: &str = env!("WAAL_ICON_ASSET_FINGERPRINT");
const SUPERVISOR_TICK: Duration = Duration::from_millis(250);
const STORAGE_RECOVERY_RETRY_INTERVAL: Duration = Duration::from_secs(1);
const SETTINGS_QUIESCENCE_TIMEOUT: Duration = Duration::from_secs(15);
const SETTINGS_SESSION_TOKEN_ENV: &str = "WAAL_SETTINGS_SESSION_TOKEN";
#[cfg(target_os = "macos")]
const LEGACY_IPC_TOKEN_ENV: &str = "WAAL_IPC_TOKEN";
#[cfg(target_os = "windows")]
const LEGACY_MONITOR_CONTROL_TOKEN_ENV: &str = "WAAL_MONITOR_CONTROL_TOKEN";

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = std::env::args().skip(1).collect::<Vec<_>>();
    #[cfg(all(feature = "debug-fill", debug_assertions, not(waal_release_profile)))]
    if args.iter().any(|arg| arg == "--debug-fill-once") {
        return debug_fill::run_from_args(&args);
    }
    if args.iter().any(|arg| arg == "--full-ui") {
        return run_full_ui(initial_full_ui_tab(&args));
    }

    run_lightweight_supervisor()
}

fn run_lightweight_supervisor() -> anyhow::Result<()> {
    let single_instance = match single_instance::SingleInstanceGuard::acquire() {
        Ok(guard) => guard,
        Err(e) => {
            if single_instance::is_already_running_error(&e) {
                if let Err(activation_error) = single_instance::request_activation() {
                    tracing::warn!(
                        "Could not request existing instance activation: {activation_error}"
                    );
                }
                eprintln!("{e}");
                return Ok(());
            }
            eprintln!("{e}");
            return Err(e);
        }
    };
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    let (_single_instance, ipc_server) = {
        let mut single_instance = single_instance;
        let ipc_server = single_instance.take_ipc_server();
        (single_instance, ipc_server)
    };
    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    let _single_instance = single_instance;

    let rt = Runtime::new()?;
    let _rt_guard = rt.enter();

    let (worker_tx, worker_rx) = tokio_channel::<background::WorkerCommand>(32);
    let (worker_event_tx, worker_event_rx) = tokio_channel::<background::WorkerEvent>(100);
    let (tray_tx, tray_rx) = std_channel::<tray::TrayCommand>();
    let worker_invalidator = background::WorkerInvalidator::new();
    let worker_pause_latch = worker_invalidator.pause_latch();
    let settings_session_token = single_instance::SettingsSessionToken::generate();

    let (startup, storage_recovery_sticky_blocked) = match load_startup_config_for_session(
        &settings_session_token,
    ) {
        Ok(Some(startup)) => {
            let sticky_blocked = !startup.storage_recovery_ready;
            (startup, sticky_blocked)
        }
        Ok(None) => {
            tracing::warn!(
                "Password storage recovery deferred while an existing settings session is active"
            );
            worker_pause_latch.pause();
            (blocked_startup_config(), false)
        }
        Err(error) => {
            tracing::error!(
                %error,
                "Password storage recovery could not be locked safely; monitor will remain stopped"
            );
            worker_pause_latch.pause();
            (blocked_startup_config(), false)
        }
    };
    let config = startup.config;
    let storage_recovery_ready = startup.storage_recovery_ready;
    if !storage_recovery_ready {
        worker_pause_latch.pause();
    }
    let settings = config.settings.clone();
    let accounts = config.accounts.clone();

    background::spawn(
        worker_rx,
        worker_event_tx,
        settings.clone(),
        accounts,
        worker_invalidator.clone(),
        worker_pause_latch.clone(),
    );
    publish_initial_monitor_status(single_instance::write_monitor_status);
    start_monitor_on_launch_if_accessibility_trusted(&worker_tx, storage_recovery_ready);

    let event_loop = EventLoop::new()?;
    event_loop.set_control_flow(ControlFlow::Wait);
    let mut supervisor = LightweightSupervisor::new(
        worker_tx,
        worker_event_rx,
        tray_tx,
        tray_rx,
        worker_invalidator,
        config,
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        ipc_server,
    )
    .with_worker_pause_latch(worker_pause_latch)
    .with_settings_session_token(settings_session_token)
    .with_storage_recovery_state(storage_recovery_ready)
    .with_storage_recovery_sticky_blocked(storage_recovery_sticky_blocked);
    if !storage_recovery_ready
        && !storage_recovery_sticky_blocked
        && supervisor.accessibility_trusted
    {
        supervisor.resume_monitor_after_settings = true;
    }
    event_loop.run_app(&mut supervisor)?;

    Ok(())
}

fn run_full_ui(initial_tab: models::Tab) -> anyhow::Result<()> {
    let _settings_session_lease = acquire_authorized_settings_session_with(
        settings_session_token_from_environment,
        single_instance::request_settings_bootstrap,
        single_instance::SettingsSessionLease::acquire,
    )?;
    let _full_ui_instance = match single_instance::FullUiInstanceGuard::acquire() {
        Ok(guard) => guard,
        Err(e) => {
            eprintln!("{e}");
            return Ok(());
        }
    };

    let startup = load_full_ui_config();
    let config = startup.config;
    let storage_recovery_ready = startup.storage_recovery_ready;
    let (worker_tx, _worker_rx) = tokio_channel::<background::WorkerCommand>(32);
    let ui_worker_invalidator = background::WorkerInvalidator::new();
    let ui_worker_pause_latch = ui_worker_invalidator.pause_latch();
    let (_worker_event_tx, worker_event_rx) = tokio_channel::<background::WorkerEvent>(100);
    let (_tray_tx, tray_rx) = std_channel::<tray::TrayCommand>();

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([640.0, 420.0])
            .with_min_inner_size([560.0, 360.0])
            .with_icon(load_icon()?)
            .with_visible(true),
        renderer: eframe::Renderer::Glow,
        ..Default::default()
    };

    let result = eframe::run_native(
        "Windows App AutoLogin",
        native_options,
        Box::new(|cc| {
            ui::theme::apply(&cc.egui_ctx);
            let app = app::AutoLoginApp::new(
                worker_tx,
                ui_worker_pause_latch,
                tray_rx,
                worker_event_rx,
                config,
                true,
                initial_tab,
            )
            .with_storage_recovery_state(storage_recovery_ready);
            Ok(Box::new(app))
        }),
    );

    result.map_err(|e| anyhow::anyhow!("EFrame error: {:?}", e))
}

fn acquire_authorized_settings_session_with<Token, Lease>(
    load_token: impl FnOnce() -> anyhow::Result<Token>,
    request_supervisor_bootstrap: impl FnOnce() -> anyhow::Result<()>,
    acquire_lease: impl FnOnce(&Token) -> anyhow::Result<Lease>,
) -> anyhow::Result<Lease> {
    // The supervisor must first acknowledge this exact spawned process over
    // peer-bound local IPC. Only then inspect the inherited token and acquire
    // the lease; possession of that bearer token alone is not authorization.
    request_supervisor_bootstrap()?;
    let token = load_token()?;
    acquire_lease(&token)
}

struct StartupConfig {
    config: models::AppConfig,
    storage_recovery_ready: bool,
}

fn load_startup_config() -> StartupConfig {
    let _ = autostart::cleanup_stale();
    let mut startup = load_config_with_storage_recovery_inner(true);
    let auto_start_enabled = autostart::is_enabled();
    if startup.config.settings.auto_start != auto_start_enabled {
        startup.config.settings.auto_start = auto_start_enabled;
        let _ = storage::save_config(&startup.config);
    }
    startup
}

fn load_full_ui_config() -> StartupConfig {
    let mut config = storage::load_config();
    let auto_start_enabled = autostart::is_enabled();
    if config.settings.auto_start != auto_start_enabled {
        config.settings.auto_start = auto_start_enabled;
    }
    let storage_recovery_ready = matches!(storage::pending_storage_recovery_is_clear(), Ok(true))
        && matches!(storage::storage_recovery_block_is_clear(), Ok(true));
    StartupConfig {
        config,
        storage_recovery_ready,
    }
}

fn blocked_startup_config() -> StartupConfig {
    StartupConfig {
        config: models::AppConfig::default(),
        storage_recovery_ready: false,
    }
}

fn load_startup_config_for_session(
    session_token: &single_instance::SettingsSessionToken,
) -> anyhow::Result<Option<StartupConfig>> {
    let Some(mut recovery_lease) = single_instance::SettingsRecoveryLease::try_acquire()? else {
        return Ok(None);
    };
    let startup = load_startup_config();
    // Rotate authorization even when recovery remains blocked. Otherwise a
    // delayed child from a crashed supervisor could reuse the previous token
    // after the old parent lease disappeared.
    recovery_lease.establish_session(session_token)?;
    Ok(Some(startup))
}

fn settings_session_token_from_environment() -> anyhow::Result<single_instance::SettingsSessionToken>
{
    let token = std::env::var(SETTINGS_SESSION_TOKEN_ENV)
        .map_err(|_| anyhow::anyhow!("settings session authorization is missing"))?;
    std::env::remove_var(SETTINGS_SESSION_TOKEN_ENV);
    single_instance::SettingsSessionToken::parse(&token)
}

fn load_config_with_storage_recovery() -> StartupConfig {
    load_config_with_storage_recovery_inner(false)
}

fn load_config_with_storage_recovery_inner(clear_startup_block: bool) -> StartupConfig {
    let mut config = storage::load_config();
    let storage_recovery_ready = match storage::reconcile_pending_storage_operations(&mut config) {
        Ok(()) => {
            let journals_clear = match storage::pending_storage_recovery_is_clear() {
                Ok(clear) => clear,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "Password storage recovery state could not be verified"
                    );
                    false
                }
            };
            if !journals_clear {
                false
            } else {
                match finish_startup_storage_recovery_after_journals_with_ops(
                    clear_startup_block,
                    storage::reconcile_staged_fallback_keys_after_pending_recovery,
                    storage::clear_storage_recovery_block_after_startup_recovery,
                    storage::storage_recovery_block_is_clear,
                ) {
                    Ok(ready) => ready,
                    Err(e) => {
                        // Never clear a prior recovery latch until staged key
                        // metadata has been checked against the winning
                        // password-file revision.
                        tracing::warn!(
                            error = %e,
                            "Password storage startup recovery could not be completed safely"
                        );
                        false
                    }
                }
            }
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "Pending password storage recovery could not be completed"
            );
            false
        }
    };
    if storage_recovery_ready && !matches!(storage::storage_recovery_block_is_clear(), Ok(true)) {
        tracing::warn!(
            "Password storage recovery block remained present after recovery verification"
        );
        return StartupConfig {
            config,
            storage_recovery_ready: false,
        };
    }
    StartupConfig {
        config,
        storage_recovery_ready,
    }
}

fn finish_startup_storage_recovery_after_journals_with_ops<R, C, S>(
    clear_startup_block: bool,
    reconcile_staged: R,
    clear_recovery_block: C,
    recovery_block_is_clear: S,
) -> anyhow::Result<bool>
where
    R: FnOnce() -> anyhow::Result<()>,
    C: FnOnce() -> anyhow::Result<()>,
    S: FnOnce() -> anyhow::Result<bool>,
{
    reconcile_staged()?;
    if clear_startup_block {
        clear_recovery_block()?;
        Ok(true)
    } else {
        recovery_block_is_clear()
    }
}

fn start_monitor_on_launch_if_accessibility_trusted(
    worker_tx: &TokioSender<background::WorkerCommand>,
    storage_recovery_ready: bool,
) {
    queue_monitor_start_if_accessibility_trusted(
        worker_tx,
        autologin::accessibility_is_trusted(),
        storage_recovery_ready,
    );
}

fn queue_monitor_start_if_accessibility_trusted(
    worker_tx: &TokioSender<background::WorkerCommand>,
    accessibility_trusted: bool,
    storage_recovery_ready: bool,
) {
    if accessibility_trusted && storage_recovery_ready {
        let _ = worker_tx.try_send(background::WorkerCommand::Start);
    } else if !accessibility_trusted {
        #[cfg(not(test))]
        {
            let report = debug_fill::pre_password_skip_report(
                "accessibility_not_trusted_for_current_process",
                &[("prompt_context_source", "launch_preflight".to_string())],
            );
            if let Err(e) = debug_fill::write_last_fill_attempt_report(&report) {
                tracing::warn!("Could not persist launch accessibility report: {e}");
            }
        }
    } else {
        tracing::warn!("Monitor remains stopped because password storage recovery is incomplete");
    }
}

fn publish_initial_monitor_status(
    mut write_monitor_status: impl FnMut(bool) -> anyhow::Result<()>,
) {
    if let Err(e) = write_monitor_status(false) {
        tracing::warn!("Could not clear stale monitor status during supervisor startup: {e}");
    }
}

struct PendingSettingsLaunch {
    request_id: u64,
    initial_tab: models::Tab,
    pause_monitor: bool,
    acknowledgement: StdReceiver<background::WorkerQuiescenceAck>,
    deadline: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MonitorControlState {
    Running,
    PausedWithStartIntent,
    Stopped,
}

impl MonitorControlState {
    fn from_worker_and_intent(
        worker_status: models::WorkerStatus,
        desired_monitor_running: bool,
    ) -> Self {
        if worker_status == models::WorkerStatus::Running {
            Self::Running
        } else if desired_monitor_running {
            Self::PausedWithStartIntent
        } else {
            Self::Stopped
        }
    }

    fn toggle_requests_stop(self) -> bool {
        !matches!(self, Self::Stopped)
    }
}

struct LightweightSupervisor {
    worker_tx: TokioSender<background::WorkerCommand>,
    worker_event_rx: TokioReceiver<background::WorkerEvent>,
    tray_tx: StdSender<tray::TrayCommand>,
    tray_rx: StdReceiver<tray::TrayCommand>,
    worker_invalidator: background::WorkerInvalidator,
    worker_pause_latch: background::WorkerPauseLatch,
    tray: Option<tray::AppTray>,
    config: models::AppConfig,
    storage_recovery_ready: bool,
    storage_recovery_sticky_blocked: bool,
    worker_status: models::WorkerStatus,
    desired_monitor_running: bool,
    accessibility_trusted: bool,
    last_accessibility_check: Instant,
    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    monitor_command_watcher: single_instance::MonitorCommandWatcher,
    settings_child: Option<Child>,
    settings_child_bootstrapped: bool,
    pending_settings_launch: Option<PendingSettingsLaunch>,
    next_settings_launch_request_id: u64,
    settings_session_token: single_instance::SettingsSessionToken,
    settings_session_lease: Option<single_instance::SettingsSessionLease>,
    #[cfg(test)]
    settings_lock_root: std::path::PathBuf,
    last_storage_recovery_attempt: Instant,
    resume_monitor_after_settings: bool,
    exit_requested: bool,
    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    activation_watcher: single_instance::ActivationWatcher,
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    ipc_server: Option<single_instance::LocalIpcServer>,
}

impl LightweightSupervisor {
    fn new(
        worker_tx: TokioSender<background::WorkerCommand>,
        worker_event_rx: TokioReceiver<background::WorkerEvent>,
        tray_tx: StdSender<tray::TrayCommand>,
        tray_rx: StdReceiver<tray::TrayCommand>,
        worker_invalidator: background::WorkerInvalidator,
        config: models::AppConfig,
        #[cfg(any(target_os = "macos", target_os = "windows"))] ipc_server: Option<
            single_instance::LocalIpcServer,
        >,
    ) -> Self {
        let worker_pause_latch = worker_invalidator.pause_latch();
        Self {
            worker_tx,
            worker_event_rx,
            tray_tx,
            tray_rx,
            worker_invalidator,
            worker_pause_latch,
            tray: None,
            config,
            storage_recovery_ready: true,
            storage_recovery_sticky_blocked: false,
            worker_status: models::WorkerStatus::Idle,
            desired_monitor_running: true,
            accessibility_trusted: autologin::accessibility_is_trusted(),
            last_accessibility_check: Instant::now(),
            #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
            monitor_command_watcher: single_instance::MonitorCommandWatcher::new(),
            settings_child: None,
            settings_child_bootstrapped: false,
            pending_settings_launch: None,
            next_settings_launch_request_id: 0,
            settings_session_token: single_instance::SettingsSessionToken::generate(),
            settings_session_lease: None,
            #[cfg(test)]
            settings_lock_root: std::env::temp_dir().join(format!(
                "windows-app-autologin-supervisor-test-{}",
                uuid::Uuid::new_v4().hyphenated()
            )),
            last_storage_recovery_attempt: Instant::now()
                .checked_sub(STORAGE_RECOVERY_RETRY_INTERVAL)
                .unwrap_or_else(Instant::now),
            resume_monitor_after_settings: false,
            exit_requested: false,
            #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
            activation_watcher: single_instance::ActivationWatcher::new(),
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            ipc_server,
        }
    }

    fn with_storage_recovery_state(mut self, storage_recovery_ready: bool) -> Self {
        self.storage_recovery_ready = storage_recovery_ready;
        if !storage_recovery_ready {
            self.worker_pause_latch.pause();
        }
        self
    }

    fn with_storage_recovery_sticky_blocked(
        mut self,
        storage_recovery_sticky_blocked: bool,
    ) -> Self {
        self.storage_recovery_sticky_blocked = storage_recovery_sticky_blocked;
        if storage_recovery_sticky_blocked {
            self.storage_recovery_ready = false;
            self.worker_pause_latch.pause();
        }
        self
    }

    fn with_worker_pause_latch(mut self, worker_pause_latch: background::WorkerPauseLatch) -> Self {
        self.worker_pause_latch = worker_pause_latch;
        self
    }

    fn with_settings_session_token(
        mut self,
        settings_session_token: single_instance::SettingsSessionToken,
    ) -> Self {
        self.settings_session_token = settings_session_token;
        self
    }

    fn ensure_tray(&mut self) {
        if self.tray.is_some() {
            return;
        }
        match tray::setup_tray(self.tray_tx.clone()) {
            Ok(tray) => {
                self.tray = Some(tray);
                self.update_tray_status();
            }
            Err(e) => {
                tracing::error!("Failed to create tray icon: {e}");
            }
        }
    }

    fn process_tray_commands(&mut self, event_loop: &ActiveEventLoop) -> bool {
        while let Ok(command) = self.tray_rx.try_recv() {
            match command {
                tray::TrayCommand::OpenAccounts => self.open_accounts_window(),
                tray::TrayCommand::OpenSettings => self.open_settings_window(),
                tray::TrayCommand::ToggleMonitor => self.toggle_monitor(),
                tray::TrayCommand::RequestAccessibilityAccess => {
                    let trusted = autologin::request_accessibility_access_prompt();
                    self.apply_accessibility_trust_state(
                        trusted || autologin::accessibility_is_trusted(),
                    );
                }
                tray::TrayCommand::OpenAccessibilitySettings => {
                    if let Err(e) = autologin::open_accessibility_settings() {
                        tracing::warn!("Could not open Accessibility settings: {e}");
                    }
                }
                tray::TrayCommand::Exit => {
                    self.handle_exit_request();
                    event_loop.exit();
                    return true;
                }
            }
        }
        false
    }

    fn handle_exit_request(&mut self) {
        self.handle_exit_request_with_monitor_status_writer(single_instance::write_monitor_status);
    }

    fn handle_exit_request_with_monitor_status_writer(
        &mut self,
        mut write_monitor_status: impl FnMut(bool) -> anyhow::Result<()>,
    ) {
        if self.exit_requested {
            self.close_settings_child_for_exit();
            return;
        }
        self.exit_requested = true;
        self.worker_pause_latch.pause();
        self.worker_invalidator.invalidate();
        self.worker_status = models::WorkerStatus::Idle;
        self.desired_monitor_running = false;
        if let Err(e) = write_monitor_status(false) {
            tracing::warn!("Could not publish stopped monitor status during quit: {e}");
        }
        let _ = self.worker_tx.try_send(background::WorkerCommand::Stop);
        self.close_settings_child_for_exit();
    }

    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    fn process_monitor_commands(&mut self) {
        let command = self.monitor_command_watcher.consume_command();
        let Some(command) = command else {
            return;
        };

        match command {
            single_instance::MonitorControlCommand::Start => {
                self.start_monitor_from_control_command()
            }
            single_instance::MonitorControlCommand::Stop => self.stop_monitor(),
            single_instance::MonitorControlCommand::StorageRecoveryBlocked => {
                self.block_storage_recovery_until_restart()
            }
            single_instance::MonitorControlCommand::ReloadConfig => {
                self.reload_config_after_settings()
            }
        }
    }

    fn process_worker_events(&mut self) {
        while let Ok(event) = self.worker_event_rx.try_recv() {
            match event {
                background::WorkerEvent::StatusChanged(status) => {
                    self.worker_status = status;
                    self.update_tray_status();
                }
                background::WorkerEvent::FillAttemptReport(report) => {
                    if let Some(tray) = &self.tray {
                        tray.set_last_result(&fill_result_label(&report));
                    }
                }
                background::WorkerEvent::Log(_) => {}
            }
        }
    }

    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    fn process_activation_requests(&mut self) {
        if self.activation_watcher.consume_activation_request() {
            self.open_settings_window();
        }
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    fn process_local_ipc_commands(&mut self) {
        let Some(ipc_server) = self.ipc_server.as_mut() else {
            return;
        };
        let commands = ipc_server.consume_commands();
        for peer_command in commands {
            if peer_command.command == single_instance::LocalIpcCommand::SettingsBootstrap {
                let peer_pid = peer_command.peer_pid;
                if !self.acknowledge_settings_bootstrap_with(peer_pid, || {
                    acknowledge_settings_bootstrap_peer(peer_command)
                }) {
                    tracing::warn!(
                        peer_pid,
                        "Rejected or could not acknowledge settings bootstrap"
                    );
                }
                continue;
            }
            if !self.authorize_local_ipc_command(peer_command.command, peer_command.peer_pid) {
                tracing::warn!(
                    peer_pid = peer_command.peer_pid,
                    "Rejected privileged local IPC command from unauthorized peer"
                );
                continue;
            }

            if !self.handle_authorized_local_ipc_command(peer_command.command) {
                tracing::warn!(
                    peer_pid = peer_command.peer_pid,
                    "Authorized local IPC command could not be committed"
                );
                continue;
            }
            if let Err(error) = peer_command.acknowledge() {
                tracing::warn!(%error, "Could not acknowledge committed local IPC command");
            }
        }
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    fn handle_authorized_local_ipc_command(
        &mut self,
        command: single_instance::LocalIpcCommand,
    ) -> bool {
        match command {
            single_instance::LocalIpcCommand::Activate => self.handle_activation_request(),
            single_instance::LocalIpcCommand::SettingsBootstrap => false,
            single_instance::LocalIpcCommand::ReloadConfig => {
                self.reload_config_after_settings();
                true
            }
            single_instance::LocalIpcCommand::Monitor(command) => {
                match command {
                    single_instance::MonitorControlCommand::Start => {
                        self.start_monitor_from_control_command()
                    }
                    single_instance::MonitorControlCommand::Stop => self.stop_monitor(),
                    single_instance::MonitorControlCommand::StorageRecoveryBlocked => {
                        self.block_storage_recovery_until_restart()
                    }
                    #[cfg(target_os = "windows")]
                    single_instance::MonitorControlCommand::ReloadConfig => {
                        self.reload_config_after_settings()
                    }
                }
                true
            }
        }
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    fn authorize_local_ipc_command(
        &mut self,
        command: single_instance::LocalIpcCommand,
        peer_pid: u32,
    ) -> bool {
        if command == single_instance::LocalIpcCommand::Activate {
            return true;
        }
        let settings_child_pid = self.live_settings_child_pid();
        local_ipc_command_authorized(
            command,
            peer_pid,
            settings_child_pid,
            self.settings_child_bootstrapped,
        )
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    fn acknowledge_settings_bootstrap_with(
        &mut self,
        peer_pid: u32,
        acknowledge: impl FnOnce() -> anyhow::Result<()>,
    ) -> bool {
        // Revalidate the Child handle immediately before ACK. A stale PID or
        // an already-exited child must not promote a connection into an
        // authorized settings session, and a failed ACK must not leave one.
        if self.live_settings_child_pid() != Some(peer_pid) {
            return false;
        }
        if let Err(error) = acknowledge() {
            tracing::warn!(%error, "Could not acknowledge settings bootstrap");
            return false;
        }
        self.settings_child_bootstrapped = true;
        true
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    fn live_settings_child_pid(&mut self) -> Option<u32> {
        let child = self.settings_child.as_mut()?;
        match child.try_wait() {
            Ok(None) => Some(child.id()),
            Ok(Some(_)) => None,
            Err(error) => {
                tracing::warn!(%error, "Could not prove settings child is still live for local IPC");
                None
            }
        }
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    fn handle_activation_request(&mut self) -> bool {
        self.poll_settings_window();
        if self.settings_transition_active() {
            return true;
        }
        self.open_accounts_window_for_activation()
    }

    #[cfg(all(test, any(target_os = "macos", target_os = "windows")))]
    fn settings_child_pid_for_local_ipc(&mut self) -> Option<u32> {
        self.live_settings_child_pid()
    }

    fn poll_accessibility(&mut self) {
        if self.last_accessibility_check.elapsed() < Duration::from_secs(1) {
            return;
        }
        self.last_accessibility_check = Instant::now();
        self.refresh_accessibility_trust_state();
    }

    fn refresh_accessibility_trust_state(&mut self) -> bool {
        self.refresh_accessibility_trust_state_with_grant_start(true)
    }

    fn refresh_accessibility_trust_state_for_start(&mut self) -> bool {
        self.refresh_accessibility_trust_state_with_grant_start(false)
    }

    fn refresh_accessibility_trust_state_with_grant_start(
        &mut self,
        start_monitor_on_grant: bool,
    ) -> bool {
        let trusted = autologin::accessibility_is_trusted();
        if trusted != self.accessibility_trusted {
            self.apply_accessibility_trust_state_with_grant_start(trusted, start_monitor_on_grant);
        }
        self.accessibility_trusted
    }

    fn apply_accessibility_trust_state(&mut self, trusted: bool) {
        self.apply_accessibility_trust_state_with_grant_start(trusted, true);
    }

    fn apply_accessibility_trust_state_with_grant_start(
        &mut self,
        trusted: bool,
        start_monitor_on_grant: bool,
    ) {
        if trusted == self.accessibility_trusted {
            self.update_tray_status();
            return;
        }

        self.accessibility_trusted = trusted;
        if trusted {
            if start_monitor_on_grant && self.desired_monitor_running {
                self.start_monitor_after_accessibility_grant();
            }
        } else {
            self.pause_monitor_preserving_intent();
        }
        self.update_tray_status();
    }

    fn toggle_monitor(&mut self) {
        if self.monitor_control_state().toggle_requests_stop() {
            self.stop_monitor();
        } else {
            self.start_monitor_if_ready();
        }
    }

    fn monitor_control_state(&self) -> MonitorControlState {
        MonitorControlState::from_worker_and_intent(
            self.worker_status,
            self.desired_monitor_running,
        )
    }

    fn accessibility_ready_for_start(&mut self) -> bool {
        if !self.accessibility_trusted {
            self.refresh_accessibility_trust_state_for_start();
        }
        self.accessibility_trusted
    }

    fn start_monitor_if_ready(&mut self) {
        if self.storage_recovery_sticky_blocked {
            tracing::warn!(
                "Monitor remains stopped until password storage recovery completes after restart"
            );
            return;
        }
        self.desired_monitor_running = true;
        if !self.storage_recovery_ready {
            self.resume_monitor_after_settings = true;
            tracing::warn!(
                "Monitor remains stopped because password storage recovery is incomplete"
            );
            return;
        }
        if !self.accessibility_ready_for_start() {
            tracing::warn!("Automation permission is required before starting monitor");
            return;
        }
        if self.settings_transition_active() {
            self.resume_monitor_after_settings = true;
            return;
        }

        if self.worker_pause_latch.is_paused() {
            self.queue_fresh_config_and_start();
            return;
        }
        if self.worker_status != models::WorkerStatus::Idle {
            return;
        }

        self.queue_worker_start_fail_closed();
    }

    fn start_monitor_after_accessibility_grant(&mut self) {
        if !self.desired_monitor_running {
            return;
        }
        if self.storage_recovery_sticky_blocked {
            tracing::warn!(
                "Monitor remains stopped until password storage recovery completes after restart"
            );
            return;
        }
        if !self.storage_recovery_ready {
            self.resume_monitor_after_settings = true;
            tracing::warn!(
                "Monitor remains stopped because password storage recovery is incomplete"
            );
            return;
        }
        if self.settings_transition_active() {
            self.resume_monitor_after_settings = true;
            return;
        }
        if self.worker_pause_latch.is_paused() {
            self.queue_fresh_config_and_start();
            return;
        }
        if self.worker_status != models::WorkerStatus::Idle {
            return;
        }
        self.queue_worker_start_fail_closed();
    }

    fn start_monitor_from_control_command(&mut self) {
        self.start_monitor_from_control_command_with_loader(load_config_with_storage_recovery);
    }

    fn start_monitor_from_control_command_with_loader(
        &mut self,
        load_config: impl FnOnce() -> StartupConfig,
    ) {
        if self.storage_recovery_sticky_blocked {
            tracing::warn!(
                "Monitor remains stopped until password storage recovery completes after restart"
            );
            return;
        }
        self.desired_monitor_running = true;
        if !self.storage_recovery_ready && !self.settings_transition_active() {
            self.resume_monitor_after_settings = true;
            tracing::warn!(
                "Monitor remains stopped because password storage recovery is incomplete"
            );
            return;
        }
        if !self.accessibility_ready_for_start() {
            tracing::warn!("Automation permission is required before starting monitor");
            return;
        }
        self.resume_monitor_after_settings = false;
        if self.settings_transition_active() {
            // The child may be between journal creation, credential migration,
            // and config commit. Never interpret its live transaction as crash
            // recovery; reload exactly once after the child exits.
            let _ = load_config;
            self.resume_monitor_after_settings = true;
            return;
        }
        if self.worker_pause_latch.is_paused() {
            self.queue_fresh_config_and_start();
        } else if self.worker_status == models::WorkerStatus::Idle {
            self.queue_worker_start_fail_closed();
        }
    }

    fn queue_worker_start_fail_closed(&mut self) {
        if let Err(error) = self.worker_tx.try_send(background::WorkerCommand::Start) {
            self.worker_pause_latch.pause();
            tracing::warn!(%error, "Monitor start command could not be queued; pause latch remains active");
        }
    }

    fn stop_monitor(&mut self) {
        self.desired_monitor_running = false;
        self.resume_monitor_after_settings = false;
        self.worker_pause_latch.pause();
        if let Err(error) = self.worker_tx.try_send(background::WorkerCommand::Stop) {
            tracing::warn!(%error, "Monitor stop command could not be queued; pause latch remains active");
        }
    }

    fn pause_monitor_preserving_intent(&mut self) {
        self.resume_monitor_after_settings = false;
        self.worker_pause_latch.pause();
        if let Err(error) = self.worker_tx.try_send(background::WorkerCommand::Stop) {
            tracing::warn!(%error, "Monitor pause command could not be queued; pause latch remains active");
        }
    }

    fn block_storage_recovery_until_restart(&mut self) {
        // A child reports this only after a credential transaction has reached
        // an ambiguous durability outcome. A missing journal pathname is not
        // proof of safety after an unlink/parent-fsync failure, so this gate is
        // intentionally process-sticky and only fresh startup recovery may
        // clear it.
        self.storage_recovery_ready = false;
        self.storage_recovery_sticky_blocked = true;
        self.pending_settings_launch = None;
        self.desired_monitor_running = false;
        self.resume_monitor_after_settings = false;
        #[cfg(not(test))]
        {
            if let Err(error) = storage::mark_storage_recovery_blocked() {
                tracing::error!(%error, "Password storage recovery block could not be persisted; supervisor-local pause remains active");
            }
        }
        self.worker_pause_latch.pause();
        self.worker_invalidator.invalidate();
        if let Err(error) = self.worker_tx.try_send(background::WorkerCommand::Stop) {
            tracing::error!(%error, "Password storage recovery block could not queue worker stop; pause latch remains active");
        }
        self.update_tray_status();
    }

    fn queue_fresh_config_and_start(&mut self) {
        if !self.desired_monitor_running || self.storage_recovery_sticky_blocked {
            self.worker_pause_latch.pause();
            return;
        }
        let pause_epoch = self.worker_pause_latch.pause_with_epoch();
        let command = self.worker_pause_latch.apply_config_command(
            pause_epoch,
            self.config.settings.clone(),
            self.config.accounts.clone(),
            true,
            true,
        );
        if let Err(error) = self.worker_tx.try_send(command) {
            self.worker_pause_latch.pause();
            tracing::warn!(
                %error,
                "Monitor start could not be queued safely; pause latch remains active"
            );
        }
    }

    fn open_accounts_window(&mut self) {
        self.open_full_ui_window(models::Tab::Accounts);
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    fn open_accounts_window_for_activation(&mut self) -> bool {
        self.open_full_ui_window_with_monitor_policy(models::Tab::Accounts, true)
    }

    fn open_settings_window(&mut self) {
        self.open_full_ui_window(models::Tab::Settings);
    }

    fn open_full_ui_window(&mut self, initial_tab: models::Tab) {
        let _ = self.open_full_ui_window_with_monitor_policy(initial_tab, true);
    }

    fn open_full_ui_window_with_monitor_policy(
        &mut self,
        initial_tab: models::Tab,
        pause_monitor: bool,
    ) -> bool {
        if self.settings_transition_active() {
            return true;
        }

        // Settings may mutate password storage. Close the synchronous gate and
        // serialize a quiescence request behind every worker decision already
        // in progress before creating any child authorization or lease.
        self.resume_monitor_after_settings = false;
        self.worker_pause_latch.pause();
        self.worker_invalidator.invalidate();
        if let Err(error) = self.worker_tx.try_send(background::WorkerCommand::Stop) {
            self.worker_pause_latch.pause();
            tracing::warn!(%error, "Could not queue settings worker stop; settings launch remains unauthorized");
            return false;
        }

        let Some(request_id) = self.next_settings_launch_request_id.checked_add(1) else {
            self.worker_pause_latch.pause();
            tracing::warn!("Settings quiescence request identifier space is exhausted");
            return false;
        };
        self.next_settings_launch_request_id = request_id;
        let (acknowledgement, acknowledgement_receiver) = std_channel();
        if let Err(error) = self.worker_tx.try_send(background::WorkerCommand::Quiesce {
            request_id,
            acknowledgement,
        }) {
            self.worker_pause_latch.pause();
            tracing::warn!(%error, "Could not queue worker quiescence request; settings launch remains unauthorized");
            return false;
        }
        let Some(deadline) = Instant::now().checked_add(SETTINGS_QUIESCENCE_TIMEOUT) else {
            self.worker_pause_latch.pause();
            tracing::warn!("Could not establish settings quiescence deadline");
            return false;
        };
        self.pending_settings_launch = Some(PendingSettingsLaunch {
            request_id,
            initial_tab,
            pause_monitor,
            acknowledgement: acknowledgement_receiver,
            deadline,
        });
        true
    }

    fn settings_transition_active(&self) -> bool {
        self.settings_child.is_some() || self.pending_settings_launch.is_some()
    }

    fn poll_pending_settings_launch(&mut self) {
        let privileged_ipc_available = self.privileged_ipc_available();
        self.poll_pending_settings_launch_with(Instant::now(), |initial_tab, token| {
            spawn_full_ui_window(initial_tab, privileged_ipc_available, token)
        });
    }

    fn poll_pending_settings_launch_with(
        &mut self,
        now: Instant,
        spawn: impl FnOnce(models::Tab, &single_instance::SettingsSessionToken) -> anyhow::Result<Child>,
    ) {
        enum PollResult {
            Waiting,
            Ready,
            Failed(String),
        }

        let poll_result = {
            let Some(pending) = self.pending_settings_launch.as_ref() else {
                return;
            };
            match pending.acknowledgement.try_recv() {
                Ok(acknowledgement) if acknowledgement.request_id == pending.request_id => {
                    PollResult::Ready
                }
                Ok(acknowledgement) => PollResult::Failed(format!(
                    "worker quiescence acknowledgement mismatch: expected {}, received {}",
                    pending.request_id, acknowledgement.request_id
                )),
                Err(std::sync::mpsc::TryRecvError::Disconnected) => PollResult::Failed(
                    "worker quiescence acknowledgement channel disconnected".to_string(),
                ),
                Err(std::sync::mpsc::TryRecvError::Empty) if now >= pending.deadline => {
                    PollResult::Failed("worker quiescence acknowledgement timed out".to_string())
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => PollResult::Waiting,
            }
        };

        match poll_result {
            PollResult::Waiting => return,
            PollResult::Failed(error) => {
                self.pending_settings_launch = None;
                self.resume_monitor_after_settings = false;
                self.worker_pause_latch.pause();
                tracing::warn!(%error, "Settings launch remains unauthorized");
                return;
            }
            PollResult::Ready => {}
        }

        let pending = self
            .pending_settings_launch
            .take()
            .expect("ready settings launch must still be pending");
        if self.exit_requested
            || self.settings_child.is_some()
            || !self.worker_pause_latch.is_paused()
        {
            self.resume_monitor_after_settings = false;
            self.worker_pause_latch.pause();
            tracing::warn!(
                request_id = pending.request_id,
                "Settings launch state changed after quiescence; launch remains unauthorized"
            );
            return;
        }

        // Re-read intent only after quiescence. An explicit Stop while waiting
        // must never be overwritten by the older request's resume policy.
        self.resume_monitor_after_settings = pending.pause_monitor && self.desired_monitor_running;
        let session = self.prepare_settings_session_for_spawn();
        let (session_lease, session_token) = match session {
            Ok(session) => session,
            Err(error) => {
                tracing::warn!(%error, "Could not authorize settings window");
                self.resume_monitor_after_settings = false;
                return;
            }
        };

        match spawn(pending.initial_tab, &session_token) {
            Ok(child) => {
                self.settings_child_bootstrapped = false;
                self.settings_child = Some(child);
                self.settings_session_lease = Some(session_lease);
            }
            Err(e) => {
                tracing::warn!("Could not open settings window: {e}");
                let should_resume = self.resume_monitor_after_settings;
                self.finish_failed_settings_spawn(session_lease, should_resume);
            }
        }
    }

    fn prepare_settings_session_for_spawn(
        &mut self,
    ) -> anyhow::Result<(
        single_instance::SettingsSessionLease,
        single_instance::SettingsSessionToken,
    )> {
        let Some(mut recovery_lease) = self.try_acquire_settings_recovery_lease()? else {
            anyhow::bail!("another settings session is still active");
        };
        let token = self.rotate_settings_session_authorization(&mut recovery_lease)?;
        drop(recovery_lease);
        match self.acquire_settings_session_lease(&token) {
            Ok(session_lease) => Ok((session_lease, token)),
            Err(error) => {
                if let Err(revocation_error) = self.revoke_settings_session_authorization() {
                    self.storage_recovery_ready = false;
                    self.worker_pause_latch.pause();
                    anyhow::bail!(
                        "could not acquire settings session lease: {error}; fresh authorization could not be revoked: {revocation_error}"
                    );
                }
                Err(error)
            }
        }
    }

    fn finish_failed_settings_spawn(
        &mut self,
        session_lease: single_instance::SettingsSessionLease,
        should_resume: bool,
    ) {
        // The local lease is not stored in settings_session_lease until spawn
        // succeeds. Release it explicitly before taking the exclusive recovery
        // lease used to revoke the token passed to the failed child command.
        drop(session_lease);
        self.settings_session_lease = None;
        self.settings_child_bootstrapped = false;
        self.resume_monitor_after_settings = false;
        if should_resume {
            self.reload_config_after_settings_with_recovery_lease(true);
        } else {
            self.revoke_settings_session_authorization_fail_closed(
                "Could not revoke failed settings launch authorization",
            );
        }
    }

    fn poll_settings_window(&mut self) {
        self.poll_settings_window_with_loader(|_| load_config_with_storage_recovery());
    }

    fn close_settings_child_for_exit(&mut self) {
        self.resume_monitor_after_settings = false;
        self.pending_settings_launch = None;
        self.settings_child_bootstrapped = false;
        let Some(mut child) = self.settings_child.take() else {
            self.settings_session_lease = None;
            return;
        };

        if child_has_exited(&mut child) {
            self.settings_session_lease = None;
            self.revoke_settings_session_authorization_fail_closed(
                "Could not revoke settings authorization during supervisor exit",
            );
            return;
        }

        terminate_child_process(&mut child, "settings window");
        self.settings_session_lease = None;
        if child_has_exited(&mut child) {
            self.revoke_settings_session_authorization_fail_closed(
                "Could not revoke settings authorization during supervisor exit",
            );
        }
    }

    fn poll_settings_window_with_loader(
        &mut self,
        load_config: impl FnOnce(&mut single_instance::SettingsRecoveryLease) -> StartupConfig,
    ) {
        let Some(child) = self.settings_child.as_mut() else {
            return;
        };

        match child.try_wait() {
            Ok(Some(_)) => {
                self.settings_child = None;
                self.settings_child_bootstrapped = false;
                self.settings_session_lease = None;
                let should_resume = self.resume_monitor_after_settings
                    && self.desired_monitor_running
                    && !self.storage_recovery_sticky_blocked
                    && self.accessibility_ready_for_start();
                self.resume_monitor_after_settings = false;
                let reload_succeeded =
                    self.reload_config_after_settings_with_lease_loader(load_config, should_resume);
                if should_resume && !reload_succeeded {
                    tracing::warn!(
                        "Monitor left stopped because settings reload could not be delivered safely"
                    );
                }
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!("Settings window status check failed: {e}");
                // Fail closed: without a confirmed process exit, keep both the
                // child handle and shared storage lease. Dropping either could
                // let recovery race a still-live settings transaction.
            }
        }
    }

    fn reload_config_after_settings(&mut self) {
        if self.settings_transition_active() {
            // A reload request from the live child is only a hint. The child
            // deliberately holds a shared lease while it may be between
            // journal phases, so recovery and authoritative reload wait for
            // the confirmed process exit in poll_settings_window.
            tracing::debug!("Deferred config reload until settings window exits");
            return;
        }
        self.reload_config_after_settings_with_recovery_lease(false);
    }

    fn reload_config_after_settings_with_recovery_lease(&mut self, start_monitor: bool) -> bool {
        self.reload_config_after_settings_with_lease_loader(
            |_| load_config_with_storage_recovery(),
            start_monitor,
        )
    }

    fn reload_config_after_settings_with_lease_loader(
        &mut self,
        load_config: impl FnOnce(&mut single_instance::SettingsRecoveryLease) -> StartupConfig,
        start_monitor: bool,
    ) -> bool {
        let Some(mut recovery_lease) = (match self.try_acquire_settings_recovery_lease() {
            Ok(lease) => lease,
            Err(error) => {
                tracing::error!(%error, "Could not lock password storage recovery safely");
                None
            }
        }) else {
            self.storage_recovery_ready = false;
            self.worker_pause_latch.pause();
            return false;
        };
        if self.storage_recovery_sticky_blocked {
            // Still rotate authorization while holding the exclusive lease so
            // a delayed child from an older supervisor cannot attach. Do not
            // run recovery again: this process has already observed an
            // ambiguous durability result that only restart may clear.
            if let Err(error) = self.rotate_settings_session_authorization(&mut recovery_lease) {
                tracing::error!(%error, "Could not rotate settings session authorization");
            }
            self.worker_pause_latch.pause();
            return false;
        }
        let startup = load_config(&mut recovery_lease);
        // The token rotation is independent of recovery success. Holding the
        // exclusive lease proves no authorized settings child is live; rotate
        // now so a delayed child from an older supervisor cannot attach later.
        if let Err(error) = self.rotate_settings_session_authorization(&mut recovery_lease) {
            tracing::error!(%error, "Could not rotate settings session authorization");
            self.storage_recovery_ready = false;
            self.worker_pause_latch.pause();
            return false;
        }
        self.apply_reloaded_config(startup, start_monitor)
    }

    fn rotate_settings_session_authorization(
        &mut self,
        recovery_lease: &mut single_instance::SettingsRecoveryLease,
    ) -> anyhow::Result<single_instance::SettingsSessionToken> {
        let token = single_instance::SettingsSessionToken::generate();
        recovery_lease.establish_session(&token)?;
        self.settings_session_token = token.clone();
        Ok(token)
    }

    fn revoke_settings_session_authorization(&mut self) -> anyhow::Result<()> {
        let Some(mut recovery_lease) = self.try_acquire_settings_recovery_lease()? else {
            anyhow::bail!("another settings session is still active");
        };
        self.rotate_settings_session_authorization(&mut recovery_lease)?;
        Ok(())
    }

    fn revoke_settings_session_authorization_fail_closed(&mut self, message: &'static str) {
        if let Err(error) = self.revoke_settings_session_authorization() {
            tracing::error!(%error, "{message}");
            self.storage_recovery_ready = false;
            self.worker_pause_latch.pause();
        }
    }

    fn try_acquire_settings_recovery_lease(
        &self,
    ) -> anyhow::Result<Option<single_instance::SettingsRecoveryLease>> {
        #[cfg(test)]
        {
            single_instance::SettingsRecoveryLease::try_acquire_in_root(&self.settings_lock_root)
        }
        #[cfg(not(test))]
        {
            single_instance::SettingsRecoveryLease::try_acquire()
        }
    }

    fn acquire_settings_session_lease(
        &self,
        token: &single_instance::SettingsSessionToken,
    ) -> anyhow::Result<single_instance::SettingsSessionLease> {
        #[cfg(test)]
        {
            single_instance::SettingsSessionLease::acquire_in_root(&self.settings_lock_root, token)
        }
        #[cfg(not(test))]
        {
            single_instance::SettingsSessionLease::acquire(token)
        }
    }

    #[cfg(test)]
    fn reload_config_after_settings_with_loader(
        &mut self,
        load_config: impl FnOnce() -> StartupConfig,
    ) -> bool {
        if self.settings_transition_active() {
            // Reload IPC is intentionally only a hint while the settings child
            // is alive. Its transaction journals belong to that live process
            // and must not be consumed by the supervisor. poll_settings_window
            // performs the authoritative reload after process exit.
            let _ = load_config;
            tracing::debug!("Deferred config reload until settings window exits");
            return false;
        }
        self.reload_config_after_settings_with_loader_and_start(load_config, false)
    }

    #[cfg(test)]
    fn reload_config_after_settings_with_loader_and_start(
        &mut self,
        load_config: impl FnOnce() -> StartupConfig,
        start_monitor: bool,
    ) -> bool {
        self.reload_config_after_settings_with_lease_loader(|_| load_config(), start_monitor)
    }

    fn apply_reloaded_config(&mut self, startup: StartupConfig, start_monitor: bool) -> bool {
        let pause_epoch = self.worker_pause_latch.pause_with_epoch();
        self.worker_invalidator.invalidate();
        if !startup.storage_recovery_ready {
            self.block_storage_recovery_until_restart();
            tracing::error!(
                "Saved config was not delivered to the worker because password storage recovery is incomplete; monitor will remain stopped"
            );
            return false;
        }
        if self.storage_recovery_sticky_blocked {
            self.worker_pause_latch.pause();
            return false;
        }
        let next_config = startup.config;
        let start_monitor = start_monitor && self.desired_monitor_running;
        let apply_command = self.worker_pause_latch.apply_config_command(
            pause_epoch,
            next_config.settings.clone(),
            next_config.accounts.clone(),
            true,
            start_monitor,
        );
        if let Err(e) = self.worker_tx.try_send(apply_command) {
            self.storage_recovery_ready = false;
            self.resume_monitor_after_settings = false;
            self.worker_pause_latch.pause();
            if self.worker_status == models::WorkerStatus::Running {
                let _ = self.worker_tx.try_send(background::WorkerCommand::Stop);
            }
            tracing::error!(
                error = %e,
                "Could not deliver saved config to worker; monitor will remain stopped"
            );
            return false;
        }
        self.config = next_config;
        self.storage_recovery_ready = true;
        self.update_tray_status();
        true
    }

    fn retry_blocked_storage_recovery(&mut self) {
        if self.storage_recovery_ready
            || self.storage_recovery_sticky_blocked
            || self.settings_transition_active()
        {
            return;
        }
        if self.last_storage_recovery_attempt.elapsed() < STORAGE_RECOVERY_RETRY_INTERVAL {
            return;
        }
        self.last_storage_recovery_attempt = Instant::now();
        let should_resume = self.resume_monitor_after_settings
            && self.desired_monitor_running
            && self.accessibility_ready_for_start();
        if self.reload_config_after_settings_with_recovery_lease(should_resume) {
            self.resume_monitor_after_settings = false;
            tracing::info!("Deferred password storage recovery completed safely");
        }
    }

    fn update_tray_status(&self) {
        let running = self.worker_status == models::WorkerStatus::Running;
        if let Err(e) = single_instance::write_monitor_status(running) {
            tracing::warn!("Could not write monitor status: {e}");
        }

        let Some(tray) = &self.tray else {
            return;
        };
        tray.set_accessibility_trusted(self.accessibility_trusted);
        tray.set_keychain_enabled(self.config.settings.use_keyring);
        tray.set_monitor_running(self.monitor_control_state().toggle_requests_stop());
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    fn privileged_ipc_available(&self) -> bool {
        self.ipc_server.is_some()
    }

    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    fn privileged_ipc_available(&self) -> bool {
        false
    }
}

impl ApplicationHandler for LightweightSupervisor {
    fn new_events(&mut self, _event_loop: &ActiveEventLoop, cause: StartCause) {
        if matches!(cause, StartCause::Init) {
            self.ensure_tray();
        }
    }

    fn resumed(&mut self, _event_loop: &ActiveEventLoop) {}

    fn window_event(
        &mut self,
        _event_loop: &ActiveEventLoop,
        _window_id: WindowId,
        _event: WindowEvent,
    ) {
    }

    fn about_to_wait(&mut self, event_loop: &ActiveEventLoop) {
        self.ensure_tray();
        if self.process_tray_commands(event_loop) {
            return;
        }
        self.process_worker_events();
        self.poll_pending_settings_launch();
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        self.process_local_ipc_commands();
        #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
        {
            self.process_monitor_commands();
            self.process_activation_requests();
        }
        self.poll_settings_window();
        self.retry_blocked_storage_recovery();
        self.poll_accessibility();
        event_loop.set_control_flow(ControlFlow::WaitUntil(Instant::now() + SUPERVISOR_TICK));
    }

    fn exiting(&mut self, _event_loop: &ActiveEventLoop) {
        self.handle_exit_request();
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn acknowledge_settings_bootstrap_peer(
    peer_command: single_instance::PeerLocalIpcCommand,
) -> anyhow::Result<()> {
    peer_command.acknowledge()
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn local_ipc_command_authorized(
    command: single_instance::LocalIpcCommand,
    peer_pid: u32,
    settings_child_pid: Option<u32>,
    settings_child_bootstrapped: bool,
) -> bool {
    match command {
        single_instance::LocalIpcCommand::Activate => true,
        single_instance::LocalIpcCommand::SettingsBootstrap => Some(peer_pid) == settings_child_pid,
        single_instance::LocalIpcCommand::ReloadConfig
        | single_instance::LocalIpcCommand::Monitor(_) => {
            settings_child_bootstrapped && Some(peer_pid) == settings_child_pid
        }
    }
}

fn initial_full_ui_tab(args: &[String]) -> models::Tab {
    for arg in args {
        match arg.as_str() {
            "--initial-tab=accounts" | "--accounts" => return models::Tab::Accounts,
            "--initial-tab=settings" | "--settings" => return models::Tab::Settings,
            #[cfg(feature = "diagnostics-ui")]
            "--initial-tab=diagnose" | "--diagnose" => return models::Tab::Diagnose,
            _ => {}
        }
    }

    models::Tab::Settings
}

fn initial_tab_arg(initial_tab: models::Tab) -> &'static str {
    match initial_tab {
        models::Tab::Accounts => "--initial-tab=accounts",
        models::Tab::Settings => "--initial-tab=settings",
        #[cfg(feature = "diagnostics-ui")]
        models::Tab::Diagnose => "--initial-tab=diagnose",
    }
}

fn spawn_full_ui_window(
    initial_tab: models::Tab,
    privileged_ipc_available: bool,
    settings_session_token: &single_instance::SettingsSessionToken,
) -> anyhow::Result<Child> {
    Ok(full_ui_command(
        std::env::current_exe()?,
        initial_tab,
        privileged_ipc_available,
        Some(settings_session_token),
    )
    .spawn()?)
}

fn full_ui_command(
    current_exe: impl AsRef<std::ffi::OsStr>,
    initial_tab: models::Tab,
    privileged_ipc_available: bool,
    settings_session_token: Option<&single_instance::SettingsSessionToken>,
) -> Command {
    let mut command = Command::new(current_exe);
    command.arg("--full-ui").arg(initial_tab_arg(initial_tab));
    if let Some(token) = settings_session_token {
        command.env(SETTINGS_SESSION_TOKEN_ENV, token.as_str());
    } else {
        command.env_remove(SETTINGS_SESSION_TOKEN_ENV);
    }
    #[cfg(target_os = "windows")]
    {
        let _ = privileged_ipc_available;
        command.env_remove(LEGACY_MONITOR_CONTROL_TOKEN_ENV);
    }
    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    {
        let _ = privileged_ipc_available;
    }
    #[cfg(target_os = "macos")]
    {
        let _ = privileged_ipc_available;
        command.env_remove(LEGACY_IPC_TOKEN_ENV);
    }
    command
}

fn child_has_exited(child: &mut Child) -> bool {
    match child.try_wait() {
        Ok(Some(_)) => true,
        Ok(None) => false,
        Err(e) => {
            tracing::warn!("Could not check child process state before exit: {e}");
            true
        }
    }
}

fn terminate_child_process(child: &mut Child, label: &str) {
    request_child_termination(child, label);
    if wait_for_child_exit(child, Duration::from_millis(500)) {
        return;
    }

    if let Err(e) = child.kill() {
        tracing::warn!("Could not force quit {label}: {e}");
        return;
    }
    let _ = wait_for_child_exit(child, Duration::from_millis(500));
}

#[cfg(unix)]
fn request_child_termination(child: &mut Child, label: &str) {
    let status = unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
    if status != 0 {
        tracing::warn!(
            "Could not request graceful shutdown for {label}: {}",
            std::io::Error::last_os_error()
        );
    }
}

#[cfg(not(unix))]
fn request_child_termination(child: &mut Child, label: &str) {
    if let Err(e) = child.kill() {
        tracing::warn!("Could not request shutdown for {label}: {e}");
    }
}

fn wait_for_child_exit(child: &mut Child, timeout: Duration) -> bool {
    let started = Instant::now();
    loop {
        if child_has_exited(child) {
            return true;
        }
        if started.elapsed() >= timeout {
            return false;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn fill_result_label(report: &debug_fill::FillAttemptReport) -> String {
    match report.field("post_check_state").unwrap_or("unknown") {
        "authenticated" => "authenticated".to_string(),
        "still_prompt" => "still prompt".to_string(),
        "prompt_mismatch" => "prompt mismatch".to_string(),
        "prompt_gone_unknown" => "prompt gone".to_string(),
        _ if report.success => "submitted".to_string(),
        _ => report
            .failure_reason
            .as_deref()
            .filter(|reason| !reason.is_empty())
            .unwrap_or("failed")
            .chars()
            .take(48)
            .collect(),
    }
}

fn load_icon() -> anyhow::Result<egui::IconData> {
    let icon_bytes = include_bytes!("../assets/icon_tray.png");
    let image = image::load_from_memory(icon_bytes)?;
    let rgba = image.into_rgba8();
    let (width, height) = rgba.dimensions();
    Ok(egui::IconData {
        rgba: rgba.into_raw(),
        width,
        height,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        acquire_authorized_settings_session_with, fill_result_label,
        finish_startup_storage_recovery_after_journals_with_ops, full_ui_command, initial_tab_arg,
        publish_initial_monitor_status, std_channel, tokio_channel, LightweightSupervisor,
        MonitorControlState, StartupConfig,
    };
    use crate::background::{WorkerCommand, WorkerInvalidator, WorkerQuiescenceAck};
    use crate::debug_fill::FillAttemptReport;
    use crate::models::{Account, AppConfig};

    fn report(success: bool, fields: &[(&str, &str)], failure: Option<&str>) -> FillAttemptReport {
        FillAttemptReport {
            fields: fields
                .iter()
                .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
                .collect(),
            success,
            failure_reason: failure.map(str::to_string),
        }
    }

    fn take_quiescence_request(
        worker_rx: &mut tokio::sync::mpsc::Receiver<WorkerCommand>,
    ) -> (u64, std::sync::mpsc::Sender<WorkerQuiescenceAck>) {
        match worker_rx.try_recv().unwrap() {
            WorkerCommand::Quiesce {
                request_id,
                acknowledgement,
            } => (request_id, acknowledgement),
            other => panic!("expected Quiesce, got {other:?}"),
        }
    }

    fn complete_pending_settings_launch(
        supervisor: &mut LightweightSupervisor,
        worker_rx: &mut tokio::sync::mpsc::Receiver<WorkerCommand>,
        expected_tab: crate::models::Tab,
    ) {
        let (request_id, acknowledgement) = take_quiescence_request(worker_rx);
        acknowledgement
            .send(WorkerQuiescenceAck { request_id })
            .unwrap();
        supervisor.poll_pending_settings_launch_with(std::time::Instant::now(), |tab, _token| {
            assert_eq!(tab, expected_tab);
            Ok(spawn_test_child("exec sleep 30"))
        });
    }

    #[test]
    fn fill_result_label_maps_report_state_for_menu_display() {
        for (success, fields, failure, expected) in [
            (
                true,
                &[("post_check_state", "authenticated")][..],
                None,
                "authenticated",
            ),
            (
                false,
                &[("post_check_state", "prompt_mismatch")][..],
                None,
                "prompt mismatch",
            ),
        ] {
            assert_eq!(
                fill_result_label(&report(success, fields, failure)),
                expected
            );
        }

        let long_failure = report(
            false,
            &[("post_check_state", "unknown")],
            Some("very_long_failure_reason_that_should_not_expand_the_status_menu_forever"),
        );
        assert!(fill_result_label(&long_failure).len() <= 48);
    }

    #[test]
    fn full_ui_command_includes_full_ui_args() {
        let command = full_ui_command(
            "/tmp/windows-app-autologin",
            crate::models::Tab::Accounts,
            false,
            None,
        );

        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        assert_eq!(
            args,
            vec![
                "--full-ui".to_string(),
                initial_tab_arg(crate::models::Tab::Accounts).to_string()
            ]
        );
    }

    #[test]
    fn copied_settings_token_cannot_reach_lease_or_ui_without_bootstrap_ack() {
        let events = std::cell::RefCell::new(Vec::new());
        let result = acquire_authorized_settings_session_with(
            || {
                events.borrow_mut().push("token");
                Ok("copied-bearer-token")
            },
            || {
                events.borrow_mut().push("bootstrap-denied");
                anyhow::bail!("supervisor did not acknowledge this PID")
            },
            |_| {
                events.borrow_mut().push("lease");
                Ok(())
            },
        );

        assert!(result.is_err());
        assert_eq!(events.into_inner(), vec!["bootstrap-denied"]);
    }

    #[test]
    fn full_ui_bootstrap_precedes_settings_lease_and_all_ui_initialization() {
        let events = std::cell::RefCell::new(Vec::new());
        acquire_authorized_settings_session_with(
            || {
                events.borrow_mut().push("token");
                Ok("session-token")
            },
            || {
                events.borrow_mut().push("bootstrap-ack");
                Ok(())
            },
            |_| {
                events.borrow_mut().push("lease");
                Ok(())
            },
        )
        .unwrap();
        events.borrow_mut().push("ui");
        assert_eq!(
            events.into_inner(),
            vec!["bootstrap-ack", "token", "lease", "ui"]
        );

        let source = include_str!("main.rs");
        let run_full_ui_start = source
            .find("fn run_full_ui(initial_tab: models::Tab)")
            .unwrap();
        let helper_start = source[run_full_ui_start..]
            .find("fn acquire_authorized_settings_session_with")
            .map(|offset| run_full_ui_start + offset)
            .unwrap();
        let body = &source[run_full_ui_start..helper_start];
        let authorization = body
            .find("acquire_authorized_settings_session_with(")
            .unwrap();
        let full_ui_guard = body
            .find("single_instance::FullUiInstanceGuard::acquire()")
            .unwrap();
        let config_load = body.find("load_full_ui_config()").unwrap();
        let ui_start = body.find("eframe::run_native(").unwrap();
        assert!(authorization < full_ui_guard);
        assert!(full_ui_guard < config_load);
        assert!(config_load < ui_start);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn full_ui_command_removes_legacy_monitor_control_token_env() {
        let command = full_ui_command(
            "/tmp/windows-app-autologin",
            crate::models::Tab::Settings,
            false,
            None,
        );

        let token_env = command
            .get_envs()
            .find(|(key, _)| *key == super::LEGACY_MONITOR_CONTROL_TOKEN_ENV);

        assert_eq!(
            token_env,
            Some((
                std::ffi::OsStr::new(super::LEGACY_MONITOR_CONTROL_TOKEN_ENV),
                None
            ))
        );
    }

    #[test]
    fn launch_init_queues_monitor_start_when_accessibility_is_trusted() {
        let (worker_tx, mut worker_rx) = tokio_channel(8);

        super::queue_monitor_start_if_accessibility_trusted(&worker_tx, true, true);

        match worker_rx.try_recv().unwrap() {
            WorkerCommand::Start => {}
            other => panic!("expected Start, got {other:?}"),
        }
    }

    #[test]
    fn launch_init_leaves_monitor_idle_without_accessibility() {
        let (worker_tx, mut worker_rx) = tokio_channel(8);

        super::queue_monitor_start_if_accessibility_trusted(&worker_tx, false, true);

        assert!(worker_rx.try_recv().is_err());
    }

    #[test]
    fn launch_init_leaves_monitor_idle_while_storage_recovery_is_blocked() {
        let (worker_tx, mut worker_rx) = tokio_channel(8);

        super::queue_monitor_start_if_accessibility_trusted(&worker_tx, true, false);

        assert!(worker_rx.try_recv().is_err());
    }

    #[test]
    fn startup_staged_recovery_failure_preserves_the_durable_block() {
        let events = std::cell::RefCell::new(Vec::new());

        let result = finish_startup_storage_recovery_after_journals_with_ops(
            true,
            || {
                events.borrow_mut().push("reconcile-staged");
                anyhow::bail!("staged fallback key conflict")
            },
            || {
                events.borrow_mut().push("clear-block");
                Ok(())
            },
            || {
                events.borrow_mut().push("read-block");
                Ok(true)
            },
        );

        assert!(result.is_err());
        assert_eq!(events.into_inner(), vec!["reconcile-staged"]);
    }

    #[test]
    fn launch_init_publishes_idle_status_before_worker_ack() {
        let mut published_statuses = Vec::new();

        publish_initial_monitor_status(|running| {
            published_statuses.push(running);
            Ok(())
        });

        assert_eq!(published_statuses, vec![false]);
    }

    #[test]
    fn consecutive_settings_spawns_use_distinct_authorization_tokens() {
        let (worker_tx, _worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (tray_tx, tray_rx) = std_channel();
        let mut supervisor = LightweightSupervisor::new(
            worker_tx,
            worker_event_rx,
            tray_tx,
            tray_rx,
            WorkerInvalidator::new(),
            AppConfig::default(),
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            None,
        );
        let initial_token = supervisor.settings_session_token.clone();

        let (first_lease, first_token) = supervisor.prepare_settings_session_for_spawn().unwrap();
        assert_ne!(first_token.as_str(), initial_token.as_str());
        drop(first_lease);

        let (second_lease, second_token) = supervisor.prepare_settings_session_for_spawn().unwrap();
        assert_ne!(second_token.as_str(), first_token.as_str());
        assert_ne!(second_token.as_str(), initial_token.as_str());
        assert!(supervisor
            .acquire_settings_session_lease(&first_token)
            .is_err());
        drop(second_lease);
    }

    #[test]
    fn failed_spawn_revokes_token_and_stale_child_cannot_reacquire() {
        let (worker_tx, _worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (tray_tx, tray_rx) = std_channel();
        let mut supervisor = LightweightSupervisor::new(
            worker_tx,
            worker_event_rx,
            tray_tx,
            tray_rx,
            WorkerInvalidator::new(),
            AppConfig::default(),
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            None,
        );
        let (session_lease, failed_spawn_token) =
            supervisor.prepare_settings_session_for_spawn().unwrap();

        supervisor.finish_failed_settings_spawn(session_lease, false);

        assert_ne!(
            supervisor.settings_session_token.as_str(),
            failed_spawn_token.as_str()
        );
        assert!(supervisor
            .acquire_settings_session_lease(&failed_spawn_token)
            .is_err());
    }

    #[test]
    fn confirmed_exit_rotates_token_even_when_recovery_is_blocked() {
        let (worker_tx, _worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (tray_tx, tray_rx) = std_channel();
        let mut supervisor = LightweightSupervisor::new(
            worker_tx,
            worker_event_rx,
            tray_tx,
            tray_rx,
            WorkerInvalidator::new(),
            AppConfig::default(),
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            None,
        );
        let (session_lease, exited_child_token) =
            supervisor.prepare_settings_session_for_spawn().unwrap();
        supervisor.settings_session_lease = Some(session_lease);
        supervisor.settings_child = Some(spawn_test_child("exit 0"));
        wait_for_test_child_exit(&mut supervisor);

        supervisor.poll_settings_window_with_loader(|_| StartupConfig {
            config: AppConfig::default(),
            storage_recovery_ready: false,
        });

        assert!(supervisor.settings_child.is_none());
        assert!(supervisor.storage_recovery_sticky_blocked);
        assert_ne!(
            supervisor.settings_session_token.as_str(),
            exited_child_token.as_str()
        );
        assert!(supervisor
            .acquire_settings_session_lease(&exited_child_token)
            .is_err());

        let recovery_failure_revocation = supervisor.settings_session_token.clone();
        assert!(!supervisor.reload_config_after_settings_with_loader(|| {
            panic!("sticky recovery must not invoke the loader")
        }));
        assert_ne!(
            supervisor.settings_session_token.as_str(),
            recovery_failure_revocation.as_str()
        );
        assert!(supervisor
            .acquire_settings_session_lease(&recovery_failure_revocation)
            .is_err());
    }

    #[test]
    fn reload_config_after_settings_uses_recovered_config_before_worker_refresh() {
        let (worker_tx, mut worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (tray_tx, tray_rx) = std_channel();
        let mut supervisor = LightweightSupervisor::new(
            worker_tx,
            worker_event_rx,
            tray_tx,
            tray_rx,
            WorkerInvalidator::new(),
            AppConfig::default(),
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            None,
        );

        let mut recovered = AppConfig::default();
        recovered.settings.use_keyring = false;
        let mut account = Account::new("user@example.com");
        account.id = "account-1".to_string();
        account.has_saved_password = true;
        recovered.accounts.push(account);
        let expected = recovered.clone();

        assert!(
            supervisor.reload_config_after_settings_with_loader(|| StartupConfig {
                config: recovered,
                storage_recovery_ready: true,
            })
        );

        assert_eq!(supervisor.config, expected);
        match worker_rx.try_recv().unwrap() {
            WorkerCommand::ApplyConfigAndReleasePause {
                settings,
                accounts,
                refresh_passwords,
                start_monitor,
                pause_epoch: _,
            } => {
                assert_eq!(settings, expected.settings);
                assert_eq!(accounts, expected.accounts);
                assert!(refresh_passwords);
                assert!(!start_monitor);
            }
            other => panic!("expected ApplyConfigAndReleasePause, got {other:?}"),
        }
        assert!(worker_rx.try_recv().is_err());
    }

    #[test]
    fn reload_config_after_settings_fails_closed_when_worker_sync_cannot_be_queued() {
        let (worker_tx, worker_rx) = tokio_channel(1);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (tray_tx, tray_rx) = std_channel();
        worker_tx.try_send(WorkerCommand::Start).unwrap();
        let original_config = AppConfig::default();
        let mut supervisor = LightweightSupervisor::new(
            worker_tx,
            worker_event_rx,
            tray_tx,
            tray_rx,
            WorkerInvalidator::new(),
            original_config.clone(),
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            None,
        );
        supervisor.worker_status = crate::models::WorkerStatus::Running;
        supervisor.resume_monitor_after_settings = true;

        let mut recovered = AppConfig::default();
        recovered.settings.use_keyring = false;

        assert!(
            !supervisor.reload_config_after_settings_with_loader(|| StartupConfig {
                config: recovered,
                storage_recovery_ready: true,
            })
        );
        assert_eq!(supervisor.config, original_config);
        assert!(!supervisor.resume_monitor_after_settings);
        assert_eq!(worker_rx.capacity(), 0);
    }

    #[test]
    fn reload_config_stops_monitor_and_withholds_credentials_when_recovery_is_blocked() {
        let (worker_tx, mut worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (tray_tx, tray_rx) = std_channel();
        let original_config = AppConfig::default();
        let mut supervisor = LightweightSupervisor::new(
            worker_tx,
            worker_event_rx,
            tray_tx,
            tray_rx,
            WorkerInvalidator::new(),
            original_config.clone(),
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            None,
        );
        supervisor.worker_status = crate::models::WorkerStatus::Running;
        supervisor.resume_monitor_after_settings = true;

        let mut unverified = AppConfig::default();
        unverified.settings.use_keyring = false;
        assert!(
            !supervisor.reload_config_after_settings_with_loader(|| StartupConfig {
                config: unverified,
                storage_recovery_ready: false,
            })
        );

        assert_eq!(supervisor.config, original_config);
        assert!(!supervisor.storage_recovery_ready);
        assert!(!supervisor.resume_monitor_after_settings);
        match worker_rx.try_recv().unwrap() {
            WorkerCommand::Stop => {}
            other => panic!("expected Stop, got {other:?}"),
        }
        assert!(worker_rx.try_recv().is_err());
    }

    #[test]
    fn blocked_recovery_orders_stop_after_a_queued_start_while_status_is_idle() {
        let (worker_tx, mut worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (tray_tx, tray_rx) = std_channel();
        worker_tx.try_send(WorkerCommand::Start).unwrap();
        let mut supervisor = LightweightSupervisor::new(
            worker_tx,
            worker_event_rx,
            tray_tx,
            tray_rx,
            WorkerInvalidator::new(),
            AppConfig::default(),
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            None,
        );
        supervisor.worker_status = crate::models::WorkerStatus::Idle;

        assert!(
            !supervisor.reload_config_after_settings_with_loader(|| StartupConfig {
                config: AppConfig::default(),
                storage_recovery_ready: false,
            })
        );

        assert!(!supervisor.storage_recovery_ready);
        match worker_rx.try_recv().unwrap() {
            WorkerCommand::Start => {}
            other => panic!("expected queued Start, got {other:?}"),
        }
        match worker_rx.try_recv().unwrap() {
            WorkerCommand::Stop => {}
            other => panic!("expected ordered Stop, got {other:?}"),
        }
        assert!(worker_rx.try_recv().is_err());
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    #[test]
    fn local_ipc_authorization_requires_bootstrapped_settings_child_for_privileged_commands() {
        use super::single_instance::{LocalIpcCommand, MonitorControlCommand};

        assert!(super::local_ipc_command_authorized(
            LocalIpcCommand::Activate,
            42,
            None,
            false,
        ));
        assert!(!super::local_ipc_command_authorized(
            LocalIpcCommand::ReloadConfig,
            42,
            None,
            true,
        ));
        assert!(!super::local_ipc_command_authorized(
            LocalIpcCommand::Monitor(MonitorControlCommand::Start),
            42,
            Some(7),
            true,
        ));
        assert!(!super::local_ipc_command_authorized(
            LocalIpcCommand::Monitor(MonitorControlCommand::Stop),
            42,
            Some(42),
            false,
        ));
        assert!(super::local_ipc_command_authorized(
            LocalIpcCommand::Monitor(MonitorControlCommand::Stop),
            42,
            Some(42),
            true,
        ));
        assert!(super::local_ipc_command_authorized(
            LocalIpcCommand::Monitor(MonitorControlCommand::StorageRecoveryBlocked),
            42,
            Some(42),
            true,
        ));
        assert!(!super::local_ipc_command_authorized(
            LocalIpcCommand::Monitor(MonitorControlCommand::StorageRecoveryBlocked),
            7,
            Some(42),
            true,
        ));
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    #[test]
    fn settings_bootstrap_accepts_only_the_exact_live_spawned_child_pid() {
        use super::single_instance::LocalIpcCommand;

        let (worker_tx, _worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (tray_tx, tray_rx) = std_channel();
        let mut supervisor = LightweightSupervisor::new(
            worker_tx,
            worker_event_rx,
            tray_tx,
            tray_rx,
            WorkerInvalidator::new(),
            AppConfig::default(),
            None,
        );
        let child = spawn_test_child("exec sleep 30");
        let child_pid = child.id();
        let unauthorized_pid = child_pid.checked_add(1).unwrap_or(child_pid - 1);
        supervisor.settings_child = Some(child);

        assert!(!supervisor.acknowledge_settings_bootstrap_with(unauthorized_pid, || Ok(())));
        assert!(!supervisor.settings_child_bootstrapped);
        assert!(
            !supervisor.acknowledge_settings_bootstrap_with(child_pid, || {
                anyhow::bail!("client disconnected before ACK")
            })
        );
        assert!(!supervisor.settings_child_bootstrapped);
        assert!(supervisor.acknowledge_settings_bootstrap_with(child_pid, || Ok(())));
        assert!(supervisor.settings_child_bootstrapped);
        assert!(supervisor.authorize_local_ipc_command(LocalIpcCommand::ReloadConfig, child_pid));

        let mut child = supervisor.settings_child.take().unwrap();
        let _ = child.kill();
        let _ = child.wait();
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    #[test]
    fn arbitrary_activation_peer_never_bootstraps_settings() {
        use super::single_instance::LocalIpcCommand;

        let (worker_tx, _worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (tray_tx, tray_rx) = std_channel();
        let mut supervisor = LightweightSupervisor::new(
            worker_tx,
            worker_event_rx,
            tray_tx,
            tray_rx,
            WorkerInvalidator::new(),
            AppConfig::default(),
            None,
        );

        assert!(supervisor.authorize_local_ipc_command(LocalIpcCommand::Activate, 4242));
        assert!(!supervisor.settings_child_bootstrapped);
        assert!(!supervisor.acknowledge_settings_bootstrap_with(4242, || Ok(())));
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    #[test]
    fn activate_ipc_pauses_running_monitor_before_opening_accounts() {
        use super::single_instance::LocalIpcCommand;

        let (worker_tx, mut worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (tray_tx, tray_rx) = std_channel();
        let mut supervisor = LightweightSupervisor::new(
            worker_tx,
            worker_event_rx,
            tray_tx,
            tray_rx,
            WorkerInvalidator::new(),
            AppConfig::default(),
            None,
        );
        supervisor.worker_status = crate::models::WorkerStatus::Running;
        supervisor.accessibility_trusted = true;
        supervisor.resume_monitor_after_settings = false;

        assert!(supervisor.handle_authorized_local_ipc_command(LocalIpcCommand::Activate));

        match worker_rx.try_recv().unwrap() {
            WorkerCommand::Stop => {}
            other => panic!("expected Stop, got {other:?}"),
        }
        assert_eq!(
            supervisor.worker_status,
            crate::models::WorkerStatus::Running
        );
        assert!(supervisor.pending_settings_launch.is_some());
        assert!(supervisor.settings_child.is_none());
        complete_pending_settings_launch(
            &mut supervisor,
            &mut worker_rx,
            crate::models::Tab::Accounts,
        );
        assert!(supervisor.resume_monitor_after_settings);
        assert!(supervisor.settings_child.is_some());
        let _ = supervisor.settings_child.take().unwrap().kill();
    }

    #[test]
    fn opening_settings_window_pauses_running_monitor_until_safe_reload() {
        let (worker_tx, mut worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (tray_tx, tray_rx) = std_channel();
        let mut supervisor = LightweightSupervisor::new(
            worker_tx,
            worker_event_rx,
            tray_tx,
            tray_rx,
            WorkerInvalidator::new(),
            AppConfig::default(),
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            None,
        );
        supervisor.worker_status = crate::models::WorkerStatus::Running;
        supervisor.accessibility_trusted = true;
        supervisor.resume_monitor_after_settings = false;
        let initial_token = supervisor.settings_session_token.clone();

        supervisor.open_settings_window();

        match worker_rx.try_recv().unwrap() {
            WorkerCommand::Stop => {}
            other => panic!("expected Stop, got {other:?}"),
        }
        assert_eq!(
            supervisor.worker_status,
            crate::models::WorkerStatus::Running
        );
        assert!(supervisor.worker_pause_latch.is_paused());
        assert!(!supervisor.resume_monitor_after_settings);
        assert!(supervisor.pending_settings_launch.is_some());
        assert!(supervisor.settings_child.is_none());
        assert_eq!(
            supervisor.settings_session_token.as_str(),
            initial_token.as_str()
        );
        supervisor.poll_pending_settings_launch_with(std::time::Instant::now(), |_, _| {
            panic!("settings must not spawn before worker quiescence is acknowledged")
        });
        assert!(supervisor.pending_settings_launch.is_some());
        assert!(supervisor.settings_child.is_none());
        assert_eq!(
            supervisor.settings_session_token.as_str(),
            initial_token.as_str()
        );

        complete_pending_settings_launch(
            &mut supervisor,
            &mut worker_rx,
            crate::models::Tab::Settings,
        );
        assert_ne!(
            supervisor.settings_session_token.as_str(),
            initial_token.as_str()
        );
        assert!(supervisor.resume_monitor_after_settings);
        assert!(supervisor.settings_child.is_some());
        let _ = supervisor.settings_child.take().unwrap().kill();
    }

    #[test]
    fn opening_settings_preserves_queued_start_intent_even_when_status_is_idle() {
        let (worker_tx, mut worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (tray_tx, tray_rx) = std_channel();
        worker_tx.try_send(WorkerCommand::Start).unwrap();
        let mut supervisor = LightweightSupervisor::new(
            worker_tx,
            worker_event_rx,
            tray_tx,
            tray_rx,
            WorkerInvalidator::new(),
            AppConfig::default(),
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            None,
        );
        supervisor.worker_status = crate::models::WorkerStatus::Idle;
        supervisor.accessibility_trusted = true;

        supervisor.open_settings_window();

        match worker_rx.try_recv().unwrap() {
            WorkerCommand::Start => {}
            other => panic!("expected queued Start, got {other:?}"),
        }
        match worker_rx.try_recv().unwrap() {
            WorkerCommand::Stop => {}
            other => panic!("expected ordered Stop, got {other:?}"),
        }
        complete_pending_settings_launch(
            &mut supervisor,
            &mut worker_rx,
            crate::models::Tab::Settings,
        );
        assert!(supervisor.resume_monitor_after_settings);
        assert!(supervisor.settings_child.is_some());
        let _ = supervisor.settings_child.take().unwrap().kill();
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    #[test]
    fn quiescence_queue_full_keeps_settings_unauthorized_and_worker_paused() {
        use super::single_instance::LocalIpcCommand;

        let (worker_tx, mut worker_rx) = tokio_channel(1);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (tray_tx, tray_rx) = std_channel();
        let mut supervisor = LightweightSupervisor::new(
            worker_tx,
            worker_event_rx,
            tray_tx,
            tray_rx,
            WorkerInvalidator::new(),
            AppConfig::default(),
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            None,
        );
        let initial_token = supervisor.settings_session_token.clone();

        assert!(!supervisor.handle_authorized_local_ipc_command(LocalIpcCommand::Activate));

        assert!(matches!(worker_rx.try_recv(), Ok(WorkerCommand::Stop)));
        assert!(supervisor.worker_pause_latch.is_paused());
        assert!(supervisor.pending_settings_launch.is_none());
        assert!(supervisor.settings_child.is_none());
        assert_eq!(
            supervisor.settings_session_token.as_str(),
            initial_token.as_str()
        );
        supervisor.poll_pending_settings_launch_with(std::time::Instant::now(), |_, _| {
            panic!("queue-full settings request must not invoke spawn")
        });
    }

    #[test]
    fn disconnected_quiescence_ack_keeps_settings_unauthorized_and_worker_paused() {
        let (worker_tx, mut worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (tray_tx, tray_rx) = std_channel();
        let mut supervisor = LightweightSupervisor::new(
            worker_tx,
            worker_event_rx,
            tray_tx,
            tray_rx,
            WorkerInvalidator::new(),
            AppConfig::default(),
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            None,
        );
        let initial_token = supervisor.settings_session_token.clone();

        supervisor.open_settings_window();
        assert!(matches!(worker_rx.try_recv(), Ok(WorkerCommand::Stop)));
        let (_, acknowledgement) = take_quiescence_request(&mut worker_rx);
        drop(acknowledgement);
        supervisor.poll_pending_settings_launch_with(std::time::Instant::now(), |_, _| {
            panic!("disconnected settings request must not invoke spawn")
        });

        assert!(supervisor.worker_pause_latch.is_paused());
        assert!(supervisor.pending_settings_launch.is_none());
        assert!(supervisor.settings_child.is_none());
        assert_eq!(
            supervisor.settings_session_token.as_str(),
            initial_token.as_str()
        );
    }

    #[test]
    fn mismatched_quiescence_ack_keeps_settings_unauthorized_and_worker_paused() {
        let (worker_tx, mut worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (tray_tx, tray_rx) = std_channel();
        let mut supervisor = LightweightSupervisor::new(
            worker_tx,
            worker_event_rx,
            tray_tx,
            tray_rx,
            WorkerInvalidator::new(),
            AppConfig::default(),
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            None,
        );
        let initial_token = supervisor.settings_session_token.clone();

        supervisor.open_settings_window();
        assert!(matches!(worker_rx.try_recv(), Ok(WorkerCommand::Stop)));
        let (request_id, acknowledgement) = take_quiescence_request(&mut worker_rx);
        acknowledgement
            .send(WorkerQuiescenceAck {
                request_id: request_id + 1,
            })
            .unwrap();
        supervisor.poll_pending_settings_launch_with(std::time::Instant::now(), |_, _| {
            panic!("mismatched settings request must not invoke spawn")
        });

        assert!(supervisor.worker_pause_latch.is_paused());
        assert!(supervisor.pending_settings_launch.is_none());
        assert!(supervisor.settings_child.is_none());
        assert_eq!(
            supervisor.settings_session_token.as_str(),
            initial_token.as_str()
        );
    }

    #[test]
    fn timed_out_quiescence_ignores_late_ack_and_uses_a_fresh_request() {
        let (worker_tx, mut worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (tray_tx, tray_rx) = std_channel();
        let mut supervisor = LightweightSupervisor::new(
            worker_tx,
            worker_event_rx,
            tray_tx,
            tray_rx,
            WorkerInvalidator::new(),
            AppConfig::default(),
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            None,
        );
        let initial_token = supervisor.settings_session_token.clone();

        supervisor.open_settings_window();
        assert!(matches!(worker_rx.try_recv(), Ok(WorkerCommand::Stop)));
        let (old_request_id, old_acknowledgement) = take_quiescence_request(&mut worker_rx);
        let deadline = supervisor
            .pending_settings_launch
            .as_ref()
            .unwrap()
            .deadline;
        supervisor.poll_pending_settings_launch_with(deadline, |_, _| {
            panic!("timed-out settings request must not invoke spawn")
        });

        assert!(supervisor.worker_pause_latch.is_paused());
        assert!(supervisor.pending_settings_launch.is_none());
        assert!(supervisor.settings_child.is_none());
        assert_eq!(
            supervisor.settings_session_token.as_str(),
            initial_token.as_str()
        );
        assert!(old_acknowledgement
            .send(WorkerQuiescenceAck {
                request_id: old_request_id,
            })
            .is_err());

        supervisor.open_settings_window();
        assert!(matches!(worker_rx.try_recv(), Ok(WorkerCommand::Stop)));
        let (new_request_id, new_acknowledgement) = take_quiescence_request(&mut worker_rx);
        assert_ne!(new_request_id, old_request_id);
        supervisor.poll_pending_settings_launch_with(std::time::Instant::now(), |_, _| {
            panic!("late acknowledgement must not satisfy a fresh settings request")
        });
        assert!(supervisor.pending_settings_launch.is_some());
        assert!(supervisor.settings_child.is_none());

        new_acknowledgement
            .send(WorkerQuiescenceAck {
                request_id: new_request_id,
            })
            .unwrap();
        supervisor.poll_pending_settings_launch_with(std::time::Instant::now(), |tab, _| {
            assert_eq!(tab, crate::models::Tab::Settings);
            Ok(spawn_test_child("exec sleep 30"))
        });
        assert!(supervisor.settings_child.is_some());
        let _ = supervisor.settings_child.take().unwrap().kill();
    }

    #[test]
    fn explicit_stop_is_a_barrier_across_stale_status_and_settings_exit() {
        let (worker_tx, mut worker_rx) = tokio_channel(8);
        let (worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (tray_tx, tray_rx) = std_channel();
        let mut supervisor = LightweightSupervisor::new(
            worker_tx,
            worker_event_rx,
            tray_tx,
            tray_rx,
            WorkerInvalidator::new(),
            AppConfig::default(),
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            None,
        );
        supervisor.accessibility_trusted = true;
        supervisor.worker_status = crate::models::WorkerStatus::Running;
        supervisor.desired_monitor_running = true;

        supervisor.open_settings_window();
        match worker_rx.try_recv().unwrap() {
            WorkerCommand::Stop => {}
            other => panic!("expected settings pause Stop, got {other:?}"),
        }
        let (request_id, acknowledgement) = take_quiescence_request(&mut worker_rx);

        supervisor.stop_monitor();
        worker_event_tx
            .try_send(crate::background::WorkerEvent::StatusChanged(
                crate::models::WorkerStatus::Running,
            ))
            .unwrap();
        supervisor.process_worker_events();

        assert!(!supervisor.desired_monitor_running);
        assert!(!supervisor.resume_monitor_after_settings);
        assert!(supervisor.pending_settings_launch.is_some());
        assert!(supervisor.settings_child.is_none());
        match worker_rx.try_recv().unwrap() {
            WorkerCommand::Stop => {}
            other => panic!("expected explicit Stop, got {other:?}"),
        }

        acknowledgement
            .send(WorkerQuiescenceAck { request_id })
            .unwrap();
        supervisor.poll_pending_settings_launch_with(std::time::Instant::now(), |tab, _| {
            assert_eq!(tab, crate::models::Tab::Settings);
            Ok(spawn_test_child("exec sleep 30"))
        });
        assert!(!supervisor.resume_monitor_after_settings);
        assert!(supervisor.settings_child.is_some());

        let _ = supervisor.settings_child.as_mut().unwrap().kill();
        wait_for_test_child_exit(&mut supervisor);
        supervisor.poll_settings_window_with_loader(|_| StartupConfig {
            config: AppConfig::default(),
            storage_recovery_ready: true,
        });

        match worker_rx.try_recv().unwrap() {
            WorkerCommand::ApplyConfigAndReleasePause { start_monitor, .. } => {
                assert!(!start_monitor);
            }
            other => panic!("expected stopped config apply, got {other:?}"),
        }
        assert!(worker_rx.try_recv().is_err());
        assert!(!supervisor.desired_monitor_running);
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    #[test]
    fn stop_ipc_is_committed_before_immediately_exited_settings_child_is_reaped() {
        use super::single_instance::{LocalIpcCommand, MonitorControlCommand};

        let (worker_tx, mut worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (tray_tx, tray_rx) = std_channel();
        let mut supervisor = LightweightSupervisor::new(
            worker_tx,
            worker_event_rx,
            tray_tx,
            tray_rx,
            WorkerInvalidator::new(),
            AppConfig::default(),
            None,
        );
        supervisor.accessibility_trusted = true;
        supervisor.worker_status = crate::models::WorkerStatus::Running;
        supervisor.desired_monitor_running = true;
        supervisor.resume_monitor_after_settings = true;
        supervisor.settings_child = Some(spawn_test_child("exit 0"));

        assert!(
            supervisor.handle_authorized_local_ipc_command(LocalIpcCommand::Monitor(
                MonitorControlCommand::Stop,
            ))
        );

        assert!(!supervisor.desired_monitor_running);
        assert!(!supervisor.resume_monitor_after_settings);
        assert!(supervisor.worker_pause_latch.is_paused());
        assert!(matches!(worker_rx.try_recv(), Ok(WorkerCommand::Stop)));

        wait_for_test_child_exit(&mut supervisor);
        supervisor.poll_settings_window_with_loader(|_| StartupConfig {
            config: AppConfig::default(),
            storage_recovery_ready: true,
        });

        assert!(supervisor.settings_child.is_none());
        assert!(!supervisor.desired_monitor_running);
        assert!(!supervisor.resume_monitor_after_settings);
        match worker_rx.try_recv().unwrap() {
            WorkerCommand::ApplyConfigAndReleasePause { start_monitor, .. } => {
                assert!(!start_monitor);
            }
            other => panic!("expected stopped config apply, got {other:?}"),
        }
        assert!(worker_rx.try_recv().is_err());
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    #[test]
    fn storage_block_ipc_is_sticky_after_immediately_exited_settings_child_is_reaped() {
        use super::single_instance::{LocalIpcCommand, MonitorControlCommand};

        let (worker_tx, mut worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (tray_tx, tray_rx) = std_channel();
        let mut supervisor = LightweightSupervisor::new(
            worker_tx,
            worker_event_rx,
            tray_tx,
            tray_rx,
            WorkerInvalidator::new(),
            AppConfig::default(),
            None,
        );
        supervisor.accessibility_trusted = true;
        supervisor.worker_status = crate::models::WorkerStatus::Running;
        supervisor.desired_monitor_running = true;
        supervisor.resume_monitor_after_settings = true;
        supervisor.settings_child = Some(spawn_test_child("exit 0"));

        assert!(
            supervisor.handle_authorized_local_ipc_command(LocalIpcCommand::Monitor(
                MonitorControlCommand::StorageRecoveryBlocked,
            ))
        );

        assert!(!supervisor.storage_recovery_ready);
        assert!(supervisor.storage_recovery_sticky_blocked);
        assert!(!supervisor.desired_monitor_running);
        assert!(!supervisor.resume_monitor_after_settings);
        assert!(supervisor.worker_pause_latch.is_paused());
        assert!(matches!(worker_rx.try_recv(), Ok(WorkerCommand::Stop)));

        wait_for_test_child_exit(&mut supervisor);
        supervisor.poll_settings_window_with_loader(|_| {
            panic!("a process-sticky storage block must not run recovery after child exit")
        });

        assert!(supervisor.settings_child.is_none());
        assert!(!supervisor.storage_recovery_ready);
        assert!(supervisor.storage_recovery_sticky_blocked);
        assert!(!supervisor.desired_monitor_running);
        assert!(!supervisor.resume_monitor_after_settings);
        assert!(supervisor.worker_pause_latch.is_paused());
        assert!(worker_rx.try_recv().is_err());
    }

    #[test]
    fn sticky_storage_recovery_block_rejects_retry_and_every_start() {
        let (worker_tx, mut worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (tray_tx, tray_rx) = std_channel();
        let pause_latch = WorkerInvalidator::new().pause_latch();
        let mut supervisor = LightweightSupervisor::new(
            worker_tx,
            worker_event_rx,
            tray_tx,
            tray_rx,
            WorkerInvalidator::new(),
            AppConfig::default(),
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            None,
        )
        .with_worker_pause_latch(pause_latch.clone());
        supervisor.accessibility_trusted = true;
        supervisor.worker_status = crate::models::WorkerStatus::Running;

        supervisor.block_storage_recovery_until_restart();

        assert!(supervisor.storage_recovery_sticky_blocked);
        assert!(!supervisor.storage_recovery_ready);
        assert!(!supervisor.desired_monitor_running);
        assert!(pause_latch.is_paused());
        assert!(matches!(worker_rx.try_recv(), Ok(WorkerCommand::Stop)));

        supervisor.start_monitor_if_ready();
        assert!(!supervisor.reload_config_after_settings_with_loader(|| {
            panic!("sticky recovery must not be retried in the same supervisor")
        }));
        supervisor.retry_blocked_storage_recovery();

        assert!(worker_rx.try_recv().is_err());
        assert!(pause_latch.is_paused());
        assert!(!supervisor.desired_monitor_running);
    }

    #[test]
    fn accessibility_grant_starts_idle_monitor_or_defers_until_settings_close() {
        for settings_child_open in [false, true] {
            let (worker_tx, mut worker_rx) = tokio_channel(8);
            let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
            let (tray_tx, tray_rx) = std_channel();
            let mut supervisor = LightweightSupervisor::new(
                worker_tx,
                worker_event_rx,
                tray_tx,
                tray_rx,
                WorkerInvalidator::new(),
                AppConfig::default(),
                #[cfg(any(target_os = "macos", target_os = "windows"))]
                None,
            );
            supervisor.accessibility_trusted = false;
            supervisor.worker_status = crate::models::WorkerStatus::Idle;
            if settings_child_open {
                supervisor.settings_child = Some(spawn_test_child("sleep 1"));
            }

            supervisor.apply_accessibility_trust_state(true);

            assert!(supervisor.accessibility_trusted);
            if settings_child_open {
                assert!(supervisor.resume_monitor_after_settings);
                assert!(worker_rx.try_recv().is_err());
            } else {
                assert!(!supervisor.resume_monitor_after_settings);
                match worker_rx.try_recv().unwrap() {
                    WorkerCommand::Start => {}
                    other => panic!("expected Start, got {other:?}"),
                }
            }
            if let Some(mut child) = supervisor.settings_child.take() {
                let _ = child.kill();
            }
        }
    }

    #[test]
    fn accessibility_start_check_updates_trust_without_implicit_start() {
        let (worker_tx, mut worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (tray_tx, tray_rx) = std_channel();
        let mut supervisor = LightweightSupervisor::new(
            worker_tx,
            worker_event_rx,
            tray_tx,
            tray_rx,
            WorkerInvalidator::new(),
            AppConfig::default(),
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            None,
        );
        supervisor.accessibility_trusted = false;
        supervisor.worker_status = crate::models::WorkerStatus::Idle;

        supervisor.apply_accessibility_trust_state_with_grant_start(true, false);

        assert!(supervisor.accessibility_trusted);
        assert!(worker_rx.try_recv().is_err());
    }

    #[test]
    fn accessibility_loss_stops_running_monitor() {
        let (worker_tx, mut worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (tray_tx, tray_rx) = std_channel();
        let mut supervisor = LightweightSupervisor::new(
            worker_tx,
            worker_event_rx,
            tray_tx,
            tray_rx,
            WorkerInvalidator::new(),
            AppConfig::default(),
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            None,
        );
        supervisor.accessibility_trusted = true;
        supervisor.worker_status = crate::models::WorkerStatus::Running;

        supervisor.apply_accessibility_trust_state(false);

        assert!(!supervisor.accessibility_trusted);
        match worker_rx.try_recv().unwrap() {
            WorkerCommand::Stop => {}
            other => panic!("expected Stop, got {other:?}"),
        }
    }

    #[test]
    fn exit_request_terminates_settings_child_and_stops_worker() {
        let (worker_tx, mut worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (tray_tx, tray_rx) = std_channel();
        let mut supervisor = LightweightSupervisor::new(
            worker_tx,
            worker_event_rx,
            tray_tx,
            tray_rx,
            WorkerInvalidator::new(),
            AppConfig::default(),
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            None,
        );
        supervisor.worker_status = crate::models::WorkerStatus::Running;
        supervisor.resume_monitor_after_settings = true;
        let child = spawn_test_child("exec sleep 30");
        #[cfg(unix)]
        let child_pid = child.id();
        supervisor.settings_child = Some(child);

        supervisor.handle_exit_request();

        assert!(supervisor.exit_requested);
        assert!(supervisor.settings_child.is_none());
        assert!(!supervisor.resume_monitor_after_settings);
        match worker_rx.try_recv().unwrap() {
            WorkerCommand::Stop => {}
            other => panic!("expected Stop, got {other:?}"),
        }
        #[cfg(unix)]
        {
            let still_running = process_is_running(child_pid);
            if still_running {
                unsafe {
                    libc::kill(child_pid as libc::pid_t, libc::SIGKILL);
                }
            }
            assert!(!still_running);
        }

        supervisor.handle_exit_request();
        assert!(worker_rx.try_recv().is_err());
    }

    #[test]
    fn exit_request_publishes_idle_status_before_worker_ack() {
        let (worker_tx, mut worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (tray_tx, tray_rx) = std_channel();
        let mut supervisor = LightweightSupervisor::new(
            worker_tx,
            worker_event_rx,
            tray_tx,
            tray_rx,
            WorkerInvalidator::new(),
            AppConfig::default(),
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            None,
        );
        supervisor.worker_status = crate::models::WorkerStatus::Running;
        let mut published_statuses = Vec::new();

        supervisor.handle_exit_request_with_monitor_status_writer(|running| {
            published_statuses.push(running);
            Ok(())
        });

        assert_eq!(published_statuses, vec![false]);
        assert_eq!(supervisor.worker_status, crate::models::WorkerStatus::Idle);
        match worker_rx.try_recv().unwrap() {
            WorkerCommand::Stop => {}
            other => panic!("expected Stop, got {other:?}"),
        }
    }

    #[test]
    fn explicit_toggle_starts_when_accessibility_is_trusted() {
        let (worker_tx, mut worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (tray_tx, tray_rx) = std_channel();
        let mut supervisor = LightweightSupervisor::new(
            worker_tx,
            worker_event_rx,
            tray_tx,
            tray_rx,
            WorkerInvalidator::new(),
            AppConfig::default(),
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            None,
        );
        supervisor.accessibility_trusted = true;
        supervisor.worker_status = crate::models::WorkerStatus::Idle;
        supervisor.desired_monitor_running = false;

        supervisor.toggle_monitor();

        match worker_rx.try_recv().unwrap() {
            WorkerCommand::Start => {}
            other => panic!("expected Start, got {other:?}"),
        }
    }

    #[test]
    fn tray_label_and_toggle_share_one_monitor_control_state() {
        assert_eq!(
            MonitorControlState::from_worker_and_intent(
                crate::models::WorkerStatus::Running,
                false,
            ),
            MonitorControlState::Running
        );
        assert!(MonitorControlState::Running.toggle_requests_stop());

        assert_eq!(
            MonitorControlState::from_worker_and_intent(crate::models::WorkerStatus::Idle, true,),
            MonitorControlState::PausedWithStartIntent
        );
        assert!(MonitorControlState::PausedWithStartIntent.toggle_requests_stop());

        assert_eq!(
            MonitorControlState::from_worker_and_intent(crate::models::WorkerStatus::Idle, false,),
            MonitorControlState::Stopped
        );
        assert!(!MonitorControlState::Stopped.toggle_requests_stop());
    }

    #[test]
    fn development_full_ui_launcher_uses_supervised_activation() {
        let launcher = include_str!("../script/build_and_run.sh");

        assert!(!launcher.contains("--args --full-ui"));
        assert!(launcher.contains("wait_for_monitor_status\n  /usr/bin/open -n \"$BUNDLE_DIR\""));
        assert_eq!(
            launcher.matches("/usr/bin/open -n \"$BUNDLE_DIR\"").count(),
            2
        );
        assert!(launcher.contains("target/debug/$BINARY_NAME"));
        assert!(launcher.contains("cargo build --features dev-tools --bin \"$BINARY_NAME\""));
        assert!(!launcher.contains("cargo build --release --features dev-tools"));
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    #[test]
    fn monitor_start_ipc_from_settings_child_defers_reload_and_start_until_close() {
        let (worker_tx, mut worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (tray_tx, tray_rx) = std_channel();
        let mut supervisor = LightweightSupervisor::new(
            worker_tx,
            worker_event_rx,
            tray_tx,
            tray_rx,
            WorkerInvalidator::new(),
            AppConfig::default(),
            None,
        );
        supervisor.accessibility_trusted = true;
        supervisor.worker_status = crate::models::WorkerStatus::Idle;
        supervisor.resume_monitor_after_settings = true;
        supervisor.settings_child = Some(spawn_test_child("sleep 1"));

        let original = supervisor.config.clone();
        supervisor.start_monitor_from_control_command_with_loader(|| {
            panic!("live settings transactions must not be loaded or recovered")
        });

        assert_eq!(supervisor.config, original);
        assert!(worker_rx.try_recv().is_err());
        assert!(supervisor.resume_monitor_after_settings);
        assert!(supervisor.settings_child.is_some());
        let _ = supervisor.settings_child.take().unwrap().kill();
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    #[test]
    fn reload_ipc_from_settings_child_never_consumes_a_live_transaction_journal() {
        let (worker_tx, mut worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (tray_tx, tray_rx) = std_channel();
        let mut supervisor = LightweightSupervisor::new(
            worker_tx,
            worker_event_rx,
            tray_tx,
            tray_rx,
            WorkerInvalidator::new(),
            AppConfig::default(),
            None,
        );
        supervisor.settings_child = Some(spawn_test_child("sleep 1"));

        assert!(!supervisor.reload_config_after_settings_with_loader(|| {
            panic!("live settings transactions must not be loaded or recovered")
        }));

        assert!(worker_rx.try_recv().is_err());
        assert!(supervisor.settings_child.is_some());
        let _ = supervisor.settings_child.take().unwrap().kill();
    }

    #[test]
    fn deferred_toggle_reloads_config_before_starting_after_settings_exit() {
        let (worker_tx, mut worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (tray_tx, tray_rx) = std_channel();
        let mut supervisor = LightweightSupervisor::new(
            worker_tx,
            worker_event_rx,
            tray_tx,
            tray_rx,
            WorkerInvalidator::new(),
            AppConfig::default(),
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            None,
        );
        supervisor.accessibility_trusted = true;
        supervisor.worker_status = crate::models::WorkerStatus::Idle;
        supervisor.desired_monitor_running = false;
        supervisor.settings_child = Some(spawn_test_child("exit 0"));

        supervisor.toggle_monitor();
        assert!(supervisor.resume_monitor_after_settings);
        assert!(worker_rx.try_recv().is_err());

        let mut recovered = AppConfig::default();
        recovered.settings.use_keyring = false;
        let mut account = Account::new("user@example.com");
        account.id = "account-1".to_string();
        account.has_saved_password = true;
        recovered.accounts.push(account);
        let expected = recovered.clone();
        wait_for_test_child_exit(&mut supervisor);

        supervisor.poll_settings_window_with_loader(|_| StartupConfig {
            config: recovered,
            storage_recovery_ready: true,
        });

        assert_eq!(supervisor.config, expected);
        match worker_rx.try_recv().unwrap() {
            WorkerCommand::ApplyConfigAndReleasePause {
                settings,
                accounts,
                refresh_passwords,
                start_monitor,
                pause_epoch: _,
            } => {
                assert_eq!(settings, expected.settings);
                assert_eq!(accounts, expected.accounts);
                assert!(refresh_passwords);
                assert!(start_monitor);
            }
            other => panic!("expected ApplyConfigAndReleasePause, got {other:?}"),
        }
        assert!(worker_rx.try_recv().is_err());
        assert!(!supervisor.resume_monitor_after_settings);
    }

    #[test]
    fn newer_pause_keeps_queued_reload_from_releasing_or_starting_worker() {
        let (worker_tx, mut worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (tray_tx, tray_rx) = std_channel();
        let invalidator = WorkerInvalidator::new();
        let pause_latch = invalidator.pause_latch();
        let mut supervisor = LightweightSupervisor::new(
            worker_tx,
            worker_event_rx,
            tray_tx,
            tray_rx,
            invalidator,
            AppConfig::default(),
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            None,
        )
        .with_worker_pause_latch(pause_latch.clone());

        assert!(
            supervisor.reload_config_after_settings_with_loader_and_start(
                || StartupConfig {
                    config: AppConfig::default(),
                    storage_recovery_ready: true,
                },
                true,
            )
        );
        let queued = worker_rx.try_recv().unwrap();
        pause_latch.pause();

        let WorkerCommand::ApplyConfigAndReleasePause {
            pause_epoch,
            start_monitor,
            ..
        } = queued
        else {
            panic!("expected queued config release");
        };
        assert!(start_monitor);
        assert_ne!(pause_epoch, pause_latch.current_epoch());
        assert!(pause_latch.is_paused());
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    #[test]
    fn exited_settings_child_handle_rejects_bootstrap_even_if_its_pid_is_reused() {
        use super::single_instance::LocalIpcCommand;
        use std::time::Duration;

        let (worker_tx, _worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (tray_tx, tray_rx) = std_channel();
        let mut supervisor = LightweightSupervisor::new(
            worker_tx,
            worker_event_rx,
            tray_tx,
            tray_rx,
            WorkerInvalidator::new(),
            AppConfig::default(),
            None,
        );
        let child = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("exit 0")
            .spawn()
            .unwrap();
        let stale_child_pid = child.id();
        supervisor.settings_child = Some(child);

        let mut authorized_pid = Some(stale_child_pid);
        for _ in 0..50 {
            authorized_pid = supervisor.settings_child_pid_for_local_ipc();
            if authorized_pid.is_none() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        assert!(supervisor.settings_child.is_some());
        assert_eq!(authorized_pid, None);
        assert!(!supervisor.acknowledge_settings_bootstrap_with(stale_child_pid, || Ok(())));
        assert!(!supervisor.settings_child_bootstrapped);
        assert!(!super::local_ipc_command_authorized(
            LocalIpcCommand::ReloadConfig,
            stale_child_pid,
            authorized_pid,
            true,
        ));
    }

    #[cfg(unix)]
    fn spawn_test_child(command: &str) -> std::process::Child {
        std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(command)
            .spawn()
            .unwrap()
    }

    #[cfg(windows)]
    fn spawn_test_child(command: &str) -> std::process::Child {
        use std::os::windows::process::CommandExt;

        const CREATE_NO_WINDOW: u32 = 0x0800_0000;

        let (program, args): (&str, &[&str]) = match command {
            "exit 0" => ("cmd.exe", &["/C", "exit 0"]),
            "sleep 1" => ("timeout.exe", &["/T", "1", "/NOBREAK"]),
            "exec sleep 30" => ("timeout.exe", &["/T", "30", "/NOBREAK"]),
            other => panic!("unsupported Windows test child command: {other}"),
        };
        std::process::Command::new(program)
            .args(args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .unwrap()
    }

    fn wait_for_test_child_exit(supervisor: &mut LightweightSupervisor) {
        for _ in 0..50 {
            if supervisor
                .settings_child
                .as_mut()
                .is_some_and(|child| matches!(child.try_wait(), Ok(Some(_))))
            {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    #[cfg(unix)]
    fn process_is_running(pid: u32) -> bool {
        unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
    }
}
