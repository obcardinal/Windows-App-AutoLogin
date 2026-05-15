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

#[cfg(target_os = "macos")]
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

    let config = load_startup_config();
    let settings = config.settings.clone();
    let accounts = config.accounts.clone();

    background::spawn(
        worker_rx,
        worker_event_tx,
        settings.clone(),
        accounts,
        worker_invalidator.clone(),
    );
    publish_initial_monitor_status(single_instance::write_monitor_status);
    start_monitor_on_launch_if_accessibility_trusted(&worker_tx);

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
    );
    event_loop.run_app(&mut supervisor)?;

    Ok(())
}

fn run_full_ui(initial_tab: models::Tab) -> anyhow::Result<()> {
    let _full_ui_instance = match single_instance::FullUiInstanceGuard::acquire() {
        Ok(guard) => guard,
        Err(e) => {
            eprintln!("{e}");
            return Ok(());
        }
    };

    let config = load_startup_config();
    let (worker_tx, _worker_rx) = tokio_channel::<background::WorkerCommand>(32);
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
                tray_rx,
                worker_event_rx,
                config,
                true,
                initial_tab,
            );
            Ok(Box::new(app))
        }),
    );

    result.map_err(|e| anyhow::anyhow!("EFrame error: {:?}", e))
}

fn load_startup_config() -> models::AppConfig {
    let _ = autostart::cleanup_stale();
    let mut config = load_config_with_storage_recovery();
    let auto_start_enabled = autostart::is_enabled();
    if config.settings.auto_start != auto_start_enabled {
        config.settings.auto_start = auto_start_enabled;
        let _ = storage::save_config(&config);
    }
    config
}

fn load_config_with_storage_recovery() -> models::AppConfig {
    let mut config = storage::load_config();
    if let Err(e) = storage::reconcile_pending_storage_operations(&mut config) {
        tracing::warn!(
            error = %e,
            "Pending password storage recovery could not be completed"
        );
    }
    config
}

fn start_monitor_on_launch_if_accessibility_trusted(
    worker_tx: &TokioSender<background::WorkerCommand>,
) {
    queue_monitor_start_if_accessibility_trusted(worker_tx, autologin::accessibility_is_trusted());
}

fn queue_monitor_start_if_accessibility_trusted(
    worker_tx: &TokioSender<background::WorkerCommand>,
    accessibility_trusted: bool,
) {
    if accessibility_trusted {
        let _ = worker_tx.try_send(background::WorkerCommand::Start);
    } else {
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
    }
}

fn publish_initial_monitor_status(
    mut write_monitor_status: impl FnMut(bool) -> anyhow::Result<()>,
) {
    if let Err(e) = write_monitor_status(false) {
        tracing::warn!("Could not clear stale monitor status during supervisor startup: {e}");
    }
}

struct LightweightSupervisor {
    worker_tx: TokioSender<background::WorkerCommand>,
    worker_event_rx: TokioReceiver<background::WorkerEvent>,
    tray_tx: StdSender<tray::TrayCommand>,
    tray_rx: StdReceiver<tray::TrayCommand>,
    worker_invalidator: background::WorkerInvalidator,
    tray: Option<tray::AppTray>,
    config: models::AppConfig,
    worker_status: models::WorkerStatus,
    accessibility_trusted: bool,
    last_accessibility_check: Instant,
    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    monitor_command_watcher: single_instance::MonitorCommandWatcher,
    settings_child: Option<Child>,
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
        Self {
            worker_tx,
            worker_event_rx,
            tray_tx,
            tray_rx,
            worker_invalidator,
            tray: None,
            config,
            worker_status: models::WorkerStatus::Idle,
            accessibility_trusted: autologin::accessibility_is_trusted(),
            last_accessibility_check: Instant::now(),
            #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
            monitor_command_watcher: single_instance::MonitorCommandWatcher::new(),
            settings_child: None,
            resume_monitor_after_settings: false,
            exit_requested: false,
            #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
            activation_watcher: single_instance::ActivationWatcher::new(),
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            ipc_server,
        }
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
        self.worker_invalidator.invalidate();
        self.worker_status = models::WorkerStatus::Idle;
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
                    if let Err(e) = debug_fill::write_last_fill_attempt_report(&report) {
                        tracing::warn!("Could not persist last fill attempt report: {e}");
                    }
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
        let settings_child_pid = self.settings_child_pid_for_local_ipc();
        let Some(ipc_server) = self.ipc_server.as_mut() else {
            return;
        };
        let commands = ipc_server.consume_commands();
        for peer_command in commands {
            if !local_ipc_command_authorized(
                peer_command.command,
                peer_command.peer_pid,
                settings_child_pid,
            ) {
                tracing::warn!(
                    peer_pid = peer_command.peer_pid,
                    "Rejected privileged local IPC command from unauthorized peer"
                );
                continue;
            }

            self.handle_authorized_local_ipc_command(peer_command.command);
        }
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    fn handle_authorized_local_ipc_command(&mut self, command: single_instance::LocalIpcCommand) {
        match command {
            single_instance::LocalIpcCommand::Activate => self.handle_activation_request(),
            single_instance::LocalIpcCommand::ReloadConfig => self.reload_config_after_settings(),
            single_instance::LocalIpcCommand::Monitor(command) => match command {
                single_instance::MonitorControlCommand::Start => {
                    self.start_monitor_from_control_command()
                }
                single_instance::MonitorControlCommand::Stop => self.stop_monitor(),
                #[cfg(target_os = "windows")]
                single_instance::MonitorControlCommand::ReloadConfig => {
                    self.reload_config_after_settings()
                }
            },
        }
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    fn handle_activation_request(&mut self) {
        self.poll_settings_window();
        if self.settings_child.is_none() {
            self.open_accounts_window_without_stopping_monitor();
        }
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    fn settings_child_pid_for_local_ipc(&mut self) -> Option<u32> {
        self.poll_settings_window();
        self.settings_child.as_ref().map(|child| child.id())
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
            if start_monitor_on_grant {
                self.start_monitor_after_accessibility_grant();
            }
        } else if self.worker_status == models::WorkerStatus::Running {
            self.worker_invalidator.invalidate();
            let _ = self.worker_tx.try_send(background::WorkerCommand::Stop);
        }
        self.update_tray_status();
    }

    fn toggle_monitor(&mut self) {
        match self.worker_status {
            models::WorkerStatus::Running => self.stop_monitor(),
            models::WorkerStatus::Idle => self.start_monitor_if_ready(),
        }
    }

    fn accessibility_ready_for_start(&mut self) -> bool {
        if !self.accessibility_trusted {
            self.refresh_accessibility_trust_state_for_start();
        }
        self.accessibility_trusted
    }

    fn start_monitor_if_ready(&mut self) {
        if !self.accessibility_ready_for_start() {
            tracing::warn!("Automation permission is required before starting monitor");
            return;
        }
        if self.worker_status != models::WorkerStatus::Idle {
            return;
        }
        if self.settings_child.is_some() {
            self.resume_monitor_after_settings = true;
            return;
        }

        let _ = self.worker_tx.try_send(background::WorkerCommand::Start);
    }

    fn start_monitor_after_accessibility_grant(&mut self) {
        if self.worker_status != models::WorkerStatus::Idle {
            return;
        }
        let _ = self.worker_tx.try_send(background::WorkerCommand::Start);
    }

    fn start_monitor_from_control_command(&mut self) {
        self.start_monitor_from_control_command_with_loader(load_config_with_storage_recovery);
    }

    fn start_monitor_from_control_command_with_loader(
        &mut self,
        load_config: impl FnOnce() -> models::AppConfig,
    ) {
        if !self.accessibility_ready_for_start() {
            tracing::warn!("Automation permission is required before starting monitor");
            return;
        }
        self.resume_monitor_after_settings = false;
        if self.settings_child.is_some()
            && !self.reload_config_after_settings_with_loader(load_config)
        {
            tracing::warn!(
                "Monitor left stopped because saved settings could not be delivered before start"
            );
            return;
        }
        if self.worker_status == models::WorkerStatus::Idle {
            let _ = self.worker_tx.try_send(background::WorkerCommand::Start);
        }
    }

    fn stop_monitor(&mut self) {
        self.resume_monitor_after_settings = false;
        self.worker_invalidator.invalidate();
        if self.worker_status == models::WorkerStatus::Running {
            let _ = self.worker_tx.try_send(background::WorkerCommand::Stop);
        }
    }

    fn open_accounts_window(&mut self) {
        self.open_full_ui_window(models::Tab::Accounts);
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    fn open_accounts_window_without_stopping_monitor(&mut self) {
        self.open_full_ui_window_with_monitor_policy(models::Tab::Accounts, false);
    }

    fn open_settings_window(&mut self) {
        self.open_full_ui_window(models::Tab::Settings);
    }

    fn open_full_ui_window(&mut self, initial_tab: models::Tab) {
        self.open_full_ui_window_with_monitor_policy(initial_tab, false);
    }

    fn open_full_ui_window_with_monitor_policy(
        &mut self,
        initial_tab: models::Tab,
        pause_monitor: bool,
    ) {
        if self.settings_child.is_some() {
            return;
        }

        self.resume_monitor_after_settings =
            pause_monitor && self.worker_status == models::WorkerStatus::Running;
        if self.resume_monitor_after_settings {
            self.worker_invalidator.invalidate();
            let _ = self.worker_tx.try_send(background::WorkerCommand::Stop);
        }

        match spawn_full_ui_window(initial_tab, self.privileged_ipc_available()) {
            Ok(child) => {
                self.settings_child = Some(child);
            }
            Err(e) => {
                tracing::warn!("Could not open settings window: {e}");
                let should_resume = self.resume_monitor_after_settings;
                self.resume_monitor_after_settings = false;
                if should_resume {
                    self.start_monitor_if_ready();
                }
            }
        }
    }

    fn poll_settings_window(&mut self) {
        self.poll_settings_window_with_loader(load_config_with_storage_recovery);
    }

    fn close_settings_child_for_exit(&mut self) {
        self.resume_monitor_after_settings = false;
        let Some(mut child) = self.settings_child.take() else {
            return;
        };

        if child_has_exited(&mut child) {
            return;
        }

        terminate_child_process(&mut child, "settings window");
    }

    fn poll_settings_window_with_loader(
        &mut self,
        load_config: impl FnOnce() -> models::AppConfig,
    ) {
        let Some(child) = self.settings_child.as_mut() else {
            return;
        };

        match child.try_wait() {
            Ok(Some(_)) => {
                self.settings_child = None;
                let reload_succeeded = self.reload_config_after_settings_with_loader(load_config);
                if self.resume_monitor_after_settings {
                    self.resume_monitor_after_settings = false;
                    if reload_succeeded {
                        self.start_monitor_if_ready();
                    } else {
                        tracing::warn!(
                            "Monitor left stopped because settings reload could not be delivered safely"
                        );
                    }
                }
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!("Settings window status check failed: {e}");
                self.settings_child = None;
                self.resume_monitor_after_settings = false;
            }
        }
    }

    fn reload_config_after_settings(&mut self) {
        self.reload_config_after_settings_with_loader(load_config_with_storage_recovery);
    }

    fn reload_config_after_settings_with_loader(
        &mut self,
        load_config: impl FnOnce() -> models::AppConfig,
    ) -> bool {
        let next_config = load_config();
        self.worker_invalidator.invalidate();
        if let Err(e) = self
            .worker_tx
            .try_send(background::WorkerCommand::ApplyConfig {
                settings: next_config.settings.clone(),
                accounts: next_config.accounts.clone(),
                refresh_passwords: true,
            })
        {
            self.resume_monitor_after_settings = false;
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
        self.update_tray_status();
        true
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
        tray.set_monitor_running(running);
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
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        self.process_local_ipc_commands();
        #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
        {
            self.process_monitor_commands();
            self.process_activation_requests();
        }
        self.poll_settings_window();
        self.poll_accessibility();
        event_loop.set_control_flow(ControlFlow::WaitUntil(Instant::now() + SUPERVISOR_TICK));
    }

    fn exiting(&mut self, _event_loop: &ActiveEventLoop) {
        self.handle_exit_request();
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn local_ipc_command_authorized(
    command: single_instance::LocalIpcCommand,
    peer_pid: u32,
    settings_child_pid: Option<u32>,
) -> bool {
    match command {
        single_instance::LocalIpcCommand::Activate => true,
        single_instance::LocalIpcCommand::ReloadConfig
        | single_instance::LocalIpcCommand::Monitor(_) => Some(peer_pid) == settings_child_pid,
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
) -> anyhow::Result<Child> {
    Ok(full_ui_command(
        std::env::current_exe()?,
        initial_tab,
        privileged_ipc_available,
    )
    .spawn()?)
}

fn full_ui_command(
    current_exe: impl AsRef<std::ffi::OsStr>,
    initial_tab: models::Tab,
    privileged_ipc_available: bool,
) -> Command {
    let mut command = Command::new(current_exe);
    command.arg("--full-ui").arg(initial_tab_arg(initial_tab));
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
        fill_result_label, full_ui_command, initial_tab_arg, publish_initial_monitor_status,
        std_channel, tokio_channel, LightweightSupervisor,
    };
    use crate::background::{WorkerCommand, WorkerInvalidator};
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

    #[cfg(target_os = "windows")]
    #[test]
    fn full_ui_command_removes_legacy_monitor_control_token_env() {
        let command = full_ui_command(
            "/tmp/windows-app-autologin",
            crate::models::Tab::Settings,
            false,
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

        super::queue_monitor_start_if_accessibility_trusted(&worker_tx, true);

        match worker_rx.try_recv().unwrap() {
            WorkerCommand::Start => {}
            other => panic!("expected Start, got {other:?}"),
        }
    }

    #[test]
    fn launch_init_leaves_monitor_idle_without_accessibility() {
        let (worker_tx, mut worker_rx) = tokio_channel(8);

        super::queue_monitor_start_if_accessibility_trusted(&worker_tx, false);

        assert!(worker_rx.try_recv().is_err());
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

        assert!(supervisor.reload_config_after_settings_with_loader(|| recovered));

        assert_eq!(supervisor.config, expected);
        match worker_rx.try_recv().unwrap() {
            WorkerCommand::ApplyConfig {
                settings,
                accounts,
                refresh_passwords,
            } => {
                assert_eq!(settings, expected.settings);
                assert_eq!(accounts, expected.accounts);
                assert!(refresh_passwords);
            }
            other => panic!("expected ApplyConfig, got {other:?}"),
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

        assert!(!supervisor.reload_config_after_settings_with_loader(|| recovered));
        assert_eq!(supervisor.config, original_config);
        assert!(!supervisor.resume_monitor_after_settings);
        assert_eq!(worker_rx.capacity(), 0);
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    #[test]
    fn local_ipc_authorization_requires_settings_child_for_privileged_commands() {
        use super::single_instance::{LocalIpcCommand, MonitorControlCommand};

        assert!(super::local_ipc_command_authorized(
            LocalIpcCommand::Activate,
            42,
            None
        ));
        assert!(!super::local_ipc_command_authorized(
            LocalIpcCommand::ReloadConfig,
            42,
            None
        ));
        assert!(!super::local_ipc_command_authorized(
            LocalIpcCommand::Monitor(MonitorControlCommand::Start),
            42,
            Some(7)
        ));
        assert!(super::local_ipc_command_authorized(
            LocalIpcCommand::Monitor(MonitorControlCommand::Stop),
            42,
            Some(42)
        ));
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    #[test]
    fn activate_ipc_does_not_stop_running_monitor() {
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

        supervisor.handle_authorized_local_ipc_command(LocalIpcCommand::Activate);

        assert!(worker_rx.try_recv().is_err());
        assert_eq!(
            supervisor.worker_status,
            crate::models::WorkerStatus::Running
        );
        assert!(!supervisor.resume_monitor_after_settings);
        assert!(supervisor.settings_child.is_some());
        let _ = supervisor.settings_child.take().unwrap().kill();
    }

    #[test]
    fn opening_settings_window_does_not_pause_running_monitor() {
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

        supervisor.open_settings_window();

        assert!(worker_rx.try_recv().is_err());
        assert_eq!(
            supervisor.worker_status,
            crate::models::WorkerStatus::Running
        );
        assert!(!supervisor.resume_monitor_after_settings);
        assert!(supervisor.settings_child.is_some());
        let _ = supervisor.settings_child.take().unwrap().kill();
    }

    #[test]
    fn accessibility_grant_starts_idle_monitor_immediately() {
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
            assert!(!supervisor.resume_monitor_after_settings);
            match worker_rx.try_recv().unwrap() {
                WorkerCommand::Start => {}
                other => panic!("expected Start, got {other:?}"),
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

        supervisor.toggle_monitor();

        match worker_rx.try_recv().unwrap() {
            WorkerCommand::Start => {}
            other => panic!("expected Start, got {other:?}"),
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn monitor_start_ipc_from_settings_child_reloads_config_before_start() {
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

        let mut recovered = AppConfig::default();
        recovered.settings.use_keyring = false;
        let mut account = Account::new("user@example.com");
        account.id = "account-1".to_string();
        account.has_saved_password = true;
        recovered.accounts.push(account);
        let expected = recovered.clone();

        supervisor.start_monitor_from_control_command_with_loader(|| recovered);

        assert_eq!(supervisor.config, expected);
        match worker_rx.try_recv().unwrap() {
            WorkerCommand::ApplyConfig {
                settings,
                accounts,
                refresh_passwords,
            } => {
                assert_eq!(settings, expected.settings);
                assert_eq!(accounts, expected.accounts);
                assert!(refresh_passwords);
            }
            other => panic!("expected ApplyConfig, got {other:?}"),
        }
        match worker_rx.try_recv().unwrap() {
            WorkerCommand::Start => {}
            other => panic!("expected Start, got {other:?}"),
        }
        assert!(!supervisor.resume_monitor_after_settings);
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

        supervisor.poll_settings_window_with_loader(|| recovered);

        assert_eq!(supervisor.config, expected);
        match worker_rx.try_recv().unwrap() {
            WorkerCommand::ApplyConfig {
                settings,
                accounts,
                refresh_passwords,
            } => {
                assert_eq!(settings, expected.settings);
                assert_eq!(accounts, expected.accounts);
                assert!(refresh_passwords);
            }
            other => panic!("expected ApplyConfig, got {other:?}"),
        }
        match worker_rx.try_recv().unwrap() {
            WorkerCommand::Start => {}
            other => panic!("expected Start, got {other:?}"),
        }
        assert!(worker_rx.try_recv().is_err());
        assert!(!supervisor.resume_monitor_after_settings);
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    #[test]
    fn exited_settings_child_is_cleared_before_ipc_authorization() {
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

        assert!(supervisor.settings_child.is_none());
        assert_eq!(authorized_pid, None);
        assert!(!super::local_ipc_command_authorized(
            LocalIpcCommand::ReloadConfig,
            stale_child_pid,
            authorized_pid
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
