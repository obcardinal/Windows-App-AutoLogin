mod app;
#[allow(dead_code)]
mod autologin;
mod autostart;
mod background;
mod config;
mod debug_fill;
mod macos_identity;
mod models;
mod monitor;
mod single_instance;
mod storage;
mod tray;
mod ui;

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

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.iter().any(|arg| arg == "--debug-fill-once") {
        return debug_fill::run_from_args(&args);
    }
    if args.iter().any(|arg| arg == "--full-ui") {
        return run_full_ui(initial_full_ui_tab(&args));
    }

    run_lightweight_supervisor()
}

fn run_lightweight_supervisor() -> anyhow::Result<()> {
    let _single_instance = match single_instance::SingleInstanceGuard::acquire() {
        Ok(guard) => guard,
        Err(e) => {
            eprintln!("{e}");
            return Ok(());
        }
    };

    let rt = Runtime::new()?;
    let _rt_guard = rt.enter();

    let (worker_tx, worker_rx) = tokio_channel::<background::WorkerCommand>(32);
    let (worker_event_tx, worker_event_rx) = tokio_channel::<background::WorkerEvent>(100);
    let (tray_tx, tray_rx) = std_channel::<tray::TrayCommand>();

    let config = load_startup_config();
    let settings = config.settings.clone();
    let accounts = config.accounts.clone();

    background::spawn(worker_rx, worker_event_tx, settings.clone(), accounts);
    if autologin::accessibility_is_trusted() {
        let _ = worker_tx.try_send(background::WorkerCommand::Start);
    }

    let event_loop = EventLoop::new()?;
    event_loop.set_control_flow(ControlFlow::Wait);
    let mut supervisor =
        LightweightSupervisor::new(worker_tx, worker_event_rx, tray_tx, tray_rx, config);
    event_loop.run_app(&mut supervisor)?;

    Ok(())
}

fn run_full_ui(initial_tab: models::Tab) -> anyhow::Result<()> {
    let config = storage::load_config();
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
    let mut config = storage::load_config();
    let auto_start_enabled = autostart::is_enabled();
    if config.settings.auto_start != auto_start_enabled {
        config.settings.auto_start = auto_start_enabled;
        let _ = storage::save_config(&config);
    }
    config
}

struct LightweightSupervisor {
    worker_tx: TokioSender<background::WorkerCommand>,
    worker_event_rx: TokioReceiver<background::WorkerEvent>,
    tray_tx: StdSender<tray::TrayCommand>,
    tray_rx: StdReceiver<tray::TrayCommand>,
    tray: Option<tray::AppTray>,
    config: models::AppConfig,
    worker_status: models::WorkerStatus,
    accessibility_trusted: bool,
    last_accessibility_check: Instant,
    settings_child: Option<Child>,
}

impl LightweightSupervisor {
    fn new(
        worker_tx: TokioSender<background::WorkerCommand>,
        worker_event_rx: TokioReceiver<background::WorkerEvent>,
        tray_tx: StdSender<tray::TrayCommand>,
        tray_rx: StdReceiver<tray::TrayCommand>,
        config: models::AppConfig,
    ) -> Self {
        Self {
            worker_tx,
            worker_event_rx,
            tray_tx,
            tray_rx,
            tray: None,
            config,
            worker_status: models::WorkerStatus::Idle,
            accessibility_trusted: autologin::accessibility_is_trusted(),
            last_accessibility_check: Instant::now(),
            settings_child: None,
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

    fn process_tray_commands(&mut self, event_loop: &ActiveEventLoop) {
        while let Ok(command) = self.tray_rx.try_recv() {
            match command {
                tray::TrayCommand::OpenAccounts => self.open_accounts_window(),
                tray::TrayCommand::OpenSettings => self.open_settings_window(),
                tray::TrayCommand::ToggleMonitor => self.toggle_monitor(),
                tray::TrayCommand::RequestAccessibilityAccess => {
                    let trusted = autologin::request_accessibility_access_prompt();
                    self.accessibility_trusted = trusted || autologin::accessibility_is_trusted();
                    self.start_monitor_if_ready();
                    self.update_tray_status();
                }
                tray::TrayCommand::OpenAccessibilitySettings => {
                    if let Err(e) = autologin::open_accessibility_settings() {
                        tracing::warn!("Could not open Accessibility settings: {e}");
                    }
                }
                tray::TrayCommand::Exit => {
                    let _ = self.worker_tx.try_send(background::WorkerCommand::Stop);
                    event_loop.exit();
                }
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

    fn poll_accessibility(&mut self) {
        if self.last_accessibility_check.elapsed() < Duration::from_secs(1) {
            return;
        }
        self.last_accessibility_check = Instant::now();
        let trusted = autologin::accessibility_is_trusted();
        if trusted != self.accessibility_trusted {
            self.accessibility_trusted = trusted;
            if trusted {
                self.start_monitor_if_ready();
            } else if self.worker_status == models::WorkerStatus::Running {
                let _ = self.worker_tx.try_send(background::WorkerCommand::Stop);
            }
            self.update_tray_status();
        }
    }

    fn toggle_monitor(&mut self) {
        match self.worker_status {
            models::WorkerStatus::Running => {
                let _ = self.worker_tx.try_send(background::WorkerCommand::Stop);
            }
            models::WorkerStatus::Idle => {
                if self.accessibility_trusted {
                    let _ = self.worker_tx.try_send(background::WorkerCommand::Start);
                } else {
                    tracing::warn!("Accessibility permission is required before starting monitor");
                }
            }
        }
    }

    fn start_monitor_if_ready(&self) {
        if self.accessibility_trusted && self.worker_status == models::WorkerStatus::Idle {
            let _ = self.worker_tx.try_send(background::WorkerCommand::Start);
        }
    }

    fn open_accounts_window(&mut self) {
        self.open_full_ui_window(models::Tab::Accounts);
    }

    fn open_settings_window(&mut self) {
        self.open_full_ui_window(models::Tab::Settings);
    }

    fn open_full_ui_window(&mut self, initial_tab: models::Tab) {
        if self.settings_child.is_some() {
            return;
        }

        match spawn_full_ui_window(initial_tab) {
            Ok(child) => {
                self.settings_child = Some(child);
            }
            Err(e) => {
                tracing::warn!("Could not open settings window: {e}");
            }
        }
    }

    fn poll_settings_window(&mut self) {
        let Some(child) = self.settings_child.as_mut() else {
            return;
        };

        match child.try_wait() {
            Ok(Some(_)) => {
                self.settings_child = None;
                self.reload_config_after_settings();
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!("Settings window status check failed: {e}");
                self.settings_child = None;
            }
        }
    }

    fn reload_config_after_settings(&mut self) {
        let next_config = storage::load_config();
        let _ = self
            .worker_tx
            .try_send(background::WorkerCommand::UpdateSettings(
                next_config.settings.clone(),
            ));
        let _ = self
            .worker_tx
            .try_send(background::WorkerCommand::UpdateAccounts(
                next_config.accounts.clone(),
            ));
        let _ = self
            .worker_tx
            .try_send(background::WorkerCommand::RefreshPasswords);
        self.config = next_config;
        self.update_tray_status();
    }

    fn update_tray_status(&self) {
        let Some(tray) = &self.tray else {
            return;
        };
        tray.set_accessibility_trusted(self.accessibility_trusted);
        tray.set_keychain_enabled(self.config.settings.use_keyring);
        tray.set_monitor_running(self.worker_status == models::WorkerStatus::Running);
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
        self.process_tray_commands(event_loop);
        self.process_worker_events();
        self.poll_accessibility();
        self.poll_settings_window();
        event_loop.set_control_flow(ControlFlow::WaitUntil(Instant::now() + SUPERVISOR_TICK));
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

fn spawn_full_ui_window(initial_tab: models::Tab) -> anyhow::Result<Child> {
    let status = autologin::accessibility_status();
    if !status.app_bundle_path.is_empty() {
        return Ok(Command::new("/usr/bin/open")
            .arg("-n")
            .arg("-W")
            .arg(status.app_bundle_path)
            .arg("--args")
            .arg("--full-ui")
            .arg(initial_tab_arg(initial_tab))
            .spawn()?);
    }

    Ok(Command::new(std::env::current_exe()?)
        .arg("--full-ui")
        .arg(initial_tab_arg(initial_tab))
        .spawn()?)
}

fn fill_result_label(report: &debug_fill::FillAttemptReport) -> String {
    match report.field("post_check_state").unwrap_or("unknown") {
        "authenticated" => "authenticated".to_string(),
        "still_prompt" => "still prompt".to_string(),
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
    use super::fill_result_label;
    use crate::debug_fill::FillAttemptReport;

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
    fn fill_result_label_prefers_authenticated_post_check() {
        let report = report(true, &[("post_check_state", "authenticated")], None);

        assert_eq!(fill_result_label(&report), "authenticated");
    }

    #[test]
    fn fill_result_label_caps_failure_reason_for_menu_display() {
        let report = report(
            false,
            &[("post_check_state", "unknown")],
            Some("very_long_failure_reason_that_should_not_expand_the_status_menu_forever"),
        );

        assert!(fill_result_label(&report).len() <= 48);
    }
}
