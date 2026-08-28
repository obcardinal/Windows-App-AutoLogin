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

pub(crate) mod app;
pub(crate) mod app_identity;
pub(crate) mod autologin;
pub(crate) mod autostart;
pub(crate) mod background;
pub(crate) mod config;
pub(crate) mod debug_fill;
#[cfg(target_os = "macos")]
pub(crate) mod macos_ax;
pub(crate) mod macos_identity;
pub(crate) mod models;
pub(crate) mod monitor;
pub(crate) mod private_permissions;
pub(crate) mod single_instance;
pub(crate) mod storage;
pub(crate) mod tray;
pub(crate) mod ui;
pub(crate) mod user_paths;
#[cfg(target_os = "windows")]
pub(crate) mod windows_ui;

#[cfg(any(target_os = "macos", target_os = "windows"))]
include!(concat!(env!("OUT_DIR"), "/waal_build_metadata.rs"));

use crate::models::MonitorControlState;
use anyhow::Context;
use eframe::egui;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{channel as std_channel, Receiver as StdReceiver, Sender as StdSender};
use std::time::{Duration, Instant};
use tokio::runtime::{Builder as TokioRuntimeBuilder, Runtime};
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
const FULL_UI_CONTROL_MAX_LINE_BYTES: usize = 32;
const FULL_UI_CONTROL_SHOW_ACCOUNTS: &[u8] = b"show:accounts\n";
const FULL_UI_CONTROL_SHOW_SETTINGS: &[u8] = b"show:settings\n";
const FULL_UI_CONTROL_EXIT: &[u8] = b"exit\n";
const FULL_UI_EXIT_CONFIRMATION_GRACE: Duration = Duration::from_secs(5);
const FULL_UI_GRACEFUL_EXIT_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(target_os = "macos")]
const LEGACY_IPC_TOKEN_ENV: &str = "WAAL_IPC_TOKEN";
#[cfg(target_os = "windows")]
const LEGACY_MONITOR_CONTROL_TOKEN_ENV: &str = "WAAL_MONITOR_CONTROL_TOKEN";

pub(crate) fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        // The supervised full UI reserves stdout exclusively for its bounded
        // presentation protocol. Keeping diagnostics on stderr prevents a log
        // line from being mistaken for a child acknowledgement.
        .with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = std::env::args().skip(1).collect::<Vec<_>>();
    #[cfg(target_os = "windows")]
    match app_identity::windows_binary_role()? {
        app_identity::WindowsBinaryRole::FullUi => {
            return run_windows_full_ui_binary(&args);
        }
        app_identity::WindowsBinaryRole::Supervisor => {
            if args.iter().any(|arg| arg == "--full-ui") {
                anyhow::bail!("the Windows UIAccess supervisor cannot run in full UI mode");
            }
        }
    }
    #[cfg(all(feature = "debug-fill", debug_assertions, not(waal_release_profile)))]
    if args.iter().any(|arg| arg == "--debug-fill-once") {
        return debug_fill::run_from_args(&args);
    }
    #[cfg(not(target_os = "windows"))]
    if args.iter().any(|arg| arg == "--full-ui") {
        return run_full_ui(initial_full_ui_tab(&args));
    }

    run_lightweight_supervisor()
}

#[cfg(target_os = "windows")]
fn run_windows_full_ui_binary(args: &[String]) -> anyhow::Result<()> {
    if args.len() != 2
        || args.first().map(String::as_str) != Some("--full-ui")
        || !windows_full_ui_initial_tab_arg_is_valid(&args[1])
    {
        anyhow::bail!("the Windows full UI helper requires an exact supervisor launch command");
    }
    run_full_ui(initial_full_ui_tab(args))
}

#[cfg(any(target_os = "windows", test))]
fn windows_full_ui_initial_tab_arg_is_valid(arg: &str) -> bool {
    matches!(arg, "--initial-tab=accounts" | "--initial-tab=settings")
        || cfg!(feature = "diagnostics-ui") && arg == "--initial-tab=diagnose"
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

    let rt = build_background_runtime()?;
    let _rt_guard = rt.enter();

    let (worker_tx, worker_rx) = tokio_channel::<background::WorkerCommand>(32);
    let (worker_event_tx, worker_event_rx) = tokio_channel::<background::WorkerEvent>(100);
    let (tray_tx, tray_rx) = std_channel::<tray::TrayCommand>();
    let worker_invalidator = background::WorkerInvalidator::new();
    let worker_pause_latch = worker_invalidator.pause_latch();
    let settings_session_token = single_instance::SettingsSessionToken::generate();

    let (startup, storage_recovery_sticky_blocked, startup_window_preference_known) =
        match load_startup_config_for_session(&settings_session_token) {
            Ok(Some(startup_load)) => {
                let sticky_blocked = !startup_load.startup.storage_recovery_ready;
                (
                    startup_load.startup,
                    sticky_blocked,
                    startup_load.window_preference_known,
                )
            }
            Ok(None) => {
                tracing::warn!(
                "Password storage recovery deferred while an existing settings session is active"
            );
                worker_pause_latch.pause();
                (blocked_startup_config(), false, false)
            }
            Err(error) => {
                tracing::error!(
                    %error,
                    "Password storage recovery could not be locked safely; monitor will remain stopped"
                );
                worker_pause_latch.pause();
                (blocked_startup_config(), false, false)
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
    supervisor.apply_startup_runtime_preferences(startup_window_preference_known);
    event_loop.run_app(&mut supervisor)?;

    Ok(())
}

const BACKGROUND_RUNTIME_WORKER_THREADS: usize = 1;

fn build_background_runtime() -> anyhow::Result<Runtime> {
    // AutoLogin owns one long-lived async monitor task. Its native AX work is
    // sequential and command handling is part of that same task, so the
    // machine-wide default worker count only creates idle threads (28 on the
    // current Mac) without adding concurrency or responsiveness.
    TokioRuntimeBuilder::new_multi_thread()
        .worker_threads(BACKGROUND_RUNTIME_WORKER_THREADS)
        .enable_time()
        .build()
        .context("unable to create the background monitor runtime")
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
    let (tray_tx, tray_rx) = std_channel::<tray::TrayCommand>();

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([640.0, 420.0])
            .with_min_inner_size([560.0, 360.0])
            .with_icon(load_icon()?)
            .with_visible(true)
            .with_active(true),
        renderer: full_ui_renderer(),
        ..Default::default()
    };

    let result = eframe::run_native(
        "Windows App AutoLogin",
        native_options,
        Box::new(move |cc| {
            ui::theme::apply(&cc.egui_ctx);
            spawn_full_ui_control_reader(tray_tx, cc.egui_ctx.clone())?;
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

fn full_ui_renderer() -> eframe::Renderer {
    #[cfg(target_os = "windows")]
    {
        // Clean Windows VMs commonly expose DirectX through the Microsoft
        // software adapter but no OpenGL 2.0 driver. WGPU can use that DX12
        // path, while Glow fails before the Accounts window is created.
        eframe::Renderer::Wgpu
    }

    #[cfg(not(target_os = "windows"))]
    {
        eframe::Renderer::Glow
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FullUiControlRead {
    EndOfStream,
    Invalid,
    Exit,
    Show(models::Tab),
}

fn full_ui_control_message(initial_tab: models::Tab) -> anyhow::Result<&'static [u8]> {
    match initial_tab {
        models::Tab::Accounts => Ok(FULL_UI_CONTROL_SHOW_ACCOUNTS),
        models::Tab::Settings => Ok(FULL_UI_CONTROL_SHOW_SETTINGS),
        #[cfg(feature = "diagnostics-ui")]
        models::Tab::Diagnose => {
            anyhow::bail!("the diagnostics tab is not available through full UI control")
        }
    }
}

fn parse_full_ui_control_line(line: &[u8]) -> FullUiControlRead {
    if line.len() > FULL_UI_CONTROL_MAX_LINE_BYTES {
        return FullUiControlRead::Invalid;
    }
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    match line {
        b"exit" => FullUiControlRead::Exit,
        b"show:accounts" => FullUiControlRead::Show(models::Tab::Accounts),
        b"show:settings" => FullUiControlRead::Show(models::Tab::Settings),
        _ => FullUiControlRead::Invalid,
    }
}

fn read_full_ui_control_command(reader: &mut impl BufRead) -> std::io::Result<FullUiControlRead> {
    let mut line = Vec::with_capacity(FULL_UI_CONTROL_MAX_LINE_BYTES);
    let mut overlong = false;
    let mut saw_input = false;

    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            if !saw_input {
                return Ok(FullUiControlRead::EndOfStream);
            }
            break;
        }
        saw_input = true;

        let newline = available.iter().position(|byte| *byte == b'\n');
        let payload_len = newline.unwrap_or(available.len());
        if !overlong {
            let remaining = FULL_UI_CONTROL_MAX_LINE_BYTES.saturating_sub(line.len());
            let copy_len = payload_len.min(remaining);
            line.extend_from_slice(&available[..copy_len]);
            if payload_len > remaining {
                overlong = true;
            }
        }

        let consumed = newline.map_or(available.len(), |position| position + 1);
        reader.consume(consumed);
        if newline.is_some() {
            break;
        }
    }

    if overlong {
        Ok(FullUiControlRead::Invalid)
    } else {
        Ok(parse_full_ui_control_line(&line))
    }
}

fn spawn_full_ui_control_reader(
    tray_tx: StdSender<tray::TrayCommand>,
    egui_ctx: egui::Context,
) -> std::io::Result<()> {
    std::thread::Builder::new()
        .name("full-ui-control".to_string())
        .spawn(move || {
            let stdin = std::io::stdin();
            let mut reader = BufReader::new(stdin.lock());
            let mut writer = std::io::stdout();
            loop {
                match read_full_ui_control_command(&mut reader) {
                    Ok(FullUiControlRead::Show(models::Tab::Accounts)) => {
                        if !dispatch_full_ui_presentation(
                            &tray_tx,
                            &egui_ctx,
                            models::Tab::Accounts,
                            &mut writer,
                        ) {
                            break;
                        }
                    }
                    Ok(FullUiControlRead::Show(models::Tab::Settings)) => {
                        if !dispatch_full_ui_presentation(
                            &tray_tx,
                            &egui_ctx,
                            models::Tab::Settings,
                            &mut writer,
                        ) {
                            break;
                        }
                    }
                    Ok(FullUiControlRead::Exit) => {
                        let _ = dispatch_full_ui_exit(&tray_tx, &egui_ctx);
                        break;
                    }
                    #[cfg(feature = "diagnostics-ui")]
                    Ok(FullUiControlRead::Show(models::Tab::Diagnose)) => {
                        tracing::warn!("Rejected unsupported full UI control tab");
                    }
                    Ok(FullUiControlRead::Invalid) => {
                        tracing::warn!("Rejected invalid full UI control command");
                    }
                    Ok(FullUiControlRead::EndOfStream) => break,
                    Err(error) => {
                        tracing::warn!(%error, "Full UI control channel failed");
                        break;
                    }
                }
            }
        })?;
    Ok(())
}

fn dispatch_full_ui_exit(tray_tx: &StdSender<tray::TrayCommand>, egui_ctx: &egui::Context) -> bool {
    if tray_tx.send(tray::TrayCommand::Exit).is_err() {
        return false;
    }
    egui_ctx.request_repaint();
    true
}

fn dispatch_full_ui_presentation(
    tray_tx: &StdSender<tray::TrayCommand>,
    egui_ctx: &egui::Context,
    tab: models::Tab,
    writer: &mut impl Write,
) -> bool {
    let (acknowledgement_tx, acknowledgement_rx) = std_channel();
    let command = match tab {
        models::Tab::Accounts => tray::TrayCommand::PresentAccounts(acknowledgement_tx),
        models::Tab::Settings => tray::TrayCommand::PresentSettings(acknowledgement_tx),
        #[cfg(feature = "diagnostics-ui")]
        models::Tab::Diagnose => return false,
    };
    if tray_tx.send(command).is_err() {
        return false;
    }
    egui_ctx.request_repaint();

    // A Keychain operation or system prompt can legitimately keep the UI
    // thread busy for an arbitrary amount of time. The control reader is not
    // the process owner, so it must never turn that delay into a process exit.
    if acknowledgement_rx.recv().is_err() {
        return false;
    }

    let Ok(response) = full_ui_control_message(tab) else {
        return false;
    };
    if writer
        .write_all(response)
        .and_then(|()| writer.flush())
        .is_err()
    {
        tracing::warn!("Full UI presentation acknowledgement channel failed");
        return false;
    }
    true
}

fn send_full_ui_presentation(child: &mut Child, tab: models::Tab) -> anyhow::Result<()> {
    let message = full_ui_control_message(tab)?;
    let stdin = child
        .stdin
        .as_mut()
        .ok_or_else(|| anyhow::anyhow!("full UI control channel is unavailable"))?;
    stdin.write_all(message)?;
    stdin.flush()?;
    Ok(())
}

fn send_full_ui_exit(child: &mut Child) -> anyhow::Result<()> {
    let stdin = child
        .stdin
        .as_mut()
        .ok_or_else(|| anyhow::anyhow!("full UI control channel is unavailable"))?;
    stdin.write_all(FULL_UI_CONTROL_EXIT)?;
    stdin.flush()?;
    Ok(())
}

fn spawn_full_ui_ack_reader(
    child: &mut Child,
) -> anyhow::Result<StdReceiver<std::io::Result<FullUiControlRead>>> {
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("full UI acknowledgement channel is unavailable"))?;
    let (result_tx, result_rx) = std_channel();
    std::thread::Builder::new()
        .name("full-ui-ack".to_string())
        .spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let response = read_full_ui_control_command(&mut reader);
                let finished = matches!(response, Ok(FullUiControlRead::EndOfStream) | Err(_));
                if result_tx.send(response).is_err() || finished {
                    break;
                }
            }
        })?;
    Ok(result_rx)
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

struct StartupConfigLoad {
    startup: StartupConfig,
    window_preference_known: bool,
}

fn load_startup_config() -> StartupConfigLoad {
    let _ = autostart::cleanup_stale();
    let mut startup_load =
        load_config_with_storage_recovery_inner_with_loader(true, storage::load_config);
    sync_startup_auto_start_with(
        &mut startup_load.startup,
        autostart::is_enabled(),
        storage::save_config,
    );
    startup_load
}

fn sync_startup_auto_start_with(
    startup: &mut StartupConfig,
    auto_start_enabled: bool,
    save_config: impl FnOnce(&models::AppConfig) -> anyhow::Result<()>,
) {
    // A default config produced for a blocked startup is an in-memory safety
    // value, never a replacement for config that could not be loaded. Do not
    // let the startup auto-start reconciliation persist it over that file.
    if !startup.storage_recovery_ready || startup.config.settings.auto_start == auto_start_enabled {
        return;
    }
    startup.config.settings.auto_start = auto_start_enabled;
    if let Err(error) = save_config(&startup.config) {
        tracing::warn!(%error, "Could not persist the current auto-start state");
    }
}

fn load_full_ui_config() -> StartupConfig {
    let mut config = match storage::load_config() {
        Ok(config) => config,
        Err(error) => {
            tracing::error!(%error, "Config could not be loaded safely; settings remain blocked");
            return blocked_startup_config();
        }
    };
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
) -> anyhow::Result<Option<StartupConfigLoad>> {
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
    load_config_with_storage_recovery_inner_with_loader(clear_startup_block, storage::load_config)
        .startup
}

fn load_config_with_storage_recovery_inner_with_loader<L>(
    clear_startup_block: bool,
    load_config: L,
) -> StartupConfigLoad
where
    L: FnOnce() -> anyhow::Result<models::AppConfig>,
{
    let mut config = match load_config() {
        Ok(config) => config,
        Err(error) => {
            tracing::error!(%error, "Config could not be loaded safely; password storage recovery remains blocked");
            return StartupConfigLoad {
                startup: blocked_startup_config(),
                window_preference_known: false,
            };
        }
    };
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
        return StartupConfigLoad {
            startup: StartupConfig {
                config,
                storage_recovery_ready: false,
            },
            window_preference_known: true,
        };
    }
    StartupConfigLoad {
        startup: StartupConfig {
            config,
            storage_recovery_ready,
        },
        window_preference_known: true,
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
struct PendingSettingsPresentation {
    in_flight_tab: models::Tab,
    requested_tab: models::Tab,
    phase: SettingsPresentationPhase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SettingsPresentationPhase {
    AwaitingAcknowledgement,
    AwaitingConfirmedExit { deadline: Instant },
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
    startup_window_preference_pending: bool,
    worker_status: models::WorkerStatus,
    desired_monitor_running: bool,
    accessibility_trusted: bool,
    last_accessibility_check: Instant,
    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    monitor_command_watcher: single_instance::MonitorCommandWatcher,
    settings_child: Option<Child>,
    settings_child_acknowledgements: Option<StdReceiver<std::io::Result<FullUiControlRead>>>,
    settings_child_control_broken: bool,
    pending_settings_presentation: Option<PendingSettingsPresentation>,
    settings_child_bootstrapped: bool,
    settings_mutation_active: bool,
    pending_settings_launch: Option<PendingSettingsLaunch>,
    next_settings_launch_request_id: u64,
    settings_session_token: single_instance::SettingsSessionToken,
    settings_session_lease: Option<single_instance::SettingsSessionLease>,
    #[cfg(test)]
    settings_lock_root: std::path::PathBuf,
    #[cfg(test)]
    last_published_monitor_control_state: std::cell::Cell<Option<MonitorControlState>>,
    last_storage_recovery_attempt: Instant,
    resume_monitor_after_settings: bool,
    exit_requested: bool,
    settings_child_exit_deadline: Option<Instant>,
    exit_shutdown_finalized: bool,
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
            startup_window_preference_pending: false,
            worker_status: models::WorkerStatus::Idle,
            desired_monitor_running: true,
            accessibility_trusted: autologin::accessibility_is_trusted(),
            last_accessibility_check: Instant::now(),
            #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
            monitor_command_watcher: single_instance::MonitorCommandWatcher::new(),
            settings_child: None,
            settings_child_acknowledgements: None,
            settings_child_control_broken: false,
            pending_settings_presentation: None,
            settings_child_bootstrapped: false,
            settings_mutation_active: false,
            pending_settings_launch: None,
            next_settings_launch_request_id: 0,
            settings_session_token: single_instance::SettingsSessionToken::generate(),
            settings_session_lease: None,
            #[cfg(test)]
            settings_lock_root: std::env::temp_dir().join(format!(
                "windows-app-autologin-supervisor-test-{}",
                uuid::Uuid::new_v4().hyphenated()
            )),
            #[cfg(test)]
            last_published_monitor_control_state: std::cell::Cell::new(None),
            last_storage_recovery_attempt: Instant::now()
                .checked_sub(STORAGE_RECOVERY_RETRY_INTERVAL)
                .unwrap_or_else(Instant::now),
            resume_monitor_after_settings: false,
            exit_requested: false,
            settings_child_exit_deadline: None,
            exit_shutdown_finalized: false,
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

    fn apply_startup_runtime_preferences(&mut self, window_preference_known: bool) {
        if window_preference_known {
            self.apply_known_startup_window_preference();
        } else {
            // The in-memory blocked config contains safe defaults, not the
            // user's durable preference. Remember the one startup-only intent
            // until the deferred recovery path has loaded authoritative data.
            self.startup_window_preference_pending = true;
        }

        // Window presentation closes the synchronous worker gate before any
        // monitor Start can be queued. The bootstrapped window will resume the
        // desired monitor intent; queuing Start first could admit an automation
        // attempt and make this one-shot launch time out behind quiescence.
        if self.pending_settings_launch.is_none() {
            queue_monitor_start_if_accessibility_trusted(
                &self.worker_tx,
                self.accessibility_trusted,
                self.storage_recovery_ready,
            );
        }
    }

    fn apply_known_startup_window_preference(&mut self) {
        self.startup_window_preference_pending = false;
        if !self.config.settings.start_minimized {
            self.open_accounts_window();
        }
    }

    fn apply_deferred_startup_runtime_preferences(&mut self, start_monitor: bool) {
        if !self.startup_window_preference_pending {
            return;
        }
        self.apply_known_startup_window_preference();
        if self.pending_settings_launch.is_none() && start_monitor {
            // The recovery reload was queued first with start_monitor=false,
            // so this Start is ordered after the fresh config releases its
            // pause. A visible-window preference instead keeps the pause closed
            // until the settings child bootstraps and resumes the same intent.
            self.queue_worker_start_fail_closed();
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
            if self.exit_requested && !matches!(&command, tray::TrayCommand::Exit) {
                continue;
            }
            match command {
                tray::TrayCommand::OpenAccounts => self.open_accounts_window(),
                tray::TrayCommand::OpenSettings => self.open_settings_window(),
                tray::TrayCommand::PresentAccounts(_) | tray::TrayCommand::PresentSettings(_) => {
                    tracing::warn!("Rejected a child-only presentation command in the supervisor");
                }
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
                    if self.handle_exit_request() {
                        event_loop.exit();
                        return true;
                    }
                }
            }
        }
        false
    }

    fn handle_exit_request(&mut self) -> bool {
        #[cfg(not(test))]
        return self
            .handle_exit_request_with_monitor_status_writer(single_instance::write_monitor_status);
        #[cfg(test)]
        return self.handle_exit_request_with_monitor_status_writer(|_| Ok(()));
    }

    fn handle_exit_request_with_monitor_status_writer(
        &mut self,
        mut write_monitor_status: impl FnMut(bool) -> anyhow::Result<()>,
    ) -> bool {
        if !self.exit_requested {
            self.exit_requested = true;
            self.worker_pause_latch.pause();
            self.worker_invalidator.invalidate();
            self.desired_monitor_running = false;
            self.resume_monitor_after_settings = false;
            self.pending_settings_launch = None;
            self.pending_settings_presentation = None;

            if let Some(child) = self.settings_child.as_mut() {
                self.settings_child_exit_deadline = Some(
                    Instant::now()
                        .checked_add(FULL_UI_GRACEFUL_EXIT_TIMEOUT)
                        .unwrap_or_else(Instant::now),
                );
                if let Err(error) = send_full_ui_exit(child) {
                    tracing::warn!(%error, "Could not request graceful settings window exit");
                }
            }
        }

        if self.settings_child.is_some() {
            // The child may be waiting for mutation/reload IPC while its
            // background save chain drains. Preserve that state and keep the
            // supervisor event loop alive until try_wait confirms process
            // exit. The pause latch above prevents any new automation work.
            return false;
        }
        if self.exit_shutdown_finalized {
            return true;
        }

        self.exit_shutdown_finalized = true;
        self.settings_child_exit_deadline = None;
        self.worker_pause_latch.pause();
        self.worker_invalidator.invalidate();
        self.worker_status = models::WorkerStatus::Idle;
        self.settings_mutation_active = false;
        if let Err(e) = write_monitor_status(false) {
            tracing::warn!("Could not publish stopped monitor status during quit: {e}");
        }
        let _ = self.worker_tx.try_send(background::WorkerCommand::Stop);
        true
    }

    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    fn process_monitor_commands(&mut self) {
        let command = self.monitor_command_watcher.consume_command();
        let Some(command) = command else {
            return;
        };

        if self.exit_requested
            && matches!(
                command,
                single_instance::MonitorControlCommand::Start
                    | single_instance::MonitorControlCommand::Stop
            )
        {
            return;
        }

        match command {
            single_instance::MonitorControlCommand::Start => {
                let _ = self.start_monitor_from_control_command();
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

            if peer_command.command == single_instance::LocalIpcCommand::ReloadConfig {
                let peer_pid = peer_command.peer_pid;
                if !self.acknowledge_live_settings_commit_with_loader(
                    || peer_command.acknowledge(),
                    load_full_ui_config,
                ) {
                    tracing::warn!(
                        peer_pid,
                        "Authorized settings commit could not be acknowledged safely"
                    );
                }
                continue;
            }

            if let single_instance::LocalIpcCommand::Monitor(command) = peer_command.command {
                let peer_pid = peer_command.peer_pid;
                if !self.acknowledge_monitor_control_command_with(
                    command,
                    single_instance::write_monitor_control_state,
                    || peer_command.acknowledge(),
                ) {
                    tracing::warn!(
                        peer_pid,
                        "Authorized monitor command could not be published and acknowledged safely"
                    );
                }
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
        if self.exit_requested
            && matches!(
                command,
                single_instance::LocalIpcCommand::Activate
                    | single_instance::LocalIpcCommand::Monitor(
                        single_instance::MonitorControlCommand::Start
                            | single_instance::MonitorControlCommand::Stop
                    )
            )
        {
            return false;
        }
        match command {
            single_instance::LocalIpcCommand::Activate => self.handle_activation_request(),
            single_instance::LocalIpcCommand::SettingsBootstrap => false,
            single_instance::LocalIpcCommand::SettingsMutationBegin => {
                self.begin_settings_mutation()
            }
            single_instance::LocalIpcCommand::SettingsMutationCancel => {
                self.cancel_settings_mutation()
            }
            // Live commit reload has ACK-before-release ordering and is
            // handled directly by process_local_ipc_commands.
            single_instance::LocalIpcCommand::ReloadConfig => false,
            single_instance::LocalIpcCommand::Monitor(command) => match command {
                single_instance::MonitorControlCommand::Start => {
                    self.start_monitor_from_control_command()
                }
                single_instance::MonitorControlCommand::Stop => {
                    self.stop_monitor();
                    true
                }
                single_instance::MonitorControlCommand::StorageRecoveryBlocked => {
                    self.block_storage_recovery_until_restart();
                    true
                }
                #[cfg(target_os = "windows")]
                single_instance::MonitorControlCommand::ReloadConfig => {
                    self.reload_config_after_settings();
                    true
                }
            },
        }
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    fn acknowledge_monitor_control_command_with(
        &mut self,
        command: single_instance::MonitorControlCommand,
        mut publish_control_state: impl FnMut(MonitorControlState) -> anyhow::Result<()>,
        acknowledge: impl FnOnce() -> anyhow::Result<()>,
    ) -> bool {
        if !self
            .handle_authorized_local_ipc_command(single_instance::LocalIpcCommand::Monitor(command))
        {
            return false;
        }

        let control_state = match command {
            single_instance::MonitorControlCommand::Stop
            | single_instance::MonitorControlCommand::StorageRecoveryBlocked => {
                MonitorControlState::Stopped
            }
            single_instance::MonitorControlCommand::Start => self.monitor_control_state(),
            #[cfg(target_os = "windows")]
            single_instance::MonitorControlCommand::ReloadConfig => self.monitor_control_state(),
        };
        if let Err(error) = publish_control_state(control_state) {
            tracing::warn!(
                %error,
                ?control_state,
                "Committed monitor command was not acknowledged because its control state could not be published"
            );
            return false;
        }
        if let Err(error) = acknowledge() {
            tracing::warn!(%error, "Could not acknowledge committed monitor command");
            return false;
        }
        true
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
        self.resume_monitor_after_settings_bootstrap();
        true
    }

    fn resume_monitor_after_settings_bootstrap(&mut self) {
        if !self.desired_monitor_running || self.storage_recovery_sticky_blocked {
            self.resume_monitor_after_settings = false;
            self.update_tray_status();
            return;
        }
        if !self.storage_recovery_ready {
            self.resume_monitor_after_settings = true;
            self.update_tray_status();
            return;
        }
        if !self.accessibility_ready_for_start() {
            self.resume_monitor_after_settings = false;
            self.update_tray_status();
            return;
        }
        let _ = self.queue_fresh_config_and_start();
        // Preserve the desired intent for the authoritative reload on child
        // exit. The monitor is allowed to run during a bootstrapped, idle UI,
        // but closing that UI must not turn an explicit running intent into a
        // stop request.
        self.resume_monitor_after_settings = self.desired_monitor_running;
        self.update_tray_status();
    }

    fn begin_settings_mutation(&mut self) -> bool {
        if !self.settings_child_bootstrapped
            || self.storage_recovery_sticky_blocked
            || !self.storage_recovery_ready
        {
            return false;
        }
        if self.settings_mutation_active {
            // A previous request may have reached the pause latch but lost its
            // quiescence acknowledgement or its IPC ACK. Never let a retry
            // convert that uncertainty into permission to mutate.
            return false;
        }

        // Close the synchronous gate before ACK. Stop and Quiesce are ordered
        // behind every already-started worker decision, so no credential or
        // config mutation can overlap an active fill or admit a new one.
        self.settings_mutation_active = true;
        self.resume_monitor_after_settings = self.desired_monitor_running;
        self.worker_pause_latch.pause();
        self.worker_invalidator.invalidate();
        if let Err(error) = self.worker_tx.try_send(background::WorkerCommand::Stop) {
            tracing::warn!(%error, "Could not queue settings mutation worker stop; pause remains active");
            return false;
        }
        let Some(request_id) = self.next_settings_launch_request_id.checked_add(1) else {
            tracing::warn!("Settings mutation quiescence request identifier space is exhausted");
            return false;
        };
        self.next_settings_launch_request_id = request_id;
        let (acknowledgement, acknowledgement_receiver) = std_channel();
        if let Err(error) = self.worker_tx.try_send(background::WorkerCommand::Quiesce {
            request_id,
            acknowledgement,
        }) {
            tracing::warn!(%error, "Could not queue settings mutation quiescence; pause remains active");
            return false;
        }
        match acknowledgement_receiver.recv_timeout(SETTINGS_QUIESCENCE_TIMEOUT) {
            Ok(acknowledgement) if acknowledgement.request_id == request_id => {
                self.worker_status = models::WorkerStatus::Idle;
                self.update_tray_status();
                true
            }
            Ok(acknowledgement) => {
                tracing::warn!(
                    expected_request_id = request_id,
                    received_request_id = acknowledgement.request_id,
                    "Settings mutation quiescence acknowledgement mismatch; pause remains active"
                );
                false
            }
            Err(error) => {
                tracing::warn!(%error, "Settings mutation quiescence was not acknowledged; pause remains active");
                false
            }
        }
    }

    fn cancel_settings_mutation(&mut self) -> bool {
        if !self.settings_mutation_active {
            return true;
        }
        self.settings_mutation_active = false;
        let should_resume = self.resume_monitor_after_settings
            && self.desired_monitor_running
            && self.storage_recovery_ready
            && !self.storage_recovery_sticky_blocked
            && self.accessibility_ready_for_start();
        let resumed = !should_resume || self.queue_fresh_config_and_start();
        self.resume_monitor_after_settings = self.desired_monitor_running;
        self.update_tray_status();
        resumed
    }

    fn acknowledge_live_settings_commit_with_loader(
        &mut self,
        acknowledge: impl FnOnce() -> anyhow::Result<()>,
        load_config: impl FnOnce() -> StartupConfig,
    ) -> bool {
        if !self.settings_mutation_active {
            tracing::warn!("Rejected settings commit without an acknowledged mutation pause");
            return false;
        }
        let startup = load_config();
        if !startup.storage_recovery_ready {
            self.block_storage_recovery_until_restart();
            tracing::error!(
                "Saved config could not be verified as a clean durable commit; monitor remains stopped"
            );
            return false;
        }
        if self.storage_recovery_sticky_blocked {
            self.worker_pause_latch.pause();
            return false;
        }
        let should_resume = self.desired_monitor_running
            && !self.storage_recovery_sticky_blocked
            && self.accessibility_ready_for_start();

        let Some((next_config, apply_command)) =
            self.prepare_reloaded_config(startup, should_resume)
        else {
            return false;
        };
        // Reserve capacity before ACK, but do not publish the release command
        // yet. This makes a successful IPC acknowledgement mean that the new
        // config can be delivered, while still ensuring automation cannot be
        // released before the child receives that acknowledgement.
        let apply_permit = match self.worker_tx.clone().try_reserve_owned() {
            Ok(permit) => permit,
            Err(error) => {
                self.fail_reloaded_config_delivery(&error);
                return false;
            }
        };

        // Do not release automation until the child knows its durable commit
        // notification was accepted. If the peer disappeared before ACK, its
        // Drop guard is already terminal and the supervisor stays paused until
        // confirmed child exit performs authoritative recovery.
        if let Err(error) = acknowledge() {
            tracing::warn!(%error, "Could not acknowledge the clean settings commit; pause remains active");
            return false;
        }
        apply_permit.send(apply_command);
        self.finish_reloaded_config(next_config);
        self.settings_mutation_active = false;
        self.resume_monitor_after_settings = self.desired_monitor_running;
        self.update_tray_status();
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
        self.update_tray_status();
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
        if self.monitor_pause_transition_active() {
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
        if self.monitor_pause_transition_active() {
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

    fn start_monitor_from_control_command(&mut self) -> bool {
        self.start_monitor_from_control_command_with_loader(load_config_with_storage_recovery)
    }

    fn start_monitor_from_control_command_with_loader(
        &mut self,
        load_config: impl FnOnce() -> StartupConfig,
    ) -> bool {
        if self.storage_recovery_sticky_blocked {
            tracing::warn!(
                "Monitor remains stopped until password storage recovery completes after restart"
            );
            return false;
        }
        self.desired_monitor_running = true;
        self.update_tray_status();
        if !self.storage_recovery_ready && !self.settings_transition_active() {
            self.resume_monitor_after_settings = true;
            tracing::warn!(
                "Monitor remains stopped because password storage recovery is incomplete"
            );
            return true;
        }
        if !self.accessibility_ready_for_start() {
            tracing::warn!("Automation permission is required before starting monitor");
            return true;
        }
        self.resume_monitor_after_settings = false;
        if self.monitor_pause_transition_active() {
            // A not-yet-bootstrapped child or an acknowledged live mutation is
            // a safety pause. Do not interpret its journal as crash recovery.
            let _ = load_config;
            self.resume_monitor_after_settings = true;
            return true;
        }
        if self.worker_pause_latch.is_paused() {
            self.queue_fresh_config_and_start();
        } else if self.worker_status == models::WorkerStatus::Idle {
            self.queue_worker_start_fail_closed();
        }
        true
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
        // An already-idle worker does not emit another StatusChanged event.
        // Publish the changed control intent now so both UI surfaces update.
        self.update_tray_status();
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
        self.settings_mutation_active = false;
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

    fn queue_fresh_config_and_start(&mut self) -> bool {
        if !self.desired_monitor_running || self.storage_recovery_sticky_blocked {
            self.worker_pause_latch.pause();
            return false;
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
            return false;
        }
        true
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
        if let Some(pending) = self.pending_settings_launch.as_mut() {
            pending.initial_tab = initial_tab;
            return true;
        }

        self.poll_settings_presentation_acknowledgements();
        if let Some(pending) = self.pending_settings_presentation.as_mut() {
            // Serialize presentation commands so a late acknowledgement can
            // never be mistaken for a newer request. Only the latest tab
            // matters; it is sent as soon as the in-flight request completes.
            pending.requested_tab = initial_tab;
            return true;
        }

        if self.settings_child.is_some() {
            // Reap a child that exited immediately before this user action. A
            // confirmed live child keeps the same settings lease and receives
            // a private presentation command through its inherited stdin.
            self.poll_settings_window();
        }
        if self.settings_child.is_some() {
            return self.queue_settings_child_presentation(initial_tab);
        }

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

    fn queue_settings_child_presentation(&mut self, tab: models::Tab) -> bool {
        if let Some(pending) = self.pending_settings_presentation.as_mut() {
            pending.requested_tab = tab;
            return true;
        }
        if self.settings_child_control_broken {
            tracing::warn!(
                "Could not present the settings window because its control channel is closed"
            );
            return false;
        }
        if self.settings_child.is_none() {
            return false;
        }

        if self.settings_child_acknowledgements.is_none() {
            let reader = self
                .settings_child
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("settings child is unavailable"))
                .and_then(spawn_full_ui_ack_reader);
            match reader {
                Ok(acknowledgements) => {
                    self.settings_child_acknowledgements = Some(acknowledgements);
                }
                Err(error) => {
                    tracing::warn!(%error, "Could not establish the settings presentation acknowledgement reader");
                    self.settings_child_control_broken = true;
                }
            }
        }

        // Record the user's intent even if the write races process shutdown.
        // A live child is never killed for failing to ACK; once try_wait proves
        // it exited, poll_settings_window reopens the latest requested tab.
        self.pending_settings_presentation = Some(PendingSettingsPresentation {
            in_flight_tab: tab,
            requested_tab: tab,
            phase: SettingsPresentationPhase::AwaitingAcknowledgement,
        });
        let send_result = self
            .settings_child
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("settings child is unavailable"))
            .and_then(|child| send_full_ui_presentation(child, tab));
        if let Err(error) = send_result {
            tracing::warn!(%error, "Could not send a presentation command to the existing settings window");
            self.mark_settings_child_control_broken();
        } else if self.settings_child_control_broken {
            // The command was best-effort delivered, but without an ACK reader
            // it is safe to reopen only if this process is confirmed to exit
            // promptly. Never retain stale reopen intent indefinitely.
            self.mark_settings_child_control_broken();
        }
        true
    }

    fn mark_settings_child_control_broken(&mut self) {
        self.settings_child_control_broken = true;
        self.settings_child_acknowledgements = None;
        let deadline = Instant::now()
            .checked_add(FULL_UI_EXIT_CONFIRMATION_GRACE)
            .unwrap_or_else(Instant::now);
        if let Some(pending) = self.pending_settings_presentation.as_mut() {
            pending.phase = SettingsPresentationPhase::AwaitingConfirmedExit { deadline };
        }
    }

    fn expire_unconfirmed_settings_presentation(&mut self, now: Instant) {
        let expired = self
            .pending_settings_presentation
            .as_ref()
            .is_some_and(|pending| {
                matches!(
                    pending.phase,
                    SettingsPresentationPhase::AwaitingConfirmedExit { deadline }
                        if now >= deadline
                )
            });
        if expired {
            self.pending_settings_presentation = None;
            tracing::warn!(
                "Abandoned stale settings presentation intent because the control channel failed but the child remained live"
            );
        }
    }

    fn poll_settings_presentation_acknowledgements(&mut self) {
        loop {
            let response = match self.settings_child_acknowledgements.as_ref() {
                Some(acknowledgements) => acknowledgements.try_recv(),
                None => return,
            };
            match response {
                Ok(Ok(FullUiControlRead::Show(acknowledged_tab))) => {
                    let Some(pending) = self.pending_settings_presentation else {
                        tracing::warn!(?acknowledged_tab, "Settings presentation protocol returned an unsolicited acknowledgement");
                        self.mark_settings_child_control_broken();
                        return;
                    };
                    if acknowledged_tab != pending.in_flight_tab {
                        tracing::warn!(
                            ?acknowledged_tab,
                            expected_tab = ?pending.in_flight_tab,
                            "Settings presentation protocol returned an out-of-order acknowledgement"
                        );
                        self.mark_settings_child_control_broken();
                        return;
                    }

                    self.pending_settings_presentation = None;
                    if pending.requested_tab != acknowledged_tab {
                        let _ = self.queue_settings_child_presentation(pending.requested_tab);
                    }
                }
                Ok(Ok(FullUiControlRead::Invalid | FullUiControlRead::Exit)) => {
                    tracing::warn!(
                        "Settings presentation protocol returned an invalid acknowledgement"
                    );
                    self.mark_settings_child_control_broken();
                    return;
                }
                Ok(Ok(FullUiControlRead::EndOfStream)) => {
                    self.mark_settings_child_control_broken();
                    return;
                }
                Ok(Err(error)) => {
                    tracing::warn!(%error, "Settings presentation acknowledgement reader failed");
                    self.mark_settings_child_control_broken();
                    return;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => return,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.mark_settings_child_control_broken();
                    return;
                }
            }
        }
    }

    fn settings_transition_active(&self) -> bool {
        self.settings_child.is_some() || self.pending_settings_launch.is_some()
    }

    fn monitor_pause_transition_active(&self) -> bool {
        self.pending_settings_launch.is_some()
            || self.settings_child.is_some()
                && (!self.settings_child_bootstrapped || self.settings_mutation_active)
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
                self.settings_child_acknowledgements = None;
                self.settings_child_control_broken = false;
                self.pending_settings_presentation = None;
                self.settings_child_bootstrapped = false;
                self.settings_mutation_active = false;
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
        self.settings_mutation_active = false;
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
        self.poll_settings_presentation_acknowledgements();
        self.poll_settings_window_with_loader(|_| load_config_with_storage_recovery());
        self.expire_unconfirmed_settings_presentation(Instant::now());
    }

    fn poll_exit_request(&mut self, now: Instant) -> bool {
        #[cfg(not(test))]
        return self.poll_exit_request_with_monitor_status_writer(
            now,
            single_instance::write_monitor_status,
        );
        #[cfg(test)]
        return self.poll_exit_request_with_monitor_status_writer(now, |_| Ok(()));
    }

    fn poll_exit_request_with_monitor_status_writer(
        &mut self,
        now: Instant,
        write_monitor_status: impl FnMut(bool) -> anyhow::Result<()>,
    ) -> bool {
        if !self.exit_requested {
            return false;
        }
        if self
            .settings_child_exit_deadline
            .is_some_and(|deadline| now >= deadline)
            && self.settings_child.is_some()
        {
            self.force_settings_child_exit_after_timeout(now);
        }
        self.handle_exit_request_with_monitor_status_writer(write_monitor_status)
    }

    fn force_settings_child_exit_after_timeout(&mut self, now: Instant) {
        let Some(mut child) = self.settings_child.take() else {
            self.settings_child_exit_deadline = None;
            return;
        };
        let mutation_was_active = self.settings_mutation_active;
        let exited = child_has_exited(&mut child)
            || terminate_child_process(&mut child, "settings window after save timeout");
        if !exited {
            // Do not drop the process handle or the shared settings lease
            // without confirmed exit. Keep automation synchronously gated and
            // retry the forced close on a later supervisor tick.
            self.settings_child = Some(child);
            self.settings_child_exit_deadline = Some(
                now.checked_add(FULL_UI_EXIT_CONFIRMATION_GRACE)
                    .unwrap_or(now),
            );
            if mutation_was_active {
                self.mark_settings_exit_storage_recovery_required();
            }
            return;
        }

        self.settings_child_acknowledgements = None;
        self.settings_child_control_broken = false;
        self.settings_child_bootstrapped = false;
        self.settings_mutation_active = false;
        self.settings_child_exit_deadline = None;
        self.settings_session_lease = None;
        if mutation_was_active {
            self.mark_settings_exit_storage_recovery_required();
        }
        self.revoke_settings_session_authorization_fail_closed(
            "Could not revoke settings authorization after forced settings exit",
        );
    }

    fn mark_settings_exit_storage_recovery_required(&mut self) {
        self.storage_recovery_ready = false;
        self.storage_recovery_sticky_blocked = true;
        self.desired_monitor_running = false;
        self.resume_monitor_after_settings = false;
        #[cfg(not(test))]
        if let Err(error) = storage::mark_storage_recovery_blocked() {
            tracing::error!(%error, "Ambiguous settings exit recovery block could not be persisted; supervisor-local pause remains active");
        }
        self.worker_pause_latch.pause();
        self.worker_invalidator.invalidate();
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
                // Reload/cancel/recovery ACKs all clear this flag before a
                // healthy child is allowed to close. Seeing it at confirmed
                // process exit means the background transaction ended
                // ambiguously (including panic=abort release builds), so the
                // supervisor must make the pause sticky before any reload.
                let mutation_was_active = self.settings_mutation_active;
                let requested_replacement_tab = self
                    .pending_settings_presentation
                    .take()
                    .map(|pending| pending.requested_tab);
                self.settings_child = None;
                self.settings_child_acknowledgements = None;
                self.settings_child_control_broken = false;
                self.settings_child_bootstrapped = false;
                self.settings_mutation_active = false;
                self.settings_session_lease = None;
                if mutation_was_active {
                    self.mark_settings_exit_storage_recovery_required();
                }
                let should_resume = requested_replacement_tab.is_none()
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
                if let Some(tab) = requested_replacement_tab {
                    // The presentation command raced a confirmed process exit.
                    // Reopen the requested tab only after the old child's
                    // storage lease has been released and recovery/reload ran.
                    let _ = self.open_full_ui_window_with_monitor_policy(tab, true);
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

    #[cfg_attr(test, allow(dead_code))]
    #[cfg(any(target_os = "windows", test))]
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
        let Some((next_config, apply_command)) =
            self.prepare_reloaded_config(startup, start_monitor)
        else {
            return false;
        };
        if let Err(error) = self.worker_tx.try_send(apply_command) {
            self.fail_reloaded_config_delivery(&error);
            return false;
        }
        self.finish_reloaded_config(next_config);
        true
    }

    fn prepare_reloaded_config(
        &mut self,
        startup: StartupConfig,
        start_monitor: bool,
    ) -> Option<(models::AppConfig, background::WorkerCommand)> {
        let pause_epoch = self.worker_pause_latch.pause_with_epoch();
        self.worker_invalidator.invalidate();
        if !startup.storage_recovery_ready {
            self.block_storage_recovery_until_restart();
            tracing::error!(
                "Saved config was not delivered to the worker because password storage recovery is incomplete; monitor will remain stopped"
            );
            return None;
        }
        if self.storage_recovery_sticky_blocked {
            self.worker_pause_latch.pause();
            return None;
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
        Some((next_config, apply_command))
    }

    fn fail_reloaded_config_delivery(&mut self, error: &impl std::fmt::Display) {
        self.storage_recovery_ready = false;
        self.resume_monitor_after_settings = false;
        self.worker_pause_latch.pause();
        if self.worker_status == models::WorkerStatus::Running {
            let _ = self.worker_tx.try_send(background::WorkerCommand::Stop);
        }
        tracing::error!(
            %error,
            "Could not deliver saved config to worker; monitor will remain stopped"
        );
    }

    fn finish_reloaded_config(&mut self, next_config: models::AppConfig) {
        self.config = next_config;
        self.storage_recovery_ready = true;
        self.update_tray_status();
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
        if self.complete_blocked_storage_recovery_with(
            should_resume,
            |supervisor, start_monitor| {
                supervisor.reload_config_after_settings_with_recovery_lease(start_monitor)
            },
        ) {
            tracing::info!("Deferred password storage recovery completed safely");
        }
    }

    fn complete_blocked_storage_recovery_with<R>(&mut self, should_resume: bool, reload: R) -> bool
    where
        R: FnOnce(&mut Self, bool) -> bool,
    {
        let startup_preference_deferred = self.startup_window_preference_pending;
        let start_during_reload = should_resume && !startup_preference_deferred;
        if !reload(self, start_during_reload) {
            return false;
        }
        self.resume_monitor_after_settings = false;
        if startup_preference_deferred {
            self.apply_deferred_startup_runtime_preferences(should_resume);
        }
        true
    }

    fn update_tray_status(&self) {
        let control_state = self.monitor_control_state();
        #[cfg(test)]
        self.last_published_monitor_control_state
            .set(Some(control_state));
        #[cfg(not(test))]
        {
            if let Err(e) = single_instance::write_monitor_control_state(control_state) {
                tracing::warn!("Could not write monitor status: {e}");
            }
        }

        let Some(tray) = &self.tray else {
            return;
        };
        tray.set_accessibility_trusted(self.accessibility_trusted);
        tray.set_keychain_enabled(self.config.settings.use_keyring);
        tray.set_monitor_control_state(control_state);
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
            if !self.exit_requested {
                self.process_activation_requests();
            }
        }
        self.poll_settings_window();
        if self.exit_requested {
            if self.poll_exit_request(Instant::now()) {
                event_loop.exit();
                return;
            }
            event_loop.set_control_flow(ControlFlow::WaitUntil(Instant::now() + SUPERVISOR_TICK));
            return;
        }
        self.retry_blocked_storage_recovery();
        self.poll_accessibility();
        event_loop.set_control_flow(ControlFlow::WaitUntil(Instant::now() + SUPERVISOR_TICK));
    }

    fn exiting(&mut self, _event_loop: &ActiveEventLoop) {
        if self.handle_exit_request() {
            return;
        }
        // This callback also covers an externally initiated event-loop exit,
        // where there is no future tick in which to honor the normal grace
        // period. Force the already-gated child down and leave recovery
        // blocked if a mutation may have been interrupted.
        self.force_settings_child_exit_after_timeout(Instant::now());
        let _ = self.handle_exit_request();
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
        single_instance::LocalIpcCommand::SettingsMutationBegin
        | single_instance::LocalIpcCommand::SettingsMutationCancel
        | single_instance::LocalIpcCommand::ReloadConfig
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
    #[cfg(target_os = "windows")]
    let executable = app_identity::windows_full_ui_executable_path()?;
    #[cfg(not(target_os = "windows"))]
    let executable = std::env::current_exe()?;

    Ok(full_ui_command(
        executable,
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
    command
        .arg("--full-ui")
        .arg(initial_tab_arg(initial_tab))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
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
            false
        }
    }
}

fn terminate_child_process(child: &mut Child, label: &str) -> bool {
    request_child_termination(child, label);
    if wait_for_child_exit(child, Duration::from_millis(500)) {
        return true;
    }

    if let Err(e) = child.kill() {
        tracing::warn!("Could not force quit {label}: {e}");
        return false;
    }
    wait_for_child_exit(child, Duration::from_millis(500))
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
        acquire_authorized_settings_session_with, build_background_runtime, dispatch_full_ui_exit,
        fill_result_label, finish_startup_storage_recovery_after_journals_with_ops,
        full_ui_command, full_ui_control_message, full_ui_renderer, initial_tab_arg,
        publish_initial_monitor_status, read_full_ui_control_command, send_full_ui_presentation,
        spawn_full_ui_ack_reader, std_channel, sync_startup_auto_start_with, tokio_channel,
        FullUiControlRead, LightweightSupervisor, MonitorControlState, SettingsPresentationPhase,
        StartupConfig, BACKGROUND_RUNTIME_WORKER_THREADS,
    };
    use crate::background::{WorkerCommand, WorkerInvalidator, WorkerQuiescenceAck};
    use crate::debug_fill::FillAttemptReport;
    use crate::models::{Account, AppConfig};
    use crate::tray::TrayCommand;
    use eframe::egui;
    use std::io::{BufReader, Cursor};

    #[test]
    fn background_runtime_uses_one_worker_for_the_one_monitor_task() {
        let runtime = build_background_runtime().unwrap();

        assert_eq!(BACKGROUND_RUNTIME_WORKER_THREADS, 1);
        assert_eq!(runtime.metrics().num_workers(), 1);
    }

    #[test]
    fn live_settings_commit_acknowledges_only_after_worker_capacity_is_reserved() {
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
        supervisor.settings_mutation_active = true;
        let mut next_config = AppConfig::default();
        next_config.settings.start_minimized = true;
        let expected = next_config.clone();
        let ack_saw_no_released_command = std::cell::Cell::new(false);

        assert!(supervisor.acknowledge_live_settings_commit_with_loader(
            || {
                ack_saw_no_released_command.set(worker_rx.try_recv().is_err());
                Ok(())
            },
            || StartupConfig {
                config: next_config,
                storage_recovery_ready: true,
            },
        ));

        assert!(ack_saw_no_released_command.get());
        assert_eq!(supervisor.config, expected);
        assert!(!supervisor.settings_mutation_active);
        assert!(matches!(
            worker_rx.try_recv(),
            Ok(WorkerCommand::ApplyConfigAndReleasePause { .. })
        ));
    }

    #[test]
    fn live_settings_commit_does_not_ack_when_worker_capacity_is_unavailable() {
        let (worker_tx, mut worker_rx) = tokio_channel(1);
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
        supervisor.settings_mutation_active = true;
        let acknowledged = std::cell::Cell::new(false);

        assert!(!supervisor.acknowledge_live_settings_commit_with_loader(
            || {
                acknowledged.set(true);
                Ok(())
            },
            || StartupConfig {
                config: AppConfig::default(),
                storage_recovery_ready: true,
            },
        ));

        assert!(!acknowledged.get());
        assert!(supervisor.settings_mutation_active);
        assert_eq!(supervisor.config, original_config);
        assert!(matches!(worker_rx.try_recv(), Ok(WorkerCommand::Start)));
    }

    #[test]
    fn live_settings_commit_ack_failure_never_publishes_release_command() {
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
        supervisor.settings_mutation_active = true;

        assert!(!supervisor.acknowledge_live_settings_commit_with_loader(
            || anyhow::bail!("test acknowledgement failure"),
            || StartupConfig {
                config: AppConfig::default(),
                storage_recovery_ready: true,
            },
        ));

        assert!(supervisor.settings_mutation_active);
        assert!(worker_rx.try_recv().is_err());
    }

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
    fn blocked_startup_does_not_autosave_in_memory_defaults() {
        let mut startup = super::blocked_startup_config();
        let save_called = std::cell::Cell::new(false);

        sync_startup_auto_start_with(&mut startup, true, |_| {
            save_called.set(true);
            Ok(())
        });

        assert!(!save_called.get());
        assert!(!startup.config.settings.auto_start);
        assert!(!startup.storage_recovery_ready);
    }

    #[test]
    fn config_load_failure_keeps_startup_window_preference_unknown() {
        let startup_load =
            super::load_config_with_storage_recovery_inner_with_loader(false, || {
                anyhow::bail!("simulated unreadable config")
            });

        assert!(!startup_load.window_preference_known);
        assert!(!startup_load.startup.storage_recovery_ready);
        assert!(!startup_load.startup.config.settings.start_minimized);
    }

    #[test]
    fn verified_startup_reconciles_and_persists_auto_start() {
        let mut startup = StartupConfig {
            config: AppConfig::default(),
            storage_recovery_ready: true,
        };
        let saved_auto_start = std::cell::Cell::new(None);

        sync_startup_auto_start_with(&mut startup, true, |config| {
            saved_auto_start.set(Some(config.settings.auto_start));
            Ok(())
        });

        assert_eq!(saved_auto_start.get(), Some(true));
        assert!(startup.config.settings.auto_start);
    }

    #[test]
    fn launch_requests_accounts_when_main_window_is_not_hidden() {
        let (worker_tx, mut worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (tray_tx, tray_rx) = std_channel();
        let mut config = AppConfig::default();
        config.settings.start_minimized = false;
        let mut supervisor = LightweightSupervisor::new(
            worker_tx,
            worker_event_rx,
            tray_tx,
            tray_rx,
            WorkerInvalidator::new(),
            config,
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            None,
        );
        supervisor.accessibility_trusted = true;

        supervisor.apply_startup_runtime_preferences(true);

        assert!(matches!(worker_rx.try_recv(), Ok(WorkerCommand::Stop)));
        // Startup presentation closes the worker gate before monitor intent is
        // applied, so a fill cannot race this one-shot window launch.
        assert_eq!(
            supervisor
                .pending_settings_launch
                .as_ref()
                .map(|pending| pending.initial_tab),
            Some(crate::models::Tab::Accounts)
        );
        assert!(supervisor.settings_child.is_none());

        complete_pending_settings_launch(
            &mut supervisor,
            &mut worker_rx,
            crate::models::Tab::Accounts,
        );

        assert!(supervisor.pending_settings_launch.is_none());
        assert!(supervisor.settings_child.is_some());
        // The child must bootstrap before monitor intent can resume, so no
        // Start is allowed merely because the native UI process was spawned.
        assert!(worker_rx.try_recv().is_err());
        let _ = supervisor.settings_child.take().unwrap().kill();
    }

    #[test]
    fn launch_stays_tray_only_when_main_window_is_hidden() {
        let (worker_tx, mut worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (tray_tx, tray_rx) = std_channel();
        let mut config = AppConfig::default();
        config.settings.start_minimized = true;
        let mut supervisor = LightweightSupervisor::new(
            worker_tx,
            worker_event_rx,
            tray_tx,
            tray_rx,
            WorkerInvalidator::new(),
            config,
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            None,
        );
        supervisor.accessibility_trusted = true;

        supervisor.apply_startup_runtime_preferences(true);

        assert!(matches!(worker_rx.try_recv(), Ok(WorkerCommand::Start)));
        assert!(worker_rx.try_recv().is_err());
        assert!(supervisor.pending_settings_launch.is_none());
        assert!(supervisor.settings_child.is_none());
        assert!(!supervisor.worker_pause_latch.is_paused());
    }

    #[test]
    fn launch_does_not_guess_window_preference_from_blocked_defaults() {
        let (worker_tx, mut worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (tray_tx, tray_rx) = std_channel();
        let mut supervisor = LightweightSupervisor::new(
            worker_tx,
            worker_event_rx,
            tray_tx,
            tray_rx,
            WorkerInvalidator::new(),
            super::blocked_startup_config().config,
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            None,
        )
        .with_storage_recovery_state(false);
        supervisor.resume_monitor_after_settings = true;

        supervisor.apply_startup_runtime_preferences(false);

        assert!(worker_rx.try_recv().is_err());
        assert!(supervisor.pending_settings_launch.is_none());
        assert!(supervisor.settings_child.is_none());
        assert!(supervisor.worker_pause_latch.is_paused());
        assert!(supervisor.resume_monitor_after_settings);
        assert!(supervisor.startup_window_preference_pending);
    }

    #[test]
    fn deferred_startup_window_preference_uses_recovered_value_exactly_once() {
        for start_minimized in [false, true] {
            let (worker_tx, mut worker_rx) = tokio_channel(8);
            let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
            let (tray_tx, tray_rx) = std_channel();
            let mut supervisor = LightweightSupervisor::new(
                worker_tx,
                worker_event_rx,
                tray_tx,
                tray_rx,
                WorkerInvalidator::new(),
                super::blocked_startup_config().config,
                #[cfg(any(target_os = "macos", target_os = "windows"))]
                None,
            )
            .with_storage_recovery_state(false);

            supervisor.apply_startup_runtime_preferences(false);
            assert!(supervisor.startup_window_preference_pending);
            assert!(worker_rx.try_recv().is_err());

            let mut recovered = AppConfig::default();
            recovered.settings.start_minimized = start_minimized;
            let start_during_reload = std::cell::Cell::new(None);
            assert!(supervisor.complete_blocked_storage_recovery_with(
                true,
                |supervisor, start_monitor| {
                    start_during_reload.set(Some(start_monitor));
                    supervisor.apply_reloaded_config(
                        StartupConfig {
                            config: recovered,
                            storage_recovery_ready: true,
                        },
                        start_monitor,
                    )
                },
            ));

            // A deferred preference always loads and publishes the recovered
            // config without starting automation. Window presentation (or the
            // tray-only Start) is deliberately ordered after that reload.
            assert_eq!(start_during_reload.get(), Some(false));
            assert!(!supervisor.startup_window_preference_pending);
            match worker_rx.try_recv().unwrap() {
                WorkerCommand::ApplyConfigAndReleasePause {
                    settings,
                    start_monitor,
                    ..
                } => {
                    assert_eq!(settings.start_minimized, start_minimized);
                    assert!(!start_monitor);
                }
                other => panic!("expected recovered config apply, got {other:?}"),
            }
            if start_minimized {
                assert!(supervisor.pending_settings_launch.is_none());
                assert!(matches!(worker_rx.try_recv(), Ok(WorkerCommand::Start)));
                assert!(worker_rx.try_recv().is_err());
            } else {
                assert!(matches!(worker_rx.try_recv(), Ok(WorkerCommand::Stop)));
                let (_request_id, _acknowledgement) = take_quiescence_request(&mut worker_rx);
                assert_eq!(
                    supervisor
                        .pending_settings_launch
                        .as_ref()
                        .map(|pending| pending.initial_tab),
                    Some(crate::models::Tab::Accounts)
                );
                assert!(worker_rx.try_recv().is_err());
            }

            supervisor.apply_deferred_startup_runtime_preferences(true);
            assert!(worker_rx.try_recv().is_err());
        }
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
    fn windows_full_ui_helper_accepts_only_the_bounded_supervisor_arguments() {
        assert!(super::windows_full_ui_initial_tab_arg_is_valid(
            "--initial-tab=accounts"
        ));
        assert!(super::windows_full_ui_initial_tab_arg_is_valid(
            "--initial-tab=settings"
        ));
        assert_eq!(
            super::windows_full_ui_initial_tab_arg_is_valid("--initial-tab=diagnose"),
            cfg!(feature = "diagnostics-ui")
        );
        for rejected in [
            "--accounts",
            "--settings",
            "--full-ui",
            "--debug-fill-once",
            "--initial-tab=unknown",
            "--initial-tab=settings --extra",
        ] {
            assert!(
                !super::windows_full_ui_initial_tab_arg_is_valid(rejected),
                "{rejected}"
            );
        }
    }

    #[test]
    fn windows_helper_split_is_feature_gated_and_fails_closed_off_windows() {
        let source = include_str!("main.rs");
        let entrypoint = source
            .split_once("pub(crate) fn main()")
            .and_then(|(_, tail)| tail.split_once("fn run_lightweight_supervisor()"))
            .map(|(body, _)| body)
            .unwrap();
        let spawn = source
            .split_once("fn spawn_full_ui_window(")
            .and_then(|(_, tail)| tail.split_once("fn full_ui_command("))
            .map(|(body, _)| body)
            .unwrap();
        let helper = include_str!("bin/windows-app-autologin-ui.rs");
        let manifest = include_str!("../Cargo.toml");

        assert!(entrypoint.contains("app_identity::windows_binary_role()?"));
        assert!(entrypoint.contains("WindowsBinaryRole::FullUi"));
        assert!(entrypoint.contains("WindowsBinaryRole::Supervisor"));
        assert!(entrypoint.contains("run_windows_full_ui_binary(&args)"));
        assert!(entrypoint.contains("cannot run in full UI mode"));
        assert!(spawn.contains("app_identity::windows_full_ui_executable_path()?"));
        assert!(spawn.contains("#[cfg(not(target_os = \"windows\"))]"));
        assert!(spawn.contains("std::env::current_exe()?"));
        assert!(manifest.contains("required-features = [\"windows-ui-helper\"]"));
        assert!(manifest.contains("windows-ui-helper = []"));
        assert!(helper.contains("#[cfg(target_os = \"windows\")]\n#[path = \"../main.rs\"]"));
        assert!(helper.contains("#[cfg(target_os = \"windows\")]\nfn main()"));
        assert!(helper.contains("#[cfg(not(target_os = \"windows\"))]\nfn main()"));
        assert!(helper.contains("unavailable on this platform"));
        assert!(helper.contains("#[path = \"../main.rs\"]"));
        assert!(helper.contains("application::main()"));
    }

    #[test]
    fn full_ui_control_protocol_is_bounded_and_cross_platform() {
        assert_eq!(
            full_ui_control_message(crate::models::Tab::Accounts).unwrap(),
            b"show:accounts\n"
        );
        assert_eq!(
            full_ui_control_message(crate::models::Tab::Settings).unwrap(),
            b"show:settings\n"
        );

        let input = b"show:accounts\nshow:settings\r\nexit\nunknown\n";
        let mut reader = BufReader::with_capacity(3, Cursor::new(input));
        assert_eq!(
            read_full_ui_control_command(&mut reader).unwrap(),
            FullUiControlRead::Show(crate::models::Tab::Accounts)
        );
        assert_eq!(
            read_full_ui_control_command(&mut reader).unwrap(),
            FullUiControlRead::Show(crate::models::Tab::Settings)
        );
        assert_eq!(
            read_full_ui_control_command(&mut reader).unwrap(),
            FullUiControlRead::Exit
        );
        assert_eq!(
            read_full_ui_control_command(&mut reader).unwrap(),
            FullUiControlRead::Invalid
        );
        assert_eq!(
            read_full_ui_control_command(&mut reader).unwrap(),
            FullUiControlRead::EndOfStream
        );

        let overlong = format!(
            "{}\nshow:accounts\n",
            "x".repeat(super::FULL_UI_CONTROL_MAX_LINE_BYTES + 1)
        );
        let mut reader = BufReader::with_capacity(5, Cursor::new(overlong.into_bytes()));
        assert_eq!(
            read_full_ui_control_command(&mut reader).unwrap(),
            FullUiControlRead::Invalid
        );
        assert_eq!(
            read_full_ui_control_command(&mut reader).unwrap(),
            FullUiControlRead::Show(crate::models::Tab::Accounts)
        );
    }

    #[test]
    fn full_ui_exit_control_dispatches_to_the_ui_owner() {
        let (tray_tx, tray_rx) = std_channel();
        let ctx = egui::Context::default();

        assert!(dispatch_full_ui_exit(&tray_tx, &ctx));
        assert!(matches!(tray_rx.try_recv(), Ok(TrayCommand::Exit)));
    }

    #[test]
    fn presentation_ack_channel_is_not_contaminated_by_stderr_diagnostics() {
        let mut child = spawn_test_control_child_with_stderr_noise();
        let acknowledgements = spawn_full_ui_ack_reader(&mut child).unwrap();

        send_full_ui_presentation(&mut child, crate::models::Tab::Accounts).unwrap();

        assert_eq!(
            acknowledgements
                .recv_timeout(std::time::Duration::from_secs(1))
                .unwrap()
                .unwrap(),
            FullUiControlRead::Show(crate::models::Tab::Accounts)
        );
        let _ = child.wait();
    }

    #[test]
    fn busy_live_ui_is_not_terminated_for_a_delayed_presentation_acknowledgement() {
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
        let child = spawn_test_unacknowledging_control_child();
        let child_pid = child.id();
        supervisor.settings_child = Some(child);

        assert!(
            supervisor.open_full_ui_window_with_monitor_policy(crate::models::Tab::Accounts, true,)
        );
        assert_eq!(
            supervisor
                .settings_child
                .as_ref()
                .map(std::process::Child::id),
            Some(child_pid)
        );
        assert!(supervisor
            .settings_child
            .as_mut()
            .unwrap()
            .try_wait()
            .unwrap()
            .is_none());
        assert_eq!(
            supervisor
                .pending_settings_presentation
                .as_ref()
                .map(|pending| pending.requested_tab),
            Some(crate::models::Tab::Accounts)
        );
        assert!(worker_rx.try_recv().is_err());

        let mut child = supervisor.settings_child.take().unwrap();
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn broken_presentation_protocol_does_not_kill_child_or_retain_stale_reopen_intent() {
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
        let child = spawn_test_invalid_ack_control_child();
        let child_pid = child.id();
        supervisor.settings_child = Some(child);

        assert!(
            supervisor.open_full_ui_window_with_monitor_policy(crate::models::Tab::Accounts, true,)
        );
        for _ in 0..100 {
            supervisor.poll_settings_presentation_acknowledgements();
            if supervisor.settings_child_control_broken {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(supervisor.settings_child_control_broken);
        let deadline = match supervisor
            .pending_settings_presentation
            .as_ref()
            .map(|pending| pending.phase)
        {
            Some(SettingsPresentationPhase::AwaitingConfirmedExit { deadline }) => deadline,
            other => panic!("expected exit-confirmation phase, got {other:?}"),
        };
        assert!(supervisor
            .settings_child
            .as_mut()
            .unwrap()
            .try_wait()
            .unwrap()
            .is_none());

        supervisor.expire_unconfirmed_settings_presentation(deadline);

        assert!(supervisor.pending_settings_presentation.is_none());
        assert!(!supervisor
            .open_full_ui_window_with_monitor_policy(crate::models::Tab::Settings, true,));
        assert_eq!(
            supervisor
                .settings_child
                .as_ref()
                .map(std::process::Child::id),
            Some(child_pid)
        );
        assert!(supervisor.pending_settings_presentation.is_none());
        assert!(worker_rx.try_recv().is_err());

        let mut child = supervisor.settings_child.take().unwrap();
        let _ = child.kill();
        let _ = child.wait();
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
    fn windows_full_ui_uses_wgpu_without_an_opengl_requirement() {
        assert_eq!(full_ui_renderer(), eframe::Renderer::Wgpu);
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn non_windows_full_ui_keeps_the_existing_glow_renderer() {
        assert_eq!(full_ui_renderer(), eframe::Renderer::Glow);
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
        recovered.settings.start_minimized = true;
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

    #[test]
    fn repeated_full_ui_requests_present_the_live_child_without_requiescing() {
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
        let child = spawn_test_control_child();
        let child_pid = child.id();
        supervisor.settings_child = Some(child);
        supervisor.resume_monitor_after_settings = true;
        let session_token = supervisor.settings_session_token.as_str().to_string();
        let pause_epoch = supervisor.worker_pause_latch.current_epoch();
        let was_paused = supervisor.worker_pause_latch.is_paused();

        assert!(
            supervisor.open_full_ui_window_with_monitor_policy(crate::models::Tab::Accounts, true,)
        );
        assert!(
            supervisor.open_full_ui_window_with_monitor_policy(crate::models::Tab::Settings, true,)
        );
        for _ in 0..100 {
            supervisor.poll_settings_presentation_acknowledgements();
            if supervisor.pending_settings_presentation.is_none() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        assert_eq!(
            supervisor
                .settings_child
                .as_ref()
                .map(std::process::Child::id),
            Some(child_pid)
        );
        assert!(supervisor.pending_settings_presentation.is_none());
        assert!(supervisor.pending_settings_launch.is_none());
        assert_eq!(supervisor.settings_session_token.as_str(), session_token);
        assert!(supervisor.resume_monitor_after_settings);
        assert_eq!(supervisor.worker_pause_latch.current_epoch(), pause_epoch);
        assert_eq!(supervisor.worker_pause_latch.is_paused(), was_paused);
        assert!(worker_rx.try_recv().is_err());

        let mut child = supervisor.settings_child.take().unwrap();
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn presentation_racing_child_exit_reopens_the_latest_tab_only_after_confirmed_exit() {
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
        supervisor.settings_child = Some(spawn_test_exiting_control_child());
        supervisor.resume_monitor_after_settings = true;

        assert!(
            supervisor.open_full_ui_window_with_monitor_policy(crate::models::Tab::Accounts, true,)
        );
        assert!(
            supervisor.open_full_ui_window_with_monitor_policy(crate::models::Tab::Settings, true,)
        );
        assert!(supervisor.pending_settings_launch.is_none());
        assert_eq!(
            supervisor
                .pending_settings_presentation
                .as_ref()
                .map(|pending| pending.requested_tab),
            Some(crate::models::Tab::Settings)
        );

        wait_for_test_child_exit(&mut supervisor);
        supervisor.poll_settings_window_with_loader(|_| StartupConfig {
            config: AppConfig::default(),
            storage_recovery_ready: true,
        });

        assert!(supervisor.settings_child.is_none());
        assert!(supervisor.pending_settings_presentation.is_none());
        assert_eq!(
            supervisor
                .pending_settings_launch
                .as_ref()
                .map(|pending| pending.initial_tab),
            Some(crate::models::Tab::Settings)
        );
        assert!(matches!(
            worker_rx.try_recv(),
            Ok(WorkerCommand::ApplyConfigAndReleasePause {
                start_monitor: false,
                ..
            })
        ));
        assert!(matches!(worker_rx.try_recv(), Ok(WorkerCommand::Stop)));
        let (_request_id, _acknowledgement) = take_quiescence_request(&mut worker_rx);
        assert!(worker_rx.try_recv().is_err());
    }

    #[test]
    fn repeated_request_retargets_pending_launch_without_duplicate_worker_commands() {
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

        supervisor.open_settings_window();
        assert!(matches!(worker_rx.try_recv(), Ok(WorkerCommand::Stop)));
        let (request_id, _acknowledgement) = take_quiescence_request(&mut worker_rx);
        let session_token = supervisor.settings_session_token.as_str().to_string();

        #[cfg(any(target_os = "macos", target_os = "windows"))]
        assert!(supervisor.handle_activation_request());
        #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
        supervisor.open_accounts_window();

        let pending = supervisor.pending_settings_launch.as_ref().unwrap();
        assert_eq!(pending.request_id, request_id);
        assert_eq!(pending.initial_tab, crate::models::Tab::Accounts);
        assert_eq!(supervisor.settings_session_token.as_str(), session_token);
        assert!(supervisor.settings_child.is_none());
        assert!(worker_rx.try_recv().is_err());
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
        supervisor.desired_monitor_running = true;
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
        supervisor.desired_monitor_running = true;
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
    fn monitor_ipc_is_not_acknowledged_when_control_state_publish_fails() {
        use super::single_instance::MonitorControlCommand;

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
        supervisor.desired_monitor_running = true;
        let published_state = std::cell::Cell::new(None);
        let (acknowledged_tx, acknowledged_rx) = std_channel();

        let committed_and_acknowledged = supervisor.acknowledge_monitor_control_command_with(
            MonitorControlCommand::Stop,
            |state| {
                published_state.set(Some(state));
                anyhow::bail!("synthetic monitor status publication failure")
            },
            || {
                acknowledged_tx.send(())?;
                Ok(())
            },
        );

        assert!(!committed_and_acknowledged);
        assert_eq!(published_state.get(), Some(MonitorControlState::Stopped));
        assert!(acknowledged_rx.try_recv().is_err());
        assert!(!supervisor.desired_monitor_running);
        assert!(matches!(worker_rx.try_recv(), Ok(WorkerCommand::Stop)));
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    #[test]
    fn monitor_start_ipc_blocked_by_recovery_is_neither_published_nor_acknowledged() {
        use super::single_instance::MonitorControlCommand;

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
        supervisor.storage_recovery_sticky_blocked = true;
        supervisor.desired_monitor_running = false;
        let publish_count = std::cell::Cell::new(0);
        let acknowledge_count = std::cell::Cell::new(0);

        assert!(!supervisor.acknowledge_monitor_control_command_with(
            MonitorControlCommand::Start,
            |_| {
                publish_count.set(publish_count.get() + 1);
                Ok(())
            },
            || {
                acknowledge_count.set(acknowledge_count.get() + 1);
                Ok(())
            },
        ));
        assert_eq!(publish_count.get(), 0);
        assert_eq!(acknowledge_count.get(), 0);
        assert!(!supervisor.desired_monitor_running);
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
    fn exit_request_marks_active_mutation_recovery_before_shutdown() {
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
        supervisor.settings_mutation_active = true;
        let child = spawn_test_exiting_control_child();
        supervisor.settings_child = Some(child);
        let mut published_statuses = Vec::new();

        assert!(
            !supervisor.handle_exit_request_with_monitor_status_writer(|running| {
                published_statuses.push(running);
                Ok(())
            })
        );

        assert!(supervisor.exit_requested);
        assert!(supervisor.settings_child.is_some());
        assert!(supervisor.settings_mutation_active);
        assert!(!supervisor.resume_monitor_after_settings);
        assert!(published_statuses.is_empty());
        assert!(worker_rx.try_recv().is_err());

        wait_for_test_child_exit(&mut supervisor);
        supervisor.poll_settings_window_with_loader(|_| StartupConfig {
            config: AppConfig::default(),
            storage_recovery_ready: true,
        });
        assert!(supervisor.settings_child.is_none());
        assert!(supervisor.storage_recovery_sticky_blocked);
        assert!(!supervisor.storage_recovery_ready);

        assert!(
            supervisor.handle_exit_request_with_monitor_status_writer(|running| {
                published_statuses.push(running);
                Ok(())
            })
        );
        assert_eq!(published_statuses, vec![false]);
        assert!(matches!(worker_rx.try_recv(), Ok(WorkerCommand::Stop)));
        assert!(worker_rx.try_recv().is_err());
    }

    #[test]
    fn settings_exit_timeout_forces_fail_closed_shutdown_for_active_mutation() {
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
        supervisor.settings_mutation_active = true;
        supervisor.settings_child = Some(spawn_test_unacknowledging_control_child());
        let mut published_statuses = Vec::new();

        assert!(
            !supervisor.handle_exit_request_with_monitor_status_writer(|running| {
                published_statuses.push(running);
                Ok(())
            })
        );
        assert!(worker_rx.try_recv().is_err());
        let deadline = supervisor.settings_child_exit_deadline.unwrap();

        assert!(
            supervisor.poll_exit_request_with_monitor_status_writer(deadline, |running| {
                published_statuses.push(running);
                Ok(())
            })
        );

        assert!(supervisor.settings_child.is_none());
        assert!(supervisor.storage_recovery_sticky_blocked);
        assert!(!supervisor.settings_mutation_active);
        assert_eq!(published_statuses, vec![false]);
        assert!(matches!(worker_rx.try_recv(), Ok(WorkerCommand::Stop)));
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
            MonitorControlState::Stopped
        );
        assert!(MonitorControlState::Running.toggle_requests_stop());
        assert_eq!(MonitorControlState::Running.toggle_label(), "Stop Monitor");

        assert_eq!(
            MonitorControlState::from_worker_and_intent(crate::models::WorkerStatus::Idle, true,),
            MonitorControlState::PausedWithStartIntent
        );
        assert!(MonitorControlState::PausedWithStartIntent.toggle_requests_stop());
        assert_eq!(
            MonitorControlState::PausedWithStartIntent.toggle_label(),
            "Stop Monitor"
        );

        assert_eq!(
            MonitorControlState::from_worker_and_intent(crate::models::WorkerStatus::Idle, false,),
            MonitorControlState::Stopped
        );
        assert!(!MonitorControlState::Stopped.toggle_requests_stop());
        assert_eq!(MonitorControlState::Stopped.toggle_label(), "Start Monitor");
    }

    #[test]
    fn stopping_an_idle_deferred_monitor_updates_control_state_without_worker_event() {
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
        supervisor.worker_status = crate::models::WorkerStatus::Idle;
        supervisor.desired_monitor_running = true;
        supervisor.resume_monitor_after_settings = true;
        assert_eq!(
            supervisor.monitor_control_state(),
            MonitorControlState::PausedWithStartIntent
        );

        supervisor.stop_monitor();

        assert_eq!(
            supervisor.monitor_control_state(),
            MonitorControlState::Stopped
        );
        assert_eq!(
            supervisor.last_published_monitor_control_state.get(),
            Some(MonitorControlState::Stopped)
        );
        assert!(!supervisor.resume_monitor_after_settings);
        assert!(matches!(worker_rx.try_recv(), Ok(WorkerCommand::Stop)));
        assert!(worker_rx.try_recv().is_err());
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
        assert_eq!(
            supervisor.monitor_control_state(),
            MonitorControlState::PausedWithStartIntent
        );
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
            // `timeout.exe` exits immediately when stdin is redirected, which
            // makes live-child lifecycle tests pass without exercising their
            // intended wait. `ping.exe` does not depend on console stdin; its
            // first reply is immediate and each additional reply adds roughly
            // one second.
            "sleep 1" => ("ping.exe", &["-n", "2", "127.0.0.1"]),
            "exec sleep 30" => ("ping.exe", &["-n", "31", "127.0.0.1"]),
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

    #[cfg(unix)]
    fn spawn_test_control_child() -> std::process::Child {
        std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("while IFS= read -r line; do printf '%s\\n' \"$line\"; done")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap()
    }

    #[cfg(windows)]
    fn spawn_test_control_child() -> std::process::Child {
        use std::os::windows::process::CommandExt;

        const CREATE_NO_WINDOW: u32 = 0x0800_0000;

        std::process::Command::new("more.com")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .unwrap()
    }

    #[cfg(unix)]
    fn spawn_test_control_child_with_stderr_noise() -> std::process::Child {
        std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("IFS= read -r line; printf 'ordinary diagnostic\\n' >&2; printf '%s\\n' \"$line\"")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap()
    }

    #[cfg(windows)]
    fn spawn_test_control_child_with_stderr_noise() -> std::process::Child {
        use std::os::windows::process::CommandExt;

        const CREATE_NO_WINDOW: u32 = 0x0800_0000;

        std::process::Command::new("cmd.exe")
            .args([
                "/D",
                "/Q",
                "/V:ON",
                "/C",
                "set /p line=& echo ordinary diagnostic 1>&2 & echo !line!",
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .unwrap()
    }

    #[cfg(unix)]
    fn spawn_test_unacknowledging_control_child() -> std::process::Child {
        std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("exec sleep 30")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap()
    }

    #[cfg(windows)]
    fn spawn_test_unacknowledging_control_child() -> std::process::Child {
        use std::os::windows::process::CommandExt;

        const CREATE_NO_WINDOW: u32 = 0x0800_0000;

        std::process::Command::new("cmd.exe")
            .args(["/D", "/Q", "/C", "ping -n 30 127.0.0.1 >NUL"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .unwrap()
    }

    #[cfg(unix)]
    fn spawn_test_exiting_control_child() -> std::process::Child {
        std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("IFS= read -r line; exit 0")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap()
    }

    #[cfg(windows)]
    fn spawn_test_exiting_control_child() -> std::process::Child {
        use std::os::windows::process::CommandExt;

        const CREATE_NO_WINDOW: u32 = 0x0800_0000;

        std::process::Command::new("cmd.exe")
            .args(["/D", "/Q", "/C", "set /p line=& exit /b 0"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .unwrap()
    }

    #[cfg(unix)]
    fn spawn_test_invalid_ack_control_child() -> std::process::Child {
        std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("IFS= read -r line; printf 'invalid\\n'; exec sleep 30")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap()
    }

    #[cfg(windows)]
    fn spawn_test_invalid_ack_control_child() -> std::process::Child {
        use std::os::windows::process::CommandExt;

        const CREATE_NO_WINDOW: u32 = 0x0800_0000;

        std::process::Command::new("cmd.exe")
            .args([
                "/D",
                "/Q",
                "/C",
                "set /p line=& echo invalid & ping -n 30 127.0.0.1 >NUL",
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
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
}
