use std::sync::mpsc::Sender;
use tray_icon::{
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
    TrayIconBuilder,
};

#[derive(Debug, Clone)]
pub(crate) enum TrayCommand {
    OpenSettings,
    ToggleMonitor,
    RequestAccessibilityAccess,
    OpenAccessibilitySettings,
    Exit,
}

pub(crate) struct AppTray {
    _tray: tray_icon::TrayIcon,
    monitor_i: MenuItem,
    accessibility_i: MenuItem,
    keychain_i: MenuItem,
    last_result_i: MenuItem,
}

impl AppTray {
    pub(crate) fn set_monitor_running(&self, running: bool) {
        self.monitor_i.set_text(if running {
            "Stop Monitor"
        } else {
            "Start Monitor"
        });
    }

    pub(crate) fn set_accessibility_trusted(&self, trusted: bool) {
        self.accessibility_i.set_text(if trusted {
            "Accessibility: Ready"
        } else {
            "Accessibility: Missing"
        });
    }

    pub(crate) fn set_keychain_enabled(&self, enabled: bool) {
        self.keychain_i.set_text(if enabled {
            "Keychain: Enabled"
        } else {
            "Keychain: Disabled"
        });
    }

    pub(crate) fn set_last_result(&self, result: &str) {
        self.last_result_i.set_text(format!("Last fill: {result}"));
    }
}

pub(crate) fn setup_tray(tx: Sender<TrayCommand>) -> anyhow::Result<AppTray> {
    let menu = Menu::new();
    let settings_i = MenuItem::new("Open Settings", true, None);
    let toggle_i = MenuItem::new("Start Monitor", true, None);
    let request_accessibility_i = MenuItem::new("Request Accessibility Access", true, None);
    let open_accessibility_i = MenuItem::new("Open Accessibility Settings", true, None);
    let accessibility_i = MenuItem::new("Accessibility: Checking", false, None);
    let keychain_i = MenuItem::new("Keychain: Checking", false, None);
    let last_result_i = MenuItem::new("Last fill: none", false, None);
    let separator = PredefinedMenuItem::separator();
    let quit_i = MenuItem::new("Quit", true, None);

    menu.append(&settings_i)?;
    menu.append(&toggle_i)?;
    menu.append(&separator)?;
    menu.append(&request_accessibility_i)?;
    menu.append(&open_accessibility_i)?;
    menu.append(&separator)?;
    menu.append(&accessibility_i)?;
    menu.append(&keychain_i)?;
    menu.append(&last_result_i)?;
    menu.append(&separator)?;
    menu.append(&quit_i)?;

    let icon = load_icon()?;

    let tray = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip("Windows App AutoLogin")
        .with_icon(icon)
        .with_icon_as_template(false)
        .build()?;

    let settings_id = settings_i.id().clone();
    let toggle_id = toggle_i.id().clone();
    let request_accessibility_id = request_accessibility_i.id().clone();
    let open_accessibility_id = open_accessibility_i.id().clone();
    let quit_id = quit_i.id().clone();

    let tx_settings = tx.clone();
    let tx_toggle = tx.clone();
    let tx_request_accessibility = tx.clone();
    let tx_open_accessibility = tx.clone();
    let tx_quit = tx.clone();

    std::thread::spawn(move || {
        let menu_channel = MenuEvent::receiver();
        loop {
            if let Ok(event) = menu_channel.recv() {
                if event.id == settings_id {
                    let _ = tx_settings.send(TrayCommand::OpenSettings);
                } else if event.id == toggle_id {
                    let _ = tx_toggle.send(TrayCommand::ToggleMonitor);
                } else if event.id == request_accessibility_id {
                    let _ = tx_request_accessibility.send(TrayCommand::RequestAccessibilityAccess);
                } else if event.id == open_accessibility_id {
                    let _ = tx_open_accessibility.send(TrayCommand::OpenAccessibilitySettings);
                } else if event.id == quit_id {
                    let _ = tx_quit.send(TrayCommand::Exit);
                    break;
                }
            }
        }
    });

    Ok(AppTray {
        _tray: tray,
        monitor_i: toggle_i,
        accessibility_i,
        keychain_i,
        last_result_i,
    })
}

fn load_icon() -> anyhow::Result<tray_icon::Icon> {
    let icon_bytes = include_bytes!("../assets/icon_tray.png");
    let image = image::load_from_memory(icon_bytes)?;
    let rgba = image.into_rgba8();
    let (width, height) = rgba.dimensions();
    Ok(tray_icon::Icon::from_rgba(rgba.into_raw(), width, height)?)
}
