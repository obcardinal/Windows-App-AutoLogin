use crate::models::MonitorControlState;
use std::cell::Cell;
use std::sync::mpsc::Sender;
use tray_icon::{
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
    TrayIconBuilder,
};

#[cfg(target_os = "windows")]
mod windows_visibility;

#[derive(Debug, Clone)]
pub(crate) enum TrayCommand {
    OpenAccounts,
    OpenSettings,
    OpenAbout,
    PresentAccounts(Sender<()>),
    PresentSettings(Sender<()>),
    ToggleMonitor,
    Exit,
}

pub(crate) struct AppTray {
    _tray: tray_icon::TrayIcon,
    diagnostic_menu: Menu,
    compact_menu: Menu,
    diagnostics_visible: Cell<bool>,
    #[cfg(target_os = "windows")]
    windows_visibility: windows_visibility::WindowsTrayVisibility,
    monitor_i: MenuItem,
    #[cfg(not(target_os = "windows"))]
    accessibility_i: Option<MenuItem>,
    keychain_i: MenuItem,
    last_result_i: MenuItem,
}

impl AppTray {
    pub(crate) fn set_diagnostics_visible(&self, visible: bool) {
        if self.diagnostics_visible.get() == visible {
            return;
        }
        let menu = if visible {
            &self.diagnostic_menu
        } else {
            &self.compact_menu
        };
        self._tray.set_menu(Some(Box::new(menu.clone())));
        self.diagnostics_visible.set(visible);
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn set_icon_hidden(&self, hidden: bool) -> anyhow::Result<()> {
        self._tray.set_visible(!hidden)?;
        Ok(())
    }

    #[cfg(target_os = "windows")]
    pub(crate) fn set_icon_hidden(&self, hidden: bool) -> anyhow::Result<()> {
        self.windows_visibility.set_hidden(hidden)
    }

    pub(crate) fn set_monitor_control_state(&self, state: MonitorControlState) {
        self.monitor_i.set_text(state.toggle_label());
    }

    pub(crate) fn set_accessibility_trusted(&self, trusted: bool) {
        #[cfg(target_os = "windows")]
        let _ = trusted;

        #[cfg(not(target_os = "windows"))]
        if let Some(accessibility_i) = &self.accessibility_i {
            accessibility_i.set_text(automation_status_label(trusted));
        }
    }

    pub(crate) fn set_keychain_enabled(&self, enabled: bool) {
        self.keychain_i.set_text(secure_storage_label(enabled));
    }

    pub(crate) fn set_last_result(&self, result: &str) {
        self.last_result_i.set_text(format!("Last fill: {result}"));
    }
}

pub(crate) fn setup_tray(tx: Sender<TrayCommand>) -> anyhow::Result<AppTray> {
    let menu = Menu::new();
    let accounts_i = MenuItem::new("Accounts", true, None);
    let settings_i = MenuItem::new("Settings…", true, None);
    let about_i = MenuItem::new("About Windows App AutoLogin", true, None);
    let toggle_i = MenuItem::new("Start Monitor", true, None);
    let accessibility_i = automation_status_item();
    let keychain_i = MenuItem::new("Password storage: Checking", false, None);
    let last_result_i = MenuItem::new("Last fill: none", false, None);
    let status_separator = PredefinedMenuItem::separator();
    let about_separator = PredefinedMenuItem::separator();
    let settings_separator = PredefinedMenuItem::separator();
    let quit_separator = PredefinedMenuItem::separator();
    let quit_i = MenuItem::new("Quit Windows App AutoLogin", true, None);

    #[cfg(target_os = "macos")]
    {
        use tray_icon::menu::accelerator::{Key, KeyAccelerator, Modifiers};
        settings_i.set_key_accelerator(Some(KeyAccelerator::new(
            Some(Modifiers::SUPER),
            Key::Character(",".into()),
        )))?;
        quit_i.set_key_accelerator(Some(KeyAccelerator::new(
            Some(Modifiers::SUPER),
            Key::Character("q".into()),
        )))?;
    }

    // Both menus share item handles, so commands keep their IDs and status updates
    // made while diagnostics are hidden are visible immediately when restored.
    let compact_menu = Menu::new();
    for (menu, diagnostics_visible) in [(&menu, true), (&compact_menu, false)] {
        menu.append(&accounts_i)?;
        menu.append(&toggle_i)?;
        if diagnostics_visible {
            menu.append(&status_separator)?;
            if let Some(accessibility_i) = &accessibility_i {
                menu.append(accessibility_i)?;
            }
            menu.append(&keychain_i)?;
            menu.append(&last_result_i)?;
        }
        menu.append(&about_separator)?;
        menu.append(&about_i)?;
        menu.append(&settings_separator)?;
        menu.append(&settings_i)?;
        menu.append(&quit_separator)?;
        menu.append(&quit_i)?;
    }

    let icon = load_icon()?;

    let tray = TrayIconBuilder::new()
        .with_menu(Box::new(compact_menu.clone()))
        .with_tooltip("Windows App AutoLogin")
        .with_icon(icon)
        .with_icon_as_template(tray_icon_uses_template_rendering())
        .build()?;
    #[cfg(target_os = "windows")]
    let windows_visibility = windows_visibility::WindowsTrayVisibility::new(tray.clone());

    let accounts_id = accounts_i.id().clone();
    let settings_id = settings_i.id().clone();
    let about_id = about_i.id().clone();
    let toggle_id = toggle_i.id().clone();
    let quit_id = quit_i.id().clone();

    let tx_accounts = tx.clone();
    let tx_settings = tx.clone();
    let tx_about = tx.clone();
    let tx_toggle = tx.clone();
    let tx_quit = tx.clone();

    std::thread::spawn(move || {
        let menu_channel = MenuEvent::receiver();
        loop {
            if let Ok(event) = menu_channel.recv() {
                if event.id == accounts_id {
                    let _ = tx_accounts.send(TrayCommand::OpenAccounts);
                    continue;
                }
                if event.id == settings_id {
                    let _ = tx_settings.send(TrayCommand::OpenSettings);
                    continue;
                }
                if event.id == about_id {
                    let _ = tx_about.send(TrayCommand::OpenAbout);
                    continue;
                }
                if event.id == toggle_id {
                    let _ = tx_toggle.send(TrayCommand::ToggleMonitor);
                    continue;
                }
                if event.id == quit_id {
                    let _ = tx_quit.send(TrayCommand::Exit);
                    break;
                }
            }
        }
    });

    Ok(AppTray {
        _tray: tray,
        diagnostic_menu: menu,
        compact_menu,
        diagnostics_visible: Cell::new(false),
        #[cfg(target_os = "windows")]
        windows_visibility,
        monitor_i: toggle_i,
        #[cfg(not(target_os = "windows"))]
        accessibility_i,
        keychain_i,
        last_result_i,
    })
}

#[cfg(not(target_os = "windows"))]
fn automation_status_item() -> Option<MenuItem> {
    Some(MenuItem::new(automation_status_label(false), false, None))
}

#[cfg(target_os = "windows")]
fn automation_status_item() -> Option<MenuItem> {
    None
}

#[cfg(not(target_os = "windows"))]
fn automation_status_label(ready: bool) -> &'static str {
    #[cfg(target_os = "macos")]
    {
        if ready {
            "Accessibility: Ready"
        } else {
            "Accessibility: Missing"
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        if ready {
            "Automation: Ready"
        } else {
            "Automation: Missing"
        }
    }
}

fn secure_storage_label(enabled: bool) -> &'static str {
    if enabled {
        "Password storage: System store"
    } else {
        "Password storage: Encrypted file"
    }
}

fn load_icon() -> anyhow::Result<tray_icon::Icon> {
    #[cfg(target_os = "macos")]
    let icon_bytes = include_bytes!("../assets/icon_tray.png");
    #[cfg(not(target_os = "macos"))]
    let icon_bytes = include_bytes!("../assets/icon.png");
    let image = image::load_from_memory(icon_bytes)?;
    // AppKit renders the template at 18 points; retain enough pixels for Retina displays.
    // Windows uses the colored application mark because it does not tint template images.
    let size = if cfg!(target_os = "macos") { 128 } else { 32 };
    let rgba = image
        .resize(size, size, image::imageops::FilterType::Lanczos3)
        .into_rgba8();
    let (width, height) = rgba.dimensions();
    Ok(tray_icon::Icon::from_rgba(rgba.into_raw(), width, height)?)
}

fn tray_icon_uses_template_rendering() -> bool {
    cfg!(target_os = "macos")
}
