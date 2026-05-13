use std::sync::mpsc::Sender;
use tray_icon::{
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
    TrayIconBuilder,
};

#[derive(Debug, Clone)]
pub(crate) enum TrayCommand {
    OpenAccounts,
    OpenSettings,
    ToggleMonitor,
    RequestAccessibilityAccess,
    OpenAccessibilitySettings,
    Exit,
}

pub(crate) struct AppTray {
    _tray: tray_icon::TrayIcon,
    monitor_i: MenuItem,
    #[cfg(not(target_os = "windows"))]
    accessibility_i: Option<MenuItem>,
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
    let settings_i = MenuItem::new("Settings", true, None);
    let toggle_i = MenuItem::new("Start Monitor", true, None);
    let request_accessibility_i = automation_request_item();
    let open_accessibility_i = automation_settings_item();
    let accessibility_i = automation_status_item();
    let keychain_i = MenuItem::new("Secure storage: Checking", false, None);
    let last_result_i = MenuItem::new("Last fill: none", false, None);
    let permission_separator = PredefinedMenuItem::separator();
    let status_separator = PredefinedMenuItem::separator();
    let quit_separator = PredefinedMenuItem::separator();
    let quit_i = MenuItem::new("Quit", true, None);

    menu.append(&accounts_i)?;
    menu.append(&settings_i)?;
    menu.append(&toggle_i)?;
    if let Some(request_accessibility_i) = &request_accessibility_i {
        menu.append(&permission_separator)?;
        menu.append(request_accessibility_i)?;
    }
    if let Some(open_accessibility_i) = &open_accessibility_i {
        menu.append(open_accessibility_i)?;
    }
    menu.append(&status_separator)?;
    if let Some(accessibility_i) = &accessibility_i {
        menu.append(accessibility_i)?;
    }
    menu.append(&keychain_i)?;
    menu.append(&last_result_i)?;
    menu.append(&quit_separator)?;
    menu.append(&quit_i)?;

    let icon = load_icon()?;

    let tray = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip("Windows App AutoLogin")
        .with_icon(icon)
        .with_icon_as_template(tray_icon_uses_template_rendering())
        .build()?;

    let accounts_id = accounts_i.id().clone();
    let settings_id = settings_i.id().clone();
    let toggle_id = toggle_i.id().clone();
    let request_accessibility_id = request_accessibility_i
        .as_ref()
        .map(|item| item.id().clone());
    let open_accessibility_id = open_accessibility_i.as_ref().map(|item| item.id().clone());
    let quit_id = quit_i.id().clone();

    let tx_accounts = tx.clone();
    let tx_settings = tx.clone();
    let tx_toggle = tx.clone();
    let tx_request_accessibility = tx.clone();
    let tx_open_accessibility = tx.clone();
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
                if event.id == toggle_id {
                    let _ = tx_toggle.send(TrayCommand::ToggleMonitor);
                    continue;
                }
                if request_accessibility_id
                    .as_ref()
                    .is_some_and(|id| id == &event.id)
                {
                    let _ = tx_request_accessibility.send(TrayCommand::RequestAccessibilityAccess);
                    continue;
                }
                if open_accessibility_id
                    .as_ref()
                    .is_some_and(|id| id == &event.id)
                {
                    let _ = tx_open_accessibility.send(TrayCommand::OpenAccessibilitySettings);
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
        monitor_i: toggle_i,
        #[cfg(not(target_os = "windows"))]
        accessibility_i,
        keychain_i,
        last_result_i,
    })
}

#[cfg(not(target_os = "windows"))]
fn automation_request_item() -> Option<MenuItem> {
    Some(MenuItem::new(
        automation_request_label(),
        automation_settings_available(),
        None,
    ))
}

#[cfg(target_os = "windows")]
fn automation_request_item() -> Option<MenuItem> {
    None
}

#[cfg(not(target_os = "windows"))]
fn automation_settings_item() -> Option<MenuItem> {
    Some(MenuItem::new(
        automation_settings_label(),
        automation_settings_available(),
        None,
    ))
}

#[cfg(target_os = "windows")]
fn automation_settings_item() -> Option<MenuItem> {
    None
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
fn automation_request_label() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "Request Accessibility Access"
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        "Automation Ready"
    }
}

#[cfg(not(target_os = "windows"))]
fn automation_settings_label() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "Open Accessibility Settings"
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        "No Permission Setup Needed"
    }
}

#[cfg(not(target_os = "windows"))]
fn automation_settings_available() -> bool {
    cfg!(target_os = "macos")
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
        "Secure storage: Enabled"
    } else {
        "Secure storage: Disabled"
    }
}

fn load_icon() -> anyhow::Result<tray_icon::Icon> {
    let icon_bytes = include_bytes!("../assets/icon_tray.png");
    let image = image::load_from_memory(icon_bytes)?;
    let rgba = image.into_rgba8();
    let (width, height) = rgba.dimensions();
    Ok(tray_icon::Icon::from_rgba(rgba.into_raw(), width, height)?)
}

fn tray_icon_uses_template_rendering() -> bool {
    cfg!(target_os = "macos")
}

#[cfg(test)]
mod tests {
    use super::tray_icon_uses_template_rendering;

    #[test]
    fn template_rendering_is_only_enabled_on_macos() {
        assert_eq!(
            tray_icon_uses_template_rendering(),
            cfg!(target_os = "macos")
        );
    }
}
