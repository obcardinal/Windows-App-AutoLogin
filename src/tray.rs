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
    #[cfg(target_os = "macos")]
    CheckForUpdates,
    PresentAccounts(Sender<()>),
    PresentSettings(Sender<()>),
    #[cfg(target_os = "macos")]
    SetMacosPresentation(crate::macos_panel::Presentation),
    #[cfg(target_os = "macos")]
    OpenMacosContextMenu,
    #[cfg(target_os = "macos")]
    ToggleMacosPanel(u64, Option<crate::macos_panel::PanelAnchor>),
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
    #[cfg(target_os = "macos")]
    updates_i: MenuItem,
    #[cfg(not(target_os = "windows"))]
    accessibility_i: Option<MenuItem>,
    keychain_i: MenuItem,
    last_result_i: MenuItem,
}

impl AppTray {
    #[cfg(target_os = "macos")]
    pub(crate) fn set_updates_enabled(&self, enabled: bool) {
        self.updates_i.set_enabled(enabled);
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn show_context_menu(&self) {
        use objc2_app_kit::NSMenu;
        use objc2_foundation::MainThreadMarker;
        use tray_icon::menu::ContextMenu;

        let Some(mtm) = MainThreadMarker::new() else {
            return;
        };
        let Some(status_item) = self.status_item() else {
            return;
        };
        let Some(button) = status_item.button(mtm) else {
            return;
        };
        if button.window().is_none() {
            return;
        }
        let menu = self.current_menu();
        // Let NSStatusItem position its menu beneath the menu-bar icon. A
        // generic NSView popup can align around the pointer and jump above the
        // menu bar. Attach only for this synchronous right-click tracking;
        // keeping the menu attached would consume the next left click.
        // SAFETY: Menu owns this NSMenu for the complete synchronous call and
        // all AppKit access occurs on its main thread.
        unsafe {
            let native_menu = &*menu.ns_menu().cast::<NSMenu>();
            status_item.setMenu(Some(native_menu));
            button.performClick(None);
            status_item.setMenu(None);
        }
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn status_item(&self) -> Option<objc2::rc::Retained<objc2_app_kit::NSStatusItem>> {
        self._tray.ns_status_item()
    }

    pub(crate) fn set_diagnostics_visible(&self, visible: bool) {
        if self.diagnostics_visible.get() == visible {
            return;
        }
        self.diagnostics_visible.set(visible);
        // On macOS a menu attached to NSStatusItem consumes the left click
        // before tray-icon can deliver it, even with menu_on_left_click=false.
        // Keep both menus detached and open the current one on right release.
        #[cfg(not(target_os = "macos"))]
        self._tray
            .set_menu(Some(Box::new(self.current_menu().clone())));
    }

    fn current_menu(&self) -> &Menu {
        if self.diagnostics_visible.get() {
            &self.diagnostic_menu
        } else {
            &self.compact_menu
        }
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
        #[cfg(target_os = "macos")]
        let changed = self.monitor_i.text() != state.toggle_label();
        self.monitor_i.set_text(state.toggle_label());
        #[cfg(target_os = "macos")]
        if changed {
            let symbol = if state.toggle_requests_stop() {
                "stop"
            } else {
                "play"
            };
            for menu in [&self.diagnostic_menu, &self.compact_menu] {
                set_macos_menu_symbol(menu, state.toggle_label(), symbol);
            }
        }
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
    #[cfg(target_os = "macos")]
    let updates_i = MenuItem::new("Check for Updates…", true, None);
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
        #[cfg(target_os = "macos")]
        menu.append(&updates_i)?;
        menu.append(&quit_separator)?;
        menu.append(&quit_i)?;
        #[cfg(target_os = "macos")]
        {
            set_macos_menu_symbol(menu, "Accounts", "person.2");
            set_macos_menu_symbol(menu, "Start Monitor", "play");
        }
    }

    let icon = load_icon()?;

    let tray_builder = TrayIconBuilder::new()
        .with_tooltip("Windows App AutoLogin")
        .with_icon(icon)
        .with_icon_as_template(tray_icon_uses_template_rendering());
    #[cfg(not(target_os = "macos"))]
    let tray_builder = tray_builder.with_menu(Box::new(compact_menu.clone()));
    #[cfg(target_os = "macos")]
    let tray_builder = {
        // tray-icon fixes its process-wide handler on the first event. Install
        // it before creating the status item and keep its ID stable on retries.
        let builder = tray_builder
            .with_id("windows-app-autologin")
            .with_menu_on_left_click(false)
            .with_menu_on_right_click(false);
        register_macos_tray_clicks(builder.id().clone(), tx.clone());
        builder
    };
    let tray = tray_builder.build()?;
    #[cfg(target_os = "windows")]
    let windows_visibility = windows_visibility::WindowsTrayVisibility::new(tray.clone());

    let accounts_id = accounts_i.id().clone();
    let settings_id = settings_i.id().clone();
    #[cfg(target_os = "macos")]
    let updates_id = updates_i.id().clone();
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
                #[cfg(target_os = "macos")]
                if event.id == updates_id {
                    let _ = tx.send(TrayCommand::CheckForUpdates);
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
        #[cfg(target_os = "macos")]
        updates_i,
        #[cfg(not(target_os = "windows"))]
        accessibility_i,
        keychain_i,
        last_result_i,
    })
}

#[cfg(target_os = "macos")]
fn set_macos_menu_symbol(menu: &Menu, title: &str, symbol: &str) {
    use objc2_app_kit::{NSImage, NSMenu};
    use objc2_foundation::{MainThreadMarker, NSSize, NSString};
    use tray_icon::menu::ContextMenu;

    let Some(_mtm) = MainThreadMarker::new() else {
        return;
    };
    // Muda owns each native item and keeps its command ID. Decorate both menu
    // copies directly so SF Symbols follow macOS appearance and highlighting.
    // SAFETY: Menu retains this NSMenu; all access is on the AppKit main thread.
    let native_menu = unsafe { &*menu.ns_menu().cast::<NSMenu>() };
    let title = NSString::from_str(title);
    let Some(item) = native_menu.itemWithTitle(&title) else {
        return;
    };
    if let Some(image) = NSImage::imageWithSystemSymbolName_accessibilityDescription(
        &NSString::from_str(symbol),
        None,
    ) {
        image.setSize(NSSize::new(16.0, 16.0));
        image.setTemplate(true);
        item.setImage(Some(&image));
        if objc2::available!(macos = 27.0) {
            // AppKit 27 normally hides menu images with automatic visibility.
            // SAFETY: The version check guards this NSMenuItem setter, whose
            // parameter is NSMenuItemImageVisibility (NSInteger in the SDK).
            const IMAGE_VISIBILITY_VISIBLE: isize = 1;
            let _: () = unsafe {
                objc2::msg_send![&*item, setPreferredImageVisibility: IMAGE_VISIBILITY_VISIBLE]
            };
        }
    }
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

#[cfg(target_os = "macos")]
fn register_macos_tray_clicks(tray_id: tray_icon::TrayIconId, tx: Sender<TrayCommand>) {
    use std::sync::atomic::AtomicU64;
    use tray_icon::TrayIconEvent;

    let pending_press_id = AtomicU64::new(0);
    TrayIconEvent::set_event_handler(Some(move |event| {
        if let Some(command) = macos_tray_click(
            &event,
            &tray_id,
            &pending_press_id,
            crate::macos_panel::left_mouse_press_id,
        ) {
            tracing::debug!(target: "waal::panel", ?command, "Status item released");
            let _ = tx.send(command);
        }
    }));
}

#[cfg(target_os = "macos")]
fn macos_tray_click(
    event: &tray_icon::TrayIconEvent,
    tray_id: &tray_icon::TrayIconId,
    pending_press_id: &std::sync::atomic::AtomicU64,
    press_id: impl FnOnce() -> u64,
) -> Option<TrayCommand> {
    use std::sync::atomic::Ordering;
    use tray_icon::{MouseButton, MouseButtonState, TrayIconEvent};

    let TrayIconEvent::Click {
        id,
        button,
        button_state,
        ..
    } = event
    else {
        return None;
    };
    if id != tray_id {
        return None;
    }
    match (button, button_state) {
        (MouseButton::Left, MouseButtonState::Down) => {
            // Clicking the status item can blur the panel before mouse-up.
            pending_press_id.store(press_id(), Ordering::Relaxed);
            None
        }
        (MouseButton::Left, MouseButtonState::Up) => {
            let down = pending_press_id.swap(0, Ordering::Relaxed);
            let press = if down == 0 { press_id() } else { down };
            Some(TrayCommand::ToggleMacosPanel(press, None))
        }
        (MouseButton::Right, MouseButtonState::Up) => Some(TrayCommand::OpenMacosContextMenu),
        _ => None,
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::{macos_tray_click, TrayCommand};
    use std::sync::atomic::AtomicU64;
    use tray_icon::{MouseButton, MouseButtonState, Rect, TrayIconEvent, TrayIconId};

    #[test]
    fn each_own_left_release_preserves_its_press_id_and_right_click_opens_the_menu() {
        let own_id = TrayIconId::new("autologin");
        let other_id = TrayIconId::new("another-app");
        let pending_press_id = AtomicU64::new(0);
        let click = |id: &TrayIconId, button, button_state, press_id| {
            let event = TrayIconEvent::Click {
                id: id.clone(),
                position: Default::default(),
                rect: Rect::default(),
                button,
                button_state,
            };
            macos_tray_click(&event, &own_id, &pending_press_id, || press_id)
        };
        use MouseButton::{Left, Middle, Right};
        use MouseButtonState::{Down, Up};
        assert!(click(&own_id, Left, Down, 100).is_none());
        assert!(click(&other_id, Left, Down, 110).is_none());
        assert!(click(&other_id, Left, Up, 120).is_none());
        assert!(matches!(
            click(&own_id, Left, Up, 300),
            Some(TrayCommand::ToggleMacosPanel(100, None))
        ));
        assert!(click(&own_id, Left, Down, 310).is_none());
        assert!(matches!(
            click(&own_id, Left, Up, 312),
            Some(TrayCommand::ToggleMacosPanel(310, None))
        ));
        assert!(matches!(
            click(&own_id, Left, Up, 315),
            Some(TrayCommand::ToggleMacosPanel(315, None))
        ));
        assert!(click(&own_id, Right, Down, 320).is_none());
        assert!(matches!(
            click(&own_id, Right, Up, 321),
            Some(TrayCommand::OpenMacosContextMenu)
        ));
        assert!(click(&other_id, Right, Up, 330).is_none());
        assert!(click(&own_id, Middle, Up, 340).is_none());
        let movement = TrayIconEvent::Move {
            id: own_id.clone(),
            position: Default::default(),
            rect: Rect::default(),
        };
        assert!(macos_tray_click(&movement, &own_id, &pending_press_id, || 350).is_none());
    }
}
