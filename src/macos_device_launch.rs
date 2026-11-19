//! Launch the saved Windows App device so its workspace and gateway settings apply.
use super::desktops::LaunchHost;
use super::{
    collect_descendants_bounded, macos_identity, role_matches, AXUIElementSetAttributeValue,
    AxElement, AX_CHILDREN, AX_DESCRIPTION, AX_ENABLED, AX_FRONTMOST, AX_PRESS, AX_ROLE,
    AX_SUBROLE, AX_TITLE, AX_VALUE, AX_WINDOWS, K_AX_ERROR_SUCCESS,
};
use crate::config::TARGET_APP_NAME;
use anyhow::{ensure, Context, Result};
use core_foundation::{array::CFArray, base::TCFType, string::CFString};
use std::time::{Duration, Instant};

#[path = "macos_device_catalog.rs"]
mod catalog;
#[path = "macos_connected_card.rs"]
mod connected;
#[path = "macos_connection_center.rs"]
mod connection_center;
#[path = "macos_enter_profile.rs"]
mod enter_profile;
pub(super) use catalog::verify_card_identity_in;
pub(crate) use catalog::{saved_devices, saved_remote_pc, SavedDevice};
pub(super) use connection_center::ConnectionCenter;
use enter_profile::prepare_profile_devices;

const READ_ERROR: &str = "Could not read the Windows App Devices view.";
const SELECTION_ERROR: &str = "Windows App could not select the saved device.";
const SELECTED_CHILDREN: &str = "AXSelectedChildren";
const PROFILE_ERROR: &str = "Could not verify the current Windows App account for this desktop.";

struct DeviceList {
    app: AxElement,
    window: AxElement,
    collection: AxElement,
    devices: Vec<(String, AxElement)>,
}

pub(crate) fn open_saved_device(device: &SavedDevice) -> Result<()> {
    if device.id.starts_with("workspace:") && !device.owner.trim().is_empty() {
        let app = trusted_app()?;
        let (list, profile) = prepare_profile_devices(&app, &device.owner, || Ok(()))?;
        catalog::verify_card_identity(device)?;
        return list.connect(&device.name, || {
            list.ensure_profile(&profile)?;
            catalog::verify_card_identity(device)
        });
    }
    open_saved_device_if(device, || Ok(()))
}

pub(super) fn open_saved_device_if(
    device: &SavedDevice,
    before_connect: impl FnOnce() -> Result<()>,
) -> Result<()> {
    catalog::verify_card_identity(device)?;
    let list = devices_in_app(trusted_app()?)?;
    list.connect(&device.name, || {
        catalog::verify_card_identity(device)?;
        before_connect()
    })
}

/// Window-only bindings predate a stable resource ID. The native Devices view
/// can still reconnect the exact card under the account that owns the binding.
pub(crate) fn reconnect_window_device(
    name: &str,
    account_email: &str,
    host: Option<&LaunchHost>,
) -> Result<()> {
    let app = trusted_app()?;
    ensure!(
        !name.trim().is_empty(),
        "Choose a desktop in the account editor."
    );
    let (list, profile) = prepare_profile_devices(&app, account_email, || Ok(()))?;
    let selected = launch_card_name(&list.devices, name, host, |card| {
        list.ensure_profile(&profile)?;
        connected::cloud_pc_device_name(&app, &list.window, card)
    })?;
    // On repeated Enter Windows App may already have a newly named session.
    if selected != name && super::device_windows::focus_open_session(selected)? {
        return Ok(());
    }
    list.connect(selected, || list.ensure_profile(&profile))
}

pub(super) struct VerifiedWindowDevice {
    center: AxElement,
    profile: String,
    card: String,
}

impl VerifiedWindowDevice {
    pub(super) fn reconnect(
        self,
        app: &AxElement,
        before_connect: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        let center = devices_window(app)?;
        ensure!(
            center.same_element(&self.center),
            "The Windows App Connection Center changed."
        );
        // Closing a VM can rebuild the Devices list. Resolve its card again under
        // the profile whose unique toolbar label we matched to the email before Close.
        let list = devices_from_window(app.clone(), center)?;
        list.ensure_profile(&self.profile)?;
        list.connect(&self.card, || {
            before_connect()?;
            list.ensure_profile(&self.profile)
        })
    }
}

fn launch_card_name<'a, T>(
    cards: &'a [(String, T)],
    title: &str,
    host: Option<&LaunchHost>,
    mut read_device_name: impl FnMut(&T) -> Result<Option<String>>,
) -> Result<&'a str> {
    if let Some((name, _)) = cards.iter().find(|(name, _)| name == title) {
        exact_device(cards, name)?;
        return Ok(name);
    }
    let host = host.context("The saved device was not found. Choose its current name in the account editor or set its Remote PC address.")?;
    let mut matched = None;
    for (name, card) in cards {
        if read_device_name(card)?.is_some_and(|reported| host.matches(&reported)) {
            ensure!(matched.is_none(), "Multiple Windows App devices match this Remote PC. Choose the intended device in the account editor.");
            exact_device(cards, name)?;
            matched = Some(name.as_str());
        }
    }
    matched.context("No Cloud PC in the selected Windows App profile matches this account’s Remote PC. Check the address or choose the device in the account editor.")
}

/// Preflight a window-only binding through the client's current Devices view
/// before disconnecting. Only a verified endpoint can authorize a profile switch.
pub(super) fn verify_window_device(
    app: &AxElement,
    name: &str,
    email: &str,
    only_open_session: bool,
    before_switch: impl FnOnce() -> Result<()>,
    cancelled: &impl Fn() -> bool,
) -> Result<VerifiedWindowDevice> {
    ensure!(
        !cancelled() && app.bool_attr(AX_FRONTMOST) == Some(true),
        "The active desktop changed."
    );
    let (list, profile) = prepare_profile_devices(app, email, || {
        ensure!(!cancelled(), "Cancelled.");
        before_switch()
    })?;
    let check_center = || {
        ensure!(
            !cancelled()
                && app.bool_attr(AX_FRONTMOST) == Some(true)
                && app
                    .element_attr("AXFocusedWindow")
                    .is_some_and(|w| w.same_element(&list.window)),
            "The Windows App Devices view lost focus."
        );
        list.ensure_profile(&profile)
    };
    let card = reconnect_card(&list.devices, name, only_open_session, |item| {
        check_center()?;
        let entries = super::device_windows::session_entries(app)?;
        ensure!(
            matches!(entries.as_slice(), [(title, _)] if title == name),
            "The connected desktop changed."
        );
        connected::connected_card(app, &list.window, item)
    })?;
    check_center()?;
    ensure!(!card.trim().is_empty(), SELECTION_ERROR);
    Ok(VerifiedWindowDevice {
        center: list.window,
        profile,
        card: card.to_owned(),
    })
}

fn reconnect_card<'a, T>(
    cards: &'a [(String, T)],
    title: &str,
    only_open_session: bool,
    mut connected: impl FnMut(&T) -> Result<bool>,
) -> Result<&'a str> {
    if let Some((name, _)) = cards.iter().find(|(name, _)| name == title) {
        exact_device(cards, name)?;
        return Ok(name);
    }
    // Windows App may keep the original title in the open window. When
    // exactly one session is open, its connected card identifies that VM.
    if only_open_session {
        let mut matched = None;
        for (name, item) in cards {
            if connected(item)? {
                ensure!(
                    matched.is_none(),
                    "Windows App shows several connected desktops."
                );
                exact_device(cards, name)?;
                matched = Some(name.as_str());
            }
        }
        if let Some(name) = matched {
            return Ok(name);
        }
    }
    anyhow::bail!("Windows App could not identify the connected desktop in Devices.")
}

pub(super) fn verify_saved_card(
    app: &AxElement,
    device: &SavedDevice,
    cancelled: &impl Fn() -> bool,
) -> Result<()> {
    ensure!(
        !cancelled() && app.bool_attr(AX_FRONTMOST) == Some(true),
        "The active desktop changed."
    );
    if let Some(cards) = center_window(app)
        .map(|center| read_cards(&center))
        .transpose()?
        .flatten()
    {
        exact_device(&cards.1, &device.name)?;
    } else {
        // AXWindows only contains windows on the active fullscreen Space.
        // Open the native Devices view to verify the card before closing the VM.
        let list = devices_in_app(app.clone())?;
        exact_device(&list.devices, &device.name)?;
    }
    catalog::verify_card_identity(device)
}

pub(super) fn exact_device<'a, T>(devices: &'a [(String, T)], name: &str) -> Result<&'a T> {
    let mut matches = devices.iter().filter(|(label, _)| label == name);
    let (_, item) = matches.next().context(
        "The saved device was not found. Check the selected profile in Windows App or choose the device again.",
    )?;
    ensure!(matches.next().is_none(), "Multiple devices have the same name in Windows App. Give the target a unique name and choose it again.");
    Ok(item)
}

impl DeviceList {
    fn ensure_profile(&self, expected: &str) -> Result<()> {
        ensure!(
            profile_label(&self.window)?.1 == expected,
            "The active Windows App account changed. Try opening the desktop again."
        );
        Ok(())
    }

    fn connect(&self, name: &str, verify_binding: impl FnOnce() -> Result<()>) -> Result<()> {
        let item = exact_device(&self.devices, name)?;
        self.select(item)?;
        let connect = menu_item(&self.app, &["Connections", "连接"], &["Connect", "连接"])
            .context("Windows App could not find its Connect command.")?;
        // Connect applies to the current selection in the frontmost window.
        wait_for(|| (connect.bool_attr(AX_ENABLED) == Some(true)).then_some(()))
            .context("Windows App cannot connect to the selected device right now.")?;
        verify_binding()?;
        self.ensure_frontmost_selection(item)?;
        ensure!(
            connect.perform_action(AX_PRESS),
            "Windows App could not start the connection."
        );
        Ok(())
    }

    fn select(&self, item: &AxElement) -> Result<()> {
        let selection = CFArray::from_copyable(&[item.raw]);
        let attribute = CFString::from_static_string(SELECTED_CHILDREN);
        let result = unsafe {
            AXUIElementSetAttributeValue(
                self.collection.raw,
                attribute.as_concrete_TypeRef(),
                selection.as_CFTypeRef(),
            )
        };
        ensure!(result == K_AX_ERROR_SUCCESS, SELECTION_ERROR);
        self.ensure_selection(item)
    }

    fn ensure_selection(&self, item: &AxElement) -> Result<()> {
        let selected = self
            .collection
            .array_attr_result(SELECTED_CHILDREN)
            .context(SELECTION_ERROR)?;
        ensure!(
            matches!(selected.as_slice(), [current] if current.same_element(item)),
            SELECTION_ERROR
        );
        Ok(())
    }

    fn ensure_frontmost_selection(&self, item: &AxElement) -> Result<()> {
        ensure!(
            self.app.bool_attr(AX_FRONTMOST) == Some(true)
                && self
                    .app
                    .element_attr("AXFocusedWindow")
                    .is_some_and(|w| w.same_element(&self.window)),
            "The active Windows App window changed. Try opening the desktop again."
        );
        self.ensure_selection(item)
    }
}

fn profile_label(window: &AxElement) -> Result<(AxElement, String)> {
    let mut matches = center_elements(window)?.into_iter().filter_map(|node| {
        if !role_matches(&node, "AXButton") {
            return None;
        }
        let label = node.string_attr(AX_DESCRIPTION)?;
        let current = label
            .strip_prefix("Select Account, ")
            .or_else(|| label.strip_prefix("选择帐户, "))?
            .to_owned();
        Some((node, current))
    });
    let matched = matches.next().context(PROFILE_ERROR)?;
    ensure!(matches.next().is_none(), PROFILE_ERROR);
    Ok(matched)
}

fn sheet_controls(sheet: &AxElement) -> Option<Vec<AxElement>> {
    let roots = children(sheet).ok()?;
    let [root] = roots.as_slice() else {
        return None;
    };
    children(root).ok()
}

fn profile_selector(window: &AxElement) -> Option<(AxElement, AxElement)> {
    let sheet = children(window)
        .ok()?
        .into_iter()
        .find(|node| role_matches(node, "AXSheet"))?;
    let controls = sheet_controls(&sheet)?;
    if !controls.iter().any(|node| {
        role_matches(node, "AXStaticText")
            && matches!(
                node.string_attr(AX_VALUE).as_deref(),
                Some("Account" | "帐户")
            )
    }) {
        return None;
    }
    let close = controls.into_iter().find(|node| {
        role_matches(node, "AXButton")
            && [AX_TITLE, AX_DESCRIPTION]
                .iter()
                .any(|attr| matches!(node.string_attr(attr).as_deref(), Some("Close" | "关闭")))
    })?;
    Some((sheet, close))
}

fn devices_in_app(app: AxElement) -> Result<DeviceList> {
    let window = devices_window(&app)?;
    devices_from_window(app, window)
}

// AXMain can still describe the device list while AXFocusedWindow points to a
// VM on another Space. Only the latter identifies the actual input target.
fn key_center(app: &AxElement) -> Option<AxElement> {
    let focused = app.element_attr("AXFocusedWindow")?;
    let window = center_window(app)?;
    (focused.same_element(&window) && window.bool_attr("AXMinimized") == Some(false))
        .then_some(window)
}

fn show_center_command(app: &AxElement) -> Option<AxElement> {
    menu_item(app, &["Window", "窗口"], &["Connection Center", "连接中心"])
        .filter(|item| item.bool_attr(AX_ENABLED) == Some(true))
}

fn devices_window(app: &AxElement) -> Result<AxElement> {
    if app.bool_attr(AX_FRONTMOST) != Some(true) || key_center(app).is_none() {
        let command = wait_for(|| {
            let command = show_center_command(app);
            // Cocoa may disable the menu in the background. In that case
            // bringing the app forward is safe only if its key window is the list.
            (command.is_some() || key_center(app).is_some()).then_some(command)
        })
        .context("Windows App's Connection Center is unavailable.")?;
        // The Window menu targets the list directly, including when closed.
        // An AXPress may time out after delivery; observe its effect once.
        if let Some(command) = command {
            command.perform_action(AX_PRESS);
        }
        if let Some(window) =
            center_window(app).filter(|w| w.bool_attr("AXMinimized") == Some(true))
        {
            window.set_bool_attr("AXMinimized", false);
        }
    }
    let mut requested_activation = false;
    let window = wait_for(|| {
        let window = key_center(app)?;
        if app.bool_attr(AX_FRONTMOST) == Some(true) {
            return Some(window);
        }
        if !requested_activation {
            requested_activation = true;
            app.set_bool_attr(AX_FRONTMOST, true);
        }
        None
    })
    .context("Windows App did not bring its device list to the front.")?;
    show_devices(app, &window)?;
    Ok(window)
}

fn devices_from_window(app: AxElement, window: AxElement) -> Result<DeviceList> {
    let (collection, devices) = wait_for(|| read_cards(&window).transpose())
        .context("Windows App did not load the saved devices for this profile.")??;
    Ok(DeviceList {
        app,
        window,
        collection,
        devices,
    })
}

fn show_devices(app: &AxElement, window: &AxElement) -> Result<()> {
    if let Some(row) = devices_sidebar_row(window) {
        if row.bool_attr("AXSelected") != Some(true) {
            ensure!(
                row.set_bool_attr("AXSelected", true),
                "Could not switch Windows App to Devices."
            );
            wait_for(|| (row.bool_attr("AXSelected") == Some(true)).then_some(()))
                .context("Windows App did not switch to Devices.")?;
        }
    } else {
        // The sidebar can be hidden. View → Devices is the client's native
        // equivalent and leaves that layout preference intact.
        let devices = wait_for(|| {
            menu_item(app, &["View", "查看"], &["Devices", "设备"])
                .filter(|item| item.bool_attr(AX_ENABLED) == Some(true))
        })
        .context("The Devices view is unavailable in Windows App.")?;
        ensure!(
            devices.perform_action(AX_PRESS),
            "Could not switch Windows App to Devices."
        );
    }
    Ok(())
}

type DeviceCards = (AxElement, Vec<(String, AxElement)>);

pub(super) fn read_cards(window: &AxElement) -> Result<Option<DeviceCards>> {
    let elements = center_elements(window)?;
    ensure!(
        !elements.iter().any(
            |e| e.string_attr(AX_SUBROLE).as_deref() == Some("AXSearchField")
                && e.string_attr(AX_VALUE).is_some()
        ),
        "Clear the device search in Windows App and try again."
    );
    let mut collections = elements
        .into_iter()
        .filter(|n| n.string_attr(AX_SUBROLE).as_deref() == Some("AXCollectionList"));
    let Some(collection) = collections.next() else {
        return Ok(None);
    };
    ensure!(collections.next().is_none(), READ_ERROR);
    let mut devices = Vec::new();
    for section in children(&collection)?
        .into_iter()
        .filter(|n| n.string_attr(AX_SUBROLE).as_deref() == Some("AXSectionList"))
    {
        let before = devices.len();
        for item in children(&section)? {
            if !role_matches(&item, "AXGroup") {
                continue;
            }
            for tile in children(&item)? {
                if role_matches(&tile, "AXGroup") {
                    if let Some(label) = tile.string_attr(AX_DESCRIPTION) {
                        // A title belongs to the inner tile. The selectable item
                        // owned by the collection is its outer accessibility group.
                        devices.push((label, item.clone()));
                    }
                }
            }
        }
        ensure!(
            devices.len() > before,
            "Expand any collapsed device groups in Windows App and try again."
        );
    }
    Ok(Some((collection, devices)))
}

fn trusted_app() -> Result<AxElement> {
    ensure!(
        crate::autologin::accessibility_is_trusted(),
        "Allow Accessibility access for Windows App AutoLogin first."
    );
    let processes = || {
        macos_identity::trusted_process_infos(TARGET_APP_NAME)
            .context("Could not verify the Microsoft Windows App.")
    };
    let mut running = processes()?;
    if running.is_empty() {
        macos_identity::start_windows_app_in_background()
            .context("Could not start the Microsoft-signed Windows App from Applications.")?;
        running = wait_for(|| match processes() {
            Ok(procs) if procs.is_empty() => None,
            result => Some(result),
        })
        .context("Windows App did not finish starting.")??;
    }
    let [process] = running.as_slice() else {
        anyhow::bail!("Could not identify one running copy of Windows App.");
    };
    AxElement::application(process.pid).context("Windows App is unavailable.")
}

fn wait_for<T>(mut read: impl FnMut() -> Option<T>) -> Option<T> {
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(value) = read() {
            return Some(value);
        }
        if Instant::now() >= until {
            return None;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

pub(super) fn center_window(app: &AxElement) -> Option<AxElement> {
    let mut windows = app.array_attr_checked(AX_WINDOWS)?.into_iter().filter(|w| {
        is_center_window(w)
            && w.optional_relationship_array_attr_result("AXSheets")
                .is_ok_and(|s| s.is_empty())
    });
    let window = windows.next()?;
    windows.next().is_none().then_some(window)
}

fn is_center_window(window: &AxElement) -> bool {
    let [role, subrole, title] = window.string_attrs(&[AX_ROLE, AX_SUBROLE, AX_TITLE]);
    role.as_deref() == Some("AXWindow")
        && subrole.as_deref() == Some("AXStandardWindow")
        && matches!(
            title.as_deref(),
            Some("Windows App" | "Connection Center" | "连接中心")
        )
}

fn children(element: &AxElement) -> Result<Vec<AxElement>> {
    element
        .optional_relationship_array_attr_result(AX_CHILDREN)
        .context(READ_ERROR)
}

fn center_elements(window: &AxElement) -> Result<Vec<AxElement>> {
    // Only inspect Connection Center containers. Stop at the collection itself,
    // other controls, and any credential sheet or embedded remote content.
    collect_descendants_bounded(window, 10, 400, &mut |node| {
        if matches!(
            node.string_attr(AX_ROLE).as_deref(),
            Some(
                "AXWindow" | "AXSplitGroup" | "AXGroup" | "AXScrollArea" | "AXToolbar" | "AXTable"
            )
        ) {
            children(node)
        } else {
            Ok(Vec::new())
        }
    })
    .into_complete_elements()
    .context(READ_ERROR)
}

fn devices_sidebar_row(window: &AxElement) -> Option<AxElement> {
    let mut rows = center_elements(window).ok()?.into_iter().filter(|n| {
        role_matches(n, "AXRow")
            && children(n).is_ok_and(|cells| {
                cells.iter().any(|cell| {
                    role_matches(cell, "AXCell")
                        && matches!(
                            cell.string_attr(AX_DESCRIPTION).as_deref(),
                            Some("Devices" | "设备")
                        )
                })
            })
    });
    let row = rows.next()?;
    rows.next().is_none().then_some(row)
}

pub(super) fn menu_item(
    app: &AxElement,
    menu_titles: &[&str],
    item_titles: &[&str],
) -> Option<AxElement> {
    let bar = app.element_attr("AXMenuBar")?;
    let top = children(&bar).ok()?.into_iter().find(|item| {
        item.string_attr(AX_TITLE)
            .is_some_and(|t| menu_titles.contains(&t.as_str()))
    })?;
    let menus = children(&top).ok()?;
    let [menu] = menus.as_slice() else {
        return None;
    };
    let mut items = children(menu).ok()?.into_iter().filter(|i| {
        role_matches(i, "AXMenuItem")
            && i.string_attr(AX_TITLE)
                .is_some_and(|t| item_titles.contains(&t.as_str()))
    });
    let item = items.next()?;
    items.next().is_none().then_some(item)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enter_after_restart_recognizes_the_cloud_pc_by_its_computer_name() {
        use crate::models::Account;
        let mut account = Account::new("user@example.test");
        account.remote_pc = "vm-01.north.example.test".into();
        let mut other = Account::new("another@example.test");
        other.remote_pc = "vm-02.south.example.test".into();
        let host = LaunchHost::for_account(&account, &[account.clone(), other.clone()]).unwrap();
        let cards = vec![
            ("Personal".into(), "VM-010"),
            ("Renamed desktop".into(), "VM-01"),
        ];
        assert_eq!(
            launch_card_name(&cards, "Previous title", Some(&host), |s| Ok(Some(
                s.to_string()
            )))
            .unwrap(),
            "Renamed desktop"
        );
        assert_eq!(
            launch_card_name(&cards, "Personal", None, |_| panic!("exact title")).unwrap(),
            "Personal"
        );
        assert!(
            launch_card_name(&cards, "Previous title", Some(&host), |_| Ok(Some(
                "VM-01".into()
            )))
            .is_err()
        );
        assert!(launch_card_name(&cards, "Previous title", Some(&host), |_| Ok(None)).is_err());
        assert!(
            launch_card_name(&cards, "Previous title", Some(&host), |_| anyhow::bail!(
                "profile changed"
            ))
            .is_err()
        );
        assert!(launch_card_name(&cards, "Previous title", None, |_| panic!("no host")).is_err());
        assert!(!host.matches("vm-01.wrong.example.test"));
        other.remote_pc = "VM-01.south.example.test".into();
        let ambiguous = LaunchHost::for_account(&account, &[account.clone(), other]).unwrap();
        assert!(!ambiguous.matches("VM-01"));
        assert!(ambiguous.matches("VM-01.NORTH.EXAMPLE.TEST."));
    }

    #[test]
    fn reconnect_uses_the_connected_card_for_a_single_renamed_session() {
        let cards = vec![("Offline".to_owned(), false), ("New name".to_owned(), true)];
        assert_eq!(
            reconnect_card(&cards, "Old name", true, |state| Ok(*state)).unwrap(),
            "New name"
        );
        assert!(
            reconnect_card(&cards, "Old name", false, |_| panic!("ambiguous session")).is_err()
        );
        assert!(reconnect_card(&cards[..1], "Old name", true, |state| Ok(*state)).is_err());
        assert_eq!(
            reconnect_card(&cards, "New name", false, |_| panic!("exact name")).unwrap(),
            "New name"
        );
        assert!(reconnect_card(&cards, "Old name", true, |_| Ok(true)).is_err());
        let duplicate = vec![
            ("Duplicate".to_owned(), true),
            ("Duplicate".to_owned(), false),
        ];
        assert!(reconnect_card(&duplicate, "Old name", true, |state| Ok(*state)).is_err());
        assert!(
            reconnect_card(&duplicate, "Duplicate", true, |_| panic!("ambiguous name")).is_err()
        );
    }

    #[test]
    fn connects_only_by_unique_exact_device_name() {
        let devices = vec![
            ("Desktop A".to_string(), 1),
            ("Desktop B".to_string(), 2),
            ("Desktop B".to_string(), 3),
        ];
        assert_eq!(exact_device(&devices, "Desktop A").unwrap(), &1);
        for name in ["Desktop", "desktop a", "Desktop B", ""] {
            assert!(exact_device(&devices, name).is_err());
        }
    }
}
