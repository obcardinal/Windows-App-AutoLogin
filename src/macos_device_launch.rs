//! Launch the saved Windows App device so its workspace and gateway settings apply.
use super::{
    collect_descendants_bounded, macos_identity, role_matches, AXUIElementSetAttributeValue,
    AxElement, AX_CHILDREN, AX_DESCRIPTION, AX_ENABLED, AX_FRONTMOST, AX_MAIN, AX_PRESS, AX_ROLE,
    AX_SUBROLE, AX_TITLE, AX_VALUE, AX_WINDOWS, K_AX_ERROR_SUCCESS,
};
use crate::config::TARGET_APP_NAME;
use anyhow::{ensure, Context, Result};
use core_foundation::{array::CFArray, base::TCFType, string::CFString};
use std::time::{Duration, Instant};

#[path = "macos_device_catalog.rs"]
mod catalog;
pub(super) use catalog::verify_card_identity_in;
pub(crate) use catalog::{saved_devices, saved_remote_pc, SavedDevice};

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
pub(crate) fn reconnect_window_device(name: &str, account_email: &str) -> Result<()> {
    let app = trusted_app()?;
    reconnect_window_device_if(&app, name, account_email, || Ok(()))
}

pub(super) fn reconnect_window_device_if(
    app: &AxElement,
    name: &str,
    account_email: &str,
    before_connect: impl FnOnce() -> Result<()>,
) -> Result<()> {
    ensure!(
        !name.trim().is_empty() && !account_email.trim().is_empty(),
        PROFILE_ERROR
    );
    let list = devices_in_app(app.clone())?;
    exact_device(&list.devices, name)?;
    let profile = list.verify_profile(account_email.trim())?;
    list.connect(name, || {
        ensure!(
            profile_label(&list.window)?.1 == profile,
            "The active Windows App account changed. Try opening the desktop again."
        );
        before_connect()
    })
}

/// Preflight a window-only binding through the client's current Devices view
/// before disconnecting. Reading the profile selector never changes its account.
pub(super) fn verify_window_device(
    app: &AxElement,
    name: &str,
    email: &str,
    cancelled: &impl Fn() -> bool,
) -> Result<()> {
    ensure!(
        !cancelled() && app.bool_attr(AX_FRONTMOST) == Some(true),
        "The active desktop changed."
    );
    let list = devices_in_app(app.clone())?;
    exact_device(&list.devices, name)?;
    ensure!(
        !cancelled()
            && app.bool_attr(AX_FRONTMOST) == Some(true)
            && app
                .element_attr("AXFocusedWindow")
                .is_some_and(|w| w.same_element(&list.window)),
        "The Windows App Devices view lost focus."
    );
    list.verify_profile(email)?;
    ensure!(!cancelled(), "Cancelled.");
    Ok(())
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

    fn verify_profile(&self, email: &str) -> Result<String> {
        let (button, label) = profile_label(&self.window)?;
        ensure!(
            children(&self.window)?
                .iter()
                .all(|node| !role_matches(node, "AXSheet")),
            PROFILE_ERROR
        );
        // Opening the selector can outlast the AX reply timeout even though
        // Windows App has accepted the press. Observe its resulting sheet.
        button.perform_action(AX_PRESS);
        let (sheet, close) = wait_for(|| profile_selector(&self.window))
            .context("Windows App did not display its account selector.")?;
        let verified = wait_for(|| {
            let controls = sheet_controls(&sheet)?;
            let owners = profile_owners(&controls, &label)?;
            Some(matches!(owners.as_slice(), [owner] if owner.eq_ignore_ascii_case(email)))
        });
        close.perform_action(AX_PRESS);
        wait_for(|| {
            children(&self.window)
                .ok()?
                .iter()
                .all(|node| !node.same_element(&sheet))
                .then_some(())
        })
        .context("Windows App did not finish closing its account selector.")?;
        ensure!(
            verified.context(PROFILE_ERROR)?,
            "The selected desktop could not be verified under this Windows App account."
        );
        Ok(label)
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

fn profile_owners(controls: &[AxElement], label: &str) -> Option<Vec<String>> {
    let scroll = controls
        .iter()
        .find(|node| role_matches(node, "AXScrollArea"))?;
    let rows = children(scroll).ok()?;
    if rows.is_empty() {
        return None;
    }
    let mut owners = Vec::new();
    for row in rows {
        let texts: Vec<_> = children(&row)
            .ok()?
            .into_iter()
            .filter(|node| role_matches(node, "AXStaticText"))
            .map(|node| node.string_attr(AX_VALUE))
            .collect::<Option<_>>()?;
        let [display, owner, organization] = texts.as_slice() else {
            return None;
        };
        if label == format!("{display} {organization}") {
            owners.push(owner.clone());
        }
    }
    Some(owners)
}

fn devices_in_app(app: AxElement) -> Result<DeviceList> {
    app.set_bool_attr(AX_FRONTMOST, true);
    let mut window = center_window(&app);
    if window
        .as_ref()
        .is_none_or(|w| w.bool_attr(AX_MAIN) != Some(true))
    {
        let show_center = wait_for(|| {
            menu_item(
                &app,
                &["Window", "窗口"],
                &["Connection Center", "连接中心"],
            )
        })
        .context("Windows App's Connection Center is unavailable.")?;
        ensure!(
            show_center.perform_action(AX_PRESS),
            "Could not open the Windows App Connection Center."
        );
        window = wait_for(|| center_window(&app));
    }
    let window = window.context("The Windows App Connection Center did not open.")?;
    if window.bool_attr("AXMinimized") == Some(true) {
        window.set_bool_attr("AXMinimized", false);
    }
    window.perform_action("AXRaise");
    show_devices(&app, &window)?;
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
        w.string_attr(AX_SUBROLE).as_deref() == Some("AXStandardWindow")
            && matches!(
                w.string_attr(AX_TITLE).as_deref(),
                Some("Windows App" | "Connection Center" | "连接中心")
            )
            && w.optional_relationship_array_attr_result("AXSheets")
                .is_ok_and(|s| s.is_empty())
    });
    let window = windows.next()?;
    windows.next().is_none().then_some(window)
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
