//! Read the connection state and Cloud PC Details of a verified Windows App card.
use super::*;
use crate::macos_ax::{
    locked_session::window_id, AXUIElementRef, AXValueGetTypeID, AXValueGetValue,
};
use core_foundation::base::{CFType, CFTypeRef};

const UNAVAILABLE: &str = "Could not verify this device’s connection state in Windows App.";
const MENU_DISMISSED: &str = "Windows App did not dismiss the device menu.";
const DETAILS_ERROR: &str = "Could not verify the Cloud PC Details for this Windows App device.";

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Point {
    x: f64,
    y: f64,
}

#[link(name = "ApplicationServices", kind = "framework")]
unsafe extern "C" {
    fn AXUIElementCreateSystemWide() -> AXUIElementRef;
    fn AXUIElementCopyElementAtPosition(
        app: AXUIElementRef,
        x: f32,
        y: f32,
        element: *mut AXUIElementRef,
    ) -> i32;
    fn CGPreflightPostEventAccess() -> bool;
    fn CGEventCreateMouseEvent(
        source: CFTypeRef,
        kind: u32,
        position: Point,
        button: u32,
    ) -> CFTypeRef;
    fn CGEventPost(tap: u32, event: CFTypeRef);
}

fn geometry(node: &AxElement, attr: &'static str, kind: u32) -> Option<Point> {
    let value = node.copy_attr(attr)?;
    let mut pair = Point::default();
    // CGPoint and CGSize are each two consecutive CGFloats on supported Macs.
    let ok = unsafe {
        value.type_of() == AXValueGetTypeID()
            && AXValueGetValue(value.as_CFTypeRef(), kind, (&mut pair as *mut Point).cast()) != 0
    };
    (ok && pair.x.is_finite() && pair.y.is_finite()).then_some(pair)
}

fn hit_test(system: &AxElement, point: Point) -> Option<AxElement> {
    let mut raw = std::ptr::null();
    let status = unsafe {
        AXUIElementCopyElementAtPosition(system.raw, point.x as f32, point.y as f32, &mut raw)
    };
    (status == K_AX_ERROR_SUCCESS && !raw.is_null())
        .then_some(raw)
        .map(|raw| AxElement { raw })
}

fn ancestor_at(
    system: &AxElement,
    point: Point,
    pid: i32,
    matches: impl Fn(&AxElement) -> bool,
) -> Option<AxElement> {
    let mut node = hit_test(system, point)?;
    for _ in 0..12 {
        if node.process_id() != Some(pid) {
            return None;
        }
        if matches(&node) {
            return Some(node);
        }
        node = node.element_attr("AXParent")?;
    }
    None
}

fn popup_at(system: &AxElement, anchor: Point, pid: i32) -> Option<AxElement> {
    // AppKit opens a context menu next to the click, on the side that fits
    // the display. Never walk another application's accessibility tree.
    for (dx, dy) in [
        (8., 9.),
        (-8., 9.),
        (8., -9.),
        (-8., -9.),
        (8., 32.),
        (8., -32.),
    ] {
        let p = Point {
            x: anchor.x + dx,
            y: anchor.y + dy,
        };
        if let Some(menu) = ancestor_at(system, p, pid, |n| role_matches(n, "AXMenu")) {
            return Some(menu);
        }
    }
    None
}

fn mouse_event(kind: u32, at: Point, button: u32) -> Result<CFType> {
    let raw = unsafe { CGEventCreateMouseEvent(std::ptr::null(), kind, at, button) };
    ensure!(
        !raw.is_null(),
        "Could not create the Windows App mouse event."
    );
    Ok(unsafe { TCFType::wrap_under_create_rule(raw) })
}

fn element_midpoint(node: &AxElement) -> Option<Point> {
    let origin = geometry(node, "AXPosition", 1)?;
    let size = geometry(node, "AXSize", 2)?;
    (size.x > 0. && size.y > 0.).then(|| Point {
        x: origin.x + size.x / 2.,
        y: origin.y + size.y / 2.,
    })
}

fn card_state(commands: &[(String, Option<bool>)]) -> Result<bool> {
    let mut choices = commands
        .iter()
        .filter_map(|(title, enabled)| match title.as_str() {
            "Disconnect" | "断开连接" => Some((true, *enabled)),
            "Connect" | "连接" => Some((false, *enabled)),
            _ => None,
        });
    let Some((connected, Some(true))) = choices.next() else {
        anyhow::bail!(UNAVAILABLE)
    };
    ensure!(choices.next().is_none(), UNAVAILABLE);
    Ok(connected)
}

fn with_card_menu<T>(
    app: &AxElement,
    center: &AxElement,
    card: &AxElement,
    read: impl FnOnce(&AxElement, &str, i32) -> Result<T>,
) -> Result<T> {
    let pid = app.process_id().context(UNAVAILABLE)?;
    let center_id = window_id(center).context(UNAVAILABLE)?;
    let center_focused = || {
        app.bool_attr(AX_FRONTMOST) == Some(true)
            && window_id(center) == Some(center_id)
            && app
                .element_attr("AXFocusedWindow")
                .is_some_and(|w| w.same_element(center))
            && center_window(app).is_some_and(|w| w.same_element(center))
    };
    ensure!(
        crate::autologin::accessibility_is_trusted()
            && unsafe { CGPreflightPostEventAccess() }
            && center_focused(),
        UNAVAILABLE
    );
    let (_, cards) = read_cards(center)?.context(UNAVAILABLE)?;
    ensure!(
        cards
            .iter()
            .filter(|(_, item)| item.same_element(card))
            .count()
            == 1,
        UNAVAILABLE
    );
    let tiles = children(card)?;
    let mut labelled = tiles.iter().filter(|t| {
        role_matches(t, "AXGroup")
            && t.process_id() == Some(pid)
            && t.string_attr(AX_DESCRIPTION).is_some()
    });
    let tile = labelled.next().context(UNAVAILABLE)?;
    let label = tile.string_attr(AX_DESCRIPTION).context(UNAVAILABLE)?;
    ensure!(
        labelled.next().is_none()
            && tile
                .element_attr("AXWindow")
                .is_some_and(|w| w.same_element(center)),
        UNAVAILABLE
    );
    let anchor = element_midpoint(tile).context(UNAVAILABLE)?;
    let raw = unsafe { AXUIElementCreateSystemWide() };
    ensure!(!raw.is_null(), UNAVAILABLE);
    let system = AxElement { raw };
    let down = mouse_event(3, anchor, 1)?;
    let up = mouse_event(4, anchor, 1)?;
    ensure!(
        popup_at(&system, anchor, pid).is_none()
            && center_focused()
            && ancestor_at(&system, anchor, pid, |n| n.same_element(tile)).is_some(),
        UNAVAILABLE
    );
    // PID-only mouse events are ignored by some AppKit collection views.
    // Only the checked right-click is posted, without any cursor warp.
    unsafe {
        CGEventPost(0, down.as_CFTypeRef());
        CGEventPost(0, up.as_CFTypeRef());
    }
    let menu = wait_for(|| popup_at(&system, anchor, pid)).context(UNAVAILABLE)?;
    let result = (|| {
        ensure!(
            app.bool_attr(AX_FRONTMOST) == Some(true) && window_id(center) == Some(center_id),
            UNAVAILABLE
        );
        read(&menu, &label, pid)
    })();
    // Cancel only this observed popup. Escape or a click outside it could
    // affect an unrelated prompt if focus moves while the menu is open.
    if popup_at(&system, anchor, pid).is_some_and(|current| current.same_element(&menu)) {
        menu.perform_action("AXCancel");
    }
    wait_for(|| (popup_at(&system, anchor, pid).is_none() && center_focused()).then_some(()))
        .context(MENU_DISMISSED)?;
    result
}

fn menu_commands(menu: &AxElement, pid: i32) -> Result<Vec<(String, AxElement)>> {
    let mut commands = Vec::new();
    for item in children(menu)? {
        ensure!(
            item.process_id() == Some(pid) && role_matches(&item, "AXMenuItem"),
            UNAVAILABLE
        );
        if let Some(title) = item.string_attr(AX_TITLE) {
            commands.push((title, item));
        }
    }
    Ok(commands)
}

pub(super) fn connected_card(
    app: &AxElement,
    center: &AxElement,
    card: &AxElement,
) -> Result<bool> {
    with_card_menu(app, center, card, |menu, _, pid| {
        let commands = menu_commands(menu, pid)?
            .into_iter()
            .map(|(title, item)| (title, item.bool_attr(AX_ENABLED)))
            .collect::<Vec<_>>();
        card_state(&commands)
    })
}

fn is_details_window(window: &AxElement, pid: i32) -> bool {
    window.process_id() == Some(pid)
        && role_matches(window, "AXWindow")
        && matches!(
            window.string_attr(AX_TITLE).as_deref(),
            Some("Cloud PC Details" | "云电脑详细信息")
        )
}

// The native panel publishes a group with four consecutive static texts:
// Cloud PC Name, the selected card's name, Device Name, and its hostname.
// Preserve sibling positions (including non-text controls) and reject
// duplicate or partial sections instead of matching text anywhere in a window.
fn device_row<'a>(rows: &[Option<&'a str>], card: &str) -> Result<Option<&'a str>> {
    let labels = rows
        .iter()
        .enumerate()
        .filter_map(|(i, text)| match text {
            Some("Cloud PC Name" | "云电脑名称") => Some((i, true)),
            Some("Device Name" | "设备名") => Some((i, false)),
            _ => None,
        })
        .collect::<Vec<_>>();
    if labels.is_empty() {
        return Ok(None);
    }
    let [(cloud, true), (device, false)] = labels.as_slice() else {
        anyhow::bail!(DETAILS_ERROR)
    };
    ensure!(
        cloud + 2 == *device && rows[cloud + 1] == Some(card),
        DETAILS_ERROR
    );
    let host = rows
        .get(device + 1)
        .copied()
        .flatten()
        .context(DETAILS_ERROR)?;
    ensure!(
        crate::models::canonical_remote_pc(host).is_some(),
        DETAILS_ERROR
    );
    Ok(Some(host))
}

fn device_name_in_dialog(dialog: &AxElement, pid: i32, card: &str) -> Result<String> {
    let mut hostname = None;
    let traversal = collect_descendants_bounded(dialog, 6, 200, &mut |node| {
        if !node.same_element(dialog) && !role_matches(node, "AXGroup") {
            return Ok(Vec::new());
        }
        let items = children(node)?;
        ensure!(
            items.iter().all(|i| i.process_id() == Some(pid)),
            DETAILS_ERROR
        );
        let texts: Vec<_> = items
            .iter()
            .map(|i| {
                if role_matches(i, "AXStaticText") {
                    i.string_attr(AX_VALUE)
                } else {
                    None
                }
            })
            .collect();
        let values: Vec<_> = texts.iter().map(Option::as_deref).collect();
        if let Some(name) = device_row(&values, card)? {
            ensure!(hostname.is_none(), DETAILS_ERROR);
            hostname = Some(name.to_owned());
        }
        Ok(items)
    });
    traversal.into_complete_elements().context(DETAILS_ERROR)?;
    hostname.context(DETAILS_ERROR)
}

pub(super) fn cloud_pc_device_name(
    app: &AxElement,
    center: &AxElement,
    card: &AxElement,
) -> Result<Option<String>> {
    with_card_menu(app, center, card, |menu, label, pid| {
        let mut items = menu_commands(menu, pid)?
            .into_iter()
            .filter(|(title, _)| matches!(title.as_str(), "View Details" | "查看详细信息"));
        let Some((_, command)) = items.next() else {
            return Ok(None);
        };
        ensure!(items.next().is_none(), DETAILS_ERROR);
        if !command.bool_attr(AX_ENABLED).context(DETAILS_ERROR)? {
            return Ok(None);
        }
        let previous = app.array_attr_result(AX_WINDOWS)?;
        ensure!(
            !previous.iter().any(|w| is_details_window(w, pid)),
            DETAILS_ERROR
        );
        ensure!(
            app.bool_attr(AX_FRONTMOST) == Some(true)
                && command.bool_attr(AX_ENABLED) == Some(true),
            DETAILS_ERROR
        );
        // A press can time out after AppKit accepted it. Observe the result once.
        command.perform_action(AX_PRESS);
        let dialog = wait_for(|| {
            let windows = app.array_attr_checked(AX_WINDOWS)?;
            let mut candidates = windows.into_iter().filter(|w| is_details_window(w, pid));
            let window = candidates.next()?;
            let id = window_id(&window)?;
            (candidates.next().is_none()
                && !previous
                    .iter()
                    .any(|w| w.same_element(&window) || window_id(w) == Some(id))
                && app.bool_attr(AX_FRONTMOST) == Some(true)
                && app
                    .element_attr("AXFocusedWindow")
                    .is_some_and(|w| w.same_element(&window))
                && window
                    .optional_relationship_array_attr_result("AXSheets")
                    .is_ok_and(|s| s.is_empty()))
            .then_some(window)
        })
        .context(DETAILS_ERROR)?;
        let close = dialog
            .element_attr("AXCloseButton")
            .context(DETAILS_ERROR)?;
        ensure!(
            close.process_id() == Some(pid)
                && role_matches(&close, "AXButton")
                && close.bool_attr(AX_ENABLED) == Some(true),
            DETAILS_ERROR
        );
        let result = device_name_in_dialog(&dialog, pid, label);
        close.perform_action(AX_PRESS);
        wait_for(|| {
            app.array_attr_checked(AX_WINDOWS)?
                .iter()
                .all(|w| !w.same_element(&dialog))
                .then_some(())
        })
        .context("Windows App did not close its Cloud PC Details window.")?;
        result.map(Some)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reads_only_the_verified_cards_adjacent_device_name() {
        let english = [
            Some("Cloud PC Name"),
            Some("Dev VM"),
            Some("Device Name"),
            Some("CPC-HOST"),
        ];
        let chinese = [
            Some("云电脑名称"),
            Some("Dev VM"),
            Some("设备名"),
            Some("CPC-HOST"),
        ];
        for rows in [english, chinese] {
            assert_eq!(device_row(&rows, "Dev VM").unwrap(), Some("CPC-HOST"));
            assert!(device_row(&rows, "Different VM").is_err());
            assert!(device_row(&rows, "dev vm").is_err());
        }
        assert_eq!(device_row(&[None, Some("Status")], "Dev VM").unwrap(), None);
        for rows in [
            vec![english[0], english[1]],
            vec![english[2], english[3]],
            vec![english[0], None, english[2], english[3]],
            vec![english[0], english[1], None, english[2], english[3]],
            vec![english[0], english[1], english[2], None],
            vec![english[0], english[1], english[2], Some("host name")],
            vec![english[0], english[1], english[2], english[3], english[2]],
        ] {
            assert!(device_row(&rows, "Dev VM").is_err());
        }
    }
    #[test]
    fn only_one_enabled_card_connection_command_confirms_state() {
        let menu = |pairs: &[(&str, Option<bool>)]| {
            pairs
                .iter()
                .map(|(s, b)| ((*s).to_owned(), *b))
                .collect::<Vec<_>>()
        };
        assert!(card_state(&menu(&[
            ("View Details", Some(true)),
            ("Disconnect", Some(true))
        ]))
        .unwrap());
        assert!(!card_state(&menu(&[("Connect", Some(true))])).unwrap());
        assert!(card_state(&menu(&[("断开连接", Some(true))])).unwrap());
        for invalid in [
            vec![],
            vec![("Disconnect", None)],
            vec![("Connect", Some(false))],
            vec![("Connect", Some(false)), ("Disconnect", Some(true))],
            vec![("Disconnect", Some(true)), ("Disconnect", Some(true))],
        ] {
            assert!(card_state(&menu(&invalid)).is_err());
        }
    }
}
