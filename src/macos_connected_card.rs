//! Read the connection state from the menu of a verified Windows App device
//! card. None of the menu's connection commands is invoked.
use super::*;
use crate::macos_ax::{
    locked_session::window_id, AXUIElementRef, AXValueGetTypeID, AXValueGetValue,
};
use core_foundation::base::{CFType, CFTypeRef};

const UNAVAILABLE: &str = "Could not verify this device’s connection state in Windows App.";
const MENU_DISMISSED: &str = "Windows App did not dismiss the device menu.";

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

fn mouse_event(kind: u32, at: Point) -> Result<CFType> {
    // kCGMouseButtonRight. AppKit's card does not publish AXShowMenu.
    let raw = unsafe { CGEventCreateMouseEvent(std::ptr::null(), kind, at, 1) };
    ensure!(!raw.is_null(), UNAVAILABLE);
    Ok(unsafe { TCFType::wrap_under_create_rule(raw) })
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

pub(super) fn connected_card(
    app: &AxElement,
    center: &AxElement,
    card: &AxElement,
) -> Result<bool> {
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
    ensure!(
        labelled.next().is_none()
            && tile
                .element_attr("AXWindow")
                .is_some_and(|w| w.same_element(center)),
        UNAVAILABLE
    );
    let origin = geometry(tile, "AXPosition", 1).context(UNAVAILABLE)?;
    let size = geometry(tile, "AXSize", 2).context(UNAVAILABLE)?;
    ensure!(size.x > 0. && size.y > 0., UNAVAILABLE);
    let anchor = Point {
        x: origin.x + size.x / 2.,
        y: origin.y + size.y / 2.,
    };
    let raw = unsafe { AXUIElementCreateSystemWide() };
    ensure!(!raw.is_null(), UNAVAILABLE);
    let system = AxElement { raw };
    let down = mouse_event(3, anchor)?;
    let up = mouse_event(4, anchor)?;
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
        let mut commands = Vec::new();
        for item in children(&menu)? {
            ensure!(
                item.process_id() == Some(pid) && role_matches(&item, "AXMenuItem"),
                UNAVAILABLE
            );
            if let Some(title) = item.string_attr(AX_TITLE) {
                commands.push((title, item.bool_attr(AX_ENABLED)));
            }
        }
        card_state(&commands)
    })();
    // Cancel only this observed popup. Escape or a click outside it could
    // affect an unrelated prompt if focus moves while the menu is open.
    menu.perform_action("AXCancel");
    wait_for(|| (popup_at(&system, anchor, pid).is_none() && center_focused()).then_some(()))
        .context(MENU_DISMISSED)?;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
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
