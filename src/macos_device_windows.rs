//! Windows App exposes a native Window menu item for each running desktop.
//! AXWindows can omit a full-screen desktop on another Space. The client's
//! activateSession: action also restores minimized windows and switches Spaces.
use super::{
    macos_identity, AxElement, AX_CHILDREN, AX_ENABLED, AX_FRONTMOST, AX_PRESS, AX_ROLE, AX_TITLE,
};
use crate::config::TARGET_APP_NAME;
use anyhow::{ensure, Context, Result};
use std::time::{Duration, Instant};

const SESSION_ACTION: &str = "activateSession:";
const MENU_ERROR: &str = "Could not read the open sessions in Windows App’s Window menu.";

pub(super) fn running_app() -> Result<Option<AxElement>> {
    let processes = macos_identity::trusted_process_infos(TARGET_APP_NAME)
        .context("Could not verify Microsoft Windows App.")?;
    let process = match processes.as_slice() {
        [] => return Ok(None),
        [process] => process,
        _ => anyhow::bail!("More than one copy of Windows App is running."),
    };
    ensure!(
        crate::autologin::accessibility_is_trusted(),
        "Allow Accessibility access for Windows App AutoLogin to show open VM windows."
    );
    let app = AxElement::application(process.pid)
        .filter(|app| app.process_id() == Some(process.pid))
        .context("Windows App is unavailable.")?;
    Ok(Some(app))
}

pub(super) fn session_entries(app: &AxElement) -> Result<Vec<(String, AxElement)>> {
    let pid = app.process_id().context(MENU_ERROR)?;
    let bar = app.element_attr("AXMenuBar").context(MENU_ERROR)?;
    let top = bar.array_attr_result(AX_CHILDREN).context(MENU_ERROR)?;
    let window_menu = top
        .iter()
        .find(|item| {
            matches!(
                item.string_attr(AX_TITLE).as_deref(),
                Some("Window" | "窗口")
            )
        })
        .context(MENU_ERROR)?;
    let menus = window_menu
        .array_attr_result(AX_CHILDREN)
        .context(MENU_ERROR)?;
    let [menu] = menus.as_slice() else {
        anyhow::bail!(MENU_ERROR)
    };
    let mut entries = Vec::new();
    for item in menu.array_attr_result(AX_CHILDREN).context(MENU_ERROR)? {
        if item.process_id() == Some(pid)
            && item.string_attr("AXIdentifier").as_deref() == Some(SESSION_ACTION)
            && item.string_attr(AX_ROLE).as_deref() == Some("AXMenuItem")
        {
            let title = item.string_attr(AX_TITLE).context(MENU_ERROR)?;
            entries.push((title, item));
        }
    }
    Ok(entries)
}

pub(crate) fn open_session_titles() -> Result<Vec<String>> {
    let Some(app) = running_app()? else {
        return Ok(vec![]);
    };
    Ok(session_entries(&app)?
        .into_iter()
        .map(|(title, _)| title)
        .collect())
}

pub(super) fn exact_session<'a, T>(
    entries: &'a [(String, T)],
    title: &str,
) -> Result<Option<&'a T>> {
    let mut matches = entries.iter().filter(|(name, _)| name == title);
    let matched = matches.next();
    ensure!(
        matches.next().is_none(),
        "Several open desktops have this name. Select the intended window in Windows App."
    );
    Ok(matched.map(|(_, item)| item))
}

pub(crate) fn focus_open_session(title: &str) -> Result<bool> {
    let Some(app) = running_app()? else {
        return Ok(false);
    };
    Ok(focus_session_in_app(&app, title, &|| false, || {})?.is_some())
}

pub(super) fn focused_session(app: &AxElement, title: &str) -> Option<AxElement> {
    if app.bool_attr(AX_FRONTMOST) != Some(true) {
        return None;
    }
    app.element_attr("AXFocusedWindow").filter(|window| {
        window.process_id() == app.process_id()
            && window.string_attr(AX_ROLE).as_deref() == Some("AXWindow")
            && window.string_attr(AX_TITLE).as_deref() == Some(title)
            && window.bool_attr("AXMinimized") == Some(false)
    })
}

pub(super) fn focus_session_in_app(
    app: &AxElement,
    title: &str,
    cancelled: &impl Fn() -> bool,
    on_handoff: impl FnOnce(),
) -> Result<Option<AxElement>> {
    let entries = session_entries(app)?;
    if exact_session(&entries, title)?.is_none() {
        return Ok(None);
    }
    ensure!(!cancelled(), "Cancelled.");
    if let Some(window) = focused_session(app, title) {
        return Ok(Some(window));
    }
    if app.bool_attr(AX_FRONTMOST) != Some(true) {
        ensure!(!cancelled(), "Cancelled.");
        ensure!(
            app.set_bool_attr(AX_FRONTMOST, true),
            "Windows App could not come to the front."
        );
        on_handoff();
    }
    // Cocoa can leave menu entries disabled while the app is in the background.
    // Resolve the exact entry again after activation and press it at most once.
    let until = Instant::now() + Duration::from_secs(3);
    let mut pressed = false;
    loop {
        ensure!(!cancelled(), "Cancelled.");
        if let Some(window) = focused_session(app, title) {
            return Ok(Some(window));
        }
        if !pressed && app.bool_attr(AX_FRONTMOST) == Some(true) {
            let entries = session_entries(app)?;
            let item = exact_session(&entries, title)?
                .context("The selected desktop has disconnected.")?;
            if item.bool_attr(AX_ENABLED) == Some(true) {
                ensure!(!cancelled(), "Cancelled.");
                ensure!(
                    item.perform_action(AX_PRESS),
                    "Windows App could not bring the session to the front."
                );
                pressed = true;
            }
        }
        ensure!(
            Instant::now() < until,
            "Windows App did not focus the selected desktop."
        );
        std::thread::sleep(Duration::from_millis(60));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_exact_unique_open_session_can_be_focused() {
        let items = [
            ("VM A".into(), 1),
            ("VM A test".into(), 2),
            ("VM B".into(), 3),
            ("VM B".into(), 4),
        ];
        assert_eq!(exact_session(&items, "VM A").unwrap(), Some(&1));
        assert_eq!(exact_session(&items, "VM").unwrap(), None);
        assert_eq!(exact_session(&items, "vm a").unwrap(), None);
        assert!(exact_session(&items, "VM B").is_err());
    }
}
