use super::{
    device_launch::menu_item, device_windows, is_hidden, role_matches, AxElement, AX_BUTTON_ROLE,
    AX_CHILDREN, AX_DESCRIPTION, AX_DIALOG_SUBROLE, AX_ENABLED, AX_FRONTMOST, AX_PRESS, AX_SHEETS,
    AX_STATIC_TEXT_ROLE, AX_SUBROLE, AX_TITLE, AX_VALUE, AX_WINDOWS, AX_WINDOW_ROLE,
};
use crate::remote_pc::{prompt_destination, PromptDestination};
use anyhow::{ensure, Context, Result};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SessionRemotePc {
    Selected(String),
    /// Windows App does not expose the owning session of an existing dialog.
    /// Always ask for confirmation before applying this address.
    OpenDialog(String),
}

fn information_windows(app: &AxElement, pid: i32) -> Result<Vec<AxElement>> {
    let windows = app.array_attr_result(AX_WINDOWS)?;
    ensure!(
        windows.len() <= 64,
        "Too many Windows App windows are open."
    );
    Ok(windows
        .into_iter()
        .filter(|window| {
            window.process_id() == Some(pid)
                && matches!(
                    window.string_attr(AX_TITLE).as_deref(),
                    Some("Connection Information" | "连接信息")
                )
                && role_matches(window, AX_WINDOW_ROLE)
                && window.string_attr(AX_SUBROLE).as_deref() == Some(AX_DIALOG_SUBROLE)
        })
        .collect())
}

fn existing_preview(app: &AxElement, pid: i32) -> Result<Option<SessionRemotePc>> {
    match information_windows(app, pid)?.as_slice() {
        [] => Ok(None),
        [dialog] => Ok(Some(SessionRemotePc::OpenDialog(read_host(dialog, pid)?))),
        _ => anyhow::bail!("Several Connection Information windows are open. Leave only the one you want to import open, then try again."),
    }
}

fn sole_session_title<T>(entries: &[(String, T)]) -> Result<&str> {
    match entries {
        [] => anyhow::bail!("Connect to a desktop in Windows App, then try again."),
        [(title, _)] => Ok(title),
        _ => anyhow::bail!(
            "Several desktops are connected. Select a Device in AutoLogin, then try again."
        ),
    }
}

/// Ask the connected desktop itself. Windows App's information command is routed
/// to its key window, and the resulting dialog does not identify its session.
pub(crate) fn request_session_remote_pc(
    title: Option<&str>,
    cancelled: impl Fn() -> bool,
    mut on_handoff: impl FnMut(i32),
) -> Result<SessionRemotePc> {
    ensure!(!cancelled(), "Cancelled.");
    let app = device_windows::running_app()?.context("Windows App is not running.")?;
    let pid = app.process_id().context("Windows App is unavailable.")?;
    if let Some(preview) = existing_preview(&app, pid)? {
        return Ok(preview);
    }
    let entries;
    let title = match title {
        Some(title) => title,
        None => {
            entries = device_windows::session_entries(&app)?;
            sole_session_title(&entries)?
        }
    };
    ensure!(!title.trim().is_empty(), "Choose a connected desktop.");
    let session =
        device_windows::focus_session_in_app(&app, title, &cancelled, || on_handoff(pid))?
            .context("Connect to this desktop in Windows App, then try again.")?;
    read_focused_session_with_settle(
        &app,
        &session,
        title,
        &cancelled,
        Duration::from_millis(400),
    )
}

/// Read only the session supplied by the caller. Never bring it back to the
/// front if the user switched away. An existing dialog remains an unbound preview.
pub(super) fn read_focused_session(
    app: &AxElement,
    session: &AxElement,
    title: &str,
    cancelled: &impl Fn() -> bool,
) -> Result<SessionRemotePc> {
    read_focused_session_with_settle(app, session, title, cancelled, Duration::ZERO)
}

/// Menu enablement applies to the active native desktop in Windows App.
pub(super) fn connection_information_command(app: &AxElement, pid: i32) -> Option<AxElement> {
    menu_item(
        app,
        &["Connections", "连接"],
        &["Show Connection Information", "显示连接信息"],
    )
    .filter(|item| item.process_id() == Some(pid) && item.bool_attr(AX_ENABLED) == Some(true))
}

fn read_focused_session_with_settle(
    app: &AxElement,
    session: &AxElement,
    title: &str,
    cancelled: &impl Fn() -> bool,
    focus_settle: Duration,
) -> Result<SessionRemotePc> {
    let pid = app.process_id().context("Windows App is unavailable.")?;
    let until = Instant::now() + Duration::from_secs(2);
    let command = loop {
        ensure!(!cancelled(), "Cancelled.");
        if let Some(command) = connection_information_command(app, pid) {
            break command;
        }
        ensure!(
            Instant::now() < until,
            "Windows App's Show Connection Information command is unavailable for this desktop."
        );
        std::thread::sleep(Duration::from_millis(60));
    };
    if let Some(preview) = existing_preview(app, pid)? {
        return Ok(preview);
    }
    ensure!(
        session
            .optional_relationship_array_attr_result(AX_SHEETS)?
            .is_empty()
            && device_windows::focused_session(app, title).is_some_and(|w| w.same_element(session)),
        "The selected desktop lost focus. Try again."
    );
    ensure!(!cancelled(), "Cancelled.");
    ensure!(
        command.perform_action(AX_PRESS),
        "Windows App could not show Connection Information."
    );

    let until = Instant::now() + Duration::from_secs(3);
    let dialog = loop {
        let dialogs = information_windows(app, pid)?;
        let focused = app.element_attr("AXFocusedWindow");
        match dialogs.as_slice() {
            [dialog] if focused.as_ref().is_some_and(|w| w.same_element(dialog)) => {
                break dialog.clone()
            }
            [] | [_] => {}
            _ => anyhow::bail!("Several Connection Information windows opened. Try again."),
        }
        // AXPress may return before Cocoa orders the dialog. Even on cancel,
        // observe its bounded arrival so we can close our window without focus.
        ensure!(
            focused.as_ref().is_none_or(
                |w| w.same_element(session) || dialogs.iter().any(|d| d.same_element(w))
            ),
            "The selected desktop lost focus. Try again."
        );
        if Instant::now() >= until {
            ensure!(!cancelled(), "Cancelled.");
            anyhow::bail!("Windows App did not show Connection Information.");
        }
        std::thread::sleep(Duration::from_millis(60));
    };
    let result = loop {
        if cancelled() {
            break Err(anyhow::anyhow!("Cancelled."));
        }
        let address = read_host(&dialog, pid);
        if address.is_ok() || Instant::now() >= until {
            break address;
        }
        std::thread::sleep(Duration::from_millis(80));
    };
    // Close only the newly observed dialog, using its own close button. This
    // also works if the user has switched applications during the read.
    if let Some(close) = dialog
        .element_attr("AXCloseButton")
        .filter(|button| button.process_id() == Some(pid) && role_matches(button, AX_BUTTON_ROLE))
    {
        if close.perform_action(AX_PRESS) {
            // Closing the native dialog reactivates its owner asynchronously.
            // Returning to AutoLogin during this transition can switch Spaces twice.
            wait_for_session_after_close(app, session, cancelled, focus_settle);
        }
    }
    result.map(SessionRemotePc::Selected)
}

fn wait_for_session_after_close(
    app: &AxElement,
    session: &AxElement,
    cancelled: &impl Fn() -> bool,
    settle: Duration,
) {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut key_since = None;
    while Instant::now() < deadline && !cancelled() && app.bool_attr(AX_FRONTMOST) == Some(true) {
        if app
            .element_attr("AXFocusedWindow")
            .is_some_and(|w| w.same_element(session))
        {
            // AppKit can report the new key window before its Space transition finishes.
            if key_since.get_or_insert_with(Instant::now).elapsed() >= settle {
                break;
            }
        } else {
            key_since = None;
        }
        std::thread::sleep(Duration::from_millis(40));
    }
}

fn read_host(window: &AxElement, pid: i32) -> Result<String> {
    let mut sections = Vec::new();
    for content in children(window, pid)? {
        if !role_matches(&content, "AXGroup")
            || content.string_attr(AX_SUBROLE).as_deref() != Some("AXHostingView")
        {
            continue;
        }
        for group in children(&content, pid)? {
            if !role_matches(&group, "AXGroup") {
                continue;
            }
            let items = children(&group, pid)?;
            if items.iter().any(|item| {
                role_matches(item, "AXHeading")
                    && item
                        .string_attrs(&[AX_TITLE, AX_DESCRIPTION, AX_VALUE])
                        .iter()
                        .flatten()
                        .any(|heading| matches!(heading.trim(), "Connection" | "连接"))
            }) {
                sections.push(items);
            }
        }
    }
    let [items] = sections.as_slice() else {
        anyhow::bail!("Could not identify a single Connection section in Windows App.");
    };
    let values: Vec<String> = items
        .iter()
        .filter(|item| role_matches(item, AX_STATIC_TEXT_ROLE))
        .map(|item| native_text(item).context("An entry in Connection Information is unreadable."))
        .collect::<anyhow::Result<_>>()?;
    host_from_connection_rows(&values).context("Windows App did not report a unique Remote PC.")
}

fn children(parent: &AxElement, pid: i32) -> anyhow::Result<Vec<AxElement>> {
    let children = parent.optional_relationship_array_attr_result(AX_CHILDREN)?;
    ensure!(
        children.len() <= 32 && children.iter().all(|child| child.process_id() == Some(pid)),
        "Unexpected Connection Information layout."
    );
    Ok(children
        .into_iter()
        .filter(|child| !is_hidden(child))
        .collect())
}

fn native_text(item: &AxElement) -> Option<String> {
    item.string_attrs(&[AX_VALUE, AX_TITLE, AX_DESCRIPTION])
        .into_iter()
        .flatten()
        .find(|value| value.len() <= 4096)
}

fn host_from_connection_rows(items: &[String]) -> Option<String> {
    // SwiftUI exposes ordered label/value pairs, not a table of network peers.
    // A missing value must never turn the next row's label into a hostname.
    let mut rows = items.chunks_exact(2);
    if !rows.remainder().is_empty() {
        return None;
    }
    let mut desktop = None;
    let mut host = None;
    for row in &mut rows {
        match row[0].trim() {
            "Session Type" | "会话类型" if desktop.is_none() => {
                desktop = Some(matches!(row[1].trim(), "Remote Desktop" | "远程桌面"))
            }
            "Remote PC" | "远程 PC" if host.is_none() => {
                let value = row[1].trim();
                if value.split_whitespace().count() != 1 || matches!(value, "Gateway" | "网关") {
                    return None;
                }
                let PromptDestination::Host(parsed) =
                    prompt_destination(&format!("Remote PC {value}"))
                else {
                    return None;
                };
                host = Some(parsed);
            }
            "Session Type" | "会话类型" | "Remote PC" | "远程 PC" => return None,
            _ => {}
        }
    }
    if desktop == Some(true) {
        host
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{host_from_connection_rows, request_session_remote_pc, sole_session_title};

    #[test]
    fn cancelled_request_stops_before_accessing_windows_app() {
        let error = request_session_remote_pc(
            Some("Desktop"),
            || true,
            |_| panic!("cancelled import moved focus"),
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "Cancelled.");
    }

    #[test]
    fn unbound_import_requires_exactly_one_connected_desktop() {
        let entries = [("Desktop A".into(), ()), ("Desktop B".into(), ())];
        assert_eq!(sole_session_title(&entries[..1]).unwrap(), "Desktop A");
        assert!(sole_session_title(&entries[..0])
            .unwrap_err()
            .to_string()
            .contains("Connect to a desktop"));
        assert!(sole_session_title(&entries)
            .unwrap_err()
            .to_string()
            .contains("Select a Device"));
    }

    #[test]
    fn imports_only_the_desktop_row_of_a_complete_remote_desktop_section() {
        let parse = |fields: &[&str]| {
            host_from_connection_rows(&fields.iter().map(|s| s.to_string()).collect::<Vec<_>>())
        };
        assert_eq!(
            parse(&[
                "Session Type",
                "Remote Desktop",
                "Gateway",
                "relay.example:443",
                "Remote PC",
                "Desktop.Example.",
                "Service Region",
                "GRN"
            ])
            .as_deref(),
            Some("desktop.example")
        );
        assert_eq!(
            parse(&[
                "会话类型",
                "远程桌面",
                "网关",
                "relay.example",
                "远程 PC",
                "Desktop.Example."
            ])
            .as_deref(),
            Some("desktop.example")
        );
        for fields in [
            &["Session Type", "Remote Desktop", "Gateway", "relay.example"][..],
            &[
                "Session Type",
                "Remote Desktop",
                "Remote PC",
                "Service Region",
                "GRN",
            ],
            &[
                "Session Type",
                "Remote Desktop",
                "Remote PC",
                "a",
                "Remote PC",
                "b",
            ],
            &["Session Type", "RemoteApp", "Remote PC", "a"],
            &[
                "Session Type",
                "Remote Desktop",
                "Remote PC",
                "Remote PC host.example",
            ],
        ] {
            assert!(parse(fields).is_none());
        }
    }
}
