use super::{
    is_hidden, macos_identity, role_matches, AxElement, AX_CHILDREN, AX_DESCRIPTION,
    AX_DIALOG_SUBROLE, AX_ROLE, AX_STATIC_TEXT_ROLE, AX_SUBROLE, AX_TITLE, AX_VALUE, AX_WINDOWS,
    AX_WINDOW_ROLE,
};
use crate::remote_pc::{prompt_destination, PromptDestination};
use anyhow::{ensure, Context};

/// Import an explicitly opened native information dialog into an account draft.
pub(crate) fn open_connection_remote_pc() -> anyhow::Result<String> {
    let mut selected = None;
    for process in macos_identity::trusted_process_infos(crate::config::TARGET_APP_NAME)? {
        let app = AxElement::application(process.pid).context("Windows App is unavailable.")?;
        let windows = app.array_attr_result(AX_WINDOWS)?;
        ensure!(
            windows.len() <= 64,
            "Too many Windows App windows are open."
        );
        for window in windows {
            if window.process_id() != Some(process.pid)
                || is_hidden(&window)
                || window.bool_attr("AXMinimized") == Some(true)
                || window.string_attr(AX_TITLE).as_deref() != Some("Connection Information")
            {
                continue;
            }
            let identity = window.string_attrs(&[AX_ROLE, AX_SUBROLE]);
            if identity[0].as_deref() == Some(AX_WINDOW_ROLE)
                && identity[1].as_deref() == Some(AX_DIALOG_SUBROLE)
            {
                ensure!(
                    selected.is_none(),
                    "Leave only one Connection Information window open."
                );
                selected = Some((window, process.pid));
            }
        }
    }
    let (window, pid) =
        selected.context("Open Connection Information for the desktop in Windows App first.")?;
    let mut sections = Vec::new();
    for content in children(&window, pid)? {
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
                        .any(|heading| heading.trim() == "Connection")
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
            "Session Type" if desktop.is_none() => {
                desktop = Some(row[1].trim() == "Remote Desktop")
            }
            "Remote PC" if host.is_none() => {
                let value = row[1].trim();
                if value.split_whitespace().count() != 1 || value == "Gateway" {
                    return None;
                }
                let PromptDestination::Host(parsed) =
                    prompt_destination(&format!("Remote PC {value}"))
                else {
                    return None;
                };
                host = Some(parsed);
            }
            "Session Type" | "Remote PC" => return None,
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
    use super::host_from_connection_rows;

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
