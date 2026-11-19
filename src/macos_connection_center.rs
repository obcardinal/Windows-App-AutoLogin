use super::{devices_sidebar_row, is_center_window, profile_label};
use crate::macos_ax::{
    device_windows, is_hidden, locked_session::window_id,
    remote_pc_info::connection_information_command, role_matches, sheet_candidates_for_window,
    AxElement, AX_BUTTON_ROLE, AX_DIALOG_SUBROLE, AX_ENABLED, AX_PRESS, AX_ROLE, AX_SUBROLE,
    AX_SYSTEM_DIALOG_SUBROLE, AX_TITLE, AX_WINDOWS, AX_WINDOW_ROLE,
};

/// Keep the actual window, so a newly full-screen desktop doesn't require
/// switching Spaces or raising the Connection Center to find its close button.
#[derive(Clone)]
pub(in crate::macos_ax) struct ConnectionCenter {
    window: AxElement,
    window_id: Option<u32>,
}

impl ConnectionCenter {
    pub(in crate::macos_ax) fn find(app: &AxElement, known: Option<&Self>) -> Option<Self> {
        let mut windows = app
            .array_attr_checked(AX_WINDOWS)?
            .into_iter()
            .filter_map(|w| {
                if let Some(center) = known.filter(|k| k.window.same_element(&w) && k.is_live()) {
                    Some(center.clone())
                } else {
                    Self::from_window(app, w)
                }
            });
        let center = windows.next()?;
        windows.next().is_none().then_some(center)
    }

    pub(in crate::macos_ax) fn from_window(app: &AxElement, window: AxElement) -> Option<Self> {
        let pid = app.process_id()?;
        if window.process_id() != Some(pid)
            || !is_center_window(&window)
            || (devices_sidebar_row(&window).is_none() && profile_label(&window).is_err())
        {
            return None;
        }
        Some(Self {
            window_id: window_id(&window),
            window,
        })
    }

    pub(in crate::macos_ax) fn is_live(&self) -> bool {
        is_center_window(&self.window)
            && self
                .window_id
                .is_none_or(|id| window_id(&self.window) == Some(id))
    }

    pub(in crate::macos_ax) fn same_window(&self, other: &Self) -> bool {
        self.window_id == other.window_id && self.window.same_element(&other.window)
    }

    pub(in crate::macos_ax) fn close_if_connected(
        &self,
        app: &AxElement,
        session_title: &str,
        cancelled: &impl Fn() -> bool,
    ) -> bool {
        let Some(pid) = app.process_id() else {
            return false;
        };
        if cancelled()
            || session_title.is_empty()
            || self.window.process_id() != Some(pid)
            || !self.is_live()
        {
            return false;
        }
        let Ok(sessions) = device_windows::session_entries(app) else {
            return false;
        };
        if !matches!(
            device_windows::exact_session(&sessions, session_title),
            Ok(Some(_))
        ) {
            return false;
        }
        let Ok(mut windows) = app.array_attr_result(AX_WINDOWS) else {
            return false;
        };
        // During a fullscreen Space transition the new key window can be
        // exposed before it is included in AXWindows.
        if let Some(focused) = app.element_attr("AXFocusedWindow") {
            if !windows.iter().any(|w| w.same_element(&focused)) {
                windows.push(focused);
            }
        }
        let mut target = None;
        for window in &windows {
            if window.process_id() != Some(pid) {
                return false;
            }
            let [role, subrole, title] = window.string_attrs(&[AX_ROLE, AX_SUBROLE, AX_TITLE]);
            if is_hidden(window) {
                continue;
            }
            if matches!(
                subrole.as_deref(),
                Some(AX_DIALOG_SUBROLE | AX_SYSTEM_DIALOG_SUBROLE)
            ) || window.bool_attr("AXModal") == Some(true)
            {
                return false;
            }
            if title.as_deref() == Some(session_title) {
                if target.is_some()
                    || self.window.same_element(window)
                    || !is_session_window(role.as_deref(), subrole.as_deref(), || {
                        sheet_candidates_for_window(window).is_ok_and(|sheets| sheets.is_empty())
                    })
                {
                    return false;
                }
                target = Some(window);
            }
        }
        let Some(target) = target else { return false };
        // The native client also has a SessionConnect window while negotiating.
        // Connection Information is enabled for the actual desktop. Its menu
        // state applies to the key window, even when another app is in front.
        let is_focused_session = || {
            app.element_attr("AXFocusedWindow")
                .is_some_and(|w| w.same_element(target))
        };
        if !is_focused_session()
            || connection_information_command(app, pid).is_none()
            || !sheet_candidates_for_window(&self.window).is_ok_and(|s| s.is_empty())
        {
            return false;
        }
        let Some(close) = self.window.element_attr("AXCloseButton") else {
            return false;
        };
        close.process_id() == Some(pid)
            && role_matches(&close, AX_BUTTON_ROLE)
            && close.string_attr(AX_SUBROLE).as_deref() == Some("AXCloseButton")
            && close
                .element_attr("AXWindow")
                .is_some_and(|w| w.same_element(&self.window))
            && close.bool_attr(AX_ENABLED) == Some(true)
            && is_focused_session()
            && !cancelled()
            && close.perform_action(AX_PRESS)
    }
}

fn is_session_window(
    role: Option<&str>,
    subrole: Option<&str>,
    no_sheets: impl FnOnce() -> bool,
) -> bool {
    role == Some(AX_WINDOW_ROLE) && subrole == Some("AXStandardWindow") && no_sheets()
}

#[cfg(test)]
mod tests {
    use super::is_session_window;

    #[test]
    fn an_authentication_window_or_attached_sheet_is_not_a_connected_desktop() {
        assert!(is_session_window(
            Some("AXWindow"),
            Some("AXStandardWindow"),
            || true
        ));
        assert!(!is_session_window(
            Some("AXWindow"),
            Some("AXStandardWindow"),
            || false
        ));
        assert!(!is_session_window(
            Some("AXWindow"),
            Some("AXDialog"),
            || panic!("dialog")
        ));
        assert!(!is_session_window(Some("AXSheet"), None, || panic!(
            "sheet"
        )));
    }
}
