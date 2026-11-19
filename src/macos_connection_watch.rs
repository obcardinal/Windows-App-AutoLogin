//! Close the device list once for a new native session. The supervisor owns this
//! independently of password monitoring, so a manual connection behaves like Enter.
use super::{device_launch::ConnectionCenter, device_windows, locked_session, AxElement, AX_TITLE};
use crate::background::window_hints::observe_connection_windows;
use crate::{config::TARGET_APP_NAME, macos_identity};
use objc2_app_kit::NSRunningApplication;
use objc2_foundation::NSString;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

#[derive(Default)]
pub(crate) struct ConnectionWatch {
    enabled: bool,
    client: Option<ClientWatch>,
}

impl ConnectionWatch {
    pub(crate) fn update(&mut self, enabled: bool) {
        let already_enabled = self.enabled;
        self.enabled = enabled;
        if !enabled {
            self.client = None;
            return;
        }
        // AppKit supplies only a discovery hint. Verify the live Microsoft
        // process before using AX. The supervisor already services AppKit events.
        let bundle_id = NSString::from_str(macos_identity::MICROSOFT_REMOTE_DESKTOP_BUNDLE_ID);
        let apps = NSRunningApplication::runningApplicationsWithBundleIdentifier(&bundle_id);
        let pid = (apps.count() == 1).then(|| apps.objectAtIndex(0).processIdentifier());
        if self.client.as_ref().map(|client| client.pid) == pid {
            return;
        }
        self.client = None;
        if let Some(pid) = pid {
            self.client = ClientWatch::start(pid, already_enabled);
        }
    }
}

struct ClientWatch {
    pid: i32,
    cancelled: Arc<AtomicBool>,
    thread: JoinHandle<()>,
}

impl ClientWatch {
    fn start(pid: i32, new_client: bool) -> Option<Self> {
        let cancelled = Arc::new(AtomicBool::new(false));
        let stop = cancelled.clone();
        let thread = thread::Builder::new()
            .name("connection-center".into())
            .spawn(move || watch_client(pid, new_client, &stop))
            .map_err(|err| tracing::warn!(%err, "Could not observe new Windows App connections"))
            .ok()?;
        Some(Self {
            pid,
            cancelled,
            thread,
        })
    }
}

impl Drop for ClientWatch {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        self.thread.thread().unpark();
    }
}

fn watch_client(pid: i32, new_client: bool, stop: &AtomicBool) {
    let cancelled = || stop.load(Ordering::Acquire);
    // Launch Services can announce a new process before its AX or signing
    // information is ready. Keep waiting for this exact PID until it exits.
    let app = loop {
        if cancelled() {
            return;
        }
        if macos_identity::trusted_process_info_for_pid(TARGET_APP_NAME, pid)
            .is_ok_and(|info| info.is_some())
        {
            if let Some(app) = AxElement::application(pid) {
                break app;
            }
        }
        thread::park_timeout(Duration::from_millis(500));
    };
    observe_connections(app, pid, new_client, stop);
}

pub(super) fn observe_connections(app: AxElement, pid: i32, new_client: bool, stop: &AtomicBool) {
    let cancelled = || stop.load(Ordering::Acquire);
    let notifications = observe_connection_windows(pid, thread::current());
    let mut center: Option<ConnectionCenter> = None;
    let mut sessions = Sessions::default();
    // Existing desktops are a baseline when the setting is enabled. If the
    // client itself just launched, every desktop it opens is new.
    if new_client {
        sessions.previous = Some(BTreeMap::new());
    }
    while !cancelled() {
        // The window from a notification remains addressable when a fast
        // fullscreen transition has already removed it from AXWindows.
        let notified_center = notifications.as_ref().and_then(|observer| {
            std::iter::from_fn(|| observer.take_window())
                .filter_map(|event| {
                    ConnectionCenter::from_window(&app, AxElement::from_cf(&event)?)
                })
                .last()
        });
        let visible = ConnectionCenter::find(&app, notified_center.as_ref().or(center.as_ref()));
        if let Some(found) = visible.or(notified_center) {
            if center.as_ref().is_some_and(|c| !c.same_window(&found)) {
                sessions.pending.clear();
            }
            center = Some(found);
        } else if center.as_ref().is_some_and(|c| !c.is_live()) {
            center = None;
            sessions.pending.clear();
        }
        if let Ok(entries) = device_windows::session_entries(&app) {
            let focused = app
                .element_attr("AXFocusedWindow")
                .and_then(|w| Some((w.string_attr(AX_TITLE)?, locked_session::window_id(&w)?)));
            sessions.observe(
                entries.into_iter().map(|(name, _)| name),
                focused,
                center.is_some(),
            );
            if let Some(target) = &center {
                if sessions
                    .pending
                    .iter()
                    .any(|title| !cancelled() && target.close_if_connected(&app, title, &cancelled))
                {
                    sessions.pending.clear();
                    center = None;
                }
            }
        }
        // AX notifications wake immediately. The fallback covers missed events
        // and completion of an authentication sheet without a focus change.
        let fallback = if sessions.pending.is_empty() {
            Duration::from_secs(2)
        } else {
            Duration::from_millis(250)
        };
        thread::park_timeout(fallback);
    }
}

#[derive(Default)]
struct Session {
    count: usize,
    window: Option<u32>,
}

#[derive(Default)]
struct Sessions {
    previous: Option<BTreeMap<String, Session>>,
    pending: BTreeSet<String>,
}

impl Sessions {
    fn observe(
        &mut self,
        titles: impl Iterator<Item = String>,
        focused: Option<(String, u32)>,
        center_open: bool,
    ) {
        let mut current = BTreeMap::<String, Session>::new();
        for title in titles {
            current.entry(title).or_default().count += 1;
        }
        if let Some((title, id)) = focused {
            if let Some(session) = current.get_mut(&title) {
                session.window = Some(id);
            }
        }
        self.pending
            .retain(|title| center_open && current.get(title).is_some_and(|s| s.count == 1));
        if let Some(previous) = &self.previous {
            for (title, session) in &mut current {
                if session.count != 1 {
                    continue;
                }
                let old = previous.get(title);
                // A reconnect can replace a window under the same menu title.
                // Retain its last known ID when the user changes Spaces.
                let replaced = old.is_some_and(|s| {
                    s.count == 1 && s.window.zip(session.window).is_some_and(|(a, b)| a != b)
                });
                if center_open && (old.is_none() || replaced) {
                    self.pending.insert(title.clone());
                }
                if session.window.is_none() {
                    session.window = old.filter(|s| s.count == 1).and_then(|s| s.window);
                }
            }
        }
        self.previous = Some(current);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observe(s: &mut Sessions, names: &[&str], focused: Option<(&str, u32)>, center: bool) {
        s.observe(
            names.iter().map(|&n| n.to_owned()),
            focused.map(|(n, id)| (n.to_owned(), id)),
            center,
        );
    }

    #[test]
    fn only_new_sessions_close_the_center_and_reopening_devices_is_allowed() {
        let mut s = Sessions::default();
        observe(&mut s, &["Existing"], Some(("Existing", 3)), true);
        assert!(s.pending.is_empty());
        observe(&mut s, &["Existing", "New VM"], None, true);
        assert_eq!(s.pending.iter().collect::<Vec<_>>(), ["New VM"]);
        // Auth can take arbitrarily long while the session's native menu entry exists.
        observe(&mut s, &["Existing", "New VM"], Some(("Sign in", 12)), true);
        assert!(s.pending.contains("New VM"));
        s.pending.clear(); // the confirmed close completed
        observe(&mut s, &["Existing", "New VM"], Some(("New VM", 20)), false);
        observe(
            &mut s,
            &["Existing", "New VM"],
            Some(("Windows App", 17)),
            true,
        );
        assert!(s.pending.is_empty());
    }

    #[test]
    fn crossing_spaces_retains_identity_and_a_same_title_reconnect_is_detected() {
        let mut s = Sessions::default();
        observe(&mut s, &["Desktop"], Some(("Desktop", 71)), true);
        observe(&mut s, &["Desktop"], None, true);
        observe(&mut s, &["Desktop"], Some(("Desktop", 71)), true);
        assert!(s.pending.is_empty());
        observe(&mut s, &["Desktop"], Some(("Desktop", 75)), true);
        assert!(s.pending.contains("Desktop"));
    }

    #[test]
    fn aborted_or_ambiguous_connections_cannot_close_a_later_center() {
        let mut s = Sessions::default();
        observe(&mut s, &[], None, true);
        observe(&mut s, &["VM", "VM"], None, true);
        observe(&mut s, &["VM"], None, true);
        assert!(s.pending.is_empty());
        observe(&mut s, &[], None, true);
        observe(&mut s, &["VM"], None, true);
        assert!(s.pending.contains("VM"));
        observe(&mut s, &[], None, true);
        assert!(s.pending.is_empty());
        observe(&mut s, &["VM"], None, false);
        observe(&mut s, &["VM"], None, true);
        assert!(s.pending.is_empty());
    }
}
