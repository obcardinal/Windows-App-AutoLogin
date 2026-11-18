use super::{log_event, WorkerActivityTracker, WorkerEvent, WorkerPauseLatch};
use crate::macos_ax::locked_session;
use crate::macos_lock_screen::{self, LockScreenObservation};
use crate::models::{Account, LogLevel};
use crate::monitor::MacosMonitorSnapshot;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc::Sender, Semaphore};

const RETURN_WINDOW: Duration = Duration::from_secs(12);
const SCAN_INTERVAL: Duration = Duration::from_secs(2);
const IDLE_RETURN: Duration = Duration::from_secs(20);
const RECONNECT_COOLDOWN: Duration = Duration::from_secs(90);

#[link(name = "CoreGraphics", kind = "framework")]
extern "C" {
    fn CGEventSourceSecondsSinceLastEventType(state: i32, event: u32) -> f64;
}

fn local_idle() -> Option<Duration> {
    // Public CoreGraphics aggregate age of HID input; no event contents or keycodes.
    let age = unsafe { CGEventSourceSecondsSinceLastEventType(1, u32::MAX) };
    Duration::try_from_secs_f64(age).ok()
}

#[derive(Default)]
struct ReturnWindow {
    focused: Option<(i32, String)>,
    observed_away: bool,
    idle: bool,
    deadline: Option<Instant>,
    last_scan: Option<Instant>,
}

impl ReturnWindow {
    fn due(&mut self, target: Option<(i32, &str)>, idle: Duration, now: Instant) -> bool {
        let Some((pid, title)) = target else {
            self.focused = None;
            self.observed_away = true;
            self.deadline = None;
            self.idle = false;
            return false;
        };
        let changed = !self
            .focused
            .as_ref()
            .is_some_and(|(previous_pid, previous_title)| {
                *previous_pid == pid && previous_title == title
            });
        let returned_to_window = changed && (self.observed_away || self.focused.is_some());
        self.observed_away = false;
        if changed {
            self.focused = Some((pid, title.to_owned()));
        }
        if changed || (self.idle && idle < RETURN_WINDOW) {
            self.deadline = Some(now + RETURN_WINDOW);
        }
        self.idle = idle >= IDLE_RETURN;
        (returned_to_window || idle < RETURN_WINDOW)
            && self.deadline.is_some_and(|deadline| now < deadline)
            && self
                .last_scan
                .is_none_or(|last| now.duration_since(last) >= SCAN_INTERVAL)
    }
}

#[derive(Default)]
pub(super) struct ReturnMonitor {
    visit: ReturnWindow,
    attempted: Arc<Mutex<HashMap<String, Instant>>>,
}

impl ReturnMonitor {
    pub(super) fn reset_focus(&mut self) {
        self.visit = ReturnWindow::default();
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn poll(
        &mut self,
        snapshot: Option<&MacosMonitorSnapshot>,
        accounts: &[Account],
        slot: &Arc<Semaphore>,
        activity: &WorkerActivityTracker,
        pause: &WorkerPauseLatch,
        generation: u64,
        events: &Sender<WorkerEvent>,
    ) -> bool {
        if !accounts.iter().any(Account::locked_vm_reconnect_enabled) {
            self.reset_focus();
            return false;
        }
        let Some(snapshot) = snapshot else { return false };
        if snapshot.process_found && snapshot.target_frontmost.is_none() {
            return false;
        }
        let target = if snapshot.target_frontmost == Some(true)
            && snapshot.target_window_observed
            && snapshot.prompt_candidate_count == 0
        {
            snapshot.target_process_id.zip(snapshot.target_window_title.as_deref())
        } else {
            None
        };
        let now = Instant::now();
        let idle = local_idle().unwrap_or(Duration::MAX);
        let due = self.visit.due(target, idle, now);
        tracing::trace!(foreground = target.is_some(), due, "Checking for a return to Windows App");
        if !due {
            return false;
        }
        let Some((requested_pid, requested_title)) = target else {
            return false;
        };
        self.visit.last_scan = Some(now);
        if !macos_lock_screen::screen_recording_allowed() {
            tracing::debug!("Skipping locked desktop recognition because Screen Recording access is unavailable");
            return false;
        }
        let Ok(permit) = slot.clone().try_acquire_owned() else {
            return false;
        };
        let Some(activity_guard) = activity.begin_attempt() else {
            return false;
        };
        let accounts = accounts.to_vec();
        let requested_title = requested_title.to_owned();
        let attempts = self.attempted.clone();
        let pause = pause.clone();
        let events = events.clone();
        std::thread::spawn(move || {
            let _active = activity_guard;
            let _permit = permit;
            let cancelled = || pause.stable_unpaused_generation() != Some(generation);
            if cancelled() {
                return;
            }
            let session = match locked_session::probe(&accounts) {
                Ok(Some(session)) => session,
                Ok(None) => {
                    tracing::debug!("The focused desktop does not match an enabled reconnect account");
                    return;
                }
                Err(err) => {
                    tracing::debug!(reason = %err, "Could not identify the focused desktop");
                    return;
                }
            };
            if session.pid != requested_pid || session.title() != requested_title {
                return;
            }
            let recent = |last: &Instant| last.elapsed() < RECONNECT_COOLDOWN;
            if !attempts
                .lock()
                .is_ok_and(|a| !a.get(&session.account_id).is_some_and(recent))
            {
                return;
            }
            let detection_started = Instant::now();
            if cancelled() {
                return;
            }
            let observation = macos_lock_screen::observe(session.pid, session.window_id);
            if observation != LockScreenObservation::Password {
                tracing::debug!(?observation, "No Windows password screen detected");
                return;
            }
            tracing::debug!(
                recognition_ms = detection_started.elapsed().as_millis(),
                "Recognized locked desktop"
            );
            // Suppress a fresh RDP window for the same account as well as this
            // exact window. A failed reconnect must never cause a disconnect loop.
            let Ok(mut previous) = attempts.lock() else {
                return;
            };
            previous.retain(|_, time| recent(time));
            previous.insert(session.account_id.clone(), Instant::now());
            drop(previous);
            match locked_session::reconnect(&session, &accounts, cancelled) {
                Ok(()) => {
                    let _ = events.try_send(log_event(
                        LogLevel::Info,
                        "Requested reconnection to the locked desktop.",
                    ));
                }
                Err(_) if cancelled() => {}
                Err(err) => {
                    tracing::warn!(reason = %err, "Locked desktop reconnect stopped");
                    let _ = events.try_send(log_event(
                        LogLevel::Warn,
                        format!("Locked desktop reconnect: {err}"),
                    ));
                }
            }
        });
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_scan_in_a_bounded_window_after_return_and_space_out_samples() {
        let now = Instant::now();
        let vm = Some((12, "VM"));
        let active = Duration::ZERO;
        let mut visit = ReturnWindow::default();
        assert!(visit.due(vm, active, now));
        visit.last_scan = Some(now);
        assert!(!visit.due(vm, active, now + Duration::from_secs(1)));
        assert!(visit.due(vm, active, now + SCAN_INTERVAL));
        assert!(!visit.due(vm, active, now + RETURN_WINDOW));
        assert!(!visit.due(None, active, now + RETURN_WINDOW));
        assert!(visit.due(vm, active, now + RETURN_WINDOW));
    }

    #[test]
    fn leaving_a_locked_vm_foreground_does_not_unlock_it_while_user_is_away() {
        let now = Instant::now();
        let vm = Some((12, "VM"));
        let mut visit = ReturnWindow::default();
        assert!(!visit.due(vm, IDLE_RETURN, now));
        assert!(!visit.due(vm, IDLE_RETURN * 2, now + IDLE_RETURN));
        assert!(visit.due(vm, Duration::ZERO, now + IDLE_RETURN * 2));
    }

    #[test]
    fn returning_to_a_window_via_accessibility_needs_no_physical_mouse_event() {
        let now = Instant::now();
        let vm = Some((12, "VM"));
        let mut visit = ReturnWindow::default();
        assert!(!visit.due(None, IDLE_RETURN * 2, now));
        assert!(visit.due(vm, IDLE_RETURN * 2, now + SCAN_INTERVAL));
        assert!(!visit.due(vm, IDLE_RETURN * 2, now + SCAN_INTERVAL * 2));
    }
}
