use super::{log_event, WorkerActivityTracker, WorkerEvent, WorkerPauseLatch};
use crate::macos_ax::{locked_session, SessionPresentation};
use crate::macos_lock_screen::{self, LockScreenObservation};
use crate::models::{Account, LogLevel};
use crate::monitor::MacosMonitorSnapshot;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc::Sender, Semaphore};

const RETURN_WINDOW: Duration = Duration::from_secs(12);
const SCAN_INTERVAL: Duration = Duration::from_secs(2);
const RECONNECT_COOLDOWN: Duration = Duration::from_secs(90);
const HID_SYSTEM_STATE: i32 = 1;
const LEFT_MOUSE_DOWN: u32 = 1;

#[link(name = "CoreGraphics", kind = "framework")]
extern "C" {
    fn CGEventSourceSecondsSinceLastEventType(state: i32, event: u32) -> f64;
    fn CGEventSourceCounterForEventType(state: i32, event_type: u32) -> u32;
}

fn local_idle() -> Option<Duration> {
    // Public CoreGraphics aggregate age of HID input; no event contents or keycodes.
    let age = unsafe { CGEventSourceSecondsSinceLastEventType(HID_SYSTEM_STATE, u32::MAX) };
    Duration::try_from_secs_f64(age).ok()
}

#[derive(Default)]
struct ReturnWindow {
    focused: Option<(i32, String)>,
    presentation: Option<SessionPresentation>,
    observed_away: bool,
    idle: bool,
    deadline: Option<Instant>,
    last_scan: Option<Instant>,
    last_click: Option<(u32, Instant)>,
    pending_click: Option<Instant>,
}

impl ReturnWindow {
    fn due(
        &mut self,
        target: Option<(i32, &str, Option<SessionPresentation>)>,
        idle: Duration,
        clicks: Option<u32>,
        now: Instant,
    ) -> bool {
        let Some((pid, title, presentation)) = target else {
            self.focused = None;
            self.presentation = None;
            self.observed_away = true;
            self.deadline = None;
            self.idle = false;
            self.last_click = None;
            self.pending_click = None;
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
            self.presentation = None;
            self.last_click = None;
            self.pending_click = None;
        }
        let changed_presentation = self.observe_presentation(presentation);
        if changed || changed_presentation || (self.idle && idle < RETURN_WINDOW) {
            self.deadline = Some(now + RETURN_WINDOW);
        }
        self.idle = idle >= RETURN_WINDOW;
        self.observe_click(clicks, now);
        let in_return_window = self.deadline.is_some_and(|deadline| now < deadline);
        let recent_click = self
            .pending_click
            .is_some_and(|click| now.duration_since(click) < RETURN_WINDOW);
        // Windows can lock while the same fullscreen Space stays foreground.
        // After the initial burst, new physical input (including movement or
        // typing) gets one check, then at most one per return interval.
        let active_fullscreen = presentation.is_some_and(|p| p.fullscreen == Some(true));
        let fullscreen_retry = active_fullscreen
            && self
                .last_scan
                .zip(self.deadline)
                .is_some_and(|(last, end)| {
                    let elapsed = now.duration_since(last);
                    now >= end
                    && (last < end || elapsed >= RETURN_WINDOW)
                    // Only an input newer than the last scan can trigger it.
                    // Allow for scheduling jitter between querying HID and
                    // sampling the clock in consecutive passes.
                    && elapsed > idle.saturating_add(Duration::from_millis(50))
                });
        (returned_to_window || idle < RETURN_WINDOW)
            && (in_return_window || recent_click || fullscreen_retry)
            && self
                .last_scan
                .is_none_or(|last| now.duration_since(last) >= SCAN_INTERVAL)
    }

    fn observe_presentation(&mut self, current: Option<SessionPresentation>) -> bool {
        let Some(mut current) = current else {
            return false;
        };
        let changed = self.presentation.is_some_and(|previous| {
            if previous.window_id != current.window_id {
                return true;
            }
            // AX may omit the flag while Spaces are animating. Preserve the
            // last known mode for this exact window until AX reports it again.
            if current.fullscreen.is_none() {
                current.fullscreen = previous.fullscreen;
            }
            previous.fullscreen.is_some() && previous.fullscreen != current.fullscreen
        });
        self.presentation = Some(current);
        changed
    }

    fn observe_click(&mut self, clicks: Option<u32>, now: Instant) {
        let Some(count) = clicks else {
            self.last_click = None;
            self.pending_click = None;
            return;
        };
        if let Some((previous, observed)) = self.last_click {
            if previous == count {
                return;
            }
            // One extra check for a click crossing the end of the return
            // window or starting a fresh burst. Continuous clicking inside
            // a working desktop must not keep recognition running.
            if self.deadline.is_some_and(|end| observed < end)
                || now.duration_since(observed) >= RETURN_WINDOW
            {
                self.pending_click = Some(now);
            }
        }
        self.last_click = Some((count, now));
    }

    fn scanned(&mut self, now: Instant) {
        self.last_scan = Some(now);
        self.pending_click = None;
    }
}

#[derive(Eq, Hash, PartialEq)]
enum AttemptTarget {
    Window(i32, u32),
    Account(String),
}

#[derive(Default)]
pub(super) struct ReturnMonitor {
    visit: ReturnWindow,
    attempted: Arc<Mutex<HashMap<AttemptTarget, Instant>>>,
    warmup_started: bool,
    next_warmup_permission_check: Option<Instant>,
}

impl ReturnMonitor {
    pub(super) fn prepare_recognition(&mut self, accounts: &[Account]) {
        let now = Instant::now();
        if self.warmup_started
            || self
                .next_warmup_permission_check
                .is_some_and(|next| now < next)
            || !accounts.iter().any(Account::locked_vm_reconnect_enabled)
        {
            return;
        }
        if macos_lock_screen::screen_recording_allowed() {
            self.warmup_started = true;
            macos_lock_screen::prepare_recognition();
        } else {
            self.next_warmup_permission_check = Some(now + Duration::from_secs(30));
        }
    }

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
        let Some(snapshot) = snapshot else {
            return false;
        };
        if snapshot.process_found && snapshot.target_frontmost.is_none() {
            return false;
        }
        let target = if snapshot.target_frontmost == Some(true)
            && snapshot.target_window_observed
            && snapshot.prompt_candidate_count == 0
        {
            snapshot
                .target_process_id
                .zip(snapshot.target_window_title.as_deref())
        } else {
            None
        };
        let now = Instant::now();
        let idle = target.and_then(|_| local_idle()).unwrap_or(Duration::MAX);
        let linked_target = target.filter(|(_, title)| {
            locked_session::should_probe(accounts, title, snapshot.session_presentation.is_some())
        });
        let clicks = linked_target.map(|_| unsafe {
            CGEventSourceCounterForEventType(HID_SYSTEM_STATE, LEFT_MOUSE_DOWN)
        });
        let presentation = linked_target.and(snapshot.session_presentation);
        let due = self.visit.due(
            linked_target.map(|(pid, title)| (pid, title, presentation)),
            idle,
            clicks,
            now,
        );
        tracing::trace!(
            foreground = target.is_some(),
            fullscreen = presentation.and_then(|p| p.fullscreen),
            linked = linked_target.is_some(),
            due,
            "Checking for a return to Windows App"
        );
        if !due {
            return false;
        }
        let Some((requested_pid, requested_title)) = linked_target else {
            return false;
        };
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
        self.visit.scanned(now);
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
            let probe = match locked_session::probe(
                &accounts,
                requested_pid,
                &requested_title,
                presentation.map(|p| p.window_id),
            ) {
                Ok(Some(session)) => session,
                Ok(None) => {
                    tracing::debug!(
                        "The focused desktop does not match an enabled reconnect account"
                    );
                    return;
                }
                Err(err) => {
                    tracing::debug!(reason = %err, "Could not identify the focused desktop");
                    return;
                }
            };
            let Ok(mut deadlines) = attempts.lock() else {
                return;
            };
            let now = Instant::now();
            deadlines.retain(|_, until| *until > now);
            let window_key = AttemptTarget::Window(probe.pid, probe.window_id);
            if deadlines.contains_key(&window_key)
                || probe.known_account_id().is_some_and(|id| {
                    deadlines.contains_key(&AttemptTarget::Account(id.to_owned()))
                })
            {
                tracing::trace!("Waiting to retry the locked desktop");
                return;
            }
            drop(deadlines);
            let detection_started = Instant::now();
            if cancelled() {
                return;
            }
            // Preserve account indices for the independent session-binding check.
            // A disabled duplicate must not mask the enabled account's login.
            let usernames: Vec<_> = accounts
                .iter()
                .map(|account| {
                    if account.locked_vm_reconnect_enabled() {
                        account.username.as_str()
                    } else {
                        ""
                    }
                })
                .collect();
            let observation = macos_lock_screen::observe(probe.pid, probe.window_id, &usernames);
            let visible_account = match observation {
                LockScreenObservation::Password => None,
                LockScreenObservation::AccountPassword(index) => Some(&accounts[index].id),
                _ => {
                    tracing::debug!(?observation, "No Windows password screen detected");
                    return;
                }
            };
            tracing::debug!(
                recognition_ms = detection_started.elapsed().as_millis(),
                "Recognized locked desktop"
            );
            // A Space transition can interrupt preflight while the original
            // VM stays connected. Briefly debounce those checks. The long
            // cooldown starts only when Windows App receives a close action.
            let Ok(mut deadlines) = attempts.lock() else {
                return;
            };
            deadlines.insert(window_key, Instant::now() + RETURN_WINDOW);
            drop(deadlines);
            let session = match probe.identify_locked(&accounts, &cancelled) {
                Ok(Some(session)) => session,
                Ok(None) => {
                    tracing::debug!("The active Remote PC has no unique enabled desktop binding");
                    return;
                }
                Err(err) => {
                    tracing::debug!(reason = %err, "Could not confirm the locked desktop");
                    return;
                }
            };
            if visible_account.is_some_and(|id| id != &session.account_id) {
                tracing::debug!(
                    "The Windows sign-in account differs from the linked desktop account"
                );
                return;
            }
            let account_key = AttemptTarget::Account(session.account_id.clone());
            let Ok(mut deadlines) = attempts.lock() else {
                return;
            };
            if deadlines
                .get(&account_key)
                .is_some_and(|end| *end > Instant::now())
            {
                return;
            }
            deadlines.insert(
                AttemptTarget::Account(session.account_id.clone()),
                Instant::now() + RETURN_WINDOW,
            );
            drop(deadlines);
            let before_disconnect = || {
                let mut deadlines = attempts
                    .lock()
                    .map_err(|_| anyhow::anyhow!("Reconnect state is unavailable."))?;
                deadlines.insert(account_key, Instant::now() + RECONNECT_COOLDOWN);
                Ok(())
            };
            let result =
                locked_session::reconnect(&session, &accounts, cancelled, before_disconnect);
            drop(_active);
            drop(_permit);
            match result {
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
    fn same_titled_fullscreen_transition_and_replacement_rearm_a_bounded_scan() {
        let start = Instant::now();
        let mut visit = ReturnWindow::default();
        let mut tick = |second, id: Option<u32>, fullscreen, idle| {
            let now = start + Duration::from_secs(second);
            let presentation = id.map(|window_id| SessionPresentation {
                window_id,
                fullscreen,
            });
            let due = visit.due(Some((12, "VM", presentation)), idle, Some(3), now);
            if due {
                visit.scanned(now);
            }
            due
        };
        let active = Duration::ZERO;
        assert!(tick(0, Some(5), Some(false), active));
        assert!(!tick(13, Some(5), None, active));
        assert!(!tick(14, None, None, active));
        assert!(tick(15, Some(5), Some(true), active));
        assert!(tick(28, Some(5), Some(false), active));
        assert!(!tick(41, Some(5), Some(false), active));
        assert!(tick(42, Some(6), Some(false), active));
        assert!(!tick(55, Some(6), Some(false), active));
        // A background-triggered resize or replacement cannot establish user presence.
        assert!(!tick(56, Some(6), Some(true), RETURN_WINDOW));
        assert!(!tick(57, Some(7), Some(true), RETURN_WINDOW));
        assert!(tick(58, Some(7), Some(true), active));
    }

    #[test]
    fn staying_fullscreen_rechecks_new_hid_activity_without_a_click_or_focus_change() {
        let start = Instant::now();
        let mut visit = ReturnWindow::default();
        let fullscreen = Some(SessionPresentation {
            window_id: 5,
            fullscreen: Some(true),
        });
        let mut tick = |second, input_second| {
            let now = start + Duration::from_secs(second);
            let due = visit.due(
                Some((12, "VM", fullscreen)),
                Duration::from_secs(second - input_second),
                Some(10),
                now,
            );
            if due {
                visit.scanned(now);
            }
            due
        };
        // Initial return burst, identical mouse-down count throughout.
        for t in 0..12 {
            assert_eq!(tick(t, 0), t % 2 == 0);
        }
        // The same old input never starts a scan after the return burst.
        assert!(!tick(12, 4));
        assert!(!tick(13, 5));
        // A movement/key press after the last scan immediately gets one try.
        assert!(tick(14, 14));
        for t in 15..26 {
            assert!(!tick(t, t));
        }
        assert!(tick(26, 26));
        // A stale sample remains ineligible at expiry even if clock skew
        // makes it appear a few milliseconds younger than the last scan.
        let retry = start + Duration::from_secs(38);
        assert!(!visit.due(
            Some((12, "VM", fullscreen)),
            RETURN_WINDOW - Duration::from_millis(4),
            Some(10),
            retry
        ));
        assert!(!visit.due(
            Some((12, "VM", fullscreen)),
            RETURN_WINDOW + Duration::from_secs(1),
            Some(10),
            retry + Duration::from_secs(1)
        ));
        assert!(visit.due(
            Some((12, "VM", fullscreen)),
            Duration::ZERO,
            Some(10),
            retry + Duration::from_secs(2)
        ));
    }

    #[test]
    fn sustained_activity_in_a_window_or_an_unknown_space_does_not_run_fullscreen_checks() {
        for mode in [Some(false), None] {
            let start = Instant::now();
            let presentation = Some(SessionPresentation {
                window_id: 1,
                fullscreen: mode,
            });
            let vm = Some((12, "VM", presentation));
            let mut visit = ReturnWindow::default();
            assert!(visit.due(vm, Duration::ZERO, Some(1), start));
            visit.scanned(start);
            assert!(!visit.due(vm, Duration::ZERO, Some(1), start + RETURN_WINDOW));
            assert!(!visit.due(vm, Duration::ZERO, Some(1), start + RETURN_WINDOW * 2));
        }
    }

    #[test]
    fn only_scan_in_a_bounded_window_after_return_and_space_out_samples() {
        let now = Instant::now();
        let vm = Some((12, "VM", None));
        let active = Duration::ZERO;
        let mut visit = ReturnWindow::default();
        assert!(visit.due(vm, active, None, now));
        visit.scanned(now);
        assert!(!visit.due(vm, active, None, now + Duration::from_secs(1)));
        assert!(visit.due(vm, active, None, now + SCAN_INTERVAL));
        assert!(!visit.due(vm, active, None, now + RETURN_WINDOW));
        assert!(!visit.due(None, active, None, now + RETURN_WINDOW));
        assert!(visit.due(vm, active, None, now + RETURN_WINDOW));
    }

    #[test]
    fn leaving_a_locked_vm_foreground_does_not_unlock_it_while_user_is_away() {
        let now = Instant::now();
        let vm = Some((12, "VM", None));
        let mut visit = ReturnWindow::default();
        assert!(!visit.due(vm, RETURN_WINDOW, None, now));
        assert!(!visit.due(vm, RETURN_WINDOW * 2, None, now + RETURN_WINDOW));
        assert!(visit.due(vm, Duration::ZERO, None, now + RETURN_WINDOW * 2));
    }

    #[test]
    fn returning_to_a_window_via_accessibility_needs_no_physical_mouse_event() {
        let now = Instant::now();
        let vm = Some((12, "VM", None));
        let mut visit = ReturnWindow::default();
        assert!(!visit.due(None, RETURN_WINDOW * 2, None, now));
        assert!(visit.due(vm, RETURN_WINDOW * 2, None, now + SCAN_INTERVAL));
        assert!(!visit.due(vm, RETURN_WINDOW * 2, None, now + SCAN_INTERVAL * 2));
    }

    #[test]
    fn clicking_the_same_vm_after_the_deadline_enables_one_check_per_burst() {
        let start = Instant::now();
        let vm = Some((12, "VM", None));
        let mut visit = ReturnWindow::default();
        let mut tick = |second, count| {
            let now = start + Duration::from_secs(second);
            let due = visit.due(vm, Duration::ZERO, Some(count), now);
            if due {
                visit.scanned(now);
            }
            due
        };
        assert!(tick(0, 100));
        assert!(!tick(12, 100));
        assert!(tick(18, 101));
        for i in 1..=25 {
            assert!(!tick(18 + i, (101 + i) as u32));
        }
        assert!(!tick(60, 126));
        assert!(tick(61, 127));
        assert!(!tick(64, 127));
    }

    #[test]
    fn late_click_survives_the_scan_interval_and_expires_on_focus_loss() {
        let start = Instant::now();
        let vm = Some((12, "VM", None));
        let mut visit = ReturnWindow::default();
        let tick = |visit: &mut ReturnWindow, millis, count| {
            visit.due(
                vm,
                Duration::ZERO,
                Some(count),
                start + Duration::from_millis(millis),
            )
        };
        assert!(tick(&mut visit, 0, u32::MAX));
        visit.scanned(start);
        assert!(tick(&mut visit, 11_000, u32::MAX));
        visit.scanned(start + Duration::from_secs(11));
        assert!(!tick(&mut visit, 11_500, 0)); // Counter wrapped after one click.
        assert!(!tick(&mut visit, 12_000, 0));
        assert!(tick(&mut visit, 13_000, 0)); // Resources may still be occupied.
        assert!(tick(&mut visit, 14_000, 0));
        visit.scanned(start + Duration::from_secs(14));
        assert!(!tick(&mut visit, 16_000, 0));
        assert!(tick(&mut visit, 30_000, 1));
        assert!(!visit.due(None, Duration::ZERO, None, start + Duration::from_secs(31)));
        assert!(visit.pending_click.is_none() && visit.last_click.is_none());
        assert!(tick(&mut visit, 32_000, 400));
        assert!(visit.pending_click.is_none()); // Clicks in a different app are not replayed.
    }

    #[test]
    fn returning_from_a_short_idle_period_rearms_the_same_focused_vm() {
        let now = Instant::now();
        let vm = Some((12, "VM", None));
        let mut visit = ReturnWindow::default();
        assert!(visit.due(vm, Duration::ZERO, None, now));
        visit.scanned(now);
        assert!(!visit.due(
            vm,
            Duration::from_secs(15),
            None,
            now + Duration::from_secs(15)
        ));
        assert!(visit.due(vm, Duration::ZERO, None, now + Duration::from_secs(16)));
    }
}
