mod recognition;

use super::{log_event, WorkerActivityTracker, WorkerEvent, WorkerPauseLatch};
use crate::macos_ax::{locked_session, SessionPresentation};
use crate::macos_lock_screen::{self, LockScreenObservation};
use crate::models::{Account, LogLevel};
use crate::monitor::MacosMonitorSnapshot;
use recognition::RecognitionMaintenance;
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc::Sender, Semaphore};

const RETURN_WINDOW: Duration = Duration::from_secs(12);
const SCAN_INTERVAL: Duration = Duration::from_secs(2);
const FOREGROUND_RECHECK_INTERVAL: Duration = Duration::from_secs(12);
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
        let recent_click = self
            .pending_click
            .is_some_and(|click| now.duration_since(click) < RETURN_WINDOW);
        // Windows can lock without any macOS focus or input event. Keep
        // sampling the focused VM after the faster checks on return.
        self.last_scan.is_none_or(|last| {
            let interval = if recent_click || self.deadline.is_some_and(|end| last < end) {
                SCAN_INTERVAL
            } else {
                FOREGROUND_RECHECK_INTERVAL
            };
            now.duration_since(last) >= interval
        })
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
    recognition: Option<RecognitionMaintenance>,
    warmup_started: bool,
    next_warmup_permission_check: Option<Instant>,
}

impl ReturnMonitor {
    pub(super) fn maintain_model_cache(&mut self, accounts: &[Account]) {
        if !accounts.iter().any(Account::locked_vm_reconnect_enabled)
            || !macos_lock_screen::supported()
        {
            if self.recognition.take().is_some() {
                self.reset_focus();
            }
            return;
        }
        if self
            .recognition
            .get_or_insert_with(RecognitionMaintenance::default)
            .update(Instant::now())
        {
            self.reset_focus();
        }
    }

    pub(super) fn prepare_recognition(&mut self) {
        let now = Instant::now();
        if self.warmup_started
            || self
                .next_warmup_permission_check
                .is_some_and(|next| now < next)
            || self
                .recognition
                .as_ref()
                .is_none_or(RecognitionMaintenance::is_repairing)
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
        let Some(snapshot) = snapshot else {
            return false;
        };
        let Some(maintenance) = self.recognition.as_ref() else {
            return false;
        };
        if maintenance.waiting_for_rescan() {
            return false;
        }
        if snapshot.process_found && snapshot.target_frontmost.is_none() {
            return false;
        }
        let target = reconnect_target(snapshot);
        let now = Instant::now();
        let idle = target.and_then(|_| local_idle()).unwrap_or(Duration::MAX);
        let linked_target = target.filter(|(_, title, presentation)| {
            locked_session::should_probe(accounts, title, presentation.is_some())
        });
        let clicks = linked_target.map(|_| unsafe {
            CGEventSourceCounterForEventType(HID_SYSTEM_STATE, LEFT_MOUSE_DOWN)
        });
        let presentation = linked_target.and_then(|(_, _, p)| p);
        let due = self.visit.due(linked_target, idle, clicks, now);
        tracing::trace!(
            foreground = target.is_some(),
            fullscreen = presentation.and_then(|p| p.fullscreen),
            linked = linked_target.is_some(),
            due,
            "Checking the focused Windows desktop"
        );
        if !due {
            return false;
        }
        let Some((requested_pid, requested_title, _)) = linked_target else {
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
        let recognition_failed = maintenance.failure_signal();
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
                LockScreenObservation::RecognitionFailed => {
                    // The maintenance worker coalesces this failure with cache
                    // events, after this thread gives up the automation slot.
                    recognition_failed.store(true, Ordering::Release);
                    return;
                }
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

fn reconnect_target(
    snapshot: &MacosMonitorSnapshot,
) -> Option<(i32, &str, Option<SessionPresentation>)> {
    if snapshot.prompt_candidate_count != 0 || snapshot.selected_prompt_present {
        return None;
    }
    let pid = snapshot.target_process_id?;
    if snapshot.target_frontmost == Some(true) && snapshot.target_window_observed {
        return Some((
            pid,
            snapshot.target_window_title.as_deref()?,
            snapshot.session_presentation,
        ));
    }
    let desktop = snapshot
        .split_focus_desktop
        .as_ref()
        .filter(|d| d.process_id == pid)?;
    Some((pid, &desktop.title, Some(desktop.presentation)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn focused_vm_is_checked_throughout_inactivity_in_each_window_mode() {
        for mode in [Some(true), Some(false), None] {
            let start = Instant::now();
            let vm = Some((
                12,
                "VM",
                Some(SessionPresentation {
                    window_id: 5,
                    fullscreen: mode,
                }),
            ));
            let mut visit = ReturnWindow::default();
            let mut scans = Vec::new();
            for second in 0..=60 {
                let now = start + Duration::from_secs(second);
                if visit.due(vm, Duration::MAX, Some(0), now) {
                    visit.scanned(now);
                    scans.push(second);
                }
            }
            assert_eq!(scans, [0, 2, 4, 6, 8, 10, 12, 24, 36, 48, 60]);
        }
    }

    #[test]
    fn losing_focus_stops_checks_until_return_even_if_idle() {
        let start = Instant::now();
        let vm = Some((12, "VM", None));
        let mut visit = ReturnWindow::default();
        assert!(visit.due(vm, Duration::MAX, None, start));
        visit.scanned(start);
        for second in 1..=60 {
            assert!(!visit.due(
                None,
                Duration::ZERO,
                Some(second as u32),
                start + Duration::from_secs(second)
            ));
        }
        let back = start + Duration::from_secs(61);
        assert!(visit.due(vm, Duration::MAX, None, back));
        visit.scanned(back);
        assert!(!visit.due(vm, Duration::MAX, None, back + Duration::from_secs(1)));
        assert!(visit.due(vm, Duration::MAX, None, back + SCAN_INTERVAL));
    }

    #[test]
    fn reconnect_admits_the_verified_key_desktop_only_without_credential_candidates() {
        let presentation = SessionPresentation {
            window_id: 51,
            fullscreen: Some(true),
        };
        let mut snapshot = MacosMonitorSnapshot {
            process_found: true,
            target_process_id: Some(12),
            target_window_title: Some("Connection Center".into()),
            target_frontmost: Some(false),
            target_window_observed: true,
            session_presentation: None,
            split_focus_desktop: Some(crate::macos_ax::ReconnectDesktop {
                process_id: 12,
                title: "VM".into(),
                presentation,
            }),
            selected_prompt_present: false,
            prompt_candidate_count: 0,
        };
        assert_eq!(
            reconnect_target(&snapshot),
            Some((12, "VM", Some(presentation)))
        );
        snapshot.prompt_candidate_count = 2;
        assert!(reconnect_target(&snapshot).is_none());
        snapshot.prompt_candidate_count = 0;
        snapshot.selected_prompt_present = true;
        assert!(reconnect_target(&snapshot).is_none());
        snapshot.selected_prompt_present = false;
        snapshot.target_process_id = Some(13);
        assert!(reconnect_target(&snapshot).is_none());
        snapshot.target_process_id = Some(12);
        snapshot.split_focus_desktop = None;
        assert!(reconnect_target(&snapshot).is_none());
    }

    #[test]
    fn visible_background_vm_is_excluded_from_reconnect() {
        let snapshot = MacosMonitorSnapshot {
            process_found: true,
            target_process_id: Some(12),
            target_window_title: Some("VM".into()),
            target_frontmost: Some(false),
            target_window_observed: true,
            session_presentation: Some(SessionPresentation {
                window_id: 5,
                fullscreen: Some(false),
            }),
            split_focus_desktop: None,
            selected_prompt_present: false,
            prompt_candidate_count: 0,
        };
        let mut account = Account::new("user@example.test");
        account.vm_target = "VM".into();
        account.vm_device_id = "open-window".into();
        account.has_saved_password = true;
        let mut monitor = ReturnMonitor {
            recognition: Some(RecognitionMaintenance::default()),
            ..Default::default()
        };
        monitor.visit.focused = Some((12, "VM".into()));
        let (events, _) = tokio::sync::mpsc::channel(1);
        assert!(!monitor.poll(
            Some(&snapshot),
            &[account],
            &Arc::new(Semaphore::new(0)),
            &WorkerActivityTracker::default(),
            &crate::background::WorkerInvalidator::new().pause_latch(),
            0,
            &events,
        ));
        assert!(monitor.visit.focused.is_none());
        assert!(monitor.visit.last_scan.is_none());
    }

    #[test]
    fn presentation_changes_restart_fast_checks_while_idle() {
        let start = Instant::now();
        let mut visit = ReturnWindow::default();
        let mut tick = |second, id: Option<u32>, fullscreen| {
            let now = start + Duration::from_secs(second);
            let presentation = id.map(|window_id| SessionPresentation {
                window_id,
                fullscreen,
            });
            let due = visit.due(Some((12, "VM", presentation)), Duration::MAX, None, now);
            if due {
                visit.scanned(now);
            }
            due
        };
        assert!(tick(0, Some(5), Some(false)));
        assert!(tick(12, Some(5), Some(false)));
        assert!(!tick(14, Some(5), None));
        assert!(!tick(15, None, None));
        assert!(tick(16, Some(5), Some(true)));
        assert!(tick(28, Some(5), Some(true)));
        assert!(!tick(30, Some(5), Some(true)));
        assert!(tick(31, Some(6), Some(true)));
    }

    #[test]
    fn a_new_click_can_run_before_the_next_periodic_check() {
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
        assert!(tick(12, 100));
        assert!(!tick(16, 100));
        assert!(tick(18, 101));
        for i in 1..=25 {
            assert_eq!(tick(18 + i, (101 + i) as u32), i % 12 == 0);
        }
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
        let idle = now + Duration::from_secs(15);
        assert!(visit.due(vm, Duration::from_secs(15), None, idle));
        visit.scanned(idle);
        assert!(!visit.due(
            vm,
            Duration::from_secs(18),
            None,
            idle + Duration::from_secs(3)
        ));
        assert!(visit.due(vm, Duration::ZERO, None, idle + Duration::from_secs(4)));
    }
}
