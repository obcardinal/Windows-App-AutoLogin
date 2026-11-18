//! A non-modal progress panel owned by the supervisor, so opening Settings is
//! never required while an authentication attempt holds its activity guard.
use crate::iphone_sso::{Event, Phase};
use objc2::rc::Retained;
use objc2::runtime::AnyObject;
use objc2::{define_class, msg_send, sel, DefinedClass, MainThreadOnly};
use objc2_app_kit::{NSAlert, NSAlertStyle, NSFloatingWindowLevel, NSWindowStyleMask};
use objc2_foundation::{MainThreadMarker, NSObject, NSObjectProtocol, NSString};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

pub(crate) type ProgressProxy = Arc<winit::event_loop::EventLoopProxy<PendingProgress>>;

/// Each sign-in attempt has at most one pending main-thread notification.
#[derive(Clone, Default, Debug)]
pub(crate) struct PendingProgress(Arc<Mutex<Option<Event>>>);

impl PendingProgress {
    pub(crate) fn publish(&self, event: Event, wake: impl FnOnce(Self)) {
        let needs_wake = self.0.lock().unwrap().replace(event).is_none();
        if needs_wake {
            wake(self.clone());
        }
    }

    pub(crate) fn take(&self) -> Option<Event> {
        self.0.lock().unwrap().take()
    }
}

define_class!(
    #[unsafe(super = NSObject)]
    #[thread_kind = MainThreadOnly]
    #[name = "WAALIphoneAssistanceTarget"]
    #[ivars = Arc<AtomicBool>]
    struct CancelTarget;

    unsafe impl NSObjectProtocol for CancelTarget {}

    impl CancelTarget {
        #[unsafe(method(cancel:))]
        fn cancel(&self, _sender: Option<&AnyObject>) {
            self.ivars().store(true, Ordering::SeqCst);
        }
    }
);

struct Panel {
    id: u64,
    alert: Retained<NSAlert>,
    target: Retained<CancelTarget>,
    phase: Phase,
}

impl Drop for Panel {
    fn drop(&mut self) {
        self.alert.window().orderOut(None);
    }
}

#[derive(Default)]
pub(crate) struct ProgressUi {
    panel: Option<Panel>,
}

impl ProgressUi {
    pub(crate) fn update(&mut self, event: Event) {
        // Keep final errors and the manual approval instructions visible until dismissed.
        if event.phase.needs_close_button() {
            event.cancelled.store(false, Ordering::SeqCst);
        }
        if matches!(event.phase, Phase::Finished | Phase::Cancelled) {
            // The first phase displayed for a newer attempt can be its last.
            if self
                .panel
                .as_ref()
                .is_some_and(|panel| panel.id <= event.id)
            {
                self.panel = None;
            }
            return;
        }
        let Some(mtm) = MainThreadMarker::new() else {
            return;
        };
        if self.panel.as_ref().is_none_or(|panel| panel.id != event.id) {
            let allocated = CancelTarget::alloc(mtm).set_ivars(event.cancelled);
            // SAFETY: NSObject init initializes this retained main-thread target.
            let target: Retained<CancelTarget> = unsafe { msg_send![super(allocated), init] };
            let alert = NSAlert::new(mtm);
            alert.setAlertStyle(NSAlertStyle::Informational);
            alert.setMessageText(&NSString::from_str("Sign in with iPhone"));
            alert.setInformativeText(&NSString::from_str(event.phase.message()));
            let button = alert.addButtonWithTitle(&NSString::from_str("Cancel"));
            // SAFETY: Target remains retained alongside this alert and implements
            // the AppKit action signature; NSControl does not retain its target.
            unsafe {
                button.setTarget(Some(&target));
                button.setAction(Some(sel!(cancel:)));
            }
            alert.layout();
            let window = alert.window();
            window.setStyleMask(window.styleMask() | NSWindowStyleMask::NonactivatingPanel);
            window.setLevel(NSFloatingWindowLevel);
            window.setHidesOnDeactivate(false);
            window.center();
            // Show without stealing focus from the trusted Windows App dialog.
            window.orderFrontRegardless();
            self.panel = Some(Panel {
                id: event.id,
                alert,
                target,
                phase: event.phase,
            });
        }
        if let Some(panel) = &mut self.panel {
            if panel.phase != event.phase {
                panel
                    .alert
                    .setInformativeText(&NSString::from_str(event.phase.message()));
                panel.alert.layout();
                panel.phase = event.phase;
            }
            if event.phase.needs_close_button() {
                panel
                    .alert
                    .buttons()
                    .objectAtIndex(0)
                    .setTitle(&NSString::from_str("Close"));
            }
        }
    }

    pub(crate) fn poll(&mut self) {
        if self
            .panel
            .as_ref()
            .is_some_and(|panel| panel.target.ivars().load(Ordering::SeqCst))
        {
            self.panel = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_wakes_once_per_pending_update_and_preserves_each_attempts_last_phase() {
        let first = PendingProgress::default();
        let second = PendingProgress::default();
        let mut wakes = Vec::new();
        let event = |id, phase| Event {
            id,
            phase,
            cancelled: Arc::new(AtomicBool::new(false)),
        };
        first.publish(event(1, Phase::Preparing), |wake| wakes.push(wake));
        first.publish(event(1, Phase::Connecting), |_| panic!("already awake"));
        assert_eq!(
            wakes.pop().unwrap().take().unwrap().phase,
            Phase::Connecting
        );

        first.publish(event(1, Phase::FaceId), |wake| wakes.push(wake));
        first.publish(event(1, Phase::Failed), |_| panic!("already awake"));
        second.publish(event(2, Phase::Preparing), |wake| wakes.push(wake));
        second.publish(event(2, Phase::Cancelled), |_| panic!("already awake"));
        let shown: Vec<_> = wakes
            .iter()
            .map(|wake| {
                let event = wake.take().unwrap();
                (event.id, event.phase)
            })
            .collect();
        assert_eq!(shown, [(1, Phase::Failed), (2, Phase::Cancelled)]);
    }
}
