//! A non-modal progress panel owned by the supervisor, so opening Settings is
//! never required while an authentication attempt holds its activity guard.
use crate::iphone_sso::{Event, Phase};
use objc2::rc::Retained;
use objc2::runtime::AnyObject;
use objc2::{define_class, msg_send, sel, DefinedClass, MainThreadOnly};
use objc2_app_kit::{NSAlert, NSAlertStyle, NSFloatingWindowLevel, NSWindowStyleMask};
use objc2_foundation::{MainThreadMarker, NSObject, NSObjectProtocol, NSString};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

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
        // A cleanup error can arrive after Cancel. The operation has ended;
        // retain the error panel until its Close button is pressed.
        if event.phase.is_failure() {
            event.cancelled.store(false, Ordering::SeqCst);
        }
        if matches!(event.phase, Phase::Finished | Phase::Cancelled) {
            if self
                .panel
                .as_ref()
                .is_some_and(|panel| panel.id == event.id)
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
            if event.phase.is_failure() {
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
