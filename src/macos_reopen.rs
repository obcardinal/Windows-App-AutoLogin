use crate::tray::TrayCommand;
use objc2::rc::Retained;
use objc2::{define_class, msg_send, sel, DefinedClass, MainThreadOnly};
use objc2_foundation::{
    MainThreadMarker, NSAppleEventDescriptor, NSAppleEventManager, NSObject, NSObjectProtocol,
};
use std::sync::mpsc::Sender;

const CORE_EVENT_CLASS: u32 = u32::from_be_bytes(*b"aevt");
const REOPEN_APPLICATION_EVENT: u32 = u32::from_be_bytes(*b"rapp");

struct ReopenTarget {
    tx: Sender<TrayCommand>,
    forward_to_supervisor: bool,
}

impl ReopenTarget {
    fn open_accounts(&self) {
        if self.forward_to_supervisor {
            let fallback = self.tx.clone();
            // LaunchServices may target either process in this bundle. Ask
            // the supervisor for fresh icon geometry without blocking AppKit.
            if std::thread::Builder::new()
                .name("ui-reopen".to_string())
                .spawn(move || {
                    if let Err(error) = crate::single_instance::request_activation() {
                        tracing::warn!(%error, "Could not forward app reopening; restoring the existing UI");
                        let _ = fallback.send(TrayCommand::OpenAccounts);
                    }
                })
                .is_ok()
            {
                return;
            }
        }
        let _ = self.tx.send(TrayCommand::OpenAccounts);
    }
}

define_class!(
    // SAFETY: NSObject has no subclassing requirements; this class has no Drop implementation.
    #[unsafe(super = NSObject)]
    #[thread_kind = MainThreadOnly]
    #[name = "WAALReopenApplicationHandler"]
    #[ivars = ReopenTarget]
    struct ReopenHandler;

    // SAFETY: NSObjectProtocol has no additional requirements.
    unsafe impl NSObjectProtocol for ReopenHandler {}

    impl ReopenHandler {
        // SAFETY: NSAppleEventManager invokes this selector with the event and reply descriptors.
        #[unsafe(method(handleReopen:withReplyEvent:))]
        fn handle_reopen(
            &self,
            _event: Option<&NSAppleEventDescriptor>,
            _reply: Option<&NSAppleEventDescriptor>,
        ) {
            // Keep all window and monitor state transitions on the existing supervisor path.
            self.ivars().open_accounts();
        }
    }
);

pub(crate) struct ReopenRegistration {
    manager: Retained<NSAppleEventManager>,
    _handler: Retained<ReopenHandler>,
}

/// Install from winit's first `resumed` callback and retain until the event loop exits.
/// AppKit replaces an earlier Apple-event registration while finishing application launch.
pub(crate) fn install(tx: Sender<TrayCommand>) -> anyhow::Result<ReopenRegistration> {
    install_target(ReopenTarget {
        tx,
        forward_to_supervisor: false,
    })
}

pub(crate) fn install_for_ui(tx: Sender<TrayCommand>) -> anyhow::Result<ReopenRegistration> {
    install_target(ReopenTarget {
        tx,
        forward_to_supervisor: true,
    })
}

fn install_target(target: ReopenTarget) -> anyhow::Result<ReopenRegistration> {
    let mtm = MainThreadMarker::new()
        .ok_or_else(|| anyhow::anyhow!("macOS reopen handler requires the main thread"))?;
    let allocated = ReopenHandler::alloc(mtm).set_ivars(target);
    // SAFETY: NSObject's init initializes the newly allocated handler and returns the same type.
    let handler: Retained<ReopenHandler> = unsafe { msg_send![super(allocated), init] };
    let manager = NSAppleEventManager::sharedAppleEventManager();
    // Handle only LaunchServices reopen events. Replacing NSApplication's delegate would
    // interfere with winit's lifecycle and event delivery.
    // SAFETY: The retained handler implements this selector with the required signature.
    unsafe {
        manager.setEventHandler_andSelector_forEventClass_andEventID(
            &handler,
            sel!(handleReopen:withReplyEvent:),
            CORE_EVENT_CLASS,
            REOPEN_APPLICATION_EVENT,
        );
    }
    Ok(ReopenRegistration {
        manager,
        _handler: handler,
    })
}

impl Drop for ReopenRegistration {
    fn drop(&mut self) {
        self.manager
            .removeEventHandlerForEventClass_andEventID(CORE_EVENT_CLASS, REOPEN_APPLICATION_EVENT);
    }
}
