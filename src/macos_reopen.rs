use crate::tray::TrayCommand;
use objc2::rc::Retained;
use objc2::{define_class, msg_send, sel, DefinedClass, MainThreadOnly};
use objc2_app_kit::NSApplicationWillFinishLaunchingNotification;
use objc2_foundation::{
    MainThreadMarker, NSAppleEventDescriptor, NSAppleEventManager, NSNotification,
    NSNotificationCenter, NSObject, NSObjectProtocol,
};
use std::sync::mpsc::Sender;

const CORE_EVENT_CLASS: u32 = u32::from_be_bytes(*b"aevt");
const REOPEN_APPLICATION_EVENT: u32 = u32::from_be_bytes(*b"rapp");
const INTERNET_EVENT_CLASS: u32 = u32::from_be_bytes(*b"GURL");
const GET_URL_EVENT: u32 = u32::from_be_bytes(*b"GURL");
const DIRECT_OBJECT_KEYWORD: u32 = u32::from_be_bytes(*b"----");
const CHECK_FOR_UPDATES_URL: &str = "windows-app-autologin://check-for-updates";

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

    fn handle_url(&self, url: &str) {
        if !is_check_for_updates_url(url) {
            return;
        }
        tracing::debug!(target: "waal::updates", forward = self.forward_to_supervisor, "Received update-check URL");
        if self.forward_to_supervisor {
            // Sparkle belongs to the supervisor, including when LaunchServices
            // delivers this URL to an already-running Accounts/Settings child.
            // Keep the authenticated IPC handshake off the AppKit thread.
            if let Err(error) = std::thread::Builder::new()
                .name("ui-update-check".to_string())
                .spawn(|| {
                    if let Err(error) = crate::single_instance::request_check_for_updates() {
                        tracing::warn!(%error, "Could not forward the update check to the supervisor");
                    }
                })
            {
                tracing::warn!(%error, "Could not schedule the update check");
            }
        } else {
            let _ = self.tx.send(TrayCommand::CheckForUpdates);
        }
    }
}

fn is_check_for_updates_url(url: &str) -> bool {
    // This is a fixed action, not a generic URL/command interface. Scheme and
    // host are case-insensitive; paths, parameters and alternate feeds are not
    // accepted, even when percent-encoding could normalize them to this URL.
    url.eq_ignore_ascii_case(CHECK_FOR_UPDATES_URL)
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
            event: Option<&NSAppleEventDescriptor>,
            _reply: Option<&NSAppleEventDescriptor>,
        ) {
            tracing::debug!(
                target: "waal::updates",
                pid = std::process::id(),
                forward = self.ivars().forward_to_supervisor,
                event_class = ?event.map(NSAppleEventDescriptor::eventClass),
                event_id = ?event.map(NSAppleEventDescriptor::eventID),
                "Entered macOS reopen event handler"
            );
            // Keep all window and monitor state transitions on the existing supervisor path.
            self.ivars().open_accounts();
        }

        // SAFETY: NSApplication posts this notification on its main thread.
        #[unsafe(method(applicationWillFinishLaunching:))]
        fn application_will_finish_launching(&self, _notification: &NSNotification) {
            tracing::debug!(
                target: "waal::updates",
                pid = std::process::id(),
                "Refreshing activation handlers before AppKit finishes launching"
            );
            register_handlers(&NSAppleEventManager::sharedAppleEventManager(), self);
        }

        // SAFETY: NSAppleEventManager invokes this selector with event/reply descriptors.
        #[unsafe(method(handleGetURL:withReplyEvent:))]
        fn handle_get_url(
            &self,
            event: Option<&NSAppleEventDescriptor>,
            _reply: Option<&NSAppleEventDescriptor>,
        ) {
            tracing::debug!(
                target: "waal::updates",
                pid = std::process::id(),
                forward = self.ivars().forward_to_supervisor,
                event_present = event.is_some(),
                event_class = ?event.map(NSAppleEventDescriptor::eventClass),
                event_id = ?event.map(NSAppleEventDescriptor::eventID),
                "Entered macOS URL event handler"
            );
            let Some(descriptor) =
                event.and_then(|event| event.paramDescriptorForKeyword(DIRECT_OBJECT_KEYWORD))
            else {
                tracing::debug!(target: "waal::updates", "URL event has no direct-object descriptor");
                return;
            };
            let url = descriptor.stringValue();
            tracing::debug!(
                target: "waal::updates",
                descriptor_type = descriptor.descriptorType(),
                string_present = url.is_some(),
                utf16_length = ?url.as_ref().map(|value| value.length()),
                "Inspected macOS URL event shape"
            );
            let Some(url) = url else {
                return;
            };
            // Check the UTF-16 length before allocating a Rust string. The one
            // accepted route is ASCII and has a fixed, short representation.
            if url.length() == CHECK_FOR_UPDATES_URL.len() {
                self.ivars().handle_url(&url.to_string());
            }
        }
    }
);

pub(crate) struct ReopenRegistration {
    manager: Retained<NSAppleEventManager>,
    notification_center: Retained<NSNotificationCenter>,
    handler: Retained<ReopenHandler>,
}

/// Install after EventLoop::new initializes AppKit, before native startup work,
/// then refresh from `resumed`. Early registration receives the launch URL;
/// refreshing preserves reopen handling after AppKit finishes application launch.
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
    let notification_center = NSNotificationCenter::defaultCenter();
    // Cocoa recommends registering URL Apple-event handlers at will-finish-
    // launching, before it delivers the initial event. Retain our existing
    // handler and leave winit's application delegate in place.
    // SAFETY: The retained handler implements the notification selector with
    // its required signature. Drop removes this exact observer before release.
    unsafe {
        notification_center.addObserver_selector_name_object(
            &handler,
            sel!(applicationWillFinishLaunching:),
            Some(NSApplicationWillFinishLaunchingNotification),
            None,
        );
    }
    let registration = ReopenRegistration {
        manager,
        notification_center,
        handler,
    };
    registration.refresh();
    Ok(registration)
}

impl ReopenRegistration {
    pub(crate) fn refresh(&self) {
        register_handlers(&self.manager, &self.handler);
    }
}

fn register_handlers(manager: &NSAppleEventManager, handler: &ReopenHandler) {
    // Handle only reopening and the fixed updater URL. Replacing
    // NSApplication's delegate would interfere with winit's lifecycle.
    // SAFETY: The retained handler implements each selector with the required
    // signature, and registration stays on the AppKit main thread.
    unsafe {
        manager.setEventHandler_andSelector_forEventClass_andEventID(
            handler,
            sel!(handleReopen:withReplyEvent:),
            CORE_EVENT_CLASS,
            REOPEN_APPLICATION_EVENT,
        );
        manager.setEventHandler_andSelector_forEventClass_andEventID(
            handler,
            sel!(handleGetURL:withReplyEvent:),
            INTERNET_EVENT_CLASS,
            GET_URL_EVENT,
        );
    }
    tracing::debug!(
        target: "waal::updates",
        pid = std::process::id(),
        forward = handler.ivars().forward_to_supervisor,
        "Registered macOS activation handlers"
    );
}

impl Drop for ReopenRegistration {
    fn drop(&mut self) {
        tracing::debug!(
            target: "waal::updates",
            pid = std::process::id(),
            forward = self.handler.ivars().forward_to_supervisor,
            "Unregistering macOS activation handlers"
        );
        // SAFETY: This removes only the observer installed for our retained
        // handler; the handler is still alive throughout unregistration.
        unsafe {
            self.notification_center.removeObserver_name_object(
                &self.handler,
                Some(NSApplicationWillFinishLaunchingNotification),
                None,
            );
        }
        self.manager
            .removeEventHandlerForEventClass_andEventID(CORE_EVENT_CLASS, REOPEN_APPLICATION_EVENT);
        self.manager
            .removeEventHandlerForEventClass_andEventID(INTERNET_EVENT_CLASS, GET_URL_EVENT);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn updater_url_accepts_only_the_fixed_action() {
        assert!(is_check_for_updates_url(CHECK_FOR_UPDATES_URL));
        assert!(is_check_for_updates_url(
            "WINDOWS-APP-AUTOLOGIN://CHECK-FOR-UPDATES"
        ));
        for invalid in [
            "",
            "windows-app-autologin://",
            "windows-app-autologin://check-for-updates/",
            "windows-app-autologin://check-for-updates?feed=https://example.com/appcast.xml",
            "windows-app-autologin://check-for-updates#fragment",
            "windows-app-autologin://check-for-updates/quit",
            "windows-app-autologin://user@check-for-updates",
            "windows-app-autologin://check-for-updates:80",
            "windows-app-autologin://%63heck-for-updates",
            "windows-app-autologin:///check-for-updates",
            "windows-app-autologin:check-for-updates",
            "windows-app-autologin://check-for-updates\n",
            " windows-app-autologin://check-for-updates",
            "windows-app-autologin://check-for-updates\0",
            "https://check-for-updates",
            "windows-app-autologin://quit",
            "windows-app-autologin://сheck-for-updates",
        ] {
            assert!(!is_check_for_updates_url(invalid), "accepted {invalid:?}");
        }
    }

    #[test]
    fn accepted_url_queues_only_update_check_on_supervisor() {
        let (tx, rx) = std::sync::mpsc::channel();
        let target = ReopenTarget {
            tx,
            forward_to_supervisor: false,
        };
        target.handle_url("windows-app-autologin://check-for-updates?command=quit");
        assert!(rx.try_recv().is_err());
        target.handle_url(CHECK_FOR_UPDATES_URL);
        assert!(matches!(rx.try_recv(), Ok(TrayCommand::CheckForUpdates)));
        assert!(rx.try_recv().is_err());
    }
}
