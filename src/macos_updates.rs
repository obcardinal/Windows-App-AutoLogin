//! Sparkle owns download, verification, installation and relaunch. This adapter
//! only presents its standard UI and postpones installation while the supervisor
//! drains the settings child and stops credential automation.

use base64::Engine;
use block2::{DynBlock, RcBlock};
use objc2::rc::{Allocated, Retained};
use objc2::runtime::AnyObject;
use objc2::{define_class, msg_send, sel, DefinedClass, MainThreadOnly};
use objc2_app_kit::{NSAlert, NSAlertStyle, NSApplication};
use objc2_foundation::{
    MainThreadMarker, NSBundle, NSError, NSObject, NSObjectNSDelayedPerforming, NSObjectProtocol,
    NSString, NSURL,
};
use std::cell::{Cell, RefCell};
use std::path::Path;

const UNCONFIGURED: &str = "Software updates are available in the packaged macOS app. \
    This build does not include an update feed and signing key.";
const INVALID_CONFIGURATION: &str = "This app has an invalid update configuration. \
    Please install a correctly signed copy of Windows App AutoLogin.";
const FRAMEWORK_UNAVAILABLE: &str = "The bundled software updater could not be loaded. \
    Please install a complete copy of Windows App AutoLogin.";
const STARTUP_FAILED: &str = "The software updater could not start. \
    Please relaunch Windows App AutoLogin or install a complete signed copy.";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum InstallationPhase {
    #[default]
    Idle,
    WaitingForSupervisor,
    ContinuationScheduled,
    Installing,
}

#[derive(Default)]
struct InstallationState {
    phase: Cell<InstallationPhase>,
    continuation: RefCell<Option<RcBlock<dyn Fn()>>>,
    interrupted: Cell<bool>,
}

impl InstallationState {
    fn postpone(&self, continuation: RcBlock<dyn Fn()>) {
        self.continuation.replace(Some(continuation));
        self.interrupted.set(false);
        self.phase.set(InstallationPhase::WaitingForSupervisor);
    }

    fn schedule(&self) -> bool {
        if self.phase.get() != InstallationPhase::WaitingForSupervisor {
            return false;
        }
        self.phase.set(InstallationPhase::ContinuationScheduled);
        true
    }

    fn resume(&self) {
        if self.phase.get() != InstallationPhase::ContinuationScheduled {
            return;
        }
        // Release the RefCell borrow before entering Sparkle: the continuation
        // may synchronously invoke another delegate callback.
        let continuation = self.continuation.take();
        if let Some(continuation) = continuation {
            self.phase.set(InstallationPhase::Installing);
            continuation.call(());
        } else {
            self.interrupt();
        }
    }

    fn interrupt(&self) {
        if self.phase.replace(InstallationPhase::Idle) != InstallationPhase::Idle {
            self.continuation.take();
            self.interrupted.set(true);
        }
    }
}

struct DelegateState {
    feed_url: Retained<NSString>,
    installation: InstallationState,
}

define_class!(
    // SAFETY: NSObject has no subclassing requirements. All callbacks and
    // retained Sparkle blocks stay on AppKit's main thread.
    #[unsafe(super = NSObject)]
    #[thread_kind = MainThreadOnly]
    #[name = "WAALSparkleUpdaterDelegate"]
    #[ivars = DelegateState]
    struct UpdaterDelegate;

    unsafe impl NSObjectProtocol for UpdaterDelegate {}

    // Sparkle discovers these optional SPUUpdaterDelegate callbacks using
    // respondsToSelector:. No NSApplication delegate is replaced.
    impl UpdaterDelegate {
        #[unsafe(method_id(feedURLStringForUpdater:))]
        fn feed_url(&self, _updater: &AnyObject) -> Retained<NSString> {
            // A stale Sparkle user-default override must not replace the feed
            // validated from this app's signed Info.plist.
            self.ivars().feed_url.clone()
        }

        #[unsafe(method(updater:shouldPostponeRelaunchForUpdate:untilInvokingBlock:))]
        fn postpone_installation(
            &self,
            _updater: &AnyObject,
            _item: &AnyObject,
            continuation: &DynBlock<dyn Fn()>,
        ) -> bool {
            self.ivars().installation.postpone(continuation.copy());
            true
        }

        #[unsafe(method(resumeInstallation:))]
        fn resume_installation(&self, _sender: Option<&AnyObject>) {
            self.ivars().installation.resume();
        }

        #[unsafe(method(updater:didAbortWithError:))]
        fn did_abort(&self, _updater: &AnyObject, _error: &NSError) {
            self.ivars().installation.interrupt();
        }

        #[unsafe(method(updater:didFinishUpdateCycleForUpdateCheck:error:))]
        fn did_finish(
            &self,
            _updater: &AnyObject,
            _check: isize,
            _error: Option<&NSError>,
        ) {
            // A dismissed/cancelled cycle may finish without an NSError. If
            // this process survives the postponed cycle, restore the normal
            // supervisor lifecycle instead of leaving it permanently paused.
            self.ivars().installation.interrupt();
        }
    }
);

struct ActiveUpdater {
    // Drop the controller before its weakly referenced delegate and framework.
    controller: Retained<AnyObject>,
    updater: Retained<AnyObject>,
    delegate: Retained<UpdaterDelegate>,
    _framework: Retained<NSBundle>,
}

pub(crate) struct Updater {
    active: Option<ActiveUpdater>,
    unavailable_message: &'static str,
    main_thread: MainThreadMarker,
}

impl Updater {
    /// Call once from the supervisor after AppKit has finished launching.
    /// Raw Cargo builds retain an actionable menu item with an explanatory
    /// dialog; they do not look for frameworks or feeds outside their bundle.
    pub(crate) fn new() -> anyhow::Result<Self> {
        let main_thread = MainThreadMarker::new()
            .ok_or_else(|| anyhow::anyhow!("software updates require the macOS main thread"))?;
        let bundle = NSBundle::mainBundle();
        let feed = bundle_string(&bundle, "SUFeedURL");
        let key = bundle_string(&bundle, "SUPublicEDKey");
        let result = match (feed, key) {
            (Some(feed), Some(key)) if valid_feed_url(&feed) && valid_public_key(&key) => {
                if bundle_string(&bundle, "CFBundlePackageType").as_deref() != Some("APPL") {
                    Err(UNCONFIGURED)
                } else {
                    start_updater(&bundle, &feed, main_thread)
                }
            }
            (None, None) => Err(UNCONFIGURED),
            _ => Err(INVALID_CONFIGURATION),
        };
        let (active, unavailable_message) = match result {
            Ok(active) => (Some(active), UNCONFIGURED),
            Err(message) => (None, message),
        };
        Ok(Self {
            active,
            unavailable_message,
            main_thread,
        })
    }

    /// Unconfigured builds keep the command enabled to explain availability.
    pub(crate) fn can_check_for_updates(&self) -> bool {
        let Some(active) = &self.active else {
            return true;
        };
        if active.delegate.ivars().installation.phase.get() != InstallationPhase::Idle {
            return false;
        }
        // SAFETY: this retained object is the SPUUpdater returned by Sparkle.
        unsafe { msg_send![&*active.updater, canCheckForUpdates] }
    }

    pub(crate) fn check_for_updates(&self) {
        let application = NSApplication::sharedApplication(self.main_thread);
        #[allow(deprecated)]
        application.activateIgnoringOtherApps(true);
        if let Some(active) = &self.active {
            if self.can_check_for_updates() {
                // SAFETY: SPUStandardUpdaterController declares this IBAction;
                // a nil sender is the documented programmatic invocation.
                unsafe {
                    let (): () =
                        msg_send![&*active.controller, checkForUpdates: None::<&AnyObject>];
                }
            }
        } else {
            let alert = NSAlert::new(self.main_thread);
            alert.setAlertStyle(NSAlertStyle::Informational);
            alert.setMessageText(&NSString::from_str("Software Updates Unavailable"));
            alert.setInformativeText(&NSString::from_str(self.unavailable_message));
            alert.addButtonWithTitle(&NSString::from_str("OK"));
            alert.runModal();
        }
    }

    pub(crate) fn installation_pending(&self) -> bool {
        self.active.as_ref().is_some_and(|active| {
            active.delegate.ivars().installation.phase.get()
                == InstallationPhase::WaitingForSupervisor
        })
    }

    /// The supervisor calls this only after the child has drained and all
    /// automation has stopped. Invocation is deferred until the next run-loop
    /// turn, so Sparkle cannot reenter a borrowed winit application handler.
    pub(crate) fn resume_installation(&self) {
        let Some(active) = &self.active else {
            return;
        };
        if active.delegate.ivars().installation.schedule() {
            // SAFETY: this selector is implemented above with one optional
            // object argument. Foundation retains its target until delivery.
            unsafe {
                active.delegate.performSelector_withObject_afterDelay(
                    sel!(resumeInstallation:),
                    None,
                    0.0,
                );
            }
        }
    }

    /// True after the continuation is scheduled, until Sparkle exits the app
    /// or reports that the installation cycle was interrupted.
    pub(crate) fn installation_started(&self) -> bool {
        self.active.as_ref().is_some_and(|active| {
            matches!(
                active.delegate.ivars().installation.phase.get(),
                InstallationPhase::ContinuationScheduled | InstallationPhase::Installing
            )
        })
    }

    /// Includes a cancelled/dismissed installation even if Sparkle has no error.
    pub(crate) fn take_installation_error(&self) -> bool {
        self.active.as_ref().is_some_and(|active| {
            active
                .delegate
                .ivars()
                .installation
                .interrupted
                .replace(false)
        })
    }
}

fn start_updater(
    host: &NSBundle,
    feed: &str,
    main_thread: MainThreadMarker,
) -> Result<ActiveUpdater, &'static str> {
    let frameworks = host.privateFrameworksPath().ok_or(FRAMEWORK_UNAVAILABLE)?;
    let framework_path = Path::new(&frameworks.to_string()).join("Sparkle.framework");
    let host_path =
        std::fs::canonicalize(host.bundlePath().to_string()).map_err(|_| FRAMEWORK_UNAVAILABLE)?;
    let resolved_framework =
        std::fs::canonicalize(&framework_path).map_err(|_| FRAMEWORK_UNAVAILABLE)?;
    if !resolved_framework.starts_with(host_path.join("Contents/Frameworks")) {
        return Err(FRAMEWORK_UNAVAILABLE);
    }
    let framework = NSBundle::bundleWithPath(&NSString::from_str(
        framework_path.to_str().ok_or(FRAMEWORK_UNAVAILABLE)?,
    ))
    .ok_or(FRAMEWORK_UNAVAILABLE)?;
    // SAFETY: only the framework inside this application's bundle is loaded;
    // packaging signs it and all its helpers with the app's Developer ID.
    unsafe { framework.loadAndReturnError() }.map_err(|_| FRAMEWORK_UNAVAILABLE)?;
    let class = framework
        .classNamed(&NSString::from_str("SPUStandardUpdaterController"))
        .ok_or(FRAMEWORK_UNAVAILABLE)?;
    // SAFETY: the dynamically loaded class is retained for the process lifetime.
    let class_bundle = unsafe { NSBundle::bundleForClass(class) };
    if std::fs::canonicalize(class_bundle.bundlePath().to_string())
        .ok()
        .as_ref()
        != Some(&resolved_framework)
    {
        return Err(FRAMEWORK_UNAVAILABLE);
    }
    let allocated_delegate = UpdaterDelegate::alloc(main_thread).set_ivars(DelegateState {
        feed_url: NSString::from_str(feed),
        installation: InstallationState::default(),
    });
    // SAFETY: NSObject initializes this newly allocated delegate.
    let delegate: Retained<UpdaterDelegate> = unsafe { msg_send![super(allocated_delegate), init] };
    // SAFETY: these selectors and argument types follow Sparkle 2's published
    // SPUStandardUpdaterController/SPUUpdater headers. Starting explicitly lets
    // us handle configuration errors without a delayed unsolicited alert.
    let (controller, updater) = unsafe {
        let allocated: Allocated<AnyObject> = msg_send![class, alloc];
        let controller: Option<Retained<AnyObject>> = msg_send![
            allocated,
            initWithStartingUpdater: false,
            updaterDelegate: &*delegate,
            userDriverDelegate: None::<&AnyObject>
        ];
        let controller = controller.ok_or(STARTUP_FAILED)?;
        let updater: Retained<AnyObject> = msg_send![&*controller, updater];
        let mut error: Option<Retained<NSError>> = None;
        let started: bool = msg_send![&*updater, startUpdater: &mut error];
        if !started {
            return Err(STARTUP_FAILED);
        }
        let automatic_checks: bool = msg_send![&*updater, automaticallyChecksForUpdates];
        if automatic_checks {
            let (): () = msg_send![&*updater, checkForUpdatesInBackground];
        }
        (controller, updater)
    };
    Ok(ActiveUpdater {
        controller,
        updater,
        delegate,
        _framework: framework,
    })
}

fn bundle_string(bundle: &NSBundle, key: &str) -> Option<String> {
    bundle
        .objectForInfoDictionaryKey(&NSString::from_str(key))?
        .downcast_ref::<NSString>()
        .map(ToString::to_string)
}

fn valid_feed_url(value: &str) -> bool {
    if value.len() > 2048
        || value.is_empty()
        || value
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == '\\')
    {
        return false;
    }
    let Some(url) = NSURL::URLWithString(&NSString::from_str(value)) else {
        return false;
    };
    url.scheme()
        .is_some_and(|scheme| scheme.to_string().eq_ignore_ascii_case("https"))
        && url.host().is_some_and(|host| !host.is_empty())
        && url.user().is_none()
        && url.password().is_none()
        && url.fragment().is_none()
}

fn valid_public_key(value: &str) -> bool {
    value.len() == 44
        && base64::engine::general_purpose::STANDARD
            .decode(value)
            .is_ok_and(|decoded| decoded.len() == 32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::rc::Rc;

    #[test]
    fn rejects_untrusted_or_ambiguous_feed_urls() {
        assert!(valid_feed_url(
            "https://updates.example.com/autologin/appcast.xml"
        ));
        for value in [
            "",
            "http://updates.example.com/appcast.xml",
            "file:///tmp/appcast.xml",
            "https:///appcast.xml",
            "https://name:secret@example.com/appcast.xml",
            "https://example.com/appcast.xml#fragment",
            "https://example.com/a b",
            "https://example.com/a\n",
            "https://example.com\\appcast.xml",
        ] {
            assert!(!valid_feed_url(value), "unexpectedly accepted {value:?}");
        }
    }

    #[test]
    fn signing_key_must_be_exactly_32_bytes_of_base64() {
        assert!(valid_public_key(
            &base64::engine::general_purpose::STANDARD.encode([7; 32])
        ));
        for value in [
            "".to_string(),
            "a".repeat(44),
            base64::engine::general_purpose::STANDARD.encode([7; 31]),
            base64::engine::general_purpose::STANDARD.encode([7; 33]),
        ] {
            assert!(!valid_public_key(&value));
        }
    }

    #[test]
    fn continuation_waits_for_supervisor_and_runs_only_once() {
        let state = InstallationState::default();
        let calls = Rc::new(Cell::new(0));
        let block_calls = calls.clone();
        state.postpone(RcBlock::new(move || block_calls.set(block_calls.get() + 1)));
        state.resume();
        assert_eq!(calls.get(), 0);
        assert!(state.schedule());
        assert!(!state.schedule());
        assert_eq!(calls.get(), 0);
        state.resume();
        state.resume();
        assert_eq!(calls.get(), 1);
        assert_eq!(state.phase.get(), InstallationPhase::Installing);
    }

    #[test]
    fn cancelled_cycle_discards_even_a_scheduled_continuation() {
        let state = InstallationState::default();
        let calls = Rc::new(Cell::new(0));
        let block_calls = calls.clone();
        state.postpone(RcBlock::new(move || block_calls.set(block_calls.get() + 1)));
        state.schedule();
        state.interrupt();
        state.resume();
        assert_eq!(calls.get(), 0);
        assert_eq!(state.phase.get(), InstallationPhase::Idle);
        assert!(state.interrupted.replace(false));
        state.interrupt();
        assert!(!state.interrupted.get());
    }
}
