//! App-level macOS notifications wake an ordinary, fully verified monitor pass.
use core_foundation::base::{CFOptionFlags, CFType, CFTypeRef, TCFType};
use core_foundation::filedescriptor::{
    kCFFileDescriptorReadCallBack, CFFileDescriptor, CFFileDescriptorRef,
};
use core_foundation::runloop::{
    kCFRunLoopDefaultMode, CFRunLoop, CFRunLoopSource, CFRunLoopSourceRef,
};
use core_foundation::string::{CFString, CFStringRef};
use std::ffi::c_void;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::ptr;
use std::sync::mpsc::{sync_channel, Receiver as WindowReceiver, SyncSender};
use std::thread::Thread;
use std::time::Instant;
use tokio::sync::mpsc::{self, Receiver, Sender};

#[derive(Default)]
pub(super) struct WindowHints {
    pid: Option<i32>,
    subscription: Option<Subscription>,
    early_until: Option<Instant>,
}

struct Subscription {
    hints: Receiver<()>,
    _lifetime: UnixStream,
}

pub(crate) struct WindowObservation {
    // Closing the peer stops the native run loop, including when cancellation
    // happens before it has installed its sources.
    _lifetime: UnixStream,
    windows: WindowReceiver<ObservedElement>,
}

struct ObservedElement(CFType);
// SAFETY: This wrapper only receives a retained AXUIElementRef, an immutable
// remote proxy. The producer only retains it; AX queries run on the receiver.
unsafe impl Send for ObservedElement {}

const WINDOW_QUEUE_LIMIT: usize = 16;

enum Wake {
    Prompt(Sender<()>),
    Connection(Thread, SyncSender<ObservedElement>),
}

impl Wake {
    unsafe fn notify(&self, element: CFTypeRef, notification: CFStringRef) {
        match self {
            Self::Prompt(sender) => {
                let _ = sender.try_send(());
            }
            Self::Connection(worker, windows) => {
                if !element.is_null() && !notification.is_null() {
                    let name = CFString::wrap_under_get_rule(notification);
                    if name != CFString::from_static_string("AXApplicationActivated") {
                        let proxy = ObservedElement(CFType::wrap_under_get_rule(element));
                        let _ = windows.try_send(proxy);
                    }
                }
                worker.unpark();
            }
        }
    }

    fn is_closed(&self) -> bool {
        matches!(self, Self::Prompt(sender) if sender.is_closed())
    }
}

impl WindowHints {
    pub(super) fn set_target(&mut self, pid: Option<i32>) {
        if self.pid == pid {
            return;
        }
        self.subscription = None;
        self.pid = pid;
        self.early_until = None;
        if let Some(pid) = pid {
            self.subscription = Subscription::start(pid);
        }
    }

    pub(super) fn targets(&self, pid: i32) -> bool {
        self.pid == Some(pid)
    }

    pub(super) fn begin_pass(&mut self, now: Instant) -> Option<Instant> {
        if let Some(sub) = &mut self.subscription {
            // This fresh inspection covers anything queued before it starts.
            let _ = sub.hints.try_recv();
        }
        self.early_until.take().filter(|deadline| now < *deadline)
    }

    pub(super) async fn wait(&mut self, deadline: Instant, allow_hint: bool) {
        let timer = tokio::time::sleep_until(deadline.into());
        if let Some(sub) = self.subscription.as_mut().filter(|_| allow_hint) {
            tokio::select! {
                biased;
                _ = timer => {}
                Some(()) = sub.hints.recv() => self.early_until = Some(deadline),
            }
        } else {
            timer.await;
        }
    }
}

impl Subscription {
    fn start(pid: i32) -> Option<Self> {
        let (sender, hints) = mpsc::channel(1);
        let lifetime = start_observation(pid, Wake::Prompt(sender))?;
        Some(Self {
            hints,
            _lifetime: lifetime,
        })
    }
}

/// Wakes the connection watcher for a fresh inspection. Thread park tokens
/// coalesce repeated notifications and retain a wake that precedes the wait.
pub(crate) fn observe_connection_windows(pid: i32, wake: Thread) -> Option<WindowObservation> {
    let (sender, windows) = sync_channel(WINDOW_QUEUE_LIMIT);
    Some(WindowObservation {
        _lifetime: start_observation(pid, Wake::Connection(wake, sender))?,
        windows,
    })
}

impl WindowObservation {
    /// Notifications can refer to unrelated windows or to the application
    /// itself. Resolve the owner, role and window identity on the watcher.
    pub(crate) fn take_window(&self) -> Option<CFType> {
        self.windows.try_recv().ok().map(|proxy| proxy.0)
    }
}

fn start_observation(pid: i32, wake: Wake) -> Option<UnixStream> {
    let (lifetime, cancellation) = UnixStream::pair().ok()?;
    std::thread::Builder::new()
        .name("desktop-window-observer".to_owned())
        .spawn(move || observe_windows(pid, wake, cancellation))
        .ok()?;
    Some(lifetime)
}

type ObserverCallback = extern "C" fn(CFTypeRef, CFTypeRef, CFStringRef, *mut c_void);

#[link(name = "ApplicationServices", kind = "framework")]
unsafe extern "C" {
    fn AXUIElementCreateApplication(pid: i32) -> CFTypeRef;
    fn AXUIElementSetMessagingTimeout(element: CFTypeRef, timeout: f32) -> i32;
    fn AXObserverCreate(pid: i32, callback: ObserverCallback, observer: *mut CFTypeRef) -> i32;
    fn AXObserverAddNotification(
        observer: CFTypeRef,
        element: CFTypeRef,
        name: CFStringRef,
        context: *mut c_void,
    ) -> i32;
    fn AXObserverGetRunLoopSource(observer: CFTypeRef) -> CFRunLoopSourceRef;
}

extern "C" fn received_window_hint(
    _: CFTypeRef,
    element: CFTypeRef,
    notification: CFStringRef,
    context: *mut c_void,
) {
    // SAFETY: Registration and delivery share one thread. Its wake handle lives
    // until after both the run-loop source and observer have been removed.
    unsafe { (&*context.cast::<Wake>()).notify(element, notification) };
}

extern "C" fn cancel_observation(_: CFFileDescriptorRef, _: CFOptionFlags, _: *mut c_void) {
    CFRunLoop::get_current().stop();
}

fn observe_windows(pid: i32, wake: Wake, cancellation: UnixStream) {
    let Some(stop_fd) =
        CFFileDescriptor::new(cancellation.as_raw_fd(), false, cancel_observation, None)
    else {
        return;
    };
    let Some(stop_source) = stop_fd.to_run_loop_source(0) else {
        return;
    };
    if wake.is_closed() {
        return;
    }
    // SAFETY: The create rules return owned CF objects. The callback can retain
    // the notifying AX proxy but never reads its attributes or performs actions.
    unsafe {
        let app = AXUIElementCreateApplication(pid);
        if app.is_null() {
            return;
        }
        let app = CFType::wrap_under_create_rule(app);
        if AXUIElementSetMessagingTimeout(app.as_CFTypeRef(), 0.15) != 0 {
            return;
        }
        let mut observer = ptr::null();
        if AXObserverCreate(pid, received_window_hint, &mut observer) != 0 || observer.is_null() {
            return;
        }
        let observer = CFType::wrap_under_create_rule(observer);
        let mut subscribed = false;
        let notifications: &[&str] = match &wake {
            Wake::Prompt(_) => &["AXWindowCreated", "AXSheetCreated"],
            Wake::Connection(_, _) => &[
                "AXWindowCreated",
                "AXFocusedWindowChanged",
                "AXMainWindowChanged",
                "AXApplicationActivated",
            ],
        };
        for &name in notifications {
            if wake.is_closed() {
                return;
            }
            let name = CFString::from_static_string(name);
            subscribed |= AXObserverAddNotification(
                observer.as_CFTypeRef(),
                app.as_CFTypeRef(),
                name.as_concrete_TypeRef(),
                ptr::from_ref(&wake).cast_mut().cast(),
            ) == 0;
        }
        if !subscribed || wake.is_closed() {
            return;
        }
        let source = AXObserverGetRunLoopSource(observer.as_CFTypeRef());
        if source.is_null() {
            return;
        }
        let source = CFRunLoopSource::wrap_under_get_rule(source);
        let run_loop = CFRunLoop::get_current();
        run_loop.add_source(&stop_source, kCFRunLoopDefaultMode);
        run_loop.add_source(&source, kCFRunLoopDefaultMode);
        stop_fd.enable_callbacks(kCFFileDescriptorReadCallBack);
        if let Wake::Connection(worker, _) = &wake {
            // Catch changes between the watcher's first snapshot and registration.
            worker.unpark();
        }
        CFRunLoop::run_current();
        run_loop.remove_source(&source, kCFRunLoopDefaultMode);
        run_loop.remove_source(&stop_source, kCFRunLoopDefaultMode);
        stop_fd.invalidate();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn connection_window_hints_retain_bounded_proxies_and_skip_app_activation() {
        let (lifetime, _peer) = UnixStream::pair().unwrap();
        let (sender, windows) = sync_channel(WINDOW_QUEUE_LIMIT);
        let observation = WindowObservation {
            _lifetime: lifetime,
            windows,
        };
        let wake = Wake::Connection(std::thread::current(), sender);
        let emit = move |event, count| {
            let raw = unsafe { AXUIElementCreateApplication(std::process::id() as i32) };
            assert!(!raw.is_null());
            let app = unsafe { CFType::wrap_under_create_rule(raw) };
            let name = CFString::from_static_string(event);
            for _ in 0..count {
                unsafe { wake.notify(app.as_CFTypeRef(), name.as_concrete_TypeRef()) };
            }
            raw as usize
        };
        emit("AXApplicationActivated", 1);
        assert!(observation.take_window().is_none());
        let expected = std::thread::spawn(move || emit("AXWindowCreated", WINDOW_QUEUE_LIMIT + 1))
            .join()
            .unwrap();
        for _ in 0..WINDOW_QUEUE_LIMIT {
            assert_eq!(
                observation.take_window().unwrap().as_CFTypeRef() as usize,
                expected
            );
        }
        assert!(observation.take_window().is_none());
    }

    fn fixture() -> (WindowHints, Sender<()>, UnixStream) {
        let (lifetime, peer) = UnixStream::pair().unwrap();
        let (sender, hints) = mpsc::channel(1);
        (
            WindowHints {
                pid: Some(123),
                subscription: Some(Subscription {
                    hints,
                    _lifetime: lifetime,
                }),
                early_until: None,
            },
            sender,
            peer,
        )
    }

    #[tokio::test]
    async fn hint_during_inspection_coalesces_and_preserves_periodic_deadline() {
        let (mut watcher, sender, _peer) = fixture();
        assert!(watcher.begin_pass(Instant::now()).is_none());
        sender.try_send(()).unwrap();
        assert!(matches!(
            sender.try_send(()),
            Err(mpsc::error::TrySendError::Full(()))
        ));
        let deadline = Instant::now() + Duration::from_secs(60);
        tokio::time::timeout(Duration::from_secs(1), watcher.wait(deadline, true))
            .await
            .unwrap();
        assert_eq!(watcher.begin_pass(Instant::now()), Some(deadline));
        sender.try_send(()).unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(5), watcher.wait(deadline, false))
                .await
                .is_err()
        );
        watcher.wait(Instant::now(), true).await;
        assert!(watcher.begin_pass(Instant::now()).is_none());
    }

    #[tokio::test]
    async fn unsupported_subscription_waits_for_timer_and_old_hints_cannot_survive_detach() {
        let (mut watcher, sender, mut peer) = fixture();
        sender.try_send(()).unwrap();
        watcher.set_target(None);
        use std::io::Read;
        assert_eq!(peer.read(&mut [0; 1]).unwrap(), 0);
        assert!(sender.is_closed());
        assert!(watcher.begin_pass(Instant::now()).is_none());
        assert!(tokio::time::timeout(
            Duration::from_millis(5),
            watcher.wait(Instant::now() + Duration::from_secs(1), true)
        )
        .await
        .is_err());
        let (mut watcher, sender, _peer) = fixture();
        drop(sender);
        assert!(tokio::time::timeout(
            Duration::from_millis(5),
            watcher.wait(Instant::now() + Duration::from_secs(1), true)
        )
        .await
        .is_err());
    }
}
