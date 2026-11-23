use crate::macos_lock_screen::{self, ModelCacheWatch};
use std::process::Child;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const RETRY_DELAY: Duration = Duration::from_secs(60);
const REPAIR_TIMEOUT: Duration = Duration::from_secs(180);

struct Repair {
    child: Child,
    deadline: Instant,
}

impl Repair {
    fn result(&mut self, now: Instant) -> Option<bool> {
        match self.child.try_wait() {
            Ok(Some(status)) => Some(status.success()),
            Ok(None) if now < self.deadline => None,
            _ => Some(false),
        }
    }
}

impl Drop for Repair {
    fn drop(&mut self) {
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

// Owned only while there is a reconnect-enabled account. A scan already in
// flight can notify its original instance, never a newly enabled one.
#[derive(Default)]
pub(super) struct RecognitionMaintenance {
    watch: Option<ModelCacheWatch>,
    retry_watch_at: Option<Instant>,
    repair: Option<Repair>,
    last_attempt: Option<(Instant, bool)>,
    cache_loss: bool,
    failed_scan: Arc<AtomicBool>,
    needs_rescan: bool,
}

impl RecognitionMaintenance {
    pub(super) fn failure_signal(&self) -> Arc<AtomicBool> {
        self.failed_scan.clone()
    }

    pub(super) fn is_repairing(&self) -> bool {
        self.repair.is_some()
    }

    pub(super) fn waiting_for_rescan(&self) -> bool {
        self.needs_rescan && self.is_repairing()
    }

    // Called from the existing worker loop, including while the Monitor is
    // stopped. The watcher signals changes through native filesystem events.
    // Returns true only when a previously failed foreground scan can retry.
    pub(super) fn update(&mut self, now: Instant) -> bool {
        if self.watch.is_none() && self.retry_watch_at.is_none_or(|at| at <= now) {
            self.watch = ModelCacheWatch::start();
            self.retry_watch_at = Some(now + RETRY_DELAY);
        }
        // One purge may arrive in several event batches. After a repair, the
        // watcher checks whether any signalled files are still missing.
        if !self.is_repairing() {
            self.cache_loss |= self.watch.as_ref().is_some_and(ModelCacheWatch::take_loss);
        }
        self.update_repair(now, macos_lock_screen::start_recognition_repair)
    }

    fn update_repair(
        &mut self,
        now: Instant,
        start: impl FnOnce() -> std::io::Result<Child>,
    ) -> bool {
        self.needs_rescan |= self.failed_scan.swap(false, Ordering::AcqRel);

        if let Some(repair) = self.repair.as_mut() {
            let Some(success) = repair.result(now) else {
                return false;
            };
            self.repair = None;
            self.last_attempt = Some((now, success));
            if success {
                tracing::debug!("Lock screen recognition models are ready");
                return std::mem::take(&mut self.needs_rescan);
            }
            tracing::warn!("Could not restore lock screen recognition");
            self.cache_loss = true;
        }

        if !(self.cache_loss || self.needs_rescan) || self.backing_off(now) {
            return false;
        }
        match start() {
            Ok(child) => {
                tracing::debug!("Preparing lock screen recognition models in the background");
                self.cache_loss = false;
                self.repair = Some(Repair {
                    child,
                    deadline: now + REPAIR_TIMEOUT,
                });
            }
            Err(err) => {
                tracing::warn!(reason = %err, "Could not start lock screen recognition repair");
                self.last_attempt = Some((now, false));
            }
        }
        false
    }

    fn backing_off(&self, now: Instant) -> bool {
        self.last_attempt.is_some_and(|(end, succeeded)| {
            now < end + RETRY_DELAY && !(succeeded && self.cache_loss)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    fn unexpected_start() -> std::io::Result<Child> {
        panic!("unexpected recognition repair");
    }

    // Remains running until Child::wait closes the pipe.
    fn test_child() -> std::io::Result<Child> {
        Command::new("/bin/cat").stdin(Stdio::piped()).spawn()
    }

    #[test]
    fn one_repair_handles_both_eviction_and_foreground_failure() {
        let now = Instant::now();
        let mut state = RecognitionMaintenance::default();
        assert!(!state.update_repair(now, unexpected_start));
        state.cache_loss = true;
        assert!(!state.update_repair(now, test_child));
        assert!(!state.waiting_for_rescan());
        state.failure_signal().store(true, Ordering::Release);
        assert!(!state.update_repair(now, unexpected_start));
        assert!(state.waiting_for_rescan());
        state.repair.as_mut().unwrap().child.wait().unwrap();
        assert!(state.update_repair(now, unexpected_start));
        assert!(!state.update_repair(now, unexpected_start));
        assert!(!state.waiting_for_rescan());
    }

    #[test]
    fn failed_repairs_back_off_but_a_new_eviction_after_success_starts_immediately() {
        let now = Instant::now();
        let mut state = RecognitionMaintenance {
            cache_loss: true,
            ..Default::default()
        };
        assert!(!state.update_repair(now, || Err(std::io::Error::other("could not start"))));
        assert!(!state.update_repair(now + RETRY_DELAY / 2, unexpected_start));
        let retry = now + RETRY_DELAY;
        assert!(!state.update_repair(retry, test_child));
        state.repair.as_mut().unwrap().child.wait().unwrap();
        assert!(!state.update_repair(retry, unexpected_start));
        assert!(!state.update_repair(retry, unexpected_start));
        state.cache_loss = true;
        assert!(!state.update_repair(retry, test_child));
        assert!(state.is_repairing());
    }

    #[test]
    fn disabling_the_last_account_cancels_repairs_and_discards_late_scan_failures() {
        use super::super::ReturnMonitor;
        use crate::models::Account;

        let mut account = Account::new("example");
        account.has_saved_password = true;
        account.vm_device_id = "workspace:example".into();
        let mut accounts = [account.clone(), account];
        let now = Instant::now();
        let mut state = RecognitionMaintenance {
            cache_loss: true,
            // Test the account lifecycle without watching the user's cache.
            retry_watch_at: Some(now + RETRY_DELAY),
            ..Default::default()
        };
        state.update_repair(now, test_child);
        let pid = state.repair.as_ref().unwrap().child.id();
        let late_failure = state.failure_signal();
        let mut monitor = ReturnMonitor {
            recognition: Some(state),
            ..Default::default()
        };
        monitor.maintain_model_cache(&accounts);
        accounts[0].reconnect_locked_vm = false;
        monitor.maintain_model_cache(&accounts);
        if macos_lock_screen::supported() {
            assert!(monitor.recognition.as_ref().unwrap().is_repairing());
        }
        accounts[1].enabled = false;
        monitor.maintain_model_cache(&accounts);
        assert!(monitor.recognition.is_none());
        assert_eq!(
            unsafe { libc::waitpid(pid as _, std::ptr::null_mut(), libc::WNOHANG) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
        late_failure.store(true, Ordering::Release);
        let mut new_state = RecognitionMaintenance::default();
        assert!(!new_state.update_repair(now, unexpected_start));
    }
}
