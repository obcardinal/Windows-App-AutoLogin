//! Supervise the local Xcode build of the signed iPhone runner.
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Sender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const SELECTION_CHECK_INTERVAL: Duration = Duration::from_secs(3);
const PREPARATION_TIMEOUT: Duration = Duration::from_secs(125);
const WIFI_TIMEOUT: Duration = Duration::from_secs(25);
const CHILD_POLL: Duration = Duration::from_millis(50);
const EOF_GRACE: Duration = Duration::from_secs(4);

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Trigger {
    Tick,
    Configuration,
    DesktopConnect,
    PasswordWritten { warm_wifi: bool },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Preparation {
    Build,
    WarmWifi,
}

// The shared phone selector and setup CLI publish config.json by rename.
// Modification and status-change times also capture in-place updates.
#[derive(Clone, Copy, PartialEq, Eq)]
struct ConfigStamp {
    device: u64,
    inode: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl ConfigStamp {
    fn read(path: &Path) -> Option<Self> {
        let file = fs::symlink_metadata(path).ok()?;
        file.is_file().then_some(Self {
            device: file.dev(),
            inode: file.ino(),
            modified: (file.mtime(), file.mtime_nsec()),
            changed: (file.ctime(), file.ctime_nsec()),
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Pending,
    Ready,
    Failed,
}

pub(crate) struct HostPreparation {
    config_path: PathBuf,
    config: Option<ConfigStamp>,
    next_config_check: Option<Instant>,
    outcome: Outcome,
    job: Option<PreparationJob>,
    wifi_job: Option<PreparationJob>,
}

impl HostPreparation {
    pub(crate) fn new(config_path: PathBuf) -> Self {
        Self {
            config_path,
            config: None,
            next_config_check: None,
            outcome: Outcome::Pending,
            job: None,
            wifi_job: None,
        }
    }

    pub(crate) fn stop(&mut self) {
        self.cancel_jobs();
        self.config = None;
        self.next_config_check = None;
        self.outcome = Outcome::Pending;
    }

    fn cancel_jobs(&mut self) {
        for job in [&mut self.job, &mut self.wifi_job].into_iter().flatten() {
            job.cancel();
        }
    }

    pub(crate) fn poll(&mut self, now: Instant, eligible: bool, trigger: Trigger) {
        self.poll_with(
            now,
            eligible,
            trigger,
            crate::iphone_sso::host_prepare_command,
        );
    }

    fn poll_with(
        &mut self,
        now: Instant,
        eligible: bool,
        trigger: Trigger,
        command: impl FnOnce(Preparation) -> anyhow::Result<Command> + Send + Clone + 'static,
    ) {
        PreparationJob::reap_finished(&mut self.wifi_job);
        if let Some(success) = PreparationJob::reap_finished(&mut self.job) {
            self.outcome = if success {
                Outcome::Ready
            } else {
                Outcome::Failed
            };
        }
        if !eligible {
            self.stop();
            return;
        }
        if trigger != Trigger::Tick || self.next_config_check.is_none_or(|next| now >= next) {
            self.next_config_check = Some(now + SELECTION_CHECK_INTERVAL);
            let config = ConfigStamp::read(&self.config_path);
            if config != self.config {
                self.cancel_jobs();
                self.config = config;
                self.outcome = Outcome::Pending;
            }
        }
        if self.config.is_none() {
            return;
        }
        // A cancelled job still owns processes until it has been reaped.
        if [&self.job, &self.wifi_job]
            .into_iter()
            .flatten()
            .any(|job| job.lease.is_none())
        {
            return;
        }
        let first_preparation = self.job.is_none() && self.outcome == Outcome::Pending;
        let start_wifi = self.wifi_job.is_none()
            && (first_preparation
                || matches!(
                    trigger,
                    Trigger::DesktopConnect | Trigger::PasswordWritten { warm_wifi: true }
                ));
        if start_wifi {
            // Enter and a later password write share a single in-flight probe.
            self.wifi_job = PreparationJob::start(Preparation::WarmWifi, command.clone()).ok();
        }
        let retry_build = matches!(trigger, Trigger::PasswordWritten { .. })
            && (self.outcome == Outcome::Failed || start_wifi);
        if self.job.is_none() && (first_preparation || retry_build) {
            match PreparationJob::start(Preparation::Build, command) {
                Ok(job) => self.job = Some(job),
                Err(_) => self.outcome = Outcome::Failed,
            }
        }
    }
}

impl Drop for HostPreparation {
    fn drop(&mut self) {
        self.cancel_jobs();
        for job in [self.job.take(), self.wifi_job.take()]
            .into_iter()
            .flatten()
        {
            let _ = job.thread.join();
        }
    }
}

struct PreparationJob {
    lease: Option<Sender<()>>,
    thread: JoinHandle<bool>,
}

impl PreparationJob {
    fn reap_finished(slot: &mut Option<Self>) -> Option<bool> {
        if !slot.as_ref().is_some_and(|job| job.thread.is_finished()) {
            return None;
        }
        let job = slot.take().unwrap();
        let current = job.lease.is_some();
        let succeeded = job.thread.join().unwrap_or(false);
        current.then_some(succeeded)
    }

    fn start(
        kind: Preparation,
        command: impl FnOnce(Preparation) -> anyhow::Result<Command> + Send + 'static,
    ) -> std::io::Result<Self> {
        let (lease, cancelled) = mpsc::channel();
        let thread = thread::Builder::new()
            .name("iphone-host-preparation".into())
            .spawn(move || {
                // The command factory verifies the installed helper and selected
                // phone on this thread before any process is launched.
                let Ok(mut command) = command(kind) else {
                    return false;
                };
                if cancelled.try_recv() != Err(mpsc::TryRecvError::Empty) {
                    return false;
                }
                let Ok(mut child) = command
                    .process_group(0)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                else {
                    return false;
                };
                let timeout = if kind == Preparation::WarmWifi {
                    WIFI_TIMEOUT
                } else {
                    PREPARATION_TIMEOUT
                };
                let deadline = Instant::now() + timeout;
                loop {
                    match has_exited(&child) {
                        Ok(true) => return finish_owned_group(&mut child),
                        Ok(false) => {}
                        Err(_) => break,
                    }
                    if Instant::now() >= deadline
                        || cancelled.recv_timeout(CHILD_POLL)
                            != Err(mpsc::RecvTimeoutError::Timeout)
                    {
                        break;
                    }
                }
                stop_child(&mut child);
                false
            })?;
        Ok(Self {
            lease: Some(lease),
            thread,
        })
    }

    fn cancel(&mut self) {
        self.lease.take();
    }
}

fn has_exited(child: &Child) -> std::io::Result<bool> {
    // Keep the group leader waitable. This pins its PID until any leftover
    // compiler descendants have been stopped, including if Node crashed.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    loop {
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                child.id(),
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result == 0 {
            return Ok(info.si_pid != 0);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn finish_owned_group(child: &mut Child) -> bool {
    // No other code waits on this child. Its private process group was
    // created at spawn, independently of Xcode.app and other build jobs.
    unsafe { libc::killpg(child.id() as libc::pid_t, libc::SIGKILL) };
    child.wait().is_ok_and(|status| status.success())
}

fn stop_child(child: &mut Child) {
    // EOF asks the Node helper to stop its own compiler child. A separate
    // process group lets the supervisor interrupt both if the helper hangs.
    child.stdin.take();
    let deadline = Instant::now() + EOF_GRACE;
    while Instant::now() < deadline {
        match has_exited(child) {
            Ok(true) => break,
            Ok(false) => thread::sleep(CHILD_POLL),
            Err(_) => return,
        }
    }
    finish_owned_group(child);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let root =
                std::env::temp_dir().join(format!("waal-preparation-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&root).unwrap();
            Self(root)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn wait_until(mut ready: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !ready() {
            assert!(Instant::now() < deadline, "local preparation timed out");
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn finish(preparation: &mut HostPreparation) {
        wait_until(|| {
            [&preparation.job, &preparation.wifi_job]
                .into_iter()
                .flatten()
                .all(|job| job.thread.is_finished())
        });
        preparation.poll_with(Instant::now(), true, Trigger::Tick, |_| {
            panic!("a tick must not launch a second preparation")
        });
        assert!(preparation.job.is_none() && preparation.wifi_job.is_none());
    }

    #[test]
    fn prepares_once_for_installed_config_and_retries_failure_after_password_write() {
        let fixture = Fixture::new();
        let path = fixture.0.join("config.json");
        let mut preparation = HostPreparation::new(path.clone());
        let now = Instant::now();
        preparation.poll_with(now, true, Trigger::Configuration, |_| {
            panic!("missing install")
        });
        assert!(preparation.job.is_none());
        fs::write(&path, b"first").unwrap();
        preparation.poll_with(now, false, Trigger::Configuration, |_| {
            panic!("disabled account")
        });
        assert!(preparation.job.is_none());

        preparation.poll_with(now, true, Trigger::Configuration, |kind| {
            Ok(Command::new(if kind == Preparation::Build {
                "/usr/bin/false"
            } else {
                "/usr/bin/true"
            }))
        });
        finish(&mut preparation);
        assert!(preparation.outcome == Outcome::Failed);
        preparation.poll_with(now, true, Trigger::Configuration, |_| {
            panic!("unchanged config")
        });
        assert!(preparation.job.is_none());
        preparation.poll_with(now, true, Trigger::DesktopConnect, |kind| {
            assert_eq!(kind, Preparation::WarmWifi);
            Ok(Command::new("/usr/bin/true"))
        });
        assert!(preparation.wifi_job.is_some() && preparation.job.is_none());
        finish(&mut preparation);
        assert!(preparation.outcome == Outcome::Failed);
        preparation.poll_with(
            now,
            true,
            Trigger::PasswordWritten { warm_wifi: false },
            |_| Ok(Command::new("/usr/bin/true")),
        );
        finish(&mut preparation);
        assert!(preparation.outcome == Outcome::Ready);
        preparation.poll_with(
            now,
            true,
            Trigger::PasswordWritten { warm_wifi: false },
            |_| panic!("2FA is off for this account and the build is ready"),
        );
        assert!(preparation.job.is_none());
        preparation.poll_with(
            now,
            true,
            Trigger::PasswordWritten { warm_wifi: true },
            |_| Ok(Command::new("/usr/bin/true")),
        );
        assert!(preparation.job.is_some()); // warm the Wi-Fi tunnel even with a ready build
        finish(&mut preparation);

        // A separately saved choice is published by renaming a new file. Its
        // metadata is seen on the next periodic check while the app is idle.
        let replacement = fixture.0.join("replacement");
        fs::write(&replacement, b"second").unwrap();
        fs::rename(&replacement, path).unwrap();
        preparation.poll_with(now + SELECTION_CHECK_INTERVAL, true, Trigger::Tick, |_| {
            Ok(Command::new("/usr/bin/true"))
        });
        finish(&mut preparation);
        assert!(preparation.outcome == Outcome::Ready);
    }

    #[test]
    fn disable_closes_lifetime_pipe_and_drop_reaps_the_helper() {
        let fixture = Fixture::new();
        let config = fixture.0.join("config.json");
        fs::write(&config, b"fixture").unwrap();
        let state = fixture.0.join("state");
        let child_state = state.clone();
        let mut preparation = HostPreparation::new(config);
        preparation.poll_with(Instant::now(), true, Trigger::Configuration, move |kind| {
            if kind == Preparation::WarmWifi {
                return Ok(Command::new("/usr/bin/true"));
            }
            let mut command = Command::new("/bin/sh");
            command.args([
                "-c",
                "echo ready > \"$1\"; /bin/cat >/dev/null; echo closed > \"$1\"",
                "local-test",
            ]);
            command.arg(child_state);
            Ok(command)
        });
        wait_until(|| fs::read_to_string(&state).is_ok_and(|s| s.trim() == "ready"));
        preparation.poll_with(Instant::now(), false, Trigger::Configuration, |_| {
            panic!("disabled")
        });
        wait_until(|| fs::read_to_string(&state).is_ok_and(|s| s.trim() == "closed"));
        drop(preparation);
    }

    #[test]
    fn selection_warms_wifi_and_password_can_wake_it_again_during_the_same_build() {
        let fixture = Fixture::new();
        let config = fixture.0.join("config.json");
        fs::write(&config, b"first").unwrap();
        let build_state = fixture.0.join("build");
        let wifi_state = fixture.0.join("wifi");
        let mut preparation = HostPreparation::new(config.clone());
        let now = Instant::now();
        let wait_for_eof = |state: PathBuf, expected: Preparation| {
            move |kind| {
                assert_eq!(kind, expected);
                let mut child = Command::new("/bin/sh");
                child.args([
                    "-c",
                    "echo ready > \"$1\"; /bin/cat >/dev/null; echo closed > \"$1\"",
                    "fixture",
                ]);
                child.arg(state);
                Ok(child)
            }
        };
        let state_is =
            |file: &Path, value| fs::read_to_string(file).is_ok_and(|s| s.trim() == value);
        let password = Trigger::PasswordWritten { warm_wifi: true };
        let first_wifi = fixture.0.join("first-wifi");
        let startup_wifi = first_wifi.clone();
        let startup_build = build_state.clone();
        preparation.poll_with(now, true, Trigger::Configuration, move |kind| match kind {
            Preparation::Build => wait_for_eof(startup_build, Preparation::Build)(kind),
            Preparation::WarmWifi => {
                fs::write(startup_wifi, "ready")?;
                Ok(Command::new("/usr/bin/true"))
            }
        });
        wait_until(|| {
            state_is(&build_state, "ready")
                && state_is(&first_wifi, "ready")
                && preparation.wifi_job.as_ref().unwrap().thread.is_finished()
        });
        preparation.poll_with(now, true, Trigger::Tick, |_| {
            panic!("no extra Wi-Fi wake on tick")
        });
        assert!(preparation.wifi_job.is_none());
        let build = preparation.job.as_ref().unwrap().thread.thread().id();
        preparation.poll_with(
            now,
            true,
            password,
            wait_for_eof(wifi_state.clone(), Preparation::WarmWifi),
        );
        wait_until(|| state_is(&wifi_state, "ready"));
        let wifi = preparation.wifi_job.as_ref().unwrap().thread.thread().id();
        preparation.poll_with(now, true, Trigger::DesktopConnect, |_| {
            panic!("a desktop launch must reuse the in-flight Wi-Fi check")
        });
        preparation.poll_with(now, true, password, |_| panic!("duplicate preparation"));
        assert_eq!(
            preparation.job.as_ref().unwrap().thread.thread().id(),
            build
        );
        assert_eq!(
            preparation.wifi_job.as_ref().unwrap().thread.thread().id(),
            wifi
        );

        let replacement = fixture.0.join("replacement");
        fs::write(&replacement, b"second").unwrap();
        fs::rename(replacement, config).unwrap();
        preparation.poll_with(now, true, Trigger::Configuration, |_| {
            panic!("old jobs must stop first")
        });
        wait_until(|| state_is(&wifi_state, "closed") && state_is(&build_state, "closed"));
        wait_until(|| {
            preparation.job.as_ref().unwrap().thread.is_finished()
                && preparation.wifi_job.as_ref().unwrap().thread.is_finished()
        });
        preparation.poll_with(now, true, Trigger::Tick, |_| {
            Ok(Command::new("/usr/bin/true"))
        });
        assert!(preparation.wifi_job.is_some());
        finish(&mut preparation);
        assert!(preparation.outcome == Outcome::Ready);
    }

    #[test]
    fn failed_worker_leaves_no_orphan_compiler() {
        let fixture = Fixture::new();
        let pid_file = fixture.0.join("compiler-pid");
        let child_pid_file = pid_file.clone();
        let job = PreparationJob::start(Preparation::Build, move |_| {
            let mut command = Command::new("/bin/sh");
            command.args([
                "-c",
                "/bin/sleep 45 & echo $! > \"$1\"; exit 1",
                "local-test",
            ]);
            command.arg(child_pid_file);
            Ok(command)
        })
        .unwrap();
        assert!(!job.thread.join().unwrap());
        let pid: i32 = fs::read_to_string(pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        wait_until(|| unsafe { libc::kill(pid, 0) } == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH));
    }

    #[test]
    fn dropping_supervisor_kills_a_compiler_that_ignores_eof() {
        let fixture = Fixture::new();
        let config = fixture.0.join("config.json");
        fs::write(&config, b"fixture").unwrap();
        let pid_file = fixture.0.join("compiler-pid");
        let child_pid_file = pid_file.clone();
        let mut preparation = HostPreparation::new(config);
        preparation.poll_with(Instant::now(), true, Trigger::Configuration, move |kind| {
            if kind == Preparation::WarmWifi {
                return Ok(Command::new("/usr/bin/true"));
            }
            let mut command = Command::new("/bin/sh");
            command.args([
                "-c",
                "/bin/sleep 120 & child=$!; echo \"$child\" > \"$1\"; wait \"$child\"",
                "local-test",
            ]);
            command.arg(child_pid_file);
            Ok(command)
        });
        wait_until(|| {
            fs::read_to_string(&pid_file).is_ok_and(|pid| pid.trim().parse::<i32>().is_ok())
        });
        let pid: i32 = fs::read_to_string(pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        drop(preparation);
        wait_until(|| unsafe { libc::kill(pid, 0) } == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH));
    }
}
