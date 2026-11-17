//! Bounded, cancellable handoff to the local iPhone helper. Numbers travel only
//! over stdin; the helper must obtain a fresh desktop permit before each action.

use serde::Deserialize;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

const LIFETIME: Duration = Duration::from_secs(120);
const MAX_LINE: usize = 4096;
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    Preparing,
    WaitingForDevice,
    Unlock,
    Connecting,
    WaitingForRequest,
    EnteringNumber,
    FaceId,
    Finished,
    Cancelled,
    Failed,
    SetupRequired,
    DeviceSetupRequired,
    UnsupportedLayout,
    ConnectionFailed,
    CleanupFailed,
}

impl Phase {
    pub(crate) fn is_failure(self) -> bool {
        matches!(
            self,
            Self::Failed
                | Self::SetupRequired
                | Self::DeviceSetupRequired
                | Self::UnsupportedLayout
                | Self::ConnectionFailed
                | Self::CleanupFailed
        )
    }

    fn from_error(code: &str) -> Self {
        match code {
            "wda_cleanup_unverified" => Self::CleanupFailed,
            "not_configured"
            | "runtime_missing"
            | "device_selection_required"
            | "invalid_configuration"
            | "unsafe_configuration"
            | "unsafe_storage"
            | "driver_unavailable" => Self::SetupRequired,
            "developer_mode_required"
            | "ui_automation_required"
            | "wda_signing_required"
            | "wda_build_failed"
            | "authenticator_not_installed" => Self::DeviceSetupRequired,
            "unsupported_authenticator_layout" => Self::UnsupportedLayout,
            "wifi_device_required"
            | "iphone_not_available_to_appium"
            | "wda_connection_failed"
            | "device_discovery_failed"
            | "server_start_failed"
            | "transport_failed" => Self::ConnectionFailed,
            _ => Self::Failed,
        }
    }

    fn from_helper(value: &str) -> anyhow::Result<Self> {
        Ok(match value {
            "waiting_for_device" => Self::WaitingForDevice,
            "waiting_for_unlock" | "lock_state_unavailable" => Self::Unlock,
            "starting_iphone_connection"
            | "preparing_iphone_runner"
            | "starting_iphone_runner"
            | "iphone_connected" => Self::Connecting,
            "waiting_for_authenticator" | "waiting_for_number_request" => Self::WaitingForRequest,
            "entering_number" => Self::EnteringNumber,
            "manual_confirmation_required" | "complete_confirmation_on_iphone" => Self::FaceId,
            _ => anyhow::bail!("unexpected iPhone progress"),
        })
    }

    pub(crate) fn message(self) -> &'static str {
        match self {
            Self::Preparing => "Preparing iPhone sign-in…",
            Self::WaitingForDevice => "Keep your iPhone nearby and connected to Wi-Fi.",
            Self::Unlock => "Unlock your iPhone to continue signing in.",
            Self::Connecting => "Connecting to your iPhone…",
            Self::WaitingForRequest => "Waiting for the matching Microsoft Authenticator request…",
            Self::EnteringNumber => "Entering the sign-in number on your iPhone…",
            Self::FaceId => "Complete Face ID or the remaining confirmation on your iPhone.",
            Self::Finished => "iPhone assistance finished.",
            Self::Cancelled => "iPhone assistance cancelled. You can finish signing in manually.",
            Self::Failed => {
                "iPhone assistance could not complete. You can finish signing in manually."
            }
            Self::SetupRequired => "Set up the iPhone helper and select your phone before using this option. You can finish this sign-in manually.",
            Self::DeviceSetupRequired => "Check the iPhone helper setup, Developer Mode, and Enable UI Automation on your phone. You can finish this sign-in manually.",
            Self::UnsupportedLayout => "This Microsoft Authenticator screen is not supported yet. Complete this sign-in manually.",
            Self::ConnectionFailed => "Could not connect to your iPhone over Wi-Fi. Keep it nearby, unlocked, and on the same network. You can finish this sign-in manually.",
            Self::CleanupFailed => "The iPhone automation session could not be fully closed. Close WebDriverAgentRunner on your iPhone before trying again.",
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Event {
    pub(crate) id: u64,
    pub(crate) phase: Phase,
    pub(crate) cancelled: Arc<AtomicBool>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    SubmittedUnverified,
    Cancelled,
    Unavailable,
}

#[derive(Deserialize)]
struct HelperConfig {
    schema_version: u32,
    node_path: PathBuf,
    device_udid: Option<String>,
}

pub(crate) fn private_file(path: &std::path::Path, limit: u64) -> anyhow::Result<Vec<u8>> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0
            && !crate::private_permissions::file_has_macos_acl_fd(&file)?
            && metadata.len() <= limit,
        "iPhone helper file is not private"
    );
    let mut contents = Vec::new();
    file.take(limit + 1).read_to_end(&mut contents)?;
    anyhow::ensure!(
        contents.len() as u64 <= limit,
        "iPhone helper file is too large"
    );
    Ok(contents)
}

fn helper_command() -> anyhow::Result<Command> {
    let root = crate::user_paths::config_dir()?.join("iphone-automation");
    let metadata = std::fs::symlink_metadata(&root)?;
    anyhow::ensure!(
        metadata.is_dir()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0,
        "iPhone helper directory is not private"
    );
    let config: HelperConfig =
        serde_json::from_slice(&private_file(&root.join("config.json"), 8192)?)?;
    anyhow::ensure!(
        config.schema_version == 1 && config.device_udid.is_some(),
        "iPhone is not configured"
    );
    anyhow::ensure!(
        config.node_path.is_absolute()
            && config
                .node_path
                .file_name()
                .is_some_and(|name| name == "node"),
        "iPhone runtime path is invalid"
    );
    // Setup installs these exact modules. A stale or modified helper must be
    // updated explicitly; the app never executes a user-provided script path.
    for (name, expected) in [
        (
            "support.mjs",
            include_bytes!("../script/iphone-automation/support.mjs").as_slice(),
        ),
        (
            "bridge.mjs",
            include_bytes!("../script/iphone-automation/bridge.mjs").as_slice(),
        ),
        (
            "wda.mjs",
            include_bytes!("../script/iphone-automation/wda.mjs").as_slice(),
        ),
        (
            "authenticator.mjs",
            include_bytes!("../script/iphone-automation/authenticator.mjs").as_slice(),
        ),
        (
            "run-request.mjs",
            include_bytes!("../script/iphone-automation/run-request.mjs").as_slice(),
        ),
    ] {
        anyhow::ensure!(
            private_file(&root.join(name), 128 * 1024)? == expected,
            "iPhone helper needs setup"
        );
    }
    let mut command = Command::new(&config.node_path);
    command
        .arg(root.join("run-request.mjs"))
        .current_dir(&root)
        .env_clear()
        .env(
            "HOME",
            crate::user_paths::home_dir().ok_or_else(|| anyhow::anyhow!("home unavailable"))?,
        )
        .env(
            "PATH",
            format!(
                "{}:/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin",
                config.node_path.parent().unwrap().display()
            ),
        )
        .env("LANG", "en_US.UTF-8")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    Ok(command)
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum HelperEvent {
    Status { phase: String },
    Authorize { sequence: u64, action: String },
    Submitted {},
    Closed {},
    Error { code: String },
}

#[derive(Default)]
struct Protocol {
    next: usize,
    submitted: bool,
    finishing: bool,
}

impl Protocol {
    fn authorize(&mut self, sequence: u64, action: &str) -> anyhow::Result<()> {
        const ACTIONS: [&str; 3] = ["open_authenticator", "enter_number", "submit_number"];
        anyhow::ensure!(
            !self.submitted
                && sequence == self.next as u64 + 1
                && ACTIONS
                    .get(self.next)
                    .is_some_and(|expected| *expected == action),
            "unexpected iPhone action"
        );
        self.next += 1;
        Ok(())
    }

    fn submitted(&mut self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.next == 3 && !self.submitted,
            "unexpected iPhone submission"
        );
        self.submitted = true;
        Ok(())
    }

    fn finish(&mut self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.submitted && !self.finishing,
            "unexpected iPhone finish"
        );
        self.finishing = true;
        Ok(())
    }

    fn closed(&self) -> anyhow::Result<()> {
        anyhow::ensure!(self.finishing, "unexpected iPhone cleanup response");
        Ok(())
    }
}

fn read_event(reader: &mut impl BufRead) -> anyhow::Result<Option<HelperEvent>> {
    let mut line = Vec::new();
    let read = reader
        .take((MAX_LINE + 1) as u64)
        .read_until(b'\n', &mut line)?;
    if read == 0 {
        return Ok(None);
    }
    anyhow::ensure!(
        read <= MAX_LINE && line.last() == Some(&b'\n'),
        "invalid iPhone response length"
    );
    Ok(Some(serde_json::from_slice(&line)?))
}

fn send(input: &mut ChildStdin, value: &impl serde::Serialize) -> anyhow::Result<()> {
    serde_json::to_writer(&mut *input, value)?;
    input.write_all(b"\n")?;
    input.flush()?;
    Ok(())
}

struct HelperProcess {
    child: Child,
    input: Option<ChildStdin>,
    reader: Option<std::thread::JoinHandle<()>>,
    cleanup_failed: Arc<AtomicBool>,
}

impl Drop for HelperProcess {
    fn drop(&mut self) {
        // EOF is the normal cancellation/cleanup path. Give the helper time to
        // close WDA and its owned Appium group before terminating a stuck runner.
        self.input.take();
        let deadline = Instant::now() + Duration::from_secs(12);
        while matches!(self.child.try_wait(), Ok(None)) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        if matches!(self.child.try_wait(), Ok(None)) {
            self.cleanup_failed.store(true, Ordering::SeqCst);
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

/// Caller owns the current automation/activity guards for the entire operation.
/// Disappearance of an SSO dialog does not prove authentication succeeded.
pub(crate) fn assist(
    challenge: &crate::macos_ax::sso::Challenge,
    account: &crate::models::Account,
    guard: &dyn Fn() -> anyhow::Result<()>,
    progress: impl Fn(Event),
) -> Outcome {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let cancelled = Arc::new(AtomicBool::new(false));
    let notify = |phase| {
        progress(Event {
            id,
            phase,
            cancelled: cancelled.clone(),
        })
    };
    let is_current = || {
        anyhow::ensure!(
            !cancelled.load(Ordering::SeqCst),
            "iPhone assistance cancelled"
        );
        guard()
    };
    notify(Phase::Preparing);
    let mut failure_phase = Phase::Failed;
    let cleanup_failed = Arc::new(AtomicBool::new(false));
    let result = (|| -> anyhow::Result<Outcome> {
        anyhow::ensure!(
            account.enabled && account.iphone_authenticator_enabled,
            "iPhone assistance is disabled"
        );
        anyhow::ensure!(challenge.matches_account(account), "iPhone account changed");
        challenge.revalidate(&is_current)?;
        let mut command = helper_command().inspect_err(|_| failure_phase = Phase::SetupRequired)?;
        let mut process = HelperProcess {
            child: command.spawn()?,
            input: None,
            reader: None,
            cleanup_failed: cleanup_failed.clone(),
        };
        process.input = Some(
            process
                .child
                .stdin
                .take()
                .ok_or_else(|| anyhow::anyhow!("missing helper input"))?,
        );
        let output = process
            .child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("missing helper output"))?;
        let (tx, rx) = mpsc::sync_channel(16);
        let reader_cleanup_failed = cleanup_failed.clone();
        process.reader = Some(std::thread::spawn(move || {
            let mut reader = BufReader::new(output);
            loop {
                let result = read_event(&mut reader);
                if matches!(&result, Ok(Some(HelperEvent::Error { code })) if code == "wda_cleanup_unverified")
                {
                    reader_cleanup_failed.store(true, Ordering::SeqCst);
                }
                let terminal = !matches!(result, Ok(Some(_)));
                // Errors deliberately lose their parser/input text here.
                // Continue draining after cancellation drops the receiver, so
                // the final cleanup failure is retained before the child exits.
                let _ = tx.send(result.map_err(|_| ()));
                if terminal {
                    break;
                }
            }
        }));
        #[derive(serde::Serialize)]
        struct Request<'a> {
            version: u8,
            account: &'a str,
            number: &'a str,
            expires_in_ms: u64,
        }
        send(
            process.input.as_mut().unwrap(),
            &Request {
                version: 1,
                account: account.username.trim(),
                number: challenge.number(),
                expires_in_ms: LIFETIME.as_millis() as u64,
            },
        )?;
        let deadline = Instant::now() + LIFETIME;
        let mut protocol = Protocol::default();
        let mut last_validation = Instant::now();
        let mut cleanup_deadline = None;
        loop {
            is_current()?;
            anyhow::ensure!(
                Instant::now() < cleanup_deadline.unwrap_or(deadline),
                "iPhone assistance expired"
            );
            if !protocol.finishing && last_validation.elapsed() >= Duration::from_millis(500) {
                if protocol.submitted {
                    use crate::macos_ax::sso::Completion;
                    if !matches!(challenge.poll_completion(&is_current)?, Completion::Pending) {
                        send(
                            process.input.as_mut().unwrap(),
                            &serde_json::json!({"finish": true}),
                        )?;
                        protocol.finish()?;
                        cleanup_deadline = Some(Instant::now() + Duration::from_secs(12));
                    }
                } else if protocol.next < 3 {
                    // Once submit is permitted the desktop can advance before
                    // WDA returns its click response. Await the explicit helper
                    // response instead of cancelling a completed click as stale.
                    challenge.revalidate(&is_current)?;
                }
                last_validation = Instant::now();
            }
            match rx.recv_timeout(Duration::from_millis(100)) {
                Ok(Ok(Some(HelperEvent::Status { phase }))) => {
                    notify(Phase::from_helper(&phase)?);
                }
                Ok(Ok(Some(HelperEvent::Authorize { sequence, action }))) => {
                    protocol.authorize(sequence, &action)?;
                    challenge.revalidate(&is_current)?;
                    send(
                        process.input.as_mut().unwrap(),
                        &serde_json::json!({"permit": sequence}),
                    )?;
                }
                Ok(Ok(Some(HelperEvent::Submitted {}))) => {
                    protocol.submitted()?;
                    notify(Phase::FaceId);
                }
                Ok(Ok(Some(HelperEvent::Closed {}))) => {
                    protocol.closed()?;
                    return Ok(Outcome::SubmittedUnverified);
                }
                Ok(Ok(Some(HelperEvent::Error { code }))) => {
                    // Never interpolate helper-provided strings into an error.
                    failure_phase = Phase::from_error(&code);
                    anyhow::bail!("iPhone helper could not complete");
                }
                Ok(_) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                    anyhow::bail!("iPhone helper ended before completion")
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
        }
    })();
    match result {
        _ if cleanup_failed.load(Ordering::SeqCst) => {
            notify(Phase::CleanupFailed);
            Outcome::Unavailable
        }
        Ok(outcome) => {
            notify(Phase::Finished);
            outcome
        }
        Err(_) if cancelled.load(Ordering::SeqCst) || guard().is_err() => {
            notify(Phase::Cancelled);
            Outcome::Cancelled
        }
        Err(_) => {
            notify(failure_phase);
            Outcome::Unavailable
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permissions_are_ordered_and_cannot_be_reused() {
        let mut state = Protocol::default();
        assert!(state.authorize(1, "submit_number").is_err());
        assert!(state.submitted().is_err());
        assert!(state.closed().is_err());
        assert!(state.finish().is_err());
        state.authorize(1, "open_authenticator").unwrap();
        assert!(state.authorize(1, "open_authenticator").is_err());
        state.authorize(2, "enter_number").unwrap();
        assert!(state.authorize(3, "accept_alert").is_err());
        state.authorize(3, "submit_number").unwrap();
        state.submitted().unwrap();
        assert!(state.closed().is_err());
        state.finish().unwrap();
        state.closed().unwrap();
        assert!(state.finish().is_err());
        assert!(state.submitted().is_err());
        assert!(state.authorize(4, "submit_number").is_err());
    }

    #[test]
    fn helper_protocol_rejects_oversize_unterminated_and_extra_payloads() {
        for bytes in [
            vec![b'x'; MAX_LINE + 1],
            b"{\"type\":\"submitted\"}".to_vec(),
            b"{\"type\":\"submitted\",\"number\":\"42\"}\n".to_vec(),
        ] {
            assert!(read_event(&mut bytes.as_slice()).is_err());
        }
        assert!(matches!(
            read_event(&mut b"{\"type\":\"submitted\"}\n".as_slice()),
            Ok(Some(HelperEvent::Submitted {}))
        ));
    }
}
