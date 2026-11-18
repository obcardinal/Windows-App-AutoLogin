//! Bounded, cancellable handoff to the local iPhone helper. Numbers travel only
//! over stdin; the helper must obtain a fresh desktop permit before each action.

#[path = "iphone_attempt_report.rs"]
mod report;

use report::{Milestone, Reason, Stage};
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
    ManualApprovalRequired,
    Finished,
    Cancelled,
    Failed,
    SetupRequired,
    DeviceSetupRequired,
    UnsupportedLayout,
    FieldCheckTimedOut,
    ConnectionFailed,
    CleanupFailed,
}

impl Phase {
    pub(crate) fn needs_close_button(self) -> bool {
        matches!(
            self,
            Self::ManualApprovalRequired
                | Self::Failed
                | Self::FieldCheckTimedOut
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
            "field_verification_timeout" => Self::FieldCheckTimedOut,
            "wifi_device_required"
            | "iphone_not_available_to_appium"
            | "wda_connection_failed"
            | "device_discovery_failed"
            | "server_start_failed"
            | "transport_failed" => Self::ConnectionFailed,
            _ => Self::Failed,
        }
    }

    fn from_helper(value: &str) -> Result<(Self, Stage, Option<Milestone>), Reason> {
        Ok(match value {
            "waiting_for_device" => (Self::WaitingForDevice, Stage::WaitingForDevice, None),
            "waiting_for_unlock" | "lock_state_unavailable" => {
                (Self::Unlock, Stage::WaitingForUnlock, None)
            }
            "preparing_iphone_runner" => (Self::Connecting, Stage::Connecting, None),
            "starting_iphone_runner" => (
                Self::Connecting,
                Stage::Connecting,
                Some(Milestone::RunnerStarting),
            ),
            "starting_iphone_connection" => (
                Self::Connecting,
                Stage::Connecting,
                Some(Milestone::RunnerReady),
            ),
            "iphone_connected" => (
                Self::Connecting,
                Stage::Connecting,
                Some(Milestone::PhoneConnected),
            ),
            "waiting_for_authenticator" | "waiting_for_number_request" => {
                (Self::WaitingForRequest, Stage::WaitingForRequest, None)
            }
            "entering_number" => (
                Self::EnteringNumber,
                Stage::EnteringNumber,
                Some(Milestone::NumberEntryStarting),
            ),
            "manual_confirmation_required" | "complete_confirmation_on_iphone" => {
                (Self::FaceId, Stage::WaitingForConfirmation, None)
            }
            _ => return Err(Reason::ProtocolError),
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
            Self::ManualApprovalRequired => "Review the sign-in request in Microsoft Authenticator on your iPhone. If it’s yours, tap Approve and complete Face ID if asked.",
            Self::Finished => "iPhone assistance finished.",
            Self::Cancelled => "iPhone assistance cancelled. You can finish signing in manually.",
            Self::Failed => {
                "iPhone assistance could not complete. You can finish signing in manually."
            }
            Self::SetupRequired => "Set up the iPhone helper and select your phone before using this option. You can finish this sign-in manually.",
            Self::DeviceSetupRequired => "Check the iPhone helper setup, Developer Mode, and Enable UI Automation on your phone. You can finish this sign-in manually.",
            Self::UnsupportedLayout => "This Microsoft Authenticator screen is not supported yet. Complete this sign-in manually.",
            Self::FieldCheckTimedOut => "The iPhone field check timed out after 10 seconds. Complete this request in Microsoft Authenticator.",
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
    ManualApprovalRequired,
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
    ManualApprovalRequired {},
    Closed {},
    Error { code: String },
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Protocol {
    #[default]
    Initial,
    OpenPermitted,
    EntryPermitted,
    SubmitPermitted,
    ManualEntryPermitted,
    Submitted,
    Finishing,
    Closed,
}

impl Protocol {
    fn authorize(&mut self, sequence: u64, action: &str) -> anyhow::Result<Stage> {
        let (next, stage) = match (*self, sequence, action) {
            (Self::Initial, 1, "open_authenticator") => {
                (Self::OpenPermitted, Stage::OpeningAuthenticator)
            }
            (Self::OpenPermitted, 2, "enter_number") => {
                (Self::EntryPermitted, Stage::VerifyingNumberField)
            }
            (Self::EntryPermitted, 3, "submit_number") => {
                (Self::SubmitPermitted, Stage::SubmittingNumber)
            }
            (Self::EntryPermitted, 3, "enter_number_for_manual_approval") => {
                (Self::ManualEntryPermitted, Stage::RecheckingManualEntry)
            }
            _ => anyhow::bail!("unexpected iPhone action"),
        };
        *self = next;
        Ok(stage)
    }

    fn submitted(&mut self) -> anyhow::Result<()> {
        anyhow::ensure!(
            *self == Self::SubmitPermitted,
            "unexpected iPhone submission"
        );
        *self = Self::Submitted;
        Ok(())
    }

    fn finish(&mut self) -> anyhow::Result<()> {
        anyhow::ensure!(*self == Self::Submitted, "unexpected iPhone finish");
        *self = Self::Finishing;
        Ok(())
    }

    fn closed(&mut self) -> anyhow::Result<()> {
        anyhow::ensure!(
            *self == Self::Finishing,
            "unexpected iPhone cleanup response"
        );
        *self = Self::Closed;
        Ok(())
    }

    fn manual_approval_required(&mut self) -> anyhow::Result<()> {
        anyhow::ensure!(
            *self == Self::ManualEntryPermitted,
            "unexpected iPhone handoff"
        );
        *self = Self::Closed;
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

fn desktop_reason(error: anyhow::Error) -> Reason {
    use crate::macos_ax::sso::DesktopCheckFailure;
    match error.downcast_ref::<DesktopCheckFailure>() {
        Some(DesktopCheckFailure::Expired) => Reason::DesktopRequestExpired,
        Some(DesktopCheckFailure::WindowGone) => Reason::DesktopWindowGone,
        Some(DesktopCheckFailure::WindowChanged) => Reason::DesktopWindowChanged,
        Some(DesktopCheckFailure::RequestGone) => Reason::DesktopRequestGone,
        Some(DesktopCheckFailure::RequestChanged) => Reason::DesktopRequestChanged,
        None => Reason::DesktopRequestUnavailable,
    }
}

/// Caller owns the current automation/activity guards for the entire operation.
/// Disappearance of an SSO dialog does not prove authentication succeeded.
pub(crate) fn assist(
    challenge: &crate::macos_ax::sso::Challenge,
    account: &crate::models::Account,
    detection_time: Duration,
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
    let mut trace = report::Trace::start(detection_time);
    let validate_desktop = || challenge.revalidate(&is_current).map_err(desktop_reason);
    notify(Phase::Preparing);
    let mut failure_phase = Phase::Failed;
    let cleanup_failed = Arc::new(AtomicBool::new(false));
    enum CompletionMode {
        Submitted,
        ManualApprovalRequired,
    }
    let result = (|| -> Result<CompletionMode, Reason> {
        if !account.enabled || !account.iphone_authenticator_enabled {
            return Err(Reason::AccountDisabled);
        }
        if !challenge.matches_account(account) {
            return Err(Reason::AccountChanged);
        }
        validate_desktop()?;
        let mut command = helper_command().map_err(|_| {
            failure_phase = Phase::SetupRequired;
            Reason::HelperSetupRequired
        })?;
        let mut process = HelperProcess {
            child: command.spawn().map_err(|_| Reason::HelperStartFailed)?,
            input: None,
            reader: None,
            cleanup_failed: cleanup_failed.clone(),
        };
        trace.observe(Stage::Preparing, Some(Milestone::HelperSpawned));
        process.input = Some(process.child.stdin.take().ok_or(Reason::HelperIoFailed)?);
        let output = process.child.stdout.take().ok_or(Reason::HelperIoFailed)?;
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
        )
        .map_err(|_| Reason::HelperIoFailed)?;
        let deadline = Instant::now() + LIFETIME;
        let mut protocol = Protocol::default();
        let mut last_validation = Instant::now();
        let mut cleanup_deadline = None;
        loop {
            is_current().map_err(|_| Reason::Cancelled)?;
            if Instant::now() >= cleanup_deadline.unwrap_or(deadline) {
                return Err(Reason::DeadlineExceeded);
            }
            if last_validation.elapsed() >= Duration::from_millis(500) {
                if protocol == Protocol::Submitted {
                    use crate::macos_ax::sso::Completion;
                    if !matches!(
                        challenge
                            .poll_completion(&is_current)
                            .map_err(desktop_reason)?,
                        Completion::Pending
                    ) {
                        send(
                            process.input.as_mut().unwrap(),
                            &serde_json::json!({"finish": true}),
                        )
                        .map_err(|_| Reason::HelperIoFailed)?;
                        protocol.finish().map_err(|_| Reason::ProtocolError)?;
                        trace.advance(Stage::ClosingSession);
                        cleanup_deadline = Some(Instant::now() + Duration::from_secs(12));
                    }
                } else if matches!(
                    protocol,
                    Protocol::Initial
                        | Protocol::OpenPermitted
                        | Protocol::EntryPermitted
                        | Protocol::ManualEntryPermitted
                ) {
                    // Once submit is permitted the desktop can advance before
                    // WDA returns its click response. Await the explicit helper
                    // response instead of cancelling a completed click as stale.
                    validate_desktop()?;
                }
                last_validation = Instant::now();
            }
            match rx.recv_timeout(Duration::from_millis(100)) {
                Ok(Ok(Some(HelperEvent::Status { phase }))) => {
                    let (phase, stage, milestone) = Phase::from_helper(&phase)?;
                    trace.observe(stage, milestone);
                    notify(phase);
                }
                Ok(Ok(Some(HelperEvent::Authorize { sequence, action }))) => {
                    let stage = protocol
                        .authorize(sequence, &action)
                        .map_err(|_| Reason::ProtocolError)?;
                    trace.advance(stage);
                    validate_desktop()?;
                    send(
                        process.input.as_mut().unwrap(),
                        &serde_json::json!({"permit": sequence}),
                    )
                    .map_err(|_| Reason::HelperIoFailed)?;
                }
                Ok(Ok(Some(HelperEvent::Submitted {}))) => {
                    protocol.submitted().map_err(|_| Reason::ProtocolError)?;
                    trace.advance(Stage::WaitingForConfirmation);
                    notify(Phase::FaceId);
                }
                Ok(Ok(Some(HelperEvent::Closed {}))) => {
                    protocol.closed().map_err(|_| Reason::ProtocolError)?;
                    return Ok(CompletionMode::Submitted);
                }
                Ok(Ok(Some(HelperEvent::ManualApprovalRequired {}))) => {
                    protocol
                        .manual_approval_required()
                        .map_err(|_| Reason::ProtocolError)?;
                    return Ok(CompletionMode::ManualApprovalRequired);
                }
                Ok(Ok(Some(HelperEvent::Error { code }))) => {
                    // Never interpolate helper-provided strings into an error.
                    failure_phase = Phase::from_error(&code);
                    return Err(Reason::from_helper(&code));
                }
                Ok(Err(())) => return Err(Reason::ProtocolError),
                Ok(Ok(None)) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(Reason::UnexpectedEnd)
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
        }
    })();
    match result {
        _ if cleanup_failed.load(Ordering::SeqCst) => {
            notify(Phase::CleanupFailed);
            trace.finish(report::Outcome::Failed, Some(Reason::WdaCleanupUnverified));
            Outcome::Unavailable
        }
        Ok(CompletionMode::ManualApprovalRequired) => {
            trace.advance(Stage::WaitingForConfirmation);
            trace.finish(report::Outcome::ManualApprovalRequired, None);
            notify(Phase::ManualApprovalRequired);
            Outcome::ManualApprovalRequired
        }
        Ok(CompletionMode::Submitted) => {
            notify(Phase::Finished);
            trace.finish(report::Outcome::SubmittedUnverified, None);
            Outcome::SubmittedUnverified
        }
        Err(_) if cancelled.load(Ordering::SeqCst) || guard().is_err() => {
            let reason = if cancelled.load(Ordering::SeqCst) {
                Reason::UserCancelled
            } else {
                Reason::MonitorPaused
            };
            notify(Phase::Cancelled);
            trace.finish(report::Outcome::Cancelled, Some(reason));
            Outcome::Cancelled
        }
        Err(reason) => {
            notify(failure_phase);
            trace.finish(report::Outcome::Failed, Some(reason));
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
        assert_eq!(
            state.authorize(1, "open_authenticator").unwrap(),
            Stage::OpeningAuthenticator
        );
        assert!(state.authorize(1, "open_authenticator").is_err());
        assert_eq!(
            state.authorize(2, "enter_number").unwrap(),
            Stage::VerifyingNumberField
        );
        assert!(state.authorize(3, "accept_alert").is_err());
        assert_eq!(
            state.authorize(3, "submit_number").unwrap(),
            Stage::SubmittingNumber
        );
        state.submitted().unwrap();
        assert!(state.closed().is_err());
        state.finish().unwrap();
        state.closed().unwrap();
        assert!(state.finish().is_err());
        assert!(state.submitted().is_err());
        assert!(state.authorize(4, "submit_number").is_err());
    }

    #[test]
    fn manual_entry_requires_a_separate_permit_and_cannot_submit() {
        let mut state = Protocol::default();
        assert!(state.manual_approval_required().is_err());
        assert!(state
            .authorize(3, "enter_number_for_manual_approval")
            .is_err());
        state.authorize(1, "open_authenticator").unwrap();
        assert!(state.manual_approval_required().is_err());
        state.authorize(2, "enter_number").unwrap();
        assert!(state.manual_approval_required().is_err());
        let mut automatic = state;
        automatic.authorize(3, "submit_number").unwrap();
        assert!(automatic.manual_approval_required().is_err());
        assert!(automatic
            .authorize(4, "enter_number_for_manual_approval")
            .is_err());
        assert_eq!(
            state
                .authorize(3, "enter_number_for_manual_approval")
                .unwrap(),
            Stage::RecheckingManualEntry
        );
        assert!(state.authorize(3, "submit_number").is_err());
        assert!(state.authorize(4, "submit_number").is_err());
        assert!(state.submitted().is_err());
        assert!(state.finish().is_err());
        assert!(state.closed().is_err());
        state.manual_approval_required().unwrap();
        assert!(state.manual_approval_required().is_err());
        assert!(state.submitted().is_err());
        assert!(Phase::ManualApprovalRequired.needs_close_button());
        assert_eq!(
            serde_json::to_value(report::Outcome::ManualApprovalRequired).unwrap(),
            "manual_approval_required"
        );
        assert_eq!(
            Reason::from_helper("field_verification_timeout"),
            Reason::FieldVerificationTimeout
        );
        assert_eq!(
            Phase::from_error("field_verification_timeout"),
            Phase::FieldCheckTimedOut
        );
        assert!(Phase::FieldCheckTimedOut.needs_close_button());
    }

    #[test]
    fn diagnostics_distinguish_desktop_and_phone_failures_before_entry() {
        use crate::macos_ax::sso::DesktopCheckFailure;
        assert_eq!(
            desktop_reason(anyhow::Error::new(DesktopCheckFailure::RequestChanged)),
            Reason::DesktopRequestChanged
        );
        assert_eq!(
            desktop_reason(anyhow::anyhow!("opaque error")),
            Reason::DesktopRequestUnavailable
        );
        assert_eq!(
            Phase::from_helper("waiting_for_number_request").unwrap().1,
            Stage::WaitingForRequest
        );
        assert_eq!(
            Phase::from_helper("unrecognized"),
            Err(Reason::ProtocolError)
        );
    }

    #[test]
    fn diagnostic_times_start_at_the_corresponding_helper_status() {
        for (status, milestone) in [
            ("preparing_iphone_runner", None),
            ("starting_iphone_runner", Some(Milestone::RunnerStarting)),
            ("starting_iphone_connection", Some(Milestone::RunnerReady)),
            ("iphone_connected", Some(Milestone::PhoneConnected)),
            ("entering_number", Some(Milestone::NumberEntryStarting)),
        ] {
            assert_eq!(Phase::from_helper(status).unwrap().2, milestone);
        }
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
