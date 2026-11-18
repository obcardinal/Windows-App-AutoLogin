//! One private snapshot, replaced as the latest iPhone sign-in attempt advances.

use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{btree_map::Entry, BTreeMap};
use std::path::PathBuf;
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const FILE_NAME: &str = "last-iphone-attempt.json";

/// Elapsed times when the Mac first observes each milestone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Milestone {
    HelperSpawned,
    RunnerStarting,
    RunnerReady,
    PhoneConnected,
    AuthenticatorOpenRequested,
    FieldCheckRequested,
    NumberEntryStarting,
    SubmitRequested,
    SubmissionAcknowledged,
    CleanupRequested,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Stage {
    Preparing,
    WaitingForDevice,
    WaitingForUnlock,
    Connecting,
    OpeningAuthenticator,
    WaitingForRequest,
    VerifyingNumberField,
    EnteringNumber,
    SubmittingNumber,
    WaitingForConfirmation,
    ClosingSession,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Outcome {
    InProgress,
    Failed,
    Cancelled,
    SubmittedUnverified,
}

/// No payload strings: an unrecognized helper error cannot put its message,
/// account, or challenge contents into the report.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Reason {
    #[serde(skip_deserializing)]
    AccountDisabled,
    #[serde(skip_deserializing)]
    AccountChanged,
    #[serde(skip_deserializing)]
    DesktopRequestUnavailable,
    #[serde(skip_deserializing)]
    DesktopRequestExpired,
    #[serde(skip_deserializing)]
    DesktopWindowGone,
    #[serde(skip_deserializing)]
    DesktopWindowChanged,
    #[serde(skip_deserializing)]
    DesktopRequestGone,
    #[serde(skip_deserializing)]
    DesktopRequestChanged,
    #[serde(skip_deserializing)]
    HelperSetupRequired,
    #[serde(skip_deserializing)]
    HelperStartFailed,
    #[serde(skip_deserializing)]
    HelperIoFailed,
    #[serde(skip_deserializing)]
    ProtocolError,
    #[serde(skip_deserializing)]
    DeadlineExceeded,
    #[serde(skip_deserializing)]
    UserCancelled,
    #[serde(skip_deserializing)]
    MonitorPaused,
    #[serde(skip_deserializing)]
    UnexpectedEnd,
    InvalidRequest,
    InvalidProtocol,
    RequestTooLarge,
    ParentDisconnected,
    AuthorizationTimeout,
    AuthorizationExpired,
    Cancelled,
    ChallengeExpired,
    HelperFailed,
    UnsupportedAuthenticatorLayout,
    InvalidDeviceResponse,
    AmbiguousAuthenticatorScreen,
    PhoneLocked,
    AccountMismatch,
    NumberFieldNotEmpty,
    FieldVerificationTimeout,
    ScreenChanged,
    NumberEntryUnconfirmed,
    UnsafeStorage,
    UnsafeConfiguration,
    InvalidConfiguration,
    NotConfigured,
    RuntimeMissing,
    DeviceSelectionRequired,
    DeveloperModeRequired,
    DeviceDiscoveryFailed,
    SessionLockFailed,
    SessionBusy,
    ServerStartFailed,
    SessionStartFailed,
    SessionClosed,
    ElementUnavailable,
    DeviceCommandFailed,
    TransportFailed,
    WifiDeviceRequired,
    IphoneNotAvailableToAppium,
    WdaSigningRequired,
    UiAutomationRequired,
    DriverUnavailable,
    AuthenticatorNotInstalled,
    WdaBuildFailed,
    WdaConnectionFailed,
    WdaCleanupUnverified,
    InvalidTimeout,
    InvalidDevice,
    CommandFailed,
    #[serde(other)]
    UnknownHelperError,
}

impl Reason {
    pub(crate) fn from_helper(code: &str) -> Self {
        use serde::de::value::{Error, StrDeserializer};
        Self::deserialize(StrDeserializer::<Error>::new(code)).unwrap_or(Self::UnknownHelperError)
    }
}

#[derive(Serialize)]
struct Report {
    recorded_at: String,
    elapsed_ms: u64,
    detection_scan_ms: u64,
    stage: Stage,
    outcome: Outcome,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    milestones_ms: BTreeMap<Milestone, u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<Reason>,
}

pub(crate) struct Trace {
    started: Instant,
    detection_scan_ms: u64,
    stage: Stage,
    milestones_ms: BTreeMap<Milestone, u64>,
    pending: Arc<Mutex<Option<Report>>>,
    worker: Option<(mpsc::SyncSender<()>, JoinHandle<()>)>,
}

impl Trace {
    pub(crate) fn start(detection_time: Duration) -> Self {
        Self::start_with(detection_time, || {
            Ok(crate::user_paths::runtime_dir()?.join(FILE_NAME))
        })
    }

    fn start_with(
        detection_time: Duration,
        resolve_path: impl FnOnce() -> anyhow::Result<PathBuf> + Send + 'static,
    ) -> Self {
        let started = Instant::now();
        let pending = Arc::new(Mutex::new(None::<Report>));
        let queued = Arc::clone(&pending);
        let (wake, receive) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("iphone-attempt-report".into())
            .spawn(move || {
                let Ok(path) = resolve_path() else {
                    tracing::warn!("Could not locate the iPhone attempt report");
                    return;
                };
                for () in receive {
                    let update = queued.lock().unwrap_or_else(|e| e.into_inner()).take();
                    if let Some(report) = update {
                        let write = serde_json::to_vec_pretty(&report)
                            .map_err(anyhow::Error::from)
                            .and_then(|bytes| {
                                crate::debug_fill::write_private_report_atomic(&path, &bytes)
                            });
                        if write.is_err() {
                            tracing::warn!("Could not write the iPhone attempt report");
                        }
                    }
                }
            })
            .inspect_err(|_| tracing::warn!("Could not start the iPhone attempt report writer"))
            .ok()
            .map(|handle| (wake, handle));

        let trace = Self {
            started,
            detection_scan_ms: u64::try_from(detection_time.as_millis()).unwrap_or(u64::MAX),
            stage: Stage::Preparing,
            milestones_ms: BTreeMap::new(),
            pending,
            worker,
        };
        trace.publish(Outcome::InProgress, None);
        trace
    }

    pub(crate) fn advance(&mut self, stage: Stage) {
        let milestone = match stage {
            Stage::OpeningAuthenticator => Some(Milestone::AuthenticatorOpenRequested),
            Stage::VerifyingNumberField => Some(Milestone::FieldCheckRequested),
            Stage::SubmittingNumber => Some(Milestone::SubmitRequested),
            Stage::WaitingForConfirmation => Some(Milestone::SubmissionAcknowledged),
            Stage::ClosingSession => Some(Milestone::CleanupRequested),
            _ => None,
        };
        self.observe(stage, milestone);
    }

    pub(super) fn observe(&mut self, stage: Stage, milestone: Option<Milestone>) {
        let first_observation =
            if let Some(Entry::Vacant(slot)) = milestone.map(|key| self.milestones_ms.entry(key)) {
                slot.insert(u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX));
                true
            } else {
                false
            };
        if stage != self.stage || first_observation {
            self.stage = stage;
            self.publish(Outcome::InProgress, None);
        }
    }

    pub(crate) fn finish(self, outcome: Outcome, reason: Option<Reason>) {
        self.publish(outcome, reason);
        // Drop drains the terminal snapshot before another attempt can begin.
    }

    fn publish(&self, outcome: Outcome, reason: Option<Reason>) {
        let Some((wake, _)) = &self.worker else {
            return;
        };
        let report = Report {
            recorded_at: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            elapsed_ms: u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX),
            detection_scan_ms: self.detection_scan_ms,
            stage: self.stage,
            outcome,
            milestones_ms: self.milestones_ms.clone(),
            reason,
        };
        *self.pending.lock().unwrap_or_else(|e| e.into_inner()) = Some(report);
        // One wakeup is enough even when the disk is slower than incoming
        // updates: the worker will take the latest snapshot from the slot.
        let _ = wake.try_send(());
    }
}

impl Drop for Trace {
    fn drop(&mut self) {
        if let Some((wake, worker)) = self.worker.take() {
            drop(wake);
            if worker.join().is_err() {
                tracing::warn!("The iPhone attempt report writer stopped unexpectedly");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn report_replaces_previous_attempt_and_contains_only_bounded_fields() {
        let directory = std::env::temp_dir().join(format!("waal-report-{}", uuid::Uuid::new_v4()));
        let path = directory.join(FILE_NAME);
        let start = || {
            let path = path.clone();
            Trace::start_with(Duration::from_millis(147), move || Ok(path))
        };
        let mut previous = start();
        previous.advance(Stage::Connecting);
        previous.finish(Outcome::Cancelled, Some(Reason::UserCancelled));
        let mut trace = start();
        trace.advance(Stage::WaitingForRequest);
        trace.advance(Stage::VerifyingNumberField);
        trace.advance(Stage::VerifyingNumberField);
        trace.finish(
            Outcome::Failed,
            Some(Reason::from_helper("account_mismatch")),
        );
        let bytes = std::fs::read(&path).unwrap();
        let report: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(bytes.len() < 512);
        assert_eq!(report.as_object().unwrap().len(), 7);
        assert_eq!(report["detection_scan_ms"], 147);
        let times = report["milestones_ms"].as_object().unwrap();
        assert_eq!(times.len(), 1);
        assert!(times["field_check_requested"].is_u64());
        assert_eq!(report["stage"], "verifying_number_field");
        assert_eq!(report["outcome"], "failed");
        assert_eq!(report["reason"], "account_mismatch");
        assert!(report["elapsed_ms"].as_u64().is_some());
        let date = report["recorded_at"].as_str().unwrap();
        assert!(date.ends_with('Z') && chrono::DateTime::parse_from_rfc3339(date).is_ok());
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 1);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn first_milestone_times_survive_duplicate_statuses_and_coalesced_writes() {
        let directory = std::env::temp_dir().join(format!("waal-report-{}", uuid::Uuid::new_v4()));
        let path = directory.join(FILE_NAME);
        let writer_path = path.clone();
        let (release, wait) = mpsc::channel();
        let mut trace = Trace::start_with(Duration::ZERO, move || {
            wait.recv()?;
            Ok(writer_path)
        });
        trace.observe(Stage::Connecting, Some(Milestone::RunnerStarting));
        let first = trace.milestones_ms.get(&Milestone::RunnerStarting).copied();
        std::thread::sleep(std::time::Duration::from_millis(3));
        trace.observe(Stage::Connecting, Some(Milestone::RunnerReady));
        trace.observe(Stage::Connecting, Some(Milestone::RunnerStarting));
        trace.observe(Stage::Connecting, Some(Milestone::PhoneConnected));
        trace.observe(Stage::EnteringNumber, Some(Milestone::NumberEntryStarting));
        trace.advance(Stage::SubmittingNumber);
        // A progress message may precede the protocol's submission acknowledgement.
        trace.observe(Stage::WaitingForConfirmation, None);
        assert!(!trace
            .milestones_ms
            .contains_key(&Milestone::SubmissionAcknowledged));
        trace.advance(Stage::WaitingForConfirmation);
        trace.advance(Stage::ClosingSession);
        release.send(()).unwrap();
        trace.finish(Outcome::SubmittedUnverified, None);

        let bytes = std::fs::read(path).unwrap();
        let report: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let times = report["milestones_ms"].as_object().unwrap();
        let first = first.unwrap();
        assert_eq!(times.len(), 7);
        assert_eq!(times["runner_starting"], first);
        let ready = times["runner_ready"].as_u64().unwrap();
        let connected = times["phone_connected"].as_u64().unwrap();
        let entry = times["number_entry_starting"].as_u64().unwrap();
        assert!(first < ready && ready <= connected && connected <= entry);
        let submit = times["submit_requested"].as_u64().unwrap();
        let acknowledged = times["submission_acknowledged"].as_u64().unwrap();
        let cleanup = times["cleanup_requested"].as_u64().unwrap();
        assert!(entry <= submit && submit <= acknowledged && acknowledged <= cleanup);
        assert!(cleanup <= report["elapsed_ms"].as_u64().unwrap());
        assert_eq!(report["stage"], "closing_session");
        assert_eq!(report["outcome"], "submitted_unverified");
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn helper_may_only_supply_known_protocol_reasons() {
        for input in [
            "sample@example.invalid",
            "19",
            "nested error: screen_changed",
            "user_cancelled",
        ] {
            let reason = Reason::from_helper(input);
            assert_eq!(reason, Reason::UnknownHelperError);
            assert_eq!(
                serde_json::to_value(reason).unwrap(),
                "unknown_helper_error"
            );
        }
        assert_eq!(
            Reason::from_helper("authorization_expired"),
            Reason::AuthorizationExpired
        );
    }
}
