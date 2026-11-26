//! Install the bundled iPhone helper with the current user's Xcode signing team.
use crate::iphone_signing::{self, SigningTeam};
use serde_json::Value;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const NODE_REQUIRED: &str =
    "The downloaded helper tools couldn’t start. Retry setup to check and prepare them again.";
const STORAGE_ERROR: &str = "The iPhone setup files could not be read or saved privately. Check this Mac’s application support folder and try again.";
const CANCELLED: &str = "iPhone setup cancelled. You can try again when you’re ready.";
const SETUP_FAILED: &str =
    "iPhone setup could not finish. Check Xcode and the selected iPhone, then try again.";

#[derive(Clone, Debug)]
pub(crate) struct SetupRequirements {
    pub(crate) teams: Vec<SigningTeam>,
    pub(crate) selected_team: Option<String>,
    pub(crate) phone_selected: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SetupProgress {
    Checking,
    Installing,
    Building,
    Connecting,
    Ready,
}

impl SetupProgress {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Checking => "Checking this Mac…",
            Self::Installing => "Preparing the Mac helper…",
            Self::Building => "Preparing the iPhone helper with Xcode…",
            Self::Connecting => "Checking the helper on your iPhone…",
            Self::Ready => "iPhone helper ready",
        }
    }
}

pub(crate) fn inspect() -> Result<SetupRequirements, String> {
    let teams = iphone_signing::available_teams()?;
    let root = helper_root()?;
    let config = saved_document(&root.join("config.json"))?;
    let selection = match &config {
        Some(config) => Some(config.clone()),
        None => saved_document(&root.join("pending-device.json"))?,
    };
    let selected_team = config
        .as_ref()
        .and_then(|value| value["development_team"].as_str())
        .filter(|id| teams.iter().any(|team| team.id == *id))
        .map(str::to_owned);
    let phone_selected = selection
        .as_ref()
        .and_then(|value| value["device_udid"].as_str())
        .is_some_and(crate::iphone_setup_info::valid_id);
    Ok(SetupRequirements {
        teams,
        selected_team,
        phone_selected,
    })
}

pub(crate) fn open_xcode() -> Result<(), String> {
    let mut command = Command::new("/usr/bin/open");
    command.args(["-b", "com.apple.dt.Xcode"]);
    run_command(
        command,
        Duration::from_secs(10),
        &AtomicBool::new(false),
        |_| Ok(()),
    )
    .map_err(|_| "Couldn’t open Xcode. Install Xcode and open it once to finish setup.".into())
}

pub(crate) fn run_setup(
    team_id: &str,
    expected_device: Option<&str>,
    mut on_progress: impl FnMut(SetupProgress),
    cancelled: &AtomicBool,
) -> Result<(), String> {
    on_progress(SetupProgress::Checking);
    check_cancelled(cancelled)?;
    if !iphone_signing::available_teams()?
        .iter()
        .any(|team| team.id == team_id)
    {
        return Err("Select a team with an Apple Development certificate in Xcode → Settings → Accounts → Manage Certificates, then refresh.".into());
    }
    let root = helper_root()?;
    private_dir(&root).map_err(|_| STORAGE_ERROR)?;
    let _lock = setup_lock(&root)?;
    let config = saved_document(&root.join("config.json"))?;
    let selection = match &config {
        Some(config) => Some(config.clone()),
        None => saved_document(&root.join("pending-device.json"))?,
    };
    let selected = selection
        .as_ref()
        .and_then(|value| value["device_udid"].as_str())
        .filter(|id| crate::iphone_setup_info::valid_id(id))
        .ok_or("Connect your iPhone in AutoLogin before setting up its sign-in helper.")?;
    if expected_device.is_some_and(|id| !selected.eq_ignore_ascii_case(id)) {
        return Err("The selected iPhone changed. Connect the iPhone again.".into());
    }
    crate::iphone_setup_info::invalidate_preparation(&root).map_err(|_| STORAGE_ERROR)?;
    let node = match node_runtime(config.as_ref(), cancelled) {
        Some(node) => node,
        None => {
            check_cancelled(cancelled)?;
            on_progress(SetupProgress::Installing);
            let executable = crate::iphone_node::install(cancelled)?;
            let config = serde_json::json!({"node_path": executable});
            node_runtime(Some(&config), cancelled).ok_or(NODE_REQUIRED)?
        }
    };
    check_cancelled(cancelled)?;
    let source = BundledSource::write(&root)?;
    on_progress(SetupProgress::Installing);
    run_helper(
        &node,
        &source.0.join("cli.mjs"),
        &["setup", "--team", team_id, "--parent-lifetime"],
        "host_setup_complete",
        Duration::from_secs(660),
        cancelled,
        &mut on_progress,
    )?;
    check_cancelled(cancelled)?;
    crate::iphone_setup_info::prepare_selected_device(&root, selected, team_id, || {
        on_progress(SetupProgress::Building);
        run_helper(
            &node,
            &source.0.join("cli.mjs"),
            &["prepare-device", "--parent-lifetime"],
            "device_prepared",
            Duration::from_secs(420),
            cancelled,
            &mut on_progress,
        )?;
        check_cancelled(cancelled)
    })?;
    on_progress(SetupProgress::Ready);
    Ok(())
}

fn helper_root() -> Result<PathBuf, String> {
    crate::user_paths::config_dir()
        .map(|path| path.join("iphone-automation"))
        .map_err(|_| STORAGE_ERROR.into())
}

fn saved_document(path: &Path) -> Result<Option<Value>, String> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(STORAGE_ERROR.into()),
    };
    let read = || -> anyhow::Result<Value> {
        let stat = file.metadata()?;
        anyhow::ensure!(
            stat.is_file()
                && stat.uid() == unsafe { libc::geteuid() }
                && stat.mode() & 0o077 == 0
                && stat.len() <= 8192
                && !crate::private_permissions::file_has_macos_acl_fd(&file)?,
            "private file required"
        );
        let mut bytes = Vec::new();
        file.take(8193).read_to_end(&mut bytes)?;
        anyhow::ensure!(bytes.len() <= 8192, "invalid configuration");
        let value: Value = serde_json::from_slice(&bytes)?;
        anyhow::ensure!(value["schema_version"] == 1, "invalid configuration");
        Ok(value)
    };
    read().map(Some).map_err(|_| STORAGE_ERROR.into())
}

fn private_dir(path: &Path) -> anyhow::Result<()> {
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => crate::private_permissions::strip_macos_acl(path)?,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let stat = fs::symlink_metadata(path)?;
    anyhow::ensure!(
        stat.is_dir()
            && stat.uid() == unsafe { libc::geteuid() }
            && stat.mode() & 0o077 == 0
            && !crate::private_permissions::path_has_macos_acl(path)?,
        "private directory required"
    );
    Ok(())
}

pub(super) fn setup_lock(root: &Path) -> Result<File, String> {
    let acquire = || -> anyhow::Result<File> {
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(root.join(".setup.lock"))?;
        let stat = file.metadata()?;
        anyhow::ensure!(
            stat.is_file()
                && stat.uid() == unsafe { libc::geteuid() }
                && stat.mode() & 0o077 == 0
                && !crate::private_permissions::file_has_macos_acl_fd(&file)?,
            "private lock required"
        );
        anyhow::ensure!(
            unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "setup active"
        );
        Ok(file)
    };
    acquire().map_err(|_| {
        "Another iPhone setup is in progress. Wait for it to finish, then try again.".into()
    })
}

struct BundledSource(PathBuf);

impl BundledSource {
    fn write(root: &Path) -> Result<Self, String> {
        let source = Self(root.join(format!("setup-{}", uuid::Uuid::new_v4())));
        private_dir(&source.0).map_err(|_| STORAGE_ERROR)?;
        macro_rules! embedded {
            ($($name:literal),+ $(,)?) => { [$(($name, include_bytes!(concat!("../script/iphone-automation/", $name)).as_slice())),+] };
        }
        for (name, bytes) in embedded![
            "cli.mjs",
            "support.mjs",
            "bridge.mjs",
            "wda.mjs",
            "signing.mjs",
            "authenticator.mjs",
            "run-request.mjs",
            "prepare-host.mjs",
            "selection-config.mjs",
            "package.json",
            "package-lock.json",
        ] {
            crate::storage::write_private_file_atomic(&source.0.join(name), "setup", bytes)
                .map_err(|_| STORAGE_ERROR)?;
        }
        Ok(source)
    }
}

impl Drop for BundledSource {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct NodeRuntime {
    executable: PathBuf,
    bin: PathBuf,
}

fn node_runtime(config: Option<&Value>, cancelled: &AtomicBool) -> Option<NodeRuntime> {
    let saved = config
        .and_then(|config| config["node_path"].as_str())
        .map(PathBuf::from);
    for executable in saved
        .into_iter()
        .chain(crate::iphone_node::cached_node())
        .chain([
            PathBuf::from("/opt/homebrew/bin/node"),
            PathBuf::from("/usr/local/bin/node"),
        ])
    {
        if !executable.is_absolute()
            || executable.file_name().is_none_or(|name| name != "node")
            || !executable.is_file()
        {
            continue;
        }
        let node = NodeRuntime {
            bin: executable.parent()?.to_owned(),
            executable,
        };
        let version = tool_output(&node, &node.executable, &["--version"], cancelled);
        if !version.as_deref().is_some_and(supported_node) {
            continue;
        }
        let npm = node.bin.join("npm");
        let version = tool_output(&node, &npm, &["--version"], cancelled);
        if version
            .as_deref()
            .and_then(parse_version)
            .is_some_and(|v| v.0 >= 10)
        {
            return Some(node);
        }
    }
    None
}

fn parse_version(version: &str) -> Option<(u32, u32, u32)> {
    let mut parts = version.trim().trim_start_matches('v').split('.');
    let result = (
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    );
    parts.next().is_none().then_some(result)
}

fn supported_node(version: &str) -> bool {
    parse_version(version).is_some_and(|(major, minor, patch)| {
        major >= 26 || (major == 24 && minor >= 15) || (major == 22 && (minor, patch) >= (22, 2))
    })
}

fn environment(command: &mut Command, node: &NodeRuntime) -> Result<(), String> {
    command
        .env_clear()
        .env("HOME", crate::user_paths::home_dir().ok_or(STORAGE_ERROR)?)
        .env(
            "PATH",
            format!(
                "{}:/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin",
                node.bin.display()
            ),
        )
        .env("LANG", "en_US.UTF-8");
    Ok(())
}

fn tool_output(
    node: &NodeRuntime,
    program: &Path,
    args: &[&str],
    cancelled: &AtomicBool,
) -> Option<String> {
    let mut command = Command::new(program);
    environment(&mut command, node).ok()?;
    command.args(args);
    let mut output = Vec::new();
    run_command(command, Duration::from_secs(12), cancelled, |chunk| {
        if output.len() + chunk.len() > 4096 {
            return Err(SETUP_FAILED.into());
        }
        output.extend_from_slice(chunk);
        Ok(())
    })
    .ok()?;
    String::from_utf8(output).ok()
}

fn run_helper(
    node: &NodeRuntime,
    script: &Path,
    args: &[&str],
    completed: &str,
    timeout: Duration,
    cancelled: &AtomicBool,
    progress: &mut impl FnMut(SetupProgress),
) -> Result<(), String> {
    let mut command = Command::new(&node.executable);
    environment(&mut command, node)?;
    command
        .arg(script)
        .args(args)
        .current_dir(script.parent().ok_or(SETUP_FAILED)?);
    let mut pending = Vec::new();
    let mut successful = false;
    let mut failure = None;
    let result = run_command(command, timeout, cancelled, |chunk| {
        pending.extend_from_slice(chunk);
        if pending.len() > 65536 {
            return Err(SETUP_FAILED.into());
        }
        while let Some(end) = pending.iter().position(|byte| *byte == b'\n') {
            let event: Value = serde_json::from_slice(&pending[..end]).map_err(|_| SETUP_FAILED)?;
            match event["phase"].as_str() {
                Some(phase) if phase == completed => successful = true,
                Some("failed") => {
                    failure = Some(setup_error(event["code"].as_str().unwrap_or_default()))
                }
                Some("installing_host_dependencies") => progress(SetupProgress::Installing),
                Some("preparing_iphone_runner") => progress(SetupProgress::Building),
                Some(
                    "starting_iphone_runner" | "starting_iphone_connection" | "iphone_connected",
                ) => progress(SetupProgress::Connecting),
                _ => {}
            }
            pending.drain(..=end);
        }
        Ok(())
    });
    if let Some(failure) = failure {
        return Err(failure.into());
    }
    result?;
    if !successful {
        return Err(SETUP_FAILED.into());
    }
    Ok(())
}

fn setup_error(code: &str) -> &'static str {
    match code {
        "cancelled" => CANCELLED,
        "session_busy" | "selection_busy" => "Another iPhone operation is in progress. Wait for it to finish, then retry setup.",
        "wda_signing_required" | "wda_build_failed" | "signing_team_required" | "invalid_signing_team" => "Xcode couldn’t sign the iPhone helper. Open Xcode → Settings → Accounts, sign in to the selected team and check its Apple Development certificate. Then retry setup.",
        "phone_locked" | "device_locked" | "device_lock_unknown" => "Unlock the selected iPhone, keep its screen on and retry setup.",
        "developer_mode_required" => "Enable Developer Mode in iPhone Settings → Privacy & Security, restart the phone if requested and retry setup.",
        "ui_automation_required" => "Enable UI Automation in iPhone Settings → Developer, then retry setup.",
        "device_selection_required" | "device_unavailable" | "device_discovery_failed" | "wifi_required" | "wifi_device_required" | "wda_connection_failed" => "Reconnect the selected iPhone to the same Wi-Fi as this Mac, then retry setup.",
        "command_failed" | "runtime_install_failed" | "runtime_missing" => "The helper dependencies could not be installed. Check your internet connection and Node.js installation, then retry setup.",
        "wda_cleanup_unverified" => "Reconnect the selected iPhone so AutoLogin can finish closing its setup session, then retry.",
        _ => SETUP_FAILED,
    }
}

fn check_cancelled(cancelled: &AtomicBool) -> Result<(), String> {
    if cancelled.load(Ordering::Acquire) {
        Err(CANCELLED.into())
    } else {
        Ok(())
    }
}

fn run_command(
    mut command: Command,
    timeout: Duration,
    cancelled: &AtomicBool,
    mut receive: impl FnMut(&[u8]) -> Result<(), String>,
) -> Result<(), String> {
    check_cancelled(cancelled)?;
    let (mut reader, writer) = UnixStream::pair().map_err(|_| SETUP_FAILED)?;
    reader.set_nonblocking(true).map_err(|_| SETUP_FAILED)?;
    let mut child = command
        .process_group(0)
        .stdin(Stdio::piped())
        .stderr(Stdio::null())
        .stdout(Stdio::from(OwnedFd::from(writer)))
        .spawn()
        .map_err(|_| SETUP_FAILED)?;
    let deadline = Instant::now() + timeout;
    let mut buffer = [0; 8192];
    let result = loop {
        if let Err(error) = check_cancelled(cancelled) {
            break Err(error);
        }
        if Instant::now() >= deadline {
            break Err(
                "iPhone setup timed out. Check Xcode and the selected iPhone, then retry.".into(),
            );
        }
        match reader.read(&mut buffer) {
            Ok(0) => {}
            Ok(count) => {
                if let Err(error) = receive(&buffer[..count]) {
                    break Err(error);
                }
                continue;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(_) => break Err(SETUP_FAILED.into()),
        }
        match has_exited(&child) {
            Ok(true) => return finish_child(&mut child),
            Ok(false) => {}
            Err(_) => break Err(SETUP_FAILED.into()),
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    stop_child(&mut child);
    result
}

fn stop_child(child: &mut Child) {
    // EOF lets the CLI close its own detached XCTest/Appium groups as well.
    child.stdin.take();
    unsafe { libc::killpg(child.id() as libc::pid_t, libc::SIGTERM) };
    let deadline = Instant::now() + Duration::from_secs(15);
    while matches!(has_exited(child), Ok(false)) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(25));
    }
    let _ = finish_child(child);
}

fn has_exited(child: &Child) -> io::Result<bool> {
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            child.id(),
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if result == 0 {
        Ok(info.si_pid != 0)
    } else {
        Err(io::Error::last_os_error())
    }
}

fn finish_child(child: &mut Child) -> Result<(), String> {
    // Keep the leader waitable until its owned group has been terminated.
    unsafe { libc::killpg(child.id() as libc::pid_t, libc::SIGKILL) };
    if child.wait().is_ok_and(|status| status.success()) {
        Ok(())
    } else {
        Err(SETUP_FAILED.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_versions_follow_the_pinned_runtime_engines() {
        for version in ["v22.22.2", "22.23.0", "24.15.0", "26.0.0", "27.0.1"] {
            assert!(supported_node(version), "{version}");
        }
        for version in [
            "22.22.1",
            "24.14.9",
            "23.0.0",
            "25.9.0",
            "20.0.0",
            "26.0.0-beta",
            "26.0.0.1",
        ] {
            assert!(!supported_node(version), "{version}");
        }
    }

    #[test]
    fn setup_lock_is_exclusive_and_embedded_sources_are_private() {
        let root = std::env::temp_dir().join(format!("waal-setup-test-{}", uuid::Uuid::new_v4()));
        private_dir(&root).unwrap();
        let lock = setup_lock(&root).unwrap();
        assert!(setup_lock(&root).is_err());
        drop(lock);
        // Other process tests may fork just before this descriptor closes.
        // CLOEXEC releases that inherited copy as soon as their exec completes.
        let deadline = Instant::now() + Duration::from_secs(2);
        while setup_lock(&root).is_err() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(10));
        }
        let source = BundledSource::write(&root).unwrap();
        assert_eq!(
            fs::read(source.0.join("authenticator.mjs")).unwrap(),
            include_bytes!("../script/iphone-automation/authenticator.mjs")
        );
        assert_eq!(
            fs::metadata(source.0.join("cli.mjs")).unwrap().mode() & 0o077,
            0
        );
        let path = source.0.clone();
        drop(source);
        assert!(!path.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cancellation_stops_the_owned_command_and_hides_raw_errors() {
        let cancelled = AtomicBool::new(true);
        assert_eq!(
            run_command(
                Command::new("/usr/bin/true"),
                Duration::from_secs(1),
                &cancelled,
                |_| Ok(())
            ),
            Err(CANCELLED.into())
        );
        assert_eq!(setup_error("unknown private error message"), SETUP_FAILED);
        let mut command = Command::new("/bin/sleep");
        command.arg("30");
        let started = Instant::now();
        assert!(run_command(
            command,
            Duration::from_millis(50),
            &AtomicBool::new(false),
            |_| Ok(())
        )
        .is_err());
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn helper_requires_completed_preparation_and_reports_only_known_errors() {
        let root =
            std::env::temp_dir().join(format!("waal-setup-protocol-{}", uuid::Uuid::new_v4()));
        private_dir(&root).unwrap();
        let script = root.join("fixture.sh");
        let node = NodeRuntime {
            executable: "/bin/sh".into(),
            bin: "/bin".into(),
        };
        let run = |source: &str, phases: &mut Vec<SetupProgress>| {
            crate::storage::write_private_file_atomic(&script, "fixture", source.as_bytes())
                .unwrap();
            run_helper(
                &node,
                &script,
                &[],
                "device_prepared",
                Duration::from_secs(2),
                &AtomicBool::new(false),
                &mut |phase| phases.push(phase),
            )
        };
        let mut phases = Vec::new();
        assert!(run("printf '%s\\n' '{\"phase\":\"preparing_iphone_runner\"}' '{\"phase\":\"starting_iphone_connection\"}' '{\"phase\":\"device_prepared\"}'", &mut phases).is_ok());
        assert_eq!(phases, [SetupProgress::Building, SetupProgress::Connecting]);
        assert!(run("exit 0", &mut phases).is_err());
        assert_eq!(run("printf '%s\\n' '{\"phase\":\"failed\",\"code\":\"phone_locked\",\"message\":\"private details\"}'; exit 1", &mut phases),
            Err(setup_error("phone_locked").into()));
        fs::remove_dir_all(root).unwrap();
    }
}
