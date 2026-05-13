use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
#[cfg(target_os = "windows")]
use windows::core::PCWSTR;
#[cfg(target_os = "windows")]
use windows::Win32::Foundation::{CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, HANDLE};
#[cfg(target_os = "windows")]
use windows::Win32::System::Threading::CreateMutexW;

#[cfg(not(target_os = "windows"))]
const LOCK_DIR_NAME: &str = "WindowsAppAutoLogin.lock";
#[cfg(target_os = "windows")]
const ACTIVATION_FILE_NAME: &str = "activate";
const MONITOR_COMMAND_FILE_NAME: &str = "monitor-command";
const MONITOR_STATUS_FILE_NAME: &str = "monitor-status";
const MONITOR_COMMAND_START: &str = "start_monitor";
const MONITOR_COMMAND_STOP: &str = "stop_monitor";
#[cfg(target_os = "windows")]
const WINDOWS_SINGLE_INSTANCE_MUTEX: &str = "Local\\WindowsAppAutoLogin.SingleInstance";

pub(crate) struct SingleInstanceGuard {
    #[cfg(target_os = "windows")]
    mutex: HANDLE,
    #[cfg(not(target_os = "windows"))]
    lock_dir: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MonitorControlCommand {
    Start,
    Stop,
}

impl MonitorControlCommand {
    fn as_str(self) -> &'static str {
        match self {
            Self::Start => MONITOR_COMMAND_START,
            Self::Stop => MONITOR_COMMAND_STOP,
        }
    }

    fn from_request(value: &str) -> Option<Self> {
        match value.split(':').next().unwrap_or_default().trim() {
            MONITOR_COMMAND_START => Some(Self::Start),
            MONITOR_COMMAND_STOP => Some(Self::Stop),
            _ => None,
        }
    }
}

pub(crate) struct MonitorCommandWatcher {
    path: Option<PathBuf>,
    last_content: Option<String>,
}

impl SingleInstanceGuard {
    pub(crate) fn acquire() -> anyhow::Result<Self> {
        #[cfg(target_os = "windows")]
        {
            return acquire_windows_single_instance(WINDOWS_SINGLE_INSTANCE_MUTEX);
        }

        #[cfg(not(target_os = "windows"))]
        acquire_lock_dir()
    }
}

#[cfg(not(target_os = "windows"))]
fn acquire_lock_dir() -> anyhow::Result<SingleInstanceGuard> {
    let lock_dir = lock_root()?.join(LOCK_DIR_NAME);
    match create_lock(&lock_dir) {
        Ok(()) => Ok(SingleInstanceGuard { lock_dir }),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            if existing_process_is_alive(&lock_dir) || lock_dir_looks_fresh(&lock_dir) {
                anyhow::bail!("Windows App AutoLogin is already running");
            }

            std::fs::remove_dir_all(&lock_dir).ok();
            create_lock(&lock_dir)?;
            Ok(SingleInstanceGuard { lock_dir })
        }
        Err(e) => Err(e.into()),
    }
}

#[cfg(target_os = "windows")]
fn acquire_windows_single_instance(name: &str) -> anyhow::Result<SingleInstanceGuard> {
    let name = wide_null(name);
    let mutex = unsafe { CreateMutexW(None, false, PCWSTR(name.as_ptr()))? };
    if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        let _ = unsafe { CloseHandle(mutex) };
        anyhow::bail!("Windows App AutoLogin is already running");
    }

    Ok(SingleInstanceGuard { mutex })
}

#[cfg(target_os = "windows")]
fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(target_os = "windows")]
pub(crate) fn request_activation() -> anyhow::Result<()> {
    let path = activation_request_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        secure_dir_permissions(parent)?;
    }
    std::fs::write(path, std::process::id().to_string())?;
    Ok(())
}

pub(crate) fn request_monitor_command(command: MonitorControlCommand) -> anyhow::Result<()> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let body = format!("{}:{}:{nonce}\n", command.as_str(), std::process::id());
    write_private_text(&monitor_command_path()?, &body)
}

pub(crate) fn write_monitor_status(running: bool) -> anyhow::Result<()> {
    write_private_text(
        &monitor_status_path()?,
        if running { "running\n" } else { "idle\n" },
    )
}

pub(crate) fn read_monitor_status() -> Option<bool> {
    let status = std::fs::read_to_string(monitor_status_path().ok()?).ok()?;
    match status.trim() {
        "running" => Some(true),
        "idle" => Some(false),
        _ => None,
    }
}

impl MonitorCommandWatcher {
    pub(crate) fn new() -> Self {
        let path = monitor_command_path().ok();
        let last_content = path
            .as_deref()
            .and_then(|path| std::fs::read_to_string(path).ok());

        Self { path, last_content }
    }

    pub(crate) fn consume_command(&mut self) -> Option<MonitorControlCommand> {
        let path = self.path.as_deref()?;
        let content = std::fs::read_to_string(path).ok()?;
        if self.last_content.as_deref() == Some(content.as_str()) {
            return None;
        }

        self.last_content = Some(content.clone());
        MonitorControlCommand::from_request(&content)
    }

    #[cfg(test)]
    fn for_path(path: PathBuf) -> Self {
        let last_content = std::fs::read_to_string(&path).ok();
        Self {
            path: Some(path),
            last_content,
        }
    }
}

#[cfg(target_os = "windows")]
pub(crate) struct ActivationWatcher {
    path: Option<PathBuf>,
    last_modified: Option<SystemTime>,
}

#[cfg(target_os = "windows")]
impl ActivationWatcher {
    pub(crate) fn new() -> Self {
        let path = activation_request_path().ok();
        let last_modified = path.as_deref().and_then(file_modified_time);
        Self {
            path,
            last_modified,
        }
    }

    pub(crate) fn consume_activation_request(&mut self) -> bool {
        let Some(path) = self.path.as_deref() else {
            return false;
        };
        let Some(modified) = file_modified_time(path) else {
            return false;
        };
        if self.last_modified.is_none_or(|last| modified > last) {
            self.last_modified = Some(modified);
            return true;
        }
        false
    }

    #[cfg(test)]
    fn for_path(path: PathBuf) -> Self {
        Self {
            last_modified: file_modified_time(&path),
            path: Some(path),
        }
    }
}

impl Drop for SingleInstanceGuard {
    fn drop(&mut self) {
        #[cfg(target_os = "windows")]
        {
            let _ = unsafe { CloseHandle(self.mutex) };
        }
        #[cfg(not(target_os = "windows"))]
        {
            if lock_pid(&self.lock_dir) == Some(std::process::id()) {
                std::fs::remove_dir_all(&self.lock_dir).ok();
            }
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn create_lock(lock_dir: &Path) -> std::io::Result<()> {
    if let Some(parent) = lock_dir.parent() {
        std::fs::create_dir_all(parent)?;
        secure_dir_permissions(parent)?;
    }
    std::fs::create_dir(lock_dir)?;
    secure_dir_permissions(lock_dir)?;
    write_private_file(
        &lock_dir.join("pid"),
        std::process::id().to_string().as_bytes(),
    )?;
    Ok(())
}

fn lock_root() -> anyhow::Result<PathBuf> {
    if let Some(cache_dir) = dirs::cache_dir() {
        return Ok(cache_dir.join("WindowsAppAutoLogin"));
    }
    if let Some(home) = dirs::home_dir() {
        return Ok(home
            .join("Library")
            .join("Caches")
            .join("WindowsAppAutoLogin"));
    }
    anyhow::bail!("unable to resolve a private lock directory")
}

fn monitor_command_path() -> anyhow::Result<PathBuf> {
    Ok(lock_root()?.join(MONITOR_COMMAND_FILE_NAME))
}

fn monitor_status_path() -> anyhow::Result<PathBuf> {
    Ok(lock_root()?.join(MONITOR_STATUS_FILE_NAME))
}

#[cfg(target_os = "windows")]
fn activation_request_path() -> anyhow::Result<PathBuf> {
    Ok(lock_root()?.join(ACTIVATION_FILE_NAME))
}

#[cfg(target_os = "windows")]
fn file_modified_time(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .ok()
}

#[cfg(not(target_os = "windows"))]
fn existing_process_is_alive(lock_dir: &Path) -> bool {
    let Some(pid) = lock_pid(lock_dir) else {
        return false;
    };

    pid == std::process::id() || process_looks_like_this_app(pid)
}

#[cfg(not(target_os = "windows"))]
fn lock_dir_looks_fresh(lock_dir: &Path) -> bool {
    const STARTUP_RACE_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

    lock_pid(lock_dir).is_none()
        && std::fs::metadata(lock_dir)
            .and_then(|metadata| metadata.modified())
            .ok()
            .and_then(|modified| modified.elapsed().ok())
            .is_some_and(|age| age <= STARTUP_RACE_GRACE)
}

#[cfg(unix)]
fn process_looks_like_this_app(pid: u32) -> bool {
    let Ok(output) = std::process::Command::new("/bin/ps")
        .args(["-p", &pid.to_string(), "-o", "command="])
        .output()
    else {
        return false;
    };
    if !output.status.success() {
        return false;
    }

    let command = String::from_utf8_lossy(&output.stdout);
    let current_exe = std::env::current_exe()
        .ok()
        .and_then(|path| path.canonicalize().ok())
        .map(|path| path.to_string_lossy().to_string());

    current_exe.is_some_and(|path| {
        let command = command.trim();
        command == path || command.starts_with(&(path + " "))
    })
}

#[cfg(all(not(unix), not(target_os = "windows")))]
fn process_looks_like_this_app(_pid: u32) -> bool {
    false
}

#[cfg(not(target_os = "windows"))]
fn lock_pid(lock_dir: &Path) -> Option<u32> {
    std::fs::read_to_string(lock_dir.join("pid"))
        .ok()
        .and_then(|pid| pid.trim().parse::<u32>().ok())
}

#[cfg(unix)]
fn secure_dir_permissions(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = std::fs::metadata(path)?.permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(path, permissions)
}

#[cfg(not(unix))]
fn secure_dir_permissions(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

fn write_private_text(path: &Path, content: &str) -> anyhow::Result<()> {
    use std::io::Write;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        secure_dir_permissions(parent)?;
    }

    let temp_path = path.with_extension("tmp");
    if temp_path.exists() {
        std::fs::remove_file(&temp_path)?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp_path)?;
        file.write_all(content.as_bytes())?;
        file.sync_all().ok();
    }

    #[cfg(not(unix))]
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)?;
        file.write_all(content.as_bytes())?;
        file.sync_all().ok();
    }

    if path.exists() {
        std::fs::remove_file(path)?;
    }
    std::fs::rename(temp_path, path)?;
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn write_private_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(bytes)?;
    }

    #[cfg(not(unix))]
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        file.write_all(bytes)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_named_mutex_blocks_second_acquire() {
        let name = format!(
            "Local\\WindowsAppAutoLogin.SingleInstance.Test.{}",
            std::process::id()
        );
        let guard = acquire_windows_single_instance(&name).unwrap();
        let Err(error) = acquire_windows_single_instance(&name) else {
            panic!("second named mutex acquire succeeded");
        };

        assert!(error.to_string().contains("already running"));
        drop(guard);
        assert!(acquire_windows_single_instance(&name).is_ok());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn activation_watcher_consumes_new_request_once() {
        let path = std::env::temp_dir().join(format!(
            "windows-app-autologin-activation-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let mut watcher = ActivationWatcher::for_path(path.clone());

        assert!(!watcher.consume_activation_request());
        std::fs::write(&path, "activate").unwrap();
        assert!(watcher.consume_activation_request());
        assert!(!watcher.consume_activation_request());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn monitor_command_watcher_consumes_new_commands_once() {
        let path = std::env::temp_dir().join(format!(
            "windows-app-autologin-monitor-command-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let mut watcher = MonitorCommandWatcher::for_path(path.clone());

        assert_eq!(watcher.consume_command(), None);
        std::fs::write(&path, "start_monitor:123:1").unwrap();
        assert_eq!(
            watcher.consume_command(),
            Some(MonitorControlCommand::Start)
        );
        assert_eq!(watcher.consume_command(), None);

        std::fs::write(&path, "stop_monitor:123:2").unwrap();
        assert_eq!(watcher.consume_command(), Some(MonitorControlCommand::Stop));

        let _ = std::fs::remove_file(path);
    }
}
