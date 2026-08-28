use crate::models::MonitorControlState;
use std::path::{Path, PathBuf};
#[cfg(any(target_os = "macos", target_os = "windows"))]
use std::time::{Duration, Instant};
use std::time::{SystemTime, UNIX_EPOCH};
#[cfg(target_os = "macos")]
use std::{
    io::{Read, Write},
    net::Shutdown,
    os::fd::AsRawFd,
    os::unix::net::{UnixListener, UnixStream},
    sync::OnceLock,
};
#[cfg(target_os = "windows")]
use windows::core::{BOOL, PCWSTR, PWSTR};
#[cfg(target_os = "windows")]
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_BROKEN_PIPE, ERROR_FILE_NOT_FOUND,
    ERROR_LOCK_VIOLATION, ERROR_NO_DATA, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED,
    ERROR_PIPE_LISTENING, ERROR_SHARING_VIOLATION, GENERIC_READ, GENERIC_WRITE, HANDLE, HLOCAL,
    INVALID_HANDLE_VALUE,
};
#[cfg(target_os = "windows")]
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
#[cfg(target_os = "windows")]
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
#[cfg(target_os = "windows")]
use windows::Win32::Storage::FileSystem::{
    CreateFileW, LockFileEx, ReadFile, WriteFile, FILE_ATTRIBUTE_NORMAL,
    FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ,
    FILE_GENERIC_WRITE, FILE_SHARE_DELETE, FILE_SHARE_MODE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, OPEN_ALWAYS, OPEN_EXISTING,
    PIPE_ACCESS_DUPLEX,
};
#[cfg(target_os = "windows")]
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    GetNamedPipeServerProcessId, SetNamedPipeHandleState, WaitNamedPipeW, NAMED_PIPE_MODE,
    PIPE_NOWAIT, PIPE_READMODE_MESSAGE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_MESSAGE,
};
#[cfg(target_os = "windows")]
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};
#[cfg(target_os = "windows")]
use windows::Win32::System::IO::OVERLAPPED;

#[cfg(not(target_os = "windows"))]
const LOCK_DIR_NAME: &str = "WindowsAppAutoLogin.lock";
#[cfg(any(target_os = "macos", target_os = "windows"))]
const FULL_UI_LOCK_DIR_NAME: &str = "WindowsAppAutoLogin.full-ui.lock";
const SETTINGS_SESSION_LOCK_FILE_NAME: &str = "settings-session.lock";
const MAX_SETTINGS_SESSION_TOKEN_BYTES: u64 = 64;
#[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
const ACTIVATION_FILE_NAME: &str = "activate";
#[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
const MONITOR_COMMAND_FILE_NAME: &str = "monitor-command";
const MONITOR_STATUS_FILE_NAME: &str = "monitor-status";
#[cfg(not(target_os = "windows"))]
const LOCK_OWNER_FILE_NAME: &str = "owner";
const MONITOR_COMMAND_START: &str = "start_monitor";
const MONITOR_COMMAND_STOP: &str = "stop_monitor";
const MONITOR_COMMAND_STORAGE_RECOVERY_BLOCKED: &str = "storage_recovery_blocked";
#[cfg(not(target_os = "macos"))]
const MONITOR_COMMAND_RELOAD_CONFIG: &str = "reload_config";
const ALREADY_RUNNING_MESSAGE: &str = "Windows App AutoLogin is already running";
#[cfg(any(target_os = "macos", target_os = "windows"))]
const FULL_UI_ALREADY_RUNNING_MESSAGE: &str = "Windows App AutoLogin window is already open";
#[cfg(not(target_os = "windows"))]
const MAX_LOCK_OWNER_BYTES: u64 = 256;
#[cfg(not(target_os = "windows"))]
const MAX_LOCK_PID_BYTES: u64 = 32;
const MAX_MONITOR_STATUS_BYTES: u64 = 32;
#[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
const MAX_MONITOR_COMMAND_BYTES: u64 = 256;
#[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
const MAX_ACTIVATION_REQUEST_BYTES: u64 = 4096;
#[cfg(target_os = "windows")]
const WINDOWS_LOCAL_IPC_PIPE_PREFIX: &str = r"\\.\pipe\WindowsAppAutoLogin.LocalIpc.";
#[cfg(target_os = "windows")]
const WINDOWS_LOCAL_IPC_MAX_BYTES: usize = 128;
#[cfg(target_os = "windows")]
const WINDOWS_LOCAL_IPC_CONNECT_TIMEOUT_MS: u32 = 750;
#[cfg(target_os = "macos")]
const IPC_SOCKET_FILE_NAME: &str = "ipc.sock";
#[cfg(target_os = "macos")]
const MACOS_LOCAL_IPC_MAX_BYTES: usize = 128;
#[cfg(target_os = "macos")]
const MAX_IPC_COMMANDS_PER_TICK: usize = 16;
#[cfg(any(target_os = "macos", target_os = "windows"))]
const IPC_COMMAND_ACTIVATE: &str = "activate";
#[cfg(any(target_os = "macos", target_os = "windows"))]
const IPC_COMMAND_SETTINGS_BOOTSTRAP: &str = "settings:bootstrap";
#[cfg(any(target_os = "macos", target_os = "windows"))]
const IPC_COMMAND_SETTINGS_MUTATION_BEGIN: &str = "settings:mutation:begin";
#[cfg(any(target_os = "macos", target_os = "windows"))]
const IPC_COMMAND_SETTINGS_MUTATION_CANCEL: &str = "settings:mutation:cancel";
#[cfg(any(target_os = "macos", target_os = "windows"))]
const IPC_COMMAND_MONITOR_PREFIX: &str = "monitor:";
#[cfg(any(target_os = "macos", target_os = "windows"))]
const IPC_COMMAND_RELOAD_CONFIG: &str = "config:reload";
#[cfg(any(target_os = "macos", target_os = "windows"))]
const SETTINGS_BOOTSTRAP_MAX_ATTEMPTS: usize = 4;
#[cfg(any(target_os = "macos", target_os = "windows"))]
const SETTINGS_BOOTSTRAP_RETRY_INTERVAL: Duration = Duration::from_millis(50);
#[cfg(any(target_os = "macos", target_os = "windows"))]
const SETTINGS_MUTATION_ACK_TIMEOUT: Duration = Duration::from_secs(20);
#[cfg(target_os = "windows")]
const WINDOWS_SINGLE_INSTANCE_LOCK_FILE_NAME: &str = "single-instance.lock";
#[cfg(target_os = "macos")]
static CURRENT_EXECUTABLE_PATH: OnceLock<Option<PathBuf>> = OnceLock::new();
#[cfg(target_os = "macos")]
static CURRENT_CODE_UNIQUE_IDENTIFIER: OnceLock<Option<Vec<u8>>> = OnceLock::new();

pub(crate) struct SingleInstanceGuard {
    #[cfg(target_os = "windows")]
    ipc_server: Option<LocalIpcServer>,
    #[cfg(target_os = "windows")]
    _lock_file: std::fs::File,
    #[cfg(not(target_os = "windows"))]
    lock_dir: PathBuf,
    #[cfg(not(target_os = "windows"))]
    lock_nonce: String,
    #[cfg(all(unix, not(target_os = "windows")))]
    _lock_file: std::fs::File,
    #[cfg(target_os = "macos")]
    ipc_server: Option<LocalIpcServer>,
}

#[cfg(target_os = "macos")]
pub(crate) struct FullUiInstanceGuard {
    lock_dir: PathBuf,
    lock_nonce: String,
    _lock_file: std::fs::File,
}

#[cfg(target_os = "windows")]
pub(crate) struct FullUiInstanceGuard {
    _lock_file: std::fs::File,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct SettingsSessionToken(String);

pub(crate) struct SettingsSessionLease {
    _lock_file: std::fs::File,
}

pub(crate) struct SettingsRecoveryLease {
    lock_file: std::fs::File,
}

pub(crate) struct LocalIpcServer {
    #[cfg(target_os = "macos")]
    listener: UnixListener,
    #[cfg(target_os = "macos")]
    path: PathBuf,
    #[cfg(target_os = "macos")]
    socket_identity: LocalIpcSocketIdentity,
    #[cfg(target_os = "windows")]
    pipe_name: String,
    #[cfg(target_os = "windows")]
    pipe: Option<WindowsPipeHandle>,
    #[cfg(target_os = "windows")]
    connected: bool,
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LocalIpcCommand {
    Activate,
    SettingsBootstrap,
    SettingsMutationBegin,
    SettingsMutationCancel,
    ReloadConfig,
    Monitor(MonitorControlCommand),
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
#[derive(Debug)]
pub(crate) struct PeerLocalIpcCommand {
    pub(crate) peer_pid: u32,
    pub(crate) command: LocalIpcCommand,
    #[cfg(target_os = "macos")]
    acknowledgement: Option<UnixStream>,
    #[cfg(target_os = "windows")]
    acknowledgement: Option<WindowsPipeHandle>,
}

#[cfg(target_os = "macos")]
impl PeerLocalIpcCommand {
    pub(crate) fn acknowledge(mut self) -> anyhow::Result<()> {
        let mut stream = self
            .acknowledgement
            .take()
            .ok_or_else(|| anyhow::anyhow!("macOS local IPC acknowledgement stream is missing"))?;
        stream.write_all(b"ok\n")?;
        stream.shutdown(Shutdown::Write)?;
        Ok(())
    }
}

#[cfg(target_os = "windows")]
impl PeerLocalIpcCommand {
    pub(crate) fn acknowledge(mut self) -> anyhow::Result<()> {
        let pipe = self.acknowledgement.take().ok_or_else(|| {
            anyhow::anyhow!("Windows local IPC acknowledgement handle is missing")
        })?;
        write_windows_local_ipc_ack(pipe.0)
    }
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LocalIpcSocketIdentity {
    dev: u64,
    ino: u64,
    uid: u32,
}

#[cfg(target_os = "windows")]
#[derive(Debug)]
struct WindowsPipeHandle(HANDLE);

#[cfg(target_os = "windows")]
impl Drop for WindowsPipeHandle {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.0) };
    }
}

#[cfg(target_os = "windows")]
struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

#[cfg(target_os = "windows")]
impl Drop for LocalSecurityDescriptor {
    fn drop(&mut self) {
        let _ = unsafe { LocalFree(Some(HLOCAL(self.0 .0))) };
    }
}

#[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
pub(crate) struct FullUiInstanceGuard;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MonitorControlCommand {
    Start,
    Stop,
    StorageRecoveryBlocked,
    #[cfg(not(target_os = "macos"))]
    ReloadConfig,
}

impl MonitorControlCommand {
    fn as_str(self) -> &'static str {
        match self {
            Self::Start => MONITOR_COMMAND_START,
            Self::Stop => MONITOR_COMMAND_STOP,
            Self::StorageRecoveryBlocked => MONITOR_COMMAND_STORAGE_RECOVERY_BLOCKED,
            #[cfg(not(target_os = "macos"))]
            Self::ReloadConfig => MONITOR_COMMAND_RELOAD_CONFIG,
        }
    }

    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    fn from_request(value: &str) -> Option<Self> {
        Self::from_legacy_request(value)
    }

    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    fn from_legacy_request(value: &str) -> Option<Self> {
        if value.len() > MAX_MONITOR_COMMAND_BYTES as usize {
            return None;
        }
        let mut parts = value.trim().split(':');
        let command = parts.next()?.trim();
        let pid = parts.next().and_then(|pid| parse_pid_field(pid.trim()))?;
        parse_request_nonce(parts.next()?.trim())?;
        if parts.next().is_some() {
            return None;
        }
        if !process_looks_like_this_app(pid) {
            return None;
        }
        Self::from_command_name(command)
    }

    fn from_command_name(command: &str) -> Option<Self> {
        match command {
            MONITOR_COMMAND_START => Some(Self::Start),
            MONITOR_COMMAND_STOP => Some(Self::Stop),
            MONITOR_COMMAND_STORAGE_RECOVERY_BLOCKED => Some(Self::StorageRecoveryBlocked),
            #[cfg(not(target_os = "macos"))]
            MONITOR_COMMAND_RELOAD_CONFIG => Some(Self::ReloadConfig),
            _ => None,
        }
    }
}

#[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
pub(crate) struct MonitorCommandWatcher {
    path: Option<PathBuf>,
    last_content: Option<String>,
}

pub(crate) fn is_already_running_error(error: &anyhow::Error) -> bool {
    let message = error.to_string();
    message == ALREADY_RUNNING_MESSAGE || {
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        {
            message == FULL_UI_ALREADY_RUNNING_MESSAGE
        }
        #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
        {
            false
        }
    }
}

impl SingleInstanceGuard {
    pub(crate) fn acquire() -> anyhow::Result<Self> {
        #[cfg(target_os = "windows")]
        {
            acquire_windows_single_instance()
        }

        #[cfg(not(target_os = "windows"))]
        acquire_lock_dir()
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    pub(crate) fn take_ipc_server(&mut self) -> Option<LocalIpcServer> {
        self.ipc_server.take()
    }
}

impl FullUiInstanceGuard {
    pub(crate) fn acquire() -> anyhow::Result<Self> {
        #[cfg(target_os = "macos")]
        {
            let (lock_dir, lock_file) =
                acquire_lock_dir_named(FULL_UI_LOCK_DIR_NAME, FULL_UI_ALREADY_RUNNING_MESSAGE)?;
            Ok(Self {
                lock_nonce: lock_owner(&lock_dir)
                    .map(|owner| owner.nonce)
                    .unwrap_or_default(),
                _lock_file: lock_file,
                lock_dir,
            })
        }

        #[cfg(target_os = "windows")]
        {
            let root = lock_root()?;
            prepare_lock_root(&root)?;
            Ok(Self {
                _lock_file: acquire_windows_named_file_lock(
                    &root,
                    FULL_UI_LOCK_DIR_NAME,
                    FULL_UI_ALREADY_RUNNING_MESSAGE,
                )?,
            })
        }

        #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
        Ok(Self)
    }
}

impl SettingsSessionToken {
    pub(crate) fn generate() -> Self {
        Self(random_nonce())
    }

    pub(crate) fn parse(value: &str) -> anyhow::Result<Self> {
        let value = value.trim();
        if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            anyhow::bail!("invalid settings session token");
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl SettingsRecoveryLease {
    pub(crate) fn try_acquire() -> anyhow::Result<Option<Self>> {
        try_acquire_settings_recovery_lease_in_root(&lock_root()?)
    }

    #[cfg(test)]
    pub(crate) fn try_acquire_in_root(root: &Path) -> anyhow::Result<Option<Self>> {
        try_acquire_settings_recovery_lease_in_root(root)
    }

    pub(crate) fn establish_session(&mut self, token: &SettingsSessionToken) -> anyhow::Result<()> {
        write_settings_session_token(&mut self.lock_file, token)
    }
}

impl SettingsSessionLease {
    pub(crate) fn acquire(token: &SettingsSessionToken) -> anyhow::Result<Self> {
        acquire_settings_session_lease_in_root(&lock_root()?, token)
    }

    #[cfg(test)]
    pub(crate) fn acquire_in_root(
        root: &Path,
        token: &SettingsSessionToken,
    ) -> anyhow::Result<Self> {
        acquire_settings_session_lease_in_root(root, token)
    }
}

#[cfg(not(target_os = "windows"))]
fn acquire_lock_dir() -> anyhow::Result<SingleInstanceGuard> {
    let (lock_dir, lock_file) = acquire_lock_dir_named(LOCK_DIR_NAME, ALREADY_RUNNING_MESSAGE)?;

    #[cfg(target_os = "macos")]
    {
        let lock_nonce = lock_owner(&lock_dir)
            .map(|owner| owner.nonce)
            .unwrap_or_default();
        let ipc_server = match LocalIpcServer::bind() {
            Ok(server) => Some(server),
            Err(e) => {
                remove_current_process_lock(&lock_dir, &lock_nonce);
                return Err(e);
            }
        };
        Ok(SingleInstanceGuard {
            lock_dir,
            lock_nonce,
            _lock_file: lock_file,
            ipc_server,
        })
    }

    #[cfg(not(target_os = "macos"))]
    Ok(SingleInstanceGuard {
        lock_nonce: lock_owner(&lock_dir)
            .map(|owner| owner.nonce)
            .unwrap_or_default(),
        _lock_file: lock_file,
        lock_dir,
    })
}

#[cfg(not(target_os = "windows"))]
fn acquire_lock_dir_named(
    lock_dir_name: &str,
    already_running_message: &str,
) -> anyhow::Result<(PathBuf, std::fs::File)> {
    let root = lock_root()?;
    prepare_lock_root(&root)?;
    let lock_file = acquire_named_file_lock(&root, lock_dir_name, already_running_message)?;
    let lock_dir = acquire_lock_dir_in_root(&root, lock_dir_name, already_running_message)?;
    Ok((lock_dir, lock_file))
}

#[cfg(all(unix, not(target_os = "windows")))]
fn acquire_named_file_lock(
    root: &Path,
    lock_dir_name: &str,
    already_running_message: &str,
) -> anyhow::Result<std::fs::File> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;

    let path = root.join(format!("{lock_dir_name}.held"));
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)?;
    secure_file_permissions(&path, 0o600)?;
    let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if ret != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EWOULDBLOCK)
            || error.raw_os_error() == Some(libc::EAGAIN)
        {
            anyhow::bail!("{}", already_running_message);
        }
        return Err(error.into());
    }
    Ok(file)
}

#[cfg(not(target_os = "windows"))]
fn acquire_lock_dir_in_root(
    root: &Path,
    lock_dir_name: &str,
    already_running_message: &str,
) -> anyhow::Result<PathBuf> {
    prepare_lock_root(root)?;
    let lock_dir = root.join(lock_dir_name);
    match create_lock(&lock_dir) {
        Ok(()) => Ok(lock_dir),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            if existing_process_is_alive(&lock_dir) || lock_dir_looks_fresh(&lock_dir) {
                anyhow::bail!("{}", already_running_message);
            }

            remove_stale_lock_dir(&lock_dir)?;
            create_lock(&lock_dir)?;
            Ok(lock_dir)
        }
        Err(e) => Err(e.into()),
    }
}

fn prepare_lock_root(root: &Path) -> std::io::Result<()> {
    secure_lock_root_parent_if_app_runtime(root)?;
    match std::fs::symlink_metadata(root) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "lock root must not be a symlink",
            ));
        }
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "lock root must be a directory",
            ));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    std::fs::create_dir_all(root)?;
    secure_dir_permissions(root)
}

fn try_acquire_settings_recovery_lease_in_root(
    root: &Path,
) -> anyhow::Result<Option<SettingsRecoveryLease>> {
    let lock_file = open_settings_session_lock_file_in_root(root)?;
    match lock_file.try_lock() {
        Ok(()) => Ok(Some(SettingsRecoveryLease { lock_file })),
        Err(std::fs::TryLockError::WouldBlock) => Ok(None),
        Err(std::fs::TryLockError::Error(error)) => Err(error.into()),
    }
}

fn acquire_settings_session_lease_in_root(
    root: &Path,
    token: &SettingsSessionToken,
) -> anyhow::Result<SettingsSessionLease> {
    let mut lock_file = open_settings_session_lock_file_in_root(root)?;
    match lock_file.try_lock_shared() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => {
            anyhow::bail!("password storage recovery is in progress")
        }
        Err(std::fs::TryLockError::Error(error)) => return Err(error.into()),
    }

    let established = read_settings_session_token(&mut lock_file)?;
    if established.as_ref() != Some(token) {
        anyhow::bail!("settings session is no longer authorized");
    }

    Ok(SettingsSessionLease {
        _lock_file: lock_file,
    })
}

fn write_settings_session_token(
    lock_file: &mut std::fs::File,
    token: &SettingsSessionToken,
) -> anyhow::Result<()> {
    use std::io::{Seek, Write};

    lock_file.set_len(0)?;
    lock_file.seek(std::io::SeekFrom::Start(0))?;
    lock_file.write_all(token.as_str().as_bytes())?;
    lock_file.write_all(b"\n")?;
    lock_file.flush()?;
    lock_file.sync_data()?;
    Ok(())
}

fn read_settings_session_token(
    lock_file: &mut std::fs::File,
) -> anyhow::Result<Option<SettingsSessionToken>> {
    use std::io::{Read, Seek};

    let length = lock_file.metadata()?.len();
    if length == 0 || length > MAX_SETTINGS_SESSION_TOKEN_BYTES {
        return Ok(None);
    }
    lock_file.seek(std::io::SeekFrom::Start(0))?;
    let mut bytes = Vec::with_capacity(length as usize);
    lock_file
        .take(MAX_SETTINGS_SESSION_TOKEN_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_SETTINGS_SESSION_TOKEN_BYTES {
        return Ok(None);
    }
    let value = std::str::from_utf8(&bytes)?;
    Ok(SettingsSessionToken::parse(value).ok())
}

#[cfg(unix)]
fn open_settings_session_lock_file_in_root(root: &Path) -> anyhow::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    prepare_lock_root(root)?;
    let lock_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(root.join(SETTINGS_SESSION_LOCK_FILE_NAME))?;
    secure_file_handle_permissions(&lock_file, 0o600)?;
    Ok(lock_file)
}

#[cfg(target_os = "windows")]
fn open_settings_session_lock_file_in_root(root: &Path) -> anyhow::Result<std::fs::File> {
    prepare_lock_root(root)?;
    open_windows_private_lock_file(
        &root.join(SETTINGS_SESSION_LOCK_FILE_NAME),
        "settings session lock",
    )
}

#[cfg(not(any(unix, target_os = "windows")))]
fn open_settings_session_lock_file_in_root(root: &Path) -> anyhow::Result<std::fs::File> {
    prepare_lock_root(root)?;
    let path = root.join(SETTINGS_SESSION_LOCK_FILE_NAME);
    let lock_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&path)?;
    secure_file_permissions(&path, 0o600)?;
    Ok(lock_file)
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn secure_lock_root_parent_if_app_runtime(root: &Path) -> std::io::Result<()> {
    if crate::user_paths::runtime_dir().ok().as_deref() != Some(root) {
        return Ok(());
    }
    if let Some(parent) = root.parent() {
        std::fs::create_dir_all(parent)?;
        secure_dir_permissions(parent)?;
    }
    Ok(())
}

#[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
fn secure_lock_root_parent_if_app_runtime(_root: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(target_os = "windows")]
fn acquire_windows_single_instance() -> anyhow::Result<SingleInstanceGuard> {
    let root = lock_root()?;
    prepare_lock_root(&root)?;
    let lock_file = acquire_windows_single_instance_file_lock(&root)?;

    let ipc_server = LocalIpcServer::bind()?;

    Ok(SingleInstanceGuard {
        ipc_server: Some(ipc_server),
        _lock_file: lock_file,
    })
}

#[cfg(target_os = "windows")]
fn acquire_windows_single_instance_file_lock(root: &Path) -> anyhow::Result<std::fs::File> {
    acquire_windows_named_file_lock(
        root,
        WINDOWS_SINGLE_INSTANCE_LOCK_FILE_NAME,
        ALREADY_RUNNING_MESSAGE,
    )
}

#[cfg(target_os = "windows")]
fn acquire_windows_named_file_lock(
    root: &Path,
    file_name: &str,
    already_running_message: &str,
) -> anyhow::Result<std::fs::File> {
    let file = open_windows_private_lock_file(&root.join(file_name), "instance lock")?;

    use std::os::windows::io::AsRawHandle;

    let mut overlapped = OVERLAPPED::default();
    let lock_result = unsafe {
        LockFileEx(
            HANDLE(file.as_raw_handle()),
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            None,
            1,
            0,
            &mut overlapped,
        )
    };
    match lock_result {
        Ok(()) => Ok(file),
        Err(error) => {
            let last_error = unsafe { GetLastError() };
            if last_error == ERROR_LOCK_VIOLATION || last_error == ERROR_SHARING_VIOLATION {
                anyhow::bail!("{}", already_running_message);
            }
            Err(anyhow::anyhow!(
                "failed to lock Windows instance file: {error}"
            ))
        }
    }
}

#[cfg(target_os = "windows")]
fn open_windows_private_lock_file(path: &Path, label: &str) -> anyhow::Result<std::fs::File> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;

    let wide_path = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    if wide_path[..wide_path.len().saturating_sub(1)].contains(&0) {
        anyhow::bail!("Windows {label} path contains an interior NUL byte");
    }

    let security_descriptor = windows_local_ipc_security_descriptor()?;
    let security_attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: security_descriptor.0 .0,
        bInheritHandle: BOOL(0),
    };
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide_path.as_ptr()),
            (FILE_GENERIC_READ | FILE_GENERIC_WRITE).0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            Some(std::ptr::addr_of!(security_attributes)),
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map_err(|error| anyhow::anyhow!("failed to open Windows {label} file: {error}"))?;
    let file = unsafe { std::fs::File::from_raw_handle(handle.0) };

    secure_file_permissions(path, 0o600)?;
    crate::private_permissions::validate_windows_private_file_handle(&file)
        .map_err(|error| anyhow::anyhow!("Windows {label} file is not private: {error}"))?;
    Ok(file)
}

#[cfg(target_os = "windows")]
fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

pub(crate) fn request_activation() -> anyhow::Result<()> {
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    {
        send_local_ipc_command(IPC_COMMAND_ACTIVATE)
    }

    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    {
        let path = activation_request_path()?;
        let current_exe = std::env::current_exe()
            .map(|path| path.to_string_lossy().to_string())
            .unwrap_or_default();
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        write_private_text(
            &path,
            &format!("{}:{nonce}:{current_exe}\n", std::process::id()),
        )
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
pub(crate) fn request_settings_bootstrap() -> anyhow::Result<()> {
    request_settings_bootstrap_with_retry(
        || send_local_ipc_command(IPC_COMMAND_SETTINGS_BOOTSTRAP),
        || std::thread::sleep(SETTINGS_BOOTSTRAP_RETRY_INTERVAL),
    )
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
pub(crate) fn request_settings_mutation_begin() -> anyhow::Result<()> {
    send_local_ipc_command_with_ack_timeout(
        IPC_COMMAND_SETTINGS_MUTATION_BEGIN,
        SETTINGS_MUTATION_ACK_TIMEOUT,
    )
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
pub(crate) fn request_settings_mutation_cancel() -> anyhow::Result<()> {
    send_local_ipc_command(IPC_COMMAND_SETTINGS_MUTATION_CANCEL)
}

#[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
pub(crate) fn request_settings_mutation_cancel() -> anyhow::Result<()> {
    Ok(())
}

#[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
pub(crate) fn request_settings_mutation_begin() -> anyhow::Result<()> {
    Ok(())
}

#[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
pub(crate) fn request_settings_bootstrap() -> anyhow::Result<()> {
    anyhow::bail!("settings bootstrap requires authenticated local IPC")
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn request_settings_bootstrap_with_retry(
    mut request: impl FnMut() -> anyhow::Result<()>,
    mut wait_before_retry: impl FnMut(),
) -> anyhow::Result<()> {
    let mut last_error = None;
    for attempt in 0..SETTINGS_BOOTSTRAP_MAX_ATTEMPTS {
        match request() {
            Ok(()) => return Ok(()),
            Err(error) => last_error = Some(error.to_string()),
        }
        if attempt + 1 < SETTINGS_BOOTSTRAP_MAX_ATTEMPTS {
            wait_before_retry();
        }
    }

    anyhow::bail!(
        "settings bootstrap was not acknowledged by the supervisor after {} attempts: {}",
        SETTINGS_BOOTSTRAP_MAX_ATTEMPTS,
        last_error.as_deref().unwrap_or("local IPC is unavailable")
    )
}

pub(crate) fn request_monitor_command(command: MonitorControlCommand) -> anyhow::Result<()> {
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    {
        send_local_ipc_command(&format!("{IPC_COMMAND_MONITOR_PREFIX}{}", command.as_str()))
    }

    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let body = format!("{}:{}:{nonce}\n", command.as_str(), std::process::id());
        write_private_text(&monitor_command_path()?, &body)
    }
}

pub(crate) fn request_config_reload() -> anyhow::Result<()> {
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    {
        send_local_ipc_command(IPC_COMMAND_RELOAD_CONFIG)
    }

    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    {
        request_monitor_command(MonitorControlCommand::ReloadConfig)
    }
}

pub(crate) fn write_monitor_status(running: bool) -> anyhow::Result<()> {
    write_monitor_control_state(if running {
        MonitorControlState::Running
    } else {
        MonitorControlState::Stopped
    })
}

pub(crate) fn write_monitor_control_state(state: MonitorControlState) -> anyhow::Result<()> {
    write_private_text(&monitor_status_path()?, monitor_control_state_status(state))
}

fn monitor_control_state_status(state: MonitorControlState) -> &'static str {
    match state {
        MonitorControlState::Running => "running\nstop\n",
        MonitorControlState::PausedWithStartIntent => "idle\nstop\n",
        MonitorControlState::Stopped => "idle\nstart\n",
    }
}

pub(crate) fn read_monitor_control_state() -> Option<MonitorControlState> {
    let status = read_private_text_limited(&monitor_status_path().ok()?, MAX_MONITOR_STATUS_BYTES)
        .ok()
        .flatten()?;
    parse_monitor_control_state(&status)
}

fn parse_monitor_control_state(status: &str) -> Option<MonitorControlState> {
    if status.len() > MAX_MONITOR_STATUS_BYTES as usize {
        return None;
    }
    match status {
        // Accept one-line snapshots written by older builds. New writes always
        // include the second line so the settings child can distinguish a
        // deliberate stop from the credential-window safety pause.
        "running\n" | "running\nstop\n" => Some(MonitorControlState::Running),
        "idle\nstop\n" => Some(MonitorControlState::PausedWithStartIntent),
        "idle\n" | "idle\nstart\n" => Some(MonitorControlState::Stopped),
        _ => None,
    }
}

#[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
impl MonitorCommandWatcher {
    pub(crate) fn new() -> Self {
        let path = monitor_command_path().ok();
        let last_content = path
            .as_deref()
            .and_then(|path| read_private_text_limited(path, MAX_MONITOR_COMMAND_BYTES).ok())
            .flatten();

        Self { path, last_content }
    }

    pub(crate) fn consume_command(&mut self) -> Option<MonitorControlCommand> {
        let path = self.path.as_deref()?;
        let content = read_private_text_limited(path, MAX_MONITOR_COMMAND_BYTES)
            .ok()
            .flatten()?;
        if self.last_content.as_deref() == Some(content.as_str()) {
            return None;
        }

        self.last_content = Some(content.clone());
        MonitorControlCommand::from_request(&content)
    }

    #[cfg(test)]
    fn for_path(path: PathBuf) -> Self {
        let last_content = read_private_text_limited(&path, MAX_MONITOR_COMMAND_BYTES)
            .ok()
            .flatten();
        Self {
            path: Some(path),
            last_content,
        }
    }
}

#[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
pub(crate) struct ActivationWatcher {
    path: Option<PathBuf>,
    last_modified: Option<SystemTime>,
    last_content: Option<String>,
}

#[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
impl ActivationWatcher {
    pub(crate) fn new() -> Self {
        let path = activation_request_path().ok();
        let last_modified = path.as_deref().and_then(file_modified_time);
        let last_content = path
            .as_deref()
            .and_then(|path| read_private_text_limited(path, MAX_ACTIVATION_REQUEST_BYTES).ok())
            .flatten();
        Self {
            path,
            last_modified,
            last_content,
        }
    }

    pub(crate) fn consume_activation_request(&mut self) -> bool {
        let Some(path) = self.path.as_deref() else {
            return false;
        };
        let Some(modified) = file_modified_time(path) else {
            return false;
        };
        let content = read_private_text_limited(path, MAX_ACTIVATION_REQUEST_BYTES)
            .ok()
            .flatten();
        if self.last_modified.is_none_or(|last| modified > last)
            || (content.is_some() && content != self.last_content)
        {
            let valid_request = content.as_deref().is_some_and(activation_request_is_valid);
            self.last_modified = Some(modified);
            self.last_content = content;
            return valid_request;
        }
        false
    }

    #[cfg(test)]
    fn for_path(path: PathBuf) -> Self {
        Self {
            last_modified: file_modified_time(&path),
            last_content: read_private_text_limited(&path, MAX_ACTIVATION_REQUEST_BYTES)
                .ok()
                .flatten(),
            path: Some(path),
        }
    }
}

#[cfg(target_os = "macos")]
impl LocalIpcServer {
    fn bind() -> anyhow::Result<Self> {
        if !process_looks_like_this_app(std::process::id()) {
            anyhow::bail!("current app identity is unavailable for local IPC");
        }

        let path = ipc_socket_path()?;
        if let Some(parent) = path.parent() {
            prepare_lock_root(parent)?;
        }
        remove_stale_ipc_path(&path)?;

        let listener = UnixListener::bind(&path)?;
        listener.set_nonblocking(true)?;
        secure_socket_permissions(&path)?;
        let socket_identity = local_ipc_socket_identity(&path)?;
        Ok(Self {
            listener,
            path,
            socket_identity,
        })
    }

    pub(crate) fn consume_commands(&self) -> Vec<PeerLocalIpcCommand> {
        let mut commands = Vec::new();
        for _ in 0..MAX_IPC_COMMANDS_PER_TICK {
            match self.listener.accept() {
                Ok((stream, _addr)) => {
                    if let Ok(Some(command)) = local_ipc_command_from_stream(stream) {
                        commands.push(command);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
        commands
    }
}

#[cfg(target_os = "macos")]
impl Drop for LocalIpcServer {
    fn drop(&mut self) {
        if local_ipc_socket_identity(&self.path).ok() == Some(self.socket_identity) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(target_os = "windows")]
impl LocalIpcServer {
    fn bind() -> anyhow::Result<Self> {
        let pipe_name = windows_local_ipc_pipe_name()?;
        let pipe = create_windows_local_ipc_pipe(&pipe_name)?;
        Ok(Self {
            pipe_name,
            pipe: Some(pipe),
            connected: false,
        })
    }

    pub(crate) fn consume_commands(&mut self) -> Vec<PeerLocalIpcCommand> {
        match self.consume_one_command() {
            Ok(Some(command)) => vec![command],
            Ok(None) => Vec::new(),
            Err(error) => {
                tracing::debug!(%error, "Windows local IPC command read failed");
                self.reset_pipe();
                Vec::new()
            }
        }
    }

    fn consume_one_command(&mut self) -> anyhow::Result<Option<PeerLocalIpcCommand>> {
        if self.pipe.is_none() {
            self.pipe = Some(create_windows_local_ipc_pipe(&self.pipe_name)?);
            self.connected = false;
        }

        let Some(pipe) = self.pipe.as_ref() else {
            return Ok(None);
        };
        if !self.connected {
            match connect_windows_local_ipc_pipe(pipe.0)? {
                WindowsPipeConnectState::Connected => {
                    self.connected = true;
                }
                WindowsPipeConnectState::Listening => return Ok(None),
            }
        }

        let peer_pid = match windows_named_pipe_client_pid(pipe.0) {
            Ok(peer_pid) => peer_pid,
            Err(_) => {
                self.reset_pipe();
                return Ok(None);
            }
        };
        if !process_looks_like_this_app(peer_pid) {
            self.reset_pipe();
            return Ok(None);
        }

        match read_windows_local_ipc_message(pipe.0)? {
            WindowsPipeReadState::Pending => Ok(None),
            WindowsPipeReadState::Closed => {
                self.reset_pipe();
                Ok(None)
            }
            WindowsPipeReadState::Message(message) => {
                let command = parse_local_ipc_command(&message);
                let acknowledgement = self.pipe.take();
                self.connected = false;
                Ok(command.map(|command| PeerLocalIpcCommand {
                    peer_pid,
                    command,
                    acknowledgement,
                }))
            }
        }
    }

    fn reset_pipe(&mut self) {
        if let Some(pipe) = self.pipe.take() {
            let _ = unsafe { DisconnectNamedPipe(pipe.0) };
            drop(pipe);
        }
        self.connected = false;
        self.pipe = create_windows_local_ipc_pipe(&self.pipe_name).ok();
    }
}

#[cfg(target_os = "windows")]
enum WindowsPipeConnectState {
    Connected,
    Listening,
}

#[cfg(target_os = "windows")]
enum WindowsPipeReadState {
    Message(String),
    Pending,
    Closed,
}

#[cfg(target_os = "windows")]
fn create_windows_local_ipc_pipe(pipe_name: &str) -> anyhow::Result<WindowsPipeHandle> {
    let name = wide_null(pipe_name);
    let security_descriptor = windows_local_ipc_security_descriptor()?;
    let security_attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: security_descriptor.0 .0,
        bInheritHandle: BOOL(0),
    };
    let open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE;
    let pipe_mode =
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS;
    let handle = unsafe {
        CreateNamedPipeW(
            PCWSTR(name.as_ptr()),
            open_mode,
            pipe_mode,
            1,
            WINDOWS_LOCAL_IPC_MAX_BYTES as u32,
            WINDOWS_LOCAL_IPC_MAX_BYTES as u32,
            WINDOWS_LOCAL_IPC_CONNECT_TIMEOUT_MS,
            Some(std::ptr::addr_of!(security_attributes)),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        anyhow::bail!(
            "failed to create Windows local IPC named pipe: {}",
            unsafe { GetLastError() }.0
        );
    }
    Ok(WindowsPipeHandle(handle))
}

#[cfg(target_os = "windows")]
fn windows_local_ipc_security_descriptor() -> anyhow::Result<LocalSecurityDescriptor> {
    let user_sid = crate::private_permissions::current_windows_user_sid_string()?;
    let sddl = format!("O:{user_sid}D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{user_sid})");
    let sddl = wide_null(&sddl);
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
    }
    .map_err(|error| {
        anyhow::anyhow!("failed to create Windows local IPC security descriptor: {error}")
    })?;
    Ok(LocalSecurityDescriptor(descriptor))
}

#[cfg(target_os = "windows")]
fn connect_windows_local_ipc_pipe(pipe: HANDLE) -> anyhow::Result<WindowsPipeConnectState> {
    if unsafe { ConnectNamedPipe(pipe, None) }.is_ok() {
        return Ok(WindowsPipeConnectState::Connected);
    }

    match unsafe { GetLastError() } {
        ERROR_PIPE_CONNECTED | ERROR_NO_DATA => Ok(WindowsPipeConnectState::Connected),
        ERROR_PIPE_LISTENING => Ok(WindowsPipeConnectState::Listening),
        error => Err(anyhow::anyhow!(
            "failed to connect Windows local IPC named pipe: {}",
            error.0
        )),
    }
}

#[cfg(target_os = "windows")]
fn windows_named_pipe_client_pid(pipe: HANDLE) -> anyhow::Result<u32> {
    let mut peer_pid = 0_u32;
    unsafe { GetNamedPipeClientProcessId(pipe, &mut peer_pid) }.map_err(|error| {
        anyhow::anyhow!("failed to read Windows local IPC peer process id: {error}")
    })?;
    if peer_pid == 0 {
        anyhow::bail!("Windows local IPC peer process id is unavailable");
    }
    Ok(peer_pid)
}

#[cfg(target_os = "windows")]
fn read_windows_local_ipc_message(pipe: HANDLE) -> anyhow::Result<WindowsPipeReadState> {
    let mut buffer = [0_u8; WINDOWS_LOCAL_IPC_MAX_BYTES];
    let mut bytes_read = 0_u32;
    if unsafe { ReadFile(pipe, Some(&mut buffer), Some(&mut bytes_read), None) }.is_err() {
        return match unsafe { GetLastError() } {
            ERROR_NO_DATA | ERROR_PIPE_LISTENING => Ok(WindowsPipeReadState::Pending),
            ERROR_BROKEN_PIPE => Ok(WindowsPipeReadState::Closed),
            error => Err(anyhow::anyhow!(
                "failed to read Windows local IPC command: {}",
                error.0
            )),
        };
    }

    if bytes_read == 0 {
        return Ok(WindowsPipeReadState::Closed);
    }
    Ok(WindowsPipeReadState::Message(
        String::from_utf8_lossy(&buffer[..bytes_read as usize]).to_string(),
    ))
}

#[cfg(target_os = "windows")]
fn write_windows_local_ipc_ack(pipe: HANDLE) -> anyhow::Result<()> {
    const ACK: &[u8] = b"ok\n";
    let mut bytes_written = 0_u32;
    unsafe { WriteFile(pipe, Some(ACK), Some(&mut bytes_written), None) }.map_err(|error| {
        anyhow::anyhow!("failed to acknowledge Windows local IPC command: {error}")
    })?;
    if bytes_written as usize != ACK.len() {
        anyhow::bail!("Windows local IPC acknowledgement was only partially written");
    }
    Ok(())
}

impl Drop for SingleInstanceGuard {
    fn drop(&mut self) {
        #[cfg(not(target_os = "windows"))]
        {
            remove_current_process_lock(&self.lock_dir, &self.lock_nonce);
        }
    }
}

#[cfg(target_os = "macos")]
impl Drop for FullUiInstanceGuard {
    fn drop(&mut self) {
        remove_current_process_lock(&self.lock_dir, &self.lock_nonce);
    }
}

#[cfg(not(target_os = "windows"))]
fn create_lock(lock_dir: &Path) -> std::io::Result<()> {
    if let Some(parent) = lock_dir.parent() {
        prepare_lock_root(parent)?;
    }
    std::fs::create_dir(lock_dir)?;
    secure_dir_permissions(lock_dir)?;
    let nonce = random_nonce();
    write_private_file(
        &lock_dir.join("pid"),
        std::process::id().to_string().as_bytes(),
    )?;
    write_private_file(
        &lock_dir.join(LOCK_OWNER_FILE_NAME),
        format!("pid={}\nnonce={nonce}\n", std::process::id()).as_bytes(),
    )?;
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn remove_current_process_lock(lock_dir: &Path, expected_nonce: &str) {
    if lock_owner(lock_dir).is_some_and(|owner| {
        owner.pid == std::process::id()
            && !expected_nonce.is_empty()
            && owner.nonce == expected_nonce
    }) {
        remove_stale_lock_dir(lock_dir).ok();
    }
}

#[cfg(not(target_os = "windows"))]
fn remove_stale_lock_dir(lock_dir: &Path) -> std::io::Result<()> {
    let metadata = std::fs::symlink_metadata(lock_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "stale lock path must be owned by the current user",
            ));
        }
    }

    let file_type = metadata.file_type();
    if file_type.is_symlink() || file_type.is_file() {
        return std::fs::remove_file(lock_dir);
    }
    if !file_type.is_dir() {
        return std::fs::remove_file(lock_dir).or_else(|_| std::fs::remove_dir_all(lock_dir));
    }

    secure_dir_permissions(lock_dir)?;
    std::fs::remove_dir_all(lock_dir)
}

fn lock_root() -> anyhow::Result<PathBuf> {
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    {
        crate::user_paths::runtime_dir()
    }

    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    crate::user_paths::cache_dir()
}

#[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
fn monitor_command_path() -> anyhow::Result<PathBuf> {
    Ok(lock_root()?.join(MONITOR_COMMAND_FILE_NAME))
}

fn monitor_status_path() -> anyhow::Result<PathBuf> {
    Ok(lock_root()?.join(MONITOR_STATUS_FILE_NAME))
}

#[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
fn activation_request_path() -> anyhow::Result<PathBuf> {
    Ok(lock_root()?.join(ACTIVATION_FILE_NAME))
}

#[cfg(target_os = "macos")]
fn ipc_socket_path() -> anyhow::Result<PathBuf> {
    Ok(lock_root()?.join(IPC_SOCKET_FILE_NAME))
}

#[cfg(target_os = "windows")]
fn windows_local_ipc_pipe_name() -> anyhow::Result<String> {
    use sha2::{Digest, Sha256};

    let root = lock_root()?;
    let mut hasher = Sha256::new();
    hasher.update(root.to_string_lossy().as_bytes());
    hasher.update(b"\0WindowsAppAutoLogin.LocalIpc");
    let digest = hasher.finalize();
    let suffix = digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(format!("{WINDOWS_LOCAL_IPC_PIPE_PREFIX}{suffix}"))
}

#[cfg(target_os = "macos")]
fn send_local_ipc_command(command: &str) -> anyhow::Result<()> {
    send_local_ipc_command_with_ack_timeout(command, Duration::from_secs(2))
}

#[cfg(target_os = "macos")]
fn send_local_ipc_command_with_ack_timeout(
    command: &str,
    acknowledgement_timeout: Duration,
) -> anyhow::Result<()> {
    let socket_path = ipc_socket_path()?;
    let root = lock_root()?;
    prepare_lock_root(&root)?;
    validate_local_ipc_socket_path(&socket_path)?;
    let mut stream = UnixStream::connect(socket_path)?;
    validate_local_ipc_server_peer(&stream)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let challenge = read_local_ipc_challenge(&mut stream)?;
    stream.write_all(format!("{}:{}\n", challenge, command.trim()).as_bytes())?;
    stream.shutdown(Shutdown::Write)?;
    read_macos_local_ipc_ack(&mut stream, acknowledgement_timeout)?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn read_macos_local_ipc_ack(
    stream: &mut UnixStream,
    acknowledgement_timeout: Duration,
) -> anyhow::Result<()> {
    stream.set_nonblocking(true)?;
    let started = Instant::now();
    let mut acknowledgement = Vec::with_capacity(4);
    while acknowledgement.len() < 4 {
        let mut byte = [0_u8; 1];
        match stream.read(&mut byte) {
            Ok(0) => break,
            Ok(1) => acknowledgement.push(byte[0]),
            Ok(_) => unreachable!("single-byte local IPC acknowledgement read"),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                if started.elapsed() >= acknowledgement_timeout {
                    anyhow::bail!("macOS local IPC acknowledgement timed out");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => {
                return Err(anyhow::anyhow!(
                    "failed to read macOS local IPC acknowledgement: {error}"
                ))
            }
        }
    }
    if acknowledgement != b"ok\n" {
        anyhow::bail!("macOS local IPC acknowledgement is invalid");
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn send_local_ipc_command(command: &str) -> anyhow::Result<()> {
    send_local_ipc_command_with_ack_timeout(command, Duration::from_secs(2))
}

#[cfg(target_os = "windows")]
fn send_local_ipc_command_with_ack_timeout(
    command: &str,
    acknowledgement_timeout: Duration,
) -> anyhow::Result<()> {
    let command = format!("{}\n", command.trim());
    if command.len() > WINDOWS_LOCAL_IPC_MAX_BYTES {
        anyhow::bail!("Windows local IPC command is too large");
    }

    let pipe_name = windows_local_ipc_pipe_name()?;
    let pipe = open_windows_local_ipc_pipe(&pipe_name)?;
    validate_windows_local_ipc_server(pipe.0)?;

    let mut bytes_written = 0_u32;
    unsafe {
        WriteFile(
            pipe.0,
            Some(command.as_bytes()),
            Some(&mut bytes_written),
            None,
        )
    }
    .map_err(|error| anyhow::anyhow!("failed to write Windows local IPC command: {error}"))?;

    if bytes_written as usize != command.len() {
        anyhow::bail!("Windows local IPC command was only partially written");
    }
    read_windows_local_ipc_ack(pipe.0, acknowledgement_timeout)?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn read_windows_local_ipc_ack(
    pipe: HANDLE,
    acknowledgement_timeout: Duration,
) -> anyhow::Result<()> {
    let started = Instant::now();
    let mut ack = [0_u8; 3];
    let mut received = 0_usize;
    while received < ack.len() {
        let mut bytes_read = 0_u32;
        match unsafe {
            ReadFile(
                pipe,
                Some(&mut ack[received..]),
                Some(&mut bytes_read),
                None,
            )
        } {
            Ok(()) if bytes_read > 0 => received += bytes_read as usize,
            Ok(()) => {}
            Err(error) => match unsafe { GetLastError() } {
                ERROR_NO_DATA | ERROR_PIPE_LISTENING => {}
                ERROR_BROKEN_PIPE => {
                    anyhow::bail!("Windows local IPC server closed without acknowledgement")
                }
                _ => {
                    return Err(anyhow::anyhow!(
                        "failed to read Windows local IPC acknowledgement: {error}"
                    ))
                }
            },
        }
        if received == ack.len() {
            break;
        }
        if started.elapsed() >= acknowledgement_timeout {
            anyhow::bail!("Windows local IPC acknowledgement timed out");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if &ack != b"ok\n" {
        anyhow::bail!("Windows local IPC acknowledgement is invalid");
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn open_windows_local_ipc_pipe(pipe_name: &str) -> anyhow::Result<WindowsPipeHandle> {
    let pipe_name = wide_null(pipe_name);
    let started = Instant::now();
    loop {
        let handle = unsafe {
            CreateFileW(
                PCWSTR(pipe_name.as_ptr()),
                (GENERIC_READ | GENERIC_WRITE).0,
                FILE_SHARE_MODE(0),
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        };
        if let Ok(handle) = handle {
            let mode = NAMED_PIPE_MODE(PIPE_READMODE_MESSAGE.0 | PIPE_NOWAIT.0);
            if let Err(error) = unsafe { SetNamedPipeHandleState(handle, Some(&mode), None, None) }
            {
                let _ = unsafe { CloseHandle(handle) };
                anyhow::bail!(
                    "failed to configure Windows local IPC acknowledgement channel: {error}"
                );
            }
            return Ok(WindowsPipeHandle(handle));
        }

        let error = unsafe { GetLastError() };
        if error != ERROR_PIPE_BUSY && error != ERROR_FILE_NOT_FOUND
            || started.elapsed()
                >= Duration::from_millis(WINDOWS_LOCAL_IPC_CONNECT_TIMEOUT_MS as u64)
        {
            anyhow::bail!("failed to open Windows local IPC named pipe: {}", error.0);
        }

        if error == ERROR_PIPE_BUSY {
            let _ = unsafe {
                WaitNamedPipeW(
                    PCWSTR(pipe_name.as_ptr()),
                    WINDOWS_LOCAL_IPC_CONNECT_TIMEOUT_MS.min(100),
                )
            };
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[cfg(target_os = "windows")]
fn validate_windows_local_ipc_server(pipe: HANDLE) -> anyhow::Result<()> {
    let mut server_pid = 0_u32;
    unsafe { GetNamedPipeServerProcessId(pipe, &mut server_pid) }.map_err(|error| {
        anyhow::anyhow!("failed to read Windows local IPC server process id: {error}")
    })?;
    if server_pid == 0 || !process_looks_like_this_app(server_pid) {
        anyhow::bail!("Windows local IPC server is not the trusted app process");
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn validate_local_ipc_server_peer(stream: &UnixStream) -> anyhow::Result<()> {
    let peer_pid = validated_local_ipc_peer_pid(stream)?;
    let expected_pid = lock_pid(&lock_root()?.join(LOCK_DIR_NAME))
        .ok_or_else(|| anyhow::anyhow!("local IPC server lock owner is unavailable"))?;
    if peer_pid != expected_pid {
        anyhow::bail!("local IPC peer is not the trusted app supervisor");
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn validated_local_ipc_peer_pid(stream: &UnixStream) -> anyhow::Result<u32> {
    let Some(peer_uid) = peer_uid(stream) else {
        anyhow::bail!("local IPC peer UID is unavailable");
    };
    if peer_uid != unsafe { libc::geteuid() } {
        anyhow::bail!("local IPC peer must be owned by the current user");
    }

    let Some(peer_pid) = peer_pid(stream).and_then(|pid| u32::try_from(pid).ok()) else {
        anyhow::bail!("local IPC peer PID is unavailable");
    };
    if !process_looks_like_this_app(peer_pid) {
        anyhow::bail!("local IPC peer is not the trusted app process");
    }
    Ok(peer_pid)
}

#[cfg(target_os = "macos")]
fn peer_uid(stream: &UnixStream) -> Option<libc::uid_t> {
    let mut uid = std::mem::MaybeUninit::<libc::uid_t>::uninit();
    let mut gid = std::mem::MaybeUninit::<libc::gid_t>::uninit();
    let ret = unsafe { libc::getpeereid(stream.as_raw_fd(), uid.as_mut_ptr(), gid.as_mut_ptr()) };
    if ret != 0 {
        return None;
    }

    Some(unsafe { uid.assume_init() })
}

#[cfg(all(target_os = "macos", unix))]
fn validate_local_ipc_socket_path(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};

    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
        anyhow::bail!("local IPC endpoint must be a real Unix socket");
    }
    if metadata.uid() != unsafe { libc::geteuid() } {
        anyhow::bail!("local IPC endpoint must be owned by the current user");
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        anyhow::bail!("local IPC endpoint must not be group/world accessible");
    }
    if private_path_has_acl(path)? {
        anyhow::bail!("local IPC endpoint must not have ACL entries");
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn local_ipc_command_from_stream(
    stream: UnixStream,
) -> anyhow::Result<Option<PeerLocalIpcCommand>> {
    let Ok(peer_pid) = validated_local_ipc_peer_pid(&stream) else {
        return Ok(None);
    };

    local_ipc_command_from_validated_stream(stream, peer_pid)
}

#[cfg(target_os = "macos")]
fn local_ipc_command_from_validated_stream(
    mut stream: UnixStream,
    peer_pid: u32,
) -> anyhow::Result<Option<PeerLocalIpcCommand>> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_millis(250)))?;
    stream.set_write_timeout(Some(Duration::from_millis(250)))?;
    let challenge = random_nonce();
    if stream.write_all(challenge.as_bytes()).is_err() || stream.write_all(b"\n").is_err() {
        return Ok(None);
    }

    let deadline = Instant::now()
        .checked_add(Duration::from_millis(250))
        .ok_or_else(|| anyhow::anyhow!("local IPC read deadline is unavailable"))?;
    stream.set_nonblocking(true)?;
    let mut message = Vec::with_capacity(MACOS_LOCAL_IPC_MAX_BYTES);
    loop {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return Ok(None);
        };
        let mut byte = [0_u8; 1];
        match stream.read(&mut byte) {
            Ok(0) => break,
            Ok(1) if byte[0] == b'\n' => break,
            Ok(1) => {
                if message.len() == MACOS_LOCAL_IPC_MAX_BYTES {
                    return Ok(None);
                }
                message.push(byte[0]);
            }
            Ok(_) => unreachable!("single-byte local IPC command read"),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                std::thread::sleep(remaining.min(Duration::from_millis(2)));
            }
            Err(error) => return Err(error.into()),
        }
    }
    if message.is_empty() {
        return Ok(None);
    }
    let Ok(message) = std::str::from_utf8(&message) else {
        return Ok(None);
    };
    stream.set_nonblocking(false)?;
    Ok(
        parse_local_ipc_challenge_response(message, &challenge).map(|command| {
            PeerLocalIpcCommand {
                peer_pid,
                command,
                acknowledgement: Some(stream),
            }
        }),
    )
}

#[cfg(target_os = "macos")]
fn read_local_ipc_challenge(stream: &mut UnixStream) -> anyhow::Result<String> {
    let mut message = Vec::new();
    for _ in 0..64 {
        let mut byte = [0_u8; 1];
        let len = stream.read(&mut byte)?;
        if len == 0 || byte[0] == b'\n' {
            break;
        }
        message.push(byte[0]);
    }
    if message.is_empty() {
        anyhow::bail!("local IPC challenge is empty");
    }
    let message = String::from_utf8_lossy(&message);
    let Some(challenge) = parse_nonce_field(message.trim()) else {
        anyhow::bail!("local IPC challenge is invalid");
    };
    Ok(challenge.to_string())
}

#[cfg(target_os = "macos")]
fn parse_local_ipc_challenge_response(
    message: &str,
    expected_challenge: &str,
) -> Option<LocalIpcCommand> {
    let (challenge, command) = message.trim().split_once(':')?;
    if challenge != expected_challenge {
        return None;
    }
    parse_local_ipc_command(command)
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn parse_local_ipc_command(message: &str) -> Option<LocalIpcCommand> {
    let message = message.trim();
    if message == IPC_COMMAND_ACTIVATE {
        return Some(LocalIpcCommand::Activate);
    }

    if message == IPC_COMMAND_SETTINGS_BOOTSTRAP {
        return Some(LocalIpcCommand::SettingsBootstrap);
    }

    if message == IPC_COMMAND_SETTINGS_MUTATION_BEGIN {
        return Some(LocalIpcCommand::SettingsMutationBegin);
    }

    if message == IPC_COMMAND_SETTINGS_MUTATION_CANCEL {
        return Some(LocalIpcCommand::SettingsMutationCancel);
    }

    if message == IPC_COMMAND_RELOAD_CONFIG {
        return Some(LocalIpcCommand::ReloadConfig);
    }

    let command = message.strip_prefix(IPC_COMMAND_MONITOR_PREFIX)?;
    MonitorControlCommand::from_command_name(command).map(LocalIpcCommand::Monitor)
}

#[cfg(target_os = "macos")]
fn peer_pid(stream: &UnixStream) -> Option<libc::pid_t> {
    let mut pid = std::mem::MaybeUninit::<libc::pid_t>::uninit();
    let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEEREPID,
            pid.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if ret != 0 || len as usize != std::mem::size_of::<libc::pid_t>() {
        return None;
    }

    Some(unsafe { pid.assume_init() })
}

#[cfg(target_os = "macos")]
fn remove_stale_ipc_path(path: &Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "stale IPC path must not be a directory",
        )),
        Ok(_) => std::fs::remove_file(path),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(all(target_os = "macos", unix))]
fn local_ipc_socket_identity(path: &Path) -> anyhow::Result<LocalIpcSocketIdentity> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
        anyhow::bail!("local IPC endpoint must be a real Unix socket");
    }
    Ok(LocalIpcSocketIdentity {
        dev: metadata.dev(),
        ino: metadata.ino(),
        uid: metadata.uid(),
    })
}

#[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
fn file_modified_time(path: &Path) -> Option<SystemTime> {
    let metadata = std::fs::symlink_metadata(path).ok()?;
    metadata.file_type().is_file().then_some(())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o077 != 0
        {
            return None;
        }
    }
    metadata.modified().ok()
}

#[cfg(not(target_os = "windows"))]
fn existing_process_is_alive(lock_dir: &Path) -> bool {
    lock_pid(lock_dir)
        .is_some_and(|pid| pid == std::process::id() || process_looks_like_this_app(pid))
}

#[cfg(not(target_os = "windows"))]
fn lock_dir_looks_fresh(lock_dir: &Path) -> bool {
    const STARTUP_RACE_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

    let Ok(metadata) = std::fs::symlink_metadata(lock_dir) else {
        return false;
    };
    if !metadata.file_type().is_dir() {
        return false;
    }

    lock_owner(lock_dir).is_none()
        && lock_pid_file(lock_dir).is_none()
        && metadata
            .modified()
            .ok()
            .and_then(|modified| modified.elapsed().ok())
            .is_some_and(|age| age <= STARTUP_RACE_GRACE)
}

#[cfg(target_os = "macos")]
fn process_looks_like_this_app(pid: u32) -> bool {
    let Some(process_path) = macos_process_executable_path(pid) else {
        return false;
    };
    let Some(current_path) = current_executable_path() else {
        return false;
    };
    macos_process_identity_matches_current_app(
        &process_path,
        current_path,
        crate::app_identity::macos_bundle_id(),
        crate::app_identity::macos_team_id(),
        macos_bundle_identifier_matches,
        |bundle_path, bundle_id, team_id| {
            crate::macos_identity::signed_live_process_matches_identity(
                pid as i32,
                bundle_path,
                bundle_id,
                team_id,
            )
            .unwrap_or(false)
        },
        || macos_live_code_identity_matches_current_process(pid as i32),
    )
}

#[cfg(target_os = "macos")]
fn macos_process_identity_matches_current_app(
    process_path: &Path,
    current_path: &Path,
    bundle_id: &'static str,
    team_id: Option<&'static str>,
    mut verify_bundle_identifier: impl FnMut(&Path, &'static str) -> bool,
    mut verify_signed_live_bundle: impl FnMut(&Path, &'static str, &'static str) -> bool,
    mut verify_development_live_code: impl FnMut() -> bool,
) -> bool {
    if process_path != current_path {
        return false;
    }
    if crate::macos_identity::path_has_symlink_component(process_path)
        || crate::macos_identity::path_has_symlink_component(current_path)
    {
        return false;
    }
    let Some(process_bundle_path) = macos_containing_app_bundle(process_path) else {
        return false;
    };
    let Some(current_bundle_path) = macos_containing_app_bundle(current_path) else {
        return false;
    };
    if process_bundle_path != current_bundle_path
        || crate::macos_identity::path_has_symlink_component(&process_bundle_path)
    {
        return false;
    }
    if !verify_bundle_identifier(&process_bundle_path, bundle_id) {
        return false;
    }

    match team_id {
        Some(team_id) if crate::macos_identity::valid_team_id(team_id) => {
            verify_signed_live_bundle(&process_bundle_path, bundle_id, team_id)
        }
        Some(_) => false,
        None => verify_development_live_code(),
    }
}

#[cfg(target_os = "macos")]
fn macos_live_code_identity_matches_current_process(pid: i32) -> bool {
    let Some(current_identifier) = current_code_unique_identifier() else {
        tracing::warn!(
            "Local IPC development identity fallback is unavailable: current code identifier is missing"
        );
        return false;
    };
    let Some(peer_identifier) = crate::macos_identity::live_process_code_unique_identifier(pid)
    else {
        tracing::warn!(
            peer_pid = pid,
            "Rejected local IPC peer: live code identifier is missing"
        );
        return false;
    };
    if peer_identifier.as_slice() != current_identifier {
        tracing::warn!(
            peer_pid = pid,
            "Rejected local IPC peer: development live code identity changed"
        );
        return false;
    }
    tracing::debug!(
        peer_pid = pid,
        "Local IPC accepted peer with development live code identity fallback"
    );
    true
}

#[cfg(target_os = "macos")]
fn macos_bundle_identifier_matches(bundle_path: &Path, expected_bundle_id: &str) -> bool {
    let output = std::process::Command::new("/usr/libexec/PlistBuddy")
        .args(["-c", "Print :CFBundleIdentifier"])
        .arg(bundle_path.join("Contents/Info.plist"))
        .output();
    let Ok(output) = output else {
        return false;
    };
    output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == expected_bundle_id
}

#[cfg(target_os = "macos")]
fn current_code_unique_identifier() -> Option<&'static [u8]> {
    CURRENT_CODE_UNIQUE_IDENTIFIER
        .get_or_init(crate::macos_identity::current_process_code_unique_identifier)
        .as_deref()
}

#[cfg(target_os = "macos")]
fn current_executable_path() -> Option<&'static Path> {
    CURRENT_EXECUTABLE_PATH
        .get_or_init(|| std::env::current_exe().ok())
        .as_deref()
}

#[cfg(target_os = "macos")]
fn macos_containing_app_bundle(path: &Path) -> Option<PathBuf> {
    path.ancestors()
        .find(|candidate| candidate.extension().is_some_and(|ext| ext == "app"))
        .map(Path::to_path_buf)
}

#[cfg(target_os = "macos")]
fn macos_process_executable_path(pid: u32) -> Option<PathBuf> {
    let mut buffer = vec![0_u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let len = unsafe {
        libc::proc_pidpath(
            pid as i32,
            buffer.as_mut_ptr().cast(),
            buffer.len().try_into().ok()?,
        )
    };
    if len <= 0 {
        return None;
    }

    macos_proc_pidpath_buffer_to_path(&buffer[..len as usize])
}

#[cfg(target_os = "macos")]
fn macos_proc_pidpath_buffer_to_path(buffer: &[u8]) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStringExt;

    let end = buffer
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(buffer.len());
    let path = buffer[..end].to_vec();
    (!path.is_empty()).then(|| PathBuf::from(std::ffi::OsString::from_vec(path)))
}

#[cfg(target_os = "windows")]
fn process_looks_like_this_app(pid: u32) -> bool {
    let Some(current_path) = std::env::current_exe().ok() else {
        return false;
    };
    let Some(process_path) = windows_process_path(pid) else {
        return false;
    };
    crate::app_identity::windows_local_ipc_peer_path_is_trusted(&current_path, &process_path)
}

#[cfg(target_os = "windows")]
fn windows_process_path(pid: u32) -> Option<PathBuf> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buffer = vec![0_u16; 32768];
        let mut len = buffer.len() as u32;
        let result = QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(buffer.as_mut_ptr()),
            &mut len,
        );
        let _ = CloseHandle(handle);
        result.ok()?;
        Some(PathBuf::from(String::from_utf16_lossy(
            &buffer[..len as usize],
        )))
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
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
#[cfg_attr(not(test), allow(dead_code))]
fn lock_pid(lock_dir: &Path) -> Option<u32> {
    lock_owner(lock_dir)
        .map(|owner| owner.pid)
        .or_else(|| lock_pid_file(lock_dir))
}

#[cfg(not(target_os = "windows"))]
fn lock_pid_file(lock_dir: &Path) -> Option<u32> {
    read_private_text_limited(&lock_dir.join("pid"), MAX_LOCK_PID_BYTES)
        .ok()
        .flatten()
        .and_then(|pid| parse_pid_field(pid.trim()))
}

#[cfg(not(target_os = "windows"))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct LockOwner {
    pid: u32,
    nonce: String,
}

#[cfg(not(target_os = "windows"))]
fn lock_owner(lock_dir: &Path) -> Option<LockOwner> {
    let content =
        read_private_text_limited(&lock_dir.join(LOCK_OWNER_FILE_NAME), MAX_LOCK_OWNER_BYTES)
            .ok()
            .flatten()?;
    let mut pid = None;
    let mut nonce = None;
    for line in content.lines() {
        if let Some(value) = line.strip_prefix("pid=") {
            pid = parse_pid_field(value.trim());
        } else if let Some(value) = line.strip_prefix("nonce=") {
            nonce = parse_nonce_field(value.trim()).map(str::to_string);
        }
    }
    Some(LockOwner {
        pid: pid?,
        nonce: nonce?,
    })
}

fn random_nonce() -> String {
    use rand::RngCore;

    let mut bytes = [0_u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(not(target_os = "windows"))]
fn parse_pid_field(value: &str) -> Option<u32> {
    if value.is_empty() || value.len() > 10 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let pid = value.parse::<u32>().ok()?;
    (pid > 0).then_some(pid)
}

#[cfg(not(target_os = "windows"))]
fn parse_nonce_field(value: &str) -> Option<&str> {
    (value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())).then_some(value)
}

#[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
fn parse_request_nonce(value: &str) -> Option<&str> {
    (value.len() <= 64 && !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .then_some(value)
}

#[cfg(unix)]
fn secure_dir_permissions(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "private directory must be a real directory",
        ));
    }
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "private directory must be owned by the current user",
        ));
    }

    let dir = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(path)?;
    let metadata = dir.metadata()?;
    if !metadata.file_type().is_dir() || metadata.uid() != unsafe { libc::geteuid() } {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "private directory must be a current-user owned directory",
        ));
    }

    let mut permissions = metadata.permissions();
    permissions.set_mode(0o700);
    dir.set_permissions(permissions)?;
    strip_private_file_acl(&dir)
}

#[cfg(unix)]
fn secure_file_permissions(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    secure_file_handle_permissions(&file, mode)
}

#[cfg(unix)]
fn secure_file_handle_permissions(file: &std::fs::File, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "private file must be a real file",
        ));
    }
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "private file must be owned by the current user",
        ));
    }

    let mut permissions = metadata.permissions();
    permissions.set_mode(mode);
    file.set_permissions(permissions)?;
    strip_private_file_acl(file)
}

#[cfg(all(target_os = "macos", unix))]
fn strip_private_path_acl(path: &Path) -> std::io::Result<()> {
    crate::private_permissions::strip_macos_acl(path)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::PermissionDenied, error))
}

#[cfg(all(target_os = "macos", unix))]
fn strip_private_file_acl(file: &std::fs::File) -> std::io::Result<()> {
    crate::private_permissions::strip_macos_acl_fd(file)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::PermissionDenied, error))
}

#[cfg(all(target_os = "macos", unix))]
fn private_path_has_acl(path: &Path) -> std::io::Result<bool> {
    crate::private_permissions::path_has_macos_acl(path)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::PermissionDenied, error))
}

#[cfg(all(target_os = "macos", unix))]
fn private_file_has_acl(file: &std::fs::File) -> std::io::Result<bool> {
    crate::private_permissions::file_has_macos_acl_fd(file)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::PermissionDenied, error))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn strip_private_file_acl(_file: &std::fs::File) -> std::io::Result<()> {
    Ok(())
}

#[cfg(windows)]
fn secure_dir_permissions(path: &Path) -> std::io::Result<()> {
    crate::private_permissions::secure_windows_private_dir(path).map_err(private_security_io_error)
}

#[cfg(windows)]
fn secure_file_permissions(path: &Path, _mode: u32) -> std::io::Result<()> {
    crate::private_permissions::secure_windows_private_file(path).map_err(private_security_io_error)
}

#[cfg(windows)]
fn private_security_io_error(error: anyhow::Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::PermissionDenied, error.to_string())
}

#[cfg(not(any(unix, windows)))]
fn secure_dir_permissions(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn secure_file_permissions(_path: &Path, _mode: u32) -> std::io::Result<()> {
    Ok(())
}

#[cfg(all(target_os = "macos", unix))]
fn secure_socket_permissions(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};

    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "private socket must be a real Unix socket",
        ));
    }
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "private socket must be owned by the current user",
        ));
    }
    let identity = LocalIpcSocketIdentity {
        dev: metadata.dev(),
        ino: metadata.ino(),
        uid: metadata.uid(),
    };

    let mut permissions = metadata.permissions();
    permissions.set_mode(0o600);
    set_path_permissions_no_follow(path, permissions.mode() & 0o777)?;
    strip_private_path_acl(path)?;
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_socket()
        || metadata.dev() != identity.dev
        || metadata.ino() != identity.ino
        || metadata.uid() != identity.uid
        || metadata.permissions().mode() & 0o077 != 0
        || private_path_has_acl(path)?
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "private socket permissions could not be secured",
        ));
    }
    Ok(())
}

#[cfg(all(target_os = "macos", unix))]
fn set_path_permissions_no_follow(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;

    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "private path contains an interior NUL byte",
        )
    })?;
    let ret = unsafe {
        libc::fchmodat(
            libc::AT_FDCWD,
            path.as_ptr(),
            mode as libc::mode_t,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn write_private_text(path: &Path, content: &str) -> anyhow::Result<()> {
    use std::io::Write;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        secure_dir_permissions(parent)?;
    }
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            anyhow::bail!("private file path must be a regular file");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.uid() != unsafe { libc::geteuid() } {
                anyhow::bail!("private file must be owned by the current user");
            }
        }
    }

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp_path = path.with_extension(format!("tmp.{}.{nonce}", std::process::id()));

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp_path)?;
        secure_file_handle_permissions(&file, 0o600)?;
        file.write_all(content.as_bytes())?;
        file.sync_all().ok();
    }

    #[cfg(not(unix))]
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)?;
        secure_file_permissions(&temp_path, 0o600)?;
        file.write_all(content.as_bytes())?;
        file.sync_all().ok();
    }

    #[cfg(unix)]
    {
        std::fs::rename(&temp_path, path)?;
    }
    #[cfg(not(unix))]
    {
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        std::fs::rename(&temp_path, path)?;
    }
    secure_file_permissions(path, 0o600)?;
    Ok(())
}

fn read_private_text_limited(path: &Path, max_bytes: u64) -> std::io::Result<Option<String>> {
    use std::io::Read;

    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    #[cfg(windows)]
    use std::os::windows::fs::OpenOptionsExt;

    let mut open_options = std::fs::OpenOptions::new();
    open_options.read(true);
    #[cfg(unix)]
    open_options.custom_flags(libc::O_NOFOLLOW);
    #[cfg(windows)]
    open_options.custom_flags(windows::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT.0);

    let file = match open_options.open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) if no_follow_open_error(&e) => return Ok(None),
        Err(e) => return Err(e),
    };
    let metadata = file.metadata()?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Ok(None);
    }
    #[cfg(windows)]
    if crate::private_permissions::validate_windows_private_file_handle(&file).is_err() {
        return Ok(None);
    }
    #[cfg(windows)]
    if secure_file_permissions(path, 0o600).is_err() {
        return Ok(None);
    }
    if metadata.len() > max_bytes {
        return Ok(None);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Ok(None);
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            return Ok(None);
        }
        #[cfg(target_os = "macos")]
        if private_file_has_acl(&file)? {
            return Ok(None);
        }
    }

    let mut bytes = Vec::with_capacity(max_bytes.min(4096) as usize);
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Ok(None);
    }

    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid utf-8"))
}

#[cfg(unix)]
fn no_follow_open_error(error: &std::io::Error) -> bool {
    error.raw_os_error() == Some(libc::ELOOP)
}

#[cfg(not(unix))]
fn no_follow_open_error(_error: &std::io::Error) -> bool {
    false
}

#[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
fn activation_request_is_valid(content: &str) -> bool {
    if content.len() > MAX_ACTIVATION_REQUEST_BYTES as usize {
        return false;
    }
    let mut parts = content.trim().splitn(3, ':');
    let Some(pid) = parts.next().and_then(parse_pid_field) else {
        return false;
    };
    let Some(nonce) = parts.next() else {
        return false;
    };
    if parse_request_nonce(nonce).is_none() {
        return false;
    }
    let Some(path) = parts.next() else {
        return false;
    };
    if path.len() > 3072
        || path
            .bytes()
            .any(|byte| byte == 0 || byte == b'\n' || byte == b'\r')
    {
        return false;
    }

    if process_looks_like_this_app(pid) {
        return true;
    }

    let Some(current) = std::env::current_exe().ok() else {
        return false;
    };
    let requested = PathBuf::from(path);
    match (requested.canonicalize(), current.canonicalize()) {
        (Ok(requested), Ok(current)) => requested == current,
        _ => false,
    }
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
        secure_file_handle_permissions(&file, 0o600)?;
        file.write_all(bytes)?;
        file.sync_all().ok();
    }

    #[cfg(not(unix))]
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        file.write_all(bytes)?;
        file.sync_all().ok();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_single_instance_uses_private_file_lock_not_fixed_mutex() {
        let implementation = include_str!("single_instance.rs");
        let acquire = source_between(
            implementation,
            "#[cfg(target_os = \"windows\")]\nfn acquire_windows_single_instance(",
            "#[cfg(target_os = \"windows\")]\nfn wide_null(",
        );

        assert!(!implementation.contains(concat!("WINDOWS_SINGLE", "_INSTANCE_MUTEX")));
        assert!(
            !implementation.contains(concat!("Local\\\\", "WindowsAppAutoLogin.SingleInstance"))
        );
        assert!(!implementation.contains(concat!("Create", "MutexW")));
        assert!(acquire.contains("acquire_windows_single_instance_file_lock"));
        assert!(implementation.contains("LockFileEx"));
        assert!(implementation.contains("WINDOWS_SINGLE_INSTANCE_LOCK_FILE_NAME"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_file_lock_blocks_second_acquire_until_guard_drops() {
        let root = temp_test_root("windows-file-single-instance");
        prepare_lock_root(&root).unwrap();
        let guard = acquire_windows_single_instance_file_lock(&root).unwrap();
        let Err(error) = acquire_windows_single_instance_file_lock(&root) else {
            panic!("second Windows file lock acquire succeeded");
        };

        assert!(error.to_string().contains("already running"));
        drop(guard);
        assert!(acquire_windows_single_instance_file_lock(&root).is_ok());
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_lock_root_uses_runtime_dir_not_cache_dir() {
        let root = lock_root().unwrap();

        assert_eq!(root, crate::user_paths::runtime_dir().unwrap());
        assert_ne!(root, crate::user_paths::cache_dir().unwrap());
    }

    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    #[test]
    fn activation_watcher_consumes_new_request_once() {
        let path = std::env::temp_dir().join(format!(
            "windows-app-autologin-activation-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let mut watcher = ActivationWatcher::for_path(path.clone());

        assert!(!watcher.consume_activation_request());
        write_test_private_text(
            &path,
            format!(
                "{}:1:{}",
                std::process::id(),
                std::env::current_exe().unwrap().display()
            ),
        )
        .unwrap();
        assert!(watcher.consume_activation_request());
        assert!(!watcher.consume_activation_request());

        write_test_private_text(
            &path,
            format!(
                "{}:2:{}",
                std::process::id(),
                std::env::current_exe().unwrap().display()
            ),
        )
        .unwrap();
        assert!(watcher.consume_activation_request());
        assert!(!watcher.consume_activation_request());

        let _ = std::fs::remove_file(path);
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn lock_dir_blocks_second_acquire() {
        let root = temp_test_root("lock-blocks-second");
        let lock_dir = acquire_lock_dir_in_root(&root, LOCK_DIR_NAME, "already running").unwrap();
        let guard = SingleInstanceGuard {
            lock_dir: lock_dir.clone(),
            lock_nonce: lock_owner(&lock_dir).unwrap().nonce,
            #[cfg(all(unix, not(target_os = "windows")))]
            _lock_file: test_lock_file(&root),
            #[cfg(target_os = "macos")]
            ipc_server: None,
        };

        let Err(error) = acquire_lock_dir_in_root(&root, LOCK_DIR_NAME, "already running") else {
            panic!("second lock-dir acquire succeeded");
        };
        assert!(error.to_string().contains("already running"));

        drop(guard);
        assert!(acquire_lock_dir_in_root(&root, LOCK_DIR_NAME, "already running").is_ok());
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn full_ui_lock_blocks_second_acquire() {
        let root = temp_test_root("full-ui-lock-blocks-second");
        let lock_dir =
            acquire_lock_dir_in_root(&root, FULL_UI_LOCK_DIR_NAME, "window already open").unwrap();
        let guard = FullUiInstanceGuard {
            lock_dir: lock_dir.clone(),
            lock_nonce: lock_owner(&lock_dir).unwrap().nonce,
            #[cfg(all(unix, not(target_os = "windows")))]
            _lock_file: test_lock_file(&root),
        };

        let Err(error) =
            acquire_lock_dir_in_root(&root, FULL_UI_LOCK_DIR_NAME, "window already open")
        else {
            panic!("second full-ui lock acquire succeeded");
        };
        assert!(error.to_string().contains("window already open"));

        drop(guard);
        assert!(
            acquire_lock_dir_in_root(&root, FULL_UI_LOCK_DIR_NAME, "window already open").is_ok()
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn settings_session_shared_lease_blocks_recovery_until_drop() {
        let root = temp_test_root("settings-session-shared-blocks-recovery");
        let token = SettingsSessionToken::generate();
        let mut recovery = try_acquire_settings_recovery_lease_in_root(&root)
            .unwrap()
            .expect("initial recovery lease");
        recovery.establish_session(&token).unwrap();
        drop(recovery);

        let session = acquire_settings_session_lease_in_root(&root, &token).unwrap();
        assert!(try_acquire_settings_recovery_lease_in_root(&root)
            .unwrap()
            .is_none());

        drop(session);
        assert!(try_acquire_settings_recovery_lease_in_root(&root)
            .unwrap()
            .is_some());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn settings_recovery_exclusive_lease_blocks_child_session() {
        let root = temp_test_root("settings-recovery-blocks-child");
        let token = SettingsSessionToken::generate();
        let mut recovery = try_acquire_settings_recovery_lease_in_root(&root)
            .unwrap()
            .expect("initial recovery lease");
        recovery.establish_session(&token).unwrap();

        let Err(error) = acquire_settings_session_lease_in_root(&root, &token) else {
            panic!("settings session acquired while recovery held the exclusive lease");
        };
        assert!(error.to_string().contains("recovery is in progress"));

        drop(recovery);
        assert!(acquire_settings_session_lease_in_root(&root, &token).is_ok());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn rotating_settings_session_rejects_a_late_child() {
        let root = temp_test_root("settings-session-rotation-rejects-late-child");
        let stale_token = SettingsSessionToken::generate();
        let fresh_token = SettingsSessionToken::generate();
        assert_ne!(stale_token.as_str(), fresh_token.as_str());

        let mut recovery = try_acquire_settings_recovery_lease_in_root(&root)
            .unwrap()
            .expect("initial recovery lease");
        recovery.establish_session(&stale_token).unwrap();
        recovery.establish_session(&fresh_token).unwrap();
        drop(recovery);

        let Err(error) = acquire_settings_session_lease_in_root(&root, &stale_token) else {
            panic!("stale settings session token was accepted");
        };
        assert!(error.to_string().contains("no longer authorized"));
        assert!(acquire_settings_session_lease_in_root(&root, &fresh_token).is_ok());
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn lock_drop_only_removes_current_pid_lock() {
        let root = temp_test_root("drop-keeps-foreign-pid");
        let lock_dir = acquire_lock_dir_in_root(&root, LOCK_DIR_NAME, "already running").unwrap();
        let guard = SingleInstanceGuard {
            lock_dir: lock_dir.clone(),
            lock_nonce: lock_owner(&lock_dir).unwrap().nonce,
            #[cfg(all(unix, not(target_os = "windows")))]
            _lock_file: test_lock_file(&root),
            #[cfg(target_os = "macos")]
            ipc_server: None,
        };
        write_test_private_text(
            lock_dir.join(LOCK_OWNER_FILE_NAME),
            format!("pid={}\nnonce=foreign\n", std::process::id()),
        )
        .unwrap();

        drop(guard);
        assert!(lock_dir.exists());
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn stale_lock_entries_are_reclaimed() {
        for case in ["dead-pid", "lock-file"] {
            let root = temp_test_root(&format!("stale-lock-{case}-reclaimed"));
            match case {
                "dead-pid" => {
                    let lock_dir = root.join(LOCK_DIR_NAME);
                    std::fs::create_dir_all(&lock_dir).unwrap();
                    write_test_private_text(lock_dir.join("pid"), "99999999").unwrap();
                }
                "lock-file" => {
                    std::fs::create_dir_all(&root).unwrap();
                    std::fs::write(root.join(LOCK_DIR_NAME), "not-a-lock-directory").unwrap();
                }
                _ => unreachable!(),
            }

            let acquired =
                acquire_lock_dir_in_root(&root, LOCK_DIR_NAME, "already running").unwrap();
            assert_eq!(lock_pid(&acquired), Some(std::process::id()));

            let _ = std::fs::remove_dir_all(root);
        }
    }

    #[test]
    fn lock_root_regular_file_is_rejected_and_preserved() {
        let root = temp_test_root("lock-root-regular-file");
        let _ = std::fs::remove_dir_all(&root);
        let original = b"not-a-lock-root-directory";
        std::fs::write(&root, original).unwrap();

        let error = prepare_lock_root(&root).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(std::fs::read(&root).unwrap(), original);
        assert!(std::fs::symlink_metadata(&root)
            .unwrap()
            .file_type()
            .is_file());

        let _ = std::fs::remove_file(root);
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn legacy_pid_only_live_lock_still_blocks_startup() {
        let root = temp_test_root("legacy-live-pid-lock");
        let lock_dir = root.join(LOCK_DIR_NAME);
        std::fs::create_dir_all(&lock_dir).unwrap();
        write_test_private_text(lock_dir.join("pid"), std::process::id().to_string()).unwrap();

        let Err(error) = acquire_lock_dir_in_root(&root, LOCK_DIR_NAME, "already running") else {
            panic!("legacy live pid lock was reclaimed");
        };
        assert!(error.to_string().contains("already running"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(all(unix, not(target_os = "windows")))]
    #[test]
    fn lock_root_symlink_is_rejected() {
        use std::os::unix::fs::symlink;

        let root = temp_test_root("lock-root-symlink");
        let target = temp_test_root("lock-root-symlink-target");
        let _ = std::fs::remove_dir_all(&root);
        symlink(&target, &root).unwrap();

        let error = prepare_lock_root(&root).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(std::fs::symlink_metadata(&root)
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(target.exists());

        let _ = std::fs::remove_file(root);
        let _ = std::fs::remove_dir_all(target);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn lock_root_uses_runtime_dir_not_cache_dir() {
        use std::ffi::OsStr;

        let root = lock_root().unwrap();

        assert_eq!(root, crate::user_paths::runtime_dir().unwrap());
        assert!(!root
            .components()
            .any(|component| component.as_os_str() == OsStr::new("Caches")));
    }

    #[cfg(all(unix, not(target_os = "windows")))]
    #[test]
    fn lock_root_is_private() {
        use std::os::unix::fs::PermissionsExt;

        let root = temp_test_root("lock-root-permissions");
        let mut permissions = std::fs::metadata(&root).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&root, permissions).unwrap();

        prepare_lock_root(&root).unwrap();

        let mode = std::fs::metadata(&root).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn lock_root_removes_macos_acl() {
        let root = temp_test_root("lock-root-acl");
        if !add_macos_acl(
            &root,
            "everyone allow list,search,readattr,readextattr,readsecurity",
        ) {
            let _ = std::fs::remove_dir_all(root);
            return;
        }
        assert!(path_has_macos_acl(&root));

        prepare_lock_root(&root).unwrap();

        assert!(!path_has_macos_acl(&root));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn already_running_error_is_classified_narrowly() {
        assert!(is_already_running_error(&anyhow::anyhow!(
            "{}",
            ALREADY_RUNNING_MESSAGE
        )));
        assert!(!is_already_running_error(&anyhow::anyhow!(
            "lock root must not be a symlink"
        )));
    }

    #[cfg(all(target_os = "macos", unix))]
    #[test]
    fn local_ipc_validation_rejects_regular_file() {
        let root = temp_test_root("ipc-regular-file");
        std::fs::create_dir_all(&root).unwrap();
        let socket_path = root.join(IPC_SOCKET_FILE_NAME);
        write_test_private_text(&socket_path, "not a socket").unwrap();

        let error = validate_local_ipc_socket_path(&socket_path).unwrap_err();
        assert!(error.to_string().contains("Unix socket"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(all(target_os = "macos", unix))]
    #[test]
    fn local_ipc_validation_accepts_private_owned_socket() {
        use std::os::unix::net::UnixListener;

        let root = std::env::temp_dir().join(format!(
            "waa-ipc-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let socket_path = root.join(IPC_SOCKET_FILE_NAME);
        let _listener = UnixListener::bind(&socket_path).unwrap();
        secure_socket_permissions(&socket_path).unwrap();

        validate_local_ipc_socket_path(&socket_path).unwrap();

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(all(target_os = "macos", unix))]
    #[test]
    fn local_ipc_validation_rejects_acl_socket() {
        use std::os::unix::net::UnixListener;

        let root = std::env::temp_dir().join(format!(
            "waal-acl-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let socket_path = root.join(IPC_SOCKET_FILE_NAME);
        let _listener = UnixListener::bind(&socket_path).unwrap();
        secure_socket_permissions(&socket_path).unwrap();
        if !add_macos_acl(
            &socket_path,
            "everyone allow read,write,readattr,readextattr,readsecurity",
        ) {
            let _ = std::fs::remove_dir_all(root);
            return;
        }
        assert!(path_has_macos_acl(&socket_path));

        let error = validate_local_ipc_socket_path(&socket_path).unwrap_err();
        assert!(error.to_string().contains("ACL"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(all(target_os = "macos", unix))]
    #[test]
    fn macos_containing_app_bundle_handles_bundled_and_unbundled_paths() {
        for (path, expected) in [
            (
                PathBuf::from(
                    "/Applications/WindowsAppAutoLogin.app/Contents/MacOS/windows-app-autologin",
                ),
                Some(PathBuf::from("/Applications/WindowsAppAutoLogin.app")),
            ),
            (PathBuf::from("/tmp/windows-app-autologin"), None),
        ] {
            assert_eq!(macos_containing_app_bundle(&path), expected);
        }
    }

    #[cfg(all(target_os = "macos", unix))]
    #[test]
    fn macos_ipc_identity_requires_live_code_match_without_team_id() {
        let path = PathBuf::from(
            "/Applications/WindowsAppAutoLogin.app/Contents/MacOS/windows-app-autologin",
        );
        let mut release_verifier_called = false;
        let mut development_verifier_called = false;

        assert!(!macos_process_identity_matches_current_app(
            &path,
            &path,
            "obcardinal.windows-app-autologin",
            None,
            |_bundle_path, _bundle_id| true,
            |_bundle_path, _bundle_id, _team_id| {
                release_verifier_called = true;
                true
            },
            || {
                development_verifier_called = true;
                false
            },
        ));
        assert!(!release_verifier_called);
        assert!(development_verifier_called);

        assert!(macos_process_identity_matches_current_app(
            &path,
            &path,
            "obcardinal.windows-app-autologin",
            None,
            |_bundle_path, _bundle_id| true,
            |_bundle_path, _bundle_id, _team_id| false,
            || true,
        ));
    }

    #[cfg(all(target_os = "macos", unix))]
    #[test]
    fn macos_ipc_identity_requires_matching_bundle_identifier() {
        let path = PathBuf::from(
            "/Applications/WindowsAppAutoLogin.app/Contents/MacOS/windows-app-autologin",
        );
        let mut bundle_identifier_args = None;

        assert!(!macos_process_identity_matches_current_app(
            &path,
            &path,
            "obcardinal.windows-app-autologin",
            None,
            |bundle_path, bundle_id| {
                bundle_identifier_args = Some((bundle_path.to_path_buf(), bundle_id.to_string()));
                false
            },
            |_bundle_path, _bundle_id, _team_id| {
                panic!("release verifier must wait for matching bundle identifier")
            },
            || panic!("development verifier must wait for matching bundle identifier"),
        ));
        assert_eq!(
            bundle_identifier_args,
            Some((
                PathBuf::from("/Applications/WindowsAppAutoLogin.app"),
                "obcardinal.windows-app-autologin".to_string(),
            ))
        );
    }

    #[cfg(all(target_os = "macos", unix))]
    #[test]
    fn macos_ipc_identity_rejects_hardlink_alias_path() {
        let root = temp_test_root("macos-ipc-hardlink");
        let bundle = root.join("WindowsAppAutoLogin.app");
        let executable_dir = bundle.join("Contents/MacOS");
        std::fs::create_dir_all(&executable_dir).unwrap();
        let executable = executable_dir.join("windows-app-autologin");
        std::fs::write(&executable, "test-binary").unwrap();
        let hardlink = executable_dir.join("windows-app-autologin-hardlink");
        std::fs::hard_link(&executable, &hardlink).unwrap();

        assert!(!macos_process_identity_matches_current_app(
            &hardlink,
            &executable,
            "obcardinal.windows-app-autologin",
            None,
            |_bundle_path, _bundle_id| true,
            |_bundle_path, _bundle_id, _team_id| true,
            || panic!("development verifier must wait for exact executable path"),
        ));

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(all(target_os = "macos", unix))]
    #[test]
    fn macos_ipc_identity_rejects_symlink_bundle_path() {
        use std::os::unix::fs::symlink;

        let root = temp_test_root("macos-ipc-symlink-bundle");
        let real_bundle = root.join("Real.app");
        let real_executable_dir = real_bundle.join("Contents/MacOS");
        std::fs::create_dir_all(&real_executable_dir).unwrap();
        std::fs::write(real_executable_dir.join("windows-app-autologin"), "test").unwrap();
        let linked_bundle = root.join("WindowsAppAutoLogin.app");
        symlink(&real_bundle, &linked_bundle).unwrap();
        let linked_executable = linked_bundle.join("Contents/MacOS/windows-app-autologin");

        assert!(!macos_process_identity_matches_current_app(
            &linked_executable,
            &linked_executable,
            "obcardinal.windows-app-autologin",
            None,
            |_bundle_path, _bundle_id| true,
            |_bundle_path, _bundle_id, _team_id| true,
            || panic!("development verifier must wait for trusted bundle path"),
        ));

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(all(target_os = "macos", unix))]
    #[test]
    fn macos_ipc_identity_rejects_symlink_executable_path() {
        use std::os::unix::fs::symlink;

        let root = temp_test_root("macos-ipc-symlink-executable");
        let bundle = root.join("WindowsAppAutoLogin.app");
        let executable_dir = bundle.join("Contents/MacOS");
        std::fs::create_dir_all(&executable_dir).unwrap();
        let real_executable = executable_dir.join("windows-app-autologin-real");
        std::fs::write(&real_executable, "test").unwrap();
        let linked_executable = executable_dir.join("windows-app-autologin");
        symlink(&real_executable, &linked_executable).unwrap();

        assert!(!macos_process_identity_matches_current_app(
            &linked_executable,
            &linked_executable,
            "obcardinal.windows-app-autologin",
            None,
            |_bundle_path, _bundle_id| true,
            |_bundle_path, _bundle_id, _team_id| true,
            || panic!("development verifier must wait for a real executable path"),
        ));

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(all(target_os = "macos", unix))]
    #[test]
    fn macos_ipc_identity_rejects_unbundled_same_path() {
        let path = PathBuf::from("/tmp/windows-app-autologin");

        assert!(!macos_process_identity_matches_current_app(
            &path,
            &path,
            "obcardinal.windows-app-autologin",
            None,
            |_bundle_path, _bundle_id| true,
            |_bundle_path, _bundle_id, _team_id| true,
            || panic!("development verifier must wait for bundled executable path"),
        ));
    }

    #[cfg(all(target_os = "macos", unix))]
    #[test]
    fn macos_ipc_identity_requires_release_signature_when_team_id_is_configured() {
        let path = PathBuf::from(
            "/Applications/WindowsAppAutoLogin.app/Contents/MacOS/windows-app-autologin",
        );
        let mut verifier_args = None;

        assert!(!macos_process_identity_matches_current_app(
            &path,
            &path,
            "com.example.WindowsAppAutoLogin",
            Some("ABCDE12345"),
            |_bundle_path, _bundle_id| true,
            |bundle_path, bundle_id, team_id| {
                verifier_args = Some((
                    bundle_path.to_path_buf(),
                    bundle_id.to_string(),
                    team_id.to_string(),
                ));
                false
            },
            || panic!("development verifier must not run when Team ID is configured"),
        ));
        assert_eq!(
            verifier_args,
            Some((
                PathBuf::from("/Applications/WindowsAppAutoLogin.app"),
                "com.example.WindowsAppAutoLogin".to_string(),
                "ABCDE12345".to_string(),
            ))
        );

        assert!(macos_process_identity_matches_current_app(
            &path,
            &path,
            "com.example.WindowsAppAutoLogin",
            Some("ABCDE12345"),
            |_bundle_path, _bundle_id| true,
            |_bundle_path, _bundle_id, _team_id| true,
            || panic!("development verifier must not run when Team ID is configured"),
        ));
    }

    #[cfg(all(target_os = "macos", unix))]
    #[test]
    fn macos_ipc_identity_rejects_invalid_configured_team_id() {
        let path = PathBuf::from(
            "/Applications/WindowsAppAutoLogin.app/Contents/MacOS/windows-app-autologin",
        );

        assert!(!macos_process_identity_matches_current_app(
            &path,
            &path,
            "com.example.WindowsAppAutoLogin",
            Some("not-a-team-id"),
            |_bundle_path, _bundle_id| true,
            |_bundle_path, _bundle_id, _team_id| {
                panic!("release verifier must not run for invalid Team ID")
            },
            || panic!("invalid configured Team ID must not fall back to development IPC identity"),
        ));
    }

    #[cfg(all(target_os = "macos", unix))]
    #[test]
    fn macos_proc_pidpath_preserves_path_bytes_until_first_nul() {
        use std::os::unix::ffi::OsStrExt;

        for (buffer, expected) in [
            (
                b" /tmp/windows-app-autologin".as_slice(),
                b" /tmp/windows-app-autologin".as_slice(),
            ),
            (
                b"/tmp/windows-app-autologin ".as_slice(),
                b"/tmp/windows-app-autologin ".as_slice(),
            ),
            (b"/tmp/app \0/spoof".as_slice(), b"/tmp/app ".as_slice()),
        ] {
            let path = macos_proc_pidpath_buffer_to_path(buffer).unwrap();
            assert_eq!(path.as_os_str().as_bytes(), expected);
        }
    }

    #[cfg(all(target_os = "macos", unix))]
    #[test]
    fn stale_ipc_directory_is_rejected() {
        let root = temp_test_root("ipc-dir-rejected");
        let ipc_dir = root.join(IPC_SOCKET_FILE_NAME);
        std::fs::create_dir_all(&ipc_dir).unwrap();

        let error = remove_stale_ipc_path(&ipc_dir).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(ipc_dir.exists());

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn fresh_pidless_lock_blocks_startup_race() {
        let root = temp_test_root("fresh-pidless-lock");
        std::fs::create_dir_all(root.join(LOCK_DIR_NAME)).unwrap();

        let Err(error) = acquire_lock_dir_in_root(&root, LOCK_DIR_NAME, "already running") else {
            panic!("fresh pidless lock was reclaimed");
        };
        assert!(error.to_string().contains("already running"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(all(unix, not(target_os = "windows")))]
    #[test]
    fn lock_files_are_private() {
        use std::os::unix::fs::PermissionsExt;

        let root = temp_test_root("lock-file-permissions");
        let lock_dir = root.join(LOCK_DIR_NAME);
        create_lock(&lock_dir).unwrap();

        let dir_mode = std::fs::metadata(&lock_dir).unwrap().permissions().mode() & 0o777;
        let pid_mode = std::fs::metadata(lock_dir.join("pid"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let owner_mode = std::fs::metadata(lock_dir.join(LOCK_OWNER_FILE_NAME))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700);
        assert_eq!(pid_mode, 0o600);
        assert_eq!(owner_mode, 0o600);

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn lock_files_strip_inherited_macos_acl() {
        let root = temp_test_root("lock-file-acl");
        if !add_macos_acl(
            &root,
            "everyone allow read,readattr,readextattr,readsecurity,file_inherit,directory_inherit",
        ) {
            let _ = std::fs::remove_dir_all(root);
            return;
        }
        assert!(path_has_macos_acl(&root));

        let lock_dir = root.join(LOCK_DIR_NAME);
        create_lock(&lock_dir).unwrap();

        assert!(!path_has_macos_acl(&root));
        assert!(!path_has_macos_acl(&lock_dir));
        assert!(!path_has_macos_acl(&lock_dir.join("pid")));
        assert!(!path_has_macos_acl(&lock_dir.join(LOCK_OWNER_FILE_NAME)));
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn oversized_lock_owner_and_pid_files_are_ignored() {
        let root = temp_test_root("oversized-lock-files");
        let lock_dir = root.join(LOCK_DIR_NAME);
        std::fs::create_dir_all(&lock_dir).unwrap();
        write_test_private_text(lock_dir.join(LOCK_OWNER_FILE_NAME), "x".repeat(1024)).unwrap();
        write_test_private_text(lock_dir.join("pid"), "9".repeat(128)).unwrap();

        assert_eq!(lock_owner(&lock_dir), None);
        assert_eq!(lock_pid_file(&lock_dir), None);

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn lock_owner_requires_valid_nonce_and_pid() {
        let root = temp_test_root("invalid-owner-fields");
        let lock_dir = root.join(LOCK_DIR_NAME);
        std::fs::create_dir_all(&lock_dir).unwrap();

        write_test_private_text(
            lock_dir.join(LOCK_OWNER_FILE_NAME),
            "pid=0\nnonce=not-hex\n",
        )
        .unwrap();
        assert_eq!(lock_owner(&lock_dir), None);

        write_test_private_text(
            lock_dir.join(LOCK_OWNER_FILE_NAME),
            "pid=123\nnonce=0123456789abcdef0123456789abcdef\n",
        )
        .unwrap();
        assert_eq!(
            lock_owner(&lock_dir),
            Some(LockOwner {
                pid: 123,
                nonce: "0123456789abcdef0123456789abcdef".to_string(),
            })
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(all(unix, not(target_os = "windows")))]
    #[test]
    fn symlink_lock_owner_and_pid_files_are_ignored() {
        use std::os::unix::fs::symlink;

        let root = temp_test_root("symlink-lock-files");
        let lock_dir = root.join(LOCK_DIR_NAME);
        std::fs::create_dir_all(&lock_dir).unwrap();
        let target = root.join("target");
        std::fs::write(&target, "pid=123\nnonce=0123456789abcdef0123456789abcdef\n").unwrap();
        symlink(&target, lock_dir.join(LOCK_OWNER_FILE_NAME)).unwrap();
        symlink(&target, lock_dir.join("pid")).unwrap();

        assert_eq!(lock_owner(&lock_dir), None);
        assert_eq!(lock_pid_file(&lock_dir), None);

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    fn monitor_command_request_for_test(
        command: MonitorControlCommand,
        nonce: &str,
        auth_token: &str,
    ) -> String {
        let _ = auth_token;
        format!("{}:{}:{nonce}", command.as_str(), std::process::id())
    }

    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    fn forged_monitor_command_request_for_test(auth_token: &str) -> String {
        let _ = auth_token;
        "start_monitor:99999999:4".to_string()
    }

    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    fn consume_monitor_command_for_test(
        watcher: &mut MonitorCommandWatcher,
    ) -> Option<MonitorControlCommand> {
        watcher.consume_command()
    }

    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    #[test]
    fn monitor_command_watcher_consumes_new_commands_once() {
        let path = std::env::temp_dir().join(format!(
            "windows-app-autologin-monitor-command-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);

        let auth_token = String::new();

        let mut watcher = MonitorCommandWatcher::for_path(path.clone());

        assert_eq!(consume_monitor_command_for_test(&mut watcher), None);
        write_test_private_text(
            &path,
            monitor_command_request_for_test(MonitorControlCommand::Start, "1", &auth_token),
        )
        .unwrap();
        assert_eq!(
            consume_monitor_command_for_test(&mut watcher),
            Some(MonitorControlCommand::Start)
        );
        assert_eq!(consume_monitor_command_for_test(&mut watcher), None);

        write_test_private_text(
            &path,
            monitor_command_request_for_test(MonitorControlCommand::Stop, "2", &auth_token),
        )
        .unwrap();
        assert_eq!(
            consume_monitor_command_for_test(&mut watcher),
            Some(MonitorControlCommand::Stop)
        );

        write_test_private_text(
            &path,
            monitor_command_request_for_test(
                MonitorControlCommand::StorageRecoveryBlocked,
                "3",
                &auth_token,
            ),
        )
        .unwrap();
        assert_eq!(
            consume_monitor_command_for_test(&mut watcher),
            Some(MonitorControlCommand::StorageRecoveryBlocked)
        );

        write_test_private_text(
            &path,
            monitor_command_request_for_test(MonitorControlCommand::ReloadConfig, "4", &auth_token),
        )
        .unwrap();
        assert_eq!(
            consume_monitor_command_for_test(&mut watcher),
            Some(MonitorControlCommand::ReloadConfig)
        );

        write_test_private_text(&path, forged_monitor_command_request_for_test(&auth_token))
            .unwrap();
        assert_eq!(consume_monitor_command_for_test(&mut watcher), None);

        let _ = std::fs::remove_file(path);
    }

    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    #[test]
    fn monitor_command_requires_pid_and_nonce() {
        assert_eq!(MonitorControlCommand::from_request("start_monitor"), None);
        assert_eq!(
            MonitorControlCommand::from_request(&format!("start_monitor:{}", std::process::id())),
            None
        );
        assert_eq!(
            MonitorControlCommand::from_request(&format!("start_monitor:{}:", std::process::id())),
            None
        );
        assert_eq!(
            MonitorControlCommand::from_request(&format!(
                "start_monitor:{}:abc",
                std::process::id()
            )),
            None
        );
        assert_eq!(
            MonitorControlCommand::from_request(&format!(
                "start_monitor:{}:1:extra",
                std::process::id()
            )),
            None
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_monitor_control_uses_peer_bound_local_ipc_without_env_token() {
        let implementation = include_str!("single_instance.rs");
        let request_monitor = source_between(
            implementation,
            "pub(crate) fn request_monitor_command(",
            "pub(crate) fn request_config_reload()",
        );
        let windows_server = source_between(
            implementation,
            "#[cfg(target_os = \"windows\")]\nimpl LocalIpcServer",
            "impl Drop for SingleInstanceGuard",
        );

        assert!(request_monitor.contains("send_local_ipc_command"));
        assert!(!request_monitor.contains("write_private_text(&monitor_command_path()?"));
        assert!(!implementation.contains(concat!("monitor_", "control_token_from_env")));
        assert!(!implementation.contains(concat!("signed_", "monitor_command_request")));
        assert!(windows_server.contains("GetNamedPipeClientProcessId"));
        assert!(windows_server.contains("process_looks_like_this_app(peer_pid)"));
    }

    #[test]
    fn windows_sibling_ipc_keeps_path_and_exact_spawned_pid_authorization_layers() {
        let implementation = include_str!("single_instance.rs");
        let windows_process_identity = source_between(
            implementation,
            "#[cfg(target_os = \"windows\")]\nfn process_looks_like_this_app(pid: u32)",
            "#[cfg(all(unix, not(target_os = \"macos\")))]",
        );
        let windows_server = source_between(
            implementation,
            "#[cfg(target_os = \"windows\")]\nimpl LocalIpcServer",
            "impl Drop for SingleInstanceGuard",
        );
        let windows_client = source_between(
            implementation,
            "#[cfg(target_os = \"windows\")]\nfn send_local_ipc_command(command: &str)",
            "#[cfg(target_os = \"windows\")]\nfn read_windows_local_ipc_ack",
        );
        let main = include_str!("main.rs");
        let authorization = source_between(
            main,
            "fn local_ipc_command_authorized(",
            "fn initial_full_ui_tab(",
        );

        assert!(windows_process_identity.contains("windows_process_path(pid)"));
        assert!(windows_process_identity
            .contains("app_identity::windows_local_ipc_peer_path_is_trusted"));
        assert!(windows_server.contains("GetNamedPipeClientProcessId"));
        assert!(windows_server.contains("process_looks_like_this_app(peer_pid)"));
        assert!(windows_client.contains("validate_windows_local_ipc_server(pipe.0)?"));
        assert!(authorization.contains("Some(peer_pid) == settings_child_pid"));
        assert!(authorization.contains("settings_child_bootstrapped"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_local_ipc_client_waits_for_supervisor_acknowledgement() {
        let implementation = include_str!("single_instance.rs");
        let send_command = source_between(
            implementation,
            "#[cfg(target_os = \"windows\")]\nfn send_local_ipc_command(command: &str)",
            "#[cfg(target_os = \"windows\")]\nfn read_windows_local_ipc_ack",
        );
        let consume_command = source_between(
            implementation,
            "fn consume_one_command(&mut self)",
            "fn reset_pipe(&mut self)",
        );
        let main_source = include_str!("main.rs");
        let supervisor_dispatch = source_between(
            main_source,
            "fn process_local_ipc_commands(&mut self)",
            "fn handle_authorized_local_ipc_command",
        );

        assert!(
            send_command.contains("read_windows_local_ipc_ack(pipe.0, acknowledgement_timeout)?;")
        );
        assert!(
            send_command.find("WriteFile(").unwrap()
                < send_command
                    .find("read_windows_local_ipc_ack(pipe.0, acknowledgement_timeout)?;")
                    .unwrap()
        );
        assert!(consume_command.contains("let acknowledgement = self.pipe.take();"));
        let commit = supervisor_dispatch
            .find("if !self.handle_authorized_local_ipc_command(peer_command.command)")
            .unwrap();
        let reject_without_ack = commit + supervisor_dispatch[commit..].find("continue;").unwrap();
        let acknowledge = reject_without_ack
            + supervisor_dispatch[reject_without_ack..]
                .find("peer_command.acknowledge()")
                .unwrap();
        assert!(
            commit < reject_without_ack && reject_without_ack < acknowledge,
            "failed local IPC commit must be dropped before acknowledgement"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_local_ipc_client_waits_for_authorized_supervisor_commit() {
        let implementation = include_str!("single_instance.rs");
        let send_command = source_between(
            implementation,
            "#[cfg(target_os = \"macos\")]\nfn send_local_ipc_command(command: &str)",
            "#[cfg(target_os = \"macos\")]\nfn read_macos_local_ipc_ack",
        );
        let consume_command = source_between(
            implementation,
            "fn local_ipc_command_from_validated_stream(",
            "fn read_local_ipc_challenge(",
        );
        let main_source = include_str!("main.rs");
        let supervisor_dispatch = source_between(
            main_source,
            "fn process_local_ipc_commands(&mut self)",
            "fn handle_authorized_local_ipc_command",
        );

        assert!(send_command
            .contains("read_macos_local_ipc_ack(&mut stream, acknowledgement_timeout)?;"));
        assert!(
            send_command.find("stream.write_all(").unwrap()
                < send_command
                    .find("read_macos_local_ipc_ack(&mut stream, acknowledgement_timeout)?;")
                    .unwrap()
        );
        assert!(consume_command.contains("acknowledgement: Some(stream)"));

        let commit = supervisor_dispatch
            .find("if !self.handle_authorized_local_ipc_command(peer_command.command)")
            .unwrap();
        let reject_without_ack = commit + supervisor_dispatch[commit..].find("continue;").unwrap();
        let acknowledge = reject_without_ack
            + supervisor_dispatch[reject_without_ack..]
                .find("peer_command.acknowledge()")
                .unwrap();
        assert!(commit < reject_without_ack);
        assert!(reject_without_ack < acknowledge);
    }

    #[cfg(all(target_os = "macos", unix))]
    #[test]
    fn macos_fragmented_local_ipc_command_is_reassembled_before_parsing() {
        let (server_stream, mut client_stream) = UnixStream::pair().unwrap();
        let client = std::thread::spawn(move || {
            let challenge = read_local_ipc_challenge(&mut client_stream).unwrap();
            let response = format!("{challenge}:{IPC_COMMAND_ACTIVATE}\n");
            for chunk in response.as_bytes().chunks(3) {
                client_stream.write_all(chunk).unwrap();
                std::thread::sleep(Duration::from_millis(2));
            }
            read_macos_local_ipc_ack(&mut client_stream, Duration::from_secs(1)).unwrap();
        });

        let peer_command =
            local_ipc_command_from_validated_stream(server_stream, std::process::id())
                .unwrap()
                .expect("fragmented validated local IPC command");
        assert_eq!(peer_command.command, LocalIpcCommand::Activate);
        peer_command.acknowledge().unwrap();
        client.join().unwrap();
    }

    #[cfg(all(target_os = "macos", unix))]
    #[test]
    fn macos_local_ipc_rejects_an_overlong_fragmented_command() {
        let (server_stream, mut client_stream) = UnixStream::pair().unwrap();
        let client = std::thread::spawn(move || {
            let _ = read_local_ipc_challenge(&mut client_stream).unwrap();
            let response = [b'x'; MACOS_LOCAL_IPC_MAX_BYTES + 1];
            for chunk in response.chunks(7) {
                client_stream.write_all(chunk).unwrap();
            }
        });

        assert!(
            local_ipc_command_from_validated_stream(server_stream, std::process::id())
                .unwrap()
                .is_none()
        );
        client.join().unwrap();
    }

    #[cfg(all(target_os = "macos", unix))]
    #[test]
    fn macos_immediate_child_exit_waits_until_supervisor_acknowledgement() {
        use std::sync::mpsc::RecvTimeoutError;

        let (server_stream, mut client_stream) = UnixStream::pair().unwrap();
        let (result_tx, result_rx) = std::sync::mpsc::channel();
        let client = std::thread::spawn(move || {
            client_stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            client_stream
                .set_write_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let result = (|| {
                let challenge = read_local_ipc_challenge(&mut client_stream).map_err(|error| {
                    anyhow::anyhow!("could not read test IPC challenge: {error}")
                })?;
                client_stream
                    .write_all(format!("{challenge}:{IPC_COMMAND_ACTIVATE}\n").as_bytes())
                    .map_err(|error| {
                        anyhow::anyhow!("could not write test IPC command: {error}")
                    })?;
                client_stream.shutdown(Shutdown::Write).map_err(|error| {
                    anyhow::anyhow!("could not shut down test IPC command stream: {error}")
                })?;
                read_macos_local_ipc_ack(&mut client_stream, Duration::from_secs(1))
                    .map_err(|error| anyhow::anyhow!("could not read test IPC ack: {error}"))
            })()
            .map_err(|error: anyhow::Error| error.to_string());
            result_tx.send(result).unwrap();
        });

        let peer_command =
            local_ipc_command_from_validated_stream(server_stream, std::process::id())
                .unwrap()
                .expect("validated local IPC command");
        assert_eq!(peer_command.peer_pid, std::process::id());
        assert_eq!(peer_command.command, LocalIpcCommand::Activate);
        assert!(matches!(
            result_rx.recv_timeout(Duration::from_millis(100)),
            Err(RecvTimeoutError::Timeout)
        ));

        peer_command.acknowledge().unwrap();
        let result = result_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("macOS local IPC client did not finish after acknowledgement");
        assert!(result.is_ok(), "macOS local IPC client failed: {result:?}");
        client.join().unwrap();
    }

    #[cfg(all(target_os = "macos", unix))]
    #[test]
    fn macos_rejected_command_drop_cannot_report_acknowledged_success() {
        let (server_stream, mut client_stream) = UnixStream::pair().unwrap();
        let (result_tx, result_rx) = std::sync::mpsc::channel();
        let client = std::thread::spawn(move || {
            client_stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let result = (|| {
                let challenge = read_local_ipc_challenge(&mut client_stream)?;
                client_stream
                    .write_all(format!("{challenge}:{IPC_COMMAND_ACTIVATE}\n").as_bytes())?;
                client_stream.shutdown(Shutdown::Write)?;
                read_macos_local_ipc_ack(&mut client_stream, Duration::from_secs(1))
            })()
            .map_err(|error: anyhow::Error| error.to_string());
            result_tx.send(result).unwrap();
        });

        let peer_command =
            local_ipc_command_from_validated_stream(server_stream, std::process::id())
                .unwrap()
                .expect("validated local IPC command");
        drop(peer_command);

        assert!(result_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("macOS local IPC client remained blocked after rejection")
            .is_err());
        client.join().unwrap();
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_local_ipc_send_cannot_succeed_before_supervisor_acknowledgement() {
        use std::sync::mpsc::RecvTimeoutError;

        let mut server = LocalIpcServer::bind().unwrap();
        let (result_tx, result_rx) = std::sync::mpsc::channel();
        let client = std::thread::spawn(move || {
            let result =
                send_local_ipc_command(IPC_COMMAND_ACTIVATE).map_err(|error| error.to_string());
            result_tx.send(result).unwrap();
        });

        let started = Instant::now();
        let peer_command = loop {
            if let Some(command) = server.consume_commands().into_iter().next() {
                break command;
            }
            assert!(
                started.elapsed() < Duration::from_secs(1),
                "Windows local IPC server did not receive the test command"
            );
            std::thread::sleep(Duration::from_millis(10));
        };

        assert_eq!(peer_command.command, LocalIpcCommand::Activate);
        assert!(matches!(
            result_rx.recv_timeout(Duration::from_millis(100)),
            Err(RecvTimeoutError::Timeout)
        ));

        peer_command.acknowledge().unwrap();
        assert!(result_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("Windows local IPC client did not finish after acknowledgement")
            .is_ok());
        client.join().unwrap();
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_local_ipc_rejects_legacy_monitor_file_payloads() {
        assert_eq!(
            parse_local_ipc_command("monitor:start_monitor"),
            Some(LocalIpcCommand::Monitor(MonitorControlCommand::Start))
        );
        assert_eq!(
            parse_local_ipc_command("monitor:storage_recovery_blocked"),
            Some(LocalIpcCommand::Monitor(
                MonitorControlCommand::StorageRecoveryBlocked
            ))
        );
        assert_eq!(
            parse_local_ipc_command("config:reload"),
            Some(LocalIpcCommand::ReloadConfig)
        );
        assert_eq!(parse_local_ipc_command("start_monitor:123:1"), None);
        assert_eq!(
            parse_local_ipc_command("monitor:start_monitor:old-token"),
            None
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_activation_uses_peer_bound_local_ipc_without_file_fallback() {
        let implementation = include_str!("single_instance.rs");
        let main_source = include_str!("main.rs");
        let request_activation = source_between(
            implementation,
            "pub(crate) fn request_activation()",
            "pub(crate) fn request_monitor_command(",
        );
        let about_to_wait = source_between(main_source, "fn about_to_wait", "fn exiting");

        assert!(request_activation
            .contains("#[cfg(any(target_os = \"macos\", target_os = \"windows\"))]"));
        assert!(request_activation.contains("send_local_ipc_command(IPC_COMMAND_ACTIVATE)"));
        assert!(request_activation
            .contains("#[cfg(all(not(target_os = \"macos\"), not(target_os = \"windows\")))]"));
        assert!(!request_activation.contains("#[cfg(not(target_os = \"macos\"))]"));
        assert!(implementation.contains(
            "#[cfg(all(not(target_os = \"macos\"), not(target_os = \"windows\")))]\npub(crate) struct ActivationWatcher"
        ));
        assert!(!implementation
            .contains("#[cfg(not(target_os = \"macos\"))]\npub(crate) struct ActivationWatcher"));
        assert!(about_to_wait.contains("self.process_local_ipc_commands();"));
        assert!(about_to_wait
            .contains("#[cfg(all(not(target_os = \"macos\"), not(target_os = \"windows\")))]"));
        assert!(!about_to_wait.contains(
            "#[cfg(target_os = \"windows\")]\n        self.process_activation_requests();"
        ));
    }

    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    #[test]
    fn monitor_command_watcher_ignores_oversized_content() {
        let path = std::env::temp_dir().join(format!(
            "windows-app-autologin-monitor-command-oversized-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        write_test_private_text(&path, "x".repeat((MAX_MONITOR_COMMAND_BYTES + 1) as usize))
            .unwrap();
        let mut watcher = MonitorCommandWatcher::for_path(path.clone());

        assert_eq!(consume_monitor_command_for_test(&mut watcher), None);

        let _ = std::fs::remove_file(path);
    }

    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    #[test]
    fn activation_watcher_ignores_oversized_content() {
        let path = std::env::temp_dir().join(format!(
            "windows-app-autologin-activation-oversized-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let mut watcher = ActivationWatcher::for_path(path.clone());
        write_test_private_text(
            &path,
            "x".repeat((MAX_ACTIVATION_REQUEST_BYTES + 1) as usize),
        )
        .unwrap();

        assert!(!watcher.consume_activation_request());

        let _ = std::fs::remove_file(path);
    }

    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    #[test]
    fn activation_request_requires_valid_pid_nonce_and_path() {
        assert!(!activation_request_is_valid("0:1:/tmp/app"));
        assert!(!activation_request_is_valid(&format!(
            "{}::{}",
            std::process::id(),
            std::env::current_exe().unwrap().display()
        )));
        assert!(!activation_request_is_valid(&format!(
            "{}:abc:{}",
            std::process::id(),
            std::env::current_exe().unwrap().display()
        )));
        assert!(!activation_request_is_valid(&format!(
            "{}:1:{}\nextra",
            std::process::id(),
            std::env::current_exe().unwrap().display()
        )));
    }

    #[test]
    fn monitor_status_ignores_non_regular_or_oversized_file() {
        let status_path = std::env::temp_dir().join(format!(
            "windows-app-autologin-monitor-status-oversized-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&status_path);
        write_test_private_text(
            &status_path,
            "x".repeat((MAX_MONITOR_STATUS_BYTES + 1) as usize),
        )
        .unwrap();

        assert!(
            read_private_text_limited(&status_path, MAX_MONITOR_STATUS_BYTES)
                .unwrap()
                .is_none()
        );

        let _ = std::fs::remove_file(status_path);
    }

    #[test]
    fn private_status_write_overwrites_existing_status() {
        let root = temp_test_root("status-file-overwrite");
        let status_path = root.join(MONITOR_STATUS_FILE_NAME);

        write_private_text(&status_path, "idle\n").unwrap();
        write_private_text(&status_path, "running\n").unwrap();

        assert_eq!(
            read_private_text_limited(&status_path, MAX_MONITOR_STATUS_BYTES)
                .unwrap()
                .as_deref(),
            Some("running\n")
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn private_status_write_strips_inherited_macos_acl() {
        let root = temp_test_root("status-file-acl");
        if !add_macos_acl(
            &root,
            "everyone allow read,readattr,readextattr,readsecurity,file_inherit,directory_inherit",
        ) {
            let _ = std::fs::remove_dir_all(root);
            return;
        }
        assert!(path_has_macos_acl(&root));

        let status_path = root.join(MONITOR_STATUS_FILE_NAME);
        write_private_text(&status_path, "running\n").unwrap();

        assert!(!path_has_macos_acl(&root));
        assert!(!path_has_macos_acl(&status_path));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn monitor_status_accepts_only_consistent_bounded_control_snapshots() {
        for state in [
            MonitorControlState::Running,
            MonitorControlState::PausedWithStartIntent,
            MonitorControlState::Stopped,
        ] {
            assert_eq!(
                parse_monitor_control_state(monitor_control_state_status(state)),
                Some(state)
            );
        }

        assert_eq!(
            parse_monitor_control_state("running\nstop\n"),
            Some(MonitorControlState::Running)
        );
        assert_eq!(
            parse_monitor_control_state("idle\nstop\n"),
            Some(MonitorControlState::PausedWithStartIntent)
        );
        assert_eq!(
            parse_monitor_control_state("idle\nstart\n"),
            Some(MonitorControlState::Stopped)
        );
        assert_eq!(
            parse_monitor_control_state("running\n"),
            Some(MonitorControlState::Running)
        );
        assert_eq!(
            parse_monitor_control_state("idle\n"),
            Some(MonitorControlState::Stopped)
        );
        assert_eq!(parse_monitor_control_state("running\nstart\n"), None);
        assert_eq!(parse_monitor_control_state("paused\nstop\n"), None);
        assert_eq!(parse_monitor_control_state("RUNNING\n"), None);
        assert_eq!(parse_monitor_control_state("running:extra\n"), None);
        assert_eq!(parse_monitor_control_state("running\0\n"), None);
        assert_eq!(
            parse_monitor_control_state(&"running".repeat(MAX_MONITOR_STATUS_BYTES as usize)),
            None
        );
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    #[test]
    fn local_ipc_parses_monitor_and_activation_commands() {
        assert_eq!(
            parse_local_ipc_command("activate\n"),
            Some(LocalIpcCommand::Activate)
        );
        assert_eq!(
            parse_local_ipc_command("settings:bootstrap\n"),
            Some(LocalIpcCommand::SettingsBootstrap)
        );
        assert_eq!(
            parse_local_ipc_command("monitor:start_monitor"),
            Some(LocalIpcCommand::Monitor(MonitorControlCommand::Start))
        );
        assert_eq!(
            parse_local_ipc_command("monitor:storage_recovery_blocked"),
            Some(LocalIpcCommand::Monitor(
                MonitorControlCommand::StorageRecoveryBlocked
            ))
        );
        assert_eq!(
            parse_local_ipc_command("config:reload"),
            Some(LocalIpcCommand::ReloadConfig)
        );
        assert_eq!(parse_local_ipc_command("config:reload:old-token"), None);
        assert_eq!(
            parse_local_ipc_command("settings:bootstrap:copied-token"),
            None
        );
        assert_eq!(
            parse_local_ipc_command("monitor:start_monitor:old-token"),
            None
        );
        assert_eq!(parse_local_ipc_command("start_monitor:123:nonce"), None);
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    #[test]
    fn settings_bootstrap_retries_a_registration_race_but_remains_bounded() {
        let attempts = std::cell::Cell::new(0);
        let waits = std::cell::Cell::new(0);
        request_settings_bootstrap_with_retry(
            || {
                let attempt = attempts.get() + 1;
                attempts.set(attempt);
                if attempt < 3 {
                    anyhow::bail!("child handle is not registered yet")
                }
                Ok(())
            },
            || waits.set(waits.get() + 1),
        )
        .unwrap();

        assert_eq!(attempts.get(), 3);
        assert_eq!(waits.get(), 2);
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    #[test]
    fn settings_bootstrap_fails_closed_when_local_ipc_never_acknowledges() {
        let attempts = std::cell::Cell::new(0);
        let waits = std::cell::Cell::new(0);
        let error = request_settings_bootstrap_with_retry(
            || {
                attempts.set(attempts.get() + 1);
                anyhow::bail!("local IPC is unavailable")
            },
            || waits.set(waits.get() + 1),
        )
        .unwrap_err();

        assert_eq!(attempts.get(), SETTINGS_BOOTSTRAP_MAX_ATTEMPTS);
        assert_eq!(waits.get(), SETTINGS_BOOTSTRAP_MAX_ATTEMPTS - 1);
        assert!(error.to_string().contains("was not acknowledged"));
        assert!(error.to_string().contains("local IPC is unavailable"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn local_ipc_challenge_response_requires_matching_nonce() {
        let challenge = "0123456789abcdef0123456789abcdef";

        assert_eq!(
            parse_local_ipc_challenge_response(
                "0123456789abcdef0123456789abcdef:activate\n",
                challenge
            ),
            Some(LocalIpcCommand::Activate)
        );
        assert_eq!(
            parse_local_ipc_challenge_response(
                "fedcba9876543210fedcba9876543210:activate\n",
                challenge
            ),
            None
        );
        assert_eq!(
            parse_local_ipc_challenge_response("activate\n", challenge),
            None
        );
    }

    #[cfg(all(target_os = "macos", unix))]
    #[test]
    fn local_ipc_accepts_challenge_response_command() {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream;

        let (server_stream, mut client_stream) = UnixStream::pair().unwrap();
        let server = std::thread::spawn(move || {
            local_ipc_command_from_validated_stream(server_stream, std::process::id())
        });
        let mut challenge = String::new();
        let mut byte = [0_u8; 1];
        while client_stream.read(&mut byte).unwrap() == 1 && byte[0] != b'\n' {
            challenge.push(byte[0] as char);
        }
        client_stream
            .write_all(format!("{challenge}:activate\n").as_bytes())
            .unwrap();

        let peer_command = server
            .join()
            .unwrap()
            .unwrap()
            .expect("validated local IPC command");
        assert_eq!(peer_command.peer_pid, std::process::id());
        assert_eq!(peer_command.command, LocalIpcCommand::Activate);
    }

    #[cfg(all(target_os = "macos", unix))]
    #[test]
    fn local_ipc_rejects_prebuffered_command_without_challenge() {
        use std::io::Write;
        use std::os::unix::net::UnixStream;

        let (server_stream, mut client_stream) = UnixStream::pair().unwrap();
        client_stream.write_all(b"activate\n").unwrap();

        assert!(
            local_ipc_command_from_validated_stream(server_stream, std::process::id())
                .unwrap()
                .is_none()
        );
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    fn source_between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
        let start_index = source.find(start).expect("source start marker");
        let end_index = source[start_index..]
            .find(end)
            .map(|offset| start_index + offset)
            .expect("source end marker");
        &source[start_index..end_index]
    }

    fn temp_test_root(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "windows-app-autologin-{name}-{}-{nonce}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    #[cfg(all(unix, not(target_os = "windows")))]
    fn test_lock_file(root: &Path) -> std::fs::File {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(root.join("test-held-lock"))
            .unwrap()
    }

    fn write_test_private_text(
        path: impl AsRef<Path>,
        content: impl AsRef<[u8]>,
    ) -> std::io::Result<()> {
        let path = path.as_ref();
        std::fs::write(path, content)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = std::fs::metadata(path)?.permissions();
            permissions.set_mode(0o600);
            std::fs::set_permissions(path, permissions)?;
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn add_macos_acl(path: &Path, acl: &str) -> bool {
        let output = std::process::Command::new("/bin/chmod")
            .arg("+a")
            .arg(acl)
            .arg(path)
            .output();
        match output {
            Ok(output) if output.status.success() => true,
            Ok(output) => {
                eprintln!(
                    "skipping macOS ACL assertion; chmod +a failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                false
            }
            Err(error) => {
                eprintln!("skipping macOS ACL assertion; chmod unavailable: {error}");
                false
            }
        }
    }

    #[cfg(target_os = "macos")]
    fn path_has_macos_acl(path: &Path) -> bool {
        crate::private_permissions::path_has_macos_acl(path).unwrap()
    }
}
