use std::path::{Path, PathBuf};
#[cfg(target_os = "macos")]
use std::time::Duration;
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
use windows::core::{PCWSTR, PWSTR};
#[cfg(target_os = "windows")]
use windows::Win32::Foundation::{CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, HANDLE};
#[cfg(target_os = "windows")]
use windows::Win32::System::Threading::{
    CreateMutexW, OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

#[cfg(not(target_os = "windows"))]
const LOCK_DIR_NAME: &str = "WindowsAppAutoLogin.lock";
#[cfg(target_os = "macos")]
const FULL_UI_LOCK_DIR_NAME: &str = "WindowsAppAutoLogin.full-ui.lock";
#[cfg(not(target_os = "macos"))]
const ACTIVATION_FILE_NAME: &str = "activate";
#[cfg(not(target_os = "macos"))]
const MONITOR_COMMAND_FILE_NAME: &str = "monitor-command";
const MONITOR_STATUS_FILE_NAME: &str = "monitor-status";
#[cfg(not(target_os = "windows"))]
const LOCK_OWNER_FILE_NAME: &str = "owner";
const MONITOR_COMMAND_START: &str = "start_monitor";
const MONITOR_COMMAND_STOP: &str = "stop_monitor";
#[cfg(not(target_os = "macos"))]
const MONITOR_COMMAND_RELOAD_CONFIG: &str = "reload_config";
const ALREADY_RUNNING_MESSAGE: &str = "Windows App AutoLogin is already running";
#[cfg(target_os = "macos")]
const FULL_UI_ALREADY_RUNNING_MESSAGE: &str = "Windows App AutoLogin window is already open";
#[cfg(not(target_os = "windows"))]
const MAX_LOCK_OWNER_BYTES: u64 = 256;
#[cfg(not(target_os = "windows"))]
const MAX_LOCK_PID_BYTES: u64 = 32;
const MAX_MONITOR_STATUS_BYTES: u64 = 32;
#[cfg(not(target_os = "macos"))]
const MAX_MONITOR_COMMAND_BYTES: u64 = 256;
#[cfg(not(target_os = "macos"))]
const MAX_ACTIVATION_REQUEST_BYTES: u64 = 4096;
#[cfg(target_os = "windows")]
pub(crate) const MONITOR_CONTROL_TOKEN_ENV: &str = "WAAL_MONITOR_CONTROL_TOKEN";
#[cfg(target_os = "macos")]
const IPC_SOCKET_FILE_NAME: &str = "ipc.sock";
#[cfg(target_os = "macos")]
const MAX_IPC_COMMANDS_PER_TICK: usize = 16;
#[cfg(target_os = "macos")]
const IPC_COMMAND_ACTIVATE: &str = "activate";
#[cfg(target_os = "macos")]
const IPC_COMMAND_MONITOR_PREFIX: &str = "monitor:";
#[cfg(target_os = "macos")]
const IPC_COMMAND_RELOAD_CONFIG: &str = "config:reload";
#[cfg(target_os = "windows")]
const WINDOWS_SINGLE_INSTANCE_MUTEX: &str = "Local\\WindowsAppAutoLogin.SingleInstance";
#[cfg(target_os = "macos")]
static CURRENT_EXECUTABLE_PATH: OnceLock<Option<PathBuf>> = OnceLock::new();
#[cfg(target_os = "macos")]
static CURRENT_CODE_UNIQUE_IDENTIFIER: OnceLock<Option<Vec<u8>>> = OnceLock::new();

pub(crate) struct SingleInstanceGuard {
    #[cfg(target_os = "windows")]
    mutex: HANDLE,
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

#[cfg(target_os = "macos")]
pub(crate) struct LocalIpcServer {
    listener: UnixListener,
    path: PathBuf,
    socket_identity: LocalIpcSocketIdentity,
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LocalIpcCommand {
    Activate,
    ReloadConfig,
    Monitor(MonitorControlCommand),
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PeerLocalIpcCommand {
    pub(crate) peer_pid: u32,
    pub(crate) command: LocalIpcCommand,
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LocalIpcSocketIdentity {
    dev: u64,
    ino: u64,
    uid: u32,
}

#[cfg(not(target_os = "macos"))]
pub(crate) struct FullUiInstanceGuard;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MonitorControlCommand {
    Start,
    Stop,
    #[cfg(not(target_os = "macos"))]
    ReloadConfig,
}

impl MonitorControlCommand {
    fn as_str(self) -> &'static str {
        match self {
            Self::Start => MONITOR_COMMAND_START,
            Self::Stop => MONITOR_COMMAND_STOP,
            #[cfg(not(target_os = "macos"))]
            Self::ReloadConfig => MONITOR_COMMAND_RELOAD_CONFIG,
        }
    }

    #[cfg(not(target_os = "macos"))]
    #[cfg_attr(target_os = "windows", allow(dead_code))]
    fn from_request(value: &str) -> Option<Self> {
        #[cfg(target_os = "windows")]
        {
            return Self::from_request_with_token(
                value,
                monitor_control_token_from_env()?.as_str(),
            );
        }

        #[cfg(not(target_os = "windows"))]
        {
            Self::from_legacy_request(value)
        }
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

    #[cfg(target_os = "windows")]
    fn from_request_with_token(value: &str, auth_token: &str) -> Option<Self> {
        if value.len() > MAX_MONITOR_COMMAND_BYTES as usize {
            return None;
        }
        if parse_nonce_field(auth_token).is_none() {
            return None;
        }

        let mut parts = value.trim().split(':');
        let command = parts.next()?.trim();
        let pid = parts.next().and_then(|pid| parse_pid_field(pid.trim()))?;
        let nonce = parts.next()?.trim();
        parse_nonce_field(nonce)?;
        let signature = parts.next()?.trim();
        if parts.next().is_some() {
            return None;
        }
        if !process_looks_like_this_app(pid) {
            return None;
        }
        if !monitor_command_signature_matches(auth_token, command, pid, nonce, signature) {
            return None;
        }
        Self::from_command_name(command)
    }

    fn from_command_name(command: &str) -> Option<Self> {
        match command {
            MONITOR_COMMAND_START => Some(Self::Start),
            MONITOR_COMMAND_STOP => Some(Self::Stop),
            #[cfg(not(target_os = "macos"))]
            MONITOR_COMMAND_RELOAD_CONFIG => Some(Self::ReloadConfig),
            _ => None,
        }
    }
}

#[cfg(not(target_os = "macos"))]
pub(crate) struct MonitorCommandWatcher {
    path: Option<PathBuf>,
    last_content: Option<String>,
    #[cfg(target_os = "windows")]
    auth_token: String,
}

pub(crate) fn is_already_running_error(error: &anyhow::Error) -> bool {
    let message = error.to_string();
    message == ALREADY_RUNNING_MESSAGE || {
        #[cfg(target_os = "macos")]
        {
            message == FULL_UI_ALREADY_RUNNING_MESSAGE
        }
        #[cfg(not(target_os = "macos"))]
        {
            false
        }
    }
}

impl SingleInstanceGuard {
    pub(crate) fn acquire() -> anyhow::Result<Self> {
        #[cfg(target_os = "windows")]
        {
            acquire_windows_single_instance(WINDOWS_SINGLE_INSTANCE_MUTEX)
        }

        #[cfg(not(target_os = "windows"))]
        acquire_lock_dir()
    }

    #[cfg(target_os = "macos")]
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
            return Ok(Self {
                lock_nonce: lock_owner(&lock_dir)
                    .map(|owner| owner.nonce)
                    .unwrap_or_default(),
                _lock_file: lock_file,
                lock_dir,
            });
        }

        #[cfg(not(target_os = "macos"))]
        Ok(Self)
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
        return Ok(SingleInstanceGuard {
            lock_dir,
            lock_nonce,
            _lock_file: lock_file,
            ipc_server,
        });
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

#[cfg(not(target_os = "windows"))]
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
            std::fs::remove_file(root).or_else(|_| std::fs::remove_dir_all(root))?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    std::fs::create_dir_all(root)?;
    secure_dir_permissions(root)
}

#[cfg(target_os = "macos")]
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
fn acquire_windows_single_instance(name: &str) -> anyhow::Result<SingleInstanceGuard> {
    let name = wide_null(name);
    let mutex = unsafe { CreateMutexW(None, false, PCWSTR(name.as_ptr()))? };
    if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        let _ = unsafe { CloseHandle(mutex) };
        anyhow::bail!("{}", ALREADY_RUNNING_MESSAGE);
    }

    Ok(SingleInstanceGuard { mutex })
}

#[cfg(target_os = "windows")]
fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

pub(crate) fn request_activation() -> anyhow::Result<()> {
    #[cfg(target_os = "macos")]
    {
        return send_local_ipc_command(IPC_COMMAND_ACTIVATE);
    }

    #[cfg(not(target_os = "macos"))]
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

pub(crate) fn request_monitor_command(command: MonitorControlCommand) -> anyhow::Result<()> {
    #[cfg(target_os = "macos")]
    {
        return send_local_ipc_command(&format!(
            "{IPC_COMMAND_MONITOR_PREFIX}{}",
            command.as_str()
        ));
    }

    #[cfg(target_os = "windows")]
    {
        let token = monitor_control_token_from_env()
            .ok_or_else(|| anyhow::anyhow!("monitor control token is unavailable"))?;
        let nonce = random_nonce();
        let body = signed_monitor_command_request(
            command.as_str(),
            std::process::id(),
            &nonce,
            token.as_str(),
        );
        write_private_text(&monitor_command_path()?, &body)
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
    #[cfg(target_os = "macos")]
    {
        return send_local_ipc_command(IPC_COMMAND_RELOAD_CONFIG);
    }

    #[cfg(not(target_os = "macos"))]
    {
        request_monitor_command(MonitorControlCommand::ReloadConfig)
    }
}

pub(crate) fn write_monitor_status(running: bool) -> anyhow::Result<()> {
    write_private_text(
        &monitor_status_path()?,
        if running { "running\n" } else { "idle\n" },
    )
}

pub(crate) fn read_monitor_status() -> Option<bool> {
    let status = read_private_text_limited(&monitor_status_path().ok()?, MAX_MONITOR_STATUS_BYTES)
        .ok()
        .flatten()?;
    parse_monitor_status(&status)
}

fn parse_monitor_status(status: &str) -> Option<bool> {
    if status.len() > MAX_MONITOR_STATUS_BYTES as usize {
        return None;
    }
    match status.trim() {
        "running" => Some(true),
        "idle" => Some(false),
        _ => None,
    }
}

#[cfg(not(target_os = "macos"))]
impl MonitorCommandWatcher {
    pub(crate) fn new() -> Self {
        let path = monitor_command_path().ok();
        let last_content = path
            .as_deref()
            .and_then(|path| read_private_text_limited(path, MAX_MONITOR_COMMAND_BYTES).ok())
            .flatten();

        Self {
            path,
            last_content,
            #[cfg(target_os = "windows")]
            auth_token: random_nonce(),
        }
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
        #[cfg(target_os = "windows")]
        {
            MonitorControlCommand::from_request_with_token(&content, &self.auth_token)
        }

        #[cfg(not(target_os = "windows"))]
        {
            MonitorControlCommand::from_request(&content)
        }
    }

    #[cfg(target_os = "windows")]
    pub(crate) fn control_token(&self) -> &str {
        &self.auth_token
    }

    #[cfg(test)]
    fn for_path(path: PathBuf) -> Self {
        let last_content = read_private_text_limited(&path, MAX_MONITOR_COMMAND_BYTES)
            .ok()
            .flatten();
        Self {
            path: Some(path),
            last_content,
            #[cfg(target_os = "windows")]
            auth_token: random_nonce(),
        }
    }

    #[cfg(all(test, target_os = "windows"))]
    fn for_path_with_token(path: PathBuf, auth_token: String) -> Self {
        let last_content = read_private_text_limited(&path, MAX_MONITOR_COMMAND_BYTES)
            .ok()
            .flatten();
        Self {
            path: Some(path),
            last_content,
            auth_token,
        }
    }
}

#[cfg(not(target_os = "macos"))]
pub(crate) struct ActivationWatcher {
    path: Option<PathBuf>,
    last_modified: Option<SystemTime>,
    last_content: Option<String>,
}

#[cfg(not(target_os = "macos"))]
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

impl Drop for SingleInstanceGuard {
    fn drop(&mut self) {
        #[cfg(target_os = "windows")]
        {
            let _ = unsafe { CloseHandle(self.mutex) };
        }
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
    #[cfg(target_os = "macos")]
    {
        return crate::user_paths::runtime_dir();
    }

    #[cfg(not(target_os = "macos"))]
    crate::user_paths::cache_dir()
}

#[cfg(not(target_os = "macos"))]
fn monitor_command_path() -> anyhow::Result<PathBuf> {
    Ok(lock_root()?.join(MONITOR_COMMAND_FILE_NAME))
}

fn monitor_status_path() -> anyhow::Result<PathBuf> {
    Ok(lock_root()?.join(MONITOR_STATUS_FILE_NAME))
}

#[cfg(not(target_os = "macos"))]
fn activation_request_path() -> anyhow::Result<PathBuf> {
    Ok(lock_root()?.join(ACTIVATION_FILE_NAME))
}

#[cfg(target_os = "macos")]
fn ipc_socket_path() -> anyhow::Result<PathBuf> {
    Ok(lock_root()?.join(IPC_SOCKET_FILE_NAME))
}

#[cfg(target_os = "macos")]
fn send_local_ipc_command(command: &str) -> anyhow::Result<()> {
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
    let _ = stream.shutdown(Shutdown::Write);
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

    let mut buffer = [0_u8; 128];
    match stream.read(&mut buffer) {
        Ok(0) => Ok(None),
        Ok(len) => {
            let message = String::from_utf8_lossy(&buffer[..len]);
            Ok(parse_local_ipc_challenge_response(&message, &challenge)
                .map(|command| PeerLocalIpcCommand { peer_pid, command }))
        }
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
        Err(e) => Err(e.into()),
    }
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

#[cfg(target_os = "macos")]
fn parse_local_ipc_command(message: &str) -> Option<LocalIpcCommand> {
    let message = message.trim();
    if message == IPC_COMMAND_ACTIVATE {
        return Some(LocalIpcCommand::Activate);
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

#[cfg(not(target_os = "macos"))]
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
    let Some(process_bundle_path) = macos_containing_app_bundle(&process_path) else {
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
    match (process_path.canonicalize(), current_path.canonicalize()) {
        (Ok(process_path), Ok(current_path)) => process_path == current_path,
        _ => false,
    }
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

#[cfg(target_os = "windows")]
fn monitor_control_token_from_env() -> Option<String> {
    let token = std::env::var(MONITOR_CONTROL_TOKEN_ENV).ok()?;
    parse_nonce_field(&token).map(str::to_string)
}

#[cfg(target_os = "windows")]
fn signed_monitor_command_request(
    command: &str,
    pid: u32,
    nonce: &str,
    auth_token: &str,
) -> String {
    let signature = monitor_command_signature(auth_token, command, pid, nonce);
    format!("{command}:{pid}:{nonce}:{signature}\n")
}

#[cfg(target_os = "windows")]
fn monitor_command_signature(auth_token: &str, command: &str, pid: u32, nonce: &str) -> String {
    let message = format!("{command}:{pid}:{nonce}");
    hmac_sha256_hex(auth_token.as_bytes(), message.as_bytes())
}

#[cfg(target_os = "windows")]
fn monitor_command_signature_matches(
    auth_token: &str,
    command: &str,
    pid: u32,
    nonce: &str,
    actual_signature: &str,
) -> bool {
    if actual_signature.len() != 64
        || !actual_signature
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return false;
    }
    let expected = monitor_command_signature(auth_token, command, pid, nonce);
    constant_time_eq(expected.as_bytes(), actual_signature.as_bytes())
}

#[cfg(target_os = "windows")]
fn hmac_sha256_hex(key: &[u8], message: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    const BLOCK_SIZE: usize = 64;
    let mut key_block = [0_u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        key_block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = [0x36_u8; BLOCK_SIZE];
    let mut outer_pad = [0x5c_u8; BLOCK_SIZE];
    for index in 0..BLOCK_SIZE {
        inner_pad[index] ^= key_block[index];
        outer_pad[index] ^= key_block[index];
    }

    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_hash);
    outer
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(target_os = "windows")]
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right.iter())
        .fold(0_u8, |diff, (left, right)| diff | (left ^ right))
        == 0
}

fn parse_pid_field(value: &str) -> Option<u32> {
    if value.is_empty() || value.len() > 10 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let pid = value.parse::<u32>().ok()?;
    (pid > 0).then_some(pid)
}

fn parse_nonce_field(value: &str) -> Option<&str> {
    (value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())).then_some(value)
}

#[cfg(not(target_os = "macos"))]
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

#[cfg(not(target_os = "macos"))]
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

    #[cfg(not(target_os = "macos"))]
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
    fn stale_lock_with_dead_pid_is_reclaimed() {
        let root = temp_test_root("stale-lock-reclaimed");
        let lock_dir = root.join(LOCK_DIR_NAME);
        std::fs::create_dir_all(&lock_dir).unwrap();
        write_test_private_text(lock_dir.join("pid"), "99999999").unwrap();

        let acquired = acquire_lock_dir_in_root(&root, LOCK_DIR_NAME, "already running").unwrap();
        assert_eq!(lock_pid(&acquired), Some(std::process::id()));

        let _ = std::fs::remove_dir_all(root);
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

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn stale_lock_filename_is_reclaimed() {
        let root = temp_test_root("stale-lock-file-reclaimed");
        let lock_path = root.join(LOCK_DIR_NAME);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(&lock_path, "not-a-lock-directory").unwrap();

        let acquired = acquire_lock_dir_in_root(&root, LOCK_DIR_NAME, "already running").unwrap();
        assert_eq!(lock_pid(&acquired), Some(std::process::id()));

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn stale_lock_root_filename_is_reclaimed() {
        let root = temp_test_root("stale-lock-root-file-reclaimed");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::write(&root, "not-a-lock-root-directory").unwrap();

        let acquired = acquire_lock_dir_in_root(&root, LOCK_DIR_NAME, "already running").unwrap();
        assert_eq!(lock_pid(&acquired), Some(std::process::id()));

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
    fn macos_containing_app_bundle_finds_parent_bundle() {
        let path = PathBuf::from(
            "/Applications/WindowsAppAutoLogin.app/Contents/MacOS/windows-app-autologin",
        );

        assert_eq!(
            macos_containing_app_bundle(&path),
            Some(PathBuf::from("/Applications/WindowsAppAutoLogin.app"))
        );
    }

    #[cfg(all(target_os = "macos", unix))]
    #[test]
    fn macos_containing_app_bundle_rejects_unbundled_path() {
        let path = PathBuf::from("/tmp/windows-app-autologin");

        assert_eq!(macos_containing_app_bundle(&path), None);
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
            "dev.codex.windows-app-autologin",
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
            "dev.codex.windows-app-autologin",
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
            "dev.codex.windows-app-autologin",
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
                "dev.codex.windows-app-autologin".to_string(),
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
            "dev.codex.windows-app-autologin",
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
            "dev.codex.windows-app-autologin",
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
            "dev.codex.windows-app-autologin",
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
            "dev.codex.windows-app-autologin",
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
    fn macos_proc_pidpath_preserves_leading_and_trailing_spaces() {
        use std::os::unix::ffi::OsStrExt;

        let leading = macos_proc_pidpath_buffer_to_path(b" /tmp/windows-app-autologin").unwrap();
        let trailing = macos_proc_pidpath_buffer_to_path(b"/tmp/windows-app-autologin ").unwrap();

        assert_eq!(
            leading.as_os_str().as_bytes(),
            b" /tmp/windows-app-autologin"
        );
        assert_eq!(
            trailing.as_os_str().as_bytes(),
            b"/tmp/windows-app-autologin "
        );
    }

    #[cfg(all(target_os = "macos", unix))]
    #[test]
    fn macos_proc_pidpath_stops_at_first_nul_without_trimming() {
        use std::os::unix::ffi::OsStrExt;

        let path = macos_proc_pidpath_buffer_to_path(b"/tmp/app \0/spoof").unwrap();

        assert_eq!(path.as_os_str().as_bytes(), b"/tmp/app ");
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

    #[cfg(not(target_os = "macos"))]
    fn monitor_command_request_for_test(
        command: MonitorControlCommand,
        nonce: &str,
        auth_token: &str,
    ) -> String {
        #[cfg(target_os = "windows")]
        {
            let nonce = format!("{nonce:0>32}");
            signed_monitor_command_request(command.as_str(), std::process::id(), &nonce, auth_token)
        }

        #[cfg(not(target_os = "windows"))]
        {
            let _ = auth_token;
            format!("{}:{}:{nonce}", command.as_str(), std::process::id())
        }
    }

    #[cfg(not(target_os = "macos"))]
    fn forged_monitor_command_request_for_test(auth_token: &str) -> String {
        #[cfg(target_os = "windows")]
        {
            signed_monitor_command_request(
                MONITOR_COMMAND_START,
                99_999_999,
                &random_nonce(),
                auth_token,
            )
        }

        #[cfg(not(target_os = "windows"))]
        {
            let _ = auth_token;
            "start_monitor:99999999:4".to_string()
        }
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn monitor_command_watcher_consumes_new_commands_once() {
        let path = std::env::temp_dir().join(format!(
            "windows-app-autologin-monitor-command-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);

        #[cfg(target_os = "windows")]
        let auth_token = random_nonce();
        #[cfg(not(target_os = "windows"))]
        let auth_token = String::new();

        #[cfg(target_os = "windows")]
        let mut watcher =
            MonitorCommandWatcher::for_path_with_token(path.clone(), auth_token.clone());
        #[cfg(not(target_os = "windows"))]
        let mut watcher = MonitorCommandWatcher::for_path(path.clone());

        assert_eq!(watcher.consume_command(), None);
        write_test_private_text(
            &path,
            monitor_command_request_for_test(MonitorControlCommand::Start, "1", &auth_token),
        )
        .unwrap();
        assert_eq!(
            watcher.consume_command(),
            Some(MonitorControlCommand::Start)
        );
        assert_eq!(watcher.consume_command(), None);

        write_test_private_text(
            &path,
            monitor_command_request_for_test(MonitorControlCommand::Stop, "2", &auth_token),
        )
        .unwrap();
        assert_eq!(watcher.consume_command(), Some(MonitorControlCommand::Stop));

        write_test_private_text(
            &path,
            monitor_command_request_for_test(MonitorControlCommand::ReloadConfig, "3", &auth_token),
        )
        .unwrap();
        assert_eq!(
            watcher.consume_command(),
            Some(MonitorControlCommand::ReloadConfig)
        );

        write_test_private_text(&path, forged_monitor_command_request_for_test(&auth_token))
            .unwrap();
        assert_eq!(watcher.consume_command(), None);

        let _ = std::fs::remove_file(path);
    }

    #[cfg(not(target_os = "macos"))]
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
    fn monitor_command_requires_windows_auth_signature() {
        let auth_token = random_nonce();
        let nonce = random_nonce();
        let valid = signed_monitor_command_request(
            MONITOR_COMMAND_START,
            std::process::id(),
            &nonce,
            &auth_token,
        );

        assert_eq!(
            MonitorControlCommand::from_request_with_token(&valid, &auth_token),
            Some(MonitorControlCommand::Start)
        );
        assert_eq!(
            MonitorControlCommand::from_request_with_token(
                &format!("{}:{}:{}", MONITOR_COMMAND_START, std::process::id(), nonce),
                &auth_token
            ),
            None
        );
        assert_eq!(
            MonitorControlCommand::from_request_with_token(
                &signed_monitor_command_request(
                    MONITOR_COMMAND_START,
                    std::process::id(),
                    &nonce,
                    &random_nonce(),
                ),
                &auth_token,
            ),
            None
        );
        assert_eq!(
            MonitorControlCommand::from_request_with_token(
                &valid.replacen(MONITOR_COMMAND_START, MONITOR_COMMAND_STOP, 1),
                &auth_token,
            ),
            None
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn monitor_command_watcher_rejects_raw_spoofed_file_with_supervisor_pid() {
        let path = std::env::temp_dir().join(format!(
            "windows-app-autologin-monitor-command-spoof-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let auth_token = random_nonce();
        let mut watcher =
            MonitorCommandWatcher::for_path_with_token(path.clone(), auth_token.clone());

        write_test_private_text(
            &path,
            format!("{}:{}:1", MONITOR_COMMAND_START, std::process::id()),
        )
        .unwrap();
        assert_eq!(watcher.consume_command(), None);

        write_test_private_text(
            &path,
            signed_monitor_command_request(
                MONITOR_COMMAND_START,
                std::process::id(),
                &random_nonce(),
                &random_nonce(),
            ),
        )
        .unwrap();
        assert_eq!(watcher.consume_command(), None);

        write_test_private_text(
            &path,
            signed_monitor_command_request(
                MONITOR_COMMAND_START,
                std::process::id(),
                &random_nonce(),
                &auth_token,
            ),
        )
        .unwrap();
        assert_eq!(
            watcher.consume_command(),
            Some(MonitorControlCommand::Start)
        );

        let _ = std::fs::remove_file(path);
    }

    #[cfg(not(target_os = "macos"))]
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

        assert_eq!(watcher.consume_command(), None);

        let _ = std::fs::remove_file(path);
    }

    #[cfg(not(target_os = "macos"))]
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

    #[cfg(not(target_os = "macos"))]
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
    fn monitor_status_accepts_only_exact_states() {
        assert_eq!(parse_monitor_status("running\n"), Some(true));
        assert_eq!(parse_monitor_status("idle\n"), Some(false));
        assert_eq!(parse_monitor_status("RUNNING\n"), None);
        assert_eq!(parse_monitor_status("running:extra\n"), None);
        assert_eq!(parse_monitor_status("running\0\n"), None);
        assert_eq!(
            parse_monitor_status(&"running".repeat(MAX_MONITOR_STATUS_BYTES as usize)),
            None
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn local_ipc_parses_monitor_and_activation_commands() {
        assert_eq!(
            parse_local_ipc_command("activate\n"),
            Some(LocalIpcCommand::Activate)
        );
        assert_eq!(
            parse_local_ipc_command("monitor:start_monitor"),
            Some(LocalIpcCommand::Monitor(MonitorControlCommand::Start))
        );
        assert_eq!(
            parse_local_ipc_command("config:reload"),
            Some(LocalIpcCommand::ReloadConfig)
        );
        assert_eq!(parse_local_ipc_command("config:reload:old-token"), None);
        assert_eq!(
            parse_local_ipc_command("monitor:start_monitor:old-token"),
            None
        );
        assert_eq!(parse_local_ipc_command("start_monitor:123:nonce"), None);
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

        assert_eq!(
            server.join().unwrap().unwrap(),
            Some(PeerLocalIpcCommand {
                peer_pid: std::process::id(),
                command: LocalIpcCommand::Activate,
            })
        );
    }

    #[cfg(all(target_os = "macos", unix))]
    #[test]
    fn local_ipc_rejects_prebuffered_command_without_challenge() {
        use std::io::Write;
        use std::os::unix::net::UnixStream;

        let (server_stream, mut client_stream) = UnixStream::pair().unwrap();
        client_stream.write_all(b"activate\n").unwrap();

        assert_eq!(
            local_ipc_command_from_validated_stream(server_stream, std::process::id()).unwrap(),
            None
        );
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
