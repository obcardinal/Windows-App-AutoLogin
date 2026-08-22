use crate::models::{Account, AccountId, AppConfig, FIXED_POLL_INTERVAL_SECS};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};
#[cfg(target_os = "windows")]
use zeroize::Zeroize;
use zeroize::Zeroizing;

const SERVICE_NAME: &str = "WindowsAppAutoLogin";
const FALLBACK_KEY_SERVICE_NAME: &str = "WindowsAppAutoLoginFallbackKey";
const FALLBACK_KEY_ACCOUNT: &str = "fallback-encryption-key";
const SCOPED_FALLBACK_KEY_ACCOUNT_PREFIX: &str = "fallback-account-key:";
const CONFIG_FILE_NAME: &str = "config.json";
const PASSWORD_FILE_NAME: &str = "passwords.json";
const PASSWORD_FILE_LOCK_NAME: &str = "passwords.lock";
const STAGED_FALLBACK_KEYS_FILE_NAME: &str = "staged-fallback-keys.json";
const STORAGE_RECOVERY_BLOCK_FILE_NAME: &str = "storage-recovery-blocked";
const STORAGE_RECOVERY_BLOCK_CONTENT: &[u8] = b"windows-app-autologin-storage-recovery-block-v1\n";
const FALLBACK_KEY_FILE_NAME: &str = "fallback.key";
const PENDING_STORAGE_OPERATION_FILE_NAME: &str = "pending-storage-operation.json";
const RECOVERING_STORAGE_OPERATION_FILE_NAME: &str = "pending-storage-operation.recovering.json";
const PASSWORD_ENVELOPE_PREFIX: &str = "waa1:";
const PASSWORD_ENVELOPE_V2_PREFIX: &str = "waa2:";
#[cfg(any(target_os = "windows", test))]
const WINDOWS_USER_BOUND_SECRET_PREFIX: &str = "waub:";
#[cfg(any(target_os = "windows", test))]
const WINDOWS_LEGACY_WAAB_SECRET_PREFIX: &str = "waab:";
const PASSWORD_ENVELOPE_VERSION: u8 = 1;
const PASSWORD_ENVELOPE_V2_VERSION: u8 = 2;
const SCOPED_FALLBACK_KEY_VERSION: u8 = 1;
const SECURE_STORAGE_PASSWORD_PURPOSE: &str = "account-password";
const SECURE_STORAGE_FALLBACK_KEY_PURPOSE: &str = "fallback-encryption-key";
#[cfg(any(target_os = "windows", test))]
const WINDOWS_USER_BOUND_STORAGE_VERSION: &str = "WAAL_WINDOWS_USER_BOUND_STORAGE";
#[cfg(any(target_os = "windows", test))]
const WINDOWS_LEGACY_WAAB_STORAGE_VERSION: &str = "WAAL_WINDOWS_APP_BOUND_STORAGE";
const PENDING_STORAGE_TEMP_FILE_PREFIXES: &[&str] = &[
    "pending-storage-operation.json.tmp.",
    "pending-storage-operation.recovering.json.tmp.",
];
const PASSWORD_TRANSACTION_TEMP_FILE_PREFIXES: &[&str] =
    &["passwords.json.tmp.", "staged-fallback-keys.json.tmp."];
const LEGACY_FALLBACK_KEY_RESIDUE_PREFIXES: &[&str] =
    &["fallback.json.invalid.", "fallback.key.invalid."];
const MAX_CONFIG_FILE_BYTES: u64 = 1024 * 1024;
const MAX_PASSWORD_FILE_BYTES: u64 = 1024 * 1024;
const MAX_FALLBACK_KEY_FILE_BYTES: u64 = 128;
const MAX_PENDING_STORAGE_OPERATION_FILE_BYTES: u64 = 64 * 1024;
const MAX_STAGED_FALLBACK_KEYS_FILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_ENCRYPTED_PASSWORD_ENTRY_CHARS: usize = 16 * 1024;
const MAX_FALLBACK_KEY_ID_CHARS: usize = 64;
const MAX_RETIRED_FALLBACK_KEYS: usize = 4096;
const MAX_STAGED_FALLBACK_KEYS: usize = 4096;
const STAGED_FALLBACK_KEYS_VERSION: u8 = 1;
const PENDING_STORAGE_OPERATION_VERSION: u8 = 1;
const AES_GCM_NONCE_BYTES: usize = 12;
const AES_GCM_TAG_BYTES: usize = 16;
const PENDING_STORAGE_OPERATION_IN_PROGRESS_MESSAGE: &str = "pending password storage cleanup is already in progress; restart or wait for recovery before changing stored credentials";

#[derive(Debug)]
struct PendingStorageOperationInProgress;

impl fmt::Display for PendingStorageOperationInProgress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(PENDING_STORAGE_OPERATION_IN_PROGRESS_MESSAGE)
    }
}

impl std::error::Error for PendingStorageOperationInProgress {}

#[derive(Debug)]
struct PendingStorageRecoveryBlocked {
    source: anyhow::Error,
}

impl fmt::Display for PendingStorageRecoveryBlocked {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "pending password storage recovery is blocked by invalid or conflicting journals; the journals were retained for safe manual recovery",
        )
    }
}

impl std::error::Error for PendingStorageRecoveryBlocked {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

#[derive(Debug)]
struct StorageModeMigrationRecoveryRequired {
    message: String,
}

impl fmt::Display for StorageModeMigrationRecoveryRequired {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for StorageModeMigrationRecoveryRequired {}

#[derive(Debug)]
struct StagedFallbackKeyConflict {
    source: Option<anyhow::Error>,
}

impl StagedFallbackKeyConflict {
    fn new() -> Self {
        Self { source: None }
    }

    fn with_journal_save_error(source: anyhow::Error) -> Self {
        Self {
            source: Some(source),
        }
    }
}

impl fmt::Display for StagedFallbackKeyConflict {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "staged fallback key metadata conflicts with an active credential; restart after recovery",
        )
    }
}

impl std::error::Error for StagedFallbackKeyConflict {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|source| source.as_ref())
    }
}

#[derive(Debug)]
struct InvalidStagedFallbackKeyState {
    source: anyhow::Error,
}

impl fmt::Display for InvalidStagedFallbackKeyState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .write_str("staged fallback key recovery state is invalid; restart after safe recovery")
    }
}

impl std::error::Error for InvalidStagedFallbackKeyState {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

#[derive(Debug)]
struct PrivateFileWriteCommitted {
    source: anyhow::Error,
}

impl fmt::Display for PrivateFileWriteCommitted {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("private file replacement committed, but final validation failed")
    }
}

impl std::error::Error for PrivateFileWriteCommitted {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

#[derive(Debug)]
struct PasswordFileWriteCommitted {
    source: anyhow::Error,
}

impl fmt::Display for PasswordFileWriteCommitted {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("password file replacement committed, but final validation failed")
    }
}

impl std::error::Error for PasswordFileWriteCommitted {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

fn private_file_write_committed(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.is::<PrivateFileWriteCommitted>())
}

/// Returns true only when the target pathname was already atomically replaced.
/// Callers must keep the new in-memory state and must not perform destructive
/// rollback/cleanup in this case: only the final permission/directory durability
/// confirmation failed.
pub(crate) fn config_write_committed(error: &anyhow::Error) -> bool {
    private_file_write_committed(error)
}

#[cfg(test)]
pub(crate) fn committed_config_write_test_error() -> anyhow::Error {
    anyhow::Error::new(PrivateFileWriteCommitted {
        source: anyhow::anyhow!("test failure after config replacement"),
    })
}

pub(crate) fn is_pending_storage_operation_in_progress(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.is::<PendingStorageOperationInProgress>())
}

pub(crate) fn pending_storage_recovery_is_clear() -> anyhow::Result<bool> {
    let pending_path = pending_storage_operation_file_path()?;
    let recovering_path = recovering_storage_operation_file_path()?;
    Ok(!storage_operation_file_exists(&pending_path)?
        && !storage_operation_file_exists(&recovering_path)?)
}

/// Durably latches recovery blocking before a child process requests any IPC
/// or other process-local stop action. Re-marking an existing valid latch is
/// idempotent and re-syncs its parent directory.
pub(crate) fn mark_storage_recovery_blocked() -> anyhow::Result<()> {
    ensure_config_dir()?;
    let path = storage_recovery_block_file_path()?;
    mark_storage_recovery_blocked_at(&path)
}

fn mark_storage_recovery_blocked_at(path: &Path) -> anyhow::Result<()> {
    if storage_operation_file_exists(path)? {
        validate_private_file_for_read(path)?;
        secure_path_permissions(path, 0o600)?;
        return sync_parent_dir(path);
    }
    write_private_file_create_new_atomic(path, "block.tmp", STORAGE_RECOVERY_BLOCK_CONTENT)
}

/// Returns false for any on-disk entry, including malformed files and links;
/// callers must fail closed on errors.
pub(crate) fn storage_recovery_block_is_clear() -> anyhow::Result<bool> {
    Ok(!storage_operation_file_exists(
        &storage_recovery_block_file_path()?,
    )?)
}

/// Fresh-supervisor startup hook. Call only after journal reconciliation has
/// completed successfully. A running process must never use this to reopen its
/// own sticky recovery gate.
pub(crate) fn clear_storage_recovery_block_after_startup_recovery() -> anyhow::Result<()> {
    let recovery_is_clear = pending_storage_recovery_is_clear()?;
    let path = storage_recovery_block_file_path()?;
    clear_storage_recovery_block_after_startup_recovery_with_state(
        recovery_is_clear,
        &path,
        |target| std::fs::remove_file(target).map_err(anyhow::Error::from),
        sync_parent_dir,
    )
}

#[cfg(test)]
fn clear_storage_recovery_block_after_startup_recovery_at(path: &Path) -> anyhow::Result<()> {
    clear_storage_recovery_block_after_startup_recovery_with_state(
        true,
        path,
        |target| std::fs::remove_file(target).map_err(anyhow::Error::from),
        sync_parent_dir,
    )
}

fn clear_storage_recovery_block_after_startup_recovery_with_state<R, S>(
    recovery_is_clear: bool,
    path: &Path,
    remove: R,
    sync_parent: S,
) -> anyhow::Result<()>
where
    R: FnMut(&Path) -> anyhow::Result<()>,
    S: FnMut(&Path) -> anyhow::Result<()>,
{
    if !recovery_is_clear {
        anyhow::bail!(
            "storage recovery block cannot be cleared while a recovery journal is active"
        );
    }
    clear_storage_recovery_block_after_startup_recovery_with_ops(path, remove, sync_parent)
}

fn clear_storage_recovery_block_after_startup_recovery_with_ops<R, S>(
    path: &Path,
    mut remove: R,
    mut sync_parent: S,
) -> anyhow::Result<()>
where
    R: FnMut(&Path) -> anyhow::Result<()>,
    S: FnMut(&Path) -> anyhow::Result<()>,
{
    if !storage_operation_file_exists(path)? {
        return Ok(());
    }
    validate_private_file_for_read(path)?;
    remove(path)?;
    // Failure here means the unlink happened in this process but is not known
    // durable. The caller must remain blocked for this process lifetime.
    sync_parent(path)
}

pub(crate) fn storage_mode_migration_error_requires_recovery(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.is::<StorageModeMigrationRecoveryRequired>())
}

pub(crate) fn storage_mode_migration_recovery_required_error(
    message: impl Into<String>,
) -> anyhow::Error {
    anyhow::Error::new(StorageModeMigrationRecoveryRequired {
        message: message.into(),
    })
}

pub(crate) fn pending_storage_recovery_user_status(unchanged_detail: &str) -> String {
    format!(
        "Password storage recovery is still pending. Restart Windows App AutoLogin, then try again. {unchanged_detail}"
    )
}

pub(crate) fn keychain_service_name() -> &'static str {
    SERVICE_NAME
}

fn native_secure_storage_name() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "macOS Keychain"
    }
    #[cfg(target_os = "windows")]
    {
        "Windows Credential Manager"
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        "system credential store"
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(default)]
struct LegacyConfig {
    poll_interval_secs: u64,
    credentials: Option<LegacyCredentialsConfig>,
}

impl Default for LegacyConfig {
    fn default() -> Self {
        Self {
            poll_interval_secs: 1,
            credentials: None,
        }
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(default)]
struct LegacyCredentialsConfig {
    username: String,
    account_id: Option<String>,
    use_credential_manager: bool,
}

impl Default for LegacyCredentialsConfig {
    fn default() -> Self {
        Self {
            username: String::new(),
            account_id: None,
            use_credential_manager: true,
        }
    }
}

fn config_dir() -> anyhow::Result<PathBuf> {
    crate::user_paths::config_dir()
}

fn config_file() -> anyhow::Result<PathBuf> {
    Ok(config_dir()?.join(CONFIG_FILE_NAME))
}

fn ensure_config_dir() -> anyhow::Result<()> {
    let dir = config_dir()?;
    if !dir.exists() {
        match std::fs::create_dir_all(&dir) {
            Ok(()) => {
                debug!(dir = %redacted_path(&dir), "Config directory created");
            }
            Err(e) => {
                warn!(dir = %redacted_path(&dir), error = %e, "Failed to create config directory");
                return Err(e.into());
            }
        }
    }
    validate_private_dir(&dir)?;
    Ok(())
}

#[cfg(unix)]
fn secure_path_permissions(path: &Path, mode: u32) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!("{} must not be a symlink", redacted_path(path));
    }
    let mut permissions = metadata.permissions();
    permissions.set_mode(mode);
    std::fs::set_permissions(path, permissions)?;
    crate::private_permissions::strip_macos_acl(path)?;
    Ok(())
}

#[cfg(windows)]
fn secure_path_permissions(path: &Path, mode: u32) -> anyhow::Result<()> {
    match mode {
        0o700 => crate::private_permissions::secure_windows_private_dir(path),
        0o600 => crate::private_permissions::secure_windows_private_file(path),
        _ => anyhow::bail!("unsupported private Windows path mode"),
    }
}

#[cfg(not(any(unix, windows)))]
fn secure_path_permissions(_path: &Path, _mode: u32) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn validate_private_dir(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt;

    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() {
        anyhow::bail!("{} is not a private directory", redacted_path(path));
    }
    if metadata.uid() != unsafe { libc::geteuid() } {
        anyhow::bail!("{} is not owned by the current user", redacted_path(path));
    }
    secure_path_permissions(path, 0o700)?;
    Ok(())
}

#[cfg(windows)]
fn validate_private_dir(path: &Path) -> anyhow::Result<()> {
    crate::private_permissions::secure_windows_private_dir(path)
}

#[cfg(not(any(unix, windows)))]
fn validate_private_dir(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn validate_private_file_for_read(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt;

    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        anyhow::bail!("{} is not a regular private file", redacted_path(path));
    }
    if metadata.uid() != unsafe { libc::geteuid() } {
        anyhow::bail!("{} is not owned by the current user", redacted_path(path));
    }
    secure_path_permissions(path, 0o600)?;
    Ok(())
}

#[cfg(windows)]
fn validate_private_file_for_read(path: &Path) -> anyhow::Result<()> {
    crate::private_permissions::secure_windows_private_file(path)
}

#[cfg(not(any(unix, windows)))]
fn validate_private_file_for_read(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

fn read_private_file_bytes(path: &Path, max_bytes: u64) -> anyhow::Result<Vec<u8>> {
    use std::io::Read;

    if let Some(parent) = path.parent() {
        validate_private_dir(parent)?;
    }

    #[cfg(unix)]
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    #[cfg(windows)]
    use std::os::windows::fs::OpenOptionsExt;

    #[cfg(windows)]
    validate_private_file_for_read(path)?;

    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    #[cfg(windows)]
    options.custom_flags(windows::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT.0);

    let file = match options.open(path) {
        Ok(file) => file,
        Err(e) if no_follow_open_error(&e) => {
            anyhow::bail!("{} must be a regular private file", redacted_path(path))
        }
        Err(e) => return Err(e.into()),
    };
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        anyhow::bail!("{} is not a regular private file", redacted_path(path));
    }
    #[cfg(windows)]
    crate::private_permissions::validate_windows_private_file_handle(&file)?;
    if metadata.len() > max_bytes {
        anyhow::bail!("{} is too large", redacted_path(path));
    }
    #[cfg(unix)]
    {
        if metadata.uid() != unsafe { libc::geteuid() } {
            anyhow::bail!("{} is not owned by the current user", redacted_path(path));
        }
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o600);
        file.set_permissions(permissions)?;
        crate::private_permissions::strip_macos_acl(path)?;
    }

    let mut bytes = Vec::with_capacity(max_bytes.min(4096) as usize);
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        anyhow::bail!("{} is too large", redacted_path(path));
    }

    Ok(bytes)
}

fn read_private_text_file(path: &Path, max_bytes: u64) -> anyhow::Result<String> {
    Ok(String::from_utf8(read_private_file_bytes(
        path, max_bytes,
    )?)?)
}

#[cfg(unix)]
fn no_follow_open_error(error: &std::io::Error) -> bool {
    error.raw_os_error() == Some(libc::ELOOP)
}

#[cfg(not(unix))]
fn no_follow_open_error(_error: &std::io::Error) -> bool {
    false
}

pub(crate) fn load_config() -> AppConfig {
    let path = match config_file() {
        Ok(path) => path,
        Err(e) => {
            warn!(error = %e, "Failed to resolve config path; using defaults");
            return AppConfig::default();
        }
    };
    match load_config_file(&path) {
        Ok(config) => normalize_config(config),
        Err(e) => {
            warn!(path = %redacted_path(&path), error = %e, "Failed to load config; using defaults");
            if let Err(backup_error) = backup_invalid_config_file(&path, &e) {
                warn!(path = %redacted_path(&path), error = %backup_error, "Failed to write invalid config diagnostics before using defaults");
            }
            normalize_config(AppConfig::default())
        }
    }
}

fn load_config_file(path: &Path) -> anyhow::Result<AppConfig> {
    if !path.exists() {
        return Ok(AppConfig::default());
    }
    if let Some(dir) = path.parent() {
        validate_private_dir(dir)?;
    }
    validate_private_file_for_read(path)?;

    let content = read_private_text_file(path, MAX_CONFIG_FILE_BYTES)?;
    let value: serde_json::Value = serde_json::from_str(&content)?;
    if value.get("accounts").is_some() || value.get("settings").is_some() {
        return Ok(normalize_config(serde_json::from_value(value)?));
    }

    let legacy: LegacyConfig = serde_json::from_value(value)?;
    let mut config = normalize_config(migrate_legacy_config(&legacy));
    let legacy_password_migration = migrate_legacy_passwords(&legacy, &mut config);
    if !legacy_password_migration_ready_to_persist(&legacy_password_migration) {
        warn!(
            path = %redacted_path(path),
            "legacy config was loaded, but password migration did not complete; legacy config was left on disk for retry"
        );
        return Ok(config);
    }
    match save_config_to_file(&normalize_config(config.clone()), path) {
        Ok(()) => {
            cleanup_migrated_legacy_credentials(&legacy_password_migration.cleanup_ids_after_save)
        }
        Err(e) if config_write_committed(&e) => {
            // The migrated config is now the visible file, so deleting the
            // migration target would corrupt it. Also retain the legacy source
            // credentials until directory durability is confirmed on a later
            // launch.
            warn!(
                path = %redacted_path(path),
                error = %e,
                "Migrated config replacement committed, but durability confirmation failed; credentials retained for recovery"
            );
        }
        Err(e) => {
            if cleanup_legacy_migration_target_after_failed_save(&legacy_password_migration) {
                mark_legacy_migration_target_unsaved(&mut config, &legacy_password_migration);
            }
            warn!(
                path = %redacted_path(path),
                error = %e,
                "legacy config was loaded, but migrated config could not be saved; legacy credentials were left intact"
            );
        }
    }
    Ok(config)
}

fn migrate_legacy_config(legacy: &LegacyConfig) -> AppConfig {
    let mut config = AppConfig::default();
    let _ = legacy.poll_interval_secs;
    config.settings.poll_interval_secs = FIXED_POLL_INTERVAL_SECS;

    if let Some(credentials) = &legacy.credentials {
        let username = credentials.username.trim().to_string();
        if !username.is_empty() {
            let mut account = Account::new(&username);
            if let Some(account_id) = legacy_account_id_for_migrated_config(credentials) {
                account.id = account_id;
            }
            account.username = username;
            account.has_saved_password = false;
            config.settings.use_keyring = credentials.use_credential_manager;
            config.accounts.push(account);
        }
    }

    config
}

fn legacy_account_id_for_migrated_config(
    credentials: &LegacyCredentialsConfig,
) -> Option<AccountId> {
    credentials
        .account_id
        .as_deref()
        .map(str::trim)
        .filter(|account_id| !account_id.is_empty())
        .filter(|account_id| !account_id.contains('@'))
        .map(ToOwned::to_owned)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct LegacyPasswordMigration {
    source_ids: Vec<AccountId>,
    target_id: Option<AccountId>,
    cleanup_ids_after_save: Vec<AccountId>,
}

fn migrate_legacy_passwords(
    legacy: &LegacyConfig,
    config: &mut AppConfig,
) -> LegacyPasswordMigration {
    let Some(credentials) = &legacy.credentials else {
        return LegacyPasswordMigration::default();
    };
    let source_ids = legacy_credential_cleanup_ids(legacy);
    let Some(account) = config.accounts.first_mut() else {
        return LegacyPasswordMigration {
            source_ids,
            ..LegacyPasswordMigration::default()
        };
    };

    for source_id in &source_ids {
        let mut source_account = account.clone();
        source_account.id = source_id.clone();
        source_account.username = credentials.username.trim().to_string();
        source_account.has_saved_password = true;

        let password = match load_password(&source_account, credentials.use_credential_manager) {
            Ok(password) => password,
            Err(e) => {
                debug!(
                    account_id = %redacted_account_id(source_id),
                    error = %e,
                    "legacy password source did not load during config migration"
                );
                continue;
            }
        };

        // Ownership crosses the write boundary so the source plaintext is
        // wiped immediately after its final backend-specific use.
        let receipt =
            match write_account_password_owned(account, password, config.settings.use_keyring) {
                Ok(receipt) => receipt,
                Err(e) => {
                    warn!(
                        account_id = %redacted_account_id(&account.id),
                        error = %e,
                        "legacy password loaded, but could not be saved under migrated account"
                    );
                    return LegacyPasswordMigration {
                        source_ids,
                        ..LegacyPasswordMigration::default()
                    };
                }
            };
        if let Err(e) = load_password(account, config.settings.use_keyring) {
            warn!(
                account_id = %redacted_account_id(&account.id),
                error = %e,
                "legacy password saved under migrated account, but verification failed"
            );
            cleanup_legacy_migration_target_after_failed_save(&LegacyPasswordMigration {
                source_ids,
                target_id: Some(account.id.clone()),
                cleanup_ids_after_save: Vec::new(),
            });
            return LegacyPasswordMigration::default();
        }

        account.has_saved_password = true;
        return LegacyPasswordMigration {
            cleanup_ids_after_save: if receipt.target_durability_warning {
                warn!(account_id = %redacted_account_id(&account.id), "Legacy password target durability is unconfirmed; retaining every source credential for recovery");
                Vec::new()
            } else {
                obsolete_legacy_credential_ids(&source_ids, &account.id)
            },
            target_id: Some(account.id.clone()),
            source_ids,
        };
    }

    LegacyPasswordMigration {
        source_ids,
        ..LegacyPasswordMigration::default()
    }
}

fn legacy_password_migration_ready_to_persist(migration: &LegacyPasswordMigration) -> bool {
    migration.source_ids.is_empty() || migration.target_id.is_some()
}

fn obsolete_legacy_credential_ids(
    source_ids: &[AccountId],
    target_id: &AccountId,
) -> Vec<AccountId> {
    source_ids
        .iter()
        .filter(|source_id| *source_id != target_id)
        .cloned()
        .collect()
}

fn legacy_migration_target_cleanup_id<'a>(
    source_ids: &[AccountId],
    target_id: &'a AccountId,
) -> Option<&'a AccountId> {
    (!source_ids.iter().any(|source_id| source_id == target_id)).then_some(target_id)
}

fn cleanup_legacy_migration_target_after_failed_save(migration: &LegacyPasswordMigration) -> bool {
    let Some(target_id) = migration
        .target_id
        .as_ref()
        .and_then(|target_id| legacy_migration_target_cleanup_id(&migration.source_ids, target_id))
    else {
        return false;
    };

    match delete_password(target_id) {
        Ok(()) => true,
        Err(e) => {
            warn!(
                account_id = %redacted_account_id(target_id),
                error = %e,
                "legacy password migration target cleanup failed after config save failure"
            );
            false
        }
    }
}

fn mark_legacy_migration_target_unsaved(
    config: &mut AppConfig,
    migration: &LegacyPasswordMigration,
) {
    let Some(target_id) = &migration.target_id else {
        return;
    };
    for account in &mut config.accounts {
        if &account.id == target_id {
            account.has_saved_password = false;
        }
    }
}

pub(crate) fn save_config(config: &AppConfig) -> anyhow::Result<()> {
    ensure_config_dir()?;
    save_config_to_file(&normalize_config(config.clone()), &config_file()?)
}

fn save_config_to_file(config: &AppConfig, path: &Path) -> anyhow::Result<()> {
    let content = serde_json::to_string_pretty(config)?;
    write_private_file_atomic(path, "json.tmp", content.as_bytes())
}

fn normalize_config(mut config: AppConfig) -> AppConfig {
    config.settings.poll_interval_secs = FIXED_POLL_INTERVAL_SECS;
    normalize_account_selection_metadata(&mut config.accounts);
    config
}

fn normalize_account_selection_metadata(accounts: &mut [Account]) {
    let mut seen_enabled_saved_ids = HashSet::new();
    let mut seen_enabled_saved_usernames = HashSet::new();
    let mut disabled_duplicate_ids = 0;
    let mut disabled_duplicate_usernames = 0;

    for account in accounts {
        if !account.enabled || !account.has_saved_password {
            continue;
        }

        let duplicate_id =
            !account.id.trim().is_empty() && !seen_enabled_saved_ids.insert(account.id.clone());
        let username_key = canonical_username(&account.username);
        let duplicate_username =
            !username_key.is_empty() && !seen_enabled_saved_usernames.insert(username_key);

        if duplicate_id || duplicate_username {
            account.enabled = false;
            disabled_duplicate_ids += usize::from(duplicate_id);
            disabled_duplicate_usernames += usize::from(duplicate_username);
        }
    }

    if disabled_duplicate_ids > 0 || disabled_duplicate_usernames > 0 {
        warn!(
            disabled_duplicate_ids,
            disabled_duplicate_usernames,
            "Disabled duplicate saved account metadata to keep account selection unambiguous"
        );
    }
}

#[derive(Debug, serde::Serialize)]
struct InvalidConfigDiagnosticBackup {
    redaction_version: u8,
    kind: &'static str,
    original_file_name: String,
    original_size_bytes: usize,
    original_sha256: String,
    load_error_kind: &'static str,
    json_parse_status: &'static str,
    json_top_level_type: &'static str,
    has_accounts: bool,
    account_count: Option<usize>,
    has_settings: bool,
    raw_content: &'static str,
}

fn backup_invalid_config_file(path: &Path, load_error: &anyhow::Error) -> anyhow::Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    if metadata.file_type().is_symlink() {
        std::fs::remove_file(path)?;
        return sync_parent_dir(path);
    }
    if !metadata.file_type().is_file() {
        return Ok(());
    }
    validate_private_file_for_read(path)?;
    let content = Zeroizing::new(read_private_file_bytes(path, MAX_CONFIG_FILE_BYTES)?);
    let diagnostic = invalid_config_diagnostic_backup_bytes(path, &content, load_error)?;

    // Preserve the exact bytes (including account ids/usernames needed to recover
    // orphaned credentials) instead of replacing them with a redacted summary.
    // The containing directory and both quarantine files remain private.
    let quarantine_path = invalid_config_quarantine_path(path);
    if std::fs::symlink_metadata(&quarantine_path).is_ok() {
        anyhow::bail!("invalid config quarantine destination already exists");
    }
    std::fs::rename(path, &quarantine_path)?;
    validate_private_file_for_read(&quarantine_path)
        .map_err(|source| anyhow::Error::new(PrivateFileWriteCommitted { source }))?;
    secure_path_permissions(&quarantine_path, 0o600)
        .map_err(|source| anyhow::Error::new(PrivateFileWriteCommitted { source }))?;
    sync_parent_dir(&quarantine_path)
        .map_err(|source| anyhow::Error::new(PrivateFileWriteCommitted { source }))?;

    let diagnostic_path = invalid_config_diagnostic_path(&quarantine_path);
    write_private_file_create_new_atomic(&diagnostic_path, "json.tmp", &diagnostic)?;
    Ok(())
}

fn invalid_config_quarantine_path(path: &Path) -> PathBuf {
    let timestamp = chrono::Local::now().format("%Y%m%d%H%M%S");
    let nonce = chrono::Utc::now()
        .timestamp_nanos_opt()
        .unwrap_or_default()
        .unsigned_abs();
    path.with_extension(format!(
        "json.invalid.{timestamp}.{}.{}",
        std::process::id(),
        nonce
    ))
}

fn invalid_config_diagnostic_path(quarantine_path: &Path) -> PathBuf {
    let name = quarantine_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("config.json.invalid");
    quarantine_path.with_file_name(format!("{name}.diagnostic.json"))
}

fn invalid_config_diagnostic_backup_bytes(
    path: &Path,
    content: &[u8],
    load_error: &anyhow::Error,
) -> anyhow::Result<Vec<u8>> {
    let parsed = serde_json::from_slice::<serde_json::Value>(content);
    let (json_parse_status, json_top_level_type, has_accounts, account_count, has_settings) =
        match parsed.as_ref() {
            Ok(value) => (
                "parsed",
                json_value_kind(value),
                value.get("accounts").is_some(),
                value
                    .get("accounts")
                    .and_then(|accounts| accounts.as_array())
                    .map(Vec::len),
                value.get("settings").is_some(),
            ),
            Err(_) => ("invalid_json", "unknown", false, None, false),
        };

    let backup = InvalidConfigDiagnosticBackup {
        redaction_version: 1,
        kind: "invalid_config_diagnostic",
        original_file_name: path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(CONFIG_FILE_NAME)
            .to_string(),
        original_size_bytes: content.len(),
        original_sha256: sha256_hex(content),
        load_error_kind: invalid_config_load_error_kind(load_error),
        json_parse_status,
        json_top_level_type,
        has_accounts,
        account_count,
        has_settings,
        raw_content: "[omitted]",
    };
    Ok(serde_json::to_vec_pretty(&backup)?)
}

fn json_value_kind(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

fn invalid_config_load_error_kind(error: &anyhow::Error) -> &'static str {
    let message = error.to_string();
    if message.contains("UTF-8") || message.contains("utf-8") {
        "invalid_utf8"
    } else if message.contains("line")
        || message.contains("column")
        || message.contains("EOF")
        || message.contains("trailing")
    {
        "json_parse_failed"
    } else {
        "schema_invalid"
    }
}

fn delete_sensitive_private_file_if_present(path: &Path) -> anyhow::Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    if metadata.file_type().is_symlink() {
        std::fs::remove_file(path)?;
        return sync_parent_dir(path);
    }
    if !metadata.file_type().is_file() {
        return Ok(());
    }
    validate_private_file_for_read(path)?;
    overwrite_private_file_contents(path, metadata.len())?;
    std::fs::remove_file(path)?;
    sync_parent_dir(path)
}

fn overwrite_private_file_contents(path: &Path, len: u64) -> anyhow::Result<()> {
    use std::io::{Seek, SeekFrom, Write};

    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    #[cfg(windows)]
    use std::os::windows::fs::OpenOptionsExt;

    let mut options = std::fs::OpenOptions::new();
    options.write(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    #[cfg(windows)]
    options.custom_flags(windows::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT.0);

    let mut file = options.open(path)?;
    #[cfg(windows)]
    crate::private_permissions::validate_windows_private_file_handle(&file)?;
    file.seek(SeekFrom::Start(0))?;
    let zeroes = [0u8; 4096];
    let mut remaining = len;
    while remaining > 0 {
        let chunk_len = remaining.min(zeroes.len() as u64) as usize;
        file.write_all(&zeroes[..chunk_len])?;
        remaining -= chunk_len as u64;
    }
    file.sync_all()?;
    file.set_len(0)?;
    file.sync_all()?;
    Ok(())
}

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use rand::Rng;
use sha2::{Digest, Sha256};

fn password_file_path() -> anyhow::Result<PathBuf> {
    Ok(config_dir()?.join(PASSWORD_FILE_NAME))
}

fn password_file_lock_path() -> anyhow::Result<PathBuf> {
    Ok(config_dir()?.join(PASSWORD_FILE_LOCK_NAME))
}

struct PasswordFileTransactionLock {
    file: std::fs::File,
}

impl Drop for PasswordFileTransactionLock {
    fn drop(&mut self) {
        if let Err(error) = self.file.unlock() {
            warn!(
                error_kind = storage_error_kind(&error.into()),
                "Password file transaction lock release failed"
            );
        }
    }
}

fn acquire_password_file_transaction_lock() -> anyhow::Result<PasswordFileTransactionLock> {
    ensure_config_dir()?;
    acquire_password_file_transaction_lock_at(&password_file_lock_path()?)
}

fn acquire_password_file_transaction_lock_at(
    path: &Path,
) -> anyhow::Result<PasswordFileTransactionLock> {
    if let Some(parent) = path.parent() {
        validate_private_dir(parent)?;
    }

    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|error| {
                if no_follow_open_error(&error) {
                    anyhow::anyhow!("password transaction lock must be a regular private file")
                } else {
                    error.into()
                }
            })?
    };

    #[cfg(windows)]
    let file = {
        use std::os::windows::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .custom_flags(windows::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT.0)
            .open(path)?
    };

    #[cfg(not(any(unix, windows)))]
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)?;

    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        anyhow::bail!("password transaction lock must be a regular private file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() } {
            anyhow::bail!("password transaction lock is not owned by the current user");
        }
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o600);
        file.set_permissions(permissions)?;
        crate::private_permissions::strip_macos_acl(path)?;
    }
    #[cfg(windows)]
    crate::private_permissions::validate_windows_private_file_handle(&file)?;
    secure_path_permissions(path, 0o600)?;

    file.lock()?;
    Ok(PasswordFileTransactionLock { file })
}

fn with_password_file_transaction<T>(
    operation: impl FnOnce() -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    let _lock = acquire_password_file_transaction_lock()?;
    prepare_password_file_transaction()?;
    operation()
}

fn prepare_password_file_transaction() -> anyhow::Result<()> {
    let dir = config_dir()?;
    cleanup_storage_temp_files_in_dir(&dir, PASSWORD_TRANSACTION_TEMP_FILE_PREFIXES)?;
    reconcile_staged_fallback_keys_if_safe(
        pending_storage_recovery_is_clear,
        reconcile_staged_fallback_keys,
        mark_storage_recovery_blocked,
    )?;
    Ok(())
}

/// Startup must reconcile staged fallback-key metadata after account-journal
/// recovery and before it clears the durable recovery latch. This uses the
/// same lock and preflight as every credential mutation, so another process
/// cannot insert a password-file revision between validation and cleanup.
pub(crate) fn reconcile_staged_fallback_keys_after_pending_recovery() -> anyhow::Result<()> {
    let _lock = acquire_password_file_transaction_lock()?;
    prepare_password_file_transaction()
}

fn staged_fallback_recovery_requires_block(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.is::<StagedFallbackKeyConflict>() || cause.is::<InvalidStagedFallbackKeyState>()
    })
}

fn reconcile_staged_fallback_keys_if_safe<P, R, B>(
    mut pending_recovery_is_clear: P,
    mut reconcile_staged_keys: R,
    mut mark_recovery_blocked: B,
) -> anyhow::Result<()>
where
    P: FnMut() -> anyhow::Result<bool>,
    R: FnMut() -> anyhow::Result<()>,
    B: FnMut() -> anyhow::Result<()>,
{
    match pending_recovery_is_clear() {
        Ok(true) => {
            if let Err(error) = reconcile_staged_keys() {
                if staged_fallback_recovery_requires_block(&error) {
                    // A collision with an active credential is corrupt metadata,
                    // as is an unreadable staged-key journal. Neither is
                    // ordinary best-effort orphan cleanup. Latch recovery
                    // durably before rejecting every further credential
                    // mutation.
                    mark_recovery_blocked()?;
                    return Err(error);
                }
                // An orphan contains key material but has no ciphertext
                // reference, so failed retirement should remain retryable
                // without denying access to active password records.
                warn!(
                    error_kind = storage_error_kind(&error),
                    "Staged fallback key recovery remains pending"
                );
            }
        }
        Ok(false) => {
            // A pending account transaction may refer to a newly staged key in
            // a password-file revision whose directory durability was
            // ambiguous. Keep every staged key until that transaction has
            // authenticated the winning revision and cleared its journal.
            debug!(
                "Deferring staged fallback key recovery while account storage recovery is pending"
            );
        }
        Err(error) => {
            // Failure to prove journal absence is equivalent to a pending
            // journal. Returning success here would let a keyring mutation
            // begin without knowing whether a forward fallback-key revision
            // is still protected by an account journal.
            mark_recovery_blocked()?;
            return Err(error.context(
                "pending password storage journal state could not be verified during credential preflight",
            ));
        }
    }
    Ok(())
}

fn fallback_key_file_path() -> anyhow::Result<PathBuf> {
    Ok(config_dir()?.join(FALLBACK_KEY_FILE_NAME))
}

fn staged_fallback_keys_file_path() -> anyhow::Result<PathBuf> {
    Ok(config_dir()?.join(STAGED_FALLBACK_KEYS_FILE_NAME))
}

fn pending_storage_operation_file_path() -> anyhow::Result<PathBuf> {
    Ok(config_dir()?.join(PENDING_STORAGE_OPERATION_FILE_NAME))
}

fn recovering_storage_operation_file_path() -> anyhow::Result<PathBuf> {
    Ok(config_dir()?.join(RECOVERING_STORAGE_OPERATION_FILE_NAME))
}

fn storage_recovery_block_file_path() -> anyhow::Result<PathBuf> {
    Ok(config_dir()?.join(STORAGE_RECOVERY_BLOCK_FILE_NAME))
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
struct PasswordFile {
    #[serde(default)]
    passwords: HashMap<String, String>,
    /// New-format fallback entries use a distinct key for every account and
    /// every password revision. Missing entries are legacy ciphertexts that
    /// still use the former shared fallback key and are migrated together.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    key_ids: HashMap<AccountId, String>,
    /// Keys are retired only after the new ciphertext map has been committed.
    /// Keeping the references in the committed file makes a crash or a
    /// transient Keychain/Credential Manager error recoverable on the next
    /// fallback access.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    retired_keys: Vec<ScopedFallbackKeyRef>,
    #[serde(default, skip_serializing_if = "is_false")]
    retire_legacy_shared_key: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq, Hash)]
struct ScopedFallbackKeyRef {
    account_id: AccountId,
    key_id: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
struct StagedFallbackKeysJournal {
    version: u8,
    #[serde(default)]
    keys: Vec<ScopedFallbackKeyRef>,
}

impl Default for StagedFallbackKeysJournal {
    fn default() -> Self {
        Self {
            version: STAGED_FALLBACK_KEYS_VERSION,
            keys: Vec::new(),
        }
    }
}

#[derive(Debug, serde::Serialize)]
struct ScopedFallbackKeyEnvelope<'a> {
    version: u8,
    service: &'a str,
    account_id_sha256: String,
    key_id: &'a str,
    key: &'a str,
}

#[derive(Debug, serde::Deserialize)]
struct ScopedFallbackKeyEnvelopeOwned {
    version: u8,
    service: String,
    account_id_sha256: String,
    key_id: String,
    key: Zeroizing<String>,
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
struct PendingStorageOperation {
    version: u8,
    kind: String,
    #[serde(default)]
    account_ids: Vec<AccountId>,
    #[serde(default)]
    from_use_keyring: bool,
    #[serde(default)]
    to_use_keyring: bool,
    #[serde(default)]
    use_keyring: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    before_account: Option<Account>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    after_account: Option<Account>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rollback_marker: Option<String>,
}

#[derive(Debug)]
struct PendingStorageOperationRecord {
    operation: PendingStorageOperation,
    path: PathBuf,
}

#[derive(Debug, serde::Serialize)]
struct StoredPasswordEnvelopeV1<'a> {
    version: u8,
    service: String,
    account_id: AccountId,
    username_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    rollback_marker: Option<&'a str>,
    password: &'a str,
}

#[derive(Debug, serde::Deserialize)]
struct StoredPasswordEnvelopeV1Owned {
    version: u8,
    service: String,
    account_id: AccountId,
    username_sha256: String,
    #[serde(default)]
    rollback_marker: Option<String>,
    password: Zeroizing<String>,
}

#[derive(Debug, serde::Deserialize)]
struct StoredPasswordEnvelopeV2Owned {
    version: u8,
    service: String,
    account_id: AccountId,
    username_sha256: String,
    #[serde(rename = "target_window_title_sha256")]
    _target_window_title_sha256: String,
    #[serde(default)]
    rollback_marker: Option<String>,
    password: Zeroizing<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StoredPasswordFormat {
    BoundV1,
    BoundV2,
    LegacyRaw,
}

struct SecureStorageSecret {
    plaintext: Zeroizing<String>,
    needs_migration: bool,
}

fn canonical_username(username: &str) -> String {
    username.trim().to_lowercase()
}

fn username_binding_hash(username: &str) -> String {
    sha256_hex(canonical_username(username).as_bytes())
}

fn password_binding_matches(left: &Account, right: &Account) -> bool {
    left.id == right.id
        && username_binding_hash(&left.username) == username_binding_hash(&right.username)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn redacted_account_id(account_id: &str) -> &'static str {
    if account_id.trim().is_empty() {
        ""
    } else {
        "[account]"
    }
}

fn validate_rollback_marker(marker: &str) -> anyhow::Result<()> {
    let parsed = uuid::Uuid::parse_str(marker)
        .map_err(|_| anyhow::anyhow!("stored password has an invalid rollback marker"))?;
    if parsed.hyphenated().to_string() != marker {
        anyhow::bail!("stored password has a non-canonical rollback marker");
    }
    Ok(())
}

fn encode_bound_password(account: &Account, password: &str) -> anyhow::Result<Zeroizing<String>> {
    encode_bound_password_with_rollback_marker(account, password, None)
}

fn encode_bound_password_with_rollback_marker(
    account: &Account,
    password: &str,
    rollback_marker: Option<&str>,
) -> anyhow::Result<Zeroizing<String>> {
    if let Some(marker) = rollback_marker {
        validate_rollback_marker(marker)?;
    }
    let envelope = StoredPasswordEnvelopeV1 {
        version: PASSWORD_ENVELOPE_VERSION,
        service: SERVICE_NAME.to_string(),
        account_id: account.id.clone(),
        username_sha256: username_binding_hash(&account.username),
        rollback_marker,
        password,
    };
    let json = Zeroizing::new(serde_json::to_string(&envelope)?);
    let mut payload = Zeroizing::new(String::with_capacity(
        PASSWORD_ENVELOPE_PREFIX.len() + json.len(),
    ));
    payload.push_str(PASSWORD_ENVELOPE_PREFIX);
    payload.push_str(json.as_str());
    Ok(payload)
}

#[cfg(all(test, target_os = "windows"))]
fn encode_keyring_password(account: &Account, password: &str) -> anyhow::Result<Zeroizing<String>> {
    encode_keyring_password_with_rollback_marker(account, password, None)
}

fn encode_keyring_password_with_rollback_marker(
    account: &Account,
    password: &str,
    rollback_marker: Option<&str>,
) -> anyhow::Result<Zeroizing<String>> {
    let payload = encode_bound_password_with_rollback_marker(account, password, rollback_marker)?;
    encode_secure_storage_secret(SECURE_STORAGE_PASSWORD_PURPOSE, payload.as_str())
}

fn decode_keyring_password(
    account: &Account,
    stored: &str,
) -> anyhow::Result<(
    Zeroizing<String>,
    StoredPasswordFormat,
    bool,
    Option<String>,
)> {
    let secret = decode_secure_storage_secret(SECURE_STORAGE_PASSWORD_PURPOSE, stored)?;
    let (password, format, rollback_marker) =
        decode_bound_password_with_rollback_marker(account, secret.plaintext.as_str())?;
    Ok((password, format, secret.needs_migration, rollback_marker))
}

#[cfg(not(target_os = "windows"))]
fn encode_secure_storage_secret(
    _purpose: &str,
    plaintext: &str,
) -> anyhow::Result<Zeroizing<String>> {
    Ok(Zeroizing::new(plaintext.to_string()))
}

#[cfg(not(target_os = "windows"))]
fn decode_secure_storage_secret(
    _purpose: &str,
    stored: &str,
) -> anyhow::Result<SecureStorageSecret> {
    Ok(SecureStorageSecret {
        plaintext: Zeroizing::new(stored.to_string()),
        needs_migration: false,
    })
}

#[cfg(target_os = "windows")]
fn encode_secure_storage_secret(
    purpose: &str,
    plaintext: &str,
) -> anyhow::Result<Zeroizing<String>> {
    if plaintext.is_empty() {
        anyhow::bail!("user-bound secure storage payload is empty");
    }
    let protected = windows_user_bound_protect(purpose, plaintext.as_bytes())?;
    let encoded = STANDARD.encode(&*protected);
    let mut payload = Zeroizing::new(String::with_capacity(
        WINDOWS_USER_BOUND_SECRET_PREFIX.len() + encoded.len(),
    ));
    payload.push_str(WINDOWS_USER_BOUND_SECRET_PREFIX);
    payload.push_str(&encoded);
    Ok(payload)
}

#[cfg(target_os = "windows")]
fn decode_secure_storage_secret(
    purpose: &str,
    stored: &str,
) -> anyhow::Result<SecureStorageSecret> {
    if let Some(encoded) = stored.strip_prefix(WINDOWS_USER_BOUND_SECRET_PREFIX) {
        let protected = Zeroizing::new(STANDARD.decode(encoded)?);
        let plaintext_bytes = windows_user_bound_unprotect(purpose, &protected)?;
        return Ok(SecureStorageSecret {
            plaintext: zeroizing_bytes_into_string(plaintext_bytes)?,
            needs_migration: false,
        });
    }
    if let Some(encoded) = stored.strip_prefix(WINDOWS_LEGACY_WAAB_SECRET_PREFIX) {
        let protected = Zeroizing::new(STANDARD.decode(encoded)?);
        let plaintext_bytes = windows_legacy_waab_unprotect(purpose, &protected)?;
        return Ok(SecureStorageSecret {
            plaintext: zeroizing_bytes_into_string(plaintext_bytes)?,
            needs_migration: true,
        });
    }
    if has_unsupported_windows_bound_prefix(stored) {
        anyhow::bail!("unsupported Windows user-bound secure storage payload version");
    }
    if stored.is_empty() {
        anyhow::bail!("secure storage payload is empty");
    }
    Ok(SecureStorageSecret {
        plaintext: Zeroizing::new(stored.to_string()),
        needs_migration: true,
    })
}

#[cfg(target_os = "windows")]
fn has_unsupported_windows_bound_prefix(stored: &str) -> bool {
    (stored.starts_with("waub") && !stored.starts_with(WINDOWS_USER_BOUND_SECRET_PREFIX))
        || (stored.starts_with("waab") && !stored.starts_with(WINDOWS_LEGACY_WAAB_SECRET_PREFIX))
}

#[cfg(target_os = "windows")]
fn windows_user_bound_protect(
    purpose: &str,
    plaintext: &[u8],
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let entropy = windows_user_bound_entropy(purpose);
    windows_protect_data_with_entropy(plaintext, &entropy)
        .map_err(|e| anyhow::anyhow!("Windows user-bound DPAPI protect failed: {e}"))
}

#[cfg(target_os = "windows")]
fn windows_user_bound_unprotect(
    purpose: &str,
    protected: &[u8],
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let entropy = windows_user_bound_entropy(purpose);
    windows_unprotect_data_with_entropy(protected, &entropy)
        .map_err(|e| anyhow::anyhow!("Windows user-bound DPAPI unprotect failed: {e}"))
}

#[cfg(target_os = "windows")]
fn windows_legacy_waab_unprotect(
    purpose: &str,
    protected: &[u8],
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let entropy = windows_legacy_waab_entropy(purpose);
    windows_unprotect_data_with_entropy(protected, &entropy)
        .map_err(|e| anyhow::anyhow!("Windows legacy user-bound DPAPI unprotect failed: {e}"))
}

#[cfg(target_os = "windows")]
fn windows_protect_data_with_entropy(
    plaintext: &[u8],
    entropy: &[u8; 32],
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    use windows::Win32::Security::Cryptography::{
        CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    let mut input = Zeroizing::new(plaintext.to_vec());
    let mut entropy = Zeroizing::new(entropy.to_vec());
    let input_blob = windows_data_blob(&mut input)?;
    let entropy_blob = windows_data_blob(&mut entropy)?;
    let mut output_blob = CRYPT_INTEGER_BLOB::default();

    unsafe {
        CryptProtectData(
            &input_blob,
            windows::core::PCWSTR::null(),
            Some(&entropy_blob as *const _),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output_blob,
        )
        .map_err(|e| anyhow::anyhow!("{e}"))?;

        windows_blob_to_zeroizing_vec_and_free(&mut output_blob)
    }
}

#[cfg(target_os = "windows")]
fn windows_unprotect_data_with_entropy(
    protected: &[u8],
    entropy: &[u8; 32],
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    use windows::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    let mut input = Zeroizing::new(protected.to_vec());
    let mut entropy = Zeroizing::new(entropy.to_vec());
    let input_blob = windows_data_blob(&mut input)?;
    let entropy_blob = windows_data_blob(&mut entropy)?;
    let mut output_blob = CRYPT_INTEGER_BLOB::default();

    unsafe {
        CryptUnprotectData(
            &input_blob,
            None,
            Some(&entropy_blob as *const _),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output_blob,
        )
        .map_err(|e| anyhow::anyhow!("{e}"))?;

        windows_blob_to_zeroizing_vec_and_free(&mut output_blob)
    }
}

#[cfg(target_os = "windows")]
fn windows_data_blob(
    bytes: &mut [u8],
) -> anyhow::Result<windows::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB> {
    if bytes.is_empty() {
        anyhow::bail!("Windows user-bound DPAPI blob is empty");
    }
    let cb_data = u32::try_from(bytes.len())
        .map_err(|_| anyhow::anyhow!("Windows user-bound DPAPI blob is too large"))?;
    Ok(windows::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB {
        cbData: cb_data,
        pbData: bytes.as_mut_ptr(),
    })
}

#[cfg(target_os = "windows")]
unsafe fn windows_blob_to_zeroizing_vec_and_free(
    blob: &mut windows::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    if blob.pbData.is_null() || blob.cbData == 0 {
        anyhow::bail!("Windows user-bound DPAPI returned an empty blob");
    }
    let local_blob = WindowsLocalBlob {
        ptr: blob.pbData,
        len: blob.cbData as usize,
    };
    *blob = windows::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB::default();
    let bytes = unsafe { std::slice::from_raw_parts(local_blob.ptr, local_blob.len) };
    Ok(Zeroizing::new(bytes.to_vec()))
}

#[cfg(target_os = "windows")]
struct WindowsLocalBlob {
    ptr: *mut u8,
    len: usize,
}

#[cfg(target_os = "windows")]
impl Drop for WindowsLocalBlob {
    fn drop(&mut self) {
        use windows::Win32::Foundation::{LocalFree, HLOCAL};

        if self.ptr.is_null() {
            return;
        }
        // DPAPI allocates both protect and unprotect output with LocalAlloc.
        // Wipe the OS-owned allocation before releasing it. This is essential
        // for plaintext and cheap defense-in-depth for protected output.
        unsafe {
            std::slice::from_raw_parts_mut(self.ptr, self.len).zeroize();
            let _ = LocalFree(Some(HLOCAL(self.ptr.cast())));
        }
        self.ptr = std::ptr::null_mut();
        self.len = 0;
    }
}

fn zeroizing_bytes_into_string(mut bytes: Zeroizing<Vec<u8>>) -> anyhow::Result<Zeroizing<String>> {
    match String::from_utf8(std::mem::take(&mut *bytes)) {
        Ok(value) => Ok(Zeroizing::new(value)),
        Err(error) => {
            let _invalid_bytes = Zeroizing::new(error.into_bytes());
            anyhow::bail!("secure storage plaintext is not valid UTF-8")
        }
    }
}

#[cfg(any(target_os = "windows", test))]
fn windows_user_bound_entropy(purpose: &str) -> [u8; 32] {
    windows_bound_entropy(WINDOWS_USER_BOUND_STORAGE_VERSION, purpose)
}

#[cfg(any(target_os = "windows", test))]
fn windows_legacy_waab_entropy(purpose: &str) -> [u8; 32] {
    windows_bound_entropy(WINDOWS_LEGACY_WAAB_STORAGE_VERSION, purpose)
}

#[cfg(any(target_os = "windows", test))]
fn windows_bound_entropy(storage_version: &str, purpose: &str) -> [u8; 32] {
    let mut material = Vec::new();
    material.extend_from_slice(storage_version.as_bytes());
    material.push(0);
    material.extend_from_slice(crate::app_identity::APP_NAME.as_bytes());
    material.push(0);
    material.extend_from_slice(SERVICE_NAME.as_bytes());
    material.push(0);
    material.extend_from_slice(purpose.as_bytes());

    let digest = Sha256::digest(&material);
    let mut entropy = [0u8; 32];
    entropy.copy_from_slice(&digest);
    entropy
}

fn decode_bound_password(
    account: &Account,
    stored: &str,
) -> anyhow::Result<(Zeroizing<String>, StoredPasswordFormat)> {
    let (password, format, _) = decode_bound_password_with_rollback_marker(account, stored)?;
    Ok((password, format))
}

fn decode_bound_password_with_rollback_marker(
    account: &Account,
    stored: &str,
) -> anyhow::Result<(Zeroizing<String>, StoredPasswordFormat, Option<String>)> {
    if let Some(json) = stored.strip_prefix(PASSWORD_ENVELOPE_V2_PREFIX) {
        let envelope: StoredPasswordEnvelopeV2Owned = serde_json::from_str(json)?;
        if envelope.version != PASSWORD_ENVELOPE_V2_VERSION
            || envelope.service != SERVICE_NAME
            || envelope.account_id != account.id
            || envelope.username_sha256 != username_binding_hash(&account.username)
        {
            anyhow::bail!("stored password binding does not match account metadata");
        }
        if let Some(marker) = envelope.rollback_marker.as_deref() {
            validate_rollback_marker(marker)?;
        }

        return Ok((
            envelope.password,
            StoredPasswordFormat::BoundV2,
            envelope.rollback_marker,
        ));
    }

    let Some(json) = stored.strip_prefix(PASSWORD_ENVELOPE_PREFIX) else {
        if stored.is_empty() {
            anyhow::bail!("stored password is empty");
        }
        return Ok((
            Zeroizing::new(stored.to_string()),
            StoredPasswordFormat::LegacyRaw,
            None,
        ));
    };

    let envelope: StoredPasswordEnvelopeV1Owned = serde_json::from_str(json)?;
    if envelope.version != PASSWORD_ENVELOPE_VERSION
        || envelope.service != SERVICE_NAME
        || envelope.account_id != account.id
        || envelope.username_sha256 != username_binding_hash(&account.username)
    {
        anyhow::bail!("stored password binding does not match account metadata");
    }
    if let Some(marker) = envelope.rollback_marker.as_deref() {
        validate_rollback_marker(marker)?;
    }

    Ok((
        envelope.password,
        StoredPasswordFormat::BoundV1,
        envelope.rollback_marker,
    ))
}

fn load_password_file() -> anyhow::Result<PasswordFile> {
    let path = password_file_path()?;
    if !storage_operation_file_exists(&path)? {
        return Ok(PasswordFile::default());
    }
    let content = match read_private_text_file(&path, MAX_PASSWORD_FILE_BYTES) {
        Ok(c) => c,
        Err(e) => {
            warn!(path = %redacted_path(&path), error = %e, "Failed to read password file");
            return Err(e);
        }
    };
    let file: PasswordFile = match serde_json::from_str::<PasswordFile>(&content) {
        Ok(f) => f,
        Err(e) => {
            warn!(path = %redacted_path(&path), error = %e, "Failed to parse password file JSON");
            return Err(e.into());
        }
    };
    validate_password_file_shape(&file)?;
    Ok(file)
}

fn validate_password_file_shape(file: &PasswordFile) -> anyhow::Result<()> {
    if file.passwords.len() > 2048 {
        anyhow::bail!("password file contains too many entries");
    }
    for (account_id, encrypted) in &file.passwords {
        if account_id.trim().is_empty() || account_id.len() > 256 {
            anyhow::bail!("password file contains invalid account id");
        }
        if encrypted.len() > MAX_ENCRYPTED_PASSWORD_ENTRY_CHARS {
            anyhow::bail!("password file contains oversized encrypted entry");
        }
    }
    if file.key_ids.len() > file.passwords.len() {
        anyhow::bail!("password file contains orphan fallback key references");
    }
    let mut active_key_ids = HashSet::new();
    for (account_id, key_id) in &file.key_ids {
        if !file.passwords.contains_key(account_id) {
            anyhow::bail!("password file contains orphan fallback key reference");
        }
        validate_fallback_key_id(key_id)?;
        if !active_key_ids.insert(key_id.as_str()) {
            anyhow::bail!("password file reuses a scoped fallback key");
        }
    }
    if file.retired_keys.len() > MAX_RETIRED_FALLBACK_KEYS {
        anyhow::bail!("password file contains too many retired fallback keys");
    }
    let mut retired_key_ids = HashSet::new();
    for retired in &file.retired_keys {
        if retired.account_id.trim().is_empty() || retired.account_id.len() > 256 {
            anyhow::bail!("password file contains invalid retired fallback account id");
        }
        validate_fallback_key_id(&retired.key_id)?;
        if active_key_ids.contains(retired.key_id.as_str()) {
            anyhow::bail!("password file retires an active fallback key");
        }
        if !retired_key_ids.insert(retired.key_id.as_str()) {
            anyhow::bail!("password file contains duplicate retired fallback key");
        }
    }
    if file.retire_legacy_shared_key
        && file
            .passwords
            .keys()
            .any(|id| !file.key_ids.contains_key(id))
    {
        anyhow::bail!("password file retires the shared key while legacy entries remain");
    }
    Ok(())
}

fn validate_fallback_key_id(key_id: &str) -> anyhow::Result<()> {
    if key_id.is_empty() || key_id.len() > MAX_FALLBACK_KEY_ID_CHARS {
        anyhow::bail!("password file contains invalid fallback key id");
    }
    let parsed = uuid::Uuid::parse_str(key_id)
        .map_err(|_| anyhow::anyhow!("password file contains invalid fallback key id"))?;
    if parsed.hyphenated().to_string() != key_id {
        anyhow::bail!("password file contains non-canonical fallback key id");
    }
    Ok(())
}

fn validate_scoped_fallback_key_ref(key_ref: &ScopedFallbackKeyRef) -> anyhow::Result<()> {
    if key_ref.account_id.trim().is_empty() || key_ref.account_id.len() > 256 {
        anyhow::bail!("staged fallback key journal contains invalid account id");
    }
    validate_fallback_key_id(&key_ref.key_id)
}

fn validate_staged_fallback_keys_journal(
    journal: &StagedFallbackKeysJournal,
) -> anyhow::Result<()> {
    if journal.version != STAGED_FALLBACK_KEYS_VERSION {
        anyhow::bail!("staged fallback key journal has unsupported version");
    }
    if journal.keys.len() > MAX_STAGED_FALLBACK_KEYS {
        anyhow::bail!("staged fallback key journal contains too many entries");
    }
    let mut key_ids = HashSet::new();
    for key_ref in &journal.keys {
        validate_scoped_fallback_key_ref(key_ref)?;
        if !key_ids.insert(key_ref.key_id.as_str()) {
            anyhow::bail!("staged fallback key journal contains a duplicate key id");
        }
    }
    Ok(())
}

fn load_staged_fallback_keys_journal() -> anyhow::Result<StagedFallbackKeysJournal> {
    let path = staged_fallback_keys_file_path()?;
    if !storage_operation_file_exists(&path)? {
        return Ok(StagedFallbackKeysJournal::default());
    }
    let content = read_private_text_file(&path, MAX_STAGED_FALLBACK_KEYS_FILE_BYTES)?;
    let journal = serde_json::from_str::<StagedFallbackKeysJournal>(&content)?;
    validate_staged_fallback_keys_journal(&journal)?;
    Ok(journal)
}

fn save_staged_fallback_keys_journal(journal: &StagedFallbackKeysJournal) -> anyhow::Result<()> {
    validate_staged_fallback_keys_journal(journal)?;
    let path = staged_fallback_keys_file_path()?;
    if journal.keys.is_empty() {
        return delete_sensitive_private_file_if_present(&path);
    }
    let content = serde_json::to_string_pretty(journal)?;
    write_private_file_atomic(&path, "json.tmp", content.as_bytes())
}

fn track_staged_fallback_key(key_ref: &ScopedFallbackKeyRef) -> anyhow::Result<()> {
    validate_scoped_fallback_key_ref(key_ref)?;
    let mut journal = load_staged_fallback_keys_journal()?;
    if !journal.keys.contains(key_ref) {
        journal.keys.push(key_ref.clone());
        save_staged_fallback_keys_journal(&journal)?;
    }
    Ok(())
}

fn untrack_staged_fallback_keys(keys: &[ScopedFallbackKeyRef]) -> anyhow::Result<()> {
    if keys.is_empty() {
        return Ok(());
    }
    let key_ids = keys
        .iter()
        .map(|key_ref| key_ref.key_id.as_str())
        .collect::<HashSet<_>>();
    let mut journal = load_staged_fallback_keys_journal()?;
    journal
        .keys
        .retain(|key_ref| !key_ids.contains(key_ref.key_id.as_str()));
    save_staged_fallback_keys_journal(&journal)
}

fn active_scoped_fallback_keys_by_id(file: &PasswordFile) -> HashMap<String, AccountId> {
    file.key_ids
        .iter()
        .map(|(account_id, key_id)| (key_id.clone(), account_id.clone()))
        .collect()
}

fn reconcile_staged_fallback_keys() -> anyhow::Result<()> {
    let journal = load_staged_fallback_keys_journal()
        .map_err(|source| anyhow::Error::new(InvalidStagedFallbackKeyState { source }))?;
    if journal.keys.is_empty() {
        return Ok(());
    }

    // Active key addresses must be known before any staged credential can be
    // classified as an orphan. A malformed password file therefore blocks
    // recovery instead of degrading to best-effort deletion.
    let file = load_password_file()
        .map_err(|source| anyhow::Error::new(InvalidStagedFallbackKeyState { source }))?;

    let active = active_scoped_fallback_keys_by_id(&file);
    reconcile_staged_fallback_keys_with_ops(journal, &active, delete_scoped_fallback_key, |next| {
        save_staged_fallback_keys_journal(next)
    })
}

fn reconcile_staged_fallback_keys_with_ops<D, S>(
    mut journal: StagedFallbackKeysJournal,
    active_keys_by_id: &HashMap<String, AccountId>,
    mut delete_key: D,
    mut save_journal: S,
) -> anyhow::Result<()>
where
    D: FnMut(&ScopedFallbackKeyRef) -> anyhow::Result<()>,
    S: FnMut(&StagedFallbackKeysJournal) -> anyhow::Result<()>,
{
    let mut remaining = Vec::new();
    let mut failures = 0usize;
    let mut conflicts = 0usize;
    for key_ref in std::mem::take(&mut journal.keys) {
        // The system credential-store address is derived from key_id alone.
        // A corrupt/stale journal may pair an active key_id with a different
        // account_id; comparing the whole pair would then delete the live
        // credential. Protect every active credential by its actual address.
        if let Some(active_account_id) = active_keys_by_id.get(&key_ref.key_id) {
            if active_account_id == &key_ref.account_id {
                continue;
            }
            // A key-id collision with a different account is corrupt metadata,
            // not a proven orphan. Keep it retryable and fail closed rather
            // than silently erasing the evidence or deleting the live key.
            conflicts += 1;
            warn!(
                account_id = %redacted_account_id(&key_ref.account_id),
                "Staged fallback key journal conflicts with an active credential"
            );
            remaining.push(key_ref);
            continue;
        }
        if let Err(error) = delete_key(&key_ref) {
            failures += 1;
            warn!(
                account_id = %redacted_account_id(&key_ref.account_id),
                error_kind = storage_error_kind(&error),
                "Crash-orphaned staged fallback key cleanup failed"
            );
            remaining.push(key_ref);
        }
    }
    journal.keys = remaining;
    if conflicts > 0 {
        if let Err(error) = save_journal(&journal) {
            return Err(anyhow::Error::new(
                StagedFallbackKeyConflict::with_journal_save_error(error),
            ));
        }
        return Err(anyhow::Error::new(StagedFallbackKeyConflict::new()));
    }
    save_journal(&journal)?;
    if failures > 0 {
        anyhow::bail!("{failures} staged fallback key cleanup attempts failed");
    }
    Ok(())
}

fn validate_pending_storage_operation(operation: &PendingStorageOperation) -> anyhow::Result<()> {
    if operation.version != PENDING_STORAGE_OPERATION_VERSION {
        anyhow::bail!("pending storage operation has unsupported version");
    }
    match operation.kind.as_str() {
        "storage_mode_migration" => {
            if operation.from_use_keyring == operation.to_use_keyring {
                anyhow::bail!("pending storage operation does not change storage backend");
            }
            if operation.before_account.is_some() || operation.after_account.is_some() {
                anyhow::bail!("storage migration journal must not contain account snapshots");
            }
            if operation.rollback_marker.is_some() {
                anyhow::bail!("storage migration journal must not contain a rollback marker");
            }
        }
        "account_config_save" => {
            let Some(after_account) = &operation.after_account else {
                anyhow::bail!("account config journal is missing target account");
            };
            if operation.account_ids.len() != 1
                || operation.account_ids[0] != after_account.id.as_str()
            {
                anyhow::bail!("account config journal account id does not match target account");
            }
            if operation
                .before_account
                .as_ref()
                .is_some_and(|before_account| before_account.id != after_account.id)
            {
                anyhow::bail!(
                    "account config journal source account id does not match target account"
                );
            }
            if let Some(marker) = operation.rollback_marker.as_deref() {
                validate_rollback_marker(marker)?;
            }
        }
        "account_config_rollback" => {
            let Some(before_account) = &operation.before_account else {
                anyhow::bail!("account rollback journal is missing source account");
            };
            if operation.after_account.is_some() {
                anyhow::bail!("account rollback journal must not contain a target account");
            }
            if operation.account_ids.len() != 1
                || operation.account_ids[0] != before_account.id.as_str()
            {
                anyhow::bail!("account rollback journal account id does not match source account");
            }
            // Pre-marker rollback journals may already exist after an older
            // process crash. Keep them valid enough to remain blocking; the
            // recovery path below deliberately refuses to complete them.
            if let Some(marker) = operation.rollback_marker.as_deref() {
                validate_rollback_marker(marker)?;
            }
        }
        "account_delete" | "account_delete_prepared" | "account_delete_committed" => {
            if operation.after_account.is_some() {
                anyhow::bail!("account delete journal must not contain target account");
            }
            if operation.account_ids.len() != 1 {
                anyhow::bail!("account delete journal must contain one account id");
            }
            if operation.kind != "account_delete" && operation.before_account.is_none() {
                anyhow::bail!("phased account delete journal is missing source account");
            }
            if let Some(before_account) = &operation.before_account {
                if operation.account_ids[0] != before_account.id.as_str() {
                    anyhow::bail!(
                        "account delete journal account id does not match source account"
                    );
                }
            }
            if operation.rollback_marker.is_some() {
                anyhow::bail!("account delete journal must not contain a rollback marker");
            }
        }
        "account_enabled_toggle_prepared" | "account_enabled_toggle_committed" => {
            let Some(before_account) = &operation.before_account else {
                anyhow::bail!("account enabled-toggle journal is missing source account");
            };
            let Some(after_account) = &operation.after_account else {
                anyhow::bail!("account enabled-toggle journal is missing target account");
            };
            if operation.account_ids.len() != 1
                || operation.account_ids[0] != before_account.id.as_str()
                || operation.account_ids[0] != after_account.id.as_str()
            {
                anyhow::bail!(
                    "account enabled-toggle journal account id does not match its snapshots"
                );
            }
            let mut expected_after = before_account.clone();
            expected_after.enabled = after_account.enabled;
            if before_account.enabled == after_account.enabled || &expected_after != after_account {
                anyhow::bail!("account enabled-toggle journal changes fields other than enabled");
            }
            if operation.rollback_marker.is_some() {
                anyhow::bail!(
                    "account enabled-toggle journal must not contain a password revision marker"
                );
            }
        }
        _ => anyhow::bail!("pending storage operation has unsupported kind"),
    }
    for account_id in &operation.account_ids {
        if account_id.trim().is_empty() || account_id.len() > 256 {
            anyhow::bail!("pending storage operation contains invalid account id");
        }
    }
    Ok(())
}

fn save_password_file(file: &PasswordFile) -> anyhow::Result<()> {
    ensure_config_dir()?;
    validate_password_file_shape(file)?;
    let path = password_file_path()?;
    let content = match serde_json::to_string_pretty(file) {
        Ok(c) => c,
        Err(e) => {
            warn!(path = %redacted_path(&path), error = %e, "Failed to serialize password file");
            return Err(e.into());
        }
    };
    write_password_file_atomic(&path, "json.tmp", content.as_bytes())?;
    debug!(path = %redacted_path(&path), entries = file.passwords.len(), "Password file written");
    Ok(())
}

fn write_password_file_atomic(
    path: &Path,
    temp_extension: &str,
    bytes: &[u8],
) -> anyhow::Result<()> {
    match write_private_file_atomic(path, temp_extension, bytes) {
        Err(error) if private_file_write_committed(&error) => {
            Err(anyhow::Error::new(PasswordFileWriteCommitted {
                source: error,
            }))
        }
        result => result,
    }
}

fn write_private_file_atomic(
    path: &Path,
    temp_extension: &str,
    bytes: &[u8],
) -> anyhow::Result<()> {
    use std::io::Write;

    if let Some(parent) = path.parent() {
        validate_private_dir(parent)?;
    }

    let nonce = chrono::Utc::now()
        .timestamp_nanos_opt()
        .unwrap_or_default()
        .unsigned_abs();
    let temp_path =
        path.with_extension(format!("{temp_extension}.{}.{}", std::process::id(), nonce));
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
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temp_path)?;
        crate::private_permissions::strip_macos_acl(&temp_path)?;
        if let Err(e) = file.write_all(bytes).and_then(|_| file.sync_all()) {
            let _ = std::fs::remove_file(&temp_path);
            return Err(e.into());
        }
    }

    #[cfg(not(unix))]
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)?;
        if let Err(e) = secure_path_permissions(&temp_path, 0o600) {
            let _ = std::fs::remove_file(&temp_path);
            return Err(e);
        }
        if let Err(e) = file.write_all(bytes).and_then(|_| file.sync_all()) {
            let _ = std::fs::remove_file(&temp_path);
            return Err(e.into());
        }
    }

    if let Err(e) = secure_path_permissions(&temp_path, 0o600) {
        let _ = std::fs::remove_file(&temp_path);
        return Err(e);
    }
    if let Err(e) = replace_private_file(&temp_path, path) {
        let _ = std::fs::remove_file(&temp_path);
        return Err(e);
    }
    finish_private_file_commit_with_ops(
        path,
        |target| secure_path_permissions(target, 0o600),
        sync_parent_dir,
    )
}

fn finish_private_file_commit_with_ops<P, S>(
    path: &Path,
    mut secure_permissions: P,
    mut sync_parent: S,
) -> anyhow::Result<()>
where
    P: FnMut(&Path) -> anyhow::Result<()>,
    S: FnMut(&Path) -> anyhow::Result<()>,
{
    secure_permissions(path)
        .map_err(|source| anyhow::Error::new(PrivateFileWriteCommitted { source }))?;
    sync_parent(path).map_err(|source| anyhow::Error::new(PrivateFileWriteCommitted { source }))?;
    Ok(())
}

#[cfg(windows)]
fn replace_private_file(temp_path: &Path, path: &Path) -> anyhow::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    if let Some(parent) = path.parent() {
        validate_private_dir(parent)?;
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => validate_private_file_for_read(path)?,
        Ok(_) => anyhow::bail!("{} is not a regular private file", redacted_path(path)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }

    let temp_path = temp_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let path = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();

    unsafe {
        MoveFileExW(
            PCWSTR(temp_path.as_ptr()),
            PCWSTR(path.as_ptr()),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )?;
    }
    Ok(())
}

#[cfg(not(windows))]
fn replace_private_file(temp_path: &Path, path: &Path) -> anyhow::Result<()> {
    std::fs::rename(temp_path, path)?;
    Ok(())
}

fn write_private_file_create_new_atomic(
    path: &Path,
    temp_extension: &str,
    bytes: &[u8],
) -> anyhow::Result<()> {
    use std::io::Write;

    if let Some(parent) = path.parent() {
        validate_private_dir(parent)?;
    }

    let nonce = chrono::Utc::now()
        .timestamp_nanos_opt()
        .unwrap_or_default()
        .unsigned_abs();
    let temp_path =
        path.with_extension(format!("{temp_extension}.{}.{}", std::process::id(), nonce));
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
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temp_path)?;
        crate::private_permissions::strip_macos_acl(&temp_path)?;
        if let Err(e) = file.write_all(bytes).and_then(|_| file.sync_all()) {
            let _ = std::fs::remove_file(&temp_path);
            return Err(e.into());
        }
    }

    #[cfg(not(unix))]
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)?;
        if let Err(e) = secure_path_permissions(&temp_path, 0o600) {
            let _ = std::fs::remove_file(&temp_path);
            return Err(e);
        }
        if let Err(e) = file.write_all(bytes).and_then(|_| file.sync_all()) {
            let _ = std::fs::remove_file(&temp_path);
            return Err(e.into());
        }
    }

    if let Err(e) = secure_path_permissions(&temp_path, 0o600)
        .and_then(|_| std::fs::hard_link(&temp_path, path).map_err(anyhow::Error::from))
        .and_then(|_| secure_path_permissions(path, 0o600))
        .and_then(|_| sync_parent_dir(path))
    {
        let _ = std::fs::remove_file(&temp_path);
        return Err(e);
    }
    if let Err(e) = std::fs::remove_file(&temp_path) {
        warn!(
            path = %redacted_path(&temp_path),
            error = %e,
            "private create-new temp file cleanup failed after commit"
        );
    } else if let Err(e) = sync_parent_dir(&temp_path) {
        warn!(
            path = %redacted_path(&temp_path),
            error = %e,
            "private create-new temp file cleanup committed, but parent directory sync failed"
        );
    }
    Ok(())
}

#[cfg(unix)]
fn sync_parent_dir(path: &Path) -> anyhow::Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    sync_dir(parent)?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent_dir(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn sync_dir(path: &Path) -> anyhow::Result<()> {
    std::fs::File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_dir(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

fn new_scoped_fallback_key_ref(account_id: &AccountId) -> anyhow::Result<ScopedFallbackKeyRef> {
    if account_id.trim().is_empty() || account_id.len() > 256 {
        anyhow::bail!("cannot create a fallback key for an invalid account id");
    }
    Ok(ScopedFallbackKeyRef {
        account_id: account_id.clone(),
        key_id: uuid::Uuid::new_v4().hyphenated().to_string(),
    })
}

fn new_scoped_fallback_key_material() -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    rand::thread_rng().fill(&mut *key);
    key
}

fn scoped_fallback_key_account(key_ref: &ScopedFallbackKeyRef) -> anyhow::Result<String> {
    validate_fallback_key_id(&key_ref.key_id)?;
    Ok(format!(
        "{SCOPED_FALLBACK_KEY_ACCOUNT_PREFIX}{}",
        key_ref.key_id
    ))
}

fn scoped_fallback_key_purpose(key_ref: &ScopedFallbackKeyRef) -> String {
    let mut material = Zeroizing::new(Vec::with_capacity(
        key_ref.account_id.len() + key_ref.key_id.len() + 1,
    ));
    material.extend_from_slice(key_ref.account_id.as_bytes());
    material.push(0);
    material.extend_from_slice(key_ref.key_id.as_bytes());
    format!("scoped-fallback-key:{}", sha256_hex(&material))
}

fn encode_scoped_fallback_key(
    key_ref: &ScopedFallbackKeyRef,
    key: &[u8; 32],
) -> anyhow::Result<Zeroizing<String>> {
    let encoded_key = Zeroizing::new(STANDARD.encode(key));
    let envelope = ScopedFallbackKeyEnvelope {
        version: SCOPED_FALLBACK_KEY_VERSION,
        service: FALLBACK_KEY_SERVICE_NAME,
        account_id_sha256: sha256_hex(key_ref.account_id.as_bytes()),
        key_id: &key_ref.key_id,
        key: encoded_key.as_str(),
    };
    let plaintext = Zeroizing::new(serde_json::to_string(&envelope)?);
    encode_secure_storage_secret(&scoped_fallback_key_purpose(key_ref), plaintext.as_str())
}

fn decode_scoped_fallback_key(
    key_ref: &ScopedFallbackKeyRef,
    stored: &str,
) -> anyhow::Result<Zeroizing<[u8; 32]>> {
    let decoded = decode_secure_storage_secret(&scoped_fallback_key_purpose(key_ref), stored)?;
    let envelope: ScopedFallbackKeyEnvelopeOwned =
        serde_json::from_str(decoded.plaintext.as_str())?;
    if envelope.version != SCOPED_FALLBACK_KEY_VERSION
        || envelope.service != FALLBACK_KEY_SERVICE_NAME
        || envelope.account_id_sha256 != sha256_hex(key_ref.account_id.as_bytes())
        || envelope.key_id != key_ref.key_id
    {
        anyhow::bail!("scoped fallback key binding does not match password metadata");
    }
    decode_fallback_encryption_key(envelope.key.trim())
}

fn save_scoped_fallback_key_payload(
    key_ref: &ScopedFallbackKeyRef,
    payload: &str,
) -> anyhow::Result<()> {
    let entry = keyring::Entry::new(
        FALLBACK_KEY_SERVICE_NAME,
        &scoped_fallback_key_account(key_ref)?,
    )
    .map_err(|e| {
        anyhow::anyhow!(
            "{} is unavailable for scoped fallback key storage: {e}",
            native_secure_storage_name()
        )
    })?;
    entry.set_password(payload).map_err(|e| {
        anyhow::anyhow!(
            "{} refused to save a scoped fallback key: {e}",
            native_secure_storage_name()
        )
    })
}

fn load_scoped_fallback_key(key_ref: &ScopedFallbackKeyRef) -> anyhow::Result<Zeroizing<[u8; 32]>> {
    let entry = keyring::Entry::new(
        FALLBACK_KEY_SERVICE_NAME,
        &scoped_fallback_key_account(key_ref)?,
    )?;
    let stored = Zeroizing::new(entry.get_password()?);
    decode_scoped_fallback_key(key_ref, stored.as_str())
}

fn delete_scoped_fallback_key(key_ref: &ScopedFallbackKeyRef) -> anyhow::Result<()> {
    let entry = keyring::Entry::new(
        FALLBACK_KEY_SERVICE_NAME,
        &scoped_fallback_key_account(key_ref)?,
    )?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(anyhow::anyhow!(
            "{} refused to retire a scoped fallback key: {e}",
            native_secure_storage_name()
        )),
    }
}

fn fallback_encryption_key() -> anyhow::Result<Zeroizing<[u8; 32]>> {
    ensure_config_dir()?;
    if let Err(e) = cleanup_legacy_fallback_key_residue_files_if_present() {
        warn!(
            error = %e,
            "Legacy fallback key residue cleanup failed; continuing"
        );
    }

    let entry =
        keyring::Entry::new(FALLBACK_KEY_SERVICE_NAME, FALLBACK_KEY_ACCOUNT).map_err(|e| {
            anyhow::anyhow!(
                "{} is unavailable for fallback key: {e}",
                native_secure_storage_name()
            )
        })?;
    match entry.get_password() {
        Ok(encoded) => {
            let encoded = Zeroizing::new(encoded);
            let decoded =
                decode_secure_storage_secret(SECURE_STORAGE_FALLBACK_KEY_PURPOSE, encoded.trim())?;
            let key = decode_fallback_encryption_key(decoded.plaintext.trim())?;
            let migration_result = if decoded.needs_migration {
                let payload = encode_secure_storage_secret(
                    SECURE_STORAGE_FALLBACK_KEY_PURPOSE,
                    decoded.plaintext.trim(),
                )?;
                let result = entry.set_password(payload.as_str());
                drop(payload);
                Some(result)
            } else {
                None
            };
            // `key` is an independent zeroizing copy. Retire provider payloads
            // before migration diagnostics or stale-file cleanup can block.
            drop(decoded);
            drop(encoded);
            if let Some(result) = migration_result {
                if let Err(e) = result {
                    warn!(error = %e, "Fallback key loaded from legacy Credential Manager format, but user-bound DPAPI migration failed");
                } else {
                    info!("Migrated fallback key to Windows user-bound DPAPI Credential Manager storage");
                }
            }
            cleanup_stale_fallback_key_file_if_present()?;
            return Ok(key);
        }
        Err(keyring::Error::NoEntry) => {}
        Err(e) => anyhow::bail!(
            "{} refused to load fallback key: {e}",
            native_secure_storage_name()
        ),
    }

    if let Some((legacy_key_path, legacy_key)) = load_legacy_fallback_key_from_file()? {
        let encoded = Zeroizing::new(STANDARD.encode(*legacy_key));
        let payload =
            encode_secure_storage_secret(SECURE_STORAGE_FALLBACK_KEY_PURPOSE, encoded.as_str())?;
        let set_result = entry.set_password(payload.as_str());
        drop(payload);
        drop(encoded);
        set_result.map_err(|e| {
            anyhow::anyhow!(
                "{} refused to migrate fallback key: {e}",
                native_secure_storage_name()
            )
        })?;
        cleanup_legacy_fallback_key_file(&legacy_key_path)?;
        return Ok(legacy_key);
    }

    let mut key = Zeroizing::new([0u8; 32]);
    rand::thread_rng().fill(&mut *key);
    let encoded = Zeroizing::new(STANDARD.encode(*key));
    let payload =
        encode_secure_storage_secret(SECURE_STORAGE_FALLBACK_KEY_PURPOSE, encoded.as_str())?;
    let set_result = entry.set_password(payload.as_str());
    drop(payload);
    drop(encoded);
    set_result.map_err(|e| {
        anyhow::anyhow!(
            "{} refused to save fallback key: {e}",
            native_secure_storage_name()
        )
    })?;
    Ok(key)
}

fn load_legacy_fallback_key_from_file() -> anyhow::Result<Option<(PathBuf, Zeroizing<[u8; 32]>)>> {
    let path = fallback_key_file_path()?;
    if !path.exists() {
        return Ok(None);
    }

    let key = match read_fallback_encryption_key(&path) {
        Ok(key) => key,
        Err(e) => {
            warn!(path = %redacted_path(&path), error = %e, "Fallback key file is invalid; deleting it without backup");
            if let Err(cleanup_error) = delete_sensitive_private_file_if_present(&path) {
                warn!(
                    path = %redacted_path(&path),
                    error = %cleanup_error,
                    "Invalid fallback key file cleanup failed"
                );
            }
            return Ok(None);
        }
    };

    Ok(Some((path, key)))
}

fn cleanup_stale_fallback_key_file_if_present() -> anyhow::Result<()> {
    let path = fallback_key_file_path()?;
    cleanup_legacy_fallback_key_file(&path)?;
    Ok(())
}

fn cleanup_legacy_fallback_key_file(path: &Path) -> anyhow::Result<()> {
    if let Err(e) = delete_sensitive_private_file_if_present(path) {
        warn!(
            path = %redacted_path(path),
            error = %e,
            "fallback key was migrated to Keychain, but stale key file cleanup failed"
        );
        return Err(e);
    }
    Ok(())
}

fn delete_fallback_key_material() -> anyhow::Result<()> {
    delete_fallback_key_material_with_ops(
        delete_fallback_key_from_keyring,
        delete_legacy_fallback_key_file_if_present,
    )
}

fn delete_fallback_key_material_with_ops<DK, DL>(
    mut delete_secure_key_op: DK,
    mut delete_legacy_key_file_op: DL,
) -> anyhow::Result<()>
where
    DK: FnMut() -> anyhow::Result<()>,
    DL: FnMut() -> anyhow::Result<()>,
{
    let mut failures = Vec::new();

    if let Err(e) = delete_secure_key_op() {
        warn!(
            error_kind = storage_error_kind(&e),
            error = %e,
            "Fallback key secure storage cleanup failed; continuing"
        );
        failures.push("secure storage key cleanup failed");
    }

    if let Err(e) = delete_legacy_key_file_op() {
        warn!(
            error_kind = storage_error_kind(&e),
            error = %e,
            "Legacy fallback key file cleanup failed"
        );
        failures.push("legacy key file cleanup failed");
    }

    if failures.is_empty() {
        Ok(())
    } else {
        anyhow::bail!("fallback key cleanup incomplete: {}", failures.join("; "))
    }
}

fn delete_fallback_key_from_keyring() -> anyhow::Result<()> {
    let entry =
        keyring::Entry::new(FALLBACK_KEY_SERVICE_NAME, FALLBACK_KEY_ACCOUNT).map_err(|e| {
            anyhow::anyhow!(
                "{} is unavailable for fallback key cleanup: {e}",
                native_secure_storage_name()
            )
        })?;
    match entry.delete_credential() {
        Ok(()) => {
            debug!("Fallback encryption key deleted from secure storage");
            Ok(())
        }
        Err(keyring::Error::NoEntry) => {
            debug!("Fallback encryption key did not exist");
            Ok(())
        }
        Err(e) => Err(anyhow::anyhow!(
            "{} refused to delete fallback key: {e}",
            native_secure_storage_name()
        )),
    }
}

fn delete_legacy_fallback_key_file_if_present() -> anyhow::Result<()> {
    cleanup_legacy_fallback_key_residue_files_if_present()?;
    let path = fallback_key_file_path()?;
    cleanup_legacy_fallback_key_file(&path)?;
    cleanup_legacy_fallback_key_residue_files_if_present()?;
    Ok(())
}

fn cleanup_legacy_fallback_key_residue_files_if_present() -> anyhow::Result<usize> {
    let dir = config_dir()?;
    if !dir.exists() {
        return Ok(0);
    }
    cleanup_legacy_fallback_key_residue_files_in_dir(&dir)
}

fn cleanup_legacy_fallback_key_residue_files_in_dir(dir: &Path) -> anyhow::Result<usize> {
    validate_private_dir(dir)?;

    let mut cleaned = 0;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };
        if !LEGACY_FALLBACK_KEY_RESIDUE_PREFIXES
            .iter()
            .any(|prefix| file_name.starts_with(prefix))
        {
            continue;
        }
        let path = entry.path();
        if std::fs::symlink_metadata(&path)?.file_type().is_dir() {
            continue;
        }
        delete_sensitive_private_file_if_present(&path)?;
        cleaned += 1;
    }
    Ok(cleaned)
}

fn read_fallback_encryption_key(path: &Path) -> anyhow::Result<Zeroizing<[u8; 32]>> {
    let content = Zeroizing::new(read_private_text_file(path, MAX_FALLBACK_KEY_FILE_BYTES)?);
    decode_fallback_encryption_key(content.trim())
}

fn decode_fallback_encryption_key(encoded: &str) -> anyhow::Result<Zeroizing<[u8; 32]>> {
    let bytes = Zeroizing::new(STANDARD.decode(encoded)?);
    if bytes.len() != 32 {
        anyhow::bail!("invalid fallback key length");
    }

    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&bytes);
    Ok(key)
}

fn encrypt_password_with_key(key: &[u8; 32], plaintext: &str) -> anyhow::Result<String> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| anyhow::anyhow!("failed to create cipher: {:?}", e))?;
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = Zeroizing::new(
        cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| anyhow::anyhow!("encryption failed: {:?}", e))?,
    );
    let mut combined = Zeroizing::new(nonce_bytes.to_vec());
    combined.extend_from_slice(&ciphertext);
    Ok(STANDARD.encode(&*combined))
}

fn decrypt_password_with_key(key: &[u8; 32], data: &[u8]) -> anyhow::Result<Zeroizing<String>> {
    if data.len() < AES_GCM_NONCE_BYTES + AES_GCM_TAG_BYTES {
        anyhow::bail!("invalid ciphertext: too short");
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| anyhow::anyhow!("failed to create cipher: {:?}", e))?;
    let nonce = Nonce::from_slice(&data[..AES_GCM_NONCE_BYTES]);
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(nonce, &data[AES_GCM_NONCE_BYTES..])
            .map_err(|e| anyhow::anyhow!("decryption failed: {:?}", e))?,
    );
    zeroizing_bytes_into_string(plaintext)
}

fn decrypt_password_with_fallback_key(
    key: &[u8; 32],
    encoded: &str,
) -> anyhow::Result<Zeroizing<String>> {
    if encoded.len() > MAX_ENCRYPTED_PASSWORD_ENTRY_CHARS {
        anyhow::bail!("encrypted password entry is too large");
    }
    let data = Zeroizing::new(STANDARD.decode(encoded)?);
    decrypt_password_with_key(key, &data)
}

fn scoped_fallback_key_ref(
    file: &PasswordFile,
    account_id: &AccountId,
) -> Option<ScopedFallbackKeyRef> {
    file.key_ids
        .get(account_id)
        .map(|key_id| ScopedFallbackKeyRef {
            account_id: account_id.clone(),
            key_id: key_id.clone(),
        })
}

fn push_retired_fallback_key(file: &mut PasswordFile, key_ref: ScopedFallbackKeyRef) {
    if !file.retired_keys.contains(&key_ref) {
        file.retired_keys.push(key_ref);
    }
}

fn install_scoped_fallback_entry(
    file: &mut PasswordFile,
    account_id: &AccountId,
    key_ref: &ScopedFallbackKeyRef,
    encrypted: String,
) {
    let old_key_ref = scoped_fallback_key_ref(file, account_id);
    file.passwords.insert(account_id.clone(), encrypted);
    file.key_ids
        .insert(account_id.clone(), key_ref.key_id.clone());
    if let Some(old_key_ref) = old_key_ref {
        push_retired_fallback_key(file, old_key_ref);
    }
}

fn remove_fallback_entry(file: &mut PasswordFile, account_id: &AccountId) -> bool {
    if file.passwords.remove(account_id).is_none() {
        return false;
    }
    if let Some(key_id) = file.key_ids.remove(account_id) {
        push_retired_fallback_key(
            file,
            ScopedFallbackKeyRef {
                account_id: account_id.clone(),
                key_id,
            },
        );
    }
    true
}

fn stage_scoped_fallback_entry(
    account_id: &AccountId,
    plaintext: Zeroizing<String>,
) -> anyhow::Result<(ScopedFallbackKeyRef, String)> {
    let key_ref = new_scoped_fallback_key_ref(account_id)?;
    // Persist cleanup intent before creating either half of the recoverable
    // secret. On macOS the Keychain accepts plaintext provider payloads, so
    // doing this first prevents filesystem/journal I/O from retaining an AES
    // key equivalent next to its ciphertext after encryption's final use.
    track_staged_fallback_key(&key_ref)?;

    let stage_result = (|| {
        let key = new_scoped_fallback_key_material();
        let encrypted_result = encrypt_password_with_key(&key, plaintext.as_str());
        // Encryption is the password's final use. Destroy it before provider
        // payload construction or any later operation can block.
        drop(plaintext);
        let encrypted = encrypted_result?;
        let key_payload_result = encode_scoped_fallback_key(&key_ref, &key);
        // Provider-payload construction is the raw key's final use.
        drop(key);
        let key_payload = key_payload_result?;
        // Hand the payload straight to the native provider. In particular,
        // no lock wait, recovery scan, or journal/filesystem write may occur
        // while macOS retains this plaintext Keychain payload and ciphertext.
        let save_result = save_scoped_fallback_key_payload(&key_ref, key_payload.as_str());
        drop(key_payload);
        save_result?;
        Ok(encrypted)
    })();

    let encrypted = match stage_result {
        Ok(encrypted) => encrypted,
        Err(error) => {
            // A provider may persist the value before reporting an error. The
            // staged journal is removed only after provider deletion is confirmed.
            cleanup_uncommitted_scoped_keys(std::slice::from_ref(&key_ref));
            return Err(error);
        }
    };
    Ok((key_ref, encrypted))
}

fn cleanup_uncommitted_scoped_keys(keys: &[ScopedFallbackKeyRef]) {
    let mut deleted = Vec::new();
    for key_ref in keys {
        match delete_scoped_fallback_key(key_ref) {
            Ok(()) => deleted.push(key_ref.clone()),
            Err(e) => {
                warn!(
                    account_id = %redacted_account_id(&key_ref.account_id),
                    error_kind = storage_error_kind(&e),
                    "Uncommitted scoped fallback key cleanup failed"
                );
            }
        }
    }
    if let Err(e) = untrack_staged_fallback_keys(&deleted) {
        warn!(
            error_kind = storage_error_kind(&e),
            "Uncommitted fallback keys were deleted, but staged-key journal cleanup failed"
        );
    }
}

fn migrate_legacy_fallback_entries(
    file: &mut PasswordFile,
) -> anyhow::Result<Vec<ScopedFallbackKeyRef>> {
    let legacy_account_ids = file
        .passwords
        .keys()
        .filter(|account_id| !file.key_ids.contains_key(*account_id))
        .cloned()
        .collect::<Vec<_>>();
    if legacy_account_ids.is_empty() {
        file.retire_legacy_shared_key = true;
        return Ok(Vec::new());
    }

    migrate_legacy_fallback_entries_with_ops(
        file,
        &legacy_account_ids,
        fallback_encryption_key,
        stage_scoped_fallback_entry,
        cleanup_uncommitted_scoped_keys,
    )
}

fn migrate_legacy_fallback_entries_with_ops<LK, SE, CK>(
    file: &mut PasswordFile,
    legacy_account_ids: &[AccountId],
    mut load_shared_key: LK,
    mut stage_entry: SE,
    mut cleanup_uncommitted: CK,
) -> anyhow::Result<Vec<ScopedFallbackKeyRef>>
where
    LK: FnMut() -> anyhow::Result<Zeroizing<[u8; 32]>>,
    SE: FnMut(&AccountId, Zeroizing<String>) -> anyhow::Result<(ScopedFallbackKeyRef, String)>,
    CK: FnMut(&[ScopedFallbackKeyRef]),
{
    let mut staged = Vec::<(ScopedFallbackKeyRef, String)>::new();
    for account_id in legacy_account_ids {
        let staged_entry = (|| {
            let encrypted = password_entry_for_account(file, account_id)?;
            let shared_key = load_shared_key()?;
            let plaintext_result = decrypt_password_with_fallback_key(&shared_key, encrypted);
            // Decryption is the final shared-key use for this one legacy
            // entry. Wipe it before per-entry secure-storage staging can
            // block, and reload it only for the next ciphertext.
            drop(shared_key);
            let plaintext = plaintext_result?;
            stage_entry(account_id, plaintext)
        })();
        match staged_entry {
            Ok(entry) => staged.push(entry),
            Err(e) => {
                let staged_keys = staged
                    .iter()
                    .map(|(key_ref, _)| key_ref.clone())
                    .collect::<Vec<_>>();
                cleanup_uncommitted(&staged_keys);
                return Err(e);
            }
        }
    }

    for (key_ref, encrypted) in &staged {
        file.passwords
            .insert(key_ref.account_id.clone(), encrypted.clone());
        file.key_ids
            .insert(key_ref.account_id.clone(), key_ref.key_id.clone());
    }
    file.retire_legacy_shared_key = true;
    Ok(staged.into_iter().map(|(key_ref, _)| key_ref).collect())
}

fn cleanup_retired_fallback_keys(file: &mut PasswordFile) -> anyhow::Result<bool> {
    cleanup_retired_fallback_keys_with_ops(
        file,
        delete_scoped_fallback_key,
        delete_fallback_key_material,
    )
}

fn cleanup_retired_fallback_keys_with_ops<DS, DL>(
    file: &mut PasswordFile,
    mut delete_scoped: DS,
    mut delete_legacy_shared: DL,
) -> anyhow::Result<bool>
where
    DS: FnMut(&ScopedFallbackKeyRef) -> anyhow::Result<()>,
    DL: FnMut() -> anyhow::Result<()>,
{
    let mut changed = false;
    let mut failures = 0usize;
    let mut remaining = Vec::new();
    for key_ref in std::mem::take(&mut file.retired_keys) {
        match delete_scoped(&key_ref) {
            Ok(()) => changed = true,
            Err(e) => {
                failures += 1;
                warn!(
                    account_id = %redacted_account_id(&key_ref.account_id),
                    error_kind = storage_error_kind(&e),
                    "Retired scoped fallback key cleanup failed"
                );
                remaining.push(key_ref);
            }
        }
    }
    file.retired_keys = remaining;

    if file.retire_legacy_shared_key {
        match delete_legacy_shared() {
            Ok(()) => {
                file.retire_legacy_shared_key = false;
                changed = true;
            }
            Err(e) => {
                failures += 1;
                warn!(
                    error_kind = storage_error_kind(&e),
                    "Retired shared fallback key cleanup failed"
                );
            }
        }
    }

    if failures == 0 {
        Ok(changed)
    } else {
        anyhow::bail!("{failures} retired fallback key cleanup attempts failed")
    }
}

fn commit_password_file_with_staged_keys<SF, CK>(
    file: &PasswordFile,
    staged_keys: &[ScopedFallbackKeyRef],
    save_file: SF,
    cleanup_uncommitted: CK,
) -> anyhow::Result<bool>
where
    SF: FnMut(&PasswordFile) -> anyhow::Result<()>,
    CK: FnMut(&[ScopedFallbackKeyRef]),
{
    commit_password_file_with_staged_keys_with_ops(
        file,
        staged_keys,
        save_file,
        cleanup_uncommitted,
        untrack_staged_fallback_keys,
    )
}

fn commit_password_file_with_staged_keys_with_ops<SF, CK, UT>(
    file: &PasswordFile,
    staged_keys: &[ScopedFallbackKeyRef],
    mut save_file: SF,
    mut cleanup_uncommitted: CK,
    mut untrack_staged: UT,
) -> anyhow::Result<bool>
where
    SF: FnMut(&PasswordFile) -> anyhow::Result<()>,
    CK: FnMut(&[ScopedFallbackKeyRef]),
    UT: FnMut(&[ScopedFallbackKeyRef]) -> anyhow::Result<()>,
{
    match save_file(file) {
        Ok(()) => {
            if let Err(e) = untrack_staged(staged_keys) {
                warn!(
                    error_kind = storage_error_kind(&e),
                    "Password file committed, but staged-key journal cleanup remains pending"
                );
                return Ok(true);
            }
            Ok(false)
        }
        Err(e) => {
            if password_file_write_committed(&e) {
                warn!(
                    error_kind = storage_error_kind(&e),
                    "Password file replacement completed, but directory durability is unconfirmed; staged keys remain journaled until startup resolves the durable password-file revision"
                );
                return Ok(true);
            }
            cleanup_uncommitted(staged_keys);
            Err(e)
        }
    }
}

fn password_file_write_committed(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.is::<PasswordFileWriteCommitted>())
}

fn use_owned_secret_then_drop<S, T>(
    secret: S,
    use_secret: impl FnOnce(&S) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    let result = use_secret(&secret);
    drop(secret);
    result
}

fn stage_and_commit_fallback_payload_with_ops<SE, ML, SF, CK>(
    file: &mut PasswordFile,
    account: &Account,
    payload: Zeroizing<String>,
    mut stage_entry: SE,
    mut migrate_legacy: ML,
    save_file: SF,
    mut cleanup_uncommitted: CK,
) -> anyhow::Result<bool>
where
    SE: FnMut(&AccountId, Zeroizing<String>) -> anyhow::Result<(ScopedFallbackKeyRef, String)>,
    ML: FnMut(&mut PasswordFile) -> anyhow::Result<Vec<ScopedFallbackKeyRef>>,
    SF: FnMut(&PasswordFile) -> anyhow::Result<()>,
    CK: FnMut(&[ScopedFallbackKeyRef]),
{
    let stage_result = stage_entry(&account.id, payload);
    // The bound plaintext has already been encrypted (or staging failed).
    // Wipe it before legacy-key migration and password-file commit can block.
    let (new_key_ref, encrypted) = stage_result?;
    let mut staged_keys = vec![new_key_ref.clone()];
    install_scoped_fallback_entry(file, &account.id, &new_key_ref, encrypted);
    match migrate_legacy(file) {
        Ok(mut migrated) => staged_keys.append(&mut migrated),
        Err(e) => {
            cleanup_uncommitted(&staged_keys);
            return Err(e);
        }
    }
    commit_password_file_with_staged_keys(file, &staged_keys, save_file, cleanup_uncommitted)
}

fn stage_and_commit_persisted_fallback_entry(
    file: &mut PasswordFile,
    account: &Account,
    new_key_ref: ScopedFallbackKeyRef,
    encrypted: String,
) -> anyhow::Result<bool> {
    let mut staged_keys = vec![new_key_ref.clone()];
    install_scoped_fallback_entry(file, &account.id, &new_key_ref, encrypted);
    match migrate_legacy_fallback_entries(file) {
        Ok(mut migrated) => staged_keys.append(&mut migrated),
        Err(e) => {
            cleanup_uncommitted_scoped_keys(&staged_keys);
            return Err(e);
        }
    }
    commit_password_file_with_staged_keys(
        file,
        &staged_keys,
        save_password_file,
        cleanup_uncommitted_scoped_keys,
    )
}

/// Returns a non-secret warning flag. Cleanup failure never invalidates a
/// password-file commit; failed key references remain in the file so the next
/// locked transaction can retry them.
fn finalize_fallback_key_retirement(file: &mut PasswordFile) -> bool {
    let before = (file.retired_keys.len(), file.retire_legacy_shared_key);
    let cleanup_result = cleanup_retired_fallback_keys(file);
    let after = (file.retired_keys.len(), file.retire_legacy_shared_key);
    let mut warning = cleanup_result.is_err();
    if before != after {
        if let Err(e) = save_password_file(file) {
            warning = true;
            warn!(
                error_kind = storage_error_kind(&e),
                "Fallback key retirement succeeded, but cleanup metadata could not be committed"
            );
        }
    }
    if let Err(e) = cleanup_result {
        warn!(
            error_kind = storage_error_kind(&e),
            "Fallback key retirement remains pending and will be retried"
        );
    }
    warning
}

struct FallbackPasswordWriteOutcome {
    target_durability_warning: bool,
    key_cleanup_warning: bool,
}

fn save_to_file_with_rollback_marker(
    account: &Account,
    password: &str,
    rollback_marker: Option<&str>,
) -> anyhow::Result<FallbackPasswordWriteOutcome> {
    with_password_file_transaction(|| save_to_file_locked(account, password, rollback_marker))
}

fn save_to_file_owned(
    account: &Account,
    password: Zeroizing<String>,
    revision_marker: Option<&str>,
) -> anyhow::Result<FallbackPasswordWriteOutcome> {
    // Complete every potentially blocking lock/recovery operation before the
    // password's final encryption use. This lets staging destroy the bound
    // plaintext and send the macOS Keychain payload directly to the provider,
    // without retaining a decrypting key alongside ciphertext across I/O.
    let _lock = acquire_password_file_transaction_lock()?;
    prepare_password_file_transaction()?;
    let payload = use_owned_secret_then_drop(password, |password| {
        encode_bound_password_with_rollback_marker(account, password.as_str(), revision_marker)
    })?;
    let (new_key_ref, encrypted) = stage_scoped_fallback_entry(&account.id, payload)?;
    save_to_file_locked_persisted(account, new_key_ref, encrypted)
}

fn save_to_file_locked(
    account: &Account,
    password: &str,
    rollback_marker: Option<&str>,
) -> anyhow::Result<FallbackPasswordWriteOutcome> {
    let mut file = load_password_file()?;
    let mut key_cleanup_warning = finalize_fallback_key_retirement(&mut file);
    let payload = encode_bound_password_with_rollback_marker(account, password, rollback_marker)?;
    let password_file_durability_warning = match stage_and_commit_fallback_payload_with_ops(
        &mut file,
        account,
        payload,
        stage_scoped_fallback_entry,
        migrate_legacy_fallback_entries,
        save_password_file,
        cleanup_uncommitted_scoped_keys,
    ) {
        Ok(warning) => warning,
        Err(e) => {
            warn!(account_id = %redacted_account_id(&account.id), error = %e, "save_password_file failed");
            return Err(e);
        }
    };
    if !password_file_durability_warning {
        key_cleanup_warning |= finalize_fallback_key_retirement(&mut file);
    }
    Ok(FallbackPasswordWriteOutcome {
        target_durability_warning: password_file_durability_warning,
        key_cleanup_warning,
    })
}

fn save_to_file_locked_persisted(
    account: &Account,
    new_key_ref: ScopedFallbackKeyRef,
    encrypted: String,
) -> anyhow::Result<FallbackPasswordWriteOutcome> {
    let mut file = match load_password_file() {
        Ok(file) => file,
        Err(error) => {
            cleanup_uncommitted_scoped_keys(std::slice::from_ref(&new_key_ref));
            return Err(error);
        }
    };
    let mut key_cleanup_warning = finalize_fallback_key_retirement(&mut file);
    let password_file_durability_warning = match stage_and_commit_persisted_fallback_entry(
        &mut file,
        account,
        new_key_ref,
        encrypted,
    ) {
        Ok(warning) => warning,
        Err(e) => {
            warn!(account_id = %redacted_account_id(&account.id), error = %e, "save_password_file failed");
            return Err(e);
        }
    };
    if !password_file_durability_warning {
        key_cleanup_warning |= finalize_fallback_key_retirement(&mut file);
    }
    Ok(FallbackPasswordWriteOutcome {
        target_durability_warning: password_file_durability_warning,
        key_cleanup_warning,
    })
}

fn load_from_file(account: &Account) -> anyhow::Result<LoadedStoredPassword> {
    with_password_file_transaction(|| load_from_file_locked(account))
}

fn load_from_file_locked(account: &Account) -> anyhow::Result<LoadedStoredPassword> {
    let mut file = load_password_file()?;
    let _cleanup_warning = finalize_fallback_key_retirement(&mut file);
    let encrypted = Zeroizing::new(password_entry_for_account(&file, &account.id)?.to_string());
    if encrypted.len() > MAX_ENCRYPTED_PASSWORD_ENTRY_CHARS {
        anyhow::bail!("encrypted password entry is too large");
    }
    let active_key_ref = scoped_fallback_key_ref(&file, &account.id);
    let stored = if let Some(key_ref) = &active_key_ref {
        let key = load_scoped_fallback_key(key_ref)?;
        decrypt_password_with_fallback_key(&key, encrypted.as_str())?
    } else {
        let key = fallback_encryption_key()?;
        decrypt_password_with_fallback_key(&key, encrypted.as_str())?
    };
    let used_legacy_key = active_key_ref.is_none();
    let (password, format) = decode_bound_password(account, stored.as_str())?;
    let legacy_active_payload = if format == StoredPasswordFormat::LegacyRaw {
        Some(encode_bound_password(account, password.as_str())?)
    } else {
        None
    };
    // The first decode exists only to prepare migration. Re-read and decrypt
    // the committed file after migration so no reversible in-memory handoff
    // survives the intervening secure-storage/filesystem I/O.
    drop(password);
    drop(stored);
    drop(encrypted);

    let staged_active_entry = match legacy_active_payload {
        Some(payload) => Some(stage_scoped_fallback_entry(&account.id, payload)?),
        None => None,
    };

    let mut staged_keys = Vec::new();
    let mut staged_active_entry = staged_active_entry;
    let migration_result = (|| -> anyhow::Result<bool> {
        let has_legacy_entries = file
            .passwords
            .keys()
            .any(|account_id| !file.key_ids.contains_key(account_id));

        if let Some((new_key_ref, reencrypted)) = staged_active_entry.take() {
            staged_keys.push(new_key_ref.clone());
            install_scoped_fallback_entry(&mut file, &account.id, &new_key_ref, reencrypted);
        }

        if has_legacy_entries {
            staged_keys.extend(migrate_legacy_fallback_entries(&mut file)?);
        }

        Ok(has_legacy_entries || used_legacy_key || format == StoredPasswordFormat::LegacyRaw)
    })();

    match migration_result {
        Ok(true) => match commit_password_file_with_staged_keys(
            &file,
            &staged_keys,
            save_password_file,
            cleanup_uncommitted_scoped_keys,
        ) {
            Ok(password_file_durability_warning) => {
                if !password_file_durability_warning {
                    let _cleanup_warning = finalize_fallback_key_retirement(&mut file);
                }
                info!(account_id = %redacted_account_id(&account.id), "Migrated fallback password to independently rotated key storage");
            }
            Err(e) => {
                warn!(account_id = %redacted_account_id(&account.id), error = %e, "Password loaded from legacy fallback storage, but migration commit failed");
            }
        },
        Ok(false) => {
            let _cleanup_warning = finalize_fallback_key_retirement(&mut file);
        }
        Err(e) => {
            cleanup_uncommitted_scoped_keys(&staged_keys);
            warn!(account_id = %redacted_account_id(&account.id), error = %e, "Password loaded, but migration to independently rotated fallback key storage failed");
        }
    }

    let refreshed_file = load_password_file()?;
    let (password, rollback_marker) = load_password_from_file_snapshot(account, &refreshed_file)?;
    Ok(LoadedStoredPassword {
        password,
        rollback_marker,
        zeroizing_wrap_ms: 0,
    })
}

fn load_password_from_file_snapshot(
    account: &Account,
    file: &PasswordFile,
) -> anyhow::Result<(Zeroizing<String>, Option<String>)> {
    let encrypted = Zeroizing::new(password_entry_for_account(file, &account.id)?.to_string());
    if encrypted.len() > MAX_ENCRYPTED_PASSWORD_ENTRY_CHARS {
        anyhow::bail!("encrypted password entry is too large");
    }
    let stored = if let Some(key_ref) = scoped_fallback_key_ref(file, &account.id) {
        let key = load_scoped_fallback_key(&key_ref)?;
        decrypt_password_with_fallback_key(&key, encrypted.as_str())?
    } else {
        let key = fallback_encryption_key()?;
        decrypt_password_with_fallback_key(&key, encrypted.as_str())?
    };
    let (password, _, rollback_marker) =
        decode_bound_password_with_rollback_marker(account, stored.as_str())?;
    drop(stored);
    Ok((password, rollback_marker))
}

fn password_entry_for_account<'a>(
    file: &'a PasswordFile,
    account_id: &AccountId,
) -> anyhow::Result<&'a str> {
    file.passwords
        .get(account_id)
        .map(String::as_str)
        .ok_or_else(|| anyhow::anyhow!("password not found in fallback file"))
}

fn delete_from_file(account_id: &AccountId) -> anyhow::Result<()> {
    with_password_file_transaction(|| delete_from_file_locked(account_id))
}

fn delete_from_file_locked(account_id: &AccountId) -> anyhow::Result<()> {
    let mut file = load_password_file()?;
    let prior_cleanup_warning = finalize_fallback_key_retirement(&mut file);
    if !remove_fallback_entry(&mut file, account_id) {
        return if prior_cleanup_warning {
            anyhow::bail!("fallback key retirement remains pending")
        } else {
            Ok(())
        };
    }
    let staged_keys = migrate_legacy_fallback_entries(&mut file)?;
    let password_file_durability_warning = commit_password_file_with_staged_keys(
        &file,
        &staged_keys,
        save_password_file,
        cleanup_uncommitted_scoped_keys,
    )?;
    if prior_cleanup_warning
        || password_file_durability_warning
        || finalize_fallback_key_retirement(&mut file)
    {
        anyhow::bail!("password entry was deleted, but fallback key retirement remains pending")
    }
    Ok(())
}

pub(crate) fn cleanup_unused_fallback_key_material() -> anyhow::Result<()> {
    with_password_file_transaction(cleanup_unused_fallback_key_material_locked)
}

fn cleanup_unused_fallback_key_material_locked() -> anyhow::Result<()> {
    let mut file = load_password_file()?;
    let before = (file.retired_keys.len(), file.retire_legacy_shared_key);
    let cleanup_result = cleanup_retired_fallback_keys(&mut file);
    let after = (file.retired_keys.len(), file.retire_legacy_shared_key);
    if before != after {
        save_password_file(&file)?;
    }
    cleanup_result?;
    cleanup_fallback_key_if_password_file_empty(&file, delete_fallback_key_material)
}

fn cleanup_fallback_key_if_password_file_empty<DK>(
    file: &PasswordFile,
    mut delete_fallback_key_op: DK,
) -> anyhow::Result<()>
where
    DK: FnMut() -> anyhow::Result<()>,
{
    if file.passwords.is_empty() {
        delete_fallback_key_op()?;
    }
    Ok(())
}

fn delete_from_keyring(account_id: &AccountId) -> anyhow::Result<()> {
    let entry = keyring::Entry::new(SERVICE_NAME, account_id)?;
    match entry.delete_credential() {
        Ok(()) => {
            debug!(account_id = %redacted_account_id(account_id), "Keyring credential deleted");
            Ok(())
        }
        Err(keyring::Error::NoEntry) => {
            debug!(account_id = %redacted_account_id(account_id), "Keyring credential did not exist");
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PasswordStorageBackend {
    SystemSecureStorage,
    EncryptedFallbackFile,
}

impl PasswordStorageBackend {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::SystemSecureStorage => "system secure storage",
            Self::EncryptedFallbackFile => "encrypted fallback file",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StaleBackendCleanupWarning {
    pub(crate) saved_backend: PasswordStorageBackend,
    pub(crate) stale_backend: PasswordStorageBackend,
    pub(crate) error_kind: &'static str,
}

impl StaleBackendCleanupWarning {
    fn new(
        saved_backend: PasswordStorageBackend,
        stale_backend: PasswordStorageBackend,
        error: &anyhow::Error,
    ) -> Self {
        Self {
            saved_backend,
            stale_backend,
            error_kind: storage_error_kind(error),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SaveAccountOutcome {
    pub(crate) stale_cleanup_warning: Option<StaleBackendCleanupWarning>,
    /// The selected fallback-file write committed, but directory durability
    /// could not be confirmed. The stale backend is intentionally preserved.
    pub(crate) target_durability_warning: bool,
    /// The new password is committed, but one or more obsolete fallback keys
    /// could not yet be retired. Retry metadata remains in passwords.json.
    pub(crate) fallback_key_cleanup_warning: bool,
}

pub(crate) struct PasswordWriteReceipt {
    saved_backend: PasswordStorageBackend,
    target_durability_warning: bool,
    fallback_key_cleanup_warning: bool,
}

fn write_password_to_backend_borrowed(
    account: &Account,
    password: &str,
    use_keyring: bool,
    rollback_marker: Option<&str>,
) -> anyhow::Result<PasswordWriteReceipt> {
    debug!(account_id = %redacted_account_id(&account.id), use_keyring, "save_password called");
    if use_keyring {
        let entry = keyring::Entry::new(SERVICE_NAME, &account.id)
            .map_err(|e| anyhow::anyhow!("{} is unavailable: {e}", native_secure_storage_name()))?;
        let payload =
            encode_keyring_password_with_rollback_marker(account, password, rollback_marker)?;
        let set_result = entry.set_password(payload.as_str());
        // The provider has consumed the payload. Wipe it before stale-backend
        // cleanup performs unrelated filesystem or secure-storage I/O.
        drop(payload);
        match set_result {
            Ok(()) => {
                info!(account_id = %redacted_account_id(&account.id), "Password saved to secure storage successfully");
                return Ok(PasswordWriteReceipt {
                    saved_backend: PasswordStorageBackend::SystemSecureStorage,
                    target_durability_warning: false,
                    fallback_key_cleanup_warning: false,
                });
            }
            Err(e) => anyhow::bail!(
                "{} refused to save the password: {e}",
                native_secure_storage_name()
            ),
        }
    } else {
        warn!(
            account_id = %redacted_account_id(&account.id),
            "Keyring disabled; using weaker local encrypted file storage by explicit setting"
        );
    }
    let fallback_outcome = match save_to_file_with_rollback_marker(
        account,
        password,
        rollback_marker,
    ) {
        Ok(outcome) => outcome,
        Err(e) => {
            warn!(account_id = %redacted_account_id(&account.id), error = %e, "save_to_file failed");
            return Err(e);
        }
    };
    info!(
        account_id = %redacted_account_id(&account.id),
        "Password saved to fallback encrypted file storage"
    );
    Ok(PasswordWriteReceipt {
        saved_backend: PasswordStorageBackend::EncryptedFallbackFile,
        target_durability_warning: fallback_outcome.target_durability_warning,
        fallback_key_cleanup_warning: fallback_outcome.key_cleanup_warning,
    })
}

pub(crate) fn write_account_password_owned(
    account: &Account,
    password: Zeroizing<String>,
    use_keyring: bool,
) -> anyhow::Result<PasswordWriteReceipt> {
    write_account_password_owned_preflighted(account, password, use_keyring)
}

/// Direct/legacy writes have no outer account journal, so they must prove the
/// staged fallback-key state safe before any keyring/fallback provider
/// callback. Journaled callers use the `_with_revision` entry point: their
/// journal creation already performed the same preflight under this lock, and
/// taking it again would deadlock the fallback transaction.
fn write_account_password_owned_preflighted(
    account: &Account,
    password: Zeroizing<String>,
    use_keyring: bool,
) -> anyhow::Result<PasswordWriteReceipt> {
    direct_password_write_after_preflight_with_ops(
        password,
        use_keyring,
        acquire_password_file_transaction_lock,
        prepare_password_file_transaction,
        |password| write_account_password_owned_impl(account, password, use_keyring, None),
    )
}

fn direct_password_write_after_preflight_with_ops<G, R, L, P, W>(
    password: Zeroizing<String>,
    use_keyring: bool,
    acquire_lock: L,
    preflight: P,
    write_password: W,
) -> anyhow::Result<R>
where
    L: FnOnce() -> anyhow::Result<G>,
    P: FnOnce() -> anyhow::Result<()>,
    W: FnOnce(Zeroizing<String>) -> anyhow::Result<R>,
{
    if use_keyring {
        let _lock = acquire_lock()?;
        preflight()?;
        write_password(password)
    } else {
        // The fallback implementation acquires the same lock and runs the
        // preflight immediately before staging its provider payload.
        write_password(password)
    }
}

pub(crate) fn write_account_password_owned_with_revision(
    account: &Account,
    password: Zeroizing<String>,
    use_keyring: bool,
    revision_marker: &str,
) -> anyhow::Result<PasswordWriteReceipt> {
    validate_rollback_marker(revision_marker)?;
    write_account_password_owned_impl(account, password, use_keyring, Some(revision_marker))
}

fn write_account_password_owned_impl(
    account: &Account,
    password: Zeroizing<String>,
    use_keyring: bool,
    revision_marker: Option<&str>,
) -> anyhow::Result<PasswordWriteReceipt> {
    debug!(account_id = %redacted_account_id(&account.id), use_keyring, "save_account called");
    if password.is_empty() {
        anyhow::bail!("refusing to save an empty password")
    }

    if use_keyring {
        let entry = keyring::Entry::new(SERVICE_NAME, &account.id)
            .map_err(|e| anyhow::anyhow!("{} is unavailable: {e}", native_secure_storage_name()))?;
        let payload = use_owned_secret_then_drop(password, |password| {
            encode_keyring_password_with_rollback_marker(
                account,
                password.as_str(),
                revision_marker,
            )
        })?;
        let set_result = entry.set_password(payload.as_str());
        drop(payload);
        match set_result {
            Ok(()) => {
                info!(account_id = %redacted_account_id(&account.id), "Password saved to secure storage successfully");
                return Ok(PasswordWriteReceipt {
                    saved_backend: PasswordStorageBackend::SystemSecureStorage,
                    target_durability_warning: false,
                    fallback_key_cleanup_warning: false,
                });
            }
            Err(e) => anyhow::bail!(
                "{} refused to save the password: {e}",
                native_secure_storage_name()
            ),
        }
    }

    warn!(
        account_id = %redacted_account_id(&account.id),
        "Keyring disabled; using weaker local encrypted file storage by explicit setting"
    );
    let fallback_outcome = match save_to_file_owned(account, password, revision_marker) {
        Ok(outcome) => outcome,
        Err(e) => {
            warn!(account_id = %redacted_account_id(&account.id), error = %e, "save_to_file failed");
            return Err(e);
        }
    };
    info!(
        account_id = %redacted_account_id(&account.id),
        "Password saved to fallback encrypted file storage"
    );
    Ok(PasswordWriteReceipt {
        saved_backend: PasswordStorageBackend::EncryptedFallbackFile,
        target_durability_warning: fallback_outcome.target_durability_warning,
        fallback_key_cleanup_warning: fallback_outcome.key_cleanup_warning,
    })
}

pub(crate) fn write_account_password_borrowed_with_revision(
    account: &Account,
    password: &str,
    use_keyring: bool,
    revision_marker: &str,
) -> anyhow::Result<PasswordWriteReceipt> {
    validate_rollback_marker(revision_marker)?;
    write_account_password_borrowed_impl(account, password, use_keyring, Some(revision_marker))
}

fn write_account_password_borrowed_impl(
    account: &Account,
    password: &str,
    use_keyring: bool,
    revision_marker: Option<&str>,
) -> anyhow::Result<PasswordWriteReceipt> {
    if password.is_empty() {
        anyhow::bail!("refusing to save an empty password")
    }
    write_password_to_backend_borrowed(account, password, use_keyring, revision_marker)
}

pub(crate) fn write_account_password_borrowed_for_rollback(
    account: &Account,
    password: &str,
    use_keyring: bool,
    rollback_marker: Option<&str>,
) -> anyhow::Result<PasswordWriteReceipt> {
    if password.is_empty() {
        anyhow::bail!("refusing to save an empty password")
    }
    write_password_to_backend_borrowed(account, password, use_keyring, rollback_marker)
}

pub(crate) fn finish_account_password_write(
    account_id: &AccountId,
    receipt: PasswordWriteReceipt,
) -> SaveAccountOutcome {
    finish_account_password_write_with_ops(
        account_id,
        receipt,
        |account_id| {
            delete_from_file(account_id)?;
            cleanup_unused_fallback_key_material()
        },
        delete_from_keyring,
    )
}

fn finish_account_password_write_with_ops<DF, DK>(
    account_id: &AccountId,
    receipt: PasswordWriteReceipt,
    delete_from_file_op: DF,
    delete_from_keyring_op: DK,
) -> SaveAccountOutcome
where
    DF: FnMut(&AccountId) -> anyhow::Result<()>,
    DK: FnMut(&AccountId) -> anyhow::Result<()>,
{
    let stale_cleanup_warning = if receipt.target_durability_warning {
        warn!(account_id = %redacted_account_id(account_id), "Preserving stale password backend because target durability is unconfirmed");
        None
    } else {
        cleanup_stale_backend_after_successful_save(
            account_id,
            receipt.saved_backend,
            true,
            delete_from_file_op,
            delete_from_keyring_op,
        )
    };
    SaveAccountOutcome {
        stale_cleanup_warning,
        target_durability_warning: receipt.target_durability_warning,
        fallback_key_cleanup_warning: receipt.fallback_key_cleanup_warning,
    }
}

fn cleanup_stale_backend_after_successful_save<DF, DK>(
    account_id: &AccountId,
    saved_backend: PasswordStorageBackend,
    cleanup_stale_backend: bool,
    mut delete_from_file_op: DF,
    mut delete_from_keyring_op: DK,
) -> Option<StaleBackendCleanupWarning>
where
    DF: FnMut(&AccountId) -> anyhow::Result<()>,
    DK: FnMut(&AccountId) -> anyhow::Result<()>,
{
    if !cleanup_stale_backend {
        return None;
    }

    let stale_backend = match saved_backend {
        PasswordStorageBackend::SystemSecureStorage => {
            PasswordStorageBackend::EncryptedFallbackFile
        }
        PasswordStorageBackend::EncryptedFallbackFile => {
            PasswordStorageBackend::SystemSecureStorage
        }
    };
    let result = match stale_backend {
        PasswordStorageBackend::EncryptedFallbackFile => delete_from_file_op(account_id),
        PasswordStorageBackend::SystemSecureStorage => delete_from_keyring_op(account_id),
    };

    match result {
        Ok(()) => {
            debug!(
                account_id = %redacted_account_id(account_id),
                stale_backend = stale_backend.label(),
                "Stale password backend cleaned up"
            );
            None
        }
        Err(e) => {
            let warning = StaleBackendCleanupWarning::new(saved_backend, stale_backend, &e);
            warn!(
                account_id = %redacted_account_id(account_id),
                saved_backend = saved_backend.label(),
                stale_backend = stale_backend.label(),
                error_kind = warning.error_kind,
                error = %e,
                "Password saved to selected backend; stale backend cleanup failed"
            );
            Some(warning)
        }
    }
}

pub(crate) fn load_password(
    account: &Account,
    use_keyring: bool,
) -> anyhow::Result<Zeroizing<String>> {
    load_password_with_timing(account, use_keyring)
        .map(|result| result.password)
        .map_err(anyhow::Error::from)
}

pub(crate) fn load_password_for_rollback_verification(
    account: &Account,
    use_keyring: bool,
) -> anyhow::Result<(Zeroizing<String>, Option<String>)> {
    let loaded = if use_keyring {
        load_from_keyring_timed(account)?
    } else {
        load_from_file(account)?
    };
    Ok((loaded.password, loaded.rollback_marker))
}

#[derive(Debug, Clone)]
pub(crate) struct StorageModeMigration {
    migrated_account_ids: Vec<AccountId>,
    from_use_keyring: bool,
    to_use_keyring: bool,
}

impl StorageModeMigration {
    #[cfg(test)]
    pub(crate) fn for_test(
        migrated_account_ids: Vec<AccountId>,
        from_use_keyring: bool,
        to_use_keyring: bool,
    ) -> Self {
        Self {
            migrated_account_ids,
            from_use_keyring,
            to_use_keyring,
        }
    }
}

pub(crate) fn migrate_storage_mode(
    accounts: &[Account],
    from_use_keyring: bool,
    to_use_keyring: bool,
) -> anyhow::Result<StorageModeMigration> {
    if from_use_keyring == to_use_keyring {
        return Ok(StorageModeMigration {
            migrated_account_ids: Vec::new(),
            from_use_keyring,
            to_use_keyring,
        });
    }

    let mut migrated_account_ids = Vec::new();
    for account in accounts
        .iter()
        .filter(|account| account.has_saved_password && !account.username.trim().is_empty())
    {
        let password = match load_password(account, from_use_keyring) {
            Ok(password) => password,
            Err(e) => {
                rollback_partial_storage_migration(
                    migrated_account_ids,
                    from_use_keyring,
                    to_use_keyring,
                    e,
                )?;
                unreachable!("rollback_partial_storage_migration always returns Err");
            }
        };

        let receipt = match write_account_password_owned(account, password, to_use_keyring) {
            Ok(receipt) => receipt,
            Err(e) => {
                let recovery_error = storage_mode_migration_recovery_required_error(format!(
                    "storage migration target write failed and may need recovery cleanup: {e}"
                ));
                rollback_partial_storage_migration(
                    migrated_account_ids,
                    from_use_keyring,
                    to_use_keyring,
                    recovery_error,
                )?;
                unreachable!("rollback_partial_storage_migration always returns Err");
            }
        };

        migrated_account_ids.push(account.id.clone());

        if receipt.target_durability_warning {
            let recovery_error = storage_mode_migration_recovery_required_error(
                "storage migration target write committed, but durability is unconfirmed",
            );
            rollback_partial_storage_migration(
                migrated_account_ids,
                from_use_keyring,
                to_use_keyring,
                recovery_error,
            )?;
            unreachable!("rollback_partial_storage_migration always returns Err");
        }

        if let Err(e) = load_password(account, to_use_keyring) {
            rollback_partial_storage_migration(
                migrated_account_ids,
                from_use_keyring,
                to_use_keyring,
                e,
            )?;
            unreachable!("rollback_partial_storage_migration always returns Err");
        }
    }
    Ok(StorageModeMigration {
        migrated_account_ids,
        from_use_keyring,
        to_use_keyring,
    })
}

pub(crate) fn begin_storage_mode_migration_journal(
    accounts: &[Account],
    from_use_keyring: bool,
    to_use_keyring: bool,
) -> anyhow::Result<()> {
    if from_use_keyring == to_use_keyring {
        return Ok(());
    }

    let operation = PendingStorageOperation {
        version: PENDING_STORAGE_OPERATION_VERSION,
        kind: "storage_mode_migration".to_string(),
        account_ids: storage_mode_migration_account_ids(accounts),
        from_use_keyring,
        to_use_keyring,
        use_keyring: false,
        before_account: None,
        after_account: None,
        rollback_marker: None,
    };
    validate_pending_storage_operation(&operation)?;
    save_pending_storage_operation(&operation)
}

pub(crate) fn begin_account_config_save_journal_with_revision(
    before_account: Option<&Account>,
    after_account: &Account,
    use_keyring: bool,
    revision_marker: &str,
) -> anyhow::Result<()> {
    validate_rollback_marker(revision_marker)?;
    let operation = PendingStorageOperation {
        version: PENDING_STORAGE_OPERATION_VERSION,
        kind: "account_config_save".to_string(),
        account_ids: vec![after_account.id.clone()],
        from_use_keyring: false,
        to_use_keyring: false,
        use_keyring,
        before_account: before_account.cloned(),
        after_account: Some(after_account.clone()),
        rollback_marker: Some(revision_marker.to_owned()),
    };
    validate_pending_storage_operation(&operation)?;
    save_pending_storage_operation(&operation)
}

pub(crate) fn new_account_config_rollback_marker() -> String {
    new_account_config_revision_marker()
}

pub(crate) fn new_account_config_revision_marker() -> String {
    uuid::Uuid::new_v4().hyphenated().to_string()
}

pub(crate) fn begin_account_enabled_toggle_journal(
    before_account: &Account,
    after_account: &Account,
    use_keyring: bool,
) -> anyhow::Result<()> {
    let operation = PendingStorageOperation {
        version: PENDING_STORAGE_OPERATION_VERSION,
        kind: "account_enabled_toggle_prepared".to_string(),
        account_ids: vec![before_account.id.clone()],
        from_use_keyring: false,
        to_use_keyring: false,
        use_keyring,
        before_account: Some(before_account.clone()),
        after_account: Some(after_account.clone()),
        rollback_marker: None,
    };
    validate_pending_storage_operation(&operation)?;
    save_pending_storage_operation(&operation)
}

pub(crate) fn mark_account_enabled_toggle_committed_journal(
    before_account: &Account,
    after_account: &Account,
    use_keyring: bool,
) -> anyhow::Result<()> {
    let operation = PendingStorageOperation {
        version: PENDING_STORAGE_OPERATION_VERSION,
        kind: "account_enabled_toggle_committed".to_string(),
        account_ids: vec![before_account.id.clone()],
        from_use_keyring: false,
        to_use_keyring: false,
        use_keyring,
        before_account: Some(before_account.clone()),
        after_account: Some(after_account.clone()),
        rollback_marker: None,
    };
    validate_pending_storage_operation(&operation)?;
    let pending_path = pending_storage_operation_file_path()?;
    let recovering_path = recovering_storage_operation_file_path()?;
    replace_prepared_account_enabled_toggle_journal(&operation, &pending_path, &recovering_path)
}

fn replace_prepared_account_enabled_toggle_journal(
    committed: &PendingStorageOperation,
    pending_path: &Path,
    recovering_path: &Path,
) -> anyhow::Result<()> {
    if storage_operation_file_exists(recovering_path)? {
        anyhow::bail!("account enabled-toggle recovery has already started")
    }
    let current = load_pending_storage_operation_from_path(pending_path)?;
    if current.operation.kind != "account_enabled_toggle_prepared"
        || current.operation.account_ids != committed.account_ids
        || current.operation.use_keyring != committed.use_keyring
        || current.operation.before_account != committed.before_account
        || current.operation.after_account != committed.after_account
    {
        anyhow::bail!("pending account enabled-toggle journal does not match the commit request")
    }

    let content = serde_json::to_string_pretty(committed)?;
    write_private_file_atomic(pending_path, "json.tmp", content.as_bytes())
}

pub(crate) fn mark_account_config_rollback_journal(
    before_account: &Account,
    use_keyring: bool,
    rollback_marker: &str,
) -> anyhow::Result<()> {
    validate_rollback_marker(rollback_marker)?;
    let operation = PendingStorageOperation {
        version: PENDING_STORAGE_OPERATION_VERSION,
        kind: "account_config_rollback".to_string(),
        account_ids: vec![before_account.id.clone()],
        from_use_keyring: false,
        to_use_keyring: false,
        use_keyring,
        before_account: Some(before_account.clone()),
        after_account: None,
        rollback_marker: Some(rollback_marker.to_string()),
    };
    validate_pending_storage_operation(&operation)?;
    let pending_path = pending_storage_operation_file_path()?;
    let recovering_path = recovering_storage_operation_file_path()?;
    replace_account_config_save_journal_with_rollback(&operation, &pending_path, &recovering_path)
}

fn replace_account_config_save_journal_with_rollback(
    rollback: &PendingStorageOperation,
    pending_path: &Path,
    recovering_path: &Path,
) -> anyhow::Result<()> {
    if storage_operation_file_exists(recovering_path)? {
        anyhow::bail!("account storage recovery has already started")
    }
    let current = load_pending_storage_operation_from_path(pending_path)?;
    let expected_before = rollback
        .before_account
        .as_ref()
        .expect("validated rollback journal has a source account");
    if current.operation.kind != "account_config_save"
        || current.operation.account_ids != rollback.account_ids
        || current.operation.use_keyring != rollback.use_keyring
        || current.operation.before_account.as_ref() != Some(expected_before)
    {
        anyhow::bail!("pending account journal does not match the rollback request")
    }

    let content = serde_json::to_string_pretty(rollback)?;
    write_private_file_atomic(pending_path, "json.tmp", content.as_bytes())
}

pub(crate) fn begin_account_delete_journal(
    before_account: &Account,
    use_keyring: bool,
) -> anyhow::Result<()> {
    let operation = PendingStorageOperation {
        version: PENDING_STORAGE_OPERATION_VERSION,
        kind: "account_delete_prepared".to_string(),
        account_ids: vec![before_account.id.clone()],
        from_use_keyring: false,
        to_use_keyring: false,
        use_keyring,
        before_account: Some(before_account.clone()),
        after_account: None,
        rollback_marker: None,
    };
    validate_pending_storage_operation(&operation)?;
    save_pending_storage_operation(&operation)
}

pub(crate) fn mark_account_delete_committed_journal(
    before_account: &Account,
    use_keyring: bool,
) -> anyhow::Result<()> {
    let operation = PendingStorageOperation {
        version: PENDING_STORAGE_OPERATION_VERSION,
        kind: "account_delete_committed".to_string(),
        account_ids: vec![before_account.id.clone()],
        from_use_keyring: false,
        to_use_keyring: false,
        use_keyring,
        before_account: Some(before_account.clone()),
        after_account: None,
        rollback_marker: None,
    };
    validate_pending_storage_operation(&operation)?;
    let pending_path = pending_storage_operation_file_path()?;
    let recovering_path = recovering_storage_operation_file_path()?;
    replace_prepared_account_delete_journal(&operation, &pending_path, &recovering_path)
}

fn replace_prepared_account_delete_journal(
    committed: &PendingStorageOperation,
    pending_path: &Path,
    recovering_path: &Path,
) -> anyhow::Result<()> {
    if storage_operation_file_exists(recovering_path)? {
        anyhow::bail!("account deletion recovery has already started")
    }
    let current = load_pending_storage_operation_from_path(pending_path)?;
    if current.operation.kind != "account_delete_prepared"
        || current.operation.account_ids != committed.account_ids
        || current.operation.use_keyring != committed.use_keyring
        || current.operation.before_account != committed.before_account
    {
        anyhow::bail!("pending account deletion journal does not match the commit request")
    }

    let content = serde_json::to_string_pretty(committed)?;
    write_private_file_atomic(pending_path, "json.tmp", content.as_bytes())
}

pub(crate) fn clear_pending_storage_operation() -> anyhow::Result<()> {
    let pending_path = pending_storage_operation_file_path()?;
    let recovering_path = recovering_storage_operation_file_path()?;
    clear_pending_storage_operation_with_marker(
        &pending_path,
        &recovering_path,
        mark_storage_recovery_blocked,
    )
}

fn clear_pending_storage_operation_with_marker<M>(
    pending_path: &Path,
    recovering_path: &Path,
    mut mark_recovery_blocked: M,
) -> anyhow::Result<()>
where
    M: FnMut() -> anyhow::Result<()>,
{
    match clear_pending_storage_operation_paths(pending_path, recovering_path) {
        Ok(()) => Ok(()),
        Err(clear_error) => {
            if let Err(marker_error) = mark_recovery_blocked() {
                anyhow::bail!(
                    "{clear_error}; recovery block persistence also failed: {marker_error}"
                );
            }
            Err(clear_error)
        }
    }
}

fn clear_pending_storage_operation_paths(
    pending_path: &Path,
    recovering_path: &Path,
) -> anyhow::Result<()> {
    let mut errors = Vec::new();
    if let Err(e) = remove_pending_storage_operation_file(pending_path) {
        errors.push(e.to_string());
    }
    if let Err(e) = remove_pending_storage_operation_file(recovering_path) {
        errors.push(e.to_string());
    }
    if let Err(e) =
        cleanup_pending_storage_operation_temp_files_for_paths(pending_path, recovering_path)
    {
        errors.push(e.to_string());
    }
    if errors.is_empty() {
        Ok(())
    } else {
        anyhow::bail!(
            "failed to clear pending storage operation journal: {}",
            errors.join("; ")
        )
    }
}

pub(crate) fn reconcile_pending_storage_operations(config: &mut AppConfig) -> anyhow::Result<()> {
    let Some(record) = load_pending_storage_operation_record_fail_closed()? else {
        return Ok(());
    };
    let record = consume_pending_storage_operation_record(record)?;
    match record.operation.kind.as_str() {
        "storage_mode_migration" => reconcile_storage_mode_operation(config, &record.operation)?,
        "account_config_save" => {
            reconcile_account_config_save_operation(config, &record.operation)?
        }
        "account_config_rollback" => {
            reconcile_account_config_rollback_operation(config, &record.operation)?
        }
        "account_delete" => {
            warn!(
                "Legacy unphased account deletion journal remains blocked for safe manual recovery"
            );
            anyhow::bail!("legacy account deletion journal has no recoverable transaction phase");
        }
        "account_delete_prepared" => {
            reconcile_prepared_account_delete_operation(config, &record.operation)?
        }
        "account_delete_committed" => {
            reconcile_account_delete_operation(config, &record.operation)?
        }
        "account_enabled_toggle_prepared" => {
            reconcile_prepared_account_enabled_toggle_operation(config, &record.operation)?
        }
        "account_enabled_toggle_committed" => {
            reconcile_committed_account_enabled_toggle_operation(config, &record.operation)?
        }
        _ => unreachable!("pending storage operation kind was validated"),
    }
    clear_pending_storage_operation()
}

fn remove_pending_storage_operation_file(path: &Path) -> anyhow::Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    if metadata.file_type().is_dir() {
        return quarantine_pending_storage_operation_entry(path, &metadata);
    }
    std::fs::remove_file(path)?;
    sync_parent_dir(path)
}

fn reconcile_storage_mode_operation(
    config: &AppConfig,
    operation: &PendingStorageOperation,
) -> anyhow::Result<()> {
    if !pending_storage_operation_account_ids_known(operation, &config.accounts) {
        warn!("Pending storage migration journal referenced unknown account ids; recovery remains blocked");
        anyhow::bail!(
            "pending storage migration references accounts that are absent from the current config"
        );
    }
    let Some(backend_to_cleanup) =
        pending_storage_backend_to_cleanup(operation, config.settings.use_keyring)
    else {
        return Ok(());
    };
    verify_pending_storage_surviving_backend(config, operation, |account, use_keyring| {
        load_password(account, use_keyring).map(|_| ())
    })?;

    cleanup_storage_backend(&operation.account_ids, backend_to_cleanup)?;
    Ok(())
}

fn verify_pending_storage_surviving_backend<L>(
    config: &AppConfig,
    operation: &PendingStorageOperation,
    mut load_password_op: L,
) -> anyhow::Result<()>
where
    L: FnMut(&Account, bool) -> anyhow::Result<()>,
{
    for account_id in &operation.account_ids {
        let Some(account) = config
            .accounts
            .iter()
            .find(|account| account.id == *account_id)
        else {
            continue;
        };
        if !account.has_saved_password {
            continue;
        }
        if let Err(e) = load_password_op(account, config.settings.use_keyring) {
            warn!(
                account_id = %redacted_account_id(account_id),
                error_kind = storage_error_kind(&e),
                error = %e,
                "Pending storage migration recovery refused stale backend cleanup because current backend password verification failed"
            );
            anyhow::bail!(
                "current password backend verification failed before stale backend cleanup"
            );
        }
    }
    Ok(())
}

fn reconcile_account_config_save_operation(
    config: &mut AppConfig,
    operation: &PendingStorageOperation,
) -> anyhow::Result<()> {
    reconcile_account_config_save_operation_with_ops(
        config,
        operation,
        |account, use_keyring| {
            load_password_for_rollback_verification(account, use_keyring).map(|(_, marker)| marker)
        },
        finalize_recovered_selected_backend,
        save_config,
        |account_ids, use_keyring| cleanup_storage_backend(account_ids, use_keyring).map(|_| ()),
        delete_password,
    )
}

fn reconcile_account_config_save_operation_with_ops<L, F, S, C, D>(
    config: &mut AppConfig,
    operation: &PendingStorageOperation,
    mut load_password_op: L,
    mut finalize_selected_backend_op: F,
    mut save_config_op: S,
    mut cleanup_storage_backend_op: C,
    mut delete_password_op: D,
) -> anyhow::Result<()>
where
    L: FnMut(&Account, bool) -> anyhow::Result<Option<String>>,
    F: FnMut(bool) -> anyhow::Result<()>,
    S: FnMut(&AppConfig) -> anyhow::Result<()>,
    C: FnMut(&[AccountId], bool) -> anyhow::Result<()>,
    D: FnMut(&AccountId) -> anyhow::Result<()>,
{
    let Some(after_account) = operation.after_account.as_ref() else {
        return Ok(());
    };
    let mut after_account = after_account.clone();
    after_account.has_saved_password = true;

    let target_revision = load_password_op(&after_account, operation.use_keyring);
    let mut verified_before_account = None;
    let target_is_verified = match operation.rollback_marker.as_deref() {
        Some(expected_marker) => match target_revision {
            Ok(Some(loaded_marker)) if loaded_marker == expected_marker => true,
            Ok(Some(_))
                if operation
                    .before_account
                    .as_ref()
                    .is_some_and(|before_account| {
                        before_account.has_saved_password
                            && password_binding_matches(before_account, &after_account)
                    }) =>
            {
                // The rollback-intent journal replacement may have reached
                // the filesystem while its directory sync remained
                // unconfirmed. After a crash the older forward journal can
                // therefore reappear next to the already-restored password.
                // A different authenticated revision is safe to classify as
                // the prior state only when both snapshots have identical
                // password binding metadata; otherwise fail closed below.
                verified_before_account = operation.before_account.clone();
                false
            }
            Ok(_) => {
                warn!(
                    account_id = %redacted_account_id(&after_account.id),
                    "Pending account save found a readable password from the wrong revision; recovery remains blocked"
                );
                anyhow::bail!("forward password revision marker could not be verified");
            }
            Err(target_error) => {
                let Some(before_account) = operation.before_account.as_ref() else {
                    warn!(
                        account_id = %redacted_account_id(&after_account.id),
                        error_kind = storage_error_kind(&target_error),
                        "Pending new-account save could not verify the forward password; destructive recovery was refused"
                    );
                    anyhow::bail!(
                        "forward password revision could not be read; recovery remains pending"
                    );
                };
                if !before_account.has_saved_password {
                    warn!(
                        account_id = %redacted_account_id(&after_account.id),
                        error_kind = storage_error_kind(&target_error),
                        "Pending account save has no prior password revision that can disambiguate a target read failure"
                    );
                    anyhow::bail!(
                        "forward password revision could not be read or safely rolled back"
                    );
                }

                match load_password_op(before_account, operation.use_keyring) {
                    Ok(Some(loaded_marker)) if loaded_marker == expected_marker => {
                        // When password binding metadata did not change, the
                        // same committed forward payload can be readable under
                        // both snapshots. Its authenticated marker wins over a
                        // transient first read failure.
                        true
                    }
                    Ok(_) => {
                        verified_before_account = Some(before_account.clone());
                        false
                    }
                    Err(before_error) => {
                        warn!(
                            account_id = %redacted_account_id(&after_account.id),
                            target_error_kind = storage_error_kind(&target_error),
                            before_error_kind = storage_error_kind(&before_error),
                            "Pending account save could not authenticate either password revision; recovery remains blocked"
                        );
                        anyhow::bail!(
                            "neither forward nor prior password revision could be verified"
                        );
                    }
                }
            }
        },
        // Pre-revision journals retain their legacy recovery behavior. New
        // journals always carry a marker and use the fail-closed branch above.
        None => target_revision.is_ok(),
    };

    if target_is_verified {
        finalize_selected_backend_op(operation.use_keyring)?;
        upsert_recovered_account(config, after_account);
        save_config_op(config)?;
        cleanup_storage_backend_op(&operation.account_ids, !operation.use_keyring)?;
        return Ok(());
    }

    if let Some(before_account) = verified_before_account {
        finalize_selected_backend_op(operation.use_keyring)?;
        upsert_recovered_account(config, before_account);
        save_config_op(config)?;
        return Ok(());
    }

    if let Some(before_account) = operation.before_account.as_ref() {
        let mut before_account = before_account.clone();
        if before_account.has_saved_password {
            if load_password_op(&before_account, operation.use_keyring).is_err() {
                before_account.has_saved_password = false;
                before_account.enabled = false;
            } else {
                finalize_selected_backend_op(operation.use_keyring)?;
            }
        }
        upsert_recovered_account(config, before_account);
        save_config_op(config)?;
        return Ok(());
    }

    if let Err(e) = delete_password_op(&after_account.id) {
        warn!(
            account_id = %redacted_account_id(&after_account.id),
            error = %e,
            "pending account config recovery could not delete orphan target password"
        );
        return Err(e);
    }
    config
        .accounts
        .retain(|account| account.id != after_account.id);
    save_config_op(config)
}

fn reconcile_prepared_account_enabled_toggle_operation(
    config: &mut AppConfig,
    operation: &PendingStorageOperation,
) -> anyhow::Result<()> {
    reconcile_prepared_account_enabled_toggle_operation_with_ops(config, operation, save_config)
}

fn reconcile_prepared_account_enabled_toggle_operation_with_ops<S>(
    config: &mut AppConfig,
    operation: &PendingStorageOperation,
    mut save_config_op: S,
) -> anyhow::Result<()>
where
    S: FnMut(&AppConfig) -> anyhow::Result<()>,
{
    let before_account = operation
        .before_account
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("prepared account enabled-toggle has no source snapshot"))?;
    let after_account = operation
        .after_account
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("prepared account enabled-toggle has no target snapshot"))?;
    match config
        .accounts
        .iter()
        .find(|account| account.id == before_account.id)
    {
        Some(existing) if existing == before_account || existing == after_account => {}
        Some(_) => {
            anyhow::bail!("prepared account enabled-toggle found mismatched account metadata")
        }
        None => anyhow::bail!("prepared account enabled-toggle cannot prove config was unchanged"),
    }

    // A prepared journal is the only durable entry that may survive when the
    // prepared->committed atomic replacement had ambiguous directory
    // durability. Resolve both directions to the disabled snapshot: a disable
    // request must never roll back to enabled, while an enable request is not
    // allowed to take effect until committed intent is durable.
    let disabled_account = if before_account.enabled {
        after_account
    } else {
        before_account
    };
    upsert_recovered_account(config, disabled_account.clone());
    save_config_op(config)
}

fn reconcile_committed_account_enabled_toggle_operation(
    config: &mut AppConfig,
    operation: &PendingStorageOperation,
) -> anyhow::Result<()> {
    reconcile_committed_account_enabled_toggle_operation_with_ops(config, operation, save_config)
}

fn reconcile_committed_account_enabled_toggle_operation_with_ops<S>(
    config: &mut AppConfig,
    operation: &PendingStorageOperation,
    mut save_config_op: S,
) -> anyhow::Result<()>
where
    S: FnMut(&AppConfig) -> anyhow::Result<()>,
{
    let before_account = operation.before_account.as_ref().ok_or_else(|| {
        anyhow::anyhow!("committed account enabled-toggle has no source snapshot")
    })?;
    let after_account = operation.after_account.as_ref().ok_or_else(|| {
        anyhow::anyhow!("committed account enabled-toggle has no target snapshot")
    })?;

    match config
        .accounts
        .iter()
        .find(|account| account.id == before_account.id)
    {
        Some(existing) if existing == before_account || existing == after_account => {}
        Some(_) => {
            anyhow::bail!("committed account enabled-toggle found mismatched account metadata")
        }
        None => anyhow::bail!("committed account enabled-toggle target account is absent"),
    }
    upsert_recovered_account(config, after_account.clone());
    // The committed intent wins even if an earlier atomic config rename was
    // lost after a power failure. Re-save the target snapshot durably before
    // allowing the journal to be cleared.
    save_config_op(config)
}

fn reconcile_account_config_rollback_operation(
    config: &mut AppConfig,
    operation: &PendingStorageOperation,
) -> anyhow::Result<()> {
    reconcile_account_config_rollback_operation_with_ops(
        config,
        operation,
        |account, use_keyring| {
            load_password_for_rollback_verification(account, use_keyring).map(|(_, marker)| marker)
        },
        finalize_recovered_selected_backend,
        save_config,
        |account_ids, use_keyring| cleanup_storage_backend(account_ids, use_keyring).map(|_| ()),
    )
}

fn reconcile_account_config_rollback_operation_with_ops<L, F, S, C>(
    config: &mut AppConfig,
    operation: &PendingStorageOperation,
    mut load_password_op: L,
    mut finalize_selected_backend_op: F,
    mut save_config_op: S,
    mut cleanup_storage_backend_op: C,
) -> anyhow::Result<()>
where
    L: FnMut(&Account, bool) -> anyhow::Result<Option<String>>,
    F: FnMut(bool) -> anyhow::Result<()>,
    S: FnMut(&AppConfig) -> anyhow::Result<()>,
    C: FnMut(&[AccountId], bool) -> anyhow::Result<()>,
{
    let Some(before_account) = operation.before_account.as_ref() else {
        return Ok(());
    };
    let Some(expected_marker) = operation.rollback_marker.as_deref() else {
        warn!(
            account_id = %redacted_account_id(&before_account.id),
            "Pending account rollback predates verifiable rollback markers and remains blocked"
        );
        anyhow::bail!("pending account rollback has no verifiable rollback marker");
    };
    if before_account.has_saved_password {
        let loaded_marker = load_password_op(before_account, operation.use_keyring).inspect_err(
            |error| {
                warn!(
                    account_id = %redacted_account_id(&before_account.id),
                    error_kind = storage_error_kind(error),
                    "Pending account rollback kept recovery state because the restored password could not be verified"
                );
            },
        )?;
        if loaded_marker.as_deref() != Some(expected_marker) {
            warn!(
                account_id = %redacted_account_id(&before_account.id),
                "Pending account rollback kept recovery state because the stored password lacks the matching rollback marker"
            );
            anyhow::bail!("restored password rollback marker could not be verified");
        }
        finalize_selected_backend_op(operation.use_keyring)?;
    }

    upsert_recovered_account(config, before_account.clone());
    save_config_op(config)?;
    cleanup_storage_backend_op(&operation.account_ids, !operation.use_keyring)
}

fn finalize_recovered_selected_backend(use_keyring: bool) -> anyhow::Result<()> {
    if use_keyring {
        Ok(())
    } else {
        // A fallback password load can succeed while retired-key cleanup is
        // still pending. Recovery must surface that state and retain its
        // journal instead of treating the backend as fully finalized.
        cleanup_unused_fallback_key_material()
    }
}

fn reconcile_account_delete_operation(
    config: &mut AppConfig,
    operation: &PendingStorageOperation,
) -> anyhow::Result<()> {
    reconcile_account_delete_operation_with_ops(config, operation, save_config, delete_account)
}

fn reconcile_account_delete_operation_with_ops<S, D>(
    config: &mut AppConfig,
    operation: &PendingStorageOperation,
    mut save_config_op: S,
    mut delete_account_op: D,
) -> anyhow::Result<()>
where
    S: FnMut(&AppConfig) -> anyhow::Result<()>,
    D: FnMut(&AccountId) -> anyhow::Result<()>,
{
    let Some(account_id) = operation.account_ids.first() else {
        return Ok(());
    };
    let Some(before_account) = operation.before_account.as_ref() else {
        anyhow::bail!("committed account deletion has no source snapshot");
    };
    if let Some(existing) = config
        .accounts
        .iter()
        .find(|account| account.id == *account_id)
    {
        if existing != before_account {
            anyhow::bail!("account deletion recovery found mismatched account metadata");
        }
        config.accounts.retain(|account| account.id != *account_id);
    }
    // Recovery can run in the same boot immediately after an atomic config
    // replacement whose directory sync failed. Re-save and confirm durability
    // before independently destroying the credential.
    save_config_op(config)?;
    delete_account_op(account_id)
}

fn reconcile_prepared_account_delete_operation(
    config: &AppConfig,
    operation: &PendingStorageOperation,
) -> anyhow::Result<()> {
    reconcile_prepared_account_delete_operation_with_ops(config, operation)
}

fn reconcile_prepared_account_delete_operation_with_ops(
    config: &AppConfig,
    operation: &PendingStorageOperation,
) -> anyhow::Result<()> {
    let Some(account_id) = operation.account_ids.first() else {
        return Ok(());
    };
    let Some(before_account) = operation.before_account.as_ref() else {
        anyhow::bail!("prepared account deletion has no source snapshot");
    };
    match config
        .accounts
        .iter()
        .find(|account| account.id == *account_id)
    {
        Some(existing) if existing == before_account => Ok(()),
        Some(_) => anyhow::bail!("prepared account deletion found mismatched account metadata"),
        None => anyhow::bail!(
            "prepared account deletion cannot prove that config storage was left unchanged"
        ),
    }
}

fn upsert_recovered_account(config: &mut AppConfig, account: Account) {
    if let Some(existing) = config
        .accounts
        .iter_mut()
        .find(|existing| existing.id == account.id)
    {
        *existing = account;
    } else {
        config.accounts.push(account);
    }
}

fn pending_storage_operation_account_ids_known(
    operation: &PendingStorageOperation,
    accounts: &[Account],
) -> bool {
    let known = accounts
        .iter()
        .map(|account| account.id.as_str())
        .collect::<HashSet<_>>();
    let mut seen = HashSet::new();
    operation
        .account_ids
        .iter()
        .all(|account_id| known.contains(account_id.as_str()) && seen.insert(account_id.as_str()))
}

fn storage_mode_migration_account_ids(accounts: &[Account]) -> Vec<AccountId> {
    accounts
        .iter()
        .filter(|account| account.has_saved_password && !account.username.trim().is_empty())
        .map(|account| account.id.clone())
        .collect()
}

fn save_pending_storage_operation(operation: &PendingStorageOperation) -> anyhow::Result<()> {
    ensure_config_dir()?;
    // The staged-key scan must happen before the pending journal is created:
    // once that journal exists, fallback cleanup is deliberately deferred to
    // protect an ambiguous forward revision. Holding the password lock across
    // both steps also prevents a concurrent local transaction from changing
    // the active key map between validation and intent creation.
    let path = pending_storage_operation_file_path()?;
    let recovering_path = recovering_storage_operation_file_path()?;
    save_pending_storage_operation_with_preflight_ops(
        operation,
        acquire_password_file_transaction_lock,
        prepare_password_file_transaction,
        |operation| save_pending_storage_operation_to_paths(operation, &path, &recovering_path),
    )
}

fn save_pending_storage_operation_with_preflight_ops<G, L, P, S>(
    operation: &PendingStorageOperation,
    acquire_lock: L,
    mut preflight: P,
    mut save_operation: S,
) -> anyhow::Result<()>
where
    L: FnOnce() -> anyhow::Result<G>,
    P: FnMut() -> anyhow::Result<()>,
    S: FnMut(&PendingStorageOperation) -> anyhow::Result<()>,
{
    let _lock = acquire_lock()?;
    preflight()?;
    save_operation(operation)
}

fn save_pending_storage_operation_to_paths(
    operation: &PendingStorageOperation,
    path: &Path,
    recovering_path: &Path,
) -> anyhow::Result<()> {
    if let Err(e) = cleanup_pending_storage_operation_temp_files_for_paths(path, recovering_path) {
        warn!(
            error = %e,
            "Failed to clean stale pending storage operation temp files before save"
        );
    }
    ensure_no_pending_storage_operation(path, recovering_path)?;
    let content = serde_json::to_string_pretty(operation)?;
    write_private_file_create_new_atomic(path, "json.tmp", content.as_bytes())
}

fn ensure_no_pending_storage_operation(
    pending_path: &Path,
    recovering_path: &Path,
) -> anyhow::Result<()> {
    if storage_operation_file_exists(pending_path)?
        || storage_operation_file_exists(recovering_path)?
    {
        anyhow::bail!(PendingStorageOperationInProgress);
    }
    Ok(())
}

fn storage_operation_file_exists(path: &Path) -> anyhow::Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

fn load_pending_storage_operation_record_fail_closed(
) -> anyhow::Result<Option<PendingStorageOperationRecord>> {
    let recovering_path = recovering_storage_operation_file_path()?;
    let pending_path = pending_storage_operation_file_path()?;
    load_pending_storage_operation_record_fail_closed_with_marker(
        &recovering_path,
        &pending_path,
        mark_storage_recovery_blocked,
    )
}

fn load_pending_storage_operation_record_fail_closed_with_marker<M>(
    recovering_path: &Path,
    pending_path: &Path,
    mut mark_recovery_blocked: M,
) -> anyhow::Result<Option<PendingStorageOperationRecord>>
where
    M: FnMut() -> anyhow::Result<()>,
{
    match load_pending_storage_operation_record_fail_closed_from_paths(
        recovering_path,
        pending_path,
    ) {
        Ok(record) => Ok(record),
        Err(load_error) => {
            if let Err(marker_error) = mark_recovery_blocked() {
                return Err(load_error.context(format!(
                    "storage recovery block persistence also failed: {marker_error}"
                )));
            }
            Err(load_error)
        }
    }
}

fn load_pending_storage_operation_record_fail_closed_from_paths(
    recovering_path: &Path,
    pending_path: &Path,
) -> anyhow::Result<Option<PendingStorageOperationRecord>> {
    if let Err(e) =
        cleanup_pending_storage_operation_temp_files_for_paths(pending_path, recovering_path)
    {
        warn!(
            error = %e,
            "Failed to clean stale pending storage operation temp files before recovery"
        );
    }
    // Always inspect both active slots. A crash can leave the original
    // pending name alongside the recovering name; preferring recovering
    // without authenticating pending would let one operation run and then
    // erase evidence of a different operation during journal cleanup.
    let recovering =
        load_pending_storage_operation_record_from_path_fail_closed(recovering_path, "recovering");
    let pending =
        load_pending_storage_operation_record_from_path_fail_closed(pending_path, "pending");

    match (recovering, pending) {
        (Ok(Some(recovering)), Ok(Some(pending))) => {
            if recovering.operation != pending.operation {
                warn!(
                    "recovering and pending storage operation journals conflict; retaining both active paths"
                );
                return Err(anyhow::Error::new(PendingStorageRecoveryBlocked {
                    source: anyhow::anyhow!(
                        "recovering and pending storage operation journals describe different operations"
                    ),
                }));
            }
            // The recovering slot is authoritative only after both validated
            // records proved structurally identical. Keeping its path avoids
            // a redundant rename while recovery durably re-syncs it.
            Ok(Some(recovering))
        }
        (Ok(Some(record)), Ok(None)) | (Ok(None), Ok(Some(record))) => Ok(Some(record)),
        (Ok(None), Ok(None)) => Ok(None),
        (Err(recovering_error), Ok(_)) => Err(recovering_error),
        (Ok(_), Err(pending_error)) => Err(pending_error),
        (Err(recovering_error), Err(pending_error)) => Err(recovering_error.context(format!(
            "pending journal validation also failed: {pending_error}"
        ))),
    }
}

fn load_pending_storage_operation_record_from_path_fail_closed(
    path: &Path,
    slot_name: &'static str,
) -> anyhow::Result<Option<PendingStorageOperationRecord>> {
    if !storage_operation_file_exists(path)? {
        return Ok(None);
    }

    match load_pending_storage_operation_from_path(path) {
        Ok(record) => Ok(Some(record)),
        Err(e) => {
            warn!(
                slot = slot_name,
                error_kind = storage_error_kind(&e),
                "pending storage operation journal is invalid; retaining it at the active path so credential changes remain blocked"
            );
            Err(anyhow::Error::new(PendingStorageRecoveryBlocked {
                source: e,
            }))
        }
    }
}

fn load_pending_storage_operation_from_path(
    path: &Path,
) -> anyhow::Result<PendingStorageOperationRecord> {
    validate_private_file_for_read(path)?;
    let content = read_private_text_file(path, MAX_PENDING_STORAGE_OPERATION_FILE_BYTES)?;
    let operation: PendingStorageOperation = serde_json::from_str(&content)?;
    validate_pending_storage_operation(&operation)?;
    Ok(PendingStorageOperationRecord {
        operation,
        path: path.to_path_buf(),
    })
}

fn consume_pending_storage_operation_record(
    record: PendingStorageOperationRecord,
) -> anyhow::Result<PendingStorageOperationRecord> {
    let recovering_path = recovering_storage_operation_file_path()?;
    consume_pending_storage_operation_record_with_ops(
        record,
        &recovering_path,
        |from, to| std::fs::rename(from, to).map_err(anyhow::Error::from),
        |path| secure_path_permissions(path, 0o600),
        sync_parent_dir,
    )
}

fn consume_pending_storage_operation_record_with_ops<R, P, S>(
    record: PendingStorageOperationRecord,
    recovering_path: &Path,
    mut rename: R,
    mut secure_permissions: P,
    mut sync_parent: S,
) -> anyhow::Result<PendingStorageOperationRecord>
where
    R: FnMut(&Path, &Path) -> anyhow::Result<()>,
    P: FnMut(&Path) -> anyhow::Result<()>,
    S: FnMut(&Path) -> anyhow::Result<()>,
{
    if record.path != recovering_path {
        rename(&record.path, recovering_path)?;
    }
    // Recovery side effects can retire fallback keys. Sync even when a prior
    // process already renamed the journal, because that process may have died
    // before the directory sync that also pins an earlier passwords.json
    // replacement in the same directory.
    secure_permissions(recovering_path)?;
    sync_parent(recovering_path)?;
    Ok(PendingStorageOperationRecord {
        operation: record.operation,
        path: recovering_path.to_path_buf(),
    })
}

#[cfg(test)]
fn quarantine_pending_storage_operation_file(path: &Path) -> anyhow::Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    quarantine_pending_storage_operation_entry(path, &metadata)
}

fn quarantine_pending_storage_operation_entry(
    path: &Path,
    metadata: &std::fs::Metadata,
) -> anyhow::Result<()> {
    let file_type = metadata.file_type();
    if file_type.is_file() || file_type.is_dir() {
        let quarantine_path = invalid_pending_storage_operation_path(path);
        std::fs::rename(path, &quarantine_path)?;
        secure_path_permissions(
            &quarantine_path,
            if file_type.is_dir() { 0o700 } else { 0o600 },
        )?;
        return sync_parent_dir(&quarantine_path);
    }

    std::fs::remove_file(path)?;
    sync_parent_dir(path)
}

fn invalid_pending_storage_operation_path(path: &Path) -> PathBuf {
    let timestamp = chrono::Local::now().format("%Y%m%d%H%M%S");
    let nonce = chrono::Utc::now()
        .timestamp_nanos_opt()
        .unwrap_or_default()
        .unsigned_abs();
    path.with_extension(format!(
        "invalid.{timestamp}.{}.{}",
        std::process::id(),
        nonce
    ))
}

fn cleanup_pending_storage_operation_temp_files_for_paths(
    pending_path: &Path,
    recovering_path: &Path,
) -> anyhow::Result<usize> {
    let mut cleaned = 0;
    if let Some(parent) = pending_path.parent() {
        cleaned += cleanup_storage_temp_files_in_dir(parent, PENDING_STORAGE_TEMP_FILE_PREFIXES)?;
    }
    if recovering_path.parent() != pending_path.parent() {
        if let Some(parent) = recovering_path.parent() {
            cleaned +=
                cleanup_storage_temp_files_in_dir(parent, PENDING_STORAGE_TEMP_FILE_PREFIXES)?;
        }
    }
    Ok(cleaned)
}

fn cleanup_storage_temp_files_in_dir(
    dir: &Path,
    file_name_prefixes: &[&str],
) -> anyhow::Result<usize> {
    validate_private_dir(dir)?;

    let mut cleaned = 0;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };
        if !file_name_prefixes
            .iter()
            .any(|prefix| file_name.starts_with(prefix))
        {
            continue;
        }

        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path)?;
        if metadata.file_type().is_dir() {
            continue;
        }
        std::fs::remove_file(&path)?;
        cleaned += 1;
    }

    if cleaned > 0 {
        sync_dir(dir)?;
    }
    Ok(cleaned)
}

fn pending_storage_backend_to_cleanup(
    operation: &PendingStorageOperation,
    current_use_keyring: bool,
) -> Option<bool> {
    if current_use_keyring == operation.to_use_keyring {
        Some(operation.from_use_keyring)
    } else if current_use_keyring == operation.from_use_keyring {
        Some(operation.to_use_keyring)
    } else {
        None
    }
}

fn rollback_partial_storage_migration(
    migrated_account_ids: Vec<AccountId>,
    from_use_keyring: bool,
    to_use_keyring: bool,
    original_error: anyhow::Error,
) -> anyhow::Result<()> {
    if migrated_account_ids.is_empty() {
        return Err(original_error);
    }

    let partial = StorageModeMigration {
        migrated_account_ids,
        from_use_keyring,
        to_use_keyring,
    };
    if let Err(rollback_error) = rollback_storage_mode_migration(&partial) {
        return Err(storage_mode_migration_recovery_required_error(format!(
            "storage migration failed ({original_error}); partial target cleanup also failed ({rollback_error})"
        )));
    }

    Err(original_error)
}

pub(crate) fn commit_storage_mode_migration(
    migration: &StorageModeMigration,
) -> anyhow::Result<usize> {
    cleanup_storage_backend(&migration.migrated_account_ids, migration.from_use_keyring)
}

pub(crate) fn rollback_storage_mode_migration(
    migration: &StorageModeMigration,
) -> anyhow::Result<usize> {
    cleanup_storage_backend(&migration.migrated_account_ids, migration.to_use_keyring)
}

fn cleanup_storage_backend(account_ids: &[AccountId], use_keyring: bool) -> anyhow::Result<usize> {
    cleanup_storage_backend_with_ops(
        account_ids,
        use_keyring,
        delete_from_file,
        delete_from_keyring,
        cleanup_unused_fallback_key_material,
    )
}

fn cleanup_storage_backend_with_ops<DF, DK, CF>(
    account_ids: &[AccountId],
    use_keyring: bool,
    mut delete_from_file_op: DF,
    mut delete_from_keyring_op: DK,
    mut cleanup_fallback_key_op: CF,
) -> anyhow::Result<usize>
where
    DF: FnMut(&AccountId) -> anyhow::Result<()>,
    DK: FnMut(&AccountId) -> anyhow::Result<()>,
    CF: FnMut() -> anyhow::Result<()>,
{
    let mut cleaned = 0;
    let mut failed_accounts = 0;
    let backend = if use_keyring {
        PasswordStorageBackend::SystemSecureStorage
    } else {
        PasswordStorageBackend::EncryptedFallbackFile
    };

    for account_id in account_ids {
        let result = if use_keyring {
            delete_from_keyring_op(account_id)
        } else {
            delete_from_file_op(account_id)
        };

        match result {
            Ok(()) => {
                cleaned += 1;
            }
            Err(e) => {
                failed_accounts += 1;
                warn!(
                    account_id = %redacted_account_id(account_id),
                    backend = backend.label(),
                    error_kind = storage_error_kind(&e),
                    error = %e,
                    "Stale password backend account cleanup failed; continuing"
                );
            }
        };
    }

    let mut fallback_key_cleanup_failed = false;
    if !use_keyring {
        if let Err(e) = cleanup_fallback_key_op() {
            fallback_key_cleanup_failed = true;
            warn!(
                backend = backend.label(),
                error_kind = storage_error_kind(&e),
                error = %e,
                "Unused fallback key cleanup failed after stale backend cleanup"
            );
        }
    }

    if failed_accounts > 0 || fallback_key_cleanup_failed {
        let mut reasons = Vec::new();
        if failed_accounts > 0 {
            reasons.push(format!(
                "{failed_accounts} of {} account cleanup attempts failed",
                account_ids.len()
            ));
        }
        if fallback_key_cleanup_failed {
            reasons.push("fallback key cleanup failed".to_string());
        }
        anyhow::bail!(
            "stale {} cleanup incomplete: {}",
            backend.label(),
            reasons.join("; ")
        );
    }

    Ok(cleaned)
}

#[derive(Debug, Clone, Default)]
pub(crate) struct PasswordLoadTiming {
    pub(crate) storage_lookup_start_ms: u128,
    pub(crate) keychain_query_start_ms: u128,
    pub(crate) keychain_query_ms: u128,
    pub(crate) keychain_prompt_suspected: bool,
    pub(crate) fallback_lookup_ms: u128,
    pub(crate) zeroizing_wrap_ms: u128,
    pub(crate) total_password_load_ms: u128,
}

pub(crate) struct PasswordLoadResult {
    pub(crate) password: Zeroizing<String>,
    pub(crate) timing: PasswordLoadTiming,
}

struct LoadedStoredPassword {
    password: Zeroizing<String>,
    rollback_marker: Option<String>,
    zeroizing_wrap_ms: u128,
}

#[derive(Debug, Clone)]
pub(crate) struct PasswordLoadError {
    pub(crate) timing: PasswordLoadTiming,
    pub(crate) kind: &'static str,
}

impl std::fmt::Display for PasswordLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "password could not be loaded from configured secure storage"
        )
    }
}

impl std::error::Error for PasswordLoadError {}

pub(crate) fn load_password_with_timing(
    account: &Account,
    use_keyring: bool,
) -> Result<PasswordLoadResult, Box<PasswordLoadError>> {
    load_password_with_timing_for_prompt(account, use_keyring, None)
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn load_password_for_prompt_with_timing(
    account: &Account,
    use_keyring: bool,
    prompt_window_title: &str,
) -> Result<PasswordLoadResult, Box<PasswordLoadError>> {
    load_password_with_timing_for_prompt(account, use_keyring, Some(prompt_window_title))
}

fn load_password_with_timing_for_prompt(
    account: &Account,
    use_keyring: bool,
    _prompt_window_title: Option<&str>,
) -> Result<PasswordLoadResult, Box<PasswordLoadError>> {
    let total_start = std::time::Instant::now();
    let mut timing = PasswordLoadTiming::default();
    debug!(account_id = %redacted_account_id(&account.id), use_keyring, "load_password called");
    let result = if use_keyring {
        let keychain_start = std::time::Instant::now();
        timing.keychain_query_start_ms = total_start.elapsed().as_millis();
        let result = load_from_keyring_timed(account);
        timing.keychain_query_ms = keychain_start.elapsed().as_millis();
        timing.keychain_prompt_suspected = timing.keychain_query_ms > 1_000;
        result
    } else {
        let fallback_start = std::time::Instant::now();
        let result = load_from_file(account);
        timing.fallback_lookup_ms = fallback_start.elapsed().as_millis();
        result
    };

    timing.total_password_load_ms = total_start.elapsed().as_millis();
    match result {
        Ok(loaded) => {
            timing.zeroizing_wrap_ms = loaded.zeroizing_wrap_ms;
            Ok(PasswordLoadResult {
                password: loaded.password,
                timing,
            })
        }
        Err(e) => {
            let kind = storage_error_kind(&e);
            warn!(
                account_id = %redacted_account_id(&account.id),
                use_keyring,
                error_kind = %kind,
                "Password load failed"
            );
            Err(Box::new(PasswordLoadError { timing, kind }))
        }
    }
}

#[cfg(test)]
fn redact_password_load_error(
    error: anyhow::Error,
    account_id: &AccountId,
    use_keyring: bool,
) -> anyhow::Error {
    warn!(
        account_id = %redacted_account_id(account_id),
        use_keyring,
        error_kind = %storage_error_kind(&error),
        "Password load failed"
    );
    anyhow::anyhow!("password could not be loaded from configured secure storage")
}

fn load_from_keyring_timed(account: &Account) -> anyhow::Result<LoadedStoredPassword> {
    // Finish every potentially blocking lock/recovery operation before the
    // provider can materialize a legacy plaintext password. Keep the lock
    // through a possible migration write so another credential transaction
    // cannot change staged fallback-key state between preflight and commit.
    let _lock = acquire_password_file_transaction_lock()?;
    prepare_password_file_transaction()?;
    let entry = keyring::Entry::new(SERVICE_NAME, &account.id)?;
    let stored = Zeroizing::new(entry.get_password()?);
    let zeroizing_start = std::time::Instant::now();
    let (password, format, secure_storage_needs_migration, rollback_marker) =
        decode_keyring_password(account, stored.as_str())?;
    let zeroizing_wrap_ms = zeroizing_start.elapsed().as_millis();
    let migration_payload =
        if secure_storage_needs_migration || format == StoredPasswordFormat::LegacyRaw {
            Some(encode_keyring_password_with_rollback_marker(
                account,
                password.as_str(),
                rollback_marker.as_deref(),
            )?)
        } else {
            None
        };
    if let Some(payload) = migration_payload {
        // The initial decode was needed only to construct the replacement.
        // Recreate the return allocation from that replacement after the
        // provider call instead of retaining any separately reversible copy.
        drop(password);
        drop(stored);
        let set_result = entry.set_password(payload.as_str());
        if let Err(e) = set_result {
            warn!(account_id = %redacted_account_id(&account.id), error = %e, "Password loaded from legacy keychain format, but migration to user-bound DPAPI storage failed");
        } else {
            info!(account_id = %redacted_account_id(&account.id), "Migrated legacy keychain password to user-bound DPAPI storage");
        }
        let (password, _, _, rollback_marker) = decode_keyring_password(account, payload.as_str())?;
        drop(payload);
        return Ok(LoadedStoredPassword {
            password,
            rollback_marker,
            zeroizing_wrap_ms,
        });
    }
    drop(stored);
    Ok(LoadedStoredPassword {
        password,
        rollback_marker,
        zeroizing_wrap_ms,
    })
}

fn cleanup_migrated_legacy_credentials(account_ids: &[AccountId]) {
    for account_id in account_ids {
        if let Err(e) = delete_password(account_id) {
            debug!(
                account_id = %redacted_account_id(account_id),
                error = %e,
                "legacy credential cleanup skipped"
            );
        }
    }
}

fn legacy_credential_cleanup_ids(legacy: &LegacyConfig) -> Vec<AccountId> {
    let mut ids = Vec::new();
    let Some(credentials) = &legacy.credentials else {
        return ids;
    };

    push_unique_account_id(&mut ids, credentials.account_id.as_deref());
    push_unique_account_id(&mut ids, Some(credentials.username.trim()));
    ids
}

fn push_unique_account_id(ids: &mut Vec<AccountId>, candidate: Option<&str>) {
    let Some(candidate) = candidate.map(str::trim).filter(|value| !value.is_empty()) else {
        return;
    };
    if !ids.iter().any(|existing| existing == candidate) {
        ids.push(candidate.to_string());
    }
}

fn redacted_path(path: &Path) -> String {
    crate::user_paths::redacted_path(&path.display().to_string())
}

fn storage_error_kind(error: &anyhow::Error) -> &'static str {
    let message = error.to_string();
    if message.contains("not found") || message.contains("NoEntry") {
        "not_found"
    } else if message.contains("user-bound DPAPI unprotect failed") {
        "user_bound_dpapi_unprotect_failed"
    } else if message.contains("decrypt")
        || message.contains("ciphertext")
        || message.contains("invalid fallback key")
    {
        "decrypt_failed"
    } else if message.contains("Keychain")
        || message.contains("Credential Manager")
        || message.contains("credential")
        || message.contains("keyring")
    {
        "secure_storage_unavailable"
    } else {
        "storage_error"
    }
}

fn delete_password(account_id: &AccountId) -> anyhow::Result<()> {
    let mut errors = Vec::new();
    if let Err(e) = delete_from_keyring(account_id) {
        errors.push(format!("keychain: {}", e));
    }

    if let Err(e) = delete_from_file(account_id) {
        errors.push(format!("password file: {}", e));
    }

    if !errors.is_empty() {
        anyhow::bail!("{}", errors.join("; "));
    }

    info!(account_id = %redacted_account_id(account_id), "Password deleted from all storage locations");
    Ok(())
}

pub(crate) fn delete_account(account_id: &AccountId) -> anyhow::Result<()> {
    debug!(account_id = %redacted_account_id(account_id), "delete_account called");
    if let Err(e) = delete_password(account_id) {
        debug!(
            account_id = %redacted_account_id(account_id),
            error = %e,
            "Error during password deletion (may already be gone)"
        );
        return Err(e);
    } else {
        info!(account_id = %redacted_account_id(account_id), "delete_account completed successfully");
    }
    if let Err(e) = cleanup_unused_fallback_key_material() {
        warn!(
            account_id = %redacted_account_id(account_id),
            error_kind = storage_error_kind(&e),
            error = %e,
            "Account password records were deleted, but unused fallback key cleanup failed"
        );
        return Err(e);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        active_scoped_fallback_keys_by_id, backup_invalid_config_file,
        cleanup_fallback_key_if_password_file_empty,
        cleanup_legacy_fallback_key_residue_files_in_dir, cleanup_retired_fallback_keys_with_ops,
        cleanup_stale_backend_after_successful_save, cleanup_storage_backend_with_ops,
        cleanup_storage_temp_files_in_dir, clear_pending_storage_operation_paths,
        clear_pending_storage_operation_with_marker,
        clear_storage_recovery_block_after_startup_recovery_at,
        clear_storage_recovery_block_after_startup_recovery_with_ops,
        clear_storage_recovery_block_after_startup_recovery_with_state,
        commit_password_file_with_staged_keys_with_ops, committed_config_write_test_error,
        config_write_committed, consume_pending_storage_operation_record_with_ops,
        decode_bound_password, decode_bound_password_with_rollback_marker,
        decrypt_password_with_fallback_key, decrypt_password_with_key,
        delete_fallback_key_material_with_ops, delete_sensitive_private_file_if_present,
        direct_password_write_after_preflight_with_ops, encode_bound_password,
        encode_bound_password_with_rollback_marker, encrypt_password_with_key,
        ensure_no_pending_storage_operation, finish_account_password_write_with_ops,
        install_scoped_fallback_entry, is_pending_storage_operation_in_progress,
        legacy_account_id_for_migrated_config, legacy_migration_target_cleanup_id,
        legacy_password_migration_ready_to_persist, load_config_file,
        load_pending_storage_operation_record_fail_closed_from_paths,
        load_pending_storage_operation_record_fail_closed_with_marker,
        mark_storage_recovery_blocked_at, migrate_legacy_config,
        migrate_legacy_fallback_entries_with_ops, normalize_config, password_entry_for_account,
        pending_storage_backend_to_cleanup, pending_storage_operation_account_ids_known,
        quarantine_pending_storage_operation_file, read_private_text_file,
        reconcile_account_config_rollback_operation_with_ops,
        reconcile_account_config_save_operation_with_ops,
        reconcile_account_delete_operation_with_ops,
        reconcile_committed_account_enabled_toggle_operation_with_ops,
        reconcile_prepared_account_delete_operation_with_ops,
        reconcile_prepared_account_enabled_toggle_operation_with_ops,
        reconcile_staged_fallback_keys_if_safe, reconcile_staged_fallback_keys_with_ops,
        reconcile_storage_mode_operation, redact_password_load_error, redacted_account_id,
        remove_fallback_entry, replace_account_config_save_journal_with_rollback,
        replace_prepared_account_delete_journal, replace_prepared_account_enabled_toggle_journal,
        save_pending_storage_operation_to_paths, save_pending_storage_operation_with_preflight_ops,
        sha256_hex, stage_and_commit_fallback_payload_with_ops, storage_error_kind,
        use_owned_secret_then_drop, validate_password_file_shape,
        validate_pending_storage_operation, verify_pending_storage_surviving_backend,
        write_private_file_atomic, write_private_file_create_new_atomic, LegacyConfig,
        LegacyCredentialsConfig, LegacyPasswordMigration, PasswordFile, PasswordFileWriteCommitted,
        PasswordStorageBackend, PasswordWriteReceipt, PendingStorageOperation,
        PendingStorageOperationRecord, PendingStorageRecoveryBlocked, ScopedFallbackKeyRef,
        StagedFallbackKeyConflict, StagedFallbackKeysJournal, StoredPasswordFormat,
        AES_GCM_NONCE_BYTES, AES_GCM_TAG_BYTES, MAX_PASSWORD_FILE_BYTES,
        PASSWORD_TRANSACTION_TEMP_FILE_PREFIXES, PENDING_STORAGE_OPERATION_VERSION,
        SECURE_STORAGE_FALLBACK_KEY_PURPOSE, SECURE_STORAGE_PASSWORD_PURPOSE,
        STAGED_FALLBACK_KEYS_VERSION, WINDOWS_LEGACY_WAAB_SECRET_PREFIX,
        WINDOWS_USER_BOUND_SECRET_PREFIX,
    };
    #[cfg(target_os = "windows")]
    use super::{
        decode_fallback_encryption_key, decode_keyring_password, decode_secure_storage_secret,
        encode_keyring_password, encode_secure_storage_secret, PASSWORD_ENVELOPE_PREFIX, STANDARD,
    };
    #[cfg(unix)]
    use super::{validate_private_dir, validate_private_file_for_read};
    use crate::models::{Account, AppConfig, FIXED_POLL_INTERVAL_SECS};
    #[cfg(target_os = "windows")]
    use base64::Engine as _;
    use std::cell::{Cell, RefCell};
    use std::collections::HashMap;
    use zeroize::Zeroizing;

    #[test]
    fn legacy_migration_uses_fixed_poll_interval() {
        let legacy = LegacyConfig {
            poll_interval_secs: 30,
            ..LegacyConfig::default()
        };

        let config = migrate_legacy_config(&legacy);

        assert_eq!(config.settings.poll_interval_secs, FIXED_POLL_INTERVAL_SECS);
    }

    #[test]
    fn legacy_migration_ignores_removed_target_app_fields() {
        let legacy: LegacyConfig = serde_json::from_value(serde_json::json!({
            "process_names": ["Microsoft Remote Desktop"],
            "macos_app_name": "Microsoft Remote Desktop"
        }))
        .unwrap();

        let config = migrate_legacy_config(&legacy);
        let json = serde_json::to_string(&config).unwrap();

        assert!(!json.contains("macos_app_name"));
        assert!(!json.contains("Microsoft Remote Desktop"));
        assert!(!json.contains("Windows App"));
    }

    #[test]
    fn legacy_migration_does_not_use_email_as_account_id() {
        let legacy = LegacyConfig {
            credentials: Some(LegacyCredentialsConfig {
                username: "user@example.com".to_string(),
                account_id: None,
                use_credential_manager: true,
            }),
            ..LegacyConfig::default()
        };

        let config = migrate_legacy_config(&legacy);

        assert_eq!(config.accounts[0].username, "user@example.com");
        assert_ne!(config.accounts[0].id, "user@example.com");
        assert!(!config.accounts[0].id.contains('@'));
    }

    #[test]
    fn legacy_migration_trims_reused_account_id() {
        let credentials = LegacyCredentialsConfig {
            username: "user@example.com".to_string(),
            account_id: Some(" legacy-id ".to_string()),
            use_credential_manager: true,
        };

        assert_eq!(
            legacy_account_id_for_migrated_config(&credentials).as_deref(),
            Some("legacy-id")
        );
    }

    #[test]
    fn legacy_migration_target_cleanup_tracks_generated_accounts_only() {
        for (source_ids, target_id, should_cleanup) in [
            (
                vec!["user@example.com".to_string(), "legacy-id".to_string()],
                "generated-account-id".to_string(),
                true,
            ),
            (
                vec!["legacy-id".to_string(), "user@example.com".to_string()],
                "legacy-id".to_string(),
                false,
            ),
        ] {
            assert_eq!(
                legacy_migration_target_cleanup_id(&source_ids, &target_id).is_some(),
                should_cleanup
            );
        }
    }

    #[test]
    fn legacy_password_migration_ready_to_persist_requires_target_for_sources() {
        for (migration, expected) in [
            (LegacyPasswordMigration::default(), true),
            (
                LegacyPasswordMigration {
                    source_ids: vec!["legacy-id".to_string()],
                    target_id: Some("account-1".to_string()),
                    cleanup_ids_after_save: Vec::new(),
                },
                true,
            ),
            (
                LegacyPasswordMigration {
                    source_ids: vec!["legacy-id".to_string()],
                    target_id: None,
                    cleanup_ids_after_save: Vec::new(),
                },
                false,
            ),
        ] {
            assert_eq!(
                legacy_password_migration_ready_to_persist(&migration),
                expected
            );
        }
    }

    #[test]
    fn normalize_config_disables_later_enabled_saved_duplicate_usernames() {
        let mut first = Account::new("User@Example.com");
        first.id = "account-1".to_string();
        first.has_saved_password = true;
        let mut duplicate = Account::new(" user@example.com ");
        duplicate.id = "account-2".to_string();
        duplicate.has_saved_password = true;
        let config = AppConfig {
            accounts: vec![first, duplicate],
            ..AppConfig::default()
        };

        let normalized = normalize_config(config);

        assert!(normalized.accounts[0].enabled);
        assert!(!normalized.accounts[1].enabled);
        assert!(normalized.accounts[1].has_saved_password);
    }

    #[test]
    fn normalize_config_disables_later_enabled_saved_duplicate_ids() {
        let mut first = Account::new("one@example.com");
        first.id = "account-1".to_string();
        first.has_saved_password = true;
        let mut duplicate = Account::new("two@example.com");
        duplicate.id = "account-1".to_string();
        duplicate.has_saved_password = true;
        let config = AppConfig {
            accounts: vec![first, duplicate],
            ..AppConfig::default()
        };

        let normalized = normalize_config(config);

        assert!(normalized.accounts[0].enabled);
        assert!(!normalized.accounts[1].enabled);
        assert!(normalized.accounts[1].has_saved_password);
    }

    #[test]
    fn normalize_config_keeps_auto_start_independent_of_saved_accounts() {
        let mut account = Account::new("user@example.com");
        account.id = "account-1".to_string();
        account.enabled = true;
        account.has_saved_password = false;
        let mut config = AppConfig {
            accounts: vec![account],
            ..AppConfig::default()
        };
        config.settings.auto_start = true;

        let normalized = normalize_config(config);

        assert!(normalized.settings.auto_start);
        assert!(normalized.accounts[0].enabled);
        assert!(!normalized.accounts[0].has_saved_password);
    }

    #[test]
    fn load_config_file_missing_uses_default_auto_start() {
        let dir = std::env::temp_dir().join(format!("waa-missing-config-{}", uuid::Uuid::new_v4()));
        let path = dir.join("config.json");

        let config = load_config_file(&path).unwrap();

        assert!(!config.settings.auto_start);
    }

    #[test]
    fn pending_storage_recovery_cleanup_backend_depends_on_config_save_state() {
        let operation = PendingStorageOperation {
            version: PENDING_STORAGE_OPERATION_VERSION,
            kind: "storage_mode_migration".to_string(),
            account_ids: vec!["account-1".to_string()],
            from_use_keyring: true,
            to_use_keyring: false,
            use_keyring: false,
            before_account: None,
            after_account: None,
            rollback_marker: None,
        };

        for (config_not_saved, expected_backend) in [(true, false), (false, true)] {
            assert_eq!(
                pending_storage_backend_to_cleanup(&operation, config_not_saved),
                Some(expected_backend)
            );
        }
    }

    #[test]
    fn pending_storage_recovery_verifies_current_backend_before_cleanup() {
        let mut config = AppConfig::default();
        config.settings.use_keyring = false;
        let mut account = Account::new("user@example.com");
        account.id = "account-1".to_string();
        account.has_saved_password = true;
        config.accounts.push(account);
        let operation = PendingStorageOperation {
            version: PENDING_STORAGE_OPERATION_VERSION,
            kind: "storage_mode_migration".to_string(),
            account_ids: vec!["account-1".to_string()],
            from_use_keyring: true,
            to_use_keyring: false,
            use_keyring: false,
            before_account: None,
            after_account: None,
            rollback_marker: None,
        };
        let mut attempts = Vec::new();

        verify_pending_storage_surviving_backend(&config, &operation, |account, use_keyring| {
            attempts.push((account.id.clone(), use_keyring));
            Ok(())
        })
        .unwrap();

        assert_eq!(attempts, vec![("account-1".to_string(), false)]);
    }

    #[test]
    fn pending_account_config_save_recovery_retries_stale_cleanup_after_verified_target() {
        let mut config = AppConfig::default();
        let operation = account_config_save_pending_operation(true);
        let events = RefCell::new(Vec::new());

        let error = reconcile_account_config_save_operation_with_ops(
            &mut config,
            &operation,
            |account, use_keyring| {
                events
                    .borrow_mut()
                    .push(format!("load:{}:{use_keyring}", account.id));
                Ok(None)
            },
            |use_keyring| {
                events
                    .borrow_mut()
                    .push(format!("finalize-target:{use_keyring}"));
                Ok(())
            },
            |next_config| {
                events.borrow_mut().push("save_config".to_string());
                assert!(next_config
                    .accounts
                    .iter()
                    .any(|account| account.username == "user@example.com"));
                Ok(())
            },
            |account_ids, use_keyring| {
                events
                    .borrow_mut()
                    .push(format!("cleanup:{}:{use_keyring}", account_ids.join(",")));
                anyhow::bail!("stale cleanup failed")
            },
            |_| panic!("target password should not be deleted after verified recovery"),
        )
        .unwrap_err();

        assert!(error.to_string().contains("stale cleanup failed"));
        assert_eq!(
            events.into_inner(),
            vec![
                "load:account-1:true",
                "finalize-target:true",
                "save_config",
                "cleanup:account-1:false"
            ]
        );
    }

    #[test]
    fn pending_account_config_save_recovery_does_not_cleanup_stale_backend_when_target_unverified()
    {
        let mut config = AppConfig::default();
        let operation = account_config_save_pending_operation(true);
        let events = RefCell::new(Vec::new());

        reconcile_account_config_save_operation_with_ops(
            &mut config,
            &operation,
            |account, use_keyring| {
                events
                    .borrow_mut()
                    .push(format!("load:{}:{use_keyring}", account.username));
                if account.username == "user@example.com" {
                    anyhow::bail!("target missing")
                }
                Ok(None)
            },
            |use_keyring| {
                events
                    .borrow_mut()
                    .push(format!("finalize-before:{use_keyring}"));
                Ok(())
            },
            |next_config| {
                events.borrow_mut().push("save_config".to_string());
                assert!(next_config
                    .accounts
                    .iter()
                    .any(|account| account.username == "old@example.com"));
                Ok(())
            },
            |_, _| panic!("stale cleanup must wait until target backend is verified"),
            |_| panic!("target password should not be deleted when before account exists"),
        )
        .unwrap();

        assert_eq!(
            events.into_inner(),
            vec![
                "load:user@example.com:true",
                "load:old@example.com:true",
                "finalize-before:true",
                "save_config"
            ]
        );
    }

    #[test]
    fn pending_account_config_save_rejects_readable_password_from_an_old_revision() {
        let expected_marker = "11111111-1111-4111-8111-111111111111";
        let old_marker = "22222222-2222-4222-8222-222222222222";
        let mut operation = account_config_save_pending_operation(false);
        operation.rollback_marker = Some(expected_marker.to_string());
        validate_pending_storage_operation(&operation).unwrap();

        let before_account = operation.before_account.clone().unwrap();
        let mut config = AppConfig {
            accounts: vec![before_account.clone()],
            ..AppConfig::default()
        };
        let error = reconcile_account_config_save_operation_with_ops(
            &mut config,
            &operation,
            |account, _| {
                assert_eq!(account.username, "user@example.com");
                Ok(Some(old_marker.to_string()))
            },
            |_| panic!("the wrong password revision must not be finalized"),
            |_| panic!("the wrong password revision must not change config"),
            |_, _| panic!("the wrong password revision must not trigger stale cleanup"),
            |_| panic!("the wrong password revision must not be deleted or rolled back"),
        )
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("forward password revision marker could not be verified"));
        assert_eq!(config.accounts, vec![before_account]);
    }

    #[test]
    fn pending_password_only_save_recovers_prior_authenticated_revision() {
        let forward_marker = "11111111-1111-4111-8111-111111111111";
        let rollback_marker = "22222222-2222-4222-8222-222222222222";
        let mut operation = account_config_save_pending_operation(true);
        operation.after_account = operation.before_account.clone();
        operation.rollback_marker = Some(forward_marker.to_string());
        validate_pending_storage_operation(&operation).unwrap();
        let before_account = operation.before_account.clone().unwrap();
        let mut config = AppConfig {
            accounts: vec![before_account.clone()],
            ..AppConfig::default()
        };
        let events = RefCell::new(Vec::new());

        reconcile_account_config_save_operation_with_ops(
            &mut config,
            &operation,
            |account, _| {
                assert_eq!(account.id, before_account.id);
                Ok(Some(rollback_marker.to_string()))
            },
            |_| {
                events.borrow_mut().push("finalize-prior");
                Ok(())
            },
            |_| {
                events.borrow_mut().push("save-prior-config");
                Ok(())
            },
            |_, _| panic!("prior-state recovery must preserve the stale backend"),
            |_| panic!("prior-state recovery must preserve the restored password"),
        )
        .unwrap();

        assert_eq!(config.accounts, vec![before_account]);
        assert_eq!(
            events.into_inner(),
            vec!["finalize-prior", "save-prior-config"]
        );
    }

    #[test]
    fn pending_username_change_rejects_wrong_authenticated_revision() {
        let forward_marker = "11111111-1111-4111-8111-111111111111";
        let rollback_marker = "22222222-2222-4222-8222-222222222222";
        let mut operation = account_config_save_pending_operation(false);
        operation.rollback_marker = Some(forward_marker.to_string());
        validate_pending_storage_operation(&operation).unwrap();
        let before_account = operation.before_account.clone().unwrap();
        let mut config = AppConfig {
            accounts: vec![before_account.clone()],
            ..AppConfig::default()
        };

        let error = reconcile_account_config_save_operation_with_ops(
            &mut config,
            &operation,
            |account, _| {
                assert_eq!(account.username, "user@example.com");
                Ok(Some(rollback_marker.to_string()))
            },
            |_| panic!("mismatched binding must not be finalized"),
            |_| panic!("mismatched binding must not change config"),
            |_, _| panic!("mismatched binding must not clean stale storage"),
            |_| panic!("mismatched binding must not delete a credential"),
        )
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("forward password revision marker could not be verified"));
        assert_eq!(config.accounts, vec![before_account]);
    }

    #[test]
    fn pending_account_config_save_accepts_only_the_matching_forward_revision() {
        let expected_marker = "11111111-1111-4111-8111-111111111111";
        let mut operation = account_config_save_pending_operation(true);
        operation.rollback_marker = Some(expected_marker.to_string());
        validate_pending_storage_operation(&operation).unwrap();
        let after_account = operation.after_account.clone().unwrap();
        let mut config = AppConfig::default();

        reconcile_account_config_save_operation_with_ops(
            &mut config,
            &operation,
            |_, _| Ok(Some(expected_marker.to_string())),
            |_| Ok(()),
            |_| Ok(()),
            |_, _| Ok(()),
            |_| panic!("a matching target revision must not be deleted"),
        )
        .unwrap();

        assert_eq!(config.accounts, vec![after_account]);
    }

    #[test]
    fn pending_new_account_save_retains_journal_on_transient_target_read_error() {
        let expected_marker = "11111111-1111-4111-8111-111111111111";
        let mut operation = account_config_save_pending_operation(true);
        operation.before_account = None;
        operation.rollback_marker = Some(expected_marker.to_string());
        validate_pending_storage_operation(&operation).unwrap();
        let mut config = AppConfig::default();
        let delete_called = Cell::new(false);

        let error = reconcile_account_config_save_operation_with_ops(
            &mut config,
            &operation,
            |_, _| anyhow::bail!("transient credential provider failure"),
            |_| panic!("an unreadable target must not be finalized"),
            |_| panic!("an unreadable target must not mutate config"),
            |_, _| panic!("an unreadable target must not clean stale storage"),
            |_| {
                delete_called.set(true);
                Ok(())
            },
        )
        .unwrap_err();

        assert!(error.to_string().contains("recovery remains pending"));
        assert!(config.accounts.is_empty());
        assert!(!delete_called.get());
    }

    #[test]
    fn pending_password_only_save_retry_recognizes_matching_forward_revision() {
        let expected_marker = "11111111-1111-4111-8111-111111111111";
        let mut operation = account_config_save_pending_operation(true);
        operation.after_account = operation.before_account.clone();
        operation.rollback_marker = Some(expected_marker.to_string());
        validate_pending_storage_operation(&operation).unwrap();
        let after_account = operation.after_account.clone().unwrap();
        let mut config = AppConfig {
            accounts: vec![after_account.clone()],
            ..AppConfig::default()
        };
        let load_attempts = Cell::new(0usize);
        let events = RefCell::new(Vec::new());

        reconcile_account_config_save_operation_with_ops(
            &mut config,
            &operation,
            |_, _| {
                let attempt = load_attempts.get();
                load_attempts.set(attempt + 1);
                if attempt == 0 {
                    anyhow::bail!("transient first read failure")
                }
                Ok(Some(expected_marker.to_string()))
            },
            |_| {
                events.borrow_mut().push("finalize-forward");
                Ok(())
            },
            |_| {
                events.borrow_mut().push("save-forward-config");
                Ok(())
            },
            |_, _| {
                events.borrow_mut().push("cleanup-stale-backend");
                Ok(())
            },
            |_| panic!("a matching forward revision must never be deleted"),
        )
        .unwrap();

        assert_eq!(load_attempts.get(), 2);
        assert_eq!(config.accounts, vec![after_account]);
        assert_eq!(
            events.into_inner(),
            vec![
                "finalize-forward",
                "save-forward-config",
                "cleanup-stale-backend"
            ]
        );
    }

    #[test]
    fn account_rollback_journal_restores_before_state_before_stale_cleanup() {
        let save_operation = account_config_save_pending_operation(true);
        let before_account = save_operation.before_account.clone().unwrap();
        let rollback_operation = PendingStorageOperation {
            version: PENDING_STORAGE_OPERATION_VERSION,
            kind: "account_config_rollback".to_string(),
            account_ids: vec![before_account.id.clone()],
            from_use_keyring: false,
            to_use_keyring: false,
            use_keyring: true,
            before_account: Some(before_account.clone()),
            after_account: None,
            rollback_marker: Some("11111111-1111-4111-8111-111111111111".to_string()),
        };
        validate_pending_storage_operation(&rollback_operation).unwrap();

        let mut config = AppConfig::default();
        config
            .accounts
            .push(save_operation.after_account.clone().unwrap());
        let events = RefCell::new(Vec::new());
        reconcile_account_config_rollback_operation_with_ops(
            &mut config,
            &rollback_operation,
            |account, use_keyring| {
                events
                    .borrow_mut()
                    .push(format!("verify:{}:{use_keyring}", account.username));
                Ok(Some("11111111-1111-4111-8111-111111111111".to_string()))
            },
            |use_keyring| {
                events
                    .borrow_mut()
                    .push(format!("finalize-restored:{use_keyring}"));
                Ok(())
            },
            |next_config| {
                events.borrow_mut().push("save-before-config".to_string());
                assert_eq!(next_config.accounts, vec![before_account.clone()]);
                Ok(())
            },
            |account_ids, use_keyring| {
                events.borrow_mut().push(format!(
                    "cleanup-stale:{}:{use_keyring}",
                    account_ids.join(",")
                ));
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(config.accounts, vec![before_account]);
        assert_eq!(
            events.into_inner(),
            vec![
                "verify:old@example.com:true",
                "finalize-restored:true",
                "save-before-config",
                "cleanup-stale:account-1:false"
            ]
        );
    }

    #[test]
    fn account_rollback_journal_stays_pending_when_before_password_is_unverified() {
        let save_operation = account_config_save_pending_operation(false);
        let before_account = save_operation.before_account.clone().unwrap();
        let rollback_operation = PendingStorageOperation {
            version: PENDING_STORAGE_OPERATION_VERSION,
            kind: "account_config_rollback".to_string(),
            account_ids: vec![before_account.id.clone()],
            from_use_keyring: false,
            to_use_keyring: false,
            use_keyring: false,
            before_account: Some(before_account),
            after_account: None,
            rollback_marker: Some("11111111-1111-4111-8111-111111111111".to_string()),
        };
        let mut config = AppConfig::default();
        config
            .accounts
            .push(save_operation.after_account.clone().unwrap());
        let original = config.clone();

        let error = reconcile_account_config_rollback_operation_with_ops(
            &mut config,
            &rollback_operation,
            |_, _| anyhow::bail!("restored password unavailable"),
            |_| panic!("unverified rollback must not finalize backend cleanup"),
            |_| panic!("unverified rollback must not change config"),
            |_, _| panic!("unverified rollback must not clean stale storage"),
        )
        .unwrap_err();

        assert!(error.to_string().contains("restored password unavailable"));
        assert_eq!(config, original);
    }

    #[test]
    fn account_rollback_journal_rejects_readable_password_without_matching_marker() {
        let save_operation = account_config_save_pending_operation(true);
        let before_account = save_operation.before_account.clone().unwrap();
        let rollback_operation = PendingStorageOperation {
            version: PENDING_STORAGE_OPERATION_VERSION,
            kind: "account_config_rollback".to_string(),
            account_ids: vec![before_account.id.clone()],
            from_use_keyring: false,
            to_use_keyring: false,
            use_keyring: true,
            before_account: Some(before_account),
            after_account: None,
            rollback_marker: Some("11111111-1111-4111-8111-111111111111".to_string()),
        };
        let mut config = AppConfig::default();
        config
            .accounts
            .push(save_operation.after_account.clone().unwrap());
        let original = config.clone();

        let error = reconcile_account_config_rollback_operation_with_ops(
            &mut config,
            &rollback_operation,
            |_, _| Ok(None),
            |_| panic!("unmarked password must not finalize backend cleanup"),
            |_| panic!("unmarked password must not change config"),
            |_, _| panic!("unmarked password must not clean stale storage"),
        )
        .unwrap_err();

        assert!(error.to_string().contains("rollback marker"));
        assert_eq!(config, original);
    }

    #[test]
    fn legacy_unmarked_account_rollback_journal_remains_blocked() {
        let save_operation = account_config_save_pending_operation(true);
        let before_account = save_operation.before_account.clone().unwrap();
        let rollback_operation = PendingStorageOperation {
            version: PENDING_STORAGE_OPERATION_VERSION,
            kind: "account_config_rollback".to_string(),
            account_ids: vec![before_account.id.clone()],
            from_use_keyring: false,
            to_use_keyring: false,
            use_keyring: true,
            before_account: Some(before_account),
            after_account: None,
            rollback_marker: None,
        };
        validate_pending_storage_operation(&rollback_operation).unwrap();
        let mut config = AppConfig::default();
        config
            .accounts
            .push(save_operation.after_account.clone().unwrap());
        let original = config.clone();

        let error = reconcile_account_config_rollback_operation_with_ops(
            &mut config,
            &rollback_operation,
            |_, _| panic!("unmarked rollback must not inspect or accept a password"),
            |_| panic!("unmarked rollback must not finalize backend cleanup"),
            |_| panic!("unmarked rollback must not change config"),
            |_, _| panic!("unmarked rollback must not clean stale storage"),
        )
        .unwrap_err();

        assert!(error.to_string().contains("no verifiable rollback marker"));
        assert_eq!(config, original);
    }

    #[test]
    fn account_rollback_journal_stays_pending_when_selected_backend_cleanup_is_unfinished() {
        let save_operation = account_config_save_pending_operation(false);
        let before_account = save_operation.before_account.clone().unwrap();
        let rollback_operation = PendingStorageOperation {
            version: PENDING_STORAGE_OPERATION_VERSION,
            kind: "account_config_rollback".to_string(),
            account_ids: vec![before_account.id.clone()],
            from_use_keyring: false,
            to_use_keyring: false,
            use_keyring: false,
            before_account: Some(before_account),
            after_account: None,
            rollback_marker: Some("11111111-1111-4111-8111-111111111111".to_string()),
        };
        let mut config = AppConfig::default();
        config
            .accounts
            .push(save_operation.after_account.clone().unwrap());
        let original = config.clone();

        let error = reconcile_account_config_rollback_operation_with_ops(
            &mut config,
            &rollback_operation,
            |_, _| Ok(Some("11111111-1111-4111-8111-111111111111".to_string())),
            |_| anyhow::bail!("retired fallback key cleanup pending"),
            |_| panic!("unfinished selected backend must not change config"),
            |_, _| panic!("unfinished selected backend must not clean stale storage"),
        )
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("retired fallback key cleanup pending"));
        assert_eq!(config, original);
    }

    #[test]
    fn rollback_phase_atomically_replaces_only_matching_account_save_journal() {
        let root = temp_storage_test_dir("account-rollback-journal-replace");
        let pending_path = root.join("pending-storage-operation.json");
        let recovering_path = root.join("pending-storage-operation.recovering.json");
        let save_operation = account_config_save_pending_operation(true);
        save_pending_storage_operation_to_paths(&save_operation, &pending_path, &recovering_path)
            .unwrap();
        let before_account = save_operation.before_account.clone().unwrap();
        let rollback_operation = PendingStorageOperation {
            version: PENDING_STORAGE_OPERATION_VERSION,
            kind: "account_config_rollback".to_string(),
            account_ids: vec![before_account.id.clone()],
            from_use_keyring: false,
            to_use_keyring: false,
            use_keyring: true,
            before_account: Some(before_account),
            after_account: None,
            rollback_marker: Some("11111111-1111-4111-8111-111111111111".to_string()),
        };

        replace_account_config_save_journal_with_rollback(
            &rollback_operation,
            &pending_path,
            &recovering_path,
        )
        .unwrap();
        let replaced = super::load_pending_storage_operation_from_path(&pending_path).unwrap();
        assert_eq!(replaced.operation, rollback_operation);

        let second_error = replace_account_config_save_journal_with_rollback(
            &rollback_operation,
            &pending_path,
            &recovering_path,
        )
        .unwrap_err();
        assert!(second_error
            .to_string()
            .contains("does not match the rollback request"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn account_delete_commit_phase_atomically_replaces_only_matching_prepared_journal() {
        let root = temp_storage_test_dir("account-delete-journal-phase");
        let pending_path = root.join("pending-storage-operation.json");
        let recovering_path = root.join("pending-storage-operation.recovering.json");
        let prepared = account_delete_prepared_operation();
        save_pending_storage_operation_to_paths(&prepared, &pending_path, &recovering_path)
            .unwrap();
        let committed = account_delete_pending_operation();

        replace_prepared_account_delete_journal(&committed, &pending_path, &recovering_path)
            .unwrap();
        let replaced = super::load_pending_storage_operation_from_path(&pending_path).unwrap();
        assert_eq!(replaced.operation, committed);

        let second_error =
            replace_prepared_account_delete_journal(&committed, &pending_path, &recovering_path)
                .unwrap_err();
        assert!(second_error
            .to_string()
            .contains("does not match the commit request"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn account_enabled_toggle_commit_phase_atomically_replaces_prepared_intent() {
        let root = temp_storage_test_dir("account-enabled-toggle-journal-phase");
        let pending_path = root.join("pending-storage-operation.json");
        let recovering_path = root.join("pending-storage-operation.recovering.json");
        let prepared = account_enabled_toggle_operation(true, "account_enabled_toggle_prepared");
        save_pending_storage_operation_to_paths(&prepared, &pending_path, &recovering_path)
            .unwrap();
        let committed = account_enabled_toggle_operation(true, "account_enabled_toggle_committed");

        replace_prepared_account_enabled_toggle_journal(
            &committed,
            &pending_path,
            &recovering_path,
        )
        .unwrap();
        let replaced = super::load_pending_storage_operation_from_path(&pending_path).unwrap();
        assert_eq!(replaced.operation, committed);

        let second_error = replace_prepared_account_enabled_toggle_journal(
            &committed,
            &pending_path,
            &recovering_path,
        )
        .unwrap_err();
        assert!(second_error
            .to_string()
            .contains("does not match the commit request"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn prepared_enabled_toggle_recovery_always_resolves_to_disabled() {
        for before_enabled in [true, false] {
            let operation =
                account_enabled_toggle_operation(before_enabled, "account_enabled_toggle_prepared");
            validate_pending_storage_operation(&operation).unwrap();
            let before_account = operation.before_account.clone().unwrap();
            let after_account = operation.after_account.clone().unwrap();

            // Exercise both a config that still contains the pre-toggle state
            // and one whose atomic rename became visible before journal-phase
            // durability was lost.
            for existing in [before_account.clone(), after_account] {
                let mut config = AppConfig {
                    accounts: vec![existing],
                    ..AppConfig::default()
                };
                let saves = Cell::new(0usize);
                reconcile_prepared_account_enabled_toggle_operation_with_ops(
                    &mut config,
                    &operation,
                    |saved| {
                        saves.set(saves.get() + 1);
                        assert!(!saved.accounts[0].enabled);
                        Ok(())
                    },
                )
                .unwrap();
                assert!(!config.accounts[0].enabled);
                assert_eq!(saves.get(), 1);
            }
        }
    }

    #[test]
    fn committed_disable_recovery_reapplies_target_after_ambiguous_config_commit() {
        let operation = account_enabled_toggle_operation(true, "account_enabled_toggle_committed");
        validate_pending_storage_operation(&operation).unwrap();
        let before_account = operation.before_account.clone().unwrap();
        let mut config = AppConfig {
            accounts: vec![before_account],
            ..AppConfig::default()
        };

        let first_error = reconcile_committed_account_enabled_toggle_operation_with_ops(
            &mut config,
            &operation,
            |saved| {
                assert!(!saved.accounts[0].enabled);
                Err(committed_config_write_test_error())
            },
        )
        .unwrap_err();
        assert!(config_write_committed(&first_error));
        assert!(!config.accounts[0].enabled);

        // A retained journal makes the next recovery idempotently persist the
        // same disabled target rather than resurrecting the old enabled state.
        reconcile_committed_account_enabled_toggle_operation_with_ops(
            &mut config,
            &operation,
            |saved| {
                assert!(!saved.accounts[0].enabled);
                Ok(())
            },
        )
        .unwrap();
        assert!(!config.accounts[0].enabled);
    }

    #[test]
    fn enabled_toggle_journal_rejects_changes_beyond_the_enabled_flag() {
        for kind in [
            "account_enabled_toggle_prepared",
            "account_enabled_toggle_committed",
        ] {
            let mut operation = account_enabled_toggle_operation(true, kind);
            operation.after_account.as_mut().unwrap().username = "attacker@example.com".to_string();
            assert!(validate_pending_storage_operation(&operation)
                .unwrap_err()
                .to_string()
                .contains("fields other than enabled"));
        }
    }

    #[test]
    fn committed_account_delete_recovery_durably_reapplies_removal_before_password_cleanup() {
        let mut config = AppConfig::default();
        let operation = account_delete_pending_operation();
        let attempts = RefCell::new(Vec::new());

        let error = reconcile_account_delete_operation_with_ops(
            &mut config,
            &operation,
            |_| {
                attempts.borrow_mut().push("save_config".to_string());
                Ok(())
            },
            |account_id| {
                attempts.borrow_mut().push(account_id.clone());
                anyhow::bail!("delete failed")
            },
        )
        .unwrap_err();

        assert!(error.to_string().contains("delete failed"));
        assert_eq!(
            attempts.into_inner(),
            vec!["save_config".to_string(), "account-1".to_string()]
        );

        let mut config = AppConfig::default();
        config
            .accounts
            .push(operation.before_account.clone().unwrap());
        let events = RefCell::new(Vec::new());

        reconcile_account_delete_operation_with_ops(
            &mut config,
            &operation,
            |saved| {
                events.borrow_mut().push("save_config");
                assert!(saved.accounts.is_empty());
                Ok(())
            },
            |_| {
                events.borrow_mut().push("delete");
                Ok(())
            },
        )
        .unwrap();
        assert!(config.accounts.is_empty());
        assert_eq!(events.into_inner(), vec!["save_config", "delete"]);
    }

    #[test]
    fn pending_account_delete_recovery_requires_durable_config_before_password_cleanup() {
        let mut config = AppConfig::default();
        let operation = account_delete_pending_operation();
        let events = RefCell::new(Vec::new());

        let error = reconcile_account_delete_operation_with_ops(
            &mut config,
            &operation,
            |_| {
                events.borrow_mut().push("save_config");
                Err(committed_config_write_test_error())
            },
            |_| {
                events.borrow_mut().push("delete");
                Ok(())
            },
        )
        .unwrap_err();

        assert!(config_write_committed(&error));
        assert_eq!(events.into_inner(), vec!["save_config"]);
    }

    #[test]
    fn prepared_account_delete_recovery_cancels_only_when_source_account_is_unchanged() {
        let operation = account_delete_prepared_operation();
        let mut config = AppConfig::default();
        config
            .accounts
            .push(operation.before_account.clone().unwrap());

        reconcile_prepared_account_delete_operation_with_ops(&config, &operation).unwrap();

        config.accounts.clear();
        let absent_error =
            reconcile_prepared_account_delete_operation_with_ops(&config, &operation).unwrap_err();
        assert!(absent_error
            .to_string()
            .contains("cannot prove that config storage was left unchanged"));

        config
            .accounts
            .push(operation.before_account.clone().unwrap());
        config.accounts[0].username = "different@example.com".to_string();
        let mismatch_error =
            reconcile_prepared_account_delete_operation_with_ops(&config, &operation).unwrap_err();
        assert!(mismatch_error
            .to_string()
            .contains("mismatched account metadata"));
    }

    #[test]
    fn pending_storage_recovery_blocks_cleanup_when_current_backend_unloadable() {
        let mut config = AppConfig::default();
        config.settings.use_keyring = true;
        let mut account = Account::new("user@example.com");
        account.id = "account-1".to_string();
        account.has_saved_password = true;
        config.accounts.push(account);
        let operation = PendingStorageOperation {
            version: PENDING_STORAGE_OPERATION_VERSION,
            kind: "storage_mode_migration".to_string(),
            account_ids: vec!["account-1".to_string()],
            from_use_keyring: true,
            to_use_keyring: false,
            use_keyring: false,
            before_account: None,
            after_account: None,
            rollback_marker: None,
        };

        let error = verify_pending_storage_surviving_backend(&config, &operation, |_, _| {
            anyhow::bail!("password missing")
        })
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("current password backend verification failed"));
    }

    #[test]
    fn pending_storage_recovery_skips_accounts_without_saved_password() {
        let mut config = AppConfig::default();
        config.settings.use_keyring = false;
        let mut account = Account::new("user@example.com");
        account.id = "account-1".to_string();
        account.has_saved_password = false;
        config.accounts.push(account);
        let operation = PendingStorageOperation {
            version: PENDING_STORAGE_OPERATION_VERSION,
            kind: "storage_mode_migration".to_string(),
            account_ids: vec!["account-1".to_string()],
            from_use_keyring: true,
            to_use_keyring: false,
            use_keyring: false,
            before_account: None,
            after_account: None,
            rollback_marker: None,
        };

        verify_pending_storage_surviving_backend(&config, &operation, |_, _| {
            panic!("passwordless account should not be loaded")
        })
        .unwrap();
    }

    #[test]
    fn pending_storage_recovery_rejects_unknown_or_duplicate_account_ids() {
        let mut account = Account::new("user@example.com");
        account.id = "account-1".to_string();
        account.has_saved_password = true;
        let mut operation = PendingStorageOperation {
            version: PENDING_STORAGE_OPERATION_VERSION,
            kind: "storage_mode_migration".to_string(),
            account_ids: vec!["account-1".to_string()],
            from_use_keyring: true,
            to_use_keyring: false,
            use_keyring: false,
            before_account: None,
            after_account: None,
            rollback_marker: None,
        };

        assert!(pending_storage_operation_account_ids_known(
            &operation,
            &[account.clone()]
        ));

        operation.account_ids.push("account-1".to_string());
        assert!(!pending_storage_operation_account_ids_known(
            &operation,
            &[account.clone()]
        ));

        operation.account_ids = vec!["missing-account".to_string()];
        assert!(!pending_storage_operation_account_ids_known(
            &operation,
            &[account]
        ));

        let error = reconcile_storage_mode_operation(&AppConfig::default(), &operation)
            .expect_err("unknown migration accounts must keep recovery blocked");
        assert!(error.to_string().contains("absent from the current config"));
    }

    #[test]
    fn account_journals_omit_password_material_and_accept_legacy_delete_snapshot() {
        let mut after_account = Account::new("user@example.com");
        after_account.id = "account-1".to_string();
        after_account.has_saved_password = true;
        let account_config_operation = PendingStorageOperation {
            version: PENDING_STORAGE_OPERATION_VERSION,
            kind: "account_config_save".to_string(),
            account_ids: vec![after_account.id.clone()],
            from_use_keyring: false,
            to_use_keyring: false,
            use_keyring: true,
            before_account: None,
            after_account: Some(after_account),
            rollback_marker: None,
        };

        validate_pending_storage_operation(&account_config_operation).unwrap();
        let serialized = serde_json::to_string(&account_config_operation).unwrap();
        assert!(!serialized.contains("super-secret-password"));
        assert!(!serialized.contains("encrypted_password"));

        let mut mismatched_config_operation = account_config_operation.clone();
        let mut mismatched_before = Account::new("other@example.com");
        mismatched_before.id = "different-account".to_string();
        mismatched_config_operation.before_account = Some(mismatched_before);
        let mismatch_error = validate_pending_storage_operation(&mismatched_config_operation)
            .expect_err("source and target snapshots must name the same account");
        assert!(mismatch_error
            .to_string()
            .contains("source account id does not match target account"));

        let account_delete_operation = account_delete_pending_operation();
        validate_pending_storage_operation(&account_delete_operation).unwrap();
        let serialized = serde_json::to_string(&account_delete_operation).unwrap();
        assert!(!serialized.contains("super-secret-password"));
        assert!(!serialized.contains("encrypted_password"));
        assert!(serialized.contains("before_account"));

        let mut before_account = Account::new("user@example.com");
        before_account.id = "account-1".to_string();
        before_account.has_saved_password = true;
        let legacy_delete_operation = PendingStorageOperation {
            version: PENDING_STORAGE_OPERATION_VERSION,
            kind: "account_delete".to_string(),
            account_ids: vec![before_account.id.clone()],
            from_use_keyring: false,
            to_use_keyring: false,
            use_keyring: true,
            before_account: Some(before_account),
            after_account: None,
            rollback_marker: None,
        };

        validate_pending_storage_operation(&legacy_delete_operation).unwrap();
    }

    #[test]
    fn pending_storage_operation_save_refuses_to_clobber_existing_journals() {
        let root = temp_storage_test_dir("pending-save-no-clobber");
        let pending_path = root.join("pending-storage-operation.json");
        let recovering_path = root.join("pending-storage-operation.recovering.json");
        let mut account = Account::new("user@example.com");
        account.id = "account-1".to_string();
        account.has_saved_password = true;
        let operation = PendingStorageOperation {
            version: PENDING_STORAGE_OPERATION_VERSION,
            kind: "account_delete".to_string(),
            account_ids: vec![account.id.clone()],
            from_use_keyring: false,
            to_use_keyring: false,
            use_keyring: true,
            before_account: None,
            after_account: None,
            rollback_marker: None,
        };

        ensure_no_pending_storage_operation(&pending_path, &recovering_path).unwrap();

        std::fs::write(&pending_path, "sentinel-pending").unwrap();
        let pending_error =
            save_pending_storage_operation_to_paths(&operation, &pending_path, &recovering_path)
                .unwrap_err();
        assert!(is_pending_storage_operation_in_progress(&pending_error));
        assert_eq!(
            std::fs::read_to_string(&pending_path).unwrap(),
            "sentinel-pending"
        );

        std::fs::remove_file(&pending_path).unwrap();
        std::fs::write(&recovering_path, "sentinel-recovering").unwrap();
        let recovering_error =
            save_pending_storage_operation_to_paths(&operation, &pending_path, &recovering_path)
                .unwrap_err();
        assert!(is_pending_storage_operation_in_progress(&recovering_error));
        assert!(!pending_path.exists());
        assert_eq!(
            std::fs::read_to_string(&recovering_path).unwrap(),
            "sentinel-recovering"
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn pending_storage_operation_create_new_write_preserves_existing_target() {
        let root = temp_storage_test_dir("pending-create-new");
        let path = root.join("pending-storage-operation.json");
        std::fs::write(&path, "sentinel").unwrap();

        let error = write_private_file_create_new_atomic(&path, "json.tmp", b"new").unwrap_err();

        assert!(error.downcast_ref::<std::io::Error>().is_some());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "sentinel");
        assert!(
            invalid_storage_operation_entries(&root, "pending-storage-operation.json.tmp.")
                .is_empty()
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn existing_recovering_journal_is_synced_before_recovery_side_effects() {
        let root = temp_storage_test_dir("recovering-journal-sync-order");
        let recovering_path = root.join("pending-storage-operation.recovering.json");
        let operation = account_delete_pending_operation();
        let record = PendingStorageOperationRecord {
            operation,
            path: recovering_path.clone(),
        };
        let events = RefCell::new(Vec::new());

        let durable_record = consume_pending_storage_operation_record_with_ops(
            record,
            &recovering_path,
            |_, _| -> anyhow::Result<()> {
                panic!("an existing recovering journal must not be renamed")
            },
            |_| {
                events.borrow_mut().push("secure-journal");
                Ok(())
            },
            |_| {
                events.borrow_mut().push("sync-parent");
                Ok(())
            },
        )
        .unwrap();
        events.borrow_mut().push("retire-old-key");

        assert_eq!(durable_record.path, recovering_path);
        assert_eq!(
            events.into_inner(),
            vec!["secure-journal", "sync-parent", "retire-old-key"]
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn recovering_journal_sync_failure_prevents_retired_key_deletion() {
        let root = temp_storage_test_dir("recovering-journal-sync-failure");
        let recovering_path = root.join("pending-storage-operation.recovering.json");
        let record = PendingStorageOperationRecord {
            operation: account_delete_pending_operation(),
            path: recovering_path.clone(),
        };
        let retired_key_deleted = Cell::new(false);

        let result = consume_pending_storage_operation_record_with_ops(
            record,
            &recovering_path,
            |_, _| -> anyhow::Result<()> { panic!("journal is already recovering") },
            |_| Ok(()),
            |_| anyhow::bail!("parent fsync failed"),
        )
        .map(|_| {
            retired_key_deleted.set(true);
        });

        assert!(result.is_err());
        assert!(!retired_key_deleted.get());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn durable_storage_recovery_block_persists_until_fresh_start_clear() {
        let root = temp_storage_test_dir("durable-recovery-block");
        let block_path = root.join("storage-recovery-blocked");

        mark_storage_recovery_blocked_at(&block_path).unwrap();
        assert!(block_path.exists());
        assert_eq!(
            std::fs::read(&block_path).unwrap(),
            super::STORAGE_RECOVERY_BLOCK_CONTENT
        );

        // Re-marking is idempotent and does not clear the cross-process latch.
        mark_storage_recovery_blocked_at(&block_path).unwrap();
        assert!(block_path.exists());

        clear_storage_recovery_block_after_startup_recovery_at(&block_path).unwrap();
        assert!(!block_path.exists());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn fresh_start_recovery_block_clear_refuses_while_journal_is_active() {
        let root = temp_storage_test_dir("recovery-block-active-journal");
        let block_path = root.join("storage-recovery-blocked");
        let remove_called = Cell::new(false);
        mark_storage_recovery_blocked_at(&block_path).unwrap();

        let error = clear_storage_recovery_block_after_startup_recovery_with_state(
            false,
            &block_path,
            |_| {
                remove_called.set(true);
                Ok(())
            },
            |_| panic!("an active journal must prevent marker removal"),
        )
        .unwrap_err();

        assert!(error.to_string().contains("recovery journal is active"));
        assert!(!remove_called.get());
        assert!(block_path.exists());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn recovery_block_unlink_fsync_failure_remains_ambiguous_to_caller() {
        let root = temp_storage_test_dir("recovery-block-unlink-ambiguity");
        let block_path = root.join("storage-recovery-blocked");
        mark_storage_recovery_blocked_at(&block_path).unwrap();
        let events = RefCell::new(Vec::new());

        let error = clear_storage_recovery_block_after_startup_recovery_with_ops(
            &block_path,
            |path| {
                events.borrow_mut().push("unlink-committed");
                std::fs::remove_file(path).map_err(anyhow::Error::from)
            },
            |_| {
                events.borrow_mut().push("parent-fsync-failed");
                anyhow::bail!("injected parent fsync failure")
            },
        )
        .unwrap_err();

        assert!(error.to_string().contains("parent fsync failure"));
        assert_eq!(
            events.into_inner(),
            vec!["unlink-committed", "parent-fsync-failed"]
        );
        assert!(!block_path.exists());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn pending_journal_clear_failure_marks_recovery_block_before_returning_error() {
        let root = temp_storage_test_dir("pending-clear-marks-recovery-block");
        let non_directory_parent = root.join("not-a-directory");
        let pending_path = non_directory_parent.join("pending-storage-operation.json");
        let recovering_path =
            non_directory_parent.join("pending-storage-operation.recovering.json");
        let block_path = root.join("storage-recovery-blocked");
        let marker_calls = Cell::new(0);
        std::fs::write(&non_directory_parent, "force journal clear failure").unwrap();

        let error =
            clear_pending_storage_operation_with_marker(&pending_path, &recovering_path, || {
                marker_calls.set(marker_calls.get() + 1);
                mark_storage_recovery_blocked_at(&block_path)
            })
            .unwrap_err();

        assert!(!error.to_string().is_empty());
        assert_eq!(marker_calls.get(), 1);
        assert_eq!(
            std::fs::read(&block_path).unwrap(),
            super::STORAGE_RECOVERY_BLOCK_CONTENT
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn pending_storage_operation_guard_treats_dangling_symlink_as_existing() {
        let root = temp_storage_test_dir("pending-symlink");
        let pending_path = root.join("pending-storage-operation.json");
        let recovering_path = root.join("pending-storage-operation.recovering.json");
        std::os::unix::fs::symlink(root.join("missing-target"), &pending_path).unwrap();

        let error =
            ensure_no_pending_storage_operation(&pending_path, &recovering_path).unwrap_err();

        assert!(is_pending_storage_operation_in_progress(&error));
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn pending_storage_operation_quarantine_removes_dangling_symlink() {
        let root = temp_storage_test_dir("pending-quarantine-symlink");
        let pending_path = root.join("pending-storage-operation.json");
        let missing_target = root.join("missing-target");
        std::os::unix::fs::symlink(&missing_target, &pending_path).unwrap();
        assert!(std::fs::symlink_metadata(&pending_path)
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(!pending_path.exists());

        quarantine_pending_storage_operation_file(&pending_path).unwrap();

        assert!(matches!(
            std::fs::symlink_metadata(&pending_path),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound
        ));
        assert!(!missing_target.exists());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn pending_storage_operation_guard_treats_directories_as_existing() {
        let root = temp_storage_test_dir("pending-dir-guard");
        let pending_path = root.join("pending-storage-operation.json");
        let recovering_path = root.join("pending-storage-operation.recovering.json");
        let operation = account_delete_pending_operation();

        std::fs::create_dir(&pending_path).unwrap();
        let pending_error =
            save_pending_storage_operation_to_paths(&operation, &pending_path, &recovering_path)
                .unwrap_err();
        assert!(is_pending_storage_operation_in_progress(&pending_error));
        assert!(pending_path.is_dir());

        std::fs::remove_dir(&pending_path).unwrap();
        std::fs::create_dir(&recovering_path).unwrap();
        let recovering_error =
            save_pending_storage_operation_to_paths(&operation, &pending_path, &recovering_path)
                .unwrap_err();
        assert!(is_pending_storage_operation_in_progress(&recovering_error));
        assert!(recovering_path.is_dir());
        assert!(!pending_path.exists());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn pending_storage_operation_quarantine_unpins_pending_and_recovering_directories() {
        let root = temp_storage_test_dir("pending-quarantine-dir");
        let pending_path = root.join("pending-storage-operation.json");
        std::fs::create_dir(&pending_path).unwrap();
        std::fs::write(pending_path.join("keep.txt"), "keep").unwrap();

        quarantine_pending_storage_operation_file(&pending_path).unwrap();

        assert!(matches!(
            std::fs::symlink_metadata(&pending_path),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound
        ));
        let invalid_dirs =
            invalid_storage_operation_entries(&root, "pending-storage-operation.invalid.");
        assert_eq!(invalid_dirs.len(), 1);
        assert!(invalid_dirs[0].is_dir());
        assert_eq!(
            std::fs::read_to_string(invalid_dirs[0].join("keep.txt")).unwrap(),
            "keep"
        );

        let recovering_path = root.join("pending-storage-operation.recovering.json");
        std::fs::create_dir(&recovering_path).unwrap();

        quarantine_pending_storage_operation_file(&recovering_path).unwrap();

        assert!(matches!(
            std::fs::symlink_metadata(&recovering_path),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound
        ));
        let invalid_dirs = invalid_storage_operation_entries(
            &root,
            "pending-storage-operation.recovering.invalid.",
        );
        assert_eq!(invalid_dirs.len(), 1);
        assert!(invalid_dirs[0].is_dir());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn pending_storage_operation_clear_unpins_directory_and_still_clears_recovering_file() {
        let root = temp_storage_test_dir("pending-clear-dir");
        let pending_path = root.join("pending-storage-operation.json");
        let recovering_path = root.join("pending-storage-operation.recovering.json");
        std::fs::create_dir(&pending_path).unwrap();
        std::fs::write(pending_path.join("keep.txt"), "keep").unwrap();
        std::fs::write(&recovering_path, "recovering").unwrap();

        clear_pending_storage_operation_paths(&pending_path, &recovering_path).unwrap();

        assert!(!pending_path.exists());
        assert!(!recovering_path.exists());
        let invalid_dirs =
            invalid_storage_operation_entries(&root, "pending-storage-operation.invalid.");
        assert_eq!(invalid_dirs.len(), 1);
        assert_eq!(
            std::fs::read_to_string(invalid_dirs[0].join("keep.txt")).unwrap(),
            "keep"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn pending_storage_operation_clear_removes_temp_journal_files() {
        let root = temp_storage_test_dir("pending-clear-temp");
        let pending_path = root.join("pending-storage-operation.json");
        let recovering_path = root.join("pending-storage-operation.recovering.json");
        let pending_temp_path = root.join("pending-storage-operation.json.tmp.123.456");
        let recovering_temp_path =
            root.join("pending-storage-operation.recovering.json.tmp.123.456");
        std::fs::write(&pending_path, "pending").unwrap();
        std::fs::hard_link(&pending_path, &pending_temp_path).unwrap();
        std::fs::write(&recovering_temp_path, "recovering-user@example.com").unwrap();

        clear_pending_storage_operation_paths(&pending_path, &recovering_path).unwrap();

        assert!(!pending_path.exists());
        assert!(!pending_temp_path.exists());
        assert!(!recovering_temp_path.exists());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn pending_storage_operation_recovery_removes_temp_only_journal_files() {
        let root = temp_storage_test_dir("pending-recovery-temp-only");
        let pending_path = root.join("pending-storage-operation.json");
        let recovering_path = root.join("pending-storage-operation.recovering.json");
        let pending_temp_path = root.join("pending-storage-operation.json.tmp.123.456");
        std::fs::write(&pending_temp_path, "pending-user@example.com").unwrap();

        let record = load_pending_storage_operation_record_fail_closed_from_paths(
            &recovering_path,
            &pending_path,
        )
        .unwrap();

        assert!(record.is_none());
        assert!(!pending_temp_path.exists());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn dual_identical_storage_operation_journals_select_recovering_after_both_validate() {
        let root = temp_storage_test_dir("dual-identical-journals");
        let pending_path = root.join("pending-storage-operation.json");
        let recovering_path = root.join("pending-storage-operation.recovering.json");
        let operation = account_delete_pending_operation();
        let recovering_content = serde_json::to_vec_pretty(&operation).unwrap();
        let pending_content = serde_json::to_vec(&operation).unwrap();
        assert_ne!(recovering_content, pending_content);
        write_private_file_atomic(&recovering_path, "json.tmp", &recovering_content).unwrap();
        write_private_file_atomic(&pending_path, "json.tmp", &pending_content).unwrap();
        let marker_called = Cell::new(false);

        let record = load_pending_storage_operation_record_fail_closed_with_marker(
            &recovering_path,
            &pending_path,
            || {
                marker_called.set(true);
                Ok(())
            },
        )
        .unwrap()
        .unwrap();

        assert_eq!(record.operation, operation);
        assert_eq!(record.path, recovering_path);
        assert!(!marker_called.get());
        assert_eq!(std::fs::read(&recovering_path).unwrap(), recovering_content);
        assert_eq!(std::fs::read(&pending_path).unwrap(), pending_content);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn dual_conflicting_storage_operation_journals_are_retained_and_durably_blocked() {
        let root = temp_storage_test_dir("dual-conflicting-journals");
        let pending_path = root.join("pending-storage-operation.json");
        let recovering_path = root.join("pending-storage-operation.recovering.json");
        let block_path = root.join("storage-recovery-blocked");
        let recovering_content =
            serde_json::to_vec_pretty(&account_config_save_pending_operation(true)).unwrap();
        let pending_content =
            serde_json::to_vec_pretty(&account_config_save_pending_operation(false)).unwrap();
        write_private_file_atomic(&recovering_path, "json.tmp", &recovering_content).unwrap();
        write_private_file_atomic(&pending_path, "json.tmp", &pending_content).unwrap();

        let error = load_pending_storage_operation_record_fail_closed_with_marker(
            &recovering_path,
            &pending_path,
            || mark_storage_recovery_blocked_at(&block_path),
        )
        .unwrap_err();

        assert!(error
            .downcast_ref::<PendingStorageRecoveryBlocked>()
            .is_some());
        assert_eq!(std::fs::read(&recovering_path).unwrap(), recovering_content);
        assert_eq!(std::fs::read(&pending_path).unwrap(), pending_content);
        assert_eq!(
            std::fs::read(&block_path).unwrap(),
            super::STORAGE_RECOVERY_BLOCK_CONTENT
        );
        assert!(is_pending_storage_operation_in_progress(
            &ensure_no_pending_storage_operation(&pending_path, &recovering_path).unwrap_err()
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn dual_storage_operation_journals_with_either_invalid_slot_are_retained_and_blocked() {
        for invalid_slot in ["recovering", "pending"] {
            let root = temp_storage_test_dir(&format!("dual-invalid-{invalid_slot}"));
            let pending_path = root.join("pending-storage-operation.json");
            let recovering_path = root.join("pending-storage-operation.recovering.json");
            let block_path = root.join("storage-recovery-blocked");
            let valid_content =
                serde_json::to_vec_pretty(&account_delete_pending_operation()).unwrap();
            let invalid_content = b"{\"version\":1,\"kind\":\"account_delete_committed\"";
            let recovering_content = if invalid_slot == "recovering" {
                invalid_content.as_slice()
            } else {
                valid_content.as_slice()
            };
            let pending_content = if invalid_slot == "pending" {
                invalid_content.as_slice()
            } else {
                valid_content.as_slice()
            };
            write_private_file_atomic(&recovering_path, "json.tmp", recovering_content).unwrap();
            write_private_file_atomic(&pending_path, "json.tmp", pending_content).unwrap();

            let error = load_pending_storage_operation_record_fail_closed_with_marker(
                &recovering_path,
                &pending_path,
                || mark_storage_recovery_blocked_at(&block_path),
            )
            .unwrap_err();

            assert!(error
                .downcast_ref::<PendingStorageRecoveryBlocked>()
                .is_some());
            assert_eq!(std::fs::read(&recovering_path).unwrap(), recovering_content);
            assert_eq!(std::fs::read(&pending_path).unwrap(), pending_content);
            assert_eq!(
                std::fs::read(&block_path).unwrap(),
                super::STORAGE_RECOVERY_BLOCK_CONTENT
            );
            assert!(is_pending_storage_operation_in_progress(
                &ensure_no_pending_storage_operation(&pending_path, &recovering_path).unwrap_err()
            ));
            let _ = std::fs::remove_dir_all(root);
        }
    }

    #[test]
    fn invalid_recovering_journal_blocks_older_valid_pending_journal() {
        let root = temp_storage_test_dir("recovering-dir-with-valid-pending");
        let pending_path = root.join("pending-storage-operation.json");
        let recovering_path = root.join("pending-storage-operation.recovering.json");
        let operation = account_delete_pending_operation();
        let content = serde_json::to_string_pretty(&operation).unwrap();
        write_private_file_atomic(&pending_path, "json.tmp", content.as_bytes()).unwrap();
        std::fs::create_dir(&recovering_path).unwrap();

        let error = load_pending_storage_operation_record_fail_closed_from_paths(
            &recovering_path,
            &pending_path,
        )
        .unwrap_err();

        assert!(error
            .downcast_ref::<PendingStorageRecoveryBlocked>()
            .is_some());
        assert!(pending_path.exists());
        assert!(recovering_path.is_dir());
        assert!(invalid_storage_operation_entries(
            &root,
            "pending-storage-operation.recovering.invalid."
        )
        .is_empty());
        assert!(is_pending_storage_operation_in_progress(
            &ensure_no_pending_storage_operation(&pending_path, &recovering_path).unwrap_err()
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn malformed_rollback_markers_remain_canonical_and_block_credential_mutations() {
        for (case, marker) in [
            ("invalid", "not-a-uuid"),
            ("noncanonical", "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"),
        ] {
            let root = temp_storage_test_dir(&format!("rollback-marker-{case}"));
            let pending_path = root.join("pending-storage-operation.json");
            let recovering_path = root.join("pending-storage-operation.recovering.json");
            let save_operation = account_config_save_pending_operation(true);
            let before_account = save_operation.before_account.unwrap();
            let rollback_operation = PendingStorageOperation {
                version: PENDING_STORAGE_OPERATION_VERSION,
                kind: "account_config_rollback".to_string(),
                account_ids: vec![before_account.id.clone()],
                from_use_keyring: false,
                to_use_keyring: false,
                use_keyring: true,
                before_account: Some(before_account),
                after_account: None,
                rollback_marker: Some(marker.to_string()),
            };
            let content = serde_json::to_vec_pretty(&rollback_operation).unwrap();
            write_private_file_atomic(&pending_path, "json.tmp", &content).unwrap();

            let error = load_pending_storage_operation_record_fail_closed_from_paths(
                &recovering_path,
                &pending_path,
            )
            .unwrap_err();

            assert!(error
                .downcast_ref::<PendingStorageRecoveryBlocked>()
                .is_some());
            assert_eq!(std::fs::read(&pending_path).unwrap(), content);
            assert!(
                invalid_storage_operation_entries(&root, "pending-storage-operation.invalid.")
                    .is_empty()
            );
            assert!(is_pending_storage_operation_in_progress(
                &ensure_no_pending_storage_operation(&pending_path, &recovering_path).unwrap_err()
            ));

            let second_error = load_pending_storage_operation_record_fail_closed_from_paths(
                &recovering_path,
                &pending_path,
            )
            .unwrap_err();
            assert!(second_error
                .downcast_ref::<PendingStorageRecoveryBlocked>()
                .is_some());
            assert_eq!(std::fs::read(&pending_path).unwrap(), content);
            let _ = std::fs::remove_dir_all(root);
        }
    }

    #[test]
    fn truncated_active_journal_remains_byte_exact_and_blocking() {
        let root = temp_storage_test_dir("truncated-active-journal");
        let pending_path = root.join("pending-storage-operation.json");
        let recovering_path = root.join("pending-storage-operation.recovering.json");
        let content = b"{\"version\":1,\"kind\":\"account_config_save\"";
        write_private_file_atomic(&pending_path, "json.tmp", content).unwrap();

        let error = load_pending_storage_operation_record_fail_closed_from_paths(
            &recovering_path,
            &pending_path,
        )
        .unwrap_err();

        assert!(error
            .downcast_ref::<PendingStorageRecoveryBlocked>()
            .is_some());
        assert_eq!(std::fs::read(&pending_path).unwrap(), content);
        assert!(is_pending_storage_operation_in_progress(
            &ensure_no_pending_storage_operation(&pending_path, &recovering_path).unwrap_err()
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn password_file_lookup_uses_exact_account_id_only() {
        let file = PasswordFile {
            passwords: HashMap::from([
                ("account-1".to_string(), "encrypted-one".to_string()),
                (
                    "user@example.com".to_string(),
                    "encrypted-email".to_string(),
                ),
            ]),
            ..PasswordFile::default()
        };

        assert_eq!(
            password_entry_for_account(&file, &"account-1".to_string()).unwrap(),
            "encrypted-one"
        );
        assert!(password_entry_for_account(&file, &"account".to_string()).is_err());
        assert!(password_entry_for_account(&file, &"USER@example.com".to_string()).is_err());
    }

    #[test]
    fn staged_fallback_recovery_deletes_only_crash_orphans() {
        let active_key = ScopedFallbackKeyRef {
            account_id: "active-account".to_string(),
            key_id: "00000000-0000-4000-8000-000000000001".to_string(),
        };
        let orphan_key = ScopedFallbackKeyRef {
            account_id: "orphan-account".to_string(),
            key_id: "00000000-0000-4000-8000-000000000002".to_string(),
        };
        let journal = StagedFallbackKeysJournal {
            version: STAGED_FALLBACK_KEYS_VERSION,
            keys: vec![active_key.clone(), orphan_key.clone()],
        };
        let deleted = RefCell::new(Vec::new());
        let saved = RefCell::new(None);

        reconcile_staged_fallback_keys_with_ops(
            journal,
            &std::collections::HashMap::from([(
                active_key.key_id.clone(),
                active_key.account_id.clone(),
            )]),
            |key_ref| {
                deleted.borrow_mut().push(key_ref.clone());
                Ok(())
            },
            |next| {
                *saved.borrow_mut() = Some(next.clone());
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(deleted.into_inner(), vec![orphan_key]);
        assert!(saved.into_inner().unwrap().keys.is_empty());
    }

    #[test]
    fn staged_fallback_recovery_never_deletes_an_active_key_id_with_mismatched_account() {
        let active_key_id = "00000000-0000-4000-8000-000000000004".to_string();
        let corrupt_staged_ref = ScopedFallbackKeyRef {
            account_id: "wrong-account".to_string(),
            key_id: active_key_id.clone(),
        };
        let journal = StagedFallbackKeysJournal {
            version: STAGED_FALLBACK_KEYS_VERSION,
            keys: vec![corrupt_staged_ref.clone()],
        };
        let delete_called = Cell::new(false);
        let saved = RefCell::new(None);

        let error = reconcile_staged_fallback_keys_with_ops(
            journal,
            &std::collections::HashMap::from([(active_key_id, "active-account".to_string())]),
            |_| {
                delete_called.set(true);
                Ok(())
            },
            |next| {
                *saved.borrow_mut() = Some(next.clone());
                Ok(())
            },
        )
        .unwrap_err();

        assert!(error.downcast_ref::<StagedFallbackKeyConflict>().is_some());
        assert!(!delete_called.get());
        assert_eq!(saved.into_inner().unwrap().keys, vec![corrupt_staged_ref]);
    }

    #[test]
    fn staged_fallback_recovery_keeps_failed_deletion_retryable() {
        let orphan_key = ScopedFallbackKeyRef {
            account_id: "orphan-account".to_string(),
            key_id: "00000000-0000-4000-8000-000000000003".to_string(),
        };
        let journal = StagedFallbackKeysJournal {
            version: STAGED_FALLBACK_KEYS_VERSION,
            keys: vec![orphan_key.clone()],
        };
        let saved = RefCell::new(None);

        let error = reconcile_staged_fallback_keys_with_ops(
            journal,
            &std::collections::HashMap::new(),
            |_| anyhow::bail!("credential store unavailable"),
            |next| {
                *saved.borrow_mut() = Some(next.clone());
                Ok(())
            },
        )
        .unwrap_err();

        assert!(error.to_string().contains("cleanup attempts failed"));
        assert_eq!(saved.into_inner().unwrap().keys, vec![orphan_key]);
    }

    #[test]
    fn staged_fallback_recovery_waits_until_pending_journal_absence_is_proven() {
        let reconcile_calls = Cell::new(0usize);
        reconcile_staged_fallback_keys_if_safe(
            || Ok(false),
            || {
                reconcile_calls.set(reconcile_calls.get() + 1);
                Ok(())
            },
            || panic!("a known pending journal must only defer staged-key recovery"),
        )
        .unwrap();
        assert_eq!(reconcile_calls.get(), 0);

        let reconcile_calls = Cell::new(0usize);
        reconcile_staged_fallback_keys_if_safe(
            || Ok(true),
            || {
                reconcile_calls.set(reconcile_calls.get() + 1);
                Ok(())
            },
            || Ok(()),
        )
        .unwrap();
        assert_eq!(reconcile_calls.get(), 1);
    }

    #[test]
    fn staged_fallback_preflight_fails_closed_when_journal_state_cannot_be_read() {
        let reconcile_calls = Cell::new(0usize);
        let latch_calls = Cell::new(0usize);

        let error = reconcile_staged_fallback_keys_if_safe(
            || anyhow::bail!("journal metadata unavailable"),
            || {
                reconcile_calls.set(reconcile_calls.get() + 1);
                Ok(())
            },
            || {
                latch_calls.set(latch_calls.get() + 1);
                Ok(())
            },
        )
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("journal state could not be verified"));
        assert_eq!(reconcile_calls.get(), 0);
        assert_eq!(latch_calls.get(), 1);
    }

    #[test]
    fn staged_fallback_conflict_latches_recovery_and_blocks_the_mutation() {
        let events = RefCell::new(Vec::new());

        let error = reconcile_staged_fallback_keys_if_safe(
            || Ok(true),
            || {
                events.borrow_mut().push("conflict");
                Err(anyhow::Error::new(StagedFallbackKeyConflict::new()))
            },
            || {
                events.borrow_mut().push("latch");
                Ok(())
            },
        )
        .unwrap_err();

        assert!(error.downcast_ref::<StagedFallbackKeyConflict>().is_some());
        assert_eq!(events.into_inner(), vec!["conflict", "latch"]);
    }

    #[test]
    fn ordinary_staged_orphan_cleanup_failure_remains_retryable_without_blocking_mutations() {
        let latch_called = Cell::new(false);

        reconcile_staged_fallback_keys_if_safe(
            || Ok(true),
            || anyhow::bail!("credential store temporarily unavailable"),
            || {
                latch_called.set(true);
                Ok(())
            },
        )
        .unwrap();

        assert!(!latch_called.get());
    }

    #[test]
    fn staged_fallback_conflict_still_latches_when_journal_save_fails() {
        let active_key_id = "00000000-0000-4000-8000-000000000005".to_string();
        let journal = StagedFallbackKeysJournal {
            version: STAGED_FALLBACK_KEYS_VERSION,
            keys: vec![ScopedFallbackKeyRef {
                account_id: "wrong-account".to_string(),
                key_id: active_key_id.clone(),
            }],
        };
        let reconcile_error = reconcile_staged_fallback_keys_with_ops(
            journal,
            &std::collections::HashMap::from([(active_key_id, "active-account".to_string())]),
            |_| panic!("an active fallback key must never be deleted"),
            |_| anyhow::bail!("journal storage unavailable"),
        )
        .unwrap_err();
        assert!(reconcile_error
            .chain()
            .any(|cause| cause.is::<StagedFallbackKeyConflict>()));

        let latch_called = Cell::new(false);
        let mut reconcile_error = Some(reconcile_error);
        let error = reconcile_staged_fallback_keys_if_safe(
            || Ok(true),
            || Err(reconcile_error.take().unwrap()),
            || {
                latch_called.set(true);
                Ok(())
            },
        )
        .unwrap_err();

        assert!(error
            .chain()
            .any(|cause| cause.is::<StagedFallbackKeyConflict>()));
        assert!(latch_called.get());
    }

    #[test]
    fn pending_journal_is_not_created_when_staged_key_preflight_fails() {
        let operation = PendingStorageOperation {
            version: PENDING_STORAGE_OPERATION_VERSION,
            kind: "storage_mode_migration".to_string(),
            account_ids: Vec::new(),
            from_use_keyring: true,
            to_use_keyring: false,
            use_keyring: false,
            before_account: None,
            after_account: None,
            rollback_marker: None,
        };
        let save_called = Cell::new(false);

        let error = save_pending_storage_operation_with_preflight_ops(
            &operation,
            || Ok(()),
            || Err(anyhow::Error::new(StagedFallbackKeyConflict::new())),
            |_| {
                save_called.set(true);
                Ok(())
            },
        )
        .unwrap_err();

        assert!(error.downcast_ref::<StagedFallbackKeyConflict>().is_some());
        assert!(!save_called.get());
    }

    #[test]
    fn direct_keyring_provider_is_not_called_when_staged_key_preflight_fails() {
        let provider_called = Cell::new(false);

        let error = direct_password_write_after_preflight_with_ops(
            zeroize::Zeroizing::new("secret".to_string()),
            true,
            || Ok(()),
            || Err(anyhow::Error::new(StagedFallbackKeyConflict::new())),
            |_| {
                provider_called.set(true);
                Ok(())
            },
        )
        .unwrap_err();

        assert!(error.downcast_ref::<StagedFallbackKeyConflict>().is_some());
        assert!(!provider_called.get());
    }

    #[test]
    fn password_transaction_temp_cleanup_is_prefix_bounded() {
        let root = temp_storage_test_dir("password-transaction-temp-cleanup");
        let password_temp = root.join("passwords.json.tmp.123.456");
        let journal_temp = root.join("staged-fallback-keys.json.tmp.123.456");
        let unrelated = root.join("passwords.json.backup");
        std::fs::write(&password_temp, "ciphertext").unwrap();
        std::fs::write(&journal_temp, "metadata").unwrap();
        std::fs::write(&unrelated, "keep").unwrap();

        let cleaned =
            cleanup_storage_temp_files_in_dir(&root, PASSWORD_TRANSACTION_TEMP_FILE_PREFIXES)
                .unwrap();

        assert_eq!(cleaned, 2);
        assert!(!password_temp.exists());
        assert!(!journal_temp.exists());
        assert!(unrelated.exists());
        let _ = std::fs::remove_dir_all(root);
    }

    fn temp_storage_test_dir(name: &str) -> std::path::PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "waal-storage-{name}-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    fn account_config_save_pending_operation(use_keyring: bool) -> PendingStorageOperation {
        let mut before_account = Account::new("old@example.com");
        before_account.id = "account-1".to_string();
        before_account.has_saved_password = true;

        let mut after_account = before_account.clone();
        after_account.username = "user@example.com".to_string();

        PendingStorageOperation {
            version: PENDING_STORAGE_OPERATION_VERSION,
            kind: "account_config_save".to_string(),
            account_ids: vec![after_account.id.clone()],
            from_use_keyring: use_keyring,
            to_use_keyring: use_keyring,
            use_keyring,
            before_account: Some(before_account),
            after_account: Some(after_account),
            rollback_marker: None,
        }
    }

    fn account_delete_pending_operation() -> PendingStorageOperation {
        let mut account = Account::new("user@example.com");
        account.id = "account-1".to_string();
        account.has_saved_password = true;
        PendingStorageOperation {
            version: PENDING_STORAGE_OPERATION_VERSION,
            kind: "account_delete_committed".to_string(),
            account_ids: vec![account.id.clone()],
            from_use_keyring: false,
            to_use_keyring: false,
            use_keyring: true,
            before_account: Some(account),
            after_account: None,
            rollback_marker: None,
        }
    }

    fn account_delete_prepared_operation() -> PendingStorageOperation {
        let mut operation = account_delete_pending_operation();
        operation.kind = "account_delete_prepared".to_string();
        operation
    }

    fn account_enabled_toggle_operation(
        before_enabled: bool,
        kind: &str,
    ) -> PendingStorageOperation {
        let mut before_account = Account::new("user@example.com");
        before_account.id = "account-1".to_string();
        before_account.enabled = before_enabled;
        before_account.has_saved_password = true;
        let mut after_account = before_account.clone();
        after_account.enabled = !before_enabled;
        PendingStorageOperation {
            version: PENDING_STORAGE_OPERATION_VERSION,
            kind: kind.to_string(),
            account_ids: vec![before_account.id.clone()],
            from_use_keyring: false,
            to_use_keyring: false,
            use_keyring: true,
            before_account: Some(before_account),
            after_account: Some(after_account),
            rollback_marker: None,
        }
    }

    fn invalid_storage_operation_entries(
        root: &std::path::Path,
        file_name_prefix: &str,
    ) -> Vec<std::path::PathBuf> {
        std::fs::read_dir(root)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(file_name_prefix))
            })
            .collect()
    }

    #[test]
    fn invalid_config_quarantine_preserves_exact_metadata_privately() {
        let root = temp_storage_test_dir("invalid-config-backup-redacted");
        let config_path = root.join("config.json");
        let original = r#"{
  "accounts": [
    {
      "id": "account-secret-id",
      "username": "user@example.com",
      "has_saved_password": "invalid-bool",
      "enabled": true
    }
  ],
  "settings": {
    "auto_start": true
  }
}"#;
        write_test_private_text(&config_path, original);

        backup_invalid_config_file(
            &config_path,
            &anyhow::anyhow!("schema failed for user@example.com account-secret-id"),
        )
        .unwrap();

        assert!(!config_path.exists());
        let backups = invalid_storage_operation_entries(&root, "config.json.invalid.");
        assert_eq!(backups.len(), 2);
        let quarantine = backups
            .iter()
            .find(|path| !path.to_string_lossy().ends_with(".diagnostic.json"))
            .unwrap();
        let diagnostic_path = backups
            .iter()
            .find(|path| path.to_string_lossy().ends_with(".diagnostic.json"))
            .unwrap();
        assert_eq!(std::fs::read_to_string(quarantine).unwrap(), original);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(quarantine).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        let backup = std::fs::read_to_string(diagnostic_path).unwrap();
        assert!(!backup.contains("user@example.com"));
        assert!(!backup.contains("account-secret-id"));
        assert!(!backup.contains("has_saved_password"));
        assert!(!backup.contains("invalid-bool"));

        let diagnostic: serde_json::Value = serde_json::from_str(&backup).unwrap();
        assert_eq!(diagnostic["kind"], "invalid_config_diagnostic");
        assert_eq!(diagnostic["raw_content"], "[omitted]");
        assert_eq!(diagnostic["json_parse_status"], "parsed");
        assert_eq!(diagnostic["has_accounts"], true);
        assert_eq!(diagnostic["account_count"], 1);
        assert_eq!(diagnostic["has_settings"], true);
        assert_eq!(
            diagnostic["original_sha256"],
            sha256_hex(original.as_bytes())
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn malformed_invalid_config_quarantine_preserves_raw_content_but_redacts_diagnostic() {
        let root = temp_storage_test_dir("malformed-config-backup-redacted");
        let config_path = root.join("config.json");
        let original = r#"{"accounts":[{"id":"account-secret-id","username":"user@example.com"}],"#;
        write_test_private_text(&config_path, original);

        backup_invalid_config_file(
            &config_path,
            &anyhow::anyhow!("parse failed for user@example.com account-secret-id"),
        )
        .unwrap();

        assert!(!config_path.exists());
        let backups = invalid_storage_operation_entries(&root, "config.json.invalid.");
        assert_eq!(backups.len(), 2);
        let quarantine = backups
            .iter()
            .find(|path| !path.to_string_lossy().ends_with(".diagnostic.json"))
            .unwrap();
        let diagnostic_path = backups
            .iter()
            .find(|path| path.to_string_lossy().ends_with(".diagnostic.json"))
            .unwrap();
        assert_eq!(std::fs::read_to_string(quarantine).unwrap(), original);
        let backup = std::fs::read_to_string(diagnostic_path).unwrap();
        assert!(!backup.contains("user@example.com"));
        assert!(!backup.contains("account-secret-id"));
        assert!(!backup.contains(original));

        let diagnostic: serde_json::Value = serde_json::from_str(&backup).unwrap();
        assert_eq!(diagnostic["kind"], "invalid_config_diagnostic");
        assert_eq!(diagnostic["raw_content"], "[omitted]");
        assert_eq!(diagnostic["json_parse_status"], "invalid_json");
        assert_eq!(diagnostic["has_accounts"], false);
        assert_eq!(diagnostic["has_settings"], false);
        assert_eq!(
            diagnostic["original_sha256"],
            sha256_hex(original.as_bytes())
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn app_config_serialization_does_not_contain_plaintext_password() {
        let mut account = Account::new(" user@example.com ");
        account.id = "account-1".to_string();
        account.has_saved_password = true;

        let config = AppConfig {
            accounts: vec![account],
            ..AppConfig::default()
        };
        let serialized = serde_json::to_string(&config).unwrap();

        assert!(!serialized.contains("super-secret-password"));
        assert!(!serialized.contains("temp_password"));
        assert!(serialized.contains("has_saved_password"));
    }

    #[test]
    fn bound_password_rejects_account_metadata_mismatch() {
        let mut account = Account::new(" User@Example.com ");
        account.id = "account-1".to_string();

        let encoded = encode_bound_password(&account, "super-secret-password").unwrap();
        let (decoded, format) = decode_bound_password(&account, &encoded).unwrap();

        assert_eq!(decoded.as_str(), "super-secret-password");
        assert_eq!(format, StoredPasswordFormat::BoundV1);

        let mut renamed = account.clone();
        renamed.username = "other@example.com".to_string();
        assert!(decode_bound_password(&renamed, &encoded).is_err());

        let mut different_id = account.clone();
        different_id.id = "account-2".to_string();
        assert!(decode_bound_password(&different_id, &encoded).is_err());
    }

    #[test]
    fn rollback_marker_is_authenticated_inside_the_password_envelope() {
        let mut account = Account::new("user@example.com");
        account.id = "account-1".to_string();
        let marker = "11111111-1111-4111-8111-111111111111";

        let encoded =
            encode_bound_password_with_rollback_marker(&account, "previous-secret", Some(marker))
                .unwrap();
        let (password, format, decoded_marker) =
            decode_bound_password_with_rollback_marker(&account, encoded.as_str()).unwrap();

        assert_eq!(password.as_str(), "previous-secret");
        assert_eq!(format, StoredPasswordFormat::BoundV1);
        assert_eq!(decoded_marker.as_deref(), Some(marker));
        assert!(encode_bound_password_with_rollback_marker(
            &account,
            "previous-secret",
            Some("not-a-marker")
        )
        .is_err());
    }

    #[test]
    fn windows_user_bound_entropy_is_stable_and_purpose_bound() {
        assert_eq!(WINDOWS_USER_BOUND_SECRET_PREFIX, "waub:");
        assert_eq!(WINDOWS_LEGACY_WAAB_SECRET_PREFIX, "waab:");
        assert_eq!(
            super::windows_user_bound_entropy(SECURE_STORAGE_PASSWORD_PURPOSE),
            super::windows_user_bound_entropy(SECURE_STORAGE_PASSWORD_PURPOSE)
        );
        assert_ne!(
            super::windows_user_bound_entropy(SECURE_STORAGE_PASSWORD_PURPOSE),
            super::windows_user_bound_entropy(SECURE_STORAGE_FALLBACK_KEY_PURPOSE)
        );
        assert_ne!(
            super::windows_user_bound_entropy(SECURE_STORAGE_PASSWORD_PURPOSE),
            super::windows_legacy_waab_entropy(SECURE_STORAGE_PASSWORD_PURPOSE)
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_secure_storage_secret_is_user_bound() {
        let encoded =
            encode_secure_storage_secret(SECURE_STORAGE_PASSWORD_PURPOSE, "super-secret-password")
                .unwrap();

        assert!(encoded.starts_with(WINDOWS_USER_BOUND_SECRET_PREFIX));
        assert!(!encoded.contains("super-secret-password"));

        let decoded =
            decode_secure_storage_secret(SECURE_STORAGE_PASSWORD_PURPOSE, encoded.as_str())
                .unwrap();
        assert_eq!(decoded.plaintext.as_str(), "super-secret-password");
        assert!(!decoded.needs_migration);
        assert!(decode_secure_storage_secret(
            SECURE_STORAGE_FALLBACK_KEY_PURPOSE,
            encoded.as_str()
        )
        .is_err());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn legacy_windows_waab_secret_decodes_and_requests_migration() {
        let protected = super::windows_protect_data_with_entropy(
            b"legacy-secret",
            &super::windows_legacy_waab_entropy(SECURE_STORAGE_PASSWORD_PURPOSE),
        )
        .unwrap();
        let encoded = format!(
            "{}{}",
            WINDOWS_LEGACY_WAAB_SECRET_PREFIX,
            STANDARD.encode(&*protected)
        );

        let decoded =
            decode_secure_storage_secret(SECURE_STORAGE_PASSWORD_PURPOSE, encoded.as_str())
                .unwrap();
        assert_eq!(decoded.plaintext.as_str(), "legacy-secret");
        assert!(decoded.needs_migration);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn reserved_windows_bound_prefixes_fail_closed() {
        for stored in ["waub2:future", "waubfuture", "waab2:future", "waabfuture"] {
            assert!(
                decode_secure_storage_secret(SECURE_STORAGE_PASSWORD_PURPOSE, stored).is_err(),
                "{stored} should not fall back to legacy plaintext"
            );
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn keyring_password_payload_hides_bound_envelope_and_decodes_legacy_plaintext() {
        let mut account = Account::new(" User@Example.com ");
        account.id = "account-1".to_string();

        let encoded = encode_keyring_password(&account, "super-secret-password").unwrap();
        assert!(encoded.starts_with(WINDOWS_USER_BOUND_SECRET_PREFIX));
        assert!(!encoded.contains("super-secret-password"));
        assert!(!encoded.contains(PASSWORD_ENVELOPE_PREFIX));

        let (decoded, format, needs_migration, rollback_marker) =
            decode_keyring_password(&account, encoded.as_str()).unwrap();
        assert_eq!(decoded.as_str(), "super-secret-password");
        assert_eq!(format, StoredPasswordFormat::BoundV1);
        assert!(!needs_migration);
        assert!(rollback_marker.is_none());

        let (legacy_decoded, legacy_format, legacy_needs_migration, rollback_marker) =
            decode_keyring_password(&account, "legacy-secret").unwrap();
        assert_eq!(legacy_decoded.as_str(), "legacy-secret");
        assert_eq!(legacy_format, StoredPasswordFormat::LegacyRaw);
        assert!(legacy_needs_migration);
        assert!(rollback_marker.is_none());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn fallback_key_payload_is_user_bound() {
        let encoded_key = STANDARD.encode([7u8; 32]);
        let protected =
            encode_secure_storage_secret(SECURE_STORAGE_FALLBACK_KEY_PURPOSE, &encoded_key)
                .unwrap();

        assert!(protected.starts_with(WINDOWS_USER_BOUND_SECRET_PREFIX));
        assert!(!protected.contains(&encoded_key));

        let decoded =
            decode_secure_storage_secret(SECURE_STORAGE_FALLBACK_KEY_PURPOSE, protected.as_str())
                .unwrap();
        let key = decode_fallback_encryption_key(decoded.plaintext.trim()).unwrap();

        assert_eq!(*key, [7u8; 32]);
        assert!(!decoded.needs_migration);
    }

    #[test]
    fn encrypted_password_rejects_ciphertext_without_auth_tag() {
        let key = [0u8; 32];
        let truncated = vec![0u8; AES_GCM_NONCE_BYTES + AES_GCM_TAG_BYTES - 1];

        assert!(decrypt_password_with_key(&key, &truncated).is_err());
    }

    #[test]
    fn scoped_fallback_update_and_delete_retire_each_password_revision_key() {
        let account_id = "account-1".to_string();
        let first_key = ScopedFallbackKeyRef {
            account_id: account_id.clone(),
            key_id: "11111111-1111-4111-8111-111111111111".to_string(),
        };
        let second_key = ScopedFallbackKeyRef {
            account_id: account_id.clone(),
            key_id: "22222222-2222-4222-8222-222222222222".to_string(),
        };
        let mut file = PasswordFile::default();

        install_scoped_fallback_entry(
            &mut file,
            &account_id,
            &first_key,
            "first-ciphertext".to_string(),
        );
        install_scoped_fallback_entry(
            &mut file,
            &account_id,
            &second_key,
            "second-ciphertext".to_string(),
        );

        assert_eq!(file.key_ids.get(&account_id), Some(&second_key.key_id));
        assert_eq!(file.retired_keys, vec![first_key.clone()]);
        validate_password_file_shape(&file).unwrap();

        assert!(remove_fallback_entry(&mut file, &account_id));
        assert!(file.passwords.is_empty());
        assert!(file.key_ids.is_empty());
        assert_eq!(file.retired_keys, vec![first_key, second_key]);
        validate_password_file_shape(&file).unwrap();
    }

    #[test]
    fn rotated_fallback_key_cannot_decrypt_a_prior_password_revision() {
        let prior_key = [7u8; 32];
        let next_key = [9u8; 32];
        let prior_ciphertext =
            encrypt_password_with_key(&prior_key, "previous-password-envelope").unwrap();
        let next_ciphertext =
            encrypt_password_with_key(&next_key, "current-password-envelope").unwrap();

        assert_eq!(
            decrypt_password_with_fallback_key(&prior_key, &prior_ciphertext)
                .unwrap()
                .as_str(),
            "previous-password-envelope"
        );
        assert!(decrypt_password_with_fallback_key(&next_key, &prior_ciphertext).is_err());
        assert_eq!(
            decrypt_password_with_fallback_key(&next_key, &next_ciphertext)
                .unwrap()
                .as_str(),
            "current-password-envelope"
        );
    }

    #[test]
    fn legacy_password_file_schema_loads_without_scoped_key_metadata() {
        let file: PasswordFile =
            serde_json::from_str(r#"{"passwords":{"account-1":"legacy-ciphertext"}}"#).unwrap();

        assert_eq!(
            file.passwords.get("account-1").map(String::as_str),
            Some("legacy-ciphertext")
        );
        assert!(file.key_ids.is_empty());
        assert!(file.retired_keys.is_empty());
        assert!(!file.retire_legacy_shared_key);
        validate_password_file_shape(&file).unwrap();
    }

    #[test]
    fn password_file_shape_rejects_malformed_or_ambiguous_scoped_key_metadata() {
        let account_1 = "account-1".to_string();
        let account_2 = "account-2".to_string();
        let key_1 = "11111111-1111-4111-8111-111111111111".to_string();
        let key_2 = "22222222-2222-4222-8222-222222222222".to_string();
        let passwords = HashMap::from([
            (account_1.clone(), "ciphertext-1".to_string()),
            (account_2.clone(), "ciphertext-2".to_string()),
        ]);

        let invalid_files = [
            PasswordFile {
                passwords: HashMap::from([(account_1.clone(), "ciphertext".to_string())]),
                key_ids: HashMap::from([(account_1.clone(), "not-a-key-id".to_string())]),
                ..PasswordFile::default()
            },
            PasswordFile {
                key_ids: HashMap::from([(account_1.clone(), key_1.clone())]),
                ..PasswordFile::default()
            },
            PasswordFile {
                passwords: passwords.clone(),
                key_ids: HashMap::from([
                    (account_1.clone(), key_1.clone()),
                    (account_2.clone(), key_1.clone()),
                ]),
                ..PasswordFile::default()
            },
            PasswordFile {
                passwords: HashMap::from([(account_1.clone(), "ciphertext".to_string())]),
                key_ids: HashMap::from([(account_1.clone(), key_1.clone())]),
                retired_keys: vec![ScopedFallbackKeyRef {
                    account_id: account_2.clone(),
                    key_id: key_1.clone(),
                }],
                ..PasswordFile::default()
            },
            PasswordFile {
                retired_keys: vec![
                    ScopedFallbackKeyRef {
                        account_id: account_1.clone(),
                        key_id: key_2.clone(),
                    },
                    ScopedFallbackKeyRef {
                        account_id: account_2.clone(),
                        key_id: key_2.clone(),
                    },
                ],
                ..PasswordFile::default()
            },
            PasswordFile {
                passwords: HashMap::from([(account_1.clone(), "legacy-ciphertext".to_string())]),
                retire_legacy_shared_key: true,
                ..PasswordFile::default()
            },
        ];

        for file in invalid_files {
            assert!(validate_password_file_shape(&file).is_err());
        }
    }

    #[test]
    fn legacy_shared_key_migration_preserves_every_password_entry() {
        let shared_key = [3u8; 32];
        let account_ids = vec!["account-1".to_string(), "account-2".to_string()];
        let plaintexts = HashMap::from([
            (account_ids[0].clone(), "first-bound-envelope".to_string()),
            (account_ids[1].clone(), "second-bound-envelope".to_string()),
        ]);
        let scoped_keys = HashMap::from([
            (account_ids[0].clone(), [7u8; 32]),
            (account_ids[1].clone(), [9u8; 32]),
        ]);
        let scoped_key_ids = HashMap::from([
            (
                account_ids[0].clone(),
                "11111111-1111-4111-8111-111111111111".to_string(),
            ),
            (
                account_ids[1].clone(),
                "22222222-2222-4222-8222-222222222222".to_string(),
            ),
        ]);
        let mut file = PasswordFile {
            passwords: plaintexts
                .iter()
                .map(|(account_id, plaintext)| {
                    (
                        account_id.clone(),
                        encrypt_password_with_key(&shared_key, plaintext).unwrap(),
                    )
                })
                .collect(),
            ..PasswordFile::default()
        };

        let staged = migrate_legacy_fallback_entries_with_ops(
            &mut file,
            &account_ids,
            || Ok(Zeroizing::new(shared_key)),
            |account_id, plaintext| {
                assert_eq!(plaintext.as_str(), plaintexts[account_id]);
                let key = scoped_keys[account_id];
                let key_ref = ScopedFallbackKeyRef {
                    account_id: account_id.clone(),
                    key_id: scoped_key_ids[account_id].clone(),
                };
                Ok((
                    key_ref,
                    encrypt_password_with_key(&key, plaintext.as_str()).unwrap(),
                ))
            },
            |_| panic!("successful migration must not clean staged keys"),
        )
        .unwrap();

        assert_eq!(staged.len(), account_ids.len());
        assert!(file.retire_legacy_shared_key);
        for account_id in &account_ids {
            assert_eq!(file.key_ids[account_id], scoped_key_ids[account_id]);
            assert_eq!(
                decrypt_password_with_fallback_key(
                    &scoped_keys[account_id],
                    &file.passwords[account_id],
                )
                .unwrap()
                .as_str(),
                plaintexts[account_id]
            );
        }
        validate_password_file_shape(&file).unwrap();
    }

    #[test]
    fn failed_legacy_migration_cleans_staged_keys_without_mutating_password_metadata() {
        let shared_key = [3u8; 32];
        let account_ids = vec!["account-1".to_string(), "account-2".to_string()];
        let mut file = PasswordFile {
            passwords: HashMap::from([
                (
                    account_ids[0].clone(),
                    encrypt_password_with_key(&shared_key, "first").unwrap(),
                ),
                (
                    account_ids[1].clone(),
                    encrypt_password_with_key(&shared_key, "second").unwrap(),
                ),
            ]),
            ..PasswordFile::default()
        };
        let original = file.clone();
        let stage_count = Cell::new(0usize);
        let cleaned = RefCell::new(Vec::new());
        let first_key = ScopedFallbackKeyRef {
            account_id: account_ids[0].clone(),
            key_id: "11111111-1111-4111-8111-111111111111".to_string(),
        };

        let result = migrate_legacy_fallback_entries_with_ops(
            &mut file,
            &account_ids,
            || Ok(Zeroizing::new(shared_key)),
            |account_id, plaintext| {
                let count = stage_count.get();
                stage_count.set(count + 1);
                if count == 1 {
                    anyhow::bail!("second scoped key save failed");
                }
                assert_eq!(account_id, &account_ids[0]);
                Ok((
                    first_key.clone(),
                    encrypt_password_with_key(&[7u8; 32], plaintext.as_str()).unwrap(),
                ))
            },
            |keys| cleaned.borrow_mut().extend_from_slice(keys),
        );

        assert!(result.is_err());
        assert_eq!(stage_count.get(), 2);
        assert_eq!(&*cleaned.borrow(), &[first_key]);
        assert_eq!(file.passwords, original.passwords);
        assert_eq!(file.key_ids, original.key_ids);
        assert!(!file.retire_legacy_shared_key);
    }

    #[test]
    fn rotated_fallback_save_stages_keys_before_commit_and_cleans_only_new_keys_on_failure() {
        let account_id = "account-1".to_string();
        let legacy_account_id = "account-2".to_string();
        let old_key = ScopedFallbackKeyRef {
            account_id: account_id.clone(),
            key_id: "11111111-1111-4111-8111-111111111111".to_string(),
        };
        let new_key = ScopedFallbackKeyRef {
            account_id: account_id.clone(),
            key_id: "22222222-2222-4222-8222-222222222222".to_string(),
        };
        let migrated_key = ScopedFallbackKeyRef {
            account_id: legacy_account_id.clone(),
            key_id: "33333333-3333-4333-8333-333333333333".to_string(),
        };
        let pending_retirement = ScopedFallbackKeyRef {
            account_id: "already-retired".to_string(),
            key_id: "44444444-4444-4444-8444-444444444444".to_string(),
        };
        let mut file = PasswordFile {
            passwords: HashMap::from([
                (account_id.clone(), "old-ciphertext".to_string()),
                (legacy_account_id.clone(), "legacy-ciphertext".to_string()),
            ]),
            key_ids: HashMap::from([(account_id.clone(), old_key.key_id.clone())]),
            retired_keys: vec![pending_retirement.clone()],
            ..PasswordFile::default()
        };
        let committed_file = RefCell::new(file.clone());
        let events = RefCell::new(Vec::<&'static str>::new());
        let cleaned = RefCell::new(Vec::new());
        let mut account = Account::new("user@example.com");
        account.id = account_id.clone();

        let payload = encode_bound_password(&account, "new-password").unwrap();
        let result = stage_and_commit_fallback_payload_with_ops(
            &mut file,
            &account,
            payload,
            |received_account_id, plaintext| {
                events.borrow_mut().push("stage-active-key");
                assert_eq!(received_account_id, &account_id);
                assert!(!plaintext.is_empty());
                Ok((new_key.clone(), "new-ciphertext".to_string()))
            },
            |candidate| {
                events.borrow_mut().push("stage-legacy-keys");
                candidate
                    .passwords
                    .insert(legacy_account_id.clone(), "migrated-ciphertext".to_string());
                candidate
                    .key_ids
                    .insert(legacy_account_id.clone(), migrated_key.key_id.clone());
                candidate.retire_legacy_shared_key = true;
                Ok(vec![migrated_key.clone()])
            },
            |candidate| {
                events.borrow_mut().push("commit-password-file");
                assert_eq!(candidate.key_ids[&account_id], new_key.key_id);
                assert!(candidate.retired_keys.contains(&old_key));
                anyhow::bail!("atomic password file commit failed")
            },
            |keys| {
                events.borrow_mut().push("cleanup-staged-keys");
                cleaned.borrow_mut().extend_from_slice(keys);
            },
        );

        assert!(result.is_err());
        assert_eq!(
            &*events.borrow(),
            &[
                "stage-active-key",
                "stage-legacy-keys",
                "commit-password-file",
                "cleanup-staged-keys",
            ]
        );
        assert_eq!(&*cleaned.borrow(), &[new_key, migrated_key]);
        assert!(!cleaned.borrow().contains(&old_key));
        assert!(!cleaned.borrow().contains(&pending_retirement));
        assert_eq!(committed_file.borrow().key_ids[&account_id], old_key.key_id);
        assert_eq!(
            committed_file.borrow().passwords[&account_id],
            "old-ciphertext"
        );
    }

    #[test]
    fn committed_password_file_error_never_deletes_keys_referenced_by_the_new_file() {
        let key_ref = ScopedFallbackKeyRef {
            account_id: "account-1".to_string(),
            key_id: "11111111-1111-4111-8111-111111111111".to_string(),
        };
        let file = PasswordFile {
            passwords: HashMap::from([(key_ref.account_id.clone(), "new-ciphertext".to_string())]),
            key_ids: HashMap::from([(key_ref.account_id.clone(), key_ref.key_id.clone())]),
            ..PasswordFile::default()
        };
        let cleanup_calls = Cell::new(0usize);
        let untrack_calls = Cell::new(0usize);

        let durability_warning = commit_password_file_with_staged_keys_with_ops(
            &file,
            std::slice::from_ref(&key_ref),
            |_| {
                Err(anyhow::Error::new(PasswordFileWriteCommitted {
                    source: anyhow::anyhow!("permission verification failed after rename"),
                }))
            },
            |_| cleanup_calls.set(cleanup_calls.get() + 1),
            |_| {
                untrack_calls.set(untrack_calls.get() + 1);
                Ok(())
            },
        )
        .unwrap();

        assert!(durability_warning);
        assert_eq!(cleanup_calls.get(), 0);
        assert_eq!(untrack_calls.get(), 0);
    }

    #[test]
    fn committed_password_file_keeps_active_key_when_journal_cleanup_fails() {
        let key_ref = ScopedFallbackKeyRef {
            account_id: "account-1".to_string(),
            key_id: "11111111-1111-4111-8111-111111111111".to_string(),
        };
        let file = PasswordFile {
            passwords: HashMap::from([(key_ref.account_id.clone(), "new-ciphertext".to_string())]),
            key_ids: HashMap::from([(key_ref.account_id.clone(), key_ref.key_id.clone())]),
            ..PasswordFile::default()
        };
        let cleanup_calls = Cell::new(0usize);
        let untrack_calls = Cell::new(0usize);

        let durability_warning = commit_password_file_with_staged_keys_with_ops(
            &file,
            std::slice::from_ref(&key_ref),
            |_| Ok(()),
            |_| cleanup_calls.set(cleanup_calls.get() + 1),
            |_| {
                untrack_calls.set(untrack_calls.get() + 1);
                anyhow::bail!("journal durability unavailable")
            },
        )
        .unwrap();

        assert!(durability_warning);
        assert_eq!(cleanup_calls.get(), 0);
        assert_eq!(untrack_calls.get(), 1);
        assert_eq!(
            active_scoped_fallback_keys_by_id(&file),
            std::collections::HashMap::from([(key_ref.key_id, key_ref.account_id)])
        );
    }

    #[test]
    fn failed_retired_key_cleanup_keeps_retry_metadata_until_success() {
        let first = ScopedFallbackKeyRef {
            account_id: "account-1".to_string(),
            key_id: "11111111-1111-4111-8111-111111111111".to_string(),
        };
        let second = ScopedFallbackKeyRef {
            account_id: "account-2".to_string(),
            key_id: "22222222-2222-4222-8222-222222222222".to_string(),
        };
        let mut file = PasswordFile {
            retired_keys: vec![first.clone(), second.clone()],
            retire_legacy_shared_key: true,
            ..PasswordFile::default()
        };
        let attempts = RefCell::new(HashMap::<String, usize>::new());

        let first_result = cleanup_retired_fallback_keys_with_ops(
            &mut file,
            |key_ref| {
                *attempts
                    .borrow_mut()
                    .entry(key_ref.key_id.clone())
                    .or_default() += 1;
                if key_ref == &first {
                    anyhow::bail!("transient scoped key delete failure");
                }
                Ok(())
            },
            || anyhow::bail!("transient shared key delete failure"),
        );

        assert!(first_result.is_err());
        assert_eq!(file.retired_keys, vec![first.clone()]);
        assert!(file.retire_legacy_shared_key);

        let second_result = cleanup_retired_fallback_keys_with_ops(
            &mut file,
            |key_ref| {
                *attempts
                    .borrow_mut()
                    .entry(key_ref.key_id.clone())
                    .or_default() += 1;
                Ok(())
            },
            || Ok(()),
        );

        assert!(second_result.unwrap());
        assert!(file.retired_keys.is_empty());
        assert!(!file.retire_legacy_shared_key);
        assert_eq!(attempts.borrow()[&first.key_id], 2);
        assert_eq!(attempts.borrow()[&second.key_id], 1);
    }

    #[test]
    fn stale_backend_cleanup_failure_after_save_returns_warning() {
        let account_id = "account-1".to_string();

        for (saved_backend, stale_backend, expected_kind) in [
            (
                PasswordStorageBackend::SystemSecureStorage,
                PasswordStorageBackend::EncryptedFallbackFile,
                "storage_error",
            ),
            (
                PasswordStorageBackend::EncryptedFallbackFile,
                PasswordStorageBackend::SystemSecureStorage,
                "secure_storage_unavailable",
            ),
        ] {
            let warning = cleanup_stale_backend_after_successful_save(
                &account_id,
                saved_backend,
                true,
                |id| {
                    assert_eq!(id, "account-1");
                    if saved_backend == PasswordStorageBackend::SystemSecureStorage {
                        anyhow::bail!("fallback delete failed");
                    }
                    panic!("fallback cleanup should not run after fallback save");
                },
                |id| {
                    assert_eq!(id, "account-1");
                    if saved_backend == PasswordStorageBackend::EncryptedFallbackFile {
                        anyhow::bail!("keyring delete failed");
                    }
                    panic!("keyring cleanup should not run after keyring save");
                },
            )
            .unwrap();

            assert_eq!(warning.saved_backend, saved_backend);
            assert_eq!(warning.stale_backend, stale_backend);
            assert_eq!(warning.error_kind, expected_kind);
        }
    }

    #[test]
    fn stale_backend_cleanup_disabled_skips_delete_ops() {
        let account_id = "account-1".to_string();

        let warning = cleanup_stale_backend_after_successful_save(
            &account_id,
            PasswordStorageBackend::SystemSecureStorage,
            false,
            |_| panic!("fallback cleanup should be skipped"),
            |_| panic!("keyring cleanup should be skipped"),
        );

        assert!(warning.is_none());
    }

    #[test]
    fn unconfirmed_target_durability_preserves_stale_backend() {
        let receipt = PasswordWriteReceipt {
            saved_backend: PasswordStorageBackend::EncryptedFallbackFile,
            target_durability_warning: true,
            fallback_key_cleanup_warning: false,
        };

        let outcome = finish_account_password_write_with_ops(
            &"account-1".to_string(),
            receipt,
            |_| panic!("fallback target must not delete itself"),
            |_| panic!("stale keyring must survive until target durability is confirmed"),
        );

        assert!(outcome.stale_cleanup_warning.is_none());
        assert!(outcome.target_durability_warning);
        assert!(!outcome.fallback_key_cleanup_warning);
    }

    #[test]
    fn backend_cleanup_attempts_all_accounts_after_partial_failure() {
        let account_ids = vec![
            "account-1".to_string(),
            "account-2".to_string(),
            "account-3".to_string(),
        ];
        for (use_keyring, failing_account, expected_error) in [
            (
                true,
                "account-1",
                "stale system secure storage cleanup incomplete",
            ),
            (
                false,
                "account-2",
                "stale encrypted fallback file cleanup incomplete",
            ),
        ] {
            let attempted = RefCell::new(Vec::new());
            let fallback_key_cleanup_calls = RefCell::new(0);

            let error = cleanup_storage_backend_with_ops(
                &account_ids,
                use_keyring,
                |account_id| {
                    if use_keyring {
                        panic!("fallback cleanup should not run for keyring backend");
                    }
                    attempted.borrow_mut().push(account_id.clone());
                    if account_id == failing_account {
                        anyhow::bail!("fallback delete failed")
                    }
                    Ok(())
                },
                |account_id| {
                    if !use_keyring {
                        panic!("keyring cleanup should not run for fallback backend");
                    }
                    attempted.borrow_mut().push(account_id.clone());
                    if account_id == failing_account {
                        anyhow::bail!("delete failed")
                    }
                    Ok(())
                },
                || {
                    *fallback_key_cleanup_calls.borrow_mut() += 1;
                    Ok(())
                },
            )
            .unwrap_err()
            .to_string();

            assert_eq!(attempted.into_inner(), account_ids);
            assert_eq!(
                *fallback_key_cleanup_calls.borrow(),
                usize::from(!use_keyring)
            );
            assert!(error.contains(expected_error));
            assert!(error.contains("1 of 3 account cleanup attempts failed"));
        }
    }

    #[test]
    fn fallback_backend_cleanup_aggregates_key_cleanup_failure() {
        let account_ids = vec!["account-1".to_string(), "account-2".to_string()];

        let error = cleanup_storage_backend_with_ops(
            &account_ids,
            false,
            |account_id| {
                if account_id == "account-1" {
                    anyhow::bail!("fallback delete failed")
                }
                Ok(())
            },
            |_| panic!("keyring cleanup should not run for fallback backend"),
            || anyhow::bail!("fallback key cleanup failed"),
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("1 of 2 account cleanup attempts failed"));
        assert!(error.contains("fallback key cleanup failed"));
    }

    #[test]
    fn fallback_key_material_cleanup_attempts_all_key_locations_after_failure() {
        let events = RefCell::new(Vec::new());

        let error = delete_fallback_key_material_with_ops(
            || {
                events.borrow_mut().push("secure-key".to_string());
                anyhow::bail!("keychain delete failed")
            },
            || {
                events.borrow_mut().push("legacy-file".to_string());
                anyhow::bail!("legacy file delete failed")
            },
        )
        .unwrap_err()
        .to_string();

        assert_eq!(
            events.into_inner(),
            vec!["secure-key".to_string(), "legacy-file".to_string()]
        );
        assert!(error.contains("secure storage key cleanup failed"));
        assert!(error.contains("legacy key file cleanup failed"));
    }

    #[test]
    fn sensitive_fallback_key_delete_does_not_create_invalid_backup() {
        let root = temp_storage_test_dir("fallback-key-no-backup");
        let key_path = root.join("fallback.key");
        write_test_private_text(&key_path, "invalid fallback key for token=super-secret");

        delete_sensitive_private_file_if_present(&key_path).unwrap();

        assert!(!key_path.exists());
        assert!(invalid_storage_operation_entries(&root, "fallback.json.invalid.").is_empty());
        assert!(invalid_storage_operation_entries(&root, "fallback.key.invalid.").is_empty());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn legacy_fallback_key_residue_cleanup_removes_only_fallback_backups() {
        let root = temp_storage_test_dir("fallback-key-residue");
        let fallback_json_backup = root.join("fallback.json.invalid.20260514120000");
        let fallback_key_backup = root.join("fallback.key.invalid.20260514120000");
        let config_backup = root.join("config.json.invalid.20260514120000");
        write_test_private_text(&fallback_json_backup, "old-fallback-key");
        write_test_private_text(&fallback_key_backup, "old-fallback-key");
        write_test_private_text(&config_backup, "recoverable-config");

        let cleaned = cleanup_legacy_fallback_key_residue_files_in_dir(&root).unwrap();

        assert_eq!(cleaned, 2);
        assert!(!fallback_json_backup.exists());
        assert!(!fallback_key_backup.exists());
        assert_eq!(
            std::fs::read_to_string(config_backup).unwrap(),
            "recoverable-config"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn sensitive_fallback_key_delete_removes_symlink_without_touching_target() {
        use std::os::unix::fs::symlink;

        let root = temp_storage_test_dir("fallback-key-symlink");
        let target = root.join("target-secret");
        let link = root.join("fallback.key");
        write_test_private_text(&target, "do-not-touch");
        symlink(&target, &link).unwrap();

        delete_sensitive_private_file_if_present(&link).unwrap();

        assert!(!link.exists());
        assert_eq!(std::fs::read_to_string(target).unwrap(), "do-not-touch");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn fallback_key_cleanup_runs_only_for_empty_password_files_and_reports_failure() {
        for (file, expected_calls) in [
            (PasswordFile::default(), 1),
            (
                PasswordFile {
                    passwords: HashMap::from([("account-1".to_string(), "encrypted".to_string())]),
                    ..PasswordFile::default()
                },
                0,
            ),
        ] {
            let mut cleanup_calls = 0;
            cleanup_fallback_key_if_password_file_empty(&file, || {
                cleanup_calls += 1;
                Ok(())
            })
            .unwrap();
            assert_eq!(cleanup_calls, expected_calls);
        }

        let error = cleanup_fallback_key_if_password_file_empty(&PasswordFile::default(), || {
            anyhow::bail!("fallback key cleanup failed")
        })
        .unwrap_err()
        .to_string();

        assert!(error.contains("fallback key cleanup failed"));
    }

    #[test]
    fn password_file_shape_rejects_oversized_entries() {
        let file = PasswordFile {
            passwords: HashMap::from([(
                "account-1".to_string(),
                "x".repeat(super::MAX_ENCRYPTED_PASSWORD_ENTRY_CHARS + 1),
            )]),
            ..PasswordFile::default()
        };

        assert!(validate_password_file_shape(&file).is_err());
    }

    #[test]
    fn password_file_shape_rejects_invalid_account_ids() {
        let file = PasswordFile {
            passwords: HashMap::from([("".to_string(), "encrypted".to_string())]),
            ..PasswordFile::default()
        };

        assert!(validate_password_file_shape(&file).is_err());
    }

    #[test]
    fn private_text_read_rejects_oversized_files() {
        let root = temp_test_root("oversized-private-read");
        let path = root.join("passwords.json");
        write_test_private_text(&path, "x".repeat((MAX_PASSWORD_FILE_BYTES + 1) as usize));

        assert!(read_private_text_file(&path, MAX_PASSWORD_FILE_BYTES).is_err());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn private_file_atomic_write_replaces_existing_target() {
        let root = temp_storage_test_dir("atomic-replace-existing");
        let path = root.join("config.json");
        std::fs::write(&path, "old").unwrap();

        write_private_file_atomic(&path, "json.tmp", b"new").unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn post_commit_directory_sync_failure_is_classified_as_committed() {
        let path = std::path::Path::new("config.json");
        let error = super::finish_private_file_commit_with_ops(
            path,
            |_| Ok(()),
            |_| anyhow::bail!("directory sync failed"),
        )
        .unwrap_err();

        assert!(super::private_file_write_committed(&error));
        assert!(error.to_string().contains("replacement committed"));
    }

    #[test]
    fn password_transaction_lock_serializes_independent_handles() {
        use std::sync::mpsc;
        use std::time::Duration;

        let root = temp_storage_test_dir("password-lock-serializes");
        let lock_path = root.join("passwords.lock");
        let first = super::acquire_password_file_transaction_lock_at(&lock_path).unwrap();
        let (attempting_tx, attempting_rx) = mpsc::channel();
        let (acquired_tx, acquired_rx) = mpsc::channel();
        let second_path = lock_path.clone();
        let waiter = std::thread::spawn(move || {
            attempting_tx.send(()).unwrap();
            let second = super::acquire_password_file_transaction_lock_at(&second_path).unwrap();
            acquired_tx.send(()).unwrap();
            drop(second);
        });

        attempting_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(acquired_rx
            .recv_timeout(Duration::from_millis(100))
            .is_err());
        drop(first);
        acquired_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        waiter.join().unwrap();

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn password_transaction_lock_prevents_lost_read_modify_write_updates() {
        let root = temp_storage_test_dir("password-lock-rmw");
        let lock_path = root.join("passwords.lock");
        let state_path = root.join("state.json");
        write_test_private_text(&state_path, "{}");

        let workers = (0..12)
            .map(|worker| {
                let lock_path = lock_path.clone();
                let state_path = state_path.clone();
                std::thread::spawn(move || {
                    let _lock =
                        super::acquire_password_file_transaction_lock_at(&lock_path).unwrap();
                    let content = std::fs::read_to_string(&state_path).unwrap();
                    let mut state: HashMap<String, usize> = serde_json::from_str(&content).unwrap();
                    std::thread::yield_now();
                    state.insert(format!("account-{worker}"), worker);
                    let serialized = serde_json::to_string(&state).unwrap();
                    std::fs::write(&state_path, serialized).unwrap();
                })
            })
            .collect::<Vec<_>>();
        for worker in workers {
            worker.join().unwrap();
        }

        let state: HashMap<String, usize> =
            serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
        assert_eq!(state.len(), 12);
        for worker in 0..12 {
            assert_eq!(state[&format!("account-{worker}")], worker);
        }

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn private_text_read_rejects_symlink_files() {
        use std::os::unix::fs::symlink;

        let root = temp_test_root("symlink-private-read");
        let target = root.join("target.json");
        let link = root.join("passwords.json");
        write_test_private_text(&target, "{}");
        symlink(&target, &link).unwrap();

        assert!(read_private_text_file(&link, MAX_PASSWORD_FILE_BYTES).is_err());

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn private_text_read_rejects_windows_reparse_files() {
        let root = temp_test_root("windows-reparse-private-read");
        let target = root.join("target.json");
        let link = root.join("passwords.json");
        write_test_private_text(&target, "{}");
        if !try_create_windows_file_symlink_or_skip(&target, &link) {
            let _ = std::fs::remove_dir_all(root);
            return;
        }

        assert!(read_private_text_file(&link, MAX_PASSWORD_FILE_BYTES).is_err());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "{}");

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn private_atomic_write_rejects_windows_reparse_target() {
        let root = temp_test_root("windows-reparse-atomic-write");
        let target = root.join("target.json");
        let link = root.join("config.json");
        write_test_private_text(&target, "target");
        if !try_create_windows_file_symlink_or_skip(&target, &link) {
            let _ = std::fs::remove_dir_all(root);
            return;
        }

        let error = write_private_file_atomic(&link, "json.tmp", b"new")
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("reparse") || error.contains("regular private file"),
            "{error}"
        );
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "target");

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn private_text_read_repairs_broad_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let root = temp_test_root("private-read-perms");
        let path = root.join("passwords.json");
        write_test_private_text(&path, "{}");
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o644);
        std::fs::set_permissions(&path, permissions).unwrap();

        assert_eq!(
            read_private_text_file(&path, MAX_PASSWORD_FILE_BYTES).unwrap(),
            "{}"
        );
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn validate_private_dir_removes_macos_acl() {
        let root = temp_test_root("private-dir-acl");
        if !add_macos_acl(
            &root,
            "everyone allow list,search,readattr,readextattr,readsecurity",
        ) {
            let _ = std::fs::remove_dir_all(root);
            return;
        }
        assert!(path_has_macos_acl(&root));

        validate_private_dir(&root).unwrap();

        assert!(!path_has_macos_acl(&root));
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn private_text_read_removes_macos_acl() {
        let root = temp_test_root("private-file-acl");
        let path = root.join("passwords.json");
        write_test_private_text(&path, "{}");
        if !add_macos_acl(
            &path,
            "everyone allow read,readattr,readextattr,readsecurity",
        ) {
            let _ = std::fs::remove_dir_all(root);
            return;
        }
        assert!(path_has_macos_acl(&path));

        assert_eq!(
            read_private_text_file(&path, MAX_PASSWORD_FILE_BYTES).unwrap(),
            "{}"
        );

        assert!(!path_has_macos_acl(&path));
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn private_atomic_writes_strip_inherited_macos_acl() {
        let root = temp_test_root("private-atomic-acl");
        if !add_macos_acl(
            &root,
            "everyone allow read,readattr,readextattr,readsecurity,file_inherit,directory_inherit",
        ) {
            let _ = std::fs::remove_dir_all(root);
            return;
        }
        assert!(path_has_macos_acl(&root));

        let replace_path = root.join("config.json");
        write_private_file_atomic(&replace_path, "json.tmp", b"{}").unwrap();
        let create_new_path = root.join("pending-storage-operation.json");
        write_private_file_create_new_atomic(&create_new_path, "json.tmp", b"{}").unwrap();

        assert!(!path_has_macos_acl(&root));
        assert!(!path_has_macos_acl(&replace_path));
        assert!(!path_has_macos_acl(&create_new_path));
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn private_backup_and_quarantine_strip_macos_acl() {
        let root = temp_test_root("private-backup-quarantine-acl");
        let config_path = root.join("config.json");
        write_test_private_text(&config_path, "not-json");
        let pending_path = root.join("pending-storage-operation.json");
        write_test_private_text(&pending_path, "not-json");
        if !add_macos_acl(
            &config_path,
            "everyone allow read,readattr,readextattr,readsecurity",
        ) || !add_macos_acl(
            &pending_path,
            "everyone allow read,readattr,readextattr,readsecurity",
        ) {
            let _ = std::fs::remove_dir_all(root);
            return;
        }

        backup_invalid_config_file(&config_path, &anyhow::anyhow!("invalid config")).unwrap();
        quarantine_pending_storage_operation_file(&pending_path).unwrap();

        let backed_up = std::fs::read_dir(&root)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .collect::<Vec<_>>();
        assert!(backed_up.iter().any(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("config.json.invalid."))
        }));
        assert!(backed_up.iter().any(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("pending-storage-operation.invalid."))
        }));
        for path in backed_up {
            assert!(!path_has_macos_acl(&path));
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn load_password_error_returned_to_callers_is_redacted() {
        let account_id = "account-1".to_string();
        let error = redact_password_load_error(
            anyhow::anyhow!("backend included super-secret-password in failure"),
            &account_id,
            true,
        )
        .to_string();

        assert_eq!(
            error,
            "password could not be loaded from configured secure storage"
        );
        assert!(!error.contains("super-secret-password"));
    }

    #[test]
    fn redacted_account_id_is_not_stable_identifier() {
        assert_eq!(redacted_account_id("account-1"), "[account]");
        assert_eq!(redacted_account_id("account-2"), "[account]");
        assert_eq!(redacted_account_id("user@example.com"), "[account]");
        assert_eq!(redacted_account_id("   "), "");
        assert!(!redacted_account_id("account-1").contains("account-1"));
        assert!(!redacted_account_id("account-1").contains("[account:"));
    }

    #[cfg(unix)]
    #[test]
    fn private_path_validation_errors_redact_full_paths() {
        let root = std::env::temp_dir().join(format!(
            "windows-app-autologin-private-path-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();

        let file_instead_of_dir = root.join("secret-config-dir");
        std::fs::write(&file_instead_of_dir, b"not a dir").unwrap();
        let err = validate_private_dir(&file_instead_of_dir)
            .unwrap_err()
            .to_string();
        assert!(!err.contains(root.to_string_lossy().as_ref()));
        assert!(err.contains("[path]"));
        assert!(!err.contains("secret-config-dir"));

        let dir_instead_of_file = root.join("secret-config.json");
        std::fs::create_dir_all(&dir_instead_of_file).unwrap();
        let err = validate_private_file_for_read(&dir_instead_of_file)
            .unwrap_err()
            .to_string();
        assert!(!err.contains(root.to_string_lossy().as_ref()));
        assert!(err.contains("[path]"));
        assert!(!err.contains("secret-config.json"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn storage_error_kind_is_sanitized_and_coarse() {
        assert_eq!(
            storage_error_kind(&anyhow::anyhow!(
                "Keychain denied access to password=super-secret"
            )),
            "secure_storage_unavailable"
        );
        assert_eq!(
            storage_error_kind(&anyhow::anyhow!(
                "invalid fallback key for token=super-secret"
            )),
            "decrypt_failed"
        );
        assert_eq!(
            storage_error_kind(&anyhow::anyhow!(
                "Windows user-bound DPAPI unprotect failed: redacted"
            )),
            "user_bound_dpapi_unprotect_failed"
        );
        assert_eq!(
            storage_error_kind(&anyhow::anyhow!("NoEntry for secret=super-secret")),
            "not_found"
        );
    }

    #[test]
    fn plaintext_storage_temporaries_are_dropped_before_followup_io() {
        let implementation = include_str!("mod.rs");
        let between = |start: &str, end: &str| {
            let tail = implementation
                .split_once(start)
                .unwrap_or_else(|| panic!("missing function marker: {start}"))
                .1;
            tail.split_once(end)
                .unwrap_or_else(|| panic!("missing function boundary: {end}"))
                .0
        };

        let fallback_stage = between(
            "fn stage_scoped_fallback_entry(",
            "fn cleanup_uncommitted_scoped_keys(",
        );
        assert_ordered(
            fallback_stage,
            &[
                "new_scoped_fallback_key_ref(account_id)?;",
                "track_staged_fallback_key(&key_ref)?;",
                "new_scoped_fallback_key_material();",
                "encrypt_password_with_key(&key, plaintext.as_str());",
                "drop(plaintext);",
                "let encrypted = encrypted_result?;",
                "encode_scoped_fallback_key(&key_ref, &key);",
                "drop(key);",
                "save_scoped_fallback_key_payload(&key_ref, key_payload.as_str());",
                "drop(key_payload);",
                "let encrypted = match stage_result",
                "cleanup_uncommitted_scoped_keys(",
            ],
        );
        assert!(!fallback_stage.contains("PreparedScopedFallbackEntry"));

        let owned_fallback_save = between("fn save_to_file_owned(", "fn save_to_file_locked(");
        assert_ordered(
            owned_fallback_save,
            &[
                "acquire_password_file_transaction_lock()?;",
                "prepare_password_file_transaction()?;",
                "use_owned_secret_then_drop(password,",
                "stage_scoped_fallback_entry(&account.id, payload)?;",
                "save_to_file_locked_persisted(",
            ],
        );

        let fallback_load = between(
            "fn load_from_file_locked(",
            "fn password_entry_for_account<'a>(",
        );
        assert_ordered(
            fallback_load,
            &[
                "decode_bound_password(account, stored.as_str())?;",
                "Some(encode_bound_password(account, password.as_str())?)",
                "drop(password);",
                "drop(stored);",
                "drop(encrypted);",
                "stage_scoped_fallback_entry(&account.id, payload)?",
                "let migration_result =",
                "install_scoped_fallback_entry(&mut file,",
                "commit_password_file_with_staged_keys(",
                "let refreshed_file = load_password_file()?;",
                "load_password_from_file_snapshot(account, &refreshed_file)?;",
            ],
        );

        let legacy_fallback_migration = between(
            "fn migrate_legacy_fallback_entries_with_ops<",
            "fn cleanup_retired_fallback_keys(",
        );
        assert_ordered(
            legacy_fallback_migration,
            &[
                "password_entry_for_account(file, account_id)?;",
                "let shared_key = load_shared_key()?;",
                "decrypt_password_with_fallback_key(&shared_key, encrypted);",
                "drop(shared_key);",
                "let plaintext = plaintext_result?;",
                "stage_entry(account_id, plaintext)",
            ],
        );

        let keyring_save = between(
            "pub(crate) fn write_account_password_owned(",
            "pub(crate) fn write_account_password_borrowed_with_revision(",
        );
        assert_ordered(
            keyring_save,
            &[
                "use_owned_secret_then_drop(password,",
                "let set_result = entry.set_password(payload.as_str());",
                "drop(payload);",
                "match set_result",
            ],
        );

        let keyring_load = between(
            "fn load_from_keyring_timed(",
            "fn cleanup_migrated_legacy_credentials(",
        );
        assert_ordered(
            keyring_load,
            &[
                "acquire_password_file_transaction_lock()?;",
                "prepare_password_file_transaction()?;",
                "entry.get_password()?",
                "decode_keyring_password(account, stored.as_str())?;",
                "let migration_payload =",
                "if let Some(payload) = migration_payload",
                "drop(password);",
                "drop(stored);",
                "let set_result = entry.set_password(payload.as_str());",
                "decode_keyring_password(account, payload.as_str())?;",
                "drop(payload);",
                "return Ok(LoadedStoredPassword",
            ],
        );
        assert_eq!(
            keyring_load
                .matches("acquire_password_file_transaction_lock()?;")
                .count(),
            1
        );
        assert_eq!(
            keyring_load
                .matches("prepare_password_file_transaction()?;")
                .count(),
            1
        );
    }

    #[test]
    fn owned_secret_helper_drops_before_followup_work() {
        struct DropProbe<'a>(&'a RefCell<Vec<&'static str>>);
        impl Drop for DropProbe<'_> {
            fn drop(&mut self) {
                self.0.borrow_mut().push("drop-secret");
            }
        }

        let events = RefCell::new(Vec::new());
        use_owned_secret_then_drop(DropProbe(&events), |_| {
            events.borrow_mut().push("use-secret");
            Ok(())
        })
        .unwrap();
        events.borrow_mut().push("followup-io");

        assert_eq!(
            events.into_inner(),
            vec!["use-secret", "drop-secret", "followup-io"]
        );
    }

    #[cfg(target_os = "macos")]
    fn add_macos_acl(path: &std::path::Path, acl: &str) -> bool {
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
    fn path_has_macos_acl(path: &std::path::Path) -> bool {
        let output = std::process::Command::new("/bin/ls")
            .arg("-lde")
            .arg(path)
            .output()
            .expect("ls should inspect macOS ACL state");
        assert!(
            output.status.success(),
            "ls -lde failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .skip(1)
            .any(|line| line.trim_start().starts_with("0:"))
    }

    fn temp_test_root(name: &str) -> std::path::PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "windows-app-autologin-storage-{name}-{}-{nonce}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = std::fs::metadata(&root).unwrap().permissions();
            permissions.set_mode(0o700);
            std::fs::set_permissions(&root, permissions).unwrap();
        }
        root
    }

    fn write_test_private_text(path: &std::path::Path, content: impl AsRef<[u8]>) {
        std::fs::write(path, content).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = std::fs::metadata(path).unwrap().permissions();
            permissions.set_mode(0o600);
            std::fs::set_permissions(path, permissions).unwrap();
        }
    }

    fn assert_ordered(source: &str, markers: &[&str]) {
        let mut offset = 0;
        for marker in markers {
            let relative = source[offset..]
                .find(marker)
                .unwrap_or_else(|| panic!("missing ordered source marker: {marker}"));
            offset += relative + marker.len();
        }
    }

    #[cfg(target_os = "windows")]
    fn try_create_windows_file_symlink_or_skip(
        target: &std::path::Path,
        link: &std::path::Path,
    ) -> bool {
        match std::os::windows::fs::symlink_file(target, link) {
            Ok(()) => true,
            Err(e)
                if e.kind() == std::io::ErrorKind::PermissionDenied
                    || e.raw_os_error() == Some(1314) =>
            {
                false
            }
            Err(e) => panic!("failed to create Windows file symlink: {e}"),
        }
    }
}
