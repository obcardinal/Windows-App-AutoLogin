use crate::models::{Account, AccountId, AppConfig, FIXED_POLL_INTERVAL_SECS};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

const SERVICE_NAME: &str = "WindowsAppAutoLogin";
const FALLBACK_KEY_SERVICE_NAME: &str = "WindowsAppAutoLoginFallbackKey";
const FALLBACK_KEY_ACCOUNT: &str = "fallback-encryption-key";
const CONFIG_FILE_NAME: &str = "config.json";
const PASSWORD_FILE_NAME: &str = "passwords.json";
const FALLBACK_KEY_FILE_NAME: &str = "fallback.key";
const PENDING_STORAGE_OPERATION_FILE_NAME: &str = "pending-storage-operation.json";
const RECOVERING_STORAGE_OPERATION_FILE_NAME: &str = "pending-storage-operation.recovering.json";
const PASSWORD_ENVELOPE_PREFIX: &str = "waa1:";
const PASSWORD_ENVELOPE_V2_PREFIX: &str = "waa2:";
const PASSWORD_ENVELOPE_VERSION: u8 = 1;
const PASSWORD_ENVELOPE_V2_VERSION: u8 = 2;
const MAX_CONFIG_FILE_BYTES: u64 = 1024 * 1024;
const MAX_PASSWORD_FILE_BYTES: u64 = 1024 * 1024;
const MAX_FALLBACK_KEY_FILE_BYTES: u64 = 128;
const MAX_PENDING_STORAGE_OPERATION_FILE_BYTES: u64 = 64 * 1024;
const MAX_ENCRYPTED_PASSWORD_ENTRY_CHARS: usize = 16 * 1024;
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
struct StorageModeMigrationRecoveryRequired {
    message: String,
}

impl fmt::Display for StorageModeMigrationRecoveryRequired {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for StorageModeMigrationRecoveryRequired {}

pub(crate) fn is_pending_storage_operation_in_progress(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.is::<PendingStorageOperationInProgress>())
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

#[cfg(not(unix))]
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

#[cfg(not(unix))]
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

#[cfg(not(unix))]
fn validate_private_file_for_read(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

fn read_private_text_file(path: &Path, max_bytes: u64) -> anyhow::Result<String> {
    use std::io::Read;

    if let Some(parent) = path.parent() {
        validate_private_dir(parent)?;
    }

    #[cfg(unix)]
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);

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

    Ok(String::from_utf8(bytes)?)
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
            if let Err(backup_error) = backup_invalid_file(&path) {
                warn!(path = %redacted_path(&path), error = %backup_error, "Failed to back up invalid config before using defaults");
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

        if let Err(e) = save_password_to_backend(
            account,
            password.as_str(),
            config.settings.use_keyring,
            false,
        ) {
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
            cleanup_ids_after_save: obsolete_legacy_credential_ids(&source_ids, &account.id),
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

fn backup_invalid_file(path: &Path) -> anyhow::Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    if metadata.file_type().is_symlink() {
        std::fs::remove_file(path)?;
        return Ok(());
    }
    if !metadata.file_type().is_file() {
        return Ok(());
    }
    validate_private_file_for_read(path)?;

    let timestamp = chrono::Local::now().format("%Y%m%d%H%M%S");
    let backup_path = path.with_extension(format!("json.invalid.{timestamp}"));
    std::fs::rename(path, &backup_path)?;
    secure_path_permissions(&backup_path, 0o600)?;
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

fn fallback_key_file_path() -> anyhow::Result<PathBuf> {
    Ok(config_dir()?.join(FALLBACK_KEY_FILE_NAME))
}

fn pending_storage_operation_file_path() -> anyhow::Result<PathBuf> {
    Ok(config_dir()?.join(PENDING_STORAGE_OPERATION_FILE_NAME))
}

fn recovering_storage_operation_file_path() -> anyhow::Result<PathBuf> {
    Ok(config_dir()?.join(RECOVERING_STORAGE_OPERATION_FILE_NAME))
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
struct PasswordFile {
    #[serde(default)]
    passwords: HashMap<String, String>,
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
}

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
    password: &'a str,
}

#[derive(Debug, serde::Deserialize)]
struct StoredPasswordEnvelopeV1Owned {
    version: u8,
    service: String,
    account_id: AccountId,
    username_sha256: String,
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
    password: Zeroizing<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StoredPasswordFormat {
    BoundV1,
    BoundV2,
    LegacyRaw,
}

fn canonical_username(username: &str) -> String {
    username.trim().to_lowercase()
}

fn username_binding_hash(username: &str) -> String {
    sha256_hex(canonical_username(username).as_bytes())
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

fn encode_bound_password(account: &Account, password: &str) -> anyhow::Result<Zeroizing<String>> {
    let envelope = StoredPasswordEnvelopeV1 {
        version: PASSWORD_ENVELOPE_VERSION,
        service: SERVICE_NAME.to_string(),
        account_id: account.id.clone(),
        username_sha256: username_binding_hash(&account.username),
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

fn decode_bound_password(
    account: &Account,
    stored: &str,
) -> anyhow::Result<(Zeroizing<String>, StoredPasswordFormat)> {
    if let Some(json) = stored.strip_prefix(PASSWORD_ENVELOPE_V2_PREFIX) {
        let envelope: StoredPasswordEnvelopeV2Owned = serde_json::from_str(json)?;
        if envelope.version != PASSWORD_ENVELOPE_V2_VERSION
            || envelope.service != SERVICE_NAME
            || envelope.account_id != account.id
            || envelope.username_sha256 != username_binding_hash(&account.username)
        {
            anyhow::bail!("stored password binding does not match account metadata");
        }

        return Ok((envelope.password, StoredPasswordFormat::BoundV2));
    }

    let Some(json) = stored.strip_prefix(PASSWORD_ENVELOPE_PREFIX) else {
        if stored.is_empty() {
            anyhow::bail!("stored password is empty");
        }
        return Ok((
            Zeroizing::new(stored.to_string()),
            StoredPasswordFormat::LegacyRaw,
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

    Ok((envelope.password, StoredPasswordFormat::BoundV1))
}

fn load_password_file() -> anyhow::Result<PasswordFile> {
    let path = password_file_path()?;
    if !path.exists() {
        return Ok(PasswordFile::default());
    }
    let content = match read_private_text_file(&path, MAX_PASSWORD_FILE_BYTES) {
        Ok(c) => c,
        Err(e) => {
            warn!(path = %redacted_path(&path), error = %e, "Failed to read password file");
            return Err(e.into());
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
        }
        "account_delete" => {
            let Some(before_account) = &operation.before_account else {
                anyhow::bail!("account delete journal is missing source account");
            };
            if operation.after_account.is_some() {
                anyhow::bail!("account delete journal must not contain target account");
            }
            if operation.account_ids.len() != 1
                || operation.account_ids[0] != before_account.id.as_str()
            {
                anyhow::bail!("account delete journal account id does not match source account");
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
    let path = password_file_path()?;
    let content = match serde_json::to_string_pretty(file) {
        Ok(c) => c,
        Err(e) => {
            warn!(path = %redacted_path(&path), error = %e, "Failed to serialize password file");
            return Err(e.into());
        }
    };
    write_private_file_atomic(&path, "json.tmp", content.as_bytes())?;
    debug!(path = %redacted_path(&path), entries = file.passwords.len(), "Password file written");
    Ok(())
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
        if let Err(e) = file.write_all(bytes).and_then(|_| file.sync_all()) {
            let _ = std::fs::remove_file(&temp_path);
            return Err(e.into());
        }
    }

    if let Err(e) = secure_path_permissions(&temp_path, 0o600) {
        let _ = std::fs::remove_file(&temp_path);
        return Err(e);
    }
    std::fs::rename(&temp_path, path)?;
    secure_path_permissions(path, 0o600)?;
    if let Err(e) = sync_parent_dir(path) {
        warn!(
            path = %crate::user_paths::redacted_path(&path.display().to_string()),
            error = %e,
            "private file write committed, but parent directory sync failed"
        );
    }
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
    let _ = std::fs::remove_file(&temp_path);
    Ok(())
}

fn sync_parent_dir(path: &Path) -> anyhow::Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

fn fallback_encryption_key() -> anyhow::Result<Zeroizing<[u8; 32]>> {
    ensure_config_dir()?;

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
            let key = decode_fallback_encryption_key(encoded.trim())?;
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
        let encoded = Zeroizing::new(STANDARD.encode(&*legacy_key));
        entry.set_password(encoded.as_str()).map_err(|e| {
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
    let encoded = Zeroizing::new(STANDARD.encode(&*key));
    entry.set_password(encoded.as_str()).map_err(|e| {
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
            warn!(path = %redacted_path(&path), error = %e, "Fallback key file is invalid; backing it up");
            backup_invalid_file(&path).ok();
            std::fs::remove_file(&path).ok();
            return Ok(None);
        }
    };

    Ok(Some((path, key)))
}

fn cleanup_stale_fallback_key_file_if_present() -> anyhow::Result<()> {
    let path = fallback_key_file_path()?;
    if path.exists() {
        cleanup_legacy_fallback_key_file(&path)?;
    }
    Ok(())
}

fn cleanup_legacy_fallback_key_file(path: &Path) -> anyhow::Result<()> {
    if let Err(e) = std::fs::remove_file(path) {
        warn!(
            path = %redacted_path(path),
            error = %e,
            "fallback key was migrated to Keychain, but stale key file cleanup failed"
        );
        return Err(e.into());
    }
    if let Err(e) = sync_parent_dir(path) {
        warn!(
            path = %redacted_path(path),
            error = %e,
            "fallback key file was removed, but parent directory sync failed"
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
    let path = fallback_key_file_path()?;
    if path.exists() {
        cleanup_legacy_fallback_key_file(&path)?;
    }
    Ok(())
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

fn encrypt_password(plaintext: &str) -> anyhow::Result<String> {
    let key = fallback_encryption_key()?;
    let cipher = Aes256Gcm::new_from_slice(&*key)
        .map_err(|e| anyhow::anyhow!("failed to create cipher: {:?}", e))?;
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| anyhow::anyhow!("encryption failed: {:?}", e))?;
    let mut combined = nonce_bytes.to_vec();
    combined.extend_from_slice(&ciphertext);
    Ok(STANDARD.encode(&combined))
}

fn decrypt_password_with_key(key: &[u8; 32], data: &[u8]) -> anyhow::Result<Zeroizing<String>> {
    if data.len() < AES_GCM_NONCE_BYTES + AES_GCM_TAG_BYTES {
        anyhow::bail!("invalid ciphertext: too short");
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| anyhow::anyhow!("failed to create cipher: {:?}", e))?;
    let nonce = Nonce::from_slice(&data[..AES_GCM_NONCE_BYTES]);
    let plaintext = cipher
        .decrypt(nonce, &data[AES_GCM_NONCE_BYTES..])
        .map_err(|e| anyhow::anyhow!("decryption failed: {:?}", e))?;
    Ok(Zeroizing::new(String::from_utf8(plaintext)?))
}

fn decrypt_password(b64: &str) -> anyhow::Result<(Zeroizing<String>, bool)> {
    if b64.len() > MAX_ENCRYPTED_PASSWORD_ENTRY_CHARS {
        anyhow::bail!("encrypted password entry is too large");
    }
    let data = STANDARD.decode(b64)?;
    let key = fallback_encryption_key()?;
    decrypt_password_with_key(&*key, &data).map(|password| (password, false))
}

fn save_to_file(account: &Account, password: &str) -> anyhow::Result<()> {
    let mut file = load_password_file()?;
    let payload = encode_bound_password(account, password)?;
    let encrypted = match encrypt_password(payload.as_str()) {
        Ok(enc) => enc,
        Err(e) => {
            warn!(account_id = %redacted_account_id(&account.id), error = %e, "Failed to encrypt password");
            return Err(e);
        }
    };
    file.passwords.insert(account.id.clone(), encrypted);
    match save_password_file(&file) {
        Ok(()) => {}
        Err(e) => {
            warn!(account_id = %redacted_account_id(&account.id), error = %e, "save_password_file failed");
            return Err(e);
        }
    }
    Ok(())
}

fn load_from_file(account: &Account) -> anyhow::Result<LoadedStoredPassword> {
    let mut file = load_password_file()?;
    let encrypted = password_entry_for_account(&file, &account.id)?.to_string();
    if encrypted.len() > MAX_ENCRYPTED_PASSWORD_ENTRY_CHARS {
        anyhow::bail!("encrypted password entry is too large");
    }
    let (stored, used_legacy_key) = decrypt_password(&encrypted)?;
    let (password, format) = decode_bound_password(account, stored.as_str())?;

    if used_legacy_key || format == StoredPasswordFormat::LegacyRaw {
        let payload = encode_bound_password(account, password.as_str())?;
        match encrypt_password(payload.as_str()) {
            Ok(reencrypted) => {
                file.passwords.insert(account.id.clone(), reencrypted);
                if let Err(e) = save_password_file(&file) {
                    warn!(account_id = %redacted_account_id(&account.id), error = %e, "Password loaded from legacy fallback storage, but migration to bound storage failed");
                } else {
                    info!(account_id = %redacted_account_id(&account.id), "Migrated fallback password to bound storage");
                }
            }
            Err(e) => {
                warn!(account_id = %redacted_account_id(&account.id), error = %e, "Password loaded from legacy fallback storage, but re-encryption failed");
            }
        }
    }

    Ok(LoadedStoredPassword {
        password,
        zeroizing_wrap_ms: 0,
    })
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
    let mut file = load_password_file()?;
    if file.passwords.remove(account_id).is_some() {
        save_password_file(&file)?;
    }
    Ok(())
}

pub(crate) fn cleanup_unused_fallback_key_material() -> anyhow::Result<()> {
    let file = load_password_file()?;
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
}

fn save_password(
    account: &Account,
    password: &str,
    use_keyring: bool,
) -> anyhow::Result<SaveAccountOutcome> {
    save_password_to_backend(account, password, use_keyring, true)
}

fn save_password_to_backend(
    account: &Account,
    password: &str,
    use_keyring: bool,
    cleanup_stale_backend: bool,
) -> anyhow::Result<SaveAccountOutcome> {
    debug!(account_id = %redacted_account_id(&account.id), use_keyring, "save_password called");
    if use_keyring {
        let entry = keyring::Entry::new(SERVICE_NAME, &account.id)
            .map_err(|e| anyhow::anyhow!("{} is unavailable: {e}", native_secure_storage_name()))?;
        let payload = encode_bound_password(account, password)?;
        match entry.set_password(payload.as_str()) {
            Ok(()) => {
                let stale_cleanup_warning = cleanup_stale_backend_after_successful_save(
                    &account.id,
                    PasswordStorageBackend::SystemSecureStorage,
                    cleanup_stale_backend,
                    |account_id| {
                        delete_from_file(account_id)?;
                        cleanup_unused_fallback_key_material()
                    },
                    delete_from_keyring,
                );
                info!(account_id = %redacted_account_id(&account.id), "Password saved to secure storage successfully");
                return Ok(SaveAccountOutcome {
                    stale_cleanup_warning,
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
    match save_to_file(account, password) {
        Ok(()) => {}
        Err(e) => {
            warn!(account_id = %redacted_account_id(&account.id), error = %e, "save_to_file failed");
            return Err(e);
        }
    }
    info!(
        account_id = %redacted_account_id(&account.id),
        "Password saved to fallback encrypted file storage"
    );
    let stale_cleanup_warning = cleanup_stale_backend_after_successful_save(
        &account.id,
        PasswordStorageBackend::EncryptedFallbackFile,
        cleanup_stale_backend,
        delete_from_file,
        delete_from_keyring,
    );
    Ok(SaveAccountOutcome {
        stale_cleanup_warning,
    })
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
                    e.into(),
                )?;
                unreachable!("rollback_partial_storage_migration always returns Err");
            }
        };

        if let Err(e) = save_password_to_backend(account, password.as_str(), to_use_keyring, false)
        {
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

        migrated_account_ids.push(account.id.clone());

        if let Err(e) = load_password(account, to_use_keyring) {
            rollback_partial_storage_migration(
                migrated_account_ids,
                from_use_keyring,
                to_use_keyring,
                e.into(),
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
    };
    validate_pending_storage_operation(&operation)?;
    save_pending_storage_operation(&operation)
}

pub(crate) fn begin_account_config_save_journal(
    before_account: Option<&Account>,
    after_account: &Account,
    use_keyring: bool,
) -> anyhow::Result<()> {
    let operation = PendingStorageOperation {
        version: PENDING_STORAGE_OPERATION_VERSION,
        kind: "account_config_save".to_string(),
        account_ids: vec![after_account.id.clone()],
        from_use_keyring: false,
        to_use_keyring: false,
        use_keyring,
        before_account: before_account.cloned(),
        after_account: Some(after_account.clone()),
    };
    validate_pending_storage_operation(&operation)?;
    save_pending_storage_operation(&operation)
}

pub(crate) fn begin_account_delete_journal(
    before_account: &Account,
    use_keyring: bool,
) -> anyhow::Result<()> {
    let operation = PendingStorageOperation {
        version: PENDING_STORAGE_OPERATION_VERSION,
        kind: "account_delete".to_string(),
        account_ids: vec![before_account.id.clone()],
        from_use_keyring: false,
        to_use_keyring: false,
        use_keyring,
        before_account: Some(before_account.clone()),
        after_account: None,
    };
    validate_pending_storage_operation(&operation)?;
    save_pending_storage_operation(&operation)
}

pub(crate) fn clear_pending_storage_operation() -> anyhow::Result<()> {
    let pending_path = pending_storage_operation_file_path()?;
    let recovering_path = recovering_storage_operation_file_path()?;
    clear_pending_storage_operation_paths(&pending_path, &recovering_path)
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
    let Some(record) = load_pending_storage_operation_record_or_quarantine()? else {
        return Ok(());
    };
    let record = consume_pending_storage_operation_record(record)?;
    match record.operation.kind.as_str() {
        "storage_mode_migration" => reconcile_storage_mode_operation(config, &record.operation)?,
        "account_config_save" => {
            reconcile_account_config_save_operation(config, &record.operation)?
        }
        "account_delete" => reconcile_account_delete_operation(config, &record.operation)?,
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
        warn!("Pending storage migration journal referenced unknown account ids; quarantining");
        quarantine_pending_storage_operation_files()?;
        return Ok(());
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
        |account, use_keyring| load_password(account, use_keyring).map(|_| ()),
        save_config,
        |account_ids, use_keyring| cleanup_storage_backend(account_ids, use_keyring).map(|_| ()),
        delete_password,
    )
}

fn reconcile_account_config_save_operation_with_ops<L, S, C, D>(
    config: &mut AppConfig,
    operation: &PendingStorageOperation,
    mut load_password_op: L,
    mut save_config_op: S,
    mut cleanup_storage_backend_op: C,
    mut delete_password_op: D,
) -> anyhow::Result<()>
where
    L: FnMut(&Account, bool) -> anyhow::Result<()>,
    S: FnMut(&AppConfig) -> anyhow::Result<()>,
    C: FnMut(&[AccountId], bool) -> anyhow::Result<()>,
    D: FnMut(&AccountId) -> anyhow::Result<()>,
{
    let Some(after_account) = operation.after_account.as_ref() else {
        return Ok(());
    };
    let mut after_account = after_account.clone();
    after_account.has_saved_password = true;

    if load_password_op(&after_account, operation.use_keyring).is_ok() {
        upsert_recovered_account(config, after_account);
        save_config_op(config)?;
        cleanup_storage_backend_op(&operation.account_ids, !operation.use_keyring)?;
        return Ok(());
    }

    if let Some(before_account) = operation.before_account.as_ref() {
        let mut before_account = before_account.clone();
        if before_account.has_saved_password
            && load_password_op(&before_account, operation.use_keyring).is_err()
        {
            before_account.has_saved_password = false;
            before_account.enabled = false;
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

fn reconcile_account_delete_operation(
    config: &AppConfig,
    operation: &PendingStorageOperation,
) -> anyhow::Result<()> {
    reconcile_account_delete_operation_with_ops(config, operation, delete_account)
}

fn reconcile_account_delete_operation_with_ops<D>(
    config: &AppConfig,
    operation: &PendingStorageOperation,
    mut delete_account_op: D,
) -> anyhow::Result<()>
where
    D: FnMut(&AccountId) -> anyhow::Result<()>,
{
    let Some(before_account) = operation.before_account.as_ref() else {
        return Ok(());
    };
    if config
        .accounts
        .iter()
        .any(|account| account.id == before_account.id)
    {
        return Ok(());
    }
    delete_account_op(&before_account.id)
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
    let path = pending_storage_operation_file_path()?;
    let recovering_path = recovering_storage_operation_file_path()?;
    save_pending_storage_operation_to_paths(operation, &path, &recovering_path)
}

fn save_pending_storage_operation_to_paths(
    operation: &PendingStorageOperation,
    path: &Path,
    recovering_path: &Path,
) -> anyhow::Result<()> {
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

fn load_pending_storage_operation_record_or_quarantine(
) -> anyhow::Result<Option<PendingStorageOperationRecord>> {
    let recovering_path = recovering_storage_operation_file_path()?;
    let pending_path = pending_storage_operation_file_path()?;
    load_pending_storage_operation_record_or_quarantine_from_paths(&recovering_path, &pending_path)
}

fn load_pending_storage_operation_record_or_quarantine_from_paths(
    recovering_path: &Path,
    pending_path: &Path,
) -> anyhow::Result<Option<PendingStorageOperationRecord>> {
    if let Some(record) = load_pending_storage_operation_record_from_path_or_quarantine(
        recovering_path,
        "recovering",
    )? {
        return Ok(Some(record));
    }
    load_pending_storage_operation_record_from_path_or_quarantine(pending_path, "pending")
}

fn load_pending_storage_operation_record_from_path_or_quarantine(
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
                error = %e,
                "pending storage operation journal is invalid; quarantining"
            );
            quarantine_pending_storage_operation_file(path)?;
            Ok(None)
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
    if record.path == recovering_path {
        return Ok(record);
    }
    std::fs::rename(&record.path, &recovering_path)?;
    secure_path_permissions(&recovering_path, 0o600)?;
    sync_parent_dir(&recovering_path)?;
    Ok(PendingStorageOperationRecord {
        operation: record.operation,
        path: recovering_path,
    })
}

fn quarantine_pending_storage_operation_files() -> anyhow::Result<()> {
    quarantine_pending_storage_operation_file(&pending_storage_operation_file_path()?)?;
    quarantine_pending_storage_operation_file(&recovering_storage_operation_file_path()?)
}

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
    let entry = keyring::Entry::new(SERVICE_NAME, &account.id)?;
    let stored = Zeroizing::new(entry.get_password()?);
    let zeroizing_start = std::time::Instant::now();
    let (password, format) = decode_bound_password(account, stored.as_str())?;
    let zeroizing_wrap_ms = zeroizing_start.elapsed().as_millis();
    if format == StoredPasswordFormat::LegacyRaw {
        let payload = encode_bound_password(account, password.as_str())?;
        if let Err(e) = entry.set_password(payload.as_str()) {
            warn!(account_id = %redacted_account_id(&account.id), error = %e, "Password loaded from legacy keychain format, but migration to bound storage failed");
        } else {
            info!(account_id = %redacted_account_id(&account.id), "Migrated legacy keychain password to bound storage");
        }
    }
    debug!(account_id = %redacted_account_id(&account.id), "Password loaded from secure storage");
    Ok(LoadedStoredPassword {
        password,
        zeroizing_wrap_ms,
    })
}

fn cleanup_migrated_legacy_credentials(account_ids: &[AccountId]) {
    for account_id in account_ids {
        if let Err(e) = delete_password(&account_id) {
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

pub(crate) fn save_account(
    account: &Account,
    password: &str,
    use_keyring: bool,
) -> anyhow::Result<()> {
    save_account_with_outcome(account, password, use_keyring).map(|_| ())
}

pub(crate) fn save_account_with_outcome(
    account: &Account,
    password: &str,
    use_keyring: bool,
) -> anyhow::Result<SaveAccountOutcome> {
    debug!(account_id = %redacted_account_id(&account.id), use_keyring, "save_account called");
    if password.is_empty() {
        warn!(account_id = %redacted_account_id(&account.id), "save_account received empty password, skipping keyring storage");
        return Ok(SaveAccountOutcome::default());
    } else {
        return save_password(account, password, use_keyring);
    }
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
        backup_invalid_file, cleanup_fallback_key_if_password_file_empty,
        cleanup_stale_backend_after_successful_save, cleanup_storage_backend_with_ops,
        clear_pending_storage_operation_paths, decode_bound_password, decrypt_password_with_key,
        delete_fallback_key_material_with_ops, encode_bound_password,
        ensure_no_pending_storage_operation, is_pending_storage_operation_in_progress,
        legacy_account_id_for_migrated_config, legacy_migration_target_cleanup_id,
        legacy_password_migration_ready_to_persist, load_config_file,
        load_pending_storage_operation_record_or_quarantine_from_paths, migrate_legacy_config,
        normalize_config, password_entry_for_account, pending_storage_backend_to_cleanup,
        pending_storage_operation_account_ids_known, quarantine_pending_storage_operation_file,
        read_private_text_file, reconcile_account_config_save_operation_with_ops,
        reconcile_account_delete_operation_with_ops, redact_password_load_error,
        redacted_account_id, save_pending_storage_operation_to_paths, sha256_hex,
        storage_error_kind, username_binding_hash, validate_password_file_shape,
        validate_pending_storage_operation, validate_private_dir, validate_private_file_for_read,
        verify_pending_storage_surviving_backend, write_private_file_atomic,
        write_private_file_create_new_atomic, LegacyConfig, LegacyCredentialsConfig,
        LegacyPasswordMigration, PasswordFile, PasswordStorageBackend, PendingStorageOperation,
        StoredPasswordFormat, AES_GCM_NONCE_BYTES, AES_GCM_TAG_BYTES, MAX_PASSWORD_FILE_BYTES,
        PASSWORD_ENVELOPE_V2_PREFIX, PASSWORD_ENVELOPE_V2_VERSION,
        PENDING_STORAGE_OPERATION_VERSION, SERVICE_NAME,
    };
    use crate::models::{Account, AppConfig, FIXED_POLL_INTERVAL_SECS};
    use std::cell::RefCell;
    use std::collections::HashMap;

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
    fn legacy_migration_rolls_back_generated_target_after_config_save_failure() {
        let source_ids = vec!["user@example.com".to_string(), "legacy-id".to_string()];
        let target_id = "generated-account-id".to_string();

        assert_eq!(
            legacy_migration_target_cleanup_id(&source_ids, &target_id),
            Some(&target_id)
        );
    }

    #[test]
    fn legacy_migration_keeps_reused_source_target_after_config_save_failure() {
        let source_ids = vec!["legacy-id".to_string(), "user@example.com".to_string()];
        let target_id = "legacy-id".to_string();

        assert_eq!(
            legacy_migration_target_cleanup_id(&source_ids, &target_id),
            None
        );
    }

    #[test]
    fn incomplete_legacy_password_migration_is_not_persisted() {
        let migration = LegacyPasswordMigration {
            source_ids: vec!["legacy-id".to_string()],
            target_id: None,
            cleanup_ids_after_save: Vec::new(),
        };

        assert!(!legacy_password_migration_ready_to_persist(&migration));
    }

    #[test]
    fn legacy_config_without_password_sources_can_be_persisted() {
        assert!(legacy_password_migration_ready_to_persist(
            &LegacyPasswordMigration::default()
        ));
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
    fn pending_storage_recovery_rolls_back_target_when_config_was_not_saved() {
        let operation = PendingStorageOperation {
            version: PENDING_STORAGE_OPERATION_VERSION,
            kind: "storage_mode_migration".to_string(),
            account_ids: vec!["account-1".to_string()],
            from_use_keyring: true,
            to_use_keyring: false,
            use_keyring: false,
            before_account: None,
            after_account: None,
        };

        assert_eq!(
            pending_storage_backend_to_cleanup(&operation, true),
            Some(false)
        );
    }

    #[test]
    fn pending_storage_recovery_commits_source_cleanup_when_config_was_saved() {
        let operation = PendingStorageOperation {
            version: PENDING_STORAGE_OPERATION_VERSION,
            kind: "storage_mode_migration".to_string(),
            account_ids: vec!["account-1".to_string()],
            from_use_keyring: true,
            to_use_keyring: false,
            use_keyring: false,
            before_account: None,
            after_account: None,
        };

        assert_eq!(
            pending_storage_backend_to_cleanup(&operation, false),
            Some(true)
        );
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
                "save_config"
            ]
        );
    }

    #[test]
    fn pending_account_delete_recovery_retries_cleanup_when_config_removed_account() {
        let config = AppConfig::default();
        let operation = account_delete_pending_operation();
        let attempts = RefCell::new(Vec::new());

        let error =
            reconcile_account_delete_operation_with_ops(&config, &operation, |account_id| {
                attempts.borrow_mut().push(account_id.clone());
                anyhow::bail!("delete failed")
            })
            .unwrap_err();

        assert!(error.to_string().contains("delete failed"));
        assert_eq!(attempts.into_inner(), vec!["account-1".to_string()]);
    }

    #[test]
    fn pending_account_delete_recovery_skips_cleanup_when_account_still_configured() {
        let mut config = AppConfig::default();
        let operation = account_delete_pending_operation();
        config
            .accounts
            .push(operation.before_account.as_ref().unwrap().clone());

        reconcile_account_delete_operation_with_ops(&config, &operation, |_| {
            panic!("delete cleanup must wait until account removal is committed")
        })
        .unwrap();
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
    }

    #[test]
    fn account_config_journal_contains_no_password_material() {
        let mut after_account = Account::new("user@example.com");
        after_account.id = "account-1".to_string();
        after_account.has_saved_password = true;
        let operation = PendingStorageOperation {
            version: PENDING_STORAGE_OPERATION_VERSION,
            kind: "account_config_save".to_string(),
            account_ids: vec![after_account.id.clone()],
            from_use_keyring: false,
            to_use_keyring: false,
            use_keyring: true,
            before_account: None,
            after_account: Some(after_account),
        };

        validate_pending_storage_operation(&operation).unwrap();
        let serialized = serde_json::to_string(&operation).unwrap();
        assert!(!serialized.contains("super-secret-password"));
        assert!(!serialized.contains("encrypted_password"));
    }

    #[test]
    fn account_delete_journal_contains_no_password_material() {
        let mut before_account = Account::new("user@example.com");
        before_account.id = "account-1".to_string();
        before_account.has_saved_password = true;
        let operation = PendingStorageOperation {
            version: PENDING_STORAGE_OPERATION_VERSION,
            kind: "account_delete".to_string(),
            account_ids: vec![before_account.id.clone()],
            from_use_keyring: false,
            to_use_keyring: false,
            use_keyring: true,
            before_account: Some(before_account),
            after_account: None,
        };

        validate_pending_storage_operation(&operation).unwrap();
        let serialized = serde_json::to_string(&operation).unwrap();
        assert!(!serialized.contains("super-secret-password"));
        assert!(!serialized.contains("encrypted_password"));
    }

    #[test]
    fn pending_storage_operation_refuses_existing_pending_or_recovering_journal() {
        let root = temp_storage_test_dir("pending-overwrite");
        let pending_path = root.join("pending-storage-operation.json");
        let recovering_path = root.join("pending-storage-operation.recovering.json");

        ensure_no_pending_storage_operation(&pending_path, &recovering_path).unwrap();

        std::fs::write(&pending_path, "{}").unwrap();
        let pending_error =
            ensure_no_pending_storage_operation(&pending_path, &recovering_path).unwrap_err();
        assert!(pending_error.to_string().contains("already in progress"));

        std::fs::remove_file(&pending_path).unwrap();
        std::fs::write(&recovering_path, "{}").unwrap();
        let recovering_error =
            ensure_no_pending_storage_operation(&pending_path, &recovering_path).unwrap_err();
        assert!(recovering_error.to_string().contains("already in progress"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn pending_storage_operation_save_preserves_existing_journal() {
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
            before_account: Some(account),
            after_account: None,
        };

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
    fn pending_storage_operation_quarantine_unpins_and_preserves_directory() {
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
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn pending_storage_operation_quarantine_unpins_recovering_directory() {
        let root = temp_storage_test_dir("recovering-quarantine-dir");
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
    fn recovering_directory_does_not_mask_valid_pending_journal() {
        let root = temp_storage_test_dir("recovering-dir-with-valid-pending");
        let pending_path = root.join("pending-storage-operation.json");
        let recovering_path = root.join("pending-storage-operation.recovering.json");
        let operation = account_delete_pending_operation();
        let content = serde_json::to_string_pretty(&operation).unwrap();
        write_private_file_atomic(&pending_path, "json.tmp", content.as_bytes()).unwrap();
        std::fs::create_dir(&recovering_path).unwrap();

        let record = load_pending_storage_operation_record_or_quarantine_from_paths(
            &recovering_path,
            &pending_path,
        )
        .unwrap()
        .unwrap();

        assert_eq!(record.path, pending_path);
        assert_eq!(record.operation, operation);
        assert!(pending_path.exists());
        assert!(!recovering_path.exists());
        assert_eq!(
            invalid_storage_operation_entries(
                &root,
                "pending-storage-operation.recovering.invalid."
            )
            .len(),
            1
        );
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
        };

        assert_eq!(
            password_entry_for_account(&file, &"account-1".to_string()).unwrap(),
            "encrypted-one"
        );
        assert!(password_entry_for_account(&file, &"account".to_string()).is_err());
        assert!(password_entry_for_account(&file, &"USER@example.com".to_string()).is_err());
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
        }
    }

    fn account_delete_pending_operation() -> PendingStorageOperation {
        let mut account = Account::new("user@example.com");
        account.id = "account-1".to_string();
        account.has_saved_password = true;
        PendingStorageOperation {
            version: PENDING_STORAGE_OPERATION_VERSION,
            kind: "account_delete".to_string(),
            account_ids: vec![account.id.clone()],
            from_use_keyring: false,
            to_use_keyring: false,
            use_keyring: true,
            before_account: Some(account),
            after_account: None,
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
    fn legacy_target_bound_password_ignores_target_hash() {
        let mut account = Account::new(" User@Example.com ");
        account.id = "account-1".to_string();
        let legacy_envelope = serde_json::json!({
            "version": PASSWORD_ENVELOPE_V2_VERSION,
            "service": SERVICE_NAME,
            "account_id": account.id.clone(),
            "username_sha256": username_binding_hash(&account.username),
            "target_window_title_sha256": sha256_hex(b"legacy-target-hash-is-ignored"),
            "password": "super-secret-password",
        });
        let encoded = format!("{PASSWORD_ENVELOPE_V2_PREFIX}{legacy_envelope}");
        let (decoded, format) = decode_bound_password(&account, &encoded).unwrap();

        assert_eq!(decoded.as_str(), "super-secret-password");
        assert_eq!(format, StoredPasswordFormat::BoundV2);
    }

    #[test]
    fn legacy_raw_password_entries_load_for_migration() {
        let mut account = Account::new("user@example.com");
        account.id = "account-1".to_string();

        let (decoded, format) = decode_bound_password(&account, "super-secret-password").unwrap();

        assert_eq!(decoded.as_str(), "super-secret-password");
        assert_eq!(format, StoredPasswordFormat::LegacyRaw);
    }

    #[test]
    fn encrypted_password_rejects_ciphertext_without_auth_tag() {
        let key = [0u8; 32];
        let truncated = vec![0u8; AES_GCM_NONCE_BYTES + AES_GCM_TAG_BYTES - 1];

        assert!(decrypt_password_with_key(&key, &truncated).is_err());
    }

    #[test]
    fn stale_fallback_cleanup_failure_after_keyring_save_returns_warning() {
        let account_id = "account-1".to_string();

        let warning = cleanup_stale_backend_after_successful_save(
            &account_id,
            PasswordStorageBackend::SystemSecureStorage,
            true,
            |id| {
                assert_eq!(id, "account-1");
                anyhow::bail!("fallback delete failed")
            },
            |_| panic!("keyring cleanup should not run after keyring save"),
        )
        .unwrap();

        assert_eq!(
            warning.saved_backend,
            PasswordStorageBackend::SystemSecureStorage
        );
        assert_eq!(
            warning.stale_backend,
            PasswordStorageBackend::EncryptedFallbackFile
        );
        assert_eq!(warning.error_kind, "storage_error");
    }

    #[test]
    fn stale_keyring_cleanup_failure_after_fallback_save_returns_warning() {
        let account_id = "account-1".to_string();

        let warning = cleanup_stale_backend_after_successful_save(
            &account_id,
            PasswordStorageBackend::EncryptedFallbackFile,
            true,
            |_| panic!("fallback cleanup should not run after fallback save"),
            |id| {
                assert_eq!(id, "account-1");
                anyhow::bail!("keyring delete failed")
            },
        )
        .unwrap();

        assert_eq!(
            warning.saved_backend,
            PasswordStorageBackend::EncryptedFallbackFile
        );
        assert_eq!(
            warning.stale_backend,
            PasswordStorageBackend::SystemSecureStorage
        );
        assert_eq!(warning.error_kind, "secure_storage_unavailable");
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
    fn keyring_backend_cleanup_attempts_all_accounts_after_partial_failure() {
        let account_ids = vec![
            "account-1".to_string(),
            "account-2".to_string(),
            "account-3".to_string(),
        ];
        let attempted = RefCell::new(Vec::new());

        let error = cleanup_storage_backend_with_ops(
            &account_ids,
            true,
            |_| panic!("fallback cleanup should not run for keyring backend"),
            |account_id| {
                attempted.borrow_mut().push(account_id.clone());
                if account_id == "account-1" {
                    anyhow::bail!("delete failed")
                }
                Ok(())
            },
            || panic!("fallback key cleanup should not run for keyring backend"),
        )
        .unwrap_err()
        .to_string();

        assert_eq!(attempted.into_inner(), account_ids);
        assert!(error.contains("stale system secure storage cleanup incomplete"));
        assert!(error.contains("1 of 3 account cleanup attempts failed"));
    }

    #[test]
    fn fallback_backend_cleanup_attempts_all_accounts_after_partial_failure() {
        let account_ids = vec![
            "account-1".to_string(),
            "account-2".to_string(),
            "account-3".to_string(),
        ];
        let attempted = RefCell::new(Vec::new());
        let fallback_key_cleanup_calls = RefCell::new(0);

        let error = cleanup_storage_backend_with_ops(
            &account_ids,
            false,
            |account_id| {
                attempted.borrow_mut().push(account_id.clone());
                if account_id == "account-2" {
                    anyhow::bail!("fallback delete failed")
                }
                Ok(())
            },
            |_| panic!("keyring cleanup should not run for fallback backend"),
            || {
                *fallback_key_cleanup_calls.borrow_mut() += 1;
                Ok(())
            },
        )
        .unwrap_err()
        .to_string();

        assert_eq!(attempted.into_inner(), account_ids);
        assert_eq!(*fallback_key_cleanup_calls.borrow(), 1);
        assert!(error.contains("stale encrypted fallback file cleanup incomplete"));
        assert!(error.contains("1 of 3 account cleanup attempts failed"));
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
    fn empty_fallback_password_file_triggers_key_cleanup() {
        let file = PasswordFile::default();
        let mut cleanup_calls = 0;

        cleanup_fallback_key_if_password_file_empty(&file, || {
            cleanup_calls += 1;
            Ok(())
        })
        .unwrap();

        assert_eq!(cleanup_calls, 1);
    }

    #[test]
    fn non_empty_fallback_password_file_keeps_key() {
        let file = PasswordFile {
            passwords: HashMap::from([("account-1".to_string(), "encrypted".to_string())]),
        };
        let mut cleanup_calls = 0;

        cleanup_fallback_key_if_password_file_empty(&file, || {
            cleanup_calls += 1;
            Ok(())
        })
        .unwrap();

        assert_eq!(cleanup_calls, 0);
    }

    #[test]
    fn fallback_key_cleanup_failure_is_reported() {
        let file = PasswordFile::default();
        let error = cleanup_fallback_key_if_password_file_empty(&file, || {
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
        };

        assert!(validate_password_file_shape(&file).is_err());
    }

    #[test]
    fn password_file_shape_rejects_invalid_account_ids() {
        let file = PasswordFile {
            passwords: HashMap::from([("".to_string(), "encrypted".to_string())]),
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

        backup_invalid_file(&config_path).unwrap();
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
            storage_error_kind(&anyhow::anyhow!("NoEntry for secret=super-secret")),
            "not_found"
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
}
