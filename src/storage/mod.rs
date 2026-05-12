use crate::models::{Account, AccountId, AppConfig};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

const SERVICE_NAME: &str = "WindowsAppAutoLogin";
const FALLBACK_KEY_SERVICE_NAME: &str = "WindowsAppAutoLoginFallbackKey";
const FALLBACK_KEY_ACCOUNT: &str = "fallback-encryption-key";
const CONFIG_FILE_NAME: &str = "config.json";
const PASSWORD_FILE_NAME: &str = "passwords.json";
const FALLBACK_KEY_FILE_NAME: &str = "fallback.key";

pub(crate) fn keychain_service_name() -> &'static str {
    SERVICE_NAME
}

#[derive(Debug, serde::Deserialize)]
#[serde(default)]
struct LegacyConfig {
    process_names: Vec<String>,
    poll_interval_secs: u64,
    credentials: Option<LegacyCredentialsConfig>,
    macos_app_name: Option<String>,
}

impl Default for LegacyConfig {
    fn default() -> Self {
        Self {
            process_names: vec![
                "Windows App".to_string(),
                "Microsoft Remote Desktop".to_string(),
            ],
            poll_interval_secs: 1,
            credentials: None,
            macos_app_name: None,
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
    if let Some(dir) = dirs::config_dir() {
        return Ok(dir.join("WindowsAppAutoLogin"));
    }
    if let Some(home) = dirs::home_dir() {
        return Ok(home.join(".config").join("WindowsAppAutoLogin"));
    }
    anyhow::bail!("unable to resolve a private config directory for credential storage")
}

fn config_file() -> anyhow::Result<PathBuf> {
    Ok(config_dir()?.join(CONFIG_FILE_NAME))
}

fn ensure_config_dir() -> anyhow::Result<()> {
    let dir = config_dir()?;
    if !dir.exists() {
        match std::fs::create_dir_all(&dir) {
            Ok(()) => {
                debug!(dir = %dir.display(), "Config directory created");
            }
            Err(e) => {
                warn!(dir = %dir.display(), error = %e, "Failed to create config directory");
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

    let mut permissions = std::fs::metadata(path)?.permissions();
    permissions.set_mode(mode);
    std::fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn secure_path_permissions(_path: &Path, _mode: u32) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn validate_private_dir(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() {
        anyhow::bail!("{} is not a private directory", path.display());
    }
    if metadata.uid() != unsafe { libc::geteuid() } {
        anyhow::bail!("{} is not owned by the current user", path.display());
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        secure_path_permissions(path, 0o700)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_dir(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn validate_private_file_for_read(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        anyhow::bail!("{} is not a regular private file", path.display());
    }
    if metadata.uid() != unsafe { libc::geteuid() } {
        anyhow::bail!("{} is not owned by the current user", path.display());
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        secure_path_permissions(path, 0o600)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_file_for_read(_path: &Path) -> anyhow::Result<()> {
    Ok(())
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
        Ok(config) => config,
        Err(e) => {
            warn!(path = %path.display(), error = %e, "Failed to load config; using defaults");
            if let Err(backup_error) = backup_invalid_file(&path) {
                warn!(path = %path.display(), error = %backup_error, "Failed to back up invalid config before using defaults");
            }
            AppConfig::default()
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

    let content = std::fs::read_to_string(path)?;
    let value: serde_json::Value = serde_json::from_str(&content)?;
    if value.get("accounts").is_some() || value.get("settings").is_some() {
        return Ok(serde_json::from_value(value)?);
    }

    let legacy: LegacyConfig = serde_json::from_value(value)?;
    Ok(migrate_legacy_config(legacy))
}

fn migrate_legacy_config(legacy: LegacyConfig) -> AppConfig {
    let mut config = AppConfig::default();
    config.settings.poll_interval_secs = legacy.poll_interval_secs;
    config.settings.macos_app_name = legacy
        .macos_app_name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| legacy.process_names.first().cloned())
        .unwrap_or_else(|| "Windows App".to_string());

    if let Some(credentials) = legacy.credentials {
        let username = credentials.username.trim().to_string();
        if !username.is_empty() {
            let mut account = Account::new(&username);
            if let Some(account_id) = credentials
                .account_id
                .filter(|account_id| !account_id.contains('@'))
            {
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

pub(crate) fn save_config(config: &AppConfig) -> anyhow::Result<()> {
    ensure_config_dir()?;
    config.save(config_file()?)
}

fn backup_invalid_file(path: &Path) -> anyhow::Result<()> {
    if !path.exists() {
        return Ok(());
    }

    let timestamp = chrono::Local::now().format("%Y%m%d%H%M%S");
    let backup_path = path.with_extension(format!("json.invalid.{timestamp}"));
    let result = match std::fs::copy(path, &backup_path) {
        Ok(_) => Ok(()),
        Err(copy_error) => match std::fs::rename(path, &backup_path) {
            Ok(()) => Ok(()),
            Err(rename_error) => Err(anyhow::anyhow!(
                "copy backup failed: {copy_error}; rename backup failed: {rename_error}"
            )),
        },
    };
    if result.is_ok() {
        secure_path_permissions(&backup_path, 0o600).ok();
    }
    result
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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
struct PasswordFile {
    #[serde(default)]
    passwords: HashMap<String, String>,
}

fn load_password_file() -> anyhow::Result<PasswordFile> {
    let path = password_file_path()?;
    if !path.exists() {
        return Ok(PasswordFile::default());
    }
    validate_private_file_for_read(&path)?;
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => {
            warn!(path = %path.display(), error = %e, "Failed to read password file");
            return Err(e.into());
        }
    };
    let file: PasswordFile = match serde_json::from_str::<PasswordFile>(&content) {
        Ok(f) => f,
        Err(e) => {
            warn!(path = %path.display(), error = %e, "Failed to parse password file JSON");
            return Err(e.into());
        }
    };
    Ok(file)
}

fn save_password_file(file: &PasswordFile) -> anyhow::Result<()> {
    ensure_config_dir()?;
    let path = password_file_path()?;
    let content = match serde_json::to_string_pretty(file) {
        Ok(c) => c,
        Err(e) => {
            warn!(path = %path.display(), error = %e, "Failed to serialize password file");
            return Err(e.into());
        }
    };
    write_private_file_atomic(&path, "json.tmp", content.as_bytes())?;
    debug!(path = %path.display(), entries = file.passwords.len(), "Password file written");
    Ok(())
}

fn write_private_file_atomic(
    path: &Path,
    temp_extension: &str,
    bytes: &[u8],
) -> anyhow::Result<()> {
    use std::io::Write;

    let temp_path = path.with_extension(temp_extension);
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
        file.write_all(bytes)?;
        file.sync_all().ok();
    }

    #[cfg(not(unix))]
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)?;
        file.write_all(bytes)?;
        file.sync_all().ok();
    }

    secure_path_permissions(&temp_path, 0o600)?;
    std::fs::rename(&temp_path, path)?;
    Ok(())
}

fn legacy_encryption_key() -> [u8; 32] {
    let hostname = whoami::fallible::hostname().unwrap_or_else(|_| "unknown-host".to_string());
    let username = whoami::username();
    let input = format!("{}:{}", hostname, username);
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

fn fallback_encryption_key() -> anyhow::Result<[u8; 32]> {
    ensure_config_dir()?;

    let entry = keyring::Entry::new(FALLBACK_KEY_SERVICE_NAME, FALLBACK_KEY_ACCOUNT)
        .map_err(|e| anyhow::anyhow!("macOS Keychain is unavailable for fallback key: {e}"))?;
    match entry.get_password() {
        Ok(encoded) => return decode_fallback_encryption_key(encoded.trim()),
        Err(keyring::Error::NoEntry) => {}
        Err(e) => anyhow::bail!("macOS Keychain refused to load fallback key: {e}"),
    }

    if let Some(legacy_key) = load_legacy_fallback_key_from_file()? {
        entry
            .set_password(&STANDARD.encode(legacy_key))
            .map_err(|e| anyhow::anyhow!("macOS Keychain refused to migrate fallback key: {e}"))?;
        return Ok(legacy_key);
    }

    let mut key = [0u8; 32];
    rand::thread_rng().fill(&mut key);
    entry
        .set_password(&STANDARD.encode(key))
        .map_err(|e| anyhow::anyhow!("macOS Keychain refused to save fallback key: {e}"))?;
    Ok(key)
}

fn load_legacy_fallback_key_from_file() -> anyhow::Result<Option<[u8; 32]>> {
    let path = fallback_key_file_path()?;
    if !path.exists() {
        return Ok(None);
    }

    let key = match read_fallback_encryption_key(&path) {
        Ok(key) => key,
        Err(e) => {
            warn!(path = %path.display(), error = %e, "Fallback key file is invalid; backing it up");
            backup_invalid_file(&path).ok();
            std::fs::remove_file(&path).ok();
            return Ok(None);
        }
    };

    if let Err(e) = std::fs::remove_file(&path) {
        anyhow::bail!(
            "fallback key was migrated to Keychain, but stale key file cleanup failed: {e}"
        );
    }
    Ok(Some(key))
}

fn read_fallback_encryption_key(path: &Path) -> anyhow::Result<[u8; 32]> {
    validate_private_file_for_read(path)?;
    let content = std::fs::read_to_string(path)?;
    decode_fallback_encryption_key(content.trim())
}

fn decode_fallback_encryption_key(encoded: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = STANDARD.decode(encoded)?;
    if bytes.len() != 32 {
        anyhow::bail!("invalid fallback key length");
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

fn encrypt_password(plaintext: &str) -> anyhow::Result<String> {
    let key = fallback_encryption_key()?;
    let cipher = Aes256Gcm::new_from_slice(&key)
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
    if data.len() < 12 {
        anyhow::bail!("invalid ciphertext: too short");
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| anyhow::anyhow!("failed to create cipher: {:?}", e))?;
    let nonce = Nonce::from_slice(&data[..12]);
    let plaintext = cipher
        .decrypt(nonce, &data[12..])
        .map_err(|e| anyhow::anyhow!("decryption failed: {:?}", e))?;
    Ok(Zeroizing::new(String::from_utf8(plaintext)?))
}

fn decrypt_password(b64: &str) -> anyhow::Result<(Zeroizing<String>, bool)> {
    let data = STANDARD.decode(b64)?;
    let legacy_key = legacy_encryption_key();
    let stable_key = fallback_encryption_key();

    match stable_key {
        Ok(key) => match decrypt_password_with_key(&key, &data) {
            Ok(password) => Ok((password, false)),
            Err(stable_error) => {
                if legacy_key == key {
                    return Err(stable_error);
                }

                decrypt_password_with_key(&legacy_key, &data)
                    .map(|password| (password, true))
                    .map_err(|legacy_error| {
                        anyhow::anyhow!(
                            "decryption failed with fallback key ({stable_error}) and legacy key ({legacy_error})"
                        )
                    })
            }
        },
        Err(stable_error) => {
            decrypt_password_with_key(&legacy_key, &data).map_err(|legacy_error| {
                anyhow::anyhow!(
                    "fallback key unavailable ({stable_error}); legacy decrypt failed ({legacy_error})"
                )
            })
            .map(|password| (password, true))
        }
    }
}

fn save_to_file(account_id: &AccountId, password: &str) -> anyhow::Result<()> {
    let mut file = load_password_file()?;
    let encrypted = match encrypt_password(password) {
        Ok(enc) => enc,
        Err(e) => {
            warn!(account_id = %account_id, error = %e, "Failed to encrypt password");
            return Err(e);
        }
    };
    file.passwords.insert(account_id.clone(), encrypted);
    match save_password_file(&file) {
        Ok(()) => {}
        Err(e) => {
            warn!(account_id = %account_id, error = %e, "save_password_file failed");
            return Err(e);
        }
    }
    Ok(())
}

fn load_from_file(account_id: &AccountId) -> anyhow::Result<Zeroizing<String>> {
    let mut file = load_password_file()?;
    let encrypted = password_entry_for_account(&file, account_id)?.to_string();
    let (password, used_legacy_key) = decrypt_password(&encrypted)?;

    if used_legacy_key {
        match encrypt_password(password.as_str()) {
            Ok(reencrypted) => {
                file.passwords.insert(account_id.clone(), reencrypted);
                if let Err(e) = save_password_file(&file) {
                    warn!(account_id = %account_id, error = %e, "Password loaded with legacy fallback key, but migration to stable key failed");
                } else {
                    info!(account_id = %account_id, "Migrated fallback password to stable key");
                }
            }
            Err(e) => {
                warn!(account_id = %account_id, error = %e, "Password loaded with legacy fallback key, but re-encryption failed");
            }
        }
    }

    Ok(password)
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

fn delete_from_keyring(account_id: &AccountId) -> anyhow::Result<()> {
    let entry = keyring::Entry::new(SERVICE_NAME, account_id)?;
    match entry.delete_credential() {
        Ok(()) => {
            debug!(account_id = %account_id, "Keyring credential deleted");
            Ok(())
        }
        Err(keyring::Error::NoEntry) => {
            debug!(account_id = %account_id, "Keyring credential did not exist");
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

fn save_password(account_id: &AccountId, password: &str, use_keyring: bool) -> anyhow::Result<()> {
    debug!(account_id = %account_id, use_keyring, "save_password called");
    if use_keyring {
        let entry = keyring::Entry::new(SERVICE_NAME, account_id)
            .map_err(|e| anyhow::anyhow!("macOS Keychain is unavailable: {e}"))?;
        match entry.set_password(password) {
            Ok(()) => {
                if let Err(e) = delete_from_file(account_id) {
                    warn!(
                        account_id = %account_id,
                        error = %e,
                        "Password saved to keyring; stale fallback cleanup failed"
                    );
                    return Err(e);
                } else {
                    debug!(account_id = %account_id, "Stale fallback file entry cleaned up");
                }
                info!(account_id = %account_id, "Password saved to secure storage successfully");
                return Ok(());
            }
            Err(e) => anyhow::bail!("macOS Keychain refused to save the password: {e}"),
        }
    } else {
        warn!(
            account_id = %account_id,
            "Keyring disabled; using weaker local encrypted file storage by explicit setting"
        );
    }
    match save_to_file(account_id, password) {
        Ok(()) => {}
        Err(e) => {
            warn!(account_id = %account_id, error = %e, "save_to_file failed");
            return Err(e);
        }
    }
    info!(
        account_id = %account_id,
        "Password saved to fallback encrypted file storage"
    );
    if let Err(e) = delete_from_keyring(account_id) {
        warn!(
            account_id = %account_id,
            error = %e,
            "Password saved to fallback storage; stale keyring cleanup failed"
        );
        return Err(e);
    }
    Ok(())
}

pub(crate) fn load_password(
    account_id: &AccountId,
    use_keyring: bool,
) -> anyhow::Result<Zeroizing<String>> {
    load_password_with_timing(account_id, use_keyring)
        .map(|result| result.password)
        .map_err(anyhow::Error::from)
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
    account_id: &AccountId,
    use_keyring: bool,
) -> Result<PasswordLoadResult, Box<PasswordLoadError>> {
    let total_start = std::time::Instant::now();
    let mut timing = PasswordLoadTiming::default();
    debug!(account_id = %account_id, use_keyring, "load_password called");
    let result = if use_keyring {
        let keychain_start = std::time::Instant::now();
        timing.keychain_query_start_ms = total_start.elapsed().as_millis();
        let result = load_from_keyring_timed(account_id);
        timing.keychain_query_ms = keychain_start.elapsed().as_millis();
        timing.keychain_prompt_suspected = timing.keychain_query_ms > 1_000;
        result
    } else {
        let fallback_start = std::time::Instant::now();
        let result = load_from_file(account_id).map(|password| (password, 0));
        timing.fallback_lookup_ms = fallback_start.elapsed().as_millis();
        result
    };

    timing.total_password_load_ms = total_start.elapsed().as_millis();
    match result {
        Ok((password, zeroizing_wrap_ms)) => {
            timing.zeroizing_wrap_ms = zeroizing_wrap_ms;
            Ok(PasswordLoadResult { password, timing })
        }
        Err(e) => {
            let kind = storage_error_kind(&e);
            warn!(
                account_id = %account_id,
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
        account_id = %account_id,
        use_keyring,
        error_kind = %storage_error_kind(&error),
        "Password load failed"
    );
    anyhow::anyhow!("password could not be loaded from configured secure storage")
}

fn load_from_keyring_timed(account_id: &AccountId) -> anyhow::Result<(Zeroizing<String>, u128)> {
    let entry = keyring::Entry::new(SERVICE_NAME, account_id)?;
    let password = entry.get_password()?;
    let zeroizing_start = std::time::Instant::now();
    let password = Zeroizing::new(password);
    let zeroizing_wrap_ms = zeroizing_start.elapsed().as_millis();
    debug!(account_id = %account_id, "Password loaded from secure storage");
    Ok((password, zeroizing_wrap_ms))
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
    } else if message.contains("Keychain") || message.contains("keyring") {
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

    info!(account_id = %account_id, "Password deleted from all storage locations");
    Ok(())
}

pub(crate) fn save_account(
    account: &Account,
    password: &str,
    use_keyring: bool,
) -> anyhow::Result<()> {
    debug!(account_id = %account.id, use_keyring, "save_account called");
    if password.is_empty() {
        warn!(account_id = %account.id, "save_account received empty password, skipping keyring storage");
    } else {
        save_password(&account.id, password, use_keyring)?;
    }
    Ok(())
}

pub(crate) fn delete_account(account_id: &AccountId) -> anyhow::Result<()> {
    debug!(account_id = %account_id, "delete_account called");
    if let Err(e) = delete_password(account_id) {
        debug!(
            account_id = %account_id,
            error = %e,
            "Error during password deletion (may already be gone)"
        );
        return Err(e);
    } else {
        info!(account_id = %account_id, "delete_account completed successfully");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        migrate_legacy_config, password_entry_for_account, redact_password_load_error,
        storage_error_kind, LegacyConfig, LegacyCredentialsConfig, PasswordFile,
    };
    use crate::models::{Account, AppConfig};
    use std::collections::HashMap;

    #[test]
    fn legacy_migration_uses_first_process_name_when_app_name_is_missing() {
        let legacy = LegacyConfig {
            process_names: vec!["Microsoft Remote Desktop".to_string()],
            macos_app_name: None,
            ..LegacyConfig::default()
        };

        let config = migrate_legacy_config(legacy);

        assert_eq!(
            config.settings.macos_app_name,
            "Microsoft Remote Desktop".to_string()
        );
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

        let config = migrate_legacy_config(legacy);

        assert_eq!(config.accounts[0].username, "user@example.com");
        assert_ne!(config.accounts[0].id, "user@example.com");
        assert!(!config.accounts[0].id.contains('@'));
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
}
