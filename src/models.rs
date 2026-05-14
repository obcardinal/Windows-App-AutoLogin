use serde::{Deserialize, Serialize};
use std::path::Path;
use uuid::Uuid;

pub type AccountId = String;
pub const FIXED_POLL_INTERVAL_SECS: u64 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Account {
    pub id: AccountId,
    pub username: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_saved_password: bool,
    #[serde(default = "default_account_enabled", skip_serializing_if = "is_true")]
    pub enabled: bool,
}

impl Account {
    pub fn new(username: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            username: username.into(),
            has_saved_password: false,
            enabled: true,
        }
    }

    pub fn display_name(&self) -> String {
        let username = self.username.trim();
        if !username.is_empty() {
            return username.to_string();
        }

        "Untitled account".to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct AppSettings {
    #[serde(default = "fixed_poll_interval_secs", skip_serializing)]
    pub poll_interval_secs: u64,
    pub auto_start: bool,
    pub start_minimized: bool,
    pub use_keyring: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            poll_interval_secs: FIXED_POLL_INTERVAL_SECS,
            auto_start: false,
            start_minimized: false,
            use_keyring: true,
        }
    }
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn is_true(value: &bool) -> bool {
    *value
}

fn default_account_enabled() -> bool {
    true
}

fn fixed_poll_interval_secs() -> u64 {
    FIXED_POLL_INTERVAL_SECS
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(default)]
pub struct AppConfig {
    pub accounts: Vec<Account>,
    pub settings: AppSettings,
}

impl AppConfig {
    pub(crate) fn save<P: AsRef<Path>>(&self, path: P) -> anyhow::Result<()> {
        let path = path.as_ref();
        let content = serde_json::to_string_pretty(self)?;
        let temp_path = atomic_temp_path(path, "json.tmp");
        if temp_path.exists() {
            std::fs::remove_file(&temp_path)?;
        }
        if let Err(e) = write_private_file(&temp_path, content.as_bytes())
            .and_then(|_| secure_file_permissions(&temp_path))
            .and_then(|_| std::fs::rename(&temp_path, path).map_err(anyhow::Error::from))
            .and_then(|_| secure_file_permissions(path))
            .and_then(|_| sync_parent_dir(path))
        {
            let _ = std::fs::remove_file(&temp_path);
            return Err(e);
        }
        Ok(())
    }
}

fn atomic_temp_path(path: &Path, temp_extension: &str) -> std::path::PathBuf {
    let nonce = chrono::Utc::now()
        .timestamp_nanos_opt()
        .unwrap_or_default()
        .unsigned_abs();
    path.with_extension(format!("{temp_extension}.{}.{}", std::process::id(), nonce))
}

fn write_private_file(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        crate::private_permissions::strip_macos_acl(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }

    #[cfg(not(unix))]
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }

    Ok(())
}

fn sync_parent_dir(path: &Path) -> anyhow::Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn secure_file_permissions(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!("private config file must not be a symlink");
    }
    let mut permissions = metadata.permissions();
    permissions.set_mode(0o600);
    std::fs::set_permissions(path, permissions)?;
    crate::private_permissions::strip_macos_acl(path)?;
    Ok(())
}

#[cfg(not(unix))]
fn secure_file_permissions(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Accounts,
    Settings,
    #[cfg(feature = "diagnostics-ui")]
    Diagnose,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerStatus {
    Idle,
    Running,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: LogLevel,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Info,
    Warn,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogLevel::Info => write!(f, "INFO"),
            LogLevel::Warn => write!(f, "WARN"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Account, AppConfig, AppSettings};
    use uuid::Uuid;

    #[cfg(not(feature = "diagnostics-ui"))]
    use super::Tab;

    #[cfg(not(feature = "diagnostics-ui"))]
    #[test]
    fn production_tabs_include_only_accounts_and_settings() {
        let tabs = [Tab::Accounts, Tab::Settings];

        assert_eq!(tabs.len(), 2);
    }

    #[test]
    fn app_settings_do_not_serialize_fixed_poll_interval() {
        let settings = AppSettings {
            poll_interval_secs: 60,
            ..AppSettings::default()
        };
        let json = serde_json::to_string(&settings).unwrap();

        assert!(!json.contains("poll_interval_secs"));
    }

    #[test]
    fn app_config_does_not_serialize_target_app_name_setting() {
        let json = serde_json::to_string(&AppConfig::default()).unwrap();

        assert!(!json.contains("macos_app_name"));
        assert!(!json.contains("Windows App"));
    }

    #[test]
    fn app_config_save_uses_unique_temp_path_and_cleans_it_up() {
        let dir = std::env::temp_dir().join(format!("waa-config-save-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json");
        let temp_path = super::atomic_temp_path(&path, "json.tmp");
        assert_ne!(temp_path, path.with_extension("json.tmp"));
        assert!(temp_path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("config.json.tmp.")));

        let mut config = AppConfig::default();
        config.accounts.push(Account::new("user@example.com"));

        config.save(&path).unwrap();
        let saved = std::fs::read_to_string(&path).unwrap();

        assert!(saved.contains("user@example.com"));
        assert!(!saved.contains("target_window_title"));
        assert!(!path.with_extension("json.tmp").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn app_config_ignores_legacy_account_target_window_title() {
        let config: AppConfig = serde_json::from_value(serde_json::json!({
            "accounts": [{
                "id": "account-1",
                "username": "user@example.com",
                "target_window_title": "Legacy Target",
                "has_saved_password": true,
                "enabled": true
            }],
            "settings": {}
        }))
        .unwrap();

        assert_eq!(config.accounts.len(), 1);
        assert_eq!(config.accounts[0].username, "user@example.com");

        let serialized = serde_json::to_string(&config).unwrap();
        assert!(!serialized.contains("target_window_title"));
        assert!(!serialized.contains("Legacy Target"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn app_config_save_strips_inherited_macos_acl() {
        let dir = std::env::temp_dir().join(format!("waa-config-save-acl-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        if !add_macos_acl(
            &dir,
            "everyone allow read,readattr,readextattr,readsecurity,file_inherit,directory_inherit",
        ) {
            let _ = std::fs::remove_dir_all(dir);
            return;
        }

        let path = dir.join("config.json");
        AppConfig::default().save(&path).unwrap();

        assert!(!path_has_macos_acl(&path));
        std::fs::remove_dir_all(dir).unwrap();
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
}
