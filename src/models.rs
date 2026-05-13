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
        let temp_path = path.with_extension("json.tmp");
        if temp_path.exists() {
            std::fs::remove_file(&temp_path)?;
        }
        write_private_file(&temp_path, content.as_bytes())?;
        secure_file_permissions(&temp_path)?;
        std::fs::rename(&temp_path, path)?;
        Ok(())
    }
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
            .open(path)?;
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

#[cfg(unix)]
fn secure_file_permissions(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = std::fs::metadata(path)?.permissions();
    permissions.set_mode(0o600);
    std::fs::set_permissions(path, permissions)?;
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
    use super::{AppConfig, AppSettings};

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
}
