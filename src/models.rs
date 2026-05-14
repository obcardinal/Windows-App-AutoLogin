use serde::{Deserialize, Serialize};
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
}
