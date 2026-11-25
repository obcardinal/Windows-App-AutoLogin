use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub type AccountId = String;
pub const FIXED_POLL_INTERVAL_SECS: u64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct DesktopShortcut {
    pub modifiers: u8,
    pub key: char,
}

impl DesktopShortcut {
    pub const CONTROL: u8 = 1;
    pub const OPTION: u8 = 2;
    pub const SHIFT: u8 = 4;
    pub const COMMAND: u8 = 8;

    pub fn new(modifiers: u8, key: char) -> Option<Self> {
        let required = Self::CONTROL | Self::OPTION | Self::COMMAND;
        let supported = required | Self::SHIFT;
        (modifiers & required != 0 && modifiers & !supported == 0 && key.is_ascii_alphanumeric())
            .then(|| Self {
                modifiers,
                key: key.to_ascii_uppercase(),
            })
    }

    pub(crate) fn deserialize_optional<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Self>, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct ShortcutWire {
            modifiers: u8,
            key: char,
        }

        // An unsupported binding disables just this shortcut, including when a
        // newer version stores a different key or modifier representation.
        let value = serde_json::Value::deserialize(deserializer)?;
        Ok(serde_json::from_value::<ShortcutWire>(value)
            .ok()
            .and_then(|binding| Self::new(binding.modifiers, binding.key)))
    }
}

impl std::fmt::Display for DesktopShortcut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (flag, symbol) in [
            (Self::CONTROL, "⌃"),
            (Self::OPTION, "⌥"),
            (Self::SHIFT, "⇧"),
            (Self::COMMAND, "⌘"),
        ] {
            if self.modifiers & flag != 0 {
                f.write_str(symbol)?;
            }
        }
        write!(f, "{}", self.key)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticatorProvider {
    #[default]
    MicrosoftAuthenticator,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Account {
    pub id: AccountId,
    pub username: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub remote_pc: String,
    /// Saved Windows App device name on macOS or published desktop resource ID on Windows.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub vm_target: String,
    /// Windows App profile that owned the device when it was chosen on macOS.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub vm_profile: String,
    /// Windows App catalog identifier, or "open-window" for a window-only macOS link.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub vm_device_id: String,
    #[serde(
        default,
        deserialize_with = "DesktopShortcut::deserialize_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub desktop_shortcut: Option<DesktopShortcut>,
    /// Reconnect this linked VM on macOS when its focused window shows the Windows password screen.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub reconnect_locked_vm: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_saved_password: bool,
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub iphone_authenticator_enabled: bool,
}

impl Account {
    pub fn new(username: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            username: username.into(),
            remote_pc: String::new(),
            vm_target: String::new(),
            vm_profile: String::new(),
            vm_device_id: String::new(),
            desktop_shortcut: None,
            reconnect_locked_vm: true,
            has_saved_password: false,
            enabled: true,
            iphone_authenticator_enabled: false,
        }
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn locked_vm_reconnect_enabled(&self) -> bool {
        let catalog_binding = self.vm_device_id.starts_with("workspace:")
            || self.vm_device_id.starts_with("bookmark:");
        let window_binding = !self.vm_target.trim().is_empty()
            && (self.vm_device_id == "open-window"
                || (self.vm_device_id.is_empty() && !self.vm_profile.trim().is_empty()));
        self.enabled
            && self.reconnect_locked_vm
            && self.has_saved_password
            && (catalog_binding || window_binding)
    }

    pub fn display_name(&self) -> String {
        let username = self.username.trim();
        if !username.is_empty() {
            return username.to_string();
        }

        "Untitled account".to_string()
    }
}

/// Normalize a Remote PC host locally without resolving DNS aliases or suffixes.
pub(crate) fn canonical_remote_pc(value: &str) -> Option<String> {
    use std::net::{IpAddr, Ipv6Addr};

    let host = value.trim();
    if let Some(literal) = host.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        return literal.parse::<Ipv6Addr>().ok().map(|ip| ip.to_string());
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(ip.to_string());
    }
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() || host.len() > 253 {
        return None;
    }
    // Numeric addresses must be unambiguous IPv4, not shorthand or octal.
    if host.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return host
            .parse::<std::net::Ipv4Addr>()
            .ok()
            .map(|ip| ip.to_string());
    }
    let valid = host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    });
    valid.then(|| host.to_ascii_lowercase())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct AppSettings {
    #[serde(default = "fixed_poll_interval_secs", skip_serializing)]
    pub poll_interval_secs: u64,
    pub auto_start: bool,
    pub start_minimized: bool,
    /// Hide the macOS menu-bar icon or Windows system-tray icon.
    pub hide_menu_bar_icon: bool,
    pub show_menu_diagnostics: bool,
    pub close_connection_center_after_connect: bool,
    pub use_keyring: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            poll_interval_secs: FIXED_POLL_INTERVAL_SECS,
            auto_start: false,
            start_minimized: false,
            hide_menu_bar_icon: false,
            show_menu_diagnostics: false,
            close_connection_center_after_connect: true,
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

pub(crate) fn default_true() -> bool {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MonitorControlState {
    Running,
    PausedWithStartIntent,
    Stopped,
}

impl MonitorControlState {
    pub(crate) fn from_worker_and_intent(
        worker_status: WorkerStatus,
        desired_monitor_running: bool,
    ) -> Self {
        if !desired_monitor_running {
            Self::Stopped
        } else if worker_status == WorkerStatus::Running {
            Self::Running
        } else {
            Self::PausedWithStartIntent
        }
    }

    pub(crate) fn worker_status(self) -> WorkerStatus {
        match self {
            Self::Running => WorkerStatus::Running,
            Self::PausedWithStartIntent | Self::Stopped => WorkerStatus::Idle,
        }
    }

    pub(crate) fn toggle_requests_stop(self) -> bool {
        !matches!(self, Self::Stopped)
    }

    pub(crate) fn toggle_label(self) -> &'static str {
        if self.toggle_requests_stop() {
            "Stop Monitor"
        } else {
            "Start Monitor"
        }
    }
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
    use super::{AppConfig, AppSettings, DesktopShortcut, MonitorControlState, WorkerStatus};

    #[test]
    fn desktop_shortcut_accepts_modified_letters_and_digits() {
        use DesktopShortcut as Key;

        let mods = Key::CONTROL | Key::OPTION | Key::SHIFT | Key::COMMAND;
        let shortcut = Key::new(mods, 'w').unwrap();
        assert_eq!(shortcut, Key::new(mods, 'W').unwrap());
        assert_eq!(shortcut.to_string(), "⌃⌥⇧⌘W");
        assert_eq!(Key::new(Key::OPTION, '2').unwrap().to_string(), "⌥2");
        for (modifiers, key) in [
            (0, 'a'),
            (Key::SHIFT, 'a'),
            (Key::CONTROL | 16, 'a'),
            (Key::COMMAND, 'ß'),
            (Key::COMMAND, ' '),
        ] {
            assert_eq!(Key::new(modifiers, key), None);
        }
    }

    #[test]
    fn app_config_serialization_omits_fixed_and_removed_settings() {
        let settings = AppSettings {
            poll_interval_secs: 60,
            ..AppSettings::default()
        };
        let settings_json = serde_json::to_string(&settings).unwrap();
        let config_json = serde_json::to_string(&AppConfig::default()).unwrap();

        assert!(!settings_json.contains("poll_interval_secs"));
        assert!(!config_json.contains("macos_app_name"));
        assert!(!config_json.contains("Windows App"));
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
        assert!(config.accounts[0].remote_pc.is_empty());
        assert!(config.accounts[0].reconnect_locked_vm);
        assert!(!config.accounts[0].iphone_authenticator_enabled);

        let serialized = serde_json::to_string(&config).unwrap();
        assert!(!serialized.contains("target_window_title"));
        assert!(!serialized.contains("Legacy Target"));
        assert!(!serialized.contains("iphone_authenticator_enabled"));
        assert!(!serialized.contains("remote_pc"));
        assert!(!serialized.contains("reconnect_locked_vm"));
    }

    #[test]
    fn new_account_defaults_to_reconnect_and_remembers_explicit_off() {
        let mut account = super::Account::new("user@example.test");
        assert!(account.reconnect_locked_vm);
        account.reconnect_locked_vm = false;
        let wire = serde_json::to_value(&account).unwrap();
        assert_eq!(wire["reconnect_locked_vm"], false);
        assert_eq!(
            serde_json::from_value::<super::Account>(wire).unwrap(),
            account
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn default_reconnect_requires_a_saved_password_and_a_linked_desktop() {
        let mut account = super::Account::new("user@example.test");
        account.has_saved_password = true;
        for (device, title, profile, eligible) in [
            ("", "", "", false),
            ("", "Desktop", "", false),
            ("open-window", "", "", false),
            ("open-window", "Desktop", "", true),
            ("", "Desktop", "user@example.test", true),
            ("workspace:one", "", "", true),
            ("bookmark:one", "Desktop", "", true),
        ] {
            account.vm_device_id = device.into();
            account.vm_target = title.into();
            account.vm_profile = profile.into();
            assert_eq!(account.locked_vm_reconnect_enabled(), eligible);
        }
        account.has_saved_password = false;
        assert!(!account.locked_vm_reconnect_enabled());
        account.has_saved_password = true;
        account.enabled = false;
        assert!(!account.locked_vm_reconnect_enabled());
    }

    #[test]
    fn canonical_remote_pc_rejects_ambiguous_addresses_and_accepts_exact_hosts() {
        for (input, expected) in [
            ("  Cloud-PC.Example.NET. ", "cloud-pc.example.net"),
            ("Cloud-123", "cloud-123"),
            ("192.0.2.1", "192.0.2.1"),
            ("[2001:DB8::01]", "2001:db8::1"),
            ("2001:db8:0:0::1", "2001:db8::1"),
        ] {
            assert_eq!(super::canonical_remote_pc(input).as_deref(), Some(expected));
        }
        for input in [
            "",
            " ",
            "rdp://host",
            "host/path",
            "user@host",
            "host:3389",
            "[2001:db8::1]:3389",
            "*.example.net",
            ".example.net",
            "host..net",
            "host..",
            "-host",
            "host-.net",
            "another host",
            "127.1",
            "256.0.0.1",
            "010.0.0.1",
            &"x".repeat(64),
        ] {
            assert!(super::canonical_remote_pc(input).is_none(), "{input:?}");
        }
    }

    #[test]
    fn monitor_control_state_keeps_runtime_and_deferred_intent_distinct() {
        for (worker_status, desired, expected, published_worker_status, label) in [
            (
                WorkerStatus::Running,
                true,
                MonitorControlState::Running,
                WorkerStatus::Running,
                "Stop Monitor",
            ),
            (
                WorkerStatus::Running,
                false,
                MonitorControlState::Stopped,
                WorkerStatus::Idle,
                "Start Monitor",
            ),
            (
                WorkerStatus::Idle,
                true,
                MonitorControlState::PausedWithStartIntent,
                WorkerStatus::Idle,
                "Stop Monitor",
            ),
            (
                WorkerStatus::Idle,
                false,
                MonitorControlState::Stopped,
                WorkerStatus::Idle,
                "Start Monitor",
            ),
        ] {
            let state = MonitorControlState::from_worker_and_intent(worker_status, desired);
            assert_eq!(state, expected);
            assert_eq!(state.worker_status(), published_worker_status);
            assert_eq!(state.toggle_label(), label);
        }
    }
}
