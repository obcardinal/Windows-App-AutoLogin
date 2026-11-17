//! Read-only information for the account editor. CoreDevice's host inventory
//! can describe a paired iPhone even while its Wi-Fi tunnel is dormant.
use serde::Deserialize;
use serde_json::Value;
use std::io::{self, Read};
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SetupInfo {
    NotConfigured,
    NoDeviceSelected,
    ConfigUnavailable,
    SelectedUnavailable,
    Selected { name: String, wifi_connected: bool },
}

pub(crate) fn read() -> SetupInfo {
    let selected = match selected_id() {
        Ok(id) => id,
        Err(status) => return status,
    };
    inventory()
        .and_then(|bytes| matching_device(&bytes, &selected))
        .unwrap_or(SetupInfo::SelectedUnavailable)
}

fn selected_id() -> Result<String, SetupInfo> {
    let root = crate::user_paths::config_dir()
        .map_err(|_| SetupInfo::ConfigUnavailable)?
        .join("iphone-automation");
    let handle_error = |error: &io::Error| {
        if error.kind() == io::ErrorKind::NotFound {
            SetupInfo::NotConfigured
        } else {
            SetupInfo::ConfigUnavailable
        }
    };
    let dir = std::fs::symlink_metadata(&root).map_err(|e| handle_error(&e))?;
    if !dir.is_dir() || dir.uid() != unsafe { libc::geteuid() } || dir.mode() & 0o077 != 0 {
        return Err(SetupInfo::ConfigUnavailable);
    }
    let bytes = crate::iphone_sso::private_file(&root.join("config.json"), 8192).map_err(|e| {
        e.downcast_ref::<io::Error>()
            .map(handle_error)
            .unwrap_or(SetupInfo::ConfigUnavailable)
    })?;
    selection_from_json(&bytes)
}

fn selection_from_json(bytes: &[u8]) -> Result<String, SetupInfo> {
    #[derive(Deserialize)]
    struct Selection {
        schema_version: u32,
        device_udid: Value,
    }
    let config: Selection =
        serde_json::from_slice(bytes).map_err(|_| SetupInfo::ConfigUnavailable)?;
    if config.schema_version != 1 {
        return Err(SetupInfo::ConfigUnavailable);
    }
    if config.device_udid.is_null() {
        return Err(SetupInfo::NoDeviceSelected);
    }
    let id = config
        .device_udid
        .as_str()
        .ok_or(SetupInfo::ConfigUnavailable)?;
    let hex = |s: &str, n| s.len() == n && s.bytes().all(|c| c.is_ascii_hexdigit());
    if hex(id, 40)
        || id
            .split_once('-')
            .is_some_and(|(a, b)| hex(a, 8) && hex(b, 16))
    {
        Ok(id.to_owned())
    } else {
        Err(SetupInfo::ConfigUnavailable)
    }
}

fn inventory() -> Option<Vec<u8>> {
    const MAX_BYTES: usize = 2 * 1024 * 1024;
    let home = crate::user_paths::home_dir()?;
    let (mut reader, writer) = UnixStream::pair().ok()?;
    reader.set_nonblocking(true).ok()?;
    let mut child = Command::new("/usr/bin/xcrun")
        .args([
            "devicectl",
            "list",
            "devices",
            "--timeout",
            "5",
            "--json-output",
            "-",
        ])
        .env_clear()
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .stdout(Stdio::from(OwnedFd::from(writer)))
        .spawn()
        .ok()?;

    let deadline = Instant::now() + Duration::from_secs(7);
    let mut data = Vec::new();
    let mut buffer = [0; 16384];
    while Instant::now() < deadline {
        match reader.read(&mut buffer) {
            Ok(0) => match child.try_wait() {
                Ok(Some(status)) => return status.success().then_some(data),
                Ok(None) => {}
                Err(_) => break,
            },
            Ok(n) if data.len() + n <= MAX_BYTES => {
                data.extend_from_slice(&buffer[..n]);
                continue;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            _ => break,
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let _ = child.kill();
    let _ = child.wait();
    None
}

fn matching_device(bytes: &[u8], selected: &str) -> Option<SetupInfo> {
    let doc: Value = serde_json::from_slice(bytes).ok()?;
    let devices = doc.pointer("/result/devices")?.as_array()?;
    let mut matches = devices.iter().filter_map(|d| {
        // Current CoreDevice groups fields under properties. Earlier Xcode
        // versions expose the same cached metadata through the legacy groups.
        let h = d.pointer("/properties/hardware").or_else(|| d.get("hardwareProperties"))?;
        let c = d.pointer("/properties/connection").or_else(|| d.get("connectionProperties"))?;
        if h["platform"] != "iOS" || h["deviceType"] != "iPhone" || h["reality"] != "physical"
            || !h["udid"].as_str()?.eq_ignore_ascii_case(selected) || c["pairingState"] != "paired"
        { return None; }
        let label = d.pointer("/properties/state/name").or_else(|| d.pointer("/deviceProperties/name"))
            .and_then(Value::as_str).unwrap_or_default();
        // A device's user-editable name is UI text only. Never present the
        // hardware identifier as its fallback display label.
        let mut name = label.trim().chars().filter(|c| !c.is_control() && !matches!(*c,
            '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'))
            .take(80).collect::<String>();
        if name.trim().is_empty() || name.to_ascii_lowercase().contains(&selected.to_ascii_lowercase()) {
            name = "Paired iPhone".into();
        }
        let active = c.get("state").or_else(|| c.get("tunnelState")).and_then(Value::as_str) == Some("connected");
        Some(SetupInfo::Selected { name, wifi_connected: active && c["transportType"] == "localNetwork" })
    });
    let only = matches.next()?;
    matches.next().is_none().then_some(only)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ID: &str = "AAAAAAAA-0000000000000001";
    fn legacy_device() -> Value {
        json!({"hardwareProperties":{"udid":ID,"reality":"physical","platform":"iOS","deviceType":"iPhone"},
            "deviceProperties":{"name":"Work iPhone"},
            "connectionProperties":{"pairingState":"paired","transportType":"localNetwork","tunnelState":"connected"}})
    }

    fn result(devices: Vec<Value>) -> Option<SetupInfo> {
        matching_device(
            &serde_json::to_vec(&json!({"result":{"devices":devices}})).unwrap(),
            ID,
        )
    }

    #[test]
    fn reports_saved_selection_without_guessing_from_the_paired_list() {
        assert_eq!(
            selection_from_json(br#"{"schema_version":1,"device_udid":null}"#),
            Err(SetupInfo::NoDeviceSelected)
        );
        assert_eq!(
            selection_from_json(br#"{"schema_version":1,"device_udid":"auto"}"#),
            Err(SetupInfo::ConfigUnavailable)
        );
        assert_eq!(
            selection_from_json(br#"{"schema_version":1}"#),
            Err(SetupInfo::ConfigUnavailable)
        );
        let mut different = legacy_device();
        different["hardwareProperties"]["udid"] = json!("AAAAAAAA-0000000000000002");
        assert_eq!(result(vec![different]), None);
        assert_eq!(result(vec![legacy_device(), legacy_device()]), None);
        let mut unpaired = legacy_device();
        unpaired["connectionProperties"]["pairingState"] = json!("unpaired");
        assert_eq!(result(vec![unpaired]), None);
    }

    #[test]
    fn distinguishes_named_selected_iphone_from_current_wifi_connection() {
        let device = legacy_device();
        let expected = |connected| {
            Some(SetupInfo::Selected {
                name: "Work iPhone".into(),
                wifi_connected: connected,
            })
        };
        assert_eq!(result(vec![device.clone()]), expected(true));
        let mut dormant = device.clone();
        dormant["connectionProperties"]["tunnelState"] = json!("disconnected");
        assert_eq!(result(vec![dormant]), expected(false));
        let modern_wired = json!({"properties":{"hardware":device["hardwareProperties"],"state":{"name":"Work iPhone"},
            "connection":{"pairingState":"paired","transportType":"wired","state":"connected"}}});
        assert_eq!(result(vec![modern_wired]), expected(false));
        let mut anonymous = device;
        anonymous["deviceProperties"]["name"] = json!(ID);
        assert_eq!(
            result(vec![anonymous]),
            Some(SetupInfo::Selected {
                name: "Paired iPhone".into(),
                wifi_connected: true
            })
        );
    }
}
