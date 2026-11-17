//! Shared iPhone selection on this Mac. CoreDevice's host inventory
//! can describe a paired iPhone even while its Wi-Fi tunnel is dormant.
use serde_json::Value;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SetupInfo {
    NotConfigured,
    NoDeviceSelected,
    ConfigUnavailable,
    SelectedUnavailable,
    SelectedNeedsSetup { name: Option<String> },
    Selected { name: String, wifi_connected: bool },
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PairedPhone {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) wifi_connected: bool,
    pub(crate) selected: bool,
}

fn root() -> Result<PathBuf, SetupInfo> {
    Ok(crate::user_paths::config_dir()
        .map_err(|_| SetupInfo::ConfigUnavailable)?
        .join("iphone-automation"))
}

pub(crate) fn read() -> SetupInfo {
    let (selected, installed) = match root().and_then(|path| selected_id(&path)) {
        Ok(selection) => selection,
        Err(status) => return status,
    };
    let device = list_inventory().ok().and_then(|phones| {
        phones
            .into_iter()
            .find(|p| p.id.eq_ignore_ascii_case(&selected))
    });
    if !installed {
        return SetupInfo::SelectedNeedsSetup {
            name: device.map(|p| p.name),
        };
    }
    match device {
        Some(phone) => SetupInfo::Selected {
            name: phone.name,
            wifi_connected: phone.wifi_connected,
        },
        None => SetupInfo::SelectedUnavailable,
    }
}

pub(crate) fn paired_phones() -> Result<Vec<PairedPhone>, String> {
    let path = root().map_err(|_| "The iPhone preferences could not be located.")?;
    let selected = match selected_id(&path) {
        Ok((id, _)) => Some(id),
        Err(SetupInfo::NotConfigured | SetupInfo::NoDeviceSelected) => None,
        Err(_) => return Err("The iPhone preferences could not be read safely.".into()),
    };
    let mut phones = list_inventory()?;
    for phone in &mut phones {
        phone.selected = selected
            .as_deref()
            .is_some_and(|id| phone.id.eq_ignore_ascii_case(id));
    }
    Ok(phones)
}

pub(crate) fn select_phone(id: &str) -> Result<(), String> {
    if !valid_id(id) {
        return Err("Choose an iPhone from the paired devices.".into());
    }
    let phones = list_inventory()?;
    let selected = phones
        .iter()
        .find(|p| p.id.eq_ignore_ascii_case(id))
        .ok_or("This iPhone is no longer in the paired device list. Refresh and choose again.")?;
    let path = root().map_err(|_| "The iPhone preferences could not be located.")?;
    save_selection(&path, &selected.id)
        .map_err(|_| "The iPhone selection couldn’t be saved. Check for another setup in progress and try again.".into())
}

fn check_dir(root: &Path) -> anyhow::Result<()> {
    let dir = fs::symlink_metadata(root)?;
    anyhow::ensure!(
        dir.is_dir()
            && dir.uid() == unsafe { libc::geteuid() }
            && dir.mode() & 0o077 == 0
            && !crate::private_permissions::path_has_macos_acl(root)?,
        "private directory required"
    );
    Ok(())
}

fn config_value(path: &Path) -> anyhow::Result<Option<Value>> {
    match crate::iphone_sso::private_file(path, 8192) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        Err(e)
            if e.downcast_ref::<io::Error>()
                .is_some_and(|e| e.kind() == io::ErrorKind::NotFound) =>
        {
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

fn selected_id(root: &Path) -> Result<(String, bool), SetupInfo> {
    if let Err(e) = check_dir(root) {
        return Err(
            if e.downcast_ref::<io::Error>()
                .is_some_and(|e| e.kind() == io::ErrorKind::NotFound)
            {
                SetupInfo::NotConfigured
            } else {
                SetupInfo::ConfigUnavailable
            },
        );
    }
    // Setup publishes config.json before removing the pending choice. Reading
    // in the opposite order also sees a usable selection during promotion.
    let pending = config_value(&root.join("pending-device.json"));
    if let Some(config) =
        config_value(&root.join("config.json")).map_err(|_| SetupInfo::ConfigUnavailable)?
    {
        return id_from_document(&config).map(|id| (id, true));
    }
    let pending = pending
        .map_err(|_| SetupInfo::ConfigUnavailable)?
        .ok_or(SetupInfo::NotConfigured)?;
    id_from_document(&pending).map(|id| (id, false))
}

fn valid_id(id: &str) -> bool {
    let hex = |s: &str, n| s.len() == n && s.bytes().all(|c| c.is_ascii_hexdigit());
    hex(id, 40)
        || id
            .split_once('-')
            .is_some_and(|(a, b)| hex(a, 8) && hex(b, 16))
}

fn id_from_document(doc: &Value) -> Result<String, SetupInfo> {
    if doc["schema_version"].as_u64() != Some(1) {
        return Err(SetupInfo::ConfigUnavailable);
    }
    match doc.get("device_udid") {
        Some(Value::Null) => Err(SetupInfo::NoDeviceSelected),
        Some(Value::String(id)) if valid_id(id) => Ok(id.clone()),
        _ => Err(SetupInfo::ConfigUnavailable),
    }
}

fn save_selection(root: &Path, id: &str) -> anyhow::Result<()> {
    anyhow::ensure!(valid_id(id), "invalid iPhone choice");
    // The application support directory contains the accounts configuration
    // and already exists by the time the Settings form is available.
    match fs::DirBuilder::new().mode(0o700).create(root) {
        Ok(()) => crate::private_permissions::strip_macos_acl(root)?,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }
    check_dir(root)?;
    let _lock = lock_selection(root)?;
    let config = root.join("config.json");
    let pending = root.join("pending-device.json");
    let (path, mut document) = if let Some(existing) = config_value(&config)? {
        match id_from_document(&existing) {
            Ok(_) | Err(SetupInfo::NoDeviceSelected) => {}
            Err(_) => anyhow::bail!("invalid iPhone configuration"),
        }
        (config, existing)
    } else {
        if let Some(old) = config_value(&pending)? {
            anyhow::ensure!(id_from_document(&old).is_ok(), "invalid saved choice");
        }
        (pending, serde_json::json!({"schema_version":1}))
    };
    document["device_udid"] = id.into();
    let bytes = serde_json::to_vec(&document)?;
    anyhow::ensure!(bytes.len() <= 8192, "invalid iPhone configuration");
    crate::storage::write_private_file_atomic(&path, "choice", &bytes)
}

fn lock_selection(root: &Path) -> anyhow::Result<File> {
    let lock = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(root.join(".selection.lock"))?;
    let stat = lock.metadata()?;
    anyhow::ensure!(
        stat.is_file()
            && stat.uid() == unsafe { libc::geteuid() }
            && stat.mode() & 0o077 == 0
            && !crate::private_permissions::file_has_macos_acl_fd(&lock)?,
        "private lock required"
    );
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(lock);
        }
        let error = io::Error::last_os_error();
        if !matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
        ) || Instant::now() >= deadline
        {
            return Err(error.into());
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn inventory() -> Result<Vec<u8>, &'static str> {
    const UNAVAILABLE: &str = "Couldn’t read Xcode’s paired iPhone list. Open Xcode and try again.";
    const MISSING: &str = "Xcode’s device tools are unavailable. Install Xcode and select it as the active developer tools.";
    const MAX_BYTES: usize = 2 * 1024 * 1024;
    let home = crate::user_paths::home_dir().ok_or(UNAVAILABLE)?;
    let (mut reader, writer) = UnixStream::pair().map_err(|_| UNAVAILABLE)?;
    reader.set_nonblocking(true).map_err(|_| UNAVAILABLE)?;
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
        .map_err(|error| match error.kind() {
            io::ErrorKind::NotFound => MISSING,
            _ => UNAVAILABLE,
        })?;

    let deadline = Instant::now() + Duration::from_secs(7);
    let mut data = Vec::new();
    let mut buffer = [0; 16384];
    while Instant::now() < deadline {
        match reader.read(&mut buffer) {
            Ok(0) => match child.try_wait() {
                Ok(Some(status)) if status.success() => return Ok(data),
                Ok(Some(status)) if matches!(status.code(), Some(69 | 72)) => return Err(MISSING),
                Ok(Some(_)) => return Err(UNAVAILABLE),
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
    Err(UNAVAILABLE)
}

fn list_inventory() -> Result<Vec<PairedPhone>, String> {
    let bytes = inventory()?;
    parse_inventory(&bytes)
        .ok_or_else(|| "Xcode returned an unreadable or ambiguous paired iPhone list.".into())
}

fn parse_inventory(bytes: &[u8]) -> Option<Vec<PairedPhone>> {
    let doc: Value = serde_json::from_slice(bytes).ok()?;
    let devices = doc.pointer("/result/devices")?.as_array()?;
    let mut phones: Vec<_> = devices.iter().filter_map(paired_iphone).collect();
    let mut ids = std::collections::HashSet::new();
    if phones
        .iter()
        .any(|p| !ids.insert(p.id.to_ascii_lowercase()))
    {
        return None;
    }
    phones.sort_by_key(|p| (p.name.to_lowercase(), p.id.to_ascii_lowercase()));
    for group in phones.chunk_by_mut(|a, b| a.name.to_lowercase() == b.name.to_lowercase()) {
        if group.len() < 2 {
            continue;
        }
        for (index, phone) in group.iter_mut().enumerate() {
            phone.name = format!(
                "{} · {} (…{})",
                phone.name,
                index + 1,
                &phone.id[phone.id.len() - 4..]
            );
        }
    }
    Some(phones)
}

fn paired_iphone(device: &Value) -> Option<PairedPhone> {
    let hardware = device
        .pointer("/properties/hardware")
        .or_else(|| device.get("hardwareProperties"))?;
    let connection = device
        .pointer("/properties/connection")
        .or_else(|| device.get("connectionProperties"))?;
    let id = hardware["udid"].as_str()?;
    if !valid_id(id)
        || hardware["platform"] != "iOS"
        || hardware["deviceType"] != "iPhone"
        || hardware["reality"] != "physical"
        || connection["pairingState"] != "paired"
    {
        return None;
    }
    let label = device
        .pointer("/properties/state/name")
        .or_else(|| device.pointer("/deviceProperties/name"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let mut name: String = label.trim().chars()
        .filter(|c| !c.is_control() && !matches!(*c,
            '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'))
        .take(80).collect();
    if name.trim().is_empty() || name.to_ascii_lowercase().contains(&id.to_ascii_lowercase()) {
        name = "Paired iPhone".into();
    }
    let tunnel = connection
        .get("state")
        .or_else(|| connection.get("tunnelState"))
        .and_then(Value::as_str);
    Some(PairedPhone {
        id: id.to_owned(),
        name,
        wifi_connected: tunnel == Some("connected")
            && connection["transportType"] == "localNetwork",
        selected: false,
    })
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
        parse_inventory(&serde_json::to_vec(&json!({"result":{"devices":devices}})).unwrap())?
            .into_iter()
            .find(|p| p.id.eq_ignore_ascii_case(ID))
            .map(|p| SetupInfo::Selected {
                name: p.name,
                wifi_connected: p.wifi_connected,
            })
    }

    #[test]
    fn reports_saved_selection_without_guessing_from_the_paired_list() {
        assert_eq!(
            id_from_document(
                &serde_json::from_slice(br#"{"schema_version":1,"device_udid":null}"#).unwrap()
            ),
            Err(SetupInfo::NoDeviceSelected)
        );
        assert_eq!(
            id_from_document(
                &serde_json::from_slice(br#"{"schema_version":1,"device_udid":"auto"}"#).unwrap()
            ),
            Err(SetupInfo::ConfigUnavailable)
        );
        assert_eq!(
            id_from_document(&serde_json::from_slice(br#"{"schema_version":1}"#).unwrap()),
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
    #[test]
    fn pending_choice_and_installed_config_have_one_authoritative_phone() {
        let root =
            std::env::temp_dir().join(format!("waal-selection-test-{}", uuid::Uuid::new_v4()));
        let other = "AAAAAAAA-0000000000000002";
        save_selection(&root, ID).unwrap();
        assert_eq!(selected_id(&root), Ok((ID.into(), false)));
        assert!(!root.join("config.json").exists());
        let config = json!({"schema_version":1,"device_udid":null,"runtime_dir":"preserve-me"});
        crate::storage::write_private_file_atomic(
            &root.join("config.json"),
            "test",
            &serde_json::to_vec(&config).unwrap(),
        )
        .unwrap();
        assert_eq!(selected_id(&root), Err(SetupInfo::NoDeviceSelected));
        save_selection(&root, other).unwrap();
        assert_eq!(selected_id(&root), Ok((other.into(), true)));
        assert_eq!(
            config_value(&root.join("config.json")).unwrap().unwrap()["runtime_dir"],
            "preserve-me"
        );
        assert!(save_selection(&root, "bad").is_err());
        assert_eq!(selected_id(&root), Ok((other.into(), true)));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn paired_iphone_names_are_distinct_even_when_short_suffixes_match() {
        let mut second = legacy_device();
        second["hardwareProperties"]["udid"] = json!("BBBBBBBB-0000000000000001");
        let first = legacy_device();
        let devices = vec![first, second];
        let phones =
            parse_inventory(&serde_json::to_vec(&json!({"result":{"devices":devices}})).unwrap())
                .unwrap();
        assert_eq!(phones.len(), 2);
        assert_ne!(phones[0].name, phones[1].name);
        assert!(phones
            .iter()
            .all(|p| p.name.starts_with("Work iPhone") && !p.name.contains(&p.id)));
        assert!(
            parse_inventory(&serde_json::to_vec(&json!({"result":{"devices":[]}})).unwrap())
                .unwrap()
                .is_empty()
        );
        assert!(parse_inventory(b"{}").is_none());
    }
}
