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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HelperFiles {
    NotInstalled,
    NeedsSetup,
    Current,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SetupInfo {
    NotConfigured,
    NoDeviceSelected,
    ConfigUnavailable,
    Selected {
        id: String,
        name: Option<String>,
        wifi_connected: bool,
        helper_files: HelperFiles,
    },
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
    let (selected, helper_files) = match root().and_then(|path| selected_id(&path)) {
        Ok(selection) => selection,
        Err(status) => return status,
    };
    let device = list_inventory().ok().and_then(|phones| {
        phones
            .into_iter()
            .find(|p| p.id.eq_ignore_ascii_case(&selected))
    });
    SetupInfo::Selected {
        id: selected,
        wifi_connected: device.as_ref().is_some_and(|p| p.wifi_connected),
        name: device.map(|p| p.name),
        helper_files,
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

const UNREACHABLE: &str = "The iPhone didn’t respond. Unlock it, connect it to the same Wi-Fi as this Mac, and try again.";
const PREPARED_CONFIG: &str = "prepared-config.json";

/// Returns true if this exact phone and helper configuration completed setup.
pub(crate) fn connect_phone(id: &str) -> Result<bool, String> {
    let path = root().map_err(|_| "The iPhone preferences could not be located.")?;
    connect_phone_at(&path, id)
}

fn connect_phone_at(path: &Path, id: &str) -> Result<bool, String> {
    if !valid_id(id) {
        return Err("Choose an iPhone from the paired devices.".into());
    }
    // A dormant Wi-Fi tunnel can still be reachable. This read asks the actual
    // phone to respond; the inventory by itself can return cached information.
    let response = device_command(
        &[
            "device",
            "info",
            "lockState",
            "--device",
            id,
            "--timeout",
            "8",
        ],
        Duration::from_secs(10),
        UNREACHABLE,
    )?;
    let live_device = responding_device(&response).ok_or(UNREACHABLE)?;
    let phone = verify_wifi_device(&inventory()?, id, live_device)?;
    save_selection(path, &phone.id)
        .map_err(|_| "The iPhone selection couldn’t be saved. Check for another setup in progress and try again.".into())
}

fn responding_device(response: &[u8]) -> Option<uuid::Uuid> {
    let doc: Value = serde_json::from_slice(response).ok()?;
    if doc.pointer("/info/outcome")?.as_str()? != "success" {
        return None;
    }
    uuid::Uuid::parse_str(doc.pointer("/result/deviceIdentifier")?.as_str()?).ok()
}

fn verify_wifi_device(
    bytes: &[u8],
    id: &str,
    live_device: uuid::Uuid,
) -> Result<PairedPhone, &'static str> {
    const MISSING: &str =
        "Xcode couldn’t confirm the selected iPhone. Refresh the device list and try again.";
    let doc: Value = serde_json::from_slice(bytes).map_err(|_| MISSING)?;
    let mut matches = doc
        .pointer("/result/devices")
        .and_then(Value::as_array)
        .ok_or(MISSING)?
        .iter()
        .filter_map(|device| Some((device, paired_iphone(device)?)))
        .filter(|(_, phone)| phone.id.eq_ignore_ascii_case(id));
    let (device, phone) = matches.next().ok_or(MISSING)?;
    let identifier = device["identifier"]
        .as_str()
        .and_then(|s| uuid::Uuid::parse_str(s).ok());
    if matches.next().is_some() || identifier != Some(live_device) {
        return Err(MISSING);
    }
    if !phone.wifi_connected {
        return Err("Xcode couldn’t confirm a Wi-Fi connection. Disconnect any USB cable, keep the iPhone on the same Wi-Fi as this Mac, and try again.");
    }
    Ok(phone)
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

// The signed app and Settings use the same list to identify an installed helper.
const HELPER_MODULES: &[(&str, &[u8])] = &[
    (
        "support.mjs",
        include_bytes!("../script/iphone-automation/support.mjs").as_slice(),
    ),
    (
        "bridge.mjs",
        include_bytes!("../script/iphone-automation/bridge.mjs").as_slice(),
    ),
    (
        "wda.mjs",
        include_bytes!("../script/iphone-automation/wda.mjs").as_slice(),
    ),
    (
        "authenticator.mjs",
        include_bytes!("../script/iphone-automation/authenticator.mjs").as_slice(),
    ),
    (
        "run-request.mjs",
        include_bytes!("../script/iphone-automation/run-request.mjs").as_slice(),
    ),
];

pub(crate) fn verify_helper_files(root: &Path) -> anyhow::Result<()> {
    for &(name, expected) in HELPER_MODULES {
        anyhow::ensure!(
            crate::iphone_sso::private_file(&root.join(name), 128 * 1024)? == expected,
            "iPhone helper needs setup"
        );
    }
    Ok(())
}

fn runtime_present(root: &Path, config: &Value) -> bool {
    let (Some(runtime), Some(node), Some(main)) = (
        config["runtime_dir"].as_str().map(Path::new),
        config["node_path"].as_str().map(Path::new),
        config["appium_main"].as_str().map(Path::new),
    ) else {
        return false;
    };
    let modules = runtime.join("node_modules");
    runtime == root.join(pinned_runtime_name())
        && node.is_absolute()
        && node
            .metadata()
            .is_ok_and(|m| m.is_file() && m.mode() & 0o111 != 0)
        && main == modules.join("appium/index.js")
        && main.is_file()
        && ["appium", "appium-xcuitest-driver"].iter().all(|&package| {
            let manifest = modules.join(package).join("package.json");
            pinned_dependencies()[package]
                .as_str()
                .is_some_and(|pin| installed_package_version(&manifest).as_deref() == Some(pin))
        })
}

fn pinned_dependencies() -> &'static Value {
    static MANIFEST: std::sync::LazyLock<Value> = std::sync::LazyLock::new(|| {
        serde_json::from_str(include_str!("../script/iphone-automation/package.json"))
            .expect("valid bundled iPhone helper manifest")
    });
    &MANIFEST["dependencies"]
}

fn installed_package_version(path: &Path) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct Package {
        version: String,
    }
    const LIMIT: u64 = 128 * 1024;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    let stat = file.metadata().ok()?;
    if !stat.is_file() || stat.len() > LIMIT {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(LIMIT + 1).read_to_end(&mut bytes).ok()?;
    if bytes.len() as u64 > LIMIT {
        return None;
    }
    Some(serde_json::from_slice::<Package>(&bytes).ok()?.version)
}

// The setup CLI installs npm packages into a directory named after the lockfile.
fn pinned_runtime_name() -> &'static str {
    use sha2::{Digest, Sha256};
    static NAME: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
        let digest = Sha256::digest(include_bytes!(
            "../script/iphone-automation/package-lock.json"
        ));
        format!("runtime-{:.16}", format!("{digest:x}"))
    });
    &NAME
}

fn prepared(root: &Path, config: &Value) -> bool {
    config_value(&root.join(PREPARED_CONFIG))
        .ok()
        .flatten()
        .as_ref()
        == Some(config)
        && verify_helper_files(root).is_ok()
        && runtime_present(root, config)
}

pub(super) fn invalidate_preparation(root: &Path) -> io::Result<()> {
    match fs::remove_file(root.join(PREPARED_CONFIG)) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

/// The device preparation tool reads config.json to build and launch its
/// runner. Keep its selection stable until the successful result is recorded.
pub(super) fn prepare_selected_device(
    root: &Path,
    device: &str,
    team: &str,
    prepare: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    const CHANGED: &str =
        "The selected iPhone or signing account changed. Connect the iPhone again.";
    let _lock = lock_selection(root)
        .map_err(|_| "The iPhone selection is busy. Try connecting again.".to_owned())?;
    let config = config_value(&root.join("config.json"))
        .map_err(|_| CHANGED.to_owned())?
        .ok_or(CHANGED)?;
    if !config["device_udid"]
        .as_str()
        .is_some_and(|id| id.eq_ignore_ascii_case(device))
        || config["development_team"].as_str() != Some(team)
    {
        return Err(CHANGED.into());
    }
    prepare()?;
    if config_value(&root.join("config.json"))
        .ok()
        .flatten()
        .as_ref()
        != Some(&config)
    {
        return Err(CHANGED.into());
    }
    crate::storage::write_private_file_atomic(
        &root.join(PREPARED_CONFIG),
        "prepared",
        &serde_json::to_vec(&config).map_err(|_| CHANGED.to_owned())?,
    )
    .map_err(|_| "Couldn’t save the completed iPhone setup. Try connecting again.".to_owned())
}

fn selected_id(root: &Path) -> Result<(String, HelperFiles), SetupInfo> {
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
        let id = id_from_document(&config)?;
        let helper_files = if prepared(root, &config) {
            HelperFiles::Current
        } else {
            HelperFiles::NeedsSetup
        };
        return Ok((id, helper_files));
    }
    let pending = pending
        .map_err(|_| SetupInfo::ConfigUnavailable)?
        .ok_or(SetupInfo::NotConfigured)?;
    id_from_document(&pending).map(|id| (id, HelperFiles::NotInstalled))
}

pub(crate) fn valid_id(id: &str) -> bool {
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

fn save_selection(root: &Path, id: &str) -> anyhow::Result<bool> {
    anyhow::ensure!(valid_id(id), "invalid iPhone choice");
    // The application support directory contains the accounts configuration
    // and already exists by the time the Settings form is available.
    match fs::DirBuilder::new().mode(0o700).create(root) {
        Ok(()) => crate::private_permissions::strip_macos_acl(root)?,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }
    check_dir(root)?;
    let _setup_lock = crate::iphone_setup::setup_lock(root).map_err(anyhow::Error::msg)?;
    let _lock = lock_selection(root)?;
    let config = root.join("config.json");
    let pending = root.join("pending-device.json");
    let (path, mut document) = if let Some(existing) = config_value(&config)? {
        match id_from_document(&existing) {
            Ok(saved) if saved.eq_ignore_ascii_case(id) => return Ok(prepared(root, &existing)),
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
    invalidate_preparation(root)?;
    document["device_udid"] = id.into();
    let bytes = serde_json::to_vec(&document)?;
    anyhow::ensure!(bytes.len() <= 8192, "invalid iPhone configuration");
    crate::storage::write_private_file_atomic(&path, "choice", &bytes)?;
    Ok(false)
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
    device_command(
        &["list", "devices", "--timeout", "5"],
        Duration::from_secs(7),
        "Couldn’t read Xcode’s paired iPhone list. Open Xcode and try again.",
    )
}

fn device_command(
    args: &[&str],
    timeout: Duration,
    unavailable: &'static str,
) -> Result<Vec<u8>, &'static str> {
    const MISSING: &str = "Xcode’s device tools are unavailable. Install Xcode and select it as the active developer tools.";
    const MAX_BYTES: usize = 2 * 1024 * 1024;
    let home = crate::user_paths::home_dir().ok_or(unavailable)?;
    let (mut reader, writer) = UnixStream::pair().map_err(|_| unavailable)?;
    reader.set_nonblocking(true).map_err(|_| unavailable)?;
    let mut child = Command::new("/usr/bin/xcrun")
        .arg("devicectl")
        .args(args)
        .args(["--json-output", "-"])
        .env_clear()
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .stdout(Stdio::from(OwnedFd::from(writer)))
        .spawn()
        .map_err(|error| match error.kind() {
            io::ErrorKind::NotFound => MISSING,
            _ => unavailable,
        })?;

    let deadline = Instant::now() + timeout;
    let mut data = Vec::new();
    let mut buffer = [0; 16384];
    while Instant::now() < deadline {
        match reader.read(&mut buffer) {
            Ok(0) => match child.try_wait() {
                Ok(Some(status)) if status.success() => return Ok(data),
                Ok(Some(status)) if matches!(status.code(), Some(69 | 72)) => return Err(MISSING),
                Ok(Some(_)) => return Err(unavailable),
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
    Err(unavailable)
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

    fn result(devices: Vec<Value>) -> Option<(String, bool)> {
        parse_inventory(&serde_json::to_vec(&json!({"result":{"devices":devices}})).unwrap())?
            .into_iter()
            .find(|p| p.id.eq_ignore_ascii_case(ID))
            .map(|p| (p.name, p.wifi_connected))
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
        let expected = |connected| Some(("Work iPhone".into(), connected));
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
            Some(("Paired iPhone".into(), true))
        );
    }

    #[test]
    fn connection_requires_a_response_from_the_selected_physical_wifi_device() {
        let identifier = uuid::Uuid::new_v4();
        let mut response = json!({"info":{"outcome":"success"},"result":{
            "deviceIdentifier":identifier.to_string(),"passcodeRequired":true}});
        let live = responding_device(&serde_json::to_vec(&response).unwrap()).unwrap();
        assert_eq!(live, identifier);
        response["info"]["outcome"] = json!("failed");
        assert!(responding_device(&serde_json::to_vec(&response).unwrap()).is_none());
        assert!(responding_device(b"{}").is_none());

        let mut device = legacy_device();
        device["identifier"] = json!(identifier.to_string());
        let inventory = |devices: Vec<Value>| {
            serde_json::to_vec(&json!({"result":{"devices":devices}})).unwrap()
        };
        let verify = |devices| verify_wifi_device(&inventory(devices), ID, live);
        assert_eq!(verify(vec![device.clone()]).unwrap().id, ID);
        assert!(verify(vec![device.clone(), device.clone()]).is_err());
        let mut modern = json!({"identifier":identifier.to_string(),"properties":{
            "hardware":device["hardwareProperties"],
            "state":{"name":"Work iPhone"},
            "connection":{"pairingState":"paired","state":"connected","transportType":"localNetwork"}
        }});
        assert!(verify(vec![modern.clone()]).is_ok());
        modern["properties"]["connection"]["transportType"] = json!("wired");
        assert!(verify(vec![modern]).is_err());
        let mut dormant = device.clone();
        dormant["connectionProperties"]["tunnelState"] = json!("disconnected");
        assert!(verify(vec![dormant]).is_err());
        let mut unpaired = device.clone();
        unpaired["connectionProperties"]["pairingState"] = json!("unpaired");
        assert!(verify(vec![unpaired]).is_err());
        let mut wrong_phone = device.clone();
        wrong_phone["hardwareProperties"]["udid"] = json!("AAAAAAAA-0000000000000002");
        assert!(verify(vec![wrong_phone]).is_err());
        device["identifier"] = json!(uuid::Uuid::new_v4().to_string());
        assert!(verify(vec![device]).is_err());
    }
    #[test]
    fn pending_choice_and_installed_config_have_one_authoritative_phone() {
        let root =
            std::env::temp_dir().join(format!("waal-selection-test-{}", uuid::Uuid::new_v4()));
        let other = "AAAAAAAA-0000000000000002";
        save_selection(&root, ID).unwrap();
        assert_eq!(
            selected_id(&root),
            Ok((ID.into(), HelperFiles::NotInstalled))
        );
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
        assert_eq!(
            selected_id(&root),
            Ok((other.into(), HelperFiles::NeedsSetup))
        );
        assert_eq!(
            config_value(&root.join("config.json")).unwrap().unwrap()["runtime_dir"],
            "preserve-me"
        );
        assert!(connect_phone_at(&root, "bad").is_err());
        assert_eq!(
            selected_id(&root),
            Ok((other.into(), HelperFiles::NeedsSetup))
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn connect_reuses_only_completed_setup_for_the_current_phone_and_runtime() {
        let root = std::env::temp_dir().join(format!("waal-helper-test-{}", uuid::Uuid::new_v4()));
        assert!(!save_selection(&root, ID).unwrap());
        let team = "ABCDEFGHI1";
        let runtime = root.join(pinned_runtime_name());
        let modules = runtime.join("node_modules");
        let entry = modules.join("appium/index.js");
        let config = json!({
            "schema_version": 1, "device_udid": ID, "development_team": team,
            "node_path": "/usr/bin/true", "runtime_dir": runtime, "appium_main": entry,
        });
        crate::storage::write_private_file_atomic(
            &root.join("config.json"),
            "test",
            &serde_json::to_vec(&config).unwrap(),
        )
        .unwrap();
        fs::create_dir_all(modules.join("appium")).unwrap();
        fs::create_dir_all(modules.join("appium-xcuitest-driver")).unwrap();
        fs::write(&entry, "").unwrap();
        for package in ["appium", "appium-xcuitest-driver"] {
            let manifest = json!({"name":package, "version":pinned_dependencies()[package]});
            fs::write(
                modules.join(package).join("package.json"),
                manifest.to_string(),
            )
            .unwrap();
        }
        for &(name, bytes) in HELPER_MODULES {
            crate::storage::write_private_file_atomic(&root.join(name), "test", bytes).unwrap();
        }
        assert!(!save_selection(&root, ID).unwrap()); // host setup alone
        let other = "AAAAAAAA-0000000000000002";
        assert!(prepare_selected_device(&root, other, team, || panic!("wrong device")).is_err());
        assert!(prepare_selected_device(&root, ID, team, || Err("cancelled".into())).is_err());
        assert!(!save_selection(&root, ID).unwrap());
        prepare_selected_device(&root, ID, team, || Ok(())).unwrap();
        assert!(save_selection(&root, ID).unwrap());
        assert_eq!(selected_id(&root), Ok((ID.into(), HelperFiles::Current)));
        let setup_lock = crate::iphone_setup::setup_lock(&root).unwrap();
        assert!(save_selection(&root, other).is_err());
        drop(setup_lock);
        assert_eq!(selected_id(&root), Ok((ID.into(), HelperFiles::Current)));
        let mut changed_config = config.clone();
        changed_config["development_team"] = json!("ABCDEFGHI2");
        assert!(!prepared(&root, &changed_config));
        fs::remove_file(&entry).unwrap();
        assert!(!save_selection(&root, ID).unwrap());
        fs::write(&entry, "{}").unwrap();
        let driver = modules.join("appium-xcuitest-driver/package.json");
        let installed_driver = fs::read(&driver).unwrap();
        for invalid in [
            r#"{"name":"appium-xcuitest-driver","version":"0.0.1"}"#,
            "{",
        ] {
            fs::write(&driver, invalid).unwrap();
            assert!(!save_selection(&root, ID).unwrap());
        }
        fs::write(&driver, installed_driver).unwrap();
        assert!(save_selection(&root, ID).unwrap());
        crate::storage::write_private_file_atomic(
            &root.join("support.mjs"),
            "test",
            b"older helper",
        )
        .unwrap();
        assert_eq!(selected_id(&root), Ok((ID.into(), HelperFiles::NeedsSetup)));
        assert!(!save_selection(&root, other).unwrap());
        assert!(!root.join(PREPARED_CONFIG).exists());
        assert!(!save_selection(&root, ID).unwrap());
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
