//! Read desktop identities and saved PC endpoints from Windows App's local catalog.
//! Workspace bookmarks are cache entries for published desktops and can outlive them.
use anyhow::{ensure, Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const CATALOG_UNAVAILABLE: &str = "Could not read the saved devices in Windows App.";
const CATALOG_DEVICES: &str = "
WITH devices (id, name, owner, profile_id, remote_pc) AS (
    SELECT 'workspace:' || lower(r.ZID), r.ZDISPLAYNAME,
           coalesce(w.ZRDMIUSERID, ''), coalesce(w.ZMSALACCOUNTID, ''), NULL
    FROM ZREMOTERESOURCEENTITY AS r
    JOIN ZWORKSPACEENTITY AS w ON w.Z_PK = r.ZWORKSPACE
    WHERE r.ZTYPE = 0
    UNION ALL
    SELECT 'bookmark:' || lower(b.ZID), coalesce(nullif(b.ZFRIENDLYNAME, ''), b.ZHOSTNAME), '', '', b.ZHOSTNAME
    FROM ZBOOKMARKENTITY AS b
    WHERE coalesce(b.ZCREATIONSOURCEENUM, '') != 'Workspace' COLLATE NOCASE
      AND NOT EXISTS (SELECT 1 FROM ZREMOTERESOURCEENTITY AS r WHERE r.ZID = b.ZID COLLATE NOCASE)
)";
const LIST_DEVICES: &str = "
SELECT json_object('id', id, 'name', name, 'owner', owner, 'profile_id', profile_id,
                   'remote_pc', CASE WHEN id_count = 1 THEN remote_pc END)
FROM (SELECT devices.*, count(*) OVER (PARTITION BY id) AS id_count FROM devices)
WHERE id IS NOT NULL AND name IS NOT NULL AND name != ''
ORDER BY name COLLATE NOCASE, owner COLLATE NOCASE, id;";

#[derive(Clone, Deserialize, Debug, PartialEq, Eq)]
pub(crate) struct SavedDevice {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) owner: String,
    profile_id: String,
    pub(crate) remote_pc: Option<String>,
}

fn is_saved_device_id(id: &str) -> bool {
    let Some(uuid) = id
        .strip_prefix("workspace:")
        .or_else(|| id.strip_prefix("bookmark:"))
    else {
        return false;
    };
    uuid::Uuid::try_parse(uuid).is_ok()
}

fn library() -> Result<PathBuf> {
    Ok(crate::user_paths::home_dir()
        .context(CATALOG_UNAVAILABLE)?
        .join("Library/Containers/com.microsoft.rdc.macos/Data/Library"))
}

fn catalog_path() -> Result<PathBuf> {
    Ok(library()?.join(
        "Application Support/com.microsoft.rdc.macos/com.microsoft.rdc.application-data.sqlite",
    ))
}

pub(crate) fn saved_devices() -> Result<Vec<SavedDevice>> {
    read_catalog(&catalog_path()?)
}

/// Workspace desktops (including legacy name/profile links) are brokered.
/// Only a manually saved bookmark supplies an explicit, durable host field.
pub(crate) fn saved_remote_pc(device_id: &str) -> Result<Option<String>> {
    let Some(uuid) = device_id
        .strip_prefix("bookmark:")
        .and_then(|id| uuid::Uuid::try_parse(id).ok())
    else {
        return Ok(None);
    };
    read_bookmark_remote_pc(&catalog_path()?, uuid)
}

fn read_bookmark_remote_pc(path: &Path, id: uuid::Uuid) -> Result<Option<String>> {
    // Only a parsed UUID is interpolated. Duplicate or stale bookmark IDs are ambiguous.
    let query =
        format!("SELECT json_quote(remote_pc) FROM devices WHERE id = 'bookmark:{id}' LIMIT 2;");
    let output = query_catalog(path, &query)?;
    let mut rows = output.lines();
    let Some(row) = rows.next() else {
        return Ok(None);
    };
    if rows.next().is_some() {
        return Ok(None);
    }
    let endpoint: Option<String> = serde_json::from_str(row).context(CATALOG_UNAVAILABLE)?;
    Ok(endpoint.as_deref().and_then(bookmark_host))
}

fn bookmark_host(endpoint: &str) -> Option<String> {
    use crate::models::canonical_remote_pc;
    // Custom-port bookmarks store host:port (or [IPv6]:port), while the
    // account field and Windows App's Remote PC label identify the host.
    let host = canonical_remote_pc(endpoint).or_else(|| {
        let (hostname, port) = endpoint.trim().rsplit_once(':')?;
        if !port.bytes().all(|byte| byte.is_ascii_digit())
            || port.parse::<u16>().ok()? == 0
            || (hostname.contains(':') && !hostname.starts_with('['))
        {
            return None;
        }
        canonical_remote_pc(hostname)
    })?;
    (!crate::remote_pc::is_cloud_pc_gateway(&host)).then_some(host)
}

fn query_catalog(path: &Path, selection: &str) -> Result<String> {
    if !path.try_exists().context(CATALOG_UNAVAILABLE)? {
        return Ok(String::new());
    }
    // -init bypasses the user's interactive sqlite shell configuration. Do not
    // export RDP files: those can carry connection tickets and gateway secrets.
    let result = Command::new("/usr/bin/sqlite3")
        .args([
            "-init",
            "/dev/null",
            "-batch",
            "-readonly",
            "-noheader",
            "-cmd",
            ".timeout 1000",
        ])
        .arg(path)
        .arg(format!("{CATALOG_DEVICES} {selection}"))
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .context(CATALOG_UNAVAILABLE)?;
    ensure!(result.status.success(), CATALOG_UNAVAILABLE);
    String::from_utf8(result.stdout).context(CATALOG_UNAVAILABLE)
}

fn read_catalog(path: &Path) -> Result<Vec<SavedDevice>> {
    let output = query_catalog(path, LIST_DEVICES)?;
    let mut devices = Vec::new();
    for line in output.lines() {
        let mut device: SavedDevice = serde_json::from_str(line).context(CATALOG_UNAVAILABLE)?;
        if is_saved_device_id(&device.id) && !device.name.trim().is_empty() {
            device.remote_pc = device.remote_pc.as_deref().and_then(bookmark_host);
            devices.push(device);
        }
    }
    Ok(devices)
}

/// Validate the catalog binding and name that the native Devices view can
/// express, without presenting or modifying the Microsoft profile selection.
pub(crate) fn verify_card_identity(selected: &SavedDevice) -> Result<()> {
    let catalog = saved_devices()?;
    verify_card_identity_in(&catalog, selected)
}

pub(crate) fn verify_card_identity_in(
    catalog: &[SavedDevice],
    selected: &SavedDevice,
) -> Result<()> {
    let mut candidates = catalog.iter().filter(|item| item.id == selected.id);
    ensure!(
        candidates.next() == Some(selected) && candidates.next().is_none(),
        "This saved device changed. Refresh devices and choose it again."
    );
    let duplicate_name = catalog.iter().any(|item| {
        item.id != selected.id
            && item.name == selected.name
            && (item.profile_id.is_empty()
                || selected.profile_id.is_empty()
                || item.profile_id.eq_ignore_ascii_case(&selected.profile_id))
    });
    ensure!(!duplicate_name,
        "Windows App has multiple saved desktops with this name. Give this desktop a unique name before opening it.");
    if selected.id.starts_with("workspace:") {
        let result = Command::new("/usr/bin/defaults")
            .arg("read")
            .arg(library()?.join("Preferences/com.microsoft.rdc.macos"))
            .arg("ProfileSwitcherViewModel.lastSelectedAccountId")
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .context("Could not read the selected Windows App profile.")?;
        ensure!(
            result.status.success()
                && !selected.profile_id.is_empty()
                && std::str::from_utf8(&result.stdout)
                    .is_ok_and(|id| id.trim().eq_ignore_ascii_case(&selected.profile_id)),
            "Select this desktop’s profile in Windows App before starting a new connection."
        );
    }
    Ok(())
}

#[cfg(test)]
impl SavedDevice {
    pub(crate) fn for_test(id: &str, name: &str, owner: &str) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            owner: owner.into(),
            profile_id: String::new(),
            remote_pc: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bookmark_import_accepts_hosts_with_custom_ports_and_excludes_gateway_names() {
        for (value, expected) in [
            ("HOST.Example.:3390", Some("host.example")),
            ("[2001:db8::5]:3389", Some("2001:db8::5")),
            ("2001:db8::5", Some("2001:db8::5")),
            ("rdgateway-r1.wvd.microsoft.com:443", None),
            ("rdp://desk.test", None),
            ("user@desk.test:3389", None),
            ("pc:65536", None),
            ("2001:db8::5:99999", None),
        ] {
            assert_eq!(bookmark_host(value).as_deref(), expected, "{value}");
        }
        for id in [
            "",
            "window",
            "workspace:00000000-0000-0000-0000-000000000001",
            "bookmark:invalid",
        ] {
            assert_eq!(saved_remote_pc(id).unwrap(), None);
        }
    }

    #[test]
    fn lists_desktops_by_id_and_owner_and_omits_workspace_bookmark_mirrors() {
        let path = std::env::temp_dir().join(format!(
            "waal-device-catalog-{}.sqlite",
            uuid::Uuid::new_v4()
        ));
        let setup = "CREATE TABLE ZWORKSPACEENTITY(Z_PK INTEGER, ZRDMIUSERID TEXT, ZMSALACCOUNTID TEXT);
             CREATE TABLE ZREMOTERESOURCEENTITY(ZID TEXT, ZDISPLAYNAME TEXT, ZTYPE INTEGER, ZWORKSPACE INTEGER);
             CREATE TABLE ZBOOKMARKENTITY(ZID TEXT, ZFRIENDLYNAME TEXT, ZHOSTNAME TEXT, ZCREATIONSOURCEENUM TEXT);
             INSERT INTO ZWORKSPACEENTITY VALUES(1,'one@example.test','A'),(2,'two@example.test','B');
             INSERT INTO ZREMOTERESOURCEENTITY VALUES
               ('00000000-0000-4000-8000-000000000001','Same desktop',0,1),
               ('00000000-0000-4000-8000-000000000002','Same desktop',0,2),
               ('00000000-0000-4000-8000-000000000003','App',1,1);
             INSERT INTO ZBOOKMARKENTITY VALUES
               ('00000000-0000-4000-8000-000000000001','Same desktop','PC1',NULL),
               ('00000000-0000-4000-8000-000000000004','Expired mirror','PC2','Workspace'),
               ('00000000-0000-4000-8000-000000000005',NULL,'LOCAL-PC.:3390',NULL),
               ('00000000-0000-4000-8000-000000000006','Z copy A','pc-a',NULL),
               ('00000000-0000-4000-8000-000000000006','Z copy B','pc-b',NULL),
               ('00000000-0000-4000-8000-000000000007','Z gateway','rdgateway-r1.wvd.microsoft.com',NULL);";
        assert!(Command::new("/usr/bin/sqlite3")
            .args(["-init", "/dev/null", "-batch"])
            .arg(&path)
            .arg(setup)
            .status()
            .unwrap()
            .success());
        let devices = read_catalog(&path).unwrap();
        let address = |number| {
            let id =
                uuid::Uuid::parse_str(&format!("00000000-0000-4000-8000-{number:012}")).unwrap();
            read_bookmark_remote_pc(&path, id).unwrap()
        };
        // Only the manually created bookmark exposes a destination.
        assert_eq!(address(5).as_deref(), Some("local-pc"));
        assert_eq!(address(1), None); // workspace mirror sharing a published resource ID
        assert_eq!(address(4), None); // stale workspace mirror
        assert_eq!(address(6), None); // duplicate ID
        assert_eq!(address(7), None); // gateway
        assert_eq!(address(99), None);
        std::fs::remove_file(path).unwrap();
        assert_eq!(devices.len(), 6);
        assert!(devices[0].id.starts_with("bookmark:"));
        assert_eq!(devices[0].name, "LOCAL-PC.:3390");
        assert_eq!(devices[0].remote_pc.as_deref(), Some("local-pc"));
        assert!(devices[1..].iter().all(|device| device.remote_pc.is_none()));
        assert_eq!(devices[1].owner, "one@example.test");
        assert_eq!(devices[2].owner, "two@example.test");
        assert_ne!(devices[1].id, devices[2].id);
    }
}
