//! Link the user's choice to a saved desktop when possible. An open session
//! can also be focused by title when it has no matching catalog entry.
use super::device_launch::{
    open_saved_device, reconnect_window_device, saved_devices, SavedDevice,
};
use super::device_windows::{focus_open_session, open_session_titles};
use crate::models::{canonical_remote_pc, Account};
use anyhow::{ensure, Context, Result};
use std::collections::BTreeMap;

const WINDOW_ONLY: &str = "open-window";

#[derive(Clone)]
pub(crate) struct DeviceChoice {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) owner: String,
    pub(crate) ambiguous: bool,
}

impl DeviceChoice {
    fn saved(device: &SavedDevice) -> Self {
        Self {
            id: device.id.clone(),
            name: device.name.clone(),
            owner: device.owner.clone(),
            ambiguous: false,
        }
    }
}

#[derive(Clone, Default)]
pub(crate) struct DeviceChoices {
    pub(crate) open: Vec<DeviceChoice>,
    pub(crate) saved: Vec<DeviceChoice>,
    pub(crate) notices: Vec<&'static str>,
}

pub(crate) fn device_choices() -> Result<DeviceChoices> {
    // Discovery is passive. Either source can still populate the picker when
    // the other is unavailable (for example, a closed Connection Center).
    choices_from_sources(open_session_titles(), saved_devices())
}

fn choices_from_sources(
    sessions: Result<Vec<String>>,
    catalog: Result<Vec<SavedDevice>>,
) -> Result<DeviceChoices> {
    ensure!(
        sessions.is_ok() || catalog.is_ok(),
        "Could not read open windows or saved desktops. Check Accessibility access for AutoLogin and refresh."
    );
    let mut choices = DeviceChoices::default();
    if sessions.is_err() {
        choices
            .notices
            .push("Open windows could not be read. Check Accessibility access for AutoLogin.");
    }
    if catalog.is_err() {
        choices.notices.push("Couldn’t load saved desktops.");
    }
    let mut windows = BTreeMap::new();
    for name in sessions.unwrap_or_default() {
        *windows.entry(name).or_insert(0usize) += 1;
    }
    let catalog = catalog.unwrap_or_default();
    for (name, count) in &windows {
        let mut matches = catalog.iter().filter(|d| &d.name == name);
        let choice = match (matches.next(), matches.next()) {
            (Some(device), None) if *count == 1 => DeviceChoice::saved(device),
            _ => DeviceChoice {
                id: WINDOW_ONLY.into(),
                name: name.clone(),
                owner: String::new(),
                ambiguous: *count > 1,
            },
        };
        choices.open.push(choice);
    }
    for device in &catalog {
        if !choices.open.iter().any(|choice| choice.id == device.id) {
            choices.saved.push(DeviceChoice::saved(device));
        }
    }
    choices
        .saved
        .sort_by(|a, b| (&a.name, &a.owner).cmp(&(&b.name, &b.owner)));
    Ok(choices)
}

pub(crate) struct LaunchHost {
    address: String,
    allow_short_name: bool,
}

impl LaunchHost {
    pub(crate) fn for_account(account: &Account, accounts: &[Account]) -> Option<Self> {
        let address = canonical_remote_pc(&account.remote_pc)?;
        if crate::remote_pc::is_cloud_pc_gateway(&address) {
            return None;
        }
        let label = address.split('.').next()?;
        let allow_short_name = address.parse::<std::net::IpAddr>().is_err()
            && !accounts.iter().any(|other| {
                other.id != account.id
                    && canonical_remote_pc(&other.remote_pc)
                        .is_some_and(|host| host.split('.').next() == Some(label))
            });
        Some(Self {
            address,
            allow_short_name,
        })
    }

    /// Windows App can show the Windows computer name without its DNS suffix.
    /// This comparison only chooses a card to open in the current profile.
    pub(super) fn matches(&self, device_name: &str) -> bool {
        let Some(name) = canonical_remote_pc(device_name) else {
            return false;
        };
        name == self.address
            || (self.allow_short_name
                && !name.contains('.')
                && self
                    .address
                    .split_once('.')
                    .is_some_and(|(label, _)| label == name))
    }
}

pub(crate) fn open_desktop(
    id: &str,
    name: &str,
    owner: &str,
    account_email: &str,
    host: Option<&LaunchHost>,
) -> Result<()> {
    open_with(
        id,
        name,
        owner,
        saved_devices,
        focus_open_session,
        open_saved_device,
        |title| {
            if host.is_some() {
                return reconnect_window_device(title, account_email, host);
            }
            if let Ok(devices) = saved_devices() {
                if let Some(device) = saved_window_device(&devices, title, account_email)? {
                    return open_saved_device(device);
                }
            }
            reconnect_window_device(title, account_email, None)
        },
    )
}

pub(crate) fn remote_pc_session_title(id: &str, name: &str, owner: &str) -> Result<Option<String>> {
    session_title_with(id, name, owner, saved_devices)
}

fn session_title_with(
    id: &str,
    name: &str,
    owner: &str,
    catalog: impl FnOnce() -> Result<Vec<SavedDevice>>,
) -> Result<Option<String>> {
    if id.is_empty() && name.is_empty() && owner.is_empty() {
        return Ok(None);
    }
    if id == WINDOW_ONLY {
        ensure!(!name.trim().is_empty(), "Choose a connected desktop.");
        return Ok(Some(name.to_owned()));
    }
    let catalog = catalog()?;
    let device = selected_saved_device(&catalog, id, name, owner)?;
    ensure!(
        has_unique_title(&catalog, device),
        "Several saved desktops have this name. Choose the connected window in the device picker and try again."
    );
    Ok(Some(device.name.clone()))
}

fn open_with(
    id: &str,
    name: &str,
    owner: &str,
    catalog: impl FnOnce() -> Result<Vec<SavedDevice>>,
    focus: impl FnOnce(&str) -> Result<bool>,
    connect: impl FnOnce(&SavedDevice) -> Result<()>,
    reconnect: impl FnOnce(&str) -> Result<()>,
) -> Result<()> {
    if id == WINDOW_ONLY {
        ensure!(!name.trim().is_empty(), "The linked VM has no device name.");
        return if focus(name)? {
            Ok(())
        } else {
            reconnect(name)
        };
    }

    let catalog = catalog()?;
    let device = selected_saved_device(&catalog, id, name, owner)?;
    if has_unique_title(&catalog, device) && focus(&device.name)? {
        return Ok(());
    }
    connect(device)
}

// Windows App identifies its session windows by title only.
fn has_unique_title(catalog: &[SavedDevice], device: &SavedDevice) -> bool {
    catalog.iter().filter(|d| d.name == device.name).count() == 1
}

fn saved_window_device<'a>(
    devices: &'a [SavedDevice],
    title: &str,
    account_email: &str,
) -> Result<Option<&'a SavedDevice>> {
    let mut matches = devices.iter().filter(|device| {
        device.name == title
            && (device.id.starts_with("bookmark:")
                || (!device.owner.is_empty()
                    && device.owner.eq_ignore_ascii_case(account_email.trim())))
    });
    let device = matches.next();
    ensure!(matches.next().is_none(), "More than one saved desktop matches this VM. Choose the intended device in the account editor.");
    Ok(device)
}

fn selected_saved_device<'a>(
    catalog: &'a [SavedDevice],
    id: &str,
    name: &str,
    owner: &str,
) -> Result<&'a SavedDevice> {
    let mut matches = catalog.iter().filter(|device| {
        if id.is_empty() {
            // Bindings saved by previous versions used a device name and a profile email.
            device.name == name && !owner.is_empty() && device.owner.eq_ignore_ascii_case(owner)
        } else {
            device.id == id
        }
    });
    let device = matches.next().context(
        "This desktop is no longer in Windows App. Choose the device again in the account editor.",
    )?;
    ensure!(matches.next().is_none(), "More than one saved desktop matches this link. Choose the device again in the account editor.");
    Ok(device)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn saved() -> SavedDevice {
        SavedDevice::for_test("workspace:example", "Desktop", "owner@example.test")
    }

    #[test]
    fn unbound_and_window_only_imports_do_not_require_a_catalog() {
        let no_catalog = || panic!("an explicit window or unbound account needs no catalog");
        assert_eq!(session_title_with("", "", "", no_catalog).unwrap(), None);
        assert_eq!(
            session_title_with(WINDOW_ONLY, "Visible", "", no_catalog)
                .unwrap()
                .as_deref(),
            Some("Visible")
        );
        assert!(session_title_with(WINDOW_ONLY, "", "", no_catalog).is_err());
    }

    #[test]
    fn import_resolves_current_catalog_title_and_rejects_stale_or_ambiguous_bindings() {
        for (id, name, owner) in [
            ("workspace:example", "Before rename", ""),
            ("", "Desktop", "OWNER@example.test"),
        ] {
            assert_eq!(
                session_title_with(id, name, owner, || Ok(vec![saved()]))
                    .unwrap()
                    .as_deref(),
                Some("Desktop")
            );
        }
        assert!(
            session_title_with("workspace:removed", "Desktop", "", || Ok(vec![saved()])).is_err()
        );
        assert!(session_title_with("", "Desktop", "", || Ok(vec![saved()])).is_err());
        assert!(session_title_with("", "", "owner@example.test", || Ok(vec![saved()])).is_err());
        let other = SavedDevice::for_test("workspace:other", "Desktop", "other@example.test");
        assert!(
            session_title_with("workspace:example", "Desktop", "", || Ok(vec![
                saved(),
                other
            ]))
            .is_err()
        );
        assert!(
            session_title_with("workspace:example", "Desktop", "", || Ok(vec![
                saved(),
                saved()
            ]))
            .is_err()
        );
    }

    #[test]
    fn live_choice_keeps_its_saved_id_for_reconnect_and_is_listed_once() {
        let choices = choices_from_sources(Ok(vec!["Desktop".into()]), Ok(vec![saved()])).unwrap();
        assert_eq!(choices.open[0].id, saved().id);
        assert!(choices.saved.is_empty());
        assert!(choices.notices.is_empty());

        let other = SavedDevice::for_test("workspace:another", "Desktop", "other@example.test");
        let choices =
            choices_from_sources(Ok(vec!["Desktop".into()]), Ok(vec![saved(), other])).unwrap();
        assert_eq!(choices.open[0].id, WINDOW_ONLY);
        assert_eq!(choices.saved.len(), 2);
    }

    #[test]
    fn failure_of_one_source_does_not_hide_the_other() {
        let choices = choices_from_sources(
            Ok(vec!["Open remote desktop".into()]),
            Err(anyhow::anyhow!("unavailable")),
        )
        .unwrap();
        assert_eq!(choices.open[0].id, WINDOW_ONLY);
        assert_eq!(choices.notices.len(), 1);
        let choices =
            choices_from_sources(Err(anyhow::anyhow!("unavailable")), Ok(vec![saved()])).unwrap();
        assert_eq!(choices.saved[0].id, saved().id);
        let duplicates = choices_from_sources(Ok(vec!["Shared".into(); 2]), Ok(vec![])).unwrap();
        assert!(duplicates.open[0].ambiguous);
    }

    #[test]
    fn existing_link_focuses_first_and_connects_only_if_the_session_is_closed() {
        // A previous version saved only the name and account UPN. A new link
        // can also survive a rename because it identifies the catalog record.
        for (id, name, owner) in [
            ("", "Desktop", "OWNER@example.test"),
            ("workspace:example", "Old name", ""),
        ] {
            open_with(
                id,
                name,
                owner,
                || Ok(vec![saved()]),
                |title| {
                    assert_eq!(title, "Desktop");
                    Ok(true)
                },
                |_| panic!("an open session must not reconnect"),
                |_| panic!("saved catalog binding"),
            )
            .unwrap();
        }
        let mut connected = false;
        open_with(
            "workspace:example",
            "Desktop",
            "",
            || Ok(vec![saved()]),
            |_| Ok(false),
            |d| {
                assert_eq!(d.id, saved().id);
                connected = true;
                Ok(())
            },
            |_| panic!("saved catalog binding"),
        )
        .unwrap();
        assert!(connected);
        open_with(
            WINDOW_ONLY,
            "Visible",
            "",
            || panic!("no catalog needed"),
            |_| Ok(true),
            |_| panic!("focus only"),
            |_| panic!("an open window must not start another connection"),
        )
        .unwrap();
        assert!(open_with(
            "",
            "Desktop",
            "different@example.test",
            || Ok(vec![saved()]),
            |_| panic!("wrong profile"),
            |_| panic!("wrong profile"),
            |_| panic!("wrong profile"),
        )
        .is_err());
    }

    #[test]
    fn closed_window_link_reconnects_the_selected_vm_without_reopening_the_editor() {
        let mut requested = Vec::new();
        open_with(
            WINDOW_ONLY,
            "Selected VM",
            "",
            || panic!("a window binding is independent of the saved catalog ID"),
            |name| {
                assert_eq!(name, "Selected VM");
                Ok(false)
            },
            |_| panic!("a window binding has no saved ID"),
            |name| {
                requested.push(name.to_owned());
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(requested, ["Selected VM"]);
        assert!(open_with(
            WINDOW_ONLY,
            "Selected VM",
            "",
            || panic!("no catalog ID"),
            |_| anyhow::bail!("ambiguous open windows"),
            |_| panic!("ambiguous"),
            |_| panic!("an ambiguous open session must not reconnect"),
        )
        .is_err());
    }

    #[test]
    fn resolves_a_closed_window_by_exact_title_and_account() {
        let other = SavedDevice::for_test("workspace:other", "Desktop", "other@example.test");
        let mut devices = vec![other, saved()];
        assert_eq!(
            saved_window_device(&devices, "Desktop", "OWNER@example.test").unwrap(),
            Some(&devices[1])
        );
        assert!(saved_window_device(&devices, "Desk", "owner@example.test")
            .unwrap()
            .is_none());
        assert!(
            saved_window_device(&devices, "Desktop", "unrelated@example.test")
                .unwrap()
                .is_none()
        );
        devices.push(SavedDevice::for_test("bookmark:pc", "Desktop", ""));
        assert!(saved_window_device(&devices, "Desktop", "owner@example.test").is_err());
    }
}
