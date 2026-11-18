//! Link the user's choice to a saved desktop when possible. An open session
//! can also be focused by title when it has no matching catalog entry.
use super::device_launch::{saved_devices, SavedDevice};
use super::device_windows::open_session_titles;
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

// Windows App identifies its session windows by title only.
fn has_unique_title(catalog: &[SavedDevice], device: &SavedDevice) -> bool {
    catalog.iter().filter(|d| d.name == device.name).count() == 1
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

}
