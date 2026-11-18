//! Reconnect a chosen desktop through Microsoft's native client. A guest image
//! is only a reason to reconnect; this module never retrieves or sends a password.
use super::{
    device_launch::{self, SavedDevice},
    device_windows, usernames_match, AXUIElementRef, AxElement, AX_FRONTMOST, AX_SHEETS, AX_TITLE,
};
use crate::models::{canonical_remote_pc, Account};
use anyhow::{Context, Result};

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct LockedSession {
    pub(crate) pid: i32,
    pub(crate) window_id: u32,
    pub(crate) account_id: String,
    device: BoundDevice,
    username: String,
    remote_pc: Option<String>,
    other_sessions: Vec<String>,
}

#[derive(Clone, PartialEq, Eq)]
enum BoundDevice {
    Saved(SavedDevice),
    Window(String),
}

impl LockedSession {
    pub(crate) fn title(&self) -> &str {
        match &self.device {
            BoundDevice::Saved(device) => &device.name,
            BoundDevice::Window(title) => title,
        }
    }
}

fn endpoint_allowed(account: &Account, account_count: usize) -> bool {
    if account.remote_pc.is_empty() {
        return account_count == 1;
    }
    canonical_remote_pc(&account.remote_pc)
        .is_some_and(|host| !crate::remote_pc::is_cloud_pc_gateway(&host))
}

fn native_account<'a>(accounts: &'a [Account], title: &str) -> Option<&'a Account> {
    let mut candidates = accounts
        .iter()
        .filter(|a| a.enabled && a.vm_target == title);
    let account = candidates.next()?;
    if candidates.next().is_some()
        || !account.locked_vm_reconnect_enabled()
        || account.username.trim().is_empty()
        || !endpoint_allowed(account, accounts.len())
    {
        return None;
    }
    let named_binding = account.vm_device_id == "open-window"
        || (account.vm_device_id.is_empty() && !account.vm_profile.is_empty());
    (named_binding
        && (account.vm_profile.is_empty()
            || usernames_match(&account.vm_profile, &account.username)))
    .then_some(account)
}

fn resolve_binding<'a>(
    accounts: &'a [Account],
    title: &str,
    read_catalog: impl FnOnce() -> Result<Vec<SavedDevice>>,
) -> Result<Option<(&'a Account, BoundDevice)>> {
    // User-chosen window bindings never require access to another app's
    // protected data. Check the actual profile and card in Windows App after OCR.
    if let Some(account) = native_account(accounts, title) {
        return Ok(Some((account, BoundDevice::Window(title.to_owned()))));
    }
    if !accounts.iter().any(|a| {
        a.locked_vm_reconnect_enabled()
            && (a.vm_device_id.starts_with("workspace:") || a.vm_device_id.starts_with("bookmark:"))
    }) {
        return Ok(None);
    }
    let catalog = read_catalog().context("Windows App’s saved device ID could not be verified. Choose this desktop under Open windows in the account editor.")?;
    Ok(scoped_account(accounts, &catalog, title)
        .map(|(account, device)| (account, BoundDevice::Saved(device.clone()))))
}

fn scoped_account<'a, 'c>(
    accounts: &'a [Account],
    catalog: &'c [SavedDevice],
    title: &str,
) -> Option<(&'a Account, &'c SavedDevice)> {
    let mut titles = catalog.iter().filter(|device| device.name == title);
    let device = titles.next()?;
    if titles.next().is_some() || catalog.iter().filter(|d| d.id == device.id).count() != 1 {
        return None;
    }
    let mut bindings = accounts.iter().filter(|account| {
        account.enabled
            && (account.vm_device_id == device.id
                || (account.vm_target == title
                    && (account.vm_device_id == "open-window"
                        || (account.vm_device_id.is_empty() && !account.vm_profile.is_empty()))))
    });
    let account = bindings.next()?;
    if bindings.next().is_some() || !account.reconnect_locked_vm || !account.has_saved_password {
        return None;
    }
    // A window-only name can be shared by different profiles. Only a uniquely
    // matching published resource with an explicit owner identifies that link.
    if device.id.starts_with("workspace:") {
        if device.owner.is_empty()
            || !usernames_match(&account.username, &device.owner)
            || (!account.vm_profile.is_empty()
                && !usernames_match(&account.vm_profile, &device.owner))
        {
            return None;
        }
    } else if !device.id.starts_with("bookmark:") || account.vm_device_id != device.id {
        return None;
    }
    endpoint_allowed(account, accounts.len()).then_some((account, device))
}

fn window_id(window: &AxElement) -> Option<u32> {
    // Resolve at runtime so unsupported OS versions simply skip reconnect.
    // The ID belongs to the exact AX object, even for identically titled windows.
    let function = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"_AXUIElementGetWindow".as_ptr()) };
    if function.is_null() {
        return None;
    }
    let get: unsafe extern "C" fn(AXUIElementRef, *mut u32) -> i32 =
        unsafe { std::mem::transmute(function) };
    let mut id = 0;
    (unsafe { get(window.raw, &mut id) } == 0 && id != 0).then_some(id)
}

fn session_members<T>(title: &str, entries: Vec<(String, T)>) -> (usize, Vec<String>) {
    let mut others = Vec::new();
    let mut target_count = 0;
    for (name, _) in entries {
        if name == title {
            target_count += 1;
        } else {
            others.push(name);
        }
    }
    others.sort_unstable();
    (target_count, others)
}

fn focused_desktop(app: &AxElement) -> Result<Option<(String, AxElement, Vec<String>)>> {
    if app.bool_attr(AX_FRONTMOST) != Some(true) {
        return Ok(None);
    }
    let Some(focused) = app.element_attr("AXFocusedWindow") else {
        return Ok(None);
    };
    let Some(title) = focused.string_attr(AX_TITLE) else {
        return Ok(None);
    };
    if !device_windows::focused_session(app, &title).is_some_and(|w| w.same_element(&focused))
        || !focused
            .optional_relationship_array_attr_result(AX_SHEETS)?
            .is_empty()
    {
        return Ok(None);
    }
    let (count, others) = session_members(&title, device_windows::session_entries(app)?);
    Ok((count == 1).then_some((title, focused, others)))
}

pub(crate) fn probe(accounts: &[Account]) -> Result<Option<LockedSession>> {
    if !accounts.iter().any(Account::locked_vm_reconnect_enabled) {
        return Ok(None);
    }
    let Some(app) = device_windows::running_app()? else {
        return Ok(None);
    };
    let Some((title, focused, other_sessions)) = focused_desktop(&app)? else {
        return Ok(None);
    };
    let Some(id) = window_id(&focused) else {
        return Ok(None);
    };
    let Some((account, device)) = resolve_binding(accounts, &title, device_launch::saved_devices)?
    else {
        return Ok(None);
    };
    Ok(Some(LockedSession {
        pid: app.process_id().context("Windows App changed.")?,
        window_id: id,
        account_id: account.id.clone(),
        device,
        username: account.username.clone(),
        remote_pc: canonical_remote_pc(&account.remote_pc),
        other_sessions,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account() -> Account {
        let mut account = Account::new("owner@example.test");
        account.vm_target = "Desktop".into();
        account.vm_device_id = "open-window".into();
        account.reconnect_locked_vm = true;
        account.has_saved_password = true;
        account
    }

    fn desktop() -> SavedDevice {
        SavedDevice::for_test("workspace:one", "Desktop", "OWNER@example.test")
    }

    #[test]
    fn window_and_legacy_profile_bindings_work_without_catalog_access() {
        let never = || {
            panic!("A window binding should not request access to another app's protected files")
        };
        let mut selected = account();
        selected.remote_pc = "remote.example.test".into();
        let other = Account::new("second@example.test");
        for (device_id, profile) in [("open-window", ""), ("", "OWNER@example.test")] {
            selected.vm_device_id = device_id.into();
            selected.vm_profile = profile.into();
            let accounts = [selected.clone(), other.clone()];
            let (a, device) = resolve_binding(&accounts, "Desktop", never)
                .unwrap()
                .unwrap();
            assert_eq!(a.id, selected.id);
            assert!(matches!(device, BoundDevice::Window(name) if name == "Desktop"));
        }
        selected.vm_profile = "wrong@example.test".into();
        assert!(resolve_binding(&[selected], "Desktop", never)
            .unwrap()
            .is_none());
    }

    #[test]
    fn window_binding_requires_unique_title_and_destination_across_accounts() {
        let never = || panic!("Catalog must not be queried for these window-only bindings");
        let mut a = account();
        assert!(resolve_binding(std::slice::from_ref(&a), "Desktop", never)
            .unwrap()
            .is_some());
        assert!(resolve_binding(
            &[a.clone(), Account::new("second@example.test")],
            "Desktop",
            never
        )
        .unwrap()
        .is_none());
        a.remote_pc = "remote.example.test".into();
        let mut second = account();
        second.reconnect_locked_vm = false;
        assert!(resolve_binding(&[a, second], "Desktop", never)
            .unwrap()
            .is_none());
    }

    #[test]
    fn catalog_uuid_binding_cannot_silently_fall_back_to_an_unverified_name() {
        let mut a = account();
        a.vm_device_id = "workspace:one".into();
        let error = resolve_binding(&[a], "Desktop", || anyhow::bail!("Catalog access denied"))
            .err()
            .expect("The specific saved-device identity needs to be verifiable.");
        assert!(error.to_string().contains("saved device ID"));
    }

    #[test]
    fn tracks_unrelated_windows_across_disconnect_regardless_of_menu_order() {
        let entries = |names: &[&str]| names.iter().map(|n| (n.to_string(), ())).collect();
        let before = session_members("VM", entries(&["Desk B", "VM", "Desk A"]));
        let after = session_members("VM", entries(&["Desk A", "Desk B"]));
        assert_eq!(before.0, 1);
        assert_eq!(after.0, 0);
        assert_eq!(before.1, after.1);
        assert_eq!(session_members("VM", entries(&["VM", "VM"])).0, 2);
        assert_ne!(before.1, session_members("VM", entries(&["Desk A"])).1);
    }

    #[test]
    fn requires_explicit_unique_binding_and_matching_workspace_owner() {
        let mut acc = account();
        let device = desktop();
        assert!(scoped_account(
            std::slice::from_ref(&acc),
            std::slice::from_ref(&device),
            "Desktop"
        )
        .is_some());
        acc.username = "other@example.test".into();
        assert!(scoped_account(
            std::slice::from_ref(&acc),
            std::slice::from_ref(&device),
            "Desktop"
        )
        .is_none());
        acc.username = "owner@example.test".into();
        acc.vm_target.clear();
        assert!(scoped_account(
            std::slice::from_ref(&acc),
            std::slice::from_ref(&device),
            "Desktop"
        )
        .is_none());
        acc.vm_device_id = device.id.clone(); // ID survives a title rename.
        assert!(scoped_account(
            std::slice::from_ref(&acc),
            std::slice::from_ref(&device),
            "Desktop"
        )
        .is_some());
        acc.vm_profile = "different@example.test".into();
        assert!(scoped_account(
            std::slice::from_ref(&acc),
            std::slice::from_ref(&device),
            "Desktop"
        )
        .is_none());
    }

    #[test]
    fn requires_opt_in_and_checks_cloud_endpoint_when_multiple_accounts_exist() {
        let mut acc = account();
        let other = Account::new("other@example.test");
        let devices = [desktop()];
        assert!(scoped_account(&[acc.clone(), other.clone()], &devices, "Desktop").is_none());
        acc.remote_pc = "rdgateway-test.wvd.microsoft.com".into();
        assert!(scoped_account(&[acc.clone(), other.clone()], &devices, "Desktop").is_none());
        acc.remote_pc = "pc.example.test".into();
        assert!(scoped_account(&[acc.clone(), other], &devices, "Desktop").is_some());
        assert!(scoped_account(&[acc.clone(), acc.clone()], &devices, "Desktop").is_none());
        acc.reconnect_locked_vm = false;
        assert!(scoped_account(&[acc.clone()], &devices, "Desktop").is_none());
        acc.reconnect_locked_vm = true;
        acc.has_saved_password = false;
        assert!(scoped_account(&[acc], &devices, "Desktop").is_none());
    }

    #[test]
    fn rejects_ambiguous_catalog_and_window_only_bookmarks() {
        let mut account = account();
        let first = desktop();
        let second = SavedDevice::for_test("workspace:two", "Desktop", "owner@example.test");
        assert!(
            scoped_account(std::slice::from_ref(&account), &[first, second], "Desktop").is_none()
        );
        let bookmark = SavedDevice::for_test("bookmark:one", "Desktop", "");
        assert!(scoped_account(
            std::slice::from_ref(&account),
            std::slice::from_ref(&bookmark),
            "Desktop"
        )
        .is_none());
        account.vm_device_id = bookmark.id.clone();
        assert!(scoped_account(&[account], &[bookmark], "Desktop").is_some());
    }
}
