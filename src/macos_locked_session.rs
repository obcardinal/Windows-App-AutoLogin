//! Reconnect a chosen desktop through Microsoft's native client. A guest image
//! is only a reason to reconnect; this module never retrieves or sends a password.
use super::{
    device_launch::{self, SavedDevice},
    device_windows, remote_pc_info, usernames_match, AXUIElementRef, AxElement, AX_ENABLED,
    AX_FRONTMOST, AX_PRESS, AX_SHEETS, AX_TITLE, AX_WINDOWS,
};
use crate::models::{canonical_remote_pc, Account};
use anyhow::{ensure, Context, Result};
use std::time::{Duration, Instant};

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct LockedSession {
    pub(crate) pid: i32,
    pub(crate) window_id: u32,
    pub(crate) account_id: String,
    device: BoundDevice,
    username: String,
    remote_pc: Option<String>,
    matched_by_remote_pc: bool,
    other_sessions: Vec<String>,
}

#[derive(Clone, PartialEq, Eq)]
enum BoundDevice {
    Saved(SavedDevice),
    Window(String),
}

impl LockedSession {
    pub(crate) fn endpoint_already_verified(&self) -> bool {
        self.matched_by_remote_pc
    }

    pub(crate) fn title(&self) -> &str {
        match &self.device {
            BoundDevice::Saved(device) => &device.name,
            BoundDevice::Window(title) => title,
        }
    }
}

fn valid_window_binding(account: &Account) -> bool {
    account.locked_vm_reconnect_enabled()
        && !account.username.trim().is_empty()
        && (account.vm_device_id == "open-window"
            || (account.vm_device_id.is_empty() && !account.vm_profile.trim().is_empty()))
        && (account.vm_profile.is_empty()
            || usernames_match(&account.vm_profile, &account.username))
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
    if candidates.next().is_some() || !endpoint_allowed(account, accounts.len()) {
        return None;
    }
    valid_window_binding(account).then_some(account)
}

fn eligible_endpoint_binding(account: &Account) -> bool {
    valid_window_binding(account)
        && canonical_remote_pc(&account.remote_pc)
            .is_some_and(|host| !crate::remote_pc::is_cloud_pc_gateway(&host))
}

fn can_match_by_endpoint(accounts: &[Account], title: &str) -> bool {
    !accounts
        .iter()
        .any(|a| a.enabled && a.vm_target.eq_ignore_ascii_case(title))
        && accounts.iter().any(eligible_endpoint_binding)
}

pub(crate) fn should_probe(accounts: &[Account], title: &str, has_session_window_id: bool) -> bool {
    accounts
        .iter()
        .any(|a| a.vm_target == title && a.locked_vm_reconnect_enabled())
        || (has_session_window_id && can_match_by_endpoint(accounts, title))
}

fn account_for_endpoint<'a>(
    accounts: &'a [Account],
    title: &str,
    other_sessions: &[String],
    host: &str,
) -> Option<&'a Account> {
    if !can_match_by_endpoint(accounts, title) {
        return None;
    }
    let mut matching = accounts
        .iter()
        .filter(|a| a.enabled && canonical_remote_pc(&a.remote_pc).as_deref() == Some(host));
    let account = matching.next()?;
    if matching.next().is_some()
        || !eligible_endpoint_binding(account)
        || other_sessions
            .iter()
            .any(|s| s.eq_ignore_ascii_case(&account.vm_target) || s.eq_ignore_ascii_case(title))
        || accounts
            .iter()
            .filter(|a| {
                a.enabled
                    && (a.id == account.id || a.vm_target.eq_ignore_ascii_case(&account.vm_target))
            })
            .count()
            != 1
    {
        return None;
    }
    Some(account)
}

fn account_for_observed_session<'a>(
    accounts: &'a [Account],
    session: &LockedSession,
) -> Option<&'a Account> {
    let account = if session.matched_by_remote_pc {
        account_for_endpoint(
            accounts,
            session.title(),
            &session.other_sessions,
            session.remote_pc.as_deref()?,
        )?
    } else {
        native_account(accounts, session.title())?
    };
    (account.id == session.account_id
        && account.username == session.username
        && canonical_remote_pc(&account.remote_pc) == session.remote_pc)
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
            && a.vm_target == title
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

pub(super) fn window_id(window: &AxElement) -> Option<u32> {
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

pub(crate) struct SessionProbe<'a> {
    pub(crate) pid: i32,
    pub(crate) window_id: u32,
    title: String,
    app: AxElement,
    window: AxElement,
    other_sessions: Vec<String>,
    direct: Option<(&'a Account, BoundDevice)>,
}

impl SessionProbe<'_> {
    pub(crate) fn known_account_id(&self) -> Option<&str> {
        self.direct.as_ref().map(|(account, _)| account.id.as_str())
    }

    // Called only after OCR recognized the Windows password screen. An
    // unmatched title can be linked only by this native session's own address.
    pub(crate) fn identify_locked(
        self,
        accounts: &[Account],
        cancelled: &impl Fn() -> bool,
    ) -> Result<Option<LockedSession>> {
        ensure!(!cancelled(), "Cancelled.");
        let matched_by_remote_pc = self.direct.is_none();
        let (account, device) = if let Some(binding) = self.direct {
            binding
        } else {
            let (title, original, others) =
                focused_desktop(&self.app)?.context("The connected desktop lost focus.")?;
            ensure!(
                title == self.title
                    && original.same_element(&self.window)
                    && window_id(&original) == Some(self.window_id)
                    && others == self.other_sessions,
                "The connected desktop changed."
            );
            let remote_pc_info::SessionRemotePc::Selected(host) =
                remote_pc_info::read_focused_session(&self.app, &original, &title, cancelled)?
            else {
                return Ok(None);
            };
            let Some(account) = account_for_endpoint(accounts, &title, &others, &host) else {
                return Ok(None);
            };
            (account, BoundDevice::Window(title))
        };
        let session = LockedSession {
            pid: self.pid,
            window_id: self.window_id,
            account_id: account.id.clone(),
            device,
            username: account.username.clone(),
            remote_pc: canonical_remote_pc(&account.remote_pc),
            matched_by_remote_pc,
            other_sessions: self.other_sessions,
        };
        if matched_by_remote_pc {
            ensure!(
                !cancelled()
                    && same_focused_session(&session, &self.app)?.same_element(&self.window),
                "The connected desktop changed."
            );
        }
        Ok(Some(session))
    }
}

pub(crate) fn probe<'a>(
    accounts: &'a [Account],
    requested_pid: i32,
    requested_title: &str,
    requested_window_id: Option<u32>,
) -> Result<Option<SessionProbe<'a>>> {
    let Some(app) = device_windows::running_app()? else {
        return Ok(None);
    };
    let Some((title, focused, other_sessions)) = focused_desktop(&app)? else {
        return Ok(None);
    };
    let Some(id) = window_id(&focused) else {
        return Ok(None);
    };
    let pid = app.process_id().context("Windows App changed.")?;
    if pid != requested_pid
        || title != requested_title
        || requested_window_id.is_some_and(|expected| expected != id)
    {
        return Ok(None);
    }
    let direct = if accounts
        .iter()
        .any(|a| a.vm_target == title && a.locked_vm_reconnect_enabled())
    {
        let Some(binding) = resolve_binding(accounts, &title, device_launch::saved_devices)? else {
            return Ok(None);
        };
        Some(binding)
    } else {
        if requested_window_id.is_none() || !can_match_by_endpoint(accounts, &title) {
            return Ok(None);
        }
        None
    };
    Ok(Some(SessionProbe {
        pid,
        window_id: id,
        title,
        app,
        window: focused,
        direct,
        other_sessions,
    }))
}

fn same_focused_session(session: &LockedSession, app: &AxElement) -> Result<AxElement> {
    let (title, window, others) =
        focused_desktop(app)?.context("The connected desktop lost focus.")?;
    ensure!(
        app.process_id() == Some(session.pid)
            && title == session.title()
            && others == session.other_sessions
            && window_id(&window) == Some(session.window_id),
        "The connected desktop changed."
    );
    Ok(window)
}

fn restore_after_card_check(
    session: &LockedSession,
    app: &AxElement,
    original: &AxElement,
) -> Result<()> {
    // Return only from Windows App's own Connection Center to the exact
    // original VM. Never reactivate the app after the user leaves it.
    let Some(center) = device_launch::center_window(app) else {
        return Ok(());
    };
    if app.bool_attr(AX_FRONTMOST) == Some(true)
        && app
            .element_attr("AXFocusedWindow")
            .is_some_and(|w| w.same_element(&center))
    {
        let restored = device_windows::focus_session_in_app(
            app,
            session.title(),
            &|| {
                app.bool_attr(AX_FRONTMOST) != Some(true)
                    || app
                        .element_attr("AXFocusedWindow")
                        .is_some_and(|w| !w.same_element(original) && !w.same_element(&center))
            },
            || {},
        )?;
        ensure!(
            restored.is_some_and(|w| w.same_element(original)),
            "The original desktop could not be restored."
        );
    }
    Ok(())
}

fn preflight_reconnect(
    session: &LockedSession,
    accounts: &[Account],
    app: &AxElement,
    original: &AxElement,
    cancelled: &impl Fn() -> bool,
) -> Result<BoundDevice> {
    let verified = match &session.device {
        BoundDevice::Window(title) => {
            account_for_observed_session(accounts, session)
                .context("The selected session or account changed.")?;
            device_launch::verify_window_device(
                app,
                title,
                &session.username,
                session.other_sessions.is_empty(),
                cancelled,
            )
            .map(BoundDevice::Window)
        }
        BoundDevice::Saved(device) => {
            let catalog = device_launch::saved_devices()?;
            ensure!(
                scoped_account(accounts, &catalog, session.title()).is_some_and(|(a, d)| d
                    == device
                    && a.id == session.account_id
                    && a.username == session.username
                    && canonical_remote_pc(&a.remote_pc) == session.remote_pc),
                "The selected session or account changed."
            );
            device_launch::verify_card_identity_in(&catalog, device)?;
            device_launch::verify_saved_card(app, device, cancelled)
                .map(|()| session.device.clone())
        }
    };
    restore_after_card_check(session, app, original)?;
    let target = verified?;
    same_focused_session(session, app)?;
    Ok(target)
}

pub(crate) fn reconnect(
    session: &LockedSession,
    accounts: &[Account],
    cancelled: impl Fn() -> bool,
) -> Result<()> {
    ensure!(!cancelled(), "Cancelled.");
    let app = device_windows::running_app()?.context("Windows App closed.")?;
    let window = same_focused_session(session, &app)?;
    if let Some(expected_host) = session
        .remote_pc
        .as_ref()
        .filter(|_| !session.endpoint_already_verified())
    {
        let endpoint =
            remote_pc_info::read_focused_session(&app, &window, session.title(), &cancelled)?;
        ensure!(
            matches!(endpoint, remote_pc_info::SessionRemotePc::Selected(host) if &host == expected_host),
            "The active Remote PC could not be matched to this account."
        );
    }
    let target = preflight_reconnect(session, accounts, &app, &window, &cancelled)?;
    let close = device_launch::menu_item(&app, &["Window", "窗口"], &["Close", "关闭"])
        .filter(|item| {
            item.process_id() == Some(session.pid) && item.bool_attr(AX_ENABLED) == Some(true)
        })
        .context("Windows App’s Window → Close command is unavailable.")?;
    ensure!(
        same_focused_session(session, &app)?.same_element(&window) && !cancelled(),
        "The selected desktop changed."
    );
    // AX can time out after accepting a press. Observe the exact window and its
    // native session entry to establish disconnection before issuing Connect.
    close.perform_action(AX_PRESS);
    wait_for_disconnect(session, &app, &window)?;
    // Once the selected session has closed, restore that same device even if
    // the user stopped Monitor in the meantime. Never choose another profile.
    let can_reopen = || {
        let (count, others) =
            session_members(session.title(), device_windows::session_entries(&app)?);
        ensure!(
            count == 0 && others == session.other_sessions,
            "The open sessions changed after disconnect. Open the selected desktop in Windows App."
        );
        Ok(())
    };
    can_reopen()?;
    // A successful native Connect action only means the client accepted the
    // request. Release Monitor immediately so it can handle any credential prompt.
    match &target {
        BoundDevice::Saved(device) => device_launch::open_saved_device_if(device, can_reopen),
        BoundDevice::Window(title) => device_launch::reconnect_window_device_if(&app, title, &session.username, can_reopen),
    }.context("The desktop disconnected, but Windows App could not reopen it. Open the selected desktop again.")?;
    Ok(())
}

fn wait_for_disconnect(session: &LockedSession, app: &AxElement, window: &AxElement) -> Result<()> {
    let until = Instant::now() + Duration::from_secs(6);
    loop {
        if let (Ok(entries), Ok(windows)) = (
            device_windows::session_entries(app),
            app.array_attr_result(AX_WINDOWS),
        ) {
            let (count, others) = session_members(session.title(), entries);
            ensure!(
                count <= 1 && others == session.other_sessions,
                "The open sessions changed while the selected desktop was closing."
            );
            let old_window_present = windows.iter().any(|w| w.same_element(window));
            if count == 0 && !old_window_present {
                return Ok(());
            }
            // The AX object can disappear between the window-list snapshot and
            // this read. The next list observation still establishes disconnection.
            if old_window_present
                && window
                    .optional_relationship_array_attr_result(AX_SHEETS)
                    .is_ok_and(|sheets| !sheets.is_empty())
            {
                anyhow::bail!(
                    "Windows App is waiting for confirmation before disconnecting this desktop."
                );
            }
        }
        ensure!(
            Instant::now() < until,
            "Windows App did not confirm that the selected desktop disconnected."
        );
        std::thread::sleep(Duration::from_millis(100));
    }
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
    fn renamed_window_needs_an_observed_session_and_the_exact_connection_address() {
        let mut owner = account();
        owner.remote_pc = "Assigned.Example.Test.".into();
        let host = "assigned.example.test";
        let accounts = std::slice::from_ref(&owner);
        assert!(should_probe(accounts, "Desktop", false));
        assert!(!should_probe(accounts, "New desktop", false));
        assert!(should_probe(accounts, "New desktop", true));
        assert_eq!(
            account_for_endpoint(accounts, "New desktop", &[], host),
            Some(&owner)
        );
        for wrong in [
            "assigned",
            "other.example.test",
            "assigned.example.test.attacker.test",
        ] {
            assert!(account_for_endpoint(accounts, "New desktop", &[], wrong).is_none());
        }
        for title in ["Desktop", "NEW DESKTOP"] {
            assert!(account_for_endpoint(accounts, "New desktop", &[title.into()], host).is_none());
        }
        let session = LockedSession {
            pid: 5,
            window_id: 9,
            account_id: owner.id.clone(),
            device: BoundDevice::Window("New desktop".into()),
            username: owner.username.clone(),
            remote_pc: Some(host.into()),
            matched_by_remote_pc: true,
            other_sessions: vec![],
        };
        assert_eq!(
            account_for_observed_session(accounts, &session),
            Some(&owner)
        );
        let mut changed = owner;
        changed.username = "new@example.test".into();
        assert!(account_for_observed_session(&[changed], &session).is_none());
    }

    #[test]
    fn renamed_window_rejects_conflicting_accounts_and_opted_out_or_unbound_targets() {
        let mut owner = account();
        let host = "selected.example.test";
        owner.remote_pc = host.into();
        let mut conflict = Account::new("other@example.test");
        conflict.remote_pc = host.into();
        assert!(
            account_for_endpoint(&[owner.clone(), conflict.clone()], "New", &[], host).is_none()
        );
        conflict.remote_pc.clear();
        for title in ["New", "desktop"] {
            conflict.vm_target = title.into();
            assert!(
                account_for_endpoint(&[owner.clone(), conflict.clone()], "New", &[], host)
                    .is_none()
            );
        }
        let mut invalid = owner.clone();
        invalid.reconnect_locked_vm = false;
        let mut targets = vec![invalid];
        for (id, profile, host) in [
            ("workspace:one", "", host),
            ("bookmark:one", "", host),
            ("", "", host),
            ("open-window", "other@example.test", host),
            ("open-window", "", ""),
            ("open-window", "", "rdgateway-test.wvd.microsoft.com"),
        ] {
            let mut a = owner.clone();
            a.vm_device_id = id.into();
            a.vm_profile = profile.into();
            a.remote_pc = host.into();
            targets.push(a);
        }
        for invalid in targets {
            assert!(!should_probe(std::slice::from_ref(&invalid), "New", true));
            assert!(account_for_endpoint(&[invalid], "New", &[], host).is_none());
        }
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
        let mut catalog_account = account();
        catalog_account.vm_target = "Different PC".into();
        catalog_account.vm_device_id = "workspace:other".into();
        assert!(
            resolve_binding(&[selected, catalog_account], "Desktop", never)
                .unwrap()
                .is_none()
        );
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
