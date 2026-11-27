//! Per-account movement uses only remembered, explicitly selected VM identities.
//! Unknown foreground sessions may be identified once through Connection Information.
use super::{
    device_launch::{saved_devices, SavedDevice},
    device_windows, locked_session, remote_pc_info, usernames_match, AxElement, AX_ROLE, AX_TITLE,
    AX_WINDOWS,
};
use crate::background::{window_hints::observe_connection_windows, WorkerPauseLatch};
use crate::models::{canonical_remote_pc, Account};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const MOVE_INTERVAL: Duration = Duration::from_secs(4 * 60);
const DISCOVERY_INTERVAL: Duration = Duration::from_secs(2);
const CATALOG_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct WindowKey {
    pid: i32,
    id: u32,
}

struct EnterHint {
    account_id: String,
    key: WindowKey,
    created: Instant,
}

static ENTER_HINTS: Mutex<VecDeque<EnterHint>> = Mutex::new(VecDeque::new());

pub(crate) fn begin_enter() {
    if let Ok(mut hints) = ENTER_HINTS.lock() {
        hints.clear();
    }
}

/// Called only after the supervisor accepts an authenticated Enter result.
pub(crate) fn remember_enter(account_id: uuid::Uuid, pid: i32, window_id: u32) {
    if pid <= 0 || window_id == 0 {
        return;
    }
    if let Ok(mut hints) = ENTER_HINTS.lock() {
        if hints.len() == 32 {
            hints.pop_front();
        }
        hints.push_back(EnterHint {
            account_id: account_id.to_string(),
            key: WindowKey { pid, id: window_id },
            created: Instant::now(),
        });
    }
}

#[derive(Clone, Default, PartialEq)]
struct Configuration {
    accounts: Vec<Account>,
    active: bool,
}

struct Control {
    config: Mutex<Configuration>,
    stop: AtomicBool,
    pause: WorkerPauseLatch,
}

#[derive(Default)]
pub(crate) struct MouseWatch {
    worker: Option<MouseWorker>,
}

struct MouseWorker {
    control: Arc<Control>,
    thread: JoinHandle<()>,
}

impl MouseWatch {
    // Shares the send mutex so mutation acknowledgement waits for the last
    // already-admitted event. Future events see inactive before being posted.
    pub(crate) fn pause(&self) {
        if let Some(worker) = &self.worker {
            if let Ok(mut config) = worker.control.config.lock() {
                config.active = false;
            }
            worker.thread.thread().unpark();
        }
    }

    pub(crate) fn update(&mut self, accounts: &[Account], active: bool, pause: &WorkerPauseLatch) {
        if self.worker.is_none() && accounts.iter().any(Account::vm_mouse_movement_enabled) {
            let control = Arc::new(Control {
                config: Mutex::new(Configuration::default()),
                stop: AtomicBool::new(false),
                pause: pause.clone(),
            });
            let shared = control.clone();
            match thread::Builder::new()
                .name("vm-mouse".into())
                .spawn(move || watch(shared))
            {
                Ok(thread) => self.worker = Some(MouseWorker { control, thread }),
                Err(error) => tracing::warn!(%error, "Could not start background VM movement"),
            }
        }
        let Some(worker) = &self.worker else { return };
        if let Ok(mut config) = worker.control.config.lock() {
            if config.accounts != accounts || config.active != active {
                *config = Configuration {
                    accounts: accounts.to_vec(),
                    active,
                };
                worker.thread.thread().unpark();
            }
        }
    }
}

impl Drop for MouseWorker {
    fn drop(&mut self) {
        self.control.stop.store(true, Ordering::Release);
        self.thread.thread().unpark();
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AccountBinding {
    id: String,
    username: String,
    target: String,
    profile: String,
    device_id: String,
    remote_pc: String,
}

impl From<&Account> for AccountBinding {
    fn from(a: &Account) -> Self {
        Self {
            id: a.id.clone(),
            username: a.username.clone(),
            target: a.vm_target.clone(),
            profile: a.vm_profile.clone(),
            device_id: a.vm_device_id.clone(),
            remote_pc: a.remote_pc.clone(),
        }
    }
}

struct Binding {
    account: AccountBinding,
    next_move: Instant,
    right: bool,
    identity: VmIdentity,
}

impl Binding {
    fn new(account: &Account, identity: VmIdentity, now: Instant) -> Self {
        Self {
            account: account.into(),
            next_move: now + MOVE_INTERVAL,
            right: true,
            identity,
        }
    }

    fn active_account<'a>(&self, accounts: &'a [Account]) -> Option<&'a Account> {
        let account = accounts.iter().find(|a| a.id == self.account.id)?;
        (account.vm_mouse_movement_enabled() && AccountBinding::from(account) == self.account)
            .then_some(account)
    }

    fn submitted(&mut self, now: Instant) {
        self.next_move = now + MOVE_INTERVAL;
        self.right = !self.right;
    }
}

struct Window {
    element: AxElement,
    title: String,
    binding: Option<Binding>,
    ready: bool,
    discovery: Discovery,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WindowStatus {
    Current,
    Incomplete,
    Gone,
}

fn window_status(
    native: WindowStatus,
    accessibility: WindowStatus,
    session_matches: usize,
) -> WindowStatus {
    if native == WindowStatus::Gone || accessibility == WindowStatus::Gone {
        WindowStatus::Gone
    } else if native == WindowStatus::Current
        && accessibility == WindowStatus::Current
        && session_matches == 1
    {
        WindowStatus::Current
    } else {
        WindowStatus::Incomplete
    }
}

fn native_window_status(pid: i32, id: u32) -> WindowStatus {
    match unsafe { waal_vm_window_presence(pid, id) } {
        1 => WindowStatus::Current,
        0 => WindowStatus::Gone,
        _ => WindowStatus::Incomplete,
    }
}

#[derive(Default)]
struct Windows {
    pid: Option<i32>,
    windows: HashMap<u32, Window>,
    catalog: Vec<SavedDevice>,
    next_catalog: Option<Instant>,
    accounts: Vec<Account>,
}

impl Windows {
    fn observe(
        &mut self,
        app: &AxElement,
        accounts: &[Account],
        now: Instant,
        notified: Vec<AxElement>,
    ) -> anyhow::Result<()> {
        for window in self.windows.values_mut() {
            window.ready = false;
        }
        let pid = app
            .process_id()
            .ok_or_else(|| anyhow::anyhow!("Windows App exited"))?;
        if self.pid != Some(pid) {
            *self = Self {
                pid: Some(pid),
                ..Self::default()
            };
        }
        if self.accounts != accounts {
            self.accounts = accounts.to_vec();
            self.next_catalog = None;
            for window in self.windows.values_mut() {
                // A newly added account can make a formerly unique device
                // ambiguous. Keep observed endpoints, resolve ownership again.
                window.binding = None;
                window.discovery.prioritize();
            }
        }
        let sessions = device_windows::session_entries(app)?;
        // AX/menu snapshots may be incomplete during fullscreen/Space changes.
        // Keep the association then, but require a complete current inspection
        // before delivery. Only proven closure or replacement evicts a window.
        self.windows.retain(|id, window| {
            let ax_pid = window.element.process_id();
            let ax_id = locked_session::window_id(&window.element);
            let accessibility = if ax_pid.is_some_and(|value| value != pid)
                || ax_id.is_some_and(|value| value != *id)
            {
                WindowStatus::Gone
            } else if ax_pid == Some(pid)
                && ax_id == Some(*id)
                && window.element.string_attr(AX_TITLE).as_deref() == Some(window.title.as_str())
            {
                WindowStatus::Current
            } else {
                WindowStatus::Incomplete
            };
            let status = window_status(
                native_window_status(pid, *id),
                accessibility,
                sessions
                    .iter()
                    .filter(|(title, _)| title == &window.title)
                    .count(),
            );
            window.ready = status == WindowStatus::Current;
            status != WindowStatus::Gone
        });
        let mut observed = app.array_attr_checked(AX_WINDOWS).unwrap_or_default();
        observed.extend(notified);
        observed.extend(app.element_attr("AXFocusedWindow"));
        observed.extend(app.element_attr("AXMainWindow"));
        for element in observed {
            if element.process_id() != Some(pid)
                || element.string_attr(AX_ROLE).as_deref() != Some("AXWindow")
            {
                continue;
            }
            let Some(id) = locked_session::window_id(&element) else {
                continue;
            };
            let Some(title) = element.string_attr(AX_TITLE) else {
                continue;
            };
            if sessions.iter().filter(|(name, _)| name == &title).count() != 1
                || native_window_status(pid, id) != WindowStatus::Current
            {
                continue;
            }
            if self
                .windows
                .get(&id)
                .is_some_and(|w| !w.element.same_element(&element))
            {
                self.windows.remove(&id);
            }
            let window = self.windows.entry(id).or_insert_with(|| Window {
                element,
                title: title.clone(),
                binding: None,
                ready: true,
                discovery: Discovery::default(),
            });
            if window.title != title {
                window.title = title;
                window.binding = None;
                window.discovery = Discovery::default();
            }
            window.ready = true;
        }
        for window in self.windows.values_mut() {
            if window
                .binding
                .as_ref()
                .is_some_and(|b| b.active_account(accounts).is_none())
            {
                window.binding = None;
            }
        }
        // Enter supplies a candidate window, never permission to send input.
        // Resolve the actual selected VM through the same identity path as a
        // window opened directly in Windows App.
        if let Ok(mut hints) = ENTER_HINTS.lock() {
            hints.retain(|hint| {
                if now.saturating_duration_since(hint.created) >= Duration::from_secs(30)
                    || hint.key.pid != pid
                    || !accounts
                        .iter()
                        .any(|a| a.id == hint.account_id && a.vm_mouse_movement_enabled())
                {
                    return false;
                }
                let Some(window) = self.windows.get_mut(&hint.key.id) else {
                    return true;
                };
                if !window.ready {
                    return true;
                }
                window.discovery.prioritize();
                false
            });
        }
        if self
            .windows
            .values()
            .any(|w| w.ready && w.binding.is_none())
            && self.next_catalog.is_none_or(|next| now >= next)
        {
            self.next_catalog = Some(now + CATALOG_INTERVAL);
            if let Ok(catalog) = saved_devices() {
                self.catalog = catalog;
            }
        }
        for window in self
            .windows
            .values_mut()
            .filter(|w| w.ready && w.binding.is_none())
        {
            // Connection Information is tied to this exact native window and
            // remains useful even when no configured account currently owns it.
            let resolved = window
                .discovery
                .host
                .as_deref()
                .and_then(|host| {
                    endpoint_account(host, accounts, &self.catalog)
                        .map(|account| (account, VmIdentity::Endpoint(host.to_owned())))
                })
                .or_else(|| {
                    // A known endpoint must not be overridden by a weaker title.
                    window
                        .discovery
                        .host
                        .is_none()
                        .then(|| passive_account(&window.title, accounts, &self.catalog))
                        .flatten()
                });
            match resolved {
                Some((account, identity)) => {
                    if window.binding.as_ref().is_none_or(|binding| {
                        binding.account != AccountBinding::from(account)
                            || binding.identity != identity
                    }) {
                        window.binding = Some(Binding::new(account, identity, now));
                    }
                }
                None => window.binding = None,
            }
        }
        Ok(())
    }

    fn identify_unknown_focused(
        &mut self,
        app: &AxElement,
        control: &Control,
        config: &Configuration,
    ) {
        let Some(generation) = control.pause.stable_unpaused_generation() else {
            return;
        };
        let Some(focused) = app.element_attr("AXFocusedWindow") else {
            return;
        };
        let Some(id) = locked_session::window_id(&focused) else {
            return;
        };
        let Some(window) = self.windows.get_mut(&id).filter(|window| {
            window.ready
                && window.binding.is_none()
                && window.element.same_element(&focused)
                && window.discovery.due(Instant::now())
        }) else {
            return;
        };
        if !device_windows::focused_session(app, &window.title)
            .is_some_and(|current| current.same_element(&window.element))
        {
            return;
        }
        // Both guards are nonblocking: respect Enter, reconnect, credential
        // entry and settings quiescence. Never identify a background window.
        let Some(activity) = control.pause.try_begin_vm_discovery() else {
            return;
        };
        let Ok(_launch) = crate::single_instance::acquire_desktop_launch_lock() else {
            return;
        };
        let cancelled = || {
            control.stop.load(Ordering::Acquire)
                || !activity.is_current()
                || control.pause.stable_unpaused_generation() != Some(generation)
                || control
                    .config
                    .lock()
                    .map_or(true, |current| *current != *config || !current.active)
        };
        if cancelled() {
            return;
        }
        window.discovery.started(Instant::now());
        match remote_pc_info::read_focused_session(app, &window.element, &window.title, &cancelled)
        {
            Ok(remote_pc_info::SessionRemotePc::Selected(host)) if !cancelled() => {
                if let Some(host) = canonical_remote_pc(&host) {
                    window.discovery.host = Some(host.clone());
                    window.binding =
                        endpoint_account(&host, &config.accounts, &self.catalog).map(|account| {
                            Binding::new(account, VmIdentity::Endpoint(host), Instant::now())
                        });
                    tracing::debug!(
                        window_id = id,
                        matched = window.binding.is_some(),
                        "Remembered the device endpoint of an unknown VM window"
                    );
                }
            }
            Ok(_) => { /* An already-open dialog does not prove its owning VM. */ }
            Err(error) => {
                tracing::debug!(window_id = id, %error, "Could not identify an unknown VM window")
            }
        }
    }

    fn delay(&mut self, now: Instant) {
        for binding in self.windows.values_mut().filter_map(|w| w.binding.as_mut()) {
            binding.next_move = now + MOVE_INTERVAL;
        }
    }

    fn move_due(&mut self, control: &Control, config: &Configuration, now: Instant) {
        let Some(pid) = self.pid else { return };
        for (&id, window) in &mut self.windows {
            if !window.ready {
                continue;
            }
            let Some(binding) = window.binding.as_mut() else {
                continue;
            };
            if now < binding.next_move || binding.active_account(&config.accounts).is_none() {
                continue;
            }
            let mut viewport = Rect::default();
            // The same remote-display geometry check used by reconnect, without
            // its foreground requirement or screen capture.
            if !unsafe {
                waal_background_guest_viewport(window.element.raw, pid, id, &mut viewport)
            } {
                continue;
            }
            let Ok(current) = control.config.lock() else {
                return;
            };
            if control.stop.load(Ordering::Acquire)
                || !current.active
                || control.pause.is_paused()
                || *current != *config
            {
                return;
            }
            let submitted = unsafe {
                waal_post_vm_mouse_move(
                    pid,
                    id,
                    viewport.x,
                    viewport.y,
                    viewport.width,
                    viewport.height,
                    binding.right,
                )
            };
            if submitted {
                binding.submitted(now);
                tracing::debug!(window_id = id, "Submitted background VM mouse movement");
            }
        }
    }
}

/// Evidence observed from this particular window, separate from account settings.
#[derive(Clone, Debug, Eq, PartialEq)]
enum VmIdentity {
    Catalog(String),
    SelectedWindow(String),
    Endpoint(String),
}

#[derive(Default)]
struct Discovery {
    host: Option<String>,
    attempts: u8,
    retry_at: Option<Instant>,
}

impl Discovery {
    fn due(&self, now: Instant) -> bool {
        self.host.is_none() && self.attempts < 3 && self.retry_at.is_none_or(|at| now >= at)
    }

    fn started(&mut self, now: Instant) {
        self.attempts += 1;
        self.retry_at = Some(now + Duration::from_secs(30));
    }

    fn prioritize(&mut self) {
        // Enter is an explicit new opportunity to identify a previously failed
        // window, but must never erase a successfully observed endpoint.
        if self.host.is_none() {
            self.attempts = 0;
            self.retry_at = None;
        }
    }
}

fn selected_account(account: &Account) -> bool {
    account.has_vm_device() && !account.username.trim().is_empty()
}

fn owner_matches(account: &Account, device: &SavedDevice) -> bool {
    let owner = if account.vm_profile.trim().is_empty() {
        &account.username
    } else {
        &account.vm_profile
    };
    device.owner.is_empty() || usernames_match(owner, &device.owner)
}

fn unique_enabled<'a>(mut candidates: impl Iterator<Item = &'a Account>) -> Option<&'a Account> {
    let account = candidates.next()?;
    (candidates.next().is_none() && account.vm_mouse_movement_enabled()).then_some(account)
}

fn passive_account<'a>(
    title: &str,
    accounts: &'a [Account],
    catalog: &[SavedDevice],
) -> Option<(&'a Account, VmIdentity)> {
    let mut devices = catalog.iter().filter(|d| d.name == title);
    let device = devices.next();
    if devices.next().is_some()
        || device.is_some_and(|matched| {
            catalog
                .iter()
                .filter(|candidate| candidate.id == matched.id)
                .count()
                != 1
        })
    {
        return None;
    }
    let candidates = accounts.iter().filter(|a| {
        if !selected_account(a) {
            return false;
        }
        if let Some(device) = device {
            if !owner_matches(a, device) {
                return false;
            }
            if !a.vm_device_id.is_empty() && a.vm_device_id != "open-window" {
                return a.vm_device_id == device.id;
            }
            // Legacy and explicitly selected open windows still require the
            // selected title; the workspace owner alone identifies no VM.
            return a.vm_target == title;
        }
        // Only an explicit open-window choice can use a window title without
        // catalog evidence. Saved-device IDs require catalog or endpoint proof.
        a.vm_target == title && a.vm_device_id == "open-window"
    });
    let account = unique_enabled(candidates)?;
    let identity = match device {
        Some(device) => VmIdentity::Catalog(device.id.clone()),
        None => VmIdentity::SelectedWindow(title.to_owned()),
    };
    Some((account, identity))
}

fn endpoint_account<'a>(
    host: &str,
    accounts: &'a [Account],
    catalog: &[SavedDevice],
) -> Option<&'a Account> {
    let host = canonical_remote_pc(host)?;
    if crate::remote_pc::is_cloud_pc_gateway(&host) {
        return None;
    }
    unique_enabled(accounts.iter().filter(|account| {
        if !selected_account(account) {
            return false;
        }
        let mut devices = catalog
            .iter()
            .filter(|device| device.id == account.vm_device_id);
        let device = devices.next();
        if devices.next().is_some() || device.is_some_and(|d| !owner_matches(account, d)) {
            return false;
        }
        // A saved bookmark's destination is authoritative. Workspace devices
        // use the endpoint imported when the user selected that VM.
        let selected_host = device
            .and_then(|d| d.remote_pc.as_deref())
            .unwrap_or(&account.remote_pc);
        canonical_remote_pc(selected_host).as_ref() == Some(&host)
    }))
}

fn watch(control: Arc<Control>) {
    let mut windows = Windows::default();
    let mut observing = None;
    let mut observation = None;
    while !control.stop.load(Ordering::Acquire) {
        let config = match control.config.lock() {
            Ok(c) => c.clone(),
            Err(_) => break,
        };
        let now = Instant::now();
        if config.active
            && !control.pause.is_paused()
            && config
                .accounts
                .iter()
                .any(Account::vm_mouse_movement_enabled)
        {
            match device_windows::running_app() {
                Ok(Some(app)) => {
                    let pid = app.process_id();
                    if observing != pid {
                        observation =
                            pid.and_then(|pid| observe_connection_windows(pid, thread::current()));
                        observing = pid;
                    }
                    let notified = observation
                        .as_ref()
                        .map(|o| {
                            std::iter::from_fn(|| o.take_window())
                                .filter_map(|w| AxElement::from_cf(&w))
                                .collect()
                        })
                        .unwrap_or_default();
                    if windows
                        .observe(&app, &config.accounts, now, notified)
                        .is_ok()
                    {
                        windows.identify_unknown_focused(&app, &control, &config);
                        windows.move_due(&control, &config, Instant::now());
                    }
                }
                Ok(None) => {
                    windows = Windows::default();
                    observation = None;
                    observing = None;
                }
                Err(_) => { /* An incomplete inspection never authorizes input. */ }
            }
        } else {
            windows.delay(now);
        }
        thread::park_timeout(DISCOVERY_INTERVAL);
    }
}

#[repr(C)]
#[derive(Default)]
struct Rect {
    x: f64,
    y: f64,
    width: f64,
    height: f64,
}

unsafe extern "C" {
    fn waal_vm_window_presence(pid: i32, id: u32) -> i32;
    fn waal_background_guest_viewport(
        window: super::AXUIElementRef,
        pid: i32,
        id: u32,
        viewport: *mut Rect,
    ) -> bool;
    fn waal_post_vm_mouse_move(
        pid: i32,
        id: u32,
        x: f64,
        y: f64,
        width: f64,
        height: f64,
        right: bool,
    ) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incomplete_window_snapshots_suspend_delivery_without_losing_the_binding() {
        use WindowStatus::*;
        for (native, accessibility, sessions) in [
            (Incomplete, Current, 1),
            (Current, Incomplete, 1),
            (Incomplete, Incomplete, 1),
            (Current, Current, 0),
            (Current, Current, 2),
        ] {
            assert_eq!(window_status(native, accessibility, sessions), Incomplete);
        }
        // A later complete snapshot permits the retained window again.
        assert_eq!(window_status(Current, Current, 1), Current);
    }

    #[test]
    fn proven_closure_or_replacement_evicts_even_with_incomplete_ax_or_menu() {
        use WindowStatus::*;
        assert_eq!(window_status(Gone, Incomplete, 0), Gone);
        assert_eq!(window_status(Gone, Current, 1), Gone);
        assert_eq!(window_status(Incomplete, Gone, 2), Gone);
        assert_eq!(window_status(Current, Gone, 1), Gone);
    }

    #[test]
    fn movement_waits_four_minutes_and_never_catches_up_in_a_burst() {
        let mut account = Account::new("user@example.com");
        account.move_mouse_in_vm = true;
        let start = Instant::now();
        account.vm_target = "My VM".into();
        account.vm_device_id = "open-window".into();
        let mut binding = Binding::new(&account, VmIdentity::SelectedWindow("My VM".into()), start);
        assert_eq!(binding.next_move, start + Duration::from_secs(240));
        assert!(start + Duration::from_secs(239) < binding.next_move);
        let late = start + Duration::from_secs(3600);
        binding.submitted(late);
        assert_eq!(binding.next_move, late + Duration::from_secs(240));
        assert!(!binding.right);
        assert!(binding.active_account(&[account.clone()]).is_some());
        account.move_mouse_in_vm = false;
        assert!(binding.active_account(&[account.clone()]).is_none());
        account.move_mouse_in_vm = true;
        account.vm_device_id = "workspace:other".into();
        assert!(binding.active_account(&[account]).is_none());
        assert!(binding.active_account(&[]).is_none());
    }

    fn device(name: &str, owner: &str, id: &str) -> SavedDevice {
        SavedDevice::for_test(id, name, owner)
    }

    #[test]
    fn profile_owner_never_authorizes_movement_without_selected_device() {
        let mut account = Account::new("user@example.com");
        account.move_mouse_in_vm = true;
        let devices = [device("My VM", &account.username, "workspace:one")];
        assert!(passive_account("My VM", &[account.clone()], &devices).is_none());
        account.vm_target = "My VM".into();
        account.vm_device_id = "workspace:one".into();
        assert_eq!(
            passive_account("My VM", &[account.clone()], &devices).map(|(a, _)| a.id.clone()),
            Some(account.id.clone())
        );
        assert!(passive_account("Unknown VM", &[account.clone()], &devices).is_none());
        let mut other = account.clone();
        other.id = "other".into();
        other.move_mouse_in_vm = false;
        assert!(passive_account("My VM", &[account.clone(), other], &devices).is_none());
        let shared = [
            devices[0].clone(),
            device("My VM", "other@example.com", "workspace:two"),
        ];
        assert!(passive_account("My VM", &[account.clone()], &shared).is_none());
        account.vm_device_id = "workspace:another".into();
        assert!(passive_account("My VM", &[account], &devices).is_none());
    }

    #[test]
    fn explicit_workspace_uses_the_profile_that_enter_verifies() {
        let mut account = Account::new("rdp-user@example.test");
        account.move_mouse_in_vm = true;
        account.vm_profile = "workspace-user@example.test".into();
        account.vm_device_id = "workspace:one".into();
        account.vm_target = "My VM".into();
        let catalog = [device("My VM", &account.vm_profile, &account.vm_device_id)];
        assert!(passive_account("My VM", &[account.clone()], &catalog).is_some());
        account.vm_profile = "different@example.test".into();
        assert!(passive_account("My VM", &[account], &catalog).is_none());
    }

    #[test]
    fn explicit_native_binding_is_unique_even_when_catalog_is_unavailable() {
        let mut account = Account::new("user@example.com");
        account.move_mouse_in_vm = true;
        account.vm_target = "My VM".into();
        account.vm_device_id = "open-window".into();
        let mut other = Account::new("second@example.com");
        other.vm_target = "My VM".into();
        other.vm_device_id = "open-window".into();
        assert!(passive_account("My VM", &[account.clone()], &[]).is_some());
        assert!(passive_account("My VM", &[account.clone(), other], &[]).is_none());
        account.vm_device_id = "workspace:unknown".into();
        assert!(passive_account("My VM", &[account], &[]).is_none());
    }
    #[test]
    fn unknown_window_endpoint_requires_a_unique_selected_vm() {
        let mut account = Account::new("user@example.com");
        account.move_mouse_in_vm = true;
        account.remote_pc = "pc.example.com".into();
        assert!(endpoint_account("pc.example.com", &[account.clone()], &[]).is_none());
        account.vm_target = "My VM".into();
        account.vm_device_id = "workspace:one".into();
        assert!(endpoint_account("PC.EXAMPLE.COM", &[account.clone()], &[]).is_some());
        assert!(endpoint_account("different.example.com", &[account.clone()], &[]).is_none());
        let mut other = account.clone();
        other.id = "other".into();
        other.move_mouse_in_vm = false;
        assert!(endpoint_account("pc.example.com", &[account.clone(), other], &[]).is_none());
        account.enabled = false;
        assert!(endpoint_account("pc.example.com", &[account], &[]).is_none());
    }

    #[test]
    fn saved_device_id_is_required_even_if_two_devices_have_the_same_owner() {
        let mut account = Account::new("user@example.com");
        account.vm_target = "Chosen VM".into();
        account.vm_device_id = "workspace:chosen".into();
        account.move_mouse_in_vm = true;
        let catalog = [
            device("Chosen VM", &account.username, "workspace:chosen"),
            device("Another VM", &account.username, "workspace:other"),
        ];
        assert!(passive_account("Chosen VM", &[account.clone()], &catalog).is_some());
        assert!(passive_account("Another VM", &[account], &catalog).is_none());
    }

    #[test]
    fn duplicate_catalog_device_ids_cannot_authorize_either_window() {
        let mut account = Account::new("user@example.com");
        account.vm_target = "Chosen VM".into();
        account.vm_device_id = "workspace:shared".into();
        account.move_mouse_in_vm = true;
        let catalog = [
            device("Chosen VM", &account.username, "workspace:shared"),
            device("Another VM", &account.username, "workspace:shared"),
        ];
        for title in ["Chosen VM", "Another VM"] {
            assert!(passive_account(title, &[account.clone()], &catalog).is_none());
        }
    }

    #[test]
    fn endpoint_cannot_override_a_different_saved_bookmark_host() {
        let mut account = Account::new("user@example.com");
        account.vm_target = "My VM".into();
        account.vm_device_id = "bookmark:one".into();
        account.remote_pc = "stale.example.com".into();
        account.move_mouse_in_vm = true;
        let mut selected = device("My VM", &account.username, "bookmark:one");
        selected.remote_pc = Some("current.example.com".into());
        assert!(
            endpoint_account("stale.example.com", &[account.clone()], &[selected.clone()])
                .is_none()
        );
        assert!(endpoint_account("current.example.com", &[account], &[selected]).is_some());
    }

    #[test]
    fn discovery_caches_success_and_bounds_transient_retries() {
        let start = Instant::now();
        let mut discovery = Discovery::default();
        assert!(discovery.due(start));
        discovery.started(start);
        assert!(!discovery.due(start + Duration::from_secs(29)));
        assert!(discovery.due(start + Duration::from_secs(30)));
        discovery.started(start + Duration::from_secs(30));
        discovery.started(start + Duration::from_secs(60));
        assert!(!discovery.due(start + Duration::from_secs(600)));
        discovery.prioritize();
        assert!(discovery.due(start + Duration::from_secs(600)));
        discovery.host = Some("pc.example.com".into());
        discovery.prioritize();
        assert!(!discovery.due(start + Duration::from_secs(3600)));
    }
}
