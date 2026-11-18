//! Read-only recognition of Windows App's own Microsoft number-matching page.
//! This deliberately does not inspect ordinary remote-session AX subtrees.

use super::{
    collect_descendants_bounded, is_hidden, AxElement, AX_CHILDREN, AX_ROLE, AX_STATIC_TEXT_ROLE,
    AX_SUBROLE, AX_TITLE, AX_VALUE, AX_WINDOWS,
};
use crate::macos_identity::{self, TrustedProcessInfo};
use crate::models::Account;
use anyhow::Context;
use core_foundation::base::CFHash;
use core_foundation::string::CFString;
use core_foundation::url::CFURL;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const AX_IDENTIFIER: &str = "AXIdentifier";
const AX_DOM_IDENTIFIER: &str = "AXDOMIdentifier";
const AX_URL: &str = "AXURL";
const SIGN_IN_WINDOW: &str = "MSID_SIGN_IN_WINDOW";
const SIGN_IN_WEBVIEW: &str = "MSID_SIGN_IN_WEBVIEW";
const CHALLENGE_CONTROL_IDS: [&str; 4] = [
    "displayName",
    "idDiv_SAOTCAS_Title",
    "idDiv_SAOTCAS_Description",
    "idRichContext_DisplaySign",
];
const MAX_NODES: usize = 300;
const MAX_DEPTH: usize = 12;
const MAX_AGE: Duration = Duration::from_secs(120);

/// Kept on the thread that detected it. No Debug/Serialize implementation:
/// account and challenge values must not enter logs or persistence.
pub(crate) struct Challenge {
    account_id: String,
    username: String,
    number: Zeroizing<String>,
    process: TrustedProcessInfo,
    window: AxElement,
    webview: AxElement,
    web_area: AxElement,
    account_element: AxElement,
    number_element: AxElement,
    detected_at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Completion {
    Pending,
    ClosedUnverified,
    Changed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DesktopCheckFailure {
    Expired,
    WindowGone,
    WindowChanged,
    RequestGone,
    RequestChanged,
}

impl std::fmt::Display for DesktopCheckFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Expired => "iPhone sign-in request expired",
            Self::WindowGone => "Microsoft sign-in window is no longer visible",
            Self::WindowChanged => "Microsoft sign-in window changed",
            Self::RequestGone => "Microsoft number-matching request is no longer present",
            Self::RequestChanged => "Microsoft number-matching request changed",
        })
    }
}

impl std::error::Error for DesktopCheckFailure {}

impl Challenge {
    pub(crate) fn matches_account(&self, account: &Account) -> bool {
        account.enabled
            && account.iphone_authenticator_enabled
            && account.id == self.account_id
            && account.username.trim().eq_ignore_ascii_case(&self.username)
    }

    pub(crate) fn number(&self) -> &str {
        self.number.as_str()
    }

    /// Identifies one number-matching request within a native dialog. A new
    /// number may be attempted in the same window; the same request stays
    /// suppressed until definitive absence. Never log or persist this hash.
    pub(crate) fn fingerprint(&self) -> u64 {
        // CFHash follows AX object equality across freshly copied references;
        // raw AX pointer addresses do not have that property.
        request_fingerprint(
            &self.account_id,
            self.process.pid,
            unsafe { CFHash(self.window.raw.cast()) },
            &self.number,
        )
    }

    pub(crate) fn revalidate(&self, guard: &dyn Fn() -> anyhow::Result<()>) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.detected_at.elapsed() <= MAX_AGE,
            DesktopCheckFailure::Expired
        );
        guard()?;
        let Some((process, window)) = unique_sign_in_window(guard)? else {
            anyhow::bail!(DesktopCheckFailure::WindowGone);
        };
        anyhow::ensure!(
            same_process(&self.process, &process) && self.window.same_element(&window),
            DesktopCheckFailure::WindowChanged
        );
        let account = Account {
            id: self.account_id.clone(),
            username: self.username.clone(),
            has_saved_password: false,
            enabled: true,
            remote_pc: String::new(),
            vm_target: String::new(),
            vm_profile: String::new(),
            vm_device_id: String::new(),
            reconnect_locked_vm: false,
            iphone_authenticator_enabled: true,
            authenticator_provider: Default::default(),
        };
        let current = challenge_in_window(&process, &window, &[account], guard)?
            .context(DesktopCheckFailure::RequestGone)?;
        anyhow::ensure!(
            self.same_request(&current),
            DesktopCheckFailure::RequestChanged
        );
        guard()
    }

    pub(crate) fn poll_completion(
        &self,
        guard: &dyn Fn() -> anyhow::Result<()>,
    ) -> anyhow::Result<Completion> {
        guard()?;
        let Some((process, window)) = unique_sign_in_window(guard)? else {
            // Closing the dialog can also mean cancellation. Without an
            // official completion result this must never imply success.
            return Ok(Completion::ClosedUnverified);
        };
        if !same_process(&self.process, &process) || !self.window.same_element(&window) {
            return Ok(Completion::Changed);
        }
        let account = Account {
            id: self.account_id.clone(),
            username: self.username.clone(),
            has_saved_password: false,
            enabled: true,
            remote_pc: String::new(),
            vm_target: String::new(),
            vm_profile: String::new(),
            vm_device_id: String::new(),
            reconnect_locked_vm: false,
            iphone_authenticator_enabled: true,
            authenticator_provider: Default::default(),
        };
        let current = challenge_in_window(&process, &window, &[account], guard)?;
        guard()?;
        Ok(
            if current
                .as_ref()
                .is_some_and(|current| self.same_request(current))
            {
                Completion::Pending
            } else {
                Completion::Changed
            },
        )
    }

    fn same_request(&self, other: &Self) -> bool {
        self.account_id == other.account_id
            && self.username.eq_ignore_ascii_case(&other.username)
            && self.number.as_str() == other.number.as_str()
            && self.webview.same_element(&other.webview)
            && self.web_area.same_element(&other.web_area)
            && self.account_element.same_element(&other.account_element)
            && self.number_element.same_element(&other.number_element)
    }
}

fn request_fingerprint(account_id: &str, pid: i32, window_identity: usize, number: &str) -> u64 {
    let mut hash = DefaultHasher::new();
    account_id.hash(&mut hash);
    pid.hash(&mut hash);
    window_identity.hash(&mut hash);
    number.hash(&mut hash);
    hash.finish()
}

pub(crate) fn detect(
    accounts: &[Account],
    guard: &dyn Fn() -> anyhow::Result<()>,
) -> anyhow::Result<Option<Challenge>> {
    guard()?;
    if !accounts
        .iter()
        .any(|account| account.enabled && account.iphone_authenticator_enabled)
    {
        return Ok(None);
    }
    let Some((process, window)) = unique_sign_in_window(guard)? else {
        return Ok(None);
    };
    let result = challenge_in_window(&process, &window, accounts, guard)?;
    guard()?;
    Ok(result)
}

/// Absence evidence for episode suppression. A non-challenge page in an open
/// MSAL dialog must not rearm an already-submitted approval attempt.
pub(crate) fn has_visible_sign_in_window(
    guard: &dyn Fn() -> anyhow::Result<()>,
) -> anyhow::Result<bool> {
    guard()?;
    let present = unique_sign_in_window(guard)?.is_some();
    guard()?;
    Ok(present)
}

fn same_process(left: &TrustedProcessInfo, right: &TrustedProcessInfo) -> bool {
    left.pid == right.pid
        && left.bundle_id == right.bundle_id
        && left.bundle_path == right.bundle_path
        && left.team_id == right.team_id
}

fn unique_sign_in_window(
    guard: &dyn Fn() -> anyhow::Result<()>,
) -> anyhow::Result<Option<(TrustedProcessInfo, AxElement)>> {
    let mut selected = None;
    for process in macos_identity::trusted_process_infos(crate::config::TARGET_APP_NAME)? {
        guard()?;
        let app =
            AxElement::application(process.pid).context("Microsoft application is unavailable")?;
        for window in app.array_attr_result(AX_WINDOWS)? {
            guard()?;
            if is_hidden(&window)
                || !native_sign_in_identity(
                    window.string_attr(AX_ROLE).as_deref(),
                    window.string_attr(AX_SUBROLE).as_deref(),
                    window.string_attr(AX_IDENTIFIER).as_deref(),
                )
            {
                continue;
            }
            anyhow::ensure!(
                window.process_id() == Some(process.pid),
                "Microsoft sign-in window ownership changed"
            );
            anyhow::ensure!(
                selected.is_none(),
                "Multiple Microsoft sign-in windows are visible"
            );
            selected = Some((process.clone(), window));
        }
    }
    Ok(selected)
}

fn native_sign_in_identity(role: Option<&str>, subrole: Option<&str>, id: Option<&str>) -> bool {
    role == Some("AXWindow") && subrole == Some("AXDialog") && id == Some(SIGN_IN_WINDOW)
}

fn bounded_elements(
    root: &AxElement,
    guard: &dyn Fn() -> anyhow::Result<()>,
) -> anyhow::Result<Vec<AxElement>> {
    bounded_elements_until(root, None, guard)
}

fn bounded_elements_until(
    root: &AxElement,
    boundary: Option<(&'static str, &str)>,
    guard: &dyn Fn() -> anyhow::Result<()>,
) -> anyhow::Result<Vec<AxElement>> {
    guard()?;
    collect_descendants_bounded(root, MAX_DEPTH, MAX_NODES, &mut |node| {
        guard()?;
        // Keep the identified boundary element, but traverse its descendants
        // only in the next narrowly scoped recognition stage.
        if boundary.is_some_and(|(attr, value)| node.string_attr(attr).as_deref() == Some(value)) {
            return Ok(Vec::new());
        }
        Ok(node
            .optional_relationship_array_attr_result(AX_CHILDREN)?
            .into_iter()
            .filter(|child| !is_hidden(child))
            .collect())
    })
    .into_complete_elements()
}

fn unique_element(
    elements: &[AxElement],
    attr: &'static str,
    value: &str,
) -> anyhow::Result<Option<AxElement>> {
    let mut matches = elements
        .iter()
        .filter(|node| node.string_attr(attr).as_deref() == Some(value));
    let first = matches.next().cloned();
    anyhow::ensure!(
        matches.next().is_none(),
        "Microsoft sign-in page has ambiguous controls"
    );
    Ok(first)
}

fn owned(node: &AxElement, pid: i32) -> anyhow::Result<()> {
    anyhow::ensure!(
        node.process_id() == Some(pid) && !is_hidden(node),
        "Microsoft sign-in control ownership changed"
    );
    Ok(())
}

/// Index only the four supported controls during this observation. All nodes
/// must be considered: an alert or duplicate can follow the expected controls.
fn page_control_indices(
    metadata: impl Iterator<Item = anyhow::Result<(Option<String>, Option<String>)>>,
) -> anyhow::Result<Option<[usize; 4]>> {
    let mut indices = [0; 4];
    let mut counts = [0; 4];
    for (index, entry) in metadata.enumerate() {
        let (id, role) = entry?;
        if role.as_deref() == Some("AXAlert")
            || id
                .as_deref()
                .is_some_and(|id| id.to_ascii_lowercase().contains("error"))
        {
            return Ok(None);
        }
        if let Some(slot) = CHALLENGE_CONTROL_IDS
            .iter()
            .position(|required| Some(*required) == id.as_deref())
        {
            counts[slot] += 1;
            indices[slot] = index;
        }
    }
    for count in counts {
        if count == 0 {
            return Ok(None);
        }
        anyhow::ensure!(count == 1, "Microsoft sign-in page has ambiguous controls");
    }
    Ok(Some(indices))
}

fn challenge_in_window(
    process: &TrustedProcessInfo,
    window: &AxElement,
    accounts: &[Account],
    guard: &dyn Fn() -> anyhow::Result<()>,
) -> anyhow::Result<Option<Challenge>> {
    // Only this exact native MSAL window is traversed. The native bridge can
    // expose an unowned intermediate AXGroup; every selected web/control node
    // is separately required to belong to the verified Windows App PID.
    let window_nodes =
        bounded_elements_until(window, Some((AX_IDENTIFIER, SIGN_IN_WEBVIEW)), guard)?;
    let Some(webview) = unique_element(&window_nodes, AX_IDENTIFIER, SIGN_IN_WEBVIEW)? else {
        return Ok(None);
    };
    owned(&webview, process.pid)?;
    let webview_nodes = bounded_elements_until(&webview, Some((AX_ROLE, "AXWebArea")), guard)?;
    let Some(web_area) = unique_element(&webview_nodes, AX_ROLE, "AXWebArea")? else {
        return Ok(None);
    };
    owned(&web_area, process.pid)?;
    anyhow::ensure!(
        trusted_web_origin(&web_area),
        "Microsoft sign-in page origin is not supported"
    );
    let nodes = bounded_elements(&web_area, guard)?;
    let metadata = nodes.iter().map(|node| {
        guard()?;
        let mut attrs = node.string_attrs(&[AX_DOM_IDENTIFIER, AX_ROLE]).into_iter();
        // Some AX implementations return individual errors inside a successful
        // batch. Re-read missing entries before ruling out an error or alert.
        let id = attrs
            .next()
            .flatten()
            .or_else(|| node.string_attr(AX_DOM_IDENTIFIER));
        let role = attrs.next().flatten().or_else(|| node.string_attr(AX_ROLE));
        Ok((id, role))
    });
    let Some(indices) = page_control_indices(metadata)? else {
        return Ok(None);
    };
    let controls = indices.map(|index| &nodes[index]);
    for (node, expected_id) in controls.into_iter().zip(CHALLENGE_CONTROL_IDS) {
        owned(node, process.pid)?;
        anyhow::ensure!(
            node.string_attr(AX_DOM_IDENTIFIER).as_deref() == Some(expected_id),
            "Microsoft sign-in control identity changed"
        );
    }
    let [account_group, heading, description, number_group] = controls;
    if heading.string_attr(AX_ROLE).as_deref() != Some("AXHeading")
        || heading.string_attr(AX_TITLE).as_deref() != Some("Approve sign in request")
    {
        return Ok(None);
    }
    let description_text = static_text(description, process.pid, guard)?;
    if !description_text
        .to_ascii_lowercase()
        .contains("authenticator")
        || !description_text
            .to_ascii_lowercase()
            .contains("enter the number")
    {
        return Ok(None);
    }
    let (account_element, username) = single_static_value(account_group, process.pid, guard)?;
    let Some(account) = select_account(accounts, username.trim())? else {
        return Ok(None);
    };
    let (number_element, number) = single_static_value(number_group, process.pid, guard)?;
    anyhow::ensure!(
        valid_number(&number),
        "Microsoft number-matching value is not supported"
    );
    guard()?;
    Ok(Some(Challenge {
        account_id: account.id.clone(),
        username: account.username.trim().to_string(),
        number,
        process: process.clone(),
        window: window.clone(),
        webview,
        web_area,
        account_element,
        number_element,
        detected_at: Instant::now(),
    }))
}

fn select_account<'a>(
    accounts: &'a [Account],
    username: &str,
) -> anyhow::Result<Option<&'a Account>> {
    let mut matches = accounts.iter().filter(|account| {
        account.enabled
            && account.iphone_authenticator_enabled
            && account.username.trim().eq_ignore_ascii_case(username)
    });
    let first = matches.next();
    anyhow::ensure!(
        matches.next().is_none(),
        "Multiple enabled accounts match the Microsoft sign-in request"
    );
    if let Some(account) = first {
        anyhow::ensure!(
            accounts
                .iter()
                .filter(|candidate| candidate.id == account.id)
                .count()
                == 1,
            "Microsoft sign-in account identity is ambiguous"
        );
    }
    Ok(first)
}

fn single_static_element(
    parent: &AxElement,
    pid: i32,
    guard: &dyn Fn() -> anyhow::Result<()>,
) -> anyhow::Result<AxElement> {
    let nodes = bounded_elements(parent, guard)?;
    let mut matches = nodes
        .into_iter()
        .filter(|node| node.string_attr(AX_ROLE).as_deref() == Some(AX_STATIC_TEXT_ROLE));
    let node = matches
        .next()
        .context("Microsoft sign-in field is unavailable")?;
    anyhow::ensure!(
        matches.next().is_none(),
        "Microsoft sign-in field is ambiguous"
    );
    owned(&node, pid)?;
    Ok(node)
}

fn single_static_value(
    parent: &AxElement,
    pid: i32,
    guard: &dyn Fn() -> anyhow::Result<()>,
) -> anyhow::Result<(AxElement, Zeroizing<String>)> {
    let node = single_static_element(parent, pid, guard)?;
    let value = Zeroizing::new(
        node.string_attr(AX_VALUE)
            .context("Microsoft sign-in field has no text")?,
    );
    anyhow::ensure!(
        value.len() <= 320,
        "Microsoft sign-in field exceeds its bound"
    );
    Ok((node, value))
}

fn static_text(
    parent: &AxElement,
    pid: i32,
    guard: &dyn Fn() -> anyhow::Result<()>,
) -> anyhow::Result<Zeroizing<String>> {
    let (_, text) = single_static_value(parent, pid, guard)?;
    Ok(text)
}

fn trusted_web_origin(web_area: &AxElement) -> bool {
    let Some(value) = web_area.copy_attr(AX_URL) else {
        return false;
    };
    let url = Zeroizing::new(if let Some(url) = value.downcast::<CFURL>() {
        url.get_string().to_string()
    } else if let Some(url) = value.downcast::<CFString>() {
        url.to_string()
    } else {
        return false;
    });
    valid_web_origin(&url)
}

fn valid_web_origin(url: &str) -> bool {
    url.len() <= 16_384
        && url.starts_with("https://login.microsoftonline.com/")
        && !url.chars().any(char::is_control)
}

fn valid_number(number: &str) -> bool {
    number.len() == 2 && number.bytes().all(|byte| byte.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_only_page_does_not_qualify_as_an_authenticator_challenge() {
        let controls = [
            ("displayName", "AXGroup"),
            ("i0118", "AXTextField"),
            ("idSIButton9", "AXButton"),
        ];
        let page = controls
            .into_iter()
            .map(|(id, role)| Ok((Some(id.to_owned()), Some(role.to_owned()))));
        assert_eq!(page_control_indices(page).unwrap(), None);
    }

    #[test]
    fn a_complete_set_of_controls_cannot_hide_a_later_alert_error_or_duplicate() {
        let controls = [
            ("idRichContext_DisplaySign", "AXGroup"),
            ("unrelated", "AXGroup"),
            ("idDiv_SAOTCAS_Title", "AXHeading"),
            ("displayName", "AXGroup"),
            ("idDiv_SAOTCAS_Description", "AXGroup"),
        ];
        let inspect = |extra: Option<(&str, &str)>| {
            page_control_indices(
                controls
                    .into_iter()
                    .chain(extra)
                    .map(|(id, role)| Ok((Some(id.to_owned()), Some(role.to_owned())))),
            )
        };
        assert_eq!(inspect(None).unwrap(), Some([3, 2, 4, 0]));
        assert_eq!(inspect(Some(("notice", "AXAlert"))).unwrap(), None);
        assert_eq!(inspect(Some(("loginError", "AXGroup"))).unwrap(), None);
        assert!(inspect(Some(("displayName", "AXGroup"))).is_err());
    }

    #[test]
    fn a_new_number_in_the_same_dialog_is_eligible_without_replaying_the_old_request() {
        let mut attempted = std::collections::HashSet::new();
        let first = request_fingerprint("account-1", 42, 100, "17");
        assert!(attempted.insert(first));
        assert!(!attempted.insert(request_fingerprint("account-1", 42, 100, "17")));

        assert!(attempted.insert(request_fingerprint("account-1", 42, 100, "28")));
        assert!(!attempted.insert(first));
    }

    #[test]
    fn number_matching_fingerprint_remains_bound_to_account_process_and_window() {
        let request = request_fingerprint("account-1", 42, 100, "17");
        assert_ne!(request, request_fingerprint("account-2", 42, 100, "17"));
        assert_ne!(request, request_fingerprint("account-1", 43, 100, "17"));
        assert_ne!(request, request_fingerprint("account-1", 42, 101, "17"));
    }

    #[test]
    fn only_native_msal_dialog_is_eligible_not_remote_session_or_title_match() {
        assert!(native_sign_in_identity(
            Some("AXWindow"),
            Some("AXDialog"),
            Some(SIGN_IN_WINDOW)
        ));
        for (role, subrole, id) in [
            ("AXWindow", "AXStandardWindow", SIGN_IN_WINDOW),
            ("AXWindow", "AXDialog", "RemoteSession"),
            ("AXGroup", "AXDialog", SIGN_IN_WINDOW),
            ("AXWindow", "AXDialog", "Windows App"),
        ] {
            assert!(!native_sign_in_identity(
                Some(role),
                Some(subrole),
                Some(id)
            ));
        }
    }

    #[test]
    fn web_origin_rejects_lookalikes_credentials_and_non_https() {
        assert!(valid_web_origin(
            "https://login.microsoftonline.com/common/SAS/BeginAuth"
        ));
        for url in [
            "http://login.microsoftonline.com/",
            "https://login.microsoftonline.com.evil.example/",
            "https://login.microsoftonline.com@evil.example/",
            "https://evil.example/login.microsoftonline.com/",
            "https://login.microsoftonline.com:8443/",
            "https://login.microsoftonline.com\\@evil.example/",
            "https://login.microsoftonline.com/\n",
            "file:///login.microsoftonline.com/",
        ] {
            assert!(!valid_web_origin(url));
        }
    }

    #[test]
    fn number_match_accepts_only_observed_two_ascii_digit_format() {
        for number in ["00", "09", "42", "99"] {
            assert!(valid_number(number));
        }
        for number in ["", "4", "123", "123456", " 42", "42\n", "٤٢", "4.2"] {
            assert!(!valid_number(number));
        }
    }

    #[test]
    fn account_requires_exact_unique_enabled_opt_in_and_not_saved_password() {
        let mut account = Account::new("person@example.com");
        assert!(select_account(&[account.clone()], "person@example.com")
            .unwrap()
            .is_none());
        account.iphone_authenticator_enabled = true;
        assert!(select_account(&[account.clone()], "PERSON@example.com")
            .unwrap()
            .is_some());
        assert!(select_account(&[account.clone()], "other@example.com")
            .unwrap()
            .is_none());
        assert!(select_account(&[account.clone(), account.clone()], "person@example.com").is_err());
        account.enabled = false;
        assert!(select_account(&[account], "person@example.com")
            .unwrap()
            .is_none());
    }

    #[test]
    fn account_rejects_duplicate_id_even_with_distinct_emails_and_no_saved_password() {
        let mut selected = Account::new("selected@example.com");
        selected.iphone_authenticator_enabled = true;
        let mut other = Account::new("other@example.com");
        other.id = selected.id.clone();
        other.iphone_authenticator_enabled = true;
        assert!(
            select_account(&[other.clone(), selected.clone()], "selected@example.com").is_err()
        );

        // Disabled or non-opted-in metadata must not give a selected identity
        // multiple meanings elsewhere in the handoff or retry bookkeeping.
        other.enabled = false;
        other.iphone_authenticator_enabled = false;
        assert!(
            select_account(&[other.clone(), selected.clone()], "selected@example.com").is_err()
        );

        other.id = "distinct-account-id".to_string();
        assert!(select_account(&[other, selected], "selected@example.com")
            .unwrap()
            .is_some());
    }
}
