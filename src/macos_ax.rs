use crate::macos_identity;
use anyhow::Context;
use core_foundation::array::{CFArray, CFArrayRef};
use core_foundation::base::{
    CFEqual, CFGetTypeID, CFIndexConvertible, CFRelease, CFRetain, CFType, CFTypeID, CFTypeRef,
    TCFType,
};
use core_foundation::boolean::CFBoolean;
use core_foundation::string::{CFString, CFStringRef};
use std::ffi::c_void;
use std::fmt;
use std::thread;
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

const MAX_ELEMENT_COUNT: usize = 900;
const AX_SEARCH_DEPTH: usize = 12;
const MAX_DIRECT_SHEET_COUNT: usize = 8;
const AX_MESSAGING_TIMEOUT_SECONDS: f32 = 0.15;
const FOCUS_STABLE_SETTLE_MS: u64 = 150;
const FOCUS_ACQUIRE_TIMEOUT_MS: u64 = 500;
const FOCUS_POLL_INTERVAL_MS: u64 = 10;
const KEY_EVENT_SETTLE_MS: u64 = 30;
const POST_FILL_SETTLE_MS: u64 = 40;
#[cfg_attr(not(test), allow(dead_code))]
const PASSWORD_FILL_READY_MS: u64 = 40;
const FAST_SUBMIT_READY_TIMEOUT_MS: u64 = 60;
const POST_SUBMIT_REQUIRED_ABSENCE_DWELL_MS: u64 = 1_500;
const PASSWORD_CLEANUP_ATTEMPTS: usize = 3;
const PASSWORD_CLEANUP_RETRY_MS: u64 = 50;

const AX_WINDOWS: &str = "AXWindows";
const AX_SHEETS: &str = "AXSheets";
const AX_CHILDREN: &str = "AXChildren";
const AX_ROLE: &str = "AXRole";
const AX_SUBROLE: &str = "AXSubrole";
const AX_ROLE_DESCRIPTION: &str = "AXRoleDescription";
const AX_TITLE: &str = "AXTitle";
const AX_DESCRIPTION: &str = "AXDescription";
const AX_HELP: &str = "AXHelp";
const AX_PLACEHOLDER: &str = "AXPlaceholderValue";
const AX_VALUE: &str = "AXValue";
const AX_ENABLED: &str = "AXEnabled";
const AX_HIDDEN: &str = "AXHidden";
const AX_FOCUSED: &str = "AXFocused";
const AX_FOCUSED_UI_ELEMENT: &str = "AXFocusedUIElement";
const AX_FRONTMOST: &str = "AXFrontmost";
const AX_MAIN: &str = "AXMain";
const AX_PARENT: &str = "AXParent";
const AX_PRESS: &str = "AXPress";

const AX_BUTTON_ROLE: &str = "AXButton";
const AX_TEXT_FIELD_ROLE: &str = "AXTextField";
const AX_SECURE_TEXT_FIELD_ROLE: &str = "AXSecureTextField";
const AX_STATIC_TEXT_ROLE: &str = "AXStaticText";
const AX_SHEET_ROLE: &str = "AXSheet";
const AX_WINDOW_ROLE: &str = "AXWindow";
const AX_DIALOG_SUBROLE: &str = "AXDialog";
const AX_SYSTEM_DIALOG_SUBROLE: &str = "AXSystemDialog";

const KEYCODE_A: u16 = 0;
const KEYCODE_RETURN: u16 = 36;
const KEYCODE_DELETE: u16 = 51;
const CG_EVENT_FLAG_MASK_COMMAND: u64 = 1 << 20;

#[derive(Debug, Clone, Default)]
pub(crate) struct MacosInspection {
    pub(crate) process_found: bool,
    pub(crate) target: Option<MacosTarget>,
    pub(crate) prompt: Option<MacosPrompt>,
    pub(crate) prompts: Vec<MacosPrompt>,
    pub(crate) has_session: bool,
    pub(crate) session_windows: Vec<MacosWindowTitle>,
    pub(crate) window_titles: Vec<MacosWindowTitle>,
}

#[derive(Debug, Clone)]
pub(crate) struct MacosTarget {
    pub(crate) process_id: i32,
    pub(crate) window_title: String,
    pub(crate) frontmost: bool,
}

#[derive(Clone)]
pub(crate) struct MacosWindowTitle {
    pub(crate) process_id: i32,
    pub(crate) title: String,
    window: Option<AxElement>,
}

impl fmt::Debug for MacosWindowTitle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MacosWindowTitle")
            .field("process_id", &self.process_id)
            .field("title", &self.title)
            .field("window", &self.window.is_some())
            .finish()
    }
}

#[derive(Clone)]
pub(crate) struct MacosPrompt {
    pub(crate) target: MacosTarget,
    pub(crate) email: Option<String>,
    pub(crate) password_field_description: String,
    pub(crate) password_field_role: String,
    pub(crate) origin: PromptOrigin,
    trusted_process: macos_identity::TrustedProcessInfo,
    target_window: AxElement,
    native_container: AxElement,
    prompt_root: AxElement,
    password_field: AxElement,
    submit_button: Option<AxElement>,
    identity_text: Vec<PromptTextSnapshot>,
}

impl fmt::Debug for MacosPrompt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MacosPrompt")
            .field("target", &self.target)
            .field("email", &self.email)
            .field(
                "password_field_description",
                &self.password_field_description,
            )
            .field("password_field_role", &self.password_field_role)
            .field("origin", &self.origin)
            .field("bundle_id", &self.trusted_process.bundle_id)
            .field("team_id", &self.trusted_process.team_id)
            .field("submit_button", &self.submit_button.is_some())
            .finish()
    }
}

impl MacosPrompt {
    #[cfg_attr(not(feature = "diagnostics-ui"), allow(dead_code))]
    pub(crate) fn password_field_focused(&self) -> Option<bool> {
        self.password_field.bool_attr(AX_FOCUSED)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MacosFillMethod {
    Keyboard,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PromptOrigin {
    Window,
    Sheet,
}

impl PromptOrigin {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            PromptOrigin::Window => "window",
            PromptOrigin::Sheet => "sheet",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct MacosFillResult {
    pub(crate) fill_method: &'static str,
    pub(crate) fill_status: &'static str,
    pub(crate) password_field_focused: bool,
    pub(crate) password_field_role: String,
    pub(crate) password_field_description_present: bool,
    pub(crate) submit_button_ready_after_fill: bool,
    pub(crate) filled_prompt: Option<MacosFilledPrompt>,
}

#[derive(Debug)]
pub(crate) struct MacosFillFailure {
    error: anyhow::Error,
    cleanup_prompt: Option<Box<MacosFilledPrompt>>,
}

impl MacosFillFailure {
    fn before_write(error: anyhow::Error) -> Self {
        Self {
            error,
            cleanup_prompt: None,
        }
    }

    fn ambiguous_write(error: anyhow::Error, cleanup_prompt: MacosFilledPrompt) -> Self {
        Self {
            error,
            cleanup_prompt: Some(Box::new(cleanup_prompt)),
        }
    }

    pub(crate) fn cleanup_prompt(&self) -> Option<&MacosFilledPrompt> {
        self.cleanup_prompt.as_deref()
    }
}

impl fmt::Display for MacosFillFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(f)
    }
}

impl std::error::Error for MacosFillFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.error.source()
    }
}

#[derive(Clone)]
pub(crate) struct MacosFilledPrompt {
    prompt: MacosPrompt,
    expected_email: String,
    trusted_process: macos_identity::TrustedProcessInfo,
    submit_button_ready_after_fill: bool,
}

impl fmt::Debug for MacosFilledPrompt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MacosFilledPrompt")
            .field("process_id", &self.prompt.target.process_id)
            .field("window_title", &self.prompt.target.window_title)
            .field("origin", &self.prompt.origin)
            .field(
                "expected_email_present",
                &!self.expected_email.trim().is_empty(),
            )
            .field("bundle_id", &self.trusted_process.bundle_id)
            .field("team_id", &self.trusted_process.team_id)
            .field(
                "submit_button_ready_after_fill",
                &self.submit_button_ready_after_fill,
            )
            .finish()
    }
}

impl MacosFilledPrompt {
    fn matches_expected(
        &self,
        expected_process_id: i32,
        expected_window_title: &str,
        expected_prompt_origin: &str,
        expected_email: &str,
    ) -> bool {
        self.prompt.target.process_id == expected_process_id
            && self
                .prompt
                .target
                .window_title
                .eq_ignore_ascii_case(expected_window_title)
            && self
                .prompt
                .origin
                .as_str()
                .eq_ignore_ascii_case(expected_prompt_origin.trim())
            && usernames_match(&self.expected_email, expected_email)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct MacosSubmitResult {
    pub(crate) submit_method: &'static str,
    pub(crate) submit_status: &'static str,
    pub(crate) axpress_attempted: bool,
    pub(crate) axpress_result: &'static str,
    pub(crate) enter_fallback_attempted: bool,
    pub(crate) enter_fallback_result: &'static str,
    pub(crate) submitted_prompt: Option<MacosSubmittedPrompt>,
}

#[derive(Clone)]
pub(crate) struct MacosSubmittedPrompt {
    process_id: i32,
    window_title: String,
    email: String,
    origin: PromptOrigin,
    target_window: AxElement,
    prompt_container: AxElement,
}

impl fmt::Debug for MacosSubmittedPrompt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MacosSubmittedPrompt")
            .field("process_id", &self.process_id)
            .field("window_title", &self.window_title)
            .field("email_present", &!self.email.trim().is_empty())
            .field("origin", &self.origin)
            .finish()
    }
}

#[derive(Clone)]
pub(crate) struct MacosVerifiedPrompt {
    pub(crate) prompt: MacosPrompt,
    pub(crate) trusted_process: macos_identity::TrustedProcessInfo,
}

impl fmt::Debug for MacosVerifiedPrompt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MacosVerifiedPrompt")
            .field("process_id", &self.prompt.target.process_id)
            .field("window_title", &self.prompt.target.window_title)
            .field("origin", &self.prompt.origin)
            .field("bundle_id", &self.trusted_process.bundle_id)
            .field("team_id", &self.trusted_process.team_id)
            .finish()
    }
}

impl MacosVerifiedPrompt {
    pub(crate) fn from_detected_prompt(prompt: MacosPrompt) -> Self {
        let trusted_process = prompt.trusted_process.clone();
        Self {
            prompt,
            trusted_process,
        }
    }

    fn matches_expected(
        &self,
        expected_process_id: i32,
        expected_window_title: &str,
        expected_prompt_origin: &str,
        expected_email: &str,
    ) -> bool {
        self.prompt.target.process_id == expected_process_id
            && self
                .prompt
                .target
                .window_title
                .eq_ignore_ascii_case(expected_window_title)
            && self
                .prompt
                .email
                .as_deref()
                .is_some_and(|email| usernames_match(email, expected_email))
            && self
                .prompt
                .origin
                .as_str()
                .eq_ignore_ascii_case(expected_prompt_origin.trim())
    }

    fn identity_text_matches(&self, expected_email: &str, expected_window_title: &str) -> bool {
        prompt_text_snapshots_match(
            &self.prompt.identity_text,
            expected_email,
            expected_window_title,
            self.prompt.origin,
        )
    }
}

struct AxElement {
    raw: AXUIElementRef,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AxTraversalCompleteness {
    Complete,
    ChildQueryFailed(String),
    DepthLimitReached { max_depth: usize },
    ElementLimitReached { max_elements: usize },
}

#[derive(Debug)]
struct AxTraversal<T> {
    elements: Vec<T>,
    completeness: AxTraversalCompleteness,
}

impl<T> AxTraversal<T> {
    fn into_complete_elements(self) -> anyhow::Result<Vec<T>> {
        match self.completeness {
            AxTraversalCompleteness::Complete => Ok(self.elements),
            AxTraversalCompleteness::ChildQueryFailed(error) => {
                anyhow::bail!("AX element traversal was incomplete: child query failed: {error}")
            }
            AxTraversalCompleteness::DepthLimitReached { max_depth } => {
                anyhow::bail!(
                    "AX element traversal was incomplete: depth limit {max_depth} was exceeded"
                )
            }
            AxTraversalCompleteness::ElementLimitReached { max_elements } => {
                anyhow::bail!(
                    "AX element traversal was incomplete: element limit {max_elements} was exceeded"
                )
            }
        }
    }
}

#[derive(Clone)]
struct PromptTextSnapshot {
    element: AxElement,
    title: Option<String>,
    placeholder: Option<String>,
    value: Option<String>,
}

struct PreparedPromptForFill {
    trusted_process: macos_identity::TrustedProcessInfo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AxForegroundState {
    focused: Option<bool>,
    main: Option<bool>,
}

fn zeroizing_utf16_buffer(value: &str) -> Zeroizing<Vec<u16>> {
    // A UTF-8 byte string can never encode to more UTF-16 code units than its
    // byte length. Reserve that upper bound before writing any plaintext so
    // Vec growth cannot free unzeroized password prefixes.
    let mut utf16 = Zeroizing::new(Vec::with_capacity(value.len()));
    let initial_capacity = utf16.capacity();
    utf16.extend(value.encode_utf16());
    debug_assert_eq!(utf16.capacity(), initial_capacity);
    utf16
}

impl Clone for AxElement {
    fn clone(&self) -> Self {
        unsafe {
            CFRetain(self.raw.cast());
        }
        Self { raw: self.raw }
    }
}

impl AxElement {
    fn application(pid: i32) -> Option<Self> {
        let raw = unsafe { AXUIElementCreateApplication(pid) };
        if raw.is_null() {
            None
        } else {
            unsafe {
                let _ = AXUIElementSetMessagingTimeout(raw, AX_MESSAGING_TIMEOUT_SECONDS);
            }
            Some(Self { raw })
        }
    }

    unsafe fn borrowed(raw: AXUIElementRef) -> Option<Self> {
        if raw.is_null() {
            None
        } else {
            CFRetain(raw.cast());
            let _ = AXUIElementSetMessagingTimeout(raw, AX_MESSAGING_TIMEOUT_SECONDS);
            Some(Self { raw })
        }
    }

    fn copy_attr_result(&self, attr: &'static str) -> anyhow::Result<CFType> {
        let attr_name = attr;
        let attr = CFString::from_static_string(attr);
        let mut value: CFTypeRef = std::ptr::null();
        let err = unsafe {
            AXUIElementCopyAttributeValue(self.raw, attr.as_concrete_TypeRef(), &mut value)
        };
        if err != K_AX_ERROR_SUCCESS {
            anyhow::bail!("AX attribute {attr_name} query failed with error {err}");
        }
        if value.is_null() {
            anyhow::bail!("AX attribute {attr_name} query returned a null value");
        }
        Ok(unsafe { TCFType::wrap_under_create_rule(value) })
    }

    fn copy_attr(&self, attr: &'static str) -> Option<CFType> {
        self.copy_attr_result(attr).ok()
    }

    fn copy_optional_relationship_attr_result(
        &self,
        attr: &'static str,
    ) -> anyhow::Result<Option<CFType>> {
        let attr_name = attr;
        let attr = CFString::from_static_string(attr);
        let mut value: CFTypeRef = std::ptr::null();
        let err = unsafe {
            AXUIElementCopyAttributeValue(self.raw, attr.as_concrete_TypeRef(), &mut value)
        };
        if ax_relationship_attr_is_absent(err) {
            return Ok(None);
        }
        if err != K_AX_ERROR_SUCCESS {
            anyhow::bail!("AX relationship attribute {attr_name} query failed with error {err}");
        }
        if value.is_null() {
            anyhow::bail!("AX relationship attribute {attr_name} query returned a null value");
        }
        Ok(Some(unsafe { TCFType::wrap_under_create_rule(value) }))
    }

    fn string_attr(&self, attr: &'static str) -> Option<String> {
        self.copy_attr(attr)
            .and_then(|value| value.downcast_into::<CFString>())
            .map(|value| value.to_string())
            .filter(|value| !value.trim().is_empty())
    }

    fn string_attrs(&self, attrs: &[&'static str]) -> Vec<Option<String>> {
        let attr_strings = attrs
            .iter()
            .map(|attr| CFString::from_static_string(attr))
            .collect::<Vec<_>>();
        let attr_array = CFArray::from_CFTypes(&attr_strings);
        let mut values_ref: CFArrayRef = std::ptr::null();
        let err = unsafe {
            AXUIElementCopyMultipleAttributeValues(
                self.raw,
                attr_array.as_concrete_TypeRef(),
                0,
                &mut values_ref,
            )
        };
        if err != K_AX_ERROR_SUCCESS || values_ref.is_null() {
            return attrs.iter().map(|attr| self.string_attr(attr)).collect();
        }

        let values = unsafe { CFArray::<CFType>::wrap_under_create_rule(values_ref) };
        attrs
            .iter()
            .enumerate()
            .map(|(index, _)| {
                values
                    .get(index.to_CFIndex())
                    .and_then(|value| value.downcast::<CFString>())
                    .map(|value| value.to_string())
                    .filter(|value| !value.trim().is_empty())
            })
            .collect()
    }

    fn bool_attr(&self, attr: &'static str) -> Option<bool> {
        self.copy_attr(attr)
            .and_then(|value| value.downcast_into::<CFBoolean>())
            .map(bool::from)
    }

    fn element_attr(&self, attr: &'static str) -> Option<AxElement> {
        let value = self.copy_attr(attr)?;
        if unsafe { CFGetTypeID(value.as_CFTypeRef()) } != unsafe { AXUIElementGetTypeID() } {
            return None;
        }
        unsafe { AxElement::borrowed(value.as_CFTypeRef().cast()) }
    }

    fn array_attr_checked(&self, attr: &'static str) -> Option<Vec<AxElement>> {
        self.array_attr_result(attr).ok()
    }

    fn array_attr_result(&self, attr: &'static str) -> anyhow::Result<Vec<AxElement>> {
        let array = self
            .copy_attr_result(attr)?
            .downcast_into::<CFArray>()
            .ok_or_else(|| anyhow::anyhow!("AX array attribute has an unexpected value type"))?;

        array
            .get_all_values()
            .into_iter()
            .map(|raw| {
                unsafe { AxElement::borrowed(raw.cast()) }
                    .context("AX array attribute contained an invalid element")
            })
            .collect()
    }

    fn optional_relationship_array_attr_result(
        &self,
        attr: &'static str,
    ) -> anyhow::Result<Vec<AxElement>> {
        let Some(value) = self.copy_optional_relationship_attr_result(attr)? else {
            return Ok(Vec::new());
        };
        let array = value.downcast_into::<CFArray>().ok_or_else(|| {
            anyhow::anyhow!("AX relationship attribute has an unexpected value type")
        })?;

        array
            .get_all_values()
            .into_iter()
            .map(|raw| {
                unsafe { AxElement::borrowed(raw.cast()) }
                    .context("AX relationship attribute contained an invalid element")
            })
            .collect()
    }

    fn set_bool_attr(&self, attr: &'static str, value: bool) -> bool {
        let attr = CFString::from_static_string(attr);
        let value = CFBoolean::from(value);
        unsafe {
            AXUIElementSetAttributeValue(self.raw, attr.as_concrete_TypeRef(), value.as_CFTypeRef())
                == K_AX_ERROR_SUCCESS
        }
    }

    fn set_string_attr(&self, attr: &'static str, value: &str) -> bool {
        let attr = CFString::from_static_string(attr);
        let mut utf16 = zeroizing_utf16_buffer(value);
        let value_ref = unsafe {
            CFStringCreateWithCharactersNoCopy(
                std::ptr::null(),
                utf16.as_ptr(),
                utf16.len() as isize,
                kCFAllocatorNull,
            )
        };
        if value_ref.is_null() {
            return false;
        }
        let cf_value = unsafe { CFString::wrap_under_create_rule(value_ref) };
        let success = unsafe {
            AXUIElementSetAttributeValue(
                self.raw,
                attr.as_concrete_TypeRef(),
                cf_value.as_CFTypeRef(),
            ) == K_AX_ERROR_SUCCESS
        };
        // CFString does not own/copy this buffer. Release it before wiping the
        // backing UTF-16 representation so no local plaintext allocation is
        // left to the allocator after the AX call returns.
        drop(cf_value);
        utf16.zeroize();
        success
    }

    fn perform_action(&self, action: &'static str) -> bool {
        let action = CFString::from_static_string(action);
        (unsafe { AXUIElementPerformAction(self.raw, action.as_concrete_TypeRef()) })
            == K_AX_ERROR_SUCCESS
    }

    fn process_id(&self) -> Option<i32> {
        let mut pid: libc::pid_t = 0;
        let err = unsafe { AXUIElementGetPid(self.raw, &mut pid) };
        (err == K_AX_ERROR_SUCCESS && pid > 0).then_some(pid as i32)
    }

    fn parent(&self) -> Option<Self> {
        let value = self.copy_attr(AX_PARENT)?;
        unsafe { AxElement::borrowed(value.as_CFTypeRef().cast()) }
    }

    fn same_element(&self, other: &AxElement) -> bool {
        unsafe { CFEqual(self.raw.cast(), other.raw.cast()) != 0 }
    }
}

impl Drop for AxElement {
    fn drop(&mut self) {
        unsafe {
            CFRelease(self.raw.cast());
        }
    }
}

impl fmt::Debug for AxElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("AxElement").field(&self.raw).finish()
    }
}

pub(crate) fn inspect(app_name: &str) -> anyhow::Result<MacosInspection> {
    inspect_process(app_name, None, None)
}

pub(crate) fn suppressed_sheet_episode_has_visible_direct_sheet(
    trusted_process: &macos_identity::TrustedProcessInfo,
    expected_parent_window_title: &str,
) -> anyhow::Result<bool> {
    let expected_parent_window_title = expected_parent_window_title.trim();
    if expected_parent_window_title.is_empty() {
        anyhow::bail!("suppressed sheet parent window title is empty");
    }

    let app = AxElement::application(trusted_process.pid)
        .context("suppressed sheet process has no Accessibility application")?;
    if app.process_id() != Some(trusted_process.pid) {
        anyhow::bail!("suppressed sheet Accessibility application PID changed");
    }

    // Background windows are title-only here. Do not traverse their content:
    // the retry decision needs only a unique binding to the original parent
    // and its direct AXSheet relationships.
    let windows = app
        .array_attr_result(AX_WINDOWS)
        .context("unable to enumerate suppressed sheet parent windows")?;
    let mut matching_parents = Vec::new();
    for window in windows {
        if window.process_id() != Some(trusted_process.pid) || is_hidden(&window) {
            continue;
        }
        if !window.string_attr(AX_TITLE).is_some_and(|title| {
            title
                .trim()
                .eq_ignore_ascii_case(expected_parent_window_title)
        }) {
            continue;
        }
        if matching_parents
            .iter()
            .any(|existing: &AxElement| existing.same_element(&window))
        {
            continue;
        }
        matching_parents.push(window);
    }

    if matching_parents.is_empty() {
        return Ok(false);
    }
    let Some(parent) = (matching_parents.len() == 1).then(|| &matching_parents[0]) else {
        anyhow::bail!("suppressed sheet parent window binding is ambiguous");
    };
    let visible_direct_sheet_count = sheet_candidates_for_window(parent)?
        .into_iter()
        .filter(|sheet| !is_hidden(sheet) && element_is_direct_child_of(sheet, parent))
        .count();
    classify_suppressed_sheet_episode_presence(matching_parents.len(), visible_direct_sheet_count)
        .context("suppressed sheet relationship observation is ambiguous")
}

fn classify_suppressed_sheet_episode_presence(
    exact_parent_count: usize,
    visible_direct_sheet_count: usize,
) -> Option<bool> {
    match exact_parent_count {
        0 => Some(false),
        1 if visible_direct_sheet_count <= MAX_DIRECT_SHEET_COUNT => {
            Some(visible_direct_sheet_count > 0)
        }
        _ => None,
    }
}

fn inspect_process(
    app_name: &str,
    expected_process_id: Option<i32>,
    expected_window_title: Option<&str>,
) -> anyhow::Result<MacosInspection> {
    let process_infos = trusted_process_infos_for_inspection(app_name, expected_process_id)?;
    if process_infos.is_empty() {
        return Ok(MacosInspection::default());
    }

    let mut inspection = MacosInspection {
        process_found: true,
        ..Default::default()
    };
    for process in process_infos
        .into_iter()
        .filter(|process| expected_process_id.is_none_or(|pid| process.pid == pid))
    {
        let Some(app) = AxElement::application(process.pid) else {
            continue;
        };
        if app.process_id() != Some(process.pid) {
            continue;
        }
        let app_frontmost = app.bool_attr(AX_FRONTMOST) == Some(true);
        let windows = app
            .array_attr_result(AX_WINDOWS)
            .context("unable to enumerate trusted application windows")?;
        let visible_windows = windows
            .iter()
            .filter(|window| !is_hidden(window))
            .collect::<Vec<_>>();
        let window_foreground_states = visible_windows
            .iter()
            .map(|window| element_foreground_state(window))
            .collect::<Vec<_>>();
        let selected_window_index =
            select_unique_foreground_index(app_frontmost, &window_foreground_states);

        if inspection.target.is_none() {
            inspection.target = Some(MacosTarget {
                process_id: process.pid,
                window_title: String::new(),
                frontmost: app_frontmost,
            });
        }

        for (window_index, window) in visible_windows.into_iter().enumerate() {
            let window_title = window.string_attr(AX_TITLE).unwrap_or_default();
            inspection.window_titles.push(MacosWindowTitle {
                process_id: process.pid,
                title: window_title.clone(),
                window: Some(window.clone()),
            });
            if expected_window_title.is_some()
                && !prompt_window_title_matches(&window_title, expected_window_title)
            {
                continue;
            }

            let window_frontmost = selected_window_index == Some(window_index);
            let target = MacosTarget {
                process_id: process.pid,
                window_title: window_title.clone(),
                frontmost: window_frontmost,
            };
            if inspection.target.as_ref().is_some_and(|target| {
                target.window_title.is_empty() || (!target.frontmost && window_frontmost)
            }) {
                inspection.target = Some(target.clone());
            }

            // Reading an AX subtree can expose unrelated remote-session
            // content. Only the live foreground parent is eligible for
            // credential-sheet inspection; background/session windows remain
            // title-only metadata.
            let visible_sheets = if window_frontmost {
                sheet_candidates_for_window(window)?
                    .into_iter()
                    .filter(|sheet| !is_hidden(sheet) && element_is_direct_child_of(sheet, window))
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            };
            let has_visible_sheet = !visible_sheets.is_empty();
            // Windows App exposes its credential prompt as one of multiple
            // direct AXSheet children. The actual credential sheet reports
            // AXFocused=false while a companion sheet reports true, and both
            // omit AXMain. Select by the complete credential identity instead
            // of unreliable sheet-local foreground flags.
            if let Some(prompt) =
                unique_direct_sheet_prompt(&target, window, &visible_sheets, &process)?
            {
                record_prompt_candidate(&mut inspection, prompt);
            }

            let probable_session_window = is_probable_session_window_title(&window_title);
            if probable_session_window {
                inspection.has_session = true;
                inspection.session_windows.push(MacosWindowTitle {
                    process_id: process.pid,
                    title: window_title.clone(),
                    window: Some(window.clone()),
                });
            }
            if has_visible_sheet
                || !window_frontmost
                || !window_should_scan_for_prompt(window, &window_title)
            {
                continue;
            }

            let window_elements = collect_elements(window)
                .into_complete_elements()
                .context("credential window AX tree traversal was incomplete")?;
            if let Some(prompt) = prompt_from_elements(
                target.clone(),
                window,
                window,
                &window_elements,
                PromptOrigin::Window,
                &process,
            )? {
                record_prompt_candidate(&mut inspection, prompt);
            }
        }
    }

    inspection.prompt = preferred_unique_prompt(&inspection.prompts).cloned();
    Ok(inspection)
}

fn trusted_process_infos_for_inspection(
    app_name: &str,
    expected_process_id: Option<i32>,
) -> anyhow::Result<Vec<macos_identity::TrustedProcessInfo>> {
    if let Some(pid) = expected_process_id {
        return Ok(macos_identity::trusted_process_info_for_pid(app_name, pid)?
            .into_iter()
            .collect());
    }

    macos_identity::trusted_process_infos(app_name)
}

pub(crate) fn detect_visible_prompt(
    app_name: &str,
    expected_process_id: Option<i32>,
    expected_window_title: Option<&str>,
    expected_email: Option<&str>,
) -> anyhow::Result<Option<MacosPrompt>> {
    let inspection = inspect_process(app_name, expected_process_id, expected_window_title)?;
    let prompts = matching_prompt_candidates(
        &inspection.prompts,
        expected_process_id,
        None,
        expected_email,
    )
    .into_iter()
    .filter(|prompt| prompt.target.frontmost)
    .collect::<Vec<_>>();
    let prompts = if expected_window_title.is_some() {
        prompts
            .iter()
            .copied()
            .filter(|prompt| {
                prompt_window_title_matches(&prompt.target.window_title, expected_window_title)
            })
            .collect::<Vec<_>>()
    } else {
        prompts
    };
    let [prompt] = prompts.as_slice() else {
        if prompts.is_empty() {
            return Ok(None);
        }
        anyhow::bail!("Multiple matching credential prompts are visible");
    };
    let prompt = (*prompt).clone();
    if !window_title_binding_is_unique(
        &inspection.window_titles,
        prompt.target.process_id,
        &prompt.target.window_title,
    ) && expected_email.is_none()
    {
        anyhow::bail!("Multiple trusted target windows match the credential prompt title");
    }
    Ok(Some(prompt))
}

fn record_prompt_candidate(inspection: &mut MacosInspection, prompt: MacosPrompt) {
    if let Some(existing_index) = inspection
        .prompts
        .iter()
        .position(|existing| same_prompt_candidate(existing, &prompt))
    {
        if inspection.prompts[existing_index].origin == PromptOrigin::Window
            && prompt.origin == PromptOrigin::Sheet
        {
            inspection.prompts[existing_index] = prompt;
        }
        return;
    }

    inspection.prompts.push(prompt);
}

fn same_prompt_candidate(left: &MacosPrompt, right: &MacosPrompt) -> bool {
    left.target.process_id == right.target.process_id
        && left
            .target
            .window_title
            .trim()
            .eq_ignore_ascii_case(right.target.window_title.trim())
        && left.email.as_deref().map(normalized_prompt_email)
            == right.email.as_deref().map(normalized_prompt_email)
        && left.target_window.same_element(&right.target_window)
        && left.native_container.same_element(&right.native_container)
        && left.prompt_root.same_element(&right.prompt_root)
        && left.password_field.same_element(&right.password_field)
        && same_optional_element(left.submit_button.as_ref(), right.submit_button.as_ref())
}

fn same_optional_element(left: Option<&AxElement>, right: Option<&AxElement>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => left.same_element(right),
        (None, None) => true,
        _ => false,
    }
}

fn preferred_unique_prompt(prompts: &[MacosPrompt]) -> Option<&MacosPrompt> {
    unique_frontmost_index(prompts.iter().map(|prompt| prompt.target.frontmost))
        .map(|index| &prompts[index])
}

fn unique_frontmost_index(frontmost_states: impl IntoIterator<Item = bool>) -> Option<usize> {
    let mut selected = None;
    for (index, frontmost) in frontmost_states.into_iter().enumerate() {
        if !frontmost {
            continue;
        }
        if selected.is_some() {
            return None;
        }
        selected = Some(index);
    }
    selected
}

fn matching_prompt_candidates<'a>(
    prompts: &'a [MacosPrompt],
    expected_process_id: Option<i32>,
    expected_window_title: Option<&str>,
    expected_email: Option<&str>,
) -> Vec<&'a MacosPrompt> {
    prompts
        .iter()
        .filter(|prompt| {
            prompt_matches_expected(
                prompt,
                expected_process_id,
                expected_window_title,
                expected_email,
            )
        })
        .collect()
}

fn window_title_binding_is_unique(
    window_titles: &[MacosWindowTitle],
    expected_process_id: i32,
    expected_title: &str,
) -> bool {
    if expected_title.trim().is_empty() {
        return false;
    }

    let mut distinct: Vec<&MacosWindowTitle> = Vec::new();
    for candidate in window_titles.iter().filter(|title| {
        title.process_id == expected_process_id
            && title
                .title
                .trim()
                .eq_ignore_ascii_case(expected_title.trim())
    }) {
        if distinct
            .iter()
            .any(|existing| same_window_title_identity(existing, candidate))
        {
            continue;
        }
        distinct.push(candidate);
        if distinct.len() > 1 {
            return false;
        }
    }

    distinct.len() == 1
}

fn same_window_title_identity(left: &MacosWindowTitle, right: &MacosWindowTitle) -> bool {
    if left.process_id != right.process_id
        || !left.title.trim().eq_ignore_ascii_case(right.title.trim())
    {
        return false;
    }

    match (&left.window, &right.window) {
        (Some(left_window), Some(right_window)) => left_window.same_element(right_window),
        _ => false,
    }
}

fn prompt_matches_expected(
    prompt: &MacosPrompt,
    expected_process_id: Option<i32>,
    expected_window_title: Option<&str>,
    expected_email: Option<&str>,
) -> bool {
    if let Some(expected_process_id) = expected_process_id {
        if prompt.target.process_id != expected_process_id {
            return false;
        }
    }
    if !prompt_window_title_matches(&prompt.target.window_title, expected_window_title) {
        return false;
    }
    expected_email.is_none_or(|expected_email| {
        prompt
            .email
            .as_deref()
            .is_some_and(|email| usernames_match(email, expected_email))
    })
}

fn normalized_prompt_email(email: &str) -> String {
    email.trim().to_lowercase()
}

pub(crate) fn preflight_password_load_prompt(
    app_name: &str,
    verified_prompt: Option<&MacosVerifiedPrompt>,
    expected_process_id: i32,
    expected_window_title: &str,
    expected_prompt_origin: &str,
    expected_email: &str,
) -> anyhow::Result<MacosVerifiedPrompt> {
    let verified_prompt = match verified_prompt {
        Some(verified_prompt) => verified_prompt.clone(),
        None => revalidate_prompt(
            app_name,
            expected_process_id,
            expected_window_title,
            expected_prompt_origin,
            expected_email,
        )?,
    };

    ensure_verified_prompt_matches_fill_target(
        &verified_prompt,
        expected_process_id,
        expected_window_title,
        expected_prompt_origin,
        expected_email,
    )?;
    let _prepared = revalidate_prepared_prompt_for_fill(
        app_name,
        &verified_prompt,
        expected_process_id,
        expected_window_title,
        expected_email,
    )?;

    Ok(verified_prompt)
}

#[expect(
    clippy::too_many_arguments,
    reason = "security-sensitive prompt identity and write guards stay explicit at this boundary"
)]
pub(crate) fn fill_verified_password(
    app_name: &str,
    verified_prompt: MacosVerifiedPrompt,
    expected_process_id: i32,
    expected_window_title: &str,
    expected_prompt_origin: &str,
    expected_email: &str,
    password: &str,
    method: MacosFillMethod,
    guard: &dyn Fn() -> anyhow::Result<()>,
) -> Result<MacosFillResult, MacosFillFailure> {
    guard().map_err(MacosFillFailure::before_write)?;
    ensure_verified_prompt_matches_fill_target(
        &verified_prompt,
        expected_process_id,
        expected_window_title,
        expected_prompt_origin,
        expected_email,
    )
    .map_err(MacosFillFailure::before_write)?;
    let password_field_role = verified_prompt.prompt.password_field_role.clone();
    let password_field_description_present = !verified_prompt
        .prompt
        .password_field_description
        .trim()
        .is_empty();
    let prepared = revalidate_prepared_prompt_for_fill(
        app_name,
        &verified_prompt,
        expected_process_id,
        expected_window_title,
        expected_email,
    )
    .map_err(MacosFillFailure::before_write)?;

    let prompt = verified_prompt.prompt;
    let cleanup_prompt = MacosFilledPrompt {
        prompt: prompt.clone(),
        expected_email: expected_email.to_string(),
        trusted_process: prepared.trusted_process.clone(),
        submit_button_ready_after_fill: false,
    };

    let (method_used, password_field_focused, submit_button_ready_after_fill) = match method {
        MacosFillMethod::Keyboard => {
            ensure_live_prompt_window_title(&prompt, expected_window_title)
                .map_err(MacosFillFailure::before_write)?;
            ensure_revalidated_frontmost(prompt_is_frontmost_now(&prompt), "password insertion")
                .map_err(MacosFillFailure::before_write)?;
            focus_password_field_in_prompt(&prompt, app_name, expected_process_id)
                .map_err(MacosFillFailure::before_write)?;
            guard().map_err(MacosFillFailure::before_write)?;
            revalidate_focused_password_field_for_keyboard(
                &prompt,
                app_name,
                expected_process_id,
                expected_window_title,
                expected_email,
                &prepared.trusted_process,
                "password field clear shortcut",
            )
            .map_err(MacosFillFailure::before_write)?;
            guard().map_err(MacosFillFailure::before_write)?;
            if !send_key_with_flags(expected_process_id, KEYCODE_A, CG_EVENT_FLAG_MASK_COMMAND) {
                return Err(MacosFillFailure::before_write(anyhow::anyhow!(
                    "password field clear shortcut event creation failed"
                )));
            }
            thread::sleep(Duration::from_millis(KEY_EVENT_SETTLE_MS));

            guard().map_err(MacosFillFailure::before_write)?;
            revalidate_focused_password_field_for_keyboard(
                &prompt,
                app_name,
                expected_process_id,
                expected_window_title,
                expected_email,
                &prepared.trusted_process,
                "password field clear",
            )
            .map_err(MacosFillFailure::before_write)?;
            guard().map_err(MacosFillFailure::before_write)?;
            if !send_key(expected_process_id, KEYCODE_DELETE) {
                return Err(MacosFillFailure::before_write(anyhow::anyhow!(
                    "password field clear event creation failed"
                )));
            }
            thread::sleep(Duration::from_millis(KEY_EVENT_SETTLE_MS));

            guard().map_err(MacosFillFailure::before_write)?;
            revalidate_focused_password_field_for_keyboard(
                &prompt,
                app_name,
                expected_process_id,
                expected_window_title,
                expected_email,
                &prepared.trusted_process,
                "keyboard password insertion",
            )
            .map_err(MacosFillFailure::before_write)?;
            guard().map_err(MacosFillFailure::before_write)?;
            if !send_text(expected_process_id, password) {
                return Err(MacosFillFailure::before_write(anyhow::anyhow!(
                    "password insertion event creation failed"
                )));
            }
            thread::sleep(Duration::from_millis(POST_FILL_SETTLE_MS));

            if let Err(error) = revalidate_focused_password_field_for_keyboard(
                &prompt,
                app_name,
                expected_process_id,
                expected_window_title,
                expected_email,
                &prepared.trusted_process,
                "post-keyboard password insertion",
            ) {
                return Err(MacosFillFailure::ambiguous_write(error, cleanup_prompt));
            }
            let submit_button_ready_after_fill = wait_for_prompt_submit_button_enabled(
                &prompt,
                Duration::from_millis(PASSWORD_FILL_READY_MS),
            );
            ("keyboard", true, submit_button_ready_after_fill)
        }
    };

    Ok(MacosFillResult {
        fill_method: method_used,
        fill_status: "ok",
        password_field_focused,
        password_field_role,
        password_field_description_present,
        submit_button_ready_after_fill,
        filled_prompt: Some(MacosFilledPrompt {
            prompt,
            expected_email: expected_email.to_string(),
            trusted_process: prepared.trusted_process,
            submit_button_ready_after_fill,
        }),
    })
}

fn ensure_verified_prompt_matches_fill_target(
    verified_prompt: &MacosVerifiedPrompt,
    expected_process_id: i32,
    expected_window_title: &str,
    expected_prompt_origin: &str,
    expected_email: &str,
) -> anyhow::Result<()> {
    if !verified_prompt.matches_expected(
        expected_process_id,
        expected_window_title,
        expected_prompt_origin,
        expected_email,
    ) {
        anyhow::bail!("prepared credential prompt no longer matches expected automation target");
    }
    if !verified_prompt.identity_text_matches(expected_email, expected_window_title) {
        anyhow::bail!(
            "prepared credential prompt content no longer matches expected automation target"
        );
    }
    Ok(())
}

pub(crate) fn submit_filled_prompt(
    app_name: &str,
    filled_prompt: &MacosFilledPrompt,
    guard: &dyn Fn() -> anyhow::Result<()>,
) -> anyhow::Result<MacosSubmitResult> {
    let prompt = &filled_prompt.prompt;
    guard()?;
    let button = revalidate_filled_prompt(app_name, filled_prompt)?;
    ensure_submit_side_effect_target_ready(
        app_name,
        prompt,
        &button,
        &filled_prompt.trusted_process,
        &filled_prompt.expected_email,
        &prompt.target.window_title,
        "fast submit",
    )?;
    let submitted_prompt = MacosSubmittedPrompt {
        process_id: prompt.target.process_id,
        window_title: prompt.target.window_title.clone(),
        email: filled_prompt.expected_email.clone(),
        origin: prompt.origin,
        target_window: prompt.target_window.clone(),
        prompt_container: prompt.native_container.clone(),
    };

    // Restore the proven macOS path: submit with Return while the exact
    // verified secure field is focused. The immediately preceding AX checks
    // revalidate the foreground prompt and trusted process before the
    // PID-targeted keyboard event; the password never enters the clipboard or
    // shell commands.
    let enter_focus_ready =
        focus_password_field_in_prompt(prompt, app_name, prompt.target.process_id).is_ok();
    let enter_ready = if enter_focus_ready {
        guard()?;
        let focus_revalidated = revalidate_focused_password_field_for_keyboard(
            prompt,
            app_name,
            prompt.target.process_id,
            &prompt.target.window_title,
            &filled_prompt.expected_email,
            &filled_prompt.trusted_process,
            "Return submit",
        )
        .is_ok();
        focus_revalidated && guard().is_ok()
    } else {
        false
    };
    if enter_ready && send_key(prompt.target.process_id, KEYCODE_RETURN) {
        return Ok(MacosSubmitResult {
            submit_method: "enter",
            submit_status: "ok",
            axpress_attempted: false,
            axpress_result: "not_needed",
            enter_fallback_attempted: true,
            enter_fallback_result: "sent",
            submitted_prompt: Some(submitted_prompt),
        });
    }

    // If the PID-targeted Return event could not be created, keep the exact
    // verified button as a fallback. An AX error is ambiguous because Windows
    // App can dispatch the press and then time out while opening the session;
    // preserve submit evidence so the post-check decides the outcome.
    ensure_submit_side_effect_target_ready(
        app_name,
        prompt,
        &button,
        &filled_prompt.trusted_process,
        &filled_prompt.expected_email,
        &prompt.target.window_title,
        "AXPress fallback submit",
    )?;
    guard()?;
    if button.perform_action(AX_PRESS) {
        return Ok(MacosSubmitResult {
            submit_method: "axpress_fallback",
            submit_status: "ok",
            axpress_attempted: true,
            axpress_result: "success",
            enter_fallback_attempted: enter_ready,
            enter_fallback_result: if enter_ready {
                "creation_failed"
            } else {
                "focus_not_verified"
            },
            submitted_prompt: Some(submitted_prompt),
        });
    }

    Ok(MacosSubmitResult {
        submit_method: "axpress_fallback",
        submit_status: "unknown",
        axpress_attempted: true,
        axpress_result: "reported_error",
        enter_fallback_attempted: enter_ready,
        enter_fallback_result: if enter_ready {
            "creation_failed"
        } else {
            "focus_not_verified"
        },
        submitted_prompt: Some(submitted_prompt),
    })
}

pub(crate) fn submit_prompt_after_fill(
    app_name: &str,
    filled_prompt: Option<&MacosFilledPrompt>,
    expected_process_id: i32,
    expected_window_title: &str,
    expected_prompt_origin: &str,
    expected_email: &str,
    guard: &dyn Fn() -> anyhow::Result<()>,
) -> anyhow::Result<MacosSubmitResult> {
    let Some(filled_prompt) = filled_prompt.filter(|filled_prompt| {
        filled_prompt.matches_expected(
            expected_process_id,
            expected_window_title,
            expected_prompt_origin,
            expected_email,
        )
    }) else {
        anyhow::bail!("filled credential prompt identity is unavailable or changed before submit");
    };

    submit_filled_prompt(app_name, filled_prompt, guard)
}

fn revalidate_filled_prompt(
    app_name: &str,
    filled_prompt: &MacosFilledPrompt,
) -> anyhow::Result<AxElement> {
    let prompt = &filled_prompt.prompt;
    let expected_process_id = prompt.target.process_id;
    if prompt.target.window_title.trim().is_empty() {
        anyhow::bail!("credential prompt title missing before fast submit");
    }
    ensure_live_prompt_window_title(prompt, &prompt.target.window_title)?;
    if !prompt
        .email
        .as_deref()
        .is_some_and(|email| usernames_match(email, &filled_prompt.expected_email))
    {
        anyhow::bail!("credential prompt email changed before fast submit");
    }

    ensure_element_belongs_to_process(&prompt.target_window, expected_process_id, "target window")?;
    ensure_element_belongs_to_process(&prompt.prompt_root, expected_process_id, "prompt root")?;
    ensure_element_belongs_to_process(
        &prompt.password_field,
        expected_process_id,
        "password field",
    )?;
    ensure_element_within_prompt_root(
        &prompt.password_field,
        &prompt.prompt_root,
        "password field",
    )?;
    let Some(button) = prompt.submit_button.as_ref() else {
        anyhow::bail!("credential prompt submit button disappeared before fast submit");
    };
    ensure_element_belongs_to_process(button, expected_process_id, "submit button")?;
    ensure_element_within_prompt_root(button, &prompt.prompt_root, "submit button")?;
    if is_hidden(&prompt.target_window) || is_hidden(&prompt.prompt_root) {
        anyhow::bail!("credential prompt hidden before fast submit");
    }

    if !filled_prompt.submit_button_ready_after_fill {
        let button_ready = wait_for_prompt_submit_button_enabled(
            prompt,
            Duration::from_millis(FAST_SUBMIT_READY_TIMEOUT_MS),
        );
        if !button_ready {
            anyhow::bail!("verified submit button did not become enabled before fast submit");
        }
    }
    if !element_enabled(button) {
        anyhow::bail!("verified submit button is no longer enabled");
    }
    ensure_prompt_identity_text_still_matches(
        prompt,
        expected_process_id,
        &filled_prompt.expected_email,
        &prompt.target.window_title,
        prompt.origin,
        "fast submit",
    )?;
    let trusted_process = current_trusted_process_info(app_name, expected_process_id)?;
    ensure_trusted_process_matches(
        &trusted_process,
        &filled_prompt.trusted_process,
        "credential prompt process identity changed before fast submit",
    )?;
    Ok(button.clone())
}

fn ensure_submit_side_effect_target_ready(
    app_name: &str,
    prompt: &MacosPrompt,
    button: &AxElement,
    expected_trusted_process: &macos_identity::TrustedProcessInfo,
    expected_email: &str,
    expected_window_title: &str,
    action: &'static str,
) -> anyhow::Result<()> {
    let expected_process_id = prompt.target.process_id;
    ensure_live_prompt_window_title(prompt, expected_window_title)?;
    ensure_element_belongs_to_process(&prompt.target_window, expected_process_id, "target window")?;
    ensure_element_belongs_to_process(
        &prompt.native_container,
        expected_process_id,
        "prompt container",
    )?;
    ensure_element_belongs_to_process(&prompt.prompt_root, expected_process_id, "prompt root")?;
    ensure_element_belongs_to_process(
        &prompt.password_field,
        expected_process_id,
        "password field",
    )?;
    ensure_element_belongs_to_process(button, expected_process_id, "submit button")?;
    ensure_element_within_prompt_root(
        &prompt.prompt_root,
        &prompt.native_container,
        "prompt root",
    )?;
    ensure_element_within_prompt_root(
        &prompt.password_field,
        &prompt.prompt_root,
        "password field",
    )?;
    ensure_element_within_prompt_root(button, &prompt.prompt_root, "submit button")?;
    if is_hidden(&prompt.target_window)
        || is_hidden(&prompt.native_container)
        || is_hidden(&prompt.prompt_root)
        || is_hidden(&prompt.password_field)
        || is_hidden(button)
        || !has_secure_password_field_identity(&prompt.password_field)
        || !element_enabled(button)
    {
        anyhow::bail!("verified submit button is not visible and enabled before {action}");
    }
    ensure_prompt_identity_text_still_matches(
        prompt,
        expected_process_id,
        expected_email,
        expected_window_title,
        prompt.origin,
        action,
    )?;
    let trusted_process = current_trusted_process_info(app_name, expected_process_id)?;
    ensure_trusted_process_matches(
        &trusted_process,
        expected_trusted_process,
        "credential prompt process identity changed before submit side effect",
    )?;
    ensure_revalidated_frontmost(prompt_is_frontmost_now(prompt), action)
}

pub(crate) fn post_check_state(
    app_name: &str,
    expected_process_id: i32,
    expected_window_title: &str,
    expected_email: &str,
    submitted_prompt: Option<&MacosSubmittedPrompt>,
    timeout: Duration,
) -> &'static str {
    let started = Instant::now();
    let mut submitted_prompt_absent_since = None;
    let mut last_visible_prompt_state = None;
    loop {
        // Native identity or AX inspection failure is indeterminate. A
        // definitive process exit is represented by a successful inspection
        // with process_found == false and is classified inside this branch.
        if let Ok(inspection) = inspect_process(app_name, Some(expected_process_id), None) {
            let prompt_presence = submitted_prompt.and_then(submitted_prompt_presence);
            let observed_at = Instant::now();
            submitted_prompt_absent_since = next_prompt_absence_since(
                submitted_prompt_absent_since,
                prompt_presence,
                observed_at,
            );
            let state = classify_post_submit_inspection(
                &inspection,
                expected_process_id,
                expected_window_title,
                expected_email,
                submitted_prompt,
                prompt_absence_dwell_confirmed(
                    submitted_prompt_absent_since,
                    observed_at,
                    Duration::from_millis(POST_SUBMIT_REQUIRED_ABSENCE_DWELL_MS),
                ),
            );

            if inspection.prompt.is_some() {
                let prompt_state = state.unwrap_or("prompt_gone_unknown");
                if post_submit_prompt_state_is_terminal_during_poll(
                    prompt_state,
                    submitted_prompt.is_some(),
                ) {
                    return prompt_state;
                }
                last_visible_prompt_state = Some(prompt_state);
            }

            if inspection.prompt.is_none() {
                if let Some(state) = state {
                    return state;
                }
            }
        } else {
            // A failed or incomplete inspection breaks the continuous absence
            // proof. A later successful probe must establish a fresh dwell.
            submitted_prompt_absent_since = None;
        }

        if started.elapsed() >= timeout {
            return last_visible_prompt_state.unwrap_or("prompt_gone_unknown");
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn post_submit_prompt_state_is_terminal_during_poll(
    prompt_state: &str,
    submitted_prompt_available: bool,
) -> bool {
    prompt_state != "still_prompt" || !submitted_prompt_available
}

fn classify_post_submit_inspection(
    inspection: &MacosInspection,
    expected_process_id: i32,
    expected_window_title: &str,
    expected_email: &str,
    submitted_prompt: Option<&MacosSubmittedPrompt>,
    submitted_prompt_disappearance_confirmed: bool,
) -> Option<&'static str> {
    // inspect_process is scoped to expected_process_id. Native trusted-process
    // presence remains authoritative even when AX cannot create the app
    // element or read its windows; lack of AX data is not a process exit.
    let target_running = inspection.process_found;
    let has_session_for_expected_process = submitted_prompt.is_some_and(|submitted_prompt| {
        let submitted_parent_is_unique_foreground =
            submitted_parent_is_unique_foreground_target(inspection, submitted_prompt);
        submitted_prompt_disappearance_confirmed
            && submitted_parent_is_unique_foreground
            && submitted_prompt_matches_expected(
                submitted_prompt,
                expected_process_id,
                expected_email,
            )
            && inspection.session_windows.iter().any(|session| {
                session.process_id == expected_process_id
                    && submitted_prompt_matches_session_window(
                        submitted_prompt,
                        session,
                        submitted_parent_is_unique_foreground,
                    )
            })
    });
    if let Some(prompt_state) = classify_post_submit_prompt_candidates(
        &inspection.prompts,
        &inspection.window_titles,
        expected_process_id,
        expected_window_title,
        expected_email,
    ) {
        return Some(prompt_state);
    }

    classify_post_submit_state(
        None,
        target_running,
        has_session_for_expected_process,
        expected_email,
    )
}

fn next_prompt_absence_since(
    previous: Option<Instant>,
    prompt_is_present: Option<bool>,
    observed_at: Instant,
) -> Option<Instant> {
    match prompt_is_present {
        Some(true) | None => None,
        Some(false) => previous.or(Some(observed_at)),
    }
}

fn prompt_absence_dwell_confirmed(
    absent_since: Option<Instant>,
    observed_at: Instant,
    required_dwell: Duration,
) -> bool {
    absent_since.is_some_and(|absent_since| {
        observed_at.saturating_duration_since(absent_since) >= required_dwell
    })
}

fn submitted_prompt_presence(submitted_prompt: &MacosSubmittedPrompt) -> Option<bool> {
    if submitted_prompt.target_window.process_id() != Some(submitted_prompt.process_id)
        || submitted_prompt.prompt_container.process_id() != Some(submitted_prompt.process_id)
    {
        return None;
    }

    let app = AxElement::application(submitted_prompt.process_id)?;
    let windows = app.array_attr_checked(AX_WINDOWS)?;
    let current_target = windows
        .iter()
        .find(|window| window.same_element(&submitted_prompt.target_window));

    match submitted_prompt.origin {
        PromptOrigin::Sheet => {
            let Some(target_window) = current_target else {
                return Some(false);
            };
            let visible_direct_sheets = sheet_candidates_for_window(target_window)
                .ok()?
                .into_iter()
                .filter(|sheet| !is_hidden(sheet))
                .filter(|sheet| element_is_direct_child_of(sheet, target_window))
                .collect::<Vec<_>>();
            let submitted_sheet_visible = visible_direct_sheets
                .iter()
                .any(|sheet| sheet.same_element(&submitted_prompt.prompt_container));
            submitted_sheet_presence(submitted_sheet_visible, visible_direct_sheets.len())
        }
        PromptOrigin::Window => Some(windows.iter().any(|window| {
            window.same_element(&submitted_prompt.prompt_container) && !is_hidden(window)
        })),
    }
}

fn submitted_sheet_presence(
    submitted_sheet_visible: bool,
    visible_direct_sheet_count: usize,
) -> Option<bool> {
    if submitted_sheet_visible {
        Some(true)
    } else if visible_direct_sheet_count == 0 {
        Some(false)
    } else {
        // A companion or replacement sheet means the parent has not made a
        // stable transition into an unobstructed remote session.
        None
    }
}

fn classify_post_submit_prompt_candidates(
    prompts: &[MacosPrompt],
    window_titles: &[MacosWindowTitle],
    expected_process_id: i32,
    expected_window_title: &str,
    expected_email: &str,
) -> Option<&'static str> {
    classify_post_submit_prompt_identities(
        prompts.iter().map(|prompt| {
            (
                prompt.target.process_id,
                prompt.target.window_title.as_str(),
                prompt.email.as_deref(),
            )
        }),
        expected_process_id,
        expected_window_title,
        expected_email,
        window_title_binding_is_unique(window_titles, expected_process_id, expected_window_title),
    )
}

fn classify_post_submit_prompt_identities<'a>(
    prompts: impl IntoIterator<Item = (i32, &'a str, Option<&'a str>)>,
    expected_process_id: i32,
    expected_window_title: &str,
    expected_email: &str,
    expected_window_title_is_unique: bool,
) -> Option<&'static str> {
    let expected_process_prompts = prompts
        .into_iter()
        .filter(|(process_id, _, _)| *process_id == expected_process_id)
        .collect::<Vec<_>>();
    if expected_process_prompts.is_empty() {
        return None;
    }

    let matching_window = expected_process_prompts
        .iter()
        .filter(|(_, window_title, _)| {
            window_title
                .trim()
                .eq_ignore_ascii_case(expected_window_title.trim())
        })
        .collect::<Vec<_>>();
    if matching_window.len() != expected_process_prompts.len() {
        return Some(if expected_process_prompts.len() == 1 {
            "prompt_mismatch"
        } else {
            "prompt_ambiguous"
        });
    }
    if !expected_window_title_is_unique {
        return Some("prompt_ambiguous");
    }

    let matching_account = matching_window
        .iter()
        .filter(|(_, _, email)| email.is_some_and(|email| usernames_match(email, expected_email)))
        .count();
    match matching_account {
        0 => Some("prompt_mismatch"),
        1 if matching_window.len() == 1 => Some("still_prompt"),
        _ => Some("prompt_ambiguous"),
    }
}

fn submitted_prompt_matches_expected(
    submitted_prompt: &MacosSubmittedPrompt,
    expected_process_id: i32,
    expected_email: &str,
) -> bool {
    submitted_prompt.process_id == expected_process_id
        && usernames_match(&submitted_prompt.email, expected_email)
}

fn submitted_prompt_matches_session_window(
    submitted_prompt: &MacosSubmittedPrompt,
    session: &MacosWindowTitle,
    submitted_parent_is_unique_foreground: bool,
) -> bool {
    // Windows App removes the attached credential sheet and turns the same
    // parent AXWindow into the remote session. Requiring a new AXWindow here
    // rejects a successful connection even after the exact sheet has been
    // observed absent for a stable run of bounded post-check probes.
    submitted_sheet_session_identity_matches(
        submitted_prompt.origin,
        submitted_prompt.process_id,
        session.process_id,
        &submitted_prompt.window_title,
        &session.title,
        session
            .window
            .as_ref()
            .is_some_and(|window| window.same_element(&submitted_prompt.target_window)),
        submitted_parent_is_unique_foreground,
    )
}

fn submitted_parent_is_unique_foreground_target(
    inspection: &MacosInspection,
    submitted_prompt: &MacosSubmittedPrompt,
) -> bool {
    let Some(target) = inspection.target.as_ref() else {
        return false;
    };
    submitted_parent_target_identity_is_unique_foreground(
        target.process_id,
        &target.window_title,
        target.frontmost,
        submitted_prompt.process_id,
        &submitted_prompt.window_title,
        window_title_binding_is_unique(
            &inspection.window_titles,
            submitted_prompt.process_id,
            &submitted_prompt.window_title,
        ),
    )
}

fn submitted_parent_target_identity_is_unique_foreground(
    target_process_id: i32,
    target_window_title: &str,
    target_frontmost: bool,
    submitted_process_id: i32,
    submitted_window_title: &str,
    submitted_window_title_is_unique: bool,
) -> bool {
    target_frontmost
        && submitted_window_title_is_unique
        && target_process_id == submitted_process_id
        && target_window_title
            .trim()
            .eq_ignore_ascii_case(submitted_window_title.trim())
}

fn submitted_sheet_session_identity_matches(
    origin: PromptOrigin,
    submitted_process_id: i32,
    session_process_id: i32,
    submitted_window_title: &str,
    session_window_title: &str,
    same_target_window: bool,
    submitted_parent_is_unique_foreground: bool,
) -> bool {
    origin == PromptOrigin::Sheet
        && submitted_parent_is_unique_foreground
        && session_process_id == submitted_process_id
        && session_window_title
            .trim()
            .eq_ignore_ascii_case(submitted_window_title.trim())
        && same_target_window
}

fn classify_post_submit_state(
    prompt_email: Option<&str>,
    target_running: bool,
    has_session_for_expected_process: bool,
    expected_email: &str,
) -> Option<&'static str> {
    if let Some(prompt_email) = prompt_email {
        return if usernames_match(prompt_email, expected_email) {
            Some("still_prompt")
        } else {
            Some("prompt_mismatch")
        };
    }

    if !target_running {
        return Some("failed");
    }
    if has_session_for_expected_process {
        return Some("authenticated");
    }
    None
}

pub(crate) fn revalidate_visible_prompt(
    app_name: &str,
    expected_process_id: i32,
    expected_window_title: &str,
    expected_prompt_origin: &str,
    expected_email: &str,
) -> anyhow::Result<MacosVerifiedPrompt> {
    revalidate_prompt(
        app_name,
        expected_process_id,
        expected_window_title,
        expected_prompt_origin,
        expected_email,
    )
}

fn revalidate_prompt(
    app_name: &str,
    expected_process_id: i32,
    expected_window_title: &str,
    expected_prompt_origin: &str,
    expected_email: &str,
) -> anyhow::Result<MacosVerifiedPrompt> {
    let Some(prompt) = detect_visible_prompt(
        app_name,
        Some(expected_process_id),
        Some(expected_window_title),
        Some(expected_email),
    )?
    else {
        anyhow::bail!("credential prompt disappeared before automation");
    };

    if prompt.target.process_id != expected_process_id {
        anyhow::bail!("credential prompt process changed before automation");
    }
    ensure_prompt_frontmost_for_automation(&prompt, "automation")?;
    if !prompt
        .target
        .window_title
        .eq_ignore_ascii_case(expected_window_title)
    {
        anyhow::bail!("credential prompt title changed before automation");
    }
    if !prompt
        .email
        .as_deref()
        .is_some_and(|email| usernames_match(email, expected_email))
    {
        anyhow::bail!("credential prompt email changed before automation");
    }
    if !prompt
        .origin
        .as_str()
        .eq_ignore_ascii_case(expected_prompt_origin.trim())
    {
        anyhow::bail!("credential prompt origin changed before automation");
    }
    let trusted_process = prompt.trusted_process.clone();
    Ok(MacosVerifiedPrompt {
        prompt,
        trusted_process,
    })
}

fn revalidate_prepared_prompt_for_fill(
    app_name: &str,
    verified_prompt: &MacosVerifiedPrompt,
    expected_process_id: i32,
    expected_window_title: &str,
    expected_email: &str,
) -> anyhow::Result<PreparedPromptForFill> {
    let prompt = &verified_prompt.prompt;
    ensure_live_prompt_window_title(prompt, expected_window_title)?;
    ensure_element_belongs_to_process(&prompt.target_window, expected_process_id, "target window")?;
    ensure_element_belongs_to_process(&prompt.prompt_root, expected_process_id, "prompt root")?;
    ensure_element_belongs_to_process(
        &prompt.password_field,
        expected_process_id,
        "password field",
    )?;
    ensure_element_within_prompt_root(
        &prompt.password_field,
        &prompt.prompt_root,
        "password field",
    )?;
    ensure_prompt_frontmost_for_automation(prompt, "password insertion")?;
    if is_hidden(&prompt.target_window)
        || is_hidden(&prompt.prompt_root)
        || is_hidden(&prompt.password_field)
    {
        anyhow::bail!("credential prompt hidden before password insertion");
    }
    if !is_secure_password_insertion_field(&prompt.password_field) {
        anyhow::bail!("credential prompt password field is not a secure text field");
    }
    ensure_prompt_identity_text_still_matches(
        prompt,
        expected_process_id,
        expected_email,
        expected_window_title,
        prompt.origin,
        "password insertion",
    )?;
    let Some(button) = prompt.submit_button.as_ref() else {
        anyhow::bail!("credential prompt submit button disappeared before password insertion");
    };
    ensure_element_belongs_to_process(button, expected_process_id, "submit button")?;
    ensure_element_within_prompt_root(button, &prompt.prompt_root, "submit button")?;
    let trusted_process = current_trusted_process_info(app_name, expected_process_id)?;
    ensure_trusted_process_matches(
        &trusted_process,
        &verified_prompt.trusted_process,
        "credential prompt process identity changed before password insertion",
    )?;
    ensure_revalidated_frontmost(prompt_is_frontmost_now(prompt), "password insertion")?;
    Ok(PreparedPromptForFill { trusted_process })
}

fn ensure_trusted_process_matches(
    current: &macos_identity::TrustedProcessInfo,
    expected: &macos_identity::TrustedProcessInfo,
    message: &'static str,
) -> anyhow::Result<()> {
    if current.pid == expected.pid
        && current.bundle_id == expected.bundle_id
        && current.bundle_path == expected.bundle_path
        && current.team_id == expected.team_id
    {
        Ok(())
    } else {
        anyhow::bail!(message)
    }
}

fn ensure_prompt_identity_text_still_matches(
    prompt: &MacosPrompt,
    expected_process_id: i32,
    expected_email: &str,
    expected_window_title: &str,
    expected_origin: PromptOrigin,
    action: &'static str,
) -> anyhow::Result<()> {
    for snapshot in &prompt.identity_text {
        ensure_element_belongs_to_process(&snapshot.element, expected_process_id, "prompt text")?;
        ensure_element_within_prompt_root(&snapshot.element, &prompt.prompt_root, "prompt text")?;
        if prompt_text_snapshot_changed(snapshot) {
            anyhow::bail!("credential prompt content changed before {action}");
        }
    }
    if prompt_text_snapshots_match(
        &prompt.identity_text,
        expected_email,
        expected_window_title,
        expected_origin,
    ) {
        Ok(())
    } else {
        anyhow::bail!("credential prompt content changed before {action}")
    }
}

fn ensure_live_prompt_window_title(
    prompt: &MacosPrompt,
    expected_window_title: &str,
) -> anyhow::Result<()> {
    let live_title = prompt
        .target_window
        .string_attr(AX_TITLE)
        .unwrap_or_default();
    if !live_title.trim().is_empty()
        && live_title
            .trim()
            .eq_ignore_ascii_case(expected_window_title.trim())
    {
        Ok(())
    } else {
        anyhow::bail!("credential prompt window title changed before automation side effect")
    }
}

fn prompt_text_snapshot_changed(snapshot: &PromptTextSnapshot) -> bool {
    if is_hidden(&snapshot.element) || has_sensitive_password_field_identity(&snapshot.element) {
        return true;
    }
    let title = snapshot.element.string_attr(AX_TITLE);
    let placeholder = snapshot.element.string_attr(AX_PLACEHOLDER);
    // Reclassify immediately before AXValue. A previously ordinary identity
    // element that became password-sensitive must be treated as changed
    // without ever materializing its value in an ordinary String.
    let value = if is_text_or_static_text(&snapshot.element)
        && !has_sensitive_password_field_identity(&snapshot.element)
    {
        snapshot.element.string_attr(AX_VALUE)
    } else {
        None
    };
    title != snapshot.title || placeholder != snapshot.placeholder || value != snapshot.value
}

fn prompt_text_snapshots_match(
    snapshots: &[PromptTextSnapshot],
    expected_email: &str,
    expected_window_title: &str,
    expected_origin: PromptOrigin,
) -> bool {
    let text = collect_prompt_snapshot_text("", snapshots);
    scoped_prompt_matches(
        &text,
        expected_email,
        expected_window_title,
        expected_origin,
    )
}

fn focus_password_field_in_prompt(
    prompt: &MacosPrompt,
    app_name: &str,
    expected_process_id: i32,
) -> anyhow::Result<AxElement> {
    ensure_prompt_frontmost_for_automation(prompt, "password field focus")?;
    let field = verified_password_field_in_prompt(prompt, app_name, expected_process_id)?;
    focus_password_field(&field, expected_process_id, &prompt.prompt_root)
        .then_some(field)
        .context(
            "password field focus is not verified immediately before PID-targeted keyboard input",
        )
}

fn verified_password_field_in_prompt(
    prompt: &MacosPrompt,
    app_name: &str,
    expected_process_id: i32,
) -> anyhow::Result<AxElement> {
    let trusted_process = current_trusted_process_info(app_name, expected_process_id)?;
    ensure_trusted_process_matches(
        &trusted_process,
        &prompt.trusted_process,
        "credential prompt process identity changed before keyboard input",
    )?;
    verified_password_field_in_prompt_after_trust(prompt, expected_process_id)
}

fn verified_password_field_in_prompt_after_trust(
    prompt: &MacosPrompt,
    expected_process_id: i32,
) -> anyhow::Result<AxElement> {
    ensure_element_belongs_to_process(
        &prompt.password_field,
        expected_process_id,
        "password field",
    )?;
    ensure_element_within_prompt_root(
        &prompt.password_field,
        &prompt.prompt_root,
        "password field",
    )?;
    if !is_secure_password_insertion_field(&prompt.password_field) {
        anyhow::bail!(
            "credential prompt password field is not a visible enabled secure text field"
        );
    }
    Ok(prompt.password_field.clone())
}

fn revalidate_focused_password_field_for_keyboard(
    prompt: &MacosPrompt,
    app_name: &str,
    expected_process_id: i32,
    expected_window_title: &str,
    expected_email: &str,
    expected_trusted_process: &macos_identity::TrustedProcessInfo,
    action: &'static str,
) -> anyhow::Result<AxElement> {
    ensure_live_prompt_window_title(prompt, expected_window_title)?;
    ensure_prompt_frontmost_for_automation(prompt, action)?;
    ensure_prompt_identity_text_still_matches(
        prompt,
        expected_process_id,
        expected_email,
        expected_window_title,
        prompt.origin,
        action,
    )?;
    let trusted_process = current_trusted_process_info(app_name, expected_process_id)?;
    ensure_trusted_process_matches(
        &trusted_process,
        expected_trusted_process,
        "credential prompt process identity changed before keyboard side effect",
    )?;
    // The live signature/path lookup above is authoritative for this guarded
    // side-effect boundary. Compare that same result with both captured trust
    // identities instead of performing an identical native validation twice.
    ensure_trusted_process_matches(
        &trusted_process,
        &prompt.trusted_process,
        "credential prompt process identity changed before keyboard input",
    )?;
    let field = verified_password_field_in_prompt_after_trust(prompt, expected_process_id)?;
    if field.bool_attr(AX_FOCUSED) != Some(true)
        || !application_focus_matches_field(&field, expected_process_id)
    {
        anyhow::bail!("password field focus changed before {action}");
    }
    Ok(field)
}

fn ensure_prompt_frontmost_for_automation(
    prompt: &MacosPrompt,
    action: &str,
) -> anyhow::Result<()> {
    ensure_revalidated_frontmost(prompt_is_frontmost_now(prompt), action)
}

fn ensure_revalidated_frontmost(frontmost: bool, action: &str) -> anyhow::Result<()> {
    if frontmost {
        Ok(())
    } else {
        anyhow::bail!("credential prompt is not frontmost before {action}")
    }
}

fn prompt_is_frontmost_now(prompt: &MacosPrompt) -> bool {
    let Some(app) = AxElement::application(prompt.target.process_id) else {
        return false;
    };
    if app.process_id() != Some(prompt.target.process_id) {
        return false;
    }

    let app_frontmost = app.bool_attr(AX_FRONTMOST) == Some(true);
    let Ok(windows) = app.array_attr_result(AX_WINDOWS) else {
        return false;
    };
    let visible_windows = windows
        .into_iter()
        .filter(|window| !is_hidden(window))
        .collect::<Vec<_>>();
    let window_foreground_states = visible_windows
        .iter()
        .map(element_foreground_state)
        .collect::<Vec<_>>();
    let Some(target_window) =
        select_unique_foreground_index(app_frontmost, &window_foreground_states)
            .and_then(|index| visible_windows.get(index))
    else {
        return false;
    };
    if !target_window.same_element(&prompt.target_window)
        || !element_has_ancestor(&prompt.prompt_root, &prompt.native_container)
    {
        return false;
    }

    match prompt.origin {
        PromptOrigin::Window => {
            prompt.native_container.same_element(target_window)
                && window_should_scan_for_prompt(target_window, &prompt.target.window_title)
        }
        PromptOrigin::Sheet => sheet_prompt_is_uniquely_visible_now(prompt, target_window),
    }
}

fn sheet_prompt_is_uniquely_visible_now(prompt: &MacosPrompt, target_window: &AxElement) -> bool {
    let Ok(sheet_candidates) = sheet_candidates_for_window(target_window) else {
        return false;
    };
    let visible_direct_sheets = sheet_candidates
        .into_iter()
        .filter(|sheet| !is_hidden(sheet) && element_is_direct_child_of(sheet, target_window))
        .collect::<Vec<_>>();
    unique_direct_sheet_prompt(
        &prompt.target,
        target_window,
        &visible_direct_sheets,
        &prompt.trusted_process,
    )
    .ok()
    .flatten()
    .is_some_and(|candidate| same_prompt_candidate(prompt, &candidate))
}

fn current_trusted_process_info(
    app_name: &str,
    expected_process_id: i32,
) -> anyhow::Result<macos_identity::TrustedProcessInfo> {
    macos_identity::trusted_process_info_for_pid(app_name, expected_process_id)?
        .context("credential prompt process is no longer trusted")
}

fn ensure_element_belongs_to_process(
    element: &AxElement,
    expected_process_id: i32,
    description: &str,
) -> anyhow::Result<()> {
    if element.process_id() == Some(expected_process_id) {
        Ok(())
    } else {
        anyhow::bail!("{description} no longer belongs to the trusted process")
    }
}

fn ensure_element_within_prompt_root(
    element: &AxElement,
    prompt_root: &AxElement,
    description: &str,
) -> anyhow::Result<()> {
    if element_has_ancestor(element, prompt_root) {
        Ok(())
    } else {
        anyhow::bail!("{description} is no longer inside the verified credential prompt")
    }
}

fn element_has_ancestor(element: &AxElement, ancestor: &AxElement) -> bool {
    let mut current = Some(element.clone());
    for _ in 0..=AX_SEARCH_DEPTH {
        let Some(element) = current else {
            return false;
        };
        if element.same_element(ancestor) {
            return true;
        }
        current = element.parent();
    }
    false
}

fn focus_password_field(
    field: &AxElement,
    expected_process_id: i32,
    prompt_root: &AxElement,
) -> bool {
    if ensure_element_belongs_to_process(field, expected_process_id, "password field").is_err()
        || ensure_element_within_prompt_root(field, prompt_root, "password field").is_err()
    {
        return false;
    }

    // AXFocused can outlive the native secure field editor which actually
    // consumes keyboard events. Always perform an active focus attempt before
    // accepting any focused state, including when the cached flag starts true.
    let _ = field.perform_action(AX_PRESS);
    let _ = field.set_bool_attr(AX_FOCUSED, true);
    wait_for_stable_password_focus(
        field,
        expected_process_id,
        Duration::from_millis(FOCUS_STABLE_SETTLE_MS),
        Duration::from_millis(FOCUS_ACQUIRE_TIMEOUT_MS),
    )
}

fn application_focus_matches_field(field: &AxElement, expected_process_id: i32) -> bool {
    let Some(app) = AxElement::application(expected_process_id) else {
        return false;
    };
    if app.process_id() != Some(expected_process_id) || app.bool_attr(AX_FRONTMOST) != Some(true) {
        return false;
    }
    let Some(focused) = app.element_attr(AX_FOCUSED_UI_ELEMENT) else {
        return false;
    };
    focused.process_id() == Some(expected_process_id)
        && (focused.same_element(field) || element_has_ancestor(&focused, field))
}

fn wait_for_stable_password_focus(
    field: &AxElement,
    expected_process_id: i32,
    stable_for: Duration,
    timeout: Duration,
) -> bool {
    wait_for_stable_condition(stable_for, timeout, || {
        field.bool_attr(AX_FOCUSED) == Some(true)
            && application_focus_matches_field(field, expected_process_id)
    })
}

fn wait_for_stable_condition(
    stable_for: Duration,
    timeout: Duration,
    mut condition: impl FnMut() -> bool,
) -> bool {
    let started = Instant::now();
    let mut stable_since = None;
    loop {
        if condition() {
            let stable_since = stable_since.get_or_insert_with(Instant::now);
            if stable_since.elapsed() >= stable_for {
                return true;
            }
        } else {
            stable_since = None;
        }
        if started.elapsed() >= timeout {
            return false;
        }
        let remaining = timeout.saturating_sub(started.elapsed());
        thread::sleep(remaining.min(Duration::from_millis(FOCUS_POLL_INTERVAL_MS)));
    }
}

fn wait_for_prompt_submit_button_enabled(prompt: &MacosPrompt, timeout: Duration) -> bool {
    let Some(button) = prompt.submit_button.as_ref() else {
        return false;
    };
    let started = Instant::now();
    loop {
        if element_enabled(button) {
            return true;
        }
        if started.elapsed() >= timeout {
            return false;
        }
        let remaining = timeout.saturating_sub(started.elapsed());
        thread::sleep(remaining.min(Duration::from_millis(FOCUS_POLL_INTERVAL_MS)));
    }
}

pub(crate) fn clear_filled_password(
    app_name: &str,
    filled_prompt: &MacosFilledPrompt,
) -> anyhow::Result<()> {
    let mut last_error = None;
    for attempt in 0..PASSWORD_CLEANUP_ATTEMPTS {
        match clear_original_password_once(app_name, filled_prompt) {
            Ok(()) => return Ok(()),
            Err(error) => last_error = Some(error),
        }
        if attempt + 1 < PASSWORD_CLEANUP_ATTEMPTS {
            thread::sleep(Duration::from_millis(PASSWORD_CLEANUP_RETRY_MS));
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("password cleanup was not attempted")))
}

fn clear_original_password_once(
    app_name: &str,
    filled_prompt: &MacosFilledPrompt,
) -> anyhow::Result<()> {
    let prompt = &filled_prompt.prompt;
    let expected_process_id = prompt.target.process_id;
    ensure_element_belongs_to_process(&prompt.target_window, expected_process_id, "target window")?;
    ensure_element_belongs_to_process(
        &prompt.native_container,
        expected_process_id,
        "prompt container",
    )?;
    ensure_element_belongs_to_process(&prompt.prompt_root, expected_process_id, "prompt root")?;
    ensure_element_belongs_to_process(
        &prompt.password_field,
        expected_process_id,
        "password field",
    )?;
    ensure_element_within_prompt_root(
        &prompt.native_container,
        &prompt.target_window,
        "prompt container",
    )?;
    ensure_element_within_prompt_root(
        &prompt.prompt_root,
        &prompt.native_container,
        "prompt root",
    )?;
    ensure_element_within_prompt_root(
        &prompt.password_field,
        &prompt.prompt_root,
        "password field",
    )?;
    if is_hidden(&prompt.target_window)
        || is_hidden(&prompt.prompt_root)
        || is_hidden(&prompt.password_field)
        || !has_secure_password_field_identity(&prompt.password_field)
    {
        anyhow::bail!("original filled password field is no longer the visible secure field");
    }
    let trusted_process = current_trusted_process_info(app_name, expected_process_id)?;
    ensure_trusted_process_matches(
        &trusted_process,
        &filled_prompt.trusted_process,
        "credential prompt process identity changed before password cleanup",
    )?;
    if set_password_value(&prompt.password_field, "") {
        Ok(())
    } else {
        anyhow::bail!("failed to clear the original filled password field")
    }
}

fn set_password_value(field: &AxElement, password: &str) -> bool {
    field.set_string_attr(AX_VALUE, password)
}

fn collect_elements(root: &AxElement) -> AxTraversal<AxElement> {
    if is_hidden(root) {
        return AxTraversal {
            elements: Vec::new(),
            completeness: AxTraversalCompleteness::Complete,
        };
    }

    collect_descendants_bounded(root, AX_SEARCH_DEPTH, MAX_ELEMENT_COUNT, &mut |element| {
        element
            .optional_relationship_array_attr_result(AX_CHILDREN)
            .map(|children| {
                children
                    .into_iter()
                    .filter(|child| !is_hidden(child))
                    .collect()
            })
    })
}

fn collect_descendants_bounded<T, F>(
    root: &T,
    max_depth: usize,
    max_elements: usize,
    query_children: &mut F,
) -> AxTraversal<T>
where
    T: Clone,
    F: FnMut(&T) -> anyhow::Result<Vec<T>>,
{
    let mut traversal = AxTraversal {
        elements: Vec::new(),
        completeness: AxTraversalCompleteness::Complete,
    };
    collect_descendants_recursive(
        root,
        0,
        max_depth,
        max_elements,
        query_children,
        &mut traversal,
    );
    traversal
}

fn collect_descendants_recursive<T, F>(
    root: &T,
    depth: usize,
    max_depth: usize,
    max_elements: usize,
    query_children: &mut F,
    traversal: &mut AxTraversal<T>,
) where
    T: Clone,
    F: FnMut(&T) -> anyhow::Result<Vec<T>>,
{
    if traversal.completeness != AxTraversalCompleteness::Complete {
        return;
    }

    let child_elements = match query_children(root) {
        Ok(children) => children,
        Err(error) => {
            traversal.completeness = AxTraversalCompleteness::ChildQueryFailed(error.to_string());
            return;
        }
    };
    if child_elements.is_empty() {
        return;
    }
    if depth >= max_depth {
        traversal.completeness = AxTraversalCompleteness::DepthLimitReached { max_depth };
        return;
    }

    for child in child_elements {
        if traversal.elements.len() >= max_elements {
            traversal.completeness = AxTraversalCompleteness::ElementLimitReached { max_elements };
            return;
        }
        traversal.elements.push(child.clone());
        collect_descendants_recursive(
            &child,
            depth + 1,
            max_depth,
            max_elements,
            query_children,
            traversal,
        );
        if traversal.completeness != AxTraversalCompleteness::Complete {
            return;
        }
    }
}

fn sheet_candidates_for_window(window: &AxElement) -> anyhow::Result<Vec<AxElement>> {
    let mut sheets = window
        .optional_relationship_array_attr_result(AX_SHEETS)
        .context("unable to enumerate credential sheets")?;
    for element in window
        .optional_relationship_array_attr_result(AX_CHILDREN)
        .context("unable to enumerate credential window children")?
        .into_iter()
        .filter(|element| role_matches(element, AX_SHEET_ROLE))
    {
        if sheets
            .iter()
            .any(|existing| existing.same_element(&element))
        {
            continue;
        }
        sheets.push(element);
    }
    Ok(sheets)
}

fn unique_direct_sheet_prompt(
    target: &MacosTarget,
    target_window: &AxElement,
    visible_direct_sheets: &[AxElement],
    trusted_process: &macos_identity::TrustedProcessInfo,
) -> anyhow::Result<Option<MacosPrompt>> {
    if visible_direct_sheets.len() > MAX_DIRECT_SHEET_COUNT {
        anyhow::bail!("too many direct credential sheet candidates are visible");
    }

    let mut candidates = Vec::with_capacity(visible_direct_sheets.len());
    for sheet in visible_direct_sheets {
        let sheet_elements = collect_elements(sheet)
            .into_complete_elements()
            .context("credential sheet AX tree traversal was incomplete")?;
        let sheet_target = MacosTarget {
            frontmost: true,
            ..target.clone()
        };
        candidates.push(prompt_from_elements(
            sheet_target,
            target_window,
            sheet,
            &sheet_elements,
            PromptOrigin::Sheet,
            trusted_process,
        )?);
    }
    match unique_true_index(candidates.iter().map(Option::is_some)) {
        UniqueTrueIndex::None => Ok(None),
        UniqueTrueIndex::One(index) => Ok(candidates.into_iter().nth(index).flatten()),
        UniqueTrueIndex::Multiple => {
            anyhow::bail!("multiple credential sheet candidates are visible")
        }
    }
}

fn window_should_scan_for_prompt(window: &AxElement, window_title: &str) -> bool {
    let identity = window.string_attrs(&[AX_ROLE, AX_SUBROLE]);
    native_credential_window_identity(
        identity.first().and_then(Option::as_deref),
        identity.get(1).and_then(Option::as_deref),
        window_title,
    )
}

fn native_credential_window_identity(
    role: Option<&str>,
    subrole: Option<&str>,
    window_title: &str,
) -> bool {
    role.is_some_and(|role| role.eq_ignore_ascii_case(AX_WINDOW_ROLE))
        && subrole.is_some_and(|subrole| {
            subrole.eq_ignore_ascii_case(AX_DIALOG_SUBROLE)
                || subrole.eq_ignore_ascii_case(AX_SYSTEM_DIALOG_SUBROLE)
        })
        && login_title_like(window_title)
}

fn prompt_from_elements(
    target: MacosTarget,
    target_window: &AxElement,
    root: &AxElement,
    elements: &[AxElement],
    origin: PromptOrigin,
    trusted_process: &macos_identity::TrustedProcessInfo,
) -> anyhow::Result<Option<MacosPrompt>> {
    let prompt_body_text = collect_prompt_text("", elements);
    let Some(prompt_email) = extract_email_like(&prompt_body_text) else {
        return Ok(None);
    };
    if !prompt_identity_verified(&target.window_title, &prompt_body_text, origin) {
        return Ok(None);
    }
    for password_field in password_field_candidates(elements) {
        let Some((prompt_root, scoped_elements)) = select_credential_prompt_scope(
            root,
            &password_field,
            &prompt_email,
            &target.window_title,
            origin,
        )?
        else {
            continue;
        };
        let scoped_body_text = collect_prompt_text("", &scoped_elements);
        if !scoped_prompt_matches(
            &scoped_body_text,
            &prompt_email,
            &target.window_title,
            origin,
        ) {
            continue;
        }
        let submit_button = select_prompt_submit_button(&scoped_elements);
        if submit_button.is_none() {
            return Ok(None);
        }
        let identity_text = prompt_text_snapshots(
            &scoped_elements,
            &prompt_email,
            &target.window_title,
            origin,
        );

        return Ok(Some(MacosPrompt {
            target,
            email: Some(prompt_email),
            password_field_description: element_label_text(&password_field),
            password_field_role: element_role_text(&password_field),
            origin,
            trusted_process: trusted_process.clone(),
            target_window: target_window.clone(),
            native_container: root.clone(),
            prompt_root,
            password_field,
            submit_button,
            identity_text,
        }));
    }

    Ok(None)
}

fn select_credential_prompt_scope(
    root: &AxElement,
    password_field: &AxElement,
    prompt_email: &str,
    window_title: &str,
    origin: PromptOrigin,
) -> anyhow::Result<Option<(AxElement, Vec<AxElement>)>> {
    let mut ancestor = password_field.parent();
    for _ in 0..AX_SEARCH_DEPTH {
        let Some(current) = ancestor else {
            return Ok(None);
        };
        let scoped_elements = collect_elements(&current)
            .into_complete_elements()
            .context("credential prompt scope AX tree traversal was incomplete")?;
        let scoped_body_text = collect_prompt_text("", &scoped_elements);
        if scoped_prompt_matches(&scoped_body_text, prompt_email, window_title, origin)
            && select_prompt_submit_button(&scoped_elements).is_some()
        {
            return Ok(Some((current, scoped_elements)));
        }

        let reached_root = current.same_element(root);
        if reached_root {
            break;
        }
        ancestor = current.parent();
    }
    Ok(None)
}

fn scoped_prompt_matches(
    body_text: &str,
    prompt_email: &str,
    window_title: &str,
    origin: PromptOrigin,
) -> bool {
    extract_email_like(body_text)
        .as_deref()
        .is_some_and(|email| usernames_match(email, prompt_email))
        && prompt_identity_verified(window_title, body_text, origin)
}

fn password_field_candidates(elements: &[AxElement]) -> Vec<AxElement> {
    dedupe_elements(
        elements
            .iter()
            .filter(|element| is_native_password_field(element))
            .cloned()
            .collect::<Vec<_>>(),
    )
}

fn dedupe_elements(elements: Vec<AxElement>) -> Vec<AxElement> {
    let mut distinct = Vec::new();
    for element in elements {
        if distinct
            .iter()
            .any(|existing: &AxElement| existing.same_element(&element))
        {
            continue;
        }
        distinct.push(element);
    }
    distinct
}

fn select_prompt_submit_button(elements: &[AxElement]) -> Option<AxElement> {
    select_submit_button_candidate(elements, false)
}

fn select_submit_button_candidate(
    elements: &[AxElement],
    require_enabled: bool,
) -> Option<AxElement> {
    let candidates = elements
        .iter()
        .filter(|element| is_button(element))
        .filter(|element| !is_hidden(element))
        .filter(|element| !require_enabled || element_enabled(element))
        .filter_map(|element| submit_label_rank(&button_text(element)).map(|rank| (rank, element)))
        .collect::<Vec<_>>();

    let best_rank = candidates.iter().map(|(rank, _)| *rank).min()?;
    let best = candidates
        .into_iter()
        .filter(|(rank, _)| *rank == best_rank)
        .collect::<Vec<_>>();

    let [(_, candidate)] = best.as_slice() else {
        return None;
    };

    Some((*candidate).clone())
}

fn collect_prompt_text(window_title: &str, elements: &[AxElement]) -> String {
    let mut text = String::from(window_title);
    for element in elements {
        let hidden = is_hidden(element);
        if !prompt_text_element_should_contribute(
            hidden,
            false,
            has_secure_password_field_identity(element),
            has_password_like_text_field_identity(element),
        ) {
            continue;
        }

        push_text(&mut text, element.string_attr(AX_TITLE));
        push_text(&mut text, element.string_attr(AX_PLACEHOLDER));

        if is_text_or_static_text(element) && !has_sensitive_password_field_identity(element) {
            push_text(&mut text, element.string_attr(AX_VALUE));
        }
    }
    text
}

fn prompt_text_snapshots(
    elements: &[AxElement],
    prompt_email: &str,
    window_title: &str,
    origin: PromptOrigin,
) -> Vec<PromptTextSnapshot> {
    let snapshots = elements
        .iter()
        .filter(|element| {
            let hidden = is_hidden(element);
            prompt_text_element_should_contribute(
                hidden,
                false,
                has_secure_password_field_identity(element),
                has_password_like_text_field_identity(element),
            )
        })
        .map(|element| {
            let title = element.string_attr(AX_TITLE);
            let placeholder = element.string_attr(AX_PLACEHOLDER);
            // Keep AXValue out of bulk reads and repeat the sensitivity check
            // immediately before the only possible value query.
            let value = if is_text_or_static_text(element)
                && !has_sensitive_password_field_identity(element)
            {
                element.string_attr(AX_VALUE)
            } else {
                None
            };
            PromptTextSnapshot {
                element: element.clone(),
                title,
                placeholder,
                value,
            }
        })
        .collect::<Vec<_>>();

    select_identity_snapshots(snapshots, prompt_email, window_title, origin)
}

fn select_identity_snapshots(
    snapshots: Vec<PromptTextSnapshot>,
    prompt_email: &str,
    window_title: &str,
    origin: PromptOrigin,
) -> Vec<PromptTextSnapshot> {
    if snapshots.len() <= 3
        || !prompt_text_snapshots_match(&snapshots, prompt_email, window_title, origin)
    {
        return snapshots;
    }

    let mut ranked_candidates = snapshots
        .iter()
        .enumerate()
        .filter_map(|(index, snapshot)| {
            let text = prompt_text_snapshot_text(snapshot);
            let has_email = extract_email_like(&text)
                .as_deref()
                .is_some_and(|email| usernames_match(email, prompt_email));
            let has_credential_cue = prompt_identity_verified(window_title, &text, origin)
                || text_contains_password_cue(&text);
            (has_email || has_credential_cue).then_some((
                match (has_email, has_credential_cue) {
                    (true, true) => 0_u8,
                    (true, false) => 1,
                    (false, true) => 2,
                    (false, false) => 3,
                },
                index,
            ))
        })
        .collect::<Vec<_>>();
    ranked_candidates.sort_unstable();
    let candidates = ranked_candidates
        .into_iter()
        .map(|(_, index)| index)
        .take(24)
        .collect::<Vec<_>>();

    for &a in &candidates {
        let selected = vec![snapshots[a].clone()];
        if prompt_text_snapshots_match(&selected, prompt_email, window_title, origin) {
            return selected;
        }
    }
    for (offset, &a) in candidates.iter().enumerate() {
        for &b in candidates.iter().skip(offset + 1) {
            let selected = vec![snapshots[a].clone(), snapshots[b].clone()];
            if prompt_text_snapshots_match(&selected, prompt_email, window_title, origin) {
                return selected;
            }
        }
    }
    for (a_offset, &a) in candidates.iter().take(16).enumerate() {
        for (b_offset, &b) in candidates.iter().take(16).skip(a_offset + 1).enumerate() {
            for &c in candidates.iter().take(16).skip(a_offset + b_offset + 2) {
                let selected = vec![
                    snapshots[a].clone(),
                    snapshots[b].clone(),
                    snapshots[c].clone(),
                ];
                if prompt_text_snapshots_match(&selected, prompt_email, window_title, origin) {
                    return selected;
                }
            }
        }
    }

    snapshots
}

fn prompt_text_snapshot_text(snapshot: &PromptTextSnapshot) -> String {
    let mut text = String::new();
    push_text(&mut text, snapshot.title.clone());
    push_text(&mut text, snapshot.placeholder.clone());
    push_text(&mut text, snapshot.value.clone());
    text
}

fn collect_prompt_snapshot_text(window_title: &str, snapshots: &[PromptTextSnapshot]) -> String {
    let mut text = String::from(window_title);
    for snapshot in snapshots {
        push_text(&mut text, snapshot.title.clone());
        push_text(&mut text, snapshot.placeholder.clone());
        push_text(&mut text, snapshot.value.clone());
    }
    text
}

fn prompt_text_element_should_contribute(
    hidden: bool,
    hidden_ancestor: bool,
    native_password_field: bool,
    password_like_text_field: bool,
) -> bool {
    !hidden && !hidden_ancestor && !native_password_field && !password_like_text_field
}

fn button_text(element: &AxElement) -> String {
    let mut text = String::new();
    push_text(&mut text, element.string_attr(AX_TITLE));
    push_text(&mut text, element.string_attr(AX_VALUE));
    push_text(&mut text, element.string_attr(AX_DESCRIPTION));
    push_text(&mut text, element.string_attr(AX_HELP));
    text
}

fn element_label_text(element: &AxElement) -> String {
    let mut text = String::new();
    push_text(&mut text, element.string_attr(AX_TITLE));
    push_text(&mut text, element.string_attr(AX_DESCRIPTION));
    push_text(&mut text, element.string_attr(AX_HELP));
    push_text(&mut text, element.string_attr(AX_PLACEHOLDER));
    push_text(&mut text, element.string_attr(AX_ROLE_DESCRIPTION));
    text
}

fn element_role_text(element: &AxElement) -> String {
    [
        element.string_attr(AX_ROLE),
        element.string_attr(AX_SUBROLE),
        element.string_attr(AX_ROLE_DESCRIPTION),
    ]
    .into_iter()
    .flatten()
    .filter(|part| !part.trim().is_empty())
    .collect::<Vec<_>>()
    .join(" ")
}

fn push_text(target: &mut String, value: Option<String>) {
    if let Some(value) = value.map(|value| value.trim().to_string()) {
        if !value.is_empty() {
            target.push(' ');
            target.push_str(&value);
        }
    }
}

fn is_button(element: &AxElement) -> bool {
    role_matches(element, AX_BUTTON_ROLE)
}

fn is_text_or_static_text(element: &AxElement) -> bool {
    role_matches(element, AX_TEXT_FIELD_ROLE) || role_matches(element, AX_STATIC_TEXT_ROLE)
}

fn is_native_password_field(element: &AxElement) -> bool {
    is_secure_password_insertion_field(element)
}

fn is_secure_password_insertion_field(element: &AxElement) -> bool {
    !is_hidden(element) && element_enabled(element) && has_secure_password_field_identity(element)
}

fn has_secure_password_field_identity(element: &AxElement) -> bool {
    [AX_ROLE, AX_SUBROLE].iter().any(|attr| {
        element.string_attr(attr).is_some_and(|value| {
            value.eq_ignore_ascii_case(AX_SECURE_TEXT_FIELD_ROLE)
                || normalized_identifier(&value) == "securetextfield"
        })
    })
}

fn has_password_like_text_field_identity(element: &AxElement) -> bool {
    role_matches(element, AX_TEXT_FIELD_ROLE)
        && text_contains_password_cue(&element_label_text(element))
}

fn has_sensitive_password_field_identity(element: &AxElement) -> bool {
    has_secure_password_field_identity(element) || has_password_like_text_field_identity(element)
}

fn role_matches(element: &AxElement, expected: &str) -> bool {
    element
        .string_attr(AX_ROLE)
        .is_some_and(|role| role.eq_ignore_ascii_case(expected))
}

fn is_hidden(element: &AxElement) -> bool {
    // Windows App omits AXHidden on its native credential window, attached
    // sheet, and controls. Attribute absence is not a hidden state; only an
    // explicit true may remove an element from the bounded trusted AX tree.
    element.bool_attr(AX_HIDDEN).unwrap_or(false)
}

fn element_enabled(element: &AxElement) -> bool {
    element.bool_attr(AX_ENABLED) == Some(true)
}

fn element_foreground_state(element: &AxElement) -> AxForegroundState {
    AxForegroundState {
        focused: element.bool_attr(AX_FOCUSED),
        main: element.bool_attr(AX_MAIN),
    }
}

fn select_unique_foreground_index(
    app_frontmost: bool,
    states: &[AxForegroundState],
) -> Option<usize> {
    if !app_frontmost
        || states.is_empty()
        || states
            .iter()
            .any(|state| state.focused.is_none() || state.main.is_none())
    {
        return None;
    }

    match unique_true_index(
        states
            .iter()
            .map(|state| state.focused == Some(true) || state.main == Some(true)),
    ) {
        UniqueTrueIndex::One(index) => Some(index),
        UniqueTrueIndex::None | UniqueTrueIndex::Multiple => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UniqueTrueIndex {
    None,
    One(usize),
    Multiple,
}

fn unique_true_index(states: impl IntoIterator<Item = bool>) -> UniqueTrueIndex {
    let mut selected = None;
    for (index, state) in states.into_iter().enumerate() {
        if !state {
            continue;
        }
        if selected.is_some() {
            return UniqueTrueIndex::Multiple;
        }
        selected = Some(index);
    }
    selected.map_or(UniqueTrueIndex::None, UniqueTrueIndex::One)
}

fn element_is_direct_child_of(element: &AxElement, expected_parent: &AxElement) -> bool {
    element
        .parent()
        .is_some_and(|parent| parent.same_element(expected_parent))
}

fn login_title_like(title: &str) -> bool {
    LOGIN_TITLE_KEYWORDS
        .iter()
        .any(|keyword| contains_keyword(title, keyword))
}

fn credential_prompt_text_like(text: &str) -> bool {
    STRONG_CREDENTIAL_TEXT_KEYWORDS
        .iter()
        .any(|keyword| contains_keyword(text, keyword))
}

fn sheet_credential_prompt_text_like(text: &str) -> bool {
    SHEET_PASSWORD_ACTION_KEYWORDS
        .iter()
        .any(|keyword| contains_keyword(text, keyword))
}

fn prompt_identity_verified(window_title: &str, body_text: &str, origin: PromptOrigin) -> bool {
    match origin {
        PromptOrigin::Window => {
            credential_prompt_text_like(body_text) && login_title_like(window_title)
        }
        PromptOrigin::Sheet => sheet_credential_prompt_text_like(body_text),
    }
}

fn is_probable_session_window_title(title: &str) -> bool {
    let trimmed = title.trim();
    if trimmed.is_empty() {
        return false;
    }

    !NON_SESSION_TITLE_KEYWORDS
        .iter()
        .any(|keyword| contains_keyword(trimmed, keyword))
}

fn prompt_window_title_matches(current_title: &str, expected_window_title: Option<&str>) -> bool {
    let Some(expected_window_title) = expected_window_title
        .map(str::trim)
        .filter(|title| !title.is_empty())
    else {
        return true;
    };

    current_title.eq_ignore_ascii_case(expected_window_title)
}

fn usernames_match(prompt_email: &str, account_username: &str) -> bool {
    prompt_email
        .trim()
        .eq_ignore_ascii_case(account_username.trim())
}

fn submit_label_rank(label: &str) -> Option<u8> {
    let label = normalized_submit_label(label);
    if label.is_empty() {
        return None;
    }
    if label.eq_ignore_ascii_case("continue") || label == "Продолжить" {
        return Some(0);
    }
    let tokens = label
        .split_whitespace()
        .map(normalized_identifier)
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();
    if tokens
        .iter()
        .any(|token| token == "ok" || token == "okbutton")
    {
        return Some(1);
    }
    if SUBMIT_LABELS
        .iter()
        .any(|submit| label.eq_ignore_ascii_case(submit))
    {
        return Some(1);
    }
    tokens
        .iter()
        .any(|token| {
            SUBMIT_LABELS
                .iter()
                .any(|submit| normalized_identifier(submit) == *token)
        })
        .then_some(1)
}

#[cfg(test)]
fn select_submit_label_for_test(labels: &[(&str, bool)]) -> Option<String> {
    let candidates = labels
        .iter()
        .filter(|(_, enabled)| *enabled)
        .filter_map(|(label, _)| submit_label_rank(label).map(|rank| (rank, *label)))
        .collect::<Vec<_>>();

    let best_rank = candidates.iter().map(|(rank, _)| *rank).min()?;
    let best = candidates
        .into_iter()
        .filter(|(rank, _)| *rank == best_rank)
        .collect::<Vec<_>>();

    let [(_, label)] = best.as_slice() else {
        return None;
    };

    Some((*label).to_string())
}

fn normalized_submit_label(label: &str) -> String {
    let without_mnemonics = label
        .chars()
        .filter(|c| !matches!(c, '&' | '_' | '\u{200e}' | '\u{200f}'))
        .collect::<String>();
    let collapsed = without_mnemonics
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    collapsed
        .strip_suffix(" button")
        .or_else(|| collapsed.strip_suffix(" Button"))
        .unwrap_or(&collapsed)
        .trim()
        .to_string()
}

fn normalized_identifier(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(|c| c.to_lowercase())
        .collect()
}

fn text_contains_password_cue(text: &str) -> bool {
    PASSWORD_CUES
        .iter()
        .any(|cue| text.to_lowercase().contains(cue))
}

pub(crate) fn extract_email_like(text: &str) -> Option<String> {
    let chars: Vec<char> = text.chars().collect();
    let at_positions = chars
        .iter()
        .enumerate()
        .filter_map(|(idx, c)| (*c == '@').then_some(idx))
        .collect::<Vec<_>>();

    let mut matches: Vec<(String, String)> = Vec::new();
    for at in at_positions {
        let mut start = at;
        while start > 0 && is_email_char(chars[start - 1]) {
            start -= 1;
        }

        let mut end = at + 1;
        while end < chars.len() && is_email_char(chars[end]) {
            end += 1;
        }

        let candidate = chars[start..end]
            .iter()
            .collect::<String>()
            .trim_matches(|c: char| matches!(c, '.' | ',' | ';' | ':' | ')' | ']' | '}'))
            .to_string();

        let mut parts = candidate.split('@');
        let local = parts.next().unwrap_or_default();
        let domain = parts.next().unwrap_or_default();
        if parts.next().is_none()
            && !local.is_empty()
            && domain.contains('.')
            && !domain.starts_with('.')
            && !domain.ends_with('.')
        {
            let normalized = candidate.trim().to_lowercase();
            if !matches.iter().any(|(existing, _)| existing == &normalized) {
                matches.push((normalized, candidate));
            }
        }
    }

    let [(_, email)] = matches.as_slice() else {
        return None;
    };
    Some(email.clone())
}

fn is_email_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '%' | '+' | '-' | '@')
}

fn contains_keyword(text: &str, keyword: &str) -> bool {
    let text_lower = text.to_lowercase();
    let keyword_lower = keyword.to_lowercase();

    if text_lower == keyword_lower {
        return true;
    }

    let text_len = text_lower.len();
    for (abs_pos, matched) in text_lower.match_indices(&keyword_lower) {
        let keyword_len = matched.len();
        let before_ok = abs_pos == 0
            || text_lower[..abs_pos]
                .chars()
                .next_back()
                .is_none_or(|c| !c.is_alphanumeric());
        let after_ok = abs_pos + keyword_len >= text_len
            || text_lower[abs_pos + keyword_len..]
                .chars()
                .next()
                .is_none_or(|c| !c.is_alphanumeric());
        if before_ok && after_ok {
            return true;
        }
    }
    false
}

fn send_text(target_process_id: i32, text: &str) -> bool {
    let mut utf16 = zeroizing_utf16_buffer(text);
    if utf16.is_empty() {
        return true;
    }
    unsafe {
        let down = CGEventCreateKeyboardEvent(std::ptr::null(), 0, true);
        if down.is_null() {
            return false;
        }
        let up = CGEventCreateKeyboardEvent(std::ptr::null(), 0, false);
        if up.is_null() {
            CFRelease(down.cast());
            return false;
        }
        CGEventKeyboardSetUnicodeString(down, utf16.len(), utf16.as_ptr());
        CGEventKeyboardSetUnicodeString(up, utf16.len(), utf16.as_ptr());
        CGEventPostToPid(target_process_id, down);
        CGEventPostToPid(target_process_id, up);
        CFRelease(down.cast());
        CFRelease(up.cast());
    }
    utf16.zeroize();
    true
}

fn send_key(target_process_id: i32, keycode: u16) -> bool {
    send_key_with_flags(target_process_id, keycode, 0)
}

fn send_key_with_flags(target_process_id: i32, keycode: u16, flags: u64) -> bool {
    unsafe {
        let down = CGEventCreateKeyboardEvent(std::ptr::null(), keycode, true);
        if down.is_null() {
            return false;
        }
        let up = CGEventCreateKeyboardEvent(std::ptr::null(), keycode, false);
        if up.is_null() {
            CFRelease(down.cast());
            return false;
        }
        CGEventSetFlags(down, flags);
        CGEventSetFlags(up, flags);
        CGEventPostToPid(target_process_id, down);
        CGEventPostToPid(target_process_id, up);
        CFRelease(down.cast());
        CFRelease(up.cast());
    }
    true
}

const LOGIN_TITLE_KEYWORDS: &[&str] = &[
    "Sign in",
    "Authentication",
    "Credentials",
    "Login",
    "Password",
    "Enter password",
    "Microsoft account",
    "Work or school",
    "Authenticate",
    "Log in",
    "Sign-in",
    "Credential",
];

const STRONG_CREDENTIAL_TEXT_KEYWORDS: &[&str] = &[
    "Sign in",
    "Sign-in",
    "Log in",
    "Enter Your Credentials",
    "Enter password",
    "Microsoft account",
    "Work or school",
    "Authenticate",
    "These credentials will be used",
    "used to connect to",
    "Введите пароль",
    "Mot de passe",
    "Contraseña",
    "Contrasena",
    "Hasło",
    "Haslo",
];

const SHEET_PASSWORD_ACTION_KEYWORDS: &[&str] = &[
    "Enter your user account",
    "Enter Your Credentials",
    "Enter password",
    "These credentials will be used",
    "used to connect to",
    "Введите пароль",
    "Mot de passe",
    "Contraseña",
    "Contrasena",
    "Wpisz hasło",
    "Wpisz haslo",
    "Podaj hasło",
    "Podaj haslo",
];

const NON_SESSION_TITLE_KEYWORDS: &[&str] = &[
    "devices",
    "windows app",
    "settings",
    "preferences",
    "about windows app",
    "connection center",
    "connection lost",
    "disconnected",
    "unable to connect",
    "add pc",
    "add workspace",
    "workspaces",
    "workspace",
    "accounts",
    "sign in",
    "authentication",
    "credentials",
    "login",
    "password",
];

const SUBMIT_LABELS: &[&str] = &[
    "Continue",
    "Продолжить",
    "OK",
    "Sign in",
    "Log in",
    "Connect",
    "Next",
    "Submit",
    "Done",
];

const PASSWORD_CUES: &[&str] = &[
    "password",
    "passwort",
    "kennwort",
    "mot de passe",
    "contraseña",
    "contrasena",
    "hasło",
    "haslo",
    "пароль",
];

type AXUIElementRef = *const c_void;
type AXError = i32;
type CGEventRef = *const c_void;
const K_AX_ERROR_SUCCESS: AXError = 0;
const K_AX_ERROR_ATTRIBUTE_UNSUPPORTED: AXError = -25205;
const K_AX_ERROR_NO_VALUE: AXError = -25212;

fn ax_relationship_attr_is_absent(error: AXError) -> bool {
    matches!(
        error,
        K_AX_ERROR_ATTRIBUTE_UNSUPPORTED | K_AX_ERROR_NO_VALUE
    )
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    static kCFAllocatorNull: *const c_void;
    fn CFStringCreateWithCharactersNoCopy(
        allocator: *const c_void,
        chars: *const u16,
        num_chars: isize,
        contents_deallocator: *const c_void,
    ) -> CFStringRef;
}

#[link(name = "ApplicationServices", kind = "framework")]
unsafe extern "C" {
    fn AXUIElementCreateApplication(pid: i32) -> AXUIElementRef;
    fn AXUIElementGetTypeID() -> CFTypeID;
    fn AXUIElementSetMessagingTimeout(element: AXUIElementRef, timeout: f32) -> AXError;
    fn AXUIElementCopyAttributeValue(
        element: AXUIElementRef,
        attribute: CFStringRef,
        value: *mut CFTypeRef,
    ) -> AXError;
    fn AXUIElementCopyMultipleAttributeValues(
        element: AXUIElementRef,
        attributes: CFArrayRef,
        options: u32,
        values: *mut CFArrayRef,
    ) -> AXError;
    fn AXUIElementSetAttributeValue(
        element: AXUIElementRef,
        attribute: CFStringRef,
        value: CFTypeRef,
    ) -> AXError;
    fn AXUIElementPerformAction(element: AXUIElementRef, action: CFStringRef) -> AXError;
    fn AXUIElementGetPid(element: AXUIElementRef, pid: *mut libc::pid_t) -> AXError;
    fn CGEventCreateKeyboardEvent(
        source: *const c_void,
        virtual_key: u16,
        key_down: bool,
    ) -> CGEventRef;
    fn CGEventKeyboardSetUnicodeString(
        event: CGEventRef,
        string_length: usize,
        unicode_string: *const u16,
    );
    fn CGEventSetFlags(event: CGEventRef, flags: u64);
    fn CGEventPostToPid(pid: libc::pid_t, event: CGEventRef);
}

#[cfg(test)]
mod tests {
    use super::{
        collect_descendants_bounded, credential_prompt_text_like, extract_email_like,
        normalized_submit_label, prompt_identity_verified, prompt_text_element_should_contribute,
        prompt_window_title_matches, select_submit_label_for_test, submit_label_rank,
        text_contains_password_cue, AxTraversalCompleteness, PromptOrigin,
        FOCUS_ACQUIRE_TIMEOUT_MS, FOCUS_POLL_INTERVAL_MS, FOCUS_STABLE_SETTLE_MS,
        PASSWORD_FILL_READY_MS,
    };
    use std::time::{Duration, Instant};

    #[test]
    fn extracts_email_like_text() {
        assert_eq!(
            extract_email_like("Signed in as user.name+rdp@example.com"),
            Some("user.name+rdp@example.com".to_string())
        );
        assert_eq!(extract_email_like("No email here"), None);
    }

    #[test]
    fn email_extraction_rejects_multiple_distinct_visible_emails() {
        assert_eq!(
            extract_email_like("user@example.com recovery other@example.com"),
            None
        );
        assert_eq!(
            extract_email_like("user@example.com signed in as USER@example.com"),
            Some("user@example.com".to_string())
        );
    }

    #[test]
    fn checked_ax_traversal_collects_a_complete_tree() {
        let traversal = collect_descendants_bounded(&0_u8, 4, 8, &mut |node| {
            Ok(match *node {
                0 => vec![1, 2],
                1 => vec![3],
                _ => Vec::new(),
            })
        });

        assert_eq!(traversal.completeness, AxTraversalCompleteness::Complete);
        assert_eq!(traversal.into_complete_elements().unwrap(), vec![1, 3, 2]);
    }

    #[test]
    fn checked_ax_traversal_fails_closed_on_child_query_error() {
        let traversal = collect_descendants_bounded(&0_u8, 4, 8, &mut |node| {
            if *node == 1 {
                anyhow::bail!("provider denied AXChildren");
            }
            Ok(if *node == 0 { vec![1, 2] } else { Vec::new() })
        });

        assert!(matches!(
            &traversal.completeness,
            AxTraversalCompleteness::ChildQueryFailed(error)
                if error.contains("provider denied AXChildren")
        ));
        assert!(traversal.into_complete_elements().is_err());
    }

    #[test]
    fn checked_ax_traversal_fails_closed_when_depth_limit_hides_descendants() {
        let traversal = collect_descendants_bounded(&0_u8, 2, 8, &mut |node| {
            Ok(if *node < 3 {
                vec![*node + 1]
            } else {
                Vec::new()
            })
        });

        assert_eq!(
            traversal.completeness,
            AxTraversalCompleteness::DepthLimitReached { max_depth: 2 }
        );
        assert!(traversal.into_complete_elements().is_err());
    }

    #[test]
    fn checked_ax_traversal_fails_closed_when_element_limit_hides_siblings() {
        let traversal = collect_descendants_bounded(&0_u8, 4, 2, &mut |node| {
            Ok(if *node == 0 {
                vec![1, 2, 3]
            } else {
                Vec::new()
            })
        });

        assert_eq!(
            traversal.completeness,
            AxTraversalCompleteness::ElementLimitReached { max_elements: 2 }
        );
        assert!(traversal.into_complete_elements().is_err());
    }

    #[test]
    fn checked_ax_traversal_accepts_exact_complete_limits() {
        let depth_boundary = collect_descendants_bounded(&0_u8, 2, 8, &mut |node| {
            Ok(if *node < 2 {
                vec![*node + 1]
            } else {
                Vec::new()
            })
        });
        assert_eq!(
            depth_boundary.completeness,
            AxTraversalCompleteness::Complete
        );

        let element_boundary = collect_descendants_bounded(&0_u8, 4, 2, &mut |node| {
            Ok(if *node == 0 { vec![1, 2] } else { Vec::new() })
        });
        assert_eq!(
            element_boundary.completeness,
            AxTraversalCompleteness::Complete
        );
    }

    #[test]
    fn prompt_discovery_consumes_only_complete_checked_ax_traversals() {
        let implementation = include_str!("macos_ax.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        let inspection = implementation
            .split("fn inspect_process")
            .nth(1)
            .and_then(|tail| tail.split("fn trusted_process_infos_for_inspection").next())
            .unwrap();
        let scope_selection = implementation
            .split("fn select_credential_prompt_scope")
            .nth(1)
            .and_then(|tail| tail.split("fn scoped_prompt_matches").next())
            .unwrap();

        let sheet_selection = implementation
            .split("fn unique_direct_sheet_prompt")
            .nth(1)
            .and_then(|tail| tail.split("fn window_should_scan_for_prompt").next())
            .unwrap();

        assert!(inspection.contains("into_complete_elements()"));
        assert!(sheet_selection.contains("into_complete_elements()"));
        assert!(scope_selection.contains("into_complete_elements()"));
        assert!(!implementation.contains("fn array_attr("));
        assert!(!implementation.contains("array_attr(AX_CHILDREN)"));
    }

    #[test]
    fn submit_labels_are_normalized_and_ranked() {
        for (label, normalized, rank) in [
            ("Continue", "Continue", Some(0)),
            ("_Continue button", "Continue", Some(0)),
            ("Continue button", "Continue", Some(0)),
            ("Продолжить", "Продолжить", Some(0)),
            ("OK", "OK", Some(1)),
            ("OK button", "OK", Some(1)),
            ("Cancel", "Cancel", None),
        ] {
            assert_eq!(normalized_submit_label(label), normalized);
            assert_eq!(submit_label_rank(label), rank);
        }
    }

    #[test]
    fn password_insertion_implementation_has_no_global_clipboard_api() {
        let implementation = include_str!("macos_ax.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        for forbidden in [
            concat!("Clip", "board"),
            concat!("SetExt", "Apple"),
            concat!("paste_text", "_into_focused_field"),
            concat!("KEYCODE", "_V"),
            concat!("\"paste", "board\""),
        ] {
            assert!(
                !implementation.contains(forbidden),
                "password insertion implementation must not use global clipboard API: {forbidden}"
            );
        }
    }

    #[test]
    fn password_insertion_uses_verified_pid_targeted_keyboard_events() {
        let implementation = include_str!("macos_ax.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        let fill_verified_password = implementation
            .split("pub(crate) fn fill_verified_password")
            .nth(1)
            .and_then(|tail| tail.split("pub(crate) fn submit_filled_prompt").next())
            .unwrap();
        let sender = include_str!("macos_ax.rs")
            .split("\nfn send_text(")
            .nth(1)
            .and_then(|tail| tail.split("const LOGIN_TITLE_KEYWORDS").next())
            .unwrap();

        assert!(fill_verified_password.contains("focus_password_field_in_prompt("));
        assert!(fill_verified_password.contains("revalidate_focused_password_field_for_keyboard("));
        assert!(fill_verified_password.contains("send_text(expected_process_id, password)"));
        assert!(fill_verified_password.contains("KEYCODE_A"));
        assert!(fill_verified_password.contains("KEYCODE_DELETE"));
        assert!(!fill_verified_password.contains("set_password_value("));
        assert!(sender.contains("CGEventPostToPid(target_process_id"));
        assert_eq!(
            sender.matches("CGEventPostToPid(target_process_id").count(),
            4
        );
        assert!(!sender.contains("CGEventPost(CG_HID_EVENT_TAP"));
        assert!(sender.contains("zeroizing_utf16_buffer(text)"));
    }

    #[test]
    fn password_load_preflight_does_not_receive_or_write_password() {
        let implementation = include_str!("macos_ax.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        let preflight = implementation
            .split("pub(crate) fn preflight_password_load_prompt")
            .nth(1)
            .and_then(|tail| tail.split("pub(crate) fn fill_verified_password").next())
            .unwrap();

        assert!(preflight.contains("revalidate_prepared_prompt_for_fill"));
        for forbidden in [
            "password:",
            "set_password_value",
            "AX_PRESS",
            "perform_action",
        ] {
            assert!(
                !preflight.contains(forbidden),
                "pre-password-load validation must not receive secrets or mutate UI: {forbidden}"
            );
        }
    }

    #[test]
    fn final_password_fill_revalidates_focus_and_identity_before_pid_targeted_keyboard_input() {
        let implementation = include_str!("macos_ax.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        let fill_verified_password = implementation
            .split("pub(crate) fn fill_verified_password")
            .nth(1)
            .and_then(|tail| tail.split("pub(crate) fn submit_filled_prompt").next())
            .unwrap();

        let revalidation = fill_verified_password
            .find("revalidate_prepared_prompt_for_fill")
            .unwrap();
        let focus = fill_verified_password
            .find("focus_password_field_in_prompt(")
            .unwrap();
        let write = fill_verified_password
            .find("send_text(expected_process_id, password)")
            .unwrap();
        let final_revalidation = fill_verified_password[..write]
            .rfind("revalidate_focused_password_field_for_keyboard(")
            .unwrap();

        assert!(revalidation < write);
        assert!(revalidation < focus);
        assert!(focus < final_revalidation);
        let final_guard = fill_verified_password[..write]
            .rfind("guard()")
            .expect("generation guard immediately before password write");
        assert!(final_revalidation < final_guard);
        assert!(final_guard < write);

        let prepared_revalidation = implementation
            .split("fn revalidate_prepared_prompt_for_fill")
            .nth(1)
            .and_then(|tail| tail.split("fn ensure_trusted_process_matches").next())
            .unwrap();
        assert!(prepared_revalidation.contains(
            "ensure_revalidated_frontmost(prompt_is_frontmost_now(prompt), \"password insertion\")"
        ));
    }

    #[test]
    fn every_fill_keyboard_event_rechecks_guard_after_focus_revalidation() {
        let implementation = include_str!("macos_ax.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        let fill = implementation
            .split("pub(crate) fn fill_verified_password")
            .nth(1)
            .and_then(|tail| tail.split("pub(crate) fn submit_filled_prompt").next())
            .unwrap();

        for event in [
            "send_key_with_flags(expected_process_id, KEYCODE_A, CG_EVENT_FLAG_MASK_COMMAND)",
            "send_key(expected_process_id, KEYCODE_DELETE)",
            "send_text(expected_process_id, password)",
        ] {
            let post = fill.find(event).unwrap();
            let guard = fill[..post].rfind("guard()").unwrap();
            let revalidation = fill[..post]
                .rfind("revalidate_focused_password_field_for_keyboard(")
                .unwrap();
            assert!(
                revalidation < guard,
                "final guard must follow revalidation for {event}"
            );
            assert!(guard < post, "final guard must be adjacent to {event}");
        }
    }

    #[test]
    fn password_axvalue_uses_wiped_no_copy_cfstring_backing() {
        let implementation = include_str!("macos_ax.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        let setter = implementation
            .split("fn set_string_attr")
            .nth(1)
            .and_then(|tail| tail.split("fn perform_action").next())
            .unwrap();
        let encoder = implementation
            .split("fn zeroizing_utf16_buffer")
            .nth(1)
            .and_then(|tail| tail.split("impl Clone for AxElement").next())
            .unwrap();

        assert!(setter.contains("zeroizing_utf16_buffer(value)"));
        assert!(encoder.contains("Zeroizing::new"));
        assert!(encoder.contains("Vec::with_capacity(value.len())"));
        assert!(setter.contains("CFStringCreateWithCharactersNoCopy"));
        assert!(setter.contains("kCFAllocatorNull"));
        assert!(setter.contains("drop(cf_value)"));
        assert!(setter.contains("utf16.zeroize()"));
        assert!(!setter.contains("CFString::new(value)"));
    }

    #[test]
    fn live_window_title_is_rechecked_at_fill_and_submit_boundaries() {
        let implementation = include_str!("macos_ax.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        let fill = implementation
            .split("pub(crate) fn fill_verified_password")
            .nth(1)
            .and_then(|tail| tail.split("pub(crate) fn submit_filled_prompt").next())
            .unwrap();
        let fill_revalidation = implementation
            .split("fn revalidate_prepared_prompt_for_fill")
            .nth(1)
            .and_then(|tail| tail.split("fn ensure_trusted_process_matches").next())
            .unwrap();
        let fast_submit = implementation
            .split("fn revalidate_filled_prompt")
            .nth(1)
            .and_then(|tail| tail.split("pub(crate) fn post_check_state").next())
            .unwrap();

        assert!(fill.contains("revalidate_prepared_prompt_for_fill"));
        assert!(fill_revalidation.contains("ensure_live_prompt_window_title"));
        assert!(fast_submit.contains("ensure_live_prompt_window_title"));
    }

    #[test]
    fn sole_background_prompt_is_never_selected() {
        assert_eq!(super::unique_frontmost_index([false]), None);
        assert_eq!(super::unique_frontmost_index([false, true]), Some(1));
        assert_eq!(super::unique_frontmost_index([true, true]), None);

        let implementation = include_str!("macos_ax.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        let detector = implementation
            .split("pub(crate) fn detect_visible_prompt")
            .nth(1)
            .and_then(|tail| tail.split("fn record_prompt_candidate").next())
            .unwrap();
        assert!(detector.contains(".filter(|prompt| prompt.target.frontmost)"));
    }

    #[test]
    fn foreground_loss_fails_closed_without_raising_or_retrying_submit() {
        assert!(super::ensure_revalidated_frontmost(false, "password insertion").is_err());
        assert!(super::ensure_revalidated_frontmost(true, "password insertion").is_ok());

        let implementation = include_str!("macos_ax.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        let focus_revalidation = implementation
            .split("fn ensure_prompt_frontmost_for_automation")
            .nth(1)
            .and_then(|tail| tail.split("fn ensure_revalidated_frontmost").next())
            .unwrap();
        assert!(focus_revalidation.contains("prompt_is_frontmost_now(prompt)"));
        assert!(!focus_revalidation.contains("raise_prompt"));
        assert!(!implementation.contains("AX_RAISE"));

        let fast_submit = implementation
            .split("pub(crate) fn submit_filled_prompt")
            .nth(1)
            .and_then(|tail| tail.split("pub(crate) fn submit_prompt_after_fill").next())
            .unwrap();
        let submitted_evidence = fast_submit.find("let submitted_prompt =").unwrap();
        let enter_submit = fast_submit
            .find("send_key(prompt.target.process_id, KEYCODE_RETURN)")
            .unwrap();
        let axpress_fallback = fast_submit.find("button.perform_action(AX_PRESS)").unwrap();
        let enter_guard = fast_submit[..enter_submit].rfind("guard()").unwrap();
        let enter_revalidation = fast_submit[..enter_submit]
            .rfind("revalidate_focused_password_field_for_keyboard(")
            .unwrap();
        assert!(submitted_evidence < enter_submit);
        assert!(enter_revalidation < enter_guard);
        assert!(enter_guard < enter_submit);
        assert!(enter_submit < axpress_fallback);
        assert_eq!(fast_submit.matches("perform_action(AX_PRESS)").count(), 1);
        assert!(fast_submit.contains("submitted_prompt: Some(submitted_prompt)"));
        assert!(fast_submit.contains("axpress_result: \"reported_error\""));
        assert!(!fast_submit.contains("success_after_raise"));
    }

    #[test]
    fn password_field_candidates_do_not_fall_back_to_plain_text_fields() {
        let implementation = include_str!("macos_ax.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        let candidate_selector = implementation
            .split("fn password_field_candidates")
            .nth(1)
            .and_then(|tail| tail.split("fn dedupe_elements").next())
            .unwrap();

        assert!(candidate_selector.contains("is_native_password_field"));
        assert!(
            !candidate_selector.contains("is_password_like_text_field"),
            "password insertion must not choose password-like plain AXTextField candidates"
        );
    }

    #[test]
    fn native_password_field_detection_requires_secure_role() {
        let implementation = include_str!("macos_ax.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        let detector = implementation
            .split("fn is_secure_password_insertion_field")
            .nth(1)
            .and_then(|tail| {
                tail.split("fn has_password_like_text_field_identity")
                    .next()
            })
            .unwrap();

        assert!(detector.contains("AX_SECURE_TEXT_FIELD_ROLE"));
        assert!(detector.contains("securetextfield"));
        assert!(detector.contains("[AX_ROLE, AX_SUBROLE]"));
        assert!(!detector.contains("element_label_text"));
        assert!(
            !detector.contains("contains_keyword(&role_text, \"secure\")"),
            "plain AXTextField must not become a password target from loose role description text"
        );
    }

    #[test]
    fn prompt_text_never_reads_axvalue_from_password_sensitive_identity() {
        let implementation = include_str!("macos_ax.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        let collector = implementation
            .split("fn collect_prompt_text")
            .nth(1)
            .and_then(|tail| tail.split("fn prompt_text_snapshots").next())
            .unwrap();
        let snapshots = implementation
            .split("fn prompt_text_snapshots(\n")
            .nth(1)
            .and_then(|tail| tail.split("fn select_identity_snapshots").next())
            .unwrap();
        let snapshot_revalidation = implementation
            .split("fn prompt_text_snapshot_changed")
            .nth(1)
            .and_then(|tail| tail.split("fn prompt_text_snapshots_match").next())
            .unwrap();
        let sensitive_identity = implementation
            .split("fn has_password_like_text_field_identity")
            .nth(1)
            .and_then(|tail| tail.split("fn role_matches").next())
            .unwrap();

        for reader in [collector, snapshots, snapshot_revalidation] {
            let sensitivity_check = reader
                .find("has_sensitive_password_field_identity")
                .expect("password sensitivity check before AXValue");
            let value_read = reader.find("AX_VALUE").expect("guarded AXValue read");
            assert!(sensitivity_check < value_read);
        }
        assert!(collector.contains("has_secure_password_field_identity(element)"));
        assert!(collector.contains("has_password_like_text_field_identity(element)"));
        assert!(snapshots.contains("has_secure_password_field_identity(element)"));
        assert!(snapshots.contains("has_password_like_text_field_identity(element)"));
        assert!(!snapshots.contains("string_attrs(&[AX_TITLE, AX_PLACEHOLDER, AX_VALUE])"));
        assert!(
            !snapshot_revalidation.contains("string_attrs(&[AX_TITLE, AX_PLACEHOLDER, AX_VALUE])")
        );
        assert!(!sensitive_identity.contains("element_enabled"));
        assert!(!sensitive_identity.contains("is_hidden"));
    }

    #[test]
    fn automation_timing_constants_stay_bounded() {
        let fill_ready_ms = std::hint::black_box(PASSWORD_FILL_READY_MS);
        let focus_poll_interval_ms = std::hint::black_box(FOCUS_POLL_INTERVAL_MS);
        let focus_stable_settle_ms = std::hint::black_box(FOCUS_STABLE_SETTLE_MS);
        let focus_acquire_timeout_ms = std::hint::black_box(FOCUS_ACQUIRE_TIMEOUT_MS);
        let post_submit_absence_dwell_ms =
            std::hint::black_box(super::POST_SUBMIT_REQUIRED_ABSENCE_DWELL_MS);

        assert!(fill_ready_ms >= focus_poll_interval_ms);
        assert!(Duration::from_millis(fill_ready_ms) < Duration::from_millis(450));
        assert!(focus_stable_settle_ms >= 80);
        assert!(focus_acquire_timeout_ms >= focus_stable_settle_ms);
        assert!(focus_stable_settle_ms >= focus_poll_interval_ms);
        assert!(post_submit_absence_dwell_ms >= 1_500);
    }

    #[test]
    fn password_focus_requires_active_press_before_stable_settle() {
        let implementation = include_str!("macos_ax.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        let focus = implementation
            .split("fn focus_password_field(")
            .nth(1)
            .and_then(|tail| tail.split("fn application_focus_matches_field(").next())
            .unwrap();
        let stable_wait = implementation
            .split("fn wait_for_stable_condition(")
            .nth(1)
            .and_then(|tail| {
                tail.split("fn wait_for_prompt_submit_button_enabled")
                    .next()
            })
            .unwrap();

        assert!(
            !focus.contains("if field.bool_attr(AX_FOCUSED) == Some(true) {\n        return true;")
        );
        let press = focus.find("field.perform_action(AX_PRESS)").unwrap();
        let focused = focus.find("field.set_bool_attr(AX_FOCUSED, true)").unwrap();
        let stable = focus.find("wait_for_stable_password_focus(").unwrap();
        assert!(press < focused);
        assert!(focused < stable);
        assert_eq!(focus.matches("field.perform_action(AX_PRESS)").count(), 1);
        assert_eq!(focus.matches("wait_for_stable_password_focus(").count(), 1);
        assert!(!focus[..press].contains("wait_for_stable_password_focus("));
        assert!(focus.contains("Duration::from_millis(FOCUS_STABLE_SETTLE_MS)"));
        assert!(focus.contains("Duration::from_millis(FOCUS_ACQUIRE_TIMEOUT_MS)"));
        assert!(implementation.contains("element_attr(AX_FOCUSED_UI_ELEMENT)"));
        assert!(implementation.contains("application_focus_matches_field(&field"));
        assert!(stable_wait.contains("stable_since"));
        assert!(stable_wait.contains("stable_since.elapsed() >= stable_for"));
    }

    #[test]
    fn keyboard_side_effect_revalidation_reuses_one_live_trust_lookup() {
        let implementation = include_str!("macos_ax.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        let revalidation = implementation
            .split("fn revalidate_focused_password_field_for_keyboard(")
            .nth(1)
            .and_then(|tail| {
                tail.split("fn ensure_prompt_frontmost_for_automation(")
                    .next()
            })
            .unwrap();

        assert_eq!(
            revalidation
                .matches("current_trusted_process_info(")
                .count(),
            1
        );
        assert_eq!(
            revalidation
                .matches("ensure_trusted_process_matches(")
                .count(),
            2
        );
        assert!(revalidation.contains("verified_password_field_in_prompt_after_trust("));
        assert!(!revalidation.contains("verified_password_field_in_prompt(prompt"));
    }

    #[test]
    fn hidden_elements_do_not_contribute_prompt_text() {
        assert!(!prompt_text_element_should_contribute(
            true, false, false, false
        ));
        assert!(!prompt_text_element_should_contribute(
            false, true, false, false
        ));
        assert!(!prompt_text_element_should_contribute(
            false, true, false, true
        ));
        assert!(!prompt_text_element_should_contribute(
            false, false, true, false
        ));
        assert!(!prompt_text_element_should_contribute(
            false, false, false, true
        ));
        assert!(prompt_text_element_should_contribute(
            false, false, false, false
        ));
    }

    #[test]
    fn submit_selection_requires_one_enabled_candidate() {
        assert_eq!(
            select_submit_label_for_test(&[("Cancel", true), ("Continue", true)]),
            Some("Continue".to_string())
        );
        assert_eq!(
            select_submit_label_for_test(&[("Continue", true), ("OK", true)]),
            Some("Continue".to_string())
        );
        assert_eq!(
            select_submit_label_for_test(&[("OK", true), ("Continue button", true)]),
            Some("Continue button".to_string())
        );
        assert_eq!(
            select_submit_label_for_test(&[("Continue", false), ("OK", true)]),
            Some("OK".to_string())
        );
        assert_eq!(
            select_submit_label_for_test(&[("Continue", true), ("_Continue button", true)]),
            None
        );
        assert_eq!(
            select_submit_label_for_test(&[("OK", true), ("Connect", true)]),
            None
        );
        assert_eq!(select_submit_label_for_test(&[("Continue", false)]), None);
    }

    #[test]
    fn password_cues_cover_existing_locales() {
        assert!(text_contains_password_cue("Введите пароль"));
        assert!(text_contains_password_cue("Mot de passe"));
        assert!(!text_contains_password_cue("Account"));
    }

    #[test]
    fn sheet_prompt_context_requires_login_like_text() {
        assert!(credential_prompt_text_like("Sign in with user@example.com"));
        assert!(credential_prompt_text_like(
            "Enter password for user@example.com"
        ));
        assert!(!credential_prompt_text_like("user@example.com"));
        assert!(!credential_prompt_text_like("Password user@example.com"));
    }

    #[test]
    fn post_submit_state_classification_handles_prompt_session_and_failure() {
        for (prompt_email, target_running, has_session, expected) in [
            (
                Some("other@example.com"),
                true,
                false,
                Some("prompt_mismatch"),
            ),
            (Some("USER@example.com"), true, false, Some("still_prompt")),
            (None, true, false, None),
            (None, true, true, Some("authenticated")),
            (None, false, false, Some("failed")),
        ] {
            assert_eq!(
                super::classify_post_submit_state(
                    prompt_email,
                    target_running,
                    has_session,
                    "user@example.com"
                ),
                expected
            );
        }
    }

    #[test]
    fn submitted_prompt_can_remain_visible_transiently_during_bounded_post_check() {
        assert!(!super::post_submit_prompt_state_is_terminal_during_poll(
            "still_prompt",
            true
        ));
        assert!(super::post_submit_prompt_state_is_terminal_during_poll(
            "still_prompt",
            false
        ));
        assert!(super::post_submit_prompt_state_is_terminal_during_poll(
            "prompt_mismatch",
            true
        ));
        assert!(super::post_submit_prompt_state_is_terminal_during_poll(
            "prompt_ambiguous",
            true
        ));
    }

    #[test]
    fn post_submit_ignores_session_window_from_other_process() {
        const EXPECTED_PID: i32 = 101;
        const OTHER_PID: i32 = 202;

        let inspection = super::MacosInspection {
            process_found: true,
            target: Some(super::MacosTarget {
                process_id: EXPECTED_PID,
                window_title: "Sign in".to_string(),
                frontmost: true,
            }),
            window_titles: vec![super::MacosWindowTitle {
                process_id: EXPECTED_PID,
                title: "Sign in".to_string(),
                window: None,
            }],
            session_windows: vec![super::MacosWindowTitle {
                process_id: OTHER_PID,
                title: "Contoso Desktop".to_string(),
                window: None,
            }],
            ..Default::default()
        };

        assert_eq!(
            super::classify_post_submit_inspection(
                &inspection,
                EXPECTED_PID,
                "Sign in",
                "user@example.com",
                None,
                false,
            ),
            None
        );
    }

    #[test]
    fn post_submit_same_pid_session_without_submitted_window_stays_unknown() {
        const EXPECTED_PID: i32 = 101;

        let inspection = super::MacosInspection {
            process_found: true,
            target: Some(super::MacosTarget {
                process_id: EXPECTED_PID,
                window_title: "Contoso Desktop".to_string(),
                frontmost: true,
            }),
            window_titles: vec![super::MacosWindowTitle {
                process_id: EXPECTED_PID,
                title: "Contoso Desktop".to_string(),
                window: None,
            }],
            session_windows: vec![super::MacosWindowTitle {
                process_id: EXPECTED_PID,
                title: "Contoso Desktop".to_string(),
                window: None,
            }],
            ..Default::default()
        };

        assert_eq!(
            super::classify_post_submit_inspection(
                &inspection,
                EXPECTED_PID,
                "Contoso Desktop",
                "user@example.com",
                None,
                false,
            ),
            None
        );
    }

    #[test]
    fn post_submit_ax_unavailable_with_native_process_running_stays_unknown() {
        const EXPECTED_PID: i32 = 101;
        let ax_unavailable = super::MacosInspection {
            process_found: true,
            ..Default::default()
        };
        let verified_exit = super::MacosInspection::default();

        assert_eq!(
            super::classify_post_submit_inspection(
                &ax_unavailable,
                EXPECTED_PID,
                "Sign in",
                "user@example.com",
                None,
                false,
            ),
            None
        );
        assert_eq!(
            super::classify_post_submit_inspection(
                &verified_exit,
                EXPECTED_PID,
                "Sign in",
                "user@example.com",
                None,
                false,
            ),
            Some("failed")
        );
    }

    #[test]
    fn post_submit_inspection_errors_are_not_reported_as_process_exit() {
        let implementation = include_str!("macos_ax.rs");
        let post_check = implementation
            .split("pub(crate) fn post_check_state")
            .nth(1)
            .and_then(|tail| tail.split("fn classify_post_submit_inspection").next())
            .unwrap();

        assert!(post_check.contains("if let Ok(inspection) = inspect_process"));
        assert!(!post_check.contains("Err(_) => return \"failed\""));
    }

    #[test]
    fn post_submit_session_success_accepts_the_reused_parent_after_the_sheet_disappears() {
        assert!(super::submitted_sheet_session_identity_matches(
            PromptOrigin::Sheet,
            101,
            101,
            "Contoso Desktop",
            "contoso desktop",
            true,
            true,
        ));
        assert!(!super::submitted_sheet_session_identity_matches(
            PromptOrigin::Window,
            101,
            101,
            "Contoso Desktop",
            "Contoso Desktop",
            true,
            true,
        ));
        assert!(!super::submitted_sheet_session_identity_matches(
            PromptOrigin::Sheet,
            101,
            202,
            "Contoso Desktop",
            "Contoso Desktop",
            true,
            true,
        ));
        assert!(!super::submitted_sheet_session_identity_matches(
            PromptOrigin::Sheet,
            101,
            101,
            "Contoso Desktop",
            "Other Desktop",
            true,
            true,
        ));
        assert!(!super::submitted_sheet_session_identity_matches(
            PromptOrigin::Sheet,
            101,
            101,
            "Contoso Desktop",
            "Contoso Desktop",
            false,
            true,
        ));
    }

    #[test]
    fn post_submit_requires_a_continuous_time_based_prompt_absence_dwell() {
        assert_eq!(super::submitted_sheet_presence(true, 1), Some(true));
        assert_eq!(super::submitted_sheet_presence(false, 0), Some(false));
        assert_eq!(super::submitted_sheet_presence(false, 1), None);

        let required = Duration::from_millis(super::POST_SUBMIT_REQUIRED_ABSENCE_DWELL_MS);
        let started = Instant::now();
        let mut absent_since = super::next_prompt_absence_since(None, Some(false), started);
        assert!(!super::prompt_absence_dwell_confirmed(
            absent_since,
            started + required.saturating_sub(Duration::from_millis(1)),
            required,
        ));

        // A companion/replacement sheet is indeterminate and resets the
        // continuous dwell instead of authenticating a transient gap.
        absent_since = super::next_prompt_absence_since(
            absent_since,
            None,
            started + Duration::from_millis(500),
        );
        assert!(absent_since.is_none());

        let restarted = started + Duration::from_millis(750);
        absent_since = super::next_prompt_absence_since(absent_since, Some(false), restarted);
        absent_since = super::next_prompt_absence_since(
            absent_since,
            Some(true),
            restarted + Duration::from_millis(500),
        );
        assert!(absent_since.is_none());

        let final_start = started + Duration::from_secs(2);
        absent_since = super::next_prompt_absence_since(absent_since, Some(false), final_start);
        assert!(super::prompt_absence_dwell_confirmed(
            absent_since,
            final_start + required,
            required,
        ));
    }

    #[test]
    fn post_submit_authentication_requires_the_submitted_parent_as_unique_foreground_target() {
        assert!(
            super::submitted_parent_target_identity_is_unique_foreground(
                101,
                "Contoso Desktop",
                true,
                101,
                "contoso desktop",
                true,
            )
        );
        assert!(
            !super::submitted_parent_target_identity_is_unique_foreground(
                101,
                "Contoso Desktop",
                false,
                101,
                "Contoso Desktop",
                true,
            )
        );
        assert!(
            !super::submitted_parent_target_identity_is_unique_foreground(
                101,
                "Contoso Desktop",
                true,
                101,
                "Contoso Desktop",
                false,
            )
        );
        assert!(!super::submitted_sheet_session_identity_matches(
            PromptOrigin::Sheet,
            101,
            101,
            "Contoso Desktop",
            "Contoso Desktop",
            true,
            false,
        ));
    }

    #[test]
    fn post_submit_different_title_prompt_in_same_pid_blocks_authenticated() {
        assert_eq!(
            super::classify_post_submit_prompt_identities(
                [(101, "Other Desktop", Some("user@example.com"))],
                101,
                "Contoso Desktop",
                "user@example.com",
                true,
            ),
            Some("prompt_mismatch")
        );
        assert_eq!(
            super::classify_post_submit_prompt_identities(
                [
                    (101, "Contoso Desktop", Some("user@example.com")),
                    (101, "Other Desktop", Some("user@example.com")),
                ],
                101,
                "Contoso Desktop",
                "user@example.com",
                true,
            ),
            Some("prompt_ambiguous")
        );
    }

    #[test]
    fn submitted_prompt_identity_is_checked_independently_of_content_scan() {
        let implementation = include_str!("macos_ax.rs");
        let checker = implementation
            .split("fn submitted_prompt_presence")
            .nth(1)
            .and_then(|tail| {
                tail.split("fn classify_post_submit_prompt_candidates")
                    .next()
            })
            .unwrap();

        assert!(checker.contains("prompt_container"));
        assert!(checker.contains("sheet_candidates_for_window(target_window)"));
        assert!(checker.contains("submitted_sheet_presence("));
        assert!(checker.contains("array_attr_checked(AX_WINDOWS)"));
        assert!(!checker.contains("array_attr_checked(AX_SHEETS)"));
    }

    #[test]
    fn missing_axhidden_is_not_treated_as_hidden_but_enabled_stays_fail_closed() {
        let implementation = include_str!("macos_ax.rs");
        let visibility = implementation
            .split("fn is_hidden(element: &AxElement)")
            .nth(1)
            .and_then(|tail| tail.split("fn element_enabled").next())
            .unwrap();
        let enabled = implementation
            .split("fn element_enabled(element: &AxElement)")
            .nth(1)
            .and_then(|tail| tail.split("fn element_foreground_state").next())
            .unwrap();

        assert!(visibility.contains("unwrap_or(false)"));
        assert!(enabled.contains("== Some(true)"));
        assert!(!visibility.contains("!= Some(false)"));
        assert!(!enabled.contains("unwrap_or(true)"));
    }

    #[test]
    fn optional_ax_relationship_absence_is_not_a_traversal_failure() {
        assert!(super::ax_relationship_attr_is_absent(
            super::K_AX_ERROR_ATTRIBUTE_UNSUPPORTED
        ));
        assert!(super::ax_relationship_attr_is_absent(
            super::K_AX_ERROR_NO_VALUE
        ));
        assert!(!super::ax_relationship_attr_is_absent(-25204));
        assert!(!super::ax_relationship_attr_is_absent(
            super::K_AX_ERROR_SUCCESS
        ));

        let implementation = include_str!("macos_ax.rs");
        let traversal = implementation
            .split("fn collect_elements")
            .nth(1)
            .and_then(|tail| tail.split("fn collect_descendants_bounded").next())
            .unwrap();
        let sheet_enumeration = implementation
            .split("fn sheet_candidates_for_window")
            .nth(1)
            .and_then(|tail| tail.split("fn unique_direct_sheet_prompt").next())
            .unwrap();

        assert!(traversal.contains("optional_relationship_array_attr_result(AX_CHILDREN)"));
        assert!(sheet_enumeration.contains("optional_relationship_array_attr_result(AX_SHEETS)"));
        assert!(sheet_enumeration.contains("optional_relationship_array_attr_result(AX_CHILDREN)"));
    }

    #[test]
    fn password_utf16_buffer_is_preallocated_before_plaintext_encoding() {
        let value = "ASCII-paßword-🔐";
        let encoded = super::zeroizing_utf16_buffer(value);
        assert!(encoded.iter().copied().eq(value.encode_utf16()));

        let implementation = include_str!("macos_ax.rs")
            .split("fn zeroizing_utf16_buffer")
            .nth(1)
            .and_then(|tail| tail.split("impl Clone for AxElement").next())
            .unwrap();
        assert!(implementation.contains("Vec::with_capacity(value.len())"));
        assert!(implementation.contains("utf16.extend(value.encode_utf16())"));
        assert!(implementation.contains("debug_assert_eq!(utf16.capacity(), initial_capacity)"));
        assert!(!implementation.contains("collect::<Vec<u16>>"));
    }

    #[test]
    fn target_window_title_binding_is_scoped_to_expected_pid() {
        let windows = vec![
            window_title(42, "Corp Desktop"),
            window_title(77, "Corp Desktop"),
            window_title(42, "Other Desktop"),
        ];

        assert!(super::window_title_binding_is_unique(
            &windows,
            42,
            "Corp Desktop"
        ));
        assert!(super::window_title_binding_is_unique(
            &windows,
            77,
            "Corp Desktop"
        ));
        assert!(!super::window_title_binding_is_unique(
            &windows,
            42,
            "Missing Desktop"
        ));
        assert!(!super::window_title_binding_is_unique(&windows, 42, " "));

        let unique_windows = vec![
            window_title(42, "Corp Desktop"),
            window_title(42, "Other Desktop"),
        ];
        assert!(super::window_title_binding_is_unique(
            &unique_windows,
            42,
            "Corp Desktop"
        ));
    }

    #[test]
    fn target_window_title_binding_rejects_duplicate_titles_within_same_pid() {
        let windows = vec![
            window_title(42, " Corp Desktop "),
            window_title(42, "corp desktop"),
            window_title(77, "Corp Desktop"),
        ];

        assert!(!super::window_title_binding_is_unique(
            &windows,
            42,
            "Corp Desktop"
        ));
        assert!(super::window_title_binding_is_unique(
            &windows,
            77,
            "Corp Desktop"
        ));
    }

    #[test]
    fn foreground_window_selection_requires_one_affirmative_candidate() {
        use super::AxForegroundState as State;

        let states = [
            State {
                focused: Some(false),
                main: Some(false),
            },
            State {
                focused: Some(true),
                main: Some(true),
            },
        ];
        assert_eq!(
            super::select_unique_foreground_index(true, &states),
            Some(1)
        );
        assert_eq!(super::select_unique_foreground_index(false, &states), None);

        let unique_main = [
            State {
                focused: Some(false),
                main: Some(false),
            },
            State {
                focused: Some(false),
                main: Some(true),
            },
        ];
        assert_eq!(
            super::select_unique_foreground_index(true, &unique_main),
            Some(1)
        );
    }

    #[test]
    fn foreground_window_selection_fails_closed_on_ambiguous_or_unknown_state() {
        use super::AxForegroundState as State;

        let two_focused = [
            State {
                focused: Some(true),
                main: Some(false),
            },
            State {
                focused: Some(true),
                main: Some(true),
            },
        ];
        let two_main = [
            State {
                focused: Some(false),
                main: Some(true),
            },
            State {
                focused: Some(false),
                main: Some(true),
            },
        ];
        let conflicting_focus_and_main = [
            State {
                focused: Some(false),
                main: Some(true),
            },
            State {
                focused: Some(true),
                main: Some(false),
            },
        ];
        let unknown_focus = [
            State {
                focused: None,
                main: Some(false),
            },
            State {
                focused: Some(false),
                main: Some(true),
            },
        ];
        let unknown_main = [State {
            focused: Some(false),
            main: None,
        }];

        assert_eq!(
            super::select_unique_foreground_index(true, &two_focused),
            None
        );
        assert_eq!(super::select_unique_foreground_index(true, &two_main), None);
        assert_eq!(
            super::select_unique_foreground_index(true, &conflicting_focus_and_main),
            None
        );
        assert_eq!(
            super::select_unique_foreground_index(true, &unknown_focus),
            None
        );
        assert_eq!(
            super::select_unique_foreground_index(true, &unknown_main),
            None
        );
    }

    #[test]
    fn foreground_window_selection_rejects_a_single_known_background_window() {
        use super::AxForegroundState as State;

        let one = [State {
            focused: Some(false),
            main: Some(false),
        }];
        let two = [one[0], one[0]];
        assert_eq!(super::select_unique_foreground_index(true, &one), None);
        assert_eq!(super::select_unique_foreground_index(true, &two), None);
        assert_eq!(super::select_unique_foreground_index(true, &[]), None);
    }

    #[test]
    fn credential_sheet_identity_selection_is_unique_not_focus_based() {
        assert_eq!(
            super::unique_true_index([false, true]),
            super::UniqueTrueIndex::One(1)
        );
        assert_eq!(
            super::unique_true_index([true, false]),
            super::UniqueTrueIndex::One(0)
        );
        assert_eq!(
            super::unique_true_index([true, true]),
            super::UniqueTrueIndex::Multiple
        );
        assert_eq!(
            super::unique_true_index([false, false]),
            super::UniqueTrueIndex::None
        );
    }

    #[test]
    fn inspection_selects_one_bounded_credential_sheet_by_complete_identity() {
        let implementation = include_str!("macos_ax.rs")
            .split("fn inspect_process")
            .nth(1)
            .and_then(|tail| tail.split("fn trusted_process_infos_for_inspection").next())
            .unwrap();
        let helper = include_str!("macos_ax.rs")
            .split("fn unique_direct_sheet_prompt")
            .nth(1)
            .and_then(|tail| tail.split("fn window_should_scan_for_prompt").next())
            .unwrap();
        let revalidation = include_str!("macos_ax.rs")
            .split("fn sheet_prompt_is_uniquely_visible_now")
            .nth(1)
            .and_then(|tail| tail.split("fn current_trusted_process_info").next())
            .unwrap();

        let bound = helper.find("MAX_DIRECT_SHEET_COUNT").unwrap();
        let traversal = helper.find("collect_elements(sheet)").unwrap();
        assert!(bound < traversal);
        assert!(helper.contains("into_complete_elements()"));
        assert!(helper.contains("prompt_from_elements("));
        assert!(helper.contains("UniqueTrueIndex::Multiple"));
        assert!(implementation.contains("unique_direct_sheet_prompt("));
        assert!(!implementation.contains("select_unique_sheet_index"));
        assert!(implementation.contains("if has_visible_sheet"));
        assert!(revalidation.contains("unique_direct_sheet_prompt("));
        assert!(revalidation.contains("same_prompt_candidate(prompt, &candidate)"));
    }

    #[test]
    fn suppressed_sheet_exit_requires_one_exact_parent_and_no_direct_sheet() {
        assert_eq!(
            super::classify_suppressed_sheet_episode_presence(1, 0),
            Some(false)
        );
        assert_eq!(
            super::classify_suppressed_sheet_episode_presence(1, 1),
            Some(true)
        );
        assert_eq!(
            super::classify_suppressed_sheet_episode_presence(1, super::MAX_DIRECT_SHEET_COUNT,),
            Some(true)
        );
        assert_eq!(
            super::classify_suppressed_sheet_episode_presence(0, 0),
            Some(false)
        );
        assert_eq!(
            super::classify_suppressed_sheet_episode_presence(2, 0),
            None
        );
        assert_eq!(
            super::classify_suppressed_sheet_episode_presence(1, super::MAX_DIRECT_SHEET_COUNT + 1,),
            None
        );

        let helper = include_str!("macos_ax.rs")
            .split("pub(crate) fn suppressed_sheet_episode_has_visible_direct_sheet")
            .nth(1)
            .and_then(|tail| {
                tail.split("fn classify_suppressed_sheet_episode_presence")
                    .next()
            })
            .unwrap();
        assert!(helper.contains("array_attr_result(AX_WINDOWS)"));
        assert!(helper.contains("sheet_candidates_for_window(parent)"));
        assert!(helper.contains("element_is_direct_child_of(sheet, parent)"));
        assert!(!helper.contains("collect_elements("));
    }

    #[test]
    fn generic_session_window_is_not_scanned_as_a_credential_dialog() {
        let body = "Enter Your Credentials These credentials will be used to connect to \
                    rdgateway.example.com Username: user@example.com Password:";

        assert!(!super::native_credential_window_identity(
            Some("AXWindow"),
            Some("AXStandardWindow"),
            "Contoso Desktop"
        ));
        assert!(!super::native_credential_window_identity(
            Some("AXWindow"),
            Some("AXStandardWindow"),
            "Sign in"
        ));
        assert!(!prompt_identity_verified(
            "Contoso Desktop",
            body,
            PromptOrigin::Window
        ));
        assert!(prompt_identity_verified(
            "Contoso Desktop",
            body,
            PromptOrigin::Sheet
        ));
        assert!(super::native_credential_window_identity(
            Some("AXWindow"),
            Some("AXDialog"),
            "Sign in"
        ));
        assert!(super::native_credential_window_identity(
            Some("AXWindow"),
            Some("AXSystemDialog"),
            "Authentication"
        ));

        let implementation = include_str!("macos_ax.rs");
        let inspection = implementation
            .split("fn inspect_process(")
            .nth(1)
            .and_then(|tail| tail.split("fn trusted_process_infos_for_inspection").next())
            .unwrap();
        assert!(inspection.contains("let visible_sheets = if window_frontmost"));
        assert!(inspection.contains("|| !window_frontmost"));
    }

    #[test]
    fn prompt_identity_requires_credential_body_for_login_windows_and_sheets() {
        for (title, body, origin, expected) in [
            ("Password", "user@example.com", PromptOrigin::Window, false),
            (
                "Sign in",
                "Enter password for user@example.com",
                PromptOrigin::Window,
                true,
            ),
            (
                "Connection Center",
                "Sign in with user@example.com",
                PromptOrigin::Sheet,
                false,
            ),
            (
                "Contoso Desktop",
                "Sign in with user@example.com",
                PromptOrigin::Sheet,
                false,
            ),
            (
                "Contoso Desktop",
                "Enter password for user@example.com",
                PromptOrigin::Sheet,
                true,
            ),
            (
                "Contoso Desktop",
                "Enter password for Contoso Desktop user@example.com",
                PromptOrigin::Sheet,
                true,
            ),
            (
                "Contoso Desktop",
                "Enter Your User Account used to connect to user@example.com",
                PromptOrigin::Sheet,
                true,
            ),
            (
                "Contoso Desktop",
                "Enter Your User Account used to connect to Other Desktop user@example.com",
                PromptOrigin::Sheet,
                true,
            ),
            (
                "Azure DevDesktop - Windows 11",
                "Enter Your Credentials These credentials will be used to connect to rdgateway.example.com Username: user@example.com Password:",
                PromptOrigin::Sheet,
                true,
            ),
            (
                "Azure DevDesktop - Windows 11",
                "Enter Your Credentials These credentials will be used to connect to rdgateway.example.com Username: user@example.com Password:",
                PromptOrigin::Window,
                false,
            ),
            (
                "Connection Center",
                "Sign in with user@example.com",
                PromptOrigin::Window,
                false,
            ),
        ] {
            assert_eq!(prompt_identity_verified(title, body, origin), expected);
        }

        for title in [
            "Windows App",
            "Connection Center",
            "Workspaces",
            "Accounts",
            "Add PC",
            "Settings",
        ] {
            assert!(prompt_identity_verified(
                title,
                "Enter password for user@example.com",
                PromptOrigin::Sheet
            ));
        }
    }

    #[test]
    fn prompt_title_revalidation_requires_exact_expected_title() {
        assert!(prompt_window_title_matches("Sign in", None));
        assert!(prompt_window_title_matches("Sign in", Some("sign in")));
        assert!(!prompt_window_title_matches(
            "Connection Center",
            Some("Sign in")
        ));
    }

    fn window_title(process_id: i32, title: &str) -> super::MacosWindowTitle {
        super::MacosWindowTitle {
            process_id,
            title: title.to_string(),
            window: None,
        }
    }
}
