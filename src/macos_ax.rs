use crate::macos_identity;
use anyhow::Context;
use core_foundation::array::{CFArray, CFArrayRef};
use core_foundation::base::{
    CFEqual, CFIndexConvertible, CFRelease, CFRetain, CFType, CFTypeRef, TCFType,
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
const AX_MESSAGING_TIMEOUT_SECONDS: f32 = 0.15;
const FOCUS_POLL_INTERVAL_MS: u64 = 10;
#[cfg_attr(not(test), allow(dead_code))]
const DIRECT_AXVALUE_READY_MS: u64 = 40;
const FAST_SUBMIT_READY_TIMEOUT_MS: u64 = 60;
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

#[derive(Debug, Clone, Default)]
pub(crate) struct MacosInspection {
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
    DirectAxValue,
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

#[derive(Clone)]
struct PromptTextSnapshot {
    element: AxElement,
    title: Option<String>,
    placeholder: Option<String>,
    value: Option<String>,
}

struct PreparedPromptForFill {
    password_field: AxElement,
    trusted_process: macos_identity::TrustedProcessInfo,
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

    fn copy_attr(&self, attr: &'static str) -> Option<CFType> {
        let attr = CFString::from_static_string(attr);
        let mut value: CFTypeRef = std::ptr::null();
        let err = unsafe {
            AXUIElementCopyAttributeValue(self.raw, attr.as_concrete_TypeRef(), &mut value)
        };
        if err == K_AX_ERROR_SUCCESS && !value.is_null() {
            Some(unsafe { TCFType::wrap_under_create_rule(value) })
        } else {
            None
        }
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

    fn array_attr(&self, attr: &'static str) -> Vec<AxElement> {
        let Some(array) = self
            .copy_attr(attr)
            .and_then(|value| value.downcast_into::<CFArray>())
        else {
            return Vec::new();
        };

        array
            .get_all_values()
            .into_iter()
            .filter_map(|raw| unsafe { AxElement::borrowed(raw.cast()) })
            .collect()
    }

    fn set_string_attr(&self, attr: &'static str, value: &str) -> bool {
        let attr = CFString::from_static_string(attr);
        let mut utf16 = Zeroizing::new(value.encode_utf16().collect::<Vec<u16>>());
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

fn inspect_process(
    app_name: &str,
    expected_process_id: Option<i32>,
    expected_window_title: Option<&str>,
) -> anyhow::Result<MacosInspection> {
    let process_infos = trusted_process_infos_for_inspection(app_name, expected_process_id)?;
    if process_infos.is_empty() {
        return Ok(MacosInspection::default());
    }

    let mut inspection = MacosInspection::default();
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
        let app_frontmost = app.bool_attr(AX_FRONTMOST).unwrap_or(false);
        let windows = app.array_attr(AX_WINDOWS);
        let visible_windows = windows
            .iter()
            .filter(|window| !is_hidden(window))
            .collect::<Vec<_>>();
        let any_explicit_frontmost_window = visible_windows
            .iter()
            .any(|window| element_explicitly_frontmost(window));

        if inspection.target.is_none() {
            inspection.target = Some(MacosTarget {
                process_id: process.pid,
                window_title: String::new(),
                frontmost: app_frontmost,
            });
        }

        let visible_window_count = visible_windows.len();
        for window in visible_windows {
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

            let window_frontmost = window_is_frontmost_for_app(
                app_frontmost,
                visible_window_count,
                any_explicit_frontmost_window,
                element_explicitly_frontmost(window),
            );
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
                sheet_candidates_for_window(window)
                    .into_iter()
                    .filter(|sheet| !is_hidden(sheet))
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            };
            let visible_sheet_count = visible_sheets.len();
            let any_explicit_frontmost_sheet =
                visible_sheets.iter().any(element_explicitly_frontmost);
            let mut found_sheet_prompt = false;
            for sheet in visible_sheets {
                let sheet_elements = collect_elements(&sheet);
                let sheet_target = MacosTarget {
                    frontmost: sheet_is_frontmost_for_app(
                        app_frontmost,
                        target.frontmost,
                        visible_sheet_count,
                        any_explicit_frontmost_sheet,
                        element_explicitly_frontmost(&sheet),
                    ),
                    ..target.clone()
                };
                if let Some(prompt) = prompt_from_elements(
                    sheet_target,
                    window,
                    &sheet,
                    &sheet_elements,
                    PromptOrigin::Sheet,
                    &process,
                ) {
                    record_prompt_candidate(&mut inspection, prompt);
                    found_sheet_prompt = true;
                }
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
            if found_sheet_prompt
                || !window_frontmost
                || !window_should_scan_for_prompt(window, &window_title)
            {
                continue;
            }

            let window_elements = collect_elements(window);
            if let Some(prompt) = prompt_from_elements(
                target.clone(),
                window,
                window,
                &window_elements,
                PromptOrigin::Window,
                &process,
            ) {
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
) -> anyhow::Result<MacosFillResult> {
    guard()?;
    ensure_verified_prompt_matches_fill_target(
        &verified_prompt,
        expected_process_id,
        expected_window_title,
        expected_prompt_origin,
        expected_email,
    )?;
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
    )?;

    let submit_button_ready_after_fill = false;
    let password_field_focused = false;
    let method_used = match method {
        MacosFillMethod::DirectAxValue => {
            ensure_live_prompt_window_title(&verified_prompt.prompt, expected_window_title)?;
            ensure_revalidated_frontmost(
                prompt_is_frontmost_now(&verified_prompt.prompt),
                "password insertion",
            )?;
            guard()?;
            if set_password_value(&prepared.password_field, password) {
                "axvalue"
            } else {
                anyhow::bail!(
                    "direct AXValue password insertion failed; keyboard fallback disabled for password security"
                );
            }
        }
    };
    let prompt = verified_prompt.prompt;

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
    // AX reads above may block until their messaging timeout. Recheck the
    // cancellation generation immediately before the one submit side effect.
    guard()?;
    if button.perform_action(AX_PRESS) {
        return Ok(MacosSubmitResult {
            submit_method: "axpress_fast",
            submit_status: "ok",
            axpress_attempted: true,
            axpress_result: "success",
            enter_fallback_attempted: false,
            enter_fallback_result: "not_needed",
            submitted_prompt: Some(MacosSubmittedPrompt {
                process_id: prompt.target.process_id,
                window_title: prompt.target.window_title.clone(),
                email: filled_prompt.expected_email.clone(),
                origin: prompt.origin,
                target_window: prompt.target_window.clone(),
                prompt_container: prompt.native_container.clone(),
            }),
        });
    }

    Ok(MacosSubmitResult {
        submit_method: "axpress_fast",
        submit_status: "failed",
        axpress_attempted: true,
        axpress_result: "failed",
        enter_fallback_attempted: false,
        enter_fallback_result: "disabled",
        submitted_prompt: None,
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
    let mut consecutive_submitted_prompt_absences = 0_u8;
    loop {
        match inspect_process(app_name, Some(expected_process_id), None) {
            Ok(inspection) => {
                if let Some(submitted_prompt) = submitted_prompt {
                    consecutive_submitted_prompt_absences = next_prompt_absence_observations(
                        consecutive_submitted_prompt_absences,
                        submitted_prompt_is_still_present(submitted_prompt),
                    );
                }
                let state = classify_post_submit_inspection(
                    &inspection,
                    expected_process_id,
                    expected_window_title,
                    expected_email,
                    submitted_prompt,
                    consecutive_submitted_prompt_absences >= 2,
                );

                if inspection.prompt.is_some() {
                    return state.unwrap_or("prompt_gone_unknown");
                }

                if let Some(state) = state {
                    return state;
                }
            }
            Err(_) => return "failed",
        }

        if started.elapsed() >= timeout {
            return "prompt_gone_unknown";
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn classify_post_submit_inspection(
    inspection: &MacosInspection,
    expected_process_id: i32,
    expected_window_title: &str,
    expected_email: &str,
    submitted_prompt: Option<&MacosSubmittedPrompt>,
    submitted_prompt_disappearance_confirmed: bool,
) -> Option<&'static str> {
    let target_running = inspection.target.as_ref().is_some_and(|target| {
        target.process_id == expected_process_id
            || inspection
                .window_titles
                .iter()
                .any(|title| title.process_id == expected_process_id)
    });
    let has_session_for_expected_process = submitted_prompt.is_some_and(|submitted_prompt| {
        submitted_prompt_disappearance_confirmed
            && submitted_prompt_matches_expected(
                submitted_prompt,
                expected_process_id,
                expected_email,
            )
            && inspection.session_windows.iter().any(|session| {
                session.process_id == expected_process_id
                    && submitted_prompt_matches_session_window(submitted_prompt, session)
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

fn next_prompt_absence_observations(previous: u8, prompt_is_present: bool) -> u8 {
    if prompt_is_present {
        0
    } else {
        previous.saturating_add(1)
    }
}

fn submitted_prompt_is_still_present(submitted_prompt: &MacosSubmittedPrompt) -> bool {
    if submitted_prompt.target_window.process_id() != Some(submitted_prompt.process_id)
        || submitted_prompt.prompt_container.process_id() != Some(submitted_prompt.process_id)
    {
        return false;
    }

    match submitted_prompt.origin {
        PromptOrigin::Sheet => submitted_prompt
            .target_window
            .array_attr(AX_SHEETS)
            .iter()
            .any(|sheet| {
                sheet.same_element(&submitted_prompt.prompt_container) && !is_hidden(sheet)
            }),
        PromptOrigin::Window => AxElement::application(submitted_prompt.process_id)
            .map(|app| {
                app.array_attr(AX_WINDOWS).iter().any(|window| {
                    window.same_element(&submitted_prompt.prompt_container) && !is_hidden(window)
                })
            })
            .unwrap_or(false),
    }
}

fn classify_post_submit_prompt_candidates(
    prompts: &[MacosPrompt],
    window_titles: &[MacosWindowTitle],
    expected_process_id: i32,
    expected_window_title: &str,
    expected_email: &str,
) -> Option<&'static str> {
    let matching_window = matching_prompt_candidates(
        prompts,
        Some(expected_process_id),
        Some(expected_window_title),
        None,
    );
    if matching_window.is_empty() {
        return None;
    }
    if !window_title_binding_is_unique(window_titles, expected_process_id, expected_window_title) {
        return Some("prompt_ambiguous");
    }

    let matching_account = matching_window
        .iter()
        .filter(|prompt| {
            prompt
                .email
                .as_deref()
                .is_some_and(|email| usernames_match(email, expected_email))
        })
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
) -> bool {
    submitted_prompt.origin == PromptOrigin::Sheet
        && session.process_id == submitted_prompt.process_id
        && session
            .title
            .trim()
            .eq_ignore_ascii_case(submitted_prompt.window_title.trim())
        && session
            .window
            .as_ref()
            .is_some_and(|window| window.same_element(&submitted_prompt.target_window))
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
    Ok(PreparedPromptForFill {
        password_field: prompt.password_field.clone(),
        trusted_process,
    })
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
    let attrs = snapshot
        .element
        .string_attrs(&[AX_TITLE, AX_PLACEHOLDER, AX_VALUE]);
    attrs.first().cloned().unwrap_or_default() != snapshot.title
        || attrs.get(1).cloned().unwrap_or_default() != snapshot.placeholder
        || attrs.get(2).cloned().unwrap_or_default() != snapshot.value
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

    let app_frontmost = app.bool_attr(AX_FRONTMOST).unwrap_or(false);
    let visible_windows = app
        .array_attr(AX_WINDOWS)
        .into_iter()
        .filter(|window| !is_hidden(window))
        .collect::<Vec<_>>();
    let any_explicit_frontmost_window = visible_windows.iter().any(element_explicitly_frontmost);
    let Some(target_window) = visible_windows
        .iter()
        .find(|window| window.same_element(&prompt.target_window))
    else {
        return false;
    };
    let target_window_frontmost = window_is_frontmost_for_app(
        app_frontmost,
        visible_windows.len(),
        any_explicit_frontmost_window,
        element_explicitly_frontmost(target_window),
    );
    if !app_frontmost || !element_has_ancestor(&prompt.prompt_root, &prompt.native_container) {
        return false;
    }

    match prompt.origin {
        PromptOrigin::Window => {
            target_window_frontmost
                && prompt.native_container.same_element(target_window)
                && window_should_scan_for_prompt(target_window, &prompt.target.window_title)
        }
        PromptOrigin::Sheet => {
            let visible_sheets = sheet_candidates_for_window(target_window)
                .into_iter()
                .filter(|sheet| !is_hidden(sheet))
                .collect::<Vec<_>>();
            let any_explicit_frontmost_sheet =
                visible_sheets.iter().any(element_explicitly_frontmost);
            let Some(sheet) = visible_sheets
                .iter()
                .find(|sheet| sheet.same_element(&prompt.native_container))
            else {
                return false;
            };
            sheet_is_frontmost_for_app(
                app_frontmost,
                target_window_frontmost,
                visible_sheets.len(),
                any_explicit_frontmost_sheet,
                element_explicitly_frontmost(sheet),
            )
        }
    }
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

fn collect_elements(root: &AxElement) -> Vec<AxElement> {
    let mut elements = Vec::new();
    if is_hidden(root) {
        return elements;
    }
    collect_elements_recursive(root, 0, &mut elements);
    elements
}

fn collect_elements_recursive(root: &AxElement, depth: usize, elements: &mut Vec<AxElement>) {
    if depth >= AX_SEARCH_DEPTH || elements.len() >= MAX_ELEMENT_COUNT {
        return;
    }

    for child in root.array_attr(AX_CHILDREN) {
        if elements.len() >= MAX_ELEMENT_COUNT {
            break;
        }
        if is_hidden(&child) {
            continue;
        }
        elements.push(child.clone());
        collect_elements_recursive(&child, depth + 1, elements);
    }
}

fn sheet_candidates_for_window(window: &AxElement) -> Vec<AxElement> {
    let mut sheets = window.array_attr(AX_SHEETS);
    for element in window
        .array_attr(AX_CHILDREN)
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
    sheets
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
) -> Option<MacosPrompt> {
    let prompt_body_text = collect_prompt_text("", elements);
    let prompt_email = extract_email_like(&prompt_body_text)?;
    if !prompt_identity_verified(&target.window_title, &prompt_body_text, origin) {
        return None;
    }
    for password_field in password_field_candidates(elements) {
        let Some((prompt_root, scoped_elements)) = select_credential_prompt_scope(
            root,
            &password_field,
            &prompt_email,
            &target.window_title,
            origin,
        ) else {
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
        submit_button.as_ref()?;
        let identity_text = prompt_text_snapshots(
            &scoped_elements,
            &prompt_email,
            &target.window_title,
            origin,
        );

        return Some(MacosPrompt {
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
        });
    }

    None
}

fn select_credential_prompt_scope(
    root: &AxElement,
    password_field: &AxElement,
    prompt_email: &str,
    window_title: &str,
    origin: PromptOrigin,
) -> Option<(AxElement, Vec<AxElement>)> {
    let mut ancestor = password_field.parent();
    for _ in 0..AX_SEARCH_DEPTH {
        let current = ancestor?;
        let scoped_elements = collect_elements(&current);
        let scoped_body_text = collect_prompt_text("", &scoped_elements);
        if scoped_prompt_matches(&scoped_body_text, prompt_email, window_title, origin)
            && select_prompt_submit_button(&scoped_elements).is_some()
        {
            return Some((current, scoped_elements));
        }

        let reached_root = current.same_element(root);
        if reached_root {
            break;
        }
        ancestor = current.parent();
    }
    None
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
            !hidden && is_native_password_field(element),
            !hidden && is_password_like_text_field(element),
        ) {
            continue;
        }

        push_text(&mut text, element.string_attr(AX_TITLE));
        push_text(&mut text, element.string_attr(AX_PLACEHOLDER));

        if is_text_or_static_text(element) {
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
                !hidden && is_native_password_field(element),
                !hidden && is_password_like_text_field(element),
            )
        })
        .map(|element| {
            let attrs = element.string_attrs(&[AX_TITLE, AX_PLACEHOLDER, AX_VALUE]);
            PromptTextSnapshot {
                element: element.clone(),
                title: attrs.first().cloned().unwrap_or_default(),
                placeholder: attrs.get(1).cloned().unwrap_or_default(),
                value: if is_text_or_static_text(element) {
                    attrs.get(2).cloned().unwrap_or_default()
                } else {
                    None
                },
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

fn is_password_like_text_field(element: &AxElement) -> bool {
    !is_hidden(element)
        && element_enabled(element)
        && role_matches(element, AX_TEXT_FIELD_ROLE)
        && text_contains_password_cue(&element_label_text(element))
}

fn role_matches(element: &AxElement, expected: &str) -> bool {
    element
        .string_attr(AX_ROLE)
        .is_some_and(|role| role.eq_ignore_ascii_case(expected))
}

fn is_hidden(element: &AxElement) -> bool {
    element.bool_attr(AX_HIDDEN).unwrap_or(false)
}

fn element_enabled(element: &AxElement) -> bool {
    element.bool_attr(AX_ENABLED).unwrap_or(true)
}

fn element_explicitly_frontmost(element: &AxElement) -> bool {
    element.bool_attr(AX_MAIN).unwrap_or(false) || element.bool_attr(AX_FOCUSED).unwrap_or(false)
}

fn window_is_frontmost_for_app(
    app_frontmost: bool,
    visible_window_count: usize,
    any_explicit_frontmost_window: bool,
    window_explicitly_frontmost: bool,
) -> bool {
    app_frontmost
        && (window_explicitly_frontmost
            || (!any_explicit_frontmost_window && visible_window_count == 1))
}

fn sheet_is_frontmost_for_app(
    app_frontmost: bool,
    parent_window_frontmost: bool,
    visible_sheet_count: usize,
    any_explicit_frontmost_sheet: bool,
    sheet_explicitly_frontmost: bool,
) -> bool {
    app_frontmost
        && (sheet_explicitly_frontmost
            || (parent_window_frontmost
                && !any_explicit_frontmost_sheet
                && visible_sheet_count == 1))
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
const K_AX_ERROR_SUCCESS: AXError = 0;

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
}

#[cfg(test)]
mod tests {
    use super::{
        credential_prompt_text_like, extract_email_like, normalized_submit_label,
        prompt_identity_verified, prompt_text_element_should_contribute,
        prompt_window_title_matches, select_submit_label_for_test, submit_label_rank,
        text_contains_password_cue, PromptOrigin, DIRECT_AXVALUE_READY_MS, FOCUS_POLL_INTERVAL_MS,
    };
    use std::time::Duration;

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
    fn password_insertion_implementation_has_no_global_keyboard_secret_fallback() {
        let implementation = include_str!("macos_ax.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        let fill_verified_password = implementation
            .split("pub(crate) fn fill_verified_password")
            .nth(1)
            .and_then(|tail| tail.split("pub(crate) fn submit_filled_prompt").next())
            .unwrap();

        assert!(fill_verified_password
            .contains("set_password_value(&prepared.password_field, password)"));
        assert!(fill_verified_password.contains("keyboard fallback disabled for password security"));
        for forbidden in [
            "send_text",
            "send_key",
            "CGEventPost",
            "CGEventKeyboardSetUnicodeString",
            "KEYCODE_A",
            "KEYCODE_DELETE",
        ] {
            assert!(
                !fill_verified_password.contains(forbidden),
                "password insertion must not use global keyboard fallback: {forbidden}"
            );
        }
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
    fn final_password_fill_revalidates_before_direct_write() {
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
        let final_frontmost_revalidation = fill_verified_password
            .find("ensure_revalidated_frontmost(")
            .unwrap();
        let write = fill_verified_password
            .find("set_password_value(&prepared.password_field, password)")
            .unwrap();

        assert!(revalidation < write);
        assert!(revalidation < final_frontmost_revalidation);
        assert!(final_frontmost_revalidation < write);
        let adjacent_guard = fill_verified_password[..write]
            .rfind("guard()?")
            .expect("generation guard immediately before password write");
        assert!(final_frontmost_revalidation < adjacent_guard);
        assert!(adjacent_guard < write);

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

        assert!(setter.contains("Zeroizing::new"));
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
        let fast_submit = implementation
            .split("fn revalidate_filled_prompt")
            .nth(1)
            .and_then(|tail| tail.split("pub(crate) fn post_check_state").next())
            .unwrap();

        assert!(fill.contains("ensure_live_prompt_window_title"));
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
        assert_eq!(fast_submit.matches("perform_action(AX_PRESS)").count(), 1);
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
            .and_then(|tail| tail.split("fn is_password_like_text_field").next())
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
    fn automation_timing_constants_stay_bounded() {
        let direct_ready_ms = std::hint::black_box(DIRECT_AXVALUE_READY_MS);
        let focus_poll_interval_ms = std::hint::black_box(FOCUS_POLL_INTERVAL_MS);

        assert!(direct_ready_ms >= focus_poll_interval_ms);
        assert!(Duration::from_millis(direct_ready_ms) < Duration::from_millis(450));
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
    fn post_submit_ignores_session_window_from_other_process() {
        const EXPECTED_PID: i32 = 101;
        const OTHER_PID: i32 = 202;

        let inspection = super::MacosInspection {
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
    fn post_submit_session_success_is_bound_to_the_submitted_sheet_parent() {
        let implementation = include_str!("macos_ax.rs");
        let matcher = implementation
            .split("fn submitted_prompt_matches_session_window")
            .nth(1)
            .and_then(|tail| tail.split("fn classify_post_submit_state").next())
            .unwrap();

        assert!(matcher.contains("submitted_prompt.origin == PromptOrigin::Sheet"));
        assert!(matcher.contains("session.process_id == submitted_prompt.process_id"));
        assert!(matcher.contains("window.same_element(&submitted_prompt.target_window)"));
    }

    #[test]
    fn post_submit_requires_two_consecutive_submitted_prompt_absences() {
        let mut observations = 0;
        observations = super::next_prompt_absence_observations(observations, false);
        assert_eq!(observations, 1);
        assert!(observations < 2);

        observations = super::next_prompt_absence_observations(observations, true);
        assert_eq!(observations, 0);

        observations = super::next_prompt_absence_observations(observations, false);
        observations = super::next_prompt_absence_observations(observations, false);
        assert_eq!(observations, 2);
    }

    #[test]
    fn submitted_prompt_identity_is_checked_independently_of_content_scan() {
        let implementation = include_str!("macos_ax.rs");
        let checker = implementation
            .split("fn submitted_prompt_is_still_present")
            .nth(1)
            .and_then(|tail| {
                tail.split("fn classify_post_submit_prompt_candidates")
                    .next()
            })
            .unwrap();

        assert!(checker.contains("prompt_container"));
        assert!(checker.contains("array_attr(AX_SHEETS)"));
        assert!(checker.contains("array_attr(AX_WINDOWS)"));
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
    fn window_frontmost_prefers_explicit_main_or_focused_over_first_window_fallback() {
        assert!(!super::window_is_frontmost_for_app(true, 0, true, false));
        assert!(super::window_is_frontmost_for_app(true, 1, true, true));
        assert!(!super::window_is_frontmost_for_app(false, 1, true, true));
    }

    #[test]
    fn window_frontmost_falls_back_only_for_one_unambiguous_visible_window() {
        assert!(super::window_is_frontmost_for_app(true, 1, false, false));
        assert!(!super::window_is_frontmost_for_app(true, 2, false, false));
    }

    #[test]
    fn sheet_frontmost_requires_an_exact_focused_sheet_or_unambiguous_foreground_parent() {
        assert!(super::sheet_is_frontmost_for_app(
            true, true, 1, false, false
        ));
        assert!(super::sheet_is_frontmost_for_app(true, true, 2, true, true));
        assert!(!super::sheet_is_frontmost_for_app(
            false, true, 1, false, false
        ));
        assert!(super::sheet_is_frontmost_for_app(
            true, false, 1, true, true
        ));
        assert!(!super::sheet_is_frontmost_for_app(
            true, true, 2, false, false
        ));
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
