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
use zeroize::Zeroizing;

const MAX_ELEMENT_COUNT: usize = 900;
const AX_SEARCH_DEPTH: usize = 12;
const AX_MESSAGING_TIMEOUT_SECONDS: f32 = 0.15;
const FOCUS_SETTLE_MS: u64 = 50;
const FOCUS_POLL_INTERVAL_MS: u64 = 10;
const KEY_EVENT_SETTLE_MS: u64 = 20;
#[cfg_attr(not(test), allow(dead_code))]
const DIRECT_AXVALUE_READY_MS: u64 = 40;
const PRESS_FOCUS_SETTLE_MS: u64 = 60;
#[cfg_attr(not(test), allow(dead_code))]
const POST_FILL_SETTLE_MS: u64 = 20;
const FAST_SUBMIT_READY_TIMEOUT_MS: u64 = 60;
const SUBMIT_SETTLE_MS: u64 = 0;

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
const AX_RAISE: &str = "AXRaise";

const AX_BUTTON_ROLE: &str = "AXButton";
const AX_TEXT_FIELD_ROLE: &str = "AXTextField";
const AX_SECURE_TEXT_FIELD_ROLE: &str = "AXSecureTextField";
const AX_STATIC_TEXT_ROLE: &str = "AXStaticText";
const AX_SHEET_ROLE: &str = "AXSheet";

const KEYCODE_A: u16 = 0;
const KEYCODE_DELETE: u16 = 51;
const CG_HID_EVENT_TAP: u32 = 0;
const CG_EVENT_FLAG_MASK_COMMAND: u64 = 1 << 20;

#[derive(Debug, Clone, Default)]
pub(crate) struct MacosInspection {
    pub(crate) target: Option<MacosTarget>,
    pub(crate) prompt: Option<MacosPrompt>,
    pub(crate) prompts: Vec<MacosPrompt>,
    pub(crate) has_session: bool,
    pub(crate) session_windows: Vec<MacosWindowTitle>,
    pub(crate) window_titles: Vec<MacosWindowTitle>,
    pub(crate) forms: Vec<MacosFormInspection>,
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

#[derive(Debug, Clone)]
pub(crate) struct MacosFormInspection {
    pub(crate) process_id: i32,
    pub(crate) title: String,
    pub(crate) prompt_email: Option<String>,
    pub(crate) prompt_origin: &'static str,
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

impl MacosFillMethod {
    fn label(self) -> &'static str {
        match self {
            MacosFillMethod::Keyboard => "keyboard",
        }
    }
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
    pre_submit_session_windows: Vec<MacosWindowTitle>,
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
        let value = CFString::new(value);
        unsafe {
            AXUIElementSetAttributeValue(self.raw, attr.as_concrete_TypeRef(), value.as_CFTypeRef())
                == K_AX_ERROR_SUCCESS
        }
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

            let window_frontmost = window_is_frontmost_for_app(
                app_frontmost,
                window_index,
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

            let mut found_sheet_prompt = false;
            for sheet in sheet_candidates_for_window(window) {
                if is_hidden(&sheet) {
                    continue;
                }
                let sheet_elements = collect_elements(&sheet);
                let sheet_target = MacosTarget {
                    frontmost: sheet_is_frontmost_for_app(
                        app_frontmost,
                        target.frontmost,
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
            if found_sheet_prompt || !window_should_scan_for_prompt(&target, &window_title) {
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
    );
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

    inspection.forms.push(MacosFormInspection {
        process_id: prompt.target.process_id,
        title: prompt.target.window_title.clone(),
        prompt_email: prompt.email.clone(),
        prompt_origin: prompt.origin.as_str(),
    });
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
    let frontmost = prompts
        .iter()
        .filter(|prompt| prompt.target.frontmost)
        .collect::<Vec<_>>();
    match frontmost.as_slice() {
        [prompt] => Some(*prompt),
        [] => match prompts {
            [prompt] => Some(prompt),
            _ => None,
        },
        _ => None,
    }
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

pub(crate) fn fill_password(
    app_name: &str,
    expected_process_id: i32,
    expected_window_title: &str,
    expected_prompt_origin: &str,
    expected_email: &str,
    password: &str,
    method: MacosFillMethod,
    guard: &dyn Fn() -> anyhow::Result<()>,
) -> anyhow::Result<MacosFillResult> {
    guard()?;

    let verified_prompt = revalidate_prompt(
        app_name,
        expected_process_id,
        expected_window_title,
        expected_prompt_origin,
        expected_email,
    )?;

    fill_verified_password(
        app_name,
        verified_prompt,
        expected_process_id,
        expected_window_title,
        expected_prompt_origin,
        expected_email,
        password,
        method,
        guard,
    )
}

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
    let prepared = revalidate_prepared_prompt_for_fill(
        app_name,
        &verified_prompt,
        expected_process_id,
        expected_window_title,
        expected_email,
    )?;
    let prompt = verified_prompt.prompt;
    let password_field_role = prompt.password_field_role.clone();
    let password_field_description_present = !prompt.password_field_description.trim().is_empty();
    let keyboard_method_label = method.label();

    let submit_button_ready_after_fill = false;
    let mut password_field_focused = false;
    let method_used = match method {
        MacosFillMethod::Keyboard => {
            if set_password_value(&prepared.password_field, password) {
                "axvalue"
            } else {
                focus_password_field_in_prompt(&prompt, app_name, expected_process_id)?;
                password_field_focused = true;
                guard()?;
                if !send_key_with_flags(KEYCODE_A, CG_EVENT_FLAG_MASK_COMMAND) {
                    anyhow::bail!("password field clear shortcut event creation failed");
                }
                thread::sleep(Duration::from_millis(KEY_EVENT_SETTLE_MS));
                if !send_key(KEYCODE_DELETE) {
                    anyhow::bail!("password field clear event creation failed");
                }
                thread::sleep(Duration::from_millis(KEY_EVENT_SETTLE_MS));

                guard()?;
                let password_field = if prompt.password_field.bool_attr(AX_FOCUSED).unwrap_or(false)
                {
                    verified_password_field_in_prompt(&prompt, app_name, expected_process_id)?
                } else {
                    focus_password_field_in_prompt(&prompt, app_name, expected_process_id)?
                };
                guard()?;
                ensure_prompt_identity_text_still_matches(
                    &prompt,
                    expected_process_id,
                    expected_email,
                    expected_window_title,
                    prompt.origin,
                    "keyboard password insertion",
                )?;
                let trusted_process = current_trusted_process_info(app_name, expected_process_id)?;
                ensure_trusted_process_matches(
                    &trusted_process,
                    &prepared.trusted_process,
                    "credential prompt process identity changed before keyboard password insertion",
                )?;
                if !password_field.bool_attr(AX_FOCUSED).unwrap_or(false) {
                    anyhow::bail!(
                        "password field focus changed before keyboard password insertion"
                    );
                }
                if send_text(password) {
                    thread::sleep(Duration::from_millis(POST_FILL_SETTLE_MS));
                    keyboard_method_label
                } else {
                    anyhow::bail!("password insertion event creation failed");
                }
            }
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

pub(crate) fn submit_filled_prompt(
    app_name: &str,
    filled_prompt: &MacosFilledPrompt,
    guard: &dyn Fn() -> anyhow::Result<()>,
) -> anyhow::Result<MacosSubmitResult> {
    guard()?;
    let prompt = &filled_prompt.prompt;
    let button = revalidate_filled_prompt(app_name, filled_prompt)?;
    let pre_submit_session_windows = Vec::new();

    if button.perform_action(AX_PRESS) {
        if SUBMIT_SETTLE_MS > 0 {
            thread::sleep(Duration::from_millis(SUBMIT_SETTLE_MS));
        }
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
                pre_submit_session_windows,
            }),
        });
    }

    raise_prompt(prompt);
    let button = revalidate_filled_prompt(app_name, filled_prompt)?;
    if button.perform_action(AX_PRESS) {
        if SUBMIT_SETTLE_MS > 0 {
            thread::sleep(Duration::from_millis(SUBMIT_SETTLE_MS));
        }
        return Ok(MacosSubmitResult {
            submit_method: "axpress_fast",
            submit_status: "ok",
            axpress_attempted: true,
            axpress_result: "success_after_raise",
            enter_fallback_attempted: false,
            enter_fallback_result: "not_needed",
            submitted_prompt: Some(MacosSubmittedPrompt {
                process_id: prompt.target.process_id,
                window_title: prompt.target.window_title.clone(),
                email: filled_prompt.expected_email.clone(),
                origin: prompt.origin,
                target_window: prompt.target_window.clone(),
                pre_submit_session_windows,
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
    if let Some(filled_prompt) = filled_prompt.filter(|filled_prompt| {
        filled_prompt.matches_expected(
            expected_process_id,
            expected_window_title,
            expected_prompt_origin,
            expected_email,
        )
    }) {
        return submit_filled_prompt(app_name, filled_prompt, guard);
    }

    submit_prompt(
        app_name,
        expected_process_id,
        expected_window_title,
        expected_prompt_origin,
        expected_email,
        guard,
    )
}

pub(crate) fn submit_prompt(
    app_name: &str,
    expected_process_id: i32,
    expected_window_title: &str,
    expected_prompt_origin: &str,
    expected_email: &str,
    guard: &dyn Fn() -> anyhow::Result<()>,
) -> anyhow::Result<MacosSubmitResult> {
    guard()?;
    let pre_submit_session_windows = Vec::new();

    guard()?;
    let revalidated_prompt = revalidate_prompt(
        app_name,
        expected_process_id,
        expected_window_title,
        expected_prompt_origin,
        expected_email,
    )?;
    let prompt = revalidated_prompt.prompt;
    let enabled_submit_button = prompt
        .submit_button
        .as_ref()
        .filter(|button| element_enabled(button))
        .cloned();
    if let Some(button) = &enabled_submit_button {
        ensure_element_belongs_to_process(button, expected_process_id, "submit button")?;
        ensure_element_within_prompt_root(button, &prompt.prompt_root, "submit button")?;
        if button.perform_action(AX_PRESS) {
            if SUBMIT_SETTLE_MS > 0 {
                thread::sleep(Duration::from_millis(SUBMIT_SETTLE_MS));
            }
            return Ok(MacosSubmitResult {
                submit_method: "axpress",
                submit_status: "ok",
                axpress_attempted: true,
                axpress_result: "success",
                enter_fallback_attempted: false,
                enter_fallback_result: "not_needed",
                submitted_prompt: Some(MacosSubmittedPrompt {
                    process_id: expected_process_id,
                    window_title: expected_window_title.to_string(),
                    email: expected_email.to_string(),
                    origin: prompt.origin,
                    target_window: prompt.target_window.clone(),
                    pre_submit_session_windows,
                }),
            });
        }
    }

    Ok(MacosSubmitResult {
        submit_method: "axpress",
        submit_status: "failed",
        axpress_attempted: enabled_submit_button.is_some(),
        axpress_result: "failed",
        enter_fallback_attempted: false,
        enter_fallback_result: "disabled",
        submitted_prompt: None,
    })
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

pub(crate) fn post_check_state(
    app_name: &str,
    expected_process_id: i32,
    expected_window_title: &str,
    expected_email: &str,
    submitted_prompt: Option<&MacosSubmittedPrompt>,
    timeout: Duration,
) -> &'static str {
    let started = Instant::now();
    loop {
        match inspect_process(app_name, Some(expected_process_id), None) {
            Ok(inspection) => {
                let state = classify_post_submit_inspection(
                    &inspection,
                    expected_process_id,
                    expected_window_title,
                    expected_email,
                    submitted_prompt,
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
) -> Option<&'static str> {
    let target_running = inspection.target.as_ref().is_some_and(|target| {
        target.process_id == expected_process_id
            || inspection
                .window_titles
                .iter()
                .any(|title| title.process_id == expected_process_id)
    });
    let has_session_for_expected_process = submitted_prompt.is_some_and(|submitted_prompt| {
        submitted_prompt_matches_expected(submitted_prompt, expected_process_id, expected_email)
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
    if submitted_prompt.origin != PromptOrigin::Sheet {
        return false;
    }
    if submitted_prompt.pre_submit_session_windows.is_empty() {
        return false;
    }
    if session_window_was_present_before_submit(
        session,
        &submitted_prompt.pre_submit_session_windows,
    ) {
        return false;
    }
    if !session
        .title
        .trim()
        .eq_ignore_ascii_case(submitted_prompt.window_title.trim())
    {
        return false;
    }
    session
        .window
        .as_ref()
        .is_some_and(|window| !window.same_element(&submitted_prompt.target_window))
}

fn session_window_was_present_before_submit(
    session: &MacosWindowTitle,
    pre_submit_sessions: &[MacosWindowTitle],
) -> bool {
    pre_submit_sessions
        .iter()
        .any(|pre_submit| same_session_window_identity(session, pre_submit))
}

fn same_session_window_identity(left: &MacosWindowTitle, right: &MacosWindowTitle) -> bool {
    if left.process_id != right.process_id
        || !left.title.trim().eq_ignore_ascii_case(right.title.trim())
    {
        return false;
    }

    match (&left.window, &right.window) {
        (Some(left_window), Some(right_window)) => left_window.same_element(right_window),
        _ => true,
    }
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
    if !prompt.target.frontmost {
        raise_prompt(&prompt);
        thread::sleep(Duration::from_millis(FOCUS_SETTLE_MS));
    }
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
    if is_hidden(&prompt.target_window)
        || is_hidden(&prompt.prompt_root)
        || is_hidden(&prompt.password_field)
    {
        anyhow::bail!("credential prompt hidden before password insertion");
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

fn focus_password_field_in_prompt(
    prompt: &MacosPrompt,
    app_name: &str,
    expected_process_id: i32,
) -> anyhow::Result<AxElement> {
    verified_password_field_in_prompt(prompt, app_name, expected_process_id)?;
    raise_prompt(prompt);
    focus_password_field(
        &prompt.password_field,
        expected_process_id,
        &prompt.prompt_root,
    )
    .then_some(prompt.password_field.clone())
    .context("password field focus is not verified immediately before target-bound input")
}

fn verified_password_field_in_prompt(
    prompt: &MacosPrompt,
    app_name: &str,
    expected_process_id: i32,
) -> anyhow::Result<AxElement> {
    ensure_trusted_process_current(app_name, expected_process_id)?;
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
    Ok(prompt.password_field.clone())
}

fn raise_prompt(prompt: &MacosPrompt) {
    if let Some(app) = AxElement::application(prompt.target.process_id) {
        let _ = app.set_bool_attr(AX_FRONTMOST, true);
    }
    let _ = prompt.target_window.perform_action(AX_RAISE);
    let _ = prompt.target_window.set_bool_attr(AX_MAIN, true);
    let _ = prompt.prompt_root.perform_action(AX_RAISE);
}

fn ensure_trusted_process_current(app_name: &str, expected_process_id: i32) -> anyhow::Result<()> {
    current_trusted_process_info(app_name, expected_process_id).map(|_| ())
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
    if field.bool_attr(AX_FOCUSED).unwrap_or(false) {
        return true;
    }
    let _ = field.set_bool_attr(AX_FOCUSED, true);
    if wait_for_bool_attr(
        field,
        AX_FOCUSED,
        true,
        Duration::from_millis(FOCUS_SETTLE_MS),
    ) {
        return true;
    }

    if ensure_element_belongs_to_process(field, expected_process_id, "password field").is_err()
        || ensure_element_within_prompt_root(field, prompt_root, "password field").is_err()
    {
        return false;
    }
    let _ = field.perform_action(AX_PRESS);
    wait_for_bool_attr(
        field,
        AX_FOCUSED,
        true,
        Duration::from_millis(PRESS_FOCUS_SETTLE_MS),
    )
}

fn wait_for_bool_attr(
    element: &AxElement,
    attr: &'static str,
    expected: bool,
    timeout: Duration,
) -> bool {
    let started = Instant::now();
    loop {
        if element.bool_attr(attr).unwrap_or(false) == expected {
            return true;
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

fn window_should_scan_for_prompt(target: &MacosTarget, window_title: &str) -> bool {
    target.frontmost
        || login_title_like(window_title)
        || is_probable_session_window_title(window_title)
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
        let target = MacosTarget {
            frontmost: target.frontmost
                || element_explicitly_frontmost(&password_field)
                || scoped_elements
                    .iter()
                    .any(|element| element_explicitly_frontmost(element)),
            ..target.clone()
        };
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
    let native_fields = elements
        .iter()
        .filter(|element| is_native_password_field(element))
        .cloned()
        .collect::<Vec<_>>();

    if !native_fields.is_empty() {
        return dedupe_elements(native_fields);
    }

    dedupe_elements(
        elements
            .iter()
            .filter(|element| is_password_like_text_field(element))
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
    let role_text = element_role_text(element);
    let normalized_role = normalized_identifier(&role_text);
    !is_hidden(element)
        && element_enabled(element)
        && (role_matches(element, AX_SECURE_TEXT_FIELD_ROLE)
            || normalized_role.contains("securetextfield")
            || (role_matches(element, AX_TEXT_FIELD_ROLE)
                && contains_keyword(&role_text, "secure")))
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
    visible_window_index: usize,
    any_explicit_frontmost_window: bool,
    window_explicitly_frontmost: bool,
) -> bool {
    app_frontmost
        && (window_explicitly_frontmost
            || (!any_explicit_frontmost_window && visible_window_index == 0))
}

fn sheet_is_frontmost_for_app(
    app_frontmost: bool,
    parent_window_frontmost: bool,
    sheet_explicitly_frontmost: bool,
) -> bool {
    app_frontmost && (parent_window_frontmost || sheet_explicitly_frontmost)
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
            credential_prompt_text_like(body_text)
                && (login_title_like(window_title)
                    || is_probable_session_window_title(window_title))
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

fn send_text(text: &str) -> bool {
    let utf16 = Zeroizing::new(text.encode_utf16().collect::<Vec<_>>());
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
        CGEventPost(CG_HID_EVENT_TAP, down);
        CGEventPost(CG_HID_EVENT_TAP, up);
        CFRelease(down.cast());
        CFRelease(up.cast());
    }
    true
}

fn send_key(keycode: u16) -> bool {
    send_key_with_flags(keycode, 0)
}

fn send_key_with_flags(keycode: u16, flags: u64) -> bool {
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
        CGEventPost(CG_HID_EVENT_TAP, down);
        CGEventPost(CG_HID_EVENT_TAP, up);
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
    fn CGEventPost(tap: u32, event: CGEventRef);
}

#[cfg(test)]
mod tests {
    use super::{
        credential_prompt_text_like, extract_email_like, normalized_submit_label,
        prompt_identity_verified, prompt_text_element_should_contribute,
        prompt_window_title_matches, select_submit_label_for_test, submit_label_rank,
        text_contains_password_cue, MacosFillMethod, PromptOrigin, DIRECT_AXVALUE_READY_MS,
        FOCUS_POLL_INTERVAL_MS, FOCUS_SETTLE_MS, KEY_EVENT_SETTLE_MS, POST_FILL_SETTLE_MS,
        PRESS_FOCUS_SETTLE_MS, SUBMIT_SETTLE_MS,
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
    fn continue_submit_labels_are_ranked_first() {
        assert_eq!(submit_label_rank("Continue"), Some(0));
        assert_eq!(submit_label_rank("_Continue button"), Some(0));
        assert_eq!(submit_label_rank("Continue button"), Some(0));
        assert_eq!(submit_label_rank("Продолжить"), Some(0));
        assert_eq!(submit_label_rank("OK"), Some(1));
        assert_eq!(submit_label_rank("OK button"), Some(1));
        assert_eq!(submit_label_rank("Cancel"), None);
    }

    #[test]
    fn normalizes_submit_label_noise() {
        assert_eq!(normalized_submit_label("_Continue button"), "Continue");
    }

    #[test]
    fn keyboard_fill_method_reports_keyboard_path() {
        assert_eq!(MacosFillMethod::Keyboard.label(), "keyboard");
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
    fn direct_axvalue_ready_wait_is_shorter_than_focus_press_fallback() {
        assert!(DIRECT_AXVALUE_READY_MS < PRESS_FOCUS_SETTLE_MS);
        assert!(DIRECT_AXVALUE_READY_MS >= FOCUS_POLL_INTERVAL_MS);
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
    fn fast_path_settle_delays_keep_bounded_fallbacks() {
        assert_eq!(KEY_EVENT_SETTLE_MS, 20);
        assert_eq!(POST_FILL_SETTLE_MS, 20);
        assert_eq!(SUBMIT_SETTLE_MS, 0);
        assert!(PRESS_FOCUS_SETTLE_MS >= FOCUS_SETTLE_MS);
        assert!(Duration::from_millis(SUBMIT_SETTLE_MS) < Duration::from_millis(450));
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
    fn post_submit_prompt_email_mismatch_returns_prompt_mismatch() {
        assert_eq!(
            super::classify_post_submit_state(
                Some("other@example.com"),
                true,
                false,
                "user@example.com"
            ),
            Some("prompt_mismatch")
        );
    }

    #[test]
    fn post_submit_prompt_matching_email_returns_still_prompt() {
        assert_eq!(
            super::classify_post_submit_state(
                Some("USER@example.com"),
                true,
                false,
                "user@example.com"
            ),
            Some("still_prompt")
        );
    }

    #[test]
    fn post_submit_no_prompt_without_session_stays_unknown_until_timeout() {
        assert_eq!(
            super::classify_post_submit_state(None, true, false, "user@example.com"),
            None
        );
    }

    #[test]
    fn post_submit_no_prompt_with_expected_session_returns_authenticated() {
        assert_eq!(
            super::classify_post_submit_state(None, true, true, "user@example.com"),
            Some("authenticated")
        );
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
                None
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
                None
            ),
            None
        );
    }

    #[test]
    fn post_submit_preexisting_session_window_is_not_positive_auth_signal() {
        const EXPECTED_PID: i32 = 101;

        let session = super::MacosWindowTitle {
            process_id: EXPECTED_PID,
            title: "Contoso Desktop".to_string(),
            window: None,
        };
        let pre_submit_sessions = vec![super::MacosWindowTitle {
            process_id: EXPECTED_PID,
            title: "contoso desktop".to_string(),
            window: None,
        }];

        assert!(super::session_window_was_present_before_submit(
            &session,
            &pre_submit_sessions
        ));
    }

    #[test]
    fn post_submit_new_session_title_can_still_be_considered_separate_signal() {
        const EXPECTED_PID: i32 = 101;

        let session = super::MacosWindowTitle {
            process_id: EXPECTED_PID,
            title: "Contoso Desktop".to_string(),
            window: None,
        };
        let pre_submit_sessions = vec![super::MacosWindowTitle {
            process_id: EXPECTED_PID,
            title: "Other Desktop".to_string(),
            window: None,
        }];

        assert!(!super::session_window_was_present_before_submit(
            &session,
            &pre_submit_sessions
        ));
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
    fn window_frontmost_falls_back_to_first_visible_window_only_without_explicit_signal() {
        assert!(super::window_is_frontmost_for_app(true, 0, false, false));
        assert!(!super::window_is_frontmost_for_app(true, 1, false, false));
    }

    #[test]
    fn sheet_frontmost_can_come_from_parent_window_or_focused_sheet() {
        assert!(super::sheet_is_frontmost_for_app(true, true, false));
        assert!(super::sheet_is_frontmost_for_app(true, false, true));
        assert!(!super::sheet_is_frontmost_for_app(false, true, true));
        assert!(!super::sheet_is_frontmost_for_app(true, false, false));
    }

    #[test]
    fn prompt_identity_requires_body_credential_context() {
        assert!(!prompt_identity_verified(
            "Password",
            "user@example.com",
            PromptOrigin::Window
        ));
        assert!(prompt_identity_verified(
            "Sign in",
            "Enter password for user@example.com",
            PromptOrigin::Window
        ));
        assert!(!prompt_identity_verified(
            "Connection Center",
            "Sign in with user@example.com",
            PromptOrigin::Sheet
        ));
        assert!(!prompt_identity_verified(
            "Contoso Desktop",
            "Sign in with user@example.com",
            PromptOrigin::Sheet
        ));
        assert!(prompt_identity_verified(
            "Contoso Desktop",
            "Enter password for user@example.com",
            PromptOrigin::Sheet
        ));
        assert!(prompt_identity_verified(
            "Contoso Desktop",
            "Enter password for Contoso Desktop user@example.com",
            PromptOrigin::Sheet
        ));
        assert!(prompt_identity_verified(
            "Contoso Desktop",
            "Enter Your User Account used to connect to user@example.com",
            PromptOrigin::Sheet
        ));
        assert!(prompt_identity_verified(
            "Contoso Desktop",
            "Enter Your User Account used to connect to Other Desktop user@example.com",
            PromptOrigin::Sheet
        ));
        assert!(prompt_identity_verified(
            "Contoso Desktop",
            "Enter Your User Account used to connect to Contoso Desktop user@example.com",
            PromptOrigin::Sheet
        ));
        assert!(prompt_identity_verified(
            "Azure DevDesktop - Windows 11",
            "Enter Your Credentials These credentials will be used to connect to rdgateway.example.com Username: user@example.com Password:",
            PromptOrigin::Sheet
        ));
        assert!(prompt_identity_verified(
            "Azure DevDesktop - Windows 11",
            "Enter Your Credentials These credentials will be used to connect to rdgateway.example.com Username: user@example.com Password:",
            PromptOrigin::Window
        ));
        assert!(!prompt_identity_verified(
            "Connection Center",
            "Sign in with user@example.com",
            PromptOrigin::Window
        ));
    }

    #[test]
    fn sheet_prompt_identity_allows_shell_parent_titles_with_credential_body() {
        for title in [
            "Windows App",
            "Connection Center",
            "Workspaces",
            "Accounts",
            "Add PC",
            "Settings",
        ] {
            assert!(
                prompt_identity_verified(
                    title,
                    "Enter password for user@example.com",
                    PromptOrigin::Sheet
                ),
                "{title} should be accepted when a trusted sheet has credential text"
            );
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
