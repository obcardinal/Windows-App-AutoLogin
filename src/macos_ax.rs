use crate::macos_identity;
use anyhow::Context;
use core_foundation::array::CFArray;
use core_foundation::base::{CFRelease, CFRetain, CFType, CFTypeRef, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::string::{CFString, CFStringRef};
use std::ffi::c_void;
use std::fmt;
use std::thread;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const MAX_ELEMENT_COUNT: usize = 900;
const AX_SEARCH_DEPTH: usize = 12;
const FOCUS_SETTLE_MS: u64 = 50;
const SUBMIT_SETTLE_MS: u64 = 120;

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
const AX_PRESS: &str = "AXPress";

const AX_BUTTON_ROLE: &str = "AXButton";
const AX_TEXT_FIELD_ROLE: &str = "AXTextField";
const AX_SECURE_TEXT_FIELD_ROLE: &str = "AXSecureTextField";
const AX_STATIC_TEXT_ROLE: &str = "AXStaticText";

const KEYCODE_A: u16 = 0;
const KEYCODE_DELETE: u16 = 51;
const KEYCODE_RETURN: u16 = 36;
const CG_HID_EVENT_TAP: u32 = 0;
const CG_EVENT_FLAG_MASK_COMMAND: u64 = 1 << 20;

#[derive(Debug, Clone, Default)]
pub(crate) struct MacosInspection {
    pub(crate) target: Option<MacosTarget>,
    pub(crate) prompt: Option<MacosPrompt>,
    pub(crate) has_session: bool,
    pub(crate) window_titles: Vec<MacosWindowTitle>,
    pub(crate) forms: Vec<MacosFormInspection>,
}

#[derive(Debug, Clone)]
pub(crate) struct MacosTarget {
    pub(crate) process_id: i32,
    pub(crate) window_title: String,
    pub(crate) frontmost: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct MacosWindowTitle {
    pub(crate) process_id: i32,
    pub(crate) title: String,
}

#[derive(Debug, Clone)]
pub(crate) struct MacosFormInspection {
    pub(crate) process_id: i32,
    pub(crate) title: String,
    pub(crate) prompt_email: Option<String>,
}

#[derive(Clone)]
pub(crate) struct MacosPrompt {
    pub(crate) target: MacosTarget,
    pub(crate) email: Option<String>,
    pub(crate) password_field_description: String,
    pub(crate) password_field_role: String,
    password_field: AxElement,
    submit_button: Option<AxElement>,
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
            .field("submit_button", &self.submit_button.is_some())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MacosFillMethod {
    Keyboard,
    DirectAxSetValue,
}

#[derive(Debug, Clone)]
pub(crate) struct MacosFillResult {
    pub(crate) fill_method: &'static str,
    pub(crate) fill_status: &'static str,
    pub(crate) password_field_focused: bool,
    pub(crate) password_field_role: String,
    pub(crate) password_field_description_present: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct MacosSubmitResult {
    pub(crate) submit_method: &'static str,
    pub(crate) submit_status: &'static str,
    pub(crate) axpress_attempted: bool,
    pub(crate) axpress_result: &'static str,
    pub(crate) enter_fallback_attempted: bool,
    pub(crate) enter_fallback_result: &'static str,
}

struct AxElement {
    raw: AXUIElementRef,
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
                let _ = AXUIElementSetMessagingTimeout(raw, 0.35);
            }
            Some(Self { raw })
        }
    }

    unsafe fn borrowed(raw: AXUIElementRef) -> Option<Self> {
        if raw.is_null() {
            None
        } else {
            CFRetain(raw.cast());
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
    let process_infos = macos_identity::trusted_process_infos(app_name)?;
    if process_infos.is_empty() {
        return Ok(MacosInspection::default());
    }

    let mut inspection = MacosInspection::default();
    let mut first_prompt: Option<MacosPrompt> = None;
    let mut frontmost_prompt: Option<MacosPrompt> = None;

    for process in process_infos {
        let Some(app) = AxElement::application(process.pid) else {
            continue;
        };
        let app_frontmost = app.bool_attr(AX_FRONTMOST).unwrap_or(false);
        let windows = app.array_attr(AX_WINDOWS);

        if inspection.target.is_none() {
            inspection.target = Some(MacosTarget {
                process_id: process.pid,
                window_title: String::new(),
                frontmost: app_frontmost,
            });
        }

        for (window_index, window) in windows.iter().enumerate() {
            if is_hidden(window) {
                continue;
            }
            let window_title = window.string_attr(AX_TITLE).unwrap_or_default();
            inspection.window_titles.push(MacosWindowTitle {
                process_id: process.pid,
                title: window_title.clone(),
            });

            let window_frontmost = app_frontmost
                && (window.bool_attr(AX_MAIN).unwrap_or(window_index == 0)
                    || window.bool_attr(AX_FOCUSED).unwrap_or(false));
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

            let window_elements = collect_elements(window);

            for sheet in window.array_attr(AX_SHEETS) {
                if is_hidden(&sheet) {
                    continue;
                }
                let sheet_elements = collect_elements(&sheet);
                if let Some(prompt) =
                    prompt_from_elements(target.clone(), &sheet_elements, Some(&window_elements))
                {
                    inspection.forms.push(MacosFormInspection {
                        process_id: prompt.target.process_id,
                        title: prompt.target.window_title.clone(),
                        prompt_email: prompt.email.clone(),
                    });
                    if prompt.target.frontmost {
                        frontmost_prompt = Some(prompt);
                    } else if first_prompt.is_none() {
                        first_prompt = Some(prompt);
                    }
                }
            }

            if let Some(prompt) = prompt_from_elements(target.clone(), &window_elements, None) {
                inspection.forms.push(MacosFormInspection {
                    process_id: prompt.target.process_id,
                    title: prompt.target.window_title.clone(),
                    prompt_email: prompt.email.clone(),
                });
                if prompt.target.frontmost {
                    frontmost_prompt = Some(prompt);
                } else if first_prompt.is_none() {
                    first_prompt = Some(prompt);
                }
            } else if is_probable_session_window_title(&window_title) {
                inspection.has_session = true;
            }
        }
    }

    inspection.prompt = frontmost_prompt.or(first_prompt);
    Ok(inspection)
}

pub(crate) fn detect_visible_prompt(
    app_name: &str,
    expected_process_id: Option<i32>,
    expected_window_title: Option<&str>,
) -> anyhow::Result<Option<MacosPrompt>> {
    let mut inspection = inspect(app_name)?;
    let Some(prompt) = inspection.prompt.take() else {
        return Ok(None);
    };
    if let Some(expected_process_id) = expected_process_id {
        if prompt.target.process_id != expected_process_id {
            anyhow::bail!("Previously detected login prompt process is no longer trusted");
        }
    }
    if !prompt_window_title_matches(&prompt.target.window_title, expected_window_title) {
        anyhow::bail!("Previously detected login prompt window title changed");
    }
    Ok(Some(prompt))
}

pub(crate) fn fill_password(
    app_name: &str,
    expected_process_id: i32,
    expected_window_title: &str,
    expected_email: &str,
    password: &str,
    method: MacosFillMethod,
    guard: &dyn Fn() -> anyhow::Result<()>,
) -> anyhow::Result<MacosFillResult> {
    activate_process(expected_process_id)?;
    guard()?;

    let prompt = revalidate_prompt(
        app_name,
        expected_process_id,
        expected_window_title,
        expected_email,
    )?;
    let password_field = prompt.password_field.clone();
    let password_field_role = prompt.password_field_role.clone();
    let password_field_description_present = !prompt.password_field_description.trim().is_empty();

    if password_field.set_string_attr(AX_VALUE, password) {
        return Ok(MacosFillResult {
            fill_method: "direct_ax_set_value",
            fill_status: "ok",
            password_field_focused: password_field.bool_attr(AX_FOCUSED).unwrap_or(false),
            password_field_role,
            password_field_description_present,
        });
    }

    if method == MacosFillMethod::DirectAxSetValue {
        anyhow::bail!("direct AX value set failed");
    }

    focus_password_field(&password_field)
        .then_some(())
        .context("password field focus is not verified")?;
    guard()?;
    send_key_with_flags(KEYCODE_A, CG_EVENT_FLAG_MASK_COMMAND);
    thread::sleep(Duration::from_millis(30));
    send_key(KEYCODE_DELETE);
    thread::sleep(Duration::from_millis(30));
    guard()?;
    send_text(password);
    thread::sleep(Duration::from_millis(FOCUS_SETTLE_MS));

    Ok(MacosFillResult {
        fill_method: "keyboard",
        fill_status: "ok",
        password_field_focused: password_field.bool_attr(AX_FOCUSED).unwrap_or(false),
        password_field_role,
        password_field_description_present,
    })
}

pub(crate) fn submit_prompt(
    app_name: &str,
    expected_process_id: i32,
    expected_window_title: &str,
    expected_email: &str,
    guard: &dyn Fn() -> anyhow::Result<()>,
) -> anyhow::Result<MacosSubmitResult> {
    activate_process(expected_process_id)?;
    guard()?;
    let prompt = revalidate_prompt(
        app_name,
        expected_process_id,
        expected_window_title,
        expected_email,
    )?;

    if let Some(button) = &prompt.submit_button {
        if button.perform_action(AX_PRESS) {
            thread::sleep(Duration::from_millis(SUBMIT_SETTLE_MS));
            return Ok(MacosSubmitResult {
                submit_method: "axpress",
                submit_status: "ok",
                axpress_attempted: true,
                axpress_result: "success",
                enter_fallback_attempted: false,
                enter_fallback_result: "not_needed",
            });
        }
    }

    if !focus_password_field(&prompt.password_field) {
        anyhow::bail!("submit fallback refused because password field focus is not verified");
    }
    send_key(KEYCODE_RETURN);
    thread::sleep(Duration::from_millis(SUBMIT_SETTLE_MS));
    Ok(MacosSubmitResult {
        submit_method: "enter",
        submit_status: "ok",
        axpress_attempted: prompt.submit_button.is_some(),
        axpress_result: "failed",
        enter_fallback_attempted: true,
        enter_fallback_result: "sent",
    })
}

pub(crate) fn post_check_state(
    app_name: &str,
    expected_process_id: i32,
    expected_email: &str,
    timeout: Duration,
) -> &'static str {
    let started = Instant::now();
    loop {
        match inspect(app_name) {
            Ok(inspection) => {
                let target_running = inspection.target.as_ref().is_some_and(|target| {
                    target.process_id == expected_process_id
                        || inspection
                            .window_titles
                            .iter()
                            .any(|title| title.process_id == expected_process_id)
                });

                if let Some(prompt) = inspection.prompt {
                    if prompt
                        .email
                        .as_deref()
                        .is_some_and(|email| usernames_match(email, expected_email))
                    {
                        return "still_prompt";
                    }
                    return "prompt_gone_unknown";
                }

                if !target_running {
                    return "failed";
                }
                if inspection.has_session {
                    return "authenticated";
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

fn revalidate_prompt(
    app_name: &str,
    expected_process_id: i32,
    expected_window_title: &str,
    expected_email: &str,
) -> anyhow::Result<MacosPrompt> {
    let Some(prompt) = detect_visible_prompt(
        app_name,
        Some(expected_process_id),
        Some(expected_window_title),
    )?
    else {
        anyhow::bail!("credential prompt disappeared before automation");
    };

    if prompt.target.process_id != expected_process_id {
        anyhow::bail!("credential prompt process changed before automation");
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
    Ok(prompt)
}

fn activate_process(process_id: i32) -> anyhow::Result<()> {
    let app = AxElement::application(process_id).context("target app is not available")?;
    if app.bool_attr(AX_FRONTMOST).unwrap_or(false) {
        return Ok(());
    }
    app.set_bool_attr(AX_FRONTMOST, true)
        .then_some(())
        .context("target app could not be made frontmost")?;
    thread::sleep(Duration::from_millis(150));
    Ok(())
}

fn focus_password_field(field: &AxElement) -> bool {
    let _ = field.set_bool_attr(AX_FOCUSED, true);
    thread::sleep(Duration::from_millis(FOCUS_SETTLE_MS));
    if field.bool_attr(AX_FOCUSED).unwrap_or(false) {
        return true;
    }

    let _ = field.perform_action(AX_PRESS);
    thread::sleep(Duration::from_millis(FOCUS_SETTLE_MS));
    field.bool_attr(AX_FOCUSED).unwrap_or(false)
}

fn collect_elements(root: &AxElement) -> Vec<AxElement> {
    let mut elements = Vec::new();
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
        elements.push(child.clone());
        collect_elements_recursive(&child, depth + 1, elements);
    }
}

fn prompt_from_elements(
    target: MacosTarget,
    elements: &[AxElement],
    extra_submit_elements: Option<&[AxElement]>,
) -> Option<MacosPrompt> {
    let submit_button = select_submit_button(elements)
        .or_else(|| extra_submit_elements.and_then(select_submit_button));
    let prompt_text = collect_prompt_text(&target.window_title, elements);
    let prompt_email = extract_email_like(&prompt_text);
    let login_title = login_title_like(&target.window_title);
    let verified_context = submit_button.is_some() && (prompt_email.is_some() || login_title);

    let password_field = select_password_field(elements, verified_context)?;
    submit_button.as_ref()?;
    if prompt_email.is_none() && !login_title {
        return None;
    }

    Some(MacosPrompt {
        target,
        email: prompt_email,
        password_field_description: element_label_text(&password_field),
        password_field_role: element_role_text(&password_field),
        password_field,
        submit_button,
    })
}

fn select_password_field(elements: &[AxElement], verified_context: bool) -> Option<AxElement> {
    elements
        .iter()
        .find(|element| is_native_password_field(element))
        .cloned()
        .or_else(|| {
            verified_context.then(|| {
                elements
                    .iter()
                    .find(|element| is_password_like_text_field(element))
                    .cloned()
            })?
        })
}

fn select_submit_button(elements: &[AxElement]) -> Option<AxElement> {
    let buttons = elements
        .iter()
        .filter(|element| is_button(element))
        .filter(|element| !is_hidden(element))
        .collect::<Vec<_>>();

    buttons
        .iter()
        .find(|element| {
            element_enabled(element) && submit_label_rank(&button_text(element)) == Some(0)
        })
        .copied()
        .cloned()
        .or_else(|| {
            buttons
                .iter()
                .find(|element| {
                    element_enabled(element) && submit_label_rank(&button_text(element)).is_some()
                })
                .copied()
                .cloned()
        })
        .or_else(|| {
            buttons
                .iter()
                .find(|element| submit_label_rank(&button_text(element)).is_some())
                .copied()
                .cloned()
        })
}

fn collect_prompt_text(window_title: &str, elements: &[AxElement]) -> String {
    let mut text = String::from(window_title);
    for element in elements {
        if is_native_password_field(element) || is_password_like_text_field(element) {
            continue;
        }

        push_text(&mut text, element.string_attr(AX_TITLE));
        push_text(&mut text, element.string_attr(AX_DESCRIPTION));
        push_text(&mut text, element.string_attr(AX_HELP));
        push_text(&mut text, element.string_attr(AX_PLACEHOLDER));

        if is_text_or_static_text(element) {
            push_text(&mut text, element.string_attr(AX_VALUE));
        }
    }
    text
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
    !is_hidden(element)
        && element_enabled(element)
        && (role_matches(element, AX_SECURE_TEXT_FIELD_ROLE)
            || element_role_text(element)
                .to_lowercase()
                .contains("secure text field"))
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

fn login_title_like(title: &str) -> bool {
    LOGIN_TITLE_KEYWORDS
        .iter()
        .any(|keyword| contains_keyword(title, keyword))
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
    let mut at_positions = chars
        .iter()
        .enumerate()
        .filter_map(|(idx, c)| (*c == '@').then_some(idx));

    at_positions.find_map(|at| {
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
            Some(candidate)
        } else {
            None
        }
    })
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

fn send_text(text: &str) {
    let utf16 = Zeroizing::new(text.encode_utf16().collect::<Vec<_>>());
    if utf16.is_empty() {
        return;
    }
    unsafe {
        let down = CGEventCreateKeyboardEvent(std::ptr::null(), 0, true);
        if !down.is_null() {
            CGEventKeyboardSetUnicodeString(down, utf16.len(), utf16.as_ptr());
            CGEventPost(CG_HID_EVENT_TAP, down);
            CFRelease(down.cast());
        }
        let up = CGEventCreateKeyboardEvent(std::ptr::null(), 0, false);
        if !up.is_null() {
            CGEventKeyboardSetUnicodeString(up, utf16.len(), utf16.as_ptr());
            CGEventPost(CG_HID_EVENT_TAP, up);
            CFRelease(up.cast());
        }
    }
}

fn send_key(keycode: u16) {
    send_key_with_flags(keycode, 0);
}

fn send_key_with_flags(keycode: u16, flags: u64) {
    unsafe {
        let down = CGEventCreateKeyboardEvent(std::ptr::null(), keycode, true);
        if !down.is_null() {
            CGEventSetFlags(down, flags);
            CGEventPost(CG_HID_EVENT_TAP, down);
            CFRelease(down.cast());
        }
        let up = CGEventCreateKeyboardEvent(std::ptr::null(), keycode, false);
        if !up.is_null() {
            CGEventSetFlags(up, flags);
            CGEventPost(CG_HID_EVENT_TAP, up);
            CFRelease(up.cast());
        }
    }
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

const NON_SESSION_TITLE_KEYWORDS: &[&str] = &[
    "devices",
    "windows app",
    "settings",
    "preferences",
    "about windows app",
    "connection lost",
    "disconnected",
    "unable to connect",
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
    fn AXUIElementSetAttributeValue(
        element: AXUIElementRef,
        attribute: CFStringRef,
        value: CFTypeRef,
    ) -> AXError;
    fn AXUIElementPerformAction(element: AXUIElementRef, action: CFStringRef) -> AXError;

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
        extract_email_like, normalized_submit_label, submit_label_rank, text_contains_password_cue,
    };

    #[test]
    fn extracts_email_like_text() {
        assert_eq!(
            extract_email_like("Signed in as user.name+rdp@example.com"),
            Some("user.name+rdp@example.com".to_string())
        );
        assert_eq!(extract_email_like("No email here"), None);
    }

    #[test]
    fn continue_submit_labels_are_ranked_first() {
        assert_eq!(submit_label_rank("Continue"), Some(0));
        assert_eq!(submit_label_rank("Продолжить"), Some(0));
        assert_eq!(submit_label_rank("OK button"), Some(1));
        assert_eq!(submit_label_rank("Cancel"), None);
    }

    #[test]
    fn normalizes_submit_label_noise() {
        assert_eq!(normalized_submit_label("_Continue button"), "Continue");
    }

    #[test]
    fn password_cues_cover_existing_locales() {
        assert!(text_contains_password_cue("Введите пароль"));
        assert!(text_contains_password_cue("Mot de passe"));
        assert!(!text_contains_password_cue("Account"));
    }
}
