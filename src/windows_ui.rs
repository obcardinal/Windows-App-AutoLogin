use crate::config::{Config, CredentialsConfig};
use crate::monitor::MonitorStatus;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};
use uiautomation::core::UIMatcherMode;
use uiautomation::inputs::Keyboard;
use uiautomation::patterns::{UIInvokePattern, UIValuePattern};
use uiautomation::types::{ControlType, Handle};
use uiautomation::{UIAutomation, UIElement};
use windows::core::BOOL;
use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, HWND, LPARAM, RECT};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetClassNameW, GetForegroundWindow, GetWindowRect, GetWindowTextW,
    GetWindowThreadProcessId, IsWindowVisible, SetForegroundWindow, ShowWindow, SW_RESTORE,
};
use zeroize::Zeroizing;

const MAX_ELEMENT_COUNT: usize = 900;
const UIA_SEARCH_DEPTH: u32 = 12;
const KEYBOARD_INTERVAL_MS: u64 = 10;
const KEYBOARD_CLEAR_SETTLE_MS: u64 = 15;
const FOCUS_SETTLE_MS: u64 = 50;
const SUBMIT_SETTLE_MS: u64 = 700;
const SUBMIT_READY_TIMEOUT_MS: u64 = 1500;

#[derive(Debug, Clone)]
pub(crate) struct WindowsTarget {
    pub(crate) process_id: i32,
    pub(crate) process_name: String,
    pub(crate) process_path: String,
    pub(crate) window_title: String,
    pub(crate) window_handle: isize,
    pub(crate) frontmost: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct WindowsPrompt {
    pub(crate) target: WindowsTarget,
    pub(crate) email: Option<String>,
    pub(crate) password_field_description: String,
    pub(crate) password_field_role: String,
    password_field: UIElement,
    submit_button: Option<UIElement>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct WindowsInspection {
    pub(crate) target: Option<WindowsTarget>,
    pub(crate) prompt: Option<WindowsPrompt>,
    pub(crate) has_session: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WindowsFillStrategy {
    Keyboard,
    DirectSetValue,
}

impl WindowsFillStrategy {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Keyboard => "keyboard",
            Self::DirectSetValue => "direct_uia_value",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct WindowsFillResult {
    pub(crate) fill_method: &'static str,
    pub(crate) fill_status: &'static str,
    pub(crate) password_field_focused: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct WindowsSubmitResult {
    pub(crate) submit_method: &'static str,
    pub(crate) submit_status: &'static str,
    pub(crate) axpress_attempted: bool,
    pub(crate) axpress_result: &'static str,
    pub(crate) enter_fallback_attempted: bool,
    pub(crate) enter_fallback_result: &'static str,
}

pub(crate) fn check_status(config: &Config) -> MonitorStatus {
    match inspect(&config.macos_app_name) {
        Ok(inspection) => {
            if let Some(prompt) = inspection.prompt {
                return MonitorStatus::LoginWindowDetected {
                    process_id: prompt.target.process_id,
                    window_title: prompt.target.window_title,
                    prompt_email: prompt.email,
                };
            }

            if inspection.target.is_none() {
                MonitorStatus::ProcessNotFound
            } else if inspection.has_session {
                MonitorStatus::Connected
            } else {
                MonitorStatus::Unknown
            }
        }
        Err(e) => {
            tracing::debug!(error = %e, "Unable to inspect Windows UI Automation tree");
            MonitorStatus::Unknown
        }
    }
}

pub(crate) fn verify_prompt_without_password(
    target_app_name: &str,
    credentials: &CredentialsConfig,
    guard: &dyn Fn() -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    ensure_fixed_target_app(target_app_name)?;
    guard()?;
    let prompt = detect_matching_prompt(
        target_app_name,
        &credentials.username,
        credentials.prompt_window_title.as_deref(),
        credentials.prompt_process_id,
    )?;
    let Some(_prompt) = prompt else {
        anyhow::bail!("Credential prompt was not detected; password was not loaded");
    };
    guard()
}

pub(crate) fn perform_login_with_password_guarded(
    target_app_name: &str,
    credentials: &CredentialsConfig,
    password: Zeroizing<String>,
    guard: &dyn Fn() -> anyhow::Result<()>,
) -> anyhow::Result<crate::autologin::AutoLoginResult> {
    ensure_fixed_target_app(target_app_name)?;
    guard()?;
    let Some(prompt) = detect_matching_prompt(
        target_app_name,
        &credentials.username,
        credentials.prompt_window_title.as_deref(),
        credentials.prompt_process_id,
    )?
    else {
        anyhow::bail!("Credential prompt has no visible email; password was not loaded");
    };

    fill_password(
        target_app_name,
        &prompt,
        &password,
        WindowsFillStrategy::Keyboard,
        guard,
    )?;
    guard()?;
    let submit = submit_prompt(target_app_name, &prompt, guard)?;
    if submit.submit_status == "ok" {
        Ok(crate::autologin::AutoLoginResult::Submitted)
    } else {
        Ok(crate::autologin::AutoLoginResult::PasswordTouchedWithoutSubmit)
    }
}

pub(crate) fn inspect(target_app_name: &str) -> anyhow::Result<WindowsInspection> {
    ensure_fixed_target_app(target_app_name)?;
    let automation = UIAutomation::new().or_else(|_| UIAutomation::new_direct())?;
    let allow_system_credential_dialogs = is_builtin_target_name(target_app_name);
    let trusted_target = allow_system_credential_dialogs
        .then(|| running_target_process(target_app_name))
        .flatten();

    if let Some(trusted_target) = trusted_target.clone() {
        if let Some(prompt) = fast_system_credential_prompt(&automation)? {
            return Ok(WindowsInspection {
                target: Some(trusted_target),
                prompt: Some(prompt),
                has_session: false,
            });
        }

        return Ok(WindowsInspection {
            target: Some(trusted_target),
            prompt: None,
            has_session: false,
        });
    }

    let root = automation.get_root_element()?;
    let walker = automation.get_raw_view_walker()?;
    let mut windows = walker.get_children(&root).unwrap_or_default();

    windows.sort_by_key(|window| !window_frontmost(window));

    let mut inspection = WindowsInspection::default();
    let mut trusted_target_seen = false;
    let mut target_prompt_frontmost: Option<WindowsPrompt> = None;
    let mut target_prompt: Option<WindowsPrompt> = None;
    let mut system_prompt_frontmost: Option<WindowsPrompt> = None;
    let mut system_prompt: Option<WindowsPrompt> = None;

    for window in windows {
        if let Some((target, class_name)) = target_from_window(target_app_name, &window) {
            trusted_target_seen = true;
            if inspection.target.is_none() {
                inspection.target = Some(target.clone());
            }

            if target_window_should_be_scanned_for_prompt(target_app_name, &target, &class_name) {
                if let Some(prompt) =
                    prompt_from_window(&automation, target.clone(), window.clone())?
                {
                    if prompt.target.frontmost {
                        target_prompt_frontmost = Some(prompt);
                    } else if target_prompt.is_none() {
                        target_prompt = Some(prompt);
                    }
                }
            } else if is_probable_session_window_title(&target.window_title) {
                inspection.has_session = true;
            }

            continue;
        }

        if allow_system_credential_dialogs {
            if let Some(target) = system_credential_target_from_window(&window) {
                if let Some(prompt) = prompt_from_window(&automation, target, window.clone())? {
                    if window_handle_is_foreground(prompt.target.window_handle) {
                        system_prompt_frontmost = Some(prompt);
                    } else if system_prompt.is_none() {
                        system_prompt = Some(prompt);
                    }
                }
            }
        }
    }

    let system_prompt = system_prompt_frontmost
        .filter(|prompt| {
            trusted_target_seen && window_handle_is_foreground(prompt.target.window_handle)
        })
        .or_else(|| system_prompt.filter(|_| trusted_target_seen));
    inspection.prompt = target_prompt_frontmost.or(system_prompt).or(target_prompt);

    Ok(inspection)
}

pub(crate) fn activate_window(window_handle: isize) -> anyhow::Result<()> {
    if window_handle == 0 {
        anyhow::bail!("target window handle is unavailable");
    }
    let hwnd = HWND(std::ptr::with_exposed_provenance_mut(
        window_handle as usize,
    ));
    unsafe {
        let _ = ShowWindow(hwnd, SW_RESTORE);
        let _ = SetForegroundWindow(hwnd);
    }
    if !wait_for_foreground_window(window_handle, Duration::from_millis(500)) {
        anyhow::bail!("target window could not be made foreground");
    }
    Ok(())
}

pub(crate) fn fill_password(
    target_app_name: &str,
    prompt: &WindowsPrompt,
    password: &str,
    strategy: WindowsFillStrategy,
    guard: &dyn Fn() -> anyhow::Result<()>,
) -> anyhow::Result<WindowsFillResult> {
    activate_window(prompt.target.window_handle)?;
    guard()?;

    match strategy {
        WindowsFillStrategy::DirectSetValue => set_password_value(
            prompt,
            password,
            WindowsFillStrategy::DirectSetValue.label(),
        ),
        WindowsFillStrategy::Keyboard => {
            if target_is_system_credential_prompt(&prompt.target) {
                if let Ok(result) = set_password_value(prompt, password, "direct_uia_value_system")
                {
                    return Ok(result);
                }
            }

            let prompt = revalidate_prompt(target_app_name, prompt)?;
            guard()?;

            let focus = focus_password_field(&prompt)?;
            if !focus.verified {
                if let Ok(result) =
                    set_password_value(&prompt, password, "direct_uia_value_focus_fallback")
                {
                    return Ok(result);
                }
                anyhow::bail!("password field focus is not verified");
            }

            let keyboard = Keyboard::new().interval(KEYBOARD_INTERVAL_MS);
            keyboard
                .send_keys("{ctrl}a")
                .map_err(|e| anyhow::anyhow!("keyboard clear shortcut failed: {e}"))?;
            thread::sleep(Duration::from_millis(KEYBOARD_CLEAR_SETTLE_MS));
            keyboard
                .send_keys("{backspace}")
                .map_err(|e| anyhow::anyhow!("keyboard clear failed: {e}"))?;
            thread::sleep(Duration::from_millis(KEYBOARD_CLEAR_SETTLE_MS));
            guard()?;
            keyboard
                .send_text(password)
                .map_err(|e| anyhow::anyhow!("keyboard password input failed: {e}"))?;
            thread::sleep(Duration::from_millis(FOCUS_SETTLE_MS));
            Ok(WindowsFillResult {
                fill_method: WindowsFillStrategy::Keyboard.label(),
                fill_status: "ok",
                password_field_focused: focus.verified,
            })
        }
    }
}

fn set_password_value(
    prompt: &WindowsPrompt,
    password: &str,
    fill_method: &'static str,
) -> anyhow::Result<WindowsFillResult> {
    let value = prompt
        .password_field
        .get_pattern::<UIValuePattern>()
        .map_err(|e| anyhow::anyhow!("password field does not expose ValuePattern: {e}"))?;
    if value.is_readonly().unwrap_or(false) {
        anyhow::bail!("password field is read-only");
    }
    value
        .set_value(password)
        .map_err(|e| anyhow::anyhow!("UIA SetValue failed: {e}"))?;
    Ok(WindowsFillResult {
        fill_method,
        fill_status: "ok",
        password_field_focused: prompt.password_field.has_keyboard_focus().unwrap_or(false),
    })
}

pub(crate) fn submit_prompt(
    target_app_name: &str,
    prompt: &WindowsPrompt,
    guard: &dyn Fn() -> anyhow::Result<()>,
) -> anyhow::Result<WindowsSubmitResult> {
    activate_window(prompt.target.window_handle)?;
    guard()?;
    let prompt = revalidate_prompt(target_app_name, prompt)?;
    guard()?;
    let prompt = wait_for_submit_ready(
        target_app_name,
        prompt,
        Duration::from_millis(SUBMIT_READY_TIMEOUT_MS),
    );

    if let Some(button) = &prompt.submit_button {
        if button.is_enabled().unwrap_or(false) {
            let invoke_result = button
                .get_pattern::<UIInvokePattern>()
                .and_then(|pattern| pattern.invoke());
            if invoke_result.is_ok() {
                thread::sleep(Duration::from_millis(SUBMIT_SETTLE_MS));
                if wait_for_prompt_dismissed(target_app_name, &prompt) {
                    return Ok(WindowsSubmitResult {
                        submit_method: "invoke",
                        submit_status: "ok",
                        axpress_attempted: true,
                        axpress_result: "ok",
                        enter_fallback_attempted: false,
                        enter_fallback_result: "not_needed",
                    });
                }
            }

            if button.click().is_ok() {
                thread::sleep(Duration::from_millis(SUBMIT_SETTLE_MS));
                if wait_for_prompt_dismissed(target_app_name, &prompt) {
                    return Ok(WindowsSubmitResult {
                        submit_method: "click",
                        submit_status: "ok",
                        axpress_attempted: true,
                        axpress_result: "click_fallback_ok",
                        enter_fallback_attempted: false,
                        enter_fallback_result: "not_needed",
                    });
                }
            }
        }
    }

    let focus = focus_password_field(&prompt)?;
    if !focus.verified {
        anyhow::bail!("submit fallback refused because password field focus is not verified");
    }
    let keyboard = Keyboard::new().interval(KEYBOARD_INTERVAL_MS);
    keyboard
        .send_keys("{enter}")
        .map_err(|e| anyhow::anyhow!("keyboard enter failed: {e}"))?;
    thread::sleep(Duration::from_millis(SUBMIT_SETTLE_MS));
    if !wait_for_prompt_dismissed(target_app_name, &prompt) {
        anyhow::bail!("credential prompt still visible after submit attempts");
    }
    Ok(WindowsSubmitResult {
        submit_method: "enter",
        submit_status: "ok",
        axpress_attempted: prompt.submit_button.is_some(),
        axpress_result: "failed",
        enter_fallback_attempted: true,
        enter_fallback_result: "ok",
    })
}

fn wait_for_prompt_dismissed(target_app_name: &str, expected: &WindowsPrompt) -> bool {
    let started = Instant::now();
    loop {
        match inspect(target_app_name) {
            Ok(inspection) => {
                let Some(current) = inspection.prompt else {
                    return true;
                };
                if !same_prompt_still_visible(&current, expected) {
                    return true;
                }
            }
            Err(_) => return false,
        }

        if started.elapsed() >= Duration::from_millis(SUBMIT_SETTLE_MS) {
            return false;
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn same_prompt_still_visible(current: &WindowsPrompt, expected: &WindowsPrompt) -> bool {
    if current.target.process_id != expected.target.process_id {
        return false;
    }
    if !current
        .target
        .window_title
        .eq_ignore_ascii_case(&expected.target.window_title)
    {
        return false;
    }
    match (current.email.as_deref(), expected.email.as_deref()) {
        (Some(current), Some(expected)) => current.eq_ignore_ascii_case(expected),
        _ => true,
    }
}

pub(crate) fn post_check_state(
    target_app_name: &str,
    expected_process_id: i32,
    expected_email: &str,
    timeout: Duration,
) -> &'static str {
    if ensure_fixed_target_app(target_app_name).is_err() {
        return "present";
    }

    let started = Instant::now();
    loop {
        match inspect(target_app_name) {
            Ok(inspection) => {
                let target_running = inspection.target.as_ref().is_some_and(|target| {
                    target.process_id == expected_process_id
                        || target_app_matches(target_app_name, target)
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

fn detect_matching_prompt(
    target_app_name: &str,
    username: &str,
    expected_window_title: Option<&str>,
    expected_process_id: Option<i32>,
) -> anyhow::Result<Option<WindowsPrompt>> {
    let inspection = inspect(target_app_name)?;
    let Some(prompt) = inspection.prompt else {
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
    match prompt.email.as_deref() {
        Some(email) if usernames_match(email, username) => {}
        Some(_) => anyhow::bail!("Credential prompt email does not match this account"),
        None => anyhow::bail!("Credential prompt has no visible email; password was not loaded"),
    }
    Ok(Some(prompt))
}

fn revalidate_prompt(
    target_app_name: &str,
    expected: &WindowsPrompt,
) -> anyhow::Result<WindowsPrompt> {
    let inspection = inspect(target_app_name)?;
    let Some(prompt) = inspection.prompt else {
        anyhow::bail!("credential prompt disappeared before automation");
    };
    if prompt.target.process_id != expected.target.process_id {
        anyhow::bail!("credential prompt process changed before automation");
    }
    if prompt.target.window_handle != 0
        && expected.target.window_handle != 0
        && prompt.target.window_handle != expected.target.window_handle
    {
        anyhow::bail!("credential prompt window changed before automation");
    }
    if !prompt
        .target
        .window_title
        .eq_ignore_ascii_case(&expected.target.window_title)
    {
        anyhow::bail!("credential prompt title changed before automation");
    }
    if prompt.email.as_deref().map(str::to_lowercase)
        != expected.email.as_deref().map(str::to_lowercase)
    {
        anyhow::bail!("credential prompt email changed before automation");
    }
    Ok(prompt)
}

fn prompt_from_window(
    automation: &UIAutomation,
    target: WindowsTarget,
    window: UIElement,
) -> anyhow::Result<Option<WindowsPrompt>> {
    if !is_usable_window(&window) {
        return Ok(None);
    }

    let mut elements = automation
        .create_matcher()
        .from_ref(&window)
        .mode(UIMatcherMode::Raw)
        .depth(UIA_SEARCH_DEPTH)
        .timeout(0)
        .find_all()
        .unwrap_or_default();
    if elements.len() > MAX_ELEMENT_COUNT {
        elements.truncate(MAX_ELEMENT_COUNT);
    }

    let submit_button = select_submit_button(&elements);
    let prompt_text = collect_prompt_text(&target.window_title, &elements);
    let prompt_email = extract_email_like(&prompt_text);
    let login_title = login_title_like(&target.window_title);
    let verified_context = submit_button.is_some() && (prompt_email.is_some() || login_title);

    let password_field = select_password_field(&elements, verified_context);
    let Some(password_field) = password_field else {
        return Ok(None);
    };
    if submit_button.is_none() {
        return Ok(None);
    }
    if prompt_email.is_none() && !login_title {
        return Ok(None);
    }

    let password_field_description = redacted_element_description(&password_field);
    let password_field_role = element_role_text(&password_field);
    Ok(Some(WindowsPrompt {
        target,
        email: prompt_email,
        password_field_description,
        password_field_role,
        password_field,
        submit_button,
    }))
}

fn target_from_window(
    target_app_name: &str,
    window: &UIElement,
) -> Option<(WindowsTarget, String)> {
    let (target, class_name) = target_details_from_window(window)?;

    target_app_matches_with_class(target_app_name, &target, &class_name)
        .then_some((target, class_name))
}

fn target_window_should_be_scanned_for_prompt(
    target_app_name: &str,
    target: &WindowsTarget,
    class_name: &str,
) -> bool {
    !is_builtin_target_name(target_app_name)
        || login_title_like(&target.window_title)
        || credential_dialog_class_like(class_name)
}

fn system_credential_target_from_window(window: &UIElement) -> Option<WindowsTarget> {
    let (target, class_name) = target_details_from_window(window)?;

    system_credential_dialog_matches(&target, &class_name).then_some(target)
}

fn fast_system_credential_prompt(
    automation: &UIAutomation,
) -> anyhow::Result<Option<WindowsPrompt>> {
    for (target, window_handle) in native_system_credential_windows() {
        let Ok(window) = automation.element_from_handle(Handle::from(window_handle)) else {
            continue;
        };
        if let Some(prompt) = prompt_from_window(automation, target, window)? {
            return Ok(Some(prompt));
        }
    }

    Ok(None)
}

fn target_details_from_window(window: &UIElement) -> Option<(WindowsTarget, String)> {
    if !is_usable_window(window) {
        return None;
    }

    let process_id = window.get_process_id().ok()? as i32;
    let process_path = process_image_path(process_id as u32).unwrap_or_default();
    let process_name = process_name_from_path(&process_path)
        .trim()
        .is_empty()
        .then(|| process_name_from_snapshot(process_id as u32))
        .flatten()
        .unwrap_or_else(|| process_name_from_path(&process_path));
    let window_title = window.get_name().unwrap_or_default();
    let window_handle = window
        .get_native_window_handle()
        .ok()
        .map(Into::<isize>::into)
        .unwrap_or_default();
    let class_name = window.get_classname().unwrap_or_default();

    let target = WindowsTarget {
        process_id,
        process_name,
        process_path,
        window_title,
        window_handle,
        frontmost: window_frontmost(window),
    };

    Some((target, class_name))
}

fn native_system_credential_windows() -> Vec<(WindowsTarget, isize)> {
    let mut candidates = Vec::<(WindowsTarget, isize)>::new();
    unsafe {
        let _ = EnumWindows(
            Some(enum_native_system_credential_window),
            LPARAM(&mut candidates as *mut _ as isize),
        );
    }
    candidates.sort_by_key(|(target, _)| !window_handle_is_foreground(target.window_handle));
    candidates
}

unsafe extern "system" fn enum_native_system_credential_window(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let candidates = unsafe { &mut *(lparam.0 as *mut Vec<(WindowsTarget, isize)>) };

    if !unsafe { IsWindowVisible(hwnd) }.as_bool() {
        return true.into();
    }

    let mut rect = RECT::default();
    if unsafe { GetWindowRect(hwnd, &mut rect) }.is_err()
        || rect.right - rect.left <= 20
        || rect.bottom - rect.top <= 20
    {
        return true.into();
    }

    let title = native_window_text(hwnd);
    let class_name = native_window_class(hwnd);
    if !credential_dialog_title_like(&title) || !credential_dialog_class_like(&class_name) {
        return true.into();
    }

    let mut process_id = 0_u32;
    unsafe {
        GetWindowThreadProcessId(hwnd, Some(&mut process_id));
    }
    if process_id == 0 {
        return true.into();
    }

    let process_path = process_image_path(process_id).unwrap_or_default();
    let process_name = process_name_from_path(&process_path)
        .trim()
        .is_empty()
        .then(|| process_name_from_snapshot(process_id))
        .flatten()
        .unwrap_or_else(|| process_name_from_path(&process_path));
    let window_handle = hwnd.0.addr() as isize;
    let target = WindowsTarget {
        process_id: process_id as i32,
        process_name,
        process_path,
        window_title: title,
        window_handle,
        frontmost: window_handle_is_foreground(window_handle),
    };

    if system_credential_dialog_matches(&target, &class_name) {
        candidates.push((target, window_handle));
    }

    true.into()
}

fn native_window_text(hwnd: HWND) -> String {
    let mut buffer = [0_u16; 512];
    let len = unsafe { GetWindowTextW(hwnd, &mut buffer) };
    wide_buffer_to_string(&buffer, len.max(0) as usize)
}

fn native_window_class(hwnd: HWND) -> String {
    let mut buffer = [0_u16; 256];
    let len = unsafe { GetClassNameW(hwnd, &mut buffer) };
    wide_buffer_to_string(&buffer, len.max(0) as usize)
}

fn wide_buffer_to_string(buffer: &[u16], len: usize) -> String {
    String::from_utf16_lossy(&buffer[..len.min(buffer.len())])
}

fn is_usable_window(window: &UIElement) -> bool {
    if window.is_offscreen().unwrap_or(true) || !window.is_enabled().unwrap_or(false) {
        return false;
    }
    window
        .get_bounding_rectangle()
        .map(|rect| rect.get_width() > 20 && rect.get_height() > 20)
        .unwrap_or(true)
}

fn window_frontmost(window: &UIElement) -> bool {
    let handle = window
        .get_native_window_handle()
        .ok()
        .map(Into::<isize>::into)
        .unwrap_or_default();
    if handle == 0 {
        return false;
    }
    if window_handle_is_foreground(handle) {
        return true;
    }

    unsafe {
        let foreground = GetForegroundWindow();
        let mut foreground_pid = 0_u32;
        GetWindowThreadProcessId(foreground, Some(&mut foreground_pid));
        window
            .get_process_id()
            .is_ok_and(|pid| pid != 0 && pid == foreground_pid)
    }
}

fn window_handle_is_foreground(window_handle: isize) -> bool {
    if window_handle == 0 {
        return false;
    }

    unsafe {
        let foreground = GetForegroundWindow();
        let foreground_handle: isize = foreground.0.addr() as isize;
        foreground_handle == window_handle
    }
}

fn wait_for_foreground_window(window_handle: isize, timeout: Duration) -> bool {
    let started = Instant::now();
    loop {
        if window_handle_is_foreground(window_handle) {
            return true;
        }
        if started.elapsed() >= timeout {
            return false;
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn foreground_process_id() -> Option<i32> {
    unsafe {
        let foreground = GetForegroundWindow();
        let mut process_id = 0_u32;
        GetWindowThreadProcessId(foreground, Some(&mut process_id));
        (process_id != 0).then_some(process_id as i32)
    }
}

fn target_accepts_keyboard_input(target: &WindowsTarget) -> bool {
    if target_is_system_credential_prompt(target) {
        return window_handle_is_foreground(target.window_handle);
    }

    window_handle_is_foreground(target.window_handle)
        || foreground_process_id().is_some_and(|process_id| process_id == target.process_id)
}

#[derive(Debug, Clone, Copy)]
struct PasswordFocusResult {
    verified: bool,
}

fn focus_password_field(prompt: &WindowsPrompt) -> anyhow::Result<PasswordFocusResult> {
    if prompt.password_field.try_focus() {
        thread::sleep(Duration::from_millis(FOCUS_SETTLE_MS));
    } else {
        prompt.password_field.set_focus().ok();
        thread::sleep(Duration::from_millis(FOCUS_SETTLE_MS));
    }

    if prompt.password_field.has_keyboard_focus().unwrap_or(false) {
        return Ok(PasswordFocusResult { verified: true });
    }

    let clicked = prompt.password_field.click().is_ok();
    if clicked {
        thread::sleep(Duration::from_millis(FOCUS_SETTLE_MS));
    }

    let verified = prompt.password_field.has_keyboard_focus().unwrap_or(false);
    if verified {
        return Ok(PasswordFocusResult { verified: true });
    }

    if clicked && target_accepts_keyboard_input(&prompt.target) {
        return Ok(PasswordFocusResult { verified: false });
    }

    anyhow::bail!("password field could not be focused");
}

fn wait_for_submit_ready(
    target_app_name: &str,
    mut prompt: WindowsPrompt,
    timeout: Duration,
) -> WindowsPrompt {
    let started = Instant::now();
    loop {
        if prompt
            .submit_button
            .as_ref()
            .is_some_and(|button| button.is_enabled().unwrap_or(false))
        {
            return prompt;
        }

        if started.elapsed() >= timeout {
            return prompt;
        }

        thread::sleep(Duration::from_millis(75));
        if let Ok(next_prompt) = revalidate_prompt(target_app_name, &prompt) {
            prompt = next_prompt;
        }
    }
}

fn select_password_field(elements: &[UIElement], verified_context: bool) -> Option<UIElement> {
    elements
        .iter()
        .find(|element| is_native_password_field(element))
        .cloned()
        .or_else(|| {
            verified_context.then(|| {
                elements
                    .iter()
                    .find(|element| is_password_like_edit(element))
                    .cloned()
            })?
        })
}

fn select_submit_button(elements: &[UIElement]) -> Option<UIElement> {
    let buttons = elements
        .iter()
        .filter(|element| element.get_control_type().ok() == Some(ControlType::Button))
        .filter(|element| !element.is_offscreen().unwrap_or(true))
        .collect::<Vec<_>>();

    buttons
        .iter()
        .find(|element| {
            let text = submit_button_text(element);
            element.is_enabled().unwrap_or(false) && submit_label_rank(&text) == Some(0)
        })
        .copied()
        .cloned()
        .or_else(|| {
            buttons
                .iter()
                .find(|element| {
                    let text = submit_button_text(element);
                    element.is_enabled().unwrap_or(false) && is_preferred_submit_label(&text)
                })
                .copied()
                .cloned()
        })
        .or_else(|| {
            buttons
                .iter()
                .find(|element| {
                    let text = submit_button_text(element);
                    submit_label_rank(&text) == Some(0)
                })
                .copied()
                .cloned()
        })
        .or_else(|| {
            buttons
                .iter()
                .find(|element| {
                    let text = submit_button_text(element);
                    is_preferred_submit_label(&text)
                })
                .copied()
                .cloned()
        })
}

fn submit_button_text(element: &UIElement) -> String {
    let mut text = String::new();
    push_text(&mut text, element.get_name().ok());
    push_text(&mut text, element.get_automation_id().ok());
    push_text(&mut text, element.get_help_text().ok());
    push_text(&mut text, element.get_item_status().ok());
    text
}

fn collect_prompt_text(window_title: &str, elements: &[UIElement]) -> String {
    let mut text = String::from(window_title);
    for element in elements {
        if should_skip_prompt_text(element) {
            continue;
        }

        push_text(&mut text, element.get_name().ok());
        push_text(&mut text, element.get_help_text().ok());
        push_text(&mut text, element.get_item_status().ok());

        if element.get_control_type().ok() == Some(ControlType::Edit) {
            if let Ok(value) = element.get_pattern::<UIValuePattern>() {
                push_text(&mut text, value.get_value().ok());
            }
        }
    }
    text
}

fn should_skip_prompt_text(element: &UIElement) -> bool {
    is_native_password_field(element) || is_password_like_edit(element)
}

fn is_native_password_field(element: &UIElement) -> bool {
    element.get_control_type().ok() == Some(ControlType::Edit)
        && element.is_password().unwrap_or(false)
        && !element.is_offscreen().unwrap_or(true)
        && element.is_enabled().unwrap_or(false)
}

fn is_password_like_edit(element: &UIElement) -> bool {
    element.get_control_type().ok() == Some(ControlType::Edit)
        && !element.is_offscreen().unwrap_or(true)
        && element.is_enabled().unwrap_or(false)
        && text_contains_password_cue(&element_label_text(element))
}

fn element_label_text(element: &UIElement) -> String {
    let mut text = String::new();
    push_text(&mut text, element.get_name().ok());
    push_text(&mut text, element.get_help_text().ok());
    push_text(&mut text, element.get_automation_id().ok());
    push_text(&mut text, element.get_classname().ok());
    push_text(&mut text, element.get_localized_control_type().ok());
    if let Ok(label) = element.get_labeled_by() {
        push_text(&mut text, label.get_name().ok());
    }
    text
}

fn element_role_text(element: &UIElement) -> String {
    let control_type = element
        .get_control_type()
        .map(|control_type| format!("{control_type:?}"))
        .unwrap_or_else(|_| "unknown".to_string());
    let localized = element.get_localized_control_type().unwrap_or_default();
    let class = element.get_classname().unwrap_or_default();
    [control_type, localized, class]
        .into_iter()
        .filter(|part| !part.trim().is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

fn redacted_element_description(element: &UIElement) -> String {
    let role = element_role_text(element);
    if role.trim().is_empty() {
        "password field".to_string()
    } else {
        format!("password field ({role})")
    }
}

fn push_text(target: &mut String, value: Option<String>) {
    if let Some(value) = value.map(|value| value.trim().to_string()) {
        if !value.is_empty() {
            target.push(' ');
            target.push_str(&value);
        }
    }
}

fn process_image_path(process_id: u32) -> Option<String> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, process_id).ok()?;
        let mut buffer = vec![0_u16; 32768];
        let mut len = buffer.len() as u32;
        let result = QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(buffer.as_mut_ptr()),
            &mut len,
        );
        let _ = CloseHandle(handle);
        result.ok()?;
        Some(String::from_utf16_lossy(&buffer[..len as usize]))
    }
}

fn process_name_from_path(path: &str) -> String {
    Path::new(path)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or_default()
        .to_string()
}

fn process_name_from_snapshot(process_id: u32) -> Option<String> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;
        let mut entry = PROCESSENTRY32W::default();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        let mut found = Process32FirstW(snapshot, &mut entry).is_ok();
        while found {
            if entry.th32ProcessID == process_id {
                let _ = CloseHandle(snapshot);
                return Some(process_name_from_exe_file(&entry.szExeFile));
            }
            found = Process32NextW(snapshot, &mut entry).is_ok();
        }

        let _ = CloseHandle(snapshot);
        None
    }
}

fn running_target_process(target_app_name: &str) -> Option<WindowsTarget> {
    let aliases = target_aliases(target_app_name);
    if aliases.is_empty() {
        return None;
    }

    running_processes()?
        .into_iter()
        .find_map(|(process_id, process_name)| {
            let normalized = normalized_identifier(
                Path::new(&process_name)
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .unwrap_or(&process_name),
            );
            aliases.contains(&normalized).then(|| WindowsTarget {
                process_id: process_id as i32,
                process_name: process_name_from_path(&process_name)
                    .trim()
                    .is_empty()
                    .then(|| Some(process_name.clone()))
                    .flatten()
                    .unwrap_or_else(|| process_name_from_path(&process_name)),
                process_path: String::new(),
                window_title: target_app_name.to_string(),
                window_handle: 0,
                frontmost: false,
            })
        })
}

fn running_processes() -> Option<Vec<(u32, String)>> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;
        let mut entry = PROCESSENTRY32W::default();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        let mut processes = Vec::new();
        let mut found = Process32FirstW(snapshot, &mut entry).is_ok();
        while found {
            processes.push((entry.th32ProcessID, process_entry_name(&entry)));
            found = Process32NextW(snapshot, &mut entry).is_ok();
        }

        let _ = CloseHandle(snapshot);
        Some(processes)
    }
}

fn process_entry_name(entry: &PROCESSENTRY32W) -> String {
    process_name_from_exe_file(&entry.szExeFile)
}

fn process_name_from_exe_file(exe_file: &[u16]) -> String {
    let len = exe_file
        .iter()
        .position(|c| *c == 0)
        .unwrap_or(exe_file.len());
    Path::new(&String::from_utf16_lossy(&exe_file[..len]))
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or_default()
        .to_string()
}

fn target_app_matches(target_app_name: &str, target: &WindowsTarget) -> bool {
    target_app_matches_with_class(target_app_name, target, "")
}

fn target_app_matches_with_class(
    target_app_name: &str,
    target: &WindowsTarget,
    class_name: &str,
) -> bool {
    let aliases = target_aliases(target_app_name);
    let process_name = normalized_identifier(&target.process_name);
    let title = target.window_title.to_lowercase();
    let class_name = normalized_identifier(class_name);
    let path = target.process_path.to_lowercase();

    let process_matches = aliases
        .iter()
        .any(|alias| !alias.is_empty() && (process_name == *alias || class_name == *alias));
    let title_matches = aliases.iter().any(|alias| {
        !alias.is_empty()
            && title
                .split(|c: char| !(c.is_alphanumeric() || c == ' '))
                .any(|part| normalized_identifier(part) == *alias)
    });

    if is_builtin_target_name(target_app_name) {
        let hosted_store_window_matches = process_name == "applicationframehost"
            && trusted_microsoft_rdp_path_hint(&path)
            && aliases
                .iter()
                .any(|alias| !alias.is_empty() && normalized_identifier(&title).contains(alias));
        (process_matches && trusted_microsoft_rdp_path_hint(&path)) || hosted_store_window_matches
    } else {
        process_matches || title_matches
    }
}

fn target_aliases(target_app_name: &str) -> Vec<String> {
    let mut aliases = Vec::new();
    let configured = normalized_identifier(target_app_name);
    if !configured.is_empty() {
        aliases.push(configured.clone());
    }

    match configured.as_str() {
        "windowsapp" => aliases.extend([
            "windowsapp".to_string(),
            "windows365".to_string(),
            "msrdc".to_string(),
            "msrdcw".to_string(),
            "rdclientwinstore".to_string(),
            "mstsc".to_string(),
        ]),
        _ => {}
    }

    aliases.sort();
    aliases.dedup();
    aliases
}

fn is_builtin_target_name(target_app_name: &str) -> bool {
    matches!(
        normalized_identifier(target_app_name).as_str(),
        "windowsapp"
    )
}

fn ensure_fixed_target_app(target_app_name: &str) -> anyhow::Result<()> {
    if normalized_identifier(target_app_name)
        == normalized_identifier(crate::config::TARGET_APP_NAME)
    {
        Ok(())
    } else {
        anyhow::bail!("Only Windows App is supported")
    }
}

fn trusted_microsoft_rdp_path_hint(path: &str) -> bool {
    path.contains("\\windowsapps\\microsoft")
        || path.contains("\\program files\\remote desktop\\")
        || path.ends_with("\\windows\\system32\\mstsc.exe")
        || path.ends_with("\\windows\\syswow64\\mstsc.exe")
        || path.ends_with("\\windows\\system32\\applicationframehost.exe")
        || path.ends_with("\\windows\\syswow64\\applicationframehost.exe")
}

fn system_credential_dialog_matches(target: &WindowsTarget, class_name: &str) -> bool {
    credential_dialog_title_like(&target.window_title)
        && trusted_windows_credential_broker(target)
        && credential_dialog_class_like(class_name)
}

pub(crate) fn target_is_system_credential_prompt(target: &WindowsTarget) -> bool {
    credential_dialog_title_like(&target.window_title) && trusted_windows_credential_broker(target)
}

fn credential_dialog_title_like(title: &str) -> bool {
    contains_keyword(title, "Windows Security") || contains_keyword(title, "Enter your credentials")
}

fn credential_dialog_class_like(class_name: &str) -> bool {
    let class_name = normalized_identifier(class_name);
    class_name.contains("credential")
        || class_name.contains("windowssecurity")
        || class_name.contains("corewindow")
        || class_name.contains("xaml")
}

fn trusted_windows_credential_broker_path(path: &str) -> bool {
    let path = path.to_lowercase();
    path.ends_with("\\windows\\system32\\credentialuibroker.exe")
        || path.ends_with("\\windows\\syswow64\\credentialuibroker.exe")
}

fn trusted_windows_credential_broker(target: &WindowsTarget) -> bool {
    trusted_windows_credential_broker_path(&target.process_path)
        || (target.process_path.trim().is_empty()
            && normalized_identifier(&target.process_name) == "credentialuibroker")
}

fn normalized_identifier(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(|c| c.to_lowercase())
        .collect()
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

fn is_preferred_submit_label(label: &str) -> bool {
    submit_label_rank(label).is_some()
}

fn submit_label_rank(label: &str) -> Option<u8> {
    let label = normalized_submit_label(label);
    if label.is_empty() {
        return None;
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
        return Some(0);
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

fn text_contains_password_cue(text: &str) -> bool {
    PASSWORD_CUES
        .iter()
        .any(|cue| text.to_lowercase().contains(cue))
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

fn extract_email_like(text: &str) -> Option<String> {
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
    "Windows Security",
];

const NON_SESSION_TITLE_KEYWORDS: &[&str] = &[
    "windows app",
    "remote desktop",
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
    "windows security",
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

const SUBMIT_LABELS: &[&str] = &[
    "Sign in",
    "Sign In",
    "Log in",
    "Login",
    "Log on",
    "Log On",
    "Connect",
    "Continue",
    "Next",
    "Submit",
    "OK",
    "Ok",
    "Done",
    "Войти",
    "Подключиться",
    "Продолжить",
    "Далее",
];

#[cfg(test)]
mod tests {
    use super::{
        contains_keyword, credential_dialog_title_like, ensure_fixed_target_app,
        extract_email_like, is_preferred_submit_label, is_probable_session_window_title,
        login_title_like, normalized_identifier, system_credential_dialog_matches, target_aliases,
        text_contains_password_cue, WindowsTarget,
    };

    #[test]
    fn lower_level_windows_target_is_fixed_to_windows_app() {
        assert!(ensure_fixed_target_app("Windows App").is_ok());
        assert!(ensure_fixed_target_app("Microsoft Remote Desktop").is_err());
        assert!(ensure_fixed_target_app("Custom App").is_err());
    }

    #[test]
    fn windows_target_aliases_include_known_rdp_clients() {
        let aliases = target_aliases("Windows App");

        assert!(aliases.contains(&"windowsapp".to_string()));
        assert!(aliases.contains(&"windows365".to_string()));
        assert!(aliases.contains(&"msrdc".to_string()));
        assert!(aliases.contains(&"mstsc".to_string()));
    }

    #[test]
    fn helper_text_matching_keeps_email_and_password_rules() {
        assert_eq!(normalized_identifier("Windows App"), "windowsapp");
        assert!(contains_keyword("Windows Security - Sign in", "Sign in"));
        assert_eq!(
            extract_email_like("Account user.name+rdp@example.com."),
            Some("user.name+rdp@example.com".to_string())
        );
        assert!(text_contains_password_cue("Enter hasło"));
    }

    #[test]
    fn email_extraction_ignores_uuid_text_around_visible_account() {
        assert_eq!(
            extract_email_like(
                "These credentials will be used to connect to 8d4d52b8-72a4-4688-87fe-1f3fd2e2911b. user.name+rdp@example.com",
            ),
            Some("user.name+rdp@example.com".to_string())
        );
        assert_eq!(
            extract_email_like("8d4d52b8-72a4-4688-87fe-1f3fd2e2911b"),
            None
        );
        assert_eq!(
            extract_email_like("id=8d4d52b8-72a4-4688-87fe-1f3fd2e2911b\nuser@example.com"),
            Some("user@example.com".to_string())
        );
    }

    #[test]
    fn submit_labels_accept_positive_actions() {
        assert!(is_preferred_submit_label("Sign in"));
        assert!(is_preferred_submit_label("OK"));
        assert!(is_preferred_submit_label("&OK"));
        assert!(is_preferred_submit_label("_OK"));
        assert!(is_preferred_submit_label("OK button"));
        assert!(is_preferred_submit_label("OK OkButton"));
        assert!(!is_preferred_submit_label("Cancel"));
        assert!(!is_preferred_submit_label("More choices"));
    }

    fn trusted_windows_security_target() -> WindowsTarget {
        WindowsTarget {
            process_id: 42,
            process_name: "CredentialUIBroker".to_string(),
            process_path: r"C:\Windows\System32\CredentialUIBroker.exe".to_string(),
            window_title: "Windows Security".to_string(),
            window_handle: 7,
            frontmost: true,
        }
    }

    #[test]
    fn system_windows_security_credential_dialog_is_trusted_prompt_host() {
        let target = trusted_windows_security_target();

        assert!(system_credential_dialog_matches(
            &target,
            "Credential Dialog Xaml Host"
        ));
        assert!(system_credential_dialog_matches(
            &target,
            "Windows.UI.Core.CoreWindow"
        ));
    }

    #[test]
    fn target_is_system_credential_prompt_accepts_trusted_windows_security_broker() {
        let target = trusted_windows_security_target();

        assert!(super::target_is_system_credential_prompt(&target));
    }

    #[test]
    fn system_windows_security_dialog_requires_system_broker_path() {
        let target = WindowsTarget {
            process_id: 42,
            process_name: "CredentialUIBroker".to_string(),
            process_path: r"C:\Users\me\CredentialUIBroker.exe".to_string(),
            window_title: "Windows Security".to_string(),
            window_handle: 7,
            frontmost: true,
        };

        assert!(!system_credential_dialog_matches(
            &target,
            "Credential Dialog Xaml Host"
        ));
    }

    #[test]
    fn windows_security_title_is_login_prompt_not_session() {
        assert!(credential_dialog_title_like("Windows Security"));
        assert!(credential_dialog_title_like("Windows Security - Sign in"));
        assert!(credential_dialog_title_like("Enter your credentials"));
        assert!(!credential_dialog_title_like("Other Security"));
        assert!(login_title_like("Windows Security"));
        assert!(login_title_like("Windows Security - Sign in"));
        assert!(!is_probable_session_window_title("Windows Security"));
    }

    #[test]
    fn system_windows_security_dialog_accepts_syswow64_broker_path() {
        let target = WindowsTarget {
            process_id: 42,
            process_name: "CredentialUIBroker".to_string(),
            process_path: r"C:\Windows\SysWOW64\CredentialUIBroker.exe".to_string(),
            window_title: "Windows Security".to_string(),
            window_handle: 7,
            frontmost: true,
        };

        assert!(system_credential_dialog_matches(
            &target,
            "Credential Dialog Xaml Host"
        ));
    }

    #[test]
    fn system_windows_security_dialog_requires_windows_security_title() {
        let target = WindowsTarget {
            process_id: 42,
            process_name: "CredentialUIBroker".to_string(),
            process_path: r"C:\Windows\System32\CredentialUIBroker.exe".to_string(),
            window_title: "Other Security".to_string(),
            window_handle: 7,
            frontmost: true,
        };

        assert!(!system_credential_dialog_matches(
            &target,
            "Credential Dialog Xaml Host"
        ));
    }
}
