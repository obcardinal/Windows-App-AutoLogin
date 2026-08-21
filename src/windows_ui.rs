use crate::config::Config;
use crate::monitor::MonitorStatus;
use anyhow::Context;
use sha2::{Digest, Sha256};
use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};
use uiautomation::core::UIMatcherMode;
use uiautomation::patterns::{UIInvokePattern, UIValuePattern};
use uiautomation::types::{ControlType, Handle};
use uiautomation::{UIAutomation, UIElement};
use windows::core::{BOOL, BSTR, GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, APPMODEL_ERROR_NO_PACKAGE, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, HANDLE, HWND,
    LPARAM, RECT,
};
use windows::Win32::Security::Cryptography::{
    CertGetNameStringW, CERT_CONTEXT, CERT_NAME_SIMPLE_DISPLAY_TYPE,
};
use windows::Win32::Security::WinTrust::{
    WTHelperGetProvCertFromChain, WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData,
    WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0,
    WINTRUST_FILE_INFO, WTD_CHOICE_FILE, WTD_DISABLE_MD2_MD4,
    WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, WTD_REVOKE_WHOLECHAIN, WTD_SAFER_FLAG,
    WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UICONTEXT_EXECUTE, WTD_UI_NONE,
};
use windows::Win32::Storage::Packaging::Appx::GetPackageFullName;
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::SystemInformation::{GetSystemDirectoryW, GetSystemWow64DirectoryW};
use windows::Win32::System::Threading::{
    AttachThreadInput, GetCurrentThreadId, OpenProcess, QueryFullProcessImageNameW,
    PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::Win32::UI::Accessibility::IUIAutomationValuePattern;
use windows::Win32::UI::Shell::{
    FOLDERID_ProgramFiles, FOLDERID_ProgramFilesX64, FOLDERID_ProgramFilesX86,
    SHGetKnownFolderPath, KF_FLAG_DEFAULT,
};
use windows::Win32::UI::WindowsAndMessaging::{
    BringWindowToTop, EnumWindows, GetAncestor, GetClassNameW, GetForegroundWindow, GetWindowRect,
    GetWindowTextW, GetWindowThreadProcessId, IsWindowVisible, SetForegroundWindow, ShowWindow,
    GA_ROOT, SW_RESTORE,
};
use zeroize::{Zeroize, Zeroizing};

const MAX_ELEMENT_COUNT: usize = 900;
const UIA_SEARCH_DEPTH: u32 = 12;
const SUBMIT_READY_TIMEOUT_MS: u64 = 1500;
const PASSWORD_CLEANUP_ATTEMPTS: usize = 3;
const PASSWORD_CLEANUP_RETRY_MS: u64 = 50;
const ACTIVATION_INITIAL_TIMEOUT_MS: u64 = 250;
const ACTIVATION_ATTACHED_TIMEOUT_MS: u64 = 750;

/// Owns the BSTR passed to UI Automation and scrubs its UTF-16 allocation
/// before `BSTR` releases it. `BSTR::from(&str)` uses a temporary `Vec<u16>`
/// and then frees the BSTR without clearing either allocation, so secrets must
/// take this explicit path instead.
struct ZeroizingBstr(BSTR);

impl ZeroizingBstr {
    fn from_secret(value: &str) -> Self {
        let wide = Zeroizing::new(value.encode_utf16().collect::<Vec<_>>());
        Self(BSTR::from_wide(wide.as_slice()))
    }

    fn as_bstr(&self) -> &BSTR {
        &self.0
    }
}

impl Drop for ZeroizingBstr {
    fn drop(&mut self) {
        if !self.0.is_empty() {
            // SAFETY: this wrapper uniquely owns the BSTR allocation and the
            // synchronous COM call has returned before it is dropped.
            unsafe {
                std::slice::from_raw_parts_mut(self.0.as_ptr().cast_mut(), self.0.len()).zeroize();
            }
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct WindowsTarget {
    pub(crate) process_id: i32,
    pub(crate) process_name: String,
    pub(crate) process_path: String,
    pub(crate) window_title: String,
    pub(crate) window_handle: isize,
    pub(crate) frontmost: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WindowsMicrosoftTargetKind {
    SystemMstsc,
    RemoteDesktopInstall,
    WindowsAppsPackage,
    CredentialBroker,
}

#[cfg(test)]
type TestWindowsTargetIdentityOverride = fn(&WindowsTarget, WindowsMicrosoftTargetKind) -> bool;

#[cfg(test)]
thread_local! {
    static WINDOWS_TARGET_IDENTITY_OVERRIDE: std::cell::RefCell<Option<TestWindowsTargetIdentityOverride>> =
        std::cell::RefCell::new(Some(default_test_windows_target_identity));
}

#[cfg(test)]
fn default_test_windows_target_identity(
    _target: &WindowsTarget,
    _kind: WindowsMicrosoftTargetKind,
) -> bool {
    true
}

#[cfg(test)]
fn windows_target_identity_override_result(
    target: &WindowsTarget,
    kind: WindowsMicrosoftTargetKind,
) -> Option<bool> {
    WINDOWS_TARGET_IDENTITY_OVERRIDE.with(|override_fn| {
        override_fn
            .borrow()
            .map(|override_fn| override_fn(target, kind))
    })
}

#[cfg(test)]
struct WindowsTargetIdentityOverrideGuard(Option<TestWindowsTargetIdentityOverride>);

#[cfg(test)]
impl Drop for WindowsTargetIdentityOverrideGuard {
    fn drop(&mut self) {
        let previous = self.0;
        WINDOWS_TARGET_IDENTITY_OVERRIDE.with(|override_fn| {
            *override_fn.borrow_mut() = previous;
        });
    }
}

#[cfg(test)]
fn set_windows_target_identity_override(
    override_fn: TestWindowsTargetIdentityOverride,
) -> WindowsTargetIdentityOverrideGuard {
    WINDOWS_TARGET_IDENTITY_OVERRIDE.with(|current| {
        let previous = current.replace(Some(override_fn));
        WindowsTargetIdentityOverrideGuard(previous)
    })
}

#[derive(Debug, Clone)]
pub(crate) struct WindowsPrompt {
    pub(crate) target: WindowsTarget,
    pub(crate) email: Option<String>,
    pub(crate) password_field_description: String,
    pub(crate) password_field_role: String,
    trust: WindowsPromptTrust,
    prompt_root: UIElement,
    password_field: UIElement,
    submit_button: Option<UIElement>,
    identity_elements: Vec<UIElement>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WindowsPromptTrust {
    TrustedTargetProcess,
    CredentialBrokerBoundToTarget,
}

impl WindowsPromptTrust {
    fn label(self) -> &'static str {
        match self {
            Self::TrustedTargetProcess => "trusted_target_process",
            Self::CredentialBrokerBoundToTarget => "credential_broker_bound_to_target",
        }
    }
}

impl WindowsPrompt {
    pub(crate) fn trust_label(&self) -> &'static str {
        self.trust.label()
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct WindowsInspection {
    pub(crate) target: Option<WindowsTarget>,
    pub(crate) prompt: Option<WindowsPrompt>,
    pub(crate) has_session: bool,
    pub(crate) session_windows: Vec<WindowsSessionWindow>,
    pub(crate) password_like_plain_edit_rejected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WindowsSessionWindow {
    process_id: i32,
    window_title: String,
    window_handle: isize,
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
    pub(crate) filled_prompt: WindowsPrompt,
}

#[derive(Debug, Clone)]
pub(crate) struct WindowsSubmitResult {
    pub(crate) submit_method: &'static str,
    pub(crate) submit_status: &'static str,
    pub(crate) axpress_attempted: bool,
    pub(crate) axpress_result: &'static str,
    pub(crate) enter_fallback_attempted: bool,
    pub(crate) enter_fallback_result: &'static str,
    pub(crate) submitted_prompt: Option<WindowsSubmittedPrompt>,
}

#[derive(Debug, Clone)]
pub(crate) struct WindowsSubmittedPrompt {
    process_id: i32,
    prompt_window_handle: isize,
    prompt_window_title: String,
    email: String,
    pre_submit_session_windows: Vec<WindowsSessionWindow>,
}

pub(crate) fn check_status(config: &Config) -> MonitorStatus {
    match inspect(&config.macos_app_name) {
        Ok(inspection) => {
            if inspection.target.is_some() {
                if let Some(prompt) = inspection.prompt {
                    return MonitorStatus::LoginWindowDetected {
                        process_id: prompt.target.process_id,
                        window_handle: prompt.target.window_handle,
                        window_title: prompt.target.window_title,
                        prompt_email: prompt.email,
                        prompt_origin: "windows".to_string(),
                    };
                }
            } else if inspection.prompt.is_some() {
                return MonitorStatus::ProcessNotFound;
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

pub(crate) fn inspect(target_app_name: &str) -> anyhow::Result<WindowsInspection> {
    ensure_fixed_target_app(target_app_name)?;
    let automation = UIAutomation::new().or_else(|_| UIAutomation::new_direct())?;
    let trusted_running_target = is_builtin_target_name(target_app_name)
        .then(|| running_target_process(target_app_name))
        .flatten();

    if trusted_running_target.is_some() {
        if let Some(prompt) = fast_system_credential_prompt(&automation, target_app_name)? {
            return Ok(WindowsInspection {
                target: trusted_running_target.clone(),
                prompt: Some(prompt),
                has_session: false,
                session_windows: Vec::new(),
                password_like_plain_edit_rejected: false,
            });
        }
    }

    let mut inspection = WindowsInspection {
        target: trusted_running_target,
        ..Default::default()
    };
    let mut trusted_target_seen = inspection.target.is_some();
    let mut target_prompt: Option<WindowsPrompt> = None;
    let mut system_prompt: Option<WindowsPrompt> = None;

    for candidate in native_visible_windows() {
        if target_app_matches_with_class(target_app_name, &candidate.target, &candidate.class_name)
        {
            trusted_target_seen = true;
            if inspection.target.is_none() {
                inspection.target = Some(candidate.target.clone());
            }

            if target_window_should_be_scanned_for_prompt(
                target_app_name,
                &candidate.target,
                &candidate.class_name,
            ) {
                let Ok(window) =
                    automation.element_from_handle(Handle::from(candidate.window_handle))
                else {
                    continue;
                };
                let prompt_window = inspect_prompt_window(
                    &automation,
                    candidate.target.clone(),
                    WindowsPromptTrust::TrustedTargetProcess,
                    window,
                )?;
                inspection.password_like_plain_edit_rejected |=
                    prompt_window.password_like_plain_edit_rejected;
                if let Some(prompt) = prompt_window.prompt {
                    if prompt.target.frontmost {
                        inspection.prompt = Some(prompt);
                        return Ok(inspection);
                    } else if target_prompt.is_none() {
                        target_prompt = Some(prompt);
                    }
                }
            } else if is_probable_session_window_title(&candidate.target.window_title) {
                inspection.has_session = true;
                inspection.session_windows.push(WindowsSessionWindow {
                    process_id: candidate.target.process_id,
                    window_title: candidate.target.window_title.clone(),
                    window_handle: candidate.target.window_handle,
                });
            }

            continue;
        }

        if system_credential_prompt_matches_target(
            target_app_name,
            &candidate.target,
            &candidate.class_name,
            candidate.window_handle,
        ) {
            let Ok(window) = automation.element_from_handle(Handle::from(candidate.window_handle))
            else {
                continue;
            };
            let prompt_window = inspect_prompt_window(
                &automation,
                candidate.target,
                WindowsPromptTrust::CredentialBrokerBoundToTarget,
                window,
            )?;
            inspection.password_like_plain_edit_rejected |=
                prompt_window.password_like_plain_edit_rejected;
            if let Some(prompt) = prompt_window.prompt {
                if window_handle_is_foreground(prompt.target.window_handle) {
                    inspection.prompt = Some(prompt);
                    return Ok(inspection);
                } else if system_prompt.is_none() {
                    system_prompt = Some(prompt);
                }
            }
        }
    }

    let system_prompt = system_prompt.filter(|_| trusted_target_seen);
    inspection.prompt = system_prompt.or(target_prompt);

    Ok(inspection)
}

pub(crate) fn inspect_prompt_snapshot(
    target_app_name: &str,
    process_id: i32,
    window_handle: isize,
    window_title: &str,
    prompt_email: Option<&str>,
) -> anyhow::Result<Option<WindowsPrompt>> {
    ensure_fixed_target_app(target_app_name)?;
    if process_id <= 0 || window_handle == 0 {
        anyhow::bail!("credential prompt snapshot has no exact PID/HWND identity");
    }
    let automation = UIAutomation::new().or_else(|_| UIAutomation::new_direct())?;
    let mut matches = Vec::new();

    for candidate in native_prompt_snapshot_candidates(process_id, window_handle, window_title) {
        let Some(trust) = prompt_candidate_trust(
            target_app_name,
            &candidate.target,
            &candidate.class_name,
            candidate.window_handle,
        ) else {
            continue;
        };

        let Ok(window) = automation.element_from_handle(Handle::from(candidate.window_handle))
        else {
            continue;
        };
        let Some(prompt) = prompt_from_window(&automation, candidate.target, trust, window)? else {
            continue;
        };
        if prompt_matches_snapshot(
            &prompt,
            process_id,
            window_handle,
            window_title,
            prompt_email,
        ) {
            matches.push(prompt);
            if matches.len() > 1 {
                anyhow::bail!("multiple credential prompts match the exact PID/HWND snapshot");
            }
        }
    }

    Ok(matches.pop())
}

pub(crate) fn activate_window(window_handle: isize) -> anyhow::Result<()> {
    if window_handle == 0 {
        anyhow::bail!("target window handle is unavailable");
    }
    if window_handle_is_foreground(window_handle) {
        return Ok(());
    }
    let hwnd = hwnd_from_handle(window_handle);
    if !native_window_is_visible_and_sized(hwnd) {
        anyhow::bail!("target window is not visible");
    }

    request_foreground_window(hwnd);
    if wait_for_foreground_window(
        window_handle,
        Duration::from_millis(ACTIVATION_INITIAL_TIMEOUT_MS),
    ) {
        return Ok(());
    }

    activate_window_with_attached_input(hwnd);
    if wait_for_foreground_window(
        window_handle,
        Duration::from_millis(ACTIVATION_ATTACHED_TIMEOUT_MS),
    ) {
        return Ok(());
    }

    anyhow::bail!("target window could not be made foreground");
}

fn request_foreground_window(hwnd: HWND) {
    unsafe {
        let _ = ShowWindow(hwnd, SW_RESTORE);
        let _ = BringWindowToTop(hwnd);
        let _ = SetForegroundWindow(hwnd);
    }
}

fn activate_window_with_attached_input(hwnd: HWND) {
    let current_thread_id = unsafe { GetCurrentThreadId() };
    let target_thread_id = window_thread_id(hwnd);
    let foreground_thread_id = unsafe {
        let foreground = GetForegroundWindow();
        window_thread_id(foreground)
    };

    let target_attached = set_thread_input_attachment(current_thread_id, target_thread_id, true);
    let foreground_attached = foreground_thread_id != target_thread_id
        && set_thread_input_attachment(current_thread_id, foreground_thread_id, true);

    request_foreground_window(hwnd);

    if foreground_attached {
        let _ = set_thread_input_attachment(current_thread_id, foreground_thread_id, false);
    }
    if target_attached {
        let _ = set_thread_input_attachment(current_thread_id, target_thread_id, false);
    }
}

fn window_thread_id(hwnd: HWND) -> u32 {
    if hwnd.0.addr() == 0 {
        return 0;
    }
    let mut process_id = 0_u32;
    unsafe { GetWindowThreadProcessId(hwnd, Some(&mut process_id)) }
}

fn set_thread_input_attachment(source_thread_id: u32, target_thread_id: u32, attach: bool) -> bool {
    if source_thread_id == 0 || target_thread_id == 0 || source_thread_id == target_thread_id {
        return false;
    }
    unsafe { AttachThreadInput(source_thread_id, target_thread_id, attach).as_bool() }
}

fn hwnd_from_handle(window_handle: isize) -> HWND {
    HWND(std::ptr::with_exposed_provenance_mut(
        window_handle as usize,
    ))
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
    let prompt = revalidate_prompt(target_app_name, prompt)?;
    guard()?;

    match strategy {
        WindowsFillStrategy::DirectSetValue => set_password_value(
            target_app_name,
            &prompt,
            password,
            WindowsFillStrategy::DirectSetValue.label(),
            guard,
        ),
        WindowsFillStrategy::Keyboard => {
            set_password_value(
                target_app_name,
                &prompt,
                password,
                "direct_uia_value_keyboard_safe",
                guard,
            )
            .map_err(|e| {
                anyhow::anyhow!(
                    "keyboard password input is disabled on Windows; direct UIA password fill failed: {e}"
                )
            })
        }
    }
}

fn set_password_value(
    target_app_name: &str,
    prompt: &WindowsPrompt,
    password: &str,
    fill_method: &'static str,
    guard: &dyn Fn() -> anyhow::Result<()>,
) -> anyhow::Result<WindowsFillResult> {
    let (prompt, value) = direct_set_value_pattern_after_final_validation(target_app_name, prompt)?;
    guard()?;
    set_zeroizing_password_value(&value, password)?;
    Ok(WindowsFillResult {
        fill_method,
        fill_status: "ok",
        password_field_focused: prompt.password_field.has_keyboard_focus().unwrap_or(false),
        filled_prompt: prompt,
    })
}

fn set_zeroizing_password_value(value: &UIValuePattern, password: &str) -> anyhow::Result<()> {
    let password_bstr = ZeroizingBstr::from_secret(password);
    let pattern: &IUIAutomationValuePattern = value.as_ref();
    unsafe { pattern.SetValue(password_bstr.as_bstr()) }
        .map_err(|e| anyhow::anyhow!("UIA SetValue failed: {e}"))
}

fn direct_set_value_pattern_after_final_validation(
    target_app_name: &str,
    expected: &WindowsPrompt,
) -> anyhow::Result<(WindowsPrompt, UIValuePattern)> {
    let prompt = revalidate_prompt_for_direct_set_value(target_app_name, expected)?;
    let value = prompt
        .password_field
        .get_pattern::<UIValuePattern>()
        .map_err(|e| anyhow::anyhow!("password field does not expose ValuePattern: {e}"))?;
    if value
        .is_readonly()
        .map_err(|e| anyhow::anyhow!("password field read-only state unavailable: {e}"))?
    {
        anyhow::bail!("password field is read-only");
    }
    ensure_direct_set_value_target_ready(target_app_name, &prompt)?;
    Ok((prompt, value))
}

pub(crate) fn submit_prompt(
    target_app_name: &str,
    prompt: &WindowsPrompt,
    guard: &dyn Fn() -> anyhow::Result<()>,
) -> anyhow::Result<WindowsSubmitResult> {
    activate_window(prompt.target.window_handle)?;
    guard()?;
    let prompt = revalidate_prompt(target_app_name, prompt)?;
    let prompt = wait_for_submit_ready(
        target_app_name,
        prompt,
        Duration::from_millis(SUBMIT_READY_TIMEOUT_MS),
    );
    let prompt = revalidate_prompt(target_app_name, &prompt)?;
    ensure_prompt_sensitive_elements_bound(&prompt)?;
    let pre_submit_session_windows = trusted_session_windows(target_app_name);

    guard()?;
    let prompt = revalidate_prompt(target_app_name, &prompt)?;
    ensure_prompt_sensitive_elements_bound(&prompt)?;
    ensure_prompt_foreground_and_trusted(target_app_name, &prompt, "submit")?;
    let button = prompt
        .submit_button
        .as_ref()
        .filter(|button| button.is_enabled().unwrap_or(false))
        .context("credential prompt submit button changed before Invoke")?;
    let invoke = button
        .get_pattern::<UIInvokePattern>()
        .map_err(|e| anyhow::anyhow!("submit button lost InvokePattern before submit: {e}"))?;
    // Keep cancellation/generation invalidation as the final operation before
    // the single submit side effect. All potentially blocking UIA reads above
    // may have yielded long enough for Stop or ApplyConfig to arrive.
    guard()?;
    invoke
        .invoke()
        .map_err(|e| anyhow::anyhow!("UIA Invoke submit failed: {e}"))?;
    Ok(WindowsSubmitResult {
        submit_method: "invoke",
        submit_status: "ok",
        axpress_attempted: true,
        axpress_result: "ok",
        enter_fallback_attempted: false,
        enter_fallback_result: "disabled",
        submitted_prompt: Some(WindowsSubmittedPrompt::new(
            &prompt,
            pre_submit_session_windows,
        )),
    })
}

pub(crate) fn clear_filled_password(
    target_app_name: &str,
    filled_prompt: &WindowsPrompt,
) -> anyhow::Result<()> {
    let mut last_error = None;
    for attempt in 0..PASSWORD_CLEANUP_ATTEMPTS {
        match clear_original_password_once(target_app_name, filled_prompt) {
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
    target_app_name: &str,
    filled_prompt: &WindowsPrompt,
) -> anyhow::Result<()> {
    let expected = &filled_prompt.target;
    if expected.process_id <= 0 || expected.window_handle == 0 {
        anyhow::bail!("original filled prompt has no exact PID/HWND identity");
    }
    let hwnd = hwnd_from_handle(expected.window_handle);
    if !native_window_is_visible_and_sized(hwnd) {
        anyhow::bail!("original filled prompt window is no longer visible");
    }
    let Some((current_target, class_name)) = target_details_from_hwnd(hwnd) else {
        anyhow::bail!("original filled prompt window disappeared before cleanup");
    };
    if current_target.process_id != expected.process_id
        || current_target.window_handle != expected.window_handle
    {
        anyhow::bail!("original filled prompt PID/HWND identity changed before cleanup");
    }
    ensure_password_cleanup_target_is_trusted(
        target_app_name,
        &current_target,
        &class_name,
        filled_prompt.trust,
    )?;
    let automation = UIAutomation::new().or_else(|_| UIAutomation::new_direct())?;
    if !uia_element_bound_to_prompt_window(
        &automation,
        &filled_prompt.prompt_root,
        &filled_prompt.prompt_root,
        expected,
    ) || !uia_element_bound_to_prompt_window(
        &automation,
        &filled_prompt.password_field,
        &filled_prompt.prompt_root,
        expected,
    ) {
        anyhow::bail!("original filled password element is no longer bound to its PID/HWND/root");
    }
    if !has_native_password_field_identity(&filled_prompt.password_field) {
        anyhow::bail!("original filled password element is no longer a secure field");
    }
    let value = filled_prompt
        .password_field
        .get_pattern::<UIValuePattern>()
        .map_err(|e| anyhow::anyhow!("password field no longer exposes ValuePattern: {e}"))?;
    if value.is_readonly().unwrap_or(true) {
        anyhow::bail!("password field became read-only before cleanup");
    }
    value
        .set_value("")
        .map_err(|e| anyhow::anyhow!("failed to clear filled password field: {e}"))
}

impl WindowsSubmittedPrompt {
    fn new(prompt: &WindowsPrompt, pre_submit_session_windows: Vec<WindowsSessionWindow>) -> Self {
        Self {
            process_id: prompt.target.process_id,
            prompt_window_handle: prompt.target.window_handle,
            prompt_window_title: prompt.target.window_title.clone(),
            email: prompt.email.clone().unwrap_or_default(),
            pre_submit_session_windows,
        }
    }
}

pub(crate) fn post_check_state(
    target_app_name: &str,
    expected_process_id: i32,
    expected_email: &str,
    submitted_prompt: Option<&WindowsSubmittedPrompt>,
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
                    return classify_post_submit_state(
                        prompt.email.as_deref(),
                        target_running,
                        submitted_prompt_has_new_session(
                            submitted_prompt,
                            &inspection.session_windows,
                            expected_process_id,
                            expected_email,
                        ),
                        expected_email,
                    )
                    .unwrap_or("prompt_gone_unknown");
                }

                if let Some(state) = classify_post_submit_state(
                    None,
                    target_running,
                    submitted_prompt_has_new_session(
                        submitted_prompt,
                        &inspection.session_windows,
                        expected_process_id,
                        expected_email,
                    ),
                    expected_email,
                ) {
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

fn submitted_prompt_has_new_session(
    submitted_prompt: Option<&WindowsSubmittedPrompt>,
    session_windows: &[WindowsSessionWindow],
    expected_process_id: i32,
    expected_email: &str,
) -> bool {
    let Some(submitted) = submitted_prompt else {
        return false;
    };
    if submitted.process_id != expected_process_id
        || submitted.prompt_window_handle == 0
        || submitted.prompt_window_title.trim().is_empty()
        || !usernames_match(&submitted.email, expected_email)
    {
        return false;
    }

    session_windows.iter().any(|session| {
        session.process_id == submitted.process_id
            && !submitted
                .pre_submit_session_windows
                .iter()
                .any(|before| same_windows_session_identity(before, session))
    })
}

fn same_windows_session_identity(
    left: &WindowsSessionWindow,
    right: &WindowsSessionWindow,
) -> bool {
    if left.process_id != right.process_id {
        return false;
    }
    if left.window_handle != 0 && right.window_handle != 0 {
        return left.window_handle == right.window_handle;
    }
    left.window_title
        .trim()
        .eq_ignore_ascii_case(right.window_title.trim())
}

fn classify_post_submit_state(
    prompt_email: Option<&str>,
    target_running: bool,
    has_session: bool,
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
    if has_session {
        return Some("authenticated");
    }
    None
}

fn revalidate_prompt(
    target_app_name: &str,
    expected: &WindowsPrompt,
) -> anyhow::Result<WindowsPrompt> {
    let Some(prompt) = inspect_prompt_snapshot(
        target_app_name,
        expected.target.process_id,
        expected.target.window_handle,
        &expected.target.window_title,
        expected.email.as_deref(),
    )?
    else {
        anyhow::bail!("credential prompt disappeared before automation");
    };
    ensure_same_revalidated_prompt(prompt, expected)
}

pub(crate) fn preflight_password_load_prompt(
    target_app_name: &str,
    expected: &WindowsPrompt,
    expected_email: &str,
) -> anyhow::Result<WindowsPrompt> {
    let Some(prompt) = inspect_prompt_snapshot(
        target_app_name,
        expected.target.process_id,
        expected.target.window_handle,
        &expected.target.window_title,
        Some(expected_email),
    )?
    else {
        anyhow::bail!("credential prompt disappeared before password load");
    };
    let prompt = ensure_same_revalidated_prompt(prompt, expected)?;
    if !prompt.target.frontmost {
        anyhow::bail!("credential prompt is not foreground before password load");
    }
    Ok(prompt)
}

pub(crate) fn revalidate_prompt_after_activation(
    target_app_name: &str,
    expected: &WindowsPrompt,
) -> anyhow::Result<WindowsPrompt> {
    let Some(prompt) = inspect_prompt_snapshot(
        target_app_name,
        expected.target.process_id,
        expected.target.window_handle,
        &expected.target.window_title,
        expected.email.as_deref(),
    )?
    else {
        anyhow::bail!("credential prompt disappeared after activation");
    };
    let prompt = ensure_same_revalidated_prompt(prompt, expected)?;
    if !prompt.target.frontmost || !window_handle_is_foreground(prompt.target.window_handle) {
        anyhow::bail!("credential prompt is not foreground after activation");
    }
    Ok(prompt)
}

fn ensure_same_revalidated_prompt(
    prompt: WindowsPrompt,
    expected: &WindowsPrompt,
) -> anyhow::Result<WindowsPrompt> {
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
    let mut prompt = prompt;
    prompt.trust = compatible_revalidated_prompt_trust(prompt.trust, expected.trust)?;
    Ok(prompt)
}

fn compatible_revalidated_prompt_trust(
    current: WindowsPromptTrust,
    expected: WindowsPromptTrust,
) -> anyhow::Result<WindowsPromptTrust> {
    match (current, expected) {
        (WindowsPromptTrust::TrustedTargetProcess, WindowsPromptTrust::TrustedTargetProcess) => {
            Ok(WindowsPromptTrust::TrustedTargetProcess)
        }
        (
            WindowsPromptTrust::CredentialBrokerBoundToTarget,
            WindowsPromptTrust::CredentialBrokerBoundToTarget,
        ) => Ok(WindowsPromptTrust::CredentialBrokerBoundToTarget),
        _ => anyhow::bail!("credential prompt trust changed before automation"),
    }
}

fn revalidate_prompt_for_direct_set_value(
    target_app_name: &str,
    expected: &WindowsPrompt,
) -> anyhow::Result<WindowsPrompt> {
    let Some(prompt) = inspect_prompt_snapshot(
        target_app_name,
        expected.target.process_id,
        expected.target.window_handle,
        &expected.target.window_title,
        expected.email.as_deref(),
    )?
    else {
        anyhow::bail!("credential prompt disappeared before password insertion");
    };
    ensure_same_revalidated_prompt(prompt, expected)
}

fn ensure_direct_set_value_target_ready(
    target_app_name: &str,
    prompt: &WindowsPrompt,
) -> anyhow::Result<()> {
    if prompt.target.window_handle == 0 {
        anyhow::bail!("credential prompt window handle is unavailable before password insertion");
    }
    if !window_handle_is_foreground(prompt.target.window_handle) {
        anyhow::bail!("credential prompt window is not foreground before password insertion");
    }

    let hwnd = hwnd_from_handle(prompt.target.window_handle);
    if !native_window_is_visible_and_sized(hwnd) {
        anyhow::bail!("credential prompt window is not visible before password insertion");
    }
    let Some((current_target, class_name)) = target_details_from_hwnd(hwnd) else {
        anyhow::bail!("credential prompt window disappeared before password insertion");
    };
    ensure_direct_set_value_target_matches_expected(&current_target, &prompt.target)?;
    ensure_direct_set_value_target_is_trusted(
        target_app_name,
        &current_target,
        &class_name,
        prompt.target.window_handle,
        prompt.trust,
    )?;
    ensure_prompt_sensitive_elements_bound(prompt)?;

    if !password_field_ready_for_direct_set_value(&prompt.password_field) {
        anyhow::bail!("password field is not visible and enabled before password insertion");
    }

    Ok(())
}

fn ensure_prompt_foreground_and_trusted(
    target_app_name: &str,
    prompt: &WindowsPrompt,
    action: &str,
) -> anyhow::Result<()> {
    if prompt.target.process_id <= 0 || prompt.target.window_handle == 0 {
        anyhow::bail!("credential prompt has no exact PID/HWND identity before {action}");
    }
    if !window_handle_is_foreground(prompt.target.window_handle) {
        anyhow::bail!("credential prompt is not foreground before {action}");
    }
    let hwnd = hwnd_from_handle(prompt.target.window_handle);
    if !native_window_is_visible_and_sized(hwnd) {
        anyhow::bail!("credential prompt is not visible before {action}");
    }
    let Some((current_target, class_name)) = target_details_from_hwnd(hwnd) else {
        anyhow::bail!("credential prompt disappeared before {action}");
    };
    if current_target.process_id != prompt.target.process_id
        || current_target.window_handle != prompt.target.window_handle
        || !window_title_matches(&current_target.window_title, &prompt.target.window_title)
    {
        anyhow::bail!("credential prompt PID/HWND/title identity changed before {action}");
    }
    ensure_direct_set_value_target_is_trusted(
        target_app_name,
        &current_target,
        &class_name,
        prompt.target.window_handle,
        prompt.trust,
    )
}

fn ensure_direct_set_value_target_matches_expected(
    current: &WindowsTarget,
    expected: &WindowsTarget,
) -> anyhow::Result<()> {
    if current.window_handle != expected.window_handle {
        anyhow::bail!("credential prompt window changed before password insertion");
    }
    if current.process_id != expected.process_id {
        anyhow::bail!("credential prompt process changed before password insertion");
    }
    if !window_title_matches(&current.window_title, &expected.window_title) {
        anyhow::bail!("credential prompt title changed before password insertion");
    }
    Ok(())
}

fn ensure_direct_set_value_target_is_trusted(
    target_app_name: &str,
    target: &WindowsTarget,
    class_name: &str,
    window_handle: isize,
    trust: WindowsPromptTrust,
) -> anyhow::Result<()> {
    match trust {
        WindowsPromptTrust::TrustedTargetProcess => {
            if prompt_candidate_is_trusted_autofill_target(target_app_name, target, class_name) {
                Ok(())
            } else {
                anyhow::bail!("credential prompt target is not trusted before password insertion")
            }
        }
        WindowsPromptTrust::CredentialBrokerBoundToTarget => {
            if system_credential_prompt_matches_target(
                target_app_name,
                target,
                class_name,
                window_handle,
            ) {
                Ok(())
            } else {
                anyhow::bail!("credential broker prompt is not trusted before password insertion")
            }
        }
    }
}

fn ensure_password_cleanup_target_is_trusted(
    target_app_name: &str,
    target: &WindowsTarget,
    class_name: &str,
    trust: WindowsPromptTrust,
) -> anyhow::Result<()> {
    match trust {
        WindowsPromptTrust::TrustedTargetProcess
            if target_app_matches_with_class(target_app_name, target, class_name) =>
        {
            Ok(())
        }
        WindowsPromptTrust::CredentialBrokerBoundToTarget => {
            anyhow::bail!("credential broker cleanup has no non-spoofable requester binding")
        }
        _ => anyhow::bail!("original filled prompt process is no longer trusted during cleanup"),
    }
}

fn password_field_ready_for_direct_set_value(element: &UIElement) -> bool {
    password_field_ready_for_direct_set_value_with_state(
        element.is_offscreen().unwrap_or(true),
        element.is_enabled().unwrap_or(false),
        prompt_element_rect(element),
        is_native_password_field(element),
    )
}

fn password_field_ready_for_direct_set_value_with_state(
    is_offscreen: bool,
    is_enabled: bool,
    rect: Option<ElementRect>,
    native_password_identity_matches: bool,
) -> bool {
    !is_offscreen && is_enabled && rect.is_some() && native_password_identity_matches
}

fn uia_element_bound_to_prompt_window(
    automation: &UIAutomation,
    element: &UIElement,
    prompt_root: &UIElement,
    target: &WindowsTarget,
) -> bool {
    if target.process_id <= 0 || target.window_handle == 0 {
        return false;
    }
    if prompt_root.get_process_id().ok() != Some(target.process_id as u32)
        || element.get_process_id().ok() != Some(target.process_id as u32)
    {
        return false;
    }
    if uia_native_window_handle(prompt_root) != Some(target.window_handle) {
        return false;
    }

    let Ok(walker) = automation.get_raw_view_walker() else {
        return false;
    };
    let mut current = element.clone();
    for _ in 0..=UIA_SEARCH_DEPTH {
        if current.get_process_id().ok() != Some(target.process_id as u32) {
            return false;
        }
        if let Some(native_handle) = uia_native_window_handle(&current) {
            if native_handle != 0
                && !native_hwnd_is_within_prompt_window(
                    native_handle,
                    target.window_handle,
                    target.process_id,
                )
            {
                return false;
            }
        }
        if automation
            .compare_elements(&current, prompt_root)
            .unwrap_or(false)
        {
            return true;
        }
        let Ok(parent) = walker.get_parent(&current) else {
            return false;
        };
        current = parent;
    }
    false
}

fn uia_native_window_handle(element: &UIElement) -> Option<isize> {
    element
        .get_native_window_handle()
        .ok()
        .map(Into::<isize>::into)
}

fn native_hwnd_is_within_prompt_window(
    element_handle: isize,
    prompt_handle: isize,
    expected_process_id: i32,
) -> bool {
    if element_handle == 0 || prompt_handle == 0 || expected_process_id <= 0 {
        return false;
    }
    let element_hwnd = hwnd_from_handle(element_handle);
    let mut element_process_id = 0_u32;
    unsafe {
        GetWindowThreadProcessId(element_hwnd, Some(&mut element_process_id));
    }
    if element_process_id != expected_process_id as u32 {
        return false;
    }
    if element_handle == prompt_handle {
        return true;
    }
    let root = unsafe { GetAncestor(element_hwnd, GA_ROOT) };
    root.0.addr() as isize == prompt_handle
}

fn ensure_prompt_sensitive_elements_bound(prompt: &WindowsPrompt) -> anyhow::Result<()> {
    let automation = UIAutomation::new().or_else(|_| UIAutomation::new_direct())?;
    if !uia_element_bound_to_prompt_window(
        &automation,
        &prompt.prompt_root,
        &prompt.prompt_root,
        &prompt.target,
    ) {
        anyhow::bail!("credential prompt root is no longer bound to the trusted process window");
    }
    if !uia_element_bound_to_prompt_window(
        &automation,
        &prompt.password_field,
        &prompt.prompt_root,
        &prompt.target,
    ) {
        anyhow::bail!("password field provider is no longer bound to the trusted prompt window");
    }
    if prompt.submit_button.as_ref().is_some_and(|button| {
        !uia_element_bound_to_prompt_window(
            &automation,
            button,
            &prompt.prompt_root,
            &prompt.target,
        )
    }) {
        anyhow::bail!("submit button provider is no longer bound to the trusted prompt window");
    }
    if prompt.identity_elements.iter().any(|element| {
        !uia_element_bound_to_prompt_window(
            &automation,
            element,
            &prompt.prompt_root,
            &prompt.target,
        )
    }) {
        anyhow::bail!("prompt identity provider is no longer bound to the trusted prompt window");
    }
    Ok(())
}

struct PromptWindowInspection {
    prompt: Option<WindowsPrompt>,
    password_like_plain_edit_rejected: bool,
}

fn prompt_from_window(
    automation: &UIAutomation,
    target: WindowsTarget,
    trust: WindowsPromptTrust,
    window: UIElement,
) -> anyhow::Result<Option<WindowsPrompt>> {
    Ok(inspect_prompt_window(automation, target, trust, window)?.prompt)
}

fn inspect_prompt_window(
    automation: &UIAutomation,
    target: WindowsTarget,
    trust: WindowsPromptTrust,
    window: UIElement,
) -> anyhow::Result<PromptWindowInspection> {
    if !is_usable_window(&window)
        || !uia_element_bound_to_prompt_window(automation, &window, &window, &target)
    {
        return Ok(PromptWindowInspection {
            prompt: None,
            password_like_plain_edit_rejected: false,
        });
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

    let Some(prompt_candidate) = select_prompt_candidate(&target.window_title, &elements) else {
        return Ok(PromptWindowInspection {
            prompt: None,
            password_like_plain_edit_rejected: has_password_like_plain_edit(&elements),
        });
    };
    let sensitive_elements_bound = uia_element_bound_to_prompt_window(
        automation,
        &prompt_candidate.password_field,
        &window,
        &target,
    ) && prompt_candidate.submit_button.as_ref().is_none_or(
        |button| uia_element_bound_to_prompt_window(automation, button, &window, &target),
    ) && prompt_candidate
        .identity_elements
        .iter()
        .all(|element| uia_element_bound_to_prompt_window(automation, element, &window, &target));
    if !sensitive_elements_bound {
        return Ok(PromptWindowInspection {
            prompt: None,
            password_like_plain_edit_rejected: false,
        });
    }

    let password_field_description = redacted_element_description(&prompt_candidate.password_field);
    let password_field_role = element_role_text(&prompt_candidate.password_field);
    Ok(PromptWindowInspection {
        prompt: Some(WindowsPrompt {
            target,
            email: prompt_candidate.email,
            password_field_description,
            password_field_role,
            trust,
            prompt_root: window,
            password_field: prompt_candidate.password_field,
            submit_button: prompt_candidate.submit_button,
            identity_elements: prompt_candidate.identity_elements,
        }),
        password_like_plain_edit_rejected: false,
    })
}

fn has_password_like_plain_edit(elements: &[UIElement]) -> bool {
    elements.iter().any(|element| {
        !is_native_password_field(element)
            && is_password_like_edit(element)
            && prompt_element_rect(element).is_some()
    })
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

fn prompt_candidate_is_trusted_autofill_target(
    target_app_name: &str,
    target: &WindowsTarget,
    class_name: &str,
) -> bool {
    target_app_matches_with_class(target_app_name, target, class_name)
        && target_window_should_be_scanned_for_prompt(target_app_name, target, class_name)
}

fn prompt_candidate_trust(
    target_app_name: &str,
    target: &WindowsTarget,
    class_name: &str,
    window_handle: isize,
) -> Option<WindowsPromptTrust> {
    if prompt_candidate_is_trusted_autofill_target(target_app_name, target, class_name) {
        return Some(WindowsPromptTrust::TrustedTargetProcess);
    }

    system_credential_prompt_matches_target(target_app_name, target, class_name, window_handle)
        .then_some(WindowsPromptTrust::CredentialBrokerBoundToTarget)
}

fn fast_system_credential_prompt(
    automation: &UIAutomation,
    target_app_name: &str,
) -> anyhow::Result<Option<WindowsPrompt>> {
    for (target, window_handle) in native_system_credential_windows() {
        if !system_credential_prompt_matches_target(
            target_app_name,
            &target,
            "Credential Dialog Xaml Host",
            window_handle,
        ) {
            continue;
        }
        let Ok(window) = automation.element_from_handle(Handle::from(window_handle)) else {
            continue;
        };
        if let Some(prompt) = prompt_from_window(
            automation,
            target,
            WindowsPromptTrust::CredentialBrokerBoundToTarget,
            window,
        )? {
            return Ok(Some(prompt));
        }
    }

    Ok(None)
}

struct NativePromptSnapshotCandidate {
    target: WindowsTarget,
    class_name: String,
    window_handle: isize,
}

struct NativePromptSnapshotSearch {
    process_id: i32,
    window_handle: isize,
    window_title: String,
    candidates: Vec<NativePromptSnapshotCandidate>,
}

fn native_prompt_snapshot_candidates(
    process_id: i32,
    window_handle: isize,
    window_title: &str,
) -> Vec<NativePromptSnapshotCandidate> {
    if process_id <= 0 || window_handle == 0 {
        return Vec::new();
    }

    let mut search = NativePromptSnapshotSearch {
        process_id,
        window_handle,
        window_title: window_title.trim().to_string(),
        candidates: Vec::new(),
    };
    unsafe {
        let _ = EnumWindows(
            Some(enum_native_prompt_snapshot_window),
            LPARAM(&mut search as *mut _ as isize),
        );
    }
    search
        .candidates
        .sort_by_key(|candidate| !window_handle_is_foreground(candidate.window_handle));
    search.candidates
}

fn native_visible_windows() -> Vec<NativePromptSnapshotCandidate> {
    let mut candidates = Vec::<NativePromptSnapshotCandidate>::new();
    unsafe {
        let _ = EnumWindows(
            Some(enum_native_visible_window),
            LPARAM(&mut candidates as *mut _ as isize),
        );
    }
    candidates.sort_by_key(|candidate| !window_handle_is_foreground(candidate.window_handle));
    candidates
}

fn trusted_session_windows(target_app_name: &str) -> Vec<WindowsSessionWindow> {
    native_visible_windows()
        .into_iter()
        .filter(|candidate| {
            target_app_matches_with_class(target_app_name, &candidate.target, &candidate.class_name)
                && is_probable_session_window_title(&candidate.target.window_title)
        })
        .map(|candidate| WindowsSessionWindow {
            process_id: candidate.target.process_id,
            window_title: candidate.target.window_title,
            window_handle: candidate.window_handle,
        })
        .collect()
}

unsafe extern "system" fn enum_native_visible_window(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let candidates = unsafe { &mut *(lparam.0 as *mut Vec<NativePromptSnapshotCandidate>) };

    if !native_window_is_visible_and_sized(hwnd) {
        return true.into();
    }

    let Some((target, class_name)) = target_details_from_hwnd(hwnd) else {
        return true.into();
    };
    candidates.push(NativePromptSnapshotCandidate {
        target,
        class_name,
        window_handle: hwnd.0.addr() as isize,
    });
    true.into()
}

unsafe extern "system" fn enum_native_prompt_snapshot_window(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let search = unsafe { &mut *(lparam.0 as *mut NativePromptSnapshotSearch) };

    if hwnd.0.addr() as isize != search.window_handle {
        return true.into();
    }
    if !native_window_is_visible_and_sized(hwnd) {
        return true.into();
    }

    let Some((target, class_name)) = target_details_from_hwnd(hwnd) else {
        return true.into();
    };
    if target.process_id != search.process_id {
        return true.into();
    }
    if !search.window_title.is_empty()
        && !window_title_matches(&target.window_title, &search.window_title)
    {
        return true.into();
    }

    search.candidates.push(NativePromptSnapshotCandidate {
        target,
        class_name,
        window_handle: hwnd.0.addr() as isize,
    });
    true.into()
}

fn native_window_is_visible_and_sized(hwnd: HWND) -> bool {
    if !unsafe { IsWindowVisible(hwnd) }.as_bool() {
        return false;
    }

    let mut rect = RECT::default();
    unsafe { GetWindowRect(hwnd, &mut rect) }.is_ok()
        && rect.right - rect.left > 20
        && rect.bottom - rect.top > 20
}

fn prompt_matches_snapshot(
    prompt: &WindowsPrompt,
    process_id: i32,
    window_handle: isize,
    window_title: &str,
    prompt_email: Option<&str>,
) -> bool {
    prompt_metadata_matches_snapshot(
        &prompt.target,
        prompt.email.as_deref(),
        process_id,
        window_handle,
        window_title,
        prompt_email,
    )
}

fn prompt_metadata_matches_snapshot(
    target: &WindowsTarget,
    current_email: Option<&str>,
    process_id: i32,
    window_handle: isize,
    window_title: &str,
    prompt_email: Option<&str>,
) -> bool {
    target.process_id == process_id
        && target.window_handle == window_handle
        && (window_title.trim().is_empty()
            || window_title_matches(&target.window_title, window_title))
        && match (current_email, prompt_email.map(str::trim)) {
            (Some(current), Some(expected)) if !expected.is_empty() => {
                current.eq_ignore_ascii_case(expected)
            }
            (_, None) => true,
            (_, Some(expected)) => expected.is_empty(),
        }
}

fn window_title_matches(current: &str, expected: &str) -> bool {
    current.trim().eq_ignore_ascii_case(expected.trim())
}

fn target_details_from_hwnd(hwnd: HWND) -> Option<(WindowsTarget, String)> {
    if hwnd.0.addr() == 0 {
        return None;
    }

    let mut process_id = 0_u32;
    unsafe {
        GetWindowThreadProcessId(hwnd, Some(&mut process_id));
    }
    if process_id == 0 {
        return None;
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
        window_title: native_window_text(hwnd),
        window_handle,
        frontmost: window_handle_is_foreground(window_handle),
    };

    Some((target, native_window_class(hwnd)))
}

fn system_credential_prompt_matches_target(
    target_app_name: &str,
    target: &WindowsTarget,
    class_name: &str,
    window_handle: isize,
) -> bool {
    let _ = (target_app_name, target, class_name, window_handle);

    // CredentialUIBroker is a trusted Windows binary, but its owner HWND does
    // not cryptographically identify the process that requested CredUI. Any
    // same-desktop process can create a broker dialog owned by a Windows App
    // HWND and receive the entered credential. Until Windows exposes a
    // non-spoofable requester correlation, automatic filling must fail closed.
    false
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

    if !native_window_is_visible_and_sized(hwnd) {
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

#[derive(Clone)]
struct PromptCandidate {
    email: Option<String>,
    password_field: UIElement,
    submit_button: Option<UIElement>,
    identity_elements: Vec<UIElement>,
}

#[derive(Clone)]
struct PasswordFieldCandidate {
    element: UIElement,
    rect: ElementRect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ElementRect {
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
}

impl ElementRect {
    fn new(left: i32, top: i32, right: i32, bottom: i32) -> Option<Self> {
        if right <= left || bottom <= top {
            return None;
        }

        Some(Self {
            left,
            top,
            right,
            bottom,
        })
    }

    fn width(self) -> i32 {
        self.right - self.left
    }

    fn height(self) -> i32 {
        self.bottom - self.top
    }

    fn center_x(self) -> i32 {
        self.left + self.width() / 2
    }

    fn horizontal_overlap(self, other: Self) -> i32 {
        (self.right.min(other.right) - self.left.max(other.left)).max(0)
    }

    fn horizontal_gap(self, other: Self) -> i32 {
        if self.right < other.left {
            other.left - self.right
        } else if other.right < self.left {
            self.left - other.right
        } else {
            0
        }
    }
}

fn select_prompt_candidate(window_title: &str, elements: &[UIElement]) -> Option<PromptCandidate> {
    let login_title = login_title_like(window_title);
    let mut selected = None;

    for candidate in password_field_candidates(elements) {
        let submit_button = select_submit_button_for_password(elements, candidate.rect);
        let submit_rect = submit_button.as_ref().and_then(prompt_element_rect);
        let (prompt_text, identity_elements) =
            collect_prompt_text(elements, candidate.rect, submit_rect);
        let prompt_email = extract_email_like(&prompt_text);
        if prompt_email.is_none() && !login_title {
            continue;
        }

        let prompt_candidate = PromptCandidate {
            email: prompt_email,
            password_field: candidate.element,
            submit_button,
            identity_elements,
        };
        if selected
            .as_ref()
            .is_some_and(|selected| prompt_candidates_conflict(selected, &prompt_candidate))
        {
            return None;
        }
        if selected
            .as_ref()
            .is_none_or(|selected| prompt_candidate_preferred(&prompt_candidate, selected))
        {
            selected = Some(prompt_candidate);
        }
    }

    selected
}

fn prompt_candidates_conflict(left: &PromptCandidate, right: &PromptCandidate) -> bool {
    match (left.email.as_deref(), right.email.as_deref()) {
        (Some(left), Some(right)) => !usernames_match(left, right),
        _ => false,
    }
}

fn prompt_candidate_preferred(candidate: &PromptCandidate, current: &PromptCandidate) -> bool {
    prompt_candidate_score(candidate) > prompt_candidate_score(current)
}

fn prompt_candidate_score(candidate: &PromptCandidate) -> u8 {
    u8::from(candidate.email.is_some()) * 4 + u8::from(candidate.submit_button.is_some())
}

fn password_field_candidates(elements: &[UIElement]) -> Vec<PasswordFieldCandidate> {
    let mut candidates = Vec::new();
    for element in elements {
        if !is_native_password_field(element) {
            continue;
        }
        if let Some(rect) = prompt_element_rect(element) {
            candidates.push(PasswordFieldCandidate {
                element: element.clone(),
                rect,
            });
        }
    }
    candidates
}

fn select_submit_button_for_password(
    elements: &[UIElement],
    password_rect: ElementRect,
) -> Option<UIElement> {
    let buttons = elements
        .iter()
        .filter(|element| element.get_control_type().ok() == Some(ControlType::Button))
        .filter(|element| !element.is_offscreen().unwrap_or(true))
        .filter_map(|element| {
            let rect = prompt_element_rect(element)?;
            submit_rect_related_to_password(password_rect, rect).then_some((element, rect))
        })
        .collect::<Vec<_>>();

    ranked_submit_button(&buttons, password_rect, |element| {
        let text = submit_button_text(element);
        element.is_enabled().unwrap_or(false) && submit_label_rank(&text) == Some(0)
    })
    .or_else(|| {
        ranked_submit_button(&buttons, password_rect, |element| {
            let text = submit_button_text(element);
            element.is_enabled().unwrap_or(false) && is_preferred_submit_label(&text)
        })
    })
    .or_else(|| {
        ranked_submit_button(&buttons, password_rect, |element| {
            let text = submit_button_text(element);
            submit_label_rank(&text) == Some(0)
        })
    })
    .or_else(|| {
        ranked_submit_button(&buttons, password_rect, |element| {
            let text = submit_button_text(element);
            is_preferred_submit_label(&text)
        })
    })
}

fn ranked_submit_button<F>(
    buttons: &[(&UIElement, ElementRect)],
    password_rect: ElementRect,
    matches_rank: F,
) -> Option<UIElement>
where
    F: Fn(&UIElement) -> bool,
{
    buttons
        .iter()
        .filter(|(element, _)| matches_rank(element))
        .min_by_key(|(_, rect)| submit_rect_distance(password_rect, *rect))
        .map(|(element, _)| (*element).clone())
}

fn submit_rect_distance(password: ElementRect, submit: ElementRect) -> i32 {
    let vertical_gap = if submit.top > password.bottom {
        submit.top - password.bottom
    } else if password.top > submit.bottom {
        password.top - submit.bottom
    } else {
        0
    };
    vertical_gap.saturating_mul(4) + (password.center_x() - submit.center_x()).abs()
}

fn submit_button_text(element: &UIElement) -> String {
    let mut text = String::new();
    push_text(&mut text, element.get_name().ok());
    push_text(&mut text, element.get_automation_id().ok());
    push_text(&mut text, element.get_help_text().ok());
    push_text(&mut text, element.get_item_status().ok());
    text
}

fn collect_prompt_text(
    elements: &[UIElement],
    password_rect: ElementRect,
    submit_rect: Option<ElementRect>,
) -> (String, Vec<UIElement>) {
    let mut text = String::new();
    let mut identity_elements = Vec::new();
    for element in elements {
        if !prompt_text_element_should_contribute(element) {
            continue;
        }
        let Some(rect) = prompt_element_rect(element) else {
            continue;
        };
        if !prompt_text_rect_related_to_password(password_rect, submit_rect, rect) {
            continue;
        }

        let before = text.len();
        push_text(&mut text, element.get_name().ok());
        push_text(&mut text, element.get_help_text().ok());
        push_text(&mut text, element.get_item_status().ok());

        if element.get_control_type().ok() == Some(ControlType::Edit) {
            if let Ok(value) = element.get_pattern::<UIValuePattern>() {
                push_text(&mut text, value.get_value().ok());
            }
        }
        if text.len() > before {
            identity_elements.push(element.clone());
        }
    }
    (text, identity_elements)
}

fn prompt_text_element_should_contribute(element: &UIElement) -> bool {
    if element.is_offscreen().unwrap_or(true)
        || is_native_password_field(element)
        || is_password_like_edit(element)
    {
        return false;
    }

    element.get_control_type().ok() != Some(ControlType::Button)
}

fn prompt_element_rect(element: &UIElement) -> Option<ElementRect> {
    let rect = element.get_bounding_rectangle().ok()?;
    ElementRect::new(
        rect.get_left(),
        rect.get_top(),
        rect.get_right(),
        rect.get_bottom(),
    )
}

fn submit_rect_related_to_password(password: ElementRect, submit: ElementRect) -> bool {
    let max_above = 80;
    let max_below = 520.max(password.height() * 12);
    submit.bottom >= password.top - max_above
        && submit.top <= password.bottom + max_below
        && rects_horizontally_related(password, submit, 420)
}

fn prompt_text_rect_related_to_password(
    password: ElementRect,
    submit: Option<ElementRect>,
    text: ElementRect,
) -> bool {
    if submit.is_some_and(|submit| text.top > submit.bottom + 160) {
        return false;
    }

    text.bottom >= password.top - 520
        && text.top <= password.bottom + 180
        && rects_horizontally_related(password, text, 420)
}

fn rects_horizontally_related(primary: ElementRect, other: ElementRect, max_gap: i32) -> bool {
    let min_width = primary.width().min(other.width()).max(1);
    primary.horizontal_overlap(other) >= min_width / 4
        || primary.horizontal_gap(other) <= max_gap
        || (primary.center_x() - other.center_x()).abs()
            <= primary.width().max(other.width()).max(max_gap)
}

fn is_native_password_field(element: &UIElement) -> bool {
    has_native_password_field_identity(element)
        && !element.is_offscreen().unwrap_or(true)
        && element.is_enabled().unwrap_or(false)
}

fn has_native_password_field_identity(element: &UIElement) -> bool {
    element.get_control_type().ok() == Some(ControlType::Edit)
        && element.is_password().unwrap_or(false)
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

fn process_package_full_name(process_id: i32) -> Option<String> {
    if process_id <= 0 {
        return None;
    }

    unsafe {
        let handle =
            OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, process_id as u32).ok()?;
        let result = process_package_full_name_from_handle(handle);
        let _ = CloseHandle(handle);
        result
    }
}

unsafe fn process_package_full_name_from_handle(handle: HANDLE) -> Option<String> {
    let mut len = 0_u32;
    let first = unsafe { GetPackageFullName(handle, &mut len, None) };
    if first == APPMODEL_ERROR_NO_PACKAGE || len == 0 {
        return None;
    }
    if first != ERROR_INSUFFICIENT_BUFFER && first != ERROR_SUCCESS {
        return None;
    }

    let mut buffer = vec![0_u16; len as usize];
    let second = unsafe { GetPackageFullName(handle, &mut len, Some(PWSTR(buffer.as_mut_ptr()))) };
    if second != ERROR_SUCCESS || len == 0 {
        return None;
    }

    let len = buffer
        .iter()
        .position(|c| *c == 0)
        .unwrap_or(len as usize)
        .min(buffer.len());
    Some(wide_buffer_to_string(&buffer, len))
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
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

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

pub(crate) fn running_target_process(target_app_name: &str) -> Option<WindowsTarget> {
    let aliases = target_aliases(target_app_name);
    if aliases.is_empty() {
        return None;
    }

    running_processes()?
        .into_iter()
        .find_map(|(process_id, snapshot_name)| {
            let normalized = normalized_identifier(
                Path::new(&snapshot_name)
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .unwrap_or(&snapshot_name),
            );
            if !aliases.contains(&normalized) {
                return None;
            }

            let process_path = process_image_path(process_id)?;
            let process_name = process_name_from_path(&process_path);
            let process_name = if process_name.trim().is_empty() {
                snapshot_name
            } else {
                process_name
            };
            let target = WindowsTarget {
                process_id: process_id as i32,
                process_name,
                process_path,
                window_title: target_app_name.to_string(),
                window_handle: 0,
                frontmost: false,
            };

            target_app_matches(target_app_name, &target).then_some(target)
        })
}

fn running_processes() -> Option<Vec<(u32, String)>> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

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
    if is_builtin_target_name(target_app_name) {
        return aliases
            .iter()
            .any(|alias| !alias.is_empty() && process_name == *alias)
            && trusted_microsoft_rdp_target(target);
    }

    let title = target.window_title.to_lowercase();
    let class_name = normalized_identifier(class_name);

    let process_matches = aliases
        .iter()
        .any(|alias| !alias.is_empty() && (process_name == *alias || class_name == *alias));
    let title_matches = aliases.iter().any(|alias| {
        !alias.is_empty()
            && title
                .split(|c: char| !(c.is_alphanumeric() || c == ' '))
                .any(|part| normalized_identifier(part) == *alias)
    });

    process_matches || title_matches
}

fn target_aliases(target_app_name: &str) -> Vec<String> {
    let mut aliases = Vec::new();
    let configured = normalized_identifier(target_app_name);
    if !configured.is_empty() {
        aliases.push(configured.clone());
    }

    if configured.as_str() == "windowsapp" {
        aliases.extend([
            "windowsapp".to_string(),
            "windows365".to_string(),
            "msrdc".to_string(),
            "msrdcw".to_string(),
            "rdclientwinstore".to_string(),
            "mstsc".to_string(),
        ])
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

fn normalized_windows_path(path: &str) -> String {
    let canonical_or_original = std::fs::canonicalize(path)
        .ok()
        .and_then(|path| path.into_os_string().into_string().ok())
        .unwrap_or_else(|| path.trim().to_string());
    let trimmed = canonical_or_original.trim();
    let without_extended_prefix = trimmed
        .strip_prefix(r"\\?\UNC\")
        .map(|rest| format!(r"\\{rest}"))
        .or_else(|| trimmed.strip_prefix(r"\\?\").map(str::to_string))
        .unwrap_or_else(|| trimmed.to_string());
    let mut normalized = without_extended_prefix.replace('/', "\\").to_lowercase();
    while normalized.ends_with('\\') && normalized.len() > 3 {
        normalized.pop();
    }
    normalized
}

fn normalized_windows_file_name(path: &str) -> Option<String> {
    normalized_windows_path(path)
        .rsplit('\\')
        .next()
        .filter(|file_name| !file_name.is_empty())
        .map(str::to_string)
}

fn normalized_windows_file_stem(path: &str) -> Option<String> {
    normalized_windows_file_name(path).map(|file_name| {
        file_name
            .strip_suffix(".exe")
            .unwrap_or(&file_name)
            .to_string()
    })
}

fn windows_directory_from_api(getter: unsafe fn(Option<&mut [u16]>) -> u32) -> Option<String> {
    let mut buffer = vec![0_u16; 32768];
    let len = unsafe { getter(Some(&mut buffer)) } as usize;
    if len == 0 || len >= buffer.len() {
        return None;
    }
    Some(normalized_windows_path(&wide_buffer_to_string(
        &buffer, len,
    )))
}

fn trusted_windows_system_directories() -> Vec<String> {
    let mut dirs = Vec::new();
    for getter in [
        GetSystemDirectoryW as unsafe fn(Option<&mut [u16]>) -> u32,
        GetSystemWow64DirectoryW as unsafe fn(Option<&mut [u16]>) -> u32,
    ] {
        if let Some(dir) = windows_directory_from_api(getter) {
            if !dir.is_empty() && !dirs.contains(&dir) {
                dirs.push(dir);
            }
        }
    }
    dirs
}

fn trusted_windows_system_exe_path(path: &str, exe_name: &str) -> bool {
    let normalized_path = normalized_windows_path(path);
    let exe_name = exe_name.to_ascii_lowercase();
    trusted_windows_system_directories()
        .into_iter()
        .any(|dir| normalized_path == format!(r"{dir}\{exe_name}"))
}

fn known_folder_path(folder_id: &GUID) -> Option<String> {
    let path = unsafe { SHGetKnownFolderPath(folder_id, KF_FLAG_DEFAULT, None).ok()? };
    if path.is_null() {
        return None;
    }

    let text = unsafe { path.to_string().ok() };
    unsafe {
        CoTaskMemFree(Some(path.as_ptr() as *const std::ffi::c_void));
    }
    text.map(|path| normalized_windows_path(&path))
}

fn trusted_program_files_roots() -> Vec<String> {
    let mut roots = Vec::new();
    for folder_id in [
        &FOLDERID_ProgramFiles,
        &FOLDERID_ProgramFilesX64,
        &FOLDERID_ProgramFilesX86,
    ] {
        if let Some(root) = known_folder_path(folder_id) {
            if !root.is_empty() && !roots.contains(&root) {
                roots.push(root);
            }
        }
    }
    roots
}

fn path_equals_trusted_program_files_child(path: &str, child_path: &str) -> bool {
    let normalized_path = normalized_windows_path(path);
    let normalized_child_path = child_path.replace('/', "\\").to_lowercase();
    trusted_program_files_roots()
        .into_iter()
        .any(|root| normalized_path == format!(r"{root}\{normalized_child_path}"))
}

fn trusted_remote_desktop_install_path(path: &str, process_name: &str) -> bool {
    if !matches!(process_name, "msrdc" | "msrdcw") {
        return false;
    }

    path_equals_trusted_program_files_child(path, &format!(r"remote desktop\{process_name}.exe"))
}

fn trusted_windowsapps_microsoft_package_path(path: &str, process_name: &str) -> bool {
    if !matches!(
        process_name,
        "msrdc" | "msrdcw" | "rdclientwinstore" | "windows365" | "windowsapp"
    ) {
        return false;
    }

    let Some(file_stem) = normalized_windows_file_stem(path) else {
        return false;
    };
    if file_stem != process_name {
        return false;
    }

    let normalized_path = normalized_windows_path(path);
    trusted_program_files_roots().into_iter().any(|root| {
        let prefix = format!(r"{root}\windowsapps\");
        let Some(rest) = normalized_path.strip_prefix(&prefix) else {
            return false;
        };
        let Some(package_name) = rest.split('\\').next() else {
            return false;
        };
        let known_package = [
            "microsoft.remotedesktop_",
            "microsoft.remotedesktoppreview_",
            "microsoftcorporationii.windows365_",
            "microsoftcorporationii.windowsapp_",
        ]
        .iter()
        .any(|prefix| package_name.starts_with(prefix));

        known_package && package_name.ends_with("__8wekyb3d8bbwe")
    })
}

fn microsoft_rdp_target_kind(process_name: &str, path: &str) -> Option<WindowsMicrosoftTargetKind> {
    if path.trim().is_empty() {
        return None;
    }

    let process_name = normalized_identifier(process_name);
    match process_name.as_str() {
        "mstsc" if trusted_windows_system_exe_path(path, "mstsc.exe") => {
            Some(WindowsMicrosoftTargetKind::SystemMstsc)
        }
        "msrdc" | "msrdcw" => {
            if trusted_remote_desktop_install_path(path, &process_name) {
                Some(WindowsMicrosoftTargetKind::RemoteDesktopInstall)
            } else if trusted_windowsapps_microsoft_package_path(path, &process_name) {
                Some(WindowsMicrosoftTargetKind::WindowsAppsPackage)
            } else {
                None
            }
        }
        "rdclientwinstore" | "windows365" | "windowsapp" => {
            trusted_windowsapps_microsoft_package_path(path, &process_name)
                .then_some(WindowsMicrosoftTargetKind::WindowsAppsPackage)
        }
        _ => None,
    }
}

#[cfg(test)]
fn trusted_microsoft_rdp_path_hint(path: &str) -> bool {
    microsoft_rdp_target_kind(
        &normalized_windows_file_stem(path).unwrap_or_default(),
        path,
    )
    .is_some()
}

fn trusted_microsoft_rdp_target(target: &WindowsTarget) -> bool {
    let Some(kind) = microsoft_rdp_target_kind(&target.process_name, &target.process_path) else {
        return false;
    };
    windows_target_identity_is_trusted(target, kind)
}

fn system_credential_dialog_matches(target: &WindowsTarget, class_name: &str) -> bool {
    credential_dialog_title_like(&target.window_title)
        && trusted_windows_credential_broker(target)
        && credential_dialog_class_like(class_name)
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
    trusted_windows_system_exe_path(path, "credentialuibroker.exe")
}

fn trusted_windows_credential_broker(target: &WindowsTarget) -> bool {
    normalized_identifier(&target.process_name) == "credentialuibroker"
        && trusted_windows_credential_broker_path(&target.process_path)
        && windows_target_identity_is_trusted(target, WindowsMicrosoftTargetKind::CredentialBroker)
}

fn windows_target_identity_is_trusted(
    target: &WindowsTarget,
    kind: WindowsMicrosoftTargetKind,
) -> bool {
    #[cfg(test)]
    if let Some(result) = windows_target_identity_override_result(target, kind) {
        return result;
    }

    if target.process_id <= 0 || target.process_path.trim().is_empty() {
        return false;
    }
    if !windows_executable_is_microsoft_signed(&target.process_path) {
        return false;
    }
    if kind == WindowsMicrosoftTargetKind::WindowsAppsPackage {
        return process_package_full_name(target.process_id)
            .as_deref()
            .is_some_and(trusted_windowsapps_microsoft_package_full_name);
    }

    true
}

fn trusted_windowsapps_microsoft_package_full_name(package_full_name: &str) -> bool {
    let normalized = package_full_name.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return false;
    }

    let Some(publisher_id) = normalized.rsplit('_').next() else {
        return false;
    };
    if publisher_id != "8wekyb3d8bbwe" {
        return false;
    }

    [
        "microsoft.remotedesktop_",
        "microsoft.remotedesktoppreview_",
        "microsoftcorporationii.windows365_",
        "microsoftcorporationii.windowsapp_",
    ]
    .iter()
    .any(|prefix| normalized.starts_with(prefix))
}

fn windows_executable_is_microsoft_signed(path: &str) -> bool {
    unsafe {
        winverifytrust_with_state_validator(path, |trust_data| {
            wintrust_state_has_microsoft_signer(trust_data)
        })
    }
}

pub(crate) fn windows_executable_authenticode_identity_matches(
    path: &str,
    expected_publisher: &str,
    expected_cert_sha256: &str,
) -> bool {
    let expected_publisher = expected_publisher.trim().to_lowercase();
    let expected_cert_sha256 = expected_cert_sha256.trim().to_ascii_lowercase();
    if expected_publisher.is_empty()
        || expected_cert_sha256.len() != 64
        || !expected_cert_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return false;
    }
    unsafe {
        winverifytrust_with_state_validator(path, |trust_data| {
            wintrust_state_leaf_identity(trust_data).is_some_and(|(publisher, cert_sha256)| {
                publisher.trim().to_lowercase() == expected_publisher
                    && cert_sha256 == expected_cert_sha256
            })
        })
    }
}

unsafe fn winverifytrust_with_state_validator(
    path: &str,
    validate_state: impl FnOnce(&WINTRUST_DATA) -> bool,
) -> bool {
    let mut path_wide = Path::new(path)
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    if path_wide.len() <= 1 {
        return false;
    }

    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(path_wide.as_mut_ptr()),
        ..Default::default()
    };
    let mut trust_data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &mut file_info,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_SAFER_FLAG | WTD_DISABLE_MD2_MD4 | WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
        dwUIContext: WTD_UICONTEXT_EXECUTE,
        ..Default::default()
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    let status = unsafe {
        WinVerifyTrust(
            HWND::default(),
            &mut action,
            (&mut trust_data as *mut WINTRUST_DATA).cast::<c_void>(),
        )
    };
    let verified = status == 0 && validate_state(&trust_data);

    trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    let _ = unsafe {
        WinVerifyTrust(
            HWND::default(),
            &mut action,
            (&mut trust_data as *mut WINTRUST_DATA).cast::<c_void>(),
        )
    };

    verified
}

fn wintrust_state_leaf_identity(trust_data: &WINTRUST_DATA) -> Option<(String, String)> {
    let provider = unsafe { WTHelperProvDataFromStateData(trust_data.hWVTStateData) };
    if provider.is_null() {
        return None;
    }
    let signer = unsafe { WTHelperGetProvSignerFromChain(provider, 0, false, 0) };
    if signer.is_null() {
        return None;
    }
    let cert = unsafe { signer_certificate_context(signer, 0) }?;
    let name = unsafe { certificate_simple_display_name(cert) }?;
    let fingerprint = unsafe { certificate_sha256_fingerprint(cert) }?;
    Some((name, fingerprint))
}

unsafe fn wintrust_state_has_microsoft_signer(trust_data: &WINTRUST_DATA) -> bool {
    let provider = unsafe { WTHelperProvDataFromStateData(trust_data.hWVTStateData) };
    if provider.is_null() {
        return false;
    }
    let signer = unsafe { WTHelperGetProvSignerFromChain(provider, 0, false, 0) };
    if signer.is_null() {
        return false;
    }

    let Some(leaf_name) = (unsafe { signer_certificate_name(signer, 0) }) else {
        return false;
    };
    if !microsoft_signing_leaf_name_is_allowed(&leaf_name) {
        return false;
    }

    let chain_len = unsafe { (*signer).csCertChain };
    if chain_len <= 1 {
        return true;
    }

    (1..chain_len).any(|index| {
        unsafe { signer_certificate_name(signer, index) }
            .as_deref()
            .is_some_and(microsoft_chain_name_is_allowed)
    })
}

unsafe fn signer_certificate_name(
    signer: *mut windows::Win32::Security::WinTrust::CRYPT_PROVIDER_SGNR,
    index: u32,
) -> Option<String> {
    let cert_context = unsafe { signer_certificate_context(signer, index) }?;
    unsafe { certificate_simple_display_name(cert_context) }
}

unsafe fn signer_certificate_context(
    signer: *mut windows::Win32::Security::WinTrust::CRYPT_PROVIDER_SGNR,
    index: u32,
) -> Option<*const CERT_CONTEXT> {
    let cert = unsafe { WTHelperGetProvCertFromChain(signer, index) };
    if cert.is_null() {
        return None;
    }
    let cert_context = unsafe { (*cert).pCert };
    if cert_context.is_null() {
        return None;
    }
    Some(cert_context)
}

unsafe fn certificate_sha256_fingerprint(cert: *const CERT_CONTEXT) -> Option<String> {
    let encoded = unsafe { (*cert).pbCertEncoded };
    let encoded_len = unsafe { (*cert).cbCertEncoded as usize };
    if encoded.is_null() || encoded_len == 0 {
        return None;
    }
    let bytes = unsafe { std::slice::from_raw_parts(encoded, encoded_len) };
    Some(format!("{:x}", Sha256::digest(bytes)))
}

unsafe fn certificate_simple_display_name(cert: *const CERT_CONTEXT) -> Option<String> {
    let needed = unsafe { CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, None) };
    if needed <= 1 {
        return None;
    }

    let mut buffer = vec![0_u16; needed as usize];
    let written = unsafe {
        CertGetNameStringW(
            cert,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            None,
            Some(&mut buffer),
        )
    };
    if written <= 1 {
        return None;
    }

    Some(wide_buffer_to_string(&buffer, (written - 1) as usize))
}

fn microsoft_signing_leaf_name_is_allowed(name: &str) -> bool {
    matches!(
        name.trim().to_ascii_lowercase().as_str(),
        "microsoft corporation" | "microsoft windows" | "microsoft windows publisher"
    )
}

fn microsoft_chain_name_is_allowed(name: &str) -> bool {
    let name = name.trim().to_ascii_lowercase();
    name == "microsoft corporation"
        || name.starts_with("microsoft ")
        || name.contains(" microsoft ")
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
        contains_keyword, ensure_fixed_target_app, extract_email_like, is_preferred_submit_label,
        is_probable_session_window_title, login_title_like, normalized_identifier,
        prompt_text_rect_related_to_password, submit_rect_related_to_password, target_aliases,
        target_app_matches_with_class, text_contains_password_cue, trusted_microsoft_rdp_path_hint,
        window_title_matches, ElementRect, WindowsTarget,
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

    fn program_files_path(child: &str) -> String {
        let root = super::trusted_program_files_roots()
            .into_iter()
            .find(|path| path.ends_with(r"\program files"))
            .unwrap_or_else(|| r"c:\program files".to_string());
        format!(r"{root}\{child}")
    }

    fn system32_path(file_name: &str) -> String {
        let dir = super::trusted_windows_system_directories()
            .into_iter()
            .find(|path| path.ends_with(r"\system32"))
            .unwrap_or_else(|| r"c:\windows\system32".to_string());
        format!(r"{dir}\{file_name}")
    }

    fn windows_target(process_name: &str, process_path: impl Into<String>) -> WindowsTarget {
        WindowsTarget {
            process_id: 42,
            process_name: process_name.to_string(),
            process_path: process_path.into(),
            window_title: "Windows App".to_string(),
            window_handle: 7,
            frontmost: true,
        }
    }

    fn trusted_remote_desktop_prompt_target() -> WindowsTarget {
        let mut target = windows_target("msrdc", program_files_path(r"Remote Desktop\msrdc.exe"));
        target.window_title = "Windows Security - Sign in".to_string();
        target
    }

    fn reject_all_windows_target_identities(
        _target: &WindowsTarget,
        _kind: super::WindowsMicrosoftTargetKind,
    ) -> bool {
        false
    }

    fn accept_only_remote_desktop_install_identity(
        _target: &WindowsTarget,
        kind: super::WindowsMicrosoftTargetKind,
    ) -> bool {
        kind == super::WindowsMicrosoftTargetKind::RemoteDesktopInstall
    }

    #[test]
    fn builtin_windows_target_requires_trusted_process_path() {
        let remote_desktop =
            windows_target("msrdc", program_files_path(r"Remote Desktop\msrdc.exe"));
        assert!(target_app_matches_with_class(
            "Windows App",
            &remote_desktop,
            ""
        ));

        let packaged_windows_app = windows_target(
            "Windows365",
            program_files_path(
                r"WindowsApps\MicrosoftCorporationII.Windows365_1.0.0.0_x64__8wekyb3d8bbwe\Windows365.exe",
            ),
        );
        assert!(target_app_matches_with_class(
            "Windows App",
            &packaged_windows_app,
            ""
        ));

        let empty_path = windows_target("msrdc", "");
        assert!(!target_app_matches_with_class(
            "Windows App",
            &empty_path,
            ""
        ));

        let user_program_files_spoof = windows_target(
            "msrdc",
            r"C:\Users\me\Program Files\Remote Desktop\msrdc.exe",
        );
        assert!(!target_app_matches_with_class(
            "Windows App",
            &user_program_files_spoof,
            ""
        ));

        let user_windowsapps_spoof = windows_target(
            "Windows365",
            r"C:\Users\me\WindowsApps\MicrosoftCorporationII.Windows365_1.0.0.0_x64__8wekyb3d8bbwe\Windows365.exe",
        );
        assert!(!target_app_matches_with_class(
            "Windows App",
            &user_windowsapps_spoof,
            ""
        ));
    }

    #[test]
    fn builtin_windows_target_requires_verified_microsoft_identity() {
        let _guard =
            super::set_windows_target_identity_override(reject_all_windows_target_identities);
        let remote_desktop =
            windows_target("msrdc", program_files_path(r"Remote Desktop\msrdc.exe"));
        let packaged_windows_app = windows_target(
            "Windows365",
            program_files_path(
                r"WindowsApps\MicrosoftCorporationII.Windows365_1.0.0.0_x64__8wekyb3d8bbwe\Windows365.exe",
            ),
        );

        assert!(!target_app_matches_with_class(
            "Windows App",
            &remote_desktop,
            ""
        ));
        assert!(!target_app_matches_with_class(
            "Windows App",
            &packaged_windows_app,
            ""
        ));
    }

    #[test]
    fn builtin_windows_target_identity_policy_tracks_target_kind() {
        let _guard = super::set_windows_target_identity_override(
            accept_only_remote_desktop_install_identity,
        );
        let remote_desktop =
            windows_target("msrdc", program_files_path(r"Remote Desktop\msrdc.exe"));
        let packaged_windows_app = windows_target(
            "Windows365",
            program_files_path(
                r"WindowsApps\MicrosoftCorporationII.Windows365_1.0.0.0_x64__8wekyb3d8bbwe\Windows365.exe",
            ),
        );

        assert!(target_app_matches_with_class(
            "Windows App",
            &remote_desktop,
            ""
        ));
        assert!(!target_app_matches_with_class(
            "Windows App",
            &packaged_windows_app,
            ""
        ));
    }

    #[test]
    fn windowsapps_package_identity_requires_pinned_microsoft_publisher_id() {
        assert!(super::trusted_windowsapps_microsoft_package_full_name(
            "MicrosoftCorporationII.Windows365_1.0.0.0_x64__8wekyb3d8bbwe"
        ));
        assert!(super::trusted_windowsapps_microsoft_package_full_name(
            "Microsoft.RemoteDesktop_10.2.0.0_x64__8wekyb3d8bbwe"
        ));
        assert!(!super::trusted_windowsapps_microsoft_package_full_name(
            "MicrosoftCorporationII.Windows365_1.0.0.0_x64__badpublisher"
        ));
        assert!(!super::trusted_windowsapps_microsoft_package_full_name(
            "Contoso.Windows365_1.0.0.0_x64__8wekyb3d8bbwe"
        ));
    }

    #[test]
    fn builtin_windows_target_rejects_application_frame_host_title_spoof() {
        let mut hosted_window = windows_target(
            "ApplicationFrameHost",
            system32_path("ApplicationFrameHost.exe"),
        );
        hosted_window.window_title = "Windows App".to_string();

        assert!(!target_app_matches_with_class(
            "Windows App",
            &hosted_window,
            "Windows.UI.Core.CoreWindow"
        ));

        let class_spoof = windows_target("notepad", "");
        assert!(!target_app_matches_with_class(
            "Windows App",
            &class_spoof,
            "WindowsApp"
        ));
    }

    #[test]
    fn trusted_microsoft_rdp_path_hint_rejects_unanchored_spoofs() {
        assert!(trusted_microsoft_rdp_path_hint(&program_files_path(
            r"Remote Desktop\msrdc.exe"
        )));
        assert!(trusted_microsoft_rdp_path_hint(&system32_path("mstsc.exe")));
        assert!(!trusted_microsoft_rdp_path_hint(
            r"C:\Users\me\Program Files\Remote Desktop\msrdc.exe"
        ));
        assert!(!trusted_microsoft_rdp_path_hint(
            r"C:\Users\me\WindowsApps\MicrosoftCorporationII.Windows365_1.0.0.0_x64__8wekyb3d8bbwe\Windows365.exe"
        ));
        assert!(!trusted_microsoft_rdp_path_hint(
            r"C:\Users\me\Windows\System32\mstsc.exe"
        ));
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
    fn prompt_text_scope_accepts_only_local_form_text() {
        let password = ElementRect::new(200, 300, 430, 330).unwrap();
        let submit = ElementRect::new(300, 350, 430, 382).unwrap();
        let account_text = ElementRect::new(190, 238, 470, 260).unwrap();
        let far_side_account = ElementRect::new(900, 238, 1160, 260).unwrap();
        let near_below_submit_account = ElementRect::new(200, 430, 470, 452).unwrap();
        let below_submit_account = ElementRect::new(200, 560, 470, 582).unwrap();

        assert!(prompt_text_rect_related_to_password(
            password,
            Some(submit),
            account_text
        ));
        assert!(!prompt_text_rect_related_to_password(
            password,
            Some(submit),
            far_side_account
        ));
        assert!(prompt_text_rect_related_to_password(
            password,
            Some(submit),
            near_below_submit_account
        ));
        assert!(!prompt_text_rect_related_to_password(
            password,
            Some(submit),
            below_submit_account
        ));
    }

    #[test]
    fn submit_scope_accepts_only_local_form_button() {
        let password = ElementRect::new(200, 300, 430, 330).unwrap();
        let submit = ElementRect::new(300, 350, 430, 382).unwrap();
        let far_side_submit = ElementRect::new(900, 350, 1030, 382).unwrap();
        let far_above_submit = ElementRect::new(300, 80, 430, 112).unwrap();

        assert!(submit_rect_related_to_password(password, submit));
        assert!(!submit_rect_related_to_password(password, far_side_submit));
        assert!(!submit_rect_related_to_password(password, far_above_submit));
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
    fn post_submit_authentication_requires_a_new_session_after_the_submitted_prompt() {
        let existing = super::WindowsSessionWindow {
            process_id: 42,
            window_title: "Existing session".to_string(),
            window_handle: 100,
        };
        let submitted = super::WindowsSubmittedPrompt {
            process_id: 42,
            prompt_window_handle: 7,
            prompt_window_title: "Windows Security".to_string(),
            email: "user@example.com".to_string(),
            pre_submit_session_windows: vec![existing.clone()],
        };

        assert!(!super::submitted_prompt_has_new_session(
            Some(&submitted),
            std::slice::from_ref(&existing),
            42,
            "user@example.com",
        ));
        assert!(!super::submitted_prompt_has_new_session(
            Some(&submitted),
            &[
                existing.clone(),
                super::WindowsSessionWindow {
                    process_id: 43,
                    window_title: "New session".to_string(),
                    window_handle: 101,
                },
            ],
            42,
            "USER@example.com",
        ));
        assert!(super::submitted_prompt_has_new_session(
            Some(&submitted),
            &[
                existing,
                super::WindowsSessionWindow {
                    process_id: 42,
                    window_title: "New session".to_string(),
                    window_handle: 101,
                },
            ],
            42,
            "USER@example.com",
        ));
        assert!(!super::submitted_prompt_has_new_session(
            None,
            &[],
            42,
            "user@example.com",
        ));
    }

    #[test]
    fn window_title_snapshot_match_ignores_case_and_surrounding_space() {
        assert!(window_title_matches(
            " Windows Security - Sign in ",
            "windows security - sign in"
        ));
        assert!(!window_title_matches("Windows Security", "Windows App"));
    }

    #[test]
    fn prompt_snapshot_match_requires_same_pid_title_and_email() {
        let target = trusted_remote_desktop_prompt_target();
        let email = Some("USER@example.com");

        assert!(super::prompt_metadata_matches_snapshot(
            &target,
            email,
            42,
            7,
            "windows security - sign in",
            Some("user@example.com")
        ));
        assert!(!super::prompt_metadata_matches_snapshot(
            &target,
            email,
            43,
            7,
            "windows security - sign in",
            Some("user@example.com")
        ));
        assert!(!super::prompt_metadata_matches_snapshot(
            &target,
            email,
            42,
            8,
            "windows security - sign in",
            Some("user@example.com")
        ));
        assert!(!super::prompt_metadata_matches_snapshot(
            &target,
            email,
            42,
            7,
            "other title",
            Some("user@example.com")
        ));
        assert!(!super::prompt_metadata_matches_snapshot(
            &target,
            email,
            42,
            7,
            "windows security - sign in",
            Some("other@example.com")
        ));
        assert!(!super::prompt_metadata_matches_snapshot(
            &target,
            None,
            42,
            7,
            "windows security - sign in",
            Some("user@example.com")
        ));
    }

    #[test]
    fn direct_setvalue_target_validation_requires_same_window_identity() {
        let expected = trusted_remote_desktop_prompt_target();
        assert!(
            super::ensure_direct_set_value_target_matches_expected(&expected, &expected).is_ok()
        );

        let mutations: [fn(&mut WindowsTarget); 3] = [
            |target: &mut WindowsTarget| target.process_id = 43,
            |target: &mut WindowsTarget| target.window_title = "Other".to_string(),
            |target: &mut WindowsTarget| target.window_handle = 8,
        ];
        for mutate in mutations {
            let mut current = expected.clone();
            mutate(&mut current);
            assert!(
                super::ensure_direct_set_value_target_matches_expected(&current, &expected)
                    .is_err()
            );
        }
    }

    #[test]
    fn direct_setvalue_password_field_requires_visible_enabled_bounds_and_native_identity() {
        let rect = ElementRect::new(10, 10, 110, 40);

        for (is_offscreen, is_enabled, bounds, native_password_identity_matches, expected) in [
            (false, true, rect, true, true),
            (true, true, rect, true, false),
            (false, false, rect, true, false),
            (false, true, None, true, false),
            (false, true, rect, false, false),
        ] {
            assert_eq!(
                super::password_field_ready_for_direct_set_value_with_state(
                    is_offscreen,
                    is_enabled,
                    bounds,
                    native_password_identity_matches,
                ),
                expected
            );
        }
    }

    #[test]
    fn direct_setvalue_readiness_requires_native_is_password() {
        let implementation = include_str!("windows_ui.rs");
        let readiness = source_between(
            implementation,
            "fn password_field_ready_for_direct_set_value(",
            "fn password_field_ready_for_direct_set_value_with_state(",
        );
        assert!(
            readiness.contains("is_native_password_field(element)"),
            "direct SetValue readiness must require native UIA password identity"
        );
        assert!(
            !readiness.contains("is_password_like_edit"),
            "direct SetValue readiness must not accept password-like plain Edit controls"
        );
    }

    #[test]
    fn sensitive_uia_elements_require_provider_pid_and_native_window_ancestry() {
        let implementation = include_str!("windows_ui.rs");
        let binding = source_between(
            implementation,
            "fn uia_element_bound_to_prompt_window(",
            "fn uia_native_window_handle(",
        );

        assert!(binding.contains("get_process_id"));
        assert!(binding.contains("get_raw_view_walker"));
        assert!(binding.contains("compare_elements"));
        assert!(binding.contains("native_hwnd_is_within_prompt_window"));

        let actions = source_between(
            implementation,
            "pub(crate) fn submit_prompt(",
            "pub(crate) fn clear_filled_password(",
        );
        assert!(actions.matches("guard()?").count() >= 3);
        assert!(actions.contains("ensure_prompt_sensitive_elements_bound"));
    }

    #[test]
    fn password_field_candidates_do_not_fall_back_to_password_like_plain_edits() {
        let implementation = include_str!("windows_ui.rs");
        let candidates = source_between(
            implementation,
            "fn password_field_candidates(",
            "fn select_submit_button_for_password(",
        );
        assert!(
            !candidates.contains("is_password_like_edit"),
            "autofill candidates must not include password-like plain Edit controls"
        );
    }

    #[test]
    fn native_password_field_detection_requires_uia_is_password() {
        let implementation = include_str!("windows_ui.rs");
        let native_detection = source_between(
            implementation,
            "fn is_native_password_field(",
            "fn is_password_like_edit(",
        );
        assert!(
            native_detection.contains("element.is_password().unwrap_or(false)"),
            "native password detection must require the UIA IsPassword property"
        );
        assert!(
            !native_detection.contains("text_contains_password_cue")
                && !native_detection.contains("element_label_text"),
            "native password detection must not use label-based password cues"
        );
    }

    fn source_between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
        let start_index = source.find(start).expect("source start marker");
        let end_index = source[start_index..]
            .find(end)
            .map(|offset| start_index + offset)
            .expect("source end marker");
        &source[start_index..end_index]
    }

    fn trusted_windows_security_target() -> WindowsTarget {
        WindowsTarget {
            process_id: 42,
            process_name: "CredentialUIBroker".to_string(),
            process_path: system32_path("CredentialUIBroker.exe"),
            window_title: "Windows Security".to_string(),
            window_handle: 7,
            frontmost: true,
        }
    }

    #[test]
    fn trusted_windows_app_prompt_is_autofill_target() {
        let target = trusted_remote_desktop_prompt_target();

        assert!(super::prompt_candidate_is_trusted_autofill_target(
            "Windows App",
            &target,
            "Credential Dialog Xaml Host"
        ));
        assert!(super::ensure_direct_set_value_target_is_trusted(
            "Windows App",
            &target,
            "Credential Dialog Xaml Host",
            target.window_handle,
            super::WindowsPromptTrust::TrustedTargetProcess
        )
        .is_ok());
    }

    #[test]
    fn credential_broker_prompt_is_not_plain_autofill_target() {
        let target = trusted_windows_security_target();

        assert!(!super::prompt_candidate_is_trusted_autofill_target(
            "Windows App",
            &target,
            "Credential Dialog Xaml Host"
        ));
        assert!(!super::prompt_candidate_is_trusted_autofill_target(
            "Windows App",
            &target,
            "Windows.UI.Core.CoreWindow"
        ));
        assert!(super::system_credential_dialog_matches(
            &target,
            "Credential Dialog Xaml Host"
        ));
        assert!(!super::system_credential_prompt_matches_target(
            "Windows App",
            &target,
            "Credential Dialog Xaml Host",
            target.window_handle,
        ));
    }

    #[test]
    fn credential_broker_prompt_requires_owner_binding_before_direct_setvalue() {
        let target = trusted_windows_security_target();

        assert!(super::ensure_direct_set_value_target_is_trusted(
            "Windows App",
            &target,
            "Credential Dialog Xaml Host",
            target.window_handle,
            super::WindowsPromptTrust::CredentialBrokerBoundToTarget
        )
        .is_err());
    }

    #[test]
    fn credential_broker_prompt_is_rejected_even_with_user_path_spoof() {
        let target = WindowsTarget {
            process_id: 42,
            process_name: "CredentialUIBroker".to_string(),
            process_path: r"C:\Users\me\CredentialUIBroker.exe".to_string(),
            window_title: "Windows Security".to_string(),
            window_handle: 7,
            frontmost: true,
        };

        assert!(!super::system_credential_dialog_matches(
            &target,
            "Credential Dialog Xaml Host"
        ));
    }

    #[test]
    fn credential_broker_prompt_is_rejected_even_with_nested_system32_suffix_spoof() {
        let target = WindowsTarget {
            process_id: 42,
            process_name: "CredentialUIBroker".to_string(),
            process_path: r"C:\Users\me\Windows\System32\CredentialUIBroker.exe".to_string(),
            window_title: "Windows Security".to_string(),
            window_handle: 7,
            frontmost: true,
        };

        assert!(!super::system_credential_dialog_matches(
            &target,
            "Credential Dialog Xaml Host"
        ));
    }

    #[test]
    fn credential_broker_prompt_is_rejected_with_empty_path_process_name_fallback() {
        let target = WindowsTarget {
            process_id: 42,
            process_name: "CredentialUIBroker".to_string(),
            process_path: String::new(),
            window_title: "Windows Security".to_string(),
            window_handle: 7,
            frontmost: true,
        };

        assert!(!super::system_credential_dialog_matches(
            &target,
            "Credential Dialog Xaml Host"
        ));
    }

    #[test]
    fn credential_broker_prompt_is_rejected_even_with_process_name_spoof() {
        let target = WindowsTarget {
            process_id: 42,
            process_name: "CredentialUIBrokerSpoof".to_string(),
            process_path: system32_path("CredentialUIBroker.exe"),
            window_title: "Windows Security".to_string(),
            window_handle: 7,
            frontmost: true,
        };

        assert!(!super::system_credential_dialog_matches(
            &target,
            "Credential Dialog Xaml Host"
        ));
    }

    #[test]
    fn windows_security_title_is_login_prompt_not_session() {
        assert!(login_title_like("Windows Security"));
        assert!(login_title_like("Windows Security - Sign in"));
        assert!(!is_probable_session_window_title("Windows Security"));
    }
}
