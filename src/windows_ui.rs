use crate::config::Config;
use crate::monitor::{MonitorObservation, MonitorStatus};
use anyhow::Context;
use sha2::{Digest, Sha256};
use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};
use uiautomation::patterns::{UIInvokePattern, UIValuePattern};
use uiautomation::types::{ControlType, Handle, TreeScope};
use uiautomation::{UIAutomation, UIElement};
use windows::core::{BOOL, BSTR, GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, APPMODEL_ERROR_NO_PACKAGE, CERT_E_REVOKED, CRYPT_E_NO_SIGNER,
    CRYPT_E_REVOKED, CRYPT_E_SIGNER_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_FILES,
    ERROR_SUCCESS, HANDLE, HWND, LPARAM, RECT, TRUST_E_BAD_DIGEST, TRUST_E_CERT_SIGNATURE,
    TRUST_E_EXPLICIT_DISTRUST, TRUST_E_MALFORMED_SIGNATURE, TRUST_E_NOSIGNATURE,
    TRUST_E_NO_SIGNER_CERT,
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
    GetWindowTextW, GetWindowThreadProcessId, IsWindow, IsWindowVisible, SetForegroundWindow,
    ShowWindow, GA_ROOT, SW_RESTORE,
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
    #[cfg(test)]
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
    pub(crate) prompt_scan_complete: bool,
    pub(crate) target_process_scan_complete: bool,
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

#[derive(Debug)]
pub(crate) struct WindowsFillFailure {
    error: anyhow::Error,
    cleanup_prompt: Option<Box<WindowsPrompt>>,
}

impl WindowsFillFailure {
    fn before_write(error: anyhow::Error) -> Self {
        Self {
            error,
            cleanup_prompt: None,
        }
    }

    fn ambiguous_write(error: anyhow::Error, cleanup_prompt: WindowsPrompt) -> Self {
        Self {
            error,
            cleanup_prompt: Some(Box::new(cleanup_prompt)),
        }
    }

    pub(crate) fn cleanup_prompt(&self) -> Option<&WindowsPrompt> {
        self.cleanup_prompt.as_deref()
    }
}

impl std::fmt::Display for WindowsFillFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}

impl std::error::Error for WindowsFillFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.error.source()
    }
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
    trust: WindowsPromptTrust,
    prompt_runtime_id: Vec<i32>,
    pre_submit_session_windows: Vec<WindowsSessionWindow>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SubmittedPromptPresence {
    Present,
    Absent,
    Indeterminate,
}

pub(crate) fn check_status(config: &Config) -> MonitorObservation {
    match inspect(&config.macos_app_name) {
        Ok(inspection) => {
            let definitive_no_prompt = if inspection.target.is_none() {
                inspection.target_process_scan_complete
            } else {
                inspection.prompt.is_none() && inspection.prompt_scan_complete
            };
            if inspection.target.is_some() {
                if let Some(prompt) = inspection.prompt {
                    return MonitorObservation::indeterminate(MonitorStatus::LoginWindowDetected {
                        process_id: prompt.target.process_id,
                        window_handle: prompt.target.window_handle,
                        window_title: prompt.target.window_title,
                        prompt_email: prompt.email,
                        prompt_origin: "windows".to_string(),
                    });
                }
            } else if inspection.prompt.is_some() {
                return MonitorObservation::indeterminate(MonitorStatus::Unknown);
            }

            let status = if inspection.target.is_none() {
                MonitorStatus::ProcessNotFound
            } else if inspection.has_session {
                MonitorStatus::Connected
            } else {
                MonitorStatus::Unknown
            };
            MonitorObservation {
                status,
                definitive_no_prompt,
            }
        }
        Err(e) => {
            tracing::debug!(error = %e, "Unable to inspect Windows UI Automation tree");
            MonitorObservation::indeterminate(MonitorStatus::Unknown)
        }
    }
}

pub(crate) fn inspect(target_app_name: &str) -> anyhow::Result<WindowsInspection> {
    ensure_fixed_target_app(target_app_name)?;
    let automation = UIAutomation::new().or_else(|_| UIAutomation::new_direct())?;
    let trusted_running_targets = if is_builtin_target_name(target_app_name) {
        trusted_running_target_processes_checked(target_app_name)?
    } else {
        Vec::new()
    };
    let trusted_running_target = trusted_running_targets.first().cloned();
    let trusted_process_ids = trusted_running_targets
        .iter()
        .map(|target| target.process_id as u32)
        .collect::<Vec<_>>();

    let mut inspection = WindowsInspection {
        target: trusted_running_target,
        target_process_scan_complete: true,
        ..Default::default()
    };
    let mut target_prompt: Option<WindowsPrompt> = None;
    let mut all_trusted_windows_classified = true;

    for candidate in native_visible_windows_for_trusted_process_ids(trusted_process_ids)? {
        let target_alias_matches = target_aliases(target_app_name)
            .contains(&normalized_identifier(&candidate.target.process_name));
        let Some(target_kind) = microsoft_rdp_target_kind(
            &candidate.target.process_name,
            &candidate.target.process_path,
        ) else {
            anyhow::bail!("trusted target process path identity changed during window enumeration");
        };
        if !target_alias_matches {
            anyhow::bail!("trusted target process name changed during window enumeration");
        }
        match windows_target_identity_trust(&candidate.target, target_kind) {
            WindowsSignatureTrust::Trusted => {}
            WindowsSignatureTrust::Rejected => anyhow::bail!(
                "trusted target executable identity changed during window enumeration"
            ),
            WindowsSignatureTrust::Indeterminate => {
                anyhow::bail!("trusted target executable signature state is indeterminate")
            }
        }
        if inspection.target.is_none() {
            inspection.target = Some(candidate.target.clone());
        }

        if target_window_should_be_scanned_for_prompt(
            target_app_name,
            &candidate.target,
            &candidate.class_name,
        ) {
            let window = automation
                .element_from_handle(Handle::from(candidate.window_handle))
                .context("unable to inspect a trusted target prompt window")?;
            let prompt_window = inspect_prompt_window(
                &automation,
                candidate.target.clone(),
                WindowsPromptTrust::TrustedTargetProcess,
                window,
            )?;
            inspection.password_like_plain_edit_rejected |=
                prompt_window.password_like_plain_edit_rejected;
            all_trusted_windows_classified &= prompt_window.scan_complete;
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
        } else {
            all_trusted_windows_classified = false;
        }
    }

    inspection.prompt = target_prompt;
    inspection.prompt_scan_complete =
        all_trusted_windows_classified && !inspection.password_like_plain_edit_rejected;

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

    for candidate in native_prompt_snapshot_candidates(process_id, window_handle, window_title)? {
        let Some(trust) = prompt_candidate_trust(
            target_app_name,
            &candidate.target,
            &candidate.class_name,
            candidate.window_handle,
        ) else {
            continue;
        };

        let window = automation
            .element_from_handle(Handle::from(candidate.window_handle))
            .context("unable to inspect the exact credential prompt snapshot")?;
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
) -> Result<WindowsFillResult, WindowsFillFailure> {
    activate_window(prompt.target.window_handle).map_err(WindowsFillFailure::before_write)?;
    guard().map_err(WindowsFillFailure::before_write)?;
    let prompt =
        revalidate_prompt(target_app_name, prompt).map_err(WindowsFillFailure::before_write)?;
    guard().map_err(WindowsFillFailure::before_write)?;

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
            .map_err(|failure| {
                WindowsFillFailure {
                    error: anyhow::anyhow!(
                        "keyboard password input is disabled on Windows; direct UIA password fill failed: {failure}"
                    ),
                    cleanup_prompt: failure.cleanup_prompt,
                }
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
) -> Result<WindowsFillResult, WindowsFillFailure> {
    let (prompt, value) = direct_set_value_pattern_after_final_validation(target_app_name, prompt)
        .map_err(WindowsFillFailure::before_write)?;
    guard().map_err(WindowsFillFailure::before_write)?;
    if let Err(error) = set_zeroizing_password_value(&value, password) {
        return Err(WindowsFillFailure::ambiguous_write(error, prompt));
    }
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
    let pre_submit_session_windows = trusted_session_windows(target_app_name)?;

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
    let submitted_prompt = WindowsSubmittedPrompt::new(&prompt, pre_submit_session_windows)?;
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
        submitted_prompt: Some(submitted_prompt),
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
    let (current_target, class_name) = target_details_from_hwnd_checked(hwnd)
        .context("original filled prompt window disappeared before cleanup")?;
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
    if !uia_element_bound_to_prompt_window_checked(
        &automation,
        &filled_prompt.prompt_root,
        &filled_prompt.prompt_root,
        expected,
    )? || !uia_element_bound_to_prompt_window_checked(
        &automation,
        &filled_prompt.password_field,
        &filled_prompt.prompt_root,
        expected,
    )? {
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
    fn new(
        prompt: &WindowsPrompt,
        pre_submit_session_windows: Vec<WindowsSessionWindow>,
    ) -> anyhow::Result<Self> {
        let prompt_runtime_id = prompt
            .prompt_root
            .get_runtime_id()
            .context("submitted prompt UI Automation identity unavailable")?;
        if prompt_runtime_id.is_empty() {
            anyhow::bail!("submitted prompt UI Automation identity is empty");
        }
        Ok(Self {
            process_id: prompt.target.process_id,
            prompt_window_handle: prompt.target.window_handle,
            prompt_window_title: prompt.target.window_title.clone(),
            email: prompt.email.clone().unwrap_or_default(),
            trust: prompt.trust,
            prompt_runtime_id,
            pre_submit_session_windows,
        })
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
    let mut consecutive_submitted_prompt_absences = 0_u8;
    loop {
        match inspect(target_app_name) {
            Ok(inspection) => {
                let submitted_presence = submitted_prompt
                    .map(|submitted| {
                        submitted_prompt_presence(
                            target_app_name,
                            submitted,
                            expected_process_id,
                            expected_email,
                        )
                        .unwrap_or(SubmittedPromptPresence::Indeterminate)
                    })
                    .unwrap_or(SubmittedPromptPresence::Indeterminate);
                consecutive_submitted_prompt_absences = next_submitted_prompt_absence_observations(
                    consecutive_submitted_prompt_absences,
                    submitted_presence,
                );
                let submitted_prompt_confirmed_absent =
                    submitted_prompt.is_some() && consecutive_submitted_prompt_absences >= 2;
                let target_running = inspection.target.as_ref().is_some_and(|target| {
                    target.process_id == expected_process_id
                        || target_app_matches(target_app_name, target)
                });

                if let Some(prompt) = inspection.prompt {
                    return if prompt
                        .email
                        .as_deref()
                        .is_some_and(|email| usernames_match(email, expected_email))
                    {
                        "still_prompt"
                    } else if prompt.email.is_some() {
                        "prompt_mismatch"
                    } else {
                        "prompt_gone_unknown"
                    };
                }

                if let Some(state) = classify_post_submit_state(
                    None,
                    target_running,
                    submitted_prompt_has_new_session(
                        submitted_prompt,
                        &inspection.session_windows,
                        expected_process_id,
                        expected_email,
                    ) && submitted_prompt_confirmed_absent
                        && inspection.prompt_scan_complete,
                    expected_email,
                ) {
                    return state;
                }
            }
            Err(_) => {
                consecutive_submitted_prompt_absences = 0;
            }
        }

        if started.elapsed() >= timeout {
            return "prompt_gone_unknown";
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn next_submitted_prompt_absence_observations(
    previous: u8,
    presence: SubmittedPromptPresence,
) -> u8 {
    match presence {
        SubmittedPromptPresence::Absent => previous.saturating_add(1),
        SubmittedPromptPresence::Present | SubmittedPromptPresence::Indeterminate => 0,
    }
}

fn submitted_prompt_presence(
    target_app_name: &str,
    submitted: &WindowsSubmittedPrompt,
    expected_process_id: i32,
    expected_email: &str,
) -> anyhow::Result<SubmittedPromptPresence> {
    if submitted.process_id != expected_process_id
        || submitted.process_id <= 0
        || submitted.prompt_window_handle == 0
        || submitted.prompt_window_title.trim().is_empty()
        || submitted.prompt_runtime_id.is_empty()
        || !usernames_match(&submitted.email, expected_email)
    {
        return Ok(SubmittedPromptPresence::Indeterminate);
    }

    let hwnd = hwnd_from_handle(submitted.prompt_window_handle);
    if !unsafe { IsWindow(Some(hwnd)) }.as_bool() {
        return submitted_prompt_absent_after_complete_native_enumeration(submitted);
    }
    let mut live_process_id = 0_u32;
    let thread_id = unsafe { GetWindowThreadProcessId(hwnd, Some(&mut live_process_id)) };
    if thread_id == 0 || live_process_id == 0 {
        anyhow::bail!("submitted prompt native window identity is unavailable");
    }
    if live_process_id != submitted.process_id as u32 {
        return submitted_prompt_absent_after_complete_native_enumeration(submitted);
    }

    let (live_target, class_name) = target_details_from_hwnd_checked(hwnd)
        .context("submitted prompt native target details are unavailable")?;
    if prompt_candidate_trust(
        target_app_name,
        &live_target,
        &class_name,
        submitted.prompt_window_handle,
    ) != Some(submitted.trust)
    {
        return Ok(SubmittedPromptPresence::Indeterminate);
    }

    let automation = UIAutomation::new().or_else(|_| UIAutomation::new_direct())?;
    let current_prompt_root = automation
        .element_from_handle(Handle::from(submitted.prompt_window_handle))
        .context("submitted prompt UI Automation root is unavailable")?;
    let current_runtime_id = current_prompt_root
        .get_runtime_id()
        .context("submitted prompt UI Automation identity is unavailable")?;
    if current_runtime_id == submitted.prompt_runtime_id {
        Ok(SubmittedPromptPresence::Present)
    } else {
        submitted_prompt_absent_after_complete_native_enumeration(submitted)
    }
}

fn submitted_prompt_absent_after_complete_native_enumeration(
    submitted: &WindowsSubmittedPrompt,
) -> anyhow::Result<SubmittedPromptPresence> {
    let remaining = native_prompt_snapshot_candidates(
        submitted.process_id,
        submitted.prompt_window_handle,
        &submitted.prompt_window_title,
    )?;
    Ok(if remaining.is_empty() {
        SubmittedPromptPresence::Absent
    } else {
        SubmittedPromptPresence::Indeterminate
    })
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
    let (current_target, class_name) = target_details_from_hwnd_checked(hwnd)
        .context("credential prompt window disappeared before password insertion")?;
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
    let (current_target, class_name) = target_details_from_hwnd_checked(hwnd)
        .with_context(|| format!("credential prompt disappeared before {action}"))?;
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

fn uia_element_bound_to_prompt_window_checked(
    automation: &UIAutomation,
    element: &UIElement,
    prompt_root: &UIElement,
    target: &WindowsTarget,
) -> anyhow::Result<bool> {
    if target.process_id <= 0 || target.window_handle == 0 {
        return Ok(false);
    }
    if prompt_root
        .get_process_id()
        .context("prompt root process identity unavailable")?
        != target.process_id as u32
        || element
            .get_process_id()
            .context("prompt element process identity unavailable")?
            != target.process_id as u32
    {
        return Ok(false);
    }
    if prompt_root
        .get_native_window_handle()
        .map(Into::<isize>::into)
        .context("prompt root native window identity unavailable")?
        != target.window_handle
    {
        return Ok(false);
    }

    let walker = automation
        .get_raw_view_walker()
        .context("UI Automation raw-view walker unavailable")?;
    let mut current = element.clone();
    for _ in 0..=UIA_SEARCH_DEPTH {
        if current
            .get_process_id()
            .context("prompt ancestry process identity unavailable")?
            != target.process_id as u32
        {
            return Ok(false);
        }
        let native_handle = current
            .get_native_window_handle()
            .map(Into::<isize>::into)
            .context("prompt ancestry native window identity unavailable")?;
        if native_handle != 0
            && !native_hwnd_is_within_prompt_window(
                native_handle,
                target.window_handle,
                target.process_id,
            )
        {
            return Ok(false);
        }
        if automation
            .compare_elements(&current, prompt_root)
            .context("unable to compare prompt ancestry elements")?
        {
            return Ok(true);
        }
        let parent = walker
            .get_parent(&current)
            .context("unable to traverse prompt ancestry")?;
        current = parent;
    }
    Ok(false)
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
    if !uia_element_bound_to_prompt_window_checked(
        &automation,
        &prompt.prompt_root,
        &prompt.prompt_root,
        &prompt.target,
    )? {
        anyhow::bail!("credential prompt root is no longer bound to the trusted process window");
    }
    if !uia_element_bound_to_prompt_window_checked(
        &automation,
        &prompt.password_field,
        &prompt.prompt_root,
        &prompt.target,
    )? {
        anyhow::bail!("password field provider is no longer bound to the trusted prompt window");
    }
    if let Some(button) = prompt.submit_button.as_ref() {
        if !uia_element_bound_to_prompt_window_checked(
            &automation,
            button,
            &prompt.prompt_root,
            &prompt.target,
        )? {
            anyhow::bail!("submit button provider is no longer bound to the trusted prompt window");
        }
    }
    for element in &prompt.identity_elements {
        if !uia_element_bound_to_prompt_window_checked(
            &automation,
            element,
            &prompt.prompt_root,
            &prompt.target,
        )? {
            anyhow::bail!(
                "prompt identity provider is no longer bound to the trusted prompt window"
            );
        }
    }
    Ok(())
}

struct PromptWindowInspection {
    prompt: Option<WindowsPrompt>,
    password_like_plain_edit_rejected: bool,
    scan_complete: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PromptCandidateSelection {
    None,
    Unique,
    Unusable,
    Ambiguous,
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
    if !is_usable_window_checked(&window)? {
        return Ok(PromptWindowInspection {
            prompt: None,
            password_like_plain_edit_rejected: false,
            scan_complete: false,
        });
    }
    if !uia_element_bound_to_prompt_window_checked(automation, &window, &window, &target)? {
        anyhow::bail!("credential prompt root is not bound to the trusted PID/HWND/root");
    }

    let condition = automation
        .create_true_condition()
        .context("unable to create the trusted prompt UI search condition")?;
    let elements = window
        .find_all(TreeScope::Descendants, &condition)
        .context("unable to enumerate the trusted credential prompt UI tree")?;
    if elements.len() > MAX_ELEMENT_COUNT {
        anyhow::bail!("trusted credential prompt UI tree exceeds the safe inspection limit");
    }

    let (selection, prompt_candidate) = select_prompt_candidate(&target.window_title, &elements)?;
    if selection == PromptCandidateSelection::Ambiguous {
        anyhow::bail!("multiple secure credential prompt candidates are visible");
    }
    if selection == PromptCandidateSelection::Unusable {
        anyhow::bail!("secure credential prompt candidate identity is insufficient");
    }
    let Some(prompt_candidate) = prompt_candidate else {
        let password_like_plain_edit_rejected = has_password_like_plain_edit_checked(&elements)?;
        return Ok(PromptWindowInspection {
            prompt: None,
            password_like_plain_edit_rejected,
            scan_complete: !password_like_plain_edit_rejected,
        });
    };
    let sensitive_elements_bound = uia_element_bound_to_prompt_window_checked(
        automation,
        &prompt_candidate.password_field,
        &window,
        &target,
    )? && match prompt_candidate.submit_button.as_ref() {
        Some(button) => {
            uia_element_bound_to_prompt_window_checked(automation, button, &window, &target)?
        }
        None => true,
    };
    let sensitive_elements_bound = if sensitive_elements_bound {
        let mut all_identity_elements_bound = true;
        for element in &prompt_candidate.identity_elements {
            if !uia_element_bound_to_prompt_window_checked(automation, element, &window, &target)? {
                all_identity_elements_bound = false;
                break;
            }
        }
        all_identity_elements_bound
    } else {
        false
    };
    if !sensitive_elements_bound {
        anyhow::bail!("credential prompt providers are not bound to the trusted PID/HWND/root");
    }

    let password_field_description =
        redacted_element_description_checked(&prompt_candidate.password_field)?;
    let password_field_role = element_role_text_checked(&prompt_candidate.password_field)?;
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
        scan_complete: true,
    })
}

fn has_password_like_plain_edit_checked(elements: &[UIElement]) -> anyhow::Result<bool> {
    for element in elements {
        if !is_native_password_field_checked(element)?
            && is_password_like_edit_checked(element)?
            && prompt_element_rect_checked(element)?.is_some()
        {
            return Ok(true);
        }
    }
    Ok(false)
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
    scan_complete: bool,
}

struct NativeVisibleWindowSearch {
    trusted_process_ids: Vec<u32>,
    candidates: Vec<NativePromptSnapshotCandidate>,
    scan_complete: bool,
}

fn native_prompt_snapshot_candidates(
    process_id: i32,
    window_handle: isize,
    window_title: &str,
) -> anyhow::Result<Vec<NativePromptSnapshotCandidate>> {
    if process_id <= 0 || window_handle == 0 {
        return Ok(Vec::new());
    }

    let mut search = NativePromptSnapshotSearch {
        process_id,
        window_handle,
        window_title: window_title.trim().to_string(),
        candidates: Vec::new(),
        scan_complete: true,
    };
    unsafe {
        EnumWindows(
            Some(enum_native_prompt_snapshot_window),
            LPARAM(&mut search as *mut _ as isize),
        )?;
    }
    if !search.scan_complete {
        anyhow::bail!("exact native prompt window enumeration was incomplete");
    }
    if search
        .candidates
        .iter()
        .any(|candidate| candidate.target.process_path.trim().is_empty())
    {
        anyhow::bail!("exact native prompt process path was unavailable");
    }
    search
        .candidates
        .sort_by_key(|candidate| !window_handle_is_foreground(candidate.window_handle));
    Ok(search.candidates)
}

fn native_visible_windows(
    target_app_name: &str,
) -> anyhow::Result<Vec<NativePromptSnapshotCandidate>> {
    let trusted_process_ids = trusted_running_target_processes_checked(target_app_name)?
        .into_iter()
        .map(|target| target.process_id as u32)
        .collect::<Vec<_>>();
    native_visible_windows_for_trusted_process_ids(trusted_process_ids)
}

fn native_visible_windows_for_trusted_process_ids(
    trusted_process_ids: Vec<u32>,
) -> anyhow::Result<Vec<NativePromptSnapshotCandidate>> {
    if trusted_process_ids.is_empty() {
        return Ok(Vec::new());
    }
    let mut search = NativeVisibleWindowSearch {
        trusted_process_ids,
        candidates: Vec::new(),
        scan_complete: true,
    };
    unsafe {
        EnumWindows(
            Some(enum_native_visible_window),
            LPARAM(&mut search as *mut _ as isize),
        )?;
    }
    if !search.scan_complete {
        anyhow::bail!("trusted target visible-window enumeration was incomplete");
    }
    search
        .candidates
        .sort_by_key(|candidate| !window_handle_is_foreground(candidate.window_handle));
    Ok(search.candidates)
}

fn trusted_session_windows(target_app_name: &str) -> anyhow::Result<Vec<WindowsSessionWindow>> {
    Ok(native_visible_windows(target_app_name)?
        .into_iter()
        .filter(|candidate| is_probable_session_window_title(&candidate.target.window_title))
        .map(|candidate| WindowsSessionWindow {
            process_id: candidate.target.process_id,
            window_title: candidate.target.window_title,
            window_handle: candidate.window_handle,
        })
        .collect())
}

unsafe extern "system" fn enum_native_visible_window(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let search = unsafe { &mut *(lparam.0 as *mut NativeVisibleWindowSearch) };

    let mut process_id = 0_u32;
    let thread_id = unsafe { GetWindowThreadProcessId(hwnd, Some(&mut process_id)) };
    if thread_id == 0 || process_id == 0 || !search.trusted_process_ids.contains(&process_id) {
        return true.into();
    }

    match native_window_is_visible_and_sized_checked(hwnd) {
        Ok(true) => {}
        Ok(false) => return true.into(),
        Err(_) => {
            search.scan_complete = false;
            return false.into();
        }
    }

    let Ok((target, class_name)) = target_details_from_hwnd_checked(hwnd) else {
        search.scan_complete = false;
        return false.into();
    };
    search.candidates.push(NativePromptSnapshotCandidate {
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
    match native_window_is_visible_and_sized_checked(hwnd) {
        Ok(true) => {}
        Ok(false) => return true.into(),
        Err(_) => {
            search.scan_complete = false;
            return false.into();
        }
    }

    let Ok((target, class_name)) = target_details_from_hwnd_checked(hwnd) else {
        search.scan_complete = false;
        return false.into();
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
    native_window_is_visible_and_sized_checked(hwnd).unwrap_or(false)
}

fn native_window_is_visible_and_sized_checked(hwnd: HWND) -> anyhow::Result<bool> {
    if !unsafe { IsWindowVisible(hwnd) }.as_bool() {
        return Ok(false);
    }
    let mut rect = RECT::default();
    unsafe { GetWindowRect(hwnd, &mut rect) }
        .context("visible native window bounds unavailable")?;
    Ok(rect.right - rect.left > 20 && rect.bottom - rect.top > 20)
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

fn target_details_from_hwnd_checked(hwnd: HWND) -> anyhow::Result<(WindowsTarget, String)> {
    if hwnd.0.addr() == 0 {
        anyhow::bail!("native window handle is empty");
    }

    let mut process_id = 0_u32;
    let thread_id = unsafe { GetWindowThreadProcessId(hwnd, Some(&mut process_id)) };
    if thread_id == 0 || process_id == 0 {
        anyhow::bail!("native window PID/TID identity is unavailable");
    }

    let process_path = process_image_path(process_id).with_context(|| {
        format!("native window process path is unavailable for PID {process_id}")
    })?;
    let process_name = process_name_from_path(&process_path)
        .trim()
        .is_empty()
        .then(|| process_name_from_snapshot(process_id))
        .flatten()
        .unwrap_or_else(|| process_name_from_path(&process_path));
    let window_handle = hwnd.0.addr() as isize;
    let window_title = native_window_text_checked(hwnd)?;
    let class_name = native_window_class_checked(hwnd)?;
    let target = WindowsTarget {
        process_id: process_id as i32,
        process_name,
        process_path,
        window_title,
        window_handle,
        frontmost: window_handle_is_foreground(window_handle),
    };

    Ok((target, class_name))
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

fn native_window_text_checked(hwnd: HWND) -> anyhow::Result<String> {
    let mut buffer = [0_u16; 512];
    let len = unsafe { GetWindowTextW(hwnd, &mut buffer) };
    if len == 0 && unsafe { GetLastError() } != ERROR_SUCCESS {
        anyhow::bail!("native window title is unavailable");
    }
    Ok(wide_buffer_to_string(&buffer, len.max(0) as usize))
}

fn native_window_class_checked(hwnd: HWND) -> anyhow::Result<String> {
    let mut buffer = [0_u16; 256];
    let len = unsafe { GetClassNameW(hwnd, &mut buffer) };
    if len <= 0 {
        anyhow::bail!("native window class is unavailable");
    }
    Ok(wide_buffer_to_string(&buffer, len as usize))
}

fn wide_buffer_to_string(buffer: &[u16], len: usize) -> String {
    String::from_utf16_lossy(&buffer[..len.min(buffer.len())])
}

fn is_usable_window_checked(window: &UIElement) -> anyhow::Result<bool> {
    if window
        .is_offscreen()
        .context("prompt window visibility unavailable")?
        || !window
            .is_enabled()
            .context("prompt window enabled state unavailable")?
    {
        return Ok(false);
    }
    window
        .get_bounding_rectangle()
        .context("prompt window bounds unavailable")
        .map(|rect| rect.get_width() > 20 && rect.get_height() > 20)
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

fn select_prompt_candidate(
    window_title: &str,
    elements: &[UIElement],
) -> anyhow::Result<(PromptCandidateSelection, Option<PromptCandidate>)> {
    let login_title = login_title_like(window_title);
    let mut selected = None;
    let password_scan = password_field_candidates_checked(elements)?;
    let mut secure_candidate_unusable = password_scan.unusable_visible_secure_field_seen;

    for candidate in password_scan.candidates {
        let submit_button = select_submit_button_for_password_checked(elements, candidate.rect)?;
        let submit_rect = submit_button
            .as_ref()
            .map(prompt_element_rect_checked)
            .transpose()?
            .flatten();
        let (prompt_text, identity_elements) =
            collect_prompt_text_checked(elements, candidate.rect, submit_rect)?;
        let prompt_email = extract_email_like(&prompt_text);
        if prompt_email.is_none() && !login_title {
            secure_candidate_unusable = true;
            continue;
        }

        let prompt_candidate = PromptCandidate {
            email: prompt_email,
            password_field: candidate.element,
            submit_button,
            identity_elements,
        };
        if selected.is_some() {
            return Ok((PromptCandidateSelection::Ambiguous, None));
        }
        selected = Some(prompt_candidate);
    }

    let selection = match (selected.is_some(), secure_candidate_unusable) {
        (_, true) => PromptCandidateSelection::Unusable,
        (true, false) => PromptCandidateSelection::Unique,
        (false, false) => PromptCandidateSelection::None,
    };
    Ok((selection, selected))
}

struct PasswordFieldCandidateScan {
    candidates: Vec<PasswordFieldCandidate>,
    unusable_visible_secure_field_seen: bool,
}

fn password_field_candidates_checked(
    elements: &[UIElement],
) -> anyhow::Result<PasswordFieldCandidateScan> {
    let mut candidates = Vec::new();
    let mut unusable_visible_secure_field_seen = false;
    for element in elements {
        if !has_native_password_field_identity_checked(element)? {
            continue;
        }
        if element
            .is_offscreen()
            .context("secure password field visibility unavailable")?
        {
            continue;
        }
        if !element
            .is_enabled()
            .context("secure password field enabled state unavailable")?
        {
            unusable_visible_secure_field_seen = true;
            continue;
        }
        if let Some(rect) = prompt_element_rect_checked(element)? {
            candidates.push(PasswordFieldCandidate {
                element: element.clone(),
                rect,
            });
        } else {
            unusable_visible_secure_field_seen = true;
        }
    }
    Ok(PasswordFieldCandidateScan {
        candidates,
        unusable_visible_secure_field_seen,
    })
}

struct SubmitButtonCandidate {
    element: UIElement,
    enabled: bool,
    text: String,
}

fn select_submit_button_for_password_checked(
    elements: &[UIElement],
    password_rect: ElementRect,
) -> anyhow::Result<Option<UIElement>> {
    let mut buttons = Vec::new();
    for element in elements {
        if element
            .get_control_type()
            .context("submit candidate control type unavailable")?
            != ControlType::Button
            || element
                .is_offscreen()
                .context("submit candidate visibility unavailable")?
        {
            continue;
        }
        let Some(rect) = prompt_element_rect_checked(element)? else {
            continue;
        };
        if !submit_rect_related_to_password(password_rect, rect) {
            continue;
        }
        buttons.push(SubmitButtonCandidate {
            element: element.clone(),
            enabled: element
                .is_enabled()
                .context("submit candidate enabled state unavailable")?,
            text: submit_button_text_checked(element)?,
        });
    }

    if let Some(button) = unique_ranked_submit_button(&buttons, |button| {
        button.enabled && submit_label_rank(&button.text) == Some(0)
    })? {
        return Ok(Some(button));
    }
    if let Some(button) = unique_ranked_submit_button(&buttons, |button| {
        button.enabled && is_preferred_submit_label(&button.text)
    })? {
        return Ok(Some(button));
    }
    if let Some(button) = unique_ranked_submit_button(&buttons, |button| {
        submit_label_rank(&button.text) == Some(0)
    })? {
        return Ok(Some(button));
    }
    unique_ranked_submit_button(&buttons, |button| is_preferred_submit_label(&button.text))
}

fn unique_ranked_submit_button<F>(
    buttons: &[SubmitButtonCandidate],
    matches_rank: F,
) -> anyhow::Result<Option<UIElement>>
where
    F: Fn(&SubmitButtonCandidate) -> bool,
{
    Ok(unique_matching_index(buttons, matches_rank)?.map(|index| buttons[index].element.clone()))
}

fn unique_matching_index<T, F>(items: &[T], matches: F) -> anyhow::Result<Option<usize>>
where
    F: Fn(&T) -> bool,
{
    let mut matching = items
        .iter()
        .enumerate()
        .filter(|(_, item)| matches(item))
        .map(|(index, _)| index);
    let Some(selected) = matching.next() else {
        return Ok(None);
    };
    if matching.next().is_some() {
        anyhow::bail!(
            "multiple equally ranked submit buttons are related to the secure password field"
        );
    }
    Ok(Some(selected))
}

fn submit_button_text_checked(element: &UIElement) -> anyhow::Result<String> {
    let mut text = String::new();
    push_text(&mut text, element.get_name().ok());
    push_text(&mut text, element.get_automation_id().ok());
    push_text(&mut text, element.get_help_text().ok());
    push_text(&mut text, element.get_item_status().ok());
    Ok(text)
}

fn collect_prompt_text_checked(
    elements: &[UIElement],
    password_rect: ElementRect,
    submit_rect: Option<ElementRect>,
) -> anyhow::Result<(String, Vec<UIElement>)> {
    let mut text = String::new();
    let mut identity_elements = Vec::new();
    for element in elements {
        if !prompt_text_element_should_contribute_checked(element)? {
            continue;
        }
        let Some(rect) = prompt_element_rect_checked(element)? else {
            continue;
        };
        if !prompt_text_rect_related_to_password(password_rect, submit_rect, rect) {
            continue;
        }

        let before = text.len();
        push_text(&mut text, element.get_name().ok());
        push_text(&mut text, element.get_help_text().ok());
        push_text(&mut text, element.get_item_status().ok());

        if element
            .get_control_type()
            .context("prompt identity control type unavailable")?
            == ControlType::Edit
        {
            if let Ok(value) = element.get_pattern::<UIValuePattern>() {
                push_text(&mut text, value.get_value().ok());
            }
        }
        if text.len() > before {
            identity_elements.push(element.clone());
        }
    }
    Ok((text, identity_elements))
}

fn prompt_text_element_should_contribute_checked(element: &UIElement) -> anyhow::Result<bool> {
    if element
        .is_offscreen()
        .context("prompt identity visibility unavailable")?
    {
        return Ok(false);
    }
    let control_type = element
        .get_control_type()
        .context("prompt identity control type unavailable")?;
    if control_type == ControlType::Edit
        && (is_native_password_field_checked(element)? || is_password_like_edit_checked(element)?)
    {
        return Ok(false);
    }

    Ok(control_type != ControlType::Button)
}

fn prompt_element_rect_checked(element: &UIElement) -> anyhow::Result<Option<ElementRect>> {
    let rect = element
        .get_bounding_rectangle()
        .context("prompt element bounds unavailable")?;
    Ok(ElementRect::new(
        rect.get_left(),
        rect.get_top(),
        rect.get_right(),
        rect.get_bottom(),
    ))
}

fn prompt_element_rect(element: &UIElement) -> Option<ElementRect> {
    prompt_element_rect_checked(element).ok().flatten()
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
    is_native_password_field_checked(element).unwrap_or(false)
}

fn is_native_password_field_checked(element: &UIElement) -> anyhow::Result<bool> {
    if !has_native_password_field_identity_checked(element)? {
        return Ok(false);
    }
    Ok(!element
        .is_offscreen()
        .context("secure password field visibility unavailable")?
        && element
            .is_enabled()
            .context("secure password field enabled state unavailable")?)
}

fn has_native_password_field_identity(element: &UIElement) -> bool {
    has_native_password_field_identity_checked(element).unwrap_or(false)
}

fn has_native_password_field_identity_checked(element: &UIElement) -> anyhow::Result<bool> {
    if element
        .get_control_type()
        .context("secure password candidate control type unavailable")?
        != ControlType::Edit
    {
        return Ok(false);
    }
    element
        .is_password()
        .context("secure password candidate IsPassword state unavailable")
}

fn is_password_like_edit_checked(element: &UIElement) -> anyhow::Result<bool> {
    if element
        .get_control_type()
        .context("plain edit control type unavailable")?
        != ControlType::Edit
        || element
            .is_offscreen()
            .context("plain edit visibility unavailable")?
        || !element
            .is_enabled()
            .context("plain edit enabled state unavailable")?
    {
        return Ok(false);
    }
    Ok(text_contains_password_cue(&element_label_text_checked(
        element,
    )?))
}

fn element_label_text_checked(element: &UIElement) -> anyhow::Result<String> {
    let mut text = String::new();
    push_text(&mut text, element.get_name().ok());
    push_text(&mut text, element.get_help_text().ok());
    push_text(&mut text, element.get_automation_id().ok());
    push_text(&mut text, element.get_classname().ok());
    push_text(&mut text, element.get_localized_control_type().ok());
    if let Ok(label) = element.get_labeled_by() {
        push_text(&mut text, label.get_name().ok());
    }
    Ok(text)
}

fn element_role_text_checked(element: &UIElement) -> anyhow::Result<String> {
    let control_type = element
        .get_control_type()
        .map(|control_type| format!("{control_type:?}"))
        .context("password field control type unavailable")?;
    let localized = element.get_localized_control_type().unwrap_or_default();
    let class = element.get_classname().unwrap_or_default();
    Ok([control_type, localized, class]
        .into_iter()
        .filter(|part| !part.trim().is_empty())
        .collect::<Vec<_>>()
        .join(" "))
}

fn redacted_element_description_checked(element: &UIElement) -> anyhow::Result<String> {
    let role = element_role_text_checked(element)?;
    Ok(if role.trim().is_empty() {
        "password field".to_string()
    } else {
        format!("password field ({role})")
    })
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
    trusted_running_target_processes_checked(target_app_name)
        .ok()
        .and_then(|targets| targets.into_iter().next())
}

fn trusted_running_target_processes_checked(
    target_app_name: &str,
) -> anyhow::Result<Vec<WindowsTarget>> {
    let aliases = target_aliases(target_app_name);
    if aliases.is_empty() {
        return Ok(Vec::new());
    }

    let mut targets = Vec::new();
    for (process_id, snapshot_name) in running_processes_checked()? {
        let normalized = normalized_identifier(
            Path::new(&snapshot_name)
                .file_stem()
                .and_then(|stem| stem.to_str())
                .unwrap_or(&snapshot_name),
        );
        if !aliases.contains(&normalized) {
            continue;
        }

        let process_path = process_image_path(process_id).with_context(|| {
            format!("unable to query a target-like process image for PID {process_id}")
        })?;
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

        let Some(kind) = microsoft_rdp_target_kind(&target.process_name, &target.process_path)
        else {
            continue;
        };
        match windows_target_identity_trust(&target, kind) {
            WindowsSignatureTrust::Trusted => targets.push(target),
            WindowsSignatureTrust::Rejected => continue,
            WindowsSignatureTrust::Indeterminate => {
                anyhow::bail!("target-like process identity is indeterminate for PID {process_id}")
            }
        }
    }

    Ok(targets)
}

fn running_processes_checked() -> anyhow::Result<Vec<(u32, String)>> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            .context("unable to create the native process snapshot")?;
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        let mut processes = Vec::new();
        if Process32FirstW(snapshot, &mut entry).is_err() {
            let error = GetLastError();
            let _ = CloseHandle(snapshot);
            anyhow::bail!("unable to read the first native process snapshot entry: {error:?}");
        }
        loop {
            processes.push((entry.th32ProcessID, process_entry_name(&entry)));
            if Process32NextW(snapshot, &mut entry).is_err() {
                let error = GetLastError();
                let _ = CloseHandle(snapshot);
                if error == ERROR_NO_MORE_FILES {
                    return Ok(processes);
                }
                anyhow::bail!("native process enumeration failed before completion: {error:?}");
            }
        }
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

#[cfg(test)]
fn system_credential_dialog_matches(target: &WindowsTarget, class_name: &str) -> bool {
    credential_dialog_title_like(&target.window_title)
        && trusted_windows_credential_broker(target)
        && credential_dialog_class_like(class_name)
}

#[cfg(test)]
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

#[cfg(test)]
fn trusted_windows_credential_broker_path(path: &str) -> bool {
    trusted_windows_system_exe_path(path, "credentialuibroker.exe")
}

#[cfg(test)]
fn trusted_windows_credential_broker(target: &WindowsTarget) -> bool {
    normalized_identifier(&target.process_name) == "credentialuibroker"
        && trusted_windows_credential_broker_path(&target.process_path)
        && windows_target_identity_is_trusted(target, WindowsMicrosoftTargetKind::CredentialBroker)
}

fn windows_target_identity_is_trusted(
    target: &WindowsTarget,
    kind: WindowsMicrosoftTargetKind,
) -> bool {
    matches!(
        windows_target_identity_trust(target, kind),
        WindowsSignatureTrust::Trusted
    )
}

fn windows_target_identity_trust(
    target: &WindowsTarget,
    kind: WindowsMicrosoftTargetKind,
) -> WindowsSignatureTrust {
    #[cfg(test)]
    if let Some(result) = windows_target_identity_override_result(target, kind) {
        return if result {
            WindowsSignatureTrust::Trusted
        } else {
            WindowsSignatureTrust::Rejected
        };
    }

    if target.process_id <= 0 || target.process_path.trim().is_empty() {
        return WindowsSignatureTrust::Indeterminate;
    }
    let signature_trust = windows_executable_microsoft_signature_trust(&target.process_path);
    if signature_trust != WindowsSignatureTrust::Trusted {
        return signature_trust;
    }
    if kind == WindowsMicrosoftTargetKind::WindowsAppsPackage {
        return if process_package_full_name(target.process_id)
            .as_deref()
            .is_some_and(trusted_windowsapps_microsoft_package_full_name)
        {
            WindowsSignatureTrust::Trusted
        } else {
            WindowsSignatureTrust::Indeterminate
        };
    }

    WindowsSignatureTrust::Trusted
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WindowsSignatureTrust {
    Trusted,
    Rejected,
    Indeterminate,
}

fn windows_executable_microsoft_signature_trust(path: &str) -> WindowsSignatureTrust {
    unsafe {
        winverifytrust_with_state_validator(path, |trust_data| {
            wintrust_state_microsoft_signer_trust(trust_data)
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
            let Some((publisher, cert_sha256)) = wintrust_state_leaf_identity(trust_data) else {
                return WindowsSignatureTrust::Indeterminate;
            };
            if publisher.trim().to_lowercase() == expected_publisher
                && cert_sha256 == expected_cert_sha256
            {
                WindowsSignatureTrust::Trusted
            } else {
                WindowsSignatureTrust::Rejected
            }
        }) == WindowsSignatureTrust::Trusted
    }
}

unsafe fn winverifytrust_with_state_validator(
    path: &str,
    validate_state: impl FnOnce(&WINTRUST_DATA) -> WindowsSignatureTrust,
) -> WindowsSignatureTrust {
    let mut path_wide = Path::new(path)
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    if path_wide.len() <= 1 {
        return WindowsSignatureTrust::Rejected;
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
    let state_trust = if status == 0 {
        validate_state(&trust_data)
    } else {
        WindowsSignatureTrust::Indeterminate
    };

    trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    let _ = unsafe {
        WinVerifyTrust(
            HWND::default(),
            &mut action,
            (&mut trust_data as *mut WINTRUST_DATA).cast::<c_void>(),
        )
    };

    classify_authenticode_status(status, state_trust)
}

fn classify_authenticode_status(
    status: i32,
    verified_state: WindowsSignatureTrust,
) -> WindowsSignatureTrust {
    if status == 0 {
        return verified_state;
    }

    if authenticode_status_is_definitive_rejection(status) {
        WindowsSignatureTrust::Rejected
    } else {
        // WinVerifyTrust can fail because its provider, revocation service,
        // certificate state, file I/O, or local policy was unavailable. Only
        // explicit signature/certificate rejection codes may prove that the
        // target is untrusted; every unknown or operational failure must keep
        // target presence indeterminate rather than collapsing to "absent".
        WindowsSignatureTrust::Indeterminate
    }
}

fn authenticode_status_is_definitive_rejection(status: i32) -> bool {
    [
        TRUST_E_NOSIGNATURE.0,
        TRUST_E_BAD_DIGEST.0,
        TRUST_E_MALFORMED_SIGNATURE.0,
        TRUST_E_CERT_SIGNATURE.0,
        TRUST_E_EXPLICIT_DISTRUST.0,
        TRUST_E_NO_SIGNER_CERT.0,
        CRYPT_E_NO_SIGNER.0,
        CRYPT_E_SIGNER_NOT_FOUND.0,
        CRYPT_E_REVOKED.0,
        CERT_E_REVOKED.0,
    ]
    .contains(&status)
}

#[cfg(test)]
fn classify_authenticode_test_status(
    status: i32,
    state_trust: WindowsSignatureTrust,
) -> WindowsSignatureTrust {
    classify_authenticode_status(status, state_trust)
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

unsafe fn wintrust_state_microsoft_signer_trust(
    trust_data: &WINTRUST_DATA,
) -> WindowsSignatureTrust {
    let provider = unsafe { WTHelperProvDataFromStateData(trust_data.hWVTStateData) };
    if provider.is_null() {
        return WindowsSignatureTrust::Indeterminate;
    }
    let signer = unsafe { WTHelperGetProvSignerFromChain(provider, 0, false, 0) };
    if signer.is_null() {
        return WindowsSignatureTrust::Indeterminate;
    }

    let Some(leaf_name) = (unsafe { signer_certificate_name(signer, 0) }) else {
        return WindowsSignatureTrust::Indeterminate;
    };
    if !microsoft_signing_leaf_name_is_allowed(&leaf_name) {
        return WindowsSignatureTrust::Rejected;
    }

    let chain_len = unsafe { (*signer).csCertChain };
    if chain_len <= 1 {
        return WindowsSignatureTrust::Trusted;
    }

    let mut unavailable_chain_name = false;
    for index in 1..chain_len {
        let Some(name) = (unsafe { signer_certificate_name(signer, index) }) else {
            unavailable_chain_name = true;
            continue;
        };
        if microsoft_chain_name_is_allowed(&name) {
            return WindowsSignatureTrust::Trusted;
        }
    }
    if unavailable_chain_name {
        WindowsSignatureTrust::Indeterminate
    } else {
        WindowsSignatureTrust::Rejected
    }
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
            trust: super::WindowsPromptTrust::TrustedTargetProcess,
            prompt_runtime_id: vec![42, 7],
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
    fn post_submit_requires_two_confirmed_exact_prompt_absences() {
        let mut observations = 0;
        observations = super::next_submitted_prompt_absence_observations(
            observations,
            super::SubmittedPromptPresence::Absent,
        );
        assert_eq!(observations, 1);

        observations = super::next_submitted_prompt_absence_observations(
            observations,
            super::SubmittedPromptPresence::Indeterminate,
        );
        assert_eq!(observations, 0);

        observations = super::next_submitted_prompt_absence_observations(
            observations,
            super::SubmittedPromptPresence::Absent,
        );
        observations = super::next_submitted_prompt_absence_observations(
            observations,
            super::SubmittedPromptPresence::Present,
        );
        assert_eq!(observations, 0);

        observations = super::next_submitted_prompt_absence_observations(
            observations,
            super::SubmittedPromptPresence::Absent,
        );
        observations = super::next_submitted_prompt_absence_observations(
            observations,
            super::SubmittedPromptPresence::Absent,
        );
        assert_eq!(observations, 2);
    }

    #[test]
    fn authenticode_operational_failures_and_missing_state_are_indeterminate() {
        for status in [
            windows::Win32::Foundation::CRYPT_E_REVOCATION_OFFLINE.0,
            windows::Win32::Foundation::CRYPT_E_NO_REVOCATION_CHECK.0,
            windows::Win32::Foundation::CRYPT_E_NO_REVOCATION_DLL.0,
            windows::Win32::Foundation::CERT_E_REVOCATION_FAILURE.0,
            windows::Win32::Foundation::TRUST_E_PROVIDER_UNKNOWN.0,
            windows::Win32::Foundation::TRUST_E_SYSTEM_ERROR.0,
            i32::MIN,
        ] {
            assert_eq!(
                super::classify_authenticode_test_status(
                    status,
                    super::WindowsSignatureTrust::Rejected,
                ),
                super::WindowsSignatureTrust::Indeterminate
            );
        }
        assert_eq!(
            super::classify_authenticode_test_status(
                0,
                super::WindowsSignatureTrust::Indeterminate,
            ),
            super::WindowsSignatureTrust::Indeterminate
        );
        assert_eq!(
            super::classify_authenticode_test_status(0, super::WindowsSignatureTrust::Trusted,),
            super::WindowsSignatureTrust::Trusted
        );
    }

    #[test]
    fn authenticode_explicit_signature_failures_are_rejected() {
        for status in [
            windows::Win32::Foundation::TRUST_E_NOSIGNATURE.0,
            windows::Win32::Foundation::TRUST_E_BAD_DIGEST.0,
            windows::Win32::Foundation::TRUST_E_MALFORMED_SIGNATURE.0,
            windows::Win32::Foundation::TRUST_E_EXPLICIT_DISTRUST.0,
            windows::Win32::Foundation::CRYPT_E_REVOKED.0,
            windows::Win32::Foundation::CERT_E_REVOKED.0,
        ] {
            assert_eq!(
                super::classify_authenticode_test_status(
                    status,
                    super::WindowsSignatureTrust::Indeterminate,
                ),
                super::WindowsSignatureTrust::Rejected
            );
        }
        assert_eq!(
            super::classify_authenticode_test_status(0, super::WindowsSignatureTrust::Rejected,),
            super::WindowsSignatureTrust::Rejected
        );
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
            "fn uia_element_bound_to_prompt_window_checked(",
            "fn native_hwnd_is_within_prompt_window(",
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
            "fn password_field_candidates_checked(",
            "struct SubmitButtonCandidate",
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
            "fn is_native_password_field_checked(",
            "fn has_native_password_field_identity(",
        );
        assert!(
            native_detection.contains("has_native_password_field_identity_checked"),
            "native password detection must require checked UIA IsPassword identity"
        );
        assert!(
            !native_detection.contains("text_contains_password_cue")
                && !native_detection.contains("element_label_text"),
            "native password detection must not use label-based password cues"
        );
    }

    #[test]
    fn prompt_scan_fails_closed_on_truncation_ambiguity_and_provider_binding() {
        let implementation = include_str!("windows_ui.rs");
        let inspection = source_between(
            implementation,
            "fn inspect_prompt_window(",
            "fn has_password_like_plain_edit_checked(",
        );

        assert!(inspection.contains("TreeScope::Descendants"));
        assert!(!inspection.contains("elements.truncate"));
        assert!(inspection.contains("exceeds the safe inspection limit"));
        assert!(inspection.contains("PromptCandidateSelection::Ambiguous"));
        assert!(inspection.contains("providers are not bound"));
    }

    #[test]
    fn equally_ranked_submit_candidates_are_rejected_as_ambiguous() {
        assert_eq!(
            super::unique_matching_index(&[1, 2, 3], |item| *item == 2).unwrap(),
            Some(1)
        );
        assert_eq!(
            super::unique_matching_index(&[1, 2, 3], |item| *item == 4).unwrap(),
            None
        );
        assert!(super::unique_matching_index(&[1, 2, 2], |item| *item == 2).is_err());
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
