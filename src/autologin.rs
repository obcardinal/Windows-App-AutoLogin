use crate::config::CredentialsConfig;
#[cfg(target_os = "macos")]
use crate::macos_identity;
#[cfg(target_os = "macos")]
use std::sync::OnceLock;
#[cfg(target_os = "macos")]
use tracing::info;
use tracing::warn;
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AccessibilityStatus {
    pub(crate) trusted: bool,
    pub(crate) raw_trusted: bool,
    pub(crate) identity_trusted: bool,
    pub(crate) current_process_path: String,
    pub(crate) app_bundle_path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AutoLoginResult {
    Submitted,
    PasswordTouchedWithoutSubmit,
}

impl AutoLoginResult {
    pub(crate) fn suppress_same_prompt_retry(self) -> bool {
        matches!(self, Self::Submitted | Self::PasswordTouchedWithoutSubmit)
    }
}

pub(crate) struct AutoLogin {
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    target_app_name: String,
}

impl AutoLogin {
    pub(crate) fn new(_target_app_name: impl Into<String>) -> Self {
        Self {
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            target_app_name: crate::config::TARGET_APP_NAME.to_string(),
        }
    }

    pub(crate) fn perform_login_with_password_guarded(
        &self,
        credentials: &CredentialsConfig,
        password: Zeroizing<String>,
        guard: impl Fn() -> anyhow::Result<()>,
    ) -> anyhow::Result<AutoLoginResult> {
        #[cfg(target_os = "macos")]
        {
            info!("perform_login: taking macOS path with guarded password");
            let result = perform_login_macos_with_password(
                &self.target_app_name,
                credentials,
                password,
                &guard,
            );
            if let Err(ref e) = result {
                warn!("perform_login (macOS) failed: {}", e);
            }
            result
        }
        #[cfg(target_os = "windows")]
        {
            let result = crate::windows_ui::perform_login_with_password_guarded(
                &self.target_app_name,
                credentials,
                password,
                &guard,
            );
            if let Err(ref e) = result {
                warn!("perform_login (Windows) failed: {}", e);
            }
            result
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            let _ = credentials;
            let _ = password;
            let _ = guard;
            warn!("perform_login: unsupported platform");
            anyhow::bail!("AutoLogin is only supported on macOS and Windows")
        }
    }

    pub(crate) fn verify_prompt_without_password(
        &self,
        credentials: &CredentialsConfig,
        guard: impl Fn() -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        #[cfg(target_os = "macos")]
        {
            guard()?;
            ensure_matching_prompt_email(
                &self.target_app_name,
                &credentials.username,
                credentials.prompt_window_title.as_deref(),
                credentials.prompt_process_id,
            )?;
            guard()
        }
        #[cfg(target_os = "windows")]
        {
            crate::windows_ui::verify_prompt_without_password(
                &self.target_app_name,
                credentials,
                &guard,
            )
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            let _ = credentials;
            let _ = guard;
            anyhow::bail!("AutoLogin is only supported on macOS and Windows")
        }
    }
}

pub(crate) fn check_accessibility_permissions() -> anyhow::Result<()> {
    #[cfg(target_os = "macos")]
    {
        let status = accessibility_status();
        if !status.trusted {
            if status.raw_trusted && !status.identity_trusted {
                anyhow::bail!(
                    "Accessibility is granted, but this app bundle is not trusted for automation: {}. \
                     Install a properly signed Windows App AutoLogin bundle at /Applications/WindowsAppAutoLogin.app.",
                    crate::user_paths::redacted_path(&status.current_process_path)
                );
            }
            anyhow::bail!(
                "Accessibility permission missing for this exact app: {}. \
                 Add or re-enable Windows App AutoLogin in System Settings → \
                 Privacy & Security → Accessibility, then restart the app.",
                crate::user_paths::redacted_path(&status.current_process_path)
            );
        }
    }
    Ok(())
}

pub(crate) fn accessibility_status() -> AccessibilityStatus {
    let current_process_path = std::env::current_exe()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let raw_trusted = raw_accessibility_is_trusted();
    let identity_trusted = current_app_identity_is_trusted();
    AccessibilityStatus {
        trusted: raw_trusted && identity_trusted,
        raw_trusted,
        identity_trusted,
        app_bundle_path: app_bundle_path_for_process(&current_process_path).unwrap_or_default(),
        current_process_path,
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn accessibility_is_trusted() -> bool {
    raw_accessibility_is_trusted() && current_app_identity_is_trusted()
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn accessibility_is_trusted() -> bool {
    true
}

#[cfg(target_os = "macos")]
fn raw_accessibility_is_trusted() -> bool {
    unsafe { AXIsProcessTrusted() != 0 }
}

#[cfg(not(target_os = "macos"))]
fn raw_accessibility_is_trusted() -> bool {
    true
}

#[cfg(target_os = "macos")]
static CURRENT_APP_IDENTITY_TRUSTED: OnceLock<bool> = OnceLock::new();

#[cfg(target_os = "macos")]
pub(crate) fn current_app_identity_is_trusted() -> bool {
    *CURRENT_APP_IDENTITY_TRUSTED.get_or_init(current_app_identity_is_trusted_uncached)
}

#[cfg(target_os = "macos")]
fn current_app_identity_is_trusted_uncached() -> bool {
    let Ok(exe_path) = std::env::current_exe() else {
        return false;
    };
    if crate::macos_identity::path_has_symlink_component(&exe_path) {
        return false;
    }
    let Some(bundle_path) = containing_app_bundle(&exe_path) else {
        return false;
    };
    if crate::macos_identity::path_has_symlink_component(&bundle_path) {
        return false;
    }
    app_bundle_identity_is_trusted(&bundle_path)
}

#[cfg(target_os = "macos")]
pub(crate) fn trusted_app_bundle_identity_is_trusted(bundle_path: &std::path::Path) -> bool {
    app_bundle_identity_is_trusted(bundle_path)
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn current_app_identity_is_trusted() -> bool {
    true
}

#[cfg(target_os = "macos")]
fn app_bundle_identity_is_trusted(bundle_path: &std::path::Path) -> bool {
    let Ok(bundle_path) = bundle_path.canonicalize() else {
        return false;
    };
    if crate::macos_identity::path_has_symlink_component(&bundle_path) {
        return false;
    }
    if bundle_identifier(&bundle_path).as_deref() != Some(crate::app_identity::macos_bundle_id()) {
        return false;
    }

    if crate::app_identity::macos_development_identity() {
        return development_app_bundle_identity_is_trusted(&bundle_path);
    }

    bundle_path == std::path::Path::new(crate::app_identity::TRUSTED_MACOS_BUNDLE_PATH)
        && app_bundle_signature_is_trusted(&bundle_path)
}

#[cfg(target_os = "macos")]
fn development_app_bundle_identity_is_trusted(bundle_path: &std::path::Path) -> bool {
    if !development_app_bundle_path_is_trusted(bundle_path) {
        return false;
    }
    crate::macos_identity::static_code_path_has_valid_internal_signature(bundle_path)
}

#[cfg(target_os = "macos")]
fn development_app_bundle_path_is_trusted(bundle_path: &std::path::Path) -> bool {
    [
        crate::app_identity::TRUSTED_MACOS_BUNDLE_PATH,
        crate::app_identity::DEVELOPMENT_MACOS_BUNDLE_PATH,
    ]
    .into_iter()
    .filter_map(|path| std::path::Path::new(path).canonicalize().ok())
    .any(|candidate| candidate == bundle_path)
}

#[cfg(target_os = "macos")]
fn app_bundle_signature_is_trusted(bundle_path: &std::path::Path) -> bool {
    let Some(team_id) = crate::app_identity::macos_team_id()
        .filter(|team_id| macos_identity::valid_team_id(team_id))
    else {
        return false;
    };

    macos_identity::verify_bundle_designated_requirement(
        bundle_path,
        crate::app_identity::macos_bundle_id(),
        team_id,
    )
    .unwrap_or(false)
}

#[cfg(target_os = "macos")]
fn bundle_identifier(bundle_path: &std::path::Path) -> Option<String> {
    let output = std::process::Command::new("/usr/libexec/PlistBuddy")
        .args(["-c", "Print :CFBundleIdentifier"])
        .arg(bundle_path.join("Contents/Info.plist"))
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
        .filter(|value| !value.is_empty())
}

#[cfg(target_os = "macos")]
pub(crate) fn request_accessibility_access_prompt() -> bool {
    unsafe {
        let keys = [kAXTrustedCheckOptionPrompt];
        let values = [kCFBooleanTrue];
        let options = CFDictionaryCreate(
            std::ptr::null(),
            keys.as_ptr(),
            values.as_ptr(),
            1,
            std::ptr::null(),
            std::ptr::null(),
        );
        if options.is_null() {
            return accessibility_is_trusted();
        }
        let trusted = AXIsProcessTrustedWithOptions(options) != 0;
        CFRelease(options);
        trusted && current_app_identity_is_trusted()
    }
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn request_accessibility_access_prompt() -> bool {
    true
}

pub(crate) fn open_accessibility_settings() -> anyhow::Result<()> {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("/usr/bin/open")
            .arg("x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility")
            .status()?;
    }
    Ok(())
}

fn app_bundle_path_for_process(process_path: &str) -> Option<String> {
    containing_app_bundle(std::path::Path::new(process_path)).map(|path| path.display().to_string())
}

fn containing_app_bundle(process_path: &std::path::Path) -> Option<std::path::PathBuf> {
    process_path
        .ancestors()
        .find(|path| path.extension().is_some_and(|ext| ext == "app"))
        .map(std::path::Path::to_path_buf)
}

#[cfg(target_os = "macos")]
#[link(name = "ApplicationServices", kind = "framework")]
unsafe extern "C" {
    fn AXIsProcessTrusted() -> u8;
    static kAXTrustedCheckOptionPrompt: *const std::ffi::c_void;
    fn AXIsProcessTrustedWithOptions(options: *const std::ffi::c_void) -> u8;
}

#[cfg(target_os = "macos")]
#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    static kCFBooleanTrue: *const std::ffi::c_void;
    fn CFDictionaryCreate(
        allocator: *const std::ffi::c_void,
        keys: *const *const std::ffi::c_void,
        values: *const *const std::ffi::c_void,
        num_values: isize,
        key_callbacks: *const std::ffi::c_void,
        value_callbacks: *const std::ffi::c_void,
    ) -> *const std::ffi::c_void;
    fn CFRelease(cf: *const std::ffi::c_void);
}

#[cfg(target_os = "macos")]
fn perform_login_macos_with_password(
    app_name: &str,
    credentials: &CredentialsConfig,
    password: Zeroizing<String>,
    guard: &dyn Fn() -> anyhow::Result<()>,
) -> anyhow::Result<AutoLoginResult> {
    info!("perform_login_macos: starting guarded macOS login sequence");

    guard()?;
    ensure_matching_prompt_email(
        app_name,
        &credentials.username,
        credentials.prompt_window_title.as_deref(),
        credentials.prompt_process_id,
    )?;

    guard()?;
    perform_login_macos_after_verified_prompt(app_name, credentials, password, guard)
}

#[cfg(target_os = "macos")]
fn perform_login_macos_after_verified_prompt(
    app_name: &str,
    credentials: &CredentialsConfig,
    password: Zeroizing<String>,
    guard: &dyn Fn() -> anyhow::Result<()>,
) -> anyhow::Result<AutoLoginResult> {
    guard()?;

    info!("perform_login_macos: native AX fill path selected; submit remains bounded");
    let prompt = matching_native_prompt(
        app_name,
        &credentials.username,
        credentials.prompt_window_title.as_deref(),
        credentials.prompt_process_id,
    )?;

    let fill_result = crate::macos_ax::fill_password(
        app_name,
        prompt.target.process_id,
        &prompt.target.window_title,
        prompt.origin.as_str(),
        &credentials.username,
        password.as_str(),
        crate::macos_ax::MacosFillMethod::Keyboard,
        guard,
    )?;
    guard()?;

    let submit_result = crate::macos_ax::submit_prompt_after_fill(
        app_name,
        fill_result.filled_prompt.as_ref(),
        prompt.target.process_id,
        &prompt.target.window_title,
        prompt.origin.as_str(),
        &credentials.username,
        guard,
    )?;
    guard()?;

    match crate::macos_ax::post_check_state(
        app_name,
        prompt.target.process_id,
        &prompt.target.window_title,
        &credentials.username,
        submit_result.submitted_prompt.as_ref(),
        std::time::Duration::from_millis(1200),
    ) {
        "authenticated" => {
            info!("Login submitted via native AX backend");
            Ok(AutoLoginResult::Submitted)
        }
        "prompt_gone_unknown" => {
            warn!("Password was submitted but post-submit authentication state was not confirmed");
            Ok(AutoLoginResult::PasswordTouchedWithoutSubmit)
        }
        "prompt_mismatch" => {
            anyhow::bail!("A different credential prompt is visible after native submit")
        }
        "still_prompt" => anyhow::bail!("Credential prompt is still visible after native submit"),
        "failed" => anyhow::bail!("Windows App is not running after native submit"),
        _ => anyhow::bail!("Post-submit state is unknown after native submit"),
    }
}

#[cfg(target_os = "macos")]
fn ensure_matching_prompt_email(
    app_name: &str,
    username: &str,
    expected_window_title: Option<&str>,
    expected_process_id: Option<i32>,
) -> anyhow::Result<()> {
    let _ = matching_native_prompt(
        app_name,
        username,
        expected_window_title,
        expected_process_id,
    )?;
    info!("Credential prompt email matched the selected account");
    Ok(())
}

#[cfg(target_os = "macos")]
fn matching_native_prompt(
    app_name: &str,
    username: &str,
    expected_window_title: Option<&str>,
    expected_process_id: Option<i32>,
) -> anyhow::Result<crate::macos_ax::MacosPrompt> {
    let Some(prompt) = crate::macos_ax::detect_visible_prompt(
        app_name,
        expected_process_id,
        expected_window_title,
        Some(username),
    )?
    else {
        anyhow::bail!("Credential prompt was not detected");
    };
    let Some(prompt_email) = prompt
        .email
        .as_deref()
        .map(str::trim)
        .filter(|email| !email.is_empty())
    else {
        anyhow::bail!("Credential prompt has no visible email; password was not loaded");
    };
    if !usernames_match(prompt_email, username) {
        anyhow::bail!("Credential prompt email does not match this account");
    }
    Ok(prompt)
}

#[cfg(target_os = "macos")]
fn trusted_pids_for_prompt(
    app_name: &str,
    expected_process_id: Option<i32>,
) -> anyhow::Result<Vec<i32>> {
    let trusted_pids = macos_identity::trusted_process_ids(app_name)?;
    trusted_pids_for_expected_prompt(
        trusted_pids,
        expected_process_id,
        ExpectedPidMismatch::Reject,
    )
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy)]
enum ExpectedPidMismatch {
    Reject,
}

#[cfg(target_os = "macos")]
fn trusted_pids_for_expected_prompt(
    trusted_pids: Vec<i32>,
    expected_process_id: Option<i32>,
    mismatch: ExpectedPidMismatch,
) -> anyhow::Result<Vec<i32>> {
    let Some(expected_process_id) = expected_process_id else {
        return Ok(trusted_pids);
    };
    if trusted_pids.contains(&expected_process_id) {
        return Ok(vec![expected_process_id]);
    }

    match mismatch {
        ExpectedPidMismatch::Reject => {
            anyhow::bail!("Previously detected login prompt process is no longer trusted")
        }
    }
}

#[cfg(all(test, target_os = "macos"))]
fn prompt_window_title_matches(current_title: &str, expected_window_title: Option<&str>) -> bool {
    let Some(expected_window_title) = expected_window_title
        .map(str::trim)
        .filter(|title| !title.is_empty())
    else {
        return true;
    };

    current_title.eq_ignore_ascii_case(expected_window_title)
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CredentialPromptState {
    Gone,
    StillPresentForAccount,
    PresentDifferentOrAmbiguous,
}

#[cfg(target_os = "macos")]
fn trusted_pids_for_prompt_state(
    app_name: &str,
    expected_process_id: Option<i32>,
) -> anyhow::Result<Vec<i32>> {
    let trusted_pids = macos_identity::trusted_process_ids(app_name)?;
    trusted_pids_for_expected_prompt(
        trusted_pids,
        expected_process_id,
        ExpectedPidMismatch::Reject,
    )
}

#[cfg(target_os = "macos")]
fn credential_prompt_state_macos(
    app_name: &str,
    username: &str,
    expected_window_title: Option<&str>,
    expected_process_id: Option<i32>,
) -> anyhow::Result<CredentialPromptState> {
    let trusted_pids = trusted_pids_for_prompt_state(app_name, expected_process_id)?;
    if trusted_pids.is_empty() {
        return Ok(CredentialPromptState::Gone);
    }

    let trusted_pids = macos_identity::applescript_pid_list_literal(&trusted_pids);
    let app_name = applescript_string_literal(app_name);
    let username = applescript_string_literal(username);
    let expected_window_title =
        applescript_string_literal(expected_window_title.unwrap_or_default());
    let script = format!(
        r#"on processMatches(procRef, expectedName, trustedPIDs)
    tell application "System Events"
        try
            if (name of procRef as string) is not expectedName then return false
            set procPID to unix id of procRef as string
            repeat with trustedPID in trustedPIDs
                if procPID is (trustedPID as string) then return true
            end repeat
            return false
        on error
            return false
        end try
    end tell
end processMatches

on windowTitleMatches(wName, expectedTitle)
    if expectedTitle is "" then return true
    ignoring case
        if wName is expectedTitle then return true
    end ignoring
    return false
end windowTitleMatches

on elementRoleText(elem)
    tell application "System Events"
        set roleText to ""
        try
            set roleText to roleText & " " & (value of attribute "AXRole" of elem as string)
        end try
        try
            set roleText to roleText & " " & (value of attribute "AXSubrole" of elem as string)
        end try
        try
            set roleText to roleText & " " & (value of attribute "AXRoleDescription" of elem as string)
        end try
        try
            set roleText to roleText & " " & (class of elem as string)
        end try
        try
            set roleText to roleText & " " & (role of elem as string)
        end try
        try
            set roleText to roleText & " " & (role description of elem as string)
        end try
    end tell
    return roleText
end elementRoleText

on elementIsNativeSecureTextField(elem)
    set roleText to my elementRoleText(elem)
    ignoring case
        if roleText contains "AXSecureTextField" then return true
        if roleText contains "secure text field" then return true
        if roleText contains "securetextfield" then return true
        if (roleText contains "AXTextField") and (roleText contains "secure") then return true
    end ignoring
    return false
end elementIsNativeSecureTextField

on elementIsCredentialPasswordField(elem, allowPasswordLike)
    if my elementIsNativeSecureTextField(elem) then return true
    if allowPasswordLike then
        set roleText to my elementRoleText(elem)
        set labelText to my elementLabelText(elem)
        ignoring case
            if my roleLooksLikeTextField(roleText) and my textContainsPasswordCue(labelText) then return true
        end ignoring
    end if
    return false
end elementIsCredentialPasswordField

on elementIsSecureTextField(elem)
    return my elementIsCredentialPasswordField(elem, true)
end elementIsSecureTextField

on elementIsHidden(elem)
    tell application "System Events"
        try
            return (value of attribute "AXHidden" of elem) as boolean
        on error
            return false
        end try
    end tell
end elementIsHidden

on elementLabelText(elem)
    tell application "System Events"
        set labelText to ""
        try
            set labelText to labelText & " " & (name of elem as string)
        end try
        try
            set labelText to labelText & " " & (value of attribute "AXTitle" of elem as string)
        end try
        try
            set labelText to labelText & " " & (value of attribute "AXPlaceholderValue" of elem as string)
        end try
    end tell
    return labelText
end elementLabelText

on roleLooksLikeTextField(roleText)
    ignoring case
        if roleText contains "AXTextField" then return true
        if roleText contains "text field" then return true
    end ignoring
    return false
end roleLooksLikeTextField

on textContainsPasswordCue(textValue)
    ignoring case
        if textValue contains "password" then return true
        if textValue contains "passwort" then return true
        if textValue contains "kennwort" then return true
        if textValue contains "mot de passe" then return true
        if textValue contains "contraseña" then return true
        if textValue contains "contrasena" then return true
        if textValue contains "hasło" then return true
        if textValue contains "haslo" then return true
        if textValue contains "пароль" then return true
    end ignoring
    return false
end textContainsPasswordCue

on countPasswordFields(containerRef)
    set fieldCount to 0
    tell application "System Events"
        try
            repeat with elem in (every UI element of containerRef)
                if not my elementIsHidden(elem) then
                    if my elementIsSecureTextField(elem) then
                        set fieldCount to fieldCount + 1
                    else
                        try
                            set fieldCount to fieldCount + my countPasswordFields(elem)
                        end try
                    end if
                end if
            end repeat
        end try
    end tell
    return fieldCount
end countPasswordFields

on countPromptButtons(containerRef)
    set buttonCount to 0
    tell application "System Events"
        tell containerRef
            try
                repeat with buttonRef in (every button)
                    if not my elementIsHidden(buttonRef) then set buttonCount to buttonCount + 1
                end repeat
            end try
            try
                repeat with elem in (every UI element)
                    if not my elementIsHidden(elem) then
                        set buttonCount to buttonCount + my countPromptButtons(elem)
                    end if
                end repeat
            end try
        end tell
    end tell
    return buttonCount
end countPromptButtons

on collectPromptText(containerRef, baseText)
    set promptText to baseText
    tell application "System Events"
        tell containerRef
            try
                repeat with tf in (every text field)
                    if (not my elementIsHidden(tf)) and (not my elementIsSecureTextField(tf)) then
                        try
                            set promptText to promptText & " " & (name of tf as string)
                        end try
                        try
                            set promptText to promptText & " " & (value of tf as string)
                        end try
                    end if
                end repeat
            end try
            try
                repeat with staticRef in (every static text)
                    if not my elementIsHidden(staticRef) then
                        try
                            set promptText to promptText & " " & (name of staticRef as string)
                        end try
                        try
                            set promptText to promptText & " " & (value of staticRef as string)
                        end try
                    end if
                end repeat
            end try
            try
                repeat with elem in (every UI element)
                    if not my elementIsHidden(elem) then
                        if not my elementIsSecureTextField(elem) then
                            try
                                set promptText to promptText & " " & (name of elem as string)
                            end try
                            try
                                set promptText to promptText & " " & (value of elem as string)
                            end try
                            try
                                set promptText to promptText & " " & (value of attribute "AXTitle" of elem as string)
                            end try
                        end if
                        set promptText to my collectPromptText(elem, promptText)
                    end if
                end repeat
            end try
        end tell
    end tell
    return promptText
end collectPromptText

on promptMatchesAccount(promptText, usernameValue)
    set promptLength to length of promptText
    set usernameLength to length of usernameValue
    if usernameLength is 0 or promptLength is less than usernameLength then return false
    ignoring case
        repeat with idx from 1 to (promptLength - usernameLength + 1)
            if text idx thru (idx + usernameLength - 1) of promptText is usernameValue then
                set beforeOk to true
                set afterOk to true
                if idx > 1 then set beforeOk to not my isEmailCharacter(character (idx - 1) of promptText)
                if (idx + usernameLength) <= promptLength then set afterOk to not my isEmailCharacter(character (idx + usernameLength) of promptText)
                if beforeOk and afterOk then return true
            end if
        end repeat
    end ignoring
    return false
end promptMatchesAccount

on isEmailCharacter(ch)
    set emailChars to "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._%+-@"
    return emailChars contains (ch as string)
end isEmailCharacter

tell application "System Events"
    set expectedName to {}
    set trustedPIDs to {}
    set usernameValue to {}
    set expectedWindowTitle to {}
    set sawCredentialPrompt to false

    set procList to every application process whose name is expectedName
    repeat with procRef in procList
        if my processMatches(procRef, expectedName, trustedPIDs) then
            repeat with w in (every window of procRef)
                if not my elementIsHidden(w) then
                    try
                        set wName to name of w as string
                        if my windowTitleMatches(wName, expectedWindowTitle) then
                            repeat with s in (every sheet of w)
                                if not my elementIsHidden(s) then
                                    set sheetButtonCount to my countPromptButtons(s)
                                    set sheetButtonCount to sheetButtonCount + my countPromptButtons(w)
                                    if my countPasswordFields(s) >= 1 and sheetButtonCount >= 1 then
                                        set sawCredentialPrompt to true
                                        if my promptMatchesAccount(my collectPromptText(s, ""), usernameValue) then return "same"
                                    end if
                                end if
                            end repeat

                            if my countPasswordFields(w) >= 1 and my countPromptButtons(w) >= 1 then
                                set sawCredentialPrompt to true
                                if my promptMatchesAccount(my collectPromptText(w, ""), usernameValue) then return "same"
                            end if
                        end if
                    end try
                end if
            end repeat
        end if
    end repeat

    if sawCredentialPrompt then return "present"
    return "gone"
end tell"#,
        app_name, trusted_pids, username, expected_window_title
    );

    let output = run_osascript(&script)?;
    if !output.status.success() {
        anyhow::bail!(
            "Failed to verify credential prompt after submit: {}",
            redacted_stderr(&output.stderr)
        );
    }

    match String::from_utf8_lossy(&output.stdout)
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "gone" => Ok(CredentialPromptState::Gone),
        "same" => Ok(CredentialPromptState::StillPresentForAccount),
        "present" => Ok(CredentialPromptState::PresentDifferentOrAmbiguous),
        _ => Ok(CredentialPromptState::PresentDifferentOrAmbiguous),
    }
}

#[cfg(target_os = "macos")]
fn visible_prompt_email_macos(
    app_name: &str,
    expected_window_title: Option<&str>,
    expected_process_id: Option<i32>,
) -> anyhow::Result<Option<String>> {
    let trusted_pids = trusted_pids_for_prompt(app_name, expected_process_id)?;
    if trusted_pids.is_empty() {
        anyhow::bail!("No trusted Microsoft Windows App process is running");
    }
    let trusted_pids = macos_identity::applescript_pid_list_literal(&trusted_pids);
    let app_name = applescript_string_literal(app_name);
    let expected_window_title =
        applescript_string_literal(expected_window_title.unwrap_or_default());
    let script = format!(
        r#"on processMatches(procRef, expectedName, trustedPIDs)
    tell application "System Events"
        try
            if (name of procRef as string) is not expectedName then return false
            set procPID to unix id of procRef as string
            repeat with trustedPID in trustedPIDs
                if procPID is (trustedPID as string) then return true
            end repeat
            return false
        on error
            return false
        end try
    end tell
end processMatches

on windowTitleMatches(wName, expectedTitle)
    if expectedTitle is "" then return true
    ignoring case
        if wName is expectedTitle then return true
    end ignoring
    return false
end windowTitleMatches

on appendAccountFieldValues(containerRef, currentOutput)
    set outputText to currentOutput
    tell application "System Events"
        tell containerRef
            try
                repeat with tf in (every text field)
                    if (not my elementIsHidden(tf)) and (not my elementIsSecureTextField(tf)) then
                        try
                            set outputText to outputText & (name of tf as string) & "\n"
                        end try
                        try
                            set outputText to outputText & (value of tf as string) & "\n"
                        end try
                    end if
                end repeat
            end try
            try
                repeat with staticRef in (every static text)
                    if not my elementIsHidden(staticRef) then
                        try
                            set outputText to outputText & (name of staticRef as string) & "\n"
                        end try
                        try
                            set outputText to outputText & (value of staticRef as string) & "\n"
                        end try
                    end if
                end repeat
            end try
            try
                repeat with elem in (every UI element)
                    if not my elementIsHidden(elem) then
                        if not my elementIsSecureTextField(elem) then
                            try
                                set outputText to outputText & (name of elem as string) & "\n"
                            end try
                            try
                                set outputText to outputText & (value of elem as string) & "\n"
                            end try
                            try
                                set outputText to outputText & (value of attribute "AXTitle" of elem as string) & "\n"
                            end try
                        end if
                        set outputText to my appendAccountFieldValues(elem, outputText)
                    end if
                end repeat
            end try
        end tell
    end tell
    return outputText
end appendAccountFieldValues

on elementRoleText(elem)
    tell application "System Events"
        set roleText to ""
        try
            set roleText to roleText & " " & (value of attribute "AXRole" of elem as string)
        end try
        try
            set roleText to roleText & " " & (value of attribute "AXSubrole" of elem as string)
        end try
        try
            set roleText to roleText & " " & (value of attribute "AXRoleDescription" of elem as string)
        end try
        try
            set roleText to roleText & " " & (class of elem as string)
        end try
        try
            set roleText to roleText & " " & (role of elem as string)
        end try
        try
            set roleText to roleText & " " & (role description of elem as string)
        end try
    end tell
    return roleText
end elementRoleText

on elementIsNativeSecureTextField(elem)
    set roleText to my elementRoleText(elem)
    ignoring case
        if roleText contains "AXSecureTextField" then return true
        if roleText contains "secure text field" then return true
        if roleText contains "securetextfield" then return true
        if (roleText contains "AXTextField") and (roleText contains "secure") then return true
    end ignoring
    return false
end elementIsNativeSecureTextField

on elementIsCredentialPasswordField(elem, allowPasswordLike)
    if my elementIsNativeSecureTextField(elem) then return true
    if allowPasswordLike then
        set roleText to my elementRoleText(elem)
        set labelText to my elementLabelText(elem)
        ignoring case
            if my roleLooksLikeTextField(roleText) and my textContainsPasswordCue(labelText) then return true
        end ignoring
    end if
    return false
end elementIsCredentialPasswordField

on elementIsSecureTextField(elem)
    return my elementIsCredentialPasswordField(elem, true)
end elementIsSecureTextField

on elementIsHidden(elem)
    tell application "System Events"
        try
            return (value of attribute "AXHidden" of elem) as boolean
        on error
            return false
        end try
    end tell
end elementIsHidden

on elementLabelText(elem)
    tell application "System Events"
        set labelText to ""
        try
            set labelText to labelText & " " & (name of elem as string)
        end try
        try
            set labelText to labelText & " " & (value of attribute "AXTitle" of elem as string)
        end try
        try
            set labelText to labelText & " " & (value of attribute "AXPlaceholderValue" of elem as string)
        end try
    end tell
    return labelText
end elementLabelText

on roleLooksLikeTextField(roleText)
    ignoring case
        if roleText contains "AXTextField" then return true
        if roleText contains "text field" then return true
    end ignoring
    return false
end roleLooksLikeTextField

on textContainsPasswordCue(textValue)
    ignoring case
        if textValue contains "password" then return true
        if textValue contains "passwort" then return true
        if textValue contains "kennwort" then return true
        if textValue contains "mot de passe" then return true
        if textValue contains "contraseña" then return true
        if textValue contains "contrasena" then return true
        if textValue contains "hasło" then return true
        if textValue contains "haslo" then return true
        if textValue contains "пароль" then return true
    end ignoring
    return false
end textContainsPasswordCue

on countPasswordFields(containerRef)
    set fieldCount to 0
    tell application "System Events"
        try
            repeat with elem in (every UI element of containerRef)
                if not my elementIsHidden(elem) then
                    if my elementIsSecureTextField(elem) then
                        set fieldCount to fieldCount + 1
                    else
                        try
                            set fieldCount to fieldCount + my countPasswordFields(elem)
                        end try
                    end if
                end if
            end repeat
        end try
    end tell
    return fieldCount
end countPasswordFields

on countPromptButtons(containerRef)
    set buttonCount to 0
    tell application "System Events"
        tell containerRef
            try
                repeat with buttonRef in (every button)
                    if not my elementIsHidden(buttonRef) then set buttonCount to buttonCount + 1
                end repeat
            end try
            try
                repeat with elem in (every UI element)
                    if not my elementIsHidden(elem) then
                        set buttonCount to buttonCount + my countPromptButtons(elem)
                    end if
                end repeat
            end try
        end tell
    end tell
    return buttonCount
end countPromptButtons

tell application "System Events"
    set output to ""
    set expectedName to {}
    set expectedWindowTitle to {}
    set trustedPIDs to {}
    try
        set procList to every application process whose name is expectedName
        repeat with procRef in procList
            if my processMatches(procRef, expectedName, trustedPIDs) then
            repeat with w in (every window of procRef)
                if not my elementIsHidden(w) then
                try
                    set wName to name of w as string
                    if my windowTitleMatches(wName, expectedWindowTitle) then
                    repeat with s in (every sheet of w)
                        if not my elementIsHidden(s) then
                        set sheetButtonCount to my countPromptButtons(s)
                        set sheetButtonCount to sheetButtonCount + my countPromptButtons(w)
                        if my countPasswordFields(s) >= 1 and sheetButtonCount >= 1 then
                            set output to my appendAccountFieldValues(s, output)
                        end if
                        end if
                    end repeat
                    end if
                end try
                try
                    set wName to name of w as string
                    if my windowTitleMatches(wName, expectedWindowTitle) then
                    if my countPasswordFields(w) >= 1 and my countPromptButtons(w) >= 1 then
                        set output to my appendAccountFieldValues(w, output)
                    end if
                    end if
                end try
                end if
            end repeat
            end if
        end repeat
    end try
    return output
end tell"#,
        app_name, expected_window_title, trusted_pids
    );

    let output = run_osascript(&script)?;
    if !output.status.success() {
        anyhow::bail!(
            "Failed to read credential prompt email: {}",
            redacted_stderr(&output.stderr)
        );
    }

    Ok(extract_email_like(&String::from_utf8_lossy(&output.stdout)))
}

#[cfg(target_os = "macos")]
fn usernames_match(prompt_email: &str, account_username: &str) -> bool {
    prompt_email
        .trim()
        .eq_ignore_ascii_case(account_username.trim())
}

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
fn is_email_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '%' | '+' | '-' | '@')
}

#[cfg(target_os = "macos")]
fn applescript_string_literal(value: &str) -> String {
    let escaped = value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace(['\r', '\n'], " ");
    format!("\"{}\"", escaped)
}

#[cfg(target_os = "macos")]
fn run_osascript(script: &str) -> anyhow::Result<std::process::Output> {
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

    let mut child = Command::new("/usr/bin/osascript")
        .args(["-e", script])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let started = Instant::now();
    loop {
        if child.try_wait()?.is_some() {
            return Ok(child.wait_with_output()?);
        }

        if started.elapsed() >= Duration::from_secs(5) {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("osascript timed out");
        }

        thread::sleep(Duration::from_millis(25));
    }
}

#[cfg(target_os = "macos")]
fn redacted_stderr(stderr: &[u8]) -> &'static str {
    if stderr.is_empty() {
        "no stderr"
    } else {
        "redacted stderr"
    }
}

#[cfg(test)]
mod accessibility_tests {
    use super::app_bundle_path_for_process;

    #[test]
    fn app_bundle_path_is_derived_from_bundled_executable() {
        let path = "/tmp/WindowsAppAutoLogin.app/Contents/MacOS/windows-app-autologin";

        assert_eq!(
            app_bundle_path_for_process(path).as_deref(),
            Some("/tmp/WindowsAppAutoLogin.app")
        );
    }

    #[test]
    fn app_bundle_path_is_empty_for_raw_debug_binary() {
        let path = "/tmp/project/target/debug/windows-app-autologin";

        assert_eq!(app_bundle_path_for_process(path), None);
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::{
        app_bundle_signature_is_trusted, extract_email_like, prompt_window_title_matches,
        redacted_stderr, trusted_pids_for_expected_prompt, usernames_match, ExpectedPidMismatch,
    };

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

    fn native_secure_field_for_test(role_text: &str) -> bool {
        let role = role_text.to_lowercase();
        role.contains("axsecuretextfield")
            || role.contains("secure text field")
            || role.contains("securetextfield")
            || (role.contains("axtextfield") && role.contains("secure"))
    }

    fn password_like_text_field_for_test(role_text: &str, label_text: &str) -> bool {
        let role = role_text.to_lowercase();
        let label = label_text.to_lowercase();
        (role.contains("axtextfield") || role.contains("text field"))
            && PASSWORD_CUES.iter().any(|cue| label.contains(cue))
    }

    fn credential_password_field_for_test(
        role_text: &str,
        label_text: &str,
        verified_prompt_context: bool,
    ) -> bool {
        let _ = (label_text, verified_prompt_context);
        native_secure_field_for_test(role_text)
    }

    fn prompt_text_collection_reads_field_for_test(
        role_text: &str,
        label_text: &str,
        _verified_prompt_context: bool,
    ) -> bool {
        !native_secure_field_for_test(role_text)
            && !password_like_text_field_for_test(role_text, label_text)
    }

    #[test]
    fn own_app_signature_requires_configured_valid_team_id() {
        assert!(!app_bundle_signature_is_trusted(std::path::Path::new(
            "/Applications/WindowsAppAutoLogin.app"
        )));
    }

    #[test]
    fn axsecure_text_field_is_password_field() {
        assert!(credential_password_field_for_test(
            "AXSecureTextField",
            "",
            false
        ));
        assert!(credential_password_field_for_test(
            "secure text field",
            "",
            false
        ));
    }

    #[test]
    fn password_like_axtextfield_requires_verified_prompt_context() {
        assert!(!credential_password_field_for_test(
            "AXTextField",
            "AXDescription Password",
            false,
        ));
        assert!(!credential_password_field_for_test(
            "AXTextField",
            "AXDescription Password",
            true,
        ));
    }

    #[test]
    fn unrelated_axtextfield_is_not_password_field() {
        assert!(!credential_password_field_for_test(
            "AXTextField",
            "Display name",
            true,
        ));
        assert!(!credential_password_field_for_test(
            "AXButton",
            "Forgot password",
            true,
        ));
    }

    #[test]
    fn password_like_axtextfield_is_excluded_from_prompt_text_collection() {
        assert!(!prompt_text_collection_reads_field_for_test(
            "AXTextField",
            "Password",
            true,
        ));
        assert!(prompt_text_collection_reads_field_for_test(
            "AXTextField",
            "Account email",
            true,
        ));
    }

    #[test]
    fn visible_prompt_email_exact_match_allows_password_load_gate() {
        assert!(usernames_match(" User@example.com ", "user@EXAMPLE.com"));
    }

    #[test]
    fn visible_prompt_email_mismatch_blocks_password_load_gate() {
        assert!(!usernames_match("other@example.com", "user@example.com"));
    }

    #[test]
    fn missing_visible_prompt_email_blocks_password_load_gate() {
        assert_eq!(extract_email_like("Sign in to continue"), None);
    }

    #[test]
    fn visible_prompt_email_rejects_multiple_distinct_emails() {
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
    fn changed_target_pid_rejects_fill_attempt() {
        let error = trusted_pids_for_expected_prompt(
            vec![101, 202],
            Some(303),
            ExpectedPidMismatch::Reject,
        )
        .unwrap_err();

        assert_eq!(
            error.to_string(),
            "Previously detected login prompt process is no longer trusted"
        );
    }

    #[test]
    fn changed_target_pid_rejects_post_submit_validation() {
        let error = trusted_pids_for_expected_prompt(
            vec![101, 202],
            Some(303),
            ExpectedPidMismatch::Reject,
        )
        .unwrap_err();

        assert_eq!(
            error.to_string(),
            "Previously detected login prompt process is no longer trusted"
        );
    }

    #[test]
    fn changed_target_window_title_rejects_fill_attempt() {
        assert!(prompt_window_title_matches("Sign in", Some("sign IN")));
        assert!(!prompt_window_title_matches(
            "Connection Center",
            Some("Sign in")
        ));
    }

    #[test]
    fn osascript_errors_are_redacted() {
        let stderr = b"failed while handling password=super-secret user@example.com";

        assert_eq!(redacted_stderr(stderr), "redacted stderr");
        assert_eq!(redacted_stderr(b""), "no stderr");
    }
}
