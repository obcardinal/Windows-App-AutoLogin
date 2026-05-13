use crate::config::CredentialsConfig;
#[cfg(target_os = "macos")]
use crate::macos_identity;
#[cfg(target_os = "macos")]
use tracing::info;
use tracing::warn;
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AccessibilityStatus {
    pub(crate) trusted: bool,
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
            anyhow::bail!(
                "Accessibility permission missing for this exact app: {}. \
                 Add or re-enable Windows App AutoLogin in System Settings → \
                 Privacy & Security → Accessibility, then restart the app.",
                status.current_process_path
            );
        }
    }
    Ok(())
}

pub(crate) fn accessibility_status() -> AccessibilityStatus {
    let current_process_path = std::env::current_exe()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    AccessibilityStatus {
        trusted: accessibility_is_trusted(),
        app_bundle_path: app_bundle_path_for_process(&current_process_path).unwrap_or_default(),
        current_process_path,
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn accessibility_is_trusted() -> bool {
    unsafe { AXIsProcessTrusted() != 0 }
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn accessibility_is_trusted() -> bool {
    true
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
        trusted
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
    std::path::Path::new(process_path)
        .ancestors()
        .find(|path| path.extension().is_some_and(|ext| ext == "app"))
        .map(|path| path.display().to_string())
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

    crate::macos_ax::fill_password(
        app_name,
        prompt.target.process_id,
        &prompt.target.window_title,
        &credentials.username,
        password.as_str(),
        crate::macos_ax::MacosFillMethod::Keyboard,
        guard,
    )?;
    guard()?;

    crate::macos_ax::submit_prompt(
        app_name,
        prompt.target.process_id,
        &prompt.target.window_title,
        &credentials.username,
        guard,
    )?;
    guard()?;

    match crate::macos_ax::post_check_state(
        app_name,
        prompt.target.process_id,
        &credentials.username,
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
fn activate_and_ensure_frontmost(
    app_name: &str,
    expected_process_id: Option<i32>,
) -> anyhow::Result<()> {
    use std::process::Command;
    use std::thread;
    use std::time::Duration;

    let app_name_literal = applescript_string_literal(app_name);
    let trusted_pids = trusted_pids_for_prompt(app_name, expected_process_id)?;
    if trusted_pids.is_empty() {
        anyhow::bail!("No trusted Microsoft Windows App process is running");
    }
    let trusted_pids_literal = macos_identity::applescript_pid_list_literal(&trusted_pids);

    let activate_script = format!("tell application {} to activate", app_name_literal);
    let _ = run_osascript(&activate_script);
    thread::sleep(Duration::from_millis(300));

    let frontmost_script = format!(
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

tell application "System Events"
    set expectedName to {}
    set trustedPIDs to {}
    repeat with procRef in every application process
        try
            if frontmost of procRef and my processMatches(procRef, expectedName, trustedPIDs) then
                return "matched"
            end if
        end try
    end repeat
    return "not_matched"
end tell"#,
        app_name_literal, trusted_pids_literal
    );
    let output = run_osascript(&frontmost_script)?;
    let frontmost = String::from_utf8_lossy(&output.stdout)
        .trim()
        .to_lowercase();

    if frontmost != "matched" {
        warn!("Target app is not frontmost, forcing it to front");
        let _ = run_osascript(&activate_script);
        thread::sleep(Duration::from_millis(300));
        if let Some(bundle_path) = macos_identity::trusted_bundle_path(app_name)? {
            let _ = Command::new("/usr/bin/open").arg(bundle_path).output();
            thread::sleep(Duration::from_millis(300));
        }
        let force_script = format!(
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

tell application "System Events"
    set expectedName to {}
    set trustedPIDs to {}
    repeat with procRef in every application process
        if my processMatches(procRef, expectedName, trustedPIDs) then
            set frontmost of procRef to true
            return "ok"
        end if
    end repeat
    error "verified target process not found"
end tell"#,
            app_name_literal, trusted_pids_literal
        );
        let _ = run_osascript(&force_script)?;
        thread::sleep(Duration::from_millis(500));

        let output = run_osascript(&frontmost_script)?;
        let frontmost = String::from_utf8_lossy(&output.stdout)
            .trim()
            .to_lowercase();
        if frontmost != "matched" {
            anyhow::bail!("Could not make '{}' frontmost", app_name);
        }
    }

    Ok(())
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

on elementLabelText(elem)
    tell application "System Events"
        set labelText to ""
        try
            set labelText to labelText & " " & (name of elem as string)
        end try
        try
            set labelText to labelText & " " & (description of elem as string)
        end try
        try
            set labelText to labelText & " " & (help of elem as string)
        end try
        try
            set labelText to labelText & " " & (value of attribute "AXTitle" of elem as string)
        end try
        try
            set labelText to labelText & " " & (value of attribute "AXDescription" of elem as string)
        end try
        try
            set labelText to labelText & " " & (value of attribute "AXHelp" of elem as string)
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
                if my elementIsSecureTextField(elem) then
                    set fieldCount to fieldCount + 1
                else
                    try
                        set fieldCount to fieldCount + my countPasswordFields(elem)
                    end try
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
                set buttonCount to buttonCount + (count of every button)
            end try
            try
                repeat with elem in (every UI element)
                    set buttonCount to buttonCount + my countPromptButtons(elem)
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
                    if not my elementIsSecureTextField(tf) then
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
                    try
                        set promptText to promptText & " " & (name of staticRef as string)
                    end try
                    try
                        set promptText to promptText & " " & (value of staticRef as string)
                    end try
                end repeat
            end try
            try
                repeat with elem in (every UI element)
                    if not my elementIsSecureTextField(elem) then
                        try
                            set promptText to promptText & " " & (name of elem as string)
                        end try
                        try
                            set promptText to promptText & " " & (value of elem as string)
                        end try
                        try
                            set promptText to promptText & " " & (description of elem as string)
                        end try
                        try
                            set promptText to promptText & " " & (help of elem as string)
                        end try
                        try
                            set promptText to promptText & " " & (value of attribute "AXTitle" of elem as string)
                        end try
                        try
                            set promptText to promptText & " " & (value of attribute "AXDescription" of elem as string)
                        end try
                        try
                            set promptText to promptText & " " & (value of attribute "AXHelp" of elem as string)
                        end try
                    end if
                    set promptText to my collectPromptText(elem, promptText)
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
                try
                    set wName to name of w as string
                    if my windowTitleMatches(wName, expectedWindowTitle) then
                        repeat with s in (every sheet of w)
                            set sheetButtonCount to my countPromptButtons(s)
                            set sheetButtonCount to sheetButtonCount + my countPromptButtons(w)
                            if my countPasswordFields(s) >= 1 and sheetButtonCount >= 1 then
                                set sawCredentialPrompt to true
                                if my promptMatchesAccount(my collectPromptText(s, ""), usernameValue) then return "same"
                            end if
                        end repeat

                        if my countPasswordFields(w) >= 1 and my countPromptButtons(w) >= 1 then
                            set sawCredentialPrompt to true
                            if my promptMatchesAccount(my collectPromptText(w, ""), usernameValue) then return "same"
                        end if
                    end if
                end try
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
                    if not my elementIsSecureTextField(tf) then
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
                    try
                        set outputText to outputText & (name of staticRef as string) & "\n"
                    end try
                    try
                        set outputText to outputText & (value of staticRef as string) & "\n"
                    end try
                end repeat
            end try
            try
                repeat with elem in (every UI element)
                    if not my elementIsSecureTextField(elem) then
                        try
                            set outputText to outputText & (name of elem as string) & "\n"
                        end try
                        try
                            set outputText to outputText & (value of elem as string) & "\n"
                        end try
                        try
                            set outputText to outputText & (description of elem as string) & "\n"
                        end try
                        try
                            set outputText to outputText & (help of elem as string) & "\n"
                        end try
                        try
                            set outputText to outputText & (value of attribute "AXTitle" of elem as string) & "\n"
                        end try
                        try
                            set outputText to outputText & (value of attribute "AXDescription" of elem as string) & "\n"
                        end try
                        try
                            set outputText to outputText & (value of attribute "AXHelp" of elem as string) & "\n"
                        end try
                    end if
                    set outputText to my appendAccountFieldValues(elem, outputText)
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

on elementLabelText(elem)
    tell application "System Events"
        set labelText to ""
        try
            set labelText to labelText & " " & (name of elem as string)
        end try
        try
            set labelText to labelText & " " & (description of elem as string)
        end try
        try
            set labelText to labelText & " " & (help of elem as string)
        end try
        try
            set labelText to labelText & " " & (value of attribute "AXTitle" of elem as string)
        end try
        try
            set labelText to labelText & " " & (value of attribute "AXDescription" of elem as string)
        end try
        try
            set labelText to labelText & " " & (value of attribute "AXHelp" of elem as string)
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
                if my elementIsSecureTextField(elem) then
                    set fieldCount to fieldCount + 1
                else
                    try
                        set fieldCount to fieldCount + my countPasswordFields(elem)
                    end try
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
                set buttonCount to buttonCount + (count of every button)
            end try
            try
                repeat with elem in (every UI element)
                    set buttonCount to buttonCount + my countPromptButtons(elem)
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
                try
                    set wName to name of w as string
                    if my windowTitleMatches(wName, expectedWindowTitle) then
                    repeat with s in (every sheet of w)
                        set sheetButtonCount to my countPromptButtons(s)
                        set sheetButtonCount to sheetButtonCount + my countPromptButtons(w)
                        if my countPasswordFields(s) >= 1 and sheetButtonCount >= 1 then
                            set output to my appendAccountFieldValues(s, output)
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
fn run_osascript_stdin(script: &str) -> anyhow::Result<std::process::Output> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

    let mut child = Command::new("/usr/bin/osascript")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(script.as_bytes())?;
    }

    let started = Instant::now();
    loop {
        if child.try_wait()?.is_some() {
            return Ok(child.wait_with_output()?);
        }

        if started.elapsed() >= Duration::from_secs(3) {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("login osascript timed out");
        }

        thread::sleep(Duration::from_millis(25));
    }
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
fn try_applescript_login(
    app_name: &str,
    username: &str,
    password: &str,
    expected_window_title: Option<&str>,
    expected_process_id: Option<i32>,
    guard: &dyn Fn() -> anyhow::Result<()>,
) -> anyhow::Result<AutoLoginResult> {
    activate_and_ensure_frontmost(app_name, expected_process_id)?;
    guard()?;

    let trusted_pids = trusted_pids_for_prompt(app_name, expected_process_id)?;
    if trusted_pids.is_empty() {
        anyhow::bail!("No trusted Microsoft Windows App process is running");
    }
    let trusted_pids_literal = macos_identity::applescript_pid_list_literal(&trusted_pids);
    let app_name_literal = applescript_string_literal(app_name);
    let username_literal = applescript_string_literal(username);
    let password_literal = Zeroizing::new(applescript_string_literal(password));
    let expected_window_title_literal =
        applescript_string_literal(expected_window_title.unwrap_or_default());
    let script = Zeroizing::new(format!(
        r#"on pressButtonFast(buttonRef)
    tell application "System Events"
        try
            with timeout of 0.35 seconds
                perform action "AXPress" of buttonRef
            end timeout
            delay 0.02
            return true
        on error
            return false
        end try
    end tell
end pressButtonFast

on clickPreferredSubmit(containerRef, expectedName, trustedPIDs)
    if not my targetIsFrontmost(expectedName, trustedPIDs) then return false
    return my clickContinueSubmit(containerRef, expectedName, trustedPIDs)
end clickPreferredSubmit

on clickContinueSubmit(containerRef, expectedName, trustedPIDs)
    tell application "System Events"
        try
            repeat with b in (every button of containerRef)
                if my buttonLooksContinue(b) then
                    if my targetIsFrontmost(expectedName, trustedPIDs) then
                        if my pressButtonFast(b) then return true
                    end if
                end if
            end repeat
        end try

        try
            repeat with elem in (every UI element of containerRef)
                if my clickContinueSubmit(elem, expectedName, trustedPIDs) then return true
            end repeat
        end try

        return false
    end tell
end clickContinueSubmit

on buttonLooksContinue(buttonRef)
    tell application "System Events"
        try
            if my buttonTextIsContinue(name of buttonRef as string) then return true
        end try
        try
            if my buttonTextIsContinue(value of buttonRef as string) then return true
        end try
        try
            if my buttonTextIsContinue(value of attribute "AXTitle" of buttonRef as string) then return true
        end try
    end tell
    return false
end buttonLooksContinue

on buttonTextIsContinue(buttonTextValue)
    ignoring case
        if buttonTextValue is "Continue" then return true
    end ignoring
    if buttonTextValue is "Продолжить" then return true
    return false
end buttonTextIsContinue

on pressDefaultSubmit(containerRef, expectedName, trustedPIDs, allowPasswordLike)
    tell application "System Events"
        if not my targetIsFrontmost(expectedName, trustedPIDs) then return false
        if my focusedSecureTextField(containerRef, expectedName, trustedPIDs, allowPasswordLike) is missing value then return false
        key code 36
        delay 0.05
        return true
    end tell
end pressDefaultSubmit

on processMatches(procRef, expectedName, trustedPIDs)
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

on targetIsFrontmost(expectedName, trustedPIDs)
    tell application "System Events"
        try
            repeat with procRef in every application process
                if frontmost of procRef and my processMatches(procRef, expectedName, trustedPIDs) then return true
            end repeat
        end try
    end tell
    return false
end targetIsFrontmost

on countPromptButtons(containerRef)
    set buttonCount to 0
    tell application "System Events"
        tell containerRef
            try
                set buttonCount to buttonCount + (count of every button)
            end try
            try
                repeat with elem in (every UI element)
                    set buttonCount to buttonCount + my countPromptButtons(elem)
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
                    if not my elementIsSecureTextField(tf) then
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
                    try
                        set promptText to promptText & " " & (name of staticRef as string)
                    end try
                    try
                        set promptText to promptText & " " & (value of staticRef as string)
                    end try
                end repeat
            end try
            try
                repeat with elem in (every UI element)
                    if not my elementIsSecureTextField(elem) then
                        try
                            set promptText to promptText & " " & (name of elem as string)
                        end try
                        try
                            set promptText to promptText & " " & (value of elem as string)
                        end try
                        try
                            set promptText to promptText & " " & (description of elem as string)
                        end try
                        try
                            set promptText to promptText & " " & (help of elem as string)
                        end try
                        try
                            set promptText to promptText & " " & (value of attribute "AXTitle" of elem as string)
                        end try
                        try
                            set promptText to promptText & " " & (value of attribute "AXDescription" of elem as string)
                        end try
                        try
                            set promptText to promptText & " " & (value of attribute "AXHelp" of elem as string)
                        end try
                    end if
                    set promptText to my collectPromptText(elem, promptText)
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

on elementLabelText(elem)
    tell application "System Events"
        set labelText to ""
        try
            set labelText to labelText & " " & (name of elem as string)
        end try
        try
            set labelText to labelText & " " & (description of elem as string)
        end try
        try
            set labelText to labelText & " " & (help of elem as string)
        end try
        try
            set labelText to labelText & " " & (value of attribute "AXTitle" of elem as string)
        end try
        try
            set labelText to labelText & " " & (value of attribute "AXDescription" of elem as string)
        end try
        try
            set labelText to labelText & " " & (value of attribute "AXHelp" of elem as string)
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

on elementIsPlainTextField(elem, allowPasswordLike)
    set roleText to my elementRoleText(elem)
    if my elementIsCredentialPasswordField(elem, allowPasswordLike) then return false
    ignoring case
        if roleText contains "text field" then return true
        if roleText contains "AXTextField" then return true
    end ignoring
    return false
end elementIsPlainTextField

on firstSecureTextField(containerRef, allowPasswordLike)
    tell application "System Events"
        try
            repeat with elem in (every UI element of containerRef)
                if my elementIsCredentialPasswordField(elem, allowPasswordLike) then return elem
                try
                    set nestedField to my firstSecureTextField(elem, allowPasswordLike)
                    if nestedField is not missing value then return nestedField
                end try
            end repeat
        end try
    end tell
    return missing value
end firstSecureTextField

on focusedSecureTextField(containerRef, expectedName, trustedPIDs, allowPasswordLike)
    tell application "System Events"
        if not my targetIsFrontmost(expectedName, trustedPIDs) then return missing value
        try
            repeat with elem in (every UI element of containerRef)
                if my elementIsCredentialPasswordField(elem, allowPasswordLike) then
                    if my secureFieldHasVerifiedFocus(elem, expectedName, trustedPIDs, allowPasswordLike) then return elem
                else
                    try
                        set nestedField to my focusedSecureTextField(elem, expectedName, trustedPIDs, allowPasswordLike)
                        if nestedField is not missing value then return nestedField
                    end try
                end if
            end repeat
        end try
    end tell
    return missing value
end focusedSecureTextField

on firstPlainTextField(containerRef, allowPasswordLike)
    tell application "System Events"
        try
            repeat with elem in (every UI element of containerRef)
                if my elementIsPlainTextField(elem, allowPasswordLike) then return elem
                try
                    set nestedField to my firstPlainTextField(elem, allowPasswordLike)
                    if nestedField is not missing value then return nestedField
                end try
            end repeat
        end try
    end tell
    return missing value
end firstPlainTextField

on focusPasswordField(passwordField, expectedName, trustedPIDs, allowPasswordLike)
    tell application "System Events"
        if not my targetIsFrontmost(expectedName, trustedPIDs) then return false
        if not my elementIsCredentialPasswordField(passwordField, allowPasswordLike) then return false
        try
            set focused of passwordField to true
        end try
        try
            click passwordField
        end try
        delay 0.08
        try
            if focused of passwordField then return true
        on error
            return false
        end try
    end tell
    return false
end focusPasswordField

on secureFieldHasVerifiedFocus(passwordField, expectedName, trustedPIDs, allowPasswordLike)
    tell application "System Events"
        if not my targetIsFrontmost(expectedName, trustedPIDs) then return false
        if not my elementIsCredentialPasswordField(passwordField, allowPasswordLike) then return false
        try
            if not (focused of passwordField) then return false
        on error
            return false
        end try
        try
            if not ((value of attribute "AXFocused" of passwordField as boolean) is true) then return false
        end try
        return true
    end tell
end secureFieldHasVerifiedFocus

on clearFocusedTextField(passwordField, expectedName, trustedPIDs, allowPasswordLike)
    tell application "System Events"
        if not my secureFieldHasVerifiedFocus(passwordField, expectedName, trustedPIDs, allowPasswordLike) then return false
        keystroke "a" using command down
        delay 0.04
        if not my secureFieldHasVerifiedFocus(passwordField, expectedName, trustedPIDs, allowPasswordLike) then return false
        key code 51
        delay 0.04
        return my secureFieldHasVerifiedFocus(passwordField, expectedName, trustedPIDs, allowPasswordLike)
    end tell
end clearFocusedTextField

on fillPasswordField(passwordField, passwordValue, expectedName, trustedPIDs, allowPasswordLike)
    tell application "System Events"
        if not my targetIsFrontmost(expectedName, trustedPIDs) then return false
        if not my elementIsCredentialPasswordField(passwordField, allowPasswordLike) then return false

        -- Keyboard path is allowed only when the same trusted process remains
        -- frontmost, the account text still matched the prompt, and the
        -- password-like field can be confirmed as focused.
        if my focusPasswordField(passwordField, expectedName, trustedPIDs, allowPasswordLike) then
            if my secureFieldHasVerifiedFocus(passwordField, expectedName, trustedPIDs, allowPasswordLike) then
                if my clearFocusedTextField(passwordField, expectedName, trustedPIDs, allowPasswordLike) then
                    if my secureFieldHasVerifiedFocus(passwordField, expectedName, trustedPIDs, allowPasswordLike) then
                        try
                            keystroke passwordValue
                            delay 0.05
                            return true
                        end try
                    end if
                end if
            end if
        end if

        return false
    end tell
end fillPasswordField

on fillLoginFields(containerRef, usernameValue, passwordValue, expectedName, trustedPIDs, allowPasswordLike)
    tell application "System Events"
        set passwordField to my firstSecureTextField(containerRef, allowPasswordLike)
        if passwordField is not missing value then
            set usernameField to my firstPlainTextField(containerRef, allowPasswordLike)
            if usernameField is not missing value then
                try
                    set value of usernameField to usernameValue
                end try
            end if
            if my fillPasswordField(passwordField, passwordValue, expectedName, trustedPIDs, allowPasswordLike) then return true
        end if
    end tell
    return false
end fillLoginFields

tell application "System Events"
            set expectedName to {}
            set trustedPIDs to {}
            set procList to every application process whose name is expectedName
            repeat with procRef in procList
                if my processMatches(procRef, expectedName, trustedPIDs) then
                set usernameValue to {}
                set passwordValue to {}
                set expectedWindowTitle to {}
                repeat with w in (every window of procRef)
	                    set wName to name of w as string
		                    if my windowTitleMatches(wName, expectedWindowTitle) then
		                        repeat with s in (every sheet of w)
		                            set promptText to my collectPromptText(s, "")
		                            set sheetButtonCount to my countPromptButtons(s)
		                            set sheetButtonCount to sheetButtonCount + my countPromptButtons(w)
		                            if sheetButtonCount >= 1 and my promptMatchesAccount(promptText, usernameValue) then
				                            if my fillLoginFields(s, usernameValue, passwordValue, expectedName, trustedPIDs, true) then
			                                if my clickPreferredSubmit(s, expectedName, trustedPIDs) then return "ok"
                                            if my clickPreferredSubmit(w, expectedName, trustedPIDs) then return "ok"
                                            if my pressDefaultSubmit(s, expectedName, trustedPIDs, true) then return "ok"
                                            return "password_touched"
			                            end if
		                            end if
		                        end repeat
		                        set promptText to my collectPromptText(w, "")
		                        if my countPromptButtons(w) >= 1 and my promptMatchesAccount(promptText, usernameValue) then
				                        if my fillLoginFields(w, usernameValue, passwordValue, expectedName, trustedPIDs, true) then
			                            if my clickPreferredSubmit(w, expectedName, trustedPIDs) then return "ok"
                                        if my pressDefaultSubmit(w, expectedName, trustedPIDs, true) then return "ok"
                                        return "password_touched"
			                        end if
		                        end if
                    end if
                end repeat
                end if
            end repeat
        end tell
        error "No suitable login window found""#,
        app_name_literal,
        trusted_pids_literal,
        username_literal,
        password_literal.as_str(),
        expected_window_title_literal
    ));

    guard()?;
    let output = run_osascript_stdin(script.as_str())?;

    if output.status.success() {
        match String::from_utf8_lossy(&output.stdout).trim() {
            "ok" => Ok(AutoLoginResult::Submitted),
            "password_touched" => Ok(AutoLoginResult::PasswordTouchedWithoutSubmit),
            _ => anyhow::bail!("AppleScript returned an unexpected result"),
        }
    } else {
        anyhow::bail!(
            "AppleScript login failed: {}",
            redacted_stderr(&output.stderr)
        )
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
        extract_email_like, prompt_window_title_matches, redacted_stderr,
        trusted_pids_for_expected_prompt, usernames_match, ExpectedPidMismatch,
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
        native_secure_field_for_test(role_text)
            || (verified_prompt_context && password_like_text_field_for_test(role_text, label_text))
    }

    fn prompt_text_collection_reads_field_for_test(
        role_text: &str,
        label_text: &str,
        verified_prompt_context: bool,
    ) -> bool {
        !credential_password_field_for_test(role_text, label_text, verified_prompt_context)
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
        assert!(credential_password_field_for_test(
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
