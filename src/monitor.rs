use crate::config::Config;
#[cfg(target_os = "macos")]
use crate::macos_identity;
use std::sync::Arc;
#[cfg(target_os = "macos")]
use tracing::debug;

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum MonitorStatus {
    Connected,
    ProcessNotFound,
    LoginWindowDetected {
        process_id: i32,
        window_title: String,
        prompt_email: Option<String>,
    },
    Unknown,
}

pub(crate) struct AppMonitor {
    config: Arc<Config>,
}

impl AppMonitor {
    pub(crate) fn new(config: Arc<Config>) -> Self {
        Self { config }
    }

    pub(crate) fn check_status(&self) -> MonitorStatus {
        #[cfg(target_os = "macos")]
        {
            check_status_macos(&self.config)
        }
        #[cfg(target_os = "windows")]
        {
            crate::windows_ui::check_status(&self.config)
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            tracing::trace!("Monitor stub on unsupported platform");
            MonitorStatus::Unknown
        }
    }
}

#[cfg(target_os = "macos")]
const MONITOR_OSASCRIPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

#[cfg(target_os = "macos")]
#[derive(Debug, Default)]
struct WindowInspection {
    process_found: Option<bool>,
    titles: Vec<WindowTitle>,
    forms: Vec<FormInspection>,
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone)]
struct WindowTitle {
    process_id: i32,
    title: String,
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone)]
struct FormInspection {
    process_id: i32,
    title: String,
    prompt_email: Option<String>,
}

#[cfg(target_os = "macos")]
fn check_status_macos(config: &Config) -> MonitorStatus {
    let inspection = inspect_windows_app_macos(&config.macos_app_name, false);
    match inspection.process_found {
        Some(false) => {
            debug!("Windows App process not found on macOS");
            return MonitorStatus::ProcessNotFound;
        }
        None => {
            debug!("Unable to inspect Windows App process on macOS");
            return MonitorStatus::Unknown;
        }
        Some(true) => {}
    }
    let app_window_titles = &inspection.titles;
    debug!(
        "macOS trusted app window count: {}",
        app_window_titles.len()
    );

    let login_title_keywords = [
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
    for title in app_window_titles {
        for keyword in &login_title_keywords {
            if contains_keyword(&title.title, keyword) {
                debug!("Login window detected on macOS by title keyword");
                let details = inspect_windows_app_macos(&config.macos_app_name, true);
                let form = matching_form(&details, title.process_id, &title.title);
                return MonitorStatus::LoginWindowDetected {
                    process_id: title.process_id,
                    window_title: title.title.clone(),
                    prompt_email: form.and_then(|form| form.prompt_email.clone()),
                };
            }
        }
    }

    if let Some(dialog_form) = inspection.forms.first() {
        let details = inspect_windows_app_macos(&config.macos_app_name, true);
        let form = matching_form(&details, dialog_form.process_id, &dialog_form.title)
            .cloned()
            .unwrap_or_else(|| dialog_form.clone());
        debug!("Login dialog detected on macOS inside trusted Windows App process");
        return MonitorStatus::LoginWindowDetected {
            process_id: form.process_id,
            window_title: form.title,
            prompt_email: form.prompt_email,
        };
    }

    let has_session = app_window_titles
        .iter()
        .any(|title| is_probable_session_window_title(&title.title));

    if has_session {
        debug!("macOS session window appears active");
        MonitorStatus::Connected
    } else {
        debug!("Windows App running but no session window detected on macOS");
        MonitorStatus::Unknown
    }
}

#[cfg(target_os = "macos")]
fn is_probable_session_window_title(title: &str) -> bool {
    let trimmed = title.trim();
    if trimmed.is_empty() {
        return false;
    }

    let lower = trimmed.to_lowercase();
    let non_session_titles = [
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

    !non_session_titles
        .iter()
        .any(|non_session| contains_keyword(&lower, non_session))
}

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
fn matching_form<'a>(
    inspection: &'a WindowInspection,
    process_id: i32,
    title: &str,
) -> Option<&'a FormInspection> {
    inspection.forms.iter().find(|form| {
        form.process_id == process_id
            && form.title == title
            && form.prompt_email.as_deref().is_some()
    })
}

#[cfg(target_os = "macos")]
fn inspect_windows_app_macos(app_name: &str, include_form_text: bool) -> WindowInspection {
    let trusted_pids = match macos_identity::trusted_process_ids(app_name) {
        Ok(pids) => pids,
        Err(e) => {
            debug!(error = %e, "Failed to resolve trusted Windows App process ids");
            return WindowInspection::default();
        }
    };
    if trusted_pids.is_empty() {
        return WindowInspection {
            process_found: Some(false),
            ..WindowInspection::default()
        };
    }
    let trusted_pids = macos_identity::applescript_pid_list_literal(&trusted_pids);
    let app_name = applescript_string_literal(app_name);
    let handlers = r#"
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

on appendFormText(containerRef, currentOutput)
    set outputText to currentOutput
    tell application "System Events"
        tell containerRef
            try
                repeat with tf in (every text field)
                    if not my elementIsSecureTextField(tf) then
                        try
                            set outputText to outputText & "FORM_TEXT:" & (name of tf as string) & linefeed
                        end try
                        try
                            set outputText to outputText & "FORM_TEXT:" & (value of tf as string) & linefeed
                        end try
                    end if
                end repeat
            end try
            try
                repeat with staticRef in (every static text)
                    try
                        set outputText to outputText & "FORM_TEXT:" & (name of staticRef as string) & linefeed
                    end try
                    try
                        set outputText to outputText & "FORM_TEXT:" & (value of staticRef as string) & linefeed
                    end try
                end repeat
            end try
            try
                repeat with elem in (every UI element)
                    if not my elementIsSecureTextField(elem) then
                        try
                            set outputText to outputText & "FORM_TEXT:" & (name of elem as string) & linefeed
                        end try
                        try
                            set outputText to outputText & "FORM_TEXT:" & (value of elem as string) & linefeed
                        end try
                        try
                            set outputText to outputText & "FORM_TEXT:" & (description of elem as string) & linefeed
                        end try
                        try
                            set outputText to outputText & "FORM_TEXT:" & (help of elem as string) & linefeed
                        end try
                        try
                            set outputText to outputText & "FORM_TEXT:" & (value of attribute "AXTitle" of elem as string) & linefeed
                        end try
                        try
                            set outputText to outputText & "FORM_TEXT:" & (value of attribute "AXDescription" of elem as string) & linefeed
                        end try
                        try
                            set outputText to outputText & "FORM_TEXT:" & (value of attribute "AXHelp" of elem as string) & linefeed
                        end try
                        set outputText to my appendFormText(elem, outputText)
                    end if
                end repeat
            end try
        end tell
    end tell
    return outputText
end appendFormText

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

on elementIsSecureTextField(elem)
    set roleText to my elementRoleText(elem)
    set labelText to my elementLabelText(elem)
    ignoring case
        if roleText contains "AXSecureTextField" then return true
        if roleText contains "secure text field" then return true
        if roleText contains "securetextfield" then return true
        if (roleText contains "AXTextField") and (roleText contains "secure") then return true
        if my roleLooksLikeTextField(roleText) and my textContainsPasswordCue(labelText) then return true
    end ignoring
    return false
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
"#;
    let collect_sheet_text = if include_form_text {
        "set output to my appendFormText(s, output)"
    } else {
        ""
    };
    let collect_window_text = if include_form_text {
        "set output to my appendFormText(w, output)"
    } else {
        ""
    };
    let script = format!(
        r#"
{}
tell application "System Events"
    set output to "PROC:false" & linefeed
    set processFound to false
    set expectedName to {}
    set trustedPIDs to {}
    try
        set procList to every application process whose name is expectedName
        repeat with proc in procList
            if my processMatches(proc, expectedName, trustedPIDs) then
            set procPID to unix id of proc as string
            if processFound is false then
                set output to "PROC:true" & linefeed
                set processFound to true
            end if
            repeat with w in (every window of proc)
                set wName to name of w as string
                set output to output & "TITLE:" & procPID & tab & wName & linefeed
                try
                    repeat with s in (every sheet of w)
                        set sheetButtonCount to my countPromptButtons(s)
                        set sheetButtonCount to sheetButtonCount + my countPromptButtons(w)
                        if my countPasswordFields(s) >= 1 and sheetButtonCount >= 1 then
                            set output to output & "FORM:SHEET:" & procPID & tab & wName & linefeed
                            {}
                        end if
                    end repeat
                end try
                try
                    if my countPasswordFields(w) >= 1 and my countPromptButtons(w) >= 1 then
                        set output to output & "FORM:" & procPID & tab & wName & linefeed
                        {}
                    end if
                end try
            end repeat
            end if
        end repeat
    end try
    return output
end tell
"#,
        handlers, app_name, trusted_pids, collect_sheet_text, collect_window_text
    );

    let output = match run_osascript(&script) {
        Ok(output) => output,
        Err(e) => {
            debug!(error = %e, "Windows App inspection AppleScript failed");
            return WindowInspection::default();
        }
    };
    if !output.status.success() {
        debug!(
            reason = classify_osascript_stderr(&output.stderr),
            "Windows App inspection AppleScript exited unsuccessfully"
        );
        return WindowInspection::default();
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut inspection = WindowInspection::default();
    let mut current_form_index: Option<usize> = None;
    for line in stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        if let Some(process_found) = line.strip_prefix("PROC:") {
            inspection.process_found = Some(process_found.trim().eq_ignore_ascii_case("true"));
        } else if let Some(title) = line.strip_prefix("TITLE:") {
            if let Some((process_id, title)) = parse_pid_and_text(title) {
                inspection.titles.push(WindowTitle { process_id, title });
            }
            current_form_index = None;
        } else if let Some(form_text) = line.strip_prefix("FORM_TEXT:") {
            if let Some(form_index) = current_form_index {
                if inspection.forms[form_index].prompt_email.is_none() {
                    inspection.forms[form_index].prompt_email = extract_email_like(form_text);
                }
            }
        } else if let Some(title) = line.strip_prefix("FORM:SHEET:") {
            current_form_index = push_form_candidate(&mut inspection.forms, title);
        } else if let Some(title) = line.strip_prefix("FORM:") {
            current_form_index = push_form_candidate(&mut inspection.forms, title);
        }
    }

    inspection
}

#[cfg(target_os = "macos")]
fn push_form_candidate(forms: &mut Vec<FormInspection>, line: &str) -> Option<usize> {
    let (process_id, title) = parse_pid_and_text(line)?;

    forms.push(FormInspection {
        process_id,
        title,
        prompt_email: None,
    });
    Some(forms.len() - 1)
}

#[cfg(target_os = "macos")]
fn parse_pid_and_text(line: &str) -> Option<(i32, String)> {
    let mut parts = line.splitn(2, '\t');
    let process_id = parts.next()?.trim().parse::<i32>().ok()?;
    let text = parts.next()?.trim().trim_matches('"').to_string();
    Some((process_id, text))
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
fn run_osascript(script: &str) -> std::io::Result<std::process::Output> {
    use std::io::{Error, ErrorKind};
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
            return child.wait_with_output();
        }

        if started.elapsed() >= MONITOR_OSASCRIPT_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Error::new(ErrorKind::TimedOut, "osascript timed out"));
        }

        thread::sleep(Duration::from_millis(25));
    }
}

#[cfg(target_os = "macos")]
fn classify_osascript_stderr(stderr: &[u8]) -> &'static str {
    let stderr = String::from_utf8_lossy(stderr).to_lowercase();
    if stderr.trim().is_empty() {
        "no stderr"
    } else if stderr.contains("assistive access") || stderr.contains("accessibility") {
        "accessibility_denied"
    } else if stderr.contains("not authorized")
        || stderr.contains("not allowed")
        || stderr.contains("privacy")
    {
        "automation_denied"
    } else if stderr.contains("syntax error") {
        "syntax_error"
    } else if stderr.contains("invalid index") || stderr.contains("can't get") {
        "accessibility_element_error"
    } else {
        "redacted_stderr"
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::{contains_keyword, extract_email_like, is_probable_session_window_title};

    #[test]
    fn contains_keyword_handles_non_ascii_boundaries() {
        assert!(contains_keyword("Введите Пароль для продолжения", "Пароль"));
        assert!(!contains_keyword("ПредПароль", "Пароль"));
    }

    #[test]
    fn extracts_email_like_text() {
        assert_eq!(
            extract_email_like("Signed in as user.name+rdp@example.com"),
            Some("user.name+rdp@example.com".to_string())
        );
        assert_eq!(extract_email_like("No email here"), None);
    }

    #[test]
    fn session_title_filter_rejects_shell_windows_but_allows_desktops() {
        assert!(!is_probable_session_window_title("Windows App"));
        assert!(!is_probable_session_window_title("About Windows App"));
        assert!(!is_probable_session_window_title("Disconnected from VM"));
        assert!(!is_probable_session_window_title(
            "Unable to connect to host"
        ));
        assert!(is_probable_session_window_title("Finance Desktop 01"));
        assert!(is_probable_session_window_title("corp-vm-7"));
    }
}
