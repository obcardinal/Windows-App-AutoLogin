use serde::{Deserialize, Serialize};
#[cfg(target_os = "macos")]
use tracing::{debug, info, warn};

#[cfg(target_os = "macos")]
const DIAGNOSE_OSASCRIPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
#[cfg(target_os = "macos")]
const MAX_SECURE_FIELD_TRAVERSAL_DEPTH: usize = 4;
#[cfg(target_os = "macos")]
const MAX_SECURE_FIELD_TRAVERSAL_ELEMENTS: usize = 24;
#[cfg(target_os = "macos")]
const MAX_SECURE_FIELDS: usize = 8;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiElement {
    pub element_type: String,
    pub name: String,
    pub value: Option<String>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowInfo {
    pub title: String,
    pub elements: Vec<UiElement>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub name: String,
    pub pid: Option<i32>,
    pub windows: Vec<WindowInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticReport {
    pub timestamp: String,
    pub target_processes: Vec<ProcessInfo>,
    pub system_dialogs: Vec<ProcessInfo>,
}

impl DiagnosticReport {
    pub fn to_plaintext(&self) -> String {
        let mut out = String::new();
        out.push_str("========================================\n");
        out.push_str("  macOS UI Diagnostic Report\n");
        out.push_str(&format!("  Generated: {}\n", self.timestamp));
        out.push_str("========================================\n\n");

        if self.target_processes.is_empty() {
            out.push_str("⚠️  No target processes found.\n");
            out.push_str("   Make sure Windows App is running.\n\n");
        } else {
            for proc in &self.target_processes {
                out.push_str(&format!(
                    "📌 PROCESS: {} (pid={})\n",
                    proc.name,
                    proc.pid.unwrap_or(-1)
                ));
                if proc.windows.is_empty() {
                    out.push_str("   (no windows)\n");
                }
                for w in &proc.windows {
                    out.push_str(&format!("   🪟 WINDOW: \"{}\"\n", w.title));
                    if w.elements.is_empty() {
                        out.push_str("      (no accessible UI elements)\n");
                    }
                    for elem in &w.elements {
                        out.push_str(&format!(
                            "      ▸ {} | name=\"{}\"",
                            elem.element_type, elem.name
                        ));
                        if let Some(e) = elem.enabled {
                            out.push_str(&format!(" | enabled={}", e));
                        }
                        out.push('\n');
                    }
                }
                out.push('\n');
            }
        }

        if !self.system_dialogs.is_empty() {
            out.push_str("----------------------------------------\n");
            out.push_str("  System Dialogs (Security / Login)\n");
            out.push_str("----------------------------------------\n");
            for proc in &self.system_dialogs {
                out.push_str(&format!("🔒 SYSTEM PROCESS: {}\n", proc.name));
                for w in &proc.windows {
                    out.push_str(&format!("   🪟 WINDOW: \"{}\"\n", w.title));
                    for elem in &w.elements {
                        out.push_str(&format!(
                            "      ▸ {} | name=\"{}\"\n",
                            elem.element_type, elem.name
                        ));
                    }
                }
                out.push('\n');
            }
        }

        out.push_str("----------------------------------------\n");
        out.push_str("  Raw AppleScript output is omitted to avoid copying field values.\n");

        out
    }
}

pub fn run() -> anyhow::Result<DiagnosticReport> {
    run_for_app("Windows App")
}

pub fn run_for_app(app_name: &str) -> anyhow::Result<DiagnosticReport> {
    #[cfg(target_os = "macos")]
    {
        run_macos(app_name)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = app_name;
        Ok(DiagnosticReport {
            timestamp: chrono::Local::now().to_rfc3339(),
            target_processes: vec![],
            system_dialogs: vec![],
        })
    }
}

#[cfg(target_os = "macos")]
fn run_macos(app_name: &str) -> anyhow::Result<DiagnosticReport> {
    info!("Starting macOS UI diagnostic...");

    let script = build_applescript(app_name);
    debug!("AppleScript length: {} chars", script.len());

    let output = run_osascript(&script).map_err(|e| {
        if e.kind() == std::io::ErrorKind::TimedOut {
            anyhow::anyhow!(
                "diagnostic timed out after {}s while querying macOS Accessibility; secure-field traversal is capped at depth {}, {} elements, {} fields; output was discarded and no field values were copied",
                DIAGNOSE_OSASCRIPT_TIMEOUT.as_secs(),
                MAX_SECURE_FIELD_TRAVERSAL_DEPTH,
                MAX_SECURE_FIELD_TRAVERSAL_ELEMENTS,
                MAX_SECURE_FIELDS
            )
        } else {
            anyhow::anyhow!("failed to run diagnostic AppleScript: {}", redacted_io_error(&e))
        }
    })?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !stderr.is_empty() {
        warn!(
            stderr_present = !stderr.trim().is_empty(),
            "osascript produced stderr during diagnosis"
        );
    }
    if !output.status.success() {
        anyhow::bail!("osascript failed: {}", redacted_stderr(stderr.trim()));
    }

    let (target_processes, system_dialogs) = parse_output(&stdout);

    info!(
        "Diagnostic complete: {} target process(es), {} system dialog(s)",
        target_processes.len(),
        system_dialogs.len()
    );

    Ok(DiagnosticReport {
        timestamp: chrono::Local::now().to_rfc3339(),
        target_processes,
        system_dialogs,
    })
}

#[cfg(target_os = "macos")]
fn redacted_stderr(stderr: &str) -> &'static str {
    if stderr.is_empty() {
        "no stderr"
    } else {
        "redacted stderr"
    }
}

#[cfg(target_os = "macos")]
fn redacted_io_error(error: &std::io::Error) -> &'static str {
    match error.kind() {
        std::io::ErrorKind::NotFound => "osascript command was not found",
        std::io::ErrorKind::PermissionDenied => "permission denied while starting osascript",
        std::io::ErrorKind::TimedOut => "osascript timed out",
        _ => "redacted I/O error",
    }
}

#[cfg(target_os = "macos")]
fn build_applescript(app_name: &str) -> String {
    let app_name = applescript_string_literal(app_name);
    format!(
        r#"
property secureTraversalCount : 0
property secureFieldCount : 0
property secureTraversalTruncated : false
property maxSecureTraversalDepth : {}
property maxSecureTraversalElements : {}
property maxSecureFields : {}

on elementRoleText(elem)
    tell application "System Events"
        set roleText to ""
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

on appendSecureTextFields(containerRef, currentOutput, currentDepth)
    set outputText to currentOutput
    if currentDepth > maxSecureTraversalDepth then
        set secureTraversalTruncated to true
        return outputText
    end if
    if secureTraversalCount >= maxSecureTraversalElements then
        set secureTraversalTruncated to true
        return outputText
    end if
    if secureFieldCount >= maxSecureFields then
        set secureTraversalTruncated to true
        return outputText
    end if
    tell application "System Events"
        try
            repeat with elem in (every UI element of containerRef)
                if secureTraversalCount >= maxSecureTraversalElements then
                    set secureTraversalTruncated to true
                    exit repeat
                end if
                if secureFieldCount >= maxSecureFields then
                    set secureTraversalTruncated to true
                    exit repeat
                end if
                set secureTraversalCount to secureTraversalCount + 1
                if my elementIsSecureTextField(elem) then
                    try
                        set n to name of elem as string
                    on error
                        set n to ""
                    end try
                    set outputText to outputText & "ELEMENT:secure_text_field|name=" & n
                    try
                        set e to enabled of elem as string
                        set outputText to outputText & "|enabled=" & e
                    end try
                    set outputText to outputText & "\n"
                    set secureFieldCount to secureFieldCount + 1
                else
                    try
                        set outputText to my appendSecureTextFields(elem, outputText, currentDepth + 1)
                    end try
                end if
            end repeat
        end try
    end tell
    return outputText
end appendSecureTextFields

tell application "System Events"
    set output to ""
    
    -- ========== Target RDP processes ==========
    set targetNames to {{{}}}
    repeat with targetName in targetNames
        try
            set procList to every application process whose name is targetName
            repeat with proc in procList
                set procName to name of proc
                try
                    set procPID to unix id of proc
                on error
                    set procPID to "unknown"
                end try
                set output to output & "PROCESS:" & procName & "|pid=" & procPID & "\n"
                
                repeat with w in (every window of proc)
                    try
                        set wName to name of w as string
                        set output to output & "WINDOW:" & wName & "\n"
                        
                        -- text fields (window level)
                        try
                            repeat with elem in (every text field of w)
                                try
                                    set n to name of elem as string
                                    set output to output & "ELEMENT:text_field|name=" & n
                                    try
                                        set e to enabled of elem as string
                                        set output to output & "|enabled=" & e
                                    end try
                                    set output to output & "\n"
                                end try
                            end repeat
                        end try

                        -- secure text fields (recursive)
                        try
                            set output to my appendSecureTextFields(w, output, 0)
                        end try
                        
                        -- buttons (window level)
                        try
                            repeat with elem in (every button of w)
                                try
                                    set n to name of elem as string
                                    set output to output & "ELEMENT:button|name=" & n
                                    try
                                        set e to enabled of elem as string
                                        set output to output & "|enabled=" & e
                                    end try
                                    set output to output & "\n"
                                end try
                            end repeat
                        end try
                        
                        -- static texts (window level)
                        try
                            repeat with elem in (every static text of w)
                                try
                                    set n to name of elem as string
                                    set output to output & "ELEMENT:static_text|name=" & n & "\n"
                                end try
                            end repeat
                        end try
                        
                        -- pop up buttons
                        try
                            repeat with elem in (every pop up button of w)
                                try
                                    set n to name of elem as string
                                    set output to output & "ELEMENT:pop_up_button|name=" & n
                                    set output to output & "\n"
                                end try
                            end repeat
                        end try
                        
                        -- checkboxes
                        try
                            repeat with elem in (every checkbox of w)
                                try
                                    set n to name of elem as string
                                    set output to output & "ELEMENT:check_box|name=" & n
                                    try
                                        set e to enabled of elem as string
                                        set output to output & "|enabled=" & e
                                    end try
                                    set output to output & "\n"
                                end try
                            end repeat
                        end try
                        
                        -- radio buttons
                        try
                            repeat with elem in (every radio button of w)
                                try
                                    set n to name of elem as string
                                    set output to output & "ELEMENT:radio_button|name=" & n
                                    try
                                        set e to enabled of elem as string
                                        set output to output & "|enabled=" & e
                                    end try
                                    set output to output & "\n"
                                end try
                            end repeat
                        end try
                        
                        -- groups (one level deep)
                        try
                            repeat with grp in (every group of w)
                                try
                                    set gName to name of grp as string
                                    set output to output & "GROUP:" & gName & "\n"
                                    
                                    try
                                        repeat with elem in (every text field of grp)
                                            try
                                                set n to name of elem as string
                                                set output to output & "ELEMENT:text_field|name=" & n
                                                try
                                                    set e to enabled of elem as string
                                                    set output to output & "|enabled=" & e
                                                end try
                                                set output to output & "\n"
                                            end try
                                        end repeat
                                    end try

                                    try
                                        set output to my appendSecureTextFields(grp, output, 0)
                                    end try
                                    
                                    try
                                        repeat with elem in (every button of grp)
                                            try
                                                set n to name of elem as string
                                                set output to output & "ELEMENT:button|name=" & n
                                                try
                                                    set e to enabled of elem as string
                                                    set output to output & "|enabled=" & e
                                                end try
                                                set output to output & "\n"
                                            end try
                                        end repeat
                                    end try
                                    
                                    try
                                        repeat with elem in (every static text of grp)
                                            try
                                                set n to name of elem as string
                                                set output to output & "ELEMENT:static_text|name=" & n & "\n"
                                            end try
                                        end repeat
                                    end try
                                end try
                            end repeat
                        end try
                        
                        -- sheets (one level deep)
                        try
                            repeat with sh in (every sheet of w)
                                try
                                    set sName to name of sh as string
                                    set output to output & "SHEET:" & sName & "\n"
                                    
                                    try
                                        repeat with elem in (every text field of sh)
                                            try
                                                set n to name of elem as string
                                                set output to output & "ELEMENT:text_field|name=" & n
                                                try
                                                    set e to enabled of elem as string
                                                    set output to output & "|enabled=" & e
                                                end try
                                                set output to output & "\n"
                                            end try
                                        end repeat
                                    end try

                                    try
                                        set output to my appendSecureTextFields(sh, output, 0)
                                    end try
                                    
                                    try
                                        repeat with elem in (every button of sh)
                                            try
                                                set n to name of elem as string
                                                set output to output & "ELEMENT:button|name=" & n
                                                try
                                                    set e to enabled of elem as string
                                                    set output to output & "|enabled=" & e
                                                end try
                                                set output to output & "\n"
                                            end try
                                        end repeat
                                    end try
                                    
                                    try
                                        repeat with elem in (every static text of sh)
                                            try
                                                set n to name of elem as string
                                                set output to output & "ELEMENT:static_text|name=" & n & "\n"
                                            end try
                                        end repeat
                                    end try
                                end try
                            end repeat
                        end try
                        
                    on error errMsg
                        set output to output & "WINDOW_ERROR:" & errMsg & "\n"
                    end try
                end repeat
            end repeat
        on error errMsg
            set output to output & "PROCESS_ERROR:" & targetName & "|" & errMsg & "\n"
        end try
    end repeat
    
    -- ========== System dialogs ==========
    set systemProcs to {{"SecurityAgent", "loginwindow"}}
    repeat with sysName in systemProcs
        try
            set procList to every application process whose name is sysName
            repeat with proc in procList
                set procName to name of proc
                set output to output & "SYSTEM_PROCESS:" & procName & "\n"
                repeat with w in (every window of proc)
                    try
                        set wName to name of w as string
                        set output to output & "WINDOW:" & wName & "\n"
                        repeat with elem in (every UI element of w)
                            try
                                set n to name of elem as string
                                set r to role description of elem as string
                                set output to output & "ELEMENT:" & r & "|name=" & n
                                set output to output & "\n"
                            on error
                            end try
                        end repeat
                    on error
                    end try
                end repeat
            end repeat
        on error
        end try
    end repeat
    
    return output
end tell
"#,
        MAX_SECURE_FIELD_TRAVERSAL_DEPTH,
        MAX_SECURE_FIELD_TRAVERSAL_ELEMENTS,
        MAX_SECURE_FIELDS,
        app_name
    )
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

        if started.elapsed() >= DIAGNOSE_OSASCRIPT_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Error::new(ErrorKind::TimedOut, "osascript timed out"));
        }

        thread::sleep(Duration::from_millis(25));
    }
}

#[cfg(target_os = "macos")]
fn parse_output(text: &str) -> (Vec<ProcessInfo>, Vec<ProcessInfo>) {
    let mut target_processes: Vec<ProcessInfo> = Vec::new();
    let mut system_dialogs: Vec<ProcessInfo> = Vec::new();

    let mut current_proc: Option<ProcessInfo> = None;
    let mut current_window: Option<WindowInfo> = None;
    let mut in_system = false;

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if let Some(rest) = line.strip_prefix("PROCESS:") {
            if let Some(w) = current_window.take() {
                if let Some(ref mut p) = current_proc {
                    p.windows.push(w);
                }
            }
            if let Some(p) = current_proc.take() {
                if in_system {
                    system_dialogs.push(p);
                } else {
                    target_processes.push(p);
                }
            }
            in_system = false;

            let mut parts = rest.splitn(2, "|pid=");
            let name = parts.next().unwrap_or("").to_string();
            let pid = parts.next().and_then(|s| s.parse::<i32>().ok());
            current_proc = Some(ProcessInfo {
                name,
                pid,
                windows: Vec::new(),
            });
            continue;
        }

        if let Some(rest) = line.strip_prefix("SYSTEM_PROCESS:") {
            if let Some(w) = current_window.take() {
                if let Some(ref mut p) = current_proc {
                    p.windows.push(w);
                }
            }
            if let Some(p) = current_proc.take() {
                if in_system {
                    system_dialogs.push(p);
                } else {
                    target_processes.push(p);
                }
            }
            in_system = true;
            current_proc = Some(ProcessInfo {
                name: rest.to_string(),
                pid: None,
                windows: Vec::new(),
            });
            continue;
        }

        if let Some(rest) = line.strip_prefix("WINDOW:") {
            if let Some(w) = current_window.take() {
                if let Some(ref mut p) = current_proc {
                    p.windows.push(w);
                }
            }
            current_window = Some(WindowInfo {
                title: rest.to_string(),
                elements: Vec::new(),
            });
            continue;
        }

        if let Some(rest) = line.strip_prefix("ELEMENT:") {
            let mut elem = UiElement {
                element_type: String::new(),
                name: String::new(),
                value: None,
                enabled: None,
            };
            let mut seen_type = false;
            for part in rest.split('|') {
                if let Some((key, val)) = part.split_once('=') {
                    match key {
                        "name" => elem.name = val.to_string(),
                        "value" => elem.value = Some(val.to_string()),
                        "enabled" => elem.enabled = Some(val == "true"),
                        _ => {}
                    }
                } else if !seen_type {
                    elem.element_type = part.to_string();
                    seen_type = true;
                }
            }
            if let Some(ref mut w) = current_window {
                w.elements.push(elem);
            }
            continue;
        }

        if line.starts_with("GROUP:") || line.starts_with("SHEET:") {
            continue;
        }
    }

    if let Some(w) = current_window.take() {
        if let Some(ref mut p) = current_proc {
            p.windows.push(w);
        }
    }
    if let Some(p) = current_proc.take() {
        if in_system {
            system_dialogs.push(p);
        } else {
            target_processes.push(p);
        }
    }

    redact_report_parts(&mut target_processes, &mut system_dialogs);
    (target_processes, system_dialogs)
}

#[cfg(target_os = "macos")]
fn redact_report_parts(target_processes: &mut [ProcessInfo], system_dialogs: &mut [ProcessInfo]) {
    for proc in target_processes {
        for window in &mut proc.windows {
            window.title = redact_title(&window.title);
            for elem in &mut window.elements {
                elem.name = redact_element_name(&elem.element_type, &elem.name, false);
                elem.value = elem.value.as_deref().map(redact_value);
            }
        }
    }

    for proc in system_dialogs {
        for window in &mut proc.windows {
            window.title = redact_title(&window.title);
            for elem in &mut window.elements {
                elem.name = redact_element_name(&elem.element_type, &elem.name, true);
                elem.value = elem.value.as_deref().map(redact_value);
            }
        }
    }
}

#[cfg(target_os = "macos")]
fn redact_title(value: &str) -> String {
    if value.trim().is_empty() {
        return String::new();
    }
    "[redacted title]".to_string()
}

#[cfg(target_os = "macos")]
fn redact_element_name(element_type: &str, value: &str, system_dialog: bool) -> String {
    if value.trim().is_empty() {
        return String::new();
    }

    let element_type = element_type.to_lowercase();
    let allowed_control_label = !system_dialog
        && matches!(
            element_type.as_str(),
            "button" | "check_box" | "radio_button" | "pop_up_button"
        );
    if allowed_control_label {
        return redact_emails(value);
    }

    "[redacted]".to_string()
}

#[cfg(target_os = "macos")]
fn redact_value(value: &str) -> String {
    if value.trim().is_empty() {
        String::new()
    } else {
        "[redacted]".to_string()
    }
}

#[cfg(target_os = "macos")]
fn redact_emails(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    let mut out = String::new();
    let mut idx = 0;

    while idx < chars.len() {
        if chars[idx] == '@' {
            let mut start = idx;
            while start > 0 && is_email_char(chars[start - 1]) {
                start -= 1;
            }
            let mut end = idx + 1;
            while end < chars.len() && is_email_char(chars[end]) {
                end += 1;
            }

            let candidate: String = chars[start..end].iter().collect();
            if looks_like_email(&candidate) {
                let keep_chars = out.chars().count().saturating_sub(idx - start);
                out = out.chars().take(keep_chars).collect();
                out.push_str("[email]");
                idx = end;
                continue;
            }
        }

        out.push(chars[idx]);
        idx += 1;
    }

    out
}

#[cfg(target_os = "macos")]
fn looks_like_email(value: &str) -> bool {
    let mut parts = value.split('@');
    let local = parts.next().unwrap_or_default();
    let domain = parts.next().unwrap_or_default();
    parts.next().is_none()
        && !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
}

#[cfg(target_os = "macos")]
fn is_email_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '%' | '+' | '-' | '@')
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn parse_output_redacts_names_titles_and_values() {
        let text = "\
PROCESS:Windows App|pid=123
WINDOW:user@example.com login
ELEMENT:text_field|name=user@example.com|value=plaintext-user
ELEMENT:secure_text_field|name=password|value=super-secret
ELEMENT:button|name=Continue user@example.com|enabled=true
SYSTEM_PROCESS:SecurityAgent
WINDOW:OTP token prompt
ELEMENT:static text|name=123456 token
";

        let (target_processes, system_dialogs) = parse_output(text);

        let target_window = &target_processes[0].windows[0];
        assert_eq!(target_window.title, "[redacted title]");
        assert_eq!(target_window.elements[0].name, "[redacted]");
        assert_eq!(
            target_window.elements[0].value.as_deref(),
            Some("[redacted]")
        );
        assert_eq!(target_window.elements[1].name, "[redacted]");
        assert_eq!(
            target_window.elements[1].value.as_deref(),
            Some("[redacted]")
        );
        assert_eq!(target_window.elements[2].name, "Continue [email]");

        let system_window = &system_dialogs[0].windows[0];
        assert_eq!(system_window.title, "[redacted title]");
        assert_eq!(system_window.elements[0].name, "[redacted]");
    }

    #[test]
    fn parse_output_redacts_password_like_field_values() {
        let text = "\
PROCESS:Windows App|pid=123
WINDOW:Sign in
ELEMENT:text_field|name=Password|value=super-secret
ELEMENT:text_field|name=Passcode|value=123456
ELEMENT:button|name=Continue|enabled=true
";

        let (target_processes, _) = parse_output(text);
        let rendered = serde_json::to_string(&target_processes).unwrap();

        assert!(!rendered.contains("super-secret"));
        assert!(!rendered.contains("123456"));
        assert!(rendered.contains("[redacted]"));
        assert!(rendered.contains("Continue"));
    }
}
