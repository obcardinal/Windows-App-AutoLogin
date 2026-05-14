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
const MAX_DIAGNOSTIC_COLLECTION_PROCESSES: usize = 8;
const MAX_DIAGNOSTIC_COLLECTION_WINDOWS: usize = 32;
const MAX_DIAGNOSTIC_COLLECTION_ELEMENTS: usize = 256;
const MAX_DIAGNOSTIC_PROTOCOL_VALUE_CHARS: usize = 160;
#[cfg(target_os = "macos")]
const MAX_DIAGNOSTIC_PARSE_LINES: usize = 4096;
#[cfg(target_os = "macos")]
const MAX_DIAGNOSTIC_RAW_OUTPUT_BYTES: usize = 128 * 1024;
pub const MAX_DIAGNOSTIC_OUTPUT_BYTES: usize = 64 * 1024;
const DIAGNOSTIC_OUTPUT_TRUNCATED_TEXT: &str = "diagnostic output truncated";
const DIAGNOSTIC_OUTPUT_TRUNCATED_MARKER: &str = "\n\n[diagnostic output truncated]\n";
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const DIAGNOSTIC_COLLECTION_TRUNCATED_TEXT: &str = "diagnostic collection truncated";
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const DIAGNOSTIC_PARSE_TRUNCATED_TEXT: &str = "diagnostic parser truncated input";
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const DIAGNOSTIC_RAW_OUTPUT_TRUNCATED_TEXT: &str = "diagnostic raw output truncated";
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const DIAGNOSTIC_SECURE_TRAVERSAL_TRUNCATED_TEXT: &str =
    "diagnostic secure-field traversal truncated";
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const DIAGNOSTIC_STDERR_TRUNCATED_TEXT: &str = "diagnostic subprocess stderr truncated";

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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub truncation_reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct DiagnosticJsonOutput {
    timestamp: String,
    target_processes: Vec<ProcessInfo>,
    system_dialogs: Vec<ProcessInfo>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    truncation_reasons: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    truncated: Option<String>,
}

impl DiagnosticJsonOutput {
    fn from_report_with_limits(
        report: &DiagnosticReport,
        mut truncated: bool,
        process_budget: usize,
        window_budget: usize,
        element_budget: usize,
    ) -> Self {
        let mut budget = DiagnosticJsonBudget {
            processes: process_budget,
            windows: window_budget,
            elements: element_budget,
        };
        let (target_processes, target_truncated) =
            clone_bounded_processes(&report.target_processes, &mut budget);
        let (system_dialogs, system_truncated) =
            clone_bounded_processes(&report.system_dialogs, &mut budget);
        truncated |= target_truncated || system_truncated;

        Self {
            timestamp: bounded_diagnostic_json_scalar(&report.timestamp, &mut truncated),
            target_processes,
            system_dialogs,
            truncation_reasons: report.truncation_reasons.clone(),
            truncated: truncated.then(|| DIAGNOSTIC_OUTPUT_TRUNCATED_TEXT.to_string()),
        }
    }
}

struct DiagnosticJsonBudget {
    processes: usize,
    windows: usize,
    elements: usize,
}

impl DiagnosticReport {
    pub fn to_plaintext(&self) -> String {
        let mut out = String::new();
        out.push_str("========================================\n");
        out.push_str("  macOS UI Diagnostic Report\n");
        out.push_str(&format!("  Generated: {}\n", self.timestamp));
        out.push_str("========================================\n\n");

        if !self.truncation_reasons.is_empty() {
            out.push_str("⚠️  Diagnostic collection was truncated.\n");
            for reason in &self.truncation_reasons {
                out.push_str(&format!("   - {}\n", reason));
            }
            out.push('\n');
        }

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

pub fn cap_diagnostic_output(output: String) -> String {
    if output.len() <= MAX_DIAGNOSTIC_OUTPUT_BYTES {
        return output;
    }

    let mut capped = output;
    let mut boundary =
        MAX_DIAGNOSTIC_OUTPUT_BYTES.saturating_sub(DIAGNOSTIC_OUTPUT_TRUNCATED_MARKER.len());
    while boundary > 0 && !capped.is_char_boundary(boundary) {
        boundary -= 1;
    }
    capped.truncate(boundary);
    capped.push_str(DIAGNOSTIC_OUTPUT_TRUNCATED_MARKER);
    capped
}

pub fn diagnostic_report_to_capped_pretty_json(
    report: &DiagnosticReport,
) -> Result<String, serde_json::Error> {
    let mut process_budget = MAX_DIAGNOSTIC_COLLECTION_PROCESSES;
    let mut window_budget = MAX_DIAGNOSTIC_COLLECTION_WINDOWS;
    let mut element_budget = MAX_DIAGNOSTIC_COLLECTION_ELEMENTS;
    let mut force_truncated = false;

    loop {
        let output = DiagnosticJsonOutput::from_report_with_limits(
            report,
            force_truncated,
            process_budget,
            window_budget,
            element_budget,
        );
        let json = serde_json::to_string_pretty(&output)?;
        if diagnostic_stdout_len(&json) <= MAX_DIAGNOSTIC_OUTPUT_BYTES {
            return Ok(json);
        }

        force_truncated = true;
        if element_budget > 0 {
            element_budget = element_budget.saturating_sub(element_budget.max(2) / 2);
        } else if window_budget > 0 {
            window_budget = window_budget.saturating_sub(window_budget.max(2) / 2);
        } else if process_budget > 0 {
            process_budget = process_budget.saturating_sub(process_budget.max(2) / 2);
        } else {
            let output = DiagnosticJsonOutput::from_report_with_limits(report, true, 0, 0, 0);
            return serde_json::to_string_pretty(&output);
        }
    }
}

fn diagnostic_stdout_len(json: &str) -> usize {
    json.len().saturating_add(1)
}

fn clone_bounded_processes(
    processes: &[ProcessInfo],
    budget: &mut DiagnosticJsonBudget,
) -> (Vec<ProcessInfo>, bool) {
    let mut cloned = Vec::new();
    let mut truncated = false;

    for process in processes {
        if budget.processes == 0 {
            truncated = true;
            break;
        }
        budget.processes -= 1;

        let mut process_truncated = false;
        let mut name_truncated = false;
        let mut cloned_process = ProcessInfo {
            name: bounded_diagnostic_json_scalar(&process.name, &mut name_truncated),
            pid: process.pid,
            windows: Vec::new(),
        };
        truncated |= name_truncated;

        for window in &process.windows {
            if budget.windows == 0 {
                truncated = true;
                process_truncated = true;
                break;
            }
            budget.windows -= 1;

            let mut title_truncated = false;
            let mut cloned_window = WindowInfo {
                title: bounded_diagnostic_json_scalar(&window.title, &mut title_truncated),
                elements: Vec::new(),
            };
            truncated |= title_truncated;

            for element in &window.elements {
                if budget.elements == 0 {
                    truncated = true;
                    process_truncated = true;
                    break;
                }
                budget.elements -= 1;

                let mut element_truncated = false;
                cloned_window.elements.push(UiElement {
                    element_type: bounded_diagnostic_json_scalar(
                        &element.element_type,
                        &mut element_truncated,
                    ),
                    name: bounded_diagnostic_json_scalar(&element.name, &mut element_truncated),
                    value: element
                        .value
                        .as_deref()
                        .map(|value| bounded_diagnostic_json_scalar(value, &mut element_truncated)),
                    enabled: element.enabled,
                });
                truncated |= element_truncated;
            }

            cloned_process.windows.push(cloned_window);
            if process_truncated {
                break;
            }
        }

        cloned.push(cloned_process);
        if process_truncated {
            continue;
        }
    }

    if cloned.len() < processes.len() {
        truncated = true;
    }

    (cloned, truncated)
}

fn bounded_diagnostic_json_scalar(value: &str, truncated: &mut bool) -> String {
    let byte_limit = MAX_DIAGNOSTIC_PROTOCOL_VALUE_CHARS.saturating_mul(4);
    if value.len() <= byte_limit && value.chars().count() <= MAX_DIAGNOSTIC_PROTOCOL_VALUE_CHARS {
        return value.to_string();
    }

    *truncated = true;
    let mut output = String::new();
    for ch in value.chars().take(MAX_DIAGNOSTIC_PROTOCOL_VALUE_CHARS) {
        output.push(ch);
    }
    output.push_str("[truncated]");
    output
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
            truncation_reasons: vec![],
        })
    }
}

#[cfg(target_os = "macos")]
fn run_macos(app_name: &str) -> anyhow::Result<DiagnosticReport> {
    info!("Starting macOS UI diagnostic...");

    let trusted_target_pids = crate::macos_identity::trusted_process_infos(app_name)
        .map_err(|_| anyhow::anyhow!("failed to verify diagnostic target identity"))?
        .into_iter()
        .map(|process| process.pid)
        .collect::<Vec<_>>();
    let script = build_applescript(app_name, &trusted_target_pids);
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
    let mut truncation_reasons = Vec::new();
    if output.stdout_truncated {
        add_truncation_reason(
            &mut truncation_reasons,
            DIAGNOSTIC_RAW_OUTPUT_TRUNCATED_TEXT,
        );
    }
    if output.stderr_truncated {
        add_truncation_reason(&mut truncation_reasons, DIAGNOSTIC_STDERR_TRUNCATED_TEXT);
    }

    if !stderr.is_empty() {
        warn!(
            stderr_present = !stderr.trim().is_empty(),
            "osascript produced stderr during diagnosis"
        );
    }
    if !output.status.success() {
        anyhow::bail!("osascript failed: {}", redacted_stderr(stderr.trim()));
    }

    let stdout = cap_raw_diagnostic_protocol_output(&stdout, output.stdout_truncated);
    let (target_processes, system_dialogs, parsed_truncation_reasons) =
        parse_output_with_truncation(&stdout, app_name, Some(&trusted_target_pids));
    for reason in parsed_truncation_reasons {
        add_truncation_reason(&mut truncation_reasons, &reason);
    }

    info!(
        "Diagnostic complete: {} target process(es), {} system dialog(s)",
        target_processes.len(),
        system_dialogs.len()
    );

    Ok(DiagnosticReport {
        timestamp: chrono::Local::now().to_rfc3339(),
        target_processes,
        system_dialogs,
        truncation_reasons,
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
fn cap_raw_diagnostic_protocol_output(
    output: &str,
    already_truncated: bool,
) -> std::borrow::Cow<'_, str> {
    if output.len() <= MAX_DIAGNOSTIC_RAW_OUTPUT_BYTES && !already_truncated {
        return std::borrow::Cow::Borrowed(output);
    }

    let marker = "\nTRUNCATED:raw-output\n";
    let mut boundary = MAX_DIAGNOSTIC_RAW_OUTPUT_BYTES.saturating_sub(marker.len());
    boundary = boundary.min(output.len());
    while boundary > 0 && !output.is_char_boundary(boundary) {
        boundary -= 1;
    }
    let mut capped = output[..boundary].to_string();
    capped.push_str(marker);
    std::borrow::Cow::Owned(capped)
}

#[cfg(target_os = "macos")]
fn build_applescript(app_name: &str, trusted_target_pids: &[i32]) -> String {
    let app_name = applescript_string_literal(app_name);
    let trusted_target_pids = applescript_pid_list_literal(trusted_target_pids);
    format!(
        r#"
	property secureTraversalCount : 0
	property secureFieldCount : 0
	property secureTraversalTruncated : false
	property diagnosticWindowCount : 0
	property diagnosticElementCount : 0
	property diagnosticCollectionTruncated : false
	property maxSecureTraversalDepth : {}
	property maxSecureTraversalElements : {}
	property maxSecureFields : {}
	property maxDiagnosticWindows : {}
	property maxDiagnosticElements : {}
	property maxDiagnosticValueChars : {}

	on diagnosticValue(rawValue)
	    set textValue to rawValue as string
	    if (length of textValue) > maxDiagnosticValueChars then
	        set textValue to (text 1 thru maxDiagnosticValueChars of textValue) & "[truncated]"
	    end if
	    set textValue to my replaceDiagnosticText(textValue, "%", "%25")
    set textValue to my replaceDiagnosticText(textValue, "|", "%7C")
    set textValue to my replaceDiagnosticText(textValue, "=", "%3D")
    set textValue to my replaceDiagnosticText(textValue, return, "%0D")
    set textValue to my replaceDiagnosticText(textValue, linefeed, "%0A")
    set textValue to my replaceDiagnosticText(textValue, tab, "%09")
	    return textValue
	end diagnosticValue

	on reserveDiagnosticWindow()
	    if diagnosticCollectionTruncated then return false
	    if diagnosticWindowCount >= maxDiagnosticWindows then
	        set diagnosticCollectionTruncated to true
	        return false
	    end if
	    set diagnosticWindowCount to diagnosticWindowCount + 1
	    return true
	end reserveDiagnosticWindow

	on reserveDiagnosticElement()
	    if diagnosticCollectionTruncated then return false
	    if diagnosticElementCount >= maxDiagnosticElements then
	        set diagnosticCollectionTruncated to true
	        return false
	    end if
	    set diagnosticElementCount to diagnosticElementCount + 1
	    return true
	end reserveDiagnosticElement

on replaceDiagnosticText(textValue, oldText, newText)
    set AppleScript's text item delimiters to oldText
    set textParts to text items of textValue
    set AppleScript's text item delimiters to newText
    set textValue to textParts as string
    set AppleScript's text item delimiters to ""
    return textValue
end replaceDiagnosticText

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
                if not my elementIsHidden(elem) then
                    set secureTraversalCount to secureTraversalCount + 1
                    if my elementIsSecureTextField(elem) then
                        if not my reserveDiagnosticElement() then exit repeat
                        try
                            set n to name of elem as string
                        on error
                            set n to ""
                        end try
                        set outputText to outputText & "ELEMENT:secure_text_field|name=" & my diagnosticValue(n)
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
                end if
            end repeat
        end try
    end tell
    return outputText
end appendSecureTextFields

tell application "System Events"
    set output to ""
    
    -- ========== Target RDP processes ==========
    set targetName to {}
    set targetPids to {}
    if (count of targetPids) > 0 then
        repeat with proc in (every application process)
            if diagnosticCollectionTruncated then exit repeat
            try
                if my processMatches(proc, targetName, targetPids) then
                if diagnosticCollectionTruncated then exit repeat
                set procName to name of proc
                try
                    set procPID to unix id of proc
                on error
                    set procPID to "unknown"
                end try
                set output to output & "PROCESS:" & my diagnosticValue(procName) & "|pid=" & my diagnosticValue(procPID) & "\n"
                
	                repeat with w in (every window of proc)
	                    try
	                        if my elementIsHidden(w) then error number -128
	                        if not my reserveDiagnosticWindow() then exit repeat
	                        set wName to name of w as string
                        set output to output & "WINDOW:" & my diagnosticValue(wName) & "\n"
                        
                        -- text fields (window level)
                        try
	                            repeat with elem in (every text field of w)
	                                try
	                                    if my elementIsHidden(elem) then error number -128
	                                    if not my reserveDiagnosticElement() then exit repeat
	                                    set n to name of elem as string
                                    set output to output & "ELEMENT:text_field|name=" & my diagnosticValue(n)
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
	                                    if my elementIsHidden(elem) then error number -128
	                                    if not my reserveDiagnosticElement() then exit repeat
	                                    set n to name of elem as string
                                    set output to output & "ELEMENT:button|name=" & my diagnosticValue(n)
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
	                                    if my elementIsHidden(elem) then error number -128
	                                    if not my reserveDiagnosticElement() then exit repeat
	                                    set n to name of elem as string
                                    set output to output & "ELEMENT:static_text|name=" & my diagnosticValue(n) & "\n"
                                end try
                            end repeat
                        end try
                        
                        -- pop up buttons
                        try
	                            repeat with elem in (every pop up button of w)
	                                try
	                                    if my elementIsHidden(elem) then error number -128
	                                    if not my reserveDiagnosticElement() then exit repeat
	                                    set n to name of elem as string
                                    set output to output & "ELEMENT:pop_up_button|name=" & my diagnosticValue(n)
                                    set output to output & "\n"
                                end try
                            end repeat
                        end try
                        
                        -- checkboxes
                        try
	                            repeat with elem in (every checkbox of w)
	                                try
	                                    if my elementIsHidden(elem) then error number -128
	                                    if not my reserveDiagnosticElement() then exit repeat
	                                    set n to name of elem as string
                                    set output to output & "ELEMENT:check_box|name=" & my diagnosticValue(n)
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
	                                    if my elementIsHidden(elem) then error number -128
	                                    if not my reserveDiagnosticElement() then exit repeat
	                                    set n to name of elem as string
                                    set output to output & "ELEMENT:radio_button|name=" & my diagnosticValue(n)
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
	                                    if my elementIsHidden(grp) then error number -128
	                                    if not my reserveDiagnosticElement() then exit repeat
	                                    set gName to name of grp as string
                                    set output to output & "GROUP:" & my diagnosticValue(gName) & "\n"
                                    
                                    try
	                                        repeat with elem in (every text field of grp)
	                                            try
	                                                if my elementIsHidden(elem) then error number -128
	                                                if not my reserveDiagnosticElement() then exit repeat
	                                                set n to name of elem as string
                                                set output to output & "ELEMENT:text_field|name=" & my diagnosticValue(n)
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
	                                                if my elementIsHidden(elem) then error number -128
	                                                if not my reserveDiagnosticElement() then exit repeat
	                                                set n to name of elem as string
                                                set output to output & "ELEMENT:button|name=" & my diagnosticValue(n)
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
	                                                if my elementIsHidden(elem) then error number -128
	                                                if not my reserveDiagnosticElement() then exit repeat
	                                                set n to name of elem as string
                                                set output to output & "ELEMENT:static_text|name=" & my diagnosticValue(n) & "\n"
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
	                                    if my elementIsHidden(sh) then error number -128
	                                    if not my reserveDiagnosticElement() then exit repeat
	                                    set sName to name of sh as string
                                    set output to output & "SHEET:" & my diagnosticValue(sName) & "\n"
                                    
                                    try
	                                        repeat with elem in (every text field of sh)
	                                            try
	                                                if my elementIsHidden(elem) then error number -128
	                                                if not my reserveDiagnosticElement() then exit repeat
	                                                set n to name of elem as string
                                                set output to output & "ELEMENT:text_field|name=" & my diagnosticValue(n)
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
	                                                if my elementIsHidden(elem) then error number -128
	                                                if not my reserveDiagnosticElement() then exit repeat
	                                                set n to name of elem as string
                                                set output to output & "ELEMENT:button|name=" & my diagnosticValue(n)
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
	                                                if my elementIsHidden(elem) then error number -128
	                                                if not my reserveDiagnosticElement() then exit repeat
	                                                set n to name of elem as string
                                                set output to output & "ELEMENT:static_text|name=" & my diagnosticValue(n) & "\n"
                                            end try
                                        end repeat
                                    end try
                                end try
                            end repeat
                        end try
                        
	                    on error errMsg number errNum
	                        if errNum is not -128 then set output to output & "WINDOW_ERROR:" & my diagnosticValue(errMsg) & "\n"
                    end try
                end repeat
                end if
            on error errMsg
                set output to output & "PROCESS_ERROR:" & my diagnosticValue(targetName) & "|" & my diagnosticValue(errMsg) & "\n"
            end try
        end repeat
    end if
    
    -- ========== System dialogs ==========
    set systemProcs to {{"SecurityAgent", "loginwindow"}}
    repeat with sysName in systemProcs
        if diagnosticCollectionTruncated then exit repeat
        try
            set procList to every application process whose name is sysName
            repeat with proc in procList
                if diagnosticCollectionTruncated then exit repeat
                set procName to name of proc
                set output to output & "SYSTEM_PROCESS:" & my diagnosticValue(procName) & "\n"
	                repeat with w in (every window of proc)
	                    try
	                        if my elementIsHidden(w) then error number -128
	                        if not my reserveDiagnosticWindow() then exit repeat
	                        set wName to name of w as string
                        set output to output & "WINDOW:" & my diagnosticValue(wName) & "\n"
	                        repeat with elem in (every UI element of w)
	                            try
	                                if my elementIsHidden(elem) then error number -128
	                                if not my reserveDiagnosticElement() then exit repeat
	                                set n to name of elem as string
                                set r to role description of elem as string
                                set output to output & "ELEMENT:" & my diagnosticValue(r) & "|name=" & my diagnosticValue(n)
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

	    if diagnosticCollectionTruncated then
	        set output to output & "TRUNCATED:collection\n"
	    end if
	    if secureTraversalTruncated then
	        set output to output & "TRUNCATED:secure-traversal\n"
	    end if
	    return output
	end tell
	"#,
        MAX_SECURE_FIELD_TRAVERSAL_DEPTH,
        MAX_SECURE_FIELD_TRAVERSAL_ELEMENTS,
        MAX_SECURE_FIELDS,
        MAX_DIAGNOSTIC_COLLECTION_WINDOWS,
        MAX_DIAGNOSTIC_COLLECTION_ELEMENTS,
        MAX_DIAGNOSTIC_PROTOCOL_VALUE_CHARS,
        app_name,
        trusted_target_pids
    )
}

#[cfg(target_os = "macos")]
fn applescript_pid_list_literal(pids: &[i32]) -> String {
    let values = pids
        .iter()
        .map(|pid| format!("\"{}\"", pid))
        .collect::<Vec<_>>()
        .join(", ");
    format!("{{{values}}}")
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
struct BoundedProcessOutput {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_truncated: bool,
    stderr_truncated: bool,
}

#[cfg(target_os = "macos")]
struct BoundedPipeCapture {
    bytes: Vec<u8>,
    truncated: bool,
}

#[cfg(target_os = "macos")]
fn run_osascript(script: &str) -> std::io::Result<BoundedProcessOutput> {
    use std::io::{Error, ErrorKind};
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

    let mut child = Command::new("/usr/bin/osascript")
        .args(["-e", script])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Error::new(ErrorKind::Other, "missing osascript stdout pipe"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| Error::new(ErrorKind::Other, "missing osascript stderr pipe"))?;
    let stdout_reader =
        thread::spawn(move || read_pipe_capped(stdout, MAX_DIAGNOSTIC_RAW_OUTPUT_BYTES));
    let stderr_reader =
        thread::spawn(move || read_pipe_capped(stderr, MAX_DIAGNOSTIC_RAW_OUTPUT_BYTES));

    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }

        if started.elapsed() >= DIAGNOSE_OSASCRIPT_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            let _ = join_pipe_reader(stdout_reader);
            let _ = join_pipe_reader(stderr_reader);
            return Err(Error::new(ErrorKind::TimedOut, "osascript timed out"));
        }

        thread::sleep(Duration::from_millis(25));
    };

    let stdout = join_pipe_reader(stdout_reader)?;
    let stderr = join_pipe_reader(stderr_reader)?;

    Ok(BoundedProcessOutput {
        status,
        stdout: stdout.bytes,
        stderr: stderr.bytes,
        stdout_truncated: stdout.truncated,
        stderr_truncated: stderr.truncated,
    })
}

#[cfg(target_os = "macos")]
fn read_pipe_capped<R: std::io::Read>(
    mut reader: R,
    byte_limit: usize,
) -> std::io::Result<BoundedPipeCapture> {
    let mut bytes = Vec::with_capacity(byte_limit.min(8192));
    let mut buffer = [0_u8; 8192];
    let mut truncated = false;

    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }

        let remaining = byte_limit.saturating_sub(bytes.len());
        if remaining == 0 {
            truncated = true;
            continue;
        }

        let keep = remaining.min(read);
        bytes.extend_from_slice(&buffer[..keep]);
        if keep < read {
            truncated = true;
        }
    }

    Ok(BoundedPipeCapture { bytes, truncated })
}

#[cfg(target_os = "macos")]
fn join_pipe_reader(
    reader: std::thread::JoinHandle<std::io::Result<BoundedPipeCapture>>,
) -> std::io::Result<BoundedPipeCapture> {
    reader
        .join()
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "pipe reader panicked"))?
}

#[cfg(target_os = "macos")]
fn parse_output_with_truncation(
    text: &str,
    app_name: &str,
    trusted_target_pids: Option<&[i32]>,
) -> (Vec<ProcessInfo>, Vec<ProcessInfo>, Vec<String>) {
    let mut target_processes: Vec<ProcessInfo> = Vec::new();
    let mut system_dialogs: Vec<ProcessInfo> = Vec::new();
    let mut truncation_reasons = Vec::new();
    let expected_app_name = sanitized_report_scalar(app_name);

    let mut current_proc: Option<ProcessInfo> = None;
    let mut current_window: Option<WindowInfo> = None;
    let mut in_system = false;
    let mut accepted_processes = 0_usize;
    let mut accepted_windows = 0_usize;
    let mut accepted_elements = 0_usize;

    for (line_index, line) in text.lines().enumerate() {
        if line_index >= MAX_DIAGNOSTIC_PARSE_LINES {
            add_truncation_reason(&mut truncation_reasons, DIAGNOSTIC_PARSE_TRUNCATED_TEXT);
            break;
        }

        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if let Some(reason) = line.strip_prefix("TRUNCATED:") {
            match reason.trim() {
                "collection" => add_truncation_reason(
                    &mut truncation_reasons,
                    DIAGNOSTIC_COLLECTION_TRUNCATED_TEXT,
                ),
                "raw-output" => add_truncation_reason(
                    &mut truncation_reasons,
                    DIAGNOSTIC_RAW_OUTPUT_TRUNCATED_TEXT,
                ),
                "secure-traversal" => add_truncation_reason(
                    &mut truncation_reasons,
                    DIAGNOSTIC_SECURE_TRAVERSAL_TRUNCATED_TEXT,
                ),
                _ => {
                    add_truncation_reason(&mut truncation_reasons, DIAGNOSTIC_PARSE_TRUNCATED_TEXT)
                }
            }
            continue;
        }

        if let Some(rest) = line.strip_prefix("PROCESS:") {
            finish_current_window(&mut current_proc, &mut current_window);
            finish_current_process(
                &mut target_processes,
                &mut system_dialogs,
                &mut current_proc,
                in_system,
            );
            in_system = false;

            let mut parts = rest.splitn(2, "|pid=");
            let name = decode_protocol_value(parts.next().unwrap_or("").trim());
            if name != expected_app_name {
                in_system = false;
                current_proc = None;
                current_window = None;
                continue;
            }
            if accepted_processes >= MAX_DIAGNOSTIC_COLLECTION_PROCESSES {
                add_truncation_reason(
                    &mut truncation_reasons,
                    DIAGNOSTIC_COLLECTION_TRUNCATED_TEXT,
                );
                current_proc = None;
                current_window = None;
                continue;
            }
            let pid = parts
                .next()
                .map(decode_protocol_value)
                .and_then(|s| s.parse::<i32>().ok());
            if let Some(trusted_pids) = trusted_target_pids {
                if !pid.is_some_and(|pid| trusted_pids.contains(&pid)) {
                    current_proc = None;
                    current_window = None;
                    continue;
                }
            }
            accepted_processes += 1;
            current_proc = Some(ProcessInfo {
                name,
                pid,
                windows: Vec::new(),
            });
            continue;
        }

        if let Some(rest) = line.strip_prefix("SYSTEM_PROCESS:") {
            finish_current_window(&mut current_proc, &mut current_window);
            finish_current_process(
                &mut target_processes,
                &mut system_dialogs,
                &mut current_proc,
                in_system,
            );
            in_system = true;
            let name = decode_protocol_value(rest.trim());
            if !matches!(name.as_str(), "SecurityAgent" | "loginwindow") {
                current_proc = None;
                current_window = None;
                continue;
            }
            if accepted_processes >= MAX_DIAGNOSTIC_COLLECTION_PROCESSES {
                add_truncation_reason(
                    &mut truncation_reasons,
                    DIAGNOSTIC_COLLECTION_TRUNCATED_TEXT,
                );
                current_proc = None;
                current_window = None;
                continue;
            }
            accepted_processes += 1;
            current_proc = Some(ProcessInfo {
                name,
                pid: None,
                windows: Vec::new(),
            });
            continue;
        }

        if let Some(rest) = line.strip_prefix("WINDOW:") {
            finish_current_window(&mut current_proc, &mut current_window);
            if current_proc.is_none() {
                continue;
            }
            if accepted_windows >= MAX_DIAGNOSTIC_COLLECTION_WINDOWS {
                add_truncation_reason(
                    &mut truncation_reasons,
                    DIAGNOSTIC_COLLECTION_TRUNCATED_TEXT,
                );
                continue;
            }
            accepted_windows += 1;
            current_window = Some(WindowInfo {
                title: decode_protocol_value(rest),
                elements: Vec::new(),
            });
            continue;
        }

        if let Some(rest) = line.strip_prefix("ELEMENT:") {
            if current_proc.is_none() || current_window.is_none() {
                continue;
            }
            if accepted_elements >= MAX_DIAGNOSTIC_COLLECTION_ELEMENTS {
                add_truncation_reason(
                    &mut truncation_reasons,
                    DIAGNOSTIC_COLLECTION_TRUNCATED_TEXT,
                );
                continue;
            }

            let mut elem = UiElement {
                element_type: String::new(),
                name: String::new(),
                value: None,
                enabled: None,
            };
            let mut seen_type = false;
            for part in rest.split('|').take(8) {
                if let Some((key, val)) = part.split_once('=') {
                    match key {
                        "name" => elem.name = decode_protocol_value(val),
                        "value" => elem.value = Some(decode_protocol_value(val)),
                        "enabled" => elem.enabled = Some(decode_protocol_value(val) == "true"),
                        _ => {}
                    }
                } else if !seen_type {
                    elem.element_type = decode_protocol_value(part);
                    seen_type = true;
                }
            }
            if let Some(ref mut w) = current_window {
                w.elements.push(elem);
                accepted_elements += 1;
            }
            continue;
        }

        if line.starts_with("GROUP:") || line.starts_with("SHEET:") {
            continue;
        }
    }

    finish_current_window(&mut current_proc, &mut current_window);
    finish_current_process(
        &mut target_processes,
        &mut system_dialogs,
        &mut current_proc,
        in_system,
    );

    redact_report_parts(&mut target_processes, &mut system_dialogs);
    (target_processes, system_dialogs, truncation_reasons)
}

#[cfg(target_os = "macos")]
fn finish_current_window(
    current_proc: &mut Option<ProcessInfo>,
    current_window: &mut Option<WindowInfo>,
) {
    if let Some(w) = current_window.take() {
        if let Some(p) = current_proc.as_mut() {
            p.windows.push(w);
        }
    }
}

#[cfg(target_os = "macos")]
fn finish_current_process(
    target_processes: &mut Vec<ProcessInfo>,
    system_dialogs: &mut Vec<ProcessInfo>,
    current_proc: &mut Option<ProcessInfo>,
    in_system: bool,
) {
    if let Some(p) = current_proc.take() {
        if in_system {
            system_dialogs.push(p);
        } else {
            target_processes.push(p);
        }
    }
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn add_truncation_reason(reasons: &mut Vec<String>, reason: &str) {
    if !reasons.iter().any(|existing| existing == reason) {
        reasons.push(reason.to_string());
    }
}

#[cfg(target_os = "macos")]
fn redact_report_parts(target_processes: &mut [ProcessInfo], system_dialogs: &mut [ProcessInfo]) {
    for proc in target_processes {
        for window in &mut proc.windows {
            window.title = redact_title(&window.title);
            for elem in &mut window.elements {
                elem.element_type = redact_element_type(&elem.element_type);
                elem.name = redact_element_name(&elem.element_type, &elem.name, false);
                elem.value = elem.value.as_deref().map(redact_value);
            }
        }
    }

    for proc in system_dialogs {
        for window in &mut proc.windows {
            window.title = redact_title(&window.title);
            for elem in &mut window.elements {
                elem.element_type = redact_element_type(&elem.element_type);
                elem.name = redact_element_name(&elem.element_type, &elem.name, true);
                elem.value = elem.value.as_deref().map(redact_value);
            }
        }
    }
}

#[cfg(target_os = "macos")]
fn decode_protocol_value(value: &str) -> String {
    sanitized_report_scalar(&percent_decode_protocol_value(capped_protocol_value(value)))
}

#[cfg(target_os = "macos")]
fn capped_protocol_value(value: &str) -> &str {
    let byte_limit = MAX_DIAGNOSTIC_PROTOCOL_VALUE_CHARS.saturating_mul(4);
    if value.len() <= byte_limit {
        return value;
    }

    let mut boundary = byte_limit;
    while boundary > 0 && !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    &value[..boundary]
}

#[cfg(target_os = "macos")]
fn percent_decode_protocol_value(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '%' {
            output.push(ch);
            continue;
        }
        let Some(high) = chars.next() else {
            output.push('%');
            break;
        };
        let Some(low) = chars.next() else {
            output.push('%');
            output.push(high);
            break;
        };
        match (high.to_digit(16), low.to_digit(16)) {
            (Some(high), Some(low)) => {
                let byte = ((high << 4) | low) as u8;
                output.push(byte as char);
            }
            _ => {
                output.push('%');
                output.push(high);
                output.push(low);
            }
        }
    }
    output
}

#[cfg(target_os = "macos")]
fn redact_title(value: &str) -> String {
    if value.trim().is_empty() {
        return String::new();
    }
    "[redacted title]".to_string()
}

#[cfg(target_os = "macos")]
fn redact_element_type(value: &str) -> String {
    let value = sanitized_report_scalar(value);
    if value.trim().is_empty() {
        return String::new();
    }
    match value.as_str() {
        "text_field" | "secure_text_field" | "button" | "static_text" | "pop_up_button"
        | "check_box" | "radio_button" => value,
        _ => "[redacted type]".to_string(),
    }
}

#[cfg(target_os = "macos")]
fn redact_element_name(element_type: &str, value: &str, system_dialog: bool) -> String {
    let _ = element_type;
    let _ = system_dialog;
    if value.trim().is_empty() {
        return String::new();
    }

    "[redacted]".to_string()
}

#[cfg(target_os = "macos")]
fn sanitized_report_scalar(value: &str) -> String {
    let mut output = String::new();
    let mut pending_space = false;

    for ch in value.chars().take(MAX_DIAGNOSTIC_PROTOCOL_VALUE_CHARS) {
        if ch.is_control() || ch == '|' || ch.is_whitespace() {
            pending_space = !output.is_empty();
            continue;
        }

        if pending_space {
            output.push(' ');
            pending_space = false;
        }
        output.push(ch);
    }

    output
}

#[cfg(target_os = "macos")]
fn redact_value(value: &str) -> String {
    if value.trim().is_empty() {
        String::new()
    } else {
        "[redacted]".to_string()
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    fn parse_output_for_test(text: &str, app_name: &str) -> (Vec<ProcessInfo>, Vec<ProcessInfo>) {
        let (target_processes, system_dialogs, _) =
            parse_output_with_truncation(text, app_name, None);
        (target_processes, system_dialogs)
    }

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

        let (target_processes, system_dialogs) = parse_output_for_test(text, "Windows App");

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
        assert_eq!(target_window.elements[2].name, "[redacted]");

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

        let (target_processes, _) = parse_output_for_test(text, "Windows App");
        let rendered = serde_json::to_string(&target_processes).unwrap();

        assert!(!rendered.contains("super-secret"));
        assert!(!rendered.contains("123456"));
        assert!(rendered.contains("[redacted]"));
        assert!(!rendered.contains("Continue"));
    }

    #[test]
    fn parse_output_ignores_injected_process_headers() {
        let text = "\
PROCESS:Windows App|pid=123
WINDOW:Sign in
ELEMENT:button|name=x
PROCESS:Sensitive Tenant|pid=999
WINDOW:secret-window
ELEMENT:button|name=secret-button
SYSTEM_PROCESS:Injected Secret
WINDOW:secret-system-window
ELEMENT:static text|name=secret-token
";

        let (target_processes, system_dialogs) = parse_output_for_test(text, "Windows App");
        let rendered = serde_json::to_string(&(target_processes, system_dialogs)).unwrap();

        assert!(!rendered.contains("Sensitive Tenant"));
        assert!(!rendered.contains("secret-window"));
        assert!(!rendered.contains("secret-button"));
        assert!(!rendered.contains("Injected Secret"));
        assert!(!rendered.contains("secret-token"));
    }

    #[test]
    fn parse_output_redacts_injected_element_type() {
        let text = "\
PROCESS:Windows App|pid=123
WINDOW:Sign in
ELEMENT:button|name=Continue
ELEMENT:api-token-12345|name=x
";

        let (target_processes, system_dialogs) = parse_output_for_test(text, "Windows App");
        let rendered =
            serde_json::to_string(&(target_processes.clone(), system_dialogs.clone())).unwrap();
        let plaintext = DiagnosticReport {
            timestamp: "now".to_string(),
            target_processes,
            system_dialogs,
            truncation_reasons: vec![],
        }
        .to_plaintext();

        assert!(!rendered.contains("api-token-12345"));
        assert!(!plaintext.contains("api-token-12345"));
        assert!(rendered.contains("[redacted type]"));
    }

    #[test]
    fn parse_output_decodes_protocol_values_before_redaction() {
        let text = "\
PROCESS:Windows App|pid=123
WINDOW:Sign%7CIn%0AUser
ELEMENT:text_field|name=user%3Dname%7Csecret@example.com|value=plain%25secret
";

        let (target_processes, _) = parse_output_for_test(text, "Windows App");
        let rendered = serde_json::to_string(&target_processes).unwrap();

        assert!(!rendered.contains("user=name"));
        assert!(!rendered.contains("plain%secret"));
        assert!(rendered.contains("[redacted title]"));
        assert!(rendered.contains("[redacted]"));
    }

    #[test]
    fn build_applescript_encodes_protocol_values_before_emitting_records() {
        let script = build_applescript("Windows App", &[123]);

        assert!(script.contains("on diagnosticValue(rawValue)"));
        assert!(script.contains(r#"my replaceDiagnosticText(textValue, "|", "%7C")"#));
        assert!(script.contains(r#"my replaceDiagnosticText(textValue, linefeed, "%0A")"#));
        assert!(!script.contains(r#""ELEMENT:text_field|name=" & n"#));
        assert!(!script.contains(r#""ELEMENT:" & r & "|name=" & n"#));
        assert!(script.contains(r#""ELEMENT:text_field|name=" & my diagnosticValue(n)"#));
        assert!(script
            .contains(r#""ELEMENT:" & my diagnosticValue(r) & "|name=" & my diagnosticValue(n)"#));
    }

    #[test]
    fn parse_output_strips_control_chars_from_report_output() {
        let app_name = "Windows App\u{1b}[31m";
        let text = format!(
            "PROCESS:{app_name}|pid=123\nWINDOW:Sign in\u{7}\nELEMENT:button\u{0}|name=Continue|enabled=true\n"
        );

        let (target_processes, system_dialogs) = parse_output_for_test(&text, app_name);
        let report = DiagnosticReport {
            timestamp: "now".to_string(),
            target_processes,
            system_dialogs,
            truncation_reasons: vec![],
        };

        let rendered = serde_json::to_string(&report).unwrap();
        let plaintext = report.to_plaintext();

        for output in [&rendered, &plaintext] {
            assert!(
                output.chars().all(|c| !c.is_control() || c == '\n'),
                "diagnostic output should not contain raw control characters"
            );
        }
        assert!(!rendered.contains("\\u001b"));
        assert!(!rendered.contains("\\u0007"));
        assert!(!rendered.contains("\\u0000"));
    }

    #[test]
    fn parse_output_reports_protocol_truncation_markers() {
        let text = "\
PROCESS:Windows App|pid=123
WINDOW:Sign in
ELEMENT:button|name=Continue
TRUNCATED:collection
TRUNCATED:secure-traversal
TRUNCATED:raw-output
";

        let (_, _, truncation_reasons) = parse_output_with_truncation(text, "Windows App", None);

        assert!(truncation_reasons
            .iter()
            .any(|reason| reason == DIAGNOSTIC_COLLECTION_TRUNCATED_TEXT));
        assert!(truncation_reasons
            .iter()
            .any(|reason| reason == DIAGNOSTIC_SECURE_TRAVERSAL_TRUNCATED_TEXT));
        assert!(truncation_reasons
            .iter()
            .any(|reason| reason == DIAGNOSTIC_RAW_OUTPUT_TRUNCATED_TEXT));
    }

    #[test]
    fn parse_output_caps_valid_element_count() {
        let mut text = "PROCESS:Windows App|pid=123\nWINDOW:Sign in\n".to_string();
        for index in 0..(MAX_DIAGNOSTIC_COLLECTION_ELEMENTS + 16) {
            text.push_str(&format!("ELEMENT:button|name={index}|enabled=true\n"));
        }

        let (target_processes, _, truncation_reasons) =
            parse_output_with_truncation(&text, "Windows App", None);

        assert_eq!(
            target_processes[0].windows[0].elements.len(),
            MAX_DIAGNOSTIC_COLLECTION_ELEMENTS
        );
        assert!(truncation_reasons
            .iter()
            .any(|reason| reason == DIAGNOSTIC_COLLECTION_TRUNCATED_TEXT));
    }

    #[test]
    fn parse_output_stops_after_max_diagnostic_parse_lines() {
        let mut text = String::new();
        for _ in 0..MAX_DIAGNOSTIC_PARSE_LINES {
            text.push_str("IGNORED\n");
        }
        text.push_str("PROCESS:Windows App|pid=123\nWINDOW:after-cap\n");

        let (target_processes, system_dialogs, truncation_reasons) =
            parse_output_with_truncation(&text, "Windows App", None);

        assert!(target_processes.is_empty());
        assert!(system_dialogs.is_empty());
        assert!(truncation_reasons
            .iter()
            .any(|reason| reason == DIAGNOSTIC_PARSE_TRUNCATED_TEXT));
    }

    #[test]
    fn parse_output_ignores_orphan_windows_and_elements() {
        let text = "\
WINDOW:secret-window
ELEMENT:button|name=secret-button
PROCESS:Windows App|pid=123
WINDOW:Sign in
ELEMENT:button|name=Continue
";

        let (target_processes, system_dialogs) = parse_output_for_test(text, "Windows App");
        let rendered = serde_json::to_string(&(target_processes, system_dialogs)).unwrap();

        assert!(!rendered.contains("secret-window"));
        assert!(!rendered.contains("secret-button"));
        assert!(rendered.contains("[redacted title]"));
    }

    #[test]
    fn parse_output_rejects_target_process_pid_not_in_trusted_set() {
        let text = "\
PROCESS:Windows App|pid=666
WINDOW:spoofed
ELEMENT:button|name=secret
PROCESS:Windows App|pid=123
WINDOW:Sign in
ELEMENT:button|name=Continue
";

        let (target_processes, system_dialogs, _) =
            parse_output_with_truncation(text, "Windows App", Some(&[123]));
        let rendered = serde_json::to_string(&(target_processes.clone(), system_dialogs)).unwrap();

        assert_eq!(target_processes.len(), 1);
        assert_eq!(target_processes[0].pid, Some(123));
        assert!(!rendered.contains("spoofed"));
        assert!(!rendered.contains("secret"));
    }

    #[test]
    fn build_applescript_uses_trusted_pid_membership_for_target_processes() {
        let script = build_applescript("Windows App", &[111, 222]);

        assert!(script.contains("on processMatches(procRef, expectedName, trustedPIDs)"));
        assert!(script.contains("set targetPids to {\"111\", \"222\"}"));
        assert!(!script.contains("set targetNames"));
        assert!(!script.contains("every application process whose name is targetName"));
    }
}

#[cfg(test)]
mod output_cap_tests {
    use super::{
        cap_diagnostic_output, diagnostic_report_to_capped_pretty_json, diagnostic_stdout_len,
        DiagnosticReport, ProcessInfo, UiElement, WindowInfo, DIAGNOSTIC_OUTPUT_TRUNCATED_MARKER,
        MAX_DIAGNOSTIC_OUTPUT_BYTES,
    };

    #[test]
    fn diagnostic_output_is_capped() {
        let output = "x".repeat(MAX_DIAGNOSTIC_OUTPUT_BYTES + 1024);
        let capped = cap_diagnostic_output(output);

        assert!(capped.len() <= MAX_DIAGNOSTIC_OUTPUT_BYTES);
        assert!(capped.ends_with(DIAGNOSTIC_OUTPUT_TRUNCATED_MARKER));
    }

    #[test]
    fn diagnostic_output_cap_uses_utf8_boundary() {
        let prefix_len = MAX_DIAGNOSTIC_OUTPUT_BYTES - DIAGNOSTIC_OUTPUT_TRUNCATED_MARKER.len() - 1;
        let output = format!("{}étail{}", "x".repeat(prefix_len), "y".repeat(1024));
        let capped = cap_diagnostic_output(output);

        assert!(capped.len() <= MAX_DIAGNOSTIC_OUTPUT_BYTES);
        assert!(capped.ends_with(DIAGNOSTIC_OUTPUT_TRUNCATED_MARKER));
        assert!(!capped.contains("tail"));
    }

    #[test]
    fn oversized_diagnostic_json_stays_valid_and_capped() {
        let report = oversized_report();
        let uncapped = serde_json::to_string_pretty(&report).unwrap();
        assert!(uncapped.len() > MAX_DIAGNOSTIC_OUTPUT_BYTES);

        let capped = diagnostic_report_to_capped_pretty_json(&report).unwrap();
        assert!(diagnostic_stdout_len(&capped) <= MAX_DIAGNOSTIC_OUTPUT_BYTES);
        let parsed: serde_json::Value = serde_json::from_str(&capped).unwrap();
        assert_eq!(
            parsed.get("truncated").and_then(|value| value.as_str()),
            Some("diagnostic output truncated")
        );
    }

    fn oversized_report() -> DiagnosticReport {
        let elements = (0..2048)
            .map(|index| UiElement {
                element_type: "static_text".to_string(),
                name: format!("redacted element {index} {}", "x".repeat(64)),
                value: None,
                enabled: Some(true),
            })
            .collect();

        DiagnosticReport {
            timestamp: "now".to_string(),
            target_processes: vec![ProcessInfo {
                name: "Windows App".to_string(),
                pid: Some(42),
                windows: vec![WindowInfo {
                    title: "[redacted title]".to_string(),
                    elements,
                }],
            }],
            system_dialogs: vec![],
            truncation_reasons: vec![],
        }
    }
}
