#[cfg(target_os = "macos")]
use crate::macos_identity;
use crate::models::{Account, AppSettings};
use crate::storage;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime};
use zeroize::Zeroizing;

#[cfg(target_os = "macos")]
struct PromptInfo {
    process_id: i32,
    window_title: String,
    email: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FillMethod {
    Keyboard,
    DirectAxSetValue,
}

impl FillMethod {
    pub(crate) fn parse(args: &[String]) -> anyhow::Result<Self> {
        let method = args
            .iter()
            .find_map(|arg| arg.strip_prefix("--fill-method="))
            .unwrap_or("keyboard");

        match method {
            "keyboard" => Ok(Self::Keyboard),
            "direct" | "direct_ax_set_value" => Ok(Self::DirectAxSetValue),
            other => anyhow::bail!(
                "unsupported fill method '{other}'; use --fill-method=keyboard or --fill-method=direct"
            ),
        }
    }

    fn as_applescript(self) -> &'static str {
        match self {
            Self::Keyboard => "keyboard",
            Self::DirectAxSetValue => "direct_ax_set_value",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct FillAttemptReport {
    pub(crate) fields: Vec<(String, String)>,
    pub(crate) success: bool,
    pub(crate) failure_reason: Option<String>,
}

impl FillAttemptReport {
    pub(crate) fn field(&self, key: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(field, _)| field == key)
            .map(|(_, value)| value.as_str())
    }

    pub(crate) fn print(&self) {
        println!("debug_fill_once_log_start");
        for (key, value) in &self.fields {
            println!("{key}={}", sanitize_log_value(value));
        }
        println!("debug_fill_once_log_end");
    }

    pub(crate) fn summary_line(&self) -> String {
        let result = if self.success { "success" } else { "failed" };
        let failure = self.failure_reason.as_deref().unwrap_or("");
        format!(
            "fill_current_prompt_once result={} prompt_detected={} account_match_count={} selected_account_id={} password_load_ms={} fill_method={} submit_method={} axpress_result={} enter_fallback_result={} post_check_state={} failure_reason={}",
            result,
            self.field("prompt_detected").unwrap_or("false"),
            self.field("account_match_count").unwrap_or("0"),
            self.field("selected_account_id").unwrap_or(""),
            self.field("password_load_ms").unwrap_or("0"),
            self.field("fill_method").unwrap_or("none"),
            self.field("submit_method").unwrap_or("none"),
            self.field("axpress_result").unwrap_or("not_found"),
            self.field("enter_fallback_result").unwrap_or("not_needed"),
            self.field("post_check_state").unwrap_or("unknown"),
            failure,
        )
    }
}

struct DebugLog {
    fields: Vec<(&'static str, String)>,
    started: Instant,
}

impl DebugLog {
    fn new(attempt_id: String) -> Self {
        let mut log = Self {
            fields: Vec::new(),
            started: Instant::now(),
        };
        for (key, value) in [
            ("attempt_id", attempt_id),
            ("ax_trusted_for_current_process", "false".to_string()),
            ("current_process_path", String::new()),
            ("executable_path", String::new()),
            ("app_bundle_path", String::new()),
            ("current_bundle_id", String::new()),
            ("current_signing_identity", String::new()),
            ("current_signing_identifier", String::new()),
            ("current_team_id", String::new()),
            ("current_launch_kind", String::new()),
            ("is_running_from_target_debug", "false".to_string()),
            ("is_running_from_dist_app", "false".to_string()),
            ("windows_app_pid", String::new()),
            ("windows_app_path", String::new()),
            ("windows_app_bundle_id", String::new()),
            ("windows_app_team_id", String::new()),
            ("windows_app_frontmost", "false".to_string()),
            ("prompt_detected", "false".to_string()),
            ("detected_email_redacted", String::new()),
            ("account_match_count", "0".to_string()),
            ("selected_account_id", String::new()),
            ("password_load_attempted", "false".to_string()),
            ("password_load_ms", "0".to_string()),
            ("storage_lookup_start_ms", "0".to_string()),
            ("account_id_lookup_ms", "0".to_string()),
            ("keychain_service_name", String::new()),
            ("keychain_account_key", String::new()),
            ("keychain_process_path", String::new()),
            ("keychain_process_bundle_id", String::new()),
            ("keychain_process_signing_identifier", String::new()),
            ("keychain_process_team_id", String::new()),
            ("keychain_query_start", "0".to_string()),
            ("keychain_query_ms", "0".to_string()),
            ("keychain_prompt_suspected", "false".to_string()),
            ("fallback_lookup_ms", "0".to_string()),
            ("zeroizing_wrap_ms", "0".to_string()),
            ("total_password_load_ms", "0".to_string()),
            ("keychain_error_redacted", String::new()),
            ("password_field_detected", "false".to_string()),
            ("password_field_role", String::new()),
            ("password_field_description_redacted", String::new()),
            ("password_field_focused", "unknown".to_string()),
            ("fill_method", "none".to_string()),
            ("fill_attempted", "false".to_string()),
            ("fill_duration_ms", "0".to_string()),
            ("submit_method", "none".to_string()),
            ("submit_attempted", "false".to_string()),
            ("axpress_attempted", "false".to_string()),
            ("axpress_result", "not_found".to_string()),
            ("enter_fallback_attempted", "false".to_string()),
            ("enter_fallback_result", "not_needed".to_string()),
            ("submit_duration_ms", "0".to_string()),
            ("post_check_state", "unknown".to_string()),
            ("total_local_attempt_ms", "0".to_string()),
            ("failure_reason", String::new()),
        ] {
            log.fields.push((key, value));
        }
        log
    }

    fn set(&mut self, key: &'static str, value: impl Into<String>) {
        let value = value.into();
        if let Some((_, existing)) = self.fields.iter_mut().find(|(field, _)| *field == key) {
            *existing = value;
        } else {
            self.fields.push((key, value));
        }
    }

    fn finish(mut self, failure_reason: Option<String>) -> FillAttemptReport {
        self.set(
            "total_local_attempt_ms",
            self.started.elapsed().as_millis().to_string(),
        );
        if let Some(reason) = failure_reason.as_deref() {
            self.set("failure_reason", reason.to_string());
        }

        FillAttemptReport {
            fields: self
                .fields
                .into_iter()
                .map(|(key, value)| (key.to_string(), sanitize_log_value(&value)))
                .collect(),
            success: failure_reason.is_none(),
            failure_reason,
        }
    }

    fn fail(self, reason: impl Into<String>) -> FillAttemptReport {
        self.finish(Some(reason.into()))
    }
}

fn log_value(log: &DebugLog, key: &str) -> Option<String> {
    log.fields
        .iter()
        .find(|(field, _)| *field == key)
        .map(|(_, value)| value.clone())
}

pub(crate) fn run_from_args(args: &[String]) -> anyhow::Result<()> {
    #[cfg(target_os = "macos")]
    {
        run_macos(args)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = args;
        anyhow::bail!("debug-fill-once is only supported on macOS")
    }
}

#[cfg(target_os = "macos")]
fn run_macos(args: &[String]) -> anyhow::Result<()> {
    let method = FillMethod::parse(args)?;
    let config = storage::load_config();
    let report = fill_current_prompt_once(&config.settings, &config.accounts, method);
    report.print();
    if let Some(reason) = report.failure_reason {
        anyhow::bail!(reason);
    }
    Ok(())
}

pub(crate) fn fill_current_prompt_once(
    settings: &AppSettings,
    accounts: &[Account],
    method: FillMethod,
) -> FillAttemptReport {
    fill_current_prompt_once_guarded(settings, accounts, method, || Ok(()))
}

#[cfg(feature = "diagnostics-ui")]
pub(crate) fn runtime_status_report(
    settings: &AppSettings,
    accounts: &[Account],
) -> FillAttemptReport {
    #[cfg(target_os = "macos")]
    {
        runtime_status_report_macos(settings, accounts)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = settings;
        let _ = accounts;
        DebugLog::new(format!("status-{}", make_attempt_id()))
            .fail("runtime status is only supported on macOS")
    }
}

pub(crate) fn fill_current_prompt_once_guarded(
    settings: &AppSettings,
    accounts: &[Account],
    method: FillMethod,
    guard: impl Fn() -> anyhow::Result<()>,
) -> FillAttemptReport {
    #[cfg(target_os = "macos")]
    {
        fill_current_prompt_once_macos(settings, accounts, method, &guard)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = settings;
        let _ = accounts;
        let _ = method;
        DebugLog::new(make_attempt_id()).fail("debug-fill-once is only supported on macOS")
    }
}

#[cfg(target_os = "macos")]
fn fill_current_prompt_once_macos(
    settings: &AppSettings,
    accounts: &[Account],
    method: FillMethod,
    guard: &dyn Fn() -> anyhow::Result<()>,
) -> FillAttemptReport {
    let mut log = DebugLog::new(make_attempt_id());

    apply_current_process_fields(&mut log);

    let ax_trusted = ax_is_process_trusted();
    log.set("ax_trusted_for_current_process", ax_trusted.to_string());
    if !ax_trusted {
        return log.fail("accessibility_not_trusted_for_current_process");
    }
    if let Err(e) = guard() {
        return log.fail(format!("attempt_cancelled_{e}"));
    }

    let app_name = settings.macos_app_name.clone();

    let trusted_infos = match macos_identity::trusted_process_infos(&app_name) {
        Ok(infos) => infos,
        Err(_) => return log.fail("windows_app_trust_check_failed"),
    };
    let Some(target) = trusted_infos.first() else {
        return log.fail("trusted_windows_app_not_running");
    };

    apply_windows_app_fields(&mut log, target);

    let frontmost_ok = match ensure_frontmost(&app_name, target.pid) {
        Ok(frontmost) => frontmost,
        Err(e) => return log.fail(format!("frontmost_check_failed_{e}")),
    };
    if !frontmost_ok {
        log.set("windows_app_frontmost", "false");
        return log.fail("windows_app_not_frontmost");
    }
    log.set("windows_app_frontmost", "true");

    let prompt = match detect_visible_prompt(&app_name, target.pid) {
        Ok(prompt) => prompt,
        Err(e) => return log.fail(format!("prompt_detection_script_failed_{e}")),
    };
    let Some(prompt) = prompt else {
        return log.fail("visible_credential_prompt_not_detected");
    };
    log.set("prompt_detected", "true");

    if prompt.process_id != target.pid {
        return log.fail("prompt_pid_does_not_match_trusted_target");
    }

    let Some(prompt_email) = prompt.email.filter(|email| !email.trim().is_empty()) else {
        return log.fail("visible_prompt_email_missing");
    };
    log.set("detected_email_redacted", redacted_email(&prompt_email));
    if let Err(e) = guard() {
        return log.fail(format!("attempt_cancelled_{e}"));
    }

    let account_lookup_start = Instant::now();
    let matches = matching_accounts(accounts, &prompt_email);
    log.set(
        "account_id_lookup_ms",
        account_lookup_start.elapsed().as_millis().to_string(),
    );
    log.set("account_match_count", matches.len().to_string());
    let [selected_account] = matches.as_slice() else {
        return if matches.is_empty() {
            log.fail("visible_prompt_email_matches_no_enabled_account")
        } else {
            log.fail("visible_prompt_email_matches_multiple_enabled_accounts")
        };
    };
    log.set("selected_account_id", selected_account.id.clone());

    log.set("password_load_attempted", "true");
    log.set("keychain_service_name", storage::keychain_service_name());
    log.set("keychain_account_key", selected_account.id.clone());
    log.set(
        "keychain_process_path",
        log_value(&log, "current_process_path").unwrap_or_default(),
    );
    log.set(
        "keychain_process_bundle_id",
        log_value(&log, "current_bundle_id").unwrap_or_default(),
    );
    log.set(
        "keychain_process_signing_identifier",
        log_value(&log, "current_signing_identifier").unwrap_or_default(),
    );
    log.set(
        "keychain_process_team_id",
        log_value(&log, "current_team_id").unwrap_or_default(),
    );
    let password =
        match storage::load_password_with_timing(&selected_account.id, settings.use_keyring) {
            Ok(result) => {
                log.set(
                    "storage_lookup_start_ms",
                    result.timing.storage_lookup_start_ms.to_string(),
                );
                log.set(
                    "keychain_query_start",
                    result.timing.keychain_query_start_ms.to_string(),
                );
                log.set(
                    "keychain_query_ms",
                    result.timing.keychain_query_ms.to_string(),
                );
                log.set(
                    "keychain_prompt_suspected",
                    result.timing.keychain_prompt_suspected.to_string(),
                );
                log.set(
                    "fallback_lookup_ms",
                    result.timing.fallback_lookup_ms.to_string(),
                );
                log.set(
                    "zeroizing_wrap_ms",
                    result.timing.zeroizing_wrap_ms.to_string(),
                );
                log.set(
                    "total_password_load_ms",
                    result.timing.total_password_load_ms.to_string(),
                );
                log.set(
                    "password_load_ms",
                    result.timing.total_password_load_ms.to_string(),
                );
                result.password
            }
            Err(e) => {
                log.set(
                    "storage_lookup_start_ms",
                    e.timing.storage_lookup_start_ms.to_string(),
                );
                log.set(
                    "keychain_query_start",
                    e.timing.keychain_query_start_ms.to_string(),
                );
                log.set("keychain_query_ms", e.timing.keychain_query_ms.to_string());
                log.set(
                    "keychain_prompt_suspected",
                    e.timing.keychain_prompt_suspected.to_string(),
                );
                log.set(
                    "fallback_lookup_ms",
                    e.timing.fallback_lookup_ms.to_string(),
                );
                log.set("zeroizing_wrap_ms", e.timing.zeroizing_wrap_ms.to_string());
                log.set(
                    "total_password_load_ms",
                    e.timing.total_password_load_ms.to_string(),
                );
                log.set(
                    "password_load_ms",
                    e.timing.total_password_load_ms.to_string(),
                );
                log.set("keychain_error_redacted", e.kind);
                return log.fail("password_load_failed_for_selected_account");
            }
        };
    if let Err(e) = guard() {
        return log.fail(format!("attempt_cancelled_after_password_load_{e}"));
    }

    let fill_start = Instant::now();
    let fill_output = match run_fill_script(
        &app_name,
        prompt.process_id,
        &prompt.window_title,
        &prompt_email,
        password,
        method,
    ) {
        Ok(output) => output,
        Err(e) => {
            log.set(
                "fill_duration_ms",
                fill_start.elapsed().as_millis().to_string(),
            );
            return log.fail(format!("fill_script_failed_{e}"));
        }
    };
    log.set(
        "fill_duration_ms",
        fill_start.elapsed().as_millis().to_string(),
    );
    apply_script_fields(&mut log, &fill_output);

    if field_value(&fill_output, "password_field_detected") != Some("true") {
        return log.fail("password_field_not_detected_in_verified_prompt");
    }
    if field_value(&fill_output, "fill_attempted") != Some("true") {
        return log
            .fail(field_value(&fill_output, "failure_reason").unwrap_or("fill_not_attempted"));
    }
    if field_value(&fill_output, "fill_status") != Some("ok") {
        return log.fail(field_value(&fill_output, "failure_reason").unwrap_or("fill_failed"));
    }

    log.set("submit_duration_ms", "0");

    if field_value(&fill_output, "submit_attempted") != Some("true") {
        return log
            .fail(field_value(&fill_output, "failure_reason").unwrap_or("submit_not_attempted"));
    }

    let post_state = post_check_state(settings, target.pid, Duration::from_millis(1200));
    log.set("post_check_state", post_state);
    if post_state == "authenticated" {
        return log.finish(None);
    }
    if field_value(&fill_output, "submit_status") != Some("ok") {
        return log.fail(field_value(&fill_output, "failure_reason").unwrap_or("submit_failed"));
    }
    match post_state {
        "authenticated" => log.finish(None),
        "still_prompt" => log.fail("credential_prompt_still_visible_after_submit"),
        "prompt_gone_unknown" => log.fail("post_submit_prompt_gone_unknown"),
        "failed" => log.fail("windows_app_not_running_after_submit"),
        _ => log.fail("post_submit_state_unknown"),
    }
}

#[cfg(all(target_os = "macos", feature = "diagnostics-ui"))]
fn runtime_status_report_macos(settings: &AppSettings, accounts: &[Account]) -> FillAttemptReport {
    let mut log = DebugLog::new(format!("status-{}", make_attempt_id()));

    apply_current_process_fields(&mut log);
    log.set("keychain_service_name", storage::keychain_service_name());

    let ax_trusted = ax_is_process_trusted();
    log.set("ax_trusted_for_current_process", ax_trusted.to_string());
    if !ax_trusted {
        return log.fail("accessibility_not_trusted_for_current_process");
    }

    let app_name = settings.macos_app_name.clone();
    let trusted_infos = match macos_identity::trusted_process_infos(&app_name) {
        Ok(infos) => infos,
        Err(_) => return log.fail("windows_app_trust_check_failed"),
    };
    let Some(target) = trusted_infos.first() else {
        return log.fail("trusted_windows_app_not_running");
    };
    apply_windows_app_fields(&mut log, target);

    let frontmost_ok = match ensure_frontmost(&app_name, target.pid) {
        Ok(frontmost) => frontmost,
        Err(e) => return log.fail(format!("frontmost_check_failed_{e}")),
    };
    log.set("windows_app_frontmost", frontmost_ok.to_string());
    if !frontmost_ok {
        return log.fail("windows_app_not_frontmost");
    }

    let prompt = match detect_visible_prompt(&app_name, target.pid) {
        Ok(prompt) => prompt,
        Err(e) => return log.fail(format!("prompt_detection_script_failed_{e}")),
    };
    let Some(prompt) = prompt else {
        return log.fail("visible_credential_prompt_not_detected");
    };
    log.set("prompt_detected", "true");
    if prompt.process_id != target.pid {
        return log.fail("prompt_pid_does_not_match_trusted_target");
    }

    let Some(prompt_email) = prompt.email.filter(|email| !email.trim().is_empty()) else {
        return log.fail("visible_prompt_email_missing");
    };
    log.set("detected_email_redacted", redacted_email(&prompt_email));

    let account_lookup_start = Instant::now();
    let matches = matching_accounts(accounts, &prompt_email);
    log.set(
        "account_id_lookup_ms",
        account_lookup_start.elapsed().as_millis().to_string(),
    );
    log.set("account_match_count", matches.len().to_string());
    let [selected_account] = matches.as_slice() else {
        return if matches.is_empty() {
            log.fail("visible_prompt_email_matches_no_enabled_account")
        } else {
            log.fail("visible_prompt_email_matches_multiple_enabled_accounts")
        };
    };

    log.set("selected_account_id", selected_account.id.clone());
    log.set("keychain_account_key", selected_account.id.clone());
    log.set(
        "keychain_process_path",
        log_value(&log, "current_process_path").unwrap_or_default(),
    );
    log.set(
        "keychain_process_bundle_id",
        log_value(&log, "current_bundle_id").unwrap_or_default(),
    );
    log.set(
        "keychain_process_signing_identifier",
        log_value(&log, "current_signing_identifier").unwrap_or_default(),
    );
    log.set(
        "keychain_process_team_id",
        log_value(&log, "current_team_id").unwrap_or_default(),
    );

    log.finish(None)
}

#[cfg(target_os = "macos")]
fn matching_accounts<'a>(accounts: &'a [Account], prompt_email: &str) -> Vec<&'a Account> {
    accounts
        .iter()
        .filter(|account| account.enabled && !account.username.trim().is_empty())
        .filter(|account| {
            account
                .username
                .trim()
                .eq_ignore_ascii_case(prompt_email.trim())
        })
        .take(2)
        .collect()
}

#[cfg(target_os = "macos")]
fn detect_visible_prompt(app_name: &str, prompt_pid: i32) -> anyhow::Result<Option<PromptInfo>> {
    let script = format!(
        r#"{handlers}
tell application "System Events"
    set expectedName to {app_name}
    set expectedProcessNumber to "{prompt_pid}"
    if not my targetIsFrontmost(expectedName, expectedProcessNumber) then return my kv("prompt_detected", "false")
    repeat with procRef in every application process whose name is expectedName
        if my processMatches(procRef, expectedName, expectedProcessNumber) then
            set procNumberText to (unix id of procRef) as string
            try
                set w to front window of procRef
                set wName to name of w as string
                repeat with s in every sheet of w
                    set resultText to my detectPromptContainer(s, procNumberText, wName)
                    if resultText is not "" then return resultText
                end repeat
                if my isProbableSessionTitle(wName) then
                    set resultText to my detectPromptContainer(w, procNumberText, wName)
                    if resultText is not "" then return resultText
                end if
            end try
        end if
    end repeat
    return my kv("prompt_detected", "false")
end tell"#,
        handlers = applescript_handlers(),
        app_name = applescript_string_literal(app_name),
        prompt_pid = prompt_pid,
    );
    let output = run_osascript_stdin(&script, Duration::from_secs(3))?;
    let fields = parse_script_output(&output)?;
    if field_value(&fields, "prompt_detected") != Some("true") {
        return Ok(None);
    }
    let process_id = fields
        .get("prompt_pid")
        .and_then(|pid| pid.parse::<i32>().ok())
        .unwrap_or(prompt_pid);
    let window_title = fields.get("prompt_title").cloned().unwrap_or_default();
    let email = fields
        .get("prompt_text")
        .and_then(|text| extract_email_like(text));
    Ok(Some(PromptInfo {
        process_id,
        window_title,
        email,
    }))
}

#[cfg(target_os = "macos")]
fn run_fill_script(
    app_name: &str,
    prompt_pid: i32,
    prompt_title: &str,
    prompt_email: &str,
    password: Zeroizing<String>,
    method: FillMethod,
) -> anyhow::Result<HashMap<String, String>> {
    let password_literal = Zeroizing::new(applescript_string_literal(password.as_str()));
    let script = Zeroizing::new(format!(
        r#"{handlers}
tell application "System Events"
    set expectedName to {app_name}
    set expectedProcessNumber to "{prompt_pid}"
    set expectedTitle to {prompt_title}
    set usernameValue to {prompt_email}
    set passwordValue to {password}
    set requestedMethod to "{method}"
    if not my targetIsFrontmost(expectedName, expectedProcessNumber) then return my failureOutput("target_not_frontmost_before_fill")
    repeat with procRef in every application process whose name is expectedName
        if my processMatches(procRef, expectedName, expectedProcessNumber) then
            try
                set w to front window of procRef
                set wName to name of w as string
                if my windowTitleMatches(wName, expectedTitle) then
                    repeat with s in every sheet of w
                        set resultText to my fillContainer(s, usernameValue, passwordValue, expectedName, expectedProcessNumber, requestedMethod)
                        if resultText is not "" then return resultText
                    end repeat
                    set resultText to my fillContainer(w, usernameValue, passwordValue, expectedName, expectedProcessNumber, requestedMethod)
                    if resultText is not "" then return resultText
                end if
            end try
        end if
    end repeat
    return my failureOutput("verified_prompt_not_found_before_fill")
end tell"#,
        handlers = applescript_handlers(),
        app_name = applescript_string_literal(app_name),
        prompt_pid = prompt_pid,
        prompt_title = applescript_string_literal(prompt_title),
        prompt_email = applescript_string_literal(prompt_email),
        password = password_literal.as_str(),
        method = method.as_applescript(),
    ));
    drop(password_literal);
    let output = run_osascript_stdin(script.as_str(), Duration::from_secs(3))?;
    parse_script_output(&output)
}

#[cfg(target_os = "macos")]
#[allow(dead_code)]
fn run_submit_script(
    app_name: &str,
    prompt_pid: i32,
    prompt_title: &str,
    prompt_email: &str,
) -> anyhow::Result<HashMap<String, String>> {
    let script = format!(
        r#"{handlers}
tell application "System Events"
    set expectedName to {app_name}
    set expectedProcessNumber to "{prompt_pid}"
    set expectedTitle to {prompt_title}
    set usernameValue to {prompt_email}
    if not my targetIsFrontmost(expectedName, expectedProcessNumber) then return my submitFailureOutput("target_not_frontmost_before_submit")
    repeat with procRef in every application process whose name is expectedName
        if my processMatches(procRef, expectedName, expectedProcessNumber) then
            repeat with w in every window of procRef
                try
                    set wName to name of w as string
                    if my windowTitleMatches(wName, expectedTitle) then
                        repeat with s in every sheet of w
                            set resultText to my submitContainer(s, usernameValue, expectedName, expectedProcessNumber)
                            if resultText is not "" then return resultText
                        end repeat
                        set resultText to my submitContainer(w, usernameValue, expectedName, expectedProcessNumber)
                        if resultText is not "" then return resultText
                    end if
                end try
            end repeat
        end if
    end repeat
    return my submitFailureOutput("verified_prompt_not_found_before_submit")
end tell"#,
        handlers = applescript_handlers(),
        app_name = applescript_string_literal(app_name),
        prompt_pid = prompt_pid,
        prompt_title = applescript_string_literal(prompt_title),
        prompt_email = applescript_string_literal(prompt_email),
    );
    let output = run_osascript_stdin(&script, Duration::from_secs(3))?;
    parse_script_output(&output)
}

#[cfg(target_os = "macos")]
fn post_check_state(settings: &AppSettings, prompt_pid: i32, timeout: Duration) -> &'static str {
    let started = Instant::now();
    let mut last_state = "unknown";

    while started.elapsed() < timeout {
        match post_check_once(&settings.macos_app_name, prompt_pid) {
            Ok("authenticated") => return "authenticated",
            Ok("still_prompt") => last_state = "still_prompt",
            Ok("failed") => return "failed",
            Ok(_) | Err(_) => last_state = "unknown",
        }
        std::thread::sleep(Duration::from_millis(250));
    }

    last_state
}

#[cfg(target_os = "macos")]
fn post_check_once(app_name: &str, prompt_pid: i32) -> anyhow::Result<&'static str> {
    let script = format!(
        r#"{handlers}
tell application "System Events"
    set expectedName to {app_name}
    set expectedProcessNumber to "{prompt_pid}"
    set sawTarget to false
    set sawSession to false
    repeat with procRef in every application process whose name is expectedName
        if my processMatches(procRef, expectedName, expectedProcessNumber) then
            set sawTarget to true
            repeat with w in every window of procRef
                try
                    set wName to name of w as string
                    if my isProbableSessionTitle(wName) then set sawSession to true
                    repeat with s in every sheet of w
                        if my detectPromptContainer(s, expectedProcessNumber, wName) is not "" then return my kv("post_check_state", "still_prompt")
                    end repeat
                    if my isProbableSessionTitle(wName) then
                        if my detectPromptContainer(w, expectedProcessNumber, wName) is not "" then return my kv("post_check_state", "still_prompt")
                    end if
                end try
            end repeat
        end if
    end repeat
    if not sawTarget then return my kv("post_check_state", "failed")
    if sawSession then return my kv("post_check_state", "authenticated")
    return my kv("post_check_state", "prompt_gone_unknown")
end tell"#,
        handlers = applescript_handlers(),
        app_name = applescript_string_literal(app_name),
        prompt_pid = prompt_pid,
    );
    let output = run_osascript_stdin(&script, Duration::from_secs(3))?;
    let fields = parse_script_output(&output)?;
    Ok(match field_value(&fields, "post_check_state") {
        Some("authenticated") => "authenticated",
        Some("still_prompt") => "still_prompt",
        Some("prompt_gone_unknown") => "prompt_gone_unknown",
        Some("failed") => "failed",
        _ => "unknown",
    })
}

#[cfg(target_os = "macos")]
fn ensure_frontmost(app_name: &str, pid: i32) -> anyhow::Result<bool> {
    target_frontmost(app_name, pid)
}

#[cfg(target_os = "macos")]
fn target_frontmost(app_name: &str, pid: i32) -> anyhow::Result<bool> {
    let script = format!(
        r#"tell application "System Events"
    repeat with procRef in every application process whose name is {app_name}
        try
            if frontmost of procRef and ((unix id of procRef) as string) is "{pid}" then
                return "true"
            end if
        end try
    end repeat
    return "false"
end tell"#,
        app_name = applescript_string_literal(app_name),
        pid = pid,
    );
    let output = run_osascript(&script, Duration::from_secs(2))?;
    Ok(String::from_utf8_lossy(&output.stdout).trim() == "true")
}

#[cfg(target_os = "macos")]
fn parse_script_output(output: &std::process::Output) -> anyhow::Result<HashMap<String, String>> {
    if !output.status.success() {
        anyhow::bail!(
            "debug AppleScript failed: {}",
            classify_osascript_stderr(&output.stderr)
        );
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.trim().to_string(), value.trim().to_string()))
        .collect())
}

#[cfg(target_os = "macos")]
fn classify_osascript_stderr(stderr: &[u8]) -> &'static str {
    let stderr = String::from_utf8_lossy(stderr).to_lowercase();
    if stderr.trim().is_empty() {
        "no stderr"
    } else if stderr.contains("syntax error") || stderr.contains("expected") {
        "syntax_error"
    } else if stderr.contains("assistive access") || stderr.contains("accessibility") {
        "accessibility_denied"
    } else if stderr.contains("not authorized")
        || stderr.contains("not allowed")
        || stderr.contains("privacy")
    {
        "automation_denied"
    } else if stderr.contains("invalid index") || stderr.contains("can't get") {
        "accessibility_element_error"
    } else {
        "redacted_stderr"
    }
}

#[cfg(target_os = "macos")]
fn apply_script_fields(log: &mut DebugLog, fields: &HashMap<String, String>) {
    for key in [
        "password_field_detected",
        "password_field_role",
        "password_field_focused",
        "fill_method",
        "fill_attempted",
        "submit_method",
        "submit_attempted",
        "axpress_attempted",
        "axpress_result",
        "enter_fallback_attempted",
        "enter_fallback_result",
    ] {
        if let Some(value) = fields.get(key) {
            log.set(key, value.clone());
        }
    }
    if fields
        .get("password_field_description_present")
        .is_some_and(|value| value == "true")
    {
        log.set("password_field_description_redacted", "[redacted]");
    }
}

#[cfg(target_os = "macos")]
fn field_value<'a>(fields: &'a HashMap<String, String>, key: &str) -> Option<&'a str> {
    fields.get(key).map(String::as_str)
}

#[cfg(target_os = "macos")]
fn run_osascript(script: &str, timeout: Duration) -> anyhow::Result<std::process::Output> {
    run_command_with_timeout(
        Command::new("/usr/bin/osascript")
            .arg("-e")
            .arg(script)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
        timeout,
    )
}

#[cfg(target_os = "macos")]
fn run_osascript_stdin(script: &str, timeout: Duration) -> anyhow::Result<std::process::Output> {
    use std::io::Write;

    let mut child = Command::new("/usr/bin/osascript")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(script.as_bytes())?;
    }

    wait_child_with_timeout(child, timeout)
}

#[cfg(target_os = "macos")]
fn run_command_with_timeout(
    command: &mut Command,
    timeout: Duration,
) -> anyhow::Result<std::process::Output> {
    let child = command.spawn()?;
    wait_child_with_timeout(child, timeout)
}

#[cfg(target_os = "macos")]
fn wait_child_with_timeout(
    mut child: std::process::Child,
    timeout: Duration,
) -> anyhow::Result<std::process::Output> {
    let started = Instant::now();
    loop {
        if child.try_wait()?.is_some() {
            return Ok(child.wait_with_output()?);
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("debug AppleScript timed out");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(target_os = "macos")]
fn ax_is_process_trusted() -> bool {
    unsafe { AXIsProcessTrusted() != 0 }
}

#[cfg(target_os = "macos")]
#[link(name = "ApplicationServices", kind = "framework")]
unsafe extern "C" {
    fn AXIsProcessTrusted() -> u8;
}

#[cfg(target_os = "macos")]
fn containing_app_bundle(exe: &Path) -> Option<PathBuf> {
    exe.ancestors()
        .find(|path| path.extension().is_some_and(|ext| ext == "app"))
        .map(Path::to_path_buf)
}

#[cfg(target_os = "macos")]
fn bundle_identifier(bundle_path: &Path) -> Option<String> {
    let output = Command::new("/usr/libexec/PlistBuddy")
        .args(["-c", "Print :CFBundleIdentifier"])
        .arg(bundle_path.join("Contents/Info.plist"))
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .filter(|value| !value.is_empty())
}

#[cfg(target_os = "macos")]
fn apply_current_process_fields(log: &mut DebugLog) -> PathBuf {
    let current_exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("<unknown>"));
    log.set("current_process_path", current_exe.display().to_string());
    log.set("executable_path", current_exe.display().to_string());
    apply_current_identity_fields(log, &current_exe);
    let current_bundle = containing_app_bundle(&current_exe);
    if let Some(bundle) = current_bundle.as_deref() {
        log.set("app_bundle_path", bundle.display().to_string());
        log.set(
            "current_bundle_id",
            bundle_identifier(bundle).unwrap_or_default(),
        );
    }
    log.set(
        "current_launch_kind",
        if current_bundle.is_some() {
            "app_bundle"
        } else {
            "cargo_or_raw_binary"
        },
    );
    current_exe
}

#[cfg(target_os = "macos")]
fn apply_windows_app_fields(log: &mut DebugLog, target: &macos_identity::TrustedProcessInfo) {
    log.set("windows_app_pid", target.pid.to_string());
    log.set("windows_app_path", target.bundle_path.display().to_string());
    log.set("windows_app_bundle_id", target.bundle_id.clone());
    log.set("windows_app_team_id", target.team_id);
}

#[cfg(target_os = "macos")]
fn apply_current_identity_fields(log: &mut DebugLog, exe_path: &Path) {
    let exe_text = exe_path.to_string_lossy();
    log.set(
        "is_running_from_target_debug",
        exe_text.contains("/target/debug/").to_string(),
    );
    log.set(
        "is_running_from_dist_app",
        exe_text
            .contains("/dist/WindowsAppAutoLogin.app/")
            .to_string(),
    );

    let signing = current_signing_info(exe_path);
    log.set("current_signing_identity", signing.identity);
    log.set("current_signing_identifier", signing.identifier);
    log.set("current_team_id", signing.team_id);
}

#[cfg(target_os = "macos")]
struct CurrentSigningInfo {
    identity: String,
    identifier: String,
    team_id: String,
}

#[cfg(target_os = "macos")]
fn current_signing_info(exe_path: &Path) -> CurrentSigningInfo {
    let output = Command::new("/usr/bin/codesign")
        .args(["-dv", "--verbose=2"])
        .arg(exe_path)
        .output();
    let Ok(output) = output else {
        return CurrentSigningInfo {
            identity: "unknown".to_string(),
            identifier: String::new(),
            team_id: String::new(),
        };
    };
    let stderr = String::from_utf8_lossy(&output.stderr);
    let mut identity = if stderr.contains("Signature=adhoc") {
        "adhoc".to_string()
    } else {
        "unknown".to_string()
    };
    let mut identifier = String::new();
    let mut team_id = String::new();
    for line in stderr.lines() {
        let line = line.trim();
        if let Some(authority) = line.strip_prefix("Authority=") {
            identity = authority.trim().to_string();
        } else if let Some(value) = line.strip_prefix("Identifier=") {
            identifier = value.trim().to_string();
        } else if let Some(value) = line.strip_prefix("TeamIdentifier=") {
            team_id = value.trim().to_string();
        }
    }
    CurrentSigningInfo {
        identity,
        identifier,
        team_id,
    }
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

fn redacted_email(email: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(email.trim().to_lowercase().as_bytes());
    let digest = hasher.finalize();
    let short = digest
        .iter()
        .take(6)
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("[email:{short}]")
}

fn make_attempt_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!("{}-{nanos}", std::process::id())
}

fn sanitize_log_value(value: &str) -> String {
    let value = value.replace(['\r', '\n'], " ");
    if value.trim().is_empty() {
        return String::new();
    }
    value
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
fn applescript_handlers() -> &'static str {
    r#"
on kv(keyName, valueText)
    return keyName & "=" & valueText & linefeed
end kv

on failureOutput(reasonText)
    set out to my kv("fill_status", "failed")
    set out to out & my kv("fill_attempted", "false")
    set out to out & my kv("fill_method", "none")
    set out to out & my kv("failure_reason", reasonText)
    return out
end failureOutput

on submitFailureOutput(reasonText)
    set out to my kv("submit_status", "failed")
    set out to out & my kv("submit_attempted", "false")
    set out to out & my kv("submit_method", "none")
    set out to out & my kv("failure_reason", reasonText)
    return out
end submitFailureOutput

on processMatches(procRef, expectedName, expectedProcessNumber)
    try
        tell application "System Events"
            set procNameText to name of procRef as string
            set procNumberText to unix id of procRef as string
        end tell
        if procNameText is not expectedName then return false
        if procNumberText is not expectedProcessNumber then return false
        return true
    on error
        return false
    end try
end processMatches

on targetIsFrontmost(expectedName, expectedProcessNumber)
    tell application "System Events"
        repeat with procRef in every application process whose name is expectedName
            try
                if frontmost of procRef and my processMatches(procRef, expectedName, expectedProcessNumber) then return true
            end try
        end repeat
    end tell
    return false
end targetIsFrontmost

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
            set roleText to roleText & " " & ((value of attribute "AXRole" of elem) as string)
        end try
        try
            set roleText to roleText & " " & ((value of attribute "AXSubrole" of elem) as string)
        end try
        try
            set roleText to roleText & " " & ((value of attribute "AXRoleDescription" of elem) as string)
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
            set labelText to labelText & " " & ((value of attribute "AXTitle" of elem) as string)
        end try
        try
            set labelText to labelText & " " & ((value of attribute "AXDescription" of elem) as string)
        end try
        try
            set labelText to labelText & " " & ((value of attribute "AXHelp" of elem) as string)
        end try
        try
            set labelText to labelText & " " & ((value of attribute "AXPlaceholderValue" of elem) as string)
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

on fastElementRoleText(elem)
    tell application "System Events"
        set roleText to ""
        try
            set roleText to roleText & " " & ((value of attribute "AXRole" of elem) as string)
        end try
        try
            set roleText to roleText & " " & ((value of attribute "AXRoleDescription" of elem) as string)
        end try
        try
            set roleText to roleText & " " & (role of elem as string)
        end try
        try
            set roleText to roleText & " " & (role description of elem as string)
        end try
    end tell
    return roleText
end fastElementRoleText

on fastElementLabelText(elem)
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
            set labelText to labelText & " " & ((value of attribute "AXTitle" of elem) as string)
        end try
        try
            set labelText to labelText & " " & ((value of attribute "AXDescription" of elem) as string)
        end try
        try
            set labelText to labelText & " " & ((value of attribute "AXHelp" of elem) as string)
        end try
        try
            set labelText to labelText & " " & ((value of attribute "AXPlaceholderValue" of elem) as string)
        end try
    end tell
    return labelText
end fastElementLabelText

on fastElementIsCredentialPasswordField(elem)
    set roleText to my fastElementRoleText(elem)
    ignoring case
        if roleText contains "AXSecureTextField" then return true
        if roleText contains "secure text field" then return true
        if roleText contains "securetextfield" then return true
        if (roleText contains "AXTextField") and (roleText contains "secure") then return true
    end ignoring
    set labelText to my fastElementLabelText(elem)
    ignoring case
        if my roleLooksLikeTextField(roleText) and my textContainsPasswordCue(labelText) then return true
    end ignoring
    return false
end fastElementIsCredentialPasswordField

on fastElementLooksCollectableText(elem)
    set roleText to my fastElementRoleText(elem)
    ignoring case
        if roleText contains "AXStaticText" then return true
        if roleText contains "static text" then return true
        if roleText contains "AXTextField" then return true
        if roleText contains "text field" then return true
    end ignoring
    return false
end fastElementLooksCollectableText

on countPromptButtons(containerRef)
    set buttonCount to 0
    tell application "System Events"
        tell containerRef
            try
                set buttonCount to buttonCount + (count of every button)
            end try
            try
                repeat with elem in every UI element
                    set buttonCount to buttonCount + my countPromptButtons(elem)
                end repeat
            end try
        end tell
    end tell
    return buttonCount
end countPromptButtons

on countPasswordFields(containerRef)
    set fieldCount to 0
    tell application "System Events"
        try
            repeat with elem in every UI element of containerRef
                if my elementIsCredentialPasswordField(elem, true) then
                    set fieldCount to fieldCount + 1
                else
                    set fieldCount to fieldCount + my countPasswordFields(elem)
                end if
            end repeat
        end try
    end tell
    return fieldCount
end countPasswordFields

on isProbableSessionTitle(titleText)
    if titleText is "" then return false
    ignoring case
        if titleText is "Windows App" then return false
        if titleText is "Devices" then return false
        if titleText contains "About Windows App" then return false
        if titleText contains "Disconnected" then return false
        if titleText contains "Unable to connect" then return false
        if titleText contains "Connection Center" then return false
    end ignoring
    return true
end isProbableSessionTitle

on countDirectPasswordFields(containerRef)
    set fieldCount to 0
    tell application "System Events"
        try
            repeat with elem in every text field of containerRef
                if my fastElementIsCredentialPasswordField(elem) then set fieldCount to fieldCount + 1
            end repeat
        end try
    end tell
    return fieldCount
end countDirectPasswordFields

on countDirectButtons(containerRef)
    tell application "System Events"
        tell containerRef
            try
                return count of every button
            end try
        end tell
    end tell
    return 0
end countDirectButtons

on firstDirectCredentialPasswordField(containerRef)
    tell application "System Events"
        try
            repeat with elem in every text field of containerRef
                if my fastElementIsCredentialPasswordField(elem) then return elem
            end repeat
        end try
    end tell
    return missing value
end firstDirectCredentialPasswordField

on collectPromptTextDirect(containerRef, baseText)
    set promptText to baseText
    tell application "System Events"
        tell containerRef
            try
                repeat with staticRef in every static text
                    try
                        set promptText to promptText & " " & (name of staticRef as string)
                    end try
                    try
                        set promptText to promptText & " " & (value of staticRef as string)
                    end try
                end repeat
            end try
            try
                repeat with elem in every text field
                    if not my fastElementIsCredentialPasswordField(elem) then
                        try
                            set promptText to promptText & " " & (name of elem as string)
                        end try
                        try
                            set promptText to promptText & " " & (value of elem as string)
                        end try
                    end if
                end repeat
            end try
        end tell
    end tell
    return promptText
end collectPromptTextDirect

on detectPromptContainer(containerRef, procNumberText, wName)
    if my countDirectButtons(containerRef) < 1 then return ""
    if my countDirectPasswordFields(containerRef) < 1 then return ""
    set promptText to my collectPromptTextDirect(containerRef, "")
    set out to ""
    set out to out & my kv("prompt_detected", "true")
    set out to out & my kv("prompt_pid", procNumberText as string)
    set out to out & my kv("prompt_title", wName)
    set out to out & my kv("prompt_text", promptText)
    return out
end detectPromptContainer

on collectPromptText(containerRef, baseText)
    set promptText to baseText
    tell application "System Events"
        tell containerRef
            try
                repeat with tf in every text field
                    if not my elementIsCredentialPasswordField(tf, true) then
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
                repeat with staticRef in every static text
                    try
                        set promptText to promptText & " " & (name of staticRef as string)
                    end try
                    try
                        set promptText to promptText & " " & (value of staticRef as string)
                    end try
                end repeat
            end try
            try
                repeat with elem in every UI element
                    if not my elementIsCredentialPasswordField(elem, true) then
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
                            set promptText to promptText & " " & ((value of attribute "AXTitle" of elem) as string)
                        end try
                        try
                            set promptText to promptText & " " & ((value of attribute "AXDescription" of elem) as string)
                        end try
                        try
                            set promptText to promptText & " " & ((value of attribute "AXHelp" of elem) as string)
                        end try
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

on firstCredentialPasswordField(containerRef)
    tell application "System Events"
        try
            repeat with elem in every UI element of containerRef
                if my elementIsCredentialPasswordField(elem, true) then return elem
                set nestedField to my firstCredentialPasswordField(elem)
                if nestedField is not missing value then return nestedField
            end repeat
        end try
    end tell
    return missing value
end firstCredentialPasswordField

on fieldFocusState(passwordField)
    set sawFocusSignal to false
    try
        tell application "System Events"
            set focusedValue to focused of passwordField
        end tell
        if focusedValue then
            set sawFocusSignal to true
        else
            return "false"
        end if
    end try
    try
        tell application "System Events"
            set axFocusedValue to value of attribute "AXFocused" of passwordField
        end tell
        if axFocusedValue then
            set sawFocusSignal to true
        else
            return "false"
        end if
    end try
    if sawFocusSignal then return "true"
    return "unknown"
end fieldFocusState

on focusPasswordField(passwordField)
    try
        tell application "System Events"
            set focused of passwordField to true
        end tell
    end try
    try
        tell application "System Events"
            click passwordField
        end tell
    end try
    delay 0.05
    return my fieldFocusState(passwordField)
end focusPasswordField

on fillContainer(containerRef, usernameValue, passwordValue, expectedName, expectedProcessNumber, requestedMethod)
    if my countDirectButtons(containerRef) < 1 then return ""
    if my countDirectPasswordFields(containerRef) < 1 then return ""
    set promptText to my collectPromptTextDirect(containerRef, "")
    if not my promptMatchesAccount(promptText, usernameValue) then return ""
    set passwordField to my firstDirectCredentialPasswordField(containerRef)
    if passwordField is missing value then return my failureOutput("password_field_not_found")

    set out to ""
    set out to out & my kv("password_field_detected", "true")
    set out to out & my kv("password_field_role", my elementRoleText(passwordField))
    if (length of my elementLabelText(passwordField)) > 0 then
        set out to out & my kv("password_field_description_present", "true")
    else
        set out to out & my kv("password_field_description_present", "false")
    end if

    if requestedMethod is "direct_ax_set_value" then
        set out to out & my kv("fill_method", "direct_ax_set_value")
        set out to out & my kv("fill_attempted", "true")
        try
            tell application "System Events"
                set value of passwordField to passwordValue
            end tell
            set out to out & my kv("password_field_focused", my fieldFocusState(passwordField))
            set out to out & my kv("fill_status", "ok")
            return out & my submitContainer(containerRef, usernameValue, expectedName, expectedProcessNumber)
        on error
            set out to out & my kv("fill_status", "failed")
            set out to out & my kv("failure_reason", "direct_ax_set_value_failed")
            return out
        end try
    end if

    set focusState to my focusPasswordField(passwordField)
    set out to out & my kv("password_field_focused", focusState)
    set out to out & my kv("fill_method", "keyboard")
    if focusState is not "true" then
        set out to out & my kv("fill_attempted", "false")
        set out to out & my kv("fill_status", "failed")
        set out to out & my kv("failure_reason", "password_field_focus_not_verified")
        return out
    end if

    set out to out & my kv("fill_attempted", "true")
    try
        tell application "System Events"
            keystroke "a" using command down
        end tell
        delay 0.03
        if my fieldFocusState(passwordField) is not "true" then
            set out to out & my kv("fill_status", "failed")
            set out to out & my kv("failure_reason", "password_field_focus_lost_before_clear")
            return out
        end if
        tell application "System Events"
            key code 51
        end tell
        delay 0.03
        if my fieldFocusState(passwordField) is not "true" then
            set out to out & my kv("fill_status", "failed")
            set out to out & my kv("failure_reason", "password_field_focus_lost_before_type")
            return out
        end if
        tell application "System Events"
            keystroke passwordValue
        end tell
        delay 0.04
        set out to out & my kv("fill_status", "ok")
        return out & my submitContainer(containerRef, usernameValue, expectedName, expectedProcessNumber)
    on error
        set out to out & my kv("fill_status", "failed")
        set out to out & my kv("failure_reason", "keyboard_fill_failed")
        return out
    end try
end fillContainer

on pressButtonFast(buttonRef)
    try
        with timeout of 0.75 seconds
            tell application "System Events"
                perform action "AXPress" of buttonRef
            end tell
        end timeout
        return true
    on error
        return false
    end try
end pressButtonFast

on clickPreferredSubmit(containerRef)
    tell application "System Events"
        set preferredNames to {"Sign in", "Sign In", "Log in", "Login", "Log on", "Log On", "Connect", "Continue", "Next", "Submit", "OK", "Ok", "Done", "Войти", "Подключиться", "Продолжить", "Далее"}
        repeat with preferredName in preferredNames
            try
                repeat with b in every button of containerRef
                    try
                        if (name of b as string) is (preferredName as string) then
                            if my pressButtonFast(b) then return true
                        end if
                    end try
                end repeat
            end try
        end repeat
    end tell
    return false
end clickPreferredSubmit

on submitContainer(containerRef, usernameValue, expectedName, expectedProcessNumber)
    if my countDirectButtons(containerRef) < 1 then return ""
    if my countDirectPasswordFields(containerRef) < 1 then return ""
    set promptText to my collectPromptTextDirect(containerRef, "")
    if not my promptMatchesAccount(promptText, usernameValue) then return ""
    set passwordField to my firstDirectCredentialPasswordField(containerRef)
    if passwordField is missing value then return my submitFailureOutput("password_field_not_found_before_submit")

    set out to ""
    set out to out & my kv("submit_attempted", "true")
    set out to out & my kv("axpress_attempted", "true")
    if my clickPreferredSubmit(containerRef) then
        set out to out & my kv("submit_method", "axpress")
        set out to out & my kv("axpress_result", "success")
        set out to out & my kv("enter_fallback_attempted", "false")
        set out to out & my kv("enter_fallback_result", "not_needed")
        set out to out & my kv("submit_status", "ok")
        return out
    end if
    set out to out & my kv("axpress_result", "failed")

    if my fieldFocusState(passwordField) is not "true" then
        set refocusState to my focusPasswordField(passwordField)
    end if

    set out to out & my kv("enter_fallback_attempted", "true")
    if my fieldFocusState(passwordField) is "true" then
        try
            tell application "System Events"
                key code 36
            end tell
            delay 0.05
            set out to out & my kv("submit_method", "enter")
            set out to out & my kv("enter_fallback_result", "sent")
            set out to out & my kv("submit_status", "ok")
            return out
        end try
    end if

    set out to out & my kv("submit_method", "none")
    set out to out & my kv("enter_fallback_result", "focus_not_verified")
    set out to out & my kv("submit_status", "failed")
    set out to out & my kv("failure_reason", "submit_control_not_pressed")
    return out
end submitContainer
"#
}
