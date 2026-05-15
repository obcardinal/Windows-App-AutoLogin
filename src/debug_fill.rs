#[cfg(target_os = "macos")]
use crate::macos_identity;
use crate::models::{Account, AppSettings};
use crate::storage;
#[cfg(target_os = "macos")]
use std::path::Path;
use std::path::PathBuf;
#[cfg(target_os = "macos")]
use std::process::Command;
use std::time::{Duration, Instant, SystemTime};

#[cfg(target_os = "macos")]
struct PromptInfo {
    process_id: i32,
    window_title: String,
    prompt_origin: String,
    verified_prompt: Option<crate::macos_ax::MacosVerifiedPrompt>,
}

const LAST_FILL_ATTEMPT_REPORT_FILE: &str = "last-fill-attempt.json";

#[derive(Debug, Clone)]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) struct VerifiedPromptContext {
    pub(crate) account_id: String,
    pub(crate) process_id: i32,
    pub(crate) window_title: String,
    pub(crate) prompt_email: String,
    pub(crate) prompt_origin: String,
    pub(crate) detected_at: Instant,
    #[cfg(target_os = "windows")]
    pub(crate) monitor_check_ms: u128,
}

impl VerifiedPromptContext {
    #[cfg(target_os = "macos")]
    fn age(&self) -> Duration {
        Instant::now().saturating_duration_since(self.detected_at)
    }

    #[cfg(target_os = "macos")]
    fn is_fresh(&self) -> bool {
        self.age() <= VERIFIED_PROMPT_CONTEXT_MAX_AGE
    }

    #[cfg(target_os = "windows")]
    fn windows_age(&self) -> Duration {
        Instant::now().saturating_duration_since(self.detected_at)
    }

    #[cfg(target_os = "windows")]
    fn is_fresh_for_windows(&self) -> bool {
        self.windows_age() <= VERIFIED_PROMPT_CONTEXT_MAX_AGE
    }
}

const VERIFIED_PROMPT_CONTEXT_MAX_AGE: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FillMethod {
    Keyboard,
    #[cfg(target_os = "windows")]
    #[allow(dead_code)]
    DirectAxSetValue,
}

impl FillMethod {
    #[cfg(all(feature = "debug-fill", debug_assertions, not(waal_release_profile)))]
    pub(crate) fn parse(args: &[String]) -> anyhow::Result<Self> {
        let method = args
            .iter()
            .find_map(|arg| arg.strip_prefix("--fill-method="))
            .unwrap_or("keyboard");

        match method {
            "keyboard" => Ok(Self::Keyboard),
            "direct" | "direct_ax_set_value" => {
                #[cfg(target_os = "windows")]
                {
                    Ok(Self::DirectAxSetValue)
                }
                #[cfg(not(target_os = "windows"))]
                {
                    anyhow::bail!(
                        "unsupported fill method '{method}'; direct password fill is not available on this platform"
                    )
                }
            }
            other => anyhow::bail!("unsupported fill method '{other}'; use --fill-method=keyboard"),
        }
    }

    #[cfg(target_os = "windows")]
    fn as_windows_strategy(self) -> crate::windows_ui::WindowsFillStrategy {
        match self {
            Self::Keyboard => crate::windows_ui::WindowsFillStrategy::Keyboard,
            #[cfg(target_os = "windows")]
            Self::DirectAxSetValue => crate::windows_ui::WindowsFillStrategy::DirectSetValue,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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

    #[cfg_attr(
        not(all(feature = "debug-fill", debug_assertions, not(waal_release_profile))),
        allow(dead_code)
    )]
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
            "fill_current_prompt_once result={} prompt_context_source={} prompt_context_age_ms={} prompt_context_revalidation_result={} prompt_detected={} account_enabled_email_match_count={} account_saved_email_match_count={} account_match_count={} selected_account_id={} password_load_attempted={} password_loaded={} password_load_skip_reason={} password_load_ms={} fill_method={} submit_method={} axpress_result={} enter_fallback_result={} post_check_state={} failure_reason={}",
            result,
            self.field("prompt_context_source").unwrap_or("live_scan"),
            self.field("prompt_context_age_ms").unwrap_or("0"),
            self.field("prompt_context_revalidation_result")
                .unwrap_or("not_needed"),
            self.field("prompt_detected").unwrap_or("false"),
            self.field("account_enabled_email_match_count").unwrap_or("0"),
            self.field("account_saved_email_match_count").unwrap_or("0"),
            self.field("account_match_count").unwrap_or("0"),
            self.field("selected_account_id").unwrap_or(""),
            self.field("password_load_attempted").unwrap_or("false"),
            self.field("password_loaded").unwrap_or("false"),
            self.field("password_load_skip_reason").unwrap_or(""),
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

pub(crate) fn pre_password_skip_report(
    reason: impl Into<String>,
    fields: &[(&'static str, String)],
) -> FillAttemptReport {
    let mut log = DebugLog::new(make_attempt_id());
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    apply_current_process_fields(&mut log);
    #[cfg(target_os = "macos")]
    log.set(
        "ax_trusted_for_current_process",
        ax_is_process_trusted().to_string(),
    );
    for (field, value) in fields {
        log.set(field, value.clone());
    }
    log.fail(reason)
}

pub(crate) fn write_last_fill_attempt_report(report: &FillAttemptReport) -> anyhow::Result<()> {
    let dir = crate::user_paths::runtime_dir()?;
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(LAST_FILL_ATTEMPT_REPORT_FILE);
    let tmp_path = dir.join(format!("{LAST_FILL_ATTEMPT_REPORT_FILE}.tmp"));
    let bytes = serde_json::to_vec_pretty(report)?;
    std::fs::write(&tmp_path, bytes)?;
    std::fs::rename(tmp_path, path)?;
    Ok(())
}

#[cfg_attr(test, allow(dead_code))]
pub(crate) fn read_last_fill_attempt_report() -> anyhow::Result<Option<FillAttemptReport>> {
    let path = crate::user_paths::runtime_dir()?.join(LAST_FILL_ATTEMPT_REPORT_FILE);
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
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
            ("prompt_context_present", "false".to_string()),
            ("prompt_context_source", "live_scan".to_string()),
            ("prompt_context_age_ms", "0".to_string()),
            (
                "prompt_context_max_age_ms",
                VERIFIED_PROMPT_CONTEXT_MAX_AGE.as_millis().to_string(),
            ),
            (
                "prompt_context_revalidation_result",
                "not_needed".to_string(),
            ),
            ("windows_monitor_check_ms", "0".to_string()),
            ("windows_prompt_inspect_ms", "0".to_string()),
            ("prompt_detected", "false".to_string()),
            ("detected_email_redacted", String::new()),
            ("account_match_count", "0".to_string()),
            ("account_enabled_email_match_count", "0".to_string()),
            ("account_saved_email_match_count", "0".to_string()),
            ("selected_account_id", String::new()),
            ("password_load_attempted", "false".to_string()),
            ("password_loaded", "false".to_string()),
            ("password_load_skip_reason", String::new()),
            ("pre_password_revalidation_attempted", "false".to_string()),
            (
                "pre_password_revalidation_result",
                "not_attempted".to_string(),
            ),
            ("pre_password_revalidation_ms", "0".to_string()),
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
            ("submit_button_ready_after_fill", "false".to_string()),
            ("fill_method", "none".to_string()),
            ("fill_attempted", "false".to_string()),
            ("fill_status", "not_attempted".to_string()),
            ("fill_duration_ms", "0".to_string()),
            ("submit_method", "none".to_string()),
            ("submit_attempted", "false".to_string()),
            ("submit_status", "not_attempted".to_string()),
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
        let failure_reason = failure_reason.map(|reason| sanitize_failure_reason(&reason));
        if let Some(reason) = failure_reason.as_deref() {
            self.set("failure_reason", reason.to_string());
            let password_load_attempted = self
                .fields
                .iter()
                .find(|(field, _)| *field == "password_load_attempted")
                .is_some_and(|(_, value)| value == "true");
            if !password_load_attempted {
                self.set("password_load_skip_reason", reason.to_string());
            }
        }

        FillAttemptReport {
            fields: self
                .fields
                .into_iter()
                .map(|(key, value)| (key.to_string(), sanitize_log_field(key, &value)))
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

#[cfg(all(feature = "debug-fill", debug_assertions, not(waal_release_profile)))]
pub(crate) fn run_from_args(args: &[String]) -> anyhow::Result<()> {
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    {
        run_platform(args)
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let _ = args;
        anyhow::bail!("debug-fill-once is only supported on macOS and Windows")
    }
}

#[cfg(all(
    any(target_os = "macos", target_os = "windows"),
    feature = "debug-fill",
    debug_assertions,
    not(waal_release_profile)
))]
fn run_platform(args: &[String]) -> anyhow::Result<()> {
    let method = FillMethod::parse(args)?;
    let config = storage::load_config();
    let report = fill_current_prompt_once(&config.settings, &config.accounts, method);
    report.print();
    if let Some(reason) = report.failure_reason {
        anyhow::bail!(reason);
    }
    Ok(())
}

#[cfg_attr(
    not(all(feature = "debug-fill", debug_assertions, not(waal_release_profile))),
    allow(dead_code)
)]
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
    #[cfg(target_os = "windows")]
    {
        runtime_status_report_windows(settings, accounts)
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let _ = settings;
        let _ = accounts;
        DebugLog::new(format!("status-{}", make_attempt_id()))
            .fail("runtime status is only supported on macOS and Windows")
    }
}

#[cfg_attr(
    not(any(
        feature = "diagnostics-ui",
        all(feature = "debug-fill", debug_assertions, not(waal_release_profile))
    )),
    allow(dead_code)
)]
pub(crate) fn fill_current_prompt_once_guarded(
    settings: &AppSettings,
    accounts: &[Account],
    method: FillMethod,
    guard: impl Fn() -> anyhow::Result<()>,
) -> FillAttemptReport {
    fill_current_prompt_once_guarded_with_context(settings, accounts, method, None, guard)
}

pub(crate) fn fill_current_prompt_once_guarded_with_context(
    settings: &AppSettings,
    accounts: &[Account],
    method: FillMethod,
    verified_prompt: Option<VerifiedPromptContext>,
    guard: impl Fn() -> anyhow::Result<()>,
) -> FillAttemptReport {
    #[cfg(target_os = "macos")]
    {
        fill_current_prompt_once_macos(settings, accounts, method, verified_prompt.as_ref(), &guard)
    }
    #[cfg(target_os = "windows")]
    {
        fill_current_prompt_once_windows(
            settings,
            accounts,
            method,
            verified_prompt.as_ref(),
            &guard,
        )
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let _ = settings;
        let _ = accounts;
        let _ = method;
        let _ = verified_prompt;
        DebugLog::new(make_attempt_id())
            .fail("debug-fill-once is only supported on macOS and Windows")
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn detect_current_prompt_context(
    accounts: &[Account],
    guard: impl Fn() -> anyhow::Result<()>,
) -> Result<Option<VerifiedPromptContext>, String> {
    let app_name = crate::config::TARGET_APP_NAME;
    detect_current_prompt_context_macos(app_name, accounts, &guard)
}

#[cfg(target_os = "macos")]
fn fill_current_prompt_once_macos(
    settings: &AppSettings,
    accounts: &[Account],
    method: FillMethod,
    verified_prompt: Option<&VerifiedPromptContext>,
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

    let app_name = crate::config::TARGET_APP_NAME;

    let (prompt, prompt_email, selected_account) =
        match select_prompt_and_account(&mut log, app_name, accounts, verified_prompt, guard) {
            Ok(selection) => selection,
            Err(reason) => return log.fail(reason),
        };

    if let Err(e) = guard() {
        return log.fail(format!("attempt_cancelled_{e}"));
    }
    log.set("pre_password_revalidation_attempted", "true");
    let pre_password_revalidation_start = Instant::now();
    let verified_prompt = match crate::macos_ax::preflight_password_load_prompt(
        &app_name,
        prompt.verified_prompt.as_ref(),
        prompt.process_id,
        &prompt.window_title,
        &prompt.prompt_origin,
        &prompt_email,
    ) {
        Ok(verified_prompt) => {
            log.set("pre_password_revalidation_result", "ok");
            log.set(
                "pre_password_revalidation_ms",
                pre_password_revalidation_start
                    .elapsed()
                    .as_millis()
                    .to_string(),
            );
            verified_prompt
        }
        Err(_) => {
            log.set("pre_password_revalidation_result", "failed");
            log.set(
                "pre_password_revalidation_ms",
                pre_password_revalidation_start
                    .elapsed()
                    .as_millis()
                    .to_string(),
            );
            return log.fail("pre_password_revalidation_failed");
        }
    };
    if let Err(e) = guard() {
        return log.fail(format!("attempt_cancelled_{e}"));
    }

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
    let password_result = {
        #[cfg(target_os = "macos")]
        {
            storage::load_password_for_prompt_with_timing(
                selected_account,
                settings.use_keyring,
                &prompt.window_title,
            )
        }
        #[cfg(not(target_os = "macos"))]
        {
            storage::load_password_with_timing(selected_account, settings.use_keyring)
        }
    };
    let password = match password_result {
        Ok(result) => {
            log.set("password_loaded", "true");
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
    let fill_result = match crate::macos_ax::fill_verified_password(
        &app_name,
        verified_prompt,
        prompt.process_id,
        &prompt.window_title,
        &prompt.prompt_origin,
        &prompt_email,
        password.as_str(),
        macos_fill_method(method),
        guard,
    ) {
        Ok(result) => result,
        Err(e) => {
            log.set(
                "fill_duration_ms",
                fill_start.elapsed().as_millis().to_string(),
            );
            return log.fail(format!("fill_failed_{e}"));
        }
    };
    log.set(
        "fill_duration_ms",
        fill_start.elapsed().as_millis().to_string(),
    );
    apply_macos_fill_fields(&mut log, &fill_result);

    if fill_result.fill_status != "ok" {
        return log.fail("password_field_not_detected_in_verified_prompt");
    }

    let submit_start = Instant::now();
    let submit_result = match crate::macos_ax::submit_prompt_after_fill(
        &app_name,
        fill_result.filled_prompt.as_ref(),
        prompt.process_id,
        &prompt.window_title,
        &prompt.prompt_origin,
        &prompt_email,
        guard,
    ) {
        Ok(result) => result,
        Err(e) => {
            log.set(
                "submit_duration_ms",
                submit_start.elapsed().as_millis().to_string(),
            );
            let post_state = post_check_state(
                settings,
                prompt.process_id,
                &prompt.window_title,
                &prompt_email,
                None,
                Duration::from_millis(450),
            );
            log.set("post_check_state", post_state);
            return if post_state == "authenticated" {
                log.finish(None)
            } else {
                log.fail(format!("submit_failed_{e}"))
            };
        }
    };
    log.set(
        "submit_duration_ms",
        submit_start.elapsed().as_millis().to_string(),
    );
    apply_macos_submit_fields(&mut log, &submit_result);

    let post_state = post_check_state(
        settings,
        prompt.process_id,
        &prompt.window_title,
        &prompt_email,
        submit_result.submitted_prompt.as_ref(),
        Duration::from_millis(450),
    );
    log.set("post_check_state", post_state);
    if post_state == "authenticated" {
        return log.finish(None);
    }
    if submit_result.submit_status != "ok" {
        return log.fail("submit_failed");
    }
    match post_state {
        "authenticated" => log.finish(None),
        "still_prompt" => log.fail("credential_prompt_still_visible_after_submit"),
        "prompt_mismatch" => log.fail("post_submit_prompt_mismatch"),
        "prompt_gone_unknown" => log.fail("post_submit_prompt_gone_unknown"),
        "failed" => log.fail("windows_app_not_running_after_submit"),
        _ => log.fail("post_submit_state_unknown"),
    }
}

#[cfg(target_os = "macos")]
fn detect_current_prompt_context_macos(
    app_name: &str,
    accounts: &[Account],
    guard: &dyn Fn() -> anyhow::Result<()>,
) -> Result<Option<VerifiedPromptContext>, String> {
    let trusted_infos = macos_identity::trusted_process_infos(app_name)
        .map_err(|_| "windows_app_trust_check_failed".to_string())?;
    if trusted_infos.is_empty() {
        return Ok(None);
    }

    let native_prompt = crate::macos_ax::detect_visible_prompt(app_name, None, None, None)
        .map_err(|e| format!("prompt_detection_failed_{e}"))?;
    let Some(native_prompt) = native_prompt else {
        return Ok(None);
    };
    let Some(_target) = trusted_infos
        .iter()
        .find(|target| target.pid == native_prompt.target.process_id)
    else {
        return Err("prompt_pid_does_not_match_trusted_target".to_string());
    };

    let Some(prompt_email) = native_prompt
        .email
        .clone()
        .filter(|email| !email.trim().is_empty())
    else {
        return Err("visible_prompt_email_missing".to_string());
    };
    guard().map_err(|e| format!("attempt_cancelled_{e}"))?;

    let enabled_email_matches = enabled_email_match_count(accounts, &prompt_email);
    let matches = matching_macos_accounts(accounts, &prompt_email);
    let [selected_account] = matches.as_slice() else {
        return if matches.is_empty() {
            Err(account_match_failure_reason(enabled_email_matches).to_string())
        } else {
            Err("visible_prompt_email_matches_multiple_enabled_accounts".to_string())
        };
    };

    Ok(Some(VerifiedPromptContext {
        account_id: selected_account.id.clone(),
        process_id: native_prompt.target.process_id,
        window_title: native_prompt.target.window_title.clone(),
        prompt_email,
        prompt_origin: native_prompt.origin.as_str().to_string(),
        detected_at: Instant::now(),
    }))
}

#[cfg(target_os = "macos")]
fn select_prompt_and_account<'a>(
    log: &mut DebugLog,
    app_name: &str,
    accounts: &'a [Account],
    verified_prompt: Option<&VerifiedPromptContext>,
    guard: &dyn Fn() -> anyhow::Result<()>,
) -> Result<(PromptInfo, String, &'a Account), String> {
    if let Some(context) = verified_prompt {
        log.set("prompt_context_present", "true");
        let context_age = context.age();
        log.set("prompt_context_age_ms", context_age.as_millis().to_string());
        if context.is_fresh() {
            log.set("prompt_context_source", "monitor_snapshot");
            match select_fresh_prompt_context(log, app_name, accounts, context, guard) {
                Ok(selection) => return Ok(selection),
                Err(reason) => {
                    if reason.starts_with("attempt_cancelled_") {
                        return Err(reason);
                    }
                    let revalidation_result = log_value(log, "prompt_context_revalidation_result")
                        .filter(|value| value != "not_needed")
                        .unwrap_or_else(|| "failed".to_string());
                    log.set("prompt_context_source", "monitor_snapshot_fresh_live_scan");
                    log.set(
                        "prompt_context_revalidation_result",
                        format!("{revalidation_result}_live_scan"),
                    );
                }
            }
        } else {
            log.set("prompt_context_source", "monitor_snapshot_stale_live_scan");
            log.set("prompt_context_revalidation_result", "stale_live_scan");
        }
    }

    let trusted_infos = macos_identity::trusted_process_infos(app_name)
        .map_err(|_| "windows_app_trust_check_failed".to_string())?;
    let Some(target) = trusted_infos.first() else {
        return Err("trusted_windows_app_not_running".to_string());
    };

    let native_prompt = crate::macos_ax::detect_visible_prompt(app_name, None, None, None)
        .map_err(|e| format!("prompt_detection_failed_{e}"))?;
    let Some(native_prompt) = native_prompt else {
        return Err("visible_credential_prompt_not_detected".to_string());
    };
    log.set("prompt_detected", "true");

    let target = trusted_infos
        .iter()
        .find(|target| target.pid == native_prompt.target.process_id)
        .unwrap_or(target);
    apply_windows_app_fields(log, target);
    log.set(
        "windows_app_frontmost",
        native_prompt.target.frontmost.to_string(),
    );
    if native_prompt.target.process_id != target.pid {
        return Err("prompt_pid_does_not_match_trusted_target".to_string());
    }

    let Some(prompt_email) = native_prompt
        .email
        .clone()
        .filter(|email| !email.trim().is_empty())
    else {
        return Err("visible_prompt_email_missing".to_string());
    };
    log.set("detected_email_redacted", redacted_email(&prompt_email));
    guard().map_err(|e| format!("attempt_cancelled_{e}"))?;

    let account_lookup_start = Instant::now();
    let enabled_email_matches = enabled_email_match_count(accounts, &prompt_email);
    let matches = matching_macos_accounts(accounts, &prompt_email);
    log.set(
        "account_id_lookup_ms",
        account_lookup_start.elapsed().as_millis().to_string(),
    );
    log.set(
        "account_enabled_email_match_count",
        enabled_email_matches.to_string(),
    );
    log.set("account_saved_email_match_count", matches.len().to_string());
    log.set("account_match_count", matches.len().to_string());
    let [selected_account] = matches.as_slice() else {
        return if matches.is_empty() {
            Err(account_match_failure_reason(enabled_email_matches).to_string())
        } else {
            Err("visible_prompt_email_matches_multiple_enabled_accounts".to_string())
        };
    };
    log.set("selected_account_id", selected_account.id.clone());

    let process_id = native_prompt.target.process_id;
    let window_title = native_prompt.target.window_title.clone();
    let prompt_origin = native_prompt.origin.as_str().to_string();
    let verified_prompt = crate::macos_ax::MacosVerifiedPrompt::from_detected_prompt(native_prompt);

    Ok((
        PromptInfo {
            process_id,
            window_title,
            prompt_origin,
            verified_prompt: Some(verified_prompt),
        },
        prompt_email,
        *selected_account,
    ))
}

#[cfg(target_os = "macos")]
fn select_fresh_prompt_context<'a>(
    log: &mut DebugLog,
    app_name: &str,
    accounts: &'a [Account],
    context: &VerifiedPromptContext,
    guard: &dyn Fn() -> anyhow::Result<()>,
) -> Result<(PromptInfo, String, &'a Account), String> {
    let verified_prompt = match crate::macos_ax::revalidate_visible_prompt(
        app_name,
        context.process_id,
        &context.window_title,
        &context.prompt_origin,
        &context.prompt_email,
    ) {
        Ok(prompt) => prompt,
        Err(e) => {
            log.set("prompt_context_revalidation_result", "inspection_failed");
            return Err(format!("prompt_context_live_revalidation_failed_{e}"));
        }
    };
    let native_prompt = &verified_prompt.prompt;
    log.set("prompt_detected", "true");
    log.set(
        "windows_app_frontmost",
        native_prompt.target.frontmost.to_string(),
    );
    if native_prompt.target.process_id != context.process_id {
        log.set("prompt_context_revalidation_result", "pid_changed");
        return Err("monitor_prompt_context_pid_changed".to_string());
    }

    let prompt_email = native_prompt
        .email
        .clone()
        .unwrap_or_default()
        .trim()
        .to_string();
    if prompt_email.is_empty() {
        log.set("prompt_context_revalidation_result", "email_missing");
        return Err("visible_prompt_email_missing".to_string());
    }
    if !prompt_email.eq_ignore_ascii_case(context.prompt_email.trim()) {
        log.set("prompt_context_revalidation_result", "email_changed");
        return Err("monitor_prompt_context_email_changed".to_string());
    }
    if !native_prompt
        .origin
        .as_str()
        .eq_ignore_ascii_case(context.prompt_origin.trim())
    {
        log.set("prompt_context_revalidation_result", "origin_changed");
        return Err("monitor_prompt_context_origin_changed".to_string());
    }
    log.set(
        "windows_app_pid",
        native_prompt.target.process_id.to_string(),
    );
    log.set("detected_email_redacted", redacted_email(&prompt_email));

    guard().map_err(|e| format!("attempt_cancelled_{e}"))?;

    let account_lookup_start = Instant::now();
    let enabled_email_matches = enabled_email_match_count(accounts, &prompt_email);
    let matches = matching_macos_accounts(accounts, &prompt_email);
    log.set(
        "account_id_lookup_ms",
        account_lookup_start.elapsed().as_millis().to_string(),
    );
    log.set(
        "account_enabled_email_match_count",
        enabled_email_matches.to_string(),
    );
    log.set("account_saved_email_match_count", matches.len().to_string());
    log.set("account_match_count", matches.len().to_string());
    let [selected_account] = matches.as_slice() else {
        return if matches.is_empty() {
            log.set(
                "prompt_context_revalidation_result",
                if enabled_email_matches == 0 {
                    "no_account_match"
                } else {
                    "no_saved_password_match"
                },
            );
            Err(account_match_failure_reason(enabled_email_matches).to_string())
        } else {
            log.set(
                "prompt_context_revalidation_result",
                "multiple_account_matches",
            );
            Err("visible_prompt_email_matches_multiple_enabled_accounts".to_string())
        };
    };
    if selected_account.id != context.account_id {
        log.set("prompt_context_revalidation_result", "account_changed");
        return Err("monitor_prompt_context_account_changed".to_string());
    }
    log.set("selected_account_id", selected_account.id.clone());
    log.set("prompt_context_revalidation_result", "ok");

    Ok((
        PromptInfo {
            process_id: native_prompt.target.process_id,
            window_title: native_prompt.target.window_title.clone(),
            prompt_origin: native_prompt.origin.as_str().to_string(),
            verified_prompt: Some(verified_prompt),
        },
        prompt_email,
        *selected_account,
    ))
}

#[cfg(target_os = "windows")]
fn fill_current_prompt_once_windows(
    settings: &AppSettings,
    accounts: &[Account],
    method: FillMethod,
    verified_prompt: Option<&VerifiedPromptContext>,
    guard: &dyn Fn() -> anyhow::Result<()>,
) -> FillAttemptReport {
    let mut log = DebugLog::new(make_attempt_id());

    apply_current_process_fields(&mut log);
    log.set("ax_trusted_for_current_process", "true");

    if let Err(e) = guard() {
        return log.fail(format!("attempt_cancelled_{e}"));
    }

    let app_name = crate::config::TARGET_APP_NAME;
    let inspect_start = Instant::now();
    let mut inspection = match inspect_windows_prompt_for_fill(app_name, verified_prompt, &mut log)
    {
        Ok(inspection) => {
            log.set(
                "windows_prompt_inspect_ms",
                inspect_start.elapsed().as_millis().to_string(),
            );
            inspection
        }
        Err(e) => {
            log.set(
                "windows_prompt_inspect_ms",
                inspect_start.elapsed().as_millis().to_string(),
            );
            return log.fail(format!("windows_uia_inspection_failed_{e}"));
        }
    };

    let target = inspection.target.clone();
    let Some(target) = target else {
        return log.fail("trusted_windows_app_not_running");
    };
    apply_windows_target_fields(&mut log, &target);

    let Some(mut prompt) = inspection.prompt else {
        return log.fail("visible_credential_prompt_not_detected");
    };
    if !prompt.target.frontmost {
        if let Err(e) = crate::windows_ui::activate_window(prompt.target.window_handle) {
            return log.fail(format!("credential_prompt_activation_failed_{e}"));
        }
        inspection = match crate::windows_ui::inspect(app_name) {
            Ok(inspection) => inspection,
            Err(e) => return log.fail(format!("windows_uia_reinspection_failed_{e}")),
        };
        let Some(next_prompt) = inspection.prompt else {
            return log.fail("visible_credential_prompt_not_detected_after_activation");
        };
        prompt = next_prompt;
    }
    log.set("windows_app_frontmost", prompt.target.frontmost.to_string());
    if !prompt.target.frontmost {
        return log.fail("windows_app_not_frontmost");
    }

    log.set("prompt_detected", "true");
    log.set("password_field_detected", "true");
    log.set("password_field_role", prompt.password_field_role.clone());
    log.set(
        "password_field_description_redacted",
        prompt.password_field_description.clone(),
    );

    let account_lookup_start = Instant::now();
    let (matches, prompt_email) = match windows_prompt_account_matches(accounts, &prompt) {
        Ok((matches, prompt_email)) => {
            log.set("detected_email_redacted", redacted_email(&prompt_email));
            (matches, prompt_email)
        }
        Err(reason) => return log.fail(reason),
    };
    if let Err(e) = guard() {
        return log.fail(format!("attempt_cancelled_{e}"));
    }

    log.set(
        "account_id_lookup_ms",
        account_lookup_start.elapsed().as_millis().to_string(),
    );
    let enabled_email_matches = enabled_email_match_count(accounts, &prompt_email);
    log.set(
        "account_enabled_email_match_count",
        enabled_email_matches.to_string(),
    );
    log.set("account_saved_email_match_count", matches.len().to_string());
    log.set("account_match_count", matches.len().to_string());
    let [selected_account] = matches.as_slice() else {
        return if matches.is_empty() {
            log.fail(account_match_failure_reason(enabled_email_matches))
        } else {
            log.fail("visible_prompt_email_matches_multiple_enabled_accounts")
        };
    };
    log.set("selected_account_id", selected_account.id.clone());
    let expected_email = prompt_email.as_str();

    log.set("password_load_attempted", "true");
    log.set("keychain_service_name", storage::keychain_service_name());
    log.set("keychain_account_key", selected_account.id.clone());
    log.set(
        "keychain_process_path",
        log_value(&log, "current_process_path").unwrap_or_default(),
    );

    let password = match storage::load_password_with_timing(selected_account, settings.use_keyring)
    {
        Ok(result) => {
            log.set("password_loaded", "true");
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
    let fill_result = match crate::windows_ui::fill_password(
        app_name,
        &prompt,
        password.as_str(),
        method.as_windows_strategy(),
        guard,
    ) {
        Ok(result) => result,
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
    log.set("fill_method", fill_result.fill_method);
    log.set("fill_attempted", "true");
    log.set("fill_status", fill_result.fill_status);
    log.set(
        "password_field_focused",
        fill_result.password_field_focused.to_string(),
    );

    let submit_start = Instant::now();
    let submit_result = match crate::windows_ui::submit_prompt(app_name, &prompt, guard) {
        Ok(result) => result,
        Err(e) => {
            log.set(
                "submit_duration_ms",
                submit_start.elapsed().as_millis().to_string(),
            );
            let post_state = crate::windows_ui::post_check_state(
                app_name,
                target.process_id,
                expected_email,
                Duration::from_millis(1200),
            );
            log.set("post_check_state", post_state);
            return if post_state == "authenticated" {
                log.finish(None)
            } else {
                log.fail(format!("submit_script_failed_{e}"))
            };
        }
    };
    log.set(
        "submit_duration_ms",
        submit_start.elapsed().as_millis().to_string(),
    );
    log.set("submit_method", submit_result.submit_method);
    log.set("submit_attempted", "true");
    log.set("submit_status", submit_result.submit_status);
    log.set(
        "axpress_attempted",
        submit_result.axpress_attempted.to_string(),
    );
    log.set("axpress_result", submit_result.axpress_result);
    log.set(
        "enter_fallback_attempted",
        submit_result.enter_fallback_attempted.to_string(),
    );
    log.set("enter_fallback_result", submit_result.enter_fallback_result);

    let post_state = crate::windows_ui::post_check_state(
        app_name,
        target.process_id,
        expected_email,
        Duration::from_millis(1200),
    );
    log.set("post_check_state", post_state);
    match post_state {
        "authenticated" => log.finish(None),
        "prompt_mismatch" => log.fail("post_submit_prompt_mismatch"),
        "prompt_gone_unknown" => log.fail("post_submit_prompt_gone_unknown"),
        "still_prompt" => log.fail("credential_prompt_still_visible_after_submit"),
        "failed" => log.fail("windows_app_not_running_after_submit"),
        _ => log.fail("post_submit_state_unknown"),
    }
}

#[cfg(target_os = "windows")]
fn inspect_windows_prompt_for_fill(
    app_name: &str,
    verified_prompt: Option<&VerifiedPromptContext>,
    log: &mut DebugLog,
) -> anyhow::Result<crate::windows_ui::WindowsInspection> {
    let Some(context) = verified_prompt else {
        return crate::windows_ui::inspect(app_name);
    };

    log.set("prompt_context_present", "true");
    log.set(
        "prompt_context_age_ms",
        context.windows_age().as_millis().to_string(),
    );
    log.set(
        "windows_monitor_check_ms",
        context.monitor_check_ms.to_string(),
    );

    if !context.is_fresh_for_windows() {
        log.set("prompt_context_source", "monitor_snapshot_stale_live_scan");
        log.set("prompt_context_revalidation_result", "stale_live_scan");
        return crate::windows_ui::inspect(app_name);
    }

    log.set("prompt_context_source", "monitor_snapshot_windows_fast");
    match crate::windows_ui::inspect_prompt_snapshot(
        app_name,
        context.process_id,
        &context.window_title,
        Some(&context.prompt_email),
    ) {
        Ok(Some(prompt)) => {
            log.set("prompt_context_revalidation_result", "ok");
            let target = crate::windows_ui::running_target_process(app_name);
            Ok(crate::windows_ui::WindowsInspection {
                target,
                prompt: Some(prompt),
                has_session: false,
            })
        }
        Ok(None) => {
            log.set(
                "prompt_context_source",
                "monitor_snapshot_windows_fast_live_scan",
            );
            log.set("prompt_context_revalidation_result", "not_found_live_scan");
            crate::windows_ui::inspect(app_name)
        }
        Err(e) => {
            log.set(
                "prompt_context_source",
                "monitor_snapshot_windows_fast_live_scan",
            );
            log.set(
                "prompt_context_revalidation_result",
                "inspection_failed_live_scan",
            );
            tracing::debug!(error = %e, "Windows prompt snapshot revalidation failed");
            crate::windows_ui::inspect(app_name)
        }
    }
}

#[cfg(all(target_os = "macos", feature = "diagnostics-ui"))]
fn runtime_status_report_macos(_settings: &AppSettings, accounts: &[Account]) -> FillAttemptReport {
    let mut log = DebugLog::new(format!("status-{}", make_attempt_id()));

    apply_current_process_fields(&mut log);
    log.set("keychain_service_name", storage::keychain_service_name());

    let ax_trusted = ax_is_process_trusted();
    log.set("ax_trusted_for_current_process", ax_trusted.to_string());
    if !ax_trusted {
        return log.fail("accessibility_not_trusted_for_current_process");
    }

    let app_name = crate::config::TARGET_APP_NAME;
    let trusted_infos = match macos_identity::trusted_process_infos(app_name) {
        Ok(infos) => infos,
        Err(_) => return log.fail("windows_app_trust_check_failed"),
    };
    let Some(target) = trusted_infos.first() else {
        return log.fail("trusted_windows_app_not_running");
    };
    apply_windows_app_fields(&mut log, target);

    let prompt = match crate::macos_ax::detect_visible_prompt(&app_name, None, None, None) {
        Ok(prompt) => prompt,
        Err(e) => return log.fail(format!("prompt_detection_failed_{e}")),
    };
    let Some(prompt) = prompt else {
        return log.fail("visible_credential_prompt_not_detected");
    };
    log.set("prompt_detected", "true");
    log.set("password_field_detected", "true");
    log.set("password_field_role", prompt.password_field_role.clone());
    log.set(
        "password_field_focused",
        prompt.password_field_focused().unwrap_or(false).to_string(),
    );
    if !prompt.password_field_description.trim().is_empty() {
        log.set("password_field_description_redacted", "[redacted]");
    }
    let target = trusted_infos
        .iter()
        .find(|target| target.pid == prompt.target.process_id)
        .unwrap_or(target);
    apply_windows_app_fields(&mut log, target);
    log.set("windows_app_frontmost", prompt.target.frontmost.to_string());
    if !prompt.target.frontmost {
        return log.fail("windows_app_not_frontmost");
    }
    if prompt.target.process_id != target.pid {
        return log.fail("prompt_pid_does_not_match_trusted_target");
    }

    let account_lookup_start = Instant::now();
    let Some(prompt_email) = prompt.email.filter(|email| !email.trim().is_empty()) else {
        return log.fail("visible_prompt_email_missing");
    };
    log.set("detected_email_redacted", redacted_email(&prompt_email));
    let enabled_email_matches = enabled_email_match_count(accounts, &prompt_email);
    let matches = matching_macos_accounts(accounts, &prompt_email);
    log.set(
        "account_id_lookup_ms",
        account_lookup_start.elapsed().as_millis().to_string(),
    );
    log.set(
        "account_enabled_email_match_count",
        enabled_email_matches.to_string(),
    );
    log.set("account_saved_email_match_count", matches.len().to_string());
    log.set("account_match_count", matches.len().to_string());
    let [selected_account] = matches.as_slice() else {
        return if matches.is_empty() {
            log.fail(account_match_failure_reason(enabled_email_matches))
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

#[cfg(all(target_os = "windows", feature = "diagnostics-ui"))]
fn runtime_status_report_windows(
    _settings: &AppSettings,
    accounts: &[Account],
) -> FillAttemptReport {
    let mut log = DebugLog::new(format!("status-{}", make_attempt_id()));

    apply_current_process_fields(&mut log);
    log.set("ax_trusted_for_current_process", "true");
    log.set("keychain_service_name", storage::keychain_service_name());

    let app_name = crate::config::TARGET_APP_NAME;
    let inspection = match crate::windows_ui::inspect(app_name) {
        Ok(inspection) => inspection,
        Err(e) => return log.fail(format!("windows_uia_inspection_failed_{e}")),
    };

    let target = inspection.target.clone();
    let Some(target) = target else {
        return log.fail("trusted_windows_app_not_running");
    };
    apply_windows_target_fields(&mut log, &target);

    let Some(prompt) = inspection.prompt else {
        return log.finish(None);
    };
    log.set("prompt_detected", "true");
    log.set("password_field_detected", "true");
    log.set("password_field_role", prompt.password_field_role.clone());
    log.set(
        "password_field_description_redacted",
        prompt.password_field_description.clone(),
    );

    let account_lookup_start = Instant::now();
    let (matches, prompt_email) = match windows_prompt_account_matches(accounts, &prompt) {
        Ok((matches, prompt_email)) => {
            log.set("detected_email_redacted", redacted_email(&prompt_email));
            (matches, prompt_email)
        }
        Err(reason) => return log.fail(reason),
    };
    log.set(
        "account_id_lookup_ms",
        account_lookup_start.elapsed().as_millis().to_string(),
    );
    let enabled_email_matches = enabled_email_match_count(accounts, &prompt_email);
    log.set(
        "account_enabled_email_match_count",
        enabled_email_matches.to_string(),
    );
    log.set("account_saved_email_match_count", matches.len().to_string());
    log.set("account_match_count", matches.len().to_string());
    let [selected_account] = matches.as_slice() else {
        return if matches.is_empty() {
            log.fail(account_match_failure_reason(enabled_email_matches))
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
    log.finish(None)
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn matching_accounts<'a>(accounts: &'a [Account], prompt_email: &str) -> Vec<&'a Account> {
    accounts
        .iter()
        .filter(|account| {
            account.enabled && account.has_saved_password && !account.username.trim().is_empty()
        })
        .filter(|account| {
            account
                .username
                .trim()
                .eq_ignore_ascii_case(prompt_email.trim())
        })
        .collect()
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn enabled_email_match_count(accounts: &[Account], prompt_email: &str) -> usize {
    accounts
        .iter()
        .filter(|account| account.enabled && !account.username.trim().is_empty())
        .filter(|account| {
            account
                .username
                .trim()
                .eq_ignore_ascii_case(prompt_email.trim())
        })
        .count()
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn account_match_failure_reason(enabled_email_matches: usize) -> &'static str {
    if enabled_email_matches == 0 {
        "visible_prompt_email_matches_no_enabled_account"
    } else {
        "visible_prompt_email_matches_no_saved_password"
    }
}

#[cfg(target_os = "macos")]
fn matching_macos_accounts<'a>(accounts: &'a [Account], prompt_email: &str) -> Vec<&'a Account> {
    matching_accounts(accounts, prompt_email)
}

#[cfg(target_os = "windows")]
fn windows_prompt_account_matches<'a>(
    accounts: &'a [Account],
    prompt: &crate::windows_ui::WindowsPrompt,
) -> Result<(Vec<&'a Account>, String), &'static str> {
    windows_prompt_account_matches_for_context(accounts, prompt.email.as_deref())
}

#[cfg(target_os = "windows")]
fn windows_prompt_account_matches_for_context<'a>(
    accounts: &'a [Account],
    prompt_email: Option<&str>,
) -> Result<(Vec<&'a Account>, String), &'static str> {
    if let Some(prompt_email) = prompt_email
        .map(str::trim)
        .filter(|email| !email.is_empty())
    {
        return Ok((
            matching_accounts(accounts, prompt_email),
            prompt_email.to_string(),
        ));
    }

    Err("visible_prompt_email_missing")
}

#[cfg(all(test, target_os = "windows"))]
mod windows_tests {
    use super::windows_prompt_account_matches_for_context;
    use crate::models::Account;

    fn account(id: &str, username: &str, enabled: bool) -> Account {
        Account {
            id: id.to_string(),
            username: username.to_string(),
            has_saved_password: true,
            enabled,
        }
    }

    #[test]
    fn windows_prompt_without_email_is_rejected_even_with_single_account() {
        let accounts = vec![account("a", "user@example.com", true)];

        assert_eq!(
            windows_prompt_account_matches_for_context(&accounts, None),
            Err("visible_prompt_email_missing")
        );
    }

    #[test]
    fn visible_email_still_matches_exact_enabled_account() {
        let accounts = vec![
            account("a", "user@example.com", true),
            account("b", "other@example.com", true),
            account("c", "disabled@example.com", false),
        ];

        let (matches, prompt_email) =
            windows_prompt_account_matches_for_context(&accounts, Some(" USER@example.com "))
                .unwrap();

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].id.as_str(), "a");
        assert_eq!(prompt_email, "USER@example.com");
    }
}

#[cfg(all(test, target_os = "macos"))]
mod macos_context_tests {
    use super::VerifiedPromptContext;
    use crate::models::Account;
    use std::time::{Duration, Instant};

    fn account(id: &str, username: &str) -> Account {
        account_with_saved_password(id, username, true)
    }

    fn account_with_saved_password(id: &str, username: &str, has_saved_password: bool) -> Account {
        Account {
            id: id.to_string(),
            username: username.to_string(),
            has_saved_password,
            enabled: true,
        }
    }

    fn context(detected_at: Instant) -> VerifiedPromptContext {
        VerifiedPromptContext {
            account_id: "account-1".to_string(),
            process_id: 42,
            window_title: "Sign in".to_string(),
            prompt_email: "user@example.com".to_string(),
            prompt_origin: "window".to_string(),
            detected_at,
        }
    }

    #[test]
    fn fresh_monitor_prompt_context_is_accepted() {
        assert!(context(Instant::now() - Duration::from_millis(500)).is_fresh());
    }

    #[test]
    fn stale_monitor_prompt_context_is_not_fresh() {
        assert!(!context(
            Instant::now() - super::VERIFIED_PROMPT_CONTEXT_MAX_AGE - Duration::from_millis(1)
        )
        .is_fresh());
    }

    #[test]
    fn stale_monitor_prompt_context_falls_back_to_live_scan() {
        let stale = context(
            Instant::now() - super::VERIFIED_PROMPT_CONTEXT_MAX_AGE - Duration::from_secs(1),
        );
        let mut log = super::DebugLog::new("test".to_string());

        let result = super::select_prompt_and_account(
            &mut log,
            "__must_not_be_used_for_stale_context__",
            &[],
            Some(&stale),
            &|| panic!("guard should not run for stale context"),
        );

        match result {
            Ok(_) => panic!("stale context unexpectedly selected a prompt"),
            Err(error) => assert_eq!(error, "windows_app_trust_check_failed"),
        }
        assert_eq!(
            super::log_value(&log, "prompt_context_present").as_deref(),
            Some("true")
        );
        assert_eq!(
            super::log_value(&log, "prompt_context_source").as_deref(),
            Some("monitor_snapshot_stale_live_scan")
        );
        assert_eq!(
            super::log_value(&log, "prompt_context_revalidation_result").as_deref(),
            Some("stale_live_scan")
        );
        assert_eq!(
            super::log_value(&log, "prompt_detected").as_deref(),
            Some("false")
        );
    }

    #[test]
    fn fresh_monitor_prompt_context_revalidation_failure_falls_back_to_live_scan() {
        let fresh = context(Instant::now());
        let mut log = super::DebugLog::new("test".to_string());

        let result = super::select_prompt_and_account(
            &mut log,
            "__must_not_be_used_for_fresh_context__",
            &[],
            Some(&fresh),
            &|| panic!("guard should not run without a revalidated prompt"),
        );

        match result {
            Ok(_) => panic!("fresh context unexpectedly selected a prompt"),
            Err(error) => assert_eq!(error, "windows_app_trust_check_failed"),
        }
        assert_eq!(
            super::log_value(&log, "prompt_context_present").as_deref(),
            Some("true")
        );
        assert_eq!(
            super::log_value(&log, "prompt_context_source").as_deref(),
            Some("monitor_snapshot_fresh_live_scan")
        );
        assert!(super::log_value(&log, "prompt_context_revalidation_result")
            .as_deref()
            .is_some_and(|value| value.ends_with("_live_scan")));
    }

    #[test]
    fn macos_account_matching_allows_one_email_match() {
        let accounts = vec![account("a1", "user@example.com")];

        let matches = super::matching_macos_accounts(&accounts, " user@example.com ");

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].id.as_str(), "a1");
    }

    #[test]
    fn macos_account_matching_returns_duplicate_email_matches() {
        let accounts = vec![
            account("a1", "user@example.com"),
            account("a2", "USER@example.com"),
            account("a3", "other@example.com"),
        ];

        let matches = super::matching_macos_accounts(&accounts, " user@example.com ");

        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].id.as_str(), "a1");
        assert_eq!(matches[1].id.as_str(), "a2");
    }

    #[test]
    fn macos_account_matching_keeps_all_duplicate_email_matches() {
        let accounts = vec![
            account("a1", "user@example.com"),
            account("a2", "user@example.com"),
            account("a3", "USER@example.com"),
        ];

        let matches = super::matching_macos_accounts(&accounts, "user@example.com");

        assert_eq!(matches.len(), 3);
        assert_eq!(matches[0].id.as_str(), "a1");
        assert_eq!(matches[1].id.as_str(), "a2");
        assert_eq!(matches[2].id.as_str(), "a3");
    }

    #[test]
    fn macos_account_matching_reports_enabled_match_without_saved_password() {
        let accounts = vec![account_with_saved_password("a1", "user@example.com", false)];

        let saved_matches = super::matching_macos_accounts(&accounts, "user@example.com");
        let enabled_matches = super::enabled_email_match_count(&accounts, " user@example.com ");

        assert!(saved_matches.is_empty());
        assert_eq!(enabled_matches, 1);
        assert_eq!(
            super::account_match_failure_reason(enabled_matches),
            "visible_prompt_email_matches_no_saved_password"
        );
    }
}
#[cfg(target_os = "macos")]
fn post_check_state(
    _settings: &AppSettings,
    prompt_pid: i32,
    prompt_window_title: &str,
    expected_email: &str,
    submitted_prompt: Option<&crate::macos_ax::MacosSubmittedPrompt>,
    timeout: Duration,
) -> &'static str {
    crate::macos_ax::post_check_state(
        crate::config::TARGET_APP_NAME,
        prompt_pid,
        prompt_window_title,
        expected_email,
        submitted_prompt,
        timeout,
    )
}
#[cfg(target_os = "macos")]
fn macos_fill_method(method: FillMethod) -> crate::macos_ax::MacosFillMethod {
    match method {
        // Keep the legacy debug-fill option name for compatibility; macOS password
        // insertion itself is target-bound AXValue only.
        FillMethod::Keyboard => crate::macos_ax::MacosFillMethod::DirectAxValue,
    }
}

#[cfg(target_os = "macos")]
fn apply_macos_fill_fields(log: &mut DebugLog, result: &crate::macos_ax::MacosFillResult) {
    log.set("password_field_detected", "true");
    log.set("password_field_role", result.password_field_role.clone());
    log.set(
        "password_field_focused",
        result.password_field_focused.to_string(),
    );
    log.set("fill_method", result.fill_method);
    log.set("fill_attempted", "true");
    log.set("fill_status", result.fill_status);
    log.set(
        "submit_button_ready_after_fill",
        result.submit_button_ready_after_fill.to_string(),
    );
    if result.password_field_description_present {
        log.set("password_field_description_redacted", "[redacted]");
    }
}

#[cfg(target_os = "macos")]
fn apply_macos_submit_fields(log: &mut DebugLog, result: &crate::macos_ax::MacosSubmitResult) {
    log.set("submit_method", result.submit_method);
    log.set("submit_attempted", "true");
    log.set("submit_status", result.submit_status);
    log.set("axpress_attempted", result.axpress_attempted.to_string());
    log.set("axpress_result", result.axpress_result);
    log.set(
        "enter_fallback_attempted",
        result.enter_fallback_attempted.to_string(),
    );
    log.set("enter_fallback_result", result.enter_fallback_result);
}
#[cfg(target_os = "macos")]
fn ax_is_process_trusted() -> bool {
    crate::autologin::accessibility_is_trusted()
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

#[cfg(target_os = "windows")]
fn apply_current_process_fields(log: &mut DebugLog) -> PathBuf {
    let current_exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("<unknown>"));
    log.set("current_process_path", current_exe.display().to_string());
    log.set("executable_path", current_exe.display().to_string());
    log.set(
        "current_launch_kind",
        if current_exe.parent().is_some_and(|parent| {
            parent.ends_with("target\\debug") || parent.ends_with("target\\release")
        }) {
            "cargo_or_raw_binary"
        } else {
            "installed_exe"
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

#[cfg(target_os = "windows")]
fn apply_windows_target_fields(log: &mut DebugLog, target: &crate::windows_ui::WindowsTarget) {
    log.set("windows_app_pid", target.process_id.to_string());
    log.set("windows_app_path", target.process_path.clone());
    log.set("windows_app_bundle_id", String::new());
    log.set("windows_app_team_id", String::new());
    log.set("windows_app_frontmost", target.frontmost.to_string());
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
    parse_current_signing_info(&String::from_utf8_lossy(&output.stderr))
}

#[cfg(target_os = "macos")]
fn parse_current_signing_info(codesign_stderr: &str) -> CurrentSigningInfo {
    let mut identity = if codesign_stderr.contains("Signature=adhoc") {
        "ad_hoc".to_string()
    } else {
        "unknown".to_string()
    };
    let mut identifier = String::new();
    let mut team_id = String::new();
    for line in codesign_stderr.lines() {
        let line = line.trim();
        if let Some(authority) = line.strip_prefix("Authority=") {
            identity = coarse_signing_identity(authority);
        } else if let Some(value) = line.strip_prefix("Identifier=") {
            identifier = diagnostic_presence(value);
        } else if let Some(value) = line.strip_prefix("TeamIdentifier=") {
            team_id = diagnostic_presence(value);
        }
    }
    CurrentSigningInfo {
        identity,
        identifier,
        team_id,
    }
}

fn coarse_signing_identity(value: &str) -> String {
    let value = sanitize_log_value(value);
    if value.is_empty() {
        return String::new();
    }
    let lower = value.to_ascii_lowercase();
    if lower == "adhoc" || lower == "ad_hoc" || lower.contains("signature=adhoc") {
        return "ad_hoc".to_string();
    }
    if lower.starts_with("developer id application:") {
        return "developer_id_application".to_string();
    }
    if lower.starts_with("developer id installer:") {
        return "developer_id_installer".to_string();
    }
    if lower.starts_with("apple development:") {
        return "apple_development".to_string();
    }
    if lower.starts_with("apple distribution:") {
        return "apple_distribution".to_string();
    }
    if lower.starts_with("mac developer:") {
        return "mac_developer".to_string();
    }
    if lower.starts_with("3rd party mac developer application:") {
        return "app_store_distribution".to_string();
    }
    if lower == "unknown" {
        return "unknown".to_string();
    }
    "signed".to_string()
}

fn diagnostic_presence(value: &str) -> String {
    let value = sanitize_log_value(value);
    if value.is_empty() {
        return String::new();
    }
    let lower = value.to_ascii_lowercase();
    if lower == "not set" || lower == "none" || lower == "unknown" {
        return lower.replace(' ', "_");
    }
    "present".to_string()
}

pub(crate) fn redacted_email(email: &str) -> String {
    let _ = email;
    "[email]".to_string()
}

fn make_attempt_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!("{}-{nanos}", std::process::id())
}

fn sanitize_log_field(key: &str, value: &str) -> String {
    match key {
        "selected_account_id" | "keychain_account_key" => redacted_account_presence(value),
        "current_signing_identity" => coarse_signing_identity(value),
        "current_bundle_id" | "keychain_process_bundle_id" => diagnostic_presence(value),
        "current_signing_identifier"
        | "current_team_id"
        | "windows_app_team_id"
        | "keychain_process_signing_identifier"
        | "keychain_process_team_id" => diagnostic_presence(value),
        "current_process_path"
        | "app_bundle_path"
        | "executable_path"
        | "windows_app_path"
        | "keychain_process_path" => crate::user_paths::redacted_path(value),
        "failure_reason" => sanitize_failure_reason(value),
        _ => sanitize_log_value(value),
    }
}

fn redacted_account_presence(value: &str) -> String {
    let value = sanitize_log_value(value);
    if value.is_empty() {
        String::new()
    } else {
        "[account]".to_string()
    }
}

fn sanitize_log_value(value: &str) -> String {
    let value = value.replace(['\r', '\n'], " ");
    if value.trim().is_empty() {
        return String::new();
    }
    value
}

fn sanitize_failure_reason(value: &str) -> String {
    let value = sanitize_log_value(value);
    if value.is_empty() {
        return value;
    }

    const DYNAMIC_PREFIXES: &[&str] = &[
        "attempt_cancelled_after_password_load_",
        "attempt_cancelled_",
        "credential_prompt_activation_failed_",
        "fill_failed_",
        "fill_script_failed_",
        "post_submit_state_",
        "prompt_detection_failed_",
        "prompt_context_live_revalidation_failed_",
        "submit_failed_",
        "submit_script_failed_",
        "windows_uia_inspection_failed_",
        "windows_uia_reinspection_failed_",
    ];

    for prefix in DYNAMIC_PREFIXES {
        if value.starts_with(prefix) {
            return prefix.trim_end_matches('_').to_string();
        }
    }

    let allowed = value
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
    if allowed && value.len() <= 96 {
        value
    } else {
        "redacted_failure".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::redacted_email;
    #[cfg(all(
        feature = "debug-fill",
        debug_assertions,
        not(waal_release_profile),
        not(target_os = "windows")
    ))]
    use super::FillMethod;

    #[test]
    fn redacted_email_is_not_stable_identifier() {
        assert_eq!(redacted_email("user@example.com"), "[email]");
        assert_eq!(redacted_email("other@example.com"), "[email]");
    }

    #[test]
    fn account_id_fields_are_not_stable_identifiers() {
        let mut log = super::DebugLog::new("test".to_string());
        log.set("selected_account_id", "account-1".to_string());
        log.set("keychain_account_key", "user@example.com".to_string());

        let report = log.finish(None);
        let selected = report.field("selected_account_id").unwrap();
        let keychain_key = report.field("keychain_account_key").unwrap();
        let summary = report.summary_line();

        assert_eq!(selected, "[account]");
        assert_eq!(keychain_key, "[account]");
        assert!(summary.contains("selected_account_id=[account]"));
        assert!(!summary.contains("account-1"));
        assert!(!summary.contains("user@example.com"));
        assert!(!summary.contains("[account:"));
    }

    #[test]
    fn empty_account_id_fields_stay_empty() {
        let mut log = super::DebugLog::new("test".to_string());
        log.set("selected_account_id", "   ".to_string());
        log.set("keychain_account_key", String::new());

        let report = log.finish(None);

        assert_eq!(report.field("selected_account_id").unwrap(), "");
        assert_eq!(report.field("keychain_account_key").unwrap(), "");
    }

    #[test]
    fn pre_password_load_failure_records_skip_reason() {
        let report = super::DebugLog::new("test".to_string()).fail("visible_prompt_email_missing");

        assert_eq!(report.field("password_load_attempted").unwrap(), "false");
        assert_eq!(
            report.field("password_load_skip_reason").unwrap(),
            "visible_prompt_email_missing"
        );
        assert!(report
            .summary_line()
            .contains("password_load_skip_reason=visible_prompt_email_missing"));
    }

    #[test]
    fn pre_password_revalidation_failure_records_skip_reason() {
        let report =
            super::DebugLog::new("test".to_string()).fail("pre_password_revalidation_failed");

        assert_eq!(report.field("password_load_attempted").unwrap(), "false");
        assert_eq!(report.field("password_loaded").unwrap(), "false");
        assert_eq!(
            report.field("password_load_skip_reason").unwrap(),
            "pre_password_revalidation_failed"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_pre_password_revalidation_stays_before_keychain_load() {
        let implementation = include_str!("debug_fill.rs")
            .split("fn fill_current_prompt_once_macos")
            .nth(1)
            .and_then(|tail| {
                tail.split(
                    "\n#[cfg(target_os = \"macos\")]\nfn detect_current_prompt_context_macos",
                )
                .next()
            })
            .unwrap();

        let preflight = implementation
            .find("preflight_password_load_prompt")
            .unwrap();
        let password_load_marker = implementation.find("password_load_attempted").unwrap();
        let keychain_load = implementation
            .find("storage::load_password_for_prompt_with_timing")
            .unwrap();
        let final_fill = implementation.find("fill_verified_password").unwrap();

        assert!(preflight < password_load_marker);
        assert!(password_load_marker < keychain_load);
        assert!(keychain_load < final_fill);
        assert!(!implementation.contains("crate::macos_ax::fill_password("));
    }

    #[test]
    fn password_load_failure_does_not_record_skip_reason() {
        let mut log = super::DebugLog::new("test".to_string());
        log.set("password_load_attempted", "true");

        let report = log.fail("password_load_failed_for_selected_account");

        assert_eq!(report.field("password_load_attempted").unwrap(), "true");
        assert_eq!(report.field("password_loaded").unwrap(), "false");
        assert_eq!(report.field("password_load_skip_reason").unwrap(), "");
    }

    #[test]
    fn post_password_load_failure_preserves_loaded_marker() {
        let mut log = super::DebugLog::new("test".to_string());
        log.set("password_load_attempted", "true");
        log.set("password_loaded", "true");

        let report = log.fail("fill_script_failed_password_field_not_ready");

        assert!(!report.success);
        assert_eq!(report.field("password_load_attempted").unwrap(), "true");
        assert_eq!(report.field("password_loaded").unwrap(), "true");
        assert_eq!(report.field("password_load_skip_reason").unwrap(), "");
        assert_eq!(report.failure_reason.as_deref(), Some("fill_script_failed"));
        assert!(report.summary_line().contains("password_loaded=true"));
    }

    #[test]
    fn path_fields_are_redacted_to_hash_without_leaf_name() {
        let mut log = super::DebugLog::new("test".to_string());
        log.set(
            "current_process_path",
            "/Users/alice/private/project/target/debug/windows-app-autologin",
        );
        let report = log.finish(None);
        let value = report.field("current_process_path").unwrap();

        assert_eq!(value, "[path]");
        assert!(!value.contains("windows-app-autologin"));
        assert!(!value.contains("/Users/alice"));
        assert!(!value.contains("private"));
        assert!(!value.contains("project"));
    }

    #[test]
    fn signing_fields_are_redacted_before_diagnostic_output() {
        let mut log = super::DebugLog::new("test".to_string());
        log.set(
            "current_signing_identity",
            "Developer ID Application: Jane Doe (ABCDE12345)",
        );
        log.set("current_bundle_id", "com.jane.secret.autologin");
        log.set("current_signing_identifier", "com.jane.secret.autologin");
        log.set("current_team_id", "ABCDE12345");
        log.set("keychain_process_bundle_id", "com.jane.secret.autologin");
        log.set(
            "keychain_process_signing_identifier",
            "com.jane.secret.autologin",
        );
        log.set("keychain_process_team_id", "ABCDE12345");
        log.set("windows_app_team_id", "UBF8T346G9");

        let report = log.finish(None);
        let serialized = serde_json::to_string(&report).unwrap();

        assert_eq!(
            report.field("current_signing_identity").unwrap(),
            "developer_id_application"
        );
        assert_eq!(report.field("current_bundle_id").unwrap(), "present");
        assert_eq!(
            report.field("current_signing_identifier").unwrap(),
            "present"
        );
        assert_eq!(report.field("current_team_id").unwrap(), "present");
        assert_eq!(
            report.field("keychain_process_bundle_id").unwrap(),
            "present"
        );
        assert_eq!(
            report.field("keychain_process_signing_identifier").unwrap(),
            "present"
        );
        assert_eq!(report.field("keychain_process_team_id").unwrap(), "present");
        assert_eq!(report.field("windows_app_team_id").unwrap(), "present");
        assert!(!serialized.contains("Jane Doe"));
        assert!(!serialized.contains("ABCDE12345"));
        assert!(!serialized.contains("com.jane.secret.autologin"));
        assert!(!serialized.contains("UBF8T346G9"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn codesign_parser_keeps_only_coarse_signing_status() {
        let info = super::parse_current_signing_info(
            "Executable=/private/app\nIdentifier=com.jane.secret.autologin\nAuthority=Developer ID Application: Jane Doe (ABCDE12345)\nTeamIdentifier=ABCDE12345\n",
        );

        assert_eq!(info.identity, "developer_id_application");
        assert_eq!(info.identifier, "present");
        assert_eq!(info.team_id, "present");
        assert!(!info.identity.contains("Jane"));
        assert!(!info.identifier.contains("com.jane"));
        assert!(!info.team_id.contains("ABCDE12345"));
    }

    #[cfg(all(
        feature = "debug-fill",
        debug_assertions,
        not(waal_release_profile),
        not(target_os = "windows")
    ))]
    #[test]
    fn direct_fill_method_is_not_available_off_windows() {
        let args = vec!["--fill-method=direct".to_string()];

        assert!(FillMethod::parse(&args).is_err());
    }
}
