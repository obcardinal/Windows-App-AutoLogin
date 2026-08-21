use crate::config::Config;
use std::sync::Arc;
#[cfg(target_os = "macos")]
use tracing::debug;

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum MonitorStatus {
    Connected,
    ProcessNotFound,
    LoginWindowDetected {
        process_id: i32,
        window_handle: isize,
        window_title: String,
        prompt_email: Option<String>,
        prompt_origin: String,
    },
    Unknown,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct MonitorObservation {
    pub(crate) status: MonitorStatus,
    pub(crate) definitive_no_prompt: bool,
}

impl MonitorObservation {
    #[allow(dead_code)]
    pub(crate) fn indeterminate(status: MonitorStatus) -> Self {
        Self {
            status,
            definitive_no_prompt: false,
        }
    }
}

pub(crate) struct AppMonitor {
    config: Arc<Config>,
}

impl AppMonitor {
    pub(crate) fn new(config: Arc<Config>) -> Self {
        Self { config }
    }

    pub(crate) fn check_status(&self) -> MonitorObservation {
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
            MonitorObservation::indeterminate(MonitorStatus::Unknown)
        }
    }
}

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
    title: String,
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone)]
struct FormInspection {
    process_id: i32,
    title: String,
    prompt_email: Option<String>,
    prompt_origin: &'static str,
}

#[cfg(target_os = "macos")]
fn check_status_macos(config: &Config) -> MonitorObservation {
    check_status_macos_with_inspector(config, inspect_windows_app_macos_native)
}

#[cfg(target_os = "macos")]
fn check_status_macos_with_inspector<F>(config: &Config, inspect: F) -> MonitorObservation
where
    F: FnOnce(&str, bool) -> WindowInspection,
{
    let inspection = inspect(&config.macos_app_name, true);
    let status = status_from_macos_inspection(&inspection);
    MonitorObservation {
        definitive_no_prompt: matches!(status, MonitorStatus::ProcessNotFound)
            && inspection.process_found == Some(false),
        status,
    }
}

#[cfg(target_os = "macos")]
fn status_from_macos_inspection(inspection: &WindowInspection) -> MonitorStatus {
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

    debug!(
        "macOS trusted app window count: {}",
        inspection.titles.len()
    );

    if let [form] = inspection.forms.as_slice() {
        debug!("Login dialog detected on macOS inside trusted Windows App process");
        return MonitorStatus::LoginWindowDetected {
            process_id: form.process_id,
            window_handle: 0,
            window_title: form.title.clone(),
            prompt_email: form.prompt_email.clone(),
            prompt_origin: form.prompt_origin.to_string(),
        };
    }

    if inspection.forms.len() > 1 {
        debug!("Multiple macOS login forms were reported; refusing ambiguous automation");
        return MonitorStatus::Unknown;
    }

    if inspection
        .titles
        .iter()
        .any(|title| is_probable_session_window_title(&title.title))
    {
        debug!("macOS session window appears active");
        MonitorStatus::Connected
    } else {
        debug!("Windows App running but no session window detected on macOS");
        MonitorStatus::Unknown
    }
}

#[cfg(target_os = "macos")]
fn inspect_windows_app_macos_native(app_name: &str, _include_form_text: bool) -> WindowInspection {
    match crate::macos_ax::inspect(app_name) {
        Ok(inspection) => {
            // macos_ax::prompt is populated only for one unambiguous live
            // foreground prompt. Never promote background forms or a login-like
            // background window title into an automatic-fill event.
            let foreground_form = inspection.prompt.as_ref().map(|prompt| FormInspection {
                process_id: prompt.target.process_id,
                title: prompt.target.window_title.clone(),
                prompt_email: prompt.email.clone(),
                prompt_origin: prompt.origin.as_str(),
            });
            WindowInspection {
                // A trusted process may be running even when AX refuses the
                // application/window lookup. Keep native process presence
                // separate from AX target/window availability so an AX error
                // can never be mistaken for a verified process exit.
                process_found: Some(inspection.process_found),
                titles: inspection
                    .window_titles
                    .into_iter()
                    .map(|title| WindowTitle { title: title.title })
                    .collect(),
                forms: foreground_form.into_iter().collect(),
            }
        }
        Err(e) => {
            debug!(error = %e, "Native macOS AX inspection failed");
            WindowInspection::default()
        }
    }
}

#[cfg(target_os = "macos")]
fn is_probable_session_window_title(title: &str) -> bool {
    let trimmed = title.trim();
    if trimmed.is_empty() {
        return false;
    }

    !NON_SESSION_TITLE_KEYWORDS
        .iter()
        .any(|keyword| contains_keyword(trimmed, keyword))
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
const NON_SESSION_TITLE_KEYWORDS: &[&str] = &[
    "devices",
    "windows app",
    "settings",
    "preferences",
    "about windows app",
    "connection center",
    "connection lost",
    "disconnected",
    "unable to connect",
    "add pc",
    "add workspace",
    "workspaces",
    "workspace",
    "accounts",
    "sign in",
    "authentication",
    "credentials",
    "login",
    "password",
];

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use crate::config::Config;

    use super::{
        check_status_macos_with_inspector, contains_keyword, is_probable_session_window_title,
        status_from_macos_inspection, FormInspection, MonitorStatus, WindowInspection, WindowTitle,
    };

    #[test]
    fn contains_keyword_handles_non_ascii_boundaries() {
        assert!(contains_keyword("Введите Пароль для продолжения", "Пароль"));
        assert!(!contains_keyword("ПредПароль", "Пароль"));
    }

    #[test]
    fn session_title_filter_rejects_shell_windows_but_allows_desktops() {
        assert!(!is_probable_session_window_title("Windows App"));
        assert!(!is_probable_session_window_title("About Windows App"));
        assert!(!is_probable_session_window_title("Connection Center"));
        assert!(!is_probable_session_window_title("Workspaces"));
        assert!(!is_probable_session_window_title("Accounts"));
        assert!(!is_probable_session_window_title("Add PC"));
        assert!(!is_probable_session_window_title("Disconnected from VM"));
        assert!(!is_probable_session_window_title(
            "Unable to connect to host"
        ));
        assert!(is_probable_session_window_title("Finance Desktop 01"));
        assert!(is_probable_session_window_title("corp-vm-7"));
    }

    #[test]
    fn check_status_macos_detects_login_window_from_inspection() {
        let config = Config {
            macos_app_name: crate::config::TARGET_APP_NAME.to_string(),
        };

        let observation =
            check_status_macos_with_inspector(&config, |_app_name, _include_form_text| {
                inspection(
                    vec![title(42, "Sign in")],
                    vec![form(42, "Sign in", Some("user@example.com"))],
                )
            });

        assert_eq!(
            observation.status,
            login_status(42, "Sign in", Some("user@example.com"))
        );
        assert!(!observation.definitive_no_prompt);
    }

    #[test]
    fn macos_only_verified_native_process_absence_is_definitive() {
        let config = Config {
            macos_app_name: crate::config::TARGET_APP_NAME.to_string(),
        };

        let running_but_ax_unavailable =
            check_status_macos_with_inspector(&config, |_, _| WindowInspection {
                process_found: Some(true),
                ..Default::default()
            });
        assert_eq!(running_but_ax_unavailable.status, MonitorStatus::Unknown);
        assert!(!running_but_ax_unavailable.definitive_no_prompt);

        let connected = check_status_macos_with_inspector(&config, |_, _| {
            inspection(vec![title(42, "Finance Desktop 01")], vec![])
        });
        assert_eq!(connected.status, MonitorStatus::Connected);
        assert!(!connected.definitive_no_prompt);

        let native_enumeration_failed =
            check_status_macos_with_inspector(&config, |_, _| WindowInspection::default());
        assert_eq!(native_enumeration_failed.status, MonitorStatus::Unknown);
        assert!(!native_enumeration_failed.definitive_no_prompt);

        let verified_absence =
            check_status_macos_with_inspector(&config, |_, _| WindowInspection {
                process_found: Some(false),
                ..Default::default()
            });
        assert_eq!(verified_absence.status, MonitorStatus::ProcessNotFound);
        assert!(verified_absence.definitive_no_prompt);
    }

    #[test]
    fn login_like_background_title_without_foreground_form_is_not_automated() {
        let status = status_from_macos_inspection(&inspection(vec![title(42, "Sign in")], vec![]));

        assert_eq!(status, MonitorStatus::Unknown);
    }

    #[test]
    fn sole_foreground_prompt_is_authoritative_and_multiple_forms_fail_closed() {
        let foreground = inspection(
            vec![title(42, "Unrelated background window")],
            vec![form(77, "Sign in", Some("person@example.com"))],
        );
        assert_eq!(
            status_from_macos_inspection(&foreground),
            login_status(77, "Sign in", Some("person@example.com"))
        );

        let ambiguous = inspection(
            vec![title(42, "Sign in"), title(43, "Sign in")],
            vec![
                form(42, "Sign in", Some("person@example.com")),
                form(43, "Sign in", Some("other@example.com")),
            ],
        );
        assert_eq!(
            status_from_macos_inspection(&ambiguous),
            MonitorStatus::Unknown
        );
    }

    fn login_status(
        process_id: i32,
        window_title: &str,
        prompt_email: Option<&str>,
    ) -> MonitorStatus {
        MonitorStatus::LoginWindowDetected {
            process_id,
            window_handle: 0,
            window_title: window_title.to_string(),
            prompt_email: prompt_email.map(str::to_string),
            prompt_origin: "window".to_string(),
        }
    }

    fn inspection(titles: Vec<WindowTitle>, forms: Vec<FormInspection>) -> WindowInspection {
        WindowInspection {
            process_found: Some(true),
            titles,
            forms,
        }
    }

    fn title(_process_id: i32, title: &str) -> WindowTitle {
        WindowTitle {
            title: title.to_string(),
        }
    }

    fn form(process_id: i32, title: &str, prompt_email: Option<&str>) -> FormInspection {
        FormInspection {
            process_id,
            title: title.to_string(),
            prompt_email: prompt_email.map(str::to_string),
            prompt_origin: "window",
        }
    }
}
