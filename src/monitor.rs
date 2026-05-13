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
    check_status_macos_with_inspector(config, inspect_windows_app_macos_native)
}

#[cfg(target_os = "macos")]
fn check_status_macos_with_inspector<F>(config: &Config, inspect: F) -> MonitorStatus
where
    F: FnOnce(&str, bool) -> WindowInspection,
{
    let inspection = inspect(&config.macos_app_name, true);
    status_from_macos_inspection(&inspection)
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

    for title in &inspection.titles {
        for keyword in LOGIN_TITLE_KEYWORDS {
            if contains_keyword(&title.title, keyword) {
                debug!("Login window detected on macOS by title keyword");
                let form = matching_form(inspection, title.process_id, &title.title);
                return MonitorStatus::LoginWindowDetected {
                    process_id: title.process_id,
                    window_title: title.title.clone(),
                    prompt_email: form.and_then(|form| form.prompt_email.clone()),
                };
            }
        }
    }

    if let Some(dialog_form) = inspection.forms.first() {
        let form = matching_form(inspection, dialog_form.process_id, &dialog_form.title)
            .cloned()
            .unwrap_or_else(|| dialog_form.clone());
        debug!("Login dialog detected on macOS inside trusted Windows App process");
        return MonitorStatus::LoginWindowDetected {
            process_id: form.process_id,
            window_title: form.title,
            prompt_email: form.prompt_email,
        };
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
        Ok(inspection) => WindowInspection {
            process_found: Some(inspection.target.is_some()),
            titles: inspection
                .window_titles
                .into_iter()
                .map(|title| WindowTitle {
                    process_id: title.process_id,
                    title: title.title,
                })
                .collect(),
            forms: inspection
                .forms
                .into_iter()
                .map(|form| FormInspection {
                    process_id: form.process_id,
                    title: form.title,
                    prompt_email: form.prompt_email,
                })
                .collect(),
        },
        Err(e) => {
            debug!(error = %e, "Native macOS AX inspection failed");
            WindowInspection::default()
        }
    }
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
];

#[cfg(target_os = "macos")]
const NON_SESSION_TITLE_KEYWORDS: &[&str] = &[
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
    fn extracts_email_like_text() {
        assert_eq!(
            crate::macos_ax::extract_email_like("Signed in as user.name+rdp@example.com"),
            Some("user.name+rdp@example.com".to_string())
        );
        assert_eq!(crate::macos_ax::extract_email_like("No email here"), None);
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

    #[test]
    fn check_status_macos_uses_one_detailed_inspection() {
        let config = Config {
            macos_app_name: "Windows App".to_string(),
        };
        let mut calls = Vec::new();

        let status = check_status_macos_with_inspector(&config, |app_name, include_form_text| {
            calls.push((app_name.to_string(), include_form_text));
            inspection(
                vec![title(42, "Sign in")],
                vec![form(42, "Sign in", Some("user@example.com"))],
            )
        });

        assert_eq!(calls, vec![("Windows App".to_string(), true)]);
        assert_eq!(
            status,
            MonitorStatus::LoginWindowDetected {
                process_id: 42,
                window_title: "Sign in".to_string(),
                prompt_email: Some("user@example.com".to_string()),
            }
        );
    }

    #[test]
    fn title_detection_uses_prompt_email_from_same_inspection() {
        let status = status_from_macos_inspection(&inspection(
            vec![title(42, "Sign in")],
            vec![form(42, "Sign in", Some("user@example.com"))],
        ));

        assert_eq!(
            status,
            MonitorStatus::LoginWindowDetected {
                process_id: 42,
                window_title: "Sign in".to_string(),
                prompt_email: Some("user@example.com".to_string()),
            }
        );
    }

    #[test]
    fn title_detection_ignores_prompt_email_from_other_window() {
        let status = status_from_macos_inspection(&inspection(
            vec![title(42, "Sign in")],
            vec![
                form(43, "Sign in", Some("other@example.com")),
                form(42, "Different", Some("wrong@example.com")),
            ],
        ));

        assert_eq!(
            status,
            MonitorStatus::LoginWindowDetected {
                process_id: 42,
                window_title: "Sign in".to_string(),
                prompt_email: None,
            }
        );
    }

    #[test]
    fn form_detection_uses_prompt_email_from_same_inspection() {
        let status = status_from_macos_inspection(&inspection(
            vec![title(77, "Finance Desktop 01")],
            vec![form(77, "Finance Desktop 01", Some("person@example.com"))],
        ));

        assert_eq!(
            status,
            MonitorStatus::LoginWindowDetected {
                process_id: 77,
                window_title: "Finance Desktop 01".to_string(),
                prompt_email: Some("person@example.com".to_string()),
            }
        );
    }

    #[test]
    fn form_detection_prefers_later_matching_prompt_email_for_dialog() {
        let status = status_from_macos_inspection(&inspection(
            vec![title(77, "Finance Desktop 01")],
            vec![
                form(77, "Finance Desktop 01", None),
                form(77, "Finance Desktop 01", Some("person@example.com")),
            ],
        ));

        assert_eq!(
            status,
            MonitorStatus::LoginWindowDetected {
                process_id: 77,
                window_title: "Finance Desktop 01".to_string(),
                prompt_email: Some("person@example.com".to_string()),
            }
        );
    }

    #[test]
    fn form_detection_does_not_steal_email_from_unrelated_form() {
        let status = status_from_macos_inspection(&inspection(
            vec![title(77, "Finance Desktop 01")],
            vec![
                form(77, "Finance Desktop 01", None),
                form(88, "Sign in", Some("other@example.com")),
            ],
        ));

        assert_eq!(
            status,
            MonitorStatus::LoginWindowDetected {
                process_id: 77,
                window_title: "Finance Desktop 01".to_string(),
                prompt_email: None,
            }
        );
    }

    fn inspection(titles: Vec<WindowTitle>, forms: Vec<FormInspection>) -> WindowInspection {
        WindowInspection {
            process_found: Some(true),
            titles,
            forms,
        }
    }

    fn title(process_id: i32, title: &str) -> WindowTitle {
        WindowTitle {
            process_id,
            title: title.to_string(),
        }
    }

    fn form(process_id: i32, title: &str, prompt_email: Option<&str>) -> FormInspection {
        FormInspection {
            process_id,
            title: title.to_string(),
            prompt_email: prompt_email.map(str::to_string),
        }
    }
}
