#[cfg(feature = "diagnostics-ui")]
use crate::app::AutoLoginApp;
#[cfg(feature = "diagnostics-ui")]
use crate::ui::theme;
#[cfg(feature = "diagnostics-ui")]
use eframe::egui;

#[cfg(feature = "diagnostics-ui")]
pub fn show(ui: &mut egui::Ui, app: &mut AutoLoginApp) {
    theme::page_header(
        ui,
        "Diagnose",
        "Inspect Windows App windows and accessibility elements on macOS.",
        |ui| {
            if ui
                .add_enabled(
                    !app.runtime_status_running,
                    theme::secondary_button("Refresh Status"),
                )
                .clicked()
            {
                start_runtime_status(app);
            }
            if ui
                .add_enabled(
                    !app.diagnose_running,
                    theme::primary_button("Run Diagnosis"),
                )
                .clicked()
            {
                start_diagnosis(app);
            }
            let can_copy = !app.diagnose_running
                && !app.diagnose_result.is_empty()
                && !app.diagnose_result.starts_with("Running diagnosis");
            if ui
                .add_enabled(can_copy, theme::secondary_button("Copy Output"))
                .clicked()
            {
                ui.ctx().copy_text(app.diagnose_result.clone());
                app.set_status("Diagnostic output copied");
            }
            if ui
                .add_enabled(
                    !app.diagnose_running && !app.diagnose_result.is_empty(),
                    theme::secondary_button("Clear Diagnosis"),
                )
                .clicked()
            {
                clear_diagnosis(app);
            }
        },
    );

    theme::compact_frame().show(ui, |ui| {
        ui.heading("Runtime status");
        if app.runtime_status_running {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Refreshing status...");
            });
        }
        if let Some(report) = &app.runtime_status_report {
            show_report_fields(ui, report, RUNTIME_STATUS_FIELDS);
        } else {
            ui.label(theme::muted(
                "Refresh status to inspect the bundled app identity and visible prompt state.",
            ));
        }
    });
    ui.add_space(8.0);

    theme::compact_frame().show(ui, |ui| {
        ui.heading("Last fill attempt");
        if let Some(report) = &app.last_fill_report {
            show_report_fields(ui, report, LAST_FILL_FIELDS);
        } else {
            ui.label(theme::muted("No fill attempt has been reported yet."));
        }
    });
    ui.add_space(8.0);

    if app.diagnose_running {
        theme::glass_frame().show(ui, |ui| {
            ui.spinner();
            ui.label("Running diagnosis...");
            ui.label(theme::muted(
                "Reading visible windows and accessibility elements.",
            ));
        });
        ui.add_space(8.0);
    }

    let has_output =
        !app.diagnose_result.is_empty() && !app.diagnose_result.starts_with("Running diagnosis");

    if !has_output {
        theme::glass_frame().show(ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.heading("No diagnostic output");
                ui.label(theme::muted(
                    "Run a diagnosis to inspect visible Windows App windows and controls.",
                ));
                ui.add_space(6.0);
                if ui
                    .add_enabled(
                        !app.diagnose_running,
                        theme::primary_button("Run Diagnosis"),
                    )
                    .clicked()
                {
                    start_diagnosis(app);
                }
            });
        });
        return;
    }

    theme::compact_frame().show(ui, |ui| {
        egui::ScrollArea::vertical()
            .auto_shrink([false; 2])
            .show(ui, |ui| {
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(&app.diagnose_result)
                            .monospace()
                            .color(theme::TEXT),
                    )
                    .selectable(true),
                );
            });
    });
}

#[cfg(feature = "diagnostics-ui")]
const RUNTIME_STATUS_FIELDS: &[&str] = &[
    "current_process_path",
    "current_bundle_id",
    "current_signing_identity",
    "current_signing_identifier",
    "current_team_id",
    "ax_trusted_for_current_process",
    "is_running_from_target_debug",
    "is_running_from_dist_app",
    "app_bundle_path",
    "executable_path",
    "windows_app_pid",
    "windows_app_bundle_id",
    "windows_app_team_id",
    "windows_app_path",
    "windows_app_frontmost",
    "prompt_context_present",
    "prompt_context_source",
    "prompt_context_age_ms",
    "prompt_context_max_age_ms",
    "prompt_context_revalidation_result",
    "prompt_detected",
    "windows_prompt_trust",
    "password_like_plain_edit_rejected",
    "password_field_reject_reason",
    "password_field_detected",
    "password_field_role",
    "password_field_description_redacted",
    "detected_email_redacted",
    "account_enabled_email_match_count",
    "account_saved_email_match_count",
    "account_match_count",
    "selected_account_id",
    "password_load_attempted",
    "password_loaded",
    "password_load_skip_reason",
    "keychain_service_name",
    "keychain_account_key",
    "keychain_process_path",
    "keychain_process_bundle_id",
    "keychain_process_signing_identifier",
    "keychain_process_team_id",
    "password_load_ms",
    "keychain_query_ms",
    "fill_method",
    "fill_status",
    "submit_method",
    "submit_status",
    "post_check_state",
    "failure_reason",
];

#[cfg(feature = "diagnostics-ui")]
const LAST_FILL_FIELDS: &[&str] = &[
    "ax_trusted_for_current_process",
    "current_process_path",
    "executable_path",
    "app_bundle_path",
    "current_bundle_id",
    "current_signing_identity",
    "current_signing_identifier",
    "current_team_id",
    "current_launch_kind",
    "is_running_from_target_debug",
    "is_running_from_dist_app",
    "windows_app_pid",
    "windows_app_path",
    "windows_app_bundle_id",
    "windows_app_team_id",
    "windows_app_frontmost",
    "prompt_context_present",
    "prompt_context_source",
    "prompt_context_age_ms",
    "prompt_context_max_age_ms",
    "prompt_context_revalidation_result",
    "prompt_detected",
    "windows_prompt_trust",
    "password_like_plain_edit_rejected",
    "password_field_reject_reason",
    "detected_email_redacted",
    "account_enabled_email_match_count",
    "account_saved_email_match_count",
    "account_match_count",
    "selected_account_id",
    "password_load_attempted",
    "password_loaded",
    "password_load_skip_reason",
    "password_load_ms",
    "storage_lookup_start_ms",
    "account_id_lookup_ms",
    "keychain_service_name",
    "keychain_account_key",
    "keychain_process_path",
    "keychain_process_bundle_id",
    "keychain_process_signing_identifier",
    "keychain_process_team_id",
    "keychain_query_start",
    "keychain_query_ms",
    "keychain_prompt_suspected",
    "fallback_lookup_ms",
    "zeroizing_wrap_ms",
    "total_password_load_ms",
    "keychain_error_redacted",
    "password_field_detected",
    "password_field_role",
    "password_field_description_redacted",
    "password_field_focused",
    "fill_method",
    "fill_attempted",
    "fill_status",
    "fill_duration_ms",
    "submit_method",
    "submit_attempted",
    "submit_status",
    "axpress_attempted",
    "axpress_result",
    "enter_fallback_attempted",
    "enter_fallback_result",
    "submit_duration_ms",
    "post_check_state",
    "failure_reason",
];

#[cfg(feature = "diagnostics-ui")]
fn show_report_fields(
    ui: &mut egui::Ui,
    report: &crate::debug_fill::FillAttemptReport,
    keys: &[&str],
) {
    for key in keys {
        ui.horizontal_wrapped(|ui| {
            ui.monospace(format!("{key}:"));
            ui.label(report.field(key).unwrap_or(""));
        });
    }
}

#[cfg(feature = "diagnostics-ui")]
pub(crate) fn poll_diagnosis(app: &mut AutoLoginApp) {
    if let Some(ref rx) = app.diagnose_rx {
        match rx.try_recv() {
            Ok(result) => {
                app.diagnose_result = result;
                app.diagnose_running = false;
                app.diagnose_rx = None;
                app.set_status("Diagnosis complete");
            }
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                app.diagnose_result = "Diagnostic failed: worker stopped unexpectedly".to_string();
                app.diagnose_running = false;
                app.diagnose_rx = None;
                app.set_status("Diagnosis failed");
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
        }
    }
}

#[cfg(feature = "diagnostics-ui")]
fn clear_diagnosis(app: &mut AutoLoginApp) {
    app.diagnose_result.clear();
    app.diagnose_rx = None;
    app.diagnose_running = false;
    app.set_status("Diagnosis cleared");
}

#[cfg(feature = "diagnostics-ui")]
pub(crate) fn poll_runtime_status(app: &mut AutoLoginApp) {
    if let Some(ref rx) = app.runtime_status_rx {
        match rx.try_recv() {
            Ok(report) => {
                app.runtime_status_report = Some(report);
                app.runtime_status_running = false;
                app.runtime_status_rx = None;
                app.set_status("Runtime status refreshed");
            }
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                app.runtime_status_running = false;
                app.runtime_status_rx = None;
                app.set_status("Runtime status failed");
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
        }
    }
}

#[cfg(feature = "diagnostics-ui")]
fn start_diagnosis(app: &mut AutoLoginApp) {
    app.diagnose_running = true;
    app.diagnose_result = "Running diagnosis, please wait...".to_string();

    let (tx, rx) = std::sync::mpsc::channel();
    app.diagnose_rx = Some(rx);
    let app_name = crate::config::TARGET_APP_NAME.to_string();

    std::thread::spawn(move || {
        let output = match windows_app_autologin::diagnose::run_for_app(&app_name) {
            Ok(report) => {
                windows_app_autologin::diagnose::cap_diagnostic_output(report.to_plaintext())
            }
            Err(e) => format!("Diagnostic failed: {}", e),
        };
        let _ = tx.send(output);
    });
}

#[cfg(feature = "diagnostics-ui")]
pub(crate) fn start_runtime_status(app: &mut AutoLoginApp) {
    app.runtime_status_running = true;

    let (tx, rx) = std::sync::mpsc::channel();
    app.runtime_status_rx = Some(rx);
    let settings = app.config.settings.clone();
    let accounts = app.config.accounts.clone();

    std::thread::spawn(move || {
        let report = crate::debug_fill::runtime_status_report(&settings, &accounts);
        let _ = tx.send(report);
    });
}

#[cfg(all(test, feature = "diagnostics-ui"))]
mod tests {
    use super::poll_runtime_status;
    use crate::app::AutoLoginApp;
    use crate::models::{AppConfig, Tab};
    use std::sync::mpsc::channel as std_channel;
    use tokio::sync::mpsc::channel as tokio_channel;

    #[test]
    fn runtime_status_disconnect_clears_running_state() {
        let (worker_tx, _worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (_tray_tx, tray_rx) = std_channel();
        let mut app = AutoLoginApp::new(
            worker_tx,
            tray_rx,
            worker_event_rx,
            AppConfig::default(),
            true,
            Tab::Diagnose,
        );
        let (tx, rx) = std_channel();
        drop(tx);
        app.runtime_status_running = true;
        app.runtime_status_rx = Some(rx);

        poll_runtime_status(&mut app);

        assert!(!app.runtime_status_running);
        assert!(app.runtime_status_rx.is_none());
        assert!(app
            .status_message
            .as_ref()
            .is_some_and(|(message, _)| message == "Runtime status failed"));
    }
}
