use crate::app::AutoLoginApp;
use crate::autostart;
use crate::models::FIXED_POLL_INTERVAL_SECS;
use crate::ui::theme;
use eframe::egui;

pub fn show(ui: &mut egui::Ui, app: &mut AutoLoginApp) {
    let mut settings_changed = false;
    theme::page_header_plain(
        ui,
        "Settings",
        "Adjust login behavior and system integration.",
    );

    egui::ScrollArea::vertical()
        .id_salt("settings_scroll")
        .auto_shrink([false; 2])
        .show(ui, |ui| {
            section(ui, "System", |ui| {
                settings_changed |= ui
                    .checkbox(&mut app.settings_draft.auto_start, "Open at Login")
                    .changed();
                settings_changed |= ui
                    .checkbox(
                        &mut app.settings_draft.start_minimized,
                        "Hide main window at launch",
                    )
                    .on_hover_text("The app keeps running from the menu bar or system tray.")
                    .changed();
            });

            section(ui, "Security", |ui| {
                settings_changed |= ui
                    .checkbox(
                        &mut app.settings_draft.use_keyring,
                        "Use system secure storage",
                    )
                    .on_hover_text(
                        "Recommended. If disabled, password ciphertext is stored locally and its encryption key is still kept in the system credential store.",
                    )
                    .changed();
            });
        });

    if settings_changed {
        save_settings(app);
    }
}

fn save_settings(app: &mut AutoLoginApp) {
    let previous_settings = app.config.settings.clone();
    let mut next_config = app.config.clone();
    next_config.settings = app.settings_draft.clone();
    next_config.settings.poll_interval_secs = FIXED_POLL_INTERVAL_SECS;

    if next_config.settings.auto_start != previous_settings.auto_start {
        if let Err(e) = autostart::set_enabled(next_config.settings.auto_start) {
            app.settings_draft = previous_settings;
            app.set_status(format!("Auto-start error: {}", e));
            return;
        }
    }

    if let Err(e) = crate::storage::save_config(&next_config) {
        if next_config.settings.auto_start != previous_settings.auto_start {
            let _ = autostart::set_enabled(previous_settings.auto_start);
        }
        app.settings_draft = app.config.settings.clone();
        app.set_status(format!("Save failed: {}", e));
        return;
    }

    app.config = next_config;
    app.settings_draft = app.config.settings.clone();
    app.set_status("Settings saved");
    if let Err(e) = app
        .worker_tx
        .try_send(crate::background::WorkerCommand::UpdateSettings(
            app.config.settings.clone(),
        ))
    {
        app.set_status(format!("Settings saved, but monitor update failed: {}", e));
    }
}

fn section(ui: &mut egui::Ui, title: &str, add_contents: impl FnOnce(&mut egui::Ui)) {
    theme::compact_frame().show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.label(egui::RichText::new(title).strong());
        ui.add_space(4.0);
        add_contents(ui);
    });
    ui.add_space(6.0);
}
