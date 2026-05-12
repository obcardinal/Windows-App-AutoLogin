use crate::app::AutoLoginApp;
use crate::autostart;
use crate::ui::theme;
use eframe::egui;

const FOOTER_GAP: f32 = 8.0;

pub fn show(ui: &mut egui::Ui, app: &mut AutoLoginApp) {
    theme::simple_page_header(
        ui,
        "Settings",
        "Tune monitoring, login behavior, and macOS integration.",
    );

    let mut save_clicked = false;

    egui::Panel::bottom("settings_footer")
        .resizable(false)
        .show_separator_line(false)
        .frame(egui::Frame::new())
        .show_inside(ui, |ui| {
            ui.add_space(FOOTER_GAP);
            theme::compact_frame().show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .add_sized([172.0, 30.0], theme::primary_button("Apply and Save"))
                        .clicked()
                    {
                        save_clicked = true;
                    }
                });
            });
        });

    egui::CentralPanel::default()
        .frame(egui::Frame::new())
        .show_inside(ui, |ui| {
            egui::ScrollArea::vertical()
                .id_salt("settings_scroll")
                .auto_shrink([false; 2])
                .show(ui, |ui| {
                    section(ui, "Monitoring", |ui| {
                        egui::Grid::new("monitoring_settings")
                            .num_columns(2)
                            .spacing([18.0, 10.0])
                            .show(ui, |ui| {
                                ui.label("Check every");
                                ui.add(
                                    egui::Slider::new(
                                        &mut app.settings_draft.poll_interval_secs,
                                        1..=60,
                                    )
                                    .suffix(" sec"),
                                );
                                ui.end_row();
                            });
                    });

                    section(ui, "macOS", |ui| {
                        ui.checkbox(&mut app.settings_draft.auto_start, "Open at Login");
                        ui.checkbox(
                            &mut app.settings_draft.start_minimized,
                            "Hide main window at launch",
                        )
                            .on_hover_text("The app keeps running from the menu bar.");
                    });

                    section(ui, "Remote Desktop App", |ui| {
                        egui::Grid::new("remote_desktop_app_settings")
                            .num_columns(2)
                            .spacing([12.0, 8.0])
                            .show(ui, |ui| {
                                ui.label("Process");
                                egui::ComboBox::from_id_salt("macos_app_name")
                                    .selected_text(&app.settings_draft.macos_app_name)
                                    .show_ui(ui, |ui| {
                                        ui.selectable_value(
                                            &mut app.settings_draft.macos_app_name,
                                            "Windows App".to_string(),
                                            "Windows App",
                                        );
                                        ui.selectable_value(
                                            &mut app.settings_draft.macos_app_name,
                                            "Microsoft Remote Desktop".to_string(),
                                            "Microsoft Remote Desktop",
                                        );
                                    });
                                ui.end_row();

                                ui.label("Custom");
                                ui.add_sized(
                                    [ui.available_width().min(300.0), 24.0],
                                    egui::TextEdit::singleline(
                                        &mut app.settings_draft.macos_app_name,
                                    )
                                    .hint_text("Custom app process name"),
                                );
                                ui.end_row();
                            });
                    });

                    section(ui, "Security", |ui| {
                        ui.checkbox(&mut app.settings_draft.use_keyring, "Use macOS Keychain")
                            .on_hover_text(
                                "Recommended. If disabled, password ciphertext is stored locally and its encryption key is still kept in Keychain.",
                            );
                    });

                });
        });

    if save_clicked {
        let previous_settings = app.config.settings.clone();
        let mut next_config = app.config.clone();
        next_config.settings = app.settings_draft.clone();
        next_config.settings.macos_app_name =
            next_config.settings.macos_app_name.trim().to_string();
        if next_config.settings.macos_app_name.is_empty() {
            app.set_status("App process name is required");
            return;
        }

        if next_config.settings.auto_start != previous_settings.auto_start {
            if let Err(e) = autostart::set_enabled(next_config.settings.auto_start) {
                app.set_status(format!("Auto-start error: {}", e));
                app.settings_draft.auto_start = autostart::is_enabled();
                return;
            }
        }

        if let Err(e) = crate::storage::save_config(&next_config) {
            if next_config.settings.auto_start != previous_settings.auto_start {
                let _ = autostart::set_enabled(previous_settings.auto_start);
                app.settings_draft.auto_start = autostart::is_enabled();
            }
            app.set_status(format!("Save failed: {}", e));
        } else {
            app.config = next_config;
            app.settings_draft = app.config.settings.clone();
            app.set_status("Settings saved");
            if let Err(e) =
                app.worker_tx
                    .try_send(crate::background::WorkerCommand::UpdateSettings(
                        app.config.settings.clone(),
                    ))
            {
                app.set_status(format!("Settings saved, but monitor update failed: {}", e));
            }
        }
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
