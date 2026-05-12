use crate::app::AutoLoginApp;
use crate::ui::theme;
use eframe::egui;

pub fn show(ui: &mut egui::Ui, app: &mut AutoLoginApp) {
    theme::page_header(ui, "Logs", "Recent monitor and recovery events.", |ui| {
        if ui
            .add_enabled(!app.logs.is_empty(), theme::secondary_button("Clear Logs"))
            .clicked()
        {
            app.logs.clear();
            app.set_status("Logs cleared");
        }
        ui.label(format!("{} entries", app.logs.len()));
    });

    if app.logs.is_empty() {
        theme::glass_frame().show(ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.heading("No log entries yet");
                ui.label(theme::muted(
                    "When the monitor detects a connection event, it will appear here.",
                ));
            });
        });
        return;
    }

    theme::compact_frame().show(ui, |ui| {
        egui::ScrollArea::vertical()
            .auto_shrink([false; 2])
            .stick_to_bottom(true)
            .show(ui, |ui| {
                for entry in &app.logs {
                    ui.horizontal_top(|ui| {
                        ui.add_sized(
                            [64.0, 18.0],
                            egui::Label::new(
                                egui::RichText::new(&entry.timestamp)
                                    .monospace()
                                    .small()
                                    .color(theme::MUTED),
                            ),
                        );
                        let (color, fill) = log_style(entry.level);
                        ui.allocate_ui(egui::vec2(58.0, 18.0), |ui| {
                            theme::pill(ui, &entry.level.to_string(), color, fill);
                        });
                        ui.add(egui::Label::new(&entry.message).wrap());
                    });
                    ui.add_space(3.0);
                }
            });
    });
}

fn log_style(level: crate::models::LogLevel) -> (egui::Color32, egui::Color32) {
    match level {
        crate::models::LogLevel::Info => (theme::SUCCESS, theme::SUCCESS_SOFT),
        crate::models::LogLevel::Warn => (theme::WARNING, theme::WARNING_SOFT),
        crate::models::LogLevel::Error => (theme::DANGER, theme::DANGER_SOFT),
    }
}
