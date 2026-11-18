use super::{settings, theme};
use eframe::egui;

const STEPS: [&str; 4] = [
    "Pair your iPhone in Xcode",
    "Set up your iPhone",
    "Install the Mac helper",
    "Prepare the selected iPhone",
];

pub(super) fn show(ui: &mut egui::Ui) {
    let id = ui.make_persistent_id("iphone_setup_guide_step");
    let step = ui.data(|data| data.get_temp::<usize>(id)).unwrap_or(0);

    settings::section(ui, "SETUP GUIDE", |ui| {
        egui::containers::Sides::new().shrink_left().show(
            ui,
            |ui| ui.strong(STEPS[step]),
            |ui| {
                ui.label(
                    egui::RichText::new(format!("Step {} of {}", step + 1, STEPS.len()))
                        .small()
                        .color(theme::MUTED),
                )
            },
        );
        ui.add_space(4.0);

        match step {
            0 => {
                ui.label("On your Mac, open Xcode → Window → Devices and Simulators.");
                ui.label("Pair your iPhone for network use. Keep both devices on the same Wi-Fi.");
            }
            1 => {
                ui.label("In Settings → Privacy & Security, turn on Developer Mode.");
                ui.label("In Settings → Developer, turn on Enable UI Automation.");
                ui.label("Add your work account in Microsoft Authenticator.");
            }
            2 => {
                ui.label("In Terminal, open the project folder for this version of AutoLogin. Run the setup command there.");
                command(ui, "node script/iphone-automation/cli.mjs setup");
                egui::CollapsingHeader::new("Mac requirements").show(ui, |ui| {
                    ui.label("Node.js 22.22.2+ (22.x), 24.15+ (24.x), or 26+");
                    ui.label("npm 10 or later");
                    ui.label("Apple Development signing identity for team 76C2QW8JV3");
                });
            }
            _ => {
                ui.label("Choose your paired iPhone above and click Save iPhone.");
                ui.label("Unlock it, then run this command from the same project folder.");
                command(ui, "node script/iphone-automation/cli.mjs prepare-device");
            }
        }

        ui.add_space(6.0);
        let (previous, next) = egui::containers::Sides::new().show(
            ui,
            |ui| {
                if step == 0 {
                    ui.hyperlink_to("Get Xcode", "https://apps.apple.com/app/xcode/id497799835");
                    false
                } else {
                    ui.add(theme::secondary_button("Previous step")).clicked()
                }
            },
            |ui| step + 1 < STEPS.len() && ui.add(theme::secondary_button("Next step")).clicked(),
        );
        if previous || next {
            let target = if previous { step - 1 } else { step + 1 };
            ui.data_mut(|data| data.insert_temp(id, target));
            ui.ctx().request_repaint();
        }
    });
}

fn command(ui: &mut egui::Ui, text: &'static str) {
    let id = ui.make_persistent_id(text);
    let now = ui.input(|input| input.time);
    let copied = ui.data(|data| data.get_temp::<f64>(id).is_some_and(|until| until > now));
    egui::containers::Sides::new().shrink_left().show(
        ui,
        |ui| ui.add(egui::Label::new(egui::RichText::new(text).monospace().small()).wrap()),
        |ui| {
            if ui
                .add(theme::secondary_button(if copied {
                    "Copied"
                } else {
                    "Copy"
                }))
                .on_hover_text("Copy command")
                .clicked()
            {
                ui.ctx().copy_text(text.to_owned());
                let duration = std::time::Duration::from_secs(2);
                ui.data_mut(|data| data.insert_temp(id, now + duration.as_secs_f64()));
                ui.ctx().request_repaint_after(duration);
            }
        },
    );
}
