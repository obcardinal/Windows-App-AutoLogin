use eframe::egui;

pub(super) fn show(ui: &mut egui::Ui) {
    egui::CollapsingHeader::new("Setup instructions")
        .id_salt("iphone_setup_instructions")
        .show(ui, |ui| {
            ui.strong("Pair with Xcode");
            ui.label("Install and open Xcode on your Mac. In Window → Devices and Simulators, pair your iPhone and enable its network connection.");
            ui.hyperlink_to("Get Xcode", "https://apps.apple.com/app/xcode/id497799835");

            ui.add_space(6.0);
            ui.strong("Prepare your iPhone");
            ui.label("Enable Developer Mode and Enable UI Automation, then add your account in Microsoft Authenticator.");

            ui.add_space(6.0);
            ui.strong("Install the Mac helper");
            ui.label("Use Node.js 22.22.2+ (22.x), 24.15+ (24.x) or 26+, npm 10+, and an Apple Development signing identity for team 76C2QW8JV3.");
            ui.label("In Terminal, open this version’s project folder and install the helper.");
            ui.monospace("node script/iphone-automation/cli.mjs setup");
            ui.label("Save your iPhone in Settings, then unlock it and prepare it once.");
            ui.monospace("node script/iphone-automation/cli.mjs prepare-device");
        });
}
