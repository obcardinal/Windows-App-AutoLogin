//! Read-only device information and an explanation of the account preference.
use crate::iphone_setup_info::{self, SetupInfo};
use crate::ui::theme;
use eframe::egui;
use std::sync::{Arc, OnceLock};

pub(super) const TITLE: &str = "Microsoft Authenticator on iPhone";
pub(super) const TRIGGER: &str =
    "Starts when Monitor sees a Microsoft sign-in number for this account in Windows App.";

#[derive(Clone, Default)]
struct DeviceSnapshot(Arc<OnceLock<SetupInfo>>);

impl DeviceSnapshot {
    fn start(ctx: &egui::Context) -> Self {
        let snapshot = Self::default();
        let result = snapshot.0.clone();
        let repaint = ctx.clone();
        let viewport = ctx.viewport_id();
        if std::thread::Builder::new()
            .name("iphone-setup-info".into())
            .spawn(move || {
                let _ = result.set(iphone_setup_info::read());
                repaint.request_repaint_of(viewport);
            })
            .is_err()
        {
            let _ = snapshot.0.set(SetupInfo::ConfigUnavailable);
        }
        snapshot
    }

    fn get(ctx: &egui::Context) -> Self {
        let id = egui::Id::new("iphone_setup_info");
        if let Some(cached) = ctx.data_mut(|data| data.get_temp::<Self>(id)) {
            return cached;
        }
        let snapshot = Self::start(ctx);
        ctx.data_mut(|data| data.insert_temp(id, snapshot.clone()));
        snapshot
    }
}

fn details_id(account_id: &str) -> egui::Id {
    egui::Id::new(("iphone_sign_in_details", account_id))
}

pub(super) fn reset_editor(ctx: &egui::Context, account_id: &str) {
    ctx.data_mut(|data| {
        data.remove::<DeviceSnapshot>(egui::Id::new("iphone_setup_info"));
        data.remove::<bool>(details_id(account_id));
    });
}

fn device_label(info: Option<&SetupInfo>) -> &str {
    match info {
        None => "Checking…",
        Some(SetupInfo::NotConfigured) => "Setup required",
        Some(SetupInfo::NoDeviceSelected) => "No iPhone selected",
        Some(SetupInfo::ConfigUnavailable) => "Setup information unavailable",
        Some(SetupInfo::SelectedUnavailable) => "Selected iPhone · name unavailable",
        Some(SetupInfo::Selected { name, .. }) => name,
    }
}

pub(super) fn summary(ui: &mut egui::Ui, account_id: &str) {
    let snapshot = DeviceSnapshot::get(ui.ctx());
    ui.horizontal(|ui| {
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.small_button("Sign-in details…").clicked() {
                ui.ctx()
                    .data_mut(|data| data.insert_temp(details_id(account_id), true));
                ui.ctx().request_repaint();
            }
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 0.0;
                let label = device_label(snapshot.0.get());
                ui.add(egui::Label::new(format!("iPhone: {label}")).truncate())
                    .on_hover_text(label);
                ui.label(
                    egui::RichText::new("Monitor starts it when Windows App shows a number.")
                        .small()
                        .color(theme::MUTED),
                )
                .on_hover_text(TRIGGER);
            });
        });
    });
}

pub(super) fn show_if_open(ui: &mut egui::Ui, account_id: &str) -> bool {
    let id = details_id(account_id);
    if ui.ctx().data(|data| data.get_temp::<bool>(id)) != Some(true) {
        return false;
    }
    ui.heading("iPhone sign-in details");
    ui.add_space(6.0);
    let snapshot = DeviceSnapshot::get(ui.ctx());
    ui.strong("Selected iPhone");
    ui.add(egui::Label::new(device_label(snapshot.0.get())).wrap());
    let status = match snapshot.0.get() {
        Some(SetupInfo::Selected { wifi_connected: true, .. }) => Some("Wi-Fi connection reported by this Mac."),
        Some(SetupInfo::Selected { wifi_connected: false, .. }) => Some("No active Wi-Fi connection reported."),
        Some(SetupInfo::SelectedUnavailable) => Some("This Mac has a saved selection, but couldn’t identify the phone in its paired devices."),
        Some(SetupInfo::NotConfigured | SetupInfo::NoDeviceSelected) => Some("Pair your iPhone with this Mac and select it during iPhone setup. Add this account in Microsoft Authenticator on the phone."),
        _ => None,
    };
    if let Some(status) = status {
        ui.label(status);
    }
    ui.label("All enabled accounts use the same paired iPhone selected during setup on this Mac.");
    if ui
        .add_enabled(
            snapshot.0.get().is_some(),
            egui::Button::new("Refresh device info").small(),
        )
        .clicked()
    {
        let fresh = DeviceSnapshot::start(ui.ctx());
        ui.ctx()
            .data_mut(|data| data.insert_temp(egui::Id::new("iphone_setup_info"), fresh));
        ui.ctx().request_repaint();
    }

    ui.separator();
    ui.strong("When it runs");
    ui.label("Turn on this option, save the account and leave Monitor running. Assistance starts when Windows App shows a Microsoft sign-in number for this account.");
    ui.strong("What happens on your iPhone");
    ui.label("Unlock your iPhone on the same Wi-Fi network. AutoLogin opens Microsoft Authenticator, enters the matching number and taps Approve. Complete Face ID if prompted.");
    ui.label(
        egui::RichText::new("Duo Mobile and other authenticator apps are not supported.")
            .small()
            .color(theme::MUTED),
    );
    ui.separator();
    if ui.button("Back to account").clicked()
        || ui.input_mut(|input| input.consume_key(egui::Modifiers::NONE, egui::Key::Escape))
    {
        ui.ctx().data_mut(|data| data.remove::<bool>(id));
        ui.ctx().request_repaint();
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_details_open_for_this_account_and_escape_returns_to_its_editor() {
        let ctx = egui::Context::default();
        let view = DeviceSnapshot::default();
        view.0
            .set(SetupInfo::Selected {
                name: "Work iPhone".into(),
                wifi_connected: true,
            })
            .unwrap();
        ctx.data_mut(|d| d.insert_temp(egui::Id::new("iphone_setup_info"), view));
        let frame = |events, account_id: &str| {
            ctx.run_ui(
                egui::RawInput {
                    events,
                    ..Default::default()
                },
                |ui| {
                    ui.set_width(420.0);
                    if !show_if_open(ui, account_id) {
                        summary(ui, account_id);
                    }
                },
            )
        };
        let text_rect = |frame: &egui::FullOutput, label: &str| {
            frame.shapes.iter().find_map(|item| match &item.shape {
                egui::Shape::Text(t) if t.galley.text() == label => Some(t.visual_bounding_rect()),
                _ => None,
            })
        };
        frame(vec![], "a");
        let home = frame(vec![], "a");
        assert!(text_rect(&home, "iPhone: Work iPhone").is_some());
        let pos = text_rect(&home, "Sign-in details…").unwrap().center();
        let pointer = |pressed| egui::Event::PointerButton {
            pos,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: Default::default(),
        };
        frame(
            vec![
                egui::Event::PointerMoved(pos),
                pointer(true),
                pointer(false),
            ],
            "a",
        );
        let details = frame(vec![], "a");
        for label in [
            "Work iPhone",
            "When it runs",
            "What happens on your iPhone",
            "Duo Mobile and other authenticator apps are not supported.",
        ] {
            assert!(text_rect(&details, label).is_some(), "{label}");
        }
        assert!(text_rect(&frame(vec![], "b"), "iPhone sign-in details").is_none());
        frame(
            vec![egui::Event::Key {
                key: egui::Key::Escape,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: Default::default(),
            }],
            "a",
        );
        assert!(text_rect(&frame(vec![], "a"), "Sign-in details…").is_some());
    }
}
