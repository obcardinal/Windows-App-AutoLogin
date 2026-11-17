//! Read-only details for the iPhone shared by accounts on this Mac.
use crate::iphone_setup_info::{self, SetupInfo};
use crate::models::AuthenticatorProvider;
use crate::ui::theme;
use eframe::egui;
use std::sync::{Arc, OnceLock};

pub(super) const TITLE: &str = "Use 2FA";
pub(super) const TRIGGER: &str = "Use the shared iPhone for two-factor sign-in with this account.";

pub(super) fn provider_picker(ui: &mut egui::Ui, provider: &mut AuthenticatorProvider) {
    ui.horizontal(|ui| {
        let label = ui.label("Authenticator");
        egui::ComboBox::from_id_salt("account_authenticator_provider")
            .selected_text(provider.label())
            .show_ui(ui, |ui| {
                for &option in AuthenticatorProvider::SUPPORTED {
                    ui.selectable_value(provider, option, option.label());
                }
            })
            .response
            .labelled_by(label.id);
    });
}

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

fn details_id() -> egui::Id {
    egui::Id::new("iphone_sign_in_details")
}

pub(crate) fn close_details(ctx: &egui::Context) {
    ctx.data_mut(|data| data.remove::<bool>(details_id()));
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

pub(super) fn summary(ui: &mut egui::Ui) {
    let snapshot = DeviceSnapshot::get(ui.ctx());
    ui.horizontal(|ui| {
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.small_button("Sign-in details…").clicked() {
                ui.ctx()
                    .data_mut(|data| data.insert_temp(details_id(), true));
                ui.ctx().request_repaint();
            }
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 0.0;
                let label = device_label(snapshot.0.get());
                ui.add(egui::Label::new(format!("iPhone: {label}")).truncate())
                    .on_hover_text(label);
                ui.label(
                    egui::RichText::new("Microsoft Authenticator over Wi-Fi")
                        .small()
                        .color(theme::MUTED),
                );
            });
        });
    });
}

pub(super) fn show_if_open(ui: &mut egui::Ui) -> bool {
    let id = details_id();
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
        Some(SetupInfo::NotConfigured | SetupInfo::NoDeviceSelected) => Some("Pair your iPhone with this Mac and select it during iPhone setup. Add the accounts you use to Microsoft Authenticator on the phone."),
        _ => None,
    };
    if let Some(status) = status {
        ui.label(status);
    }
    ui.label(
        "This Mac uses the same paired iPhone for every account that uses Microsoft Authenticator.",
    );
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
    ui.label("In Accounts, turn on “Use 2FA”, choose Microsoft Authenticator and save. With Monitor running, assistance starts when Windows App shows a Microsoft sign-in number for that account.");
    ui.strong("What happens on your iPhone");
    ui.label("Unlock your iPhone on the same Wi-Fi network. AutoLogin opens Microsoft Authenticator, enters the matching number and taps Approve. Complete Face ID if prompted.");
    ui.label(
        egui::RichText::new("Duo Mobile and other authenticator apps are not supported.")
            .small()
            .color(theme::MUTED),
    );
    ui.separator();
    if ui.button("Back to Settings").clicked()
        || ui.input_mut(|input| input.consume_key(egui::Modifiers::NONE, egui::Key::Escape))
    {
        close_details(ui.ctx());
        ui.ctx().request_repaint();
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_picker_shows_the_selected_provider_and_only_supported_choices() {
        let ctx = egui::Context::default();
        let mut provider = AuthenticatorProvider::MicrosoftAuthenticator;
        let mut render = |events| {
            ctx.run_ui(
                egui::RawInput {
                    events,
                    ..Default::default()
                },
                |ui| {
                    provider_picker(ui, &mut provider);
                },
            )
        };
        let find = |frame: &egui::FullOutput, text: &str| -> Vec<egui::Rect> {
            frame
                .shapes
                .iter()
                .filter_map(|shape| match &shape.shape {
                    egui::Shape::Text(label) if label.galley.text() == text => {
                        Some(label.visual_bounding_rect())
                    }
                    _ => None,
                })
                .collect()
        };
        render(vec![]);
        let closed = render(vec![]);
        assert_eq!(find(&closed, "Authenticator").len(), 1);
        let selected = find(&closed, "Microsoft Authenticator");
        assert_eq!(selected.len(), 1);
        let pos = selected[0].center();
        let press = |pressed| egui::Event::PointerButton {
            pos,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: Default::default(),
        };
        render(vec![
            egui::Event::PointerMoved(pos),
            press(true),
            press(false),
        ]);
        let open = render(vec![]);
        assert_eq!(find(&open, "Microsoft Authenticator").len(), 2);
        assert!(find(&open, "Duo Mobile").is_empty());
    }

    #[test]
    fn shared_device_details_return_to_settings_and_preserve_the_selected_offline_phone() {
        let ctx = egui::Context::default();
        let view = DeviceSnapshot::default();
        view.0
            .set(SetupInfo::Selected {
                name: "Work iPhone".into(),
                wifi_connected: false,
            })
            .unwrap();
        ctx.data_mut(|d| d.insert_temp(egui::Id::new("iphone_setup_info"), view));
        let frame = |events| {
            ctx.run_ui(
                egui::RawInput {
                    events,
                    ..Default::default()
                },
                |ui| {
                    ui.set_width(420.0);
                    if !show_if_open(ui) {
                        summary(ui);
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
        frame(vec![]);
        let home = frame(vec![]);
        assert!(text_rect(&home, "iPhone: Work iPhone").is_some());
        let click_button = |output: &egui::FullOutput, label: &str| {
            let pos = text_rect(output, label).unwrap().center();
            let click = |pressed| egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed,
                modifiers: Default::default(),
            };
            frame(vec![
                egui::Event::PointerMoved(pos),
                click(true),
                click(false),
            ]);
        };
        click_button(&home, "Sign-in details…");
        let details = frame(vec![]);
        for label in [
            "Work iPhone",
            "No active Wi-Fi connection reported.",
            "When it runs",
            "What happens on your iPhone",
            "Duo Mobile and other authenticator apps are not supported.",
        ] {
            assert!(text_rect(&details, label).is_some(), "{label}");
        }
        click_button(&details, "Back to Settings");
        let home = frame(vec![]);
        assert!(text_rect(&home, "iPhone: Work iPhone").is_some());
        click_button(&home, "Sign-in details…");
        frame(vec![]);
        frame(vec![egui::Event::Key {
            key: egui::Key::Escape,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: Default::default(),
        }]);
        assert!(text_rect(&frame(vec![]), "Sign-in details…").is_some());
    }
}
