//! Account authentication choices and details for the iPhone shared by this Mac.
use crate::iphone_setup_info::{self, SetupInfo};
use crate::models::{Account, AuthenticatorProvider};
use crate::ui::theme;
use eframe::egui;
use std::sync::{Arc, OnceLock};

pub(super) const ACCOUNT_HELP: &str = "When Windows App shows a sign-in number for this account, Monitor opens Microsoft Authenticator on your unlocked iPhone over Wi-Fi, enters the number and taps Approve. Complete Face ID if prompted. Choose Off to approve sign-ins manually.";

pub(super) fn provider_picker(
    ui: &mut egui::Ui,
    account: &mut Account,
    field_width: f32,
) -> egui::Response {
    let initial = account
        .iphone_authenticator_enabled
        .then_some(account.authenticator_provider);
    let mut selection = initial;
    let popup_id = ui.make_persistent_id(("account_authenticator_provider", &account.id));
    let mut response = super::accounts::account_picker_button(
        ui,
        popup_id,
        initial.map_or("Off", AuthenticatorProvider::label),
        field_width,
    );
    let frame = egui::Frame::popup(ui.style());
    let content_width = response.rect.width() - frame.total_margin().sum().x;
    egui::Popup::menu(&response)
        .id(popup_id)
        .width(response.rect.width())
        .frame(frame)
        .style(egui::style::StyleModifier::default())
        .show(|ui| {
            ui.set_width(content_width);
            if ui.selectable_value(&mut selection, None, "Off").clicked() {
                ui.close();
            }
            for &provider in AuthenticatorProvider::SUPPORTED {
                if ui
                    .selectable_value(&mut selection, Some(provider), provider.label())
                    .clicked()
                {
                    ui.close();
                }
            }
        });
    if initial != selection {
        account.iphone_authenticator_enabled = selection.is_some();
        if let Some(provider) = selection {
            account.authenticator_provider = provider;
        }
        response.mark_changed();
    }
    response
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
    ui.label("Open the account you want to use. Under 2FA, choose Microsoft Authenticator from the iPhone app menu and save. With Monitor running, assistance starts when Windows App shows a sign-in number for that account. Choose Off to approve sign-ins manually.");
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
    fn provider_picker_selects_and_restores_the_account_choice() {
        let ctx = egui::Context::default();
        let mut account = Account::new("example");
        let render = |account: &mut Account, events| {
            ctx.run_ui(
                egui::RawInput {
                    events,
                    ..Default::default()
                },
                |ui| {
                    ui.set_width(350.0);
                    provider_picker(ui, account, 240.0);
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
        let click = |account: &mut Account, screen: &egui::FullOutput, label| {
            let items = find(screen, label);
            assert_eq!(items.len(), 1, "expected one clickable {label}");
            let pos = items[0].center();
            let press = |pressed| egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed,
                modifiers: Default::default(),
            };
            render(
                account,
                vec![egui::Event::PointerMoved(pos), press(true), press(false)],
            );
            render(account, vec![])
        };

        render(&mut account, vec![]);
        let closed = render(&mut account, vec![]);
        let open = click(&mut account, &closed, "Off");
        assert_eq!(find(&open, "Off").len(), 2);
        assert_eq!(find(&open, "Microsoft Authenticator").len(), 1);
        assert!(find(&open, "Duo Mobile").is_empty());
        render(
            &mut account,
            vec![egui::Event::Key {
                key: egui::Key::Escape,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: Default::default(),
            }],
        );
        let dismissed = render(&mut account, vec![]);
        assert!(find(&dismissed, "Microsoft Authenticator").is_empty());
        assert!(!account.iphone_authenticator_enabled);
        let open = click(&mut account, &dismissed, "Off");
        let selected = click(&mut account, &open, "Microsoft Authenticator");
        assert!(account.iphone_authenticator_enabled);
        assert_eq!(
            account.authenticator_provider,
            AuthenticatorProvider::MicrosoftAuthenticator
        );
        let open = click(&mut account, &selected, "Microsoft Authenticator");
        let disabled = click(&mut account, &open, "Off");
        assert!(!account.iphone_authenticator_enabled);
        assert_eq!(find(&disabled, "Off").len(), 1);

        let mut legacy: Account = serde_json::from_value(serde_json::json!({
            "id": "legacy", "username": "legacy", "iphone_authenticator_enabled": true
        }))
        .unwrap();
        let initial = render(&mut legacy, vec![]);
        assert_eq!(find(&initial, "Microsoft Authenticator").len(), 1);
        assert!(legacy.iphone_authenticator_enabled);
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
