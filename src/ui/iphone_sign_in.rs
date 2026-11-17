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
    let text_height = ui.text_style_height(&egui::TextStyle::Body)
        + ui.text_style_height(&egui::TextStyle::Small);
    let (_, details) = egui::containers::Sides::new()
        .height(text_height.max(ui.spacing().interact_size.y))
        .shrink_left()
        .show(
            ui,
            |ui| {
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
            },
            |ui| ui.add(theme::secondary_button("Sign-in details…")),
        );
    if details.clicked() {
        ui.ctx()
            .data_mut(|data| data.insert_temp(details_id(), true));
        ui.ctx().request_repaint();
    }
}

pub(super) fn show_if_open(ui: &mut egui::Ui) -> Option<f32> {
    if ui.ctx().data(|data| data.get_temp::<bool>(details_id())) != Some(true) {
        return None;
    }
    let top = ui.cursor().top();
    let (_, back) = egui::containers::Sides::new()
        .height(36.0)
        .shrink_left()
        .show(
            ui,
            |ui| ui.heading("iPhone sign-in"),
            |ui| ui.add(theme::secondary_button("Back to Settings")),
        );
    if back.clicked()
        || ui.input_mut(|input| input.consume_key(egui::Modifiers::NONE, egui::Key::Escape))
    {
        close_details(ui.ctx());
        ui.ctx().request_repaint();
    }

    let body = egui::ScrollArea::vertical()
        .id_salt("iphone_sign_in_scroll")
        .auto_shrink([false, true])
        .show(ui, |ui| {
            super::settings::section(ui, "SHARED IPHONE", show_shared_phone);
            ui.add_space(12.0);
            super::settings::section(ui, "MICROSOFT AUTHENTICATOR", |ui| {
                let steps = [
                    ("Before sign-in", "Unlock your iPhone on the same Wi-Fi as your Mac."),
                    ("On your Mac", "Monitor reads the number in Windows App."),
                    ("On your iPhone", "AutoLogin opens Authenticator, enters the number and taps Approve. Use Face ID if asked."),
                ];
                let column_gap = 14.0;
                let description_width = (ui.available_width() - 106.0 - column_gap).max(1.0);
                egui::Grid::new("iphone_sign_in_steps")
                    .num_columns(2)
                    .spacing([column_gap, 8.0])
                    .max_col_width(description_width)
                    .show(ui, |ui| {
                        for (label, description) in steps {
                            ui.label(egui::RichText::new(label).strong());
                            ui.add(egui::Label::new(description).wrap());
                            ui.end_row();
                        }
                    });
            });
            ui.add_space(4.0);
            ui.label(egui::RichText::new("Set up per account in Accounts → 2FA → iPhone app.").small().color(theme::MUTED));
        });
    Some(body.inner_rect.top() - top + body.content_size.y)
}

fn show_shared_phone(ui: &mut egui::Ui) {
    let snapshot = DeviceSnapshot::get(ui.ctx());
    let info = snapshot.0.get();
    let status = match info {
        Some(SetupInfo::Selected {
            wifi_connected: true,
            ..
        }) => Some("Connected over Wi-Fi"),
        Some(SetupInfo::Selected {
            wifi_connected: false,
            ..
        }) => Some("Wi-Fi disconnected"),
        Some(SetupInfo::SelectedUnavailable) => {
            Some("The selected iPhone isn’t visible to this Mac.")
        }
        Some(SetupInfo::NotConfigured | SetupInfo::NoDeviceSelected) => {
            Some("Pair your iPhone with this Mac and select it during setup.")
        }
        Some(SetupInfo::ConfigUnavailable) => Some("Refresh to try again."),
        None => None,
    };
    let height = ui.text_style_height(&egui::TextStyle::Body)
        + ui.text_style_height(&egui::TextStyle::Small);
    let (_, refresh) = egui::containers::Sides::new()
        .height(height)
        .shrink_left()
        .show(
            ui,
            |ui| {
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    let name = device_label(info);
                    ui.add(egui::Label::new(name).truncate())
                        .on_hover_text(name);
                    if let Some(status) = status {
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(status).small().color(theme::MUTED),
                            )
                            .wrap(),
                        );
                    }
                })
            },
            |ui| {
                ui.add_enabled(info.is_some(), theme::secondary_button("Refresh"))
                    .on_hover_text("Refresh device info")
            },
        );
    if refresh.clicked() {
        let fresh = DeviceSnapshot::start(ui.ctx());
        ui.ctx()
            .data_mut(|data| data.insert_temp(egui::Id::new("iphone_setup_info"), fresh));
        ui.ctx().request_repaint();
    }
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
        theme::apply(&ctx);
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
                    if show_if_open(ui).is_none() {
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
        let phone = text_rect(&home, "iPhone: Work iPhone").unwrap();
        let caption = text_rect(&home, "Microsoft Authenticator over Wi-Fi").unwrap();
        let details_label = text_rect(&home, "Sign-in details…").unwrap();
        let button = home
            .shapes
            .iter()
            .find_map(|item| match &item.shape {
                egui::Shape::Rect(rect)
                    if rect.stroke.color == theme::STROKE
                        && rect.rect.contains_rect(details_label) =>
                {
                    Some(rect.rect)
                }
                _ => None,
            })
            .expect("the details action should use the outlined button style");
        assert!(button.height() >= 28.0);
        assert!(phone.right().max(caption.right()) < button.left());
        assert!((button.center().y - phone.union(caption).center().y).abs() <= 2.0);
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
            "iPhone sign-in",
            "Wi-Fi disconnected",
            "Refresh",
            "Before sign-in",
            "On your Mac",
            "On your iPhone",
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
