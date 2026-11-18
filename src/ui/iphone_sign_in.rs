//! Account authentication choices and details for the iPhone shared by this Mac.
use crate::iphone_setup_info::{self, PairedPhone, SetupInfo};
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

fn start_task<T: Send + Sync + 'static>(
    ctx: &egui::Context,
    work: impl FnOnce() -> T + Send + 'static,
    unavailable: T,
) -> Arc<OnceLock<T>> {
    let result = Arc::new(OnceLock::new());
    let completion = Arc::clone(&result);
    let repaint = ctx.clone();
    let viewport = ctx.viewport_id();
    if std::thread::Builder::new()
        .name("iphone-settings".into())
        .spawn(move || {
            let _ = completion.set(work());
            repaint.request_repaint_of(viewport);
        })
        .is_err()
    {
        let _ = result.set(unavailable);
    }
    result
}

impl DeviceSnapshot {
    fn start(ctx: &egui::Context) -> Self {
        Self(start_task(
            ctx,
            iphone_setup_info::read,
            SetupInfo::ConfigUnavailable,
        ))
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

#[derive(Clone, Copy, PartialEq)]
enum PhonePage {
    Details,
    Setup,
}

pub(crate) fn close_details(ctx: &egui::Context) {
    ctx.data_mut(|data| data.remove::<PhonePage>(details_id()));
}

fn open_page(ctx: &egui::Context, page: PhonePage) {
    ctx.data_mut(|data| {
        if page == PhonePage::Setup
            && !data
                .get_temp::<PhoneForm>(details_id())
                .is_some_and(|form| form.save.is_some())
        {
            data.remove::<PhoneForm>(details_id());
        }
        data.insert_temp(details_id(), page);
    });
    ctx.request_repaint();
}

fn device_label(info: Option<&SetupInfo>) -> &str {
    match info {
        None => "Checking…",
        Some(SetupInfo::NotConfigured | SetupInfo::NoDeviceSelected) => "No iPhone selected",
        Some(SetupInfo::ConfigUnavailable) => "Setup information unavailable",
        Some(SetupInfo::SelectedUnavailable) => "Selected iPhone · name unavailable",
        Some(SetupInfo::SelectedNeedsSetup { name }) => {
            name.as_deref().unwrap_or("Selected iPhone")
        }
        Some(SetupInfo::Selected { name, .. }) => name,
    }
}

pub(super) fn summary(ui: &mut egui::Ui) {
    let snapshot = DeviceSnapshot::get(ui.ctx());
    let info = snapshot.0.get();
    let (title, caption, needs_setup) = match info {
        Some(SetupInfo::NotConfigured | SetupInfo::NoDeviceSelected) => (
            device_label(info).to_owned(),
            "Requires Xcode on this Mac",
            true,
        ),
        Some(SetupInfo::SelectedNeedsSetup { .. }) => (
            device_label(info).to_owned(),
            "Mac helper setup required",
            true,
        ),
        _ => (
            format!("iPhone: {}", device_label(info)),
            "Microsoft Authenticator over Wi-Fi",
            false,
        ),
    };
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
                    ui.add(egui::Label::new(&title).truncate())
                        .on_hover_text(&title);
                    ui.label(egui::RichText::new(caption).small().color(theme::MUTED));
                });
            },
            |ui| {
                ui.add(theme::secondary_button(if needs_setup {
                    "Set up iPhone…"
                } else {
                    "Sign-in details…"
                }))
            },
        );
    if details.clicked() {
        open_page(
            ui.ctx(),
            if needs_setup {
                PhonePage::Setup
            } else {
                PhonePage::Details
            },
        );
    }
}

pub(super) fn show_if_open(ui: &mut egui::Ui) -> Option<f32> {
    let page = ui
        .ctx()
        .data(|data| data.get_temp::<PhonePage>(details_id()))?;
    let top = ui.cursor().top();
    let (_, back) = egui::containers::Sides::new()
        .height(36.0)
        .shrink_left()
        .show(
            ui,
            |ui| {
                ui.heading(if page == PhonePage::Setup {
                    "iPhone setup"
                } else {
                    "iPhone sign-in"
                })
            },
            |ui| ui.add(theme::secondary_button("Back to Settings")),
        );
    if back.clicked()
        || (!egui::Popup::is_any_open(ui.ctx())
            && ui.input_mut(|input| input.consume_key(egui::Modifiers::NONE, egui::Key::Escape)))
    {
        close_details(ui.ctx());
        ui.ctx().request_repaint();
    }

    let body = egui::ScrollArea::vertical()
        .id_salt(("iphone_sign_in_scroll", page == PhonePage::Setup))
        .auto_shrink([false, true])
        .show(ui, |ui| {
            if page == PhonePage::Setup {
                super::settings::section(ui, "SHARED IPHONE", show_setup);
                ui.add_space(12.0);
                crate::ui::iphone_setup_guide::show(ui);
                return;
            }
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
        Some(SetupInfo::SelectedNeedsSetup { .. }) => {
            Some("Finish setting up the local helper on this Mac.")
        }
        Some(SetupInfo::NotConfigured | SetupInfo::NoDeviceSelected) => {
            Some("Pair your iPhone with this Mac and select it during setup.")
        }
        Some(SetupInfo::ConfigUnavailable) => Some("Refresh to try again."),
        None => None,
    };
    let height = ui.text_style_height(&egui::TextStyle::Body)
        + ui.text_style_height(&egui::TextStyle::Small);
    let (_, (change, refresh)) = egui::containers::Sides::new()
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
                let change = ui.add(theme::secondary_button("iPhone setup…"));
                let refresh = ui
                    .add_enabled(info.is_some(), theme::secondary_button("Refresh"))
                    .on_hover_text("Refresh device info");
                (change, refresh)
            },
        );
    if change.clicked() {
        open_page(ui.ctx(), PhonePage::Setup);
    }
    if refresh.clicked() {
        let fresh = DeviceSnapshot::start(ui.ctx());
        ui.ctx()
            .data_mut(|data| data.insert_temp(egui::Id::new("iphone_setup_info"), fresh));
        ui.ctx().request_repaint();
    }
}

#[derive(Clone)]
struct PhoneForm {
    phones: Arc<OnceLock<Result<Vec<PairedPhone>, String>>>,
    draft: Option<String>,
    save: Option<Arc<OnceLock<Result<(), String>>>>,
    feedback: Option<String>,
}

impl PhoneForm {
    fn discover(ctx: &egui::Context) -> Self {
        Self {
            phones: start_task(
                ctx,
                iphone_setup_info::paired_phones,
                Err("Couldn’t check paired iPhones. Try Refresh.".into()),
            ),
            draft: None,
            save: None,
            feedback: None,
        }
    }
}

fn show_setup(ui: &mut egui::Ui) {
    let id = details_id();
    let mut form = ui
        .ctx()
        .data(|d| d.get_temp::<PhoneForm>(id))
        .unwrap_or_else(|| PhoneForm::discover(ui.ctx()));
    if let Some(result) = form.save.as_ref().and_then(|task| task.get()).cloned() {
        match result {
            Ok(()) => {
                form = PhoneForm::discover(ui.ctx());
                form.feedback = Some("Shared iPhone saved.".into());
            }
            Err(message) => {
                form.save = None;
                form.feedback = Some(message);
            }
        }
    }

    ui.label("All accounts on this Mac share the iPhone you select here.");
    ui.add_space(4.0);
    let busy = form.save.is_some();
    let mut can_save = false;
    match form.phones.get() {
        None => {
            ui.label("Looking for paired iPhones…");
        }
        Some(Err(message)) => {
            ui.add(egui::Label::new(message.as_str()).wrap());
        }
        Some(Ok(phones)) if phones.is_empty() => {
            ui.add(
                egui::Label::new(
                    "No paired iPhones found. Pair your iPhone with Xcode, then refresh the list.",
                )
                .wrap(),
            );
        }
        Some(Ok(phones)) => {
            can_save = ui
                .add_enabled_ui(!busy, |ui| phone_choice(ui, phones, &mut form.draft))
                .inner;
        }
    }
    ui.add_space(4.0);
    let (refresh, save) =
        phone_actions(ui, !busy && form.phones.get().is_some(), !busy && can_save);
    if let Some(device) = form.draft.as_ref().filter(|_| save).cloned() {
        let ctx = ui.ctx().clone();
        form.feedback = None;
        form.save = Some(start_task(
            ui.ctx(),
            move || {
                iphone_setup_info::select_phone(&device)?;
                ctx.data_mut(|d| d.remove::<DeviceSnapshot>(egui::Id::new("iphone_setup_info")));
                Ok(())
            },
            Err("Couldn’t save the selected iPhone. Try again.".into()),
        ));
    }

    if refresh {
        form = PhoneForm::discover(ui.ctx());
        ui.ctx()
            .data_mut(|d| d.remove::<DeviceSnapshot>(egui::Id::new("iphone_setup_info")));
    }
    if form.save.is_some() {
        ui.label("Saving iPhone…");
    } else if let Some(message) = &form.feedback {
        ui.add(egui::Label::new(message.as_str()).wrap());
    }
    let snapshot = DeviceSnapshot::get(ui.ctx());
    if matches!(snapshot.0.get(), Some(SetupInfo::SelectedNeedsSetup { .. })) {
        ui.label("iPhone saved. To install the Mac helper, see step 3 below.");
    }
    ui.ctx().data_mut(|d| d.insert_temp(id, form));
}

fn phone_choice(ui: &mut egui::Ui, phones: &[PairedPhone], draft: &mut Option<String>) -> bool {
    let chosen = phones
        .iter()
        .find(|phone| draft.as_ref().map_or(phone.selected, |id| id == &phone.id));
    let popup_id = ui.make_persistent_id("paired_iphone_picker");
    let response = ui
        .allocate_ui_with_layout(
            egui::vec2(ui.available_width(), 28.0),
            egui::Layout::left_to_right(egui::Align::Center),
            |ui| {
                let label = ui.label("Paired iPhone");
                super::accounts::account_editor_input_scope(ui, |ui| {
                    super::accounts::account_picker_button(
                        ui,
                        popup_id,
                        chosen.map_or("Choose iPhone…", |p| p.name.as_str()),
                        ui.available_width(),
                    )
                })
                .inner
                .labelled_by(label.id)
            },
        )
        .inner;
    let frame = egui::Frame::popup(ui.style());
    let width = response.rect.width() - frame.total_margin().sum().x;
    egui::Popup::menu(&response)
        .id(popup_id)
        .width(response.rect.width())
        .frame(frame)
        .style(egui::style::StyleModifier::default())
        .show(|ui| {
            ui.set_width(width);
            egui::ScrollArea::vertical()
                .max_height(180.0)
                .show(ui, |ui| {
                    for phone in phones {
                        let selected = chosen.is_some_and(|chosen| chosen.id == phone.id);
                        if ui
                            .add(egui::Button::selectable(selected, &phone.name).truncate())
                            .on_hover_text(&phone.name)
                            .clicked()
                        {
                            *draft = Some(phone.id.clone());
                            ui.close();
                        }
                    }
                });
        });
    if let Some(phone) = chosen {
        ui.label(
            egui::RichText::new(if phone.wifi_connected {
                "Connected over Wi-Fi"
            } else {
                "Wi-Fi disconnected"
            })
            .small()
            .color(theme::MUTED),
        );
    }
    phones
        .iter()
        .any(|p| Some(&p.id) == draft.as_ref() && !p.selected)
}

fn phone_actions(ui: &mut egui::Ui, can_refresh: bool, can_save: bool) -> (bool, bool) {
    egui::containers::Sides::new().height(28.0).show(
        ui,
        |ui| {
            ui.add_enabled(can_refresh, theme::secondary_button("Refresh iPhones"))
                .clicked()
        },
        |ui| {
            ui.add_enabled(can_save, theme::primary_button("Save iPhone"))
                .clicked()
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text_rect(frame: &egui::FullOutput, text: &str) -> Option<egui::Rect> {
        frame.shapes.iter().find_map(|shape| match &shape.shape {
            egui::Shape::Text(t) if t.galley.text() == text => Some(t.visual_bounding_rect()),
            _ => None,
        })
    }

    fn click_events(frame: &egui::FullOutput, label: &str) -> Vec<egui::Event> {
        let pos = text_rect(frame, label)
            .unwrap_or_else(|| panic!("missing {label}"))
            .center();
        let press = |pressed| egui::Event::PointerButton {
            pos,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: Default::default(),
        };
        vec![egui::Event::PointerMoved(pos), press(true), press(false)]
    }

    #[test]
    fn choosing_a_shared_iphone_requires_an_explicit_selection_and_save() {
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let phones = [PairedPhone {
            id: "AAAAAAAA-1234567890000001".into(),
            name: "Work iPhone".into(),
            wifi_connected: true,
            selected: false,
        }];
        let mut draft = None;
        let mut requests = Vec::new();
        let mut frame = |events| {
            ctx.run_ui(
                egui::RawInput {
                    events,
                    ..Default::default()
                },
                |ui| {
                    ui.set_width(300.0);
                    let can_save = phone_choice(ui, &phones, &mut draft);
                    if phone_actions(ui, true, can_save).1 {
                        requests.push(draft.clone());
                    }
                },
            )
        };
        frame(vec![]);
        let initial = frame(vec![]);
        let field_label = text_rect(&initial, "Paired iPhone").unwrap();
        let field = text_rect(&initial, "Choose iPhone…").unwrap();
        let field_outline = |frame: &egui::FullOutput| {
            frame.shapes.iter().find_map(|shape| match &shape.shape {
                egui::Shape::Rect(rect)
                    if rect.rect.contains_rect(field)
                        && (rect.rect.height() - 28.0).abs() < 1.0 =>
                {
                    Some((rect.fill, rect.stroke))
                }
                _ => None,
            })
        };
        assert_eq!(
            field_outline(&initial),
            Some((egui::Color32::WHITE, egui::Stroke::new(1.0, theme::STROKE)))
        );
        assert!(
            (field_label.center().y - field.center().y).abs() < 2.0
                && field_label.right() < field.left(),
            "label {field_label:?}, choice {field:?}"
        );
        let refresh = text_rect(&initial, "Refresh iPhones").unwrap();
        let save = text_rect(&initial, "Save iPhone").unwrap();
        assert!(
            (refresh.center().y - save.center().y).abs() < 2.0 && refresh.right() < save.left()
        );
        frame(click_events(&initial, "Save iPhone"));
        frame(click_events(&initial, "Choose iPhone…"));
        let open = frame(vec![]);
        assert_eq!(
            field_outline(&open).unwrap().1,
            ctx.global_style().visuals.selection.stroke
        );
        assert!(text_rect(&open, &phones[0].id).is_none());
        frame(click_events(&open, "Work iPhone"));
        let selected = frame(vec![]);
        assert!(text_rect(&selected, "Connected over Wi-Fi").is_some());
        frame(click_events(&selected, "Save iPhone"));
        assert_eq!(requests, vec![Some(phones[0].id.clone())]);
    }

    #[test]
    fn setup_guide_shows_one_step_and_copies_its_command() {
        let ctx = egui::Context::default();
        ctx.all_styles_mut(|style| style.animation_time = 0.0);
        let frame = |events| {
            ctx.run_ui(
                egui::RawInput {
                    events,
                    ..Default::default()
                },
                |ui| {
                    ui.set_width(400.0);
                    super::super::iphone_setup_guide::show(ui);
                },
            )
        };
        let click = |screen: &egui::FullOutput, label| {
            frame(click_events(screen, label));
            frame(vec![])
        };
        frame(vec![]);
        let pair = frame(vec![]);
        assert!(text_rect(&pair, "Step 1 of 4").is_some());
        assert!(text_rect(&pair, "Get Xcode").is_some());
        assert!(text_rect(&pair, "Previous step").is_none());
        assert!(text_rect(&pair, "Copy").is_none());
        let phone = click(&pair, "Next step");
        assert!(text_rect(&phone, "Set up your iPhone").is_some());
        assert!(text_rect(&phone, "Get Xcode").is_none());

        let install = click(&phone, "Next step");
        assert!(text_rect(&install, "npm 10 or later").is_none());
        let requirements = click(&install, "Mac requirements");
        assert!(text_rect(&requirements, "npm 10 or later").is_some());
        let check_copy = |screen: &egui::FullOutput, command: &str| {
            assert!(text_rect(screen, command).is_some());
            let copied = frame(click_events(screen, "Copy"));
            assert!(copied.platform_output.commands.iter().any(
                |output| matches!(output, egui::OutputCommand::CopyText(text) if text == command)
            ));
        };
        check_copy(&requirements, "node script/iphone-automation/cli.mjs setup");
        let prepare = click(&frame(vec![]), "Next step");
        assert!(text_rect(&prepare, "Next step").is_none());
        assert!(text_rect(&prepare, "Mac requirements").is_none());
        check_copy(
            &prepare,
            "node script/iphone-automation/cli.mjs prepare-device",
        );
        let previous = click(&frame(vec![]), "Previous step");
        assert!(text_rect(&previous, "Install the Mac helper").is_some());
    }

    #[test]
    fn first_run_settings_link_and_setup_statuses_explain_the_next_step() {
        let cases = [
            (
                SetupInfo::NotConfigured,
                Ok(vec![]),
                "No iPhone selected",
                "Requires Xcode on this Mac",
                "No paired iPhones found. Pair your iPhone with Xcode, then refresh the list.",
            ),
            (
                SetupInfo::NoDeviceSelected,
                Err("Open Xcode on this Mac.".into()),
                "No iPhone selected",
                "Requires Xcode on this Mac",
                "Open Xcode on this Mac.",
            ),
            (
                SetupInfo::SelectedNeedsSetup {
                    name: Some("Work iPhone".into()),
                },
                Ok(vec![]),
                "Work iPhone",
                "Mac helper setup required",
                "iPhone saved. To install the Mac helper, see step 3 below.",
            ),
        ];
        for (info, scan, title, caption, status) in cases {
            let ctx = egui::Context::default();
            let snapshot = DeviceSnapshot::default();
            snapshot.0.set(info).unwrap();
            ctx.data_mut(|d| d.insert_temp(egui::Id::new("iphone_setup_info"), snapshot));
            let frame = |events| {
                ctx.run_ui(
                    egui::RawInput {
                        events,
                        ..Default::default()
                    },
                    |ui| {
                        ui.set_width(440.0);
                        if show_if_open(ui).is_none() {
                            summary(ui)
                        }
                    },
                )
            };
            frame(vec![]);
            let home = frame(vec![]);
            assert!(text_rect(&home, title).is_some(), "{title}");
            assert!(text_rect(&home, caption).is_some(), "{caption}");
            frame(click_events(&home, "Set up iPhone…"));
            let form = PhoneForm {
                phones: Arc::new(OnceLock::from(scan)),
                draft: None,
                save: None,
                feedback: None,
            };
            ctx.data_mut(|d| d.insert_temp(details_id(), form));
            frame(vec![]);
            let setup = frame(vec![]);
            for text in ["iPhone setup", "Refresh iPhones", status] {
                assert!(text_rect(&setup, text).is_some(), "{text}");
            }
        }
    }

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
