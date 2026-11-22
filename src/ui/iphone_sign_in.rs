//! Account authentication choices and details for the iPhone shared by this Mac.
use crate::iphone_setup_info::{self, HelperFiles, PairedPhone, SetupInfo};
use crate::ui::theme;
use eframe::egui;
use std::sync::{Arc, OnceLock};

#[derive(Clone, Default)]
struct DeviceSnapshot(Arc<OnceLock<SetupInfo>>);

pub(super) fn start_task<T: Send + Sync + 'static>(
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

    fn invalidate(ctx: &egui::Context) {
        ctx.data_mut(|data| data.remove::<Self>(egui::Id::new("iphone_setup_info")));
    }
}

fn details_id() -> egui::Id {
    egui::Id::new("iphone_sign_in_details")
}

#[derive(Clone, Copy, Hash, PartialEq)]
enum PhonePage {
    Details,
    Setup,
    Helper,
}

pub(super) fn refresh_device_info(ctx: &egui::Context) {
    DeviceSnapshot::invalidate(ctx);
}

#[cfg(test)]
pub(super) fn set_connected_phone_for_test(ctx: &egui::Context) {
    let snapshot = DeviceSnapshot(Arc::new(OnceLock::from(SetupInfo::Selected {
        id: "test".into(),
        name: Some("Test iPhone".into()),
        wifi_connected: true,
        helper_files: HelperFiles::Current,
    })));
    ctx.data_mut(|data| data.insert_temp(egui::Id::new("iphone_setup_info"), snapshot));
}

pub(crate) fn close_details(ctx: &egui::Context) {
    crate::ui::iphone_setup_guide::cancel(ctx);
    ctx.data_mut(|data| data.remove::<PhonePage>(details_id()));
}

fn open_page(ctx: &egui::Context, page: PhonePage) {
    if page == PhonePage::Helper {
        crate::ui::iphone_setup_guide::refresh(ctx);
    }
    ctx.data_mut(|data| {
        if page == PhonePage::Setup
            && !data
                .get_temp::<PhoneForm>(details_id())
                .is_some_and(|form| form.connect.is_some())
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
        Some(SetupInfo::Selected { name, .. }) => name.as_deref().unwrap_or("Selected iPhone"),
    }
}

pub(super) fn summary(ui: &mut egui::Ui) {
    let snapshot = DeviceSnapshot::get(ui.ctx());
    let info = snapshot.0.get();
    let title = device_label(info);
    let (caption, page, action) = match info {
        Some(SetupInfo::NotConfigured | SetupInfo::NoDeviceSelected) => (
            "Connect over Wi-Fi with Xcode",
            PhonePage::Setup,
            "Connect iPhone…",
        ),
        Some(SetupInfo::Selected {
            helper_files: HelperFiles::NeedsSetup,
            ..
        }) => (
            "Mac helper needs setup",
            PhonePage::Details,
            "Sign-in details…",
        ),
        Some(SetupInfo::Selected {
            wifi_connected: true,
            ..
        }) => (
            "Connected over Wi-Fi",
            PhonePage::Details,
            "Sign-in details…",
        ),
        Some(SetupInfo::Selected {
            wifi_connected: false,
            ..
        }) => ("Wi-Fi disconnected", PhonePage::Details, "Sign-in details…"),
        _ => ("iPhone connection", PhonePage::Setup, "Connect iPhone…"),
    };
    let text_height = ui.text_style_height(&egui::TextStyle::Body)
        + ui.text_style_height(&egui::TextStyle::Small)
        + 3.0;
    let (_, details) = egui::containers::Sides::new()
        .height(text_height.max(ui.spacing().interact_size.y))
        .shrink_left()
        .show(
            ui,
            |ui| {
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 3.0;
                    ui.add(egui::Label::new(egui::RichText::new(title).strong()).truncate())
                        .on_hover_text(title);
                    ui.label(egui::RichText::new(caption).small().color(theme::MUTED));
                });
            },
            |ui| theme::settings_button(ui, action),
        );
    if details.clicked() {
        open_page(ui.ctx(), page);
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
                ui.heading(match page {
                    PhonePage::Setup => "iPhone connection",
                    PhonePage::Details => "iPhone sign-in",
                    PhonePage::Helper => "Set up iPhone automation",
                })
            },
            |ui| {
                ui.add_enabled(
                    !crate::ui::iphone_setup_guide::busy(ui.ctx()),
                    theme::secondary_button(if page == PhonePage::Helper {
                        "Back"
                    } else {
                        "Back to Settings"
                    }),
                )
            },
        );
    if back.clicked()
        || (!crate::ui::iphone_setup_guide::busy(ui.ctx())
            && !egui::Popup::is_any_open(ui.ctx())
            && ui.input_mut(|input| input.consume_key(egui::Modifiers::NONE, egui::Key::Escape)))
    {
        if page == PhonePage::Helper {
            open_page(ui.ctx(), PhonePage::Details);
        } else {
            close_details(ui.ctx());
        }
        ui.ctx().request_repaint();
    }

    let body = egui::ScrollArea::vertical()
        .id_salt(("iphone_sign_in_scroll", page))
        .auto_shrink([false, true])
        .show(ui, |ui| {
            if page == PhonePage::Setup {
                super::settings::section(ui, "SHARED IPHONE", show_setup);
                return;
            }
            if page == PhonePage::Helper {
                crate::ui::iphone_setup_guide::show(ui);
                return;
            }
            super::settings::section(ui, "SHARED IPHONE", show_shared_phone);
            ui.add_space(12.0);
            super::settings::section(ui, "MICROSOFT AUTHENTICATOR", |ui| {
                let snapshot = DeviceSnapshot::get(ui.ctx());
                match snapshot.0.get() {
                    Some(SetupInfo::Selected { helper_files: HelperFiles::NotInstalled, .. }) => {
                        ui.label("To use this iPhone for sign-in, set up the Mac helper.");
                    }
                    Some(SetupInfo::Selected { helper_files: HelperFiles::NeedsSetup, .. }) => {
                        ui.label("Run setup again to update or repair the Mac helper.");
                    }
                    _ => {}
                }
                if ui.add(theme::secondary_button("Set up automation…")).clicked() {
                    open_page(ui.ctx(), PhonePage::Helper);
                }
                ui.add_space(4.0);
                let steps = [
                    ("Before sign-in", "Unlock your iPhone on the same Wi-Fi as your Mac."),
                    ("On your Mac", "Monitor reads the number in Windows App."),
                    ("On your iPhone", "AutoLogin enters the number in Microsoft Authenticator. Complete Face ID if prompted."),
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
            ui.label(egui::RichText::new("In Accounts, open an account and turn on 2FA → Use iPhone.").small().color(theme::MUTED));
        });
    Some(body.inner_rect.top() - top + body.content_size.y)
}

fn show_shared_phone(ui: &mut egui::Ui) {
    let snapshot = DeviceSnapshot::get(ui.ctx());
    let info = snapshot.0.get();
    let status = match info {
        Some(SetupInfo::Selected { name: None, .. }) => {
            Some("The selected iPhone isn’t visible to this Mac.")
        }
        Some(SetupInfo::Selected {
            wifi_connected: true,
            ..
        }) => Some("Connected over Wi-Fi"),
        Some(SetupInfo::Selected {
            wifi_connected: false,
            ..
        }) => Some("Wi-Fi disconnected"),
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
                let change = ui.add(theme::secondary_button("Connect iPhone…"));
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

type PhoneAction = Arc<OnceLock<Result<(), String>>>;

#[derive(Clone)]
struct PhoneForm {
    phones: Arc<OnceLock<Result<Vec<PairedPhone>, String>>>,
    draft: Option<String>,
    connect: Option<PhoneAction>,
    pairing: Option<PhoneAction>,
    refresh_after_pairing: bool,
    feedback: Option<String>,
}

impl PhoneForm {
    fn discover(ctx: &egui::Context) -> Self {
        Self {
            phones: start_task(
                ctx,
                iphone_setup_info::paired_phones,
                Err("Couldn’t check paired iPhones. Try Refresh iPhones.".into()),
            ),
            draft: None,
            connect: None,
            pairing: None,
            refresh_after_pairing: false,
            feedback: None,
        }
    }

    fn suggest_phone(&mut self, snapshot: Option<&SetupInfo>) {
        if self.draft.is_some() {
            return;
        }
        let Some(Ok(phones)) = self.phones.get() else {
            return;
        };
        let phone = phones
            .iter()
            .find(|p| p.selected)
            .or_else(|| match snapshot {
                Some(SetupInfo::Selected { id, .. }) => {
                    phones.iter().find(|p| p.id.eq_ignore_ascii_case(id))
                }
                Some(SetupInfo::NotConfigured | SetupInfo::NoDeviceSelected)
                    if phones.len() == 1 =>
                {
                    phones.first()
                }
                _ => None,
            });
        self.draft = phone.map(|p| p.id.clone());
    }
}

fn show_setup(ui: &mut egui::Ui) {
    let id = details_id();
    let snapshot = DeviceSnapshot::get(ui.ctx());
    let mut form = ui
        .ctx()
        .data(|d| d.get_temp::<PhoneForm>(id))
        .unwrap_or_else(|| PhoneForm::discover(ui.ctx()));
    if let Some(result) = form.connect.as_ref().and_then(|task| task.get()).cloned() {
        form.connect = None;
        match result {
            Ok(()) => {
                let name = form
                    .phones
                    .get()
                    .and_then(|r| r.as_ref().ok())
                    .and_then(|phones| phones.iter().find(|p| Some(&p.id) == form.draft.as_ref()))
                    .map_or("iPhone", |p| p.name.as_str());
                let message = format!("{name} connected over Wi-Fi.");
                form = PhoneForm::discover(ui.ctx());
                form.feedback = Some(message);
            }
            Err(message) => form.feedback = Some(message),
        }
    }
    if let Some(result) = form.pairing.as_ref().and_then(|task| task.get()).cloned() {
        form.pairing = None;
        if let Err(message) = result {
            form.refresh_after_pairing = false;
            form.feedback = Some(message);
        }
    }
    let returned_from_pairing = form.refresh_after_pairing
        && ui.input(|i| i.events.contains(&egui::Event::WindowFocused(true)));
    form.suggest_phone(snapshot.0.get());
    ui.label("All accounts on this Mac share the iPhone you select here.");
    ui.add_space(4.0);
    let busy = form.connect.is_some();
    let mut can_connect = false;
    let mut has_phones = false;
    let draft_before = form.draft.clone();
    match form.phones.get() {
        None => {
            ui.label("Looking for paired iPhones…");
        }
        Some(Err(message)) => {
            ui.add(egui::Label::new(message.as_str()).wrap());
        }
        Some(Ok(phones)) if phones.is_empty() => {
            ui.label("No paired iPhones found.");
        }
        Some(Ok(phones)) => {
            has_phones = true;
            if matches!(
                snapshot.0.get(),
                Some(SetupInfo::Selected { name: None, .. })
            ) && !phones.iter().any(|p| p.selected)
            {
                ui.label("Your saved iPhone is unavailable. You can choose another.");
            }
            can_connect = ui
                .add_enabled_ui(!busy, |ui| phone_choice(ui, phones, &mut form.draft))
                .inner;
        }
    }
    if form.draft != draft_before {
        form.feedback = None;
    }

    if form.phones.get().is_some() {
        let pairing = |ui: &mut egui::Ui| pairing_help(ui, form.pairing.is_none() && !busy);
        let open_pairing = if has_phones {
            egui::CollapsingHeader::new("Pair another iPhone")
                .show(ui, pairing)
                .body_returned
                .unwrap_or(false)
        } else {
            pairing(ui)
        };
        if open_pairing {
            form.refresh_after_pairing = true;
            form.feedback = None;
            form.pairing = Some(start_task(
                ui.ctx(),
                crate::iphone_pairing::open_pairing_window,
                Err("Couldn’t open device pairing. Try again.".into()),
            ));
        }
    }
    ui.add_space(4.0);
    let (refresh, connect) = phone_actions(
        ui,
        !busy && form.phones.get().is_some(),
        !busy && can_connect,
        busy,
    );
    if let Some(device) = form.draft.as_ref().filter(|_| connect).cloned() {
        let ctx = ui.ctx().clone();
        form.feedback = None;
        form.refresh_after_pairing = false;
        form.connect = Some(start_task(
            ui.ctx(),
            move || {
                iphone_setup_info::connect_phone(&device)?;
                DeviceSnapshot::invalidate(&ctx);
                Ok(())
            },
            Err("Couldn’t connect to this iPhone. Try again.".into()),
        ));
    }
    if refresh || (returned_from_pairing && form.connect.is_none()) {
        form = PhoneForm::discover(ui.ctx());
        DeviceSnapshot::invalidate(ui.ctx());
    }
    if let Some(message) = &form.feedback {
        ui.add(egui::Label::new(message.as_str()).wrap());
    }
    if matches!(
        snapshot.0.get(),
        Some(SetupInfo::Selected {
            helper_files: HelperFiles::NotInstalled | HelperFiles::NeedsSetup,
            ..
        })
    ) {
        ui.label("Set up automation to use this iPhone for sign-in.");
        if ui
            .add(theme::secondary_button("Set up automation…"))
            .clicked()
        {
            open_page(ui.ctx(), PhonePage::Helper);
        }
    }
    ui.ctx().data_mut(|d| d.insert_temp(id, form));
}

fn pairing_help(ui: &mut egui::Ui, enabled: bool) -> bool {
    ui.label("Unlock your iPhone. In Device Hub, choose + → Pair Nearby Device and confirm Trust on the phone.");
    ui.label("With older Xcode, open Window → Devices and Simulators. A cable may be needed for the first pairing.");
    ui.label(
        "Keep both devices on the same Wi-Fi, disconnect any cable, then return here to connect.",
    );
    ui.horizontal_wrapped(|ui| {
        let open = ui
            .add_enabled(enabled, theme::secondary_button("Open device pairing…"))
            .clicked();
        ui.hyperlink_to("Get Xcode", "https://apps.apple.com/app/xcode/id497799835");
        open
    })
    .inner
}

fn phone_choice(ui: &mut egui::Ui, phones: &[PairedPhone], draft: &mut Option<String>) -> bool {
    let chosen = phones
        .iter()
        .find(|phone| Some(&phone.id) == draft.as_ref());
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
        .style(theme::picker_popup_style)
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
    phones.iter().any(|p| Some(&p.id) == draft.as_ref())
}

fn phone_actions(
    ui: &mut egui::Ui,
    can_refresh: bool,
    can_connect: bool,
    busy: bool,
) -> (bool, bool) {
    egui::containers::Sides::new().height(28.0).show(
        ui,
        |ui| {
            ui.add_enabled(can_refresh, theme::secondary_button("Refresh iPhones"))
                .clicked()
        },
        |ui| {
            ui.add_enabled(
                can_connect,
                theme::primary_button(if busy {
                    "Connecting…"
                } else {
                    "Connect iPhone"
                }),
            )
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

    fn check_option_hover(
        open: &egui::FullOutput,
        label: &str,
        mut render: impl FnMut(Vec<egui::Event>) -> egui::FullOutput,
    ) {
        let idle = text_rect(open, label).expect("option in the open picker");
        render(vec![egui::Event::PointerMoved(idle.center())]);
        let hover = render(vec![]);
        assert_eq!(
            text_rect(&hover, label),
            Some(idle),
            "{label} moved on hover"
        );
        let highlighted = |frame: &egui::FullOutput| {
            frame.shapes.iter().any(|clipped| {
                matches!(&clipped.shape, egui::Shape::Rect(row)
                    if row.fill == theme::SURFACE && row.rect.contains_rect(idle))
            })
        };
        assert!(highlighted(&hover), "{label} must be visibly highlighted");
        render(vec![egui::Event::PointerGone]);
        let outside = render(vec![]);
        assert_eq!(text_rect(&outside, label), Some(idle));
        assert!(!highlighted(&outside));
    }

    #[test]
    fn choosing_between_two_iphones_requires_an_explicit_selection_and_connect() {
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        ctx.all_styles_mut(|style| style.animation_time = 0.0);
        let phones = [
            PairedPhone {
                id: "AAAAAAAA-1234567890000001".into(),
                name: "Work iPhone".into(),
                wifi_connected: true,
                selected: false,
            },
            PairedPhone {
                id: "AAAAAAAA-1234567890000002".into(),
                name: "Personal iPhone".into(),
                wifi_connected: false,
                selected: false,
            },
        ];
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
                    let can_connect = phone_choice(ui, &phones, &mut draft);
                    if phone_actions(ui, true, can_connect, false).1 {
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
        let save = text_rect(&initial, "Connect iPhone").unwrap();
        assert!(
            (refresh.center().y - save.center().y).abs() < 2.0 && refresh.right() < save.left()
        );
        frame(click_events(&initial, "Connect iPhone"));
        frame(click_events(&initial, "Choose iPhone…"));
        let open = frame(vec![]);
        assert_eq!(
            field_outline(&open).unwrap().1,
            ctx.global_style().visuals.selection.stroke
        );
        assert!(text_rect(&open, &phones[0].id).is_none());
        check_option_hover(&open, "Work iPhone", &mut frame);
        frame(click_events(&open, "Work iPhone"));
        let selected = frame(vec![]);
        assert!(text_rect(&selected, "Connected over Wi-Fi").is_some());
        frame(click_events(&selected, "Connect iPhone"));
        assert_eq!(requests, vec![Some(phones[0].id.clone())]);
    }

    #[test]
    fn only_unsaved_setups_suggest_the_sole_phone() {
        let phone = PairedPhone {
            id: "AAAAAAAA-1234567890000001".into(),
            name: "Work iPhone".into(),
            wifi_connected: false,
            selected: false,
        };
        let mut form = PhoneForm {
            phones: Arc::new(OnceLock::from(Ok(vec![phone.clone()]))),
            draft: None,
            connect: None,
            pairing: None,
            refresh_after_pairing: false,
            feedback: None,
        };
        form.suggest_phone(None);
        assert_eq!(form.draft, None);
        let offline = SetupInfo::Selected {
            id: "AAAAAAAA-1234567890000002".into(),
            name: None,
            helper_files: HelperFiles::NotInstalled,
            wifi_connected: false,
        };
        form.suggest_phone(Some(&offline));
        assert_eq!(form.draft, None);
        form.suggest_phone(Some(&SetupInfo::NotConfigured));
        assert_eq!(form.draft.as_ref(), Some(&phone.id));
        let other = PairedPhone {
            id: "AAAAAAAA-1234567890000003".into(),
            ..phone.clone()
        };
        form.phones = Arc::new(OnceLock::from(Ok(vec![phone.clone(), other.clone()])));
        form.draft = None;
        form.suggest_phone(Some(&SetupInfo::NoDeviceSelected));
        assert_eq!(form.draft, None);
        let saved = SetupInfo::Selected {
            id: other.id.clone(),
            name: Some(other.name.clone()),
            wifi_connected: true,
            helper_files: HelperFiles::NotInstalled,
        };
        form.suggest_phone(Some(&saved));
        assert_eq!(form.draft.as_ref(), Some(&other.id));
        form.draft = Some(phone.id.clone());
        form.suggest_phone(Some(&saved));
        assert_eq!(form.draft.as_ref(), Some(&phone.id));
    }

    #[test]
    fn connection_failure_keeps_the_phone_available_for_retry() {
        let ctx = egui::Context::default();
        let phone = PairedPhone {
            id: "AAAAAAAA-1234567890000001".into(),
            name: "Work iPhone".into(),
            wifi_connected: false,
            selected: false,
        };
        let snapshot = DeviceSnapshot(Arc::new(OnceLock::from(SetupInfo::NotConfigured)));
        let result = Arc::new(OnceLock::new());
        let form = PhoneForm {
            phones: Arc::new(OnceLock::from(Ok(vec![phone.clone()]))),
            draft: Some(phone.id.clone()),
            connect: Some(result.clone()),
            pairing: None,
            refresh_after_pairing: false,
            feedback: None,
        };
        ctx.data_mut(|d| {
            d.insert_temp(egui::Id::new("iphone_setup_info"), snapshot);
            d.insert_temp(details_id(), form);
        });
        let frame = || {
            ctx.run_ui(egui::RawInput::default(), |ui| {
                ui.set_width(440.0);
                show_setup(ui);
            })
        };
        frame();
        assert!(text_rect(&frame(), "Connecting…").is_some());
        result
            .set(Err("Unlock your iPhone and try again.".into()))
            .unwrap();
        let retry = frame();
        assert!(text_rect(&retry, "Unlock your iPhone and try again.").is_some());
        assert!(text_rect(&retry, "Connect iPhone").is_some());
        let form = ctx.data(|d| d.get_temp::<PhoneForm>(details_id())).unwrap();
        assert_eq!(form.draft, Some(phone.id));
        assert!(form.connect.is_none());
    }

    #[test]
    fn first_run_settings_link_and_setup_statuses_explain_the_next_step() {
        let cases = [
            (
                SetupInfo::NotConfigured,
                Ok(vec![]),
                "No iPhone selected",
                "Connect over Wi-Fi with Xcode",
                "No paired iPhones found.",
            ),
            (
                SetupInfo::NoDeviceSelected,
                Err("Open Xcode on this Mac.".into()),
                "No iPhone selected",
                "Connect over Wi-Fi with Xcode",
                "Open Xcode on this Mac.",
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
            frame(click_events(&home, "Connect iPhone…"));
            let form = PhoneForm {
                phones: Arc::new(OnceLock::from(scan)),
                draft: None,
                connect: None,
                pairing: None,
                refresh_after_pairing: false,
                feedback: None,
            };
            ctx.data_mut(|d| d.insert_temp(details_id(), form));
            frame(vec![]);
            let setup = frame(vec![]);
            assert!(text_rect(&setup, "SETUP GUIDE").is_none());
            assert!(text_rect(&setup, "Mac requirements").is_none());
            for text in [
                "SHARED IPHONE",
                "Refresh iPhones",
                "Open device pairing…",
                "Get Xcode",
                status,
            ] {
                assert!(text_rect(&setup, text).is_some(), "{text}");
            }
        }
    }

    #[test]
    fn shared_device_details_return_to_settings_and_preserve_the_selected_offline_phone() {
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let view = DeviceSnapshot::default();
        view.0
            .set(SetupInfo::Selected {
                id: "AAAAAAAA-1234567890000001".into(),
                name: Some("Work iPhone".into()),
                wifi_connected: false,
                helper_files: HelperFiles::Current,
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
        let phone = text_rect(&home, "Work iPhone").unwrap();
        let caption = text_rect(&home, "Wi-Fi disconnected").unwrap();
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
        assert!(text_rect(&home, "Work iPhone").is_some());
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
