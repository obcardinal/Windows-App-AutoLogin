use crate::models::MonitorControlState;
use eframe::egui;
use std::sync::Arc;

pub const ACCENT: egui::Color32 = egui::Color32::from_rgb(54, 87, 198);
pub const ACCENT_SOFT: egui::Color32 = egui::Color32::from_rgb(233, 238, 255);
pub const DANGER: egui::Color32 = egui::Color32::from_rgb(166, 49, 61);
pub const DANGER_SOFT: egui::Color32 = egui::Color32::from_rgb(252, 235, 238);
pub const MUTED: egui::Color32 = egui::Color32::from_rgb(84, 96, 114);
pub const TEXT: egui::Color32 = egui::Color32::from_rgb(29, 38, 54);
pub const SURFACE: egui::Color32 = egui::Color32::from_rgb(246, 247, 250);
pub const STROKE: egui::Color32 = egui::Color32::from_rgb(216, 221, 229);
const TAB_RAIL: egui::Color32 = egui::Color32::from_rgb(238, 240, 245);
const TOOLBAR_HOVER: egui::Color32 = egui::Color32::from_rgb(226, 230, 238);
const TAB_PRESSED: egui::Color32 = egui::Color32::from_rgb(205, 213, 225);
const WINDOW_MARGIN: i8 = 9;
const SEMIBOLD: &str = "Inter Semibold";

pub fn apply(ctx: &egui::Context) {
    apply_fonts(ctx);
    egui_extras::install_image_loaders(ctx);

    let mut style = egui::Style::default();
    let mut visuals = egui::Visuals::light();

    visuals.panel_fill = SURFACE;
    visuals.window_fill = egui::Color32::WHITE;
    visuals.faint_bg_color = egui::Color32::from_rgb(241, 245, 249);
    visuals.selection.bg_fill = ACCENT_SOFT;
    visuals.selection.stroke = egui::Stroke::new(1.0, ACCENT);
    visuals.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, STROKE);
    visuals.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, egui::Color32::TRANSPARENT);
    visuals.widgets.inactive.corner_radius = egui::CornerRadius::same(7);
    visuals.widgets.hovered.corner_radius = egui::CornerRadius::same(7);
    visuals.widgets.active.corner_radius = egui::CornerRadius::same(7);
    visuals.widgets.open.corner_radius = egui::CornerRadius::same(7);
    visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(248, 250, 252);
    visuals.widgets.hovered.bg_fill = TAB_RAIL;
    visuals.widgets.active.bg_fill = ACCENT_SOFT;
    visuals.override_text_color = Some(TEXT);

    style.visuals = visuals;
    style.spacing.item_spacing = egui::vec2(8.0, 6.0);
    style.spacing.button_padding = egui::vec2(12.0, 5.0);
    style.spacing.window_margin = egui::Margin::same(12);
    style.spacing.interact_size = egui::vec2(48.0, 28.0);
    style.spacing.text_edit_width = 240.0;
    style.spacing.slider_width = 190.0;
    style.spacing.combo_width = 190.0;
    style.text_styles.insert(
        egui::TextStyle::Small,
        egui::FontId::new(12.5, egui::FontFamily::Proportional),
    );
    style
        .text_styles
        .insert(egui::TextStyle::Body, egui::FontId::proportional(14.0));
    style.text_styles.insert(
        egui::TextStyle::Button,
        egui::FontId::new(13.0, egui::FontFamily::Name(SEMIBOLD.into())),
    );
    style.text_styles.insert(
        egui::TextStyle::Heading,
        egui::FontId::new(24.0, egui::FontFamily::Name(SEMIBOLD.into())),
    );
    style.text_styles.insert(
        egui::TextStyle::Monospace,
        egui::FontId::new(15.75, egui::FontFamily::Monospace),
    );

    // eframe may first report the system appearance after this setup. Install
    // our light palette in its own slot before the first native frame.
    ctx.set_theme(egui::Theme::Light);
    ctx.set_global_style(style);
}

fn apply_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    let inter = egui::FontData::from_static(include_bytes!("../../assets/fonts/InterVariable.ttf"));
    let fallback = fonts.families[&egui::FontFamily::Proportional].clone();
    for (name, weight, family) in [
        ("Inter", 430.0, egui::FontFamily::Proportional),
        (SEMIBOLD, 620.0, egui::FontFamily::Name(SEMIBOLD.into())),
    ] {
        let face = inter.clone().tweak(egui::FontTweak {
            hinting_override: Some(true),
            coords: egui::epaint::text::VariationCoords::new([(b"wght", weight)]),
            ..Default::default()
        });
        fonts.font_data.insert(name.into(), Arc::new(face));
        let mut faces = fallback.clone();
        faces.insert(0, name.into());
        fonts.families.insert(family, faces);
    }

    ctx.set_fonts(fonts);
}

pub fn top_bar_frame() -> egui::Frame {
    egui::Frame::new()
        .fill(egui::Color32::WHITE)
        .inner_margin(egui::Margin::same(WINDOW_MARGIN))
}

fn apply_toolbar_style(ui: &mut egui::Ui) {
    let visuals = ui.visuals_mut();
    visuals.override_text_color = Some(MUTED);
    visuals.selection.bg_fill = egui::Color32::WHITE;
    visuals.selection.stroke = egui::Stroke::new(1.0, ACCENT);
    for (state, fill) in [
        (&mut visuals.widgets.inactive, egui::Color32::TRANSPARENT),
        (&mut visuals.widgets.hovered, TOOLBAR_HOVER),
        (&mut visuals.widgets.active, TOOLBAR_HOVER),
    ] {
        state.weak_bg_fill = fill;
        state.bg_stroke = egui::Stroke::NONE;
        state.expansion = 0.0;
    }
}

fn navigation_button(button: egui::Button<'_>, radius: u8) -> impl egui::Widget + '_ {
    move |ui: &mut egui::Ui| {
        let mut button = button.corner_radius(radius);
        // The selected tab normally paints white, including while the pointer is over it.
        if ui
            .ctx()
            .read_response(ui.next_auto_id())
            .is_some_and(|r| r.is_pointer_button_down_on())
        {
            button = button.fill(TAB_PRESSED);
        }
        let response = ui.add(button);
        if response.is_pointer_button_down_on() && response.has_focus() {
            response.surrender_focus();
        } else if response.has_focus() {
            ui.painter().rect_stroke(
                response.rect,
                radius,
                egui::Stroke::new(1.5, MUTED),
                egui::StrokeKind::Inside,
            );
        }
        response.on_hover_cursor(egui::CursorIcon::PointingHand)
    }
}

pub fn segmented_control(ui: &mut egui::Ui, contents: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::new()
        .fill(TAB_RAIL)
        .corner_radius(8)
        .inner_margin(3)
        .show(ui, |ui| {
            apply_toolbar_style(ui);
            ui.spacing_mut().item_spacing.x = 2.0;
            ui.spacing_mut().button_padding = egui::vec2(9.0, 3.0);
            ui.horizontal(contents);
        });
}

pub fn segment(
    ui: &mut egui::Ui,
    label: &str,
    icon: Option<egui::ImageSource<'static>>,
    selected: bool,
) -> egui::Response {
    let mut contents =
        egui::Atoms::new(egui::RichText::new(label).text_style(egui::TextStyle::Button));
    if let Some(icon) = icon {
        contents.push_left(toolbar_icon(icon));
    }
    ui.add(navigation_button(
        egui::Button::selectable(selected, contents)
            .image_tint_follows_text_color(true)
            .wrap_mode(egui::TextWrapMode::Extend)
            .min_size(egui::vec2(0.0, 28.0)),
        6,
    ))
}

pub(super) fn section_switcher<T: Copy + PartialEq>(
    ui: &mut egui::Ui,
    tabs: &[(T, &str)],
    selected: T,
) -> T {
    const HEIGHT: f32 = 34.0;
    const INSET: f32 = 3.0;
    const GAP: f32 = 2.0;

    let font = egui::TextStyle::Button.resolve(ui.style());
    let widths: Vec<f32> = tabs
        .iter()
        .map(|(_, label)| {
            ui.painter()
                .layout_no_wrap((*label).into(), font.clone(), MUTED)
                .size()
                .x
                .ceil()
                + 24.0
        })
        .collect();
    let total: f32 = widths.iter().sum();
    let spacing = 2.0 * INSET + GAP * tabs.len().saturating_sub(1) as f32;
    let (row, _) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), HEIGHT),
        egui::Sense::hover(),
    );
    let width = row.width().min(total + spacing);
    let rail = egui::Rect::from_center_size(row.center(), egui::vec2(width, HEIGHT));
    let radius = (HEIGHT * 0.5) as u8;
    ui.painter().rect_filled(rail, radius, TAB_RAIL);

    let mut controls = ui.new_child(egui::UiBuilder::new().max_rect(rail));
    apply_toolbar_style(&mut controls);
    controls.spacing_mut().button_padding = egui::Vec2::ZERO;
    let scale = ((width - spacing) / total).clamp(0.0, 1.0);
    let mut next = selected;
    let mut left = rail.left() + INSET;
    for (&(value, label), natural_width) in tabs.iter().zip(widths) {
        let rect = egui::Rect::from_min_size(
            egui::pos2(left, rail.top() + INSET),
            egui::vec2(natural_width * scale, HEIGHT - 2.0 * INSET),
        );
        let label = egui::RichText::new(label).text_style(egui::TextStyle::Button);
        let button = egui::Button::selectable(value == selected, label).truncate();
        if controls
            .place(rect, navigation_button(button, radius - INSET as u8))
            .clicked()
        {
            next = value;
        }
        left = rect.right() + GAP;
    }
    next
}

#[cfg(target_os = "macos")]
pub fn picker_popup_style(style: &mut egui::Style) {
    let widgets = &mut style.visuals.widgets;
    // A selectable button omits its idle frame. Keep its inset identical to
    // the framed hover state so neither the label nor the following rows move.
    widgets.inactive.expansion = 0.0;
    widgets.hovered.expansion = 0.0;
    widgets.active.expansion = 0.0;
    widgets.inactive.bg_stroke = egui::Stroke::NONE;
    widgets.hovered.bg_stroke = egui::Stroke::new(1.0, STROKE);
    widgets.inactive.weak_bg_fill = egui::Color32::TRANSPARENT;
    widgets.hovered.weak_bg_fill = SURFACE;
    widgets.active.weak_bg_fill = ACCENT_SOFT;
    widgets.active.bg_stroke = style.visuals.selection.stroke;
}

pub fn content_frame() -> egui::Frame {
    egui::Frame::new()
        .fill(SURFACE)
        .inner_margin(egui::Margin::symmetric(18, 12))
}

pub fn tab_content_frame() -> egui::Frame {
    egui::Frame::new()
        .fill(SURFACE)
        .inner_margin(egui::Margin::same(WINDOW_MARGIN))
}

pub fn glass_frame() -> egui::Frame {
    egui::Frame::new()
        .fill(egui::Color32::WHITE)
        .stroke(egui::Stroke::new(1.0, STROKE))
        .corner_radius(egui::CornerRadius::same(8))
        .inner_margin(egui::Margin::symmetric(16, 14))
}

pub fn compact_frame() -> egui::Frame {
    egui::Frame::new()
        .fill(egui::Color32::WHITE)
        .stroke(egui::Stroke::new(1.0, STROKE))
        .corner_radius(egui::CornerRadius::same(10))
        .inner_margin(egui::Margin::symmetric(12, 8))
}

#[cfg(feature = "diagnostics-ui")]
pub fn page_header(
    ui: &mut egui::Ui,
    title: &str,
    subtitle: &str,
    actions: impl FnOnce(&mut egui::Ui),
) {
    glass_frame().show(ui, |ui| {
        let available_width = ui.available_width();
        if available_width < 620.0 {
            ui.vertical(|ui| {
                ui.heading(title);
                ui.add_space(4.0);
                ui.add(egui::Label::new(muted(subtitle)).wrap());
                ui.add_space(10.0);
                ui.horizontal_wrapped(actions);
            });
        } else {
            ui.horizontal(|ui| {
                let action_width = (available_width * 0.34).clamp(190.0, 360.0);
                let text_width = (available_width - action_width - 12.0).max(180.0);
                ui.allocate_ui_with_layout(
                    egui::vec2(text_width, 0.0),
                    egui::Layout::top_down(egui::Align::LEFT),
                    |ui| {
                        ui.heading(title);
                        ui.add_space(4.0);
                        ui.add(egui::Label::new(muted(subtitle)).wrap());
                    },
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), actions);
            });
        }
    });
    ui.add_space(12.0);
}

pub fn tab_heading<R>(
    ui: &mut egui::Ui,
    title: &str,
    actions: impl FnOnce(&mut egui::Ui) -> R,
) -> R {
    ui.horizontal(|ui| {
        ui.set_min_height(36.0);
        ui.heading(egui::RichText::new(title).color(TEXT));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), actions)
            .inner
    })
    .inner
}

pub fn section_label(text: &str) -> egui::RichText {
    egui::RichText::new(text)
        .text_style(egui::TextStyle::Button)
        .size(10.5)
        .extra_letter_spacing(0.75)
        .color(MUTED)
}

pub fn muted(text: impl Into<String>) -> egui::RichText {
    egui::RichText::new(text)
        .color(MUTED)
        .line_height(Some(22.0))
}

pub fn toolbar_icon(source: egui::ImageSource<'static>) -> egui::Image<'static> {
    egui::Image::new(source).fit_to_exact_size(egui::vec2(16.0, 16.0))
}

pub fn status_text(text: impl Into<String>) -> egui::RichText {
    let text = text.into();
    let color = message_color(&text);
    egui::RichText::new(text)
        .color(color)
        .line_height(Some(22.0))
}

enum ButtonKind {
    Filled(egui::Color32),
    Secondary,
}

pub struct ActionButton {
    button: egui::Button<'static>,
    kind: ButtonKind,
}

impl ActionButton {
    fn new(button: egui::Button<'static>, kind: ButtonKind) -> Self {
        Self {
            button: button.corner_radius(7).min_size(egui::vec2(0.0, 28.0)),
            kind,
        }
    }

    pub fn min_size(mut self, size: egui::Vec2) -> Self {
        self.button = self.button.min_size(size);
        self
    }
}

impl egui::Widget for ActionButton {
    fn ui(self, ui: &mut egui::Ui) -> egui::Response {
        let (idle, hover, active, outline, active_outline) = match self.kind {
            ButtonKind::Filled(color) => (
                color,
                color.lerp_to_gamma(egui::Color32::BLACK, 0.12),
                color.lerp_to_gamma(egui::Color32::BLACK, 0.24),
                color,
                color,
            ),
            ButtonKind::Secondary => (
                egui::Color32::WHITE,
                TOOLBAR_HOVER,
                ACCENT_SOFT,
                STROKE,
                ACCENT,
            ),
        };
        ui.scope(|ui| {
            let enabled = ui.is_enabled();
            let widgets = &mut ui.visuals_mut().widgets;
            for (state, fill, stroke) in [
                (&mut widgets.inactive, idle, outline),
                (&mut widgets.hovered, hover, outline),
                (&mut widgets.active, active, active_outline),
            ] {
                state.weak_bg_fill = if enabled { fill } else { idle };
                state.bg_stroke = egui::Stroke::new(1.0, if enabled { stroke } else { outline });
                state.expansion = 0.0;
            }
            ui.add(self.button)
                .on_hover_cursor(egui::CursorIcon::PointingHand)
        })
        .inner
    }
}

fn filled_button(text: impl Into<String>, color: egui::Color32) -> ActionButton {
    let button = egui::Button::new(
        egui::RichText::new(text.into())
            .text_style(egui::TextStyle::Button)
            .color(egui::Color32::WHITE),
    );
    ActionButton::new(button, ButtonKind::Filled(color))
}

pub fn primary_button(text: impl Into<String>) -> ActionButton {
    filled_button(text, ACCENT)
}

pub fn danger_button(text: impl Into<String>) -> ActionButton {
    filled_button(text, DANGER)
}

#[cfg(target_os = "macos")]
pub fn settings_button(ui: &mut egui::Ui, label: &str) -> egui::Response {
    ui.add(secondary_button(label))
}

pub fn secondary_button(text: impl Into<String>) -> ActionButton {
    ActionButton::new(
        egui::Button::new(egui::RichText::new(text.into()).color(TEXT)),
        ButtonKind::Secondary,
    )
}

pub fn monitor_button(state: MonitorControlState) -> impl egui::Widget {
    move |ui: &mut egui::Ui| {
        let (rect, response) = ui.allocate_exact_size(egui::vec2(72.0, 28.0), egui::Sense::click());
        let fill = if response.is_pointer_button_down_on() {
            STROKE
        } else if response.hovered() || response.highlighted() {
            TOOLBAR_HOVER
        } else {
            TAB_RAIL
        };
        let outline = if response.has_focus() {
            egui::Stroke::new(1.0, ACCENT)
        } else {
            egui::Stroke::NONE
        };
        ui.painter()
            .rect(rect, 8, fill, outline, egui::StrokeKind::Inside);
        let (label, icon) = if state.toggle_requests_stop() {
            ("Stop", egui::include_image!("../../assets/icons/stop.svg"))
        } else {
            ("Start", egui::include_image!("../../assets/icons/play.svg"))
        };
        let icon_rect = egui::Rect::from_center_size(
            rect.left_center() + egui::vec2(18.0, 0.0),
            egui::Vec2::splat(16.0),
        );
        toolbar_icon(icon).tint(MUTED).paint_at(ui, icon_rect);
        ui.painter().text(
            icon_rect.right_center() + egui::vec2(6.0, 0.0),
            egui::Align2::LEFT_CENTER,
            label,
            egui::TextStyle::Button.resolve(ui.style()),
            MUTED,
        );
        response.widget_info(|| {
            egui::WidgetInfo::labeled(
                egui::WidgetType::Button,
                response.enabled(),
                state.toggle_label(),
            )
        });
        response.on_hover_cursor(egui::CursorIcon::PointingHand)
    }
}

pub fn message_color(msg: &str) -> egui::Color32 {
    let msg = msg.to_lowercase();
    if msg.contains("fail") || msg.contains("error") || msg.contains("missing") {
        DANGER
    } else {
        MUTED
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_switcher_centers_capsules_and_keeps_all_labels_visible() {
        let tabs = [
            (0, "System"),
            (1, "Windows App"),
            (2, "Security"),
            (3, "2FA"),
        ];
        for width in [280.0, crate::app::MIN_MAIN_WINDOW_WIDTH] {
            let ctx = egui::Context::default();
            apply(&ctx);
            let render = |events| {
                ctx.run_ui(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(
                            egui::Pos2::ZERO,
                            egui::vec2(width, 80.0),
                        )),
                        events,
                        ..Default::default()
                    },
                    |ui| {
                        section_switcher(ui, &tabs, 0);
                    },
                )
            };
            let capsule = |frame: &egui::FullOutput, fill| {
                frame
                    .shapes
                    .iter()
                    .find_map(|shape| match &shape.shape {
                        egui::Shape::Rect(r) if r.fill == fill => {
                            assert!(f32::from(r.corner_radius.nw) >= r.rect.height() * 0.5);
                            Some(r.rect)
                        }
                        _ => None,
                    })
                    .expect("visible capsule")
            };
            let idle = render(vec![]);
            let rail = capsule(&idle, TAB_RAIL);
            assert!((rail.center().x - width * 0.5).abs() <= 0.5);
            let selected = capsule(&idle, egui::Color32::WHITE);
            assert_eq!(rail.top() + 3.0, selected.top());
            let mut labels = idle.shapes.iter().filter_map(|shape| match &shape.shape {
                egui::Shape::Text(text) => Some(text),
                _ => None,
            });
            for (_, label) in tabs {
                let text = labels.next().unwrap();
                assert_eq!(text.galley.text(), label);
                assert!(!text.galley.elided);
                assert!(rail.contains_rect(text.visual_bounding_rect()));
            }
            let pointer = rail.right_center() - egui::vec2(16.0, 0.0);
            let hovered = render(vec![egui::Event::PointerMoved(pointer)]);
            assert!(capsule(&hovered, TOOLBAR_HOVER).contains(pointer));
            assert_eq!(capsule(&hovered, egui::Color32::WHITE), selected);
        }
    }

    #[test]
    fn navigation_feedback_preserves_tab_geometry_and_reserves_outlines_for_keyboard_focus() {
        for toolbar in [true, false] {
            let tabs = if toolbar {
                [(0, "Accounts"), (1, "Settings")]
            } else {
                [(0, "System"), (1, "Windows App")]
            };
            let ctx = egui::Context::default();
            apply(&ctx);
            let mut selected = 0;
            let mut render = |events| {
                ctx.run_ui(
                    egui::RawInput {
                        events,
                        ..Default::default()
                    },
                    |ui| {
                        if toolbar {
                            let icon = egui::include_image!("../../assets/icons/settings.svg");
                            segmented_control(ui, |ui| {
                                for (value, label) in tabs {
                                    if segment(ui, label, Some(icon.clone()), selected == value)
                                        .clicked()
                                    {
                                        selected = value;
                                    }
                                }
                            });
                        } else {
                            selected = section_switcher(ui, &tabs, selected);
                        }
                    },
                )
            };
            let label = |frame: &egui::FullOutput| {
                frame
                    .shapes
                    .iter()
                    .find_map(|item| match &item.shape {
                        egui::Shape::Text(t) if t.galley.text() == tabs[1].1 => {
                            Some(t.visual_bounding_rect())
                        }
                        _ => None,
                    })
                    .unwrap()
            };
            let idle = render(vec![]);
            let bounds = label(&idle);
            let pos = bounds.center();
            let button = |pos, pressed| egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed,
                modifiers: egui::Modifiers::NONE,
            };
            let painted = |frame: &egui::FullOutput| {
                assert_eq!(label(frame), bounds);
                let mut background = None;
                for item in &frame.shapes {
                    let egui::Shape::Rect(r) = &item.shape else {
                        continue;
                    };
                    if !r.rect.contains(pos) {
                        continue;
                    }
                    assert!(r.stroke.is_empty(), "pointer drew outline {:?}", r.stroke);
                    if r.fill != TAB_RAIL && r.fill != egui::Color32::TRANSPARENT {
                        background = Some((r.rect, r.fill));
                    }
                }
                background
            };
            assert!(painted(&idle).is_none());
            let (rect, hover) = painted(&render(vec![egui::Event::PointerMoved(pos)])).unwrap();
            let (pressed_rect, pressed) = painted(&render(vec![button(pos, true)])).unwrap();
            assert_eq!(rect, pressed_rect);
            assert_ne!(hover, pressed);
            painted(&render(vec![button(pos, false)]));
            let (selected_rect, fill) = painted(&render(vec![egui::Event::PointerGone])).unwrap();
            assert_eq!(rect, selected_rect);
            assert_ne!(fill, hover);
            assert_ne!(fill, pressed);

            render(vec![egui::Event::Key {
                key: egui::Key::Tab,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: egui::Modifiers::NONE,
            }]);
            let focus_ring = |frame: &egui::FullOutput| {
                frame.shapes.iter().find_map(|item| match &item.shape {
                    egui::Shape::Rect(r) if r.stroke.color == MUTED && !r.stroke.is_empty() => {
                        Some(r.rect)
                    }
                    _ => None,
                })
            };
            let focused = focus_ring(&render(vec![])).expect("Tab shows the keyboard focus ring");
            let pos = focused.center();
            assert_eq!(
                focus_ring(&render(vec![egui::Event::PointerMoved(pos)])),
                Some(focused)
            );
            assert!(focus_ring(&render(vec![button(pos, true)])).is_none());
            assert!(focus_ring(&render(vec![button(pos, false)])).is_none());
        }
    }

    #[test]
    fn action_buttons_change_fill_and_preserve_sizing_and_keyboard_activation() {
        for (label, make_button) in [
            ("Save", primary_button as fn(&'static str) -> ActionButton),
            ("Cancel", secondary_button),
            ("Delete", danger_button),
        ] {
            let ctx = egui::Context::default();
            apply(&ctx);
            let size = egui::vec2(104.0, 30.0);
            let render = |enabled, events| {
                let mut response = None;
                let output = ctx.run_ui(
                    egui::RawInput {
                        events,
                        ..Default::default()
                    },
                    |ui| {
                        response = Some(
                            ui.add_enabled_ui(enabled, |ui| {
                                ui.add_sized(size, make_button(label).min_size(size))
                            })
                            .inner,
                        );
                    },
                );
                let response = response.unwrap();
                let frame = output
                    .shapes
                    .iter()
                    .rev()
                    .find_map(|shape| match &shape.shape {
                        egui::Shape::Rect(rect) if rect.rect == response.rect => Some(rect),
                        _ => None,
                    })
                    .expect("painted button at its hit target");
                (response, frame.fill, output.platform_output.cursor_icon)
            };
            let (idle, idle_fill, _) = render(true, vec![]);
            assert_eq!(idle.rect.size(), size);
            let position = egui::pos2(idle.rect.right() - 1.0, idle.rect.center().y);
            let hover = egui::Event::PointerMoved(position);
            let (hovered, hover_fill, cursor) = render(true, vec![hover.clone()]);
            assert_eq!(hovered.rect, idle.rect);
            assert_ne!(hover_fill, idle_fill);
            assert_eq!(cursor, egui::CursorIcon::PointingHand);
            let (disabled, disabled_fill, cursor) = render(false, vec![hover]);
            assert!(!disabled.enabled());
            assert_ne!(cursor, egui::CursorIcon::PointingHand);
            let outside = egui::Event::PointerMoved(position + egui::vec2(20.0, 0.0));
            assert_eq!(render(false, vec![outside]).1, disabled_fill);
            let (enabled, _, _) = render(true, vec![]);
            enabled.request_focus();
            let (focused, active_fill, _) = render(true, vec![]);
            assert!(focused.has_focus());
            assert_ne!(active_fill, hover_fill);
            assert_ne!(active_fill, idle_fill);
            assert_eq!(focused.rect, idle.rect);
            let enter = egui::Event::Key {
                key: egui::Key::Enter,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: egui::Modifiers::NONE,
            };
            assert!(render(true, vec![enter]).0.clicked());
        }
    }

    #[test]
    fn icon_actions_keep_their_painted_contents_and_hit_target_still() {
        #[derive(Debug, PartialEq)]
        struct ButtonFrame {
            geometry: [egui::Rect; 3],
            text: Option<egui::Rect>,
            fill: egui::Color32,
            clicked: bool,
        }

        let mut monitor_geometry = None;
        for (label, monitor_state) in [
            ("Add Account", None),
            ("Stop", Some(MonitorControlState::Running)),
            ("Start", Some(MonitorControlState::Stopped)),
            ("Stop", Some(MonitorControlState::PausedWithStartIntent)),
        ] {
            let ctx = egui::Context::default();
            apply(&ctx);
            let render = |enabled, events| {
                let mut response = None;
                let input = egui::RawInput {
                    system_theme: Some(egui::Theme::Light),
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(320.0, 80.0),
                    )),
                    events,
                    ..Default::default()
                };
                let output = ctx.run_ui(input, |ui| {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        response = Some(match monitor_state {
                            Some(state) => ui.add_enabled(enabled, monitor_button(state)),
                            None => {
                                ui.add_enabled(enabled, crate::ui::accounts::add_account_button)
                            }
                        });
                    });
                });
                let response = response.unwrap();
                let mut background = None;
                let mut icon = None;
                let mut text = None;
                for clipped in &output.shapes {
                    match &clipped.shape {
                        egui::Shape::Rect(shape) if shape.brush.is_some() => {
                            icon = Some(shape.rect)
                        }
                        egui::Shape::Rect(shape) if shape.fill != egui::Color32::TRANSPARENT => {
                            background = Some((shape.rect, shape.fill));
                        }
                        egui::Shape::Circle(shape) if shape.fill != egui::Color32::TRANSPARENT => {
                            background = Some((shape.visual_bounding_rect(), shape.fill));
                        }
                        egui::Shape::Text(shape) if shape.galley.text() == label => {
                            text = Some(shape.visual_bounding_rect());
                        }
                        _ => {}
                    }
                }
                let (background, fill) = background.expect("painted button background");
                let geometry = [
                    response.interact_rect,
                    background,
                    icon.expect("painted icon"),
                ];
                ButtonFrame {
                    geometry,
                    text,
                    fill,
                    clicked: response.clicked(),
                }
            };

            let initial = render(true, vec![]);
            let [hit, background, icon] = initial.geometry;
            assert!(background.contains_rect(icon));
            if monitor_state.is_some() {
                let text = initial.text.expect("painted monitor label");
                assert!(background.contains_rect(text) && icon.right() <= text.left());
                assert_eq!(hit.size(), egui::vec2(72.0, 28.0));
                assert_eq!(
                    *monitor_geometry.get_or_insert(initial.geometry),
                    initial.geometry
                );
            } else {
                assert!(initial.text.is_none());
                assert_eq!(background.center(), icon.center());
            }
            let edge = egui::pos2(hit.right() - 1.0, hit.center().y);
            let button = |pressed| egui::Event::PointerButton {
                pos: edge,
                button: egui::PointerButton::Primary,
                pressed,
                modifiers: egui::Modifiers::NONE,
            };
            let hover = render(true, vec![egui::Event::PointerMoved(edge)]);
            let press = render(true, vec![button(true)]);
            let release = render(true, vec![button(false)]);
            let leave = render(true, vec![egui::Event::PointerMoved(egui::pos2(4.0, 4.0))]);
            for state in [&hover, &press, &release, &leave] {
                assert_eq!(
                    state.geometry, initial.geometry,
                    "{label} moved during interaction"
                );
                assert_eq!(state.text, initial.text);
            }
            assert_ne!(initial.fill, hover.fill);
            assert_ne!(hover.fill, press.fill);
            assert_eq!(release.fill, hover.fill);
            assert_eq!(leave.fill, initial.fill);
            assert!(!hover.clicked && !press.clicked && release.clicked && !leave.clicked);
            let disabled = render(false, vec![]);
            for event in [egui::Event::PointerMoved(edge), button(true), button(false)] {
                assert_eq!(render(false, vec![event]), disabled);
            }
            assert!(!disabled.clicked);
        }
    }
}
