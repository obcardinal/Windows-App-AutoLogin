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
        .inner_margin(egui::Margin::symmetric(18, 7))
}

pub fn tab_group_frame() -> egui::Frame {
    egui::Frame::new()
        .fill(TAB_RAIL)
        .corner_radius(8)
        .inner_margin(3)
}

pub fn apply_toolbar_style(ui: &mut egui::Ui) {
    let visuals = ui.visuals_mut();
    visuals.override_text_color = Some(MUTED);
    visuals.selection.bg_fill = egui::Color32::WHITE;
    visuals.selection.stroke = egui::Stroke::new(1.0, ACCENT);
    visuals.widgets.inactive.weak_bg_fill = egui::Color32::TRANSPARENT;
    visuals.widgets.inactive.bg_stroke = egui::Stroke::NONE;
    visuals.widgets.hovered.weak_bg_fill = TOOLBAR_HOVER;
    visuals.widgets.hovered.bg_stroke = egui::Stroke::new(1.0, STROKE);
    visuals.widgets.active.weak_bg_fill = ACCENT_SOFT;
    visuals.widgets.active.bg_stroke = egui::Stroke::new(1.0, ACCENT);
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
    let mut frame = content_frame();
    frame.inner_margin.bottom = frame.inner_margin.left;
    frame
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
    Primary,
    Secondary,
    Danger,
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

    pub fn wrap_mode(mut self, mode: egui::TextWrapMode) -> Self {
        self.button = self.button.wrap_mode(mode);
        self
    }

    pub fn min_size(mut self, size: egui::Vec2) -> Self {
        self.button = self.button.min_size(size);
        self
    }
}

impl egui::Widget for ActionButton {
    fn ui(self, ui: &mut egui::Ui) -> egui::Response {
        let (idle, hover, active, outline, active_outline) = match self.kind {
            ButtonKind::Primary => (
                ACCENT,
                ACCENT.lerp_to_gamma(egui::Color32::BLACK, 0.12),
                ACCENT.lerp_to_gamma(egui::Color32::BLACK, 0.24),
                ACCENT,
                ACCENT,
            ),
            ButtonKind::Secondary => (
                egui::Color32::WHITE,
                TOOLBAR_HOVER,
                ACCENT_SOFT,
                STROKE,
                ACCENT,
            ),
            ButtonKind::Danger => (
                DANGER_SOFT,
                DANGER_SOFT.lerp_to_gamma(DANGER, 0.12),
                DANGER_SOFT.lerp_to_gamma(DANGER, 0.24),
                egui::Color32::from_rgb(235, 177, 177),
                DANGER,
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

pub fn primary_button(text: impl Into<String>) -> ActionButton {
    let button = egui::Button::new(
        egui::RichText::new(text.into())
            .text_style(egui::TextStyle::Button)
            .color(egui::Color32::WHITE),
    );
    ActionButton::new(button, ButtonKind::Primary)
}

pub fn primary_button_with_icon(
    text: impl Into<String>,
    icon: egui::Image<'static>,
) -> ActionButton {
    let button = egui::Button::new((
        icon.tint(egui::Color32::WHITE),
        egui::RichText::new(text.into())
            .strong()
            .color(egui::Color32::WHITE),
    ));
    ActionButton::new(button, ButtonKind::Primary)
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

pub fn secondary_button_with_icon(
    text: impl Into<String>,
    icon: egui::Image<'static>,
) -> ActionButton {
    let button = egui::Button::new((
        icon.tint(TEXT),
        egui::RichText::new(text.into()).color(TEXT),
    ));
    ActionButton::new(button, ButtonKind::Secondary)
}

pub fn danger_button(text: impl Into<String>) -> ActionButton {
    ActionButton::new(
        egui::Button::new(egui::RichText::new(text.into()).color(DANGER)),
        ButtonKind::Danger,
    )
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
    fn action_buttons_change_fill_and_preserve_sizing_and_keyboard_activation() {
        for (label, width, make_button) in [
            (
                "Save",
                104.0,
                primary_button as fn(&'static str) -> ActionButton,
            ),
            ("Cancel", 104.0, secondary_button),
            ("Delete", 104.0, danger_button),
            ("Start", 152.0, |label| {
                primary_button_with_icon(
                    label,
                    toolbar_icon(egui::include_image!("../../assets/icons/play.svg")),
                )
                .wrap_mode(egui::TextWrapMode::Extend)
            }),
            ("Stop", 152.0, |label| {
                secondary_button_with_icon(
                    label,
                    toolbar_icon(egui::include_image!("../../assets/icons/stop.svg")),
                )
                .wrap_mode(egui::TextWrapMode::Extend)
            }),
        ] {
            let ctx = egui::Context::default();
            apply(&ctx);
            let size = egui::vec2(width, 30.0);
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
            assert_eq!(idle.rect.size(), size, "{label}");
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
}
