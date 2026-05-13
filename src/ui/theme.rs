use eframe::egui;
use std::sync::Arc;

pub const ACCENT: egui::Color32 = egui::Color32::from_rgb(58, 132, 194);
pub const ACCENT_SOFT: egui::Color32 = egui::Color32::from_rgb(226, 241, 252);
pub const DANGER: egui::Color32 = egui::Color32::from_rgb(190, 55, 55);
pub const DANGER_SOFT: egui::Color32 = egui::Color32::from_rgb(251, 226, 226);
pub const MUTED: egui::Color32 = egui::Color32::from_rgb(62, 70, 78);
pub const TEXT: egui::Color32 = egui::Color32::from_rgb(22, 28, 34);
pub const SURFACE: egui::Color32 = egui::Color32::from_rgb(248, 250, 252);
pub const STROKE: egui::Color32 = egui::Color32::from_rgb(214, 222, 230);

const INTER_FONT_NAME: &str = "inter";

fn glass() -> egui::Color32 {
    egui::Color32::from_rgba_unmultiplied(255, 255, 255, 212)
}

fn glass_dense() -> egui::Color32 {
    egui::Color32::from_rgba_unmultiplied(255, 255, 255, 236)
}

fn top_bar() -> egui::Color32 {
    egui::Color32::from_rgba_unmultiplied(250, 252, 255, 236)
}

pub fn apply(ctx: &egui::Context) {
    apply_fonts(ctx);
    egui_extras::install_image_loaders(ctx);

    let mut style = egui::Style::default();
    let mut visuals = egui::Visuals::light();

    visuals.panel_fill = SURFACE;
    visuals.window_fill = glass_dense();
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
    visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(238, 246, 252);
    visuals.widgets.active.bg_fill = egui::Color32::from_rgb(226, 241, 252);
    visuals.override_text_color = Some(TEXT);

    style.visuals = visuals;
    style.spacing.item_spacing = egui::vec2(8.0, 8.0);
    style.spacing.button_padding = egui::vec2(24.0, 4.0);
    style.spacing.window_margin = egui::Margin::same(12);
    style.spacing.interact_size = egui::vec2(48.0, 28.0);
    style.spacing.text_edit_width = 240.0;
    style.spacing.slider_width = 190.0;
    style.spacing.combo_width = 190.0;
    style.text_styles.insert(
        egui::TextStyle::Small,
        egui::FontId::new(12.5, egui::FontFamily::Proportional),
    );
    style.text_styles.insert(
        egui::TextStyle::Body,
        egui::FontId::new(15.75, egui::FontFamily::Proportional),
    );
    style.text_styles.insert(
        egui::TextStyle::Button,
        egui::FontId::new(15.75, egui::FontFamily::Proportional),
    );
    style.text_styles.insert(
        egui::TextStyle::Heading,
        egui::FontId::new(21.0, egui::FontFamily::Proportional),
    );
    style.text_styles.insert(
        egui::TextStyle::Monospace,
        egui::FontId::new(15.75, egui::FontFamily::Monospace),
    );

    ctx.set_global_style(style);
}

fn apply_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    let inter = egui::FontData::from_static(include_bytes!("../../assets/fonts/InterVariable.ttf"))
        .tweak(egui::FontTweak {
            hinting_override: Some(true),
            coords: egui::epaint::text::VariationCoords::new([(b"wght", 500.0)]),
            ..Default::default()
        });

    fonts
        .font_data
        .insert(INTER_FONT_NAME.to_owned(), Arc::new(inter));
    fonts
        .families
        .entry(egui::FontFamily::Proportional)
        .or_default()
        .insert(0, INTER_FONT_NAME.to_owned());

    ctx.set_fonts(fonts);
}

pub fn top_bar_frame() -> egui::Frame {
    egui::Frame::new()
        .fill(top_bar())
        .inner_margin(egui::Margin {
            left: 12,
            right: 12,
            top: 10,
            bottom: 8,
        })
        .stroke(egui::Stroke::new(1.0, STROKE))
}

pub fn content_frame() -> egui::Frame {
    egui::Frame::new()
        .fill(SURFACE)
        .inner_margin(egui::Margin::same(12))
}

pub fn glass_frame() -> egui::Frame {
    egui::Frame::new()
        .fill(glass())
        .stroke(egui::Stroke::new(1.0, STROKE))
        .corner_radius(egui::CornerRadius::same(8))
        .inner_margin(egui::Margin::symmetric(16, 14))
}

pub fn compact_frame() -> egui::Frame {
    egui::Frame::new()
        .fill(glass_dense())
        .stroke(egui::Stroke::new(1.0, STROKE))
        .corner_radius(egui::CornerRadius::same(7))
        .inner_margin(egui::Margin::symmetric(12, 10))
}

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

pub fn page_header_plain(ui: &mut egui::Ui, title: &str, subtitle: &str) {
    glass_frame().show(ui, |ui| {
        ui.heading(title);
        ui.add_space(4.0);
        ui.add(egui::Label::new(muted(subtitle)).wrap());
    });
    ui.add_space(12.0);
}

pub fn muted(text: impl Into<String>) -> egui::RichText {
    egui::RichText::new(text)
        .color(MUTED)
        .line_height(Some(22.0))
}

pub fn version_label(text: impl Into<String>) -> egui::RichText {
    egui::RichText::new(text)
        .color(MUTED)
        .size(13.5)
        .line_height(Some(18.0))
}

pub fn status_text(text: impl Into<String>) -> egui::RichText {
    let text = text.into();
    let color = message_color(&text);
    egui::RichText::new(text)
        .color(color)
        .line_height(Some(22.0))
}

pub fn primary_button(text: impl Into<String>) -> egui::Button<'static> {
    egui::Button::new(
        egui::RichText::new(text.into())
            .strong()
            .color(egui::Color32::WHITE),
    )
    .fill(ACCENT)
    .stroke(egui::Stroke::new(
        1.0,
        egui::Color32::from_rgb(43, 109, 166),
    ))
    .corner_radius(egui::CornerRadius::same(7))
    .min_size(egui::vec2(0.0, 28.0))
}

pub fn secondary_button(text: impl Into<String>) -> egui::Button<'static> {
    egui::Button::new(egui::RichText::new(text.into()).color(TEXT))
        .fill(egui::Color32::from_rgb(246, 249, 252))
        .stroke(egui::Stroke::new(1.0, STROKE))
        .corner_radius(egui::CornerRadius::same(7))
        .min_size(egui::vec2(0.0, 28.0))
}

pub fn danger_button(text: impl Into<String>) -> egui::Button<'static> {
    egui::Button::new(egui::RichText::new(text.into()).color(DANGER))
        .fill(DANGER_SOFT)
        .stroke(egui::Stroke::new(
            1.0,
            egui::Color32::from_rgb(235, 177, 177),
        ))
        .corner_radius(egui::CornerRadius::same(7))
        .min_size(egui::vec2(0.0, 28.0))
}

pub fn message_color(msg: &str) -> egui::Color32 {
    let msg = msg.to_lowercase();
    if msg.contains("fail") || msg.contains("error") || msg.contains("missing") {
        DANGER
    } else {
        MUTED
    }
}
