use crate::models::WorkerStatus;
use eframe::egui;

pub const ACCENT: egui::Color32 = egui::Color32::from_rgb(58, 132, 194);
pub const ACCENT_SOFT: egui::Color32 = egui::Color32::from_rgb(226, 241, 252);
pub const SUCCESS: egui::Color32 = egui::Color32::from_rgb(31, 128, 79);
pub const SUCCESS_SOFT: egui::Color32 = egui::Color32::from_rgb(222, 243, 231);
pub const DANGER: egui::Color32 = egui::Color32::from_rgb(190, 55, 55);
pub const DANGER_SOFT: egui::Color32 = egui::Color32::from_rgb(251, 226, 226);
pub const MUTED: egui::Color32 = egui::Color32::from_rgb(92, 99, 106);
pub const MUTED_SOFT: egui::Color32 = egui::Color32::from_rgb(238, 241, 244);
pub const TEXT: egui::Color32 = egui::Color32::from_rgb(36, 42, 48);
pub const SURFACE: egui::Color32 = egui::Color32::from_rgb(248, 250, 252);
pub const STROKE: egui::Color32 = egui::Color32::from_rgb(214, 222, 230);

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
    let mut style = egui::Style::default();
    let mut visuals = egui::Visuals::light();

    visuals.panel_fill = SURFACE;
    visuals.window_fill = glass_dense();
    visuals.faint_bg_color = egui::Color32::from_rgb(241, 245, 249);
    visuals.selection.bg_fill = ACCENT_SOFT;
    visuals.selection.stroke = egui::Stroke::new(1.0, ACCENT);
    visuals.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, STROKE);
    visuals.widgets.inactive.corner_radius = egui::CornerRadius::same(7);
    visuals.widgets.hovered.corner_radius = egui::CornerRadius::same(7);
    visuals.widgets.active.corner_radius = egui::CornerRadius::same(7);
    visuals.widgets.open.corner_radius = egui::CornerRadius::same(7);
    visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(248, 250, 252);
    visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(238, 246, 252);
    visuals.widgets.active.bg_fill = egui::Color32::from_rgb(226, 241, 252);
    visuals.override_text_color = Some(TEXT);

    style.visuals = visuals;
    style.spacing.item_spacing = egui::vec2(8.0, 7.0);
    style.spacing.button_padding = egui::vec2(24.0, 4.0);
    style.spacing.window_margin = egui::Margin::same(12);
    style.spacing.interact_size = egui::vec2(48.0, 28.0);
    style.spacing.text_edit_width = 240.0;
    style.spacing.slider_width = 190.0;
    style.spacing.combo_width = 190.0;

    ctx.set_global_style(style);
}

pub fn top_bar_frame() -> egui::Frame {
    egui::Frame::new()
        .fill(top_bar())
        .inner_margin(egui::Margin::symmetric(12, 8))
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
        .inner_margin(egui::Margin::symmetric(12, 10))
}

pub fn compact_frame() -> egui::Frame {
    egui::Frame::new()
        .fill(glass_dense())
        .stroke(egui::Stroke::new(1.0, STROKE))
        .corner_radius(egui::CornerRadius::same(7))
        .inner_margin(egui::Margin::symmetric(10, 8))
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
                ui.add(egui::Label::new(muted(subtitle)).wrap());
                ui.add_space(6.0);
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
                        ui.add(egui::Label::new(muted(subtitle)).wrap());
                    },
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), actions);
            });
        }
    });
    ui.add_space(8.0);
}

pub fn muted(text: impl Into<String>) -> egui::RichText {
    egui::RichText::new(text).color(MUTED)
}

pub fn small_muted(text: impl Into<String>) -> egui::RichText {
    egui::RichText::new(text).small().color(MUTED)
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

pub fn pill(ui: &mut egui::Ui, text: &str, color: egui::Color32, fill: egui::Color32) {
    draw_pill(ui, text, color, fill, 18.0, 10.0);
}

pub fn compact_pill(ui: &mut egui::Ui, text: &str, color: egui::Color32, fill: egui::Color32) {
    draw_pill(ui, text, color, fill, 18.0, 9.0);
}

fn draw_pill(
    ui: &mut egui::Ui,
    text: &str,
    color: egui::Color32,
    fill: egui::Color32,
    height: f32,
    horizontal_padding: f32,
) {
    let font_id = egui::TextStyle::Small.resolve(ui.style());
    let galley = ui
        .painter()
        .layout_no_wrap(text.to_owned(), font_id.clone(), color);
    let width = galley.size().x + horizontal_padding * 2.0;
    let (rect, _) = ui.allocate_exact_size(egui::vec2(width, height), egui::Sense::hover());
    let radius = egui::CornerRadius::same((height / 2.0) as u8);

    ui.painter().rect_filled(rect, radius, fill);
    ui.painter().rect_stroke(
        rect,
        radius,
        egui::Stroke::new(1.0, color.linear_multiply(0.42)),
        egui::StrokeKind::Inside,
    );
    ui.painter().text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        text,
        font_id,
        color,
    );
}

pub fn worker_status(status: WorkerStatus) -> (egui::Color32, egui::Color32, &'static str) {
    match status {
        WorkerStatus::Idle => (MUTED, MUTED_SOFT, "Idle"),
        WorkerStatus::Running => (SUCCESS, SUCCESS_SOFT, "Running"),
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
