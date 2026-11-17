use crate::ui::theme;
use eframe::egui;

/// A checkbox with a compact switch appearance and a larger interaction target.
pub fn switch(ui: &mut egui::Ui, checked: &mut bool, label: &str) -> egui::Response {
    let (rect, mut response) = ui.allocate_exact_size(egui::vec2(40.0, 30.0), egui::Sense::click());
    // Sense::click also supplies the standard focused Space/Enter activation.
    if response.clicked() {
        *checked = !*checked;
        response.mark_changed();
    }
    response.widget_info(|| {
        egui::WidgetInfo::selected(egui::WidgetType::Checkbox, ui.is_enabled(), *checked, label)
    });

    if ui.is_rect_visible(rect) {
        let track = egui::Rect::from_center_size(rect.center(), egui::vec2(34.0, 20.0));
        let hovered = response.hovered() && ui.is_enabled();
        let fill = if *checked {
            if hovered {
                egui::Color32::from_rgb(43, 109, 166)
            } else {
                theme::ACCENT
            }
        } else if hovered {
            egui::Color32::from_rgb(151, 164, 177)
        } else {
            egui::Color32::from_rgb(177, 188, 199)
        };
        ui.painter()
            .rect_filled(track, egui::CornerRadius::same(10), fill);
        let thumb_x = if *checked {
            track.right() - 10.0
        } else {
            track.left() + 10.0
        };
        ui.painter().circle_filled(
            egui::pos2(thumb_x, track.center().y),
            7.0,
            egui::Color32::WHITE,
        );
        if response.has_focus() {
            ui.painter().rect_stroke(
                track.expand(3.0),
                egui::CornerRadius::same(13),
                egui::Stroke::new(1.5, theme::ACCENT),
                egui::StrokeKind::Outside,
            );
        }
    }

    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(
        ctx: &egui::Context,
        checked: &mut bool,
        enabled: bool,
        events: Vec<egui::Event>,
    ) -> egui::Response {
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(200.0, 100.0),
            )),
            events,
            ..Default::default()
        };
        let mut response = None;
        let _ = ctx.run_ui(input, |ui| {
            response = Some(
                ui.add_enabled_ui(enabled, |ui| switch(ui, checked, "Enable test account"))
                    .inner,
            );
        });
        response.unwrap()
    }

    fn pointer_button(pos: egui::Pos2, pressed: bool) -> egui::Event {
        egui::Event::PointerButton {
            pos,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: egui::Modifiers::NONE,
        }
    }

    fn key_press(key: egui::Key) -> egui::Event {
        egui::Event::Key {
            key,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        }
    }

    #[test]
    fn switch_pointer_click_toggles_once_and_reports_change() {
        for initial in [false, true] {
            let ctx = egui::Context::default();
            let mut checked = initial;
            let first = frame(&ctx, &mut checked, true, vec![]);
            // The padded target outside the 20px-high track remains clickable.
            let pos = egui::pos2(first.rect.center().x, first.rect.top() + 1.0);
            let pressed = frame(
                &ctx,
                &mut checked,
                true,
                vec![egui::Event::PointerMoved(pos), pointer_button(pos, true)],
            );
            assert!(!pressed.changed());
            assert_eq!(checked, initial);
            let released = frame(&ctx, &mut checked, true, vec![pointer_button(pos, false)]);
            assert!(released.changed());
            assert_eq!(checked, !initial);
            assert_eq!(released.id, first.id);
            assert!(!frame(&ctx, &mut checked, true, vec![]).changed());
            assert_eq!(checked, !initial);
        }
    }

    #[test]
    fn switch_focused_space_and_enter_toggle_and_keep_focus() {
        for key in [egui::Key::Space, egui::Key::Enter] {
            let ctx = egui::Context::default();
            let mut checked = false;
            let first = frame(&ctx, &mut checked, true, vec![]);
            first.request_focus();
            let activated = frame(&ctx, &mut checked, true, vec![key_press(key)]);
            assert!(checked);
            assert!(activated.changed());
            assert!(activated.has_focus());
            assert_eq!(activated.id, first.id);
        }
    }

    #[test]
    fn switch_disabled_rejects_pointer_and_keyboard_activation() {
        for initial in [false, true] {
            let ctx = egui::Context::default();
            let mut checked = initial;
            let first = frame(&ctx, &mut checked, true, vec![]);
            first.request_focus();
            let pos = first.rect.center();
            let pressed = frame(
                &ctx,
                &mut checked,
                false,
                vec![egui::Event::PointerMoved(pos), pointer_button(pos, true)],
            );
            assert!(!pressed.changed());
            let released = frame(&ctx, &mut checked, false, vec![pointer_button(pos, false)]);
            assert!(!released.changed());
            for key in [egui::Key::Space, egui::Key::Enter] {
                let activated = frame(&ctx, &mut checked, false, vec![key_press(key)]);
                assert!(!activated.changed());
                assert_eq!(checked, initial);
            }
        }
    }
}
