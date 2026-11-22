use crate::ui::theme;
use eframe::egui;

pub(super) const SWITCH_SIZE: egui::Vec2 = egui::vec2(40.0, 30.0);
pub(super) const SWITCH_TRACK_SIZE: egui::Vec2 = egui::vec2(32.0, 18.0);

/// A checkbox with a compact switch appearance and a larger interaction target.
pub fn switch(ui: &mut egui::Ui, checked: &mut bool, label: &str) -> egui::Response {
    let (rect, mut response) = ui.allocate_exact_size(SWITCH_SIZE, egui::Sense::click());
    // Sense::click also supplies the standard focused Space/Enter activation.
    if response.clicked() {
        *checked = !*checked;
        response.mark_changed();
    }
    response.widget_info(|| {
        egui::WidgetInfo::selected(egui::WidgetType::Checkbox, ui.is_enabled(), *checked, label)
    });

    if ui.is_rect_visible(rect) {
        let track = egui::Rect::from_center_size(rect.center(), SWITCH_TRACK_SIZE);
        let emphasized = response.enabled() && (response.hovered() || response.has_focus());
        let fill = if *checked {
            if emphasized {
                egui::Color32::from_rgb(44, 70, 163)
            } else {
                theme::ACCENT
            }
        } else if emphasized {
            egui::Color32::from_rgb(128, 141, 159)
        } else {
            egui::Color32::from_rgb(158, 168, 185)
        };
        ui.painter()
            .rect_filled(track, egui::CornerRadius::same(10), fill);
        let thumb_x = egui::lerp(
            (track.left() + 9.0)..=(track.right() - 9.0),
            ui.ctx().animate_bool_responsive(response.id, *checked),
        );
        ui.painter().circle_filled(
            egui::pos2(thumb_x, track.center().y),
            7.0,
            egui::Color32::WHITE,
        );
    }

    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

pub(super) fn labeled_switch(
    ui: &mut egui::Ui,
    value: &mut bool,
    enabled: bool,
    label: &str,
    hint: &str,
    height: f32,
    after_label: impl FnOnce(&mut egui::Ui),
) -> bool {
    let (_, switch_response) = egui::containers::Sides::new()
        .height(height)
        .shrink_left()
        .wrap()
        .show(
            ui,
            |ui| {
                ui.add(
                    egui::Label::new(egui::RichText::new(label).color(theme::TEXT))
                        .selectable(false),
                );
                after_label(ui);
            },
            |ui| {
                if !enabled {
                    ui.disable();
                }
                switch(ui, value, label).on_hover_text(hint)
            },
        );
    switch_response.changed()
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
    fn switch_label_keeps_its_text_color_and_cursor_on_hover() {
        for enabled in [true, false] {
            let ctx = egui::Context::default();
            theme::apply(&ctx);
            let mut checked = false;
            let mut render = |events| {
                let input = egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(280.0, 80.0),
                    )),
                    events,
                    ..Default::default()
                };
                let output = ctx.run_ui(input, |ui| {
                    ui.add_enabled_ui(enabled, |ui| {
                        labeled_switch(ui, &mut checked, true, "Open at Login", "", 36.0, |_| {});
                    });
                });
                output
                    .shapes
                    .iter()
                    .find_map(|shape| match &shape.shape {
                        egui::Shape::Text(text) if text.galley.text() == "Open at Login" => {
                            let ink = text.galley.job.sections[0].format.color;
                            Some((
                                text.visual_bounding_rect(),
                                if ink == egui::Color32::PLACEHOLDER {
                                    text.fallback_color
                                } else {
                                    ink
                                },
                                output.platform_output.cursor_icon,
                            ))
                        }
                        _ => None,
                    })
                    .expect("setting label must be painted")
            };
            let (rect, idle, cursor) = render(vec![]);
            assert_eq!(cursor, egui::CursorIcon::Default);
            assert_eq!(
                render(vec![egui::Event::PointerMoved(rect.center())]),
                (rect, idle, cursor)
            );
            assert!(!checked);
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
    fn focused_switch_changes_track_color_without_painting_an_outer_ring() {
        for mut checked in [false, true] {
            let ctx = egui::Context::default();
            let mut render = || {
                let mut response = None;
                let output = ctx.run_ui(egui::RawInput::default(), |ui| {
                    response = Some(switch(ui, &mut checked, "Reconnect when locked"));
                });
                let response = response.unwrap();
                let track =
                    egui::Rect::from_center_size(response.rect.center(), egui::vec2(32.0, 18.0));
                let mut painted = output.shapes.iter().filter_map(|shape| match &shape.shape {
                    egui::Shape::Rect(rect)
                        if rect.rect.intersects(track)
                            && response.rect.contains_rect(rect.rect) =>
                    {
                        Some(rect)
                    }
                    _ => None,
                });
                let only_track = painted.next().unwrap();
                assert_eq!(only_track.rect, track);
                assert_eq!(only_track.stroke, egui::Stroke::NONE);
                assert!(painted.next().is_none());
                (response, only_track.fill)
            };
            let (idle, idle_fill) = render();
            idle.request_focus();
            let (focused, focused_fill) = render();
            assert!(focused.has_focus());
            assert_ne!(focused_fill, idle_fill);
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
