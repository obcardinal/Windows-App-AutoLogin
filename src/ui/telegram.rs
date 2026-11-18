use super::{accounts, theme};
use crate::telegram_notifications::{self, BOT_URL};
use eframe::egui;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use zeroize::{Zeroize, Zeroizing};

const WORKER_ERROR: &str = "Couldn’t finish the Telegram request. Try again.";
type LinkResult = Result<bool, &'static str>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Operation {
    Check,
    Link,
    Unlink,
}

#[derive(Default)]
pub(crate) struct TelegramSettings {
    linked: Option<bool>,
    code: Option<Zeroizing<String>>,
    pending: Option<(Operation, Receiver<LinkResult>)>,
    error: Option<&'static str>,
}

fn code_id() -> egui::Id {
    egui::Id::new("telegram_link_code")
}

impl TelegramSettings {
    pub(crate) fn change_in_progress(&self) -> bool {
        matches!(self.pending, Some((Operation::Link | Operation::Unlink, _)))
    }

    pub(crate) fn clear_code(&mut self, ctx: &egui::Context) {
        if let Some(code) = self.code.as_mut() {
            code.zeroize();
            ctx.memory_mut(|memory| memory.surrender_focus(code_id()));
        }
    }

    pub(crate) fn leave(&mut self, ctx: &egui::Context) {
        self.clear_code(ctx);
        self.code = None;
        self.linked = None;
        self.error = None;
    }

    fn start(
        &mut self,
        ctx: &egui::Context,
        operation: Operation,
        work: impl FnOnce() -> LinkResult + Send + 'static,
    ) {
        let (sender, receiver) = mpsc::sync_channel(1);
        let repaint = ctx.clone();
        let viewport = ctx.viewport_id();
        self.error = None;
        let spawn = std::thread::Builder::new()
            .name("telegram-settings".into())
            .spawn(move || {
                let _ = sender.send(work());
                repaint.request_repaint_of(viewport);
            });
        if spawn.is_ok() {
            self.pending = Some((operation, receiver));
        } else {
            self.error = Some(WORKER_ERROR);
        }
    }

    pub(crate) fn poll(&mut self) {
        let Some((_, receiver)) = &self.pending else {
            return;
        };
        let result = match receiver.try_recv() {
            Ok(result) => result,
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => Err(WORKER_ERROR),
        };
        self.pending = None;
        match result {
            Ok(linked) => {
                self.linked = Some(linked);
                self.code = None;
                self.error = None;
            }
            Err(error) => self.error = Some(error),
        }
    }

    pub(super) fn show(&mut self, ui: &mut egui::Ui) {
        if self.linked.is_none() && self.pending.is_none() && self.error.is_none() {
            self.start(
                ui.ctx(),
                Operation::Check,
                telegram_notifications::is_linked,
            );
        }
        let operation = self.pending.as_ref().map(|(operation, _)| *operation);
        let status = match operation {
            Some(Operation::Check) => "Checking link…",
            Some(Operation::Link) => "Linking…",
            Some(Operation::Unlink) => "Unlinking…",
            None => match self.linked {
                Some(true) => "Linked",
                Some(false) => "Not linked",
                None => "Link status unavailable",
            },
        };
        let form_was_closed = self.code.is_none();
        let (title_left, _) = egui::containers::Sides::new()
            .height(ui.spacing().interact_size.y)
            .shrink_left()
            .show(
                ui,
                |ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.spacing_mut().item_spacing.x = 8.0;
                        ui.add(theme::toolbar_icon(egui::include_image!(
                            "../../assets/about/contact-telegram.svg"
                        )));
                        let title = ui.strong("Telegram");
                        ui.label(egui::RichText::new(status).small().color(theme::MUTED));
                        title.rect.left()
                    })
                    .inner
                },
                |ui| {
                    if operation.is_some() {
                        ui.spinner();
                    } else if self.code.is_some() {
                        if theme::settings_button(ui, "Cancel").clicked() {
                            self.clear_code(ui.ctx());
                            self.code = None;
                            self.error = None;
                        }
                    } else {
                        match self.linked {
                            Some(true) => {
                                if theme::settings_button(ui, "Unlink").clicked() {
                                    self.start(ui.ctx(), Operation::Unlink, || {
                                        telegram_notifications::unlink().map(|()| false)
                                    });
                                }
                            }
                            Some(false) => {
                                if theme::settings_button(ui, "Link Telegram…").clicked() {
                                    self.code = Some(accounts::empty_password_buffer());
                                }
                            }
                            None => {
                                if theme::settings_button(ui, "Retry").clicked() {
                                    self.start(
                                        ui.ctx(),
                                        Operation::Check,
                                        telegram_notifications::is_linked,
                                    );
                                }
                            }
                        }
                    }
                },
            );
        let indent = title_left - ui.next_widget_position().x;
        ui.horizontal_top(|ui| {
            ui.spacing_mut().item_spacing.x = 0.0;
            ui.add_space(indent);
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 2.0;
                for line in [
                    "Can wake your iPhone for faster sign-in.",
                    "Only for Microsoft Authenticator 2FA requests.",
                ] {
                    ui.add(
                        egui::Label::new(egui::RichText::new(line).small().color(theme::MUTED))
                            .wrap(),
                    );
                }
            });
        });

        if let Some(error) = self.error {
            ui.add(
                egui::Label::new(egui::RichText::new(error).small().color(theme::DANGER)).wrap(),
            );
        }
        if self.pending.is_some() {
            return;
        }
        let Some(code) = self.code.as_mut() else {
            return;
        };
        ui.add(egui::Separator::default().spacing(12.0));
        ui.horizontal_wrapped(|ui| {
            ui.label("For a pairing code, send /link to");
            ui.hyperlink_to("@windows_app_autologin_bot", BOT_URL);
        });
        let submit = ui
            .horizontal(|ui| {
                let width = (ui.available_width() - 80.0).clamp(1.0, 200.0);
                let field = accounts::account_editor_input_scope(ui, |ui| {
                    accounts::masked_code_editor(ui, code, code_id(), width)
                })
                .inner;
                if form_was_closed {
                    field.request_focus();
                }
                let has_code = !code.trim().is_empty();
                let enter = field.has_focus()
                    && has_code
                    && ui.input_mut(|input| {
                        input.consume_key(egui::Modifiers::NONE, egui::Key::Enter)
                    });
                ui.add_enabled(has_code, theme::primary_button("Link"))
                    .clicked()
                    || enter
            })
            .inner;
        if submit {
            let submitted = std::mem::replace(code, accounts::empty_password_buffer());
            ui.ctx()
                .memory_mut(|memory| memory.surrender_focus(code_id()));
            self.start(ui.ctx(), Operation::Link, move || {
                telegram_notifications::pair(submitted.trim()).map(|()| true)
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_form_masks_pasted_codes_and_drops_them_on_cancel() {
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let mut settings = TelegramSettings {
            linked: Some(false),
            ..Default::default()
        };
        let render = |settings: &mut TelegramSettings, events| {
            ctx.run_ui(
                egui::RawInput {
                    events,
                    ..Default::default()
                },
                |ui| {
                    ui.set_width(320.0);
                    settings.show(ui);
                },
            )
        };
        let text_rect = |output: &egui::FullOutput, text: &str| {
            output
                .shapes
                .iter()
                .find_map(|clipped| match &clipped.shape {
                    egui::Shape::Text(label) if label.galley.text() == text => {
                        Some(label.visual_bounding_rect())
                    }
                    _ => None,
                })
        };
        let click = |frame: &egui::FullOutput, label| {
            let pos = text_rect(frame, label).unwrap().center();
            let press = |pressed| egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed,
                modifiers: Default::default(),
            };
            vec![egui::Event::PointerMoved(pos), press(true), press(false)]
        };
        render(&mut settings, vec![]);
        let home = render(&mut settings, vec![]);
        render(&mut settings, click(&home, "Link Telegram…"));
        let sample = "sample-pair-code";
        let form = render(&mut settings, vec![egui::Event::Paste(sample.into())]);
        let mask = egui::epaint::text::PASSWORD_REPLACEMENT_CHAR
            .to_string()
            .repeat(sample.len());
        assert!(text_rect(&form, "@windows_app_autologin_bot").is_some());
        assert!(text_rect(&form, &mask).is_some());
        assert!(text_rect(&form, sample).is_none());
        assert!(settings.code.as_ref().unwrap().as_str() == sample);
        render(&mut settings, click(&form, "Cancel"));
        assert!(settings.code.is_none());
        assert!(!ctx.memory(|memory| memory.has_focus(code_id())));
    }

    #[test]
    fn connection_changes_wait_for_the_worker_and_allow_retry_after_failure() {
        let (sender, receiver) = mpsc::sync_channel(1);
        let mut settings = TelegramSettings {
            linked: Some(true),
            pending: Some((Operation::Unlink, receiver)),
            ..Default::default()
        };
        settings.poll();
        assert!(settings.change_in_progress());
        assert_eq!(settings.linked, Some(true));
        sender.send(Err(WORKER_ERROR)).unwrap();
        settings.poll();
        assert!(!settings.change_in_progress());
        assert_eq!(settings.linked, Some(true));
        assert_eq!(settings.error, Some(WORKER_ERROR));
        let (sender, receiver) = mpsc::sync_channel(1);
        settings.pending = Some((Operation::Unlink, receiver));
        sender.send(Ok(false)).unwrap();
        settings.poll();
        assert_eq!(settings.linked, Some(false));
        assert!(settings.error.is_none());
    }
}

#[cfg(test)]
mod settings_button_tests {
    use super::{egui, theme};

    #[derive(Debug, PartialEq)]
    struct ButtonFrame {
        hit: egui::Rect,
        background: egui::Rect,
        label: egui::Rect,
        fill: egui::Color32,
        cursor: egui::CursorIcon,
        clicked: bool,
    }

    #[test]
    fn settings_actions_show_hover_without_moving() {
        for label in ["Sign-in details…", "Unlink"] {
            let ctx = egui::Context::default();
            theme::apply(&ctx);
            let frame = |enabled, events| {
                let mut response = None;
                let output = ctx.run_ui(
                    egui::RawInput {
                        events,
                        ..Default::default()
                    },
                    |ui| {
                        response = Some(ui.add_enabled(enabled, |ui: &mut egui::Ui| {
                            theme::settings_button(ui, label)
                        }));
                    },
                );
                let response = response.unwrap();
                let background = output
                    .shapes
                    .iter()
                    .rev()
                    .find_map(|item| match &item.shape {
                        egui::Shape::Rect(rect) if rect.rect.contains(response.rect.center()) => {
                            Some(rect)
                        }
                        _ => None,
                    })
                    .expect("painted button background");
                let text = output
                    .shapes
                    .iter()
                    .find_map(|item| match &item.shape {
                        egui::Shape::Text(text) if text.galley.text() == label => {
                            Some(text.visual_bounding_rect())
                        }
                        _ => None,
                    })
                    .expect("painted button label");
                ButtonFrame {
                    hit: response.interact_rect,
                    background: background.rect,
                    label: text,
                    fill: background.fill,
                    cursor: output.platform_output.cursor_icon,
                    clicked: response.clicked(),
                }
            };

            let idle = frame(true, vec![]);
            let pos = egui::pos2(idle.hit.right() - 1.0, idle.hit.center().y);
            let outside = egui::Event::PointerMoved(pos + egui::vec2(20.0, 0.0));
            let press = |pressed| egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed,
                modifiers: egui::Modifiers::NONE,
            };
            let hover = frame(true, vec![egui::Event::PointerMoved(pos)]);
            assert_ne!(hover.fill, idle.fill, "{label} hover fill");
            assert_eq!(hover.cursor, egui::CursorIcon::PointingHand);
            assert_eq!(frame(true, vec![outside.clone()]), idle);
            let pressed = frame(true, vec![egui::Event::PointerMoved(pos), press(true)]);
            let released = frame(true, vec![press(false)]);
            assert_ne!(pressed.fill, hover.fill, "{label} pressed fill");
            assert!(released.clicked);
            for state in [&hover, &pressed, &released] {
                assert_eq!(
                    (state.hit, state.background, state.label),
                    (idle.hit, idle.background, idle.label)
                );
            }

            let disabled = frame(false, vec![outside]);
            assert_ne!(disabled.cursor, egui::CursorIcon::PointingHand);
            assert!(!disabled.clicked);
            for event in [egui::Event::PointerMoved(pos), press(true), press(false)] {
                assert_eq!(frame(false, vec![event]), disabled);
            }
        }
    }
}
