use super::theme;
use crate::telegram_notifications::{self, LinkState};
use eframe::egui;
use objc2_app_kit::NSWorkspace;
use objc2_foundation::{NSString, NSURL};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::{Duration, Instant};

const WORKER_ERROR: &str = "Couldn’t finish the Telegram request. Try again.";
const OPEN_ERROR: &str = "Couldn’t open Telegram. Click Open Telegram to try again.";
const POLL_INTERVAL: Duration = Duration::from_secs(2);
const FAILED_POLL_INTERVAL: Duration = Duration::from_secs(15);
// Let an accepted mutation finish its bounded HTTP requests, even if the
// window closes. A system Keychain prompt can outlive those request timeouts.
const MAX_MUTATION_WAIT: Duration = Duration::from_secs(25);

type LinkResult = Result<LinkState, &'static str>;

#[derive(Clone)]
enum Operation {
    Check,
    Begin,
    Refresh,
    Cancel(String),
    Unlink,
}

impl Operation {
    fn run(&self) -> LinkResult {
        match self {
            Self::Check => telegram_notifications::link_state(),
            Self::Begin => telegram_notifications::begin_link(),
            Self::Refresh => telegram_notifications::refresh_link(),
            Self::Cancel(url) => telegram_notifications::cancel_pending(url),
            Self::Unlink => telegram_notifications::unlink().map(|()| LinkState::Unlinked),
        }
    }

    fn changes_link(&self) -> bool {
        matches!(self, Self::Begin | Self::Cancel(_) | Self::Unlink)
    }
}

struct Worker {
    operation: Operation,
    receiver: Receiver<LinkResult>,
    started_at: Instant,
}

#[derive(Default)]
pub(crate) struct TelegramSettings {
    state: Option<LinkState>,
    worker: Option<Worker>,
    failure: Option<(Operation, &'static str)>,
    next_refresh: Option<Instant>,
    queued_cancel: Option<String>,
    reload_on_show: bool,
    open_failed: bool,
}

fn open_telegram(link: &str) -> bool {
    // The client constructs this URL from the fixed bot address and a
    // validated start payload. LaunchServices keeps it off the command line.
    NSURL::URLWithString(&NSString::from_str(link))
        .is_some_and(|url| NSWorkspace::sharedWorkspace().openURL(&url))
}

impl TelegramSettings {
    pub(crate) fn change_in_progress(&self) -> bool {
        self.worker.as_ref().is_some_and(|worker| {
            (worker.operation.changes_link() || self.queued_cancel.is_some())
                && worker.started_at.elapsed() < MAX_MUTATION_WAIT
        })
    }

    pub(crate) fn leave(&mut self) {
        self.reload_on_show = true;
    }

    fn start(&mut self, ctx: &egui::Context, operation: Operation) {
        let (sender, receiver) = mpsc::sync_channel(1);
        let repaint = ctx.clone();
        let viewport = ctx.viewport_id();
        let task = operation.clone();
        let spawn = std::thread::Builder::new()
            .name("telegram-settings".into())
            .spawn(move || {
                let _ = sender.send(task.run());
                repaint.request_repaint_of(viewport);
            });
        if spawn.is_ok() {
            self.worker = Some(Worker {
                operation,
                receiver,
                started_at: Instant::now(),
            });
        } else {
            self.failure = Some((operation, WORKER_ERROR));
        }
        self.next_refresh = None;
    }

    fn finish_work(&mut self, closing: bool, open: impl FnOnce(&str) -> bool) {
        let Some(worker) = &self.worker else { return };
        let result = match worker.receiver.try_recv() {
            Ok(result) => result,
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => Err(WORKER_ERROR),
        };
        let operation = self.worker.take().unwrap().operation;
        match result {
            Ok(state) => {
                if let LinkState::Pending { url } = &state {
                    // Only the original button click opens Telegram. Loading a
                    // saved link, background refreshes, and reopening Settings
                    // must all leave the foreground application alone.
                    if matches!(operation, Operation::Begin) && !self.reload_on_show && !closing {
                        self.open_failed = !open(url);
                    }
                } else {
                    self.open_failed = false;
                }
                self.state = Some(state);
                self.failure = None;
            }
            Err(error) => self.failure = Some((operation, error)),
        }
        if matches!(self.state, Some(LinkState::Pending { .. })) {
            let interval = if self.failure.is_some() {
                FAILED_POLL_INTERVAL
            } else {
                POLL_INTERVAL
            };
            self.next_refresh = Some(Instant::now() + interval);
        }
    }

    pub(crate) fn poll(&mut self, ctx: &egui::Context, closing: bool) {
        self.finish_work(closing, open_telegram);
        if self.worker.is_some() {
            return;
        }
        if let Some(url) = self.queued_cancel.take() {
            self.start(ctx, Operation::Cancel(url));
        } else if let Some(next) = self.next_refresh.filter(|_| !closing) {
            let wait = next.saturating_duration_since(Instant::now());
            if wait.is_zero() {
                self.start(ctx, Operation::Refresh);
            } else {
                ctx.request_repaint_after(wait);
            }
        }
    }

    fn status(&self) -> &'static str {
        if self.queued_cancel.is_some() {
            return "Canceling…";
        }
        match self.worker.as_ref().map(|w| &w.operation) {
            Some(Operation::Begin) => return "Creating link…",
            Some(Operation::Cancel(_)) => return "Canceling…",
            Some(Operation::Unlink) => return "Unlinking…",
            Some(Operation::Check) if self.state.is_none() => return "Checking link…",
            _ => {}
        }
        match self.state {
            Some(LinkState::Linked) => "Linked",
            Some(LinkState::Unlinked) => "Not linked",
            Some(LinkState::Pending { .. }) => "Waiting for Start",
            Some(LinkState::Expired) => "Link expired",
            None => "Link status unavailable",
        }
    }

    fn actions(&mut self, ui: &mut egui::Ui) {
        if self.queued_cancel.is_some()
            || self.worker.as_ref().is_some_and(|w| {
                w.operation.changes_link() || !matches!(self.state, Some(LinkState::Pending { .. }))
            })
        {
            ui.spinner();
            return;
        }
        if let Some(LinkState::Pending { url }) = &self.state {
            if theme::settings_button(ui, "Cancel").clicked() {
                // A status request might already be promoting this generation.
                // Serialize cancellation with it and keep the identity clicked.
                self.queued_cancel = Some(url.clone());
                ui.ctx().request_repaint();
            }
            if theme::settings_button(ui, "Open Telegram").clicked() {
                self.open_failed = !open_telegram(url);
            }
        } else if let Some((operation, _)) = &self.failure {
            if theme::settings_button(ui, "Retry").clicked() {
                self.start(ui.ctx(), operation.clone());
            }
        } else if self.state == Some(LinkState::Linked) {
            if theme::settings_button(ui, "Unlink").clicked() {
                self.start(ui.ctx(), Operation::Unlink);
            }
        } else if theme::settings_button(ui, "Link Telegram…").clicked() {
            self.start(ui.ctx(), Operation::Begin);
        }
    }

    pub(super) fn show(&mut self, ui: &mut egui::Ui) {
        if ui.is_enabled()
            && self.worker.is_none()
            && self.queued_cancel.is_none()
            && (self.reload_on_show || (self.state.is_none() && self.failure.is_none()))
        {
            self.reload_on_show = false;
            self.start(ui.ctx(), Operation::Check);
        }
        let status = self.status();
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
                |ui| self.actions(ui),
            );
        let indent = title_left - ui.next_widget_position().x;
        ui.horizontal_top(|ui| {
            ui.spacing_mut().item_spacing.x = 0.0;
            ui.add_space(indent);
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 2.0;
                let pending = matches!(self.state, Some(LinkState::Pending { .. }));
                let lines: &[&str] = if pending {
                    &["Open Telegram and tap Start to connect."]
                } else {
                    &[
                        "Can wake your iPhone for faster sign-in.",
                        "Only for Microsoft Authenticator 2FA requests.",
                    ]
                };
                for line in lines {
                    ui.add(
                        egui::Label::new(egui::RichText::new(*line).small().color(theme::MUTED))
                            .wrap(),
                    );
                }
                if let Some((_, error)) = &self.failure {
                    ui.add(
                        egui::Label::new(egui::RichText::new(*error).small().color(theme::DANGER))
                            .wrap(),
                    );
                    if pending && self.worker.is_none() && self.queued_cancel.is_none() {
                        let retry = theme::settings_button(ui, "Retry");
                        if retry.clicked() {
                            let (operation, _) = self.failure.take().unwrap();
                            self.start(ui.ctx(), operation);
                        }
                    }
                }
                if pending && self.open_failed {
                    ui.label(egui::RichText::new(OPEN_ERROR).small().color(theme::DANGER));
                }
            });
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending_state() -> LinkState {
        LinkState::Pending {
            url: "https://t.me/test_bot?start=test".into(),
        }
    }

    fn worker(operation: Operation) -> (Worker, mpsc::SyncSender<LinkResult>) {
        let (sender, receiver) = mpsc::sync_channel(1);
        (
            Worker {
                operation,
                receiver,
                started_at: Instant::now(),
            },
            sender,
        )
    }

    #[test]
    fn only_a_new_link_opens_telegram_once_and_pending_polls_do_not_hold_quit() {
        for (operation, left, closing, should_open) in [
            (Operation::Begin, false, false, true),
            (Operation::Begin, true, false, false),
            (Operation::Begin, false, true, false),
            (Operation::Check, false, false, false),
            (Operation::Refresh, false, false, false),
        ] {
            let (worker, sender) = worker(operation);
            let mut settings = TelegramSettings {
                worker: Some(worker),
                ..Default::default()
            };
            if left {
                settings.leave();
            }
            sender.send(Ok(pending_state())).unwrap();
            let mut opened = false;
            settings.finish_work(closing, |_| {
                opened = true;
                true
            });
            settings.finish_work(closing, |_| panic!("opened twice"));
            assert_eq!(opened, should_open);
            assert!(settings.state == Some(pending_state()));
            assert!(settings.next_refresh.is_some());
            assert!(!settings.change_in_progress());
        }
    }

    #[test]
    fn refresh_failure_preserves_the_pending_actions_and_recovery_stops_polling() {
        let (request, sender) = worker(Operation::Refresh);
        let mut settings = TelegramSettings {
            state: Some(pending_state()),
            worker: Some(request),
            ..Default::default()
        };
        assert!(!settings.change_in_progress());
        sender.send(Err(WORKER_ERROR)).unwrap();
        settings.finish_work(false, |_| panic!("refresh opened Telegram"));
        assert!(settings.next_refresh.is_some());
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let frame = || egui::RawInput::default();
        let _ = ctx.run_ui(frame(), |ui| settings.show(ui));
        let output = ctx.run_ui(frame(), |ui| settings.show(ui));
        for label in [
            "Open Telegram",
            "Cancel",
            "Retry",
            "Open Telegram and tap Start to connect.",
        ] {
            assert!(
                output
                    .shapes
                    .iter()
                    .any(|s| matches!(&s.shape, egui::Shape::Text(t) if t.galley.text() == label)),
                "{label}"
            );
        }
        for final_state in [LinkState::Linked, LinkState::Expired] {
            let (request, sender) = worker(Operation::Refresh);
            settings.worker = Some(request);
            settings.next_refresh = None;
            sender.send(Ok(final_state.clone())).unwrap();
            settings.finish_work(false, |_| panic!("refresh opened Telegram"));
            assert!(settings.state == Some(final_state));
            assert!(settings.failure.is_none());
            assert!(settings.next_refresh.is_none());
        }
    }

    #[test]
    fn accepted_mutations_have_a_bounded_shutdown_wait() {
        let (mut request, _sender) = worker(Operation::Unlink);
        request.started_at = Instant::now() - MAX_MUTATION_WAIT;
        let mut settings = TelegramSettings {
            worker: Some(request),
            ..Default::default()
        };
        assert!(!settings.change_in_progress());
        settings.worker.as_mut().unwrap().started_at = Instant::now();
        assert!(settings.change_in_progress());
    }

    #[test]
    fn cancel_during_refresh_keeps_the_link_the_user_clicked() {
        let (request, sender) = worker(Operation::Refresh);
        let mut settings = TelegramSettings {
            state: Some(pending_state()),
            worker: Some(request),
            ..Default::default()
        };
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let mut render = |events| {
            ctx.run_ui(
                egui::RawInput {
                    events,
                    ..Default::default()
                },
                |ui| settings.show(ui),
            )
        };
        render(vec![]);
        let output = render(vec![]);
        let pos = output
            .shapes
            .iter()
            .find_map(|s| match &s.shape {
                egui::Shape::Text(t) if t.galley.text() == "Cancel" => {
                    Some(t.visual_bounding_rect().center())
                }
                _ => None,
            })
            .unwrap();
        let button = |pressed| egui::Event::PointerButton {
            pos,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: Default::default(),
        };
        render(vec![
            egui::Event::PointerMoved(pos),
            button(true),
            button(false),
        ]);
        assert!(settings.change_in_progress());
        sender
            .send(Ok(LinkState::Pending {
                url: "replacement".into(),
            }))
            .unwrap();
        settings.finish_work(false, |_| panic!("refresh opened Telegram"));
        let LinkState::Pending { url: original } = pending_state() else {
            unreachable!()
        };
        assert_eq!(settings.queued_cancel.as_deref(), Some(original.as_str()));
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
