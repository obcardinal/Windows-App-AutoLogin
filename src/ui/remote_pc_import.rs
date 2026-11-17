use crate::macos_ax::remote_pc_info::{open_connection_remote_pc, ConnectionInfo};
use crate::models::Account;
use crate::ui::theme;
use eframe::egui;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

/// Present only while this account's import screen is open. Closing it drops
/// the receiver; a late read can never change an account or reopen the screen.
#[derive(Clone, Default)]
pub(super) struct RemotePcLookup(Arc<OnceLock<(ConnectionInfo, Instant)>>);

impl RemotePcLookup {
    fn start(ctx: &egui::Context) -> Self {
        let lookup = Self::default();
        let worker = lookup.clone();
        let repaint = ctx.clone();
        if std::thread::Builder::new()
            .name("remote-pc-lookup".into())
            .spawn(move || {
                let result = open_connection_remote_pc().unwrap_or(ConnectionInfo::Unreadable);
                let _ = worker.0.set((result, Instant::now()));
                repaint.request_repaint();
            })
            .is_err()
        {
            let _ = lookup.0.set((ConnectionInfo::Unreadable, Instant::now()));
        }
        lookup
    }

    fn id(account: &Account) -> egui::Id {
        egui::Id::new(("lookup_remote_pc", &account.id))
    }

    fn begin(ctx: &egui::Context, account: &Account) {
        let lookup = Self::start(ctx);
        ctx.data_mut(|data| data.insert_temp(Self::id(account), lookup));
        ctx.request_repaint();
    }
}

pub(super) fn import_button(ui: &mut egui::Ui, account: &Account) {
    if ui.small_button("Import address…").clicked() {
        RemotePcLookup::begin(ui.ctx(), account);
    }
}

/// Takes the place of the editor body so the steps and actions fit even in
/// the menu-bar panel. The surrounding editor keeps its unsaved draft.
pub(super) fn show_if_open(ui: &mut egui::Ui, account: &mut Account) -> bool {
    let id = RemotePcLookup::id(account);
    let Some(lookup) = ui
        .ctx()
        .data_mut(|data| data.get_temp::<RemotePcLookup>(id))
    else {
        return false;
    };

    ui.heading("Import Remote PC");
    ui.add_space(6.0);
    ui.strong("1. Open the connection details");
    ui.label("In Windows App, switch to the desktop for this account.");
    ui.strong("Connections → Show Connection Information");
    ui.label("Leave that window open and return here.");

    ui.add_space(8.0);
    ui.strong("2. Review the address");
    let mut ready = None;
    let mut retry = false;
    match lookup.0.get() {
        Some((ConnectionInfo::Host(host), _)) => {
            ui.add(egui::Label::new(egui::RichText::new(host).monospace()).wrap());
            ready = Some(host);
        }
        Some((ConnectionInfo::Unreadable, _)) => {
            ui.label("Couldn’t read Remote PC. Reopen the connection details or go back to enter the address manually.");
            retry = ui.small_button("Check again").clicked();
        }
        Some((status, completed_at)) => {
            ui.label(if matches!(status, ConnectionInfo::SeveralWindows) {
                "Several information windows are open. Leave only the one for this desktop."
            } else {
                "Waiting for Connection Information…"
            });
            if ui.input(|input| input.focused) {
                let remaining = Duration::from_secs(2).saturating_sub(completed_at.elapsed());
                retry = remaining.is_zero();
                if !retry {
                    ui.ctx().request_repaint_after(remaining);
                }
            }
        }
        None => {
            ui.label("Checking Windows App…");
        }
    }
    ui.add_space(8.0);
    ui.separator();
    let mut close = false;
    ui.horizontal(|ui| {
        close = ui.button("Back").clicked();
        if ui
            .add_enabled(ready.is_some(), theme::primary_button("Use this address"))
            .clicked()
        {
            if let Some(host) = ready {
                account.remote_pc.clone_from(host);
                close = true;
            }
        }
    });
    if close {
        ui.ctx().data_mut(|data| data.remove::<RemotePcLookup>(id));
        ui.ctx().request_repaint();
    } else if retry {
        RemotePcLookup::begin(ui.ctx(), account);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn preview(
        ctx: &egui::Context,
        account: &mut Account,
        at: Option<egui::Pos2>,
    ) -> egui::FullOutput {
        let mut input = egui::RawInput::default();
        if let Some(pos) = at {
            input.events.push(egui::Event::PointerMoved(pos));
            for pressed in [true, false] {
                input.events.push(egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed,
                    modifiers: Default::default(),
                });
            }
        }
        ctx.run_ui(input, |ui| {
            show_if_open(ui, account);
        })
    }

    fn button(frame: &egui::FullOutput, label: &str) -> egui::Pos2 {
        frame
            .shapes
            .iter()
            .find_map(|item| match &item.shape {
                egui::Shape::Text(text) if text.galley.text() == label => {
                    Some(text.visual_bounding_rect().center())
                }
                _ => None,
            })
            .expect("the action must be visible")
    }

    fn set_result(ctx: &egui::Context, account: &Account, status: ConnectionInfo) {
        let lookup = RemotePcLookup::default();
        assert!(lookup.0.set((status, Instant::now())).is_ok());
        ctx.data_mut(|data| data.insert_temp(RemotePcLookup::id(account), lookup));
    }

    #[test]
    fn remote_pc_import_requires_a_detected_address_and_an_explicit_choice() {
        let ctx = egui::Context::default();
        let mut account = Account::new("user@example.test");
        account.remote_pc = "manual.example".into();
        set_result(&ctx, &account, ConnectionInfo::SeveralWindows);
        let frame = preview(&ctx, &mut account, None);
        preview(&ctx, &mut account, Some(button(&frame, "Use this address")));
        assert_eq!(account.remote_pc, "manual.example");
        set_result(&ctx, &account, ConnectionInfo::Host("desk.example".into()));
        let frame = preview(&ctx, &mut account, None);
        assert_eq!(account.remote_pc, "manual.example");
        preview(&ctx, &mut account, Some(button(&frame, "Back")));
        assert_eq!(account.remote_pc, "manual.example");
        assert!(ctx
            .data_mut(|d| d.get_temp::<RemotePcLookup>(RemotePcLookup::id(&account)))
            .is_none());
        set_result(&ctx, &account, ConnectionInfo::Host("desk.example".into()));
        let other = Account::new("other@example.test");
        assert!(ctx
            .data_mut(|d| d.get_temp::<RemotePcLookup>(RemotePcLookup::id(&other)))
            .is_none());
        let frame = preview(&ctx, &mut account, None);
        preview(&ctx, &mut account, Some(button(&frame, "Use this address")));
        assert_eq!(account.remote_pc, "desk.example");
    }
}
