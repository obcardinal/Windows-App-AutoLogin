use crate::macos_ax::desktops::remote_pc_session_title;
use crate::macos_ax::device_launch::saved_remote_pc;
use crate::macos_ax::remote_pc_info::{request_session_remote_pc, SessionRemotePc};
use crate::models::Account;
use crate::ui::theme;
use eframe::egui;
use std::sync::{Arc, OnceLock};

#[derive(Clone)]
pub(super) struct RemotePcLookup {
    // Discard a lookup when the user edits the destination or its current value.
    input: egui::Id,
    state: LookupState,
}

#[derive(Clone)]
enum LookupState {
    Pending(Arc<OnceLock<Completion>>),
    Confirm(String),
    Failed(String),
}

struct Completion {
    result: Result<SessionRemotePc, String>,
    handoff_pid: Option<i32>,
}

impl RemotePcLookup {
    fn id(account: &Account) -> egui::Id {
        egui::Id::new(("lookup_remote_pc", &account.id))
    }

    fn input(account: &Account) -> egui::Id {
        egui::Id::new((
            &account.vm_device_id,
            &account.vm_target,
            &account.vm_profile,
            &account.remote_pc,
        ))
    }

    fn start(ctx: &egui::Context, account: &Account) {
        let result = Arc::new(OnceLock::new());
        let worker = Arc::downgrade(&result);
        let id = account.vm_device_id.clone();
        let name = account.vm_target.clone();
        let owner = account.vm_profile.clone();
        let repaint = ctx.clone();
        let viewport = ctx.viewport_id();
        let thread = std::thread::Builder::new()
            .name("remote-pc-import".into())
            .spawn(move || {
                let mut handoff_pid = None;
                let result = (|| -> anyhow::Result<SessionRemotePc> {
                    if let Some(host) = saved_remote_pc(&id)? {
                        return Ok(SessionRemotePc::Selected(host));
                    }
                    let title = remote_pc_session_title(&id, &name, &owner)?;
                    request_session_remote_pc(
                        title.as_deref(),
                        || worker.strong_count() == 0,
                        |pid| handoff_pid = Some(pid),
                    )
                })()
                .map_err(|error| error.to_string());
                if let Some(completion) = worker.upgrade() {
                    let _ = completion.set(Completion {
                        result,
                        handoff_pid,
                    });
                    repaint.request_repaint_of(viewport);
                    repaint.request_repaint_of(egui::ViewportId::ROOT);
                }
            });
        let state = match thread {
            Ok(_) => LookupState::Pending(result),
            Err(_) => LookupState::Failed("Could not start the import. Try again.".into()),
        };
        ctx.data_mut(|d| {
            d.insert_temp(
                Self::id(account),
                Self {
                    input: Self::input(account),
                    state,
                },
            )
        });
        ctx.request_repaint();
    }
}

fn read_from_open_vm(ui: &mut egui::Ui, account: &Account) {
    if ui
        .link("Read from open VM…")
        .on_hover_text("Show Connection Information in Windows App to read this desktop’s address.")
        .clicked()
    {
        RemotePcLookup::start(ui.ctx(), account);
    }
}

pub(super) fn show_result(ui: &mut egui::Ui, account: &mut Account) {
    let id = RemotePcLookup::id(account);
    let lookup = ui.ctx().data_mut(|d| {
        let lookup = d.get_temp::<RemotePcLookup>(id)?;
        if lookup.input == RemotePcLookup::input(account) {
            Some(lookup)
        } else {
            d.remove::<RemotePcLookup>(id);
            None
        }
    });
    let Some(mut lookup) = lookup else {
        if !super::device_needs_setup(account)
            && crate::models::canonical_remote_pc(&account.remote_pc)
                .is_none_or(|host| crate::remote_pc::is_cloud_pc_gateway(&host))
        {
            super::account_editor_field_note(ui, |ui| read_from_open_vm(ui, account));
        }
        return;
    };

    if let LookupState::Pending(slot) = &lookup.state {
        let Some(completed) = slot.get() else {
            super::account_editor_field_note(ui, |ui| {
                super::account_editor_help(ui, "Reading the address from Windows App…");
            });
            return;
        };
        if completed.handoff_pid.is_some_and(|pid| {
            objc2_app_kit::NSWorkspace::sharedWorkspace()
                .frontmostApplication()
                .is_some_and(|front| front.processIdentifier() == pid)
        }) {
            super::focus_account_editor(ui.ctx());
        }
        lookup.state = match &completed.result {
            Ok(SessionRemotePc::Selected(host)) => {
                account.remote_pc.clone_from(host);
                ui.ctx().data_mut(|d| d.remove::<RemotePcLookup>(id));
                ui.ctx().request_repaint();
                return;
            }
            Ok(SessionRemotePc::OpenDialog(host)) => LookupState::Confirm(host.clone()),
            Err(message) => LookupState::Failed(message.clone()),
        };
        ui.ctx().data_mut(|d| d.insert_temp(id, lookup.clone()));
        ui.ctx().request_repaint();
    }

    super::account_editor_field_note(ui, |ui| match &lookup.state {
        LookupState::Confirm(host) => {
            super::account_editor_help(ui, "Windows App already has connection details open. Use this address for this account?");
            ui.label(egui::RichText::new(host).monospace());
            ui.horizontal(|ui| {
                let apply = ui
                    .add(theme::secondary_button("Use this address"))
                    .clicked();
                if apply {
                    account.remote_pc.clone_from(host);
                }
                if apply || ui.add(theme::secondary_button("Dismiss")).clicked() {
                    ui.ctx().data_mut(|d| d.remove::<RemotePcLookup>(id));
                    ui.ctx().request_repaint();
                }
            });
        }
        LookupState::Failed(message) => {
            ui.add(egui::Label::new(egui::RichText::new(message).color(theme::DANGER)).wrap());
            read_from_open_vm(ui, account);
        }
        LookupState::Pending(_) => {}
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete(ctx: &egui::Context, account: &Account, result: Result<SessionRemotePc, String>) {
        let completion = Completion {
            result,
            handoff_pid: None,
        };
        let slot = Arc::new(OnceLock::from(completion));
        let lookup = RemotePcLookup {
            input: RemotePcLookup::input(account),
            state: LookupState::Pending(slot),
        };
        ctx.data_mut(|data| data.insert_temp(RemotePcLookup::id(account), lookup));
    }

    fn draw(ctx: &egui::Context, account: &mut Account, input: egui::RawInput) -> egui::FullOutput {
        ctx.run_ui(input, |ui| show_result(ui, account))
    }

    #[test]
    fn imports_into_the_unchanged_draft_only() {
        let ctx = egui::Context::default();
        let mut account = Account::new("user@example.test");
        let selected = || Ok(SessionRemotePc::Selected("desk.example".into()));
        complete(&ctx, &account, selected());
        account.remote_pc = "manual.example".into();
        draw(&ctx, &mut account, Default::default());
        assert_eq!(account.remote_pc, "manual.example");
        complete(&ctx, &account, selected());
        account.vm_device_id = "open-window".into();
        draw(&ctx, &mut account, Default::default());
        assert_eq!(account.remote_pc, "manual.example");
        complete(&ctx, &account, Err("Unavailable.".into()));
        draw(&ctx, &mut account, Default::default());
        assert_eq!(account.remote_pc, "manual.example");
        complete(&ctx, &account, selected());
        draw(&ctx, &mut account, Default::default());
        assert_eq!(account.remote_pc, "desk.example");
    }

    #[test]
    fn a_preexisting_dialog_needs_confirmation() {
        let ctx = egui::Context::default();
        let mut account = Account::new("user@example.test");
        account.remote_pc = "manual.example".into();
        complete(
            &ctx,
            &account,
            Ok(SessionRemotePc::OpenDialog("preview.example".into())),
        );
        let preview = draw(&ctx, &mut account, Default::default());
        assert_eq!(account.remote_pc, "manual.example");
        let confirm = preview
            .shapes
            .iter()
            .find_map(|s| match &s.shape {
                egui::Shape::Text(t) if t.galley.text() == "Use this address" => {
                    Some(t.visual_bounding_rect().center())
                }
                _ => None,
            })
            .expect("Confirm action is visible");
        let mut input = egui::RawInput::default();
        input.events.push(egui::Event::PointerMoved(confirm));
        for pressed in [true, false] {
            input.events.push(egui::Event::PointerButton {
                pos: confirm,
                button: egui::PointerButton::Primary,
                pressed,
                modifiers: Default::default(),
            });
        }
        draw(&ctx, &mut account, input);
        assert_eq!(account.remote_pc, "preview.example");
    }
}
