#[cfg(not(test))]
use crate::macos_ax::desktops::remote_pc_session_title;
#[cfg(not(test))]
use crate::macos_ax::device_launch::saved_remote_pc;
#[cfg(not(test))]
use crate::macos_ax::remote_pc_info::request_session_remote_pc;
use crate::macos_ax::remote_pc_info::SessionRemotePc;
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
    Finished,
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
        let state = match dispatch(ctx, account, Arc::downgrade(&result)) {
            Ok(()) => LookupState::Pending(result),
            Err(_) => LookupState::Failed(
                "Could not start reading the address. Select the VM again to retry.".into(),
            ),
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

#[cfg(not(test))]
fn dispatch(
    ctx: &egui::Context,
    account: &Account,
    worker: std::sync::Weak<OnceLock<Completion>>,
) -> std::io::Result<()> {
    let id = account.vm_device_id.clone();
    let name = account.vm_target.clone();
    let owner = account.vm_profile.clone();
    let repaint = ctx.clone();
    let viewport = ctx.viewport_id();
    std::thread::Builder::new()
        .name("remote-pc-import".into())
        .spawn(move || {
            let mut handoff_pid = None;
            let result = (|| -> anyhow::Result<SessionRemotePc> {
                anyhow::ensure!(worker.strong_count() != 0, "Cancelled.");
                if let Some(host) = saved_remote_pc(&id)?
                    .and_then(|host| crate::models::canonical_remote_pc(&host))
                    .filter(|host| !crate::remote_pc::is_cloud_pc_gateway(host))
                {
                    return Ok(SessionRemotePc::Selected(host));
                }
                anyhow::ensure!(worker.strong_count() != 0, "Cancelled.");
                let title = remote_pc_session_title(&id, &name, &owner)?;
                anyhow::ensure!(worker.strong_count() != 0, "Cancelled.");
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
        })
        .map(|_| ())
}

// Account-editor tests render complete frames. Keep the production state
// machine, but supply completions explicitly instead of operating Windows App.
#[cfg(test)]
fn dispatch(
    _ctx: &egui::Context,
    _account: &Account,
    _worker: std::sync::Weak<OnceLock<Completion>>,
) -> std::io::Result<()> {
    Ok(())
}

fn needs_address(account: &Account) -> bool {
    account.has_vm_device()
        && crate::models::canonical_remote_pc(&account.remote_pc)
            .is_none_or(|host| crate::remote_pc::is_cloud_pc_gateway(&host))
}

/// Explicit selection is the retry action, including reselecting the same VM.
/// Removing the state also cancels any pending lookup for the old selection.
pub(super) fn selection_changed(ctx: &egui::Context, account: &Account) {
    ctx.data_mut(|data| data.remove::<RemotePcLookup>(RemotePcLookup::id(account)));
    ctx.request_repaint();
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
        if needs_address(account) {
            RemotePcLookup::start(ui.ctx(), account);
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
                lookup.input = RemotePcLookup::input(account);
                lookup.state = LookupState::Finished;
                ui.ctx().data_mut(|d| d.insert_temp(id, lookup.clone()));
                ui.ctx().request_repaint();
                return;
            }
            Ok(SessionRemotePc::OpenDialog(host)) => LookupState::Confirm(host.clone()),
            Err(message) => LookupState::Failed(message.clone()),
        };
        ui.ctx().data_mut(|d| d.insert_temp(id, lookup.clone()));
        ui.ctx().request_repaint();
    }

    if matches!(lookup.state, LookupState::Finished) {
        return;
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
                    // A dismissed preview must not immediately reopen the native
                    // dialog on the next frame. Reselecting the VM retries it.
                    ui.ctx().data_mut(|d| {
                        d.insert_temp(
                            id,
                            RemotePcLookup {
                                input: RemotePcLookup::input(account),
                                state: LookupState::Finished,
                            },
                        )
                    });
                    ui.ctx().request_repaint();
                }
            });
        }
        LookupState::Failed(message) => {
            ui.add(egui::Label::new(egui::RichText::new(message).color(theme::DANGER)).wrap());
        }
        LookupState::Pending(_) | LookupState::Finished => {}
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

    fn selected_account() -> Account {
        let mut account = Account::new("user@example.test");
        account.vm_device_id = "workspace:one".into();
        account.vm_target = "Test desktop".into();
        account
    }

    fn pending(ctx: &egui::Context, account: &Account) -> std::sync::Weak<OnceLock<Completion>> {
        let lookup = ctx
            .data(|data| data.get_temp::<RemotePcLookup>(RemotePcLookup::id(account)))
            .expect("lookup exists");
        let LookupState::Pending(slot) = lookup.state else {
            panic!("lookup is pending")
        };
        Arc::downgrade(&slot)
    }

    fn complete_pending(
        pending: &std::sync::Weak<OnceLock<Completion>>,
        result: Result<SessionRemotePc, String>,
    ) {
        assert!(pending
            .upgrade()
            .unwrap()
            .set(Completion {
                result,
                handoff_pid: None
            })
            .is_ok());
    }

    #[test]
    fn selected_vm_without_address_starts_once_and_keeps_success() {
        let ctx = egui::Context::default();
        let mut account = selected_account();
        draw(&ctx, &mut account, Default::default());
        let first = pending(&ctx, &account);
        for _ in 0..3 {
            let frame = draw(&ctx, &mut account, Default::default());
            assert!(std::sync::Weak::ptr_eq(&first, &pending(&ctx, &account)));
            assert!(!frame.shapes.iter().any(|shape| matches!(&shape.shape,
                egui::Shape::Text(text) if text.galley.text() == "Read from open VM…")));
        }
        complete_pending(&first, Ok(SessionRemotePc::Selected("desk.example".into())));
        draw(&ctx, &mut account, Default::default());
        assert_eq!(account.remote_pc, "desk.example");
        assert!(first.upgrade().is_none());
        for _ in 0..3 {
            draw(&ctx, &mut account, Default::default());
        }
        assert!(ctx.data(|data| matches!(
            data.get_temp::<RemotePcLookup>(RemotePcLookup::id(&account))
                .unwrap()
                .state,
            LookupState::Finished
        )));
    }

    #[test]
    fn address_lookup_requires_a_selected_vm_and_missing_usable_host() {
        let ctx = egui::Context::default();
        let mut account = Account::new("user@example.test");
        draw(&ctx, &mut account, Default::default());
        assert!(ctx
            .data(|data| data.get_temp::<RemotePcLookup>(RemotePcLookup::id(&account)))
            .is_none());
        account = selected_account();
        account.remote_pc = "desk.example".into();
        draw(&ctx, &mut account, Default::default());
        assert!(ctx
            .data(|data| data.get_temp::<RemotePcLookup>(RemotePcLookup::id(&account)))
            .is_none());
        account.remote_pc = "https://invalid.example".into();
        draw(&ctx, &mut account, Default::default());
        assert!(pending(&ctx, &account).upgrade().is_some());
    }

    #[test]
    fn failed_import_waits_for_explicit_reselection() {
        let ctx = egui::Context::default();
        let mut account = selected_account();
        draw(&ctx, &mut account, Default::default());
        let first = pending(&ctx, &account);
        complete_pending(&first, Err("Desktop is not connected.".into()));
        for _ in 0..3 {
            draw(&ctx, &mut account, Default::default());
        }
        assert!(ctx.data(|data| matches!(
            data.get_temp::<RemotePcLookup>(RemotePcLookup::id(&account))
                .unwrap()
                .state,
            LookupState::Failed(_)
        )));
        selection_changed(&ctx, &account);
        draw(&ctx, &mut account, Default::default());
        assert!(first.upgrade().is_none());
        assert!(pending(&ctx, &account).upgrade().is_some());
    }

    #[test]
    fn changing_device_cancels_old_lookup_before_starting_new_one() {
        let ctx = egui::Context::default();
        let mut account = selected_account();
        draw(&ctx, &mut account, Default::default());
        let first = pending(&ctx, &account);
        account.vm_device_id = "workspace:two".into();
        account.vm_target = "Second desktop".into();
        selection_changed(&ctx, &account);
        assert!(first.upgrade().is_none());
        draw(&ctx, &mut account, Default::default());
        let second = pending(&ctx, &account);
        assert!(second.upgrade().is_some());
        account.vm_target.clear();
        draw(&ctx, &mut account, Default::default());
        assert!(second.upgrade().is_none());
        assert!(account.remote_pc.is_empty());
    }

    #[test]
    fn dismissing_unbound_dialog_does_not_restart_automatic_lookup() {
        let ctx = egui::Context::default();
        let mut account = selected_account();
        complete(
            &ctx,
            &account,
            Ok(SessionRemotePc::OpenDialog("other.example".into())),
        );
        let frame = draw(&ctx, &mut account, Default::default());
        let dismiss = frame
            .shapes
            .iter()
            .find_map(|shape| match &shape.shape {
                egui::Shape::Text(text) if text.galley.text() == "Dismiss" => {
                    Some(text.visual_bounding_rect().center())
                }
                _ => None,
            })
            .unwrap();
        let mut input = egui::RawInput::default();
        input.events.push(egui::Event::PointerMoved(dismiss));
        for pressed in [true, false] {
            input.events.push(egui::Event::PointerButton {
                pos: dismiss,
                button: egui::PointerButton::Primary,
                pressed,
                modifiers: Default::default(),
            });
        }
        draw(&ctx, &mut account, input);
        for _ in 0..3 {
            draw(&ctx, &mut account, Default::default());
        }
        assert!(account.remote_pc.is_empty());
        assert!(ctx.data(|data| matches!(
            data.get_temp::<RemotePcLookup>(RemotePcLookup::id(&account))
                .unwrap()
                .state,
            LookupState::Finished
        )));
    }
}
