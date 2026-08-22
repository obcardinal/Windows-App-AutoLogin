use crate::app::AutoLoginApp;
use crate::models::{Account, AccountId, AppConfig};
use crate::storage::{
    begin_account_config_save_journal_with_revision, begin_account_delete_journal,
    begin_account_enabled_toggle_journal, cleanup_unused_fallback_key_material,
    clear_pending_storage_operation, config_write_committed, delete_account,
    finish_account_password_write, is_pending_storage_operation_in_progress, load_password,
    load_password_for_rollback_verification, mark_account_config_rollback_journal,
    mark_account_delete_committed_journal, mark_account_enabled_toggle_committed_journal,
    new_account_config_revision_marker, new_account_config_rollback_marker,
    pending_storage_recovery_user_status, save_config,
    write_account_password_borrowed_for_rollback, write_account_password_borrowed_with_revision,
    write_account_password_owned_with_revision, PasswordWriteReceipt, StaleBackendCleanupWarning,
};
use crate::ui::theme;
use eframe::egui;
use zeroize::{Zeroize, Zeroizing};

const STATE_COLUMN_WIDTH: f32 = 88.0;
const TABLE_SPACING: f32 = 8.0;
const EDIT_BUTTON_WIDTH: f32 = 40.0;
const DELETE_BUTTON_WIDTH: f32 = 40.0;
const ROW_BUTTON_HEIGHT: f32 = 30.0;
const ACTIONS_COLUMN_WIDTH: f32 = EDIT_BUTTON_WIDTH + TABLE_SPACING + DELETE_BUTTON_WIDTH;
const ACCOUNT_ROW_HEIGHT: f32 = 36.0;
const ACCOUNT_EDITOR_WIDTH: f32 = 430.0;
const ACCOUNT_EDITOR_FIELD_WIDTH: f32 = 332.0;
const ACCOUNT_EDITOR_PASSWORD_WIDTH: f32 = 286.0;
const ACTION_ICON_SIZE: f32 = 17.0;
const PASSWORD_EDITOR_ID_SALT: &str = "account_password_editor";
const PASSWORD_EDITOR_MAX_BYTES: usize = 4096;
const PENCIL_ICON: &[u8] = include_bytes!("../../assets/icons/pencil.svg");
const TRASH_ICON: &[u8] = include_bytes!("../../assets/icons/trash.svg");

pub fn show(ui: &mut egui::Ui, app: &mut AutoLoginApp) {
    let mut toggle_enabled_idx = None;
    let mut delete_idx: Option<usize> = None;
    let mut edit_account: Option<Account> = None;
    let mut confirm_delete_account: Option<String> = None;
    let modal_open = app.editing_account.is_some() || app.confirm_delete_account.is_some();
    let account_mutations_ready = app.account_mutations_ready();

    let account_count = app.config.accounts.len();
    theme::page_header(
        ui,
        "Accounts",
        &format!("{account_count} saved account(s) monitored through Windows App."),
        |ui| {
            if ui
                .add_enabled(
                    !modal_open && account_mutations_ready,
                    theme::primary_button("+ Add Account").min_size(egui::vec2(182.0, 30.0)),
                )
                .clicked()
            {
                open_account_editor(ui.ctx(), app, Account::new(""));
            }
        },
    );

    if app.config.accounts.is_empty() {
        theme::glass_frame().show(ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.heading("No accounts yet");
                ui.label(theme::muted(
                    "Add an email and password to start monitoring.",
                ));
                ui.add_space(6.0);
                if ui
                    .add_enabled(
                        !modal_open && account_mutations_ready,
                        theme::primary_button("+ Add Account").min_size(egui::vec2(182.0, 30.0)),
                    )
                    .clicked()
                {
                    open_account_editor(ui.ctx(), app, Account::new(""));
                }
            });
        });
    } else {
        egui::ScrollArea::vertical()
            .auto_shrink([false; 2])
            .show(ui, |ui| {
                theme::compact_frame().show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    show_accounts_header(ui);
                    ui.separator();

                    for (idx, account) in app.config.accounts.iter().enumerate() {
                        show_account_row(
                            ui,
                            idx,
                            account,
                            !modal_open && account_mutations_ready,
                            &mut toggle_enabled_idx,
                            &mut edit_account,
                            &mut confirm_delete_account,
                        );
                        if idx + 1 < app.config.accounts.len() {
                            ui.separator();
                        }
                    }
                });
            });
    }

    if !account_mutations_ready {
        ui.add_space(8.0);
        ui.label(theme::muted(
            "Account changes are locked until pending password storage recovery completes after restart.",
        ));
    }

    if let Some(account) = edit_account {
        open_account_editor(ui.ctx(), app, account);
    }

    if let Some(account_id) = confirm_delete_account {
        app.confirm_delete_account = Some(account_id);
    }

    if let Some(idx) = toggle_enabled_idx {
        let next_config = app.config.clone();
        if let Some(account) = next_config.accounts.get(idx) {
            let enabling = !account.enabled;
            let email = account.username.trim().to_string();
            if enabling && email.is_empty() {
                app.set_status("Email is required");
            } else if enabling && !account.has_saved_password {
                app.set_status("Password is required before enabling this account");
            } else if enabling
                && next_config
                    .accounts
                    .iter()
                    .enumerate()
                    .any(|(other_idx, other)| {
                        other_idx != idx && enabled_account_conflicts_with_candidate(other, &email)
                    })
            {
                app.set_status("An enabled account with this email already exists");
            } else {
                match toggle_account_transaction(
                    &app.config,
                    idx,
                    enabling,
                    begin_account_enabled_toggle_journal,
                    mark_account_enabled_toggle_committed_journal,
                    save_config,
                    clear_pending_storage_operation,
                ) {
                    Ok(outcome) => {
                        app.config = outcome.config;
                        if outcome.config_durability_warning {
                            tracing::warn!(
                                "Account toggle committed, but config durability confirmation failed"
                            );
                            app.set_status("Account updated, but disk durability could not be confirmed. Recovery remains pending and auto-login will stay stopped until restart.");
                            app.stop_monitor_for_pending_storage_recovery();
                        } else if outcome.journal_cleanup_warning {
                            tracing::warn!(
                                "Account toggle committed, but its recovery journal could not be cleared"
                            );
                            app.set_status("Account updated, but recovery journal cleanup is pending. Auto-login will stay stopped until restart.");
                            app.stop_monitor_for_pending_storage_recovery();
                        } else {
                            app.set_status("Account updated");
                            sync_worker_accounts(app, false);
                        }
                    }
                    Err(status) => {
                        app.set_status(status);
                        app.stop_monitor_for_pending_storage_recovery();
                    }
                }
            }
        }
    }

    show_delete_confirmation(ui, app, &mut delete_idx);

    if let Some(idx) = delete_idx {
        match delete_account_transaction(
            &app.config,
            idx,
            begin_account_delete_journal,
            mark_account_delete_committed_journal,
            delete_account,
            save_config,
            clear_pending_storage_operation,
        ) {
            Ok(outcome) => {
                let cleanup_warning = if outcome.config_durability_warning
                    || outcome.password_cleanup_warning
                    || outcome.journal_cleanup_warning
                {
                    false
                } else {
                    cleanup_unused_fallback_key_material().is_err()
                };
                app.config = outcome.config;
                if outcome.config_durability_warning {
                    tracing::warn!(
                        "Account removal committed, but config durability confirmation failed"
                    );
                    app.set_status(
                        "Account deleted, but disk durability could not be confirmed. Cleanup remains pending and will be checked on next launch.",
                    );
                } else if outcome.password_cleanup_warning {
                    tracing::warn!(
                        "Account deleted, but saved password cleanup failed after config save"
                    );
                    app.set_status(
                        "Account deleted. Saved password cleanup is still pending and will retry on next launch. Stored credential changes are blocked until recovery completes.",
                    );
                } else if outcome.journal_cleanup_warning {
                    tracing::warn!(
                        "Account deleted and saved password cleanup succeeded, but recovery journal cleanup failed"
                    );
                    app.set_status(
                        "Account deleted. Saved password cleanup succeeded, but recovery journal cleanup is still pending; restart to verify cleanup.",
                    );
                } else if cleanup_warning {
                    tracing::warn!(
                        "Account deleted, but unused fallback key cleanup failed after config save"
                    );
                    app.set_status(
                        "Account deleted. Old fallback key cleanup failed; old key material may require manual cleanup.",
                    );
                } else {
                    app.set_status("Account deleted");
                }
                if outcome.config_durability_warning
                    || outcome.password_cleanup_warning
                    || outcome.journal_cleanup_warning
                {
                    app.stop_monitor_for_pending_storage_recovery();
                } else {
                    sync_worker_accounts(app, false);
                }
            }
            Err(status) => {
                app.set_status(status);
                app.stop_monitor_for_pending_storage_recovery();
            }
        }
        app.confirm_delete_account = None;
    }

    show_account_editor(ui, app);
}

fn toggle_account_transaction<J, M, S, C>(
    config: &AppConfig,
    idx: usize,
    enabled: bool,
    mut begin_journal_op: J,
    mut commit_journal_op: M,
    mut save_config_op: S,
    mut clear_journal_op: C,
) -> Result<ToggleAccountOutcome, String>
where
    J: FnMut(&Account, &Account, bool) -> anyhow::Result<()>,
    M: FnMut(&Account, &Account, bool) -> anyhow::Result<()>,
    S: FnMut(&AppConfig) -> anyhow::Result<()>,
    C: FnMut() -> anyhow::Result<()>,
{
    let Some(before_account) = config.accounts.get(idx).cloned() else {
        return Err("Account no longer exists".to_string());
    };
    let mut after_account = before_account.clone();
    after_account.enabled = enabled;

    if let Err(error) =
        begin_journal_op(&before_account, &after_account, config.settings.use_keyring)
    {
        return Err(storage_prepare_failure_status(
            &error,
            "The account was left unchanged.",
            "Failed to prepare the account update. The account was left unchanged.",
        ));
    }
    if let Err(error) =
        commit_journal_op(&before_account, &after_account, config.settings.use_keyring)
    {
        if config_write_committed(&error) {
            return Err("The account update intent was recorded, but its disk durability could not be confirmed. The account was not changed in this window; recovery remains pending and auto-login will stay stopped until restart.".to_string());
        }
        let journal_cleared = clear_journal_op().is_ok();
        return Err(if journal_cleared {
            "Failed to commit the account update intent. The account was left unchanged."
                .to_string()
        } else {
            "Failed to commit the account update intent. The account was left unchanged, but the prepared recovery journal could not be cleared; restart before changing accounts again.".to_string()
        });
    }

    let mut next_config = config.clone();
    next_config.accounts[idx] = after_account;
    let config_durability_warning = match save_config_op(&next_config) {
        Ok(()) => false,
        Err(error) if config_write_committed(&error) => true,
        // The durable committed intent must win even if config replacement
        // failed before rename. Recovery reapplies the target toggle before
        // the monitor can start, so the in-memory view follows that intent.
        Err(_) => true,
    };
    let journal_cleanup_warning = if config_durability_warning {
        false
    } else {
        clear_journal_op().is_err()
    };

    Ok(ToggleAccountOutcome {
        config: next_config,
        config_durability_warning,
        journal_cleanup_warning,
    })
}

#[derive(Debug)]
struct ToggleAccountOutcome {
    config: AppConfig,
    config_durability_warning: bool,
    journal_cleanup_warning: bool,
}

fn delete_account_transaction<J, M, D, C, R>(
    config: &AppConfig,
    idx: usize,
    mut begin_delete_journal_op: J,
    mut commit_delete_journal_op: M,
    mut delete_account_op: D,
    mut save_config_op: C,
    mut clear_journal_op: R,
) -> Result<DeleteAccountOutcome, String>
where
    J: FnMut(&Account, bool) -> anyhow::Result<()>,
    M: FnMut(&Account, bool) -> anyhow::Result<()>,
    D: FnMut(&AccountId) -> anyhow::Result<()>,
    C: FnMut(&AppConfig) -> anyhow::Result<()>,
    R: FnMut() -> anyhow::Result<()>,
{
    let Some(account) = config.accounts.get(idx).cloned() else {
        return Err("Account no longer exists".to_string());
    };
    let use_keyring = config.settings.use_keyring;
    if let Err(e) = begin_delete_journal_op(&account, use_keyring) {
        return Err(storage_prepare_failure_status(
            &e,
            "The account was not deleted and saved password storage was left unchanged.",
            "Failed to prepare account removal. The account was not deleted and saved password storage was left unchanged.",
        ));
    }
    if let Err(e) = commit_delete_journal_op(&account, use_keyring) {
        if config_write_committed(&e) {
            return Err("Account removal intent was recorded, but its disk durability could not be confirmed. The account was not changed in this window; recovery remains pending and auto-login will stay stopped until the next launch resolves it.".to_string());
        }
        let journal_cleared = clear_journal_op().is_ok();
        return Err(if journal_cleared {
            "Failed to commit the account removal intent. The account and saved password were left unchanged.".to_string()
        } else {
            "Failed to commit the account removal intent. The account and saved password were left unchanged, but the prepared recovery journal could not be cleared; restart before using auto-login.".to_string()
        });
    }

    let mut next_config = config.clone();
    next_config.accounts.remove(idx);
    let config_durability_warning = match save_config_op(&next_config) {
        Ok(()) => false,
        Err(e) if config_write_committed(&e) => true,
        Err(_) => return Err("Failed to save the account removal. The durable removal intent remains pending; the saved password was retained and auto-login will stay stopped until recovery completes.".to_string()),
    };

    // A committed rename whose parent-directory durability is unconfirmed can
    // still roll back after power loss. Keep the credential and journal until
    // recovery first makes the account removal durable.
    let password_cleanup_warning = if config_durability_warning {
        false
    } else {
        delete_account_op(&account.id).is_err()
    };
    let journal_cleanup_warning = if password_cleanup_warning || config_durability_warning {
        false
    } else {
        clear_journal_op().is_err()
    };
    Ok(DeleteAccountOutcome {
        config: next_config,
        config_durability_warning,
        password_cleanup_warning,
        journal_cleanup_warning,
    })
}

#[derive(Debug)]
struct DeleteAccountOutcome {
    config: AppConfig,
    config_durability_warning: bool,
    password_cleanup_warning: bool,
    journal_cleanup_warning: bool,
}

fn storage_prepare_failure_status(
    error: &anyhow::Error,
    pending_detail: &str,
    fallback: &str,
) -> String {
    if is_pending_storage_operation_in_progress(error) {
        pending_storage_recovery_user_status(pending_detail)
    } else {
        fallback.to_string()
    }
}

struct AccountColumns {
    email: f32,
    state: f32,
    actions: f32,
}

fn show_accounts_header(ui: &mut egui::Ui) {
    show_table_row(ui, 22.0, |ui, cells| {
        show_cell(
            ui,
            cells.email,
            egui::Layout::left_to_right(egui::Align::Center),
            |ui| {
                ui.label(table_header_text("Account"));
            },
        );
        show_cell(
            ui,
            cells.state,
            egui::Layout::left_to_right(egui::Align::Center),
            |ui| {
                ui.label(table_header_text("Enabled"));
            },
        );
        show_cell(
            ui,
            cells.actions,
            egui::Layout::left_to_right(egui::Align::Center),
            |ui| {
                ui.label(table_header_text("Actions"));
            },
        );
    });
}

fn table_header_text(text: impl Into<String>) -> egui::RichText {
    egui::RichText::new(text)
        .size(14.0)
        .color(theme::MUTED)
        .line_height(Some(19.0))
}

fn show_account_row(
    ui: &mut egui::Ui,
    idx: usize,
    account: &Account,
    actions_enabled: bool,
    toggle_enabled_idx: &mut Option<usize>,
    edit_account: &mut Option<Account>,
    confirm_delete_account: &mut Option<String>,
) {
    show_table_row(ui, ACCOUNT_ROW_HEIGHT, |ui, cells| {
        let email = account.username.trim();
        show_cell(
            ui,
            cells.email,
            egui::Layout::left_to_right(egui::Align::Center),
            |ui| {
                if email.is_empty() {
                    ui.label(theme::muted("Missing email"));
                } else {
                    ui.add_sized(
                        [ui.available_width(), 21.0],
                        egui::Label::new(egui::RichText::new(email).strong()).truncate(),
                    )
                    .on_hover_text(email);
                }
            },
        );

        show_cell(
            ui,
            cells.state,
            egui::Layout::left_to_right(egui::Align::Center),
            |ui| {
                let mut enabled = account.enabled;
                if ui
                    .add_enabled(actions_enabled, egui::Checkbox::without_text(&mut enabled))
                    .changed()
                {
                    *toggle_enabled_idx = Some(idx);
                }
            },
        );

        show_cell(
            ui,
            cells.actions,
            egui::Layout::left_to_right(egui::Align::Center),
            |ui| {
                if account_action_button(ui, AccountActionIcon::Edit, actions_enabled)
                    .on_hover_text("Edit account")
                    .clicked()
                {
                    *edit_account = Some(account.clone());
                }
                if account_action_button(ui, AccountActionIcon::Delete, actions_enabled)
                    .on_hover_text("Delete account")
                    .clicked()
                {
                    *confirm_delete_account = Some(account.id.clone());
                }
            },
        );
    });
}

fn table_spacing() -> f32 {
    TABLE_SPACING
}

struct AccountCellRects {
    email: egui::Rect,
    state: egui::Rect,
    actions: egui::Rect,
}

fn show_table_row(
    ui: &mut egui::Ui,
    height: f32,
    add_contents: impl FnOnce(&mut egui::Ui, AccountCellRects),
) {
    let width = ui.available_width();
    let (row_rect, _) = ui.allocate_exact_size(egui::vec2(width, height), egui::Sense::hover());
    let columns = account_columns(width);
    let spacing = table_spacing();

    let email = egui::Rect::from_min_size(row_rect.min, egui::vec2(columns.email, height));
    let state = egui::Rect::from_min_size(
        egui::pos2(email.max.x + spacing, row_rect.min.y),
        egui::vec2(columns.state, height),
    );
    let actions = egui::Rect::from_min_size(
        egui::pos2(state.max.x + spacing, row_rect.min.y),
        egui::vec2(columns.actions, height),
    );

    add_contents(
        ui,
        AccountCellRects {
            email,
            state,
            actions,
        },
    );
}

fn show_cell(
    ui: &mut egui::Ui,
    rect: egui::Rect,
    layout: egui::Layout,
    add_contents: impl FnOnce(&mut egui::Ui),
) {
    ui.scope_builder(
        egui::UiBuilder::new().max_rect(rect).layout(layout),
        add_contents,
    );
}

fn account_columns(width: f32) -> AccountColumns {
    let spacing = table_spacing() * 2.0;
    let fixed_width = STATE_COLUMN_WIDTH + ACTIONS_COLUMN_WIDTH + spacing;
    AccountColumns {
        email: (width - fixed_width).max(120.0),
        state: STATE_COLUMN_WIDTH,
        actions: ACTIONS_COLUMN_WIDTH,
    }
}

fn open_account_editor(ctx: &egui::Context, app: &mut AutoLoginApp, account: Account) {
    tracing::info!("Opening account editor");
    if let Some(previous_account) = app.editing_account.as_ref() {
        forget_password_editor_state(ctx, password_editor_id(&previous_account.id));
    }
    forget_password_editor_state(ctx, password_editor_id(&account.id));
    app.editing_account = Some(account);
    clear_temp_password(app);
    app.show_password = false;
}

fn clear_temp_password(app: &mut AutoLoginApp) {
    app.temp_password = empty_password_buffer();
}

fn empty_password_buffer() -> Zeroizing<String> {
    // Fixed up-front capacity prevents password edits from leaving old heap
    // allocations behind during String growth. Zeroizing wipes the entire
    // capacity when this buffer is replaced or dropped.
    Zeroizing::new(String::with_capacity(PASSWORD_EDITOR_MAX_BYTES))
}

fn password_editor_id(account_id: &str) -> egui::Id {
    egui::Id::new((PASSWORD_EDITOR_ID_SALT, account_id))
}

fn forget_password_editor_state(ctx: &egui::Context, id: egui::Id) {
    ctx.memory_mut(|memory| memory.surrender_focus(id));
    ctx.data_mut(|data| data.remove::<egui::text_edit::TextEditState>(id));
}

/// Minimal password input used instead of egui::TextEdit. TextEdit clones its
/// complete backing string every frame for change reporting and its Undoer,
/// even when max_undos is zero. This editor keeps only the Zeroizing backing
/// buffer and consumes/zeroizes owned input-event strings immediately.
///
/// Native windowing/IME layers can still transiently own typed characters
/// before egui delivers them; application code cannot guarantee wiping those
/// platform allocations. Password reveal is intentionally unavailable so the
/// renderer and accessibility tree receive only bullets.
fn secure_password_editor(
    ui: &mut egui::Ui,
    password: &mut Zeroizing<String>,
    id: egui::Id,
    hint: &str,
) -> egui::Response {
    let desired_size = egui::vec2(ACCOUNT_EDITOR_PASSWORD_WIDTH, 24.0);
    let (_, rect) = ui.allocate_space(desired_size);
    let response = ui.interact(rect, id, egui::Sense::click());
    if response.clicked() {
        response.request_focus();
    }

    if response.has_focus() {
        consume_password_input_events(ui.ctx(), password);
        suppress_password_clipboard_output(ui.ctx(), true);
    }

    let visuals = ui.style().interact(&response);
    ui.painter().rect(
        rect,
        egui::CornerRadius::same(4),
        ui.visuals().extreme_bg_color,
        visuals.bg_stroke,
        egui::StrokeKind::Inside,
    );
    let (display, color) = if password.is_empty() {
        (hint.to_string(), ui.visuals().weak_text_color())
    } else {
        (
            std::iter::repeat_n(
                egui::epaint::text::PASSWORD_REPLACEMENT_CHAR,
                password.chars().count(),
            )
            .collect::<String>(),
            visuals.text_color(),
        )
    };
    ui.painter().text(
        rect.left_center() + egui::vec2(8.0, 0.0),
        egui::Align2::LEFT_CENTER,
        display,
        egui::TextStyle::Body.resolve(ui.style()),
        color,
    );
    if response.has_focus() {
        let cursor_x =
            (rect.left() + 8.0 + password.chars().count() as f32 * 8.0).min(rect.right() - 5.0);
        ui.painter().vline(
            cursor_x,
            (rect.top() + 4.0)..=(rect.bottom() - 4.0),
            egui::Stroke::new(1.0, visuals.text_color()),
        );
    }
    response.widget_info(|| {
        egui::WidgetInfo::labeled(egui::WidgetType::TextEdit, ui.is_enabled(), "Password")
    });
    response
}

fn consume_password_input_events(ctx: &egui::Context, password: &mut Zeroizing<String>) {
    ctx.input_mut(|input| {
        let events = std::mem::take(&mut input.events);
        let mut retained = Vec::with_capacity(events.len());
        for event in events {
            match event {
                egui::Event::Text(mut text) | egui::Event::Paste(mut text) => {
                    append_password_input(password, &text);
                    text.zeroize();
                }
                egui::Event::Ime(egui::ImeEvent::Commit(mut text)) => {
                    append_password_input(password, &text);
                    text.zeroize();
                }
                egui::Event::Ime(egui::ImeEvent::Preedit(mut text)) => {
                    // Do not retain composition plaintext in widget state.
                    text.zeroize();
                }
                egui::Event::Copy | egui::Event::Cut => {}
                egui::Event::Key {
                    key: egui::Key::Backspace | egui::Key::Delete,
                    pressed: true,
                    ..
                } => pop_password_char(password),
                other => retained.push(other),
            }
        }
        input.events = retained;

        // InputState keeps a clone of every RawInput event for the lifetime of
        // the frame. Consuming `input.events` alone therefore leaves a second
        // plaintext password copy behind. Scrub that clone without processing
        // it again; non-secret events remain available to egui.
        scrub_password_event_copies(&mut input.raw.events);
    });
}

fn scrub_password_event_copies(events: &mut Vec<egui::Event>) {
    let raw_events = std::mem::take(events);
    let mut retained = Vec::with_capacity(raw_events.len());
    for event in raw_events {
        match event {
            egui::Event::Text(mut text)
            | egui::Event::Paste(mut text)
            | egui::Event::Ime(egui::ImeEvent::Preedit(mut text))
            | egui::Event::Ime(egui::ImeEvent::Commit(mut text)) => text.zeroize(),
            egui::Event::Copy | egui::Event::Cut => {}
            other => retained.push(other),
        }
    }
    *events = retained;
}

fn append_password_input(password: &mut String, input: &str) {
    for character in input
        .chars()
        .filter(|character| !matches!(character, '\r' | '\n'))
    {
        if password.len() + character.len_utf8() > PASSWORD_EDITOR_MAX_BYTES {
            break;
        }
        password.push(character);
    }
}

fn pop_password_char(password: &mut String) {
    let Some((new_len, _)) = password.char_indices().next_back() else {
        return;
    };
    // String::truncate leaves removed bytes initialized in spare capacity.
    // Wipe the removed UTF-8 codepoint before shortening the allocation.
    unsafe {
        let bytes = password.as_mut_vec();
        bytes[new_len..].zeroize();
        bytes.truncate(new_len);
    }
}

fn suppress_password_clipboard_output(ctx: &egui::Context, password_field_has_focus: bool) {
    if !password_field_has_focus {
        return;
    }

    ctx.output_mut(|output| {
        output
            .commands
            .retain(|command| !matches!(command, egui::OutputCommand::CopyText(_)));
    });
}

fn show_delete_confirmation(
    ui: &mut egui::Ui,
    app: &mut AutoLoginApp,
    delete_idx: &mut Option<usize>,
) {
    let Some(account_id) = app.confirm_delete_account.clone() else {
        return;
    };

    let Some(idx) = app.config.accounts.iter().position(|a| a.id == account_id) else {
        app.confirm_delete_account = None;
        return;
    };

    let account_name = app.config.accounts[idx].display_name();
    let account_mutations_ready = app.account_mutations_ready();
    let mut open = true;
    egui::Window::new("Delete Account")
        .open(&mut open)
        .collapsible(false)
        .resizable(false)
        .default_width(340.0)
        .show(ui.ctx(), |ui| {
            theme::glass_frame().show(ui, |ui| {
                ui.heading("Delete account?");
                ui.label(theme::muted(format!(
                    "This removes \"{}\" and attempts to delete its saved password storage.",
                    account_name
                )));
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui
                        .add_sized([104.0, 28.0], theme::secondary_button("Cancel"))
                        .clicked()
                    {
                        app.confirm_delete_account = None;
                    }
                    if ui
                        .add_enabled(
                            account_mutations_ready,
                            theme::danger_button("Delete").min_size(egui::vec2(104.0, 28.0)),
                        )
                        .clicked()
                    {
                        *delete_idx = Some(idx);
                    }
                });
            });
        });

    if !open {
        app.confirm_delete_account = None;
    }
}

fn show_account_editor(ui: &mut egui::Ui, app: &mut AutoLoginApp) {
    let mut editing = app.editing_account.clone();
    let Some(ref account_snapshot) = editing else {
        return;
    };

    let is_existing = app
        .config
        .accounts
        .iter()
        .any(|account| account.id == account_snapshot.id);
    let title = if is_existing {
        "Edit Account"
    } else {
        "Add Account"
    };

    let mut open = true;
    let mut close_editor = false;
    let mut account_to_save: Option<Account> = None;
    let account_mutations_ready = app.account_mutations_ready();
    let password_editor_id = password_editor_id(&account_snapshot.id);
    egui::Window::new(title)
        .open(&mut open)
        .resizable(false)
        .default_width(ACCOUNT_EDITOR_WIDTH)
        .show(ui.ctx(), |ui| {
            ui.set_width(ACCOUNT_EDITOR_WIDTH);
            if let Some(ref mut account) = editing {
                egui::Grid::new("account_editor_grid")
                    .num_columns(2)
                    .spacing([16.0, 10.0])
                    .show(ui, |ui| {
                        ui.label("Email");
                        ui.add_sized(
                            [ACCOUNT_EDITOR_FIELD_WIDTH, 24.0],
                            egui::TextEdit::singleline(&mut account.username)
                                .hint_text("user@domain.com"),
                        );
                        ui.end_row();

                        ui.label("Password");
                        secure_password_editor(
                            ui,
                            &mut app.temp_password,
                            password_editor_id,
                            if is_existing {
                                "Leave blank to keep saved password"
                            } else {
                                "Password"
                            },
                        );
                        ui.end_row();
                    });

                ui.separator();
                ui.horizontal(|ui| {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui
                            .add_sized([104.0, 28.0], theme::secondary_button("Cancel"))
                            .clicked()
                        {
                            close_editor = true;
                        }

                        if ui
                            .add_enabled(
                                account_mutations_ready,
                                theme::primary_button("Save").min_size(egui::vec2(92.0, 28.0)),
                            )
                            .clicked()
                        {
                            account_to_save = Some(account.clone());
                        }
                    });
                });
            }
        });

    if let Some(account) = account_to_save {
        close_editor = save_edited_account(app, &account, is_existing);
    }

    if !open {
        close_editor = true;
    }

    if close_editor {
        editing = None;
    }

    let was_editing = app.editing_account.is_some();
    app.editing_account = editing;
    if was_editing && app.editing_account.is_none() {
        forget_password_editor_state(ui.ctx(), password_editor_id);
        clear_temp_password(app);
    }
}

#[derive(Clone, Copy)]
enum AccountActionIcon {
    Edit,
    Delete,
}

fn account_action_button(
    ui: &mut egui::Ui,
    icon: AccountActionIcon,
    enabled: bool,
) -> egui::Response {
    let (width, bytes_uri, icon_bytes, fill, stroke, icon_color) = match icon {
        AccountActionIcon::Edit => (
            EDIT_BUTTON_WIDTH,
            "bytes://icons/pencil.svg",
            PENCIL_ICON,
            egui::Color32::from_rgb(246, 249, 252),
            egui::Stroke::new(1.0, theme::STROKE),
            theme::TEXT,
        ),
        AccountActionIcon::Delete => (
            DELETE_BUTTON_WIDTH,
            "bytes://icons/trash.svg",
            TRASH_ICON,
            theme::DANGER_SOFT,
            egui::Stroke::new(1.0, egui::Color32::from_rgb(235, 177, 177)),
            theme::DANGER,
        ),
    };
    let icon_color = if enabled {
        icon_color
    } else {
        theme::MUTED.linear_multiply(0.55)
    };
    let button = egui::Button::image(svg_icon(
        bytes_uri,
        icon_bytes,
        ACTION_ICON_SIZE,
        icon_color,
    ))
    .fill(if enabled {
        fill
    } else {
        egui::Color32::from_rgb(241, 245, 249)
    })
    .stroke(stroke)
    .corner_radius(egui::CornerRadius::same(7))
    .min_size(egui::vec2(width, ROW_BUTTON_HEIGHT));

    ui.add_enabled(enabled, button)
}

fn svg_icon(
    uri: &'static str,
    bytes: &'static [u8],
    size: f32,
    tint: egui::Color32,
) -> egui::Image<'static> {
    egui::Image::from_bytes(uri, bytes)
        .fit_to_exact_size(egui::vec2(size, size))
        .tint(tint)
}

fn save_edited_account(app: &mut AutoLoginApp, account: &Account, is_existing: bool) -> bool {
    if !account_mutations_ready_or_stop(app, "The account was left unchanged.") {
        return false;
    }
    if account.username.trim().is_empty() {
        app.set_status("Email is required");
        return false;
    }
    if account.enabled
        && app.config.accounts.iter().any(|existing| {
            existing.id != account.id
                && enabled_account_conflicts_with_candidate(existing, account.username.trim())
        })
    {
        app.set_status("An enabled account with this email already exists");
        return false;
    }

    let existing_account = app
        .config
        .accounts
        .iter()
        .find(|existing| existing.id == account.id);
    let previous_password_saved = existing_account
        .map(|existing| existing.has_saved_password)
        .unwrap_or(false);

    if (!is_existing || (account.enabled && !previous_password_saved))
        && app.temp_password.is_empty()
    {
        app.set_status("Password is required");
        return false;
    }

    let mut account = account.clone();
    account.username = account.username.trim().to_string();
    account.has_saved_password = previous_password_saved;

    // Move the sole password allocation into the save transaction. Avoid a
    // second plaintext String and blank the editor immediately; all failure
    // paths then zeroize the moved buffer when this function returns.
    let mut new_password = if app.temp_password.is_empty() {
        None
    } else {
        Some(std::mem::replace(
            &mut app.temp_password,
            empty_password_buffer(),
        ))
    };
    let username_changed = existing_account
        .is_some_and(|existing| existing.username.trim() != account.username.trim());
    let password_changed = new_password.is_some();
    let only_password_changed = password_changed
        && existing_account.is_some_and(|existing| {
            previous_password_saved
                && existing.enabled == account.enabled
                && existing.username.trim() == account.username
                && existing.has_saved_password
        });
    let previous_account = existing_account.cloned();

    if only_password_changed {
        let Some(previous_account) = previous_account.as_ref() else {
            drop(new_password);
            app.set_status("Failed to find current account for password rollback");
            return false;
        };
        let previous_password = match load_password(
            previous_account,
            app.config.settings.use_keyring,
        ) {
            Ok(password) => password,
            Err(_) => {
                drop(new_password);
                app.set_status(
                    "Failed to read the current password for rollback. The password was left unchanged.",
                );
                return false;
            }
        };
        let mut after_account = account.clone();
        after_account.has_saved_password = true;
        let forward_revision_marker = new_account_config_revision_marker();
        let account_journal_started = match begin_account_config_save_journal_with_revision(
            existing_account,
            &after_account,
            app.config.settings.use_keyring,
            &forward_revision_marker,
        ) {
            Ok(()) => true,
            Err(e) => {
                drop(previous_password);
                drop(new_password);
                app.set_status(storage_prepare_failure_status(
                    &e,
                    "The password was left unchanged.",
                    "Failed to prepare password storage update. The password was left unchanged.",
                ));
                return false;
            }
        };
        let password = new_password
            .take()
            .expect("password-only update requires the editor secret");
        let receipt = match write_account_password_owned_with_revision(
            &account,
            password,
            app.config.settings.use_keyring,
            &forward_revision_marker,
        ) {
            Ok(receipt) => receipt,
            Err(_) => {
                let rollback = restore_and_verify_password(
                    previous_account,
                    previous_password.as_str(),
                    app.config.settings.use_keyring,
                    account_journal_started,
                );
                let rollback_status =
                    drop_rollback_secret_before_followup(previous_password, || {
                        finish_password_rollback(
                            previous_account,
                            account_journal_started,
                            rollback,
                        )
                    });
                match rollback_status {
                    PasswordRollbackStatus::ConfirmedClean => {
                        app.set_status("Failed to save password. The previous password was restored and the account was left unchanged.");
                    }
                    PasswordRollbackStatus::ConfirmedRecoveryPending => {
                        app.set_status("Failed to save password. The previous password was restored, but storage cleanup or durability recovery is still pending; restart before changing stored credentials again.");
                        app.stop_monitor_for_pending_storage_recovery();
                    }
                    PasswordRollbackStatus::Unconfirmed => {
                        app.set_status("Password storage reported a failed update, and the previous password could not be verified after rollback. Recovery remains pending; restart before changing stored credentials again.");
                        app.stop_monitor_for_pending_storage_recovery();
                    }
                }
                return false;
            }
        };
        // Neither rollback secret is needed after a successful replacement.
        // Wipe both before stale-backend cleanup can prompt or block.
        let outcome = finish_successful_password_write_after_secret_drop(
            (previous_password, new_password),
            &account.id,
            Some(receipt),
        )
        .expect("password-only success has a write receipt");
        let cleanup_warning = outcome.stale_cleanup_warning;
        let target_durability_warning = outcome.target_durability_warning;
        let fallback_key_cleanup_warning = outcome.fallback_key_cleanup_warning;
        let journal_cleared = clear_account_journal_after_terminal_result(
            account_journal_started,
            cleanup_warning.is_some() || target_durability_warning || fallback_key_cleanup_warning,
        );
        app.set_status(account_saved_status(
            cleanup_warning.as_ref(),
            fallback_key_cleanup_warning,
            target_durability_warning,
        ));
        if cleanup_warning.is_some()
            || target_durability_warning
            || fallback_key_cleanup_warning
            || !journal_cleared
        {
            app.stop_monitor_for_pending_storage_recovery();
        } else {
            app.sync_saved_config_to_worker(true);
        }
        return true;
    }

    let needs_previous_password =
        is_existing && previous_password_saved && (password_changed || username_changed);
    let previous_password = if needs_previous_password {
        let Some(existing) = previous_account.as_ref() else {
            drop(new_password);
            app.set_status("Failed to find current account for rollback");
            return false;
        };
        match load_password(existing, app.config.settings.use_keyring) {
            Ok(password) => Some(password),
            Err(_) => {
                drop(new_password);
                app.set_status(
                    "Failed to read the current password for rollback. The account was left unchanged.",
                );
                return false;
            }
        }
    } else {
        None
    };
    let password_write_before_config =
        new_password.is_some() || (username_changed && previous_password.is_some());
    let forward_revision_marker =
        password_write_before_config.then(new_account_config_revision_marker);
    let account_journal_started = if password_write_before_config {
        let mut after_account = account.clone();
        after_account.has_saved_password = true;
        match begin_account_config_save_journal_with_revision(
            previous_account.as_ref(),
            &after_account,
            app.config.settings.use_keyring,
            forward_revision_marker
                .as_deref()
                .expect("password write requires a forward revision marker"),
        ) {
            Ok(()) => true,
            Err(e) => {
                drop(previous_password);
                drop(new_password);
                app.set_status(storage_prepare_failure_status(
                    &e,
                    "The account was left unchanged.",
                    "Failed to prepare account storage update. The account was left unchanged.",
                ));
                return false;
            }
        }
    } else {
        false
    };
    let mut password_write_receipt: Option<PasswordWriteReceipt> = None;
    if let Some(password) = new_password.take() {
        match write_account_password_owned_with_revision(
            &account,
            password,
            app.config.settings.use_keyring,
            forward_revision_marker
                .as_deref()
                .expect("password write requires a forward revision marker"),
        ) {
            Ok(receipt) => password_write_receipt = Some(receipt),
            Err(_) => {
                if is_existing {
                    if let (Some(previous_account), Some(previous_password_value)) =
                        (previous_account.as_ref(), previous_password.as_ref())
                    {
                        let rollback = restore_and_verify_password(
                            previous_account,
                            previous_password_value.as_str(),
                            app.config.settings.use_keyring,
                            account_journal_started,
                        );
                        let rollback_status =
                            drop_rollback_secret_before_followup(previous_password, || {
                                finish_password_rollback(
                                    previous_account,
                                    account_journal_started,
                                    rollback,
                                )
                            });
                        match rollback_status {
                            PasswordRollbackStatus::ConfirmedClean => {
                                app.set_status("Failed to save password. The previous stored state was restored and the account was left unchanged.");
                            }
                            PasswordRollbackStatus::ConfirmedRecoveryPending => {
                                app.set_status("Failed to save password. The previous stored state was restored, but storage cleanup or durability recovery is still pending; restart before changing stored credentials again.");
                                app.stop_monitor_for_pending_storage_recovery();
                            }
                            PasswordRollbackStatus::Unconfirmed => {
                                app.set_status("Password storage reported a failed update, and automatic rollback could not be verified. Recovery remains pending; restart before changing stored credentials again.");
                                app.stop_monitor_for_pending_storage_recovery();
                            }
                        }
                        return false;
                    }
                }

                let rollback_confirmed = delete_account(&account.id).is_ok();
                drop(previous_password);
                if rollback_confirmed {
                    let journal_cleared =
                        clear_account_journal_after_confirmed_rollback(account_journal_started);
                    if journal_cleared {
                        app.set_status("Failed to save password. The previous stored state was restored and the account was left unchanged.");
                    } else {
                        app.set_status("Failed to save password. The previous stored state was restored, but recovery journal cleanup is still pending; restart before changing stored credentials again.");
                        app.stop_monitor_for_pending_storage_recovery();
                    }
                } else {
                    app.set_status("Password storage reported a failed update, and automatic rollback could not be verified. Recovery remains pending; restart before changing stored credentials again.");
                    app.stop_monitor_for_pending_storage_recovery();
                }
                return false;
            }
        }
        account.has_saved_password = true;
    } else if username_changed {
        if let Some(previous_password_value) = previous_password.as_ref() {
            match write_account_password_borrowed_with_revision(
                &account,
                previous_password_value.as_str(),
                app.config.settings.use_keyring,
                forward_revision_marker
                    .as_deref()
                    .expect("password rebind requires a forward revision marker"),
            ) {
                Ok(receipt) => password_write_receipt = Some(receipt),
                Err(_) => {
                    drop(new_password);
                    let Some(previous_account) = previous_account.as_ref() else {
                        drop(previous_password);
                        app.set_status("Failed to update the account email, and the previous account could not be found for rollback. Recovery remains pending; restart before changing stored credentials again.");
                        app.stop_monitor_for_pending_storage_recovery();
                        return false;
                    };
                    let rollback = restore_and_verify_password(
                        previous_account,
                        previous_password_value.as_str(),
                        app.config.settings.use_keyring,
                        account_journal_started,
                    );
                    let rollback_status =
                        drop_rollback_secret_before_followup(previous_password, || {
                            finish_password_rollback(
                                previous_account,
                                account_journal_started,
                                rollback,
                            )
                        });
                    match rollback_status {
                        PasswordRollbackStatus::ConfirmedClean => {
                            app.set_status("Failed to update the account email. The previous password binding was restored and the account was left unchanged.");
                        }
                        PasswordRollbackStatus::ConfirmedRecoveryPending => {
                            app.set_status("Failed to update the account email. The previous password binding was restored, but storage cleanup or durability recovery is still pending; restart before changing stored credentials again.");
                            app.stop_monitor_for_pending_storage_recovery();
                        }
                        PasswordRollbackStatus::Unconfirmed => {
                            app.set_status("Failed to update the account email, and the previous password binding could not be verified after rollback. Recovery remains pending; restart before changing stored credentials again.");
                            app.stop_monitor_for_pending_storage_recovery();
                        }
                    }
                    return false;
                }
            }
            account.has_saved_password = true;
        }
    } else if !is_existing {
        account.has_saved_password = false;
    }
    // The editor allocation was either consumed by the write or was empty.
    drop(new_password);

    let mut next_config = app.config.clone();
    if let Some(pos) = next_config.accounts.iter().position(|a| a.id == account.id) {
        next_config.accounts[pos] = account.clone();
    } else {
        next_config.accounts.push(account.clone());
    }

    let config_durability_warning = match save_config(&next_config) {
        Ok(()) => false,
        Err(e) if config_write_committed(&e) => {
            tracing::warn!(error = %e, "Account config replacement committed, but durability confirmation failed");
            true
        }
        Err(_) => {
            if (password_changed || username_changed) && is_existing {
                if let (Some(previous_account), Some(previous_password_value)) =
                    (previous_account.as_ref(), previous_password.as_ref())
                {
                    let rollback = restore_and_verify_password(
                        previous_account,
                        previous_password_value.as_str(),
                        app.config.settings.use_keyring,
                        account_journal_started,
                    );
                    let rollback_status =
                        drop_rollback_secret_before_followup(previous_password, || {
                            finish_password_rollback(
                                previous_account,
                                account_journal_started,
                                rollback,
                            )
                        });
                    match rollback_status {
                        PasswordRollbackStatus::ConfirmedClean => {
                            app.set_status("Failed to save account changes. The previous stored state was restored and the account was left unchanged.");
                        }
                        PasswordRollbackStatus::ConfirmedRecoveryPending => {
                            app.set_status("Failed to save account changes. The previous stored state was restored, but storage cleanup or durability recovery is still pending; restart before changing stored credentials again.");
                            app.stop_monitor_for_pending_storage_recovery();
                        }
                        PasswordRollbackStatus::Unconfirmed => {
                            app.set_status("Failed to save account changes, and automatic password rollback could not be verified. Recovery remains pending; restart before changing stored credentials again.");
                            app.stop_monitor_for_pending_storage_recovery();
                        }
                    }
                    return false;
                }
            }

            let rollback_confirmed = if password_changed || username_changed {
                delete_account(&account.id).is_ok()
            } else {
                true
            };
            drop(previous_password);
            if rollback_confirmed {
                let journal_cleared =
                    clear_account_journal_after_confirmed_rollback(account_journal_started);
                if journal_cleared {
                    app.set_status("Failed to save account changes. The previous stored state was restored and the account was left unchanged.");
                } else {
                    app.set_status("Failed to save account changes. The previous stored state was restored, but recovery journal cleanup is still pending; restart before changing stored credentials again.");
                    app.stop_monitor_for_pending_storage_recovery();
                }
            } else {
                app.set_status("Failed to save account changes, and automatic password rollback could not be verified. Recovery remains pending; restart before changing stored credentials again.");
                app.stop_monitor_for_pending_storage_recovery();
            }
            return false;
        }
    };
    // Config commit makes rollback plaintext unnecessary. Destroy it before
    // stale-backend cleanup, which may block or display a system prompt.
    let (cleanup_warning, target_durability_warning, fallback_key_cleanup_warning) =
        if let Some(outcome) = finish_successful_password_write_after_secret_drop(
            previous_password,
            &account.id,
            password_write_receipt,
        ) {
            (
                outcome.stale_cleanup_warning,
                outcome.target_durability_warning,
                outcome.fallback_key_cleanup_warning,
            )
        } else {
            (None, false, false)
        };

    {
        let journal_cleared = clear_account_journal_after_terminal_result(
            account_journal_started,
            cleanup_warning.is_some()
                || target_durability_warning
                || fallback_key_cleanup_warning
                || config_durability_warning,
        );
        app.config = next_config;
        app.set_status(account_saved_status(
            cleanup_warning.as_ref(),
            fallback_key_cleanup_warning,
            target_durability_warning || config_durability_warning,
        ));
        if cleanup_warning.is_some()
            || target_durability_warning
            || fallback_key_cleanup_warning
            || config_durability_warning
            || !journal_cleared
        {
            app.stop_monitor_for_pending_storage_recovery();
        } else {
            sync_worker_accounts(app, false);
        }
    }

    true
}

fn account_mutations_ready_or_stop(app: &mut AutoLoginApp, unchanged_detail: &str) -> bool {
    if app.account_mutations_ready() {
        true
    } else {
        app.set_status(pending_storage_recovery_user_status(unchanged_detail));
        app.stop_monitor_for_pending_storage_recovery();
        false
    }
}

enum PasswordRollbackWrite<R> {
    Verified(R),
    VerifiedRecoveryPending,
    Unconfirmed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PasswordRollbackStatus {
    ConfirmedClean,
    ConfirmedRecoveryPending,
    Unconfirmed,
}

fn restore_and_verify_password(
    account: &Account,
    previous_password: &str,
    use_keyring: bool,
    account_journal_started: bool,
) -> PasswordRollbackWrite<PasswordWriteReceipt> {
    let rollback_marker = account_journal_started.then(new_account_config_rollback_marker);
    restore_and_verify_password_after_journal_with(
        account,
        previous_password,
        use_keyring,
        rollback_marker,
        mark_account_config_rollback_journal,
        write_account_password_borrowed_for_rollback,
        load_password_for_rollback_verification,
    )
}

fn restore_and_verify_password_after_journal_with<M, S, L, R>(
    account: &Account,
    previous_password: &str,
    use_keyring: bool,
    rollback_marker: Option<String>,
    mut mark_rollback_op: M,
    save_op: S,
    load_op: L,
) -> PasswordRollbackWrite<R>
where
    M: FnMut(&Account, bool, &str) -> anyhow::Result<()>,
    S: FnMut(&Account, &str, bool, Option<&str>) -> anyhow::Result<R>,
    L: FnMut(&Account, bool) -> anyhow::Result<(Zeroizing<String>, Option<String>)>,
{
    let account_journal_started = rollback_marker.is_some();
    // Record rollback intent before the compensating write. If this durable
    // transition fails, leave the original transaction for startup recovery
    // and do not mutate password storage underneath its after-state intent.
    let journal_durability_warning = if account_journal_started {
        let Some(marker) = rollback_marker.as_deref() else {
            tracing::warn!(
                "Password rollback was deferred because no verification marker was available"
            );
            return PasswordRollbackWrite::Unconfirmed;
        };
        match mark_rollback_op(account, use_keyring, marker) {
            Ok(()) => false,
            Err(error) if config_write_committed(&error) => {
                tracing::warn!(
                    error = %error,
                    "Password rollback journal replacement committed, but durability confirmation failed"
                );
                true
            }
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "Password rollback was deferred because its recovery journal could not be advanced to rollback state"
                );
                return PasswordRollbackWrite::Unconfirmed;
            }
        }
    } else {
        false
    };
    let rollback = restore_and_verify_password_with(
        account,
        previous_password,
        use_keyring,
        rollback_marker.as_deref(),
        save_op,
        load_op,
    );
    if journal_durability_warning {
        match rollback {
            PasswordRollbackWrite::Verified(_) => PasswordRollbackWrite::VerifiedRecoveryPending,
            other => other,
        }
    } else {
        rollback
    }
}

fn restore_and_verify_password_with<S, L, R>(
    account: &Account,
    previous_password: &str,
    use_keyring: bool,
    rollback_marker: Option<&str>,
    mut save_op: S,
    mut load_op: L,
) -> PasswordRollbackWrite<R>
where
    S: FnMut(&Account, &str, bool, Option<&str>) -> anyhow::Result<R>,
    L: FnMut(&Account, bool) -> anyhow::Result<(Zeroizing<String>, Option<String>)>,
{
    // A storage API may report an error after committing its write. Always
    // attempt the compensating write, then read the selected backend back and
    // verify the previous value. An ambiguous write remains recovery-pending
    // even when read-back proves that the previous value is active.
    let save_result = save_op(account, previous_password, use_keyring, rollback_marker);
    let verified = load_op(account, use_keyring).is_ok_and(|(loaded, loaded_marker)| {
        loaded.as_bytes() == previous_password.as_bytes()
            && loaded_marker.as_deref() == rollback_marker
    });
    if !verified {
        return PasswordRollbackWrite::Unconfirmed;
    }
    match save_result {
        Ok(receipt) => PasswordRollbackWrite::Verified(receipt),
        Err(_) => PasswordRollbackWrite::VerifiedRecoveryPending,
    }
}

fn drop_rollback_secret_before_followup<S, T>(secret: S, followup: impl FnOnce() -> T) -> T {
    drop(secret);
    followup()
}

fn finish_successful_password_write_after_secret_drop<S>(
    secret: S,
    account_id: &AccountId,
    receipt: Option<PasswordWriteReceipt>,
) -> Option<crate::storage::SaveAccountOutcome> {
    drop_rollback_secret_before_followup(secret, || {
        receipt.map(|receipt| finish_account_password_write(account_id, receipt))
    })
}

fn finish_password_rollback(
    previous_account: &Account,
    account_journal_started: bool,
    rollback: PasswordRollbackWrite<PasswordWriteReceipt>,
) -> PasswordRollbackStatus {
    if matches!(&rollback, PasswordRollbackWrite::Unconfirmed) {
        return PasswordRollbackStatus::Unconfirmed;
    }

    let recovery_pending = match rollback {
        PasswordRollbackWrite::Verified(receipt) => {
            let outcome = finish_account_password_write(&previous_account.id, receipt);
            outcome.stale_cleanup_warning.is_some()
                || outcome.target_durability_warning
                || outcome.fallback_key_cleanup_warning
        }
        PasswordRollbackWrite::VerifiedRecoveryPending => true,
        PasswordRollbackWrite::Unconfirmed => unreachable!("unconfirmed rollback returned above"),
    };

    if recovery_pending {
        return PasswordRollbackStatus::ConfirmedRecoveryPending;
    }

    if clear_account_journal_after_confirmed_rollback(account_journal_started) {
        PasswordRollbackStatus::ConfirmedClean
    } else {
        PasswordRollbackStatus::ConfirmedRecoveryPending
    }
}

fn clear_account_journal_after_confirmed_rollback(started: bool) -> bool {
    if !started {
        return true;
    }
    match clear_pending_storage_operation() {
        Ok(()) => true,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "Confirmed password rollback completed, but recovery journal cleanup failed"
            );
            false
        }
    }
}

fn enabled_account_conflicts_with_candidate(existing: &Account, candidate_email: &str) -> bool {
    existing.enabled
        && existing
            .username
            .trim()
            .eq_ignore_ascii_case(candidate_email.trim())
}

fn account_saved_status(
    cleanup_warning: Option<&StaleBackendCleanupWarning>,
    fallback_key_cleanup_warning: bool,
    config_durability_warning: bool,
) -> String {
    let mut status = cleanup_warning.map_or_else(
        || "Account saved.".to_string(),
        |warning| {
            format!(
                "Account saved. Password was written to {}, but old {} cleanup is still pending and will retry on next launch. Stored credential changes are blocked until recovery completes.",
                warning.saved_backend.label(),
                warning.stale_backend.label()
            )
        },
    );
    if fallback_key_cleanup_warning {
        status.push_str(" Old fallback encryption-key cleanup is still pending and will retry; no password data was rolled back.");
    }
    if config_durability_warning {
        status.push_str(" Disk durability could not be confirmed; the committed state will be checked on next launch.");
    }
    status
}

fn clear_account_journal_after_terminal_result(
    started: bool,
    keep_for_cleanup_retry: bool,
) -> bool {
    clear_account_journal_after_terminal_result_with(
        started,
        keep_for_cleanup_retry,
        clear_pending_storage_operation,
    )
}

fn clear_account_journal_after_terminal_result_with<C>(
    started: bool,
    keep_for_cleanup_retry: bool,
    mut clear_journal_op: C,
) -> bool
where
    C: FnMut() -> anyhow::Result<()>,
{
    if !started {
        return true;
    }
    if keep_for_cleanup_retry {
        tracing::warn!(
            "Keeping pending account storage operation journal so stale password cleanup can retry"
        );
        return false;
    }
    if let Err(e) = clear_journal_op() {
        tracing::warn!(
            error = %e,
            "Failed to clear pending account storage operation journal after terminal result"
        );
        return false;
    }
    true
}

fn sync_worker_accounts(app: &mut AutoLoginApp, refresh_passwords: bool) {
    app.sync_saved_config_to_worker(refresh_passwords);
}

#[cfg(test)]
mod tests {
    use super::enabled_account_conflicts_with_candidate;
    use super::{
        account_saved_status, append_password_input,
        clear_account_journal_after_terminal_result_with, delete_account_transaction,
        drop_rollback_secret_before_followup, empty_password_buffer,
        finish_successful_password_write_after_secret_drop, forget_password_editor_state,
        password_editor_id, pop_password_char, restore_and_verify_password_after_journal_with,
        restore_and_verify_password_with, scrub_password_event_copies,
        suppress_password_clipboard_output, toggle_account_transaction, PasswordRollbackWrite,
    };
    use crate::models::{Account, AppConfig};
    use crate::storage::{
        committed_config_write_test_error, PasswordStorageBackend, StaleBackendCleanupWarning,
    };
    use eframe::egui;
    use std::cell::RefCell;

    #[test]
    fn account_toggle_journals_before_config_and_clears_only_after_durable_save() {
        let config = config_with_account(true);
        let events = RefCell::new(Vec::new());

        let outcome = toggle_account_transaction(
            &config,
            0,
            false,
            |before, after, use_keyring| {
                assert_eq!(Some(before), config.accounts.first());
                assert!(!after.enabled);
                assert!(use_keyring);
                events.borrow_mut().push("journal");
                Ok(())
            },
            |before, after, use_keyring| {
                assert_eq!(Some(before), config.accounts.first());
                assert!(!after.enabled);
                assert!(use_keyring);
                events.borrow_mut().push("commit_journal");
                Ok(())
            },
            |next| {
                assert!(!next.accounts[0].enabled);
                events.borrow_mut().push("save_config");
                Ok(())
            },
            || {
                events.borrow_mut().push("clear_journal");
                Ok(())
            },
        )
        .unwrap();

        assert!(!outcome.config.accounts[0].enabled);
        assert!(!outcome.config_durability_warning);
        assert!(!outcome.journal_cleanup_warning);
        assert_eq!(
            events.into_inner(),
            vec!["journal", "commit_journal", "save_config", "clear_journal"]
        );
    }

    #[test]
    fn account_toggle_keeps_forward_journal_when_config_durability_is_unconfirmed() {
        let config = config_with_account(true);
        let events = RefCell::new(Vec::new());

        let outcome = toggle_account_transaction(
            &config,
            0,
            false,
            |_, _, _| {
                events.borrow_mut().push("journal");
                Ok(())
            },
            |_, _, _| {
                events.borrow_mut().push("commit_journal");
                Ok(())
            },
            |_| {
                events.borrow_mut().push("save_config");
                Err(committed_config_write_test_error())
            },
            || -> anyhow::Result<()> {
                panic!("an unconfirmed config commit must retain its recovery journal")
            },
        )
        .unwrap();

        assert!(!outcome.config.accounts[0].enabled);
        assert!(outcome.config_durability_warning);
        assert!(!outcome.journal_cleanup_warning);
        assert_eq!(
            events.into_inner(),
            vec!["journal", "commit_journal", "save_config"]
        );
    }

    #[test]
    fn account_toggle_does_not_save_when_an_older_recovery_journal_exists() {
        let config = config_with_account(true);
        let error = toggle_account_transaction(
            &config,
            0,
            false,
            |_, _, _| anyhow::bail!("pending storage operation is already in progress"),
            |_, _, _| -> anyhow::Result<()> { panic!("intent must not be committed") },
            |_| -> anyhow::Result<()> { panic!("config must remain unchanged") },
            || -> anyhow::Result<()> { panic!("an older journal must not be cleared") },
        )
        .unwrap_err();

        assert!(error.contains("Failed to prepare"));
        assert!(config.accounts[0].enabled);
    }

    #[test]
    fn account_toggle_cancels_prepared_journal_when_intent_commit_fails() {
        let config = config_with_account(true);
        let events = RefCell::new(Vec::new());
        let error = toggle_account_transaction(
            &config,
            0,
            false,
            |_, _, _| {
                events.borrow_mut().push("journal");
                Ok(())
            },
            |_, _, _| {
                events.borrow_mut().push("commit_journal");
                anyhow::bail!("intent commit failed")
            },
            |_| -> anyhow::Result<()> { panic!("config must remain unchanged") },
            || {
                events.borrow_mut().push("clear_journal");
                Ok(())
            },
        )
        .unwrap_err();

        assert!(error.contains("Failed to commit"));
        assert_eq!(
            events.into_inner(),
            vec!["journal", "commit_journal", "clear_journal"]
        );
    }

    #[test]
    fn account_toggle_retains_ambiguously_committed_intent_without_saving_config() {
        let config = config_with_account(true);
        let events = RefCell::new(Vec::new());
        let error = toggle_account_transaction(
            &config,
            0,
            false,
            |_, _, _| {
                events.borrow_mut().push("journal");
                Ok(())
            },
            |_, _, _| {
                events.borrow_mut().push("commit_journal");
                Err(committed_config_write_test_error())
            },
            |_| -> anyhow::Result<()> { panic!("config must wait for recovered intent") },
            || -> anyhow::Result<()> { panic!("ambiguous intent must remain journaled") },
        )
        .unwrap_err();

        assert!(error.contains("durability could not be confirmed"));
        assert_eq!(events.into_inner(), vec!["journal", "commit_journal"]);
    }

    #[test]
    fn delete_account_transaction_aborts_when_journal_prepare_fails() {
        let config = config_with_account(true);
        let events = RefCell::new(Vec::new());

        let error = delete_account_transaction(
            &config,
            0,
            |account, use_keyring| {
                events.borrow_mut().push("journal");
                assert_eq!(account.id, "account-1");
                assert!(use_keyring);
                anyhow::bail!("journal failed")
            },
            |_, _| panic!("failed preparation must not commit deletion intent"),
            |_| {
                events.borrow_mut().push("delete");
                Ok(())
            },
            |_| {
                events.borrow_mut().push("save_config");
                Ok(())
            },
            || {
                events.borrow_mut().push("clear_journal");
                Ok(())
            },
        )
        .unwrap_err();

        assert!(error.contains("Failed to prepare account removal"));
        assert!(!error.contains("journal failed"));
        assert_eq!(events.into_inner(), vec!["journal"]);
    }

    #[test]
    fn delete_account_transaction_keeps_password_when_config_save_fails() {
        let config = config_with_account(true);
        let events = RefCell::new(Vec::new());

        let error = delete_account_transaction(
            &config,
            0,
            |_, _| {
                events.borrow_mut().push("journal");
                Ok(())
            },
            |_, _| {
                events.borrow_mut().push("commit_journal");
                Ok(())
            },
            |_| {
                events.borrow_mut().push("delete");
                Ok(())
            },
            |_| {
                events.borrow_mut().push("save_config");
                anyhow::bail!("config save failed")
            },
            || {
                events.borrow_mut().push("clear_journal");
                Ok(())
            },
        )
        .unwrap_err();

        assert!(error.contains("Failed to save the account removal"));
        assert!(!error.contains("config save failed"));
        assert_eq!(
            events.into_inner(),
            vec!["journal", "commit_journal", "save_config"]
        );
    }

    #[test]
    fn delete_account_transaction_cancels_prepared_journal_when_intent_commit_fails() {
        let config = config_with_account(true);
        let events = RefCell::new(Vec::new());

        let error = delete_account_transaction(
            &config,
            0,
            |_, _| {
                events.borrow_mut().push("journal");
                Ok(())
            },
            |_, _| {
                events.borrow_mut().push("commit_journal");
                anyhow::bail!("intent commit failed")
            },
            |_| panic!("password must remain unchanged"),
            |_| panic!("config must remain unchanged"),
            || {
                events.borrow_mut().push("clear_journal");
                Ok(())
            },
        )
        .unwrap_err();

        assert!(error.contains("Failed to commit the account removal intent"));
        assert!(!error.contains("intent commit failed"));
        assert_eq!(
            events.into_inner(),
            vec!["journal", "commit_journal", "clear_journal"]
        );
    }

    #[test]
    fn delete_account_transaction_retains_ambiguously_committed_intent() {
        let config = config_with_account(true);
        let events = RefCell::new(Vec::new());

        let error = delete_account_transaction(
            &config,
            0,
            |_, _| {
                events.borrow_mut().push("journal");
                Ok(())
            },
            |_, _| {
                events.borrow_mut().push("commit_journal");
                Err(committed_config_write_test_error())
            },
            |_| panic!("password cleanup must wait for recovered intent"),
            |_| panic!("config write must wait for recovered intent"),
            || panic!("ambiguously committed intent must remain journaled"),
        )
        .unwrap_err();

        assert!(error.contains("disk durability could not be confirmed"));
        assert_eq!(events.into_inner(), vec!["journal", "commit_journal"]);
    }

    #[test]
    fn delete_account_transaction_defers_password_cleanup_after_committed_config_warning() {
        let config = config_with_account(true);
        let events = RefCell::new(Vec::new());

        let outcome = delete_account_transaction(
            &config,
            0,
            |_, _| {
                events.borrow_mut().push("journal");
                Ok(())
            },
            |_, _| {
                events.borrow_mut().push("commit_journal");
                Ok(())
            },
            |_| panic!("password cleanup must wait for confirmed config durability"),
            |_| {
                events.borrow_mut().push("save_config_committed");
                Err(crate::storage::committed_config_write_test_error())
            },
            || {
                events.borrow_mut().push("clear_journal");
                Ok(())
            },
        )
        .unwrap();

        assert!(outcome.config.accounts.is_empty());
        assert!(outcome.config_durability_warning);
        assert!(!outcome.password_cleanup_warning);
        assert!(!outcome.journal_cleanup_warning);
        assert_eq!(
            events.into_inner(),
            vec!["journal", "commit_journal", "save_config_committed"]
        );
    }

    #[test]
    fn delete_account_transaction_saves_config_before_password_cleanup() {
        let config = config_with_account(true);
        let events = RefCell::new(Vec::new());

        let outcome = delete_account_transaction(
            &config,
            0,
            |_, _| {
                events.borrow_mut().push("journal");
                Ok(())
            },
            |_, _| {
                events.borrow_mut().push("commit_journal");
                Ok(())
            },
            |_| {
                events.borrow_mut().push("delete");
                Ok(())
            },
            |next_config| {
                events.borrow_mut().push("save_config");
                assert!(next_config.accounts.is_empty());
                Ok(())
            },
            || {
                events.borrow_mut().push("clear_journal");
                Ok(())
            },
        )
        .unwrap();

        assert!(outcome.config.accounts.is_empty());
        assert!(!outcome.password_cleanup_warning);
        assert!(!outcome.journal_cleanup_warning);
        assert_eq!(
            events.into_inner(),
            vec![
                "journal",
                "commit_journal",
                "save_config",
                "delete",
                "clear_journal"
            ]
        );
    }

    #[test]
    fn delete_account_transaction_retains_journal_after_delete_failure() {
        let config = config_with_account(true);
        let events = RefCell::new(Vec::new());

        let outcome = delete_account_transaction(
            &config,
            0,
            |_, _| {
                events.borrow_mut().push("journal");
                Ok(())
            },
            |_, _| {
                events.borrow_mut().push("commit_journal");
                Ok(())
            },
            |_| {
                events.borrow_mut().push("delete");
                anyhow::bail!("delete failed")
            },
            |next_config| {
                events.borrow_mut().push("save_config");
                assert!(next_config.accounts.is_empty());
                Ok(())
            },
            || panic!("journal must remain pending for delete cleanup retry"),
        )
        .unwrap();

        assert!(outcome.config.accounts.is_empty());
        assert!(outcome.password_cleanup_warning);
        assert!(!outcome.journal_cleanup_warning);
        assert_eq!(
            events.into_inner(),
            vec!["journal", "commit_journal", "save_config", "delete"]
        );
    }

    #[test]
    fn delete_account_transaction_surfaces_journal_clear_warning_after_commit() {
        let config = config_with_account(true);
        let events = RefCell::new(Vec::new());

        let outcome = delete_account_transaction(
            &config,
            0,
            |_, _| {
                events.borrow_mut().push("journal");
                Ok(())
            },
            |_, _| {
                events.borrow_mut().push("commit_journal");
                Ok(())
            },
            |_| {
                events.borrow_mut().push("delete");
                Ok(())
            },
            |next_config| {
                events.borrow_mut().push("save_config");
                assert!(next_config.accounts.is_empty());
                Ok(())
            },
            || {
                events.borrow_mut().push("clear_journal");
                anyhow::bail!("clear failed")
            },
        )
        .unwrap();

        assert!(outcome.config.accounts.is_empty());
        assert!(!outcome.password_cleanup_warning);
        assert!(outcome.journal_cleanup_warning);
        assert_eq!(
            events.into_inner(),
            vec![
                "journal",
                "commit_journal",
                "save_config",
                "delete",
                "clear_journal"
            ]
        );
    }

    #[test]
    fn account_saved_status_surfaces_stale_cleanup_warning() {
        let warning = StaleBackendCleanupWarning {
            saved_backend: PasswordStorageBackend::SystemSecureStorage,
            stale_backend: PasswordStorageBackend::EncryptedFallbackFile,
            error_kind: "storage_error",
        };

        let status = account_saved_status(Some(&warning), false, false);

        assert!(status.contains("Account saved"));
        assert!(status.contains("system secure storage"));
        assert!(status.contains("old encrypted fallback file cleanup is still pending"));
        assert!(status.contains("will retry on next launch"));
        assert!(status.contains("Stored credential changes are blocked"));
        assert!(!status.contains("storage_error"));
    }

    #[test]
    fn account_saved_status_surfaces_key_cleanup_and_durability_without_secrets() {
        let status = account_saved_status(None, true, true);

        assert!(status.contains("Account saved"));
        assert!(status.contains("fallback encryption-key cleanup is still pending"));
        assert!(status.contains("Disk durability could not be confirmed"));
        assert!(!status.contains("account-1"));
    }

    #[test]
    fn account_save_stale_cleanup_warning_retains_journal_for_retry() {
        let cleared = RefCell::new(false);

        assert!(!clear_account_journal_after_terminal_result_with(
            true,
            true,
            || {
                *cleared.borrow_mut() = true;
                Ok(())
            },
        ));

        assert!(!*cleared.borrow());

        assert!(clear_account_journal_after_terminal_result_with(
            true,
            false,
            || {
                *cleared.borrow_mut() = true;
                Ok(())
            },
        ));

        assert!(*cleared.borrow());
    }

    #[test]
    fn successful_password_writes_drop_rollback_secrets_before_stale_cleanup() {
        let implementation = include_str!("accounts.rs");
        let save = implementation
            .split_once("fn save_edited_account(")
            .expect("save_edited_account must exist")
            .1
            .split_once("fn restore_and_verify_password(")
            .expect("save_edited_account boundary must exist")
            .0;

        assert_eq!(
            save.matches("finish_successful_password_write_after_secret_drop(")
                .count(),
            2,
            "both successful save paths must use the secret-drop boundary"
        );
    }

    #[test]
    fn account_password_transactions_bind_journal_and_payload_to_forward_revision() {
        let implementation = include_str!("accounts.rs");
        let save = implementation
            .split_once("fn save_edited_account(")
            .expect("save_edited_account must exist")
            .1
            .split_once("fn account_mutations_ready_or_stop(")
            .expect("save_edited_account boundary must exist")
            .0;

        assert_eq!(
            save.matches("begin_account_config_save_journal_with_revision(")
                .count(),
            2,
            "both password transaction paths need an authenticated forward journal marker"
        );
        assert_eq!(
            save.matches("write_account_password_owned_with_revision(")
                .count(),
            2,
            "new password writes must carry the same forward revision marker"
        );
        assert_eq!(
            save.matches("write_account_password_borrowed_with_revision(")
                .count(),
            1,
            "username rebinding must carry the forward revision marker"
        );
        assert!(!save.contains("write_account_password_owned("));
        assert!(!save.contains("write_account_password_borrowed("));
    }

    #[test]
    fn rollback_secret_drop_helper_runs_before_followup_work() {
        struct DropProbe<'a>(&'a RefCell<Vec<&'static str>>);
        impl Drop for DropProbe<'_> {
            fn drop(&mut self) {
                self.0.borrow_mut().push("drop-secret");
            }
        }

        let events = RefCell::new(Vec::new());
        drop_rollback_secret_before_followup(DropProbe(&events), || {
            events.borrow_mut().push("followup-io");
        });
        assert_eq!(events.into_inner(), vec!["drop-secret", "followup-io"]);
    }

    #[test]
    fn successful_write_helper_drops_secret_even_without_a_receipt() {
        struct DropProbe<'a>(&'a RefCell<Vec<&'static str>>);
        impl Drop for DropProbe<'_> {
            fn drop(&mut self) {
                self.0.borrow_mut().push("drop-secret");
            }
        }

        let events = RefCell::new(Vec::new());
        let outcome = finish_successful_password_write_after_secret_drop(
            DropProbe(&events),
            &"account-1".to_string(),
            None,
        );
        events.borrow_mut().push("after-helper");
        assert!(outcome.is_none());
        assert_eq!(events.into_inner(), vec!["drop-secret", "after-helper"]);
    }

    #[test]
    fn failed_password_write_is_rolled_back_and_read_back_before_confirmation() {
        let account = Account::new("user@example.com");
        let events = RefCell::new(Vec::new());

        let result = restore_and_verify_password_with(
            &account,
            "previous-secret",
            true,
            Some("11111111-1111-4111-8111-111111111111"),
            |saved_account, password, use_keyring, rollback_marker| {
                assert_eq!(saved_account.id, account.id);
                assert_eq!(password, "previous-secret");
                assert!(use_keyring);
                assert_eq!(
                    rollback_marker,
                    Some("11111111-1111-4111-8111-111111111111")
                );
                events.borrow_mut().push("restore");
                Err::<(), _>(anyhow::anyhow!("ambiguous backend result"))
            },
            |loaded_account, use_keyring| {
                assert_eq!(loaded_account.id, account.id);
                assert!(use_keyring);
                events.borrow_mut().push("verify");
                Ok((
                    zeroize::Zeroizing::new("previous-secret".to_string()),
                    Some("11111111-1111-4111-8111-111111111111".to_string()),
                ))
            },
        );

        assert!(matches!(
            result,
            PasswordRollbackWrite::VerifiedRecoveryPending
        ));
        assert_eq!(events.into_inner(), vec!["restore", "verify"]);
    }

    #[test]
    fn password_rollback_intent_is_durable_before_compensating_write() {
        let account = Account::new("user@example.com");
        let events = RefCell::new(Vec::new());

        let result = restore_and_verify_password_after_journal_with(
            &account,
            "previous-secret",
            true,
            Some("11111111-1111-4111-8111-111111111111".to_string()),
            |_, _, marker| {
                assert_eq!(marker, "11111111-1111-4111-8111-111111111111");
                events.borrow_mut().push("mark-rollback");
                Ok(())
            },
            |_, _, _, marker| {
                assert_eq!(marker, Some("11111111-1111-4111-8111-111111111111"));
                events.borrow_mut().push("restore-password");
                Ok(())
            },
            |_, _| {
                events.borrow_mut().push("verify-password");
                Ok((
                    zeroize::Zeroizing::new("previous-secret".to_string()),
                    Some("11111111-1111-4111-8111-111111111111".to_string()),
                ))
            },
        );

        assert!(matches!(result, PasswordRollbackWrite::Verified(())));
        assert_eq!(
            events.into_inner(),
            vec!["mark-rollback", "restore-password", "verify-password"]
        );
    }

    #[test]
    fn password_rollback_does_not_write_when_intent_transition_fails() {
        let account = Account::new("user@example.com");

        let result = restore_and_verify_password_after_journal_with(
            &account,
            "previous-secret",
            false,
            Some("11111111-1111-4111-8111-111111111111".to_string()),
            |_, _, _| anyhow::bail!("journal replacement failed"),
            |_, _, _, _| -> anyhow::Result<()> {
                panic!("password rollback must wait for durable intent")
            },
            |_, _| -> anyhow::Result<(zeroize::Zeroizing<String>, Option<String>)> {
                panic!("password verification must wait for durable intent")
            },
        );

        assert!(matches!(result, PasswordRollbackWrite::Unconfirmed));
    }

    #[test]
    fn committed_rollback_intent_warning_keeps_recovery_pending() {
        let account = Account::new("user@example.com");

        let result = restore_and_verify_password_after_journal_with(
            &account,
            "previous-secret",
            true,
            Some("11111111-1111-4111-8111-111111111111".to_string()),
            |_, _, _| Err(committed_config_write_test_error()),
            |_, _, _, _| Ok(()),
            |_, _| {
                Ok((
                    zeroize::Zeroizing::new("previous-secret".to_string()),
                    Some("11111111-1111-4111-8111-111111111111".to_string()),
                ))
            },
        );

        assert!(matches!(
            result,
            PasswordRollbackWrite::VerifiedRecoveryPending
        ));
    }

    #[test]
    fn password_rollback_is_not_confirmed_when_read_back_differs() {
        let account = Account::new("user@example.com");

        assert!(matches!(
            restore_and_verify_password_with(
                &account,
                "previous-secret",
                false,
                None,
                |_, _, _, _| Ok(()),
                |_, _| {
                    Ok((
                        zeroize::Zeroizing::new("unexpected-secret".to_string()),
                        None,
                    ))
                },
            ),
            PasswordRollbackWrite::Unconfirmed
        ));
    }

    #[test]
    fn password_rollback_is_not_confirmed_without_matching_marker() {
        let account = Account::new("user@example.com");

        assert!(matches!(
            restore_and_verify_password_with(
                &account,
                "previous-secret",
                false,
                Some("11111111-1111-4111-8111-111111111111"),
                |_, _, _, _| Ok(()),
                |_, _| {
                    Ok((
                        zeroize::Zeroizing::new("previous-secret".to_string()),
                        Some("22222222-2222-4222-8222-222222222222".to_string()),
                    ))
                },
            ),
            PasswordRollbackWrite::Unconfirmed
        ));
    }

    #[test]
    fn enabled_account_conflict_policy_matches_email_only() {
        let mut existing = Account::new(" User@Example.com ");
        existing.enabled = true;

        assert!(enabled_account_conflicts_with_candidate(
            &existing,
            "user@example.com"
        ));
        assert!(!enabled_account_conflicts_with_candidate(
            &existing,
            "other@example.com"
        ));

        existing.enabled = false;
        assert!(!enabled_account_conflicts_with_candidate(
            &existing,
            "user@example.com"
        ));
    }

    #[test]
    fn password_editor_copy_text_is_suppressed_only_when_focused() {
        for (focused, expected_copy_text) in
            [(true, None), (false, Some("diagnostic text".to_string()))]
        {
            let ctx = egui::Context::default();
            ctx.copy_text("diagnostic text".to_string());

            suppress_password_clipboard_output(&ctx, focused);

            assert_eq!(
                ctx.output(|output| {
                    output.commands.iter().find_map(|command| match command {
                        egui::OutputCommand::CopyText(text) => Some(text.clone()),
                        _ => None,
                    })
                }),
                expected_copy_text
            );
        }
    }

    #[test]
    fn password_editor_scrubs_cloned_raw_secret_events_but_retains_normal_input() {
        let normal_key = egui::Event::Key {
            key: egui::Key::Tab,
            physical_key: Some(egui::Key::Tab),
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        };
        let mut events = vec![
            egui::Event::Text("typed-secret".to_string()),
            egui::Event::Paste("pasted-secret".to_string()),
            egui::Event::Ime(egui::ImeEvent::Preedit("composed-secret".to_string())),
            egui::Event::Ime(egui::ImeEvent::Commit("committed-secret".to_string())),
            egui::Event::Copy,
            egui::Event::Cut,
            egui::Event::Ime(egui::ImeEvent::Enabled),
            normal_key.clone(),
        ];

        scrub_password_event_copies(&mut events);

        assert_eq!(
            events,
            vec![egui::Event::Ime(egui::ImeEvent::Enabled), normal_key]
        );
    }

    #[test]
    fn password_editor_uses_fixed_allocation_and_wipes_deleted_utf8_bytes() {
        let mut password = empty_password_buffer();
        let original_ptr = password.as_ptr();
        append_password_input(&mut password, "secret💣");
        assert_eq!(password.as_ptr(), original_ptr);
        let old_len = password.len();

        pop_password_char(&mut password);

        assert_eq!(password.as_str(), "secret");
        let removed_len = old_len - password.len();
        let removed = unsafe {
            std::slice::from_raw_parts(password.as_ptr().add(password.len()), removed_len)
        };
        assert!(removed.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn closing_password_editor_removes_state_and_focus() {
        let ctx = egui::Context::default();
        let id = password_editor_id("account-1");
        egui::text_edit::TextEditState::default().store(&ctx, id);
        ctx.memory_mut(|memory| memory.request_focus(id));

        forget_password_editor_state(&ctx, id);

        assert!(egui::text_edit::TextEditState::load(&ctx, id).is_none());
        assert!(!ctx.memory(|memory| memory.has_focus(id)));
    }

    #[test]
    fn password_editor_lifecycle_wires_stable_state_cleanup() {
        assert_eq!(
            password_editor_id("account-1"),
            password_editor_id("account-1")
        );
        assert_ne!(
            password_editor_id("account-1"),
            password_editor_id("account-2")
        );

        let implementation = include_str!("accounts.rs");
        let editor_start = implementation
            .find("fn show_account_editor(")
            .expect("account editor start");
        let editor_end = implementation[editor_start..]
            .find("enum AccountActionIcon")
            .map(|offset| editor_start + offset)
            .expect("account editor end");
        let editor = &implementation[editor_start..editor_end];

        assert!(editor.contains("secure_password_editor("));
        assert!(!editor.contains("egui::TextEdit::singleline(&mut *app.temp_password)"));
        assert!(editor.contains("forget_password_editor_state(ui.ctx(), password_editor_id);"));
        assert!(editor.contains("clear_temp_password(app);"));
    }

    fn config_with_account(has_saved_password: bool) -> AppConfig {
        let mut account = Account::new("user@example.com");
        account.id = "account-1".to_string();
        account.has_saved_password = has_saved_password;
        AppConfig {
            accounts: vec![account],
            ..AppConfig::default()
        }
    }
}
