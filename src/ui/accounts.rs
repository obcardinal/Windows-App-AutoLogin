use crate::app::AutoLoginApp;
use crate::models::{Account, AccountId, AppConfig};
use crate::storage::{
    begin_account_config_save_journal, begin_account_delete_journal,
    cleanup_unused_fallback_key_material, clear_pending_storage_operation, delete_account,
    is_pending_storage_operation_in_progress, load_password, pending_storage_recovery_user_status,
    save_account, save_account_with_outcome, save_config, StaleBackendCleanupWarning,
};
use crate::ui::theme;
use eframe::egui;
use zeroize::Zeroizing;

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
const ACCOUNT_EDITOR_TOGGLE_WIDTH: f32 = 38.0;
const ACTION_ICON_SIZE: f32 = 17.0;
const PASSWORD_ICON_SIZE: f32 = 18.0;
const EYE_ICON: &[u8] = include_bytes!("../../assets/icons/eye.svg");
const EYE_OFF_ICON: &[u8] = include_bytes!("../../assets/icons/eye-off.svg");
const PENCIL_ICON: &[u8] = include_bytes!("../../assets/icons/pencil.svg");
const TRASH_ICON: &[u8] = include_bytes!("../../assets/icons/trash.svg");

pub fn show(ui: &mut egui::Ui, app: &mut AutoLoginApp) {
    let mut toggle_enabled_idx = None;
    let mut delete_idx: Option<usize> = None;
    let mut edit_account: Option<Account> = None;
    let mut confirm_delete_account: Option<String> = None;
    let modal_open = app.editing_account.is_some() || app.confirm_delete_account.is_some();

    let account_count = app.config.accounts.len();
    theme::page_header(
        ui,
        "Accounts",
        &format!("{account_count} saved account(s) monitored through Windows App."),
        |ui| {
            if ui
                .add_enabled(
                    !modal_open,
                    theme::primary_button("+ Add Account").min_size(egui::vec2(182.0, 30.0)),
                )
                .clicked()
            {
                open_account_editor(app, Account::new(""));
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
                        !modal_open,
                        theme::primary_button("+ Add Account").min_size(egui::vec2(182.0, 30.0)),
                    )
                    .clicked()
                {
                    open_account_editor(app, Account::new(""));
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
                            !modal_open,
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

    if let Some(account) = edit_account {
        open_account_editor(app, account);
    }

    if let Some(account_id) = confirm_delete_account {
        app.confirm_delete_account = Some(account_id);
    }

    if let Some(idx) = toggle_enabled_idx {
        let mut next_config = app.config.clone();
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
                next_config.accounts[idx].enabled = enabling;
                if let Err(e) = save_config(&next_config) {
                    let _ = e;
                    app.set_status("Failed to update account. The account was left unchanged.");
                } else {
                    app.config = next_config;
                    app.set_status("Account updated");
                    sync_worker_accounts(app, false);
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
            delete_account,
            save_config,
            clear_pending_storage_operation,
        ) {
            Ok(outcome) => {
                let cleanup_warning =
                    if outcome.password_cleanup_warning || outcome.journal_cleanup_warning {
                        false
                    } else {
                        cleanup_unused_fallback_key_material().is_err()
                    };
                app.config = outcome.config;
                if outcome.password_cleanup_warning {
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
                sync_worker_accounts(app, false);
            }
            Err(status) => app.set_status(status),
        }
        app.confirm_delete_account = None;
    }

    show_account_editor(ui, app);
}

fn delete_account_transaction<J, D, C, R>(
    config: &AppConfig,
    idx: usize,
    mut begin_delete_journal_op: J,
    mut delete_account_op: D,
    mut save_config_op: C,
    mut clear_journal_op: R,
) -> Result<DeleteAccountOutcome, String>
where
    J: FnMut(&Account, bool) -> anyhow::Result<()>,
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

    let mut next_config = config.clone();
    next_config.accounts.remove(idx);
    if let Err(e) = save_config_op(&next_config) {
        let _ = e;
        let _ = clear_journal_op();
        return Err("Failed to save the account removal. The account was not deleted and saved password storage was left unchanged.".to_string());
    }

    let password_cleanup_warning = delete_account_op(&account.id).is_err();
    let journal_cleanup_warning = if password_cleanup_warning {
        false
    } else {
        clear_journal_op().is_err()
    };
    Ok(DeleteAccountOutcome {
        config: next_config,
        password_cleanup_warning,
        journal_cleanup_warning,
    })
}

#[derive(Debug)]
struct DeleteAccountOutcome {
    config: AppConfig,
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

fn open_account_editor(app: &mut AutoLoginApp, account: Account) {
    tracing::info!("Opening account editor");
    app.editing_account = Some(account);
    clear_temp_password(app);
    app.show_password = false;
}

fn clear_temp_password(app: &mut AutoLoginApp) {
    app.temp_password = Zeroizing::new(String::new());
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
                        .add_sized([104.0, 28.0], theme::danger_button("Delete"))
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
                        ui.horizontal(|ui| {
                            let password_edit = egui::TextEdit::singleline(&mut *app.temp_password)
                                .hint_text(if is_existing {
                                    "Leave blank to keep saved password"
                                } else {
                                    "Password"
                                })
                                .password(!app.show_password);
                            let password_response =
                                ui.add_sized([ACCOUNT_EDITOR_PASSWORD_WIDTH, 24.0], password_edit);
                            suppress_password_clipboard_output(
                                ui.ctx(),
                                password_response.has_focus(),
                            );
                            let tooltip = if app.show_password {
                                "Hide password"
                            } else {
                                "Show password"
                            };
                            if password_visibility_button(ui, app.show_password)
                                .on_hover_text(tooltip)
                                .clicked()
                            {
                                app.show_password = !app.show_password;
                            }
                        });
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
                            .add_sized([92.0, 28.0], theme::primary_button("Save"))
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

fn password_visibility_button(ui: &mut egui::Ui, password_visible: bool) -> egui::Response {
    let (uri, bytes) = if password_visible {
        ("bytes://icons/eye-off.svg", EYE_OFF_ICON)
    } else {
        ("bytes://icons/eye.svg", EYE_ICON)
    };
    let button = egui::Button::image(svg_icon(uri, bytes, PASSWORD_ICON_SIZE, theme::TEXT))
        .fill(egui::Color32::from_rgb(246, 249, 252))
        .stroke(egui::Stroke::new(1.0, theme::STROKE))
        .corner_radius(egui::CornerRadius::same(7))
        .min_size(egui::vec2(ACCOUNT_EDITOR_TOGGLE_WIDTH, 28.0));

    ui.add(button)
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

    let new_password =
        (!app.temp_password.is_empty()).then(|| Zeroizing::new(app.temp_password.to_string()));
    let username_changed = existing_account
        .is_some_and(|existing| existing.username.trim() != account.username.trim());
    let only_password_changed = new_password.is_some()
        && existing_account.is_some_and(|existing| {
            previous_password_saved
                && existing.enabled == account.enabled
                && existing.username.trim() == account.username
                && existing.has_saved_password
        });

    if only_password_changed {
        let mut after_account = account.clone();
        after_account.has_saved_password = true;
        let account_journal_started = match begin_account_config_save_journal(
            existing_account,
            &after_account,
            app.config.settings.use_keyring,
        ) {
            Ok(()) => true,
            Err(e) => {
                app.set_status(storage_prepare_failure_status(
                    &e,
                    "The password was left unchanged.",
                    "Failed to prepare password storage update. The password was left unchanged.",
                ));
                return false;
            }
        };
        let mut cleanup_warning = None;
        if let Some(password) = new_password.as_ref() {
            match save_account_with_outcome(
                &account,
                password.as_str(),
                app.config.settings.use_keyring,
            ) {
                Ok(outcome) => {
                    cleanup_warning = outcome.stale_cleanup_warning;
                }
                Err(e) => {
                    let _ = e;
                    clear_account_journal_after_terminal_result(account_journal_started, false);
                    app.set_status("Failed to save password. The account was left unchanged.");
                    return false;
                }
            }
        }
        clear_account_journal_after_terminal_result(
            account_journal_started,
            cleanup_warning.is_some(),
        );
        app.set_status(account_saved_status(cleanup_warning.as_ref()));
        app.sync_saved_config_to_worker(true);
        return true;
    }

    let previous_account = existing_account.cloned();
    let needs_previous_password =
        is_existing && previous_password_saved && (new_password.is_some() || username_changed);
    let previous_password = if needs_previous_password {
        let Some(existing) = previous_account.as_ref() else {
            app.set_status("Failed to find current account for rollback");
            return false;
        };
        match load_password(existing, app.config.settings.use_keyring) {
            Ok(password) => Some(password),
            Err(e) => {
                let _ = e;
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
    let account_journal_started = if password_write_before_config {
        let mut after_account = account.clone();
        after_account.has_saved_password = true;
        match begin_account_config_save_journal(
            previous_account.as_ref(),
            &after_account,
            app.config.settings.use_keyring,
        ) {
            Ok(()) => true,
            Err(e) => {
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
    let mut cleanup_warning = None;
    if let Some(password) = new_password.as_ref() {
        match save_account_with_outcome(
            &account,
            password.as_str(),
            app.config.settings.use_keyring,
        ) {
            Ok(outcome) => {
                cleanup_warning = outcome.stale_cleanup_warning;
            }
            Err(e) => {
                let _ = e;
                let mut rollback_errors = Vec::new();
                if is_existing {
                    if let (Some(previous_account), Some(previous_password)) =
                        (previous_account.as_ref(), previous_password.as_ref())
                    {
                        if let Err(rollback_error) = save_account(
                            previous_account,
                            previous_password.as_str(),
                            app.config.settings.use_keyring,
                        ) {
                            let _ = rollback_error;
                            rollback_errors.push(());
                        }
                    } else if let Err(rollback_error) = delete_account(&account.id) {
                        let _ = rollback_error;
                        rollback_errors.push(());
                    }
                } else if let Err(rollback_error) = delete_account(&account.id) {
                    let _ = rollback_error;
                    rollback_errors.push(());
                }

                if rollback_errors.is_empty() {
                    clear_account_journal_after_terminal_result(account_journal_started, false);
                    app.set_status("Failed to save password. The account was left unchanged.");
                } else {
                    app.set_status("Failed to save password, and automatic password rollback could not be confirmed. Please check storage before trying again.");
                }
                return false;
            }
        }
        account.has_saved_password = true;
    } else if username_changed {
        if let Some(previous_password) = previous_password.as_ref() {
            match save_account_with_outcome(
                &account,
                previous_password.as_str(),
                app.config.settings.use_keyring,
            ) {
                Ok(outcome) => {
                    cleanup_warning = outcome.stale_cleanup_warning;
                }
                Err(e) => {
                    let _ = e;
                    clear_account_journal_after_terminal_result(account_journal_started, false);
                    app.set_status(
                        "Failed to rebind the saved password to the updated email. The account was left unchanged.",
                    );
                    return false;
                }
            }
            account.has_saved_password = true;
        }
    } else if !is_existing {
        account.has_saved_password = false;
    }

    let mut next_config = app.config.clone();
    if let Some(pos) = next_config.accounts.iter().position(|a| a.id == account.id) {
        next_config.accounts[pos] = account.clone();
    } else {
        next_config.accounts.push(account.clone());
    }

    if let Err(e) = save_config(&next_config) {
        let _ = e;
        let mut rollback_errors = Vec::new();
        if new_password.is_some() || username_changed {
            if is_existing {
                if let (Some(previous_account), Some(previous_password)) =
                    (previous_account.as_ref(), previous_password.as_deref())
                {
                    let previous_password = previous_password.as_str();
                    if let Err(rollback_error) = save_account(
                        previous_account,
                        previous_password,
                        app.config.settings.use_keyring,
                    ) {
                        let _ = rollback_error;
                        rollback_errors.push(());
                    }
                } else if let Err(rollback_error) = delete_account(&account.id) {
                    let _ = rollback_error;
                    rollback_errors.push(());
                }
            } else if let Err(rollback_error) = delete_account(&account.id) {
                let _ = rollback_error;
                rollback_errors.push(());
            }
        }
        if rollback_errors.is_empty() {
            clear_account_journal_after_terminal_result(account_journal_started, false);
            app.set_status("Failed to save account changes. The account was left unchanged.");
        } else {
            app.set_status("Failed to save account changes, and automatic password rollback could not be confirmed. Please check storage before trying again.");
        }
        return false;
    } else {
        clear_account_journal_after_terminal_result(
            account_journal_started,
            cleanup_warning.is_some(),
        );
        app.config = next_config;
        app.set_status(account_saved_status(cleanup_warning.as_ref()));
    }

    sync_worker_accounts(app, false);

    true
}

fn enabled_account_conflicts_with_candidate(existing: &Account, candidate_email: &str) -> bool {
    existing.enabled
        && existing
            .username
            .trim()
            .eq_ignore_ascii_case(candidate_email.trim())
}

fn account_saved_status(cleanup_warning: Option<&StaleBackendCleanupWarning>) -> String {
    cleanup_warning.map_or_else(
        || "Account saved".to_string(),
        |warning| {
            format!(
                "Account saved. Password was written to {}, but old {} cleanup is still pending and will retry on next launch. Stored credential changes are blocked until recovery completes.",
                warning.saved_backend.label(),
                warning.stale_backend.label()
            )
        },
    )
}

fn clear_account_journal_after_terminal_result(started: bool, keep_for_cleanup_retry: bool) {
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
) where
    C: FnMut() -> anyhow::Result<()>,
{
    if !started {
        return;
    }
    if keep_for_cleanup_retry {
        tracing::warn!(
            "Keeping pending account storage operation journal so stale password cleanup can retry"
        );
        return;
    }
    if let Err(e) = clear_journal_op() {
        tracing::warn!(
            error = %e,
            "Failed to clear pending account storage operation journal after terminal result"
        );
    }
}

fn sync_worker_accounts(app: &mut AutoLoginApp, refresh_passwords: bool) {
    app.sync_saved_config_to_worker(refresh_passwords);
}

#[cfg(test)]
mod tests {
    use super::enabled_account_conflicts_with_candidate;
    use super::{
        account_saved_status, clear_account_journal_after_terminal_result_with,
        delete_account_transaction, suppress_password_clipboard_output,
    };
    use crate::models::{Account, AppConfig};
    use crate::storage::{PasswordStorageBackend, StaleBackendCleanupWarning};
    use eframe::egui;
    use std::cell::RefCell;

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
            vec!["journal", "save_config", "clear_journal"]
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
            vec!["journal", "save_config", "delete", "clear_journal"]
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
            vec!["journal", "save_config", "delete"]
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
            vec!["journal", "save_config", "delete", "clear_journal"]
        );
    }

    #[test]
    fn account_saved_status_surfaces_stale_cleanup_warning() {
        let warning = StaleBackendCleanupWarning {
            saved_backend: PasswordStorageBackend::SystemSecureStorage,
            stale_backend: PasswordStorageBackend::EncryptedFallbackFile,
            error_kind: "storage_error",
        };

        let status = account_saved_status(Some(&warning));

        assert!(status.contains("Account saved"));
        assert!(status.contains("system secure storage"));
        assert!(status.contains("old encrypted fallback file cleanup is still pending"));
        assert!(status.contains("will retry on next launch"));
        assert!(status.contains("Stored credential changes are blocked"));
        assert!(!status.contains("storage_error"));
    }

    #[test]
    fn account_save_stale_cleanup_warning_retains_journal_for_retry() {
        let warning = StaleBackendCleanupWarning {
            saved_backend: PasswordStorageBackend::SystemSecureStorage,
            stale_backend: PasswordStorageBackend::EncryptedFallbackFile,
            error_kind: "storage_error",
        };
        let cleared = RefCell::new(false);

        clear_account_journal_after_terminal_result_with(true, true, || {
            *cleared.borrow_mut() = true;
            Ok(())
        });

        assert!(!*cleared.borrow());

        clear_account_journal_after_terminal_result_with(true, false, || {
            *cleared.borrow_mut() = true;
            Ok(())
        });

        assert!(*cleared.borrow());
        assert_eq!(
            account_saved_status(Some(&warning)),
            "Account saved. Password was written to system secure storage, but old encrypted fallback file cleanup is still pending and will retry on next launch. Stored credential changes are blocked until recovery completes."
        );
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
    fn focused_password_editor_suppresses_copy_text_output() {
        let ctx = egui::Context::default();
        ctx.copy_text("secret".to_string());

        suppress_password_clipboard_output(&ctx, true);

        assert!(ctx.output(|output| output
            .commands
            .iter()
            .all(|command| !matches!(command, egui::OutputCommand::CopyText(_)))));
    }

    #[test]
    fn unfocused_password_editor_leaves_copy_text_output_alone() {
        let ctx = egui::Context::default();
        ctx.copy_text("diagnostic text".to_string());

        suppress_password_clipboard_output(&ctx, false);

        assert!(ctx.output(|output| output.commands.iter().any(
            |command| matches!(command, egui::OutputCommand::CopyText(text) if text == "diagnostic text")
        )));
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
