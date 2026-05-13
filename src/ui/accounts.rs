use crate::app::AutoLoginApp;
use crate::models::Account;
use crate::storage::{delete_account, load_password, save_account, save_config};
use crate::ui::theme;
use eframe::egui;
use zeroize::Zeroizing;

const STATE_COLUMN_WIDTH: f32 = 116.0;
const TABLE_SPACING: f32 = 8.0;
const EDIT_BUTTON_WIDTH: f32 = 82.0;
const DELETE_BUTTON_WIDTH: f32 = 96.0;
const ROW_BUTTON_HEIGHT: f32 = 30.0;
const ACTIONS_COLUMN_WIDTH: f32 = EDIT_BUTTON_WIDTH + TABLE_SPACING + DELETE_BUTTON_WIDTH;
const ACCOUNT_ROW_HEIGHT: f32 = 34.0;
const ACCOUNT_EDITOR_WIDTH: f32 = 388.0;
const ACCOUNT_EDITOR_FIELD_WIDTH: f32 = 300.0;
const ACCOUNT_EDITOR_PASSWORD_WIDTH: f32 = 206.0;
const ACCOUNT_EDITOR_TOGGLE_WIDTH: f32 = 86.0;

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
                        other_idx != idx
                            && other.enabled
                            && other.username.trim().eq_ignore_ascii_case(&email)
                    })
            {
                app.set_status("An enabled account with this email already exists");
            } else {
                next_config.accounts[idx].enabled = enabling;
                if let Err(e) = save_config(&next_config) {
                    app.set_status(format!("Failed to save: {}", e));
                } else {
                    app.config = next_config;
                    app.set_status("Account updated");
                    sync_worker_accounts(app);
                }
            }
        }
    }

    show_delete_confirmation(ui, app, &mut delete_idx);

    if let Some(idx) = delete_idx {
        let account_id = app.config.accounts[idx].id.clone();
        let mut next_config = app.config.clone();
        next_config.accounts.remove(idx);
        if let Err(e) = save_config(&next_config) {
            app.set_status(format!("Failed to save: {}", e));
        } else {
            app.config = next_config;
            let cleanup_result = delete_account(&account_id);
            if let Err(e) = cleanup_result {
                app.set_status(format!("Account deleted; password cleanup failed: {}", e));
            } else {
                app.set_status("Account deleted");
            }
            sync_worker_accounts(app);
            app.confirm_delete_account = None;
        }
    }

    show_account_editor(ui, app);
}

struct AccountColumns {
    email: f32,
    state: f32,
    actions: f32,
}

fn show_accounts_header(ui: &mut egui::Ui) {
    show_table_row(ui, 20.0, |ui, cells| {
        show_cell(
            ui,
            cells.email,
            egui::Layout::left_to_right(egui::Align::Center),
            |ui| {
                ui.label(theme::small_muted("Email"));
            },
        );
        show_cell(
            ui,
            cells.state,
            egui::Layout::left_to_right(egui::Align::Center),
            |ui| {
                ui.label(theme::small_muted("State"));
            },
        );
        show_cell(
            ui,
            cells.actions,
            egui::Layout::left_to_right(egui::Align::Center),
            |ui| {
                ui.label(theme::small_muted("Actions"));
            },
        );
    });
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
                        [ui.available_width(), ACCOUNT_ROW_HEIGHT],
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
                let (state, state_color, state_fill) = if account.enabled {
                    ("Enabled", theme::SUCCESS, theme::SUCCESS_SOFT)
                } else {
                    ("Paused", theme::MUTED, theme::MUTED_SOFT)
                };
                theme::compact_pill(ui, state, state_color, state_fill);
            },
        );

        show_cell(
            ui,
            cells.actions,
            egui::Layout::left_to_right(egui::Align::Center),
            |ui| {
                let edit_button = theme::secondary_button("Edit")
                    .min_size(egui::vec2(EDIT_BUTTON_WIDTH, ROW_BUTTON_HEIGHT));
                if ui.add_enabled(actions_enabled, edit_button).clicked() {
                    *edit_account = Some(account.clone());
                }
                let delete_button = theme::danger_button("Delete")
                    .min_size(egui::vec2(DELETE_BUTTON_WIDTH, ROW_BUTTON_HEIGHT));
                if ui.add_enabled(actions_enabled, delete_button).clicked() {
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
    tracing::info!(account_id = %account.id, "Opening account editor");
    app.editing_account = Some(account);
    clear_temp_password(app);
    app.show_password = false;
}

fn clear_temp_password(app: &mut AutoLoginApp) {
    app.temp_password = Zeroizing::new(String::new());
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
                    "This removes \"{}\" and its saved password.",
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
                            ui.add_sized([ACCOUNT_EDITOR_PASSWORD_WIDTH, 24.0], password_edit);
                            let label = if app.show_password { "Hide" } else { "Show" };
                            if ui
                                .add_sized(
                                    [ACCOUNT_EDITOR_TOGGLE_WIDTH, 28.0],
                                    theme::secondary_button(label),
                                )
                                .clicked()
                            {
                                app.show_password = !app.show_password;
                            }
                        });
                        ui.end_row();
                    });

                ui.separator();
                ui.horizontal(|ui| {
                    if is_existing && account.has_saved_password {
                        theme::pill(ui, "Password saved", theme::SUCCESS, theme::SUCCESS_SOFT);
                    }

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

fn save_edited_account(app: &mut AutoLoginApp, account: &Account, is_existing: bool) -> bool {
    if account.username.trim().is_empty() {
        app.set_status("Email is required");
        return false;
    }
    if account.enabled
        && app.config.accounts.iter().any(|existing| {
            existing.id != account.id
                && existing.enabled
                && existing
                    .username
                    .trim()
                    .eq_ignore_ascii_case(account.username.trim())
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
    let only_password_changed = new_password.is_some()
        && existing_account.is_some_and(|existing| {
            previous_password_saved
                && existing.enabled == account.enabled
                && existing.username.trim() == account.username
                && existing.has_saved_password
        });

    if only_password_changed {
        if let Some(password) = new_password.as_ref() {
            if let Err(e) =
                save_account(&account, password.as_str(), app.config.settings.use_keyring)
            {
                app.set_status(format!("Failed to save password: {}", e));
                return false;
            }
        }
        app.set_status("Password saved");
        if let Err(e) = app
            .worker_tx
            .try_send(crate::background::WorkerCommand::RefreshPasswords)
        {
            app.set_status(format!("Password saved, but monitor update failed: {}", e));
        }
        return true;
    }

    let previous_password = if is_existing && previous_password_saved && new_password.is_some() {
        match load_password(&account.id, app.config.settings.use_keyring) {
            Ok(password) => Some(password),
            Err(e) => {
                app.set_status(format!(
                    "Failed to read current password for rollback: {}",
                    e
                ));
                return false;
            }
        }
    } else {
        None
    };
    if let Some(password) = new_password.as_ref() {
        if let Err(e) = save_account(&account, password.as_str(), app.config.settings.use_keyring) {
            let mut rollback_errors = Vec::new();
            if is_existing {
                if let Some(previous_password) = previous_password.as_ref() {
                    if let Err(rollback_error) = save_account(
                        &account,
                        previous_password.as_str(),
                        app.config.settings.use_keyring,
                    ) {
                        rollback_errors.push(rollback_error.to_string());
                    }
                } else if let Err(rollback_error) = delete_account(&account.id) {
                    rollback_errors.push(rollback_error.to_string());
                }
            } else if let Err(rollback_error) = delete_account(&account.id) {
                rollback_errors.push(rollback_error.to_string());
            }

            if rollback_errors.is_empty() {
                app.set_status(format!("Failed to save password: {}", e));
            } else {
                app.set_status(format!(
                    "Failed to save password: {}; password rollback failed: {}",
                    e,
                    rollback_errors.join("; ")
                ));
            }
            return false;
        }
        account.has_saved_password = true;
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
        let mut rollback_errors = Vec::new();
        if new_password.is_some() {
            if is_existing {
                if let Some(previous_password) = previous_password.as_deref() {
                    let previous_password = previous_password.as_str();
                    if let Err(rollback_error) =
                        save_account(&account, previous_password, app.config.settings.use_keyring)
                    {
                        rollback_errors.push(rollback_error.to_string());
                    }
                } else if let Err(rollback_error) = delete_account(&account.id) {
                    rollback_errors.push(rollback_error.to_string());
                }
            } else if let Err(rollback_error) = delete_account(&account.id) {
                rollback_errors.push(rollback_error.to_string());
            }
        }
        if rollback_errors.is_empty() {
            app.set_status(format!("Failed to save config: {}", e));
        } else {
            app.set_status(format!(
                "Failed to save config: {}; password rollback failed: {}",
                e,
                rollback_errors.join("; ")
            ));
        }
        return false;
    } else {
        app.config = next_config;
        app.set_status("Account saved");
    }

    sync_worker_accounts(app);

    true
}

fn sync_worker_accounts(app: &mut AutoLoginApp) {
    if let Err(e) = app
        .worker_tx
        .try_send(crate::background::WorkerCommand::UpdateAccounts(
            app.config.accounts.clone(),
        ))
    {
        app.set_status(format!("Saved, but monitor update failed: {}", e));
    }
}
