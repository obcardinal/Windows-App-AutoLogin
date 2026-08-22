use crate::app::AutoLoginApp;
use crate::autostart;
use crate::models::{AppConfig, AppSettings, FIXED_POLL_INTERVAL_SECS};
use crate::storage::{
    config_write_committed, is_pending_storage_operation_in_progress,
    pending_storage_recovery_user_status, storage_mode_migration_error_requires_recovery,
    StorageModeMigration,
};
use crate::ui::theme;
use eframe::egui;
use tracing::warn;

pub fn show(ui: &mut egui::Ui, app: &mut AutoLoginApp) {
    let mut settings_changed = false;
    let storage_mutations_ready = app.account_mutations_ready();
    theme::page_header_plain(
        ui,
        "Settings",
        "Adjust login behavior and system integration.",
    );

    egui::ScrollArea::vertical()
        .id_salt("settings_scroll")
        .auto_shrink([false; 2])
        .show(ui, |ui| {
            section(ui, "System", |ui| {
                settings_changed |= ui
                    .add_enabled(
                        storage_mutations_ready,
                        egui::Checkbox::new(
                            &mut app.settings_draft.auto_start,
                            "Open at Login",
                        ),
                    )
                    .changed();
                settings_changed |= ui
                    .add_enabled(
                        storage_mutations_ready,
                        egui::Checkbox::new(
                            &mut app.settings_draft.start_minimized,
                            "Hide main window at launch",
                        ),
                    )
                    .on_hover_text("The app keeps running from the menu bar or system tray.")
                    .changed();
            });

            section(ui, "Security", |ui| {
                settings_changed |= ui
                    .add_enabled(
                        storage_mutations_ready,
                        egui::Checkbox::new(
                        &mut app.settings_draft.use_keyring,
                        "Use system secure storage",
                        ),
                    )
                    .on_hover_text(
                        "Recommended. If disabled, password ciphertext is stored locally and its encryption key is still kept in the system credential store.",
                    )
                    .changed();
                if !storage_mutations_ready {
                    ui.label(theme::muted(
                        "Settings changes are locked until storage recovery completes after restart.",
                    ));
                }
            });
        });

    if settings_changed {
        save_settings(app);
    }
}

fn save_settings(app: &mut AutoLoginApp) {
    let storage_mutations_ready = app.account_mutations_ready();
    if restore_settings_when_recovery_blocked(
        &mut app.settings_draft,
        &app.config.settings,
        storage_mutations_ready,
    ) {
        app.set_status(pending_storage_recovery_user_status(
            "Settings were left unchanged.",
        ));
        app.stop_monitor_for_pending_storage_recovery();
        return;
    }
    let result = save_settings_transaction(
        &app.config,
        app.settings_draft.clone(),
        autostart::set_enabled,
        crate::storage::begin_storage_mode_migration_journal,
        crate::storage::migrate_storage_mode,
        crate::storage::save_config,
        crate::storage::rollback_storage_mode_migration,
        crate::storage::commit_storage_mode_migration,
        crate::storage::clear_pending_storage_operation,
        crate::storage::mark_storage_recovery_blocked,
    );

    let applied = result.applied;
    let storage_mode_changed = result.storage_mode_changed;
    let recovery_pending = result.recovery_pending
        || !matches!(
            crate::storage::pending_storage_recovery_is_clear(),
            Ok(true)
        )
        || !matches!(crate::storage::storage_recovery_block_is_clear(), Ok(true));
    app.config = result.config;
    app.settings_draft = result.settings_draft;
    app.set_status(result.status);
    if recovery_pending {
        if let Err(error) = crate::storage::mark_storage_recovery_blocked() {
            warn!(
                error = %error,
                "Failed to persist the password storage recovery block before stopping the monitor"
            );
        }
        app.stop_monitor_for_pending_storage_recovery();
    }
    if !settings_worker_sync_allowed(applied, recovery_pending) {
        return;
    }

    app.settings_draft = app.config.settings.clone();
    app.sync_saved_config_to_worker(storage_mode_changed);
}

fn restore_settings_when_recovery_blocked(
    settings_draft: &mut AppSettings,
    current_settings: &AppSettings,
    storage_mutations_ready: bool,
) -> bool {
    if storage_mutations_ready || settings_draft == current_settings {
        return false;
    }

    settings_draft.clone_from(current_settings);
    true
}

#[derive(Debug, Clone)]
struct SettingsSaveTransactionResult {
    config: AppConfig,
    settings_draft: AppSettings,
    status: String,
    applied: bool,
    storage_mode_changed: bool,
    recovery_pending: bool,
}

fn settings_worker_sync_allowed(applied: bool, recovery_pending: bool) -> bool {
    applied && !recovery_pending
}

#[allow(clippy::too_many_arguments)]
fn save_settings_transaction<A, J, M, S, R, C, X, B>(
    current_config: &AppConfig,
    settings_draft: AppSettings,
    mut set_autostart_op: A,
    mut begin_storage_journal_op: J,
    mut migrate_storage_op: M,
    mut save_config_op: S,
    mut rollback_storage_op: R,
    mut commit_storage_op: C,
    mut clear_storage_journal_op: X,
    mut mark_recovery_blocked_op: B,
) -> SettingsSaveTransactionResult
where
    A: FnMut(bool) -> anyhow::Result<()>,
    J: FnMut(&[crate::models::Account], bool, bool) -> anyhow::Result<()>,
    M: FnMut(&[crate::models::Account], bool, bool) -> anyhow::Result<StorageModeMigration>,
    S: FnMut(&AppConfig) -> anyhow::Result<()>,
    R: FnMut(&StorageModeMigration) -> anyhow::Result<usize>,
    C: FnMut(&StorageModeMigration) -> anyhow::Result<usize>,
    X: FnMut() -> anyhow::Result<()>,
    B: FnMut() -> anyhow::Result<()>,
{
    let previous_settings = current_config.settings.clone();
    let mut next_config = current_config.clone();
    next_config.settings = settings_draft;
    next_config.settings.poll_interval_secs = FIXED_POLL_INTERVAL_SECS;
    let storage_mode_changed = next_config.settings.use_keyring != previous_settings.use_keyring;
    let auto_start_changed = next_config.settings.auto_start != previous_settings.auto_start;

    let storage_journal_started = if storage_mode_changed {
        if let Err(e) = begin_storage_journal_op(
            &current_config.accounts,
            previous_settings.use_keyring,
            next_config.settings.use_keyring,
        ) {
            let recovery_pending = is_pending_storage_operation_in_progress(&e);
            persist_settings_recovery_block_if_needed(
                recovery_pending,
                &mut mark_recovery_blocked_op,
            );
            return rejected_with_recovery_pending(
                current_config,
                previous_settings,
                storage_prepare_failure_status(
                    &e,
                    "Storage mode was left unchanged.",
                    "Failed to prepare password storage migration. Storage mode was left unchanged.",
                ),
                recovery_pending,
            );
        }
        true
    } else {
        false
    };

    let storage_migration = if storage_mode_changed {
        match migrate_storage_op(
            &current_config.accounts,
            previous_settings.use_keyring,
            next_config.settings.use_keyring,
        ) {
            Ok(migration) => Some(migration),
            Err(e) => {
                let recovery_required = storage_mode_migration_error_requires_recovery(&e);
                warn!(
                    error = %e,
                    recovery_required,
                    old_storage = storage_mode_label(previous_settings.use_keyring),
                    new_storage = storage_mode_label(next_config.settings.use_keyring),
                    "Password storage migration failed"
                );
                let journal_cleared = !recovery_required
                    && clear_storage_journal_after_terminal_result(
                        storage_journal_started,
                        &mut clear_storage_journal_op,
                    );
                let recovery_pending = recovery_required || !journal_cleared;
                let status = if recovery_pending {
                    pending_storage_recovery_user_status("Storage mode was left unchanged.")
                } else {
                    "Failed to change password storage. Storage mode was left unchanged."
                        .to_string()
                };
                persist_settings_recovery_block_if_needed(
                    recovery_pending,
                    &mut mark_recovery_blocked_op,
                );
                return rejected_with_recovery_pending(
                    current_config,
                    previous_settings,
                    status,
                    recovery_pending,
                );
            }
        }
    } else {
        None
    };

    let mut config_durability_warning = match save_config_op(&next_config) {
        Ok(()) => false,
        Err(e) if config_write_committed(&e) => {
            warn!(error = %e, "Settings config replacement committed, but durability confirmation failed");
            true
        }
        Err(_) => {
            if let Some(migration) = &storage_migration {
                if let Err(rollback_error) = rollback_storage_op(migration) {
                    let _ = rollback_error;
                    persist_settings_recovery_block_if_needed(true, &mut mark_recovery_blocked_op);
                    return rejected_with_recovery_pending(
                        current_config,
                        previous_settings,
                        "Failed to save settings, and storage rollback could not be confirmed. Passwords may need manual cleanup.".to_string(),
                        true,
                    );
                }
            }
            let journal_cleared = clear_storage_journal_after_terminal_result(
                storage_journal_started,
                &mut clear_storage_journal_op,
            );
            persist_settings_recovery_block_if_needed(
                !journal_cleared,
                &mut mark_recovery_blocked_op,
            );
            return rejected_with_recovery_pending(
                current_config,
                previous_settings,
                if journal_cleared {
                    "Failed to save settings. Storage mode was left unchanged.".to_string()
                } else {
                    pending_storage_recovery_user_status("Storage mode was left unchanged.")
                },
                !journal_cleared,
            );
        }
    };

    let mut status_parts = Vec::new();
    let mut recovery_pending = false;
    if auto_start_changed {
        if let Err(e) = set_autostart_op(next_config.settings.auto_start) {
            warn!(
                error = %e,
                previous_auto_start = previous_settings.auto_start,
                attempted_auto_start = next_config.settings.auto_start,
                "Failed to update Open at Login after saving settings"
            );
            next_config.settings.auto_start = previous_settings.auto_start;
            status_parts
                .push("Settings saved, but Open at Login could not be updated.".to_string());
            match save_config_op(&next_config) {
                Ok(()) => config_durability_warning = false,
                Err(rollback_error) if config_write_committed(&rollback_error) => {
                    config_durability_warning = true;
                    warn!(error = %rollback_error, previous_auto_start = previous_settings.auto_start, "Open at Login config rollback committed, but durability confirmation failed");
                }
                Err(rollback_error) => {
                    warn!(
                        error = %rollback_error,
                        previous_auto_start = previous_settings.auto_start,
                        "Failed to persist Open at Login rollback after update failure"
                    );
                    status_parts.push(
                        "Open at Login settings rollback could not be confirmed; startup repair will re-check the system state."
                            .to_string(),
                    );
                }
            }
        }
    }

    if let Some(migration) = &storage_migration {
        if config_durability_warning {
            recovery_pending = true;
            // Deleting the old backend would be unsafe if a crash re-exposed
            // the previous config. The journal is deliberately retained.
            status_parts.push(
                "Settings were committed, but disk durability could not be confirmed. Old password storage cleanup remains pending and will retry on next launch."
                    .to_string(),
            );
        } else if let Err(e) = commit_storage_op(migration) {
            recovery_pending = true;
            warn!(
                error = %e,
                old_storage = storage_mode_label(previous_settings.use_keyring),
                new_storage = storage_mode_label(next_config.settings.use_keyring),
                "Old password storage cleanup failed after migration; keeping verified new storage mode"
            );
            status_parts.push(storage_cleanup_warning(
                previous_settings.use_keyring,
                next_config.settings.use_keyring,
            ));
        } else if !clear_storage_journal_after_terminal_result(
            storage_journal_started,
            &mut clear_storage_journal_op,
        ) {
            recovery_pending = true;
            status_parts.push(
                "Password storage recovery journal removal could not be durably confirmed; auto-login remains blocked until a fresh startup verifies recovery."
                    .to_string(),
            );
        }
    } else if config_durability_warning {
        status_parts.push(
            "Settings were committed, but disk durability could not be confirmed; the saved state will be checked on next launch."
                .to_string(),
        );
    }

    let status = if status_parts.is_empty() {
        "Settings saved".to_string()
    } else {
        status_parts.join(" ")
    };
    persist_settings_recovery_block_if_needed(recovery_pending, &mut mark_recovery_blocked_op);

    SettingsSaveTransactionResult {
        settings_draft: next_config.settings.clone(),
        config: next_config,
        status,
        applied: true,
        storage_mode_changed,
        recovery_pending,
    }
}

fn persist_settings_recovery_block_if_needed<B>(recovery_pending: bool, mark: &mut B)
where
    B: FnMut() -> anyhow::Result<()>,
{
    if recovery_pending {
        if let Err(error) = mark() {
            warn!(
                error = %error,
                "Failed to persist password storage recovery block before returning a recovery-pending result"
            );
        }
    }
}

fn rejected_with_recovery_pending(
    current_config: &AppConfig,
    settings_draft: AppSettings,
    status: String,
    recovery_pending: bool,
) -> SettingsSaveTransactionResult {
    rejected_with_config(
        current_config.clone(),
        settings_draft,
        status,
        recovery_pending,
    )
}

fn rejected_with_config(
    config: AppConfig,
    settings_draft: AppSettings,
    status: String,
    recovery_pending: bool,
) -> SettingsSaveTransactionResult {
    SettingsSaveTransactionResult {
        config,
        settings_draft,
        status,
        applied: false,
        storage_mode_changed: false,
        recovery_pending,
    }
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

fn clear_storage_journal_after_terminal_result<X>(
    started: bool,
    clear_storage_journal_op: &mut X,
) -> bool
where
    X: FnMut() -> anyhow::Result<()>,
{
    if !started {
        return true;
    }
    match clear_storage_journal_op() {
        Ok(()) => true,
        Err(e) => {
            warn!(
                error = %e,
                "Failed to clear pending storage operation journal after terminal transaction result"
            );
            false
        }
    }
}

fn storage_mode_label(use_keyring: bool) -> &'static str {
    if use_keyring {
        "system secure storage"
    } else {
        "encrypted fallback file"
    }
}

fn storage_cleanup_warning(from_use_keyring: bool, to_use_keyring: bool) -> String {
    format!(
        "Settings saved. Passwords were moved to {}, but some old {} cleanup is still pending and will retry on next launch. Stored credential changes are blocked until recovery completes.",
        storage_mode_label(to_use_keyring),
        storage_mode_label(from_use_keyring),
    )
}

fn section(ui: &mut egui::Ui, title: &str, add_contents: impl FnOnce(&mut egui::Ui)) {
    theme::compact_frame().show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.label(egui::RichText::new(title).strong());
        ui.add_space(4.0);
        add_contents(ui);
    });
    ui.add_space(6.0);
}

#[cfg(test)]
mod tests {
    use super::{
        restore_settings_when_recovery_blocked, save_settings_transaction,
        settings_worker_sync_allowed,
    };
    use crate::models::{Account, AppConfig, AppSettings, FIXED_POLL_INTERVAL_SECS};
    use crate::storage::{storage_mode_migration_recovery_required_error, StorageModeMigration};
    use std::cell::RefCell;

    #[test]
    fn blocked_recovery_restores_every_setting_without_persisting_defaults() {
        let current = AppSettings {
            use_keyring: true,
            auto_start: false,
            ..AppSettings::default()
        };
        let mut draft = current.clone();
        draft.use_keyring = false;
        draft.auto_start = true;

        assert!(restore_settings_when_recovery_blocked(
            &mut draft, &current, false
        ));
        assert!(draft.use_keyring);
        assert!(!draft.auto_start);
        assert_eq!(draft, current);
    }

    #[test]
    fn ready_storage_allows_storage_mode_change() {
        let current = AppSettings {
            use_keyring: true,
            ..AppSettings::default()
        };
        let mut draft = current.clone();
        draft.use_keyring = false;

        assert!(!restore_settings_when_recovery_blocked(
            &mut draft, &current, true
        ));
        assert!(!draft.use_keyring);
    }

    #[test]
    fn storage_mode_commit_cleanup_failure_keeps_new_mode_and_target_passwords() {
        let config = config_with_two_saved_accounts(true);
        let mut draft = config.settings.clone();
        draft.use_keyring = false;
        let events = RefCell::new(Vec::new());

        let result = save_settings_transaction(
            &config,
            draft,
            |_| Ok(()),
            |_, from_use_keyring, to_use_keyring| {
                events
                    .borrow_mut()
                    .push(format!("journal:{from_use_keyring}->{to_use_keyring}"));
                Ok(())
            },
            |_, from_use_keyring, to_use_keyring| {
                events
                    .borrow_mut()
                    .push(format!("migrate:{from_use_keyring}->{to_use_keyring}"));
                Ok(StorageModeMigration::for_test(
                    vec!["account-1".to_string(), "account-2".to_string()],
                    from_use_keyring,
                    to_use_keyring,
                ))
            },
            |next_config| {
                events
                    .borrow_mut()
                    .push(format!("save_config:{}", next_config.settings.use_keyring));
                assert!(!next_config.settings.use_keyring);
                Ok(())
            },
            |_| {
                events.borrow_mut().push("rollback_target".to_string());
                Ok(2)
            },
            |_| {
                events
                    .borrow_mut()
                    .push("commit_source_cleanup".to_string());
                anyhow::bail!("source cleanup failed after account-1")
            },
            || panic!("journal must remain pending until old storage cleanup succeeds"),
            || Ok(()),
        );

        assert!(result.applied);
        assert!(result.storage_mode_changed);
        assert!(result.recovery_pending);
        assert!(!result.config.settings.use_keyring);
        assert!(!result.settings_draft.use_keyring);
        assert_eq!(
            result.config.settings.poll_interval_secs,
            FIXED_POLL_INTERVAL_SECS
        );
        assert!(result.status.contains("will retry on next launch"));
        assert!(result
            .status
            .contains("Stored credential changes are blocked"));
        assert!(result
            .status
            .contains("old system secure storage cleanup is still pending"));
        assert_eq!(
            events.into_inner(),
            vec![
                "journal:true->false",
                "migrate:true->false",
                "save_config:false",
                "commit_source_cleanup"
            ]
        );
    }

    #[test]
    fn storage_mode_config_save_failure_rolls_back_target_migration() {
        let config = config_with_two_saved_accounts(true);
        let mut draft = config.settings.clone();
        draft.use_keyring = false;
        let events = RefCell::new(Vec::new());

        let result = save_settings_transaction(
            &config,
            draft,
            |_| Ok(()),
            |_, _, _| Ok(()),
            |_, from_use_keyring, to_use_keyring| {
                events
                    .borrow_mut()
                    .push(format!("migrate:{from_use_keyring}->{to_use_keyring}"));
                Ok(StorageModeMigration::for_test(
                    vec!["account-1".to_string()],
                    from_use_keyring,
                    to_use_keyring,
                ))
            },
            |next_config| {
                events
                    .borrow_mut()
                    .push(format!("save_config:{}", next_config.settings.use_keyring));
                anyhow::bail!("config write failed")
            },
            |_| {
                events.borrow_mut().push("rollback_target".to_string());
                Ok(1)
            },
            |_| {
                events
                    .borrow_mut()
                    .push("commit_source_cleanup".to_string());
                Ok(1)
            },
            || Ok(()),
            || Ok(()),
        );

        assert!(!result.applied);
        assert!(!result.storage_mode_changed);
        assert!(result.config.settings.use_keyring);
        assert_eq!(result.settings_draft, config.settings);
        assert!(result.status.contains("Failed to save settings"));
        assert!(!result.status.contains("config write failed"));
        assert_eq!(
            events.into_inner(),
            vec![
                "migrate:true->false",
                "save_config:false",
                "rollback_target"
            ]
        );
    }

    #[test]
    fn committed_config_warning_keeps_new_mode_and_defers_destructive_source_cleanup() {
        let config = config_with_two_saved_accounts(true);
        let mut draft = config.settings.clone();
        draft.use_keyring = false;
        let events = RefCell::new(Vec::new());

        let result = save_settings_transaction(
            &config,
            draft,
            |_| Ok(()),
            |_, _, _| {
                events.borrow_mut().push("journal");
                Ok(())
            },
            |_, from_use_keyring, to_use_keyring| {
                events.borrow_mut().push("migrate");
                Ok(StorageModeMigration::for_test(
                    vec!["account-1".to_string()],
                    from_use_keyring,
                    to_use_keyring,
                ))
            },
            |_| {
                events.borrow_mut().push("save_config_committed");
                Err(crate::storage::committed_config_write_test_error())
            },
            |_| panic!("committed config must not roll back target credentials"),
            |_| panic!("old credentials must remain until config durability is confirmed"),
            || panic!("journal must remain for recovery"),
            || Ok(()),
        );

        assert!(result.applied);
        assert!(result.storage_mode_changed);
        assert!(result.recovery_pending);
        assert!(!result.config.settings.use_keyring);
        assert!(result.status.contains("durability could not be confirmed"));
        assert!(result.status.contains("cleanup remains pending"));
        assert_eq!(
            events.into_inner(),
            vec!["journal", "migrate", "save_config_committed"]
        );
    }

    #[test]
    fn storage_mode_journal_wraps_migration_until_commit_cleanup_succeeds() {
        let config = config_with_two_saved_accounts(true);
        let mut draft = config.settings.clone();
        draft.auto_start = true;
        draft.use_keyring = false;
        let events = RefCell::new(Vec::new());

        let result = save_settings_transaction(
            &config,
            draft,
            |enabled| {
                events.borrow_mut().push(format!("autostart:{enabled}"));
                Ok(())
            },
            |_, from_use_keyring, to_use_keyring| {
                events
                    .borrow_mut()
                    .push(format!("journal:{from_use_keyring}->{to_use_keyring}"));
                Ok(())
            },
            |_, from_use_keyring, to_use_keyring| {
                events
                    .borrow_mut()
                    .push(format!("migrate:{from_use_keyring}->{to_use_keyring}"));
                Ok(StorageModeMigration::for_test(
                    vec!["account-1".to_string()],
                    from_use_keyring,
                    to_use_keyring,
                ))
            },
            |next_config| {
                events.borrow_mut().push(format!(
                    "save_config:use_keyring={},auto_start={}",
                    next_config.settings.use_keyring, next_config.settings.auto_start
                ));
                Ok(())
            },
            |_| {
                events.borrow_mut().push("rollback_target".to_string());
                Ok(1)
            },
            |_| {
                events
                    .borrow_mut()
                    .push("commit_source_cleanup".to_string());
                Ok(1)
            },
            || {
                events.borrow_mut().push("journal_clear".to_string());
                Ok(())
            },
            || Ok(()),
        );

        assert!(result.applied);
        assert!(!result.recovery_pending);
        assert_eq!(
            events.into_inner(),
            vec![
                "journal:true->false",
                "migrate:true->false",
                "save_config:use_keyring=false,auto_start=true",
                "autostart:true",
                "commit_source_cleanup",
                "journal_clear"
            ]
        );
    }

    #[test]
    fn journal_clear_ambiguity_propagates_recovery_pending_and_blocks_worker_sync() {
        let config = config_with_two_saved_accounts(true);
        let mut draft = config.settings.clone();
        draft.use_keyring = false;
        let events = RefCell::new(Vec::new());

        let result = save_settings_transaction(
            &config,
            draft,
            |_| Ok(()),
            |_, _, _| {
                events.borrow_mut().push("journal");
                Ok(())
            },
            |_, from_use_keyring, to_use_keyring| {
                events.borrow_mut().push("migrate");
                Ok(StorageModeMigration::for_test(
                    vec!["account-1".to_string(), "account-2".to_string()],
                    from_use_keyring,
                    to_use_keyring,
                ))
            },
            |_| {
                events.borrow_mut().push("save-config");
                Ok(())
            },
            |_| panic!("a committed migration must not roll back"),
            |_| {
                events.borrow_mut().push("cleanup-source");
                Ok(2)
            },
            || {
                events.borrow_mut().push("unlink-committed-fsync-failed");
                anyhow::bail!("journal unlink parent fsync failed")
            },
            || {
                events.borrow_mut().push("mark-recovery-blocked");
                Ok(())
            },
        );

        assert!(result.applied);
        assert!(result.storage_mode_changed);
        assert!(result.recovery_pending);
        assert!(!settings_worker_sync_allowed(
            result.applied,
            result.recovery_pending
        ));
        assert!(result.status.contains("auto-login remains blocked"));
        assert_eq!(
            events.into_inner(),
            vec![
                "journal",
                "migrate",
                "save-config",
                "cleanup-source",
                "unlink-committed-fsync-failed",
                "mark-recovery-blocked"
            ]
        );
    }

    #[test]
    fn storage_migration_failure_without_recovery_clears_journal_and_skips_side_effects() {
        let config = config_with_two_saved_accounts(true);
        let mut draft = config.settings.clone();
        draft.auto_start = true;
        draft.use_keyring = false;
        let events = RefCell::new(Vec::new());

        let result = save_settings_transaction(
            &config,
            draft,
            |enabled| {
                events.borrow_mut().push(format!("autostart:{enabled}"));
                Ok(())
            },
            |_, from_use_keyring, to_use_keyring| {
                events
                    .borrow_mut()
                    .push(format!("journal:{from_use_keyring}->{to_use_keyring}"));
                Ok(())
            },
            |_, from_use_keyring, to_use_keyring| {
                events
                    .borrow_mut()
                    .push(format!("migrate:{from_use_keyring}->{to_use_keyring}"));
                anyhow::bail!("migration failed")
            },
            |_| {
                events.borrow_mut().push("save_config".to_string());
                Ok(())
            },
            |_| {
                events.borrow_mut().push("rollback_target".to_string());
                Ok(1)
            },
            |_| {
                events
                    .borrow_mut()
                    .push("commit_source_cleanup".to_string());
                Ok(1)
            },
            || {
                events.borrow_mut().push("journal_clear".to_string());
                Ok(())
            },
            || Ok(()),
        );

        assert!(!result.applied);
        assert!(!result.storage_mode_changed);
        assert_eq!(result.config.settings, config.settings);
        assert_eq!(result.settings_draft, config.settings);
        assert!(!result.config.settings.auto_start);
        assert!(result.config.settings.use_keyring);
        assert!(!result.settings_draft.auto_start);
        assert!(result.settings_draft.use_keyring);
        assert!(result.status.contains("Failed to change password storage"));
        assert!(!result.status.contains("Open at Login"));
        assert!(!result.status.contains("migration failed"));
        assert_eq!(
            events.into_inner(),
            vec![
                "journal:true->false",
                "migrate:true->false",
                "journal_clear"
            ]
        );
    }

    #[test]
    fn storage_migration_failure_requiring_recovery_keeps_journal_and_skips_side_effects() {
        let config = config_with_two_saved_accounts(true);
        let mut draft = config.settings.clone();
        draft.auto_start = true;
        draft.use_keyring = false;
        let events = RefCell::new(Vec::new());

        let result = save_settings_transaction(
            &config,
            draft,
            |enabled| {
                events.borrow_mut().push(format!("autostart:{enabled}"));
                Ok(())
            },
            |_, from_use_keyring, to_use_keyring| {
                events
                    .borrow_mut()
                    .push(format!("journal:{from_use_keyring}->{to_use_keyring}"));
                Ok(())
            },
            |_, from_use_keyring, to_use_keyring| {
                events
                    .borrow_mut()
                    .push(format!("migrate:{from_use_keyring}->{to_use_keyring}"));
                Err(storage_mode_migration_recovery_required_error(
                    "target cleanup still needs recovery",
                ))
            },
            |_| {
                events.borrow_mut().push("save_config".to_string());
                Ok(())
            },
            |_| {
                events.borrow_mut().push("rollback_target".to_string());
                Ok(1)
            },
            |_| {
                events
                    .borrow_mut()
                    .push("commit_source_cleanup".to_string());
                Ok(1)
            },
            || panic!("journal must remain pending when migration recovery is required"),
            || Ok(()),
        );

        assert!(!result.applied);
        assert!(!result.storage_mode_changed);
        assert_eq!(result.config.settings, config.settings);
        assert_eq!(result.settings_draft, config.settings);
        assert!(result
            .status
            .contains("Password storage recovery is still pending"));
        assert!(result.status.contains("Storage mode was left unchanged"));
        assert!(!result
            .status
            .contains("target cleanup still needs recovery"));
        assert!(!result.status.contains("Open at Login"));
        assert_eq!(
            events.into_inner(),
            vec!["journal:true->false", "migrate:true->false"]
        );
    }

    #[test]
    fn config_save_failure_does_not_touch_autostart() {
        let config = config_with_two_saved_accounts(true);
        let mut draft = config.settings.clone();
        draft.auto_start = true;
        let events = RefCell::new(Vec::new());

        let result = save_settings_transaction(
            &config,
            draft,
            |enabled| {
                events.borrow_mut().push(format!("autostart:{enabled}"));
                Ok(())
            },
            |_, _, _| Ok(()),
            |_, from_use_keyring, to_use_keyring| {
                events
                    .borrow_mut()
                    .push(format!("migrate:{from_use_keyring}->{to_use_keyring}"));
                Ok(StorageModeMigration::for_test(
                    vec!["account-1".to_string()],
                    from_use_keyring,
                    to_use_keyring,
                ))
            },
            |next_config| {
                events.borrow_mut().push(format!(
                    "save_config:auto_start={}",
                    next_config.settings.auto_start
                ));
                anyhow::bail!("config write failed")
            },
            |_| {
                events.borrow_mut().push("rollback_target".to_string());
                Ok(1)
            },
            |_| {
                events
                    .borrow_mut()
                    .push("commit_source_cleanup".to_string());
                Ok(1)
            },
            || Ok(()),
            || Ok(()),
        );

        assert!(!result.applied);
        assert!(!result.storage_mode_changed);
        assert!(!result.config.settings.auto_start);
        assert!(!result.settings_draft.auto_start);
        assert!(result.status.contains("Failed to save settings"));
        assert!(!result.status.contains("Open at Login"));
        assert!(!result.status.contains("config write failed"));
        assert_eq!(events.into_inner(), vec!["save_config:auto_start=true"]);
    }

    #[test]
    fn autostart_failure_reverts_only_open_at_login_and_keeps_storage_change() {
        let config = config_with_two_saved_accounts(true);
        let mut draft = config.settings.clone();
        draft.auto_start = true;
        draft.use_keyring = false;
        let events = RefCell::new(Vec::new());

        let result = save_settings_transaction(
            &config,
            draft,
            |enabled| {
                events.borrow_mut().push(format!("autostart:{enabled}"));
                if enabled {
                    anyhow::bail!("autostart failed")
                } else {
                    Ok(())
                }
            },
            |_, from_use_keyring, to_use_keyring| {
                events
                    .borrow_mut()
                    .push(format!("journal:{from_use_keyring}->{to_use_keyring}"));
                Ok(())
            },
            |_, from_use_keyring, to_use_keyring| {
                events
                    .borrow_mut()
                    .push(format!("migrate:{from_use_keyring}->{to_use_keyring}"));
                Ok(StorageModeMigration::for_test(
                    vec!["account-1".to_string()],
                    from_use_keyring,
                    to_use_keyring,
                ))
            },
            |next_config| {
                events.borrow_mut().push(format!(
                    "save_config:use_keyring={},auto_start={}",
                    next_config.settings.use_keyring, next_config.settings.auto_start
                ));
                Ok(())
            },
            |_| {
                events.borrow_mut().push("rollback_target".to_string());
                Ok(1)
            },
            |_| {
                events
                    .borrow_mut()
                    .push("commit_source_cleanup".to_string());
                Ok(1)
            },
            || {
                events.borrow_mut().push("journal_clear".to_string());
                Ok(())
            },
            || Ok(()),
        );

        assert!(result.applied);
        assert!(result.storage_mode_changed);
        assert!(!result.config.settings.use_keyring);
        assert!(!result.settings_draft.use_keyring);
        assert!(!result.config.settings.auto_start);
        assert!(!result.settings_draft.auto_start);
        assert!(result
            .status
            .contains("Settings saved, but Open at Login could not be updated"));
        assert_eq!(
            events.into_inner(),
            vec![
                "journal:true->false",
                "migrate:true->false",
                "save_config:use_keyring=false,auto_start=true",
                "autostart:true",
                "save_config:use_keyring=false,auto_start=false",
                "commit_source_cleanup",
                "journal_clear"
            ]
        );
    }

    fn config_with_two_saved_accounts(use_keyring: bool) -> AppConfig {
        let mut settings = AppSettings {
            use_keyring,
            ..AppSettings::default()
        };
        settings.poll_interval_secs = FIXED_POLL_INTERVAL_SECS;

        AppConfig {
            accounts: vec![
                saved_account("account-1", "one@example.com"),
                saved_account("account-2", "two@example.com"),
            ],
            settings,
        }
    }

    fn saved_account(id: &str, username: &str) -> Account {
        let mut account = Account::new(username);
        account.id = id.to_string();
        account.has_saved_password = true;
        account
    }
}
