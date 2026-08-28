use crate::app::{
    AutoLoginApp, BackgroundMutationExecutor, SettingsMutationGuard,
    CONFIG_MUTATION_RECOVERY_REASON,
};
use crate::autostart;
use crate::models::{AppConfig, AppSettings, FIXED_POLL_INTERVAL_SECS};
use crate::single_instance::{self, MonitorControlCommand};
use crate::storage::{
    config_write_committed, is_pending_storage_operation_in_progress,
    pending_storage_recovery_user_status, storage_mode_migration_error_requires_recovery,
    StorageModeMigration,
};
use crate::ui::theme;
use eframe::egui;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::Duration;
use tracing::warn;

const SETTINGS_BEGIN_FAILED_REASON: &str =
    "Configuration controls are unavailable because the monitor could not pause safely. Restart the app to try again.";
const SETTINGS_CANCEL_FAILED_REASON: &str =
    "Configuration controls are unavailable because the failed save could not be cancelled safely. Restart the app before changing settings.";
const SETTINGS_RELOAD_FAILED_REASON: &str =
    "Configuration controls are unavailable because the monitor could not confirm the current configuration. Restart the app before changing settings again.";
const SETTINGS_JOB_DISCONNECTED_REASON: &str =
    "Configuration controls are unavailable because the background save did not finish safely. Restart the app before changing settings again.";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct QueuedSettingsIntent {
    auto_start: Option<bool>,
    start_minimized: Option<bool>,
    use_keyring: Option<bool>,
}

impl QueuedSettingsIntent {
    fn record_changes(&mut self, before: &AppSettings, after: &AppSettings) {
        if before.auto_start != after.auto_start {
            self.auto_start = Some(after.auto_start);
        }
        if before.start_minimized != after.start_minimized {
            self.start_minimized = Some(after.start_minimized);
        }
        if before.use_keyring != after.use_keyring {
            self.use_keyring = Some(after.use_keyring);
        }
    }

    fn infer_unrecorded_changes(&mut self, requested: &AppSettings, latest: &AppSettings) {
        if self.auto_start.is_none() && requested.auto_start != latest.auto_start {
            self.auto_start = Some(latest.auto_start);
        }
        if self.start_minimized.is_none() && requested.start_minimized != latest.start_minimized {
            self.start_minimized = Some(latest.start_minimized);
        }
        if self.use_keyring.is_none() && requested.use_keyring != latest.use_keyring {
            self.use_keyring = Some(latest.use_keyring);
        }
    }

    fn apply_to(&self, authoritative: &AppSettings) -> AppSettings {
        let mut rebased = authoritative.clone();
        if let Some(value) = self.auto_start {
            rebased.auto_start = value;
        }
        if let Some(value) = self.start_minimized {
            rebased.start_minimized = value;
        }
        if let Some(value) = self.use_keyring {
            rebased.use_keyring = value;
        }
        rebased.poll_interval_secs = FIXED_POLL_INTERVAL_SECS;
        rebased
    }
}

pub(crate) struct PendingSettingsSave {
    receiver: Receiver<SettingsSaveCompletion>,
    requested_settings: AppSettings,
    queued_intent: QueuedSettingsIntent,
    local_sync_required: bool,
    refresh_passwords_required: bool,
}

#[cfg(test)]
impl PendingSettingsSave {
    pub(crate) fn inert_for_test() -> Self {
        let (sender, receiver) = mpsc::sync_channel(1);
        std::mem::forget(sender);
        Self {
            receiver,
            requested_settings: AppSettings::default(),
            queued_intent: QueuedSettingsIntent::default(),
            local_sync_required: false,
            refresh_passwords_required: false,
        }
    }
}

enum SettingsSaveCompletion {
    BeginFailed,
    Finished {
        result: SettingsSaveTransactionResult,
        recovery_pending: bool,
        recovery_signal_confirmed: bool,
        blocked_reason: Option<String>,
    },
}

pub fn show(ui: &mut egui::Ui, app: &mut AutoLoginApp) {
    let settings_before_input = app.settings_draft.clone();
    let mut settings_changed = false;
    let disabled_reason = settings_disabled_reason(app);
    let settings_ready = disabled_reason.is_none();
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
                let open_at_login = ui
                    .add_enabled(
                        settings_ready,
                        egui::Checkbox::new(
                            &mut app.settings_draft.auto_start,
                            "Open at Login",
                        ),
                    );
                settings_changed |= add_setting_description(
                    open_at_login,
                    settings_ready,
                    "Start Windows App AutoLogin after signing in.",
                    disabled_reason.as_deref(),
                );
                let start_minimized = ui
                    .add_enabled(
                        settings_ready,
                        egui::Checkbox::new(
                            &mut app.settings_draft.start_minimized,
                            "Hide main window at launch",
                        ),
                    );
                settings_changed |= add_setting_description(
                    start_minimized,
                    settings_ready,
                    "The app keeps running from the menu bar or system tray.",
                    disabled_reason.as_deref(),
                );
                if let Some(reason) = disabled_reason.as_deref() {
                    ui.add_space(4.0);
                    ui.label(theme::muted(reason));
                }
            });

            section(ui, "Security", |ui| {
                let secure_storage = ui
                    .add_enabled(
                        settings_ready,
                        egui::Checkbox::new(
                            &mut app.settings_draft.use_keyring,
                            "Use system secure storage",
                        ),
                    );
                settings_changed |= add_setting_description(
                    secure_storage,
                    settings_ready,
                    "Recommended. If disabled, password ciphertext is stored locally and its encryption key is still kept in the system credential store.",
                    disabled_reason.as_deref(),
                );
                if let Some(reason) = disabled_reason.as_deref() {
                    ui.add_space(4.0);
                    ui.label(theme::muted(
                        reason,
                    ));
                }
            });
        });

    if settings_changed {
        queue_or_start_background_save(app, ui.ctx(), &settings_before_input);
    }
}

fn add_setting_description(
    response: egui::Response,
    enabled: bool,
    enabled_description: &str,
    disabled_reason: Option<&str>,
) -> bool {
    let changed = response.changed();
    if enabled {
        response.on_hover_text(enabled_description);
    } else if let Some(reason) = disabled_reason {
        response.on_hover_text(reason);
    }
    changed
}

fn settings_disabled_reason(app: &AutoLoginApp) -> Option<String> {
    app.settings_mutations_disabled_reason().map(str::to_string)
}

fn queue_or_start_background_save(
    app: &mut AutoLoginApp,
    ctx: &egui::Context,
    settings_before_input: &AppSettings,
) {
    let latest_settings = app.settings_draft.clone();
    if let Some(pending) = app.pending_settings_save.as_mut() {
        pending
            .queued_intent
            .record_changes(settings_before_input, &latest_settings);
        ctx.request_repaint();
        return;
    }
    // An account toggle owns the durable configuration mutation lease, but it
    // must not freeze the Settings UI. Keep the latest visible draft as the
    // coalescing queue; the account completion path starts one rebased save.
    if app.account_toggle_in_progress() {
        ctx.request_repaint();
        return;
    }
    start_background_save(app, ctx);
}

pub(crate) fn start_queued_background_save_after_account_toggle(
    app: &mut AutoLoginApp,
    ctx: &egui::Context,
    local_sync_required: bool,
    refresh_passwords_required: bool,
) -> bool {
    if app.settings_draft == app.config.settings {
        return false;
    }
    start_background_save_with_deferred_sync(
        app,
        ctx,
        local_sync_required,
        refresh_passwords_required,
    )
}

fn start_background_save(app: &mut AutoLoginApp, ctx: &egui::Context) {
    if app.pending_settings_save.is_some() {
        ctx.request_repaint();
        return;
    }
    if settings_disabled_reason(app).is_some() {
        app.settings_draft = app.config.settings.clone();
        return;
    }
    start_background_save_with_deferred_sync(app, ctx, false, false);
}

fn start_background_save_with_deferred_sync(
    app: &mut AutoLoginApp,
    ctx: &egui::Context,
    local_sync_required: bool,
    refresh_passwords_required: bool,
) -> bool {
    // The visible draft is the coalescing queue. A click during an active save
    // updates it immediately; the completion path rebases those newer fields
    // onto the authoritative result and starts at most one follow-up save.
    if app.pending_settings_save.is_some() {
        ctx.request_repaint();
        return false;
    }
    if app.settings_save_fail_closed_reason().is_some() {
        app.settings_draft = app.config.settings.clone();
        return false;
    }
    let executor = match app.background_mutation_executor() {
        Ok(executor) => executor,
        Err(error) => {
            warn!(%error, "The background settings executor is unavailable");
            // A terminal executor failure must discard every queued mutation.
            // Otherwise Save/Delete intents (including Zeroizing passwords)
            // keep close/quit waiting forever even though no successor can run.
            app.queued_account_transactions.clear();
            app.queued_account_toggles.clear();
            app.settings_draft = app.config.settings.clone();
            app.set_settings_changes_blocked_reason(Some(
                SETTINGS_JOB_DISCONNECTED_REASON.to_string(),
            ));
            return false;
        }
    };
    let Some(settings_mutation) = app.reserve_background_settings_mutation() else {
        app.settings_draft = app.config.settings.clone();
        return false;
    };
    let mutation_begin = app.prepare_background_settings_mutation_begin();
    let current_config = app.config.clone();
    let settings_draft = app.settings_draft.clone();
    let settings_window_mode = app.settings_window_mode();
    let repaint = ctx.clone();
    let receiver = match submit_settings_save_worker(
        executor,
        move || {
            run_settings_save_job(
                settings_mutation,
                settings_window_mode,
                move || mutation_begin.wait_for_quiescence(),
                single_instance::request_config_reload,
                || {
                    matches!(
                        crate::storage::pending_storage_recovery_is_clear(),
                        Ok(true)
                    ) && matches!(crate::storage::storage_recovery_block_is_clear(), Ok(true))
                },
                move || {
                    save_settings_transaction(
                        &current_config,
                        settings_draft,
                        autostart::set_enabled,
                        crate::storage::begin_storage_mode_migration_journal,
                        crate::storage::migrate_storage_mode,
                        crate::storage::save_config,
                        crate::storage::rollback_storage_mode_migration,
                        crate::storage::commit_storage_mode_migration,
                        crate::storage::clear_pending_storage_operation,
                        crate::storage::mark_storage_recovery_blocked,
                    )
                },
                move || signal_storage_recovery_block(settings_window_mode),
            )
        },
        repaint,
    ) {
        Ok(receiver) => receiver,
        Err(error) => {
            warn!(%error, "Could not submit the background settings save");
            app.queued_account_transactions.clear();
            app.queued_account_toggles.clear();
            app.settings_draft = app.config.settings.clone();
            app.status_message = None;
            app.reject_background_mutation_submission(
                local_sync_required,
                refresh_passwords_required,
            );
            ctx.request_repaint();
            return false;
        }
    };

    app.pending_settings_save = Some(PendingSettingsSave {
        receiver,
        requested_settings: app.settings_draft.clone(),
        queued_intent: QueuedSettingsIntent::default(),
        local_sync_required,
        refresh_passwords_required,
    });
    app.keep_window_open_for_pending_settings_save(ctx);
    ctx.request_repaint();
    true
}

fn submit_settings_save_worker<J>(
    executor: BackgroundMutationExecutor,
    job: J,
    repaint: egui::Context,
) -> std::io::Result<Receiver<SettingsSaveCompletion>>
where
    J: FnOnce() -> SettingsSaveCompletion + Send + 'static,
{
    let (sender, receiver) = mpsc::sync_channel(1);
    executor.try_submit(move || {
        let completion = job();
        let _ = sender.send(completion);
        repaint.request_repaint();
    })?;
    Ok(receiver)
}

fn run_settings_save_job<B, R, V, T, S>(
    mut settings_mutation: SettingsMutationGuard,
    settings_window_mode: bool,
    begin: B,
    reload: R,
    verify_storage_recovery_clear: V,
    transaction: T,
    signal_recovery_block: S,
) -> SettingsSaveCompletion
where
    B: FnOnce() -> anyhow::Result<()>,
    R: FnOnce() -> anyhow::Result<()>,
    V: FnOnce() -> bool,
    T: FnOnce() -> SettingsSaveTransactionResult,
    S: FnOnce() -> anyhow::Result<()>,
{
    if let Err(error) = begin() {
        warn!(%error, "The background settings save could not establish monitor quiescence");
        settings_mutation.finish_unacknowledged_begin();
        return SettingsSaveCompletion::BeginFailed;
    }
    settings_mutation.mark_begin_acknowledged();

    // From here a panic or disconnected result channel must leave the
    // supervisor paused. A verified clean transaction rejection explicitly
    // cancels below; Drop is deliberately fail-closed for every other path.
    settings_mutation.mark_fail_closed();
    let result = transaction();
    let recovery_pending = result.recovery_pending || !verify_storage_recovery_clear();

    if !result.applied && !recovery_pending {
        let blocked_reason = settings_mutation
            .cancel_verified_abort()
            .err()
            .map(|error| {
                warn!(%error, "A rejected background settings save could not be cancelled safely");
                SETTINGS_CANCEL_FAILED_REASON.to_string()
            });
        return SettingsSaveCompletion::Finished {
            result,
            recovery_pending,
            recovery_signal_confirmed: true,
            blocked_reason,
        };
    }

    if !result.applied {
        settings_mutation.mark_commit_started();
        let recovery_signal_confirmed = signal_recovery_block()
            .map_err(|error| {
                warn!(%error, "The rejected background settings save could not confirm the recovery block to every owner");
            })
            .is_ok();
        return SettingsSaveCompletion::Finished {
            result,
            recovery_pending: true,
            recovery_signal_confirmed,
            blocked_reason: Some(CONFIG_MUTATION_RECOVERY_REASON.to_string()),
        };
    }

    settings_mutation.mark_commit_started();
    let mut recovery_signal_confirmed = true;
    let blocked_reason = if recovery_pending {
        if let Err(error) = signal_recovery_block() {
            warn!(%error, "The background settings save could not confirm the recovery block to every owner");
            recovery_signal_confirmed = false;
        }
        Some(CONFIG_MUTATION_RECOVERY_REASON.to_string())
    } else if settings_window_mode && result.applied {
        reload().err().map(|error| {
            warn!(%error, "The background settings save committed, but supervisor reload acknowledgement failed");
            SETTINGS_RELOAD_FAILED_REASON.to_string()
        })
    } else {
        None
    };

    SettingsSaveCompletion::Finished {
        result,
        recovery_pending,
        recovery_signal_confirmed,
        blocked_reason,
    }
}

fn signal_storage_recovery_block(settings_window_mode: bool) -> anyhow::Result<()> {
    let persist_result = crate::storage::mark_storage_recovery_blocked();
    let signal_result = if settings_window_mode {
        single_instance::request_monitor_command(MonitorControlCommand::StorageRecoveryBlocked)
    } else {
        Ok(())
    };
    persist_result.and(signal_result)
}

pub(crate) fn poll_background_save(app: &mut AutoLoginApp, ctx: &egui::Context) {
    poll_background_save_with_recovery(
        app,
        ctx,
        start_background_save_with_deferred_sync,
        crate::ui::accounts::start_queued_background_account_work,
        AutoLoginApp::start_background_storage_recovery_signal,
    );
}

#[cfg(test)]
fn poll_background_save_with<S>(app: &mut AutoLoginApp, ctx: &egui::Context, mut start_follow_up: S)
where
    S: FnMut(&mut AutoLoginApp, &egui::Context, bool, bool) -> bool,
{
    poll_background_save_with_recovery(
        app,
        ctx,
        &mut start_follow_up,
        |_, _, _, _| false,
        AutoLoginApp::start_background_storage_recovery_signal,
    );
}

fn poll_background_save_with_recovery<S, A, B>(
    app: &mut AutoLoginApp,
    ctx: &egui::Context,
    mut start_follow_up: S,
    mut start_account_follow_up: A,
    mut begin_recovery_block: B,
) where
    S: FnMut(&mut AutoLoginApp, &egui::Context, bool, bool) -> bool,
    A: FnMut(&mut AutoLoginApp, &egui::Context, bool, bool) -> bool,
    B: FnMut(&mut AutoLoginApp, &egui::Context),
{
    let completion = match app
        .pending_settings_save
        .as_ref()
        .map(|pending| pending.receiver.try_recv())
    {
        None => return,
        Some(Err(TryRecvError::Empty)) => {
            ctx.request_repaint_after(Duration::from_millis(50));
            return;
        }
        Some(Err(TryRecvError::Disconnected)) => None,
        Some(Ok(completion)) => Some(completion),
    };
    let pending = app
        .pending_settings_save
        .take()
        .expect("a completed settings save must still be pending");
    let requested_settings = pending.requested_settings;
    let mut queued_intent = pending.queued_intent;
    let inherited_local_sync_required = pending.local_sync_required;
    let inherited_refresh_passwords_required = pending.refresh_passwords_required;
    let latest_settings_draft = app.settings_draft.clone();
    queued_intent.infer_unrecorded_changes(&requested_settings, &latest_settings_draft);

    let Some(completion) = completion else {
        app.queued_account_transactions.clear();
        app.queued_account_toggles.clear();
        app.set_settings_changes_blocked_reason(Some(SETTINGS_JOB_DISCONNECTED_REASON.to_string()));
        begin_recovery_block(app, ctx);
        return;
    };
    match completion {
        SettingsSaveCompletion::BeginFailed => {
            app.queued_account_transactions.clear();
            app.queued_account_toggles.clear();
            app.set_settings_changes_blocked_reason(Some(SETTINGS_BEGIN_FAILED_REASON.to_string()));
        }
        SettingsSaveCompletion::Finished {
            result,
            recovery_pending,
            recovery_signal_confirmed,
            blocked_reason,
        } => {
            let applied = result.applied;
            let storage_mode_changed = result.storage_mode_changed;
            let status = result.status;
            let local_sync_required = inherited_local_sync_required || applied;
            let refresh_passwords_required =
                inherited_refresh_passwords_required || (applied && storage_mode_changed);
            app.config = result.config;
            app.set_settings_changes_blocked_reason(blocked_reason);
            if recovery_pending {
                app.queued_account_transactions.clear();
                app.queued_account_toggles.clear();
                app.settings_draft = latest_settings_draft.clone();
                app.apply_background_storage_recovery_block();
                if !recovery_signal_confirmed {
                    begin_recovery_block(app, ctx);
                }
            } else if app.settings_save_fail_closed_reason().is_none() {
                app.settings_draft = rebase_latest_settings_intent(
                    &requested_settings,
                    &latest_settings_draft,
                    &queued_intent,
                    &result.settings_draft,
                );
                // Account Save/Delete/toggle intents are discrete accepted
                // actions. Give their FIFO the next lease before another
                // coalesced Settings successor so repeated checkbox clicks
                // cannot starve an accepted account transaction.
                let account_follow_up_started = start_account_follow_up(
                    app,
                    ctx,
                    local_sync_required,
                    refresh_passwords_required,
                );
                let account_follow_up_waiting = app.account_toggle_in_progress();
                let settings_follow_up_started = !account_follow_up_started
                    && !account_follow_up_waiting
                    && app.settings_draft != app.config.settings
                    && start_follow_up(app, ctx, local_sync_required, refresh_passwords_required);
                if !account_follow_up_started
                    && !account_follow_up_waiting
                    && !settings_follow_up_started
                    && !app.settings_window_mode()
                {
                    app.sync_background_saved_config_to_local_worker(refresh_passwords_required);
                }
            } else {
                // A fail-closed save invalidates queued intent. A verified
                // clean rejection reaches the branch above, where only an
                // explicit newer field intent may start a successor.
                app.queued_account_transactions.clear();
                app.queued_account_toggles.clear();
                app.settings_draft = latest_settings_draft;
            }
            if !status.trim().is_empty() {
                app.set_status(status);
            }
        }
    }
}

fn rebase_latest_settings_intent(
    requested: &AppSettings,
    latest: &AppSettings,
    queued_intent: &QueuedSettingsIntent,
    authoritative: &AppSettings,
) -> AppSettings {
    let mut queued_intent = queued_intent.clone();
    queued_intent.infer_unrecorded_changes(requested, latest);
    queued_intent.apply_to(authoritative)
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
            status_parts.push("Open at Login could not be updated.".to_string());
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
                "Disk durability could not be confirmed. Old password storage cleanup remains pending and will retry on next launch."
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
            "Disk durability could not be confirmed; the current state will be checked on next launch."
                .to_string(),
        );
    }

    let status = status_parts.join(" ");
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
        "Passwords were moved to {}, but some old {} cleanup is still pending and will retry on next launch. Stored credential changes are blocked until recovery completes.",
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
        poll_background_save, poll_background_save_with, poll_background_save_with_recovery,
        queue_or_start_background_save, rebase_latest_settings_intent, run_settings_save_job,
        save_settings_transaction, settings_disabled_reason, submit_settings_save_worker,
        PendingSettingsSave, QueuedSettingsIntent, SettingsSaveCompletion,
        SettingsSaveTransactionResult, SETTINGS_JOB_DISCONNECTED_REASON,
    };
    use crate::app::{AutoLoginApp, CONFIG_MUTATION_RECOVERY_REASON};
    use crate::background::{WorkerCommand, WorkerInvalidator, WorkerQuiescenceAck};
    use crate::models::{Account, AppConfig, AppSettings, FIXED_POLL_INTERVAL_SECS};
    use crate::storage::{storage_mode_migration_recovery_required_error, StorageModeMigration};
    use eframe::egui;
    use std::cell::{Cell, RefCell};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc::{channel, sync_channel, TryRecvError};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::mpsc::channel as tokio_channel;

    #[test]
    fn checkbox_save_path_is_background_and_has_no_close_policy() {
        let source = include_str!("settings.rs");
        let save_body = source
            .split_once("fn start_background_save(app: &mut AutoLoginApp")
            .and_then(|(_, tail)| tail.split_once("fn submit_settings_save_worker"))
            .map(|(body, _)| body)
            .expect("background save body must remain inspectable");

        assert!(save_body.contains("submit_settings_save_worker"));
        assert!(save_body.contains("app.keep_window_open_for_pending_settings_save(ctx);"));
        assert!(!save_body.contains("sync_saved_config_to_worker_and_close_settings"));
        assert!(!save_body.contains("ViewportCommand"));
    }

    #[test]
    fn pending_sync_description_is_absent_from_every_configuration_surface() {
        let removed_description = [
            "Configuration controls are temporarily unavailable ",
            "while synchronization is in progress.",
        ]
        .concat();

        assert!(!include_str!("../app.rs").contains(&removed_description));
        assert!(!include_str!("settings.rs").contains(&removed_description));
        assert!(!include_str!("accounts.rs").contains(&removed_description));
    }

    fn settings_test_app(settings_window_mode: bool) -> AutoLoginApp {
        let (worker_tx, _worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (_tray_tx, tray_rx) = channel();
        let mut app = AutoLoginApp::new(
            worker_tx,
            WorkerInvalidator::new().pause_latch(),
            tray_rx,
            worker_event_rx,
            AppConfig::default(),
            settings_window_mode,
            crate::models::Tab::Settings,
        );
        app.status_message = None;
        app
    }

    fn clean_settings_result(start_minimized: bool) -> SettingsSaveTransactionResult {
        let mut config = AppConfig::default();
        config.settings.start_minimized = start_minimized;
        SettingsSaveTransactionResult {
            settings_draft: config.settings.clone(),
            config,
            status: String::new(),
            applied: true,
            storage_mode_changed: false,
            recovery_pending: false,
        }
    }

    fn pending_save(
        receiver: std::sync::mpsc::Receiver<SettingsSaveCompletion>,
        requested_settings: AppSettings,
    ) -> PendingSettingsSave {
        PendingSettingsSave {
            receiver,
            requested_settings,
            queued_intent: QueuedSettingsIntent::default(),
            local_sync_required: false,
            refresh_passwords_required: false,
        }
    }

    #[test]
    fn blocking_begin_keeps_the_ui_owner_free_to_queue_latest_intent() {
        let mut app = settings_test_app(false);
        let guard = app
            .reserve_background_settings_mutation()
            .expect("test mutation must be reserved");
        let (begin_started_tx, begin_started_rx) = channel();
        let (release_begin_tx, release_begin_rx) = channel();

        let ctx = egui::Context::default();
        let receiver = submit_settings_save_worker(
            app.background_mutation_executor().unwrap(),
            move || {
                run_settings_save_job(
                    guard,
                    true,
                    move || {
                        begin_started_tx.send(()).unwrap();
                        release_begin_rx.recv().unwrap();
                        Ok(())
                    },
                    || Ok(()),
                    || true,
                    || clean_settings_result(true),
                    || Ok(()),
                )
            },
            ctx.clone(),
        )
        .expect("worker thread must start");
        app.pending_settings_save = Some(pending_save(receiver, app.settings_draft.clone()));

        begin_started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("background begin must start without blocking the owner");
        assert!(matches!(
            app.pending_settings_save
                .as_ref()
                .map(|pending| pending.receiver.try_recv()),
            Some(Err(TryRecvError::Empty))
        ));

        let before = app.settings_draft.clone();
        app.settings_draft.auto_start = true;
        queue_or_start_background_save(&mut app, &ctx, &before);

        assert!(app.settings_draft.auto_start);
        assert_eq!(
            app.pending_settings_save
                .as_ref()
                .and_then(|pending| pending.queued_intent.auto_start),
            Some(true)
        );
        assert!(app.status_message.is_none());

        release_begin_tx.send(()).unwrap();
        let pending = app
            .pending_settings_save
            .take()
            .expect("the original worker must remain the only active save");
        assert!(matches!(
            pending.receiver.recv_timeout(Duration::from_secs(1)),
            Ok(SettingsSaveCompletion::Finished { .. })
        ));
    }

    #[test]
    fn local_background_job_waits_for_quiescence_before_transaction() {
        let (worker_tx, mut worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (_tray_tx, tray_rx) = channel();
        let pause_latch = WorkerInvalidator::new().pause_latch();
        let mut app = AutoLoginApp::new(
            worker_tx,
            pause_latch.clone(),
            tray_rx,
            worker_event_rx,
            AppConfig::default(),
            false,
            crate::models::Tab::Settings,
        );
        let guard = app
            .reserve_background_settings_mutation()
            .expect("test mutation must be reserved");
        let begin = app.prepare_background_settings_mutation_begin();
        let pause_epoch = pause_latch.current_epoch();
        let (transaction_started_tx, transaction_started_rx) = channel();

        let completion = submit_settings_save_worker(
            app.background_mutation_executor().unwrap(),
            move || {
                run_settings_save_job(
                    guard,
                    false,
                    move || begin.wait_for_quiescence(),
                    || panic!("a local save must not request a supervisor reload"),
                    || true,
                    move || {
                        transaction_started_tx.send(()).unwrap();
                        clean_settings_result(true)
                    },
                    || panic!("a clean local save must not signal recovery"),
                )
            },
            egui::Context::default(),
        )
        .expect("settings worker must start");

        assert!(pause_latch.is_paused());
        let WorkerCommand::Quiesce {
            request_id,
            acknowledgement,
        } = worker_rx
            .blocking_recv()
            .expect("quiescence must be queued")
        else {
            panic!("expected local worker quiescence request");
        };
        assert_eq!(request_id, pause_epoch);
        assert!(transaction_started_rx.try_recv().is_err());
        assert!(matches!(completion.try_recv(), Err(TryRecvError::Empty)));

        acknowledgement
            .send(WorkerQuiescenceAck { request_id })
            .unwrap();
        transaction_started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("transaction must start after quiescence acknowledgement");
        assert!(matches!(
            completion.recv_timeout(Duration::from_secs(1)),
            Ok(SettingsSaveCompletion::Finished { .. })
        ));
    }

    #[test]
    fn pending_save_keeps_all_controls_interactive_while_serializing_commits() {
        let mut app = settings_test_app(false);
        let (_sender, receiver) = sync_channel(1);
        app.pending_settings_save = Some(pending_save(receiver, app.settings_draft.clone()));

        assert_eq!(settings_disabled_reason(&app), None);
        assert!(app.account_mutations_ready());
        assert_eq!(app.config_mutations_disabled_reason(), None);
        assert!(app.account_transaction_ready());

        let settings_before_input = app.settings_draft.clone();
        app.settings_draft.start_minimized = true;
        queue_or_start_background_save(&mut app, &egui::Context::default(), &settings_before_input);

        assert!(app.settings_draft.start_minimized);
        assert!(app.pending_settings_save.is_some());
        assert!(app.status_message.is_none());
    }

    #[test]
    fn fail_closed_reason_takes_precedence_over_pending_account_reason() {
        let mut app = settings_test_app(false);
        let (_sender, receiver) = sync_channel(1);
        app.pending_settings_save = Some(pending_save(receiver, app.settings_draft.clone()));
        app.set_settings_changes_blocked_reason(Some(SETTINGS_JOB_DISCONNECTED_REASON.to_string()));

        assert_eq!(
            settings_disabled_reason(&app).as_deref(),
            Some(SETTINGS_JOB_DISCONNECTED_REASON)
        );
        assert_eq!(
            app.config_mutations_disabled_reason(),
            Some(SETTINGS_JOB_DISCONNECTED_REASON)
        );
        assert!(!app.account_mutations_ready());
    }

    #[test]
    fn verified_clean_rejection_cancels_exactly_once() {
        let mut app = settings_test_app(false);
        let cancel_count = Arc::new(AtomicUsize::new(0));
        let count_for_cancel = cancel_count.clone();
        let guard = app
            .reserve_background_settings_mutation_with_cancel(move || {
                count_for_cancel.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .expect("test mutation must be reserved");
        let rejected = SettingsSaveTransactionResult {
            config: AppConfig::default(),
            settings_draft: AppSettings::default(),
            status: "Failed to save settings.".to_string(),
            applied: false,
            storage_mode_changed: false,
            recovery_pending: false,
        };

        let completion = run_settings_save_job(
            guard,
            true,
            || Ok(()),
            || panic!("a rejected transaction must not reload"),
            || true,
            || rejected,
            || panic!("a clean rejection must not signal recovery"),
        );

        assert!(matches!(
            completion,
            SettingsSaveCompletion::Finished {
                blocked_reason: None,
                ..
            }
        ));
        assert_eq!(cancel_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn ambiguous_rejection_signals_recovery_and_never_reloads_or_cancels() {
        let mut app = settings_test_app(false);
        let cancel_count = Arc::new(AtomicUsize::new(0));
        let count_for_cancel = cancel_count.clone();
        let guard = app
            .reserve_background_settings_mutation_with_cancel(move || {
                count_for_cancel.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .expect("test mutation must be reserved");
        let recovery_count = Arc::new(AtomicUsize::new(0));
        let count_for_recovery = recovery_count.clone();
        let rejected = SettingsSaveTransactionResult {
            config: AppConfig::default(),
            settings_draft: AppSettings::default(),
            status: "Storage recovery is required.".to_string(),
            applied: false,
            storage_mode_changed: false,
            recovery_pending: true,
        };

        let completion = run_settings_save_job(
            guard,
            true,
            || Ok(()),
            || panic!("an ambiguous rejection must not reload"),
            || false,
            || rejected,
            move || {
                count_for_recovery.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        );

        assert!(matches!(
            completion,
            SettingsSaveCompletion::Finished {
                recovery_pending: true,
                recovery_signal_confirmed: true,
                blocked_reason: Some(_),
                ..
            }
        ));
        assert_eq!(recovery_count.load(Ordering::SeqCst), 1);
        assert_eq!(cancel_count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn unconfirmed_settings_recovery_signal_is_retried_by_the_ui_owner() {
        let mut app = settings_test_app(true);
        let guard = app
            .reserve_background_settings_mutation_with_cancel(|| Ok(()))
            .expect("test mutation must be reserved");
        let rejected = SettingsSaveTransactionResult {
            config: app.config.clone(),
            settings_draft: app.settings_draft.clone(),
            status: "Storage recovery is required.".to_string(),
            applied: false,
            storage_mode_changed: false,
            recovery_pending: true,
        };
        let completion = run_settings_save_job(
            guard,
            true,
            || Ok(()),
            || panic!("an ambiguous rejection must not reload"),
            || false,
            || rejected,
            || anyhow::bail!("test recovery signal failure"),
        );
        let (sender, receiver) = sync_channel(1);
        sender.send(completion).unwrap();
        app.pending_settings_save = Some(pending_save(receiver, app.settings_draft.clone()));
        let recovery_count = Cell::new(0);

        poll_background_save_with_recovery(
            &mut app,
            &egui::Context::default(),
            |_, _, _, _| panic!("a recovery-pending save must not start a follow-up"),
            |_, _, _, _| panic!("a recovery-pending save must not start an account follow-up"),
            |app, _ctx| {
                recovery_count.set(recovery_count.get() + 1);
                app.apply_background_storage_recovery_block();
            },
        );

        assert_eq!(recovery_count.get(), 1);
        assert!(!app.account_mutations_ready());
    }

    #[test]
    fn successful_completion_reloads_once_and_never_creates_success_status() {
        let mut app = settings_test_app(true);
        let cancel_count = Arc::new(AtomicUsize::new(0));
        let count_for_cancel = cancel_count.clone();
        let guard = app
            .reserve_background_settings_mutation_with_cancel(move || {
                count_for_cancel.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .expect("test mutation must be reserved");
        let reload_count = Arc::new(AtomicUsize::new(0));
        let count_for_reload = reload_count.clone();

        let completion = run_settings_save_job(
            guard,
            true,
            || Ok(()),
            move || {
                count_for_reload.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            || true,
            || clean_settings_result(true),
            || panic!("a clean success must not signal recovery"),
        );
        let (sender, receiver) = sync_channel(1);
        sender.send(completion).unwrap();
        let mut requested_settings = app.config.settings.clone();
        requested_settings.start_minimized = true;
        app.settings_draft = requested_settings.clone();
        app.pending_settings_save = Some(pending_save(receiver, requested_settings));
        app.status_message = None;

        poll_background_save(&mut app, &egui::Context::default());

        assert!(app.config.settings.start_minimized);
        assert!(app.status_message.is_none());
        assert!(app.pending_settings_save.is_none());
        assert_eq!(reload_count.load(Ordering::SeqCst), 1);
        assert_eq!(cancel_count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn disconnected_save_fails_closed_and_explains_why_controls_are_disabled() {
        let mut app = settings_test_app(true);
        app.settings_draft.start_minimized = true;
        let queued_settings = app.settings_draft.clone();
        let (sender, receiver) = sync_channel(1);
        drop(sender);
        app.pending_settings_save = Some(pending_save(receiver, app.config.settings.clone()));
        let recovery_count = Cell::new(0);

        poll_background_save_with_recovery(
            &mut app,
            &egui::Context::default(),
            |_, _, _, _| panic!("a disconnected save must not start a follow-up"),
            |_, _, _, _| panic!("a disconnected save must not start an account follow-up"),
            |app, _ctx| {
                recovery_count.set(recovery_count.get() + 1);
                app.apply_background_storage_recovery_block();
            },
        );

        assert_eq!(recovery_count.get(), 1);
        assert_eq!(app.settings_draft, queued_settings);
        assert_eq!(
            app.config_mutations_disabled_reason(),
            Some(SETTINGS_JOB_DISCONNECTED_REASON)
        );
        assert!(!app.account_mutations_ready());
    }

    #[test]
    fn stale_completion_preserves_latest_intent_and_starts_one_follow_up() {
        let mut app = settings_test_app(true);
        let mut requested = app.config.settings.clone();
        requested.start_minimized = true;
        let mut latest = requested.clone();
        latest.auto_start = true;
        app.settings_draft = latest.clone();

        let (sender, receiver) = sync_channel(1);
        sender
            .send(SettingsSaveCompletion::Finished {
                result: clean_settings_result(true),
                recovery_pending: false,
                recovery_signal_confirmed: true,
                blocked_reason: None,
            })
            .unwrap();
        app.pending_settings_save = Some(pending_save(receiver, requested));

        let follow_up_count = std::cell::Cell::new(0);
        poll_background_save_with(&mut app, &egui::Context::default(), |app, _ctx, _, _| {
            follow_up_count.set(follow_up_count.get() + 1);
            assert!(app.config.settings.start_minimized);
            assert!(!app.config.settings.auto_start);
            assert_eq!(app.settings_draft, latest);
            true
        });

        assert_eq!(follow_up_count.get(), 1);
        assert_eq!(app.settings_draft, latest);
        assert!(app.status_message.is_none());
    }

    #[test]
    fn latest_intent_equal_to_completed_target_elides_follow_up() {
        let mut app = settings_test_app(false);
        let mut requested = app.config.settings.clone();
        requested.start_minimized = true;
        app.settings_draft = requested.clone();
        let (sender, receiver) = sync_channel(1);
        sender
            .send(SettingsSaveCompletion::Finished {
                result: clean_settings_result(true),
                recovery_pending: false,
                recovery_signal_confirmed: true,
                blocked_reason: None,
            })
            .unwrap();
        app.pending_settings_save = Some(pending_save(receiver, requested));

        poll_background_save_with(&mut app, &egui::Context::default(), |_, _, _, _| {
            panic!("an unchanged latest target must not start another save")
        });

        assert_eq!(app.settings_draft, app.config.settings);
        assert!(app.pending_settings_save.is_none());
    }

    #[test]
    fn queued_revert_to_original_runs_after_first_target_commits() {
        let mut app = settings_test_app(false);
        let original = app.config.settings.clone();
        let mut requested = original.clone();
        requested.start_minimized = true;
        app.settings_draft = original.clone();
        let (sender, receiver) = sync_channel(1);
        sender
            .send(SettingsSaveCompletion::Finished {
                result: clean_settings_result(true),
                recovery_pending: false,
                recovery_signal_confirmed: true,
                blocked_reason: None,
            })
            .unwrap();
        app.pending_settings_save = Some(pending_save(receiver, requested));

        let follow_up_count = std::cell::Cell::new(0);
        poll_background_save_with(&mut app, &egui::Context::default(), |app, _ctx, _, _| {
            follow_up_count.set(follow_up_count.get() + 1);
            assert!(app.config.settings.start_minimized);
            assert_eq!(app.settings_draft, original);
            true
        });

        assert_eq!(follow_up_count.get(), 1);
        assert_eq!(app.settings_draft, original);
    }

    #[test]
    fn latest_multi_field_intent_rebases_only_fields_changed_during_save() {
        let original = AppSettings::default();
        let mut requested = original.clone();
        requested.auto_start = true;
        requested.start_minimized = true;
        requested.use_keyring = false;

        let mut latest = requested.clone();
        latest.auto_start = false;
        latest.use_keyring = true;

        let mut authoritative = requested.clone();
        authoritative.auto_start = false;

        let rebased = rebase_latest_settings_intent(
            &requested,
            &latest,
            &QueuedSettingsIntent::default(),
            &authoritative,
        );

        assert!(!rebased.auto_start);
        assert!(rebased.start_minimized);
        assert!(rebased.use_keyring);
        assert_eq!(rebased.poll_interval_secs, FIXED_POLL_INTERVAL_SECS);
    }

    #[test]
    fn explicit_toggle_away_and_back_survives_partial_active_result() {
        let requested = AppSettings {
            auto_start: true,
            ..AppSettings::default()
        };
        let latest = requested.clone();
        let mut authoritative = requested.clone();
        authoritative.auto_start = false;
        let mut queued_intent = QueuedSettingsIntent::default();

        let mut away = requested.clone();
        away.auto_start = false;
        queued_intent.record_changes(&requested, &away);
        queued_intent.record_changes(&away, &latest);

        let rebased =
            rebase_latest_settings_intent(&requested, &latest, &queued_intent, &authoritative);

        assert!(rebased.auto_start);
        assert_ne!(rebased, authoritative);
    }

    #[test]
    fn clean_rejection_does_not_retry_the_failed_active_target() {
        let mut app = settings_test_app(false);
        let mut requested = app.config.settings.clone();
        requested.start_minimized = true;
        app.settings_draft = requested.clone();
        let rejected = SettingsSaveTransactionResult {
            config: app.config.clone(),
            settings_draft: app.config.settings.clone(),
            status: "Failed to save settings.".to_string(),
            applied: false,
            storage_mode_changed: false,
            recovery_pending: false,
        };
        let (sender, receiver) = sync_channel(1);
        sender
            .send(SettingsSaveCompletion::Finished {
                result: rejected,
                recovery_pending: false,
                recovery_signal_confirmed: true,
                blocked_reason: None,
            })
            .unwrap();
        app.pending_settings_save = Some(pending_save(receiver, requested));

        poll_background_save_with(&mut app, &egui::Context::default(), |_, _, _, _| {
            panic!("a rejected save must clear queued intent")
        });

        assert_eq!(app.settings_draft, app.config.settings);
        assert_eq!(
            app.status_message
                .as_ref()
                .map(|(message, _)| message.as_str()),
            Some("Failed to save settings.")
        );
    }

    #[test]
    fn clean_local_rejection_releases_authoritative_config_on_original_epoch() {
        let (worker_tx, mut worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (_tray_tx, tray_rx) = channel();
        let pause_latch = WorkerInvalidator::new().pause_latch();
        let mut app = AutoLoginApp::new(
            worker_tx,
            pause_latch.clone(),
            tray_rx,
            worker_event_rx,
            AppConfig::default(),
            false,
            crate::models::Tab::Settings,
        );
        let begin = app.prepare_background_settings_mutation_begin();
        let pause_epoch = pause_latch.current_epoch();
        drop(begin);
        let mut requested = app.config.settings.clone();
        requested.start_minimized = true;
        app.settings_draft = requested.clone();
        let rejected = SettingsSaveTransactionResult {
            config: app.config.clone(),
            settings_draft: app.config.settings.clone(),
            status: "Failed to save settings.".to_string(),
            applied: false,
            storage_mode_changed: false,
            recovery_pending: false,
        };
        let (sender, receiver) = sync_channel(1);
        sender
            .send(SettingsSaveCompletion::Finished {
                result: rejected,
                recovery_pending: false,
                recovery_signal_confirmed: true,
                blocked_reason: None,
            })
            .unwrap();
        app.pending_settings_save = Some(pending_save(receiver, requested));

        poll_background_save_with(&mut app, &egui::Context::default(), |_, _, _, _| {
            panic!("the rejected target must not be retried")
        });

        match worker_rx.try_recv().expect("one final release is required") {
            WorkerCommand::ApplyConfigAndReleasePause {
                settings,
                accounts,
                pause_epoch: released_epoch,
                ..
            } => {
                assert_eq!(released_epoch, pause_epoch);
                assert_eq!(settings, app.config.settings);
                assert_eq!(accounts, app.config.accounts);
            }
            other => panic!("expected one authoritative config release, got {other:?}"),
        }
        assert!(worker_rx.try_recv().is_err());
    }

    #[test]
    fn clean_rejection_preserves_a_distinct_explicit_queued_intent() {
        let mut app = settings_test_app(true);
        let mut requested = app.config.settings.clone();
        requested.start_minimized = true;
        let mut latest = requested.clone();
        latest.auto_start = true;
        app.settings_draft = latest.clone();
        let rejected = SettingsSaveTransactionResult {
            config: app.config.clone(),
            settings_draft: app.config.settings.clone(),
            status: "Failed to save settings.".to_string(),
            applied: false,
            storage_mode_changed: false,
            recovery_pending: false,
        };
        let (sender, receiver) = sync_channel(1);
        sender
            .send(SettingsSaveCompletion::Finished {
                result: rejected,
                recovery_pending: false,
                recovery_signal_confirmed: true,
                blocked_reason: None,
            })
            .unwrap();
        let mut pending = pending_save(receiver, requested.clone());
        pending.queued_intent.record_changes(&requested, &latest);
        app.pending_settings_save = Some(pending);

        let follow_up_count = std::cell::Cell::new(0);
        poll_background_save_with(&mut app, &egui::Context::default(), |app, _, _, _| {
            follow_up_count.set(follow_up_count.get() + 1);
            assert!(!app.settings_draft.start_minimized);
            assert!(app.settings_draft.auto_start);
            true
        });

        assert_eq!(follow_up_count.get(), 1);
        assert!(!app.settings_draft.start_minimized);
        assert!(app.settings_draft.auto_start);
    }

    #[test]
    fn local_worker_receives_only_the_final_coalesced_config() {
        let (worker_tx, mut worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (_tray_tx, tray_rx) = channel();
        let pause_latch = WorkerInvalidator::new().pause_latch();
        let mut app = AutoLoginApp::new(
            worker_tx,
            pause_latch.clone(),
            tray_rx,
            worker_event_rx,
            AppConfig::default(),
            false,
            crate::models::Tab::Settings,
        );
        app.status_message = None;
        let begin = app.prepare_background_settings_mutation_begin();
        let pause_epoch = pause_latch.current_epoch();
        drop(begin);

        let mut first_target = app.config.settings.clone();
        first_target.start_minimized = true;
        let mut latest = first_target.clone();
        latest.auto_start = true;
        app.settings_draft = latest.clone();
        let mut first_result = clean_settings_result(true);
        first_result.storage_mode_changed = true;
        let (sender, receiver) = sync_channel(1);
        sender
            .send(SettingsSaveCompletion::Finished {
                result: first_result,
                recovery_pending: false,
                recovery_signal_confirmed: true,
                blocked_reason: None,
            })
            .unwrap();
        app.pending_settings_save = Some(pending_save(receiver, first_target));

        poll_background_save_with(
            &mut app,
            &egui::Context::default(),
            |app, _, local_sync_required, refresh_passwords_required| {
                assert!(local_sync_required);
                assert!(refresh_passwords_required);
                assert!(worker_rx.try_recv().is_err());

                let mut final_config = app.config.clone();
                final_config.settings = app.settings_draft.clone();
                let final_result = SettingsSaveTransactionResult {
                    settings_draft: final_config.settings.clone(),
                    config: final_config,
                    status: String::new(),
                    applied: true,
                    storage_mode_changed: false,
                    recovery_pending: false,
                };
                let (sender, receiver) = sync_channel(1);
                sender
                    .send(SettingsSaveCompletion::Finished {
                        result: final_result,
                        recovery_pending: false,
                        recovery_signal_confirmed: true,
                        blocked_reason: None,
                    })
                    .unwrap();
                let mut pending = pending_save(receiver, app.settings_draft.clone());
                pending.local_sync_required = local_sync_required;
                pending.refresh_passwords_required = refresh_passwords_required;
                app.pending_settings_save = Some(pending);
                true
            },
        );

        assert!(worker_rx.try_recv().is_err());
        poll_background_save_with(&mut app, &egui::Context::default(), |_, _, _, _| {
            panic!("the final target must drain without another save")
        });

        match worker_rx
            .try_recv()
            .expect("one final worker sync is required")
        {
            WorkerCommand::ApplyConfigAndReleasePause {
                settings,
                refresh_passwords,
                pause_epoch: released_epoch,
                ..
            } => {
                assert_eq!(settings, latest);
                assert!(refresh_passwords);
                assert_eq!(released_epoch, pause_epoch);
            }
            other => panic!("expected one atomic final config apply, got {other:?}"),
        }
        assert!(worker_rx.try_recv().is_err());
    }

    #[test]
    fn start_minimized_checkbox_transaction_saves_both_values_without_other_side_effects() {
        for initial_value in [false, true] {
            let mut config = AppConfig::default();
            config.settings.start_minimized = initial_value;
            let mut draft = config.settings.clone();
            draft.start_minimized = !initial_value;
            let saved_config = RefCell::new(None);

            let result = save_settings_transaction(
                &config,
                draft,
                |_| panic!("start_minimized must not change autostart"),
                |_, _, _| panic!("start_minimized must not start a storage journal"),
                |_, _, _| panic!("start_minimized must not migrate password storage"),
                |next_config| {
                    saved_config.replace(Some(next_config.clone()));
                    Ok(())
                },
                |_| panic!("start_minimized must not roll back password storage"),
                |_| panic!("start_minimized must not commit password storage cleanup"),
                || panic!("start_minimized must not clear a storage journal"),
                || panic!("start_minimized must not mark storage recovery blocked"),
            );

            assert!(result.applied);
            assert!(!result.storage_mode_changed);
            assert!(!result.recovery_pending);
            assert!(result.status.is_empty());
            assert_eq!(result.config.settings.start_minimized, !initial_value);
            assert_eq!(result.settings_draft.start_minimized, !initial_value);
            assert_eq!(
                saved_config
                    .borrow()
                    .as_ref()
                    .map(|saved| saved.settings.start_minimized),
                Some(!initial_value)
            );
        }
    }

    #[test]
    fn recovery_state_disables_every_setting_with_a_specific_reason() {
        let app = settings_test_app(false).with_storage_recovery_state(false);

        assert_eq!(
            settings_disabled_reason(&app).as_deref(),
            Some(CONFIG_MUTATION_RECOVERY_REASON)
        );
        assert!(!app.account_mutations_ready());
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
        assert!(result.applied && result.recovery_pending);
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
        assert!(result.status.contains("Open at Login could not be updated"));
        assert!(!result.status.contains("Settings saved"));
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
