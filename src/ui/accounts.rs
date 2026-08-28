use crate::app::{
    AutoLoginApp, BackgroundMutationExecutor, SettingsMutationGuard,
    CONFIG_MUTATION_RECOVERY_REASON,
};
use crate::models::{Account, AccountId, AppConfig};
use crate::single_instance;
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
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

const ACCOUNT_TOGGLE_BEGIN_FAILED_REASON: &str =
    "Account changes are unavailable because the monitor could not pause safely. Restart the app to try again.";
const ACCOUNT_TOGGLE_CANCEL_FAILED_REASON: &str =
    "Account changes are unavailable because the failed update could not be cancelled safely. Restart the app before changing accounts again.";
const ACCOUNT_TOGGLE_RELOAD_FAILED_REASON: &str =
    "Account changes are unavailable because the monitor could not confirm the current configuration. Restart the app before changing accounts again.";
const ACCOUNT_TOGGLE_JOB_DISCONNECTED_REASON: &str =
    "Account changes are unavailable because the background update did not finish safely. Restart the app before changing accounts again.";
const ACCOUNT_TRANSACTION_IN_PROGRESS_REASON: &str =
    "Wait for the current account or settings update to finish.";

const STATE_COLUMN_WIDTH: f32 = 88.0;
const TABLE_SPACING: f32 = 8.0;
const EDIT_BUTTON_WIDTH: f32 = 40.0;
const DELETE_BUTTON_WIDTH: f32 = 40.0;
const ROW_BUTTON_HEIGHT: f32 = 30.0;
const ACTIONS_COLUMN_WIDTH: f32 = EDIT_BUTTON_WIDTH + TABLE_SPACING + DELETE_BUTTON_WIDTH;
const ACCOUNT_ROW_HEIGHT: f32 = 36.0;
const ACCOUNT_EDITOR_WIDTH: f32 = 430.0;
const ACCOUNT_EDITOR_LABEL_WIDTH: f32 = 82.0;
const ACCOUNT_EDITOR_FIELD_WIDTH: f32 = 332.0;
const ACCOUNT_EDITOR_CONTROL_HEIGHT: f32 = 28.0;
const ACCOUNT_EDITOR_TOGGLE_WIDTH: f32 = 38.0;
const ACTION_ICON_SIZE: f32 = 17.0;
const PASSWORD_ICON_SIZE: f32 = 18.0;
const PASSWORD_EDITOR_ID_SALT: &str = "account_password_editor";
const PASSWORD_EDITOR_MAX_BYTES: usize = 4096;
const ACCOUNT_TOGGLE_BURST_QUIET_PERIOD: Duration = Duration::from_millis(75);
const ACCOUNT_TOGGLE_BURST_MAX_COALESCE_PERIOD: Duration = Duration::from_millis(250);
const ACCOUNT_TOGGLE_START_RETRY_DELAY: Duration = Duration::from_secs(1);
const ACCOUNT_TOGGLE_INTENT_QUEUE_CAPACITY: usize = 16;
const PENCIL_ICON: &[u8] = include_bytes!("../../assets/icons/pencil.svg");
const TRASH_ICON: &[u8] = include_bytes!("../../assets/icons/trash.svg");
const EYE_ICON: &[u8] = include_bytes!("../../assets/icons/eye.svg");
const EYE_OFF_ICON: &[u8] = include_bytes!("../../assets/icons/eye-off.svg");

pub fn show(ui: &mut egui::Ui, app: &mut AutoLoginApp) {
    let mut row_actions = AccountRowActions::default();
    let mut account_to_delete: Option<AccountId> = None;
    let modal_open = app.editing_account.is_some() || app.confirm_delete_account.is_some();
    let availability = account_control_availability(app);
    let toggle_controls_enabled = !modal_open && availability.toggle_controls_ready;
    let launch_controls_enabled = !modal_open && availability.launch_controls_ready;
    let projected_enabled_states = projected_account_enabled_states(app);

    let account_count = app.config.accounts.len();
    theme::page_header(
        ui,
        "Accounts",
        &format!("{account_count} saved account(s) monitored through Windows App."),
        |ui| {
            let add_account = ui.add_enabled(
                launch_controls_enabled,
                theme::primary_button("+ Add Account").min_size(egui::vec2(182.0, 30.0)),
            );
            if with_transaction_disabled_reason(
                add_account,
                launch_controls_disabled_reason(&availability),
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
                let add_account = ui.add_enabled(
                    launch_controls_enabled,
                    theme::primary_button("+ Add Account").min_size(egui::vec2(182.0, 30.0)),
                );
                if with_transaction_disabled_reason(
                    add_account,
                    launch_controls_disabled_reason(&availability),
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
                        let displayed_enabled = projected_enabled_states
                            .get(&account.id)
                            .copied()
                            .unwrap_or(account.enabled);
                        show_account_row(
                            ui,
                            account,
                            displayed_enabled,
                            toggle_controls_enabled,
                            launch_controls_enabled,
                            launch_controls_disabled_reason(&availability),
                            &mut row_actions,
                        );
                        if idx + 1 < app.config.accounts.len() {
                            ui.separator();
                        }
                    }
                });
            });
    }

    if !availability.toggle_controls_ready {
        ui.add_space(8.0);
        if let Some(reason) = app.config_mutations_disabled_reason() {
            ui.label(theme::muted(reason));
        }
    }

    if let Some(account) = row_actions.edit_account.take() {
        open_account_editor(ui.ctx(), app, account);
    }

    if let Some(account_id) = row_actions.confirm_delete_account.take() {
        app.confirm_delete_account = Some(account_id);
    }

    for (account_id, enabling) in std::mem::take(&mut row_actions.toggle_enabled) {
        if let Some(account) = app
            .config
            .accounts
            .iter()
            .find(|account| account.id == account_id)
        {
            if let Some(error) = eager_account_toggle_validation_error(app, account, enabling) {
                app.set_status(error);
            } else {
                request_background_account_toggle(app, ui.ctx(), account_id, enabling);
            }
        }
    }

    show_delete_confirmation(ui, app, &mut account_to_delete);

    if let Some(account_id) = account_to_delete {
        request_background_account_delete(app, ui.ctx(), account_id);
        app.confirm_delete_account = None;
    }

    show_account_editor(ui, app);
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AccountControlAvailability {
    toggle_controls_ready: bool,
    launch_controls_ready: bool,
    transaction_controls_ready: bool,
    transaction_disabled_reason: Option<String>,
}

fn account_control_availability(app: &AutoLoginApp) -> AccountControlAvailability {
    let toggle_controls_ready = app.account_mutations_ready();
    // Presentation and final Save/Delete clicks remain responsive while a
    // checkbox save owns the durable mutation lease. Durable work is
    // serialized by the shared background FIFO, not by disabling controls.
    let launch_controls_ready = toggle_controls_ready;
    let transaction_controls_ready = app.account_transaction_ready();
    let transaction_disabled_reason = if transaction_controls_ready {
        None
    } else {
        Some(
            app.config_mutations_disabled_reason()
                .unwrap_or(ACCOUNT_TRANSACTION_IN_PROGRESS_REASON)
                .to_string(),
        )
    };
    AccountControlAvailability {
        toggle_controls_ready,
        launch_controls_ready,
        transaction_controls_ready,
        transaction_disabled_reason,
    }
}

fn launch_controls_disabled_reason(availability: &AccountControlAvailability) -> Option<&str> {
    (!availability.launch_controls_ready)
        .then_some(availability.transaction_disabled_reason.as_deref())
        .flatten()
}

fn with_transaction_disabled_reason(
    response: egui::Response,
    disabled_reason: Option<&str>,
) -> egui::Response {
    match disabled_reason {
        Some(reason) => response.on_disabled_hover_text(reason),
        None => response,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AccountToggleIntent {
    sequence: u64,
    account_id: AccountId,
    enabled: bool,
}

pub(crate) struct PendingAccountToggle {
    receiver: Receiver<AccountToggleCompletion>,
    intent_sender: SyncSender<AccountToggleIntent>,
    base_config: AppConfig,
    displayed_intents: Vec<AccountToggleIntent>,
    deferred_local_sync_required: bool,
    deferred_refresh_passwords_required: bool,
}

pub(crate) enum AccountTransactionIntent {
    Save {
        sequence: u64,
        account: Account,
        was_existing: bool,
        password: Option<Zeroizing<String>>,
    },
    Delete {
        sequence: u64,
        account_id: AccountId,
    },
}

impl AccountTransactionIntent {
    fn sequence(&self) -> u64 {
        match self {
            Self::Save { sequence, .. } | Self::Delete { sequence, .. } => *sequence,
        }
    }
}

pub(crate) struct PendingAccountTransaction {
    receiver: Receiver<AccountTransactionCompletion>,
    base_config: AppConfig,
    deferred_local_sync_required: bool,
    deferred_refresh_passwords_required: bool,
}

#[cfg(test)]
impl PendingAccountTransaction {
    pub(crate) fn inert_for_test(base_config: AppConfig) -> Self {
        let (sender, receiver) = mpsc::sync_channel(1);
        std::mem::forget(sender);
        Self {
            receiver,
            base_config,
            deferred_local_sync_required: false,
            deferred_refresh_passwords_required: false,
        }
    }
}

enum AccountTransactionCompletion {
    BeginFailed { status: String },
    Finished(AccountTransactionJobResult),
}

struct AccountTransactionJobResult {
    config: AppConfig,
    status: Option<String>,
    applied: bool,
    refresh_passwords: bool,
    recovery_pending: bool,
    recovery_signal_confirmed: bool,
    blocked_reason: Option<String>,
}

struct AccountTransactionResult {
    config: AppConfig,
    status: Option<String>,
    applied: bool,
    refresh_passwords: bool,
    recovery_pending: bool,
}

impl PendingAccountToggle {
    fn displayed_enabled(&self, account: &Account) -> Option<(u64, bool)> {
        latest_account_toggle_intent(&self.displayed_intents, &account.id)
            .map(|intent| (intent.sequence, intent.enabled))
    }

    fn record_intent(&mut self, intent: AccountToggleIntent) {
        record_latest_account_toggle_intent(&mut self.displayed_intents, intent.clone());
        // An unbounded std channel send only copies the small non-secret
        // intent into memory. If the worker has just finalized, keeping the
        // intent in displayed_intents lets the owner start a successor after
        // it receives the completion.
        // Never wait on the channel's internal mutex from an egui callback.
        // If a burst fills this bounded queue, displayed_intents still retains
        // the newest value and completion starts one authoritative successor.
        let _ = self.intent_sender.try_send(intent);
    }

    #[cfg(test)]
    pub(crate) fn inert_for_test(base_config: AppConfig) -> Self {
        let (sender, receiver) = mpsc::sync_channel(1);
        std::mem::forget(sender);
        let (intent_sender, intent_receiver) = mpsc::sync_channel(1);
        std::mem::forget(intent_receiver);
        let displayed_intents = base_config
            .accounts
            .first()
            .map(|account| AccountToggleIntent {
                sequence: 1,
                account_id: account.id.clone(),
                enabled: !account.enabled,
            })
            .into_iter()
            .collect();
        Self {
            receiver,
            intent_sender,
            base_config,
            displayed_intents,
            deferred_local_sync_required: false,
            deferred_refresh_passwords_required: false,
        }
    }
}

enum AccountToggleCompletion {
    BeginFailed { status: String },
    Finished(AccountToggleJobResult),
}

struct AccountToggleJobResult {
    config: AppConfig,
    status: Option<String>,
    applied: bool,
    failed_intent: Option<AccountToggleIntent>,
    recovery_pending: bool,
    recovery_signal_confirmed: bool,
    blocked_reason: Option<String>,
}

#[derive(Debug)]
struct AccountToggleBatchResult {
    config: AppConfig,
    status: Option<String>,
    applied: bool,
    failed_intent: Option<AccountToggleIntent>,
    config_durability_warning: bool,
    journal_cleanup_warning: bool,
}

fn latest_account_toggle_intent<'a>(
    intents: &'a [AccountToggleIntent],
    account_id: &str,
) -> Option<&'a AccountToggleIntent> {
    intents
        .iter()
        .filter(|intent| intent.account_id == account_id)
        .max_by_key(|intent| intent.sequence)
}

fn record_latest_account_toggle_intent(
    intents: &mut Vec<AccountToggleIntent>,
    intent: AccountToggleIntent,
) {
    intents.retain(|existing| existing.account_id != intent.account_id);
    intents.push(intent);
}

fn record_queued_account_toggle_intent(app: &mut AutoLoginApp, intent: AccountToggleIntent) {
    // Save/Delete intents are ordering barriers. Coalesce only with toggles in
    // the same segment after the most recent barrier; otherwise
    // OFF -> Save -> ON could incorrectly erase the OFF that Save must observe.
    let segment_start = app
        .queued_account_transactions
        .iter()
        .map(AccountTransactionIntent::sequence)
        .filter(|sequence| *sequence < intent.sequence)
        .max()
        .unwrap_or(0);
    app.queued_account_toggles.retain(|existing| {
        existing.account_id != intent.account_id || existing.sequence <= segment_start
    });
    app.queued_account_toggles.push(intent);
}

fn projected_account_enabled(app: &AutoLoginApp, account: &Account) -> bool {
    let active = app
        .pending_account_toggle
        .as_ref()
        .and_then(|pending| pending.displayed_enabled(account));
    let queued = latest_account_toggle_intent(&app.queued_account_toggles, &account.id)
        .map(|intent| (intent.sequence, intent.enabled));
    match (active, queued) {
        (Some(active), Some(queued)) => {
            if active.0 >= queued.0 {
                active.1
            } else {
                queued.1
            }
        }
        (Some(active), None) => active.1,
        (None, Some(queued)) => queued.1,
        (None, None) => account.enabled,
    }
}

fn projected_account_enabled_states(app: &AutoLoginApp) -> HashMap<AccountId, bool> {
    let mut states: HashMap<AccountId, bool> = app
        .config
        .accounts
        .iter()
        .map(|account| (account.id.clone(), account.enabled))
        .collect();
    let mut latest_intents: HashMap<&str, (u64, bool)> = HashMap::new();
    let active_intents = app
        .pending_account_toggle
        .as_ref()
        .into_iter()
        .flat_map(|pending| pending.displayed_intents.iter());
    for intent in active_intents.chain(app.queued_account_toggles.iter()) {
        let latest = latest_intents
            .entry(intent.account_id.as_str())
            .or_insert((intent.sequence, intent.enabled));
        if intent.sequence >= latest.0 {
            *latest = (intent.sequence, intent.enabled);
        }
    }
    for (account_id, (_, enabled)) in latest_intents {
        if let Some(state) = states.get_mut(account_id) {
            *state = enabled;
        }
    }
    states
}

fn projected_enabled_email_conflict(
    app: &AutoLoginApp,
    account_id: &str,
    candidate_email: &str,
) -> bool {
    app.config.accounts.iter().any(|other| {
        other.id != account_id
            && projected_account_enabled(app, other)
            && other
                .username
                .trim()
                .eq_ignore_ascii_case(candidate_email.trim())
    })
}

fn eager_account_toggle_validation_error(
    app: &AutoLoginApp,
    account: &Account,
    enabling: bool,
) -> Option<&'static str> {
    if !enabling {
        return None;
    }
    // A preceding queued Save/Delete may change email/password metadata before
    // this toggle reaches the FIFO head. Accept the click now; the worker
    // validates against the authoritative post-predecessor configuration.
    if app.pending_account_transaction.is_some() || !app.queued_account_transactions.is_empty() {
        return None;
    }
    if account.username.trim().is_empty() {
        return Some("Email is required");
    }
    if !account.has_saved_password {
        return Some("Password is required before enabling this account");
    }
    if projected_enabled_email_conflict(app, &account.id, account.username.trim()) {
        return Some("An enabled account with this email already exists");
    }
    None
}

fn validate_authoritative_account_toggle(
    config: &AppConfig,
    account: &Account,
    enabling: bool,
) -> Result<(), String> {
    if !enabling {
        return Ok(());
    }
    if account.username.trim().is_empty() {
        return Err("Email is required".to_string());
    }
    if !account.has_saved_password {
        return Err("Password is required before enabling this account".to_string());
    }
    if config.accounts.iter().any(|other| {
        other.id != account.id && enabled_account_conflicts_with_candidate(other, &account.username)
    }) {
        return Err("An enabled account with this email already exists".to_string());
    }
    Ok(())
}

fn next_account_toggle_sequence(app: &mut AutoLoginApp) -> u64 {
    app.next_account_toggle_intent_sequence =
        app.next_account_toggle_intent_sequence.wrapping_add(1);
    if app.next_account_toggle_intent_sequence == 0 {
        app.next_account_toggle_intent_sequence = 1;
    }
    app.next_account_toggle_intent_sequence
}

fn request_background_account_toggle(
    app: &mut AutoLoginApp,
    ctx: &egui::Context,
    account_id: AccountId,
    enabled: bool,
) {
    let intent = AccountToggleIntent {
        sequence: next_account_toggle_sequence(app),
        account_id,
        enabled,
    };
    if app.account_toggle_failure_status_sequence.take().is_some() {
        app.status_message = None;
    }
    if app.pending_account_toggle.is_some() {
        let transaction_precedes_intent = app
            .queued_account_transactions
            .front()
            .is_some_and(|transaction| transaction.sequence() < intent.sequence);
        if transaction_precedes_intent {
            record_queued_account_toggle_intent(app, intent);
        } else {
            app.pending_account_toggle
                .as_mut()
                .expect("the active toggle must still be pending")
                .record_intent(intent);
        }
        ctx.request_repaint();
        return;
    }

    // A fresh user action may retry immediately after a transient executor
    // submission failure; automatic retries remain throttled below.
    app.account_toggle_start_retry_at = None;
    record_queued_account_toggle_intent(app, intent);
    // Schedule the optimistic repaint before preparing the owned background
    // job. Everything below is allocation-only plus a bounded `try_send`.
    ctx.request_repaint();
    let _ = start_queued_background_account_work(app, ctx, false, false);
}

fn request_background_account_delete(
    app: &mut AutoLoginApp,
    ctx: &egui::Context,
    account_id: AccountId,
) {
    if !app.account_transaction_ready() {
        return;
    }
    let sequence = next_account_toggle_sequence(app);
    app.queued_account_transactions
        .push_back(AccountTransactionIntent::Delete {
            sequence,
            account_id,
        });
    ctx.request_repaint();
    let _ = start_queued_background_account_work(app, ctx, false, false);
}

fn first_queued_toggle_sequence(app: &AutoLoginApp) -> Option<u64> {
    app.queued_account_toggles
        .iter()
        .map(|intent| intent.sequence)
        .min()
}

pub(crate) fn start_queued_background_account_work(
    app: &mut AutoLoginApp,
    ctx: &egui::Context,
    deferred_local_sync_required: bool,
    deferred_refresh_passwords_required: bool,
) -> bool {
    let toggle_sequence = first_queued_toggle_sequence(app);
    let transaction_sequence = app
        .queued_account_transactions
        .front()
        .map(AccountTransactionIntent::sequence);
    match (toggle_sequence, transaction_sequence) {
        (Some(toggle), Some(transaction)) if transaction < toggle => {
            start_queued_background_account_transaction(
                app,
                ctx,
                deferred_local_sync_required,
                deferred_refresh_passwords_required,
            )
        }
        (Some(_), _) => start_queued_background_account_toggle(
            app,
            ctx,
            deferred_local_sync_required,
            deferred_refresh_passwords_required,
        ),
        (None, Some(_)) => start_queued_background_account_transaction(
            app,
            ctx,
            deferred_local_sync_required,
            deferred_refresh_passwords_required,
        ),
        (None, None) => false,
    }
}

pub(crate) fn start_queued_background_account_toggle(
    app: &mut AutoLoginApp,
    ctx: &egui::Context,
    deferred_local_sync_required: bool,
    deferred_refresh_passwords_required: bool,
) -> bool {
    let executor = app.background_mutation_executor();
    start_queued_background_account_toggle_with_spawner(
        app,
        ctx,
        deferred_local_sync_required,
        deferred_refresh_passwords_required,
        move |job, repaint| match executor {
            Ok(executor) => submit_account_toggle_worker(executor, job, repaint),
            Err(error) => Err(error),
        },
    )
}

fn start_queued_background_account_toggle_with_spawner<S>(
    app: &mut AutoLoginApp,
    ctx: &egui::Context,
    deferred_local_sync_required: bool,
    deferred_refresh_passwords_required: bool,
    spawn_worker: S,
) -> bool
where
    S: FnOnce(
        Box<dyn FnOnce() -> AccountToggleCompletion + Send>,
        egui::Context,
    ) -> std::io::Result<Receiver<AccountToggleCompletion>>,
{
    if app.pending_account_toggle.is_some()
        || app.pending_account_transaction.is_some()
        || app.pending_settings_save.is_some()
        || app.settings_save_fail_closed_reason().is_some()
    {
        return false;
    }

    if let Some(retry_at) = app.account_toggle_start_retry_at {
        let now = Instant::now();
        if retry_at > now {
            ctx.request_repaint_after(retry_at.saturating_duration_since(now));
            return false;
        }
        app.account_toggle_start_retry_at = None;
    }

    app.queued_account_toggles.retain(|intent| {
        app.config
            .accounts
            .iter()
            .find(|account| account.id == intent.account_id)
            .is_some_and(|account| account.enabled != intent.enabled)
    });
    if app.queued_account_toggles.is_empty() {
        if app.account_toggle_failure_status_sequence.take().is_some() {
            app.status_message = None;
        }
        return false;
    }

    if app
        .queued_account_transactions
        .front()
        .is_some_and(|intent| {
            first_queued_toggle_sequence(app).is_some_and(|sequence| intent.sequence() < sequence)
        })
    {
        return false;
    }

    let transaction_cutoff = app
        .queued_account_transactions
        .front()
        .map(AccountTransactionIntent::sequence);
    let mut initial_intents = Vec::new();
    for intent in std::mem::take(&mut app.queued_account_toggles) {
        if transaction_cutoff.is_none_or(|cutoff| intent.sequence < cutoff) {
            initial_intents.push(intent);
        } else {
            record_queued_account_toggle_intent(app, intent);
        }
    }
    let Some(settings_mutation) = app.reserve_background_settings_mutation() else {
        defer_account_toggle_start_retry(app, ctx, initial_intents);
        return false;
    };
    let mutation_begin = app.prepare_background_settings_mutation_begin();

    let base_config = app.config.clone();
    let batch_base_config = base_config.clone();
    let settings_window_mode = app.settings_window_mode();
    let worker_initial_intents = initial_intents.clone();
    let (intent_sender, intent_receiver) = mpsc::sync_channel(ACCOUNT_TOGGLE_INTENT_QUEUE_CAPACITY);
    let repaint = ctx.clone();
    let receiver = match spawn_worker(
        Box::new(move || {
            run_account_toggle_job(
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
                    run_account_toggle_batch(
                        batch_base_config,
                        worker_initial_intents,
                        intent_receiver,
                        ACCOUNT_TOGGLE_BURST_QUIET_PERIOD,
                        ACCOUNT_TOGGLE_BURST_MAX_COALESCE_PERIOD,
                        |config, intent| {
                            let Some(idx) = config
                                .accounts
                                .iter()
                                .position(|account| account.id == intent.account_id)
                            else {
                                return Err("Account no longer exists".to_string());
                            };
                            let account = &config.accounts[idx];
                            validate_authoritative_account_toggle(config, account, intent.enabled)?;
                            toggle_account_transaction(
                                config,
                                idx,
                                intent.enabled,
                                begin_account_enabled_toggle_journal,
                                mark_account_enabled_toggle_committed_journal,
                                save_config,
                                clear_pending_storage_operation,
                            )
                        },
                    )
                },
                move || signal_account_toggle_recovery_block(settings_window_mode),
            )
        }),
        repaint,
    ) {
        Ok(receiver) => receiver,
        Err(error) => {
            tracing::warn!(%error, "Could not submit the background account update");
            app.queued_account_toggles.clear();
            app.queued_account_transactions.clear();
            app.account_toggle_start_retry_at = None;
            app.account_toggle_failure_status_sequence = None;
            app.status_message = None;
            app.reject_background_mutation_submission(
                deferred_local_sync_required,
                deferred_refresh_passwords_required,
            );
            ctx.request_repaint();
            return false;
        }
    };

    // Keep the durable configuration authoritative while the worker runs.
    // Only rendering uses the requested value, so a failed transaction can
    // revert visually without ever exposing an uncommitted config to workers.
    if app.account_toggle_failure_status_sequence.take().is_some() {
        app.status_message = None;
    }
    app.pending_account_toggle = Some(PendingAccountToggle {
        receiver,
        intent_sender,
        base_config,
        displayed_intents: initial_intents,
        deferred_local_sync_required,
        deferred_refresh_passwords_required,
    });
    app.keep_window_open_for_pending_settings_save(ctx);
    ctx.request_repaint();
    true
}

fn defer_account_toggle_start_retry(
    app: &mut AutoLoginApp,
    ctx: &egui::Context,
    intents: Vec<AccountToggleIntent>,
) {
    for intent in intents {
        record_queued_account_toggle_intent(app, intent);
    }
    app.account_toggle_start_retry_at = Some(Instant::now() + ACCOUNT_TOGGLE_START_RETRY_DELAY);
    ctx.request_repaint_after(ACCOUNT_TOGGLE_START_RETRY_DELAY);
}

fn submit_account_toggle_worker<J>(
    executor: BackgroundMutationExecutor,
    job: J,
    repaint: egui::Context,
) -> std::io::Result<Receiver<AccountToggleCompletion>>
where
    J: FnOnce() -> AccountToggleCompletion + Send + 'static,
{
    let (sender, receiver) = mpsc::sync_channel(1);
    executor.try_submit(move || {
        let completion = job();
        let _ = sender.send(completion);
        repaint.request_repaint();
    })?;
    Ok(receiver)
}

#[allow(clippy::too_many_arguments)]
fn run_account_toggle_job<B, R, V, T, S>(
    mut settings_mutation: SettingsMutationGuard,
    settings_window_mode: bool,
    begin: B,
    reload: R,
    verify_storage_recovery_clear: V,
    transaction: T,
    signal_recovery_block: S,
) -> AccountToggleCompletion
where
    B: FnOnce() -> anyhow::Result<()>,
    R: FnOnce() -> anyhow::Result<()>,
    V: FnOnce() -> bool,
    T: FnOnce() -> AccountToggleBatchResult,
    S: FnOnce() -> anyhow::Result<()>,
{
    if let Err(error) = begin() {
        tracing::warn!(%error, "The background account update could not establish monitor quiescence");
        settings_mutation.finish_unacknowledged_begin();
        return AccountToggleCompletion::BeginFailed {
            status: format!(
                "The monitor could not pause safely before updating the account: {error}. Restart the app before trying again."
            ),
        };
    }
    settings_mutation.mark_begin_acknowledged();

    // A panic, lost result, ambiguous journal error, or failed durability
    // check after this boundary must never resume a stale supervisor config.
    // Only the explicit verified-clean rejection branch below may cancel.
    settings_mutation.mark_fail_closed();
    let transaction_result = transaction();
    let transaction_requires_recovery =
        transaction_result.config_durability_warning || transaction_result.journal_cleanup_warning;
    let recovery_pending = transaction_requires_recovery || !verify_storage_recovery_clear();

    if transaction_result.config_durability_warning {
        tracing::warn!("Account toggle committed, but config durability confirmation failed");
    } else if transaction_result.journal_cleanup_warning {
        tracing::warn!("Account toggle committed, but its recovery journal could not be cleared");
    }
    let AccountToggleBatchResult {
        config,
        mut status,
        applied,
        failed_intent,
        ..
    } = transaction_result;

    if !applied && !recovery_pending {
        let blocked_reason = settings_mutation
            .cancel_verified_abort()
            .err()
            .map(|error| {
                tracing::warn!(%error, "The rejected background account update could not be cancelled safely");
                ACCOUNT_TOGGLE_CANCEL_FAILED_REASON.to_string()
            });
        return AccountToggleCompletion::Finished(AccountToggleJobResult {
            config,
            status,
            applied,
            failed_intent,
            recovery_pending,
            recovery_signal_confirmed: true,
            blocked_reason,
        });
    }

    settings_mutation.mark_commit_started();
    let mut recovery_signal_confirmed = true;
    let blocked_reason = if recovery_pending {
        if let Err(error) = signal_recovery_block() {
            tracing::warn!(%error, "The background account update could not confirm the recovery block to every owner");
            recovery_signal_confirmed = false;
        }
        Some(CONFIG_MUTATION_RECOVERY_REASON.to_string())
    } else if settings_window_mode && applied {
        reload().err().map(|error| {
            tracing::warn!(%error, "The background account update committed, but supervisor reload acknowledgement failed");
            status = Some(format!(
                "The supervisor could not reload the saved account change: {error}"
            ));
            ACCOUNT_TOGGLE_RELOAD_FAILED_REASON.to_string()
        })
    } else {
        None
    };

    AccountToggleCompletion::Finished(AccountToggleJobResult {
        config,
        status,
        applied,
        failed_intent,
        recovery_pending,
        recovery_signal_confirmed,
        blocked_reason,
    })
}

fn signal_account_toggle_recovery_block(settings_window_mode: bool) -> anyhow::Result<()> {
    let persist_result = crate::storage::mark_storage_recovery_blocked();
    let signal_result = if settings_window_mode {
        single_instance::request_monitor_command(
            crate::single_instance::MonitorControlCommand::StorageRecoveryBlocked,
        )
    } else {
        Ok(())
    };
    persist_result.and(signal_result)
}

pub(crate) fn poll_background_account_toggle(app: &mut AutoLoginApp, ctx: &egui::Context) {
    if app.pending_account_toggle.is_none() {
        if app.pending_account_transaction.is_none() {
            let _ = start_queued_background_account_work(app, ctx, false, false);
        }
        return;
    }
    poll_background_account_toggle_with(
        app,
        ctx,
        crate::ui::settings::start_queued_background_save_after_account_toggle,
        start_queued_background_account_work,
        AutoLoginApp::start_background_storage_recovery_signal,
    );
}

fn poll_background_account_toggle_with<S, A, B>(
    app: &mut AutoLoginApp,
    ctx: &egui::Context,
    mut start_follow_up: S,
    mut start_account_successor: A,
    mut begin_recovery_block: B,
) where
    S: FnMut(&mut AutoLoginApp, &egui::Context, bool, bool) -> bool,
    A: FnMut(&mut AutoLoginApp, &egui::Context, bool, bool) -> bool,
    B: FnMut(&mut AutoLoginApp, &egui::Context),
{
    let completion = match app
        .pending_account_toggle
        .as_ref()
        .map(|pending| pending.receiver.try_recv())
    {
        None => return,
        Some(Err(TryRecvError::Empty)) => {
            ctx.request_repaint_after(Duration::from_millis(25));
            return;
        }
        Some(Err(TryRecvError::Disconnected)) => None,
        Some(Ok(completion)) => Some(completion),
    };
    let pending = app
        .pending_account_toggle
        .take()
        .expect("a completed account update must still be pending");

    let Some(completion) = completion else {
        app.set_status(
            "The background account update did not finish safely. Restart the app before changing accounts again.",
        );
        app.set_settings_changes_blocked_reason(Some(
            ACCOUNT_TOGGLE_JOB_DISCONNECTED_REASON.to_string(),
        ));
        app.queued_account_toggles.clear();
        app.queued_account_transactions.clear();
        begin_recovery_block(app, ctx);
        return;
    };

    if app.config != pending.base_config {
        app.set_status(
            "The account configuration changed while its background update was running. Restart the app before changing accounts again.",
        );
        app.set_settings_changes_blocked_reason(Some(
            ACCOUNT_TOGGLE_JOB_DISCONNECTED_REASON.to_string(),
        ));
        app.queued_account_toggles.clear();
        app.queued_account_transactions.clear();
        begin_recovery_block(app, ctx);
        return;
    }

    match completion {
        AccountToggleCompletion::BeginFailed { status } => {
            app.queued_account_toggles.clear();
            app.queued_account_transactions.clear();
            app.set_status(status);
            app.set_settings_changes_blocked_reason(Some(
                ACCOUNT_TOGGLE_BEGIN_FAILED_REASON.to_string(),
            ));
        }
        AccountToggleCompletion::Finished(result) => {
            let failed_sequence = result.failed_intent.as_ref().map(|intent| intent.sequence);
            let displayed_intents = pending.displayed_intents;
            let failed_status_is_superseded = result.failed_intent.as_ref().is_some_and(|failed| {
                displayed_intents.iter().any(|intent| {
                    intent.account_id == failed.account_id && intent.sequence > failed.sequence
                })
            });
            let local_sync_required = pending.deferred_local_sync_required
                || (result.applied && !app.settings_window_mode());
            let refresh_passwords_required = pending.deferred_refresh_passwords_required;
            app.config = result.config;
            app.set_settings_changes_blocked_reason(result.blocked_reason);
            if let Some(status) = result.status.filter(|_| !failed_status_is_superseded) {
                app.set_status(status);
                app.account_toggle_failure_status_sequence = failed_sequence;
            }

            if result.recovery_pending {
                app.queued_account_toggles.clear();
                app.queued_account_transactions.clear();
                app.apply_background_storage_recovery_block();
                if !result.recovery_signal_confirmed {
                    begin_recovery_block(app, ctx);
                }
                return;
            }
            if app.settings_save_fail_closed_reason().is_some() {
                app.queued_account_toggles.clear();
                app.queued_account_transactions.clear();
                return;
            }

            for intent in displayed_intents {
                if failed_sequence == Some(intent.sequence) {
                    continue;
                }
                let target_is_current = app
                    .config
                    .accounts
                    .iter()
                    .find(|account| account.id == intent.account_id)
                    .is_none_or(|account| account.enabled == intent.enabled);
                if !target_is_current {
                    record_queued_account_toggle_intent(app, intent);
                }
            }

            if start_account_successor(app, ctx, local_sync_required, refresh_passwords_required) {
                return;
            }

            let follow_up_started = app.queued_account_toggles.is_empty()
                && start_follow_up(app, ctx, local_sync_required, refresh_passwords_required);
            if !follow_up_started
                && app.queued_account_toggles.is_empty()
                && !app.settings_window_mode()
            {
                app.sync_background_saved_config_to_local_worker(refresh_passwords_required);
            }
        }
    }
}

fn start_queued_background_account_transaction(
    app: &mut AutoLoginApp,
    ctx: &egui::Context,
    deferred_local_sync_required: bool,
    deferred_refresh_passwords_required: bool,
) -> bool {
    if app.pending_account_transaction.is_some()
        || app.pending_account_toggle.is_some()
        || app.pending_settings_save.is_some()
        || app.settings_save_fail_closed_reason().is_some()
    {
        return false;
    }
    let Some(next_sequence) = app
        .queued_account_transactions
        .front()
        .map(AccountTransactionIntent::sequence)
    else {
        return false;
    };
    if first_queued_toggle_sequence(app).is_some_and(|sequence| sequence < next_sequence) {
        return false;
    }

    let executor = match app.background_mutation_executor() {
        Ok(executor) => executor,
        Err(error) => {
            tracing::warn!(%error, "The background account transaction executor is unavailable");
            app.queued_account_transactions.clear();
            app.queued_account_toggles.clear();
            app.set_settings_changes_blocked_reason(Some(
                ACCOUNT_TOGGLE_JOB_DISCONNECTED_REASON.to_string(),
            ));
            return false;
        }
    };
    let Some(settings_mutation) = app.reserve_background_settings_mutation() else {
        ctx.request_repaint_after(Duration::from_millis(25));
        return false;
    };
    let mutation_begin = app.prepare_background_settings_mutation_begin();
    let intent = app
        .queued_account_transactions
        .pop_front()
        .expect("the queued account transaction must still exist");
    let base_config = app.config.clone();
    let transaction_config = base_config.clone();
    let settings_window_mode = app.settings_window_mode();
    let repaint = ctx.clone();
    let receiver = match submit_account_transaction_worker(
        executor,
        move || {
            run_account_transaction_job(
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
                move || execute_account_transaction(transaction_config, intent),
                move || signal_account_toggle_recovery_block(settings_window_mode),
            )
        },
        repaint,
    ) {
        Ok(receiver) => receiver,
        Err(error) => {
            tracing::warn!(%error, "Could not submit the background account transaction");
            // Submission consumes and drops any password carried by the intent.
            // No durable work began, but the executor state is now ambiguous;
            // fail closed and discard all remaining secret-bearing intents.
            app.queued_account_transactions.clear();
            app.queued_account_toggles.clear();
            app.reject_background_mutation_submission(
                deferred_local_sync_required,
                deferred_refresh_passwords_required,
            );
            ctx.request_repaint();
            return false;
        }
    };

    app.pending_account_transaction = Some(PendingAccountTransaction {
        receiver,
        base_config,
        deferred_local_sync_required,
        deferred_refresh_passwords_required,
    });
    app.keep_window_open_for_pending_settings_save(ctx);
    ctx.request_repaint();
    true
}

fn submit_account_transaction_worker<J>(
    executor: BackgroundMutationExecutor,
    job: J,
    repaint: egui::Context,
) -> std::io::Result<Receiver<AccountTransactionCompletion>>
where
    J: FnOnce() -> AccountTransactionCompletion + Send + 'static,
{
    let (sender, receiver) = mpsc::sync_channel(1);
    executor.try_submit(move || {
        let completion = job();
        let _ = sender.try_send(completion);
        repaint.request_repaint();
    })?;
    Ok(receiver)
}

fn run_account_transaction_job<B, R, V, T, S>(
    mut settings_mutation: SettingsMutationGuard,
    settings_window_mode: bool,
    begin: B,
    reload: R,
    verify_storage_recovery_clear: V,
    transaction: T,
    signal_recovery_block: S,
) -> AccountTransactionCompletion
where
    B: FnOnce() -> anyhow::Result<()>,
    R: FnOnce() -> anyhow::Result<()>,
    V: FnOnce() -> bool,
    T: FnOnce() -> AccountTransactionResult,
    S: FnOnce() -> anyhow::Result<()>,
{
    if let Err(error) = begin() {
        settings_mutation.finish_unacknowledged_begin();
        return AccountTransactionCompletion::BeginFailed {
            status: format!(
                "The monitor could not pause safely before updating the account: {error}. Restart the app before trying again."
            ),
        };
    }
    settings_mutation.mark_begin_acknowledged();
    settings_mutation.mark_fail_closed();

    let result = transaction();
    let recovery_pending = result.recovery_pending || !verify_storage_recovery_clear();
    if !result.applied && !recovery_pending {
        let blocked_reason = settings_mutation
            .cancel_verified_abort()
            .err()
            .map(|error| {
                tracing::warn!(%error, "The rejected background account transaction could not be cancelled safely");
                ACCOUNT_TOGGLE_CANCEL_FAILED_REASON.to_string()
            });
        return AccountTransactionCompletion::Finished(AccountTransactionJobResult {
            config: result.config,
            status: result.status,
            applied: false,
            refresh_passwords: false,
            recovery_pending: false,
            recovery_signal_confirmed: true,
            blocked_reason,
        });
    }

    settings_mutation.mark_commit_started();
    let mut recovery_signal_confirmed = true;
    let blocked_reason = if recovery_pending {
        if let Err(error) = signal_recovery_block() {
            tracing::warn!(%error, "The background account transaction could not confirm the recovery block");
            recovery_signal_confirmed = false;
        }
        Some(CONFIG_MUTATION_RECOVERY_REASON.to_string())
    } else if settings_window_mode && result.applied {
        reload().err().map(|error| {
            tracing::warn!(%error, "The background account transaction committed, but supervisor reload acknowledgement failed");
            ACCOUNT_TOGGLE_RELOAD_FAILED_REASON.to_string()
        })
    } else {
        None
    };

    AccountTransactionCompletion::Finished(AccountTransactionJobResult {
        config: result.config,
        status: result.status,
        applied: result.applied,
        refresh_passwords: result.refresh_passwords,
        recovery_pending,
        recovery_signal_confirmed,
        blocked_reason,
    })
}

fn execute_account_transaction(
    config: AppConfig,
    intent: AccountTransactionIntent,
) -> AccountTransactionResult {
    match intent {
        AccountTransactionIntent::Save {
            account,
            was_existing,
            password,
            ..
        } => {
            let exists_now = config
                .accounts
                .iter()
                .any(|existing| existing.id == account.id);
            if was_existing && !exists_now {
                return AccountTransactionResult {
                    config,
                    status: Some("Account no longer exists".to_string()),
                    applied: false,
                    refresh_passwords: false,
                    recovery_pending: false,
                };
            }
            if !was_existing && exists_now {
                return AccountTransactionResult {
                    config,
                    status: Some(
                        "The account could not be added because it already exists".to_string(),
                    ),
                    applied: false,
                    refresh_passwords: false,
                    recovery_pending: false,
                };
            }
            if account.username.trim().is_empty() {
                return AccountTransactionResult {
                    config,
                    status: Some("Email is required".to_string()),
                    applied: false,
                    refresh_passwords: false,
                    recovery_pending: false,
                };
            }
            let existing = config
                .accounts
                .iter()
                .find(|existing| existing.id == account.id);
            let effective_enabled = existing.map_or(account.enabled, |existing| existing.enabled);
            if effective_enabled
                && config.accounts.iter().any(|other| {
                    other.id != account.id
                        && enabled_account_conflicts_with_candidate(other, account.username.trim())
                })
            {
                return AccountTransactionResult {
                    config,
                    status: Some("An enabled account with this email already exists".to_string()),
                    applied: false,
                    refresh_passwords: false,
                    recovery_pending: false,
                };
            }
            let previous_password_saved =
                existing.is_some_and(|existing| existing.has_saved_password);
            if (!exists_now || (effective_enabled && !previous_password_saved))
                && password.as_ref().is_none_or(|password| password.is_empty())
            {
                return AccountTransactionResult {
                    config,
                    status: Some("Password is required".to_string()),
                    applied: false,
                    refresh_passwords: false,
                    recovery_pending: false,
                };
            }
            let mut state = AccountSaveTransactionState::new(config, password);
            let applied = save_edited_account_transaction(&mut state, &account, exists_now);
            AccountTransactionResult {
                config: state.config,
                status: state.status_message.map(|(status, _)| status),
                applied,
                refresh_passwords: state.refresh_passwords,
                recovery_pending: state.recovery_pending,
            }
        }
        AccountTransactionIntent::Delete { account_id, .. } => {
            let Some(idx) = config
                .accounts
                .iter()
                .position(|account| account.id == account_id)
            else {
                return AccountTransactionResult {
                    config,
                    status: Some("Account no longer exists".to_string()),
                    applied: false,
                    refresh_passwords: false,
                    recovery_pending: false,
                };
            };
            match delete_account_transaction(
                &config,
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
                    if outcome.config_durability_warning {
                        tracing::warn!(
                            "Account removal committed, but config durability confirmation failed"
                        );
                    } else if outcome.password_cleanup_warning {
                        tracing::warn!(
                            "Account deleted, but saved password cleanup failed after config save"
                        );
                    } else if outcome.journal_cleanup_warning {
                        tracing::warn!("Account deleted, but recovery journal cleanup failed");
                    } else if cleanup_warning {
                        tracing::warn!("Account deleted, but unused fallback key cleanup failed");
                    }
                    let status = account_deletion_status(
                        outcome.config_durability_warning,
                        outcome.password_cleanup_warning,
                        outcome.journal_cleanup_warning,
                        cleanup_warning,
                    )
                    .map(str::to_string);
                    AccountTransactionResult {
                        config: outcome.config,
                        status,
                        applied: true,
                        refresh_passwords: false,
                        recovery_pending: outcome.config_durability_warning
                            || outcome.password_cleanup_warning
                            || outcome.journal_cleanup_warning,
                    }
                }
                Err(status) => AccountTransactionResult {
                    config,
                    status: Some(status),
                    applied: false,
                    refresh_passwords: false,
                    recovery_pending: false,
                },
            }
        }
    }
}

pub(crate) fn poll_background_account_transaction(app: &mut AutoLoginApp, ctx: &egui::Context) {
    if app.pending_account_transaction.is_none() {
        if app.pending_account_toggle.is_none() && app.pending_settings_save.is_none() {
            let _ = start_queued_background_account_work(app, ctx, false, false);
        }
        return;
    }
    let completion = match app
        .pending_account_transaction
        .as_ref()
        .map(|pending| pending.receiver.try_recv())
    {
        None => return,
        Some(Err(TryRecvError::Empty)) => {
            ctx.request_repaint_after(Duration::from_millis(25));
            return;
        }
        Some(Err(TryRecvError::Disconnected)) => None,
        Some(Ok(completion)) => Some(completion),
    };
    let pending = app
        .pending_account_transaction
        .take()
        .expect("a completed account transaction must still be pending");

    let Some(completion) = completion else {
        tracing::error!("The background account transaction disconnected");
        app.queued_account_transactions.clear();
        app.queued_account_toggles.clear();
        app.set_settings_changes_blocked_reason(Some(
            ACCOUNT_TOGGLE_JOB_DISCONNECTED_REASON.to_string(),
        ));
        app.start_background_storage_recovery_signal(ctx);
        return;
    };
    if app.config != pending.base_config {
        tracing::error!("The authoritative config changed during a serialized account transaction");
        app.queued_account_transactions.clear();
        app.queued_account_toggles.clear();
        app.set_settings_changes_blocked_reason(Some(
            ACCOUNT_TOGGLE_JOB_DISCONNECTED_REASON.to_string(),
        ));
        app.start_background_storage_recovery_signal(ctx);
        return;
    }

    match completion {
        AccountTransactionCompletion::BeginFailed { status } => {
            app.queued_account_transactions.clear();
            app.queued_account_toggles.clear();
            app.set_status(status);
            app.set_settings_changes_blocked_reason(Some(
                ACCOUNT_TOGGLE_BEGIN_FAILED_REASON.to_string(),
            ));
        }
        AccountTransactionCompletion::Finished(result) => {
            let local_sync_required = pending.deferred_local_sync_required
                || (result.applied && !app.settings_window_mode());
            let refresh_passwords_required =
                pending.deferred_refresh_passwords_required || result.refresh_passwords;
            app.config = result.config;
            app.set_settings_changes_blocked_reason(result.blocked_reason);
            if let Some(status) = result.status {
                app.set_status(status);
            } else if result.applied {
                app.status_message = None;
            }

            if result.recovery_pending {
                app.queued_account_transactions.clear();
                app.queued_account_toggles.clear();
                app.apply_background_storage_recovery_block();
                if !result.recovery_signal_confirmed {
                    app.start_background_storage_recovery_signal(ctx);
                }
                return;
            }
            if app.settings_save_fail_closed_reason().is_some() {
                app.queued_account_transactions.clear();
                app.queued_account_toggles.clear();
                return;
            }

            // Accepted Save/Delete/toggle work is one FIFO. Drain its next
            // barrier segment before a later coalesced Settings draft so an
            // account transaction cannot be starved by repeated checkbox
            // repaints.
            if start_queued_background_account_work(
                app,
                ctx,
                local_sync_required,
                refresh_passwords_required,
            ) {
                return;
            }
            if crate::ui::settings::start_queued_background_save_after_account_toggle(
                app,
                ctx,
                local_sync_required,
                refresh_passwords_required,
            ) {
                return;
            }
            if !app.settings_window_mode() {
                app.sync_background_saved_config_to_local_worker(refresh_passwords_required);
            }
        }
    }
}

fn run_account_toggle_batch<T>(
    mut config: AppConfig,
    initial_intents: Vec<AccountToggleIntent>,
    intent_receiver: Receiver<AccountToggleIntent>,
    quiet_period: Duration,
    max_coalesce_period: Duration,
    mut transaction: T,
) -> AccountToggleBatchResult
where
    T: FnMut(&AppConfig, &AccountToggleIntent) -> Result<ToggleAccountOutcome, String>,
{
    let mut intents = Vec::new();
    for intent in initial_intents {
        record_latest_account_toggle_intent(&mut intents, intent);
    }
    let mut applied = false;
    let mut config_durability_warning = false;
    let mut journal_cleanup_warning = false;

    loop {
        if max_coalesce_period.is_zero() {
            // Deterministic tests use a zero wait budget but already queued
            // intents must still participate in the same coalesced burst.
            for intent in intent_receiver.try_iter() {
                record_latest_account_toggle_intent(&mut intents, intent);
            }
        } else {
            let coalescing_deadline = Instant::now() + max_coalesce_period;
            loop {
                let remaining = coalescing_deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                match intent_receiver.recv_timeout(quiet_period.min(remaining)) {
                    Ok(intent) => record_latest_account_toggle_intent(&mut intents, intent),
                    Err(_) => break,
                }
            }
        }

        if intents.is_empty() {
            break;
        }
        let burst = std::mem::take(&mut intents);
        for intent in burst {
            let Some(account) = config
                .accounts
                .iter()
                .find(|account| account.id == intent.account_id)
            else {
                return AccountToggleBatchResult {
                    config,
                    status: Some("Account no longer exists".to_string()),
                    applied,
                    failed_intent: Some(intent),
                    config_durability_warning,
                    journal_cleanup_warning,
                };
            };
            if account.enabled == intent.enabled {
                continue;
            }
            match transaction(&config, &intent) {
                Ok(outcome) => {
                    config = outcome.config;
                    applied = true;
                    config_durability_warning |= outcome.config_durability_warning;
                    journal_cleanup_warning |= outcome.journal_cleanup_warning;
                    if config_durability_warning || journal_cleanup_warning {
                        return AccountToggleBatchResult {
                            config,
                            status: account_updated_status(
                                config_durability_warning,
                                journal_cleanup_warning,
                            )
                            .map(str::to_string),
                            applied,
                            failed_intent: None,
                            config_durability_warning,
                            journal_cleanup_warning,
                        };
                    }
                }
                Err(status) => {
                    return AccountToggleBatchResult {
                        config,
                        status: Some(status),
                        applied,
                        failed_intent: Some(intent),
                        config_durability_warning,
                        journal_cleanup_warning,
                    };
                }
            }
        }
    }

    AccountToggleBatchResult {
        config,
        status: None,
        applied,
        failed_intent: None,
        config_durability_warning,
        journal_cleanup_warning,
    }
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

fn account_updated_status(
    config_durability_warning: bool,
    journal_cleanup_warning: bool,
) -> Option<&'static str> {
    if config_durability_warning {
        Some("Account updated, but disk durability could not be confirmed. Recovery remains pending and auto-login will stay stopped until restart.")
    } else if journal_cleanup_warning {
        Some("Account updated, but recovery journal cleanup is pending. Auto-login will stay stopped until restart.")
    } else {
        None
    }
}

fn account_deletion_status(
    config_durability_warning: bool,
    password_cleanup_warning: bool,
    journal_cleanup_warning: bool,
    fallback_key_cleanup_warning: bool,
) -> Option<&'static str> {
    if config_durability_warning {
        Some(
            "Account deleted, but disk durability could not be confirmed. Cleanup remains pending and will be checked on next launch.",
        )
    } else if password_cleanup_warning {
        Some(
            "Account deleted. Saved password cleanup is still pending and will retry on next launch. Stored credential changes are blocked until recovery completes.",
        )
    } else if journal_cleanup_warning {
        Some(
            "Account deleted. Saved password cleanup succeeded, but recovery journal cleanup is still pending; restart to verify cleanup.",
        )
    } else if fallback_key_cleanup_warning {
        Some(
            "Account deleted. Old fallback key cleanup failed; old key material may require manual cleanup.",
        )
    } else {
        None
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

#[derive(Default)]
struct AccountRowActions {
    toggle_enabled: Vec<(AccountId, bool)>,
    edit_account: Option<Account>,
    confirm_delete_account: Option<String>,
}

fn show_account_row(
    ui: &mut egui::Ui,
    account: &Account,
    displayed_enabled: bool,
    toggle_enabled: bool,
    transaction_actions_enabled: bool,
    transaction_disabled_reason: Option<&str>,
    actions: &mut AccountRowActions,
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
                let mut enabled = displayed_enabled;
                if ui
                    .add_enabled(toggle_enabled, egui::Checkbox::without_text(&mut enabled))
                    .changed()
                {
                    actions.toggle_enabled.push((account.id.clone(), enabled));
                }
            },
        );

        show_cell(
            ui,
            cells.actions,
            egui::Layout::left_to_right(egui::Align::Center),
            |ui| {
                if with_transaction_disabled_reason(
                    account_action_button(ui, AccountActionIcon::Edit, transaction_actions_enabled)
                        .on_hover_text("Edit account"),
                    transaction_disabled_reason,
                )
                .clicked()
                {
                    actions.edit_account = Some(account.clone());
                }
                if with_transaction_disabled_reason(
                    account_action_button(
                        ui,
                        AccountActionIcon::Delete,
                        transaction_actions_enabled,
                    )
                    .on_hover_text("Delete account"),
                    transaction_disabled_reason,
                )
                .clicked()
                {
                    actions.confirm_delete_account = Some(account.id.clone());
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
    ctx.memory_mut(|memory| memory.surrender_focus(password_visibility_id(id)));
    ctx.data_mut(|data| data.remove::<egui::text_edit::TextEditState>(id));
}

fn password_visibility_id(password_id: egui::Id) -> egui::Id {
    password_id.with("visibility")
}

fn account_editor_input_scope<R>(
    ui: &mut egui::Ui,
    add_contents: impl FnOnce(&mut egui::Ui) -> R,
) -> egui::InnerResponse<R> {
    ui.scope(|ui| {
        // Text inputs keep a stable outline while the pointer moves across
        // them. Keyboard focus remains distinct through `selection.stroke`.
        let idle_stroke = ui.visuals().widgets.inactive.bg_stroke;
        ui.visuals_mut().widgets.hovered.bg_stroke = idle_stroke;
        add_contents(ui)
    })
}

/// Minimal password input used instead of egui::TextEdit. TextEdit clones its
/// complete backing string every frame for change reporting and its Undoer,
/// even when max_undos is zero. This editor keeps only the Zeroizing backing
/// buffer and consumes/zeroizes owned input-event strings immediately.
///
/// Native windowing/IME layers can still transiently own typed characters
/// before egui delivers them; application code cannot guarantee wiping those
/// platform allocations. In the default masked mode the renderer receives
/// only bullets. Explicit reveal transiently exposes the current password to
/// the renderer, but never includes it in WidgetInfo or persistent widget
/// state.
fn secure_password_editor(
    ui: &mut egui::Ui,
    password: &mut Zeroizing<String>,
    id: egui::Id,
    hint: &str,
    reveal: bool,
) -> SecurePasswordEditorResponse {
    let desired_size = egui::vec2(ACCOUNT_EDITOR_FIELD_WIDTH, ACCOUNT_EDITOR_CONTROL_HEIGHT);
    let (_, rect) = ui.allocate_space(desired_size);
    let (text_rect, visibility_rect) = password_editor_regions(rect);
    let field_response = ui.interact(text_rect, id, egui::Sense::click());
    if field_response.clicked() {
        field_response.request_focus();
    }

    if field_response.has_focus() {
        consume_password_input_events(ui.ctx(), password);
        suppress_password_clipboard_output(ui.ctx(), true);
    }

    let visuals = ui.style().interact(&field_response);
    let field_stroke = if field_response.has_focus() {
        ui.visuals().selection.stroke
    } else {
        visuals.bg_stroke
    };
    ui.painter().rect(
        rect,
        visuals.corner_radius,
        ui.visuals().text_edit_bg_color(),
        field_stroke,
        egui::StrokeKind::Inside,
    );
    let password_is_empty = password.is_empty();
    let display = password_editor_display(password.as_str(), reveal, hint);
    let color = if password_is_empty {
        ui.visuals().weak_text_color()
    } else {
        visuals.text_color()
    };
    let text_clip_rect = egui::Rect::from_min_max(
        text_rect.min,
        egui::pos2(text_rect.right() - 4.0, text_rect.bottom()),
    )
    .shrink(1.0);
    let field_painter = ui.painter().with_clip_rect(text_clip_rect);
    let painted_text_rect = field_painter.text(
        text_rect.left_center() + egui::vec2(8.0, 0.0),
        egui::Align2::LEFT_CENTER,
        display.as_ref(),
        egui::TextStyle::Body.resolve(ui.style()),
        color,
    );
    if field_response.has_focus() {
        let cursor_x = password_editor_cursor_x(text_rect, painted_text_rect, password_is_empty);
        field_painter.vline(
            cursor_x,
            (rect.top() + 4.0)..=(rect.bottom() - 4.0),
            egui::Stroke::new(1.0, visuals.text_color()),
        );
    }
    field_response.widget_info(|| {
        egui::WidgetInfo::labeled(egui::WidgetType::TextEdit, ui.is_enabled(), "Password")
    });
    ui.ctx().accesskit_node_builder(id, |builder| {
        builder.set_role(egui::accesskit::Role::PasswordInput);
        builder.clear_value();
    });
    let visibility_response = password_visibility_button(ui, visibility_rect, id, reveal);

    SecurePasswordEditorResponse {
        field: field_response,
        visibility: visibility_response,
    }
}

struct SecurePasswordEditorResponse {
    field: egui::Response,
    visibility: egui::Response,
}

fn password_editor_regions(rect: egui::Rect) -> (egui::Rect, egui::Rect) {
    let visibility_rect = egui::Rect::from_min_max(
        egui::pos2(rect.right() - ACCOUNT_EDITOR_TOGGLE_WIDTH, rect.top()),
        rect.max,
    );
    let text_rect =
        egui::Rect::from_min_max(rect.min, egui::pos2(visibility_rect.left(), rect.bottom()));
    (text_rect, visibility_rect)
}

fn password_editor_display<'a>(password: &'a str, reveal: bool, hint: &'a str) -> Cow<'a, str> {
    if password.is_empty() {
        Cow::Borrowed(hint)
    } else if reveal {
        // Painter::text must build an owned galley for display. Borrow here so
        // this helper itself does not create an additional plaintext copy; the
        // renderer's unavoidable copy is evicted by egui after an unused
        // follow-up frame when reveal is turned off or the editor closes.
        Cow::Borrowed(password)
    } else {
        Cow::Owned(
            std::iter::repeat_n(
                egui::epaint::text::PASSWORD_REPLACEMENT_CHAR,
                password.chars().count(),
            )
            .collect(),
        )
    }
}

fn password_editor_cursor_x(
    field_rect: egui::Rect,
    painted_text_rect: egui::Rect,
    password_is_empty: bool,
) -> f32 {
    let text_start = field_rect.left() + 8.0;
    let mask_end = if password_is_empty {
        text_start
    } else {
        painted_text_rect.right()
    };
    mask_end.min(field_rect.right() - 5.0)
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
    account_to_delete: &mut Option<AccountId>,
) {
    let Some(account_id) = app.confirm_delete_account.clone() else {
        return;
    };

    let Some(idx) = app.config.accounts.iter().position(|a| a.id == account_id) else {
        app.confirm_delete_account = None;
        return;
    };

    let account_name = app.config.accounts[idx].display_name();
    let account_transaction_ready = app.account_transaction_ready();
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
                    let delete = ui.add_enabled(
                        account_transaction_ready,
                        theme::danger_button("Delete").min_size(egui::vec2(104.0, 28.0)),
                    );
                    let delete = with_transaction_disabled_reason(
                        delete,
                        (!account_transaction_ready)
                            .then(|| app.config_mutations_disabled_reason())
                            .flatten(),
                    );
                    if delete.clicked() {
                        *account_to_delete = Some(account_id.clone());
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
    let account_transaction_ready = app.account_transaction_ready();
    let password_editor_id = password_editor_id(&account_snapshot.id);
    egui::Window::new(title)
        .open(&mut open)
        .resizable(false)
        .default_width(ACCOUNT_EDITOR_WIDTH)
        .show(ui.ctx(), |ui| {
            ui.set_width(ACCOUNT_EDITOR_WIDTH);
            if let Some(ref mut account) = editing {
                account_editor_input_scope(ui, |ui| {
                    egui::Grid::new("account_editor_grid")
                        .num_columns(2)
                        .spacing([16.0, 10.0])
                        .show(ui, |ui| {
                            account_editor_field_label(ui, "Email");
                            ui.add_sized(
                                [ACCOUNT_EDITOR_FIELD_WIDTH, ACCOUNT_EDITOR_CONTROL_HEIGHT],
                                egui::TextEdit::singleline(&mut account.username)
                                    .hint_text("user@domain.com"),
                            );
                            ui.end_row();

                            account_editor_field_label(ui, "Password");
                            let password_response = secure_password_editor(
                                ui,
                                &mut app.temp_password,
                                password_editor_id,
                                if is_existing {
                                    "Leave blank to keep saved password"
                                } else {
                                    "Password"
                                },
                                app.show_password,
                            );
                            let tooltip = if app.show_password {
                                "Hide password"
                            } else {
                                "Show password"
                            };
                            if password_response
                                .visibility
                                .on_hover_text(tooltip)
                                .clicked()
                            {
                                app.show_password = !app.show_password;
                                password_response.field.request_focus();
                                ui.ctx().request_repaint();
                            }
                            ui.end_row();
                        });
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

                        let save = ui.add_enabled(
                            account_transaction_ready,
                            theme::primary_button("Save").min_size(egui::vec2(92.0, 28.0)),
                        );
                        let save = with_transaction_disabled_reason(
                            save,
                            (!account_transaction_ready)
                                .then(|| app.config_mutations_disabled_reason())
                                .flatten(),
                        );
                        if save.clicked() {
                            account_to_save = Some(account.clone());
                        }
                    });
                });
            }
        });

    if let Some(account) = account_to_save {
        close_editor = save_edited_account(app, ui.ctx(), &account, is_existing);
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
        app.show_password = false;
        // Ensure an unused follow-up frame can evict any plaintext galley
        // created while the user explicitly revealed the password.
        ui.ctx().request_repaint();
    }
}

fn account_editor_field_label(ui: &mut egui::Ui, text: &str) -> egui::Response {
    let slot_size = egui::vec2(ACCOUNT_EDITOR_LABEL_WIDTH, ACCOUNT_EDITOR_CONTROL_HEIGHT);
    ui.allocate_ui_with_layout(
        slot_size,
        egui::Layout::left_to_right(egui::Align::Center),
        |ui| {
            ui.set_min_size(slot_size);
            ui.label(text)
        },
    )
    .inner
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

fn password_visibility_button(
    ui: &mut egui::Ui,
    rect: egui::Rect,
    password_id: egui::Id,
    password_visible: bool,
) -> egui::Response {
    let (uri, bytes, label) = if password_visible {
        ("bytes://icons/eye-off.svg", EYE_OFF_ICON, "Hide password")
    } else {
        ("bytes://icons/eye.svg", EYE_ICON, "Show password")
    };
    let response = ui.interact(
        rect,
        password_visibility_id(password_id),
        egui::Sense::click(),
    );
    let visuals = ui.style().interact_selectable(&response, password_visible);
    if response.hovered() || response.has_focus() {
        ui.painter().rect_filled(
            rect.shrink(3.0),
            egui::CornerRadius::same(4),
            visuals.weak_bg_fill,
        );
    }
    let icon_rect = egui::Rect::from_center_size(
        rect.center(),
        egui::vec2(PASSWORD_ICON_SIZE, PASSWORD_ICON_SIZE),
    );
    svg_icon(uri, bytes, PASSWORD_ICON_SIZE, visuals.text_color()).paint_at(ui, icon_rect);
    response.widget_info(|| {
        egui::WidgetInfo::labeled(egui::WidgetType::Button, ui.is_enabled(), label)
    });
    ui.ctx().accesskit_node_builder(response.id, |builder| {
        builder.set_label(label);
        builder.set_toggled(if password_visible {
            egui::accesskit::Toggled::True
        } else {
            egui::accesskit::Toggled::False
        });
    });
    response
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

fn rebase_editor_enabled_state(
    editor_snapshot: &Account,
    existing_account: Option<&Account>,
) -> Account {
    let mut account = editor_snapshot.clone();
    // Enabled is controlled by the row switch, not by this editor. If the
    // switch completed while the editor was open, keep the authoritative
    // value instead of writing the stale snapshot back with the email.
    if let Some(existing) = existing_account {
        account.enabled = existing.enabled;
    }
    account
}

fn save_edited_account(
    app: &mut AutoLoginApp,
    ctx: &egui::Context,
    account: &Account,
    is_existing: bool,
) -> bool {
    if !app.account_transaction_ready() {
        return false;
    }
    if account.username.trim().is_empty() {
        app.set_status("Email is required");
        return false;
    }
    let effective_enabled = app
        .config
        .accounts
        .iter()
        .find(|existing| existing.id == account.id)
        .map_or(account.enabled, |existing| {
            projected_account_enabled(app, existing)
        });
    if effective_enabled
        && projected_enabled_email_conflict(app, &account.id, account.username.trim())
    {
        app.set_status("An enabled account with this email already exists");
        return false;
    }
    let previous_password_saved = app
        .config
        .accounts
        .iter()
        .find(|existing| existing.id == account.id)
        .map(|existing| existing.has_saved_password)
        .unwrap_or(false);
    if (!is_existing || (effective_enabled && !previous_password_saved))
        && app.temp_password.is_empty()
    {
        app.set_status("Password is required");
        return false;
    }

    let password = if app.temp_password.is_empty() {
        None
    } else {
        Some(std::mem::replace(
            &mut app.temp_password,
            empty_password_buffer(),
        ))
    };
    let sequence = next_account_toggle_sequence(app);
    app.queued_account_transactions
        .push_back(AccountTransactionIntent::Save {
            sequence,
            account: account.clone(),
            was_existing: is_existing,
            password,
        });
    ctx.request_repaint();
    let _ = start_queued_background_account_work(app, ctx, false, false);
    true
}

struct AccountSaveTransactionState {
    config: AppConfig,
    temp_password: Zeroizing<String>,
    status_message: Option<(String, f64)>,
    recovery_pending: bool,
    refresh_passwords: bool,
}

impl AccountSaveTransactionState {
    fn new(config: AppConfig, password: Option<Zeroizing<String>>) -> Self {
        Self {
            config,
            temp_password: password.unwrap_or_else(empty_password_buffer),
            status_message: None,
            recovery_pending: false,
            refresh_passwords: false,
        }
    }

    fn set_status(&mut self, status: impl Into<String>) {
        self.status_message = Some((status.into(), 3.0));
    }

    fn stop_monitor_for_pending_storage_recovery(&mut self) {
        self.recovery_pending = true;
    }
}

fn save_edited_account_transaction(
    app: &mut AccountSaveTransactionState,
    account: &Account,
    is_existing: bool,
) -> bool {
    let existing_account = app
        .config
        .accounts
        .iter()
        .find(|existing| existing.id == account.id);
    let previous_password_saved = existing_account
        .map(|existing| existing.has_saved_password)
        .unwrap_or(false);

    let mut account = rebase_editor_enabled_state(account, existing_account);
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
        let keep_journal_for_cleanup_retry =
            cleanup_warning.is_some() || target_durability_warning || fallback_key_cleanup_warning;
        let journal_cleared = clear_account_journal_after_terminal_result(
            account_journal_started,
            keep_journal_for_cleanup_retry,
        );
        if let Some(status) = account_saved_status(
            cleanup_warning.as_ref(),
            fallback_key_cleanup_warning,
            target_durability_warning,
            !journal_cleared && !keep_journal_for_cleanup_retry,
        ) {
            app.set_status(status);
        } else {
            app.status_message = None;
        }
        if cleanup_warning.is_some()
            || target_durability_warning
            || fallback_key_cleanup_warning
            || !journal_cleared
        {
            app.stop_monitor_for_pending_storage_recovery();
        } else {
            sync_worker_accounts(app, true);
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
        let keep_journal_for_cleanup_retry = cleanup_warning.is_some()
            || target_durability_warning
            || fallback_key_cleanup_warning
            || config_durability_warning;
        let journal_cleared = clear_account_journal_after_terminal_result(
            account_journal_started,
            keep_journal_for_cleanup_retry,
        );
        app.config = next_config;
        if let Some(status) = account_saved_status(
            cleanup_warning.as_ref(),
            fallback_key_cleanup_warning,
            target_durability_warning || config_durability_warning,
            !journal_cleared && !keep_journal_for_cleanup_retry,
        ) {
            app.set_status(status);
        } else {
            app.status_message = None;
        }
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
    durability_warning: bool,
    journal_cleanup_warning: bool,
) -> Option<String> {
    let mut status = cleanup_warning.map(|warning| {
        format!(
            "Account saved. Password was written to {}, but old {} cleanup is still pending and will retry on next launch. Stored credential changes are blocked until recovery completes.",
            warning.saved_backend.label(),
            warning.stale_backend.label()
        )
    });
    if fallback_key_cleanup_warning {
        status
            .get_or_insert_with(|| "Account saved.".to_string())
            .push_str(" Old fallback encryption-key cleanup is still pending and will retry; no password data was rolled back.");
    }
    if durability_warning {
        status
            .get_or_insert_with(|| "Account saved.".to_string())
            .push_str(" Disk durability could not be confirmed; the committed state will be checked on next launch.");
    }
    if journal_cleanup_warning {
        status
            .get_or_insert_with(|| "Account saved.".to_string())
            .push_str(
                " Recovery journal cleanup is still pending; restart before changing stored credentials again.",
            );
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

fn sync_worker_accounts(app: &mut AccountSaveTransactionState, refresh_passwords: bool) {
    app.refresh_passwords |= refresh_passwords;
}

#[cfg(test)]
mod tests {
    use super::enabled_account_conflicts_with_candidate;
    use super::{
        account_control_availability, account_deletion_status, account_editor_field_label,
        account_editor_input_scope, account_saved_status, account_updated_status,
        append_password_input, clear_account_journal_after_terminal_result_with,
        delete_account_transaction, drop_rollback_secret_before_followup,
        eager_account_toggle_validation_error, empty_password_buffer,
        finish_successful_password_write_after_secret_drop, forget_password_editor_state,
        password_editor_cursor_x, password_editor_display, password_editor_id,
        password_editor_regions, password_visibility_button, password_visibility_id,
        poll_background_account_toggle_with, pop_password_char, projected_enabled_email_conflict,
        rebase_editor_enabled_state, record_queued_account_toggle_intent,
        request_background_account_toggle, restore_and_verify_password_after_journal_with,
        restore_and_verify_password_with, run_account_toggle_batch, run_account_toggle_job,
        scrub_password_event_copies, secure_password_editor,
        start_queued_background_account_toggle_with_spawner, submit_account_toggle_worker,
        suppress_password_clipboard_output, toggle_account_transaction,
        validate_authoritative_account_toggle, AccountToggleBatchResult, AccountToggleCompletion,
        AccountToggleIntent, AccountToggleJobResult, AccountTransactionIntent,
        PasswordRollbackWrite, PendingAccountToggle, ToggleAccountOutcome,
        ACCOUNT_EDITOR_CONTROL_HEIGHT, ACCOUNT_EDITOR_FIELD_WIDTH, ACCOUNT_EDITOR_LABEL_WIDTH,
        ACCOUNT_EDITOR_TOGGLE_WIDTH, ACCOUNT_TOGGLE_JOB_DISCONNECTED_REASON,
    };
    use crate::app::{AutoLoginApp, CONFIG_MUTATION_RECOVERY_REASON};
    use crate::background::{WorkerCommand, WorkerInvalidator};
    use crate::models::{Account, AppConfig, Tab};
    use crate::storage::{
        committed_config_write_test_error, PasswordStorageBackend, StaleBackendCleanupWarning,
    };
    use eframe::egui;
    use std::cell::{Cell, RefCell};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::mpsc::{channel, sync_channel, TryRecvError};
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tokio::sync::mpsc::channel as tokio_channel;

    fn account_test_app(config: AppConfig) -> AutoLoginApp {
        account_test_app_with_mode(config, false)
    }

    fn account_test_app_with_mode(config: AppConfig, settings_window_mode: bool) -> AutoLoginApp {
        let (worker_tx, _worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (_tray_tx, tray_rx) = channel();
        AutoLoginApp::new(
            worker_tx,
            WorkerInvalidator::new().pause_latch(),
            tray_rx,
            worker_event_rx,
            config,
            settings_window_mode,
            crate::models::Tab::Accounts,
        )
    }

    fn clean_toggle_outcome(config: &AppConfig, enabled: bool) -> ToggleAccountOutcome {
        let mut config = config.clone();
        config.accounts[0].enabled = enabled;
        ToggleAccountOutcome {
            config,
            config_durability_warning: false,
            journal_cleanup_warning: false,
        }
    }

    fn clean_toggle_completion(config: &AppConfig, enabled: bool) -> AccountToggleCompletion {
        AccountToggleCompletion::Finished(AccountToggleJobResult {
            config: clean_toggle_outcome(config, enabled).config,
            status: None,
            applied: true,
            failed_intent: None,
            recovery_pending: false,
            recovery_signal_confirmed: true,
            blocked_reason: None,
        })
    }

    fn pending_toggle(
        base_config: AppConfig,
        requested_enabled: bool,
        completion: AccountToggleCompletion,
    ) -> PendingAccountToggle {
        let account_id = base_config.accounts[0].id.clone();
        let (sender, receiver) = sync_channel(1);
        sender.send(completion).unwrap();
        let (intent_sender, _intent_receiver) = sync_channel(1);
        PendingAccountToggle {
            receiver,
            base_config,
            intent_sender,
            displayed_intents: vec![AccountToggleIntent {
                sequence: 1,
                account_id,
                enabled: requested_enabled,
            }],
            deferred_local_sync_required: false,
            deferred_refresh_passwords_required: false,
        }
    }

    fn clean_toggle_batch(config: &AppConfig, enabled: bool) -> AccountToggleBatchResult {
        AccountToggleBatchResult {
            config: clean_toggle_outcome(config, enabled).config,
            status: None,
            applied: true,
            failed_intent: None,
            config_durability_warning: false,
            journal_cleanup_warning: false,
        }
    }

    fn failed_toggle_batch(config: &AppConfig, status: &str) -> AccountToggleBatchResult {
        AccountToggleBatchResult {
            config: config.clone(),
            status: Some(status.to_string()),
            applied: false,
            failed_intent: None,
            config_durability_warning: false,
            journal_cleanup_warning: false,
        }
    }

    #[test]
    fn blocked_toggle_begin_runs_off_the_ui_owner_thread() {
        let config = config_with_account(true);
        let mut app = account_test_app(config.clone());
        let guard = app
            .reserve_background_settings_mutation_with_cancel(|| Ok(()))
            .expect("test mutation must be reserved");
        let (begin_started_tx, begin_started_rx) = channel();
        let (release_begin_tx, release_begin_rx) = channel();
        let owner_thread = std::thread::current().id();
        let outcome = clean_toggle_batch(&config, false);

        let receiver = submit_account_toggle_worker(
            app.background_mutation_executor().unwrap(),
            move || {
                run_account_toggle_job(
                    guard,
                    true,
                    move || {
                        begin_started_tx.send(std::thread::current().id()).unwrap();
                        release_begin_rx.recv().unwrap();
                        Ok(())
                    },
                    || Ok(()),
                    || true,
                    move || outcome,
                    || Ok(()),
                )
            },
            egui::Context::default(),
        )
        .expect("account toggle worker must start");

        let worker_thread = begin_started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("background begin must start");
        assert_ne!(worker_thread, owner_thread);
        assert!(matches!(receiver.try_recv(), Err(TryRecvError::Empty)));

        release_begin_tx.send(()).unwrap();
        assert!(matches!(
            receiver.recv_timeout(Duration::from_secs(1)),
            Ok(AccountToggleCompletion::Finished(_))
        ));
    }

    #[test]
    fn clean_toggle_rejection_cancels_once_without_reload_or_recovery_signal() {
        let config = config_with_account(true);
        let mut app = account_test_app(config.clone());
        let cancel_count = Arc::new(AtomicUsize::new(0));
        let count_for_cancel = cancel_count.clone();
        let guard = app
            .reserve_background_settings_mutation_with_cancel(move || {
                count_for_cancel.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .unwrap();

        let completion = run_account_toggle_job(
            guard,
            true,
            || Ok(()),
            || -> anyhow::Result<()> { panic!("a rejected update must not reload") },
            || true,
            || failed_toggle_batch(&config, "Failed to update account"),
            || -> anyhow::Result<()> { panic!("a clean rejection must not signal recovery") },
        );

        let AccountToggleCompletion::Finished(result) = completion else {
            panic!("begin unexpectedly failed");
        };
        assert_eq!(cancel_count.load(Ordering::SeqCst), 1);
        assert!(!result.applied);
        assert!(!result.recovery_pending);
        assert_eq!(result.config, config);
        assert_eq!(result.status.as_deref(), Some("Failed to update account"));
        assert!(result.blocked_reason.is_none());
    }

    #[test]
    fn ambiguous_toggle_failure_is_fail_closed_and_signals_recovery() {
        let config = config_with_account(true);
        let mut app = account_test_app(config.clone());
        let cancel_count = Arc::new(AtomicUsize::new(0));
        let count_for_cancel = cancel_count.clone();
        let signal_count = Arc::new(AtomicUsize::new(0));
        let count_for_signal = signal_count.clone();
        let guard = app
            .reserve_background_settings_mutation_with_cancel(move || {
                count_for_cancel.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .unwrap();

        let completion = run_account_toggle_job(
            guard,
            true,
            || Ok(()),
            || -> anyhow::Result<()> { panic!("recovery-pending update must not reload") },
            || false,
            || failed_toggle_batch(&config, "Account update durability is ambiguous"),
            move || {
                count_for_signal.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        );

        let AccountToggleCompletion::Finished(result) = completion else {
            panic!("begin unexpectedly failed");
        };
        assert_eq!(cancel_count.load(Ordering::SeqCst), 0);
        assert_eq!(signal_count.load(Ordering::SeqCst), 1);
        assert!(!result.applied);
        assert!(result.recovery_pending);
        assert!(result.recovery_signal_confirmed);
        assert_eq!(
            result.blocked_reason.as_deref(),
            Some(CONFIG_MUTATION_RECOVERY_REASON)
        );
    }

    #[test]
    fn unconfirmed_recovery_signal_is_retried_by_the_ui_owner() {
        let config = config_with_account(true);
        let mut app = account_test_app_with_mode(config.clone(), true);
        app.pending_account_toggle = Some(pending_toggle(
            config.clone(),
            false,
            AccountToggleCompletion::Finished(AccountToggleJobResult {
                config,
                status: Some("Account update durability is ambiguous".to_string()),
                applied: false,
                failed_intent: None,
                recovery_pending: true,
                recovery_signal_confirmed: false,
                blocked_reason: Some(CONFIG_MUTATION_RECOVERY_REASON.to_string()),
            }),
        ));
        let recovery_count = Cell::new(0);

        poll_background_account_toggle_with(
            &mut app,
            &egui::Context::default(),
            |_, _, _, _| panic!("a recovery-pending update must not start a settings save"),
            |_, _, _, _| panic!("a recovery-pending update must not start a successor"),
            |app, _ctx| {
                recovery_count.set(recovery_count.get() + 1);
                app.apply_background_storage_recovery_block();
            },
        );

        assert_eq!(recovery_count.get(), 1);
        assert!(!app.account_mutations_ready());
    }

    #[test]
    fn clean_toggle_success_reloads_once_without_success_status() {
        let config = config_with_account(true);
        let mut app = account_test_app(config.clone());
        let guard = app
            .reserve_background_settings_mutation_with_cancel(|| Ok(()))
            .unwrap();
        let reload_count = Arc::new(AtomicUsize::new(0));
        let count_for_reload = reload_count.clone();
        let outcome = clean_toggle_batch(&config, false);

        let completion = run_account_toggle_job(
            guard,
            true,
            || Ok(()),
            move || {
                count_for_reload.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            || true,
            move || outcome,
            || -> anyhow::Result<()> { panic!("clean update must not signal recovery") },
        );

        let AccountToggleCompletion::Finished(result) = completion else {
            panic!("begin unexpectedly failed");
        };
        assert_eq!(reload_count.load(Ordering::SeqCst), 1);
        assert!(result.applied);
        assert!(!result.config.accounts[0].enabled);
        assert!(result.status.is_none());
        assert!(result.blocked_reason.is_none());
    }

    #[test]
    fn pending_toggle_renders_requested_value_without_mutating_base_config() {
        let config = config_with_account(true);
        let pending = PendingAccountToggle::inert_for_test(config.clone());

        assert!(config.accounts[0].enabled);
        assert_eq!(
            pending.displayed_enabled(&config.accounts[0]),
            Some((1, false))
        );
        assert_eq!(pending.base_config, config);
    }

    #[test]
    fn duplicate_email_validation_uses_projected_toggle_state() {
        let mut config = config_with_account(true);
        let mut duplicate = Account::new("USER@example.com");
        duplicate.id = "account-2".to_string();
        duplicate.has_saved_password = true;
        duplicate.enabled = false;
        config.accounts.push(duplicate);
        let mut app = account_test_app(config.clone());

        assert!(projected_enabled_email_conflict(
            &app,
            "account-2",
            "user@example.com"
        ));

        app.pending_account_toggle = Some(PendingAccountToggle::inert_for_test(config));

        assert!(!projected_enabled_email_conflict(
            &app,
            "account-2",
            "user@example.com"
        ));
    }

    #[test]
    fn failed_executor_submission_reverts_intent_and_disables_mutations_without_retry() {
        let config = config_with_account(true);
        let mut app = account_test_app(config.clone());
        app.queued_account_toggles.push(AccountToggleIntent {
            sequence: 1,
            account_id: config.accounts[0].id.clone(),
            enabled: false,
        });
        let ctx = egui::Context::default();

        let started = start_queued_background_account_toggle_with_spawner(
            &mut app,
            &ctx,
            false,
            false,
            |job, _| {
                drop(job);
                Err(std::io::Error::other("synthetic submission failure"))
            },
        );

        assert!(!started);
        assert!(app.pending_account_toggle.is_none());
        assert!(app.queued_account_toggles.is_empty());
        assert!(app.account_toggle_start_retry_at.is_none());
        assert!(app.config.accounts[0].enabled);
        assert!(!app.account_mutations_ready());
        assert!(app.settings_save_fail_closed_reason().is_some());
        assert!(app.status_message.is_none());
        assert!(app.account_toggle_failure_status_sequence.is_none());
    }

    #[test]
    fn rapid_toggle_away_and_back_coalesces_without_a_durable_write() {
        let config = config_with_account(true);
        let account_id = config.accounts[0].id.clone();
        let (intent_sender, intent_receiver) = channel();
        intent_sender
            .send(AccountToggleIntent {
                sequence: 2,
                account_id: account_id.clone(),
                enabled: true,
            })
            .unwrap();
        drop(intent_sender);
        let transaction_count = Cell::new(0);

        let result = run_account_toggle_batch(
            config.clone(),
            vec![AccountToggleIntent {
                sequence: 1,
                account_id,
                enabled: false,
            }],
            intent_receiver,
            Duration::ZERO,
            Duration::ZERO,
            |_, _| {
                transaction_count.set(transaction_count.get() + 1);
                panic!("a coalesced no-op must not touch durable storage")
            },
        );

        assert!(!result.applied);
        assert_eq!(result.config, config);
        assert_eq!(transaction_count.get(), 0);
        assert!(result.status.is_none());
    }

    #[test]
    fn save_barrier_preserves_off_and_on_as_separate_toggle_segments() {
        let config = config_with_account(true);
        let account = config.accounts[0].clone();
        let account_id = account.id.clone();
        let mut app = account_test_app(config);

        record_queued_account_toggle_intent(
            &mut app,
            AccountToggleIntent {
                sequence: 1,
                account_id: account_id.clone(),
                enabled: false,
            },
        );
        app.queued_account_transactions
            .push_back(AccountTransactionIntent::Save {
                sequence: 2,
                account,
                was_existing: true,
                password: None,
            });
        record_queued_account_toggle_intent(
            &mut app,
            AccountToggleIntent {
                sequence: 3,
                account_id,
                enabled: true,
            },
        );

        assert_eq!(
            app.queued_account_toggles
                .iter()
                .map(|intent| (intent.sequence, intent.enabled))
                .collect::<Vec<_>>(),
            vec![(1, false), (3, true)]
        );
        assert_eq!(
            app.queued_account_transactions
                .front()
                .map(AccountTransactionIntent::sequence),
            Some(2)
        );
    }

    #[test]
    fn queued_password_save_does_not_reject_a_following_enable_click() {
        let mut config = config_with_account(false);
        config.accounts[0].enabled = false;
        let account = config.accounts[0].clone();
        let account_id = account.id.clone();
        let mut app = account_test_app(config);
        app.status_message = None;
        app.next_account_toggle_intent_sequence = 1;
        app.queued_account_transactions
            .push_back(AccountTransactionIntent::Save {
                sequence: 1,
                account: account.clone(),
                was_existing: true,
                password: Some(zeroize::Zeroizing::new("queued password".to_string())),
            });
        app.pending_settings_save =
            Some(crate::ui::settings::PendingSettingsSave::inert_for_test());

        assert_eq!(
            eager_account_toggle_validation_error(&app, &account, true),
            None
        );
        request_background_account_toggle(
            &mut app,
            &egui::Context::default(),
            account_id.clone(),
            true,
        );

        assert_eq!(app.queued_account_transactions.len(), 1);
        assert_eq!(app.queued_account_toggles.len(), 1);
        assert_eq!(app.queued_account_toggles[0].account_id, account_id);
        assert!(app.queued_account_toggles[0].enabled);
        assert!(app.status_message.is_none());
    }

    #[test]
    fn worker_revalidates_password_before_enabling_an_account() {
        let config = config_with_account(false);
        let account = &config.accounts[0];

        assert_eq!(
            validate_authoritative_account_toggle(&config, account, true),
            Err("Password is required before enabling this account".to_string())
        );
        assert_eq!(
            validate_authoritative_account_toggle(&config, account, false),
            Ok(())
        );
    }

    #[test]
    fn clean_local_noop_and_failure_release_authoritative_config_on_original_epoch() {
        for (requested_enabled, failed_intent) in [
            (true, None),
            (
                false,
                Some(AccountToggleIntent {
                    sequence: 1,
                    account_id: "account-1".to_string(),
                    enabled: false,
                }),
            ),
        ] {
            let config = config_with_account(true);
            let (worker_tx, mut worker_rx) = tokio_channel(8);
            let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
            let (_tray_tx, tray_rx) = channel();
            let pause_latch = WorkerInvalidator::new().pause_latch();
            let mut app = AutoLoginApp::new(
                worker_tx,
                pause_latch.clone(),
                tray_rx,
                worker_event_rx,
                config.clone(),
                false,
                crate::models::Tab::Accounts,
            );
            let begin = app.prepare_background_settings_mutation_begin();
            let pause_epoch = pause_latch.current_epoch();
            drop(begin);
            let completion = AccountToggleCompletion::Finished(AccountToggleJobResult {
                config: config.clone(),
                status: failed_intent
                    .as_ref()
                    .map(|_| "Failed to update account".to_string()),
                applied: false,
                failed_intent,
                recovery_pending: false,
                recovery_signal_confirmed: true,
                blocked_reason: None,
            });
            app.pending_account_toggle = Some(pending_toggle(
                config.clone(),
                requested_enabled,
                completion,
            ));

            poll_background_account_toggle_with(
                &mut app,
                &egui::Context::default(),
                |app, _, _, _| {
                    assert_eq!(app.settings_draft, app.config.settings);
                    false
                },
                |app, _, _, _| {
                    assert!(app.queued_account_toggles.is_empty());
                    false
                },
                |_, _| panic!("a clean result must not enter recovery"),
            );

            match worker_rx.try_recv().expect("one final release is required") {
                WorkerCommand::ApplyConfigAndReleasePause {
                    settings,
                    accounts,
                    pause_epoch: released_epoch,
                    ..
                } => {
                    assert_eq!(released_epoch, pause_epoch);
                    assert_eq!(settings, config.settings);
                    assert_eq!(accounts, config.accounts);
                }
                other => panic!("expected one authoritative config release, got {other:?}"),
            }
            assert!(worker_rx.try_recv().is_err());
        }
    }

    #[test]
    fn continuous_intents_cannot_postpone_the_first_transaction_indefinitely() {
        let config = config_with_account(true);
        let account_id = config.accounts[0].id.clone();
        let (intent_sender, intent_receiver) = channel();
        let transaction_started = Arc::new(AtomicBool::new(false));
        let producer_saw_transaction = transaction_started.clone();
        let producer_account_id = account_id.clone();
        let producer = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            let mut sequence = 2;
            while !producer_saw_transaction.load(Ordering::SeqCst) {
                if Instant::now() >= deadline {
                    return false;
                }
                if intent_sender
                    .send(AccountToggleIntent {
                        sequence,
                        account_id: producer_account_id.clone(),
                        enabled: false,
                    })
                    .is_err()
                {
                    return false;
                }
                sequence += 1;
                std::thread::sleep(Duration::from_millis(2));
            }
            true
        });
        let transaction_started_in_worker = transaction_started.clone();

        let result = run_account_toggle_batch(
            config,
            vec![AccountToggleIntent {
                sequence: 1,
                account_id,
                enabled: false,
            }],
            intent_receiver,
            Duration::from_millis(20),
            Duration::from_millis(60),
            |current, intent| {
                transaction_started_in_worker.store(true, Ordering::SeqCst);
                let mut next = current.clone();
                next.accounts[0].enabled = intent.enabled;
                Ok(ToggleAccountOutcome {
                    config: next,
                    config_durability_warning: false,
                    journal_cleanup_warning: false,
                })
            },
        );

        assert!(producer.join().unwrap());
        assert!(result.applied);
        assert!(!result.config.accounts[0].enabled);
    }

    #[test]
    fn toggles_for_different_accounts_are_serialized_in_one_batch() {
        let mut config = config_with_account(true);
        let mut second = Account::new("second@example.com");
        second.id = "account-2".to_string();
        second.has_saved_password = true;
        config.accounts.push(second);
        let (intent_sender, intent_receiver) = channel::<AccountToggleIntent>();
        drop(intent_sender);
        let applied_ids = RefCell::new(Vec::new());

        let result = run_account_toggle_batch(
            config.clone(),
            vec![
                AccountToggleIntent {
                    sequence: 1,
                    account_id: "account-1".to_string(),
                    enabled: false,
                },
                AccountToggleIntent {
                    sequence: 2,
                    account_id: "account-2".to_string(),
                    enabled: false,
                },
            ],
            intent_receiver,
            Duration::ZERO,
            Duration::ZERO,
            |current, intent| {
                applied_ids.borrow_mut().push(intent.account_id.clone());
                let mut next = current.clone();
                let account = next
                    .accounts
                    .iter_mut()
                    .find(|account| account.id == intent.account_id)
                    .unwrap();
                account.enabled = intent.enabled;
                Ok(ToggleAccountOutcome {
                    config: next,
                    config_durability_warning: false,
                    journal_cleanup_warning: false,
                })
            },
        );

        assert!(result.applied);
        assert_eq!(
            applied_ids.into_inner(),
            vec!["account-1".to_string(), "account-2".to_string()]
        );
        assert!(result
            .config
            .accounts
            .iter()
            .all(|account| !account.enabled));
    }

    #[test]
    fn newer_visible_intent_starts_one_successor_after_active_completion() {
        let config = config_with_account(true);
        let account_id = config.accounts[0].id.clone();
        let mut pending = pending_toggle(
            config.clone(),
            false,
            clean_toggle_completion(&config, false),
        );
        pending.record_intent(AccountToggleIntent {
            sequence: 2,
            account_id,
            enabled: true,
        });
        let mut app = account_test_app_with_mode(config, true);
        app.pending_account_toggle = Some(pending);
        let successor_count = Cell::new(0);

        poll_background_account_toggle_with(
            &mut app,
            &egui::Context::default(),
            |_, _, _, _| panic!("a queued account successor must run before settings"),
            |app, _, local_sync_required, refresh_passwords_required| {
                successor_count.set(successor_count.get() + 1);
                assert!(!local_sync_required);
                assert!(!refresh_passwords_required);
                assert_eq!(app.queued_account_toggles.len(), 1);
                assert!(app.queued_account_toggles[0].enabled);
                true
            },
            |_, _| panic!("a clean completion must not enter recovery"),
        );

        assert_eq!(successor_count.get(), 1);
        assert!(!app.config.accounts[0].enabled);
    }

    #[test]
    fn clean_failed_intent_is_not_retried_without_a_newer_click() {
        let config = config_with_account(true);
        let failed_intent = AccountToggleIntent {
            sequence: 1,
            account_id: config.accounts[0].id.clone(),
            enabled: false,
        };
        let completion = AccountToggleCompletion::Finished(AccountToggleJobResult {
            config: config.clone(),
            status: Some("Failed to update account".to_string()),
            applied: false,
            failed_intent: Some(failed_intent),
            recovery_pending: false,
            recovery_signal_confirmed: true,
            blocked_reason: None,
        });
        let mut app = account_test_app_with_mode(config.clone(), true);
        app.pending_account_toggle = Some(pending_toggle(config, false, completion));

        poll_background_account_toggle_with(
            &mut app,
            &egui::Context::default(),
            |app, _, _, _| {
                assert_eq!(app.settings_draft, app.config.settings);
                false
            },
            |app, _, _, _| {
                assert!(app.queued_account_toggles.is_empty());
                false
            },
            |_, _| panic!("a clean rejection must not enter recovery"),
        );

        assert!(app.queued_account_toggles.is_empty());
        assert!(app.config.accounts[0].enabled);
    }

    #[test]
    fn newer_explicit_retry_survives_a_clean_failure_of_the_same_target() {
        let config = config_with_account(true);
        let account_id = config.accounts[0].id.clone();
        let failed_intent = AccountToggleIntent {
            sequence: 1,
            account_id: account_id.clone(),
            enabled: false,
        };
        let completion = AccountToggleCompletion::Finished(AccountToggleJobResult {
            config: config.clone(),
            status: Some("Failed to update account".to_string()),
            applied: false,
            failed_intent: Some(failed_intent),
            recovery_pending: false,
            recovery_signal_confirmed: true,
            blocked_reason: None,
        });
        let mut pending = pending_toggle(config.clone(), false, completion);
        pending.record_intent(AccountToggleIntent {
            sequence: 2,
            account_id: account_id.clone(),
            enabled: true,
        });
        pending.record_intent(AccountToggleIntent {
            sequence: 3,
            account_id,
            enabled: false,
        });
        let mut app = account_test_app_with_mode(config, true);
        app.status_message = None;
        app.pending_account_toggle = Some(pending);
        let successor_count = Cell::new(0);

        poll_background_account_toggle_with(
            &mut app,
            &egui::Context::default(),
            |_, _, _, _| panic!("an explicit account retry must run before settings"),
            |app, _, _, _| {
                successor_count.set(successor_count.get() + 1);
                assert_eq!(app.queued_account_toggles.len(), 1);
                assert_eq!(app.queued_account_toggles[0].sequence, 3);
                assert!(!app.queued_account_toggles[0].enabled);
                true
            },
            |_, _| panic!("a clean rejection must not enter recovery"),
        );

        assert_eq!(successor_count.get(), 1);
        assert!(app.config.accounts[0].enabled);
        assert!(app.status_message.is_none());
        assert!(app.account_toggle_failure_status_sequence.is_none());
    }

    #[test]
    fn settings_change_queued_during_toggle_starts_after_clean_completion() {
        let mut config = config_with_account(true);
        config.settings.start_minimized = false;
        let mut app = account_test_app_with_mode(config.clone(), true);
        app.settings_draft.start_minimized = true;
        app.pending_account_toggle = Some(pending_toggle(
            config.clone(),
            false,
            clean_toggle_completion(&config, false),
        ));
        let follow_up_count = Cell::new(0);

        poll_background_account_toggle_with(
            &mut app,
            &egui::Context::default(),
            |app, _ctx, local_sync_required, refresh_passwords_required| {
                follow_up_count.set(follow_up_count.get() + 1);
                assert!(!local_sync_required);
                assert!(!refresh_passwords_required);
                assert!(!app.config.accounts[0].enabled);
                assert!(app.settings_draft.start_minimized);
                true
            },
            |app, _, _, _| {
                assert!(app.queued_account_toggles.is_empty());
                false
            },
            |_, _| panic!("a clean completion must not enter recovery"),
        );

        assert_eq!(follow_up_count.get(), 1);
        assert!(app.settings_draft.start_minimized);
        assert!(app.pending_account_toggle.is_none());
    }

    #[test]
    fn toggle_completion_is_applied_after_switching_to_settings_tab() {
        let config = config_with_account(true);
        let mut app = account_test_app_with_mode(config.clone(), true);
        app.selected_tab = Tab::Settings;
        app.status_message = Some(("Existing warning".to_string(), 8.0));
        app.pending_account_toggle = Some(pending_toggle(
            config.clone(),
            false,
            clean_toggle_completion(&config, false),
        ));
        let follow_up_count = Cell::new(0);

        poll_background_account_toggle_with(
            &mut app,
            &egui::Context::default(),
            |app, _ctx, local_sync_required, refresh_passwords_required| {
                follow_up_count.set(follow_up_count.get() + 1);
                assert!(!local_sync_required);
                assert!(!refresh_passwords_required);
                assert_eq!(app.settings_draft, app.config.settings);
                false
            },
            |app, _, _, _| {
                assert!(app.queued_account_toggles.is_empty());
                false
            },
            |_, _| panic!("a clean completion must not enter recovery"),
        );

        assert_eq!(app.selected_tab, Tab::Settings);
        assert!(!app.config.accounts[0].enabled);
        assert_eq!(follow_up_count.get(), 1);
        assert_eq!(
            app.status_message
                .as_ref()
                .map(|(message, _)| message.as_str()),
            Some("Existing warning")
        );
    }

    #[test]
    fn disconnected_toggle_preserves_queued_settings_and_enters_recovery() {
        let config = config_with_account(true);
        let mut app = account_test_app_with_mode(config.clone(), true);
        app.settings_draft.start_minimized = true;
        let queued_settings = app.settings_draft.clone();
        let account_id = config.accounts[0].id.clone();
        let (sender, receiver) = sync_channel(1);
        drop(sender);
        let (intent_sender, _intent_receiver) = sync_channel(1);
        app.pending_account_toggle = Some(PendingAccountToggle {
            receiver,
            base_config: config,
            intent_sender,
            displayed_intents: vec![AccountToggleIntent {
                sequence: 1,
                account_id,
                enabled: false,
            }],
            deferred_local_sync_required: false,
            deferred_refresh_passwords_required: false,
        });
        let recovery_count = Cell::new(0);

        poll_background_account_toggle_with(
            &mut app,
            &egui::Context::default(),
            |_, _, _, _| panic!("a disconnected update must not start a settings save"),
            |_, _, _, _| panic!("a disconnected update must not start a successor"),
            |app, _ctx| {
                recovery_count.set(recovery_count.get() + 1);
                app.apply_background_storage_recovery_block();
            },
        );

        assert_eq!(recovery_count.get(), 1);
        assert_eq!(app.settings_draft, queued_settings);
        assert_eq!(
            app.config_mutations_disabled_reason(),
            Some(ACCOUNT_TOGGLE_JOB_DISCONNECTED_REASON)
        );
        assert!(!app.account_mutations_ready());
    }

    #[test]
    fn stale_toggle_completion_keeps_current_config_and_enters_recovery() {
        let config = config_with_account(true);
        let mut app = account_test_app_with_mode(config.clone(), true);
        app.pending_account_toggle = Some(pending_toggle(
            config.clone(),
            false,
            clean_toggle_completion(&config, false),
        ));
        app.config.accounts[0].username = "newer@example.com".to_string();
        app.settings_draft.start_minimized = true;
        let queued_settings = app.settings_draft.clone();
        let recovery_count = Cell::new(0);

        poll_background_account_toggle_with(
            &mut app,
            &egui::Context::default(),
            |_, _, _, _| panic!("a stale completion must not start a settings save"),
            |_, _, _, _| panic!("a stale completion must not start a successor"),
            |app, _ctx| {
                recovery_count.set(recovery_count.get() + 1);
                app.apply_background_storage_recovery_block();
            },
        );

        assert_eq!(recovery_count.get(), 1);
        assert_eq!(app.config.accounts[0].username, "newer@example.com");
        assert!(app.config.accounts[0].enabled);
        assert_eq!(app.settings_draft, queued_settings);
        assert_eq!(
            app.config_mutations_disabled_reason(),
            Some(ACCOUNT_TOGGLE_JOB_DISCONNECTED_REASON)
        );
    }

    #[test]
    fn pending_toggle_keeps_every_account_control_interactive_but_serializes_durable_commits() {
        let config = config_with_account(true);
        let mut app = account_test_app(config.clone());
        app.pending_account_toggle = Some(PendingAccountToggle::inert_for_test(config));
        let availability = account_control_availability(&app);

        assert!(app.account_mutations_ready());
        assert!(app.account_transaction_ready());
        assert!(app.settings_mutations_disabled_reason().is_none());
        assert!(availability.toggle_controls_ready);
        assert!(availability.launch_controls_ready);
        assert!(availability.transaction_controls_ready);
        assert!(availability.transaction_disabled_reason.is_none());
        assert!(app
            .reserve_background_settings_mutation_with_cancel(|| Ok(()))
            .is_none());
    }

    #[test]
    fn pending_settings_save_keeps_every_account_control_interactive() {
        let config = config_with_account(true);
        let mut app = account_test_app(config);
        app.pending_settings_save =
            Some(crate::ui::settings::PendingSettingsSave::inert_for_test());

        let availability = account_control_availability(&app);

        assert!(availability.toggle_controls_ready);
        assert!(availability.launch_controls_ready);
        assert!(availability.transaction_controls_ready);
        assert!(availability.transaction_disabled_reason.is_none());
        assert!(app.settings_mutations_disabled_reason().is_none());
    }

    #[test]
    fn fail_closed_state_disables_every_account_control_with_the_actual_reason() {
        let app = account_test_app(config_with_account(true)).with_storage_recovery_state(false);

        let availability = account_control_availability(&app);

        assert!(!availability.toggle_controls_ready);
        assert!(!availability.transaction_controls_ready);
        assert_eq!(
            availability.transaction_disabled_reason.as_deref(),
            Some(CONFIG_MUTATION_RECOVERY_REASON)
        );
    }

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

        let status = account_saved_status(Some(&warning), false, false, false).unwrap();

        assert!(status.contains("Account saved"));
        assert!(status.contains("system secure storage"));
        assert!(status.contains("old encrypted fallback file cleanup is still pending"));
        assert!(status.contains("will retry on next launch"));
        assert!(status.contains("Stored credential changes are blocked"));
        assert!(!status.contains("storage_error"));
    }

    #[test]
    fn account_saved_status_surfaces_key_cleanup_and_durability_without_secrets() {
        let status = account_saved_status(None, true, true, false).unwrap();

        assert!(status.contains("Account saved"));
        assert!(status.contains("fallback encryption-key cleanup is still pending"));
        assert!(status.contains("Disk durability could not be confirmed"));
        assert!(!status.contains("account-1"));
    }

    #[test]
    fn account_saved_status_is_absent_after_clean_save() {
        assert_eq!(account_saved_status(None, false, false, false), None);
    }

    #[test]
    fn account_saved_status_surfaces_recovery_journal_cleanup_warning() {
        let status = account_saved_status(None, false, false, true).unwrap();

        assert!(status.contains("Recovery journal cleanup is still pending"));
        assert!(status.contains("restart before changing stored credentials again"));
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
    fn account_mutation_sync_never_requests_the_main_window_to_close() {
        let implementation = include_str!("accounts.rs");
        let production = implementation
            .split_once("#[cfg(test)]\nmod tests")
            .expect("accounts test module boundary must exist")
            .0;

        assert!(production.contains("app.refresh_passwords |= refresh_passwords;"));
        assert!(!production.contains("sync_saved_config_to_worker_and_close_settings"));
    }

    #[test]
    fn clean_account_deletion_has_no_redundant_success_status() {
        assert_eq!(account_deletion_status(false, false, false, false), None);

        for flags in [
            (true, false, false, false),
            (false, true, false, false),
            (false, false, true, false),
            (false, false, false, true),
        ] {
            let status = account_deletion_status(flags.0, flags.1, flags.2, flags.3)
                .expect("cleanup warning must remain visible");
            assert!(status.starts_with("Account deleted"));
            assert_ne!(status, "Account deleted");
        }
    }

    #[test]
    fn clean_account_toggle_has_no_redundant_success_status() {
        assert_eq!(account_updated_status(false, false), None);

        let durability = account_updated_status(true, false).unwrap();
        assert!(durability.contains("disk durability could not be confirmed"));

        let journal = account_updated_status(false, true).unwrap();
        assert!(journal.contains("recovery journal cleanup is pending"));

        assert_eq!(account_updated_status(true, true), Some(durability));
    }

    #[test]
    fn successful_account_save_closes_only_the_editor() {
        let implementation = include_str!("accounts.rs");
        let editor = implementation
            .split_once("fn show_account_editor(")
            .expect("account editor must exist")
            .1
            .split_once("enum AccountActionIcon")
            .expect("account editor boundary must exist")
            .0;

        assert!(editor
            .contains("close_editor = save_edited_account(app, ui.ctx(), &account, is_existing);"));
        assert!(editor.contains("if close_editor {\n        editing = None;\n    }"));
        assert!(!editor.contains("ViewportCommand::Close"));
    }

    #[test]
    fn stale_editor_snapshot_cannot_overwrite_a_completed_enabled_toggle() {
        let mut authoritative = Account::new("old@example.com");
        authoritative.id = "account-1".to_string();
        authoritative.has_saved_password = true;
        authoritative.enabled = false;

        let mut stale_editor_snapshot = authoritative.clone();
        stale_editor_snapshot.username = "new@example.com".to_string();
        stale_editor_snapshot.enabled = true;

        let rebased = rebase_editor_enabled_state(&stale_editor_snapshot, Some(&authoritative));

        assert_eq!(rebased.username, "new@example.com");
        assert!(!rebased.enabled);
        assert!(rebased.has_saved_password);
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
    fn password_editor_display_masks_and_reveals_unicode_without_changing_password() {
        let password = zeroize::Zeroizing::new("sëcret🔐".to_string());
        let original_ptr = password.as_ptr();

        let masked = password_editor_display(password.as_str(), false, "Password");
        let expected_mask: String = std::iter::repeat_n(
            egui::epaint::text::PASSWORD_REPLACEMENT_CHAR,
            password.chars().count(),
        )
        .collect();
        assert_eq!(masked, expected_mask);
        assert!(!masked.contains(password.as_str()));

        let revealed = password_editor_display(password.as_str(), true, "Password");
        assert_eq!(revealed, password.as_str());
        assert_eq!(revealed.as_ptr(), original_ptr);
        assert_eq!(password.as_str(), "sëcret🔐");
    }

    #[test]
    fn empty_password_uses_hint_in_both_visibility_modes() {
        for reveal in [false, true] {
            let display = password_editor_display("", reveal, "Password");
            assert_eq!(display, "Password");
        }
    }

    #[test]
    fn password_editor_regions_embed_visibility_in_single_control() {
        let outer = egui::Rect::from_min_size(
            egui::pos2(17.0, 23.0),
            egui::vec2(ACCOUNT_EDITOR_FIELD_WIDTH, ACCOUNT_EDITOR_CONTROL_HEIGHT),
        );
        let (text, visibility) = password_editor_regions(outer);

        assert_eq!(outer.size(), egui::vec2(332.0, 28.0));
        assert_eq!(visibility.size(), egui::vec2(38.0, 28.0));
        assert_eq!(visibility.width(), ACCOUNT_EDITOR_TOGGLE_WIDTH);
        assert!(outer.contains_rect(visibility));
        assert_eq!(text.union(visibility), outer);
        assert_eq!(text.right(), visibility.left());
        assert_eq!(visibility.right(), outer.right());
        assert_eq!(text.center().y, visibility.center().y);
    }

    #[test]
    fn account_editor_fields_keep_idle_outline_on_hover_and_focus_outline_distinct() {
        let ctx = egui::Context::default();
        crate::ui::theme::apply(&ctx);
        let mut strokes = None;

        let _ = ctx.run_ui(Default::default(), |ui| {
            let outer_hovered = ui.visuals().widgets.hovered.bg_stroke;
            account_editor_input_scope(ui, |ui| {
                strokes = Some((
                    ui.visuals().widgets.inactive.bg_stroke,
                    ui.visuals().widgets.hovered.bg_stroke,
                    ui.visuals().selection.stroke,
                    outer_hovered,
                ));
            });
            assert_eq!(ui.visuals().widgets.hovered.bg_stroke, outer_hovered);
        });

        let (idle, hovered, focused, outer_hovered) = strokes.unwrap();
        assert_eq!(hovered, idle);
        assert_ne!(focused, idle);
        assert_ne!(outer_hovered, idle);
    }

    #[test]
    fn embedded_visibility_button_does_not_advance_layout_cursor() {
        let ctx = egui::Context::default();
        crate::ui::theme::apply(&ctx);
        let mut result = None;

        let _ = ctx.run_ui(Default::default(), |ui| {
            let outer = egui::Rect::from_min_size(
                ui.cursor().min,
                egui::vec2(ACCOUNT_EDITOR_FIELD_WIDTH, ACCOUNT_EDITOR_CONTROL_HEIGHT),
            );
            let (_, visibility) = password_editor_regions(outer);
            let cursor_before = ui.cursor();
            let response = password_visibility_button(
                ui,
                visibility,
                password_editor_id("layout-test"),
                false,
            );
            result = Some((outer, visibility, cursor_before, ui.cursor(), response.rect));
        });

        let (outer, visibility, cursor_before, cursor_after, response_rect) = result.unwrap();
        assert_eq!(cursor_before, cursor_after);
        assert_eq!(response_rect, visibility);
        assert!(outer.contains_rect(response_rect));
    }

    #[test]
    fn account_editor_labels_are_left_aligned_and_controls_share_vertical_centers() {
        fn find_text_origin(shape: &egui::Shape, needle: &str) -> Option<egui::Pos2> {
            match shape {
                egui::Shape::Text(text) if text.galley.text() == needle => Some(text.pos),
                egui::Shape::Vec(shapes) => shapes
                    .iter()
                    .find_map(|shape| find_text_origin(shape, needle)),
                _ => None,
            }
        }

        let ctx = egui::Context::default();
        crate::ui::theme::apply(&ctx);
        let mut username = String::new();
        let mut password = empty_password_buffer();
        let mut layout = None;

        let output = ctx.run_ui(Default::default(), |ui| {
            egui::Grid::new("account_editor_alignment_test")
                .num_columns(2)
                .spacing([16.0, 10.0])
                .show(ui, |ui| {
                    let email_label = account_editor_field_label(ui, "Email");
                    let email = ui.add_sized(
                        [ACCOUNT_EDITOR_FIELD_WIDTH, ACCOUNT_EDITOR_CONTROL_HEIGHT],
                        egui::TextEdit::singleline(&mut username),
                    );
                    ui.end_row();

                    let password_label = account_editor_field_label(ui, "Password");
                    let password_response = secure_password_editor(
                        ui,
                        &mut password,
                        password_editor_id("alignment-test"),
                        "Saved password",
                        false,
                    );
                    let password_outer = password_response
                        .field
                        .rect
                        .union(password_response.visibility.rect);
                    layout = Some((
                        email_label.rect,
                        email.rect,
                        password_label.rect,
                        password_outer,
                    ));
                    ui.end_row();
                });
        });

        let (email_label, email, password_label, password) = layout.unwrap();
        assert_eq!(email_label.left(), password_label.left());
        assert_eq!(email.size(), egui::vec2(332.0, 28.0));
        assert_eq!(password.size(), email.size());
        assert_eq!(email.left(), password.left());
        assert_eq!(
            email.left() - email_label.left(),
            ACCOUNT_EDITOR_LABEL_WIDTH + 16.0
        );
        assert_eq!(
            password.left() - password_label.left(),
            ACCOUNT_EDITOR_LABEL_WIDTH + 16.0
        );
        assert_eq!(email_label.center().y, email.center().y);
        assert_eq!(password_label.center().y, password.center().y);

        let email_text_origin = output
            .shapes
            .iter()
            .find_map(|shape| find_text_origin(&shape.shape, "Email"))
            .expect("Email label must be painted");
        let password_text_origin = output
            .shapes
            .iter()
            .find_map(|shape| find_text_origin(&shape.shape, "Password"))
            .expect("Password label must be painted");
        assert_eq!(email_text_origin.x, email_label.left());
        assert_eq!(password_text_origin.x, password_label.left());
        assert_eq!(email_text_origin.x, password_text_origin.x);
    }

    #[test]
    fn password_editor_caret_tracks_the_painted_mask_end_without_length_drift() {
        let outer = egui::Rect::from_min_size(
            egui::pos2(100.0, 20.0),
            egui::vec2(ACCOUNT_EDITOR_FIELD_WIDTH, ACCOUNT_EDITOR_CONTROL_HEIGHT),
        );
        let (field, _) = password_editor_regions(outer);
        let text_start = field.left() + 8.0;

        for painted_width in [6.25, 62.5, 187.5] {
            let painted = egui::Rect::from_min_size(
                egui::pos2(text_start, field.top() + 4.0),
                egui::vec2(painted_width, 16.0),
            );

            assert_eq!(
                password_editor_cursor_x(field, painted, false),
                painted.right()
            );
        }

        let hint = egui::Rect::from_min_size(
            egui::pos2(text_start, field.top() + 4.0),
            egui::vec2(180.0, 16.0),
        );
        assert_eq!(password_editor_cursor_x(field, hint, true), text_start);

        let overflowing_mask = egui::Rect::from_min_size(
            egui::pos2(text_start, field.top() + 4.0),
            egui::vec2(400.0, 16.0),
        );
        assert_eq!(
            password_editor_cursor_x(field, overflowing_mask, false),
            field.right() - 5.0
        );
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

        let visibility_id = password_visibility_id(id);
        ctx.memory_mut(|memory| memory.request_focus(visibility_id));
        forget_password_editor_state(&ctx, id);
        assert!(!ctx.memory(|memory| memory.has_focus(visibility_id)));
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
        let editor_without_whitespace = editor.split_whitespace().collect::<String>();

        assert!(editor.contains("secure_password_editor("));
        assert!(!editor.contains("egui::TextEdit::singleline(&mut *app.temp_password)"));
        assert!(editor_without_whitespace.contains("password_response.visibility"));
        assert!(editor.contains("app.show_password = !app.show_password;"));
        assert!(editor.contains("password_response.field.request_focus();"));
        assert!(editor.contains("ui.ctx().request_repaint();"));
        assert!(editor.contains("forget_password_editor_state(ui.ctx(), password_editor_id);"));
        assert!(editor.contains("clear_temp_password(app);"));
        assert!(editor.contains("app.show_password = false;"));

        let secure_editor_start = implementation
            .find("fn secure_password_editor(")
            .expect("secure password editor start");
        let secure_editor_end = implementation[secure_editor_start..]
            .find("fn password_editor_display(")
            .map(|offset| secure_editor_start + offset)
            .expect("secure password editor end");
        let secure_editor = &implementation[secure_editor_start..secure_editor_end];
        assert!(secure_editor.contains("with_clip_rect"));
        assert!(secure_editor.contains("password_editor_regions(rect)"));
        assert!(
            secure_editor.contains("password_visibility_button(ui, visibility_rect, id, reveal)")
        );
        assert!(secure_editor.contains("egui::accesskit::Role::PasswordInput"));
        assert!(secure_editor.contains("builder.clear_value();"));
        assert!(!secure_editor.contains("WidgetInfo::text_edit"));
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
