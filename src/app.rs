use crate::autologin::{
    accessibility_status, open_accessibility_settings, request_accessibility_access_prompt,
    AccessibilityStatus,
};
use crate::background::{WorkerCommand, WorkerEvent};
use crate::debug_fill::{self, FillAttemptReport};
use crate::models::{
    Account, AccountId, AppConfig, AppSettings, LogEntry, LogLevel, Tab, WorkerStatus,
};
use crate::single_instance::{self, MonitorControlCommand};
use crate::tray::TrayCommand;
use crate::ui::theme;
use eframe::egui;
use std::collections::VecDeque;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::Sender as TokioSender;
use zeroize::Zeroizing;

const MAX_LOG_ENTRIES: usize = 200;
const APP_VERSION_LABEL: &str = concat!("v", env!("CARGO_PKG_VERSION"));
const ACCESSIBILITY_REQUEST_BUTTON_SIZE: [f32; 2] = [278.0, 34.0];
const ACCESSIBILITY_SETTINGS_BUTTON_SIZE: [f32; 2] = [248.0, 34.0];

pub(crate) struct AutoLoginApp {
    pub(crate) config: AppConfig,
    pub(crate) selected_tab: Tab,
    pub(crate) logs: VecDeque<LogEntry>,
    pub(crate) worker_status: WorkerStatus,
    pub(crate) worker_tx: TokioSender<WorkerCommand>,
    pub(crate) tray_rx: std::sync::mpsc::Receiver<TrayCommand>,
    pub(crate) worker_event_rx: tokio::sync::mpsc::Receiver<WorkerEvent>,

    pub(crate) editing_account: Option<Account>,
    pub(crate) confirm_delete_account: Option<AccountId>,
    pub(crate) settings_draft: AppSettings,
    pub(crate) temp_password: Zeroizing<String>,
    pub(crate) show_password: bool,
    pub(crate) status_message: Option<(String, f64)>,
    pub(crate) last_fill_report: Option<FillAttemptReport>,
    quit_requested: bool,

    #[cfg(feature = "diagnostics-ui")]
    pub(crate) diagnose_running: bool,
    #[cfg(feature = "diagnostics-ui")]
    pub(crate) diagnose_result: String,
    #[cfg(feature = "diagnostics-ui")]
    pub(crate) diagnose_rx: Option<std::sync::mpsc::Receiver<String>>,
    #[cfg(feature = "diagnostics-ui")]
    pub(crate) runtime_status_running: bool,
    #[cfg(feature = "diagnostics-ui")]
    pub(crate) runtime_status_report: Option<FillAttemptReport>,
    #[cfg(feature = "diagnostics-ui")]
    pub(crate) runtime_status_rx: Option<std::sync::mpsc::Receiver<FillAttemptReport>>,
    settings_window_mode: bool,

    pub(crate) accessibility_status: AccessibilityStatus,
    accessibility_last_poll: Instant,
    accessibility_last_missing_log: Option<Instant>,
    monitor_status_last_poll: Instant,
}

impl AutoLoginApp {
    pub(crate) fn new(
        worker_tx: TokioSender<WorkerCommand>,
        tray_rx: std::sync::mpsc::Receiver<TrayCommand>,
        worker_event_rx: tokio::sync::mpsc::Receiver<WorkerEvent>,
        config: AppConfig,
        settings_window_mode: bool,
        initial_tab: Tab,
    ) -> Self {
        let worker_status = if settings_window_mode {
            bridged_monitor_status().unwrap_or(WorkerStatus::Idle)
        } else {
            WorkerStatus::Idle
        };
        let settings_draft = config.settings.clone();
        let accessibility_status = accessibility_status();

        #[cfg(not(test))]
        let last_fill_report = debug_fill::read_last_fill_attempt_report().ok().flatten();
        #[cfg(test)]
        let last_fill_report = None;

        let mut app = Self {
            config,
            selected_tab: initial_tab,
            logs: VecDeque::with_capacity(MAX_LOG_ENTRIES),
            worker_status,
            worker_tx,
            tray_rx,
            worker_event_rx,
            editing_account: None,
            confirm_delete_account: None,
            settings_draft,
            temp_password: Zeroizing::new(String::new()),
            show_password: false,
            status_message: None,
            last_fill_report,
            quit_requested: false,
            #[cfg(feature = "diagnostics-ui")]
            diagnose_running: false,
            #[cfg(feature = "diagnostics-ui")]
            diagnose_result: String::new(),
            #[cfg(feature = "diagnostics-ui")]
            diagnose_rx: None,
            #[cfg(feature = "diagnostics-ui")]
            runtime_status_running: false,
            #[cfg(feature = "diagnostics-ui")]
            runtime_status_report: None,
            #[cfg(feature = "diagnostics-ui")]
            runtime_status_rx: None,
            settings_window_mode,
            accessibility_status,
            accessibility_last_poll: Instant::now(),
            accessibility_last_missing_log: None,
            monitor_status_last_poll: Instant::now(),
        };

        app.log_accessibility_event(
            "accessibility_check_result",
            if app.accessibility_status.trusted {
                LogLevel::Info
            } else {
                LogLevel::Warn
            },
        );
        if !app.accessibility_status.trusted {
            app.status_message = Some((
                "Accessibility permission is required for this exact app".to_string(),
                10.0f64,
            ));
        }
        app
    }

    fn add_log(&mut self, entry: LogEntry) {
        push_bounded_log(&mut self.logs, entry);
    }

    pub(crate) fn set_status(&mut self, msg: impl Into<String>) {
        self.status_message = Some((msg.into(), 3.0));
    }

    pub(crate) fn send_worker_command(&mut self, cmd: WorkerCommand) {
        if self.settings_window_mode {
            return;
        }
        if let Err(e) = self.worker_tx.try_send(cmd) {
            self.set_status(format!("Monitor command failed: {}", e));
        }
    }

    pub(crate) fn request_supervisor_config_reload(&mut self) -> bool {
        if !self.settings_window_mode {
            return false;
        }
        if let Err(e) = single_instance::request_config_reload() {
            self.set_status(format!("Saved, but supervisor reload failed: {e}"));
            return false;
        }
        true
    }

    pub(crate) fn sync_saved_config_to_worker(&mut self, refresh_passwords: bool) {
        if self.settings_window_mode {
            let _ = self.request_supervisor_config_reload();
            return;
        }

        if let Err(e) = self.worker_tx.try_send(WorkerCommand::ApplyConfig {
            settings: self.config.settings.clone(),
            accounts: self.config.accounts.clone(),
            refresh_passwords,
        }) {
            self.worker_status = WorkerStatus::Idle;
            self.set_status(format!(
                "Saved, but monitor was stopped because it could not reload safely: {e}"
            ));
        }
    }

    fn send_monitor_control_command(&mut self, command: MonitorControlCommand) {
        if self.settings_window_mode {
            if let Err(e) = single_instance::request_monitor_command(command) {
                self.set_status(format!("Monitor command failed: {e}"));
            }
            return;
        }

        match command {
            MonitorControlCommand::Start => self.send_worker_command(WorkerCommand::Start),
            MonitorControlCommand::Stop => self.send_worker_command(WorkerCommand::Stop),
            #[cfg(not(target_os = "macos"))]
            MonitorControlCommand::ReloadConfig => self.sync_saved_config_to_worker(true),
        }
    }

    fn toggle_monitor_from_ui(&mut self) {
        match self.worker_status {
            WorkerStatus::Running => {
                self.send_monitor_control_command(MonitorControlCommand::Stop);
            }
            WorkerStatus::Idle => {
                if self.accessibility_ready() {
                    self.send_monitor_control_command(MonitorControlCommand::Start);
                } else {
                    self.block_for_accessibility("starting the monitor");
                }
            }
        }
    }

    pub(crate) fn accessibility_ready(&self) -> bool {
        self.accessibility_status.trusted
    }

    fn log_accessibility_event(&mut self, event: &str, level: LogLevel) {
        let status = &self.accessibility_status;
        self.add_log(LogEntry {
            timestamp: chrono::Local::now().format("%H:%M:%S").to_string(),
            level,
            message: accessibility_log_message(event, status),
        });
    }

    fn block_for_accessibility(&mut self, action: &str) {
        self.log_accessibility_event("accessibility_still_missing", LogLevel::Warn);
        self.status_message = Some((
            format!("Accessibility permission is required before {action}"),
            6.0,
        ));
        self.selected_tab = Tab::Accounts;
    }

    pub(crate) fn request_accessibility_access(&mut self) {
        self.log_accessibility_event("accessibility_prompt_requested", LogLevel::Info);
        let trusted = request_accessibility_access_prompt();
        self.accessibility_status = accessibility_status();
        if trusted || self.accessibility_status.trusted {
            self.handle_accessibility_granted();
        } else {
            self.log_accessibility_event("accessibility_still_missing", LogLevel::Warn);
            self.status_message = Some((
                "macOS did not grant Accessibility yet. Enable this exact app in System Settings."
                    .to_string(),
                8.0,
            ));
        }
    }

    pub(crate) fn open_accessibility_settings(&mut self) {
        self.log_accessibility_event("accessibility_settings_opened", LogLevel::Info);
        if let Err(e) = open_accessibility_settings() {
            self.set_status(format!("Could not open Accessibility settings: {e}"));
        }
    }

    fn handle_accessibility_granted(&mut self) {
        self.apply_accessibility_granted_status(accessibility_status());
    }

    fn apply_accessibility_granted_status(&mut self, status: AccessibilityStatus) {
        self.accessibility_status = status;
        self.log_accessibility_event("accessibility_granted", LogLevel::Info);
        self.status_message = Some((
            "Accessibility permission granted. Starting monitor.".to_string(),
            5.0,
        ));
        if self.worker_status == WorkerStatus::Idle {
            self.send_monitor_control_command(MonitorControlCommand::Start);
        }
    }

    fn poll_accessibility_onboarding(&mut self, ctx: &egui::Context) {
        if self.accessibility_status.trusted {
            return;
        }
        ctx.request_repaint_after(Duration::from_secs(1));
        if self.accessibility_last_poll.elapsed() < Duration::from_secs(1) {
            return;
        }
        self.accessibility_last_poll = Instant::now();

        let previous = self.accessibility_status.trusted;
        self.accessibility_status = accessibility_status();
        if !previous && self.accessibility_status.trusted {
            self.handle_accessibility_granted();
            return;
        }

        if self.worker_status == WorkerStatus::Running {
            self.send_worker_command(WorkerCommand::Stop);
        }
        let should_log = self
            .accessibility_last_missing_log
            .is_none_or(|logged| logged.elapsed() >= Duration::from_secs(30));
        if should_log {
            self.log_accessibility_event("accessibility_still_missing", LogLevel::Warn);
            self.accessibility_last_missing_log = Some(Instant::now());
        }
    }

    fn process_tray_commands(&mut self, ctx: &egui::Context) {
        while let Ok(cmd) = self.tray_rx.try_recv() {
            match cmd {
                TrayCommand::OpenAccounts => {
                    self.selected_tab = Tab::Accounts;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
                }
                TrayCommand::OpenSettings => {
                    self.selected_tab = Tab::Settings;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
                }
                TrayCommand::ToggleMonitor => match self.worker_status {
                    WorkerStatus::Running => {
                        self.send_worker_command(WorkerCommand::Stop);
                    }
                    WorkerStatus::Idle => {
                        if self.accessibility_ready() {
                            self.send_worker_command(WorkerCommand::Start);
                        } else {
                            self.block_for_accessibility("starting the monitor");
                        }
                    }
                },
                TrayCommand::RequestAccessibilityAccess => {
                    self.request_accessibility_access();
                }
                TrayCommand::OpenAccessibilitySettings => {
                    self.open_accessibility_settings();
                }
                TrayCommand::Exit => {
                    self.quit_requested = true;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            }
        }
    }

    fn process_worker_events(&mut self) {
        while let Ok(event) = self.worker_event_rx.try_recv() {
            match event {
                WorkerEvent::StatusChanged(status) => {
                    self.worker_status = status;
                }
                WorkerEvent::Log(entry) => {
                    self.add_log(entry);
                }
                WorkerEvent::FillAttemptReport(report) => {
                    if let Err(e) = debug_fill::write_last_fill_attempt_report(&report) {
                        self.add_log(LogEntry {
                            timestamp: chrono::Local::now().format("%H:%M:%S").to_string(),
                            level: LogLevel::Warn,
                            message: format!("Could not persist last fill attempt report: {e}"),
                        });
                    }
                    self.last_fill_report = Some(report);
                }
            }
        }
    }

    fn poll_bridged_monitor_status(&mut self, ctx: &egui::Context) {
        if !self.settings_window_mode {
            return;
        }
        ctx.request_repaint_after(Duration::from_millis(500));
        if self.monitor_status_last_poll.elapsed() < Duration::from_millis(500) {
            return;
        }
        self.monitor_status_last_poll = Instant::now();

        if let Some(status) = bridged_monitor_status() {
            self.worker_status = status;
        }
        #[cfg(feature = "diagnostics-ui")]
        self.refresh_persisted_last_fill_report();
    }

    #[cfg(feature = "diagnostics-ui")]
    fn refresh_persisted_last_fill_report(&mut self) {
        let Ok(Some(report)) = debug_fill::read_last_fill_attempt_report() else {
            return;
        };
        let next_attempt = report.field("attempt_id");
        let current_attempt = self
            .last_fill_report
            .as_ref()
            .and_then(|report| report.field("attempt_id"));
        if next_attempt != current_attempt {
            self.last_fill_report = Some(report);
        }
    }
}

fn redact_sensitive_log_text(message: &str) -> String {
    redact_path_assignments(&redact_secret_assignments(&redact_email_addresses(message)))
}

fn accessibility_log_message(
    event: &str,
    status: &crate::autologin::AccessibilityStatus,
) -> String {
    format!(
        "{event} ax_trusted_for_current_process={} current_process_path_redacted={} app_bundle_path_redacted={}",
        status.trusted,
        crate::user_paths::redacted_path(&status.current_process_path),
        crate::user_paths::redacted_path(&status.app_bundle_path)
    )
}

fn redact_email_addresses(message: &str) -> String {
    let chars: Vec<char> = message.chars().collect();
    let mut out = String::new();
    let mut idx = 0;

    while idx < chars.len() {
        if chars[idx] == '@' {
            let mut start = idx;
            while start > 0 && is_email_char(chars[start - 1]) {
                start -= 1;
            }
            let mut end = idx + 1;
            while end < chars.len() && is_email_char(chars[end]) {
                end += 1;
            }

            let candidate: String = chars[start..end].iter().collect();
            if looks_like_email(&candidate) {
                let keep_chars = out.chars().count().saturating_sub(idx - start);
                out = out.chars().take(keep_chars).collect();
                out.push_str("[email]");
                idx = end;
                continue;
            }
        }

        out.push(chars[idx]);
        idx += 1;
    }

    out
}

fn redact_secret_assignments(message: &str) -> String {
    let chars: Vec<char> = message.chars().collect();
    let mut out = String::new();
    let mut idx = 0;

    while idx < chars.len() {
        if let Some((prefix, value_end)) = secret_assignment_at(&chars, idx) {
            out.push_str(&prefix);
            out.push_str("[redacted]");
            idx = value_end;
            continue;
        }

        out.push(chars[idx]);
        idx += 1;
    }

    out
}

fn redact_path_assignments(message: &str) -> String {
    let chars: Vec<char> = message.chars().collect();
    let mut out = String::new();
    let mut idx = 0;

    while idx < chars.len() {
        if let Some((prefix, value, value_end)) = path_assignment_at(&chars, idx) {
            out.push_str(&prefix);
            out.push_str(&crate::user_paths::redacted_path(&value));
            idx = value_end;
            continue;
        }

        out.push(chars[idx]);
        idx += 1;
    }

    out
}

fn path_assignment_at(chars: &[char], idx: usize) -> Option<(String, String, usize)> {
    if idx > 0 && (chars[idx - 1].is_ascii_alphanumeric() || chars[idx - 1] == '_') {
        return None;
    }

    let key_len = path_key_len_at(chars, idx)?;
    let mut cursor = idx + key_len;
    while cursor < chars.len() && chars[cursor].is_whitespace() {
        cursor += 1;
    }
    if cursor >= chars.len() || !matches!(chars[cursor], '=' | ':') {
        return None;
    }
    cursor += 1;
    while cursor < chars.len() && chars[cursor].is_whitespace() {
        cursor += 1;
    }
    if cursor >= chars.len() || value_delimiter(chars[cursor]) {
        return None;
    }

    let value_start = cursor;
    if chars[cursor] == '"' || chars[cursor] == char::from(39) {
        let quote = chars[cursor];
        cursor += 1;
        while cursor < chars.len() {
            let current = chars[cursor];
            cursor += 1;
            if current == quote {
                break;
            }
        }
    } else {
        while cursor < chars.len() && !path_value_delimiter_at(chars, cursor) {
            cursor += 1;
        }
    }

    Some((
        chars[idx..value_start].iter().collect(),
        chars[value_start..cursor]
            .iter()
            .collect::<String>()
            .trim_matches(['"', '\''])
            .trim()
            .to_string(),
        cursor,
    ))
}

fn path_value_delimiter_at(chars: &[char], idx: usize) -> bool {
    if matches!(chars[idx], ',' | ';') {
        return true;
    }
    if !chars[idx].is_whitespace() {
        return false;
    }

    let mut next = idx;
    while next < chars.len() && chars[next].is_whitespace() {
        next += 1;
    }
    if next >= chars.len() {
        return true;
    }

    assignment_starts_at(chars, next)
}

fn assignment_starts_at(chars: &[char], idx: usize) -> bool {
    if idx > 0 && (chars[idx - 1].is_ascii_alphanumeric() || chars[idx - 1] == '_') {
        return false;
    }

    let Some(key_len) = path_key_len_at(chars, idx).or_else(|| secret_key_len_at(chars, idx))
    else {
        return false;
    };
    let mut cursor = idx + key_len;
    while cursor < chars.len() && chars[cursor].is_whitespace() {
        cursor += 1;
    }

    cursor < chars.len() && matches!(chars[cursor], '=' | ':')
}

fn path_key_len_at(chars: &[char], idx: usize) -> Option<usize> {
    [
        "current_process_path",
        "app_bundle_path",
        "executable_path",
        "windows_app_path",
        "keychain_process_path",
    ]
    .iter()
    .find_map(|key| {
        let key_chars = key.chars().collect::<Vec<_>>();
        if idx + key_chars.len() > chars.len() {
            return None;
        }
        let matches = key_chars
            .iter()
            .enumerate()
            .all(|(offset, expected)| chars[idx + offset] == *expected);
        matches.then_some(key_chars.len())
    })
}

fn secret_assignment_at(chars: &[char], idx: usize) -> Option<(String, usize)> {
    if idx > 0 && (chars[idx - 1].is_ascii_alphanumeric() || chars[idx - 1] == '_') {
        return None;
    }

    let key_len = secret_key_len_at(chars, idx)?;
    let mut cursor = idx + key_len;
    while cursor < chars.len() && chars[cursor].is_whitespace() {
        cursor += 1;
    }
    if cursor >= chars.len() || !matches!(chars[cursor], '=' | ':') {
        return None;
    }
    cursor += 1;
    while cursor < chars.len() && chars[cursor].is_whitespace() {
        cursor += 1;
    }
    if cursor >= chars.len() || value_delimiter(chars[cursor]) {
        return None;
    }

    let value_start = cursor;
    if chars[cursor] == '"' || chars[cursor] == char::from(39) {
        let quote = chars[cursor];
        cursor += 1;
        while cursor < chars.len() {
            let current = chars[cursor];
            cursor += 1;
            if current == quote {
                break;
            }
        }
    } else {
        while cursor < chars.len() && !value_delimiter(chars[cursor]) {
            cursor += 1;
        }
    }

    Some((chars[idx..value_start].iter().collect(), cursor))
}

fn secret_key_len_at(chars: &[char], idx: usize) -> Option<usize> {
    ["password", "passcode", "token", "secret"]
        .iter()
        .find_map(|key| {
            let key_chars = key.chars().collect::<Vec<_>>();
            if idx + key_chars.len() > chars.len() {
                return None;
            }
            let matches = key_chars
                .iter()
                .enumerate()
                .all(|(offset, expected)| chars[idx + offset].to_ascii_lowercase() == *expected);
            matches.then_some(key_chars.len())
        })
}

fn value_delimiter(c: char) -> bool {
    c.is_whitespace() || matches!(c, ',' | ';')
}

fn looks_like_email(value: &str) -> bool {
    let mut parts = value.split('@');
    let local = parts.next().unwrap_or_default();
    let domain = parts.next().unwrap_or_default();
    parts.next().is_none()
        && !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
}

fn is_email_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '%' | '+' | '-' | '@')
}

fn bridged_monitor_status() -> Option<WorkerStatus> {
    single_instance::read_monitor_status().map(|running| {
        if running {
            WorkerStatus::Running
        } else {
            WorkerStatus::Idle
        }
    })
}

impl eframe::App for AutoLoginApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_accessibility_onboarding(ctx);
        self.process_tray_commands(ctx);
        self.process_worker_events();
        self.poll_bridged_monitor_status(ctx);
        #[cfg(feature = "diagnostics-ui")]
        crate::ui::diagnose::poll_diagnosis(self);
        #[cfg(feature = "diagnostics-ui")]
        crate::ui::diagnose::poll_runtime_status(self);
        if !self.settings_window_mode
            && !self.quit_requested
            && ctx.input(|input| input.viewport().close_requested())
        {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        }
        ctx.request_repaint_after(Duration::from_millis(500));
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        let accessibility_ready = self.accessibility_ready();

        if let Some((_, ref mut remaining)) = self.status_message {
            *remaining -= ctx.input(|i| i.stable_dt) as f64;
            if *remaining <= 0.0 {
                self.status_message = None;
            } else {
                ctx.request_repaint_after(Duration::from_millis(100));
            }
        }

        egui::Panel::top("top_panel")
            .frame(theme::top_bar_frame())
            .show_inside(ui, |ui| {
                ui.horizontal(|ui| {
                    if accessibility_ready {
                        ui.spacing_mut().item_spacing.x = 6.0;
                        let previous_button_padding = ui.spacing().button_padding;
                        ui.spacing_mut().button_padding = egui::vec2(8.0, 4.0);
                        for (tab, label) in [
                            (Tab::Accounts, "Accounts"),
                            (Tab::Settings, "Settings"),
                            #[cfg(feature = "diagnostics-ui")]
                            (Tab::Diagnose, "Diagnose"),
                        ] {
                            let selected = self.selected_tab == tab;
                            if ui
                                .add(
                                    egui::Button::selectable(
                                        selected,
                                        egui::RichText::new(label).strong(),
                                    )
                                    .corner_radius(egui::CornerRadius::same(8))
                                    .min_size(egui::vec2(0.0, 30.0)),
                                )
                                .clicked()
                            {
                                self.selected_tab = tab;
                            }
                        }
                        ui.spacing_mut().button_padding = previous_button_padding;
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.allocate_ui_with_layout(
                            egui::vec2(68.0, 30.0),
                            egui::Layout::centered_and_justified(egui::Direction::LeftToRight),
                            |ui| {
                                ui.label(theme::version_label(APP_VERSION_LABEL));
                            },
                        );

                        if accessibility_ready {
                            match self.worker_status {
                                WorkerStatus::Running => {
                                    if ui
                                        .add_sized(
                                            [140.0, 30.0],
                                            theme::secondary_button("Stop Monitor"),
                                        )
                                        .clicked()
                                    {
                                        self.toggle_monitor_from_ui();
                                    }
                                }
                                WorkerStatus::Idle => {
                                    if ui
                                        .add_sized(
                                            [140.0, 30.0],
                                            theme::primary_button("Start Monitor"),
                                        )
                                        .clicked()
                                    {
                                        self.toggle_monitor_from_ui();
                                    }
                                }
                            }
                        }
                    });
                });

                if accessibility_ready {
                    if let Some((msg, _)) = &self.status_message {
                        ui.add_space(7.0);
                        ui.label(theme::status_text(msg.as_str()));
                    }
                }
            });

        egui::CentralPanel::default()
            .frame(theme::content_frame())
            .show_inside(ui, |ui| {
                if !accessibility_ready {
                    show_accessibility_onboarding(ui, self);
                    return;
                }
                match self.selected_tab {
                    Tab::Accounts => crate::ui::accounts::show(ui, self),
                    Tab::Settings => crate::ui::settings::show(ui, self),
                    #[cfg(feature = "diagnostics-ui")]
                    Tab::Diagnose => crate::ui::diagnose::show(ui, self),
                }
            });
    }
}

fn push_bounded_log(logs: &mut VecDeque<LogEntry>, mut entry: LogEntry) {
    entry.message = redact_sensitive_log_text(&entry.message);
    logs.push_back(entry);
    while logs.len() > MAX_LOG_ENTRIES {
        logs.pop_front();
    }
}

fn show_accessibility_onboarding(ui: &mut egui::Ui, app: &mut AutoLoginApp) {
    theme::glass_frame().show(ui, |ui| {
        ui.heading("Accessibility permission is required");
        ui.add_space(8.0);
        ui.add(egui::Label::new(theme::muted(
            "Windows App AutoLogin can only detect and fill the visible credential prompt after macOS allows this exact app to use Accessibility.",
        )).wrap());
        ui.add_space(14.0);
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_sized(
                    ACCESSIBILITY_REQUEST_BUTTON_SIZE,
                    theme::primary_button("Request Accessibility Access"),
                )
                .clicked()
            {
                app.request_accessibility_access();
            }
            if ui
                .add_sized(
                    ACCESSIBILITY_SETTINGS_BUTTON_SIZE,
                    theme::secondary_button("Open Accessibility Settings"),
                )
                .clicked()
            {
                app.open_accessibility_settings();
            }
        });
    });
    ui.add_space(12.0);

    theme::glass_frame().show(ui, |ui| {
        ui.label(theme::muted(
            "System Settings -> Privacy & Security -> Accessibility",
        ));
        ui.add_space(8.0);
        ui.label(theme::muted(
            "Enable Windows App AutoLogin for the path shown above, then return here. The app checks again every second.",
        ));
    });
}

#[cfg(test)]
mod tests {
    use super::{
        accessibility_log_message, push_bounded_log, redact_sensitive_log_text, AutoLoginApp,
        WorkerCommand, MAX_LOG_ENTRIES,
    };
    use crate::autologin::AccessibilityStatus;
    use crate::models::{AppConfig, LogEntry, LogLevel, Tab, WorkerStatus};
    use std::collections::VecDeque;
    use std::sync::mpsc::channel as std_channel;
    use tokio::sync::mpsc::channel as tokio_channel;

    #[test]
    fn log_redaction_removes_email_addresses_and_secret_assignments() {
        let redacted = redact_sensitive_log_text(
            "failed for user@example.com password=super-secret token: abc123; secret = value",
        );

        assert!(redacted.contains("[email]"));
        assert!(redacted.contains("password=[redacted]"));
        assert!(redacted.contains("token: [redacted];"));
        assert!(redacted.contains("secret = [redacted]"));
        assert!(!redacted.contains("user@example.com"));
        assert!(!redacted.contains("super-secret"));
        assert!(!redacted.contains("abc123"));
        assert!(!redacted.contains(" value"));
    }

    #[test]
    fn log_redaction_does_not_rewrite_plain_password_words() {
        let redacted = redact_sensitive_log_text("password was not loaded for prompt");

        assert_eq!(redacted, "password was not loaded for prompt");
    }

    #[test]
    fn log_redaction_handles_quoted_and_uppercase_secret_assignments() {
        let redacted = redact_sensitive_log_text(
            "PASSWORD=\"secret with spaces\" PASSCODE: 123456 token='abc def'",
        );

        assert!(redacted.contains("PASSWORD=[redacted]"));
        assert!(redacted.contains("PASSCODE: [redacted]"));
        assert!(redacted.contains("token=[redacted]"));
        assert!(!redacted.contains("secret with spaces"));
        assert!(!redacted.contains("123456"));
        assert!(!redacted.contains("abc def"));
    }

    #[test]
    fn log_buffer_caps_entries_and_keeps_recent_events() {
        let mut logs = VecDeque::new();
        for idx in 0..(MAX_LOG_ENTRIES + 7) {
            push_bounded_log(
                &mut logs,
                LogEntry {
                    timestamp: format!("{idx:02}"),
                    level: LogLevel::Info,
                    message: format!("event {idx}"),
                },
            );
        }

        assert_eq!(logs.len(), MAX_LOG_ENTRIES);
        assert_eq!(
            logs.front().map(|entry| entry.message.as_str()),
            Some("event 7")
        );
        let expected_last = format!("event {}", MAX_LOG_ENTRIES + 6);
        assert_eq!(
            logs.back().map(|entry| entry.message.as_str()),
            Some(expected_last.as_str())
        );
    }

    #[test]
    fn log_buffer_redacts_before_retaining_message() {
        let mut logs = VecDeque::new();
        push_bounded_log(
            &mut logs,
            LogEntry {
                timestamp: "00:00".to_string(),
                level: LogLevel::Warn,
                message: "user@example.com password=super-secret token=abc".to_string(),
            },
        );

        let message = &logs[0].message;
        assert!(message.contains("[email]"));
        assert!(message.contains("password=[redacted]"));
        assert!(message.contains("token=[redacted]"));
        assert!(!message.contains("user@example.com"));
        assert!(!message.contains("super-secret"));
    }

    #[test]
    fn log_buffer_redacts_path_assignments_before_retaining_message() {
        let mut logs = VecDeque::new();
        push_bounded_log(
            &mut logs,
            LogEntry {
                timestamp: "00:00".to_string(),
                level: LogLevel::Warn,
                message: "current_process_path=/Users/alice/Private Projects/target/debug/windows-app-autologin app_bundle_path=/Users/alice/Applications/Windows App AutoLogin.app".to_string(),
            },
        );

        let message = &logs[0].message;
        assert!(message.contains("current_process_path=[path]"));
        assert!(message.contains("app_bundle_path=[path]"));
        assert!(!message.contains("windows-app-autologin"));
        assert!(!message.contains("Windows App AutoLogin.app"));
        assert!(!message.contains("/Users/alice"));
        assert!(!message.contains("Private Projects"));
        assert!(!message.contains("Applications"));
    }

    #[test]
    fn accessibility_event_log_redacts_paths_with_spaces_before_retaining_message() {
        let status = AccessibilityStatus {
            trusted: false,
            raw_trusted: true,
            identity_trusted: false,
            current_process_path:
                "/Applications/Windows App AutoLogin.app/Contents/MacOS/windows-app-autologin"
                    .to_string(),
            app_bundle_path: "/Applications/Windows App AutoLogin.app".to_string(),
        };

        let mut logs = VecDeque::new();
        push_bounded_log(
            &mut logs,
            LogEntry {
                timestamp: "00:00".to_string(),
                level: LogLevel::Warn,
                message: accessibility_log_message("accessibility_still_missing", &status),
            },
        );

        let message = &logs[0].message;
        assert!(message.contains("current_process_path_redacted=[path]"));
        assert!(message.contains("app_bundle_path_redacted=[path]"));
        assert!(!message.contains("windows-app-autologin"));
        assert!(!message.contains("Windows App AutoLogin.app"));
        assert!(!message.contains("/Applications"));
        assert!(!message.contains("Contents/MacOS"));
        assert!(!message.contains("current_process_path=/"));
        assert!(!message.contains("app_bundle_path=/"));
    }

    #[test]
    fn accessibility_granted_status_starts_idle_worker() {
        let (worker_tx, mut worker_rx) = tokio_channel(8);
        let (_worker_event_tx, worker_event_rx) = tokio_channel(8);
        let (_tray_tx, tray_rx) = std_channel();
        let mut app = AutoLoginApp::new(
            worker_tx,
            tray_rx,
            worker_event_rx,
            AppConfig::default(),
            false,
            Tab::Accounts,
        );
        app.worker_status = WorkerStatus::Idle;

        app.apply_accessibility_granted_status(AccessibilityStatus {
            trusted: true,
            raw_trusted: true,
            identity_trusted: true,
            current_process_path: "/Applications/WindowsAppAutoLogin.app".to_string(),
            app_bundle_path: "/Applications/WindowsAppAutoLogin.app".to_string(),
        });

        assert!(app.accessibility_status.trusted);
        assert!(app.status_message.as_ref().is_some_and(
            |(message, _)| message == "Accessibility permission granted. Starting monitor."
        ));
        match worker_rx.try_recv().unwrap() {
            WorkerCommand::Start => {}
            other => panic!("expected Start, got {other:?}"),
        }
    }
}
