use super::{iphone_sign_in::start_task, settings, theme};
use crate::iphone_setup::{self, SetupProgress, SetupRequirements};
use crate::iphone_signing::SigningTeam;
use eframe::egui;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex, OnceLock,
};

type RequirementsCheck = Arc<OnceLock<Result<SetupRequirements, String>>>;

struct CancelOnDrop(Arc<AtomicBool>);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

#[derive(Clone)]
struct SetupJob {
    _lifetime: Arc<CancelOnDrop>,
    cancelled: Arc<AtomicBool>,
    progress: Arc<Mutex<SetupProgress>>,
    result: Arc<OnceLock<Result<(), String>>>,
}

#[derive(Clone)]
struct SetupForm {
    requirements: RequirementsCheck,
    team: Option<String>,
    job: Option<SetupJob>,
    xcode: Option<Arc<OnceLock<Result<(), String>>>>,
    feedback: Option<Result<(), String>>,
    refresh_after_xcode: bool,
    expected_device: Option<String>,
    start_after_connect: bool,
}

impl SetupForm {
    fn inspect(ctx: &egui::Context, expected_device: Option<String>) -> Self {
        Self {
            requirements: start_task(
                ctx,
                iphone_setup::inspect,
                Err("Couldn’t check the setup requirements. Try again.".into()),
            ),
            team: None,
            job: None,
            xcode: None,
            feedback: None,
            refresh_after_xcode: false,
            start_after_connect: expected_device.is_some(),
            expected_device,
        }
    }

    fn recheck(&mut self, ctx: &egui::Context) {
        let start_after_connect = self.start_after_connect;
        *self = Self::inspect(ctx, self.expected_device.take());
        self.start_after_connect = start_after_connect;
    }

    fn ready_team(&self) -> Option<&str> {
        let selected = self.team.as_deref()?;
        let requirements = self.requirements.get()?.as_ref().ok()?;
        (requirements.phone_selected && requirements.teams.iter().any(|t| t.id == selected))
            .then_some(selected)
    }

    fn select_available_team(&mut self) {
        let Some(Ok(requirements)) = self.requirements.get() else {
            return;
        };
        if self.team.is_some() {
            return;
        }
        self.team = requirements
            .selected_team
            .as_ref()
            .filter(|id| requirements.teams.iter().any(|team| &team.id == *id))
            .cloned()
            .or_else(|| {
                (requirements.selected_team.is_none() && requirements.teams.len() == 1)
                    .then(|| requirements.teams[0].id.clone())
            });
    }
}

fn form_id() -> egui::Id {
    egui::Id::new("iphone_helper_setup")
}

pub(super) fn busy(ctx: &egui::Context) -> bool {
    ctx.data(|data| {
        data.get_temp::<SetupForm>(form_id())
            .and_then(|form| form.job)
            .is_some_and(|job| job.result.get().is_none())
    })
}

pub(super) fn cancel(ctx: &egui::Context) {
    ctx.data_mut(|data| {
        if let Some(mut form) = data.get_temp::<SetupForm>(form_id()) {
            form.start_after_connect = false;
            if let Some(job) = &form.job {
                job.cancelled.store(true, Ordering::Release);
            }
            data.insert_temp(form_id(), form);
        }
    });
}

pub(super) fn refresh(ctx: &egui::Context) {
    if !busy(ctx) {
        ctx.data_mut(|data| data.remove::<SetupForm>(form_id()));
    }
}

pub(super) fn prepare_after_connect(ctx: &egui::Context, device: &str) {
    replace_after_connect(ctx, SetupForm::inspect(ctx, Some(device.to_owned())));
}

fn replace_after_connect(ctx: &egui::Context, mut next: SetupForm) {
    ctx.data_mut(|data| {
        // A previous setup can still be stopping when this page is reopened.
        // Keep its job until cleanup finishes before starting the new request.
        next.job = data
            .get_temp::<SetupForm>(form_id())
            .and_then(|form| form.job)
            .filter(|job| job.result.get().is_none());
        if let Some(job) = &next.job {
            job.cancelled.store(true, Ordering::Release);
        }
        data.insert_temp(form_id(), next);
    });
    ctx.request_repaint();
}

pub(super) fn show(ui: &mut egui::Ui) {
    show_with(ui, start_setup);
}

fn show_with(
    ui: &mut egui::Ui,
    start: impl FnOnce(&egui::Context, String, Option<String>) -> SetupJob,
) {
    if ui.input(|input| input.viewport().close_requested()) {
        cancel(ui.ctx());
        return;
    }
    let mut form = ui
        .ctx()
        .data(|data| data.get_temp::<SetupForm>(form_id()))
        .unwrap_or_else(|| SetupForm::inspect(ui.ctx(), None));
    if let Some(result) = form.job.as_ref().and_then(|job| job.result.get()).cloned() {
        form.job = None;
        if result.is_ok() {
            super::iphone_sign_in::refresh_device_info(ui.ctx());
        }
        if !form.start_after_connect {
            form.feedback = Some(result);
        }
    }
    if let Some(result) = form.xcode.as_ref().and_then(|task| task.get()).cloned() {
        form.xcode = None;
        if let Err(message) = result {
            form.refresh_after_xcode = false;
            form.feedback = Some(Err(message));
        }
    }
    if form.refresh_after_xcode
        && form.job.is_none()
        && ui.input(|i| i.events.contains(&egui::Event::WindowFocused(true)))
    {
        form.recheck(ui.ctx());
    }
    form.select_available_team();
    let busy = form.job.is_some();
    let selected_before = form.team.clone();

    settings::section(ui, "ON YOUR IPHONE", |ui| {
        ui.label("Turn on Settings → Privacy & Security → Developer Mode.");
        ui.label("Turn on Settings → Developer → Enable UI Automation.");
        ui.label("Add your work account in Microsoft Authenticator.");
    });
    ui.add_space(12.0);
    settings::section(ui, "SIGNING ACCOUNT", |ui| {
        ui.label(
            "Choose the Apple account from Xcode that will install the helper on your iPhone.",
        );
        match form.requirements.get() {
            None => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Checking your Mac…");
                });
            }
            Some(Err(message)) => {
                ui.add(egui::Label::new(message.as_str()).wrap());
            }
            Some(Ok(requirements)) => {
                if requirements.teams.is_empty() {
                    ui.label("Add your Apple Account in Xcode → Settings → Accounts. Select your team, then choose Manage Certificates → + → Apple Development.");
                } else {
                    ui.add_enabled_ui(!busy, |ui| {
                        team_picker(ui, &requirements.teams, &mut form.team);
                    });
                }
                if !requirements.phone_selected {
                    ui.add_space(4.0);
                    ui.label("Connect your iPhone in AutoLogin before setting up the helper.");
                }
            }
        }
        ui.add_space(4.0);
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(
                    !busy && form.xcode.is_none(),
                    theme::secondary_button("Open Xcode"),
                )
                .clicked()
            {
                form.refresh_after_xcode = true;
                form.xcode = Some(start_task(
                    ui.ctx(),
                    iphone_setup::open_xcode,
                    Err("Couldn’t open Xcode. Try again.".into()),
                ));
            }
            if ui
                .add_enabled(
                    !busy && form.requirements.get().is_some(),
                    theme::secondary_button("Refresh"),
                )
                .clicked()
            {
                form.recheck(ui.ctx());
            }
        });
    });
    if form.team != selected_before {
        form.feedback = None;
    }
    ui.add_space(12.0);
    settings::section(ui, "PREPARE AUTOMATION", |ui| {
        ui.label("Keep your selected iPhone unlocked on the same Wi-Fi. AutoLogin installs and signs the helper, then checks its connection.");
        ui.label(
            egui::RichText::new("Downloads the required helper tools on this Mac.")
                .small()
                .color(theme::MUTED),
        );
        ui.add_space(6.0);
        if let Some(job) = &form.job {
            ui.horizontal_wrapped(|ui| {
                ui.spinner();
                let cancelled = job.cancelled.load(Ordering::Acquire);
                let label = if cancelled {
                    "Stopping setup…"
                } else {
                    job.progress.lock().map_or("Preparing…", |p| p.label())
                };
                ui.label(label);
                if ui
                    .add_enabled(!cancelled, theme::secondary_button("Cancel"))
                    .clicked()
                {
                    job.cancelled.store(true, Ordering::Release);
                }
            });
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_millis(150));
        } else {
            let team = form.ready_team();
            let requested = form.start_after_connect || {
                let label = match &form.feedback {
                    Some(Ok(())) => "Prepare again",
                    Some(Err(_)) => "Retry setup",
                    None => "Set up automation",
                };
                ui.add_enabled(team.is_some(), theme::primary_button(label))
                    .clicked()
            };
            if let Some(team) = team.filter(|_| requested).map(str::to_owned) {
                form.start_after_connect = false;
                form.feedback = None;
                form.job = Some(start(ui.ctx(), team, form.expected_device.clone()));
                ui.ctx().request_repaint();
            }
        }
        if let Some(result) = &form.feedback {
            match result {
                Ok(()) => {
                    ui.label(
                        "Helper ready. Turn on 2FA → Use iPhone for the accounts you want to use.",
                    );
                }
                Err(message) => {
                    ui.add(egui::Label::new(message.as_str()).wrap());
                }
            }
        }
    });
    ui.ctx().data_mut(|data| data.insert_temp(form_id(), form));
}

fn start_setup(ctx: &egui::Context, team: String, expected_device: Option<String>) -> SetupJob {
    let cancelled = Arc::new(AtomicBool::new(false));
    let progress = Arc::new(Mutex::new(SetupProgress::Checking));
    let cancel_worker = Arc::clone(&cancelled);
    let progress_worker = Arc::clone(&progress);
    let repaint = ctx.clone();
    let viewport = ctx.viewport_id();
    let result = start_task(
        ctx,
        move || {
            iphone_setup::run_setup(
                &team,
                expected_device.as_deref(),
                |next| {
                    if let Ok(mut progress) = progress_worker.lock() {
                        *progress = next;
                    }
                    repaint.request_repaint_of(viewport);
                },
                &cancel_worker,
            )
        },
        Err("Couldn’t start helper setup. Try again.".into()),
    );
    SetupJob {
        _lifetime: Arc::new(CancelOnDrop(Arc::clone(&cancelled))),
        cancelled,
        progress,
        result,
    }
}

fn team_picker(ui: &mut egui::Ui, teams: &[SigningTeam], selected: &mut Option<String>) {
    let chosen = teams
        .iter()
        .find(|team| Some(&team.id) == selected.as_ref());
    let label = chosen.map_or("Choose account…", |team| team.name.as_str());
    let id = ui.make_persistent_id("iphone_signing_team");
    let response = super::accounts::account_editor_input_scope(ui, |ui| {
        super::accounts::account_picker_button(ui, id, label, ui.available_width())
    })
    .inner;
    let frame = egui::Frame::popup(ui.style());
    let width = response.rect.width() - frame.total_margin().sum().x;
    egui::Popup::menu(&response)
        .id(id)
        .width(response.rect.width())
        .frame(frame)
        .style(theme::picker_popup_style)
        .show(|ui| {
            ui.set_width(width);
            egui::ScrollArea::vertical()
                .max_height(180.0)
                .show(ui, |ui| {
                    for team in teams {
                        let label = format!("{} · {}", team.name, team.id);
                        if ui
                            .add(egui::Button::selectable(
                                Some(&team.id) == selected.as_ref(),
                                label,
                            ))
                            .clicked()
                        {
                            *selected = Some(team.id.clone());
                            ui.close();
                        }
                    }
                });
        });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn requirements(teams: Vec<SigningTeam>, selected_team: Option<String>) -> SetupForm {
        SetupForm {
            requirements: Arc::new(OnceLock::from(Ok(SetupRequirements {
                teams,
                selected_team,
                phone_selected: true,
            }))),
            team: None,
            job: None,
            xcode: None,
            feedback: None,
            refresh_after_xcode: false,
            expected_device: None,
            start_after_connect: false,
        }
    }

    #[test]
    fn selects_saved_or_sole_team_and_requires_choice_for_multiple_accounts() {
        let personal = SigningTeam {
            id: "ABCDE12345".into(),
            name: "Personal account".into(),
        };
        let work = SigningTeam {
            id: "ZYXWV98765".into(),
            name: "Work account".into(),
        };
        let mut sole = requirements(vec![personal.clone()], None);
        sole.select_available_team();
        assert_eq!(sole.team.as_deref(), Some("ABCDE12345"));
        let mut multiple = requirements(vec![personal.clone(), work.clone()], None);
        multiple.select_available_team();
        assert!(multiple.team.is_none());
        multiple.team = Some(work.id.clone());
        multiple.select_available_team();
        assert_eq!(multiple.team, Some(work.id.clone()));
        let mut saved = requirements(vec![personal.clone(), work.clone()], Some(work.id.clone()));
        saved.select_available_team();
        assert_eq!(saved.team, Some(work.id));
        let mut missing = requirements(vec![personal], Some("MISSING123".into()));
        missing.select_available_team();
        assert!(missing.team.is_none());
    }

    #[test]
    fn connected_phone_starts_setup_once_when_the_signing_choice_is_ready() {
        let ctx = egui::Context::default();
        let team = SigningTeam {
            id: "ABCDE12345".into(),
            name: "Work".into(),
        };
        let device = "AAAAAAAA-1234567890000001";
        let mut form = requirements(vec![], None);
        let scan = Arc::new(OnceLock::new());
        form.requirements = Arc::clone(&scan);
        form.expected_device = Some(device.into());
        form.start_after_connect = true;
        ctx.data_mut(|data| data.insert_temp(form_id(), form));

        let attempts = Cell::new(0);
        let result = Arc::new(OnceLock::new());
        let frame = || {
            ctx.run_ui(Default::default(), |ui| {
                show_with(ui, |_, selected, expected| {
                    assert_eq!(selected, team.id);
                    assert_eq!(expected.as_deref(), Some(device));
                    attempts.set(attempts.get() + 1);
                    let cancelled = Arc::new(AtomicBool::new(false));
                    SetupJob {
                        _lifetime: Arc::new(CancelOnDrop(Arc::clone(&cancelled))),
                        cancelled,
                        progress: Arc::new(Mutex::new(SetupProgress::Checking)),
                        result: Arc::clone(&result),
                    }
                });
            })
        };
        frame();
        assert_eq!(attempts.get(), 0);
        scan.set(Ok(SetupRequirements {
            teams: vec![
                team.clone(),
                SigningTeam {
                    id: "ZYXWV98765".into(),
                    name: "Personal".into(),
                },
            ],
            selected_team: None,
            phone_selected: true,
        }))
        .unwrap();
        frame();
        assert_eq!(attempts.get(), 0);
        ctx.data_mut(|data| {
            let mut form = data.get_temp::<SetupForm>(form_id()).unwrap();
            form.team = Some(team.id.clone());
            data.insert_temp(form_id(), form);
        });
        frame();
        frame();
        assert_eq!(attempts.get(), 1);
        result
            .set(Err("Unlock your iPhone and retry.".into()))
            .unwrap();
        let failed = frame();
        assert!(failed.shapes.iter().any(|item| matches!(&item.shape,
            egui::Shape::Text(text) if text.galley.text() == "Retry setup")));
        frame();
        assert_eq!(attempts.get(), 1);
    }

    #[test]
    fn leaving_the_guide_disarms_pending_setup() {
        let ctx = egui::Context::default();
        let team = SigningTeam {
            id: "ABCDE12345".into(),
            name: "Personal".into(),
        };
        let mut form = requirements(vec![team], None);
        form.start_after_connect = true;
        form.expected_device = Some("AAAAAAAA-1234567890000001".into());
        ctx.data_mut(|data| data.insert_temp(form_id(), form));
        cancel(&ctx);
        let _ = ctx.run_ui(Default::default(), |ui| {
            show_with(ui, |_, _, _| panic!("Setup started after cancellation"));
        });
        assert!(!busy(&ctx));
    }

    #[test]
    fn reconnect_after_cancelling_offscreen_starts_for_the_new_device() {
        let team = SigningTeam {
            id: "ABCDE12345".into(),
            name: "Work".into(),
        };
        let device = "AAAAAAAA-1234567890000002";
        for finished_before_connect in [false, true] {
            let ctx = egui::Context::default();
            let cancelled = Arc::new(AtomicBool::new(false));
            let result = Arc::new(OnceLock::new());
            let mut previous = requirements(vec![team.clone()], None);
            previous.job = Some(SetupJob {
                _lifetime: Arc::new(CancelOnDrop(Arc::clone(&cancelled))),
                cancelled: Arc::clone(&cancelled),
                progress: Arc::new(Mutex::new(SetupProgress::Checking)),
                result: Arc::clone(&result),
            });
            ctx.data_mut(|data| data.insert_temp(form_id(), previous));
            cancel(&ctx);
            let finish = || result.set(Err("Old setup cancelled".into())).unwrap();
            if finished_before_connect {
                finish();
            }
            assert_eq!(busy(&ctx), !finished_before_connect);
            let mut next = requirements(vec![team.clone()], None);
            next.expected_device = Some(device.into());
            next.start_after_connect = true;
            replace_after_connect(&ctx, next);

            let started = Cell::new(0);
            let frame = || {
                ctx.run_ui(Default::default(), |ui| {
                    show_with(ui, |_, _, selected| {
                        assert!(result.get().is_some());
                        assert_eq!(selected.as_deref(), Some(device));
                        started.set(started.get() + 1);
                        let cancel = Arc::new(AtomicBool::new(false));
                        SetupJob {
                            _lifetime: Arc::new(CancelOnDrop(Arc::clone(&cancel))),
                            cancelled: cancel,
                            progress: Arc::new(Mutex::new(SetupProgress::Checking)),
                            result: Default::default(),
                        }
                    });
                })
            };
            frame();
            if !finished_before_connect {
                assert_eq!(started.get(), 0);
                finish();
            }
            frame();
            assert_eq!(started.get(), 1);
        }
    }

    #[test]
    fn setup_progress_and_errors_preserve_the_selected_account_for_retry() {
        let ctx = egui::Context::default();
        let team = SigningTeam {
            id: "ABCDE12345".into(),
            name: "My account".into(),
        };
        let mut form = requirements(vec![team.clone()], None);
        form.select_available_team();
        let result = Arc::new(OnceLock::new());
        let cancelled = Arc::new(AtomicBool::new(false));
        form.job = Some(SetupJob {
            _lifetime: Arc::new(CancelOnDrop(Arc::clone(&cancelled))),
            cancelled: Arc::clone(&cancelled),
            progress: Arc::new(Mutex::new(SetupProgress::Checking)),
            result: result.clone(),
        });
        ctx.data_mut(|data| data.insert_temp(form_id(), form));
        let texts = || {
            ctx.run_ui(Default::default(), |ui| {
                ui.set_width(440.0);
                show(ui);
            })
            .shapes
            .into_iter()
            .filter_map(|item| match item.shape {
                egui::Shape::Text(t) => Some(t.galley.text().to_owned()),
                _ => None,
            })
            .collect::<Vec<_>>()
        };
        texts();
        assert!(busy(&ctx));
        assert!(texts().iter().any(|t| t == "Cancel"));
        super::super::iphone_sign_in::close_details(&ctx);
        assert!(cancelled.load(Ordering::Acquire));
        refresh(&ctx);
        assert!(busy(&ctx));
        assert!(texts().iter().any(|t| t == "Stopping setup…"));
        result
            .set(Err("Unlock your iPhone and try again.".into()))
            .unwrap();
        let failed = texts();
        assert!(failed.iter().any(|t| t == "Retry setup"));
        assert!(failed
            .iter()
            .any(|t| t == "Unlock your iPhone and try again."));
        assert!(!busy(&ctx));
        let form = ctx
            .data(|data| data.get_temp::<SetupForm>(form_id()))
            .unwrap();
        assert_eq!(form.team.as_deref(), Some(team.id.as_str()));
        assert!(failed
            .iter()
            .all(|t| !t.contains("76C2QW8JV3") && !t.contains("Terminal")));
    }
}
