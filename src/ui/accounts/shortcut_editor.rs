use super::{
    account_editor_help, theme, ACCOUNT_EDITOR_CONTROL_HEIGHT, ACCOUNT_EDITOR_LABEL_WIDTH,
};
use crate::models::{Account, DesktopShortcut};
use block2::RcBlock;
use eframe::egui;
use objc2::{rc::Retained, runtime::AnyObject};
use objc2_app_kit::{NSApplication, NSEvent, NSEventMask, NSEventModifierFlags as Flags};
use objc2_foundation::MainThreadMarker;
use std::cell::RefCell;
use std::ptr::NonNull;

const HELP: &str = "Press a letter or number with Control, Option, or Command. Esc cancels.";

#[derive(Clone, Copy, Default)]
enum KeyPress {
    #[default]
    Cancel,
    Invalid,
    Shortcut(DesktopShortcut),
}

struct LocalMonitor(Retained<AnyObject>);

impl Drop for LocalMonitor {
    fn drop(&mut self) {
        // SAFETY: This is precisely the token returned by addLocalMonitor, on the same thread.
        unsafe { NSEvent::removeMonitor(&self.0) };
    }
}

thread_local! {
    // AppKit owns one account editor on the main thread. Only its recording
    // button installs a local monitor, which takes precedence over menu commands.
    static MONITOR: RefCell<Option<LocalMonitor>> = const { RefCell::new(None) };
}

fn state_id() -> egui::Id {
    egui::Id::new("account_desktop_shortcut_recorder")
}

fn recording() -> bool {
    MONITOR.with_borrow(Option::is_some)
}

pub(super) fn close(ctx: &egui::Context) {
    MONITOR.with_borrow_mut(Option::take);
    ctx.data_mut(|data| {
        data.remove::<KeyPress>(state_id());
        data.remove::<String>(state_id());
    });
}

fn key_press(code: u16, flags: Flags) -> KeyPress {
    if code == 0x35 {
        // kVK_Escape
        return KeyPress::Cancel;
    }
    let modifiers = [
        (Flags::Control, DesktopShortcut::CONTROL),
        (Flags::Option, DesktopShortcut::OPTION),
        (Flags::Shift, DesktopShortcut::SHIFT),
        (Flags::Command, DesktopShortcut::COMMAND),
    ]
    .into_iter()
    .filter(|(flag, _)| flags.contains(*flag))
    .fold(0, |mask, (_, modifier)| mask | modifier);
    crate::macos_shortcuts::shortcut_key_from_keycode(code)
        .and_then(|key| DesktopShortcut::new(modifiers, key))
        .map_or(KeyPress::Invalid, KeyPress::Shortcut)
}

fn start(ctx: &egui::Context) -> Result<(), &'static str> {
    let window = MainThreadMarker::new()
        .and_then(|mtm| NSApplication::sharedApplication(mtm).keyWindow())
        .ok_or("Select the account window to record a shortcut.")?;
    let window_number = window.windowNumber();
    let repaint = ctx.clone();
    let viewport = ctx.viewport_id();
    let callback = RcBlock::new(move |ptr: NonNull<NSEvent>| {
        // SAFETY: AppKit passes a live event for the synchronous callback.
        let event = unsafe { ptr.as_ref() };
        let target = event.windowNumber();
        // Key equivalents may arrive with no target window. AppKit routes
        // those to its key window. Never capture from another window.
        if !window.isKeyWindow() || (target > 0 && target != window_number) {
            return ptr.as_ptr();
        }
        if !event.isARepeat() {
            // winit delivers Command key releases directly to its NSWindow,
            // bypassing application event monitors. Commit the chord on press.
            let key = key_press(event.keyCode(), event.modifierFlags());
            repaint.data_mut(|data| data.insert_temp(state_id(), key));
            repaint.request_repaint_of(viewport);
            repaint.request_repaint_of(egui::ViewportId::ROOT);
        }
        std::ptr::null_mut()
    });
    // SAFETY: The callback returns the incoming event or null, and AppKit
    // copies the block until the token is explicitly removed.
    let token = unsafe {
        NSEvent::addLocalMonitorForEventsMatchingMask_handler(NSEventMask::KeyDown, &callback)
    }
    .ok_or("macOS could not start shortcut recording. Try again.")?;
    MONITOR.with_borrow_mut(|monitor| *monitor = Some(LocalMonitor(token)));
    Ok(())
}

pub(super) fn check_duplicate(
    shortcut: DesktopShortcut,
    account_id: &str,
    accounts: &[Account],
) -> Result<(), String> {
    if let Some(other) = accounts
        .iter()
        .find(|other| other.id != account_id && other.desktop_shortcut == Some(shortcut))
    {
        return Err(format!(
            "{shortcut} already opens the desktop for {}.",
            other.display_name()
        ));
    }
    Ok(())
}

fn viewport_key(ctx: &egui::Context) -> Option<KeyPress> {
    ctx.input_mut(|input| {
        let press = input.events.iter().find_map(|event| {
            let (key, modifiers) = match event {
                egui::Event::Key {
                    key,
                    physical_key,
                    modifiers,
                    pressed: true,
                    repeat: false,
                } => (physical_key.unwrap_or(*key), *modifiers),
                // egui-winit translates these commands before delivering a Key event.
                egui::Event::Copy => (egui::Key::C, input.modifiers),
                egui::Event::Cut => (egui::Key::X, input.modifiers),
                egui::Event::Paste(_) => (egui::Key::V, input.modifiers),
                _ => return None,
            };
            if key == egui::Key::Escape {
                return Some(KeyPress::Cancel);
            }
            let mask = u8::from(modifiers.ctrl) * DesktopShortcut::CONTROL
                | u8::from(modifiers.alt) * DesktopShortcut::OPTION
                | u8::from(modifiers.shift) * DesktopShortcut::SHIFT
                | u8::from(modifiers.mac_cmd) * DesktopShortcut::COMMAND;
            let shortcut = match key.name().as_bytes() {
                &[byte] => DesktopShortcut::new(mask, char::from(byte)),
                _ => None,
            };
            Some(shortcut.map_or(KeyPress::Invalid, KeyPress::Shortcut))
        });
        // A recording chord should never type into another control or invoke
        // the editor's Escape action, including characters generated by Option.
        super::scrub_password_event_copies(&mut input.events);
        super::scrub_password_event_copies(&mut input.raw.events);
        input
            .events
            .retain(|event| !matches!(event, egui::Event::Key { .. }));
        press
    })
}

pub(super) fn poll(ctx: &egui::Context, draft: &mut Account, accounts: &[Account]) {
    if !recording() {
        return;
    }
    if ctx.input(|i| i.viewport().focused == Some(false)) {
        close(ctx);
        return;
    }
    let from_viewport = viewport_key(ctx);
    let Some(key) = ctx
        .data_mut(|data| data.remove_temp::<KeyPress>(state_id()))
        .or(from_viewport)
    else {
        return;
    };
    let message = match key {
        KeyPress::Cancel => {
            close(ctx);
            return;
        }
        KeyPress::Invalid => HELP.to_string(),
        KeyPress::Shortcut(shortcut) => {
            let available = check_duplicate(shortcut, &draft.id, accounts).and_then(|()| {
                crate::macos_shortcuts::check_available(shortcut).map_err(|e| e.to_string())
            });
            match available {
                Ok(()) => {
                    draft.desktop_shortcut = Some(shortcut);
                    close(ctx);
                    return;
                }
                Err(message) => message,
            }
        }
    };
    ctx.data_mut(|data| data.insert_temp(state_id(), message));
}

pub(super) fn field(ui: &mut egui::Ui, account: &mut Account, field_width: f32) {
    let label = ui.add_sized(
        [ACCOUNT_EDITOR_LABEL_WIDTH, ACCOUNT_EDITOR_CONTROL_HEIGHT],
        egui::Label::new(
            egui::RichText::new("Open desktop")
                .size(12.0)
                .line_height(Some(14.0)),
        )
        .halign(egui::Align::Min),
    );
    let active = recording();
    ui.horizontal(|ui| {
        let button_text = if active {
            "Press shortcut…".into()
        } else {
            account
                .desktop_shortcut
                .map_or_else(|| "Record Shortcut".into(), |s| s.to_string())
        };
        let clear_width = 60.0;
        let width = if account.desktop_shortcut.is_some() {
            field_width - clear_width - ui.spacing().item_spacing.x
        } else {
            field_width
        };
        let button = ui
            .add_sized(
                [width, ACCOUNT_EDITOR_CONTROL_HEIGHT],
                theme::secondary_button(button_text),
            )
            .labelled_by(label.id)
            .on_hover_text("Record a global keyboard shortcut to open this VM in Windows App.");
        if button.clicked() {
            close(ui.ctx());
            if !active {
                button.request_focus();
                if let Err(message) = start(ui.ctx()) {
                    ui.data_mut(|data| data.insert_temp(state_id(), message.to_owned()));
                }
            }
            ui.ctx().request_repaint();
        } else if active && button.clicked_elsewhere() {
            close(ui.ctx());
        }
        if account.desktop_shortcut.is_some()
            && ui
                .add_sized(
                    [clear_width, ACCOUNT_EDITOR_CONTROL_HEIGHT],
                    theme::secondary_button("Clear"),
                )
                .on_hover_text("Remove this desktop shortcut.")
                .clicked()
        {
            account.desktop_shortcut = None;
            close(ui.ctx());
        }
    });
}

pub(super) fn feedback(ui: &mut egui::Ui) {
    if let Some(message) = ui.data(|data| data.get_temp::<String>(state_id())) {
        ui.add(egui::Label::new(egui::RichText::new(message).small().color(theme::DANGER)).wrap());
    } else if recording() {
        account_editor_help(ui, HELP);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recording_preserves_the_physical_key_and_all_required_modifiers() {
        // kVK_ANSI_C. In particular, Command-C must be captured before the
        // clipboard/menu code translates or consumes the event.
        for flags in [Flags::empty(), Flags::Shift] {
            assert!(matches!(key_press(0x08, flags), KeyPress::Invalid));
        }
        let flags = Flags::Control | Flags::Option | Flags::Command | Flags::Shift;
        let KeyPress::Shortcut(chord) = key_press(0x08, flags) else {
            panic!("a modified letter must be recordable");
        };
        assert_eq!(chord.key, 'C');
        assert_eq!(
            chord.modifiers,
            DesktopShortcut::CONTROL
                | DesktopShortcut::OPTION
                | DesktopShortcut::SHIFT
                | DesktopShortcut::COMMAND
        );
        assert!(matches!(key_press(0x35, flags), KeyPress::Cancel));
        assert!(matches!(key_press(0x24, flags), KeyPress::Invalid)); // Return
    }

    #[test]
    fn viewport_recording_uses_the_physical_key_and_consumes_input_before_fields() {
        let ctx = egui::Context::default();
        let modifiers = egui::Modifiers::CTRL | egui::Modifiers::ALT;
        let input = egui::RawInput {
            modifiers,
            events: vec![
                egui::Event::Key {
                    key: egui::Key::A,
                    physical_key: Some(egui::Key::K),
                    pressed: true,
                    repeat: false,
                    modifiers,
                },
                egui::Event::Text("å".into()),
            ],
            ..Default::default()
        };
        let _ = ctx.run_ui(input, |ui| {
            let Some(KeyPress::Shortcut(shortcut)) = viewport_key(ui.ctx()) else {
                panic!("expected a recorded chord");
            };
            assert_eq!(
                Some(shortcut),
                DesktopShortcut::new(DesktopShortcut::CONTROL | DesktopShortcut::OPTION, 'K')
            );
            assert!(ui.input(|input| input.events.is_empty()));
        });
    }
}
