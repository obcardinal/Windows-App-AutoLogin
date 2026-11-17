use std::cell::Cell;
use windows::core::w;
use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::UI::Shell::{DefSubclassProc, RemoveWindowSubclass, SetWindowSubclass};
use windows::Win32::UI::WindowsAndMessaging::RegisterWindowMessageW;

const SUBCLASS_ID: usize = 0x5741_414c;

pub(super) struct WindowsTrayVisibility {
    // Keep the native window alive until the subclass has been removed in Drop.
    tray: tray_icon::TrayIcon,
    hidden: Cell<bool>,
}

impl WindowsTrayVisibility {
    pub(super) fn new(tray: tray_icon::TrayIcon) -> Self {
        Self {
            tray,
            hidden: Cell::new(false),
        }
    }

    pub(super) fn set_hidden(&self, hidden: bool) -> anyhow::Result<()> {
        if hidden == self.hidden.get() {
            return Ok(());
        }

        let hwnd = HWND(self.tray.window_handle());
        if hidden {
            // tray-icon 0.24 unconditionally restores its icon after Explorer restarts.
            // Suppress only that message while hidden, without replacing its tray window.
            let taskbar_created = unsafe { RegisterWindowMessageW(w!("TaskbarCreated")) };
            if taskbar_created == 0 {
                anyhow::bail!("could not register the Windows taskbar restart message");
            }
            // SAFETY: The window belongs to this thread and is retained by self.tray.
            // The callback stores only a message number, with no borrowed state.
            if !unsafe {
                SetWindowSubclass(
                    hwnd,
                    Some(hidden_tray_proc),
                    SUBCLASS_ID,
                    taskbar_created as usize,
                )
            }
            .as_bool()
            {
                anyhow::bail!("could not preserve hidden tray icon across Explorer restarts");
            }
            if let Err(error) = self.tray.set_visible(false) {
                // SAFETY: This removes only our callback from the retained tray window.
                let _ = unsafe { RemoveWindowSubclass(hwnd, Some(hidden_tray_proc), SUBCLASS_ID) };
                return Err(error.into());
            }
        } else {
            self.tray.set_visible(true)?;
            // SAFETY: This removes only our callback from the retained tray window.
            if !unsafe { RemoveWindowSubclass(hwnd, Some(hidden_tray_proc), SUBCLASS_ID) }.as_bool()
            {
                self.tray.set_visible(false)?;
                anyhow::bail!("could not restore tray icon restart handling");
            }
        }
        self.hidden.set(hidden);
        Ok(())
    }
}

impl Drop for WindowsTrayVisibility {
    fn drop(&mut self) {
        // SAFETY: self.tray retains the native window until this Drop finishes.
        unsafe {
            let _ = RemoveWindowSubclass(
                HWND(self.tray.window_handle()),
                Some(hidden_tray_proc),
                SUBCLASS_ID,
            );
        }
    }
}

unsafe extern "system" fn hidden_tray_proc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
    _subclass_id: usize,
    taskbar_created: usize,
) -> LRESULT {
    if message as usize == taskbar_created {
        return LRESULT(0);
    }
    // SAFETY: Forward unchanged parameters to the next subclass/window procedure.
    unsafe { DefSubclassProc(hwnd, message, wparam, lparam) }
}
