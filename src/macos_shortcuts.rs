//! Carbon delivers only the global shortcuts explicitly registered by this process.
use crate::models::DesktopShortcut;
use anyhow::{anyhow, ensure, Result};
use core_foundation::{
    array::{CFArray, CFArrayRef},
    base::{CFType, TCFType},
    boolean::CFBoolean,
    dictionary::CFDictionary,
    number::CFNumber,
    string::CFString,
};
use objc2_foundation::MainThreadMarker;
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    ffi::c_void,
    ptr::{self, NonNull},
    rc::Rc,
    sync::atomic::{AtomicU32, Ordering},
};

const SIGNATURE: u32 = u32::from_be_bytes(*b"WAAL");
const KEYBOARD: u32 = u32::from_be_bytes(*b"keyb");
const PRESSED: u32 = 5;
const RELEASED: u32 = 6;
const EVENT_NOT_HANDLED: i32 = -9874;
const HOT_KEY_EXISTS: i32 = -9878;
const EXCLUSIVE: u32 = 1;

// kVK_ANSI_A through kVK_ANSI_Z, then kVK_ANSI_0 through kVK_ANSI_9.
// Register the same physical key that the shortcut recorder observed.
const LETTER_CODES: [u16; 26] = [
    0x00, 0x0B, 0x08, 0x02, 0x0E, 0x03, 0x05, 0x04, 0x22, 0x26, 0x28, 0x25, 0x2E, 0x2D, 0x1F, 0x23,
    0x0C, 0x0F, 0x01, 0x11, 0x20, 0x09, 0x0D, 0x07, 0x10, 0x06,
];
const DIGIT_CODES: [u16; 10] = [0x1D, 0x12, 0x13, 0x14, 0x15, 0x17, 0x16, 0x1A, 0x1C, 0x19];

fn keycode(key: char) -> Option<u16> {
    match key {
        'A'..='Z' => Some(LETTER_CODES[usize::from(key as u8 - b'A')]),
        '0'..='9' => Some(DIGIT_CODES[usize::from(key as u8 - b'0')]),
        _ => None,
    }
}

pub(crate) fn shortcut_key_from_keycode(code: u16) -> Option<char> {
    ('A'..='Z')
        .chain('0'..='9')
        .find(|&key| keycode(key) == Some(code))
}

fn carbon_modifiers(shortcut: DesktopShortcut) -> u32 {
    [
        (DesktopShortcut::CONTROL, 1 << 12),
        (DesktopShortcut::OPTION, 1 << 11),
        (DesktopShortcut::SHIFT, 1 << 9),
        (DesktopShortcut::COMMAND, 1 << 8),
    ]
    .into_iter()
    .filter(|(flag, _)| shortcut.modifiers & flag != 0)
    .map(|(_, mask)| mask)
    .sum()
}

#[repr(C)]
#[derive(Default)]
struct HotKeyId {
    signature: u32,
    id: u32,
}

#[repr(C)]
struct EventType {
    class: u32,
    kind: u32,
}

type NativeRef = *mut c_void;
type Handler = unsafe extern "C" fn(NativeRef, NativeRef, NativeRef) -> i32;

#[link(name = "Carbon", kind = "framework")]
extern "C" {
    fn GetApplicationEventTarget() -> NativeRef;
    fn InstallEventHandler(
        target: NativeRef,
        handler: Handler,
        count: usize,
        events: *const EventType,
        context: NativeRef,
        out_handler: *mut NativeRef,
    ) -> i32;
    fn RemoveEventHandler(handler: NativeRef) -> i32;
    fn RegisterEventHotKey(
        code: u32,
        modifiers: u32,
        id: HotKeyId,
        target: NativeRef,
        options: u32,
        out_key: *mut NativeRef,
    ) -> i32;
    fn UnregisterEventHotKey(key: NativeRef) -> i32;
    fn GetEventKind(event: NativeRef) -> u32;
    fn GetEventParameter(
        event: NativeRef,
        name: u32,
        kind: u32,
        actual_kind: *mut u32,
        size: usize,
        actual_size: *mut usize,
        data: NativeRef,
    ) -> i32;
    fn CopySymbolicHotKeys(out_keys: *mut CFArrayRef) -> i32;
}

type KeyCombination = (u32, u32);

/// macOS can grant an exclusive Carbon registration for an enabled system shortcut
/// (for example, a screenshot shortcut) even though the system consumes it.
fn system_shortcuts() -> Result<HashSet<KeyCombination>> {
    let mut array = ptr::null();
    // SAFETY: Carbon returns a retained array of dictionaries using the keys below.
    let status = unsafe { CopySymbolicHotKeys(&mut array) };
    ensure!(
        status == 0 && !array.is_null(),
        "Could not read macOS keyboard shortcuts ({status})."
    );
    let entries =
        unsafe { CFArray::<CFDictionary<CFString, CFType>>::wrap_under_create_rule(array) };
    let enabled = CFString::new("kHISymbolicHotKeyEnabled");
    let key = CFString::new("kHISymbolicHotKeyCode");
    let modifiers = CFString::new("kHISymbolicHotKeyModifiers");
    Ok(entries
        .iter()
        .filter_map(|entry| {
            if !bool::from(entry.find(&enabled)?.downcast::<CFBoolean>()?) {
                return None;
            }
            let number = |name: &CFString| entry.find(name)?.downcast::<CFNumber>()?.to_i32();
            Some((number(&key)? as u32, number(&modifiers)? as u32))
        })
        .collect())
}

fn application_target() -> Result<NonNull<c_void>> {
    ensure!(
        MainThreadMarker::new().is_some(),
        "Keyboard shortcuts require the macOS main thread."
    );
    // SAFETY: The application target is a borrowed, process-lifetime Carbon event target.
    NonNull::new(unsafe { GetApplicationEventTarget() })
        .ok_or_else(|| anyhow!("The macOS keyboard shortcut service is unavailable."))
}

struct NativeShortcut(NonNull<c_void>);

impl NativeShortcut {
    fn register(
        target: NonNull<c_void>,
        id: u32,
        shortcut: DesktopShortcut,
        reserved: &HashSet<KeyCombination>,
    ) -> Result<Self> {
        ensure!(
            DesktopShortcut::new(shortcut.modifiers, shortcut.key) == Some(shortcut),
            "Unsupported shortcut."
        );
        let code =
            u32::from(keycode(shortcut.key).ok_or_else(|| anyhow!("Unsupported shortcut key."))?);
        let modifiers = carbon_modifiers(shortcut);
        ensure!(
            !reserved.contains(&(code, modifiers)),
            "{shortcut} is used by macOS. Choose another shortcut."
        );
        let mut reference = ptr::null_mut();
        // SAFETY: target is live, the output is writable and the ID has Carbon's EventHotKeyID layout.
        let status = unsafe {
            RegisterEventHotKey(
                code,
                modifiers,
                HotKeyId {
                    signature: SIGNATURE,
                    id,
                },
                target.as_ptr(),
                EXCLUSIVE,
                &mut reference,
            )
        };
        ensure!(
            status != HOT_KEY_EXISTS,
            "{shortcut} is already in use. Choose another shortcut."
        );
        ensure!(
            status == 0,
            "macOS could not register {shortcut} ({status}). Choose another shortcut."
        );
        Ok(Self(NonNull::new(reference).ok_or_else(|| {
            anyhow!("macOS returned no registration for {shortcut}.")
        })?))
    }
}

impl Drop for NativeShortcut {
    fn drop(&mut self) {
        // SAFETY: This registration is owned exclusively by this main-thread object.
        let status = unsafe { UnregisterEventHotKey(self.0.as_ptr()) };
        if status != 0 {
            tracing::warn!(status, "Could not unregister macOS keyboard shortcut");
        }
    }
}

pub(crate) fn check_available(shortcut: DesktopShortcut) -> Result<()> {
    let target = application_target()?;
    // ID 0 belongs to probes and never routes to an account.
    drop(NativeShortcut::register(
        target,
        0,
        shortcut,
        &system_shortcuts()?,
    )?);
    Ok(())
}

struct Binding {
    account: String,
    shortcut: DesktopShortcut,
    id: u32,
    held: bool,
    _registration: NativeShortcut,
}

impl Binding {
    fn register(
        target: NonNull<c_void>,
        account: &str,
        shortcut: DesktopShortcut,
        reserved: &HashSet<KeyCombination>,
    ) -> Result<Self> {
        // A queued event from an old registration must never route to a new account,
        // even when an entire manager was dropped and reinstalled.
        static NEXT_ID: AtomicU32 = AtomicU32::new(1);
        let id = NEXT_ID
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| anyhow!("Restart the app to register more shortcuts."))?;
        Ok(Self {
            account: account.to_owned(),
            shortcut,
            id,
            held: false,
            _registration: NativeShortcut::register(target, id, shortcut, reserved)?,
        })
    }
}

struct Callbacks {
    bindings: RefCell<Vec<Binding>>,
    on_press: Rc<dyn Fn(String, DesktopShortcut)>,
}

unsafe extern "C" fn handle_hotkey(_next: NativeRef, event: NativeRef, context: NativeRef) -> i32 {
    let mut id = HotKeyId::default();
    // SAFETY: Carbon supplies an EventRef and copies at most the provided buffer size.
    let status = unsafe {
        GetEventParameter(
            event,
            u32::from_be_bytes(*b"----"),
            u32::from_be_bytes(*b"hkid"),
            ptr::null_mut(),
            size_of::<HotKeyId>(),
            ptr::null_mut(),
            ptr::from_mut(&mut id).cast(),
        )
    };
    if status != 0 || id.signature != SIGNATURE {
        return EVENT_NOT_HANDLED;
    }
    // SAFETY: The manager keeps this allocation alive until the handler is removed.
    let callbacks = unsafe { &*context.cast::<Callbacks>() };
    let kind = unsafe { GetEventKind(event) };
    let selected = {
        let mut bindings = callbacks.bindings.borrow_mut();
        let Some(binding) = bindings.iter_mut().find(|binding| binding.id == id.id) else {
            return EVENT_NOT_HANDLED;
        };
        let pressed = kind == PRESSED;
        let first_press = pressed && !binding.held;
        binding.held = pressed;
        first_press.then(|| (binding.account.clone(), binding.shortcut))
    };
    if let Some((account, shortcut)) = selected {
        // Release the bindings borrow and retain the callback independently. Dispatch
        // may synchronously reenter this handler or drop the manager.
        let on_press = Rc::clone(&callbacks.on_press);
        on_press(account, shortcut);
    }
    0
}

pub(crate) struct GlobalDesktopShortcuts {
    target: NonNull<c_void>,
    handler: NonNull<c_void>,
    callbacks: Rc<Callbacks>,
}

impl GlobalDesktopShortcuts {
    pub(crate) fn new(on_press: impl Fn(String, DesktopShortcut) + 'static) -> Result<Self> {
        let target = application_target()?;
        let callbacks = Rc::new(Callbacks {
            bindings: RefCell::default(),
            on_press: Rc::new(on_press),
        });
        let events = [
            EventType {
                class: KEYBOARD,
                kind: PRESSED,
            },
            EventType {
                class: KEYBOARD,
                kind: RELEASED,
            },
        ];
        let mut handler = ptr::null_mut();
        // SAFETY: The handler is removed before callbacks is released. Carbon copies the event list.
        let status = unsafe {
            InstallEventHandler(
                target.as_ptr(),
                handle_hotkey,
                events.len(),
                events.as_ptr(),
                Rc::as_ptr(&callbacks).cast_mut().cast(),
                &mut handler,
            )
        };
        ensure!(
            status == 0,
            "Could not start macOS keyboard shortcuts ({status})."
        );
        Ok(Self {
            target,
            handler: NonNull::new(handler)
                .ok_or_else(|| anyhow!("macOS returned no keyboard handler."))?,
            callbacks,
        })
    }

    /// Release removed/changed bindings before claiming new ones so two accounts can swap.
    pub(crate) fn sync<'a>(
        &mut self,
        requested: impl IntoIterator<Item = (&'a str, DesktopShortcut)>,
    ) -> Vec<(String, String)> {
        let mut owners = HashMap::<DesktopShortcut, Vec<&str>>::new();
        for (account, shortcut) in requested {
            owners.entry(shortcut).or_default().push(account);
        }
        let mut failures = Vec::new();
        let mut desired = HashMap::new();
        for (shortcut, accounts) in owners {
            if let [account] = accounts.as_slice() {
                desired.insert(shortcut, *account);
            } else {
                for account in accounts {
                    failures.push((
                        account.to_owned(),
                        format!(
                            "{shortcut} is assigned to multiple accounts. Choose another shortcut."
                        ),
                    ));
                }
            }
        }
        let removed: Vec<_> = self
            .callbacks
            .bindings
            .borrow_mut()
            .extract_if(.., |binding| {
                if desired.get(&binding.shortcut) == Some(&binding.account.as_str()) {
                    desired.remove(&binding.shortcut);
                    false
                } else {
                    true
                }
            })
            .collect();
        // Call Carbon outside any RefCell borrow, including during unregistration.
        drop(removed);
        if desired.is_empty() {
            return failures;
        }
        let reserved = match system_shortcuts() {
            Ok(reserved) => reserved,
            Err(error) => {
                failures.extend(
                    desired
                        .into_values()
                        .map(|account| (account.to_owned(), error.to_string())),
                );
                return failures;
            }
        };
        for (shortcut, account) in desired {
            match Binding::register(self.target, account, shortcut, &reserved) {
                Ok(binding) => self.callbacks.bindings.borrow_mut().push(binding),
                Err(error) => failures.push((account.to_owned(), error.to_string())),
            }
        }
        failures
    }
}

impl Drop for GlobalDesktopShortcuts {
    fn drop(&mut self) {
        drop(self.callbacks.bindings.take());
        // SAFETY: This is the event handler installed by new, on the same main thread.
        let status = unsafe { RemoveEventHandler(self.handler.as_ptr()) };
        if status != 0 {
            // Carbon may still reference the callback context. Keep the empty state alive.
            std::mem::forget(self.callbacks.clone());
            tracing::warn!(status, "Could not remove macOS keyboard shortcut handler");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recorder_and_registration_agree_on_physical_keys() {
        for key in ('A'..='Z').chain('0'..='9') {
            assert_eq!(shortcut_key_from_keycode(keycode(key).unwrap()), Some(key));
        }
        assert_eq!(shortcut_key_from_keycode(0x28), Some('K'));
        assert_eq!(shortcut_key_from_keycode(0x16), Some('6'));
        assert_eq!(shortcut_key_from_keycode(0x35), None); // Escape
        assert_eq!(keycode('!'), None);
    }

    #[test]
    fn translates_account_modifiers_to_carbon_masks() {
        let register = |modifiers| carbon_modifiers(DesktopShortcut::new(modifiers, 'A').unwrap());
        assert_eq!(register(DesktopShortcut::CONTROL), 0x1000);
        assert_eq!(register(DesktopShortcut::OPTION), 0x0800);
        assert_eq!(register(DesktopShortcut::COMMAND), 0x0100);
        assert_eq!(
            register(DesktopShortcut::COMMAND | DesktopShortcut::SHIFT),
            0x0300
        );
    }
}
