use crate::macos_shortcuts::GlobalDesktopShortcuts;
use crate::models::{Account, DesktopShortcut};
use crate::tray::TrayCommand;
use std::sync::mpsc::Sender;

pub(crate) fn linked_desktop(account: &Account) -> bool {
    !account.vm_target.trim().is_empty()
        && (!account.vm_device_id.is_empty() || !account.vm_profile.trim().is_empty())
}

pub(crate) fn bound_account<'a>(
    accounts: &'a [Account],
    account_id: &str,
    shortcut: DesktopShortcut,
) -> Option<&'a Account> {
    let mut matching_id = accounts.iter().filter(|account| account.id == account_id);
    let account = matching_id.next()?;
    (!account_id.is_empty()
        && matching_id.next().is_none()
        && account.desktop_shortcut == Some(shortcut)
        && linked_desktop(account))
    .then_some(account)
}

pub(crate) struct AccountShortcuts {
    native: GlobalDesktopShortcuts,
    requested: Vec<(String, DesktopShortcut)>,
}

impl AccountShortcuts {
    pub(crate) fn install(
        sender: Sender<TrayCommand>,
        repaint: Option<eframe::egui::Context>,
    ) -> Option<Self> {
        match GlobalDesktopShortcuts::new(move |id, shortcut| {
            if sender
                .send(TrayCommand::OpenDesktopShortcut(id, shortcut))
                .is_ok()
            {
                if let Some(ctx) = &repaint {
                    ctx.request_repaint_of(eframe::egui::ViewportId::ROOT);
                }
            }
        }) {
            Ok(native) => Some(Self {
                native,
                requested: Vec::new(),
            }),
            Err(error) => {
                tracing::warn!(%error, "Could not listen for desktop shortcuts");
                None
            }
        }
    }

    // The UI owns the bindings for its lifetime. Its supervisor takes them
    // back only after observing the child's exit and reloading the accounts.
    pub(crate) fn update(&mut self, accounts: &[Account]) -> Option<String> {
        let desired = accounts
            .iter()
            .filter(|a| linked_desktop(a))
            .filter_map(|a| Some((a.id.as_str(), a.desktop_shortcut?)));
        if desired.clone().eq(self
            .requested
            .iter()
            .map(|(id, chord)| (id.as_str(), *chord)))
        {
            return None;
        }
        let failures = self.native.sync(desired.clone());
        self.requested = desired.map(|(id, chord)| (id.to_owned(), chord)).collect();
        let errors: Vec<_> = failures.into_iter().map(|(_, message)| message).collect();
        if errors.is_empty() {
            None
        } else {
            Some(errors.join(" "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queued_press_requires_its_original_account_binding_and_linked_desktop() {
        let key = DesktopShortcut::new(DesktopShortcut::CONTROL, '7').unwrap();
        let other = DesktopShortcut::new(DesktopShortcut::CONTROL, '8').unwrap();
        let mut account = Account::new("user@example.test");
        account.desktop_shortcut = Some(key);
        account.vm_target = "Desktop".into();
        let id = account.id.clone();
        let mut accounts = vec![account];
        assert!(bound_account(&accounts, &id, key).is_none());
        accounts[0].vm_profile = "profile".into(); // Older saved connection.
        accounts[0].enabled = false; // Manual Open desktop works with the monitor off.
        assert!(bound_account(&accounts, &id, key).is_some());
        accounts[0].desktop_shortcut = Some(other);
        assert!(bound_account(&accounts, &id, key).is_none());
        assert!(bound_account(&accounts, "unrelated", other).is_none());
        let mut duplicate = accounts[0].clone();
        duplicate.desktop_shortcut = Some(key);
        accounts.push(duplicate);
        assert!(bound_account(&accounts, &id, other).is_none());
        assert!(bound_account(&accounts, &id, key).is_none());
    }
}
