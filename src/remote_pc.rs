//! A Remote PC is the desktop endpoint, which can differ from the RD Gateway.
use crate::models::{canonical_remote_pc, Account};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) enum PromptDestination {
    #[default]
    Unreported,
    Host(String),
    Ambiguous,
}

impl PromptDestination {
    fn record(&mut self, host: Option<String>) {
        match (&*self, host) {
            (Self::Unreported, Some(host)) => *self = Self::Host(host),
            (Self::Host(existing), Some(host)) if existing == &host => {}
            _ => *self = Self::Ambiguous,
        }
    }

    /// The caller has already matched a visible email to one enabled account
    /// with a saved password. A reported destination further narrows that match.
    pub(crate) fn check_account(
        &self,
        account: &Account,
        account_count: usize,
    ) -> Result<(), &'static str> {
        match self {
            Self::Unreported => Ok(()), // e.g. the initial RD Gateway sign-in
            Self::Ambiguous => Err("remote_pc_ambiguous"),
            Self::Host(_) if account.remote_pc.is_empty() && account_count == 1 => Ok(()),
            Self::Host(_) if account.remote_pc.is_empty() => Err("remote_pc_missing_for_account"),
            Self::Host(host) if canonical_remote_pc(&account.remote_pc).as_ref() == Some(host) => {
                Ok(())
            }
            Self::Host(_) => Err("remote_pc_account_mismatch"),
        }
    }
}

/// Input is native static text scoped to a credential prompt or the
/// Connection section of Windows App's own information dialog.
pub(crate) fn prompt_destination(text: &str) -> PromptDestination {
    let tokens: Vec<_> = text.split_whitespace().collect();
    let mut result = PromptDestination::Unreported;
    for (i, pair) in tokens.windows(2).enumerate() {
        if pair[0].eq_ignore_ascii_case("remote")
            && pair[1].trim_end_matches(':').eq_ignore_ascii_case("pc")
        {
            let rest = &tokens[i + 2..];
            let rest = rest.strip_prefix(&[":"]).unwrap_or(rest);
            result.record(remote_pc_label_value(rest));
        }
    }

    // Native credential sheets report the target in this separate sentence.
    // On Cloud PC the named target can be Microsoft's *gateway*, even when
    // its own UI appends "(remote PC)". It cannot identify the destination VM.
    let lower = text.to_ascii_lowercase();
    for rest in lower
        .split("credentials will be used to connect to ")
        .skip(1)
    {
        let mut parts = rest.split_whitespace();
        let Some(raw_host) = parts.next() else {
            continue;
        };
        if parts.next() != Some("(remote")
            || !parts
                .next()
                .is_some_and(|s| s.trim_end_matches(['.', ':']) == "pc)")
        {
            continue;
        }
        let host = canonical_remote_pc(raw_host);
        if host.as_deref().is_some_and(is_cloud_pc_gateway) {
            continue;
        }
        result.record(host);
    }
    result
}

fn remote_pc_label_value(tokens: &[&str]) -> Option<String> {
    let (&first, rest) = tokens.split_first()?;
    // If the value is absent, the following native row can start immediately.
    let label = first.trim_end_matches(':');
    if ["gateway", "username", "password", "remote"]
        .iter()
        .any(|key| label.eq_ignore_ascii_case(key))
    {
        return None;
    }
    if let Some(second) = rest.first() {
        if [
            ("service", "region"),
            ("activity", "id"),
            ("session", "type"),
        ]
        .iter()
        .any(|(a, b)| {
            label.eq_ignore_ascii_case(a) && second.trim_end_matches(':').eq_ignore_ascii_case(b)
        }) {
            return None;
        }
    }
    canonical_remote_pc(first)
}

fn is_cloud_pc_gateway(host: &str) -> bool {
    let (label, domain) = host.split_once('.').unwrap_or((host, ""));
    matches!(
        domain,
        "wvd.microsoft.com" | "wvd.microsoft.us" | "wvd.azure.cn"
    ) && (label.starts_with("rdgateway-")
        || label.starts_with("afdfp-rdgateway-")
        || label == "rdgateway")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_only_the_desktop_endpoint_and_rejects_conflicting_or_invalid_labels() {
        assert_eq!(prompt_destination("Session Type Remote Desktop Gateway relay.example:443 Remote PC HOST.corp.example Service Region GRN Activity ID 123"),
                   PromptDestination::Host("host.corp.example".into()));
        assert_eq!(
            prompt_destination("Remote PC:\n10.0.2.1"),
            PromptDestination::Host("10.0.2.1".into())
        );
        assert_eq!(
            prompt_destination("Connection Information Gateway relay.example"),
            PromptDestination::Unreported
        );
        assert_eq!(
            prompt_destination("Remote PC: desk.a\nRemote PC: desk.b"),
            PromptDestination::Ambiguous
        );
        assert_eq!(
            prompt_destination("Remote PC: https://desk.a"),
            PromptDestination::Ambiguous
        );
        assert_eq!(
            prompt_destination("Remote PC Service Region GRN Activity ID 123"),
            PromptDestination::Ambiguous
        );
        assert_eq!(prompt_destination("These credentials will be used to connect to rdgateway-r1.wvd.microsoft.com (remote PC). Username:"), PromptDestination::Unreported);
        assert_eq!(
            prompt_destination(
                "These credentials will be used to connect to desk.example (remote PC). Username:"
            ),
            PromptDestination::Host("desk.example".into())
        );
    }

    #[test]
    fn only_a_single_configured_account_can_leave_a_reported_remote_pc_unmapped() {
        let mut account = Account::new("user@example.com");
        let host = PromptDestination::Host("desk.example".into());
        assert!(host.check_account(&account, 1).is_ok());
        assert!(host.check_account(&account, 2).is_err());
        account.remote_pc = "DESK.example.".into();
        assert!(host.check_account(&account, 2).is_ok());
        let other = PromptDestination::Host("other.example".into());
        assert!(other.check_account(&account, 1).is_err());
        account.remote_pc = "https://desk.example".into();
        assert!(host.check_account(&account, 1).is_err());
        assert!(PromptDestination::Ambiguous
            .check_account(&account, 1)
            .is_err());
        assert!(PromptDestination::Unreported
            .check_account(&account, 2)
            .is_ok());
    }
}
