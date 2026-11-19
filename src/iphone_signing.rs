//! Read local Xcode signing information without accessing private key material.
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SigningTeam {
    pub(crate) id: String,
    pub(crate) name: String,
}

const XCODE_NEEDED: &str = "Install the full Xcode app, open it to finish setup, and select it under Xcode → Settings → Locations → Command Line Tools.";
const KEYCHAIN_ERROR: &str = "Couldn’t read development signing identities from your login keychain. Unlock the keychain and try again.";

// Run trusted system tools off the UI thread. In particular, diagnostics must
// not inherit the settings process's presentation protocol on stdin or stdout.
fn output(program: &str, args: &[&str], input: Option<&[u8]>) -> Option<String> {
    use std::os::unix::process::CommandExt;
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .env("HOME", crate::user_paths::home_dir()?)
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("LC_ALL", "C")
        .process_group(0)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let pipe = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        const LIMIT: u64 = 2 * 1024 * 1024;
        let mut bytes = Vec::new();
        pipe.take(LIMIT + 1).read_to_end(&mut bytes).ok()?;
        (bytes.len() as u64 <= LIMIT).then_some(bytes)
    });
    let input_ok = match input {
        None => true,
        Some(pem) => child
            .stdin
            .take()
            .is_some_and(|mut stdin| stdin.write_all(pem).is_ok()),
    };
    let deadline = Instant::now() + Duration::from_secs(12);
    let success = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.success(),
            Ok(None) if input_ok && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(25));
            }
            _ => {
                // This private group contains only the lookup we launched.
                unsafe { libc::killpg(child.id() as libc::pid_t, libc::SIGKILL) };
                let _ = child.wait();
                break false;
            }
        }
    };
    let bytes = reader.join().ok()??;
    if !success || !input_ok {
        return None;
    }
    String::from_utf8(bytes).ok()
}

fn development_identities(list: &str) -> BTreeSet<String> {
    list.lines()
        .filter_map(|line| {
            let (_, rest) = line.trim().split_once(") ")?;
            let (hash, label) = rest.trim_start().split_once(' ')?;
            (hash.len() == 40
                && hash.bytes().all(|b| b.is_ascii_hexdigit())
                && label.trim().starts_with("\"Apple Development: "))
            .then(|| hash.to_ascii_uppercase())
        })
        .collect()
}

fn signing_team(subject: &str, identities: &BTreeSet<String>) -> Option<SigningTeam> {
    let fields = || subject.lines().map(str::trim);
    let value = |name: &str| {
        let mut matches = fields().filter_map(|l| l.strip_prefix(name));
        let first = matches.next()?;
        matches.next().is_none().then_some(first)
    };
    let fingerprint = value("SHA1 Fingerprint=")?;
    if !identities.contains(&fingerprint.replace(':', "").to_ascii_uppercase()) {
        return None;
    }
    let id = value("OU=")?;
    let name = value("O=")?;
    let unsafe_name = name.chars().any(|c| {
        c.is_control()
            || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
    });
    if !crate::macos_identity::valid_team_id(id)
        || id != id.trim()
        || !value("CN=")?.starts_with("Apple Development: ")
        || name.is_empty()
        || name.len() > 256
        || unsafe_name
    {
        return None;
    }
    Some(SigningTeam {
        id: id.into(),
        name: name.into(),
    })
}

pub(crate) fn available_teams() -> Result<Vec<SigningTeam>, String> {
    if output(
        "/usr/bin/xcrun",
        &["--sdk", "iphoneos", "--find", "devicectl"],
        None,
    )
    .is_none_or(|path| !std::path::Path::new(path.trim()).is_file())
    {
        return Err(XCODE_NEEDED.into());
    }
    let identities = development_identities(
        &output(
            "/usr/bin/security",
            &["find-identity", "-v", "-p", "codesigning"],
            None,
        )
        .ok_or(KEYCHAIN_ERROR)?,
    );
    if identities.is_empty() {
        return Ok(Vec::new());
    }
    // The label in find-identity can end with a personal certificate ID. The
    // Team ID is the organizational unit in the *matching* certificate.
    let certs = output(
        "/usr/bin/security",
        &["find-certificate", "-a", "-c", "Apple Development:", "-p"],
        None,
    )
    .ok_or(KEYCHAIN_ERROR)?;
    let mut teams = BTreeMap::new();
    for pem in certs
        .split_inclusive("-----END CERTIFICATE-----")
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if !pem.starts_with("-----BEGIN CERTIFICATE-----")
            || !pem.ends_with("-----END CERTIFICATE-----")
            || pem.len() > 16 * 1024
        {
            return Err(KEYCHAIN_ERROR.into());
        }
        let subject = output(
            "/usr/bin/openssl",
            &[
                "x509",
                "-noout",
                "-subject",
                "-fingerprint",
                "-sha1",
                "-nameopt",
                "sep_multiline,utf8",
            ],
            Some(pem.as_bytes()),
        )
        .ok_or(KEYCHAIN_ERROR)?;
        if let Some(team) = signing_team(&subject, &identities) {
            teams.entry(team.id.clone()).or_insert(team);
        }
    }
    let mut result: Vec<_> = teams.into_values().collect();
    result.sort_by(|a, b| a.name.cmp(&b.name).then(a.id.cmp(&b.id)));
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    const FINGERPRINT: &str = "1234567890ABCDEF1234567890ABCDEF12345678";
    #[test]
    fn requires_matching_private_key_and_uses_subject_ou() {
        let listing = format!(
            r#"1) {FINGERPRINT} "Apple Development: Example (PERSON0001)"
          2) 0000000000000000000000000000000000000000 "Developer ID Application: Example (TEAM000001)"
          3) ABCD "Apple Development: Other"
          2 valid identities found"#
        );
        let ids = development_identities(&listing);
        assert_eq!(ids.len(), 1);
        let subject = format!("subject=\n    CN=Apple Development: Sample (PERSON0001)\n    OU=TEAM000001\n    O=Example Team\nSHA1 Fingerprint={FINGERPRINT}");
        assert_eq!(
            signing_team(&subject, &ids),
            Some(SigningTeam {
                id: "TEAM000001".into(),
                name: "Example Team".into()
            })
        );
        assert!(signing_team(&subject.replace("TEAM000001", "INVALID"), &ids).is_none());
        assert!(signing_team(
            &subject.replace("    O=", "    OU=TEAM000002\n    O="),
            &ids
        )
        .is_none());
        assert!(signing_team(&subject, &BTreeSet::new()).is_none());
    }
}
