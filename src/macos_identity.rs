#[cfg(target_os = "macos")]
use anyhow::Context;
#[cfg(target_os = "macos")]
use core_foundation::{
    base::TCFType,
    data::{CFData, CFDataRef},
    dictionary::{CFDictionary, CFDictionaryGetValueIfPresent, CFDictionaryRef},
    string::CFStringRef,
    url::CFURL,
};
#[cfg(target_os = "macos")]
use security_framework::os::macos::code_signing::{
    Flags as CodeSignFlags, GuestAttributes, SecCode, SecRequirement, SecStaticCode,
};
#[cfg(target_os = "macos")]
use std::cell::RefCell;
#[cfg(target_os = "macos")]
use std::collections::HashMap;
#[cfg(target_os = "macos")]
use std::ffi::c_void;
#[cfg(target_os = "macos")]
use std::path::{Path, PathBuf};
#[cfg(target_os = "macos")]
use std::process::Command;
#[cfg(target_os = "macos")]
use std::time::{Duration, Instant};

#[cfg(target_os = "macos")]
const MICROSOFT_REMOTE_DESKTOP_BUNDLE_ID: &str = "com.microsoft.rdc.macos";
#[cfg(target_os = "macos")]
const MICROSOFT_TEAM_ID: &str = "UBF8T346G9";
#[cfg(target_os = "macos")]
const PROC_ALL_PIDS: u32 = 1;
#[cfg(target_os = "macos")]
const SEC_CS_SIGNING_INFORMATION: u32 = 1 << 1;

#[cfg(target_os = "macos")]
thread_local! {
    static CODE_SIGN_REQUIREMENTS: RefCell<HashMap<String, SecRequirement>> =
        RefCell::new(HashMap::new());
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy)]
struct TrustedIdentity {
    bundle_id: &'static str,
    team_id: &'static str,
}

#[cfg(target_os = "macos")]
#[derive(Debug)]
struct ProcessIdentity {
    pid: i32,
    bundle_id: String,
    bundle_path: PathBuf,
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct TrustedProcessInfo {
    pub(crate) pid: i32,
    pub(crate) bundle_id: String,
    pub(crate) bundle_path: PathBuf,
    pub(crate) team_id: &'static str,
}

#[cfg(target_os = "macos")]
#[allow(dead_code)]
pub(crate) fn trusted_process_infos(app_name: &str) -> anyhow::Result<Vec<TrustedProcessInfo>> {
    let processes = enumerate_processes(app_name)?;
    trusted_process_infos_from_identities(app_name, &processes, verify_trusted_live_process)
}

#[cfg(target_os = "macos")]
#[allow(dead_code)]
pub(crate) fn trusted_process_info_for_pid(
    app_name: &str,
    pid: i32,
) -> anyhow::Result<Option<TrustedProcessInfo>> {
    let Some(executable_path) = process_executable_path(pid) else {
        return Ok(None);
    };
    let Some(bundle_path) = containing_app_bundle(&executable_path) else {
        return Ok(None);
    };
    let Some(identity) = trusted_identity(app_name) else {
        anyhow::bail!("unsupported app identity for secure automation: {app_name}");
    };

    let processes = [ProcessIdentity {
        pid,
        bundle_id: identity.bundle_id.to_string(),
        bundle_path,
    }];

    Ok(
        trusted_process_infos_from_identities(app_name, &processes, verify_trusted_live_process)?
            .into_iter()
            .next(),
    )
}

#[cfg(target_os = "macos")]
fn trusted_process_infos_from_identities(
    app_name: &str,
    processes: &[ProcessIdentity],
    mut verify_process: impl FnMut(i32, &Path, TrustedIdentity) -> anyhow::Result<bool>,
) -> anyhow::Result<Vec<TrustedProcessInfo>> {
    let Some(identity) = trusted_identity(app_name) else {
        anyhow::bail!("unsupported app identity for secure automation: {app_name}");
    };

    let mut trusted_processes = Vec::new();
    for process in processes {
        if process.bundle_id != identity.bundle_id {
            continue;
        }
        if !bundle_path_is_trusted_location(&process.bundle_path, app_name) {
            continue;
        }
        if verify_process(process.pid, &process.bundle_path, identity)? {
            trusted_processes.push(TrustedProcessInfo {
                pid: process.pid,
                bundle_id: process.bundle_id.clone(),
                bundle_path: process.bundle_path.clone(),
                team_id: identity.team_id,
            });
        }
    }

    Ok(trusted_processes)
}

#[cfg(target_os = "macos")]
fn trusted_identity(app_name: &str) -> Option<TrustedIdentity> {
    match app_name.trim() {
        "Windows App" => Some(TrustedIdentity {
            bundle_id: MICROSOFT_REMOTE_DESKTOP_BUNDLE_ID,
            team_id: MICROSOFT_TEAM_ID,
        }),
        _ => None,
    }
}

#[cfg(target_os = "macos")]
fn trusted_bundle_candidates(app_name: &str) -> Vec<PathBuf> {
    match app_name.trim() {
        "Windows App" => vec![PathBuf::from("/Applications/Windows App.app")],
        _ => Vec::new(),
    }
}

#[cfg(target_os = "macos")]
fn bundle_path_is_trusted_location(path: &Path, app_name: &str) -> bool {
    trusted_bundle_candidates(app_name)
        .into_iter()
        .any(|candidate| path == candidate && trusted_bundle_candidate_is_usable(&candidate))
}

#[cfg(target_os = "macos")]
fn enumerate_processes(app_name: &str) -> anyhow::Result<Vec<ProcessIdentity>> {
    let Some(identity) = trusted_identity(app_name) else {
        anyhow::bail!("unsupported app identity for secure automation: {app_name}");
    };

    let trusted_candidates = trusted_bundle_candidates(app_name)
        .into_iter()
        .filter(|path| trusted_bundle_candidate_is_usable(path))
        .collect::<Vec<_>>();
    if trusted_candidates.is_empty() {
        return Ok(Vec::new());
    }

    Ok(native_process_ids()
        .into_iter()
        .filter_map(|pid| {
            let executable_path = process_executable_path(pid)?;
            let bundle_path = containing_app_bundle(&executable_path)?;
            trusted_candidates
                .iter()
                .any(|candidate| *candidate == bundle_path)
                .then(|| ProcessIdentity {
                    pid,
                    bundle_id: identity.bundle_id.to_string(),
                    bundle_path,
                })
        })
        .collect())
}

#[cfg(target_os = "macos")]
fn trusted_bundle_candidate_is_usable(path: &Path) -> bool {
    path.exists() && path.is_dir() && !path_has_symlink_component(path)
}

#[cfg(target_os = "macos")]
pub(crate) fn path_has_symlink_component(path: &Path) -> bool {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if std::fs::symlink_metadata(&current)
            .map(|metadata| metadata.file_type().is_symlink())
            .unwrap_or(false)
        {
            return true;
        }
    }
    false
}

#[cfg(target_os = "macos")]
fn native_process_ids() -> Vec<i32> {
    let bytes = unsafe { libc::proc_listpids(PROC_ALL_PIDS, 0, std::ptr::null_mut(), 0) };
    if bytes <= 0 {
        return Vec::new();
    }

    let mut pids = vec![0 as libc::pid_t; bytes as usize / std::mem::size_of::<libc::pid_t>() + 64];
    let bytes = unsafe {
        libc::proc_listpids(
            PROC_ALL_PIDS,
            0,
            pids.as_mut_ptr().cast(),
            (pids.len() * std::mem::size_of::<libc::pid_t>()) as i32,
        )
    };
    if bytes <= 0 {
        return Vec::new();
    }

    pids.truncate(bytes as usize / std::mem::size_of::<libc::pid_t>());
    pids.into_iter()
        .filter(|pid| *pid > 0)
        .map(|pid| pid as i32)
        .collect()
}

#[cfg(target_os = "macos")]
fn process_executable_path(pid: i32) -> Option<PathBuf> {
    let mut buffer = vec![0_u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let len = unsafe {
        libc::proc_pidpath(
            pid,
            buffer.as_mut_ptr().cast(),
            buffer.len().try_into().ok()?,
        )
    };
    if len <= 0 {
        return None;
    }

    proc_pidpath_buffer_to_path(&buffer[..len as usize])
}

#[cfg(target_os = "macos")]
fn proc_pidpath_buffer_to_path(buffer: &[u8]) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStringExt;

    let end = buffer
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(buffer.len());
    let path = buffer[..end].to_vec();
    (!path.is_empty()).then(|| PathBuf::from(std::ffi::OsString::from_vec(path)))
}

#[cfg(target_os = "macos")]
fn containing_app_bundle(path: &Path) -> Option<PathBuf> {
    path.ancestors()
        .find(|candidate| candidate.extension().is_some_and(|ext| ext == "app"))
        .map(Path::to_path_buf)
}

#[cfg(target_os = "macos")]
fn verify_trusted_live_process(
    pid: i32,
    bundle_path: &Path,
    identity: TrustedIdentity,
) -> anyhow::Result<bool> {
    let Some(code) = live_code_for_pid(pid) else {
        return Ok(false);
    };
    let Some(live_path) = code
        .path(CodeSignFlags::NONE)
        .ok()
        .and_then(|url| url.to_path())
    else {
        return Ok(false);
    };
    let Some(live_bundle_path) = containing_app_bundle(&live_path) else {
        return Ok(false);
    };
    if live_bundle_path != bundle_path || path_has_symlink_component(&live_bundle_path) {
        return Ok(false);
    }

    with_code_sign_requirement(identity.bundle_id, identity.team_id, |requirement| {
        Ok(code
            .check_validity(live_code_validation_flags(), requirement)
            .is_ok())
    })
}

#[cfg(target_os = "macos")]
#[allow(dead_code)]
pub(crate) fn signed_live_process_matches_identity(
    pid: i32,
    bundle_path: &Path,
    bundle_id: &'static str,
    team_id: &'static str,
) -> anyhow::Result<bool> {
    verify_trusted_live_process(pid, bundle_path, TrustedIdentity { bundle_id, team_id })
}

#[cfg(target_os = "macos")]
#[allow(dead_code)]
pub(crate) fn live_process_code_unique_identifier(pid: i32) -> Option<Vec<u8>> {
    let path = process_executable_path(pid)?;
    static_code_unique_identifier_at_path(&path)
}

#[cfg(target_os = "macos")]
#[allow(dead_code)]
pub(crate) fn current_process_code_unique_identifier() -> Option<Vec<u8>> {
    let path = std::env::current_exe().ok()?;
    static_code_unique_identifier_at_path(&path)
}

#[cfg(target_os = "macos")]
#[allow(dead_code)]
pub(crate) fn static_code_path_has_valid_internal_signature(path: &Path) -> bool {
    static_code_at_path(path)
        .as_ref()
        .is_some_and(static_code_has_valid_internal_signature)
}

#[cfg(target_os = "macos")]
fn live_code_for_pid(pid: i32) -> Option<SecCode> {
    let mut attributes = GuestAttributes::new();
    attributes.set_pid(pid as libc::pid_t);
    SecCode::copy_guest_with_attribues(None, &attributes, CodeSignFlags::NONE).ok()
}

#[cfg(target_os = "macos")]
#[allow(dead_code)]
fn static_code_unique_identifier_at_path(path: &Path) -> Option<Vec<u8>> {
    let code = static_code_at_path(path)?;
    static_code_unique_identifier(&code)
}

#[cfg(target_os = "macos")]
fn static_code_at_path(path: &Path) -> Option<SecStaticCode> {
    let url = CFURL::from_path(path, path.is_dir())?;
    SecStaticCode::from_path(&url, CodeSignFlags::NONE).ok()
}

#[cfg(target_os = "macos")]
#[allow(dead_code)]
fn static_code_unique_identifier(code: &SecStaticCode) -> Option<Vec<u8>> {
    if !static_code_has_valid_internal_signature(code) {
        return None;
    }

    copy_code_unique_identifier(code.as_CFTypeRef().cast())
}

#[cfg(target_os = "macos")]
#[allow(dead_code)]
fn copy_code_unique_identifier(code: *const c_void) -> Option<Vec<u8>> {
    let mut information: CFDictionaryRef = std::ptr::null();
    let status = unsafe {
        SecCodeCopySigningInformation(
            code,
            SEC_CS_SIGNING_INFORMATION,
            &mut information as *mut CFDictionaryRef,
        )
    };
    if status != 0 || information.is_null() {
        return None;
    }

    let information = unsafe {
        CFDictionary::<*const c_void, *const c_void>::wrap_under_create_rule(information)
    };
    let key = unsafe { kSecCodeInfoUnique.cast::<c_void>() };
    let mut value: *const c_void = std::ptr::null();
    let found = unsafe {
        CFDictionaryGetValueIfPresent(information.as_concrete_TypeRef(), key, &mut value)
    };
    if found == 0 || value.is_null() {
        return None;
    }

    let data = unsafe { CFData::wrap_under_get_rule(value.cast::<_>() as CFDataRef) };
    (!data.is_empty()).then(|| data.bytes().to_vec())
}

#[cfg(target_os = "macos")]
#[allow(dead_code)]
fn static_code_has_valid_internal_signature(code: &SecStaticCode) -> bool {
    unsafe {
        SecStaticCodeCheckValidity(
            code.as_CFTypeRef().cast(),
            static_code_validation_flags().bits(),
            std::ptr::null(),
        ) == 0
    }
}

#[cfg(target_os = "macos")]
fn static_code_validation_flags() -> CodeSignFlags {
    CodeSignFlags::STRICT_VALIDATE
        | CodeSignFlags::CHECK_ALL_ARCHITECTURES
        | CodeSignFlags::CHECK_NESTED_CODE
        | CodeSignFlags::RESTRICT_SYMLINKS
}

#[cfg(target_os = "macos")]
fn live_code_validation_flags() -> CodeSignFlags {
    CodeSignFlags::NONE
}

#[cfg(target_os = "macos")]
extern "C" {
    static kSecCodeInfoUnique: CFStringRef;

    fn SecCodeCopySigningInformation(
        code: *const c_void,
        flags: u32,
        information: *mut CFDictionaryRef,
    ) -> i32;

    fn SecStaticCodeCheckValidity(
        code: *const c_void,
        flags: u32,
        requirement: *const c_void,
    ) -> i32;
}

#[cfg(target_os = "macos")]
fn code_sign_requirement_source(bundle_id: &str, team_id: &str) -> anyhow::Result<String> {
    let team_id = validated_team_id(team_id)
        .ok_or_else(|| anyhow::anyhow!("invalid macOS Team ID for codesign requirement"))?;
    let raw_bundle_id = bundle_id.trim();
    let bundle_id = requirement_string_literal(raw_bundle_id)
        .ok_or_else(|| anyhow::anyhow!("invalid bundle identifier for codesign requirement"))?;
    let application_identifier = requirement_string_literal(&format!("{team_id}.{raw_bundle_id}"))
        .ok_or_else(|| {
            anyhow::anyhow!("invalid application identifier for codesign requirement")
        })?;

    Ok(format!(
        "anchor apple generic and identifier {bundle_id} and \
         ((certificate leaf[field.1.2.840.113635.100.6.1.9] exists and \
         entitlement[\"com.apple.developer.team-identifier\"] = \"{team_id}\" and \
         entitlement[\"com.apple.application-identifier\"] = {application_identifier}) or \
         (certificate 1[field.1.2.840.113635.100.6.2.6] exists and \
         certificate leaf[field.1.2.840.113635.100.6.1.13] exists and \
         certificate leaf[subject.OU] = \"{team_id}\"))"
    ))
}

#[cfg(target_os = "macos")]
fn with_code_sign_requirement<R>(
    bundle_id: &str,
    team_id: &str,
    f: impl FnOnce(&SecRequirement) -> anyhow::Result<R>,
) -> anyhow::Result<R> {
    let key = format!("{bundle_id}\n{team_id}");
    CODE_SIGN_REQUIREMENTS.with(|cache| {
        let mut cache = cache.borrow_mut();
        if !cache.contains_key(&key) {
            let requirement = code_sign_requirement_source(bundle_id, team_id)?.parse()?;
            cache.insert(key.clone(), requirement);
        }
        let requirement = cache
            .get(&key)
            .context("cached macOS code-sign requirement disappeared")?;
        f(requirement)
    })
}

#[cfg(target_os = "macos")]
#[allow(dead_code)]
pub(crate) fn verify_bundle_designated_requirement(
    path: &Path,
    bundle_id: &str,
    team_id: &str,
) -> anyhow::Result<bool> {
    let canonical_path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let requirement = format!("={}", code_sign_requirement_source(bundle_id, team_id)?);
    let output = run_command_with_timeout(
        Command::new("/usr/bin/codesign")
            .args(["--verify", "--strict", "--test-requirement", &requirement])
            .arg(&canonical_path),
        Duration::from_secs(5),
    )?;
    Ok(output.status.success())
}

#[cfg(target_os = "macos")]
#[allow(dead_code)]
pub(crate) fn valid_team_id(team_id: &str) -> bool {
    validated_team_id(team_id).is_some()
}

#[cfg(target_os = "macos")]
fn validated_team_id(team_id: &str) -> Option<&str> {
    let team_id = team_id.trim();
    (team_id.len() == 10
        && team_id
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit()))
    .then_some(team_id)
}

#[cfg(target_os = "macos")]
fn requirement_string_literal(value: &str) -> Option<String> {
    let value = value.trim();
    (value.len() <= 255
        && !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-')))
    .then(|| format!("\"{value}\""))
}

#[cfg(target_os = "macos")]
#[allow(dead_code)]
fn run_command_with_timeout(
    command: &mut Command,
    timeout: Duration,
) -> anyhow::Result<std::process::Output> {
    let mut child = command.spawn()?;
    let started = Instant::now();
    loop {
        if child.try_wait()?.is_some() {
            return Ok(child.wait_with_output()?);
        }

        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("command timed out");
        }

        std::thread::sleep(Duration::from_millis(25));
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::{
        code_sign_requirement_source, live_code_validation_flags, path_has_symlink_component,
        proc_pidpath_buffer_to_path, static_code_validation_flags,
        trusted_process_infos_from_identities, valid_team_id, CodeSignFlags, ProcessIdentity,
    };
    use std::path::PathBuf;

    #[test]
    fn untrusted_bundle_location_is_rejected_before_signature_check() {
        let processes = vec![ProcessIdentity {
            pid: 4242,
            bundle_id: "com.microsoft.rdc.macos".to_string(),
            bundle_path: PathBuf::from("/tmp/Windows App.app"),
        }];
        let mut verifier_called = false;

        let trusted = trusted_process_infos_from_identities(
            "Windows App",
            &processes,
            |_pid, _path, _identity| {
                verifier_called = true;
                Ok(true)
            },
        )
        .unwrap();

        assert!(trusted.is_empty());
        assert!(!verifier_called);
    }

    #[test]
    fn unsupported_app_identities_are_rejected() {
        for app_name in ["Lookalike App", "Microsoft Remote Desktop"] {
            let error =
                trusted_process_infos_from_identities(app_name, &[], |_pid, _path, _identity| {
                    Ok(true)
                })
                .unwrap_err();

            assert_eq!(
                error.to_string(),
                format!("unsupported app identity for secure automation: {app_name}")
            );
        }
    }

    #[test]
    fn codesign_verifier_failure_rejects_process() {
        let processes = vec![ProcessIdentity {
            pid: 4242,
            bundle_id: "com.microsoft.rdc.macos".to_string(),
            bundle_path: PathBuf::from("/Applications/Windows App.app"),
        }];

        let trusted = trusted_process_infos_from_identities(
            "Windows App",
            &processes,
            |pid, path, identity| {
                assert_eq!(pid, 4242);
                assert_eq!(path, PathBuf::from("/Applications/Windows App.app"));
                assert_eq!(identity.bundle_id, "com.microsoft.rdc.macos");
                assert_eq!(identity.team_id, "UBF8T346G9");
                Ok(false)
            },
        )
        .unwrap();

        assert!(trusted.is_empty());
    }

    #[test]
    fn live_code_validation_uses_only_live_safe_flags() {
        let flags = live_code_validation_flags();

        assert_eq!(flags.bits(), CodeSignFlags::NONE.bits());
        assert!(!flags.contains(CodeSignFlags::STRICT_VALIDATE));
        assert!(!flags.contains(CodeSignFlags::CHECK_ALL_ARCHITECTURES));
        assert!(!flags.contains(CodeSignFlags::CHECK_NESTED_CODE));
        assert!(!flags.contains(CodeSignFlags::RESTRICT_SYMLINKS));
    }

    #[test]
    fn static_code_validation_keeps_static_bundle_architecture_check() {
        let flags = static_code_validation_flags();

        assert!(flags.contains(CodeSignFlags::STRICT_VALIDATE));
        assert!(flags.contains(CodeSignFlags::CHECK_ALL_ARCHITECTURES));
        assert!(flags.contains(CodeSignFlags::CHECK_NESTED_CODE));
        assert!(flags.contains(CodeSignFlags::RESTRICT_SYMLINKS));
    }

    #[test]
    fn trusted_process_info_carries_verified_team_id() {
        let processes = vec![ProcessIdentity {
            pid: 4242,
            bundle_id: "com.microsoft.rdc.macos".to_string(),
            bundle_path: PathBuf::from("/Applications/Windows App.app"),
        }];

        let trusted = trusted_process_infos_from_identities(
            "Windows App",
            &processes,
            |pid, _path, identity| {
                assert_eq!(pid, 4242);
                assert_eq!(identity.bundle_id, "com.microsoft.rdc.macos");
                assert_eq!(identity.team_id, "UBF8T346G9");
                Ok(true)
            },
        )
        .unwrap();

        assert_eq!(trusted.len(), 1);
        assert_eq!(trusted[0].pid, 4242);
        assert_eq!(trusted[0].bundle_id, "com.microsoft.rdc.macos");
        assert_eq!(
            trusted[0].bundle_path,
            PathBuf::from("/Applications/Windows App.app")
        );
        assert_eq!(trusted[0].team_id, "UBF8T346G9");
    }

    #[test]
    fn process_verifier_can_reject_only_one_pid_for_same_bundle() {
        let processes = vec![
            ProcessIdentity {
                pid: 1111,
                bundle_id: "com.microsoft.rdc.macos".to_string(),
                bundle_path: PathBuf::from("/Applications/Windows App.app"),
            },
            ProcessIdentity {
                pid: 2222,
                bundle_id: "com.microsoft.rdc.macos".to_string(),
                bundle_path: PathBuf::from("/Applications/Windows App.app"),
            },
        ];

        let trusted = trusted_process_infos_from_identities(
            "Windows App",
            &processes,
            |pid, _path, _identity| Ok(pid == 2222),
        )
        .unwrap();
        let trusted = trusted
            .into_iter()
            .map(|process| process.pid)
            .collect::<Vec<_>>();

        assert_eq!(trusted, vec![2222]);
    }

    #[test]
    fn process_verifier_error_is_propagated() {
        let processes = vec![ProcessIdentity {
            pid: 4242,
            bundle_id: "com.microsoft.rdc.macos".to_string(),
            bundle_path: PathBuf::from("/Applications/Windows App.app"),
        }];

        let error = trusted_process_infos_from_identities(
            "Windows App",
            &processes,
            |_pid, _path, _identity| anyhow::bail!("verifier unavailable"),
        )
        .unwrap_err();

        assert_eq!(error.to_string(), "verifier unavailable");
    }

    #[test]
    fn requirement_source_is_bare_expression_for_security_framework() {
        let requirement =
            code_sign_requirement_source("com.microsoft.rdc.macos", "UBF8T346G9").unwrap();

        assert!(!requirement.starts_with('='));
        assert!(!requirement.contains("designated =>"));
        assert!(requirement.starts_with("anchor apple generic and identifier"));
        assert!(requirement.contains("identifier \"com.microsoft.rdc.macos\""));
        assert!(requirement.contains("certificate leaf[field.1.2.840.113635.100.6.1.9] exists"));
        assert!(requirement
            .contains("entitlement[\"com.apple.developer.team-identifier\"] = \"UBF8T346G9\""));
        assert!(requirement.contains(
            "entitlement[\"com.apple.application-identifier\"] = \"UBF8T346G9.com.microsoft.rdc.macos\""
        ));
        assert!(requirement.contains("certificate 1[field.1.2.840.113635.100.6.2.6] exists"));
        assert!(requirement.contains("certificate leaf[field.1.2.840.113635.100.6.1.13] exists"));
        assert!(requirement.contains("certificate leaf[subject.OU] = \"UBF8T346G9\""));
        assert!(!requirement.contains("certificate leaf[field.1.2.840.113635.100.6.1.9] exists or"));
        assert_eq!(
            requirement
                .matches("certificate leaf[subject.OU] = \"UBF8T346G9\"")
                .count(),
            1
        );
    }

    #[test]
    fn team_id_validation_rejects_requirement_injection() {
        assert!(valid_team_id("UBF8T346G9"));
        assert!(!valid_team_id(""));
        assert!(!valid_team_id("UBF8T346G9 or true"));
        assert!(!valid_team_id("ubf8t346g9"));
        assert!(!valid_team_id("UBF8T346"));
        assert!(
            code_sign_requirement_source("com.microsoft.rdc.macos", "UBF8T346G9 or true").is_err()
        );
    }

    #[test]
    fn bundle_identifier_validation_rejects_requirement_injection() {
        for bundle_id in [
            "",
            "com.microsoft.rdc.macos\" or true",
            "com.microsoft.rdc.macos or true",
            "com.microsoft.rdc.macos\\",
            "com.microsoft.rdc.macos)",
        ] {
            assert!(code_sign_requirement_source(bundle_id, "UBF8T346G9").is_err());
        }
    }

    #[test]
    fn symlink_component_detection_rejects_aliases() {
        let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "windows-app-autologin-symlink-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let real = root.join("real");
        let link = root.join("link");
        std::fs::create_dir_all(real.join("Windows App.app")).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();

        assert!(path_has_symlink_component(&link.join("Windows App.app")));
        assert!(!path_has_symlink_component(&real.join("Windows App.app")));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn proc_pidpath_buffer_preserves_path_bytes_without_trimming() {
        use std::os::unix::ffi::OsStrExt;

        let leading = proc_pidpath_buffer_to_path(b" /Applications/Windows App.app").unwrap();
        let trailing = proc_pidpath_buffer_to_path(b"/Applications/Windows App.app ").unwrap();
        let nul_terminated =
            proc_pidpath_buffer_to_path(b"/Applications/Windows App.app\0/spoof").unwrap();

        assert_eq!(
            leading.as_os_str().as_bytes(),
            b" /Applications/Windows App.app"
        );
        assert_eq!(
            trailing.as_os_str().as_bytes(),
            b"/Applications/Windows App.app "
        );
        assert_eq!(
            nul_terminated.as_os_str().as_bytes(),
            b"/Applications/Windows App.app"
        );
    }
}
