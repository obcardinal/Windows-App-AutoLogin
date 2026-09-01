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
use std::process::{Command, Stdio};
#[cfg(target_os = "macos")]
use std::time::{Duration, Instant};

#[cfg(target_os = "macos")]
const MICROSOFT_REMOTE_DESKTOP_BUNDLE_ID: &str = "com.microsoft.rdc.macos";
#[cfg(target_os = "macos")]
const MICROSOFT_TEAM_ID: &str = "UBF8T346G9";
#[cfg(target_os = "macos")]
const PROC_ALL_PIDS: u32 = 1;
#[cfg(target_os = "macos")]
const PROC_LIST_GROWTH_ATTEMPTS: usize = 8;
#[cfg(target_os = "macos")]
const PROC_LIST_INITIAL_SLACK: usize = 64;
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
    let Some(executable_path) = process_executable_path(pid)
        .with_context(|| format!("unable to resolve executable path for PID {pid}"))?
    else {
        return Ok(None);
    };
    let Some(bundle_path) = containing_app_bundle_for_direct_main_executable(&executable_path)
    else {
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
        if !bundle_path_is_trusted_location(&process.bundle_path, app_name)? {
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
fn bundle_path_is_trusted_location(path: &Path, app_name: &str) -> anyhow::Result<bool> {
    for candidate in trusted_bundle_candidates(app_name) {
        if path == candidate {
            return trusted_bundle_candidate_is_usable(&candidate);
        }
    }
    Ok(false)
}

#[cfg(target_os = "macos")]
fn enumerate_processes(app_name: &str) -> anyhow::Result<Vec<ProcessIdentity>> {
    let Some(identity) = trusted_identity(app_name) else {
        anyhow::bail!("unsupported app identity for secure automation: {app_name}");
    };

    let mut trusted_candidates = Vec::new();
    for candidate in trusted_bundle_candidates(app_name) {
        if trusted_bundle_candidate_is_usable(&candidate)? {
            trusted_candidates.push(candidate);
        }
    }
    if trusted_candidates.is_empty() {
        return Ok(Vec::new());
    }

    process_identities_from_pids(
        native_process_ids()?,
        &trusted_candidates,
        identity,
        process_executable_path,
    )
}

#[cfg(target_os = "macos")]
fn process_identities_from_pids(
    pids: Vec<i32>,
    trusted_candidates: &[PathBuf],
    identity: TrustedIdentity,
    mut executable_path: impl FnMut(i32) -> anyhow::Result<Option<PathBuf>>,
) -> anyhow::Result<Vec<ProcessIdentity>> {
    let mut processes = Vec::new();
    for pid in pids {
        let Some(executable_path) = executable_path(pid)
            .with_context(|| format!("unable to resolve executable path for PID {pid}"))?
        else {
            // A PID may legitimately disappear after proc_listpids captured
            // the snapshot. Only that definitive race is safe to omit.
            continue;
        };
        let Some(bundle_path) = containing_app_bundle_for_direct_main_executable(&executable_path)
        else {
            continue;
        };
        if trusted_candidates.contains(&bundle_path) {
            processes.push(ProcessIdentity {
                pid,
                bundle_id: identity.bundle_id.to_string(),
                bundle_path,
            });
        }
    }
    Ok(processes)
}

#[cfg(target_os = "macos")]
fn trusted_bundle_candidate_is_usable(path: &Path) -> anyhow::Result<bool> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error).with_context(|| {
                format!("unable to inspect trusted bundle path {}", path.display())
            })
        }
    };
    if !metadata.is_dir() {
        return Ok(false);
    }
    Ok(!path_has_symlink_component_checked(path)?)
}

#[cfg(target_os = "macos")]
#[allow(dead_code)]
pub(crate) fn path_has_symlink_component(path: &Path) -> bool {
    // Existing callers use this as a fail-closed predicate. An unreadable path
    // is therefore treated as unsafe rather than silently accepted.
    path_has_symlink_component_checked(path).unwrap_or(true)
}

#[cfg(target_os = "macos")]
fn path_has_symlink_component_checked(path: &Path) -> anyhow::Result<bool> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        let metadata = std::fs::symlink_metadata(&current)
            .with_context(|| format!("unable to inspect path component {}", current.display()))?;
        if metadata.file_type().is_symlink() {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(target_os = "macos")]
fn native_process_ids() -> anyhow::Result<Vec<i32>> {
    clear_errno();
    let bytes = unsafe { libc::proc_listpids(PROC_ALL_PIDS, 0, std::ptr::null_mut(), 0) };
    if bytes <= 0 {
        return Err(std::io::Error::last_os_error())
            .context("unable to size the native process list");
    }

    let pid_size = std::mem::size_of::<libc::pid_t>();
    let initial_capacity = (bytes as usize)
        .div_ceil(pid_size)
        .checked_add(PROC_LIST_INITIAL_SLACK)
        .context("native process-list capacity overflow")?;
    native_process_ids_with_reader(initial_capacity, |pids| {
        let buffer_bytes = pids
            .len()
            .checked_mul(pid_size)
            .and_then(|bytes| i32::try_from(bytes).ok())
            .context("native process-list buffer is too large")?;
        clear_errno();
        let bytes = unsafe {
            libc::proc_listpids(PROC_ALL_PIDS, 0, pids.as_mut_ptr().cast(), buffer_bytes)
        };
        if bytes <= 0 {
            return Err(std::io::Error::last_os_error())
                .context("unable to enumerate native processes");
        }
        Ok(bytes as usize)
    })
}

#[cfg(target_os = "macos")]
fn native_process_ids_with_reader(
    initial_capacity: usize,
    mut read: impl FnMut(&mut [libc::pid_t]) -> anyhow::Result<usize>,
) -> anyhow::Result<Vec<i32>> {
    let pid_size = std::mem::size_of::<libc::pid_t>();
    let mut capacity = initial_capacity.max(1);
    for _ in 0..PROC_LIST_GROWTH_ATTEMPTS {
        let mut pids = vec![0 as libc::pid_t; capacity];
        let capacity_bytes = capacity
            .checked_mul(pid_size)
            .context("native process-list capacity overflow")?;
        let bytes = read(&mut pids)?;
        if bytes > capacity_bytes || bytes % pid_size != 0 {
            anyhow::bail!("native process list returned an invalid byte count");
        }
        if bytes == capacity_bytes {
            capacity = capacity
                .checked_mul(2)
                .context("native process-list capacity overflow")?;
            continue;
        }

        pids.truncate(bytes / pid_size);
        return Ok(pids.into_iter().filter(|pid| *pid > 0).collect());
    }
    anyhow::bail!("native process list remained full after repeated growth")
}

#[cfg(target_os = "macos")]
fn clear_errno() {
    unsafe {
        *libc::__error() = 0;
    }
}

#[cfg(target_os = "macos")]
fn process_executable_path(pid: i32) -> anyhow::Result<Option<PathBuf>> {
    let mut buffer = vec![0_u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let buffer_len = buffer
        .len()
        .try_into()
        .context("proc_pidpath buffer length does not fit its native argument")?;
    clear_errno();
    let len = unsafe { libc::proc_pidpath(pid, buffer.as_mut_ptr().cast(), buffer_len) };
    if len <= 0 {
        let error = std::io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(libc::ESRCH) | Some(libc::ENOENT) => Ok(None),
            _ => Err(error).with_context(|| format!("proc_pidpath failed for PID {pid}")),
        };
    }

    let path = proc_pidpath_buffer_to_path(&buffer[..len as usize])
        .with_context(|| format!("proc_pidpath returned an empty path for PID {pid}"))?;
    Ok(Some(path))
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
fn containing_app_bundle_for_direct_main_executable(path: &Path) -> Option<PathBuf> {
    let bundle_path = containing_app_bundle(path)?;
    let executable_name = bundle_path.file_stem()?;
    let expected_executable = bundle_path
        .join("Contents")
        .join("MacOS")
        .join(executable_name);

    (path == expected_executable).then_some(bundle_path)
}

#[cfg(target_os = "macos")]
fn verify_trusted_live_process(
    pid: i32,
    bundle_path: &Path,
    identity: TrustedIdentity,
) -> anyhow::Result<bool> {
    let Some(code) = live_code_for_pid(pid)? else {
        return Ok(false);
    };
    let live_url = code
        .path(CodeSignFlags::NONE)
        .with_context(|| format!("unable to read live code path for PID {pid}"))?;
    let live_path = live_url
        .to_path()
        .with_context(|| format!("live code path is not a filesystem path for PID {pid}"))?;
    let Some(live_bundle_path) = containing_app_bundle(&live_path) else {
        return Ok(false);
    };
    if live_bundle_path != bundle_path || path_has_symlink_component_checked(&live_bundle_path)? {
        return Ok(false);
    }

    with_code_sign_requirement(identity.bundle_id, identity.team_id, |requirement| {
        code.check_validity(live_code_validation_flags(), requirement)
            .with_context(|| format!("unable to validate live code signature for PID {pid}"))?;
        Ok(true)
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
    // This API is intentionally best-effort for an existing fail-closed
    // single-instance comparison. Trusted-target presence uses the checked
    // Result-returning path above and never reaches this lossy boundary.
    let path = process_executable_path(pid).ok().flatten()?;
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
fn live_code_for_pid(pid: i32) -> anyhow::Result<Option<SecCode>> {
    let mut attributes = GuestAttributes::new();
    attributes.set_pid(pid as libc::pid_t);
    match SecCode::copy_guest_with_attribues(None, &attributes, CodeSignFlags::NONE) {
        Ok(code) => Ok(Some(code)),
        Err(error) => {
            // Security.framework reports a lookup failure both for a process
            // exit race and for identity/signature lookup failures. Recheck
            // native PID presence: only a confirmed exit is absence; a live
            // process with an unavailable code identity is indeterminate.
            if process_executable_path(pid)?.is_none() {
                Ok(None)
            } else {
                Err(error)
                    .with_context(|| format!("unable to resolve live code identity for PID {pid}"))
            }
        }
    }
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
    // The supervised settings UI reserves its inherited stdin/stdout for a
    // private presentation protocol. Disconnect every helper stream here so a
    // verifier cannot consume commands or emit bytes that look like ACKs.
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
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
        code_sign_requirement_source, live_code_validation_flags, native_process_ids_with_reader,
        path_has_symlink_component, proc_pidpath_buffer_to_path, process_identities_from_pids,
        run_command_with_timeout, static_code_validation_flags,
        trusted_process_infos_from_identities, valid_team_id, CodeSignFlags, ProcessIdentity,
        TrustedIdentity,
    };
    use std::path::PathBuf;
    use std::process::Command;
    use std::time::Duration;

    #[test]
    fn timed_helper_process_suppresses_protocol_sensitive_output() {
        let output = run_command_with_timeout(
            Command::new("/bin/sh")
                .args(["-c", "printf protocol-output; printf diagnostic-output >&2"]),
            Duration::from_secs(1),
        )
        .unwrap();

        assert!(output.status.success());
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }

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
    fn process_path_lookup_failure_makes_presence_indeterminate() {
        let error = process_identities_from_pids(
            vec![4242],
            &[PathBuf::from("/Applications/Windows App.app")],
            TrustedIdentity {
                bundle_id: "com.microsoft.rdc.macos",
                team_id: "UBF8T346G9",
            },
            |_pid| anyhow::bail!("proc_pidpath unavailable"),
        )
        .unwrap_err();

        assert_eq!(
            error.to_string(),
            "unable to resolve executable path for PID 4242"
        );
        assert_eq!(
            error.source().map(ToString::to_string).as_deref(),
            Some("proc_pidpath unavailable")
        );
    }

    #[test]
    fn process_that_exits_during_snapshot_is_definitively_omitted() {
        let processes = process_identities_from_pids(
            vec![4242],
            &[PathBuf::from("/Applications/Windows App.app")],
            TrustedIdentity {
                bundle_id: "com.microsoft.rdc.macos",
                team_id: "UBF8T346G9",
            },
            |_pid| Ok(None),
        )
        .unwrap();

        assert!(processes.is_empty());
    }

    #[test]
    fn direct_main_executable_is_discovered_as_the_trusted_app_identity() {
        let processes = process_identities_from_pids(
            vec![49_806],
            &[PathBuf::from("/Applications/Windows App.app")],
            TrustedIdentity {
                bundle_id: "com.microsoft.rdc.macos",
                team_id: "UBF8T346G9",
            },
            |pid| {
                assert_eq!(pid, 49_806);
                Ok(Some(PathBuf::from(
                    "/Applications/Windows App.app/Contents/MacOS/Windows App",
                )))
            },
        )
        .unwrap();

        assert_eq!(processes.len(), 1);
        assert_eq!(processes[0].pid, 49_806);
        assert_eq!(processes[0].bundle_id, "com.microsoft.rdc.macos");
        assert_eq!(
            processes[0].bundle_path,
            PathBuf::from("/Applications/Windows App.app")
        );
    }

    #[test]
    fn nested_pasteboard_xpc_executable_is_not_discovered_as_the_main_app() {
        let processes = process_identities_from_pids(
            vec![68_662],
            &[PathBuf::from("/Applications/Windows App.app")],
            TrustedIdentity {
                bundle_id: "com.microsoft.rdc.macos",
                team_id: "UBF8T346G9",
            },
            |pid| {
                assert_eq!(pid, 68_662);
                Ok(Some(PathBuf::from(
                    "/Applications/Windows App.app/Contents/Frameworks/ClientShared.framework/Versions/A/XPCServices/pasteboard.xpc.xpc/Contents/MacOS/pasteboard.xpc",
                )))
            },
        )
        .unwrap();

        assert!(processes.is_empty());
    }

    #[test]
    fn full_native_process_buffer_is_grown_and_retried() {
        let mut reads = 0;
        let pids = native_process_ids_with_reader(2, |buffer| {
            reads += 1;
            match reads {
                1 => {
                    assert_eq!(buffer.len(), 2);
                    buffer.copy_from_slice(&[11, 22]);
                    Ok(std::mem::size_of_val(buffer))
                }
                2 => {
                    assert_eq!(buffer.len(), 4);
                    buffer[..3].copy_from_slice(&[11, 22, 33]);
                    Ok(std::mem::size_of_val(&buffer[..3]))
                }
                _ => panic!("unexpected process-list retry"),
            }
        })
        .unwrap();

        assert_eq!(reads, 2);
        assert_eq!(pids, vec![11, 22, 33]);
    }

    #[test]
    fn perpetually_full_native_process_buffer_is_indeterminate() {
        let mut reads = 0;
        let error = native_process_ids_with_reader(1, |buffer| {
            reads += 1;
            buffer.fill(42);
            Ok(std::mem::size_of_val(buffer))
        })
        .unwrap_err();

        assert_eq!(reads, super::PROC_LIST_GROWTH_ATTEMPTS);
        assert_eq!(
            error.to_string(),
            "native process list remained full after repeated growth"
        );
    }

    #[test]
    fn live_signature_api_failures_are_not_collapsed_to_absence() {
        let implementation = include_str!("macos_identity.rs");
        let verifier = implementation
            .split("fn verify_trusted_live_process")
            .nth(1)
            .and_then(|tail| {
                tail.split("pub(crate) fn signed_live_process_matches_identity")
                    .next()
            })
            .unwrap();

        assert!(verifier.contains("unable to read live code path"));
        assert!(verifier.contains("unable to validate live code signature"));
        assert!(!verifier.contains(
            "check_validity(live_code_validation_flags(), requirement)\n            .is_ok()"
        ));
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
