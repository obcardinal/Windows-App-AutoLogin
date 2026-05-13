#[cfg(target_os = "macos")]
use std::collections::HashMap;
#[cfg(target_os = "macos")]
use std::path::{Path, PathBuf};
#[cfg(target_os = "macos")]
use std::process::Command;
#[cfg(target_os = "macos")]
use std::sync::{Mutex, OnceLock};
#[cfg(target_os = "macos")]
use std::time::{Duration, Instant};

#[cfg(target_os = "macos")]
const MICROSOFT_REMOTE_DESKTOP_BUNDLE_ID: &str = "com.microsoft.rdc.macos";
#[cfg(target_os = "macos")]
const MICROSOFT_TEAM_ID: &str = "UBF8T346G9";
#[cfg(target_os = "macos")]
const SIGNATURE_CACHE_TTL: Duration = Duration::from_secs(10);
#[cfg(target_os = "macos")]
const PROC_ALL_PIDS: u32 = 1;

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
pub(crate) struct TrustedProcessInfo {
    pub(crate) pid: i32,
    pub(crate) bundle_id: String,
    pub(crate) bundle_path: PathBuf,
    pub(crate) team_id: &'static str,
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone)]
struct SignatureCacheEntry {
    verified_at: Instant,
}

#[cfg(target_os = "macos")]
static SIGNATURE_CACHE: OnceLock<Mutex<HashMap<String, SignatureCacheEntry>>> = OnceLock::new();

#[cfg(target_os = "macos")]
pub(crate) fn trusted_process_ids(app_name: &str) -> anyhow::Result<Vec<i32>> {
    let processes = enumerate_processes(app_name)?;
    trusted_process_ids_from_identities(app_name, &processes, verify_signed_bundle)
}

#[cfg(target_os = "macos")]
pub(crate) fn trusted_process_infos(app_name: &str) -> anyhow::Result<Vec<TrustedProcessInfo>> {
    let processes = enumerate_processes(app_name)?;
    trusted_process_infos_from_identities(app_name, &processes, verify_signed_bundle)
}

#[cfg(target_os = "macos")]
fn trusted_process_ids_from_identities(
    app_name: &str,
    processes: &[ProcessIdentity],
    mut verify_bundle: impl FnMut(&Path, TrustedIdentity) -> anyhow::Result<bool>,
) -> anyhow::Result<Vec<i32>> {
    Ok(
        trusted_process_infos_from_identities(app_name, processes, |path, identity| {
            verify_bundle(path, identity)
        })?
        .into_iter()
        .map(|process| process.pid)
        .collect(),
    )
}

#[cfg(target_os = "macos")]
fn trusted_process_infos_from_identities(
    app_name: &str,
    processes: &[ProcessIdentity],
    mut verify_bundle: impl FnMut(&Path, TrustedIdentity) -> anyhow::Result<bool>,
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
        if verify_bundle(&process.bundle_path, identity)? {
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
pub(crate) fn trusted_bundle_path(app_name: &str) -> anyhow::Result<Option<PathBuf>> {
    let Some(identity) = trusted_identity(app_name) else {
        anyhow::bail!("unsupported app identity for secure automation: {app_name}");
    };

    for candidate in trusted_bundle_candidates(app_name) {
        if candidate.exists() && verify_signed_bundle(&candidate, identity)? {
            return Ok(Some(candidate));
        }
    }

    Ok(None)
}

#[cfg(target_os = "macos")]
pub(crate) fn applescript_pid_list_literal(pids: &[i32]) -> String {
    let values = pids
        .iter()
        .map(|pid| format!("\"{}\"", pid))
        .collect::<Vec<_>>()
        .join(", ");
    format!("{{{values}}}")
}

#[cfg(target_os = "macos")]
#[allow(dead_code)]
pub(crate) fn applescript_string_literal(value: &str) -> String {
    let escaped = value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace(['\r', '\n'], " ");
    format!("\"{}\"", escaped)
}

#[cfg(target_os = "macos")]
fn trusted_identity(app_name: &str) -> Option<TrustedIdentity> {
    match app_name.trim() {
        "Windows App" | "Microsoft Remote Desktop" => Some(TrustedIdentity {
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
        "Microsoft Remote Desktop" => {
            vec![PathBuf::from("/Applications/Microsoft Remote Desktop.app")]
        }
        _ => Vec::new(),
    }
}

#[cfg(target_os = "macos")]
fn bundle_path_is_trusted_location(path: &Path, app_name: &str) -> bool {
    let Ok(canonical_path) = path.canonicalize() else {
        return false;
    };

    trusted_bundle_candidates(app_name)
        .into_iter()
        .filter_map(|candidate| candidate.canonicalize().ok())
        .any(|candidate| candidate == canonical_path)
}

#[cfg(target_os = "macos")]
fn enumerate_processes(app_name: &str) -> anyhow::Result<Vec<ProcessIdentity>> {
    let Some(identity) = trusted_identity(app_name) else {
        anyhow::bail!("unsupported app identity for secure automation: {app_name}");
    };

    let trusted_candidates = trusted_bundle_candidates(app_name)
        .into_iter()
        .filter_map(|path| path.canonicalize().ok())
        .collect::<Vec<_>>();
    if trusted_candidates.is_empty() {
        return Ok(Vec::new());
    }

    Ok(native_process_ids()
        .into_iter()
        .filter_map(|pid| {
            let executable_path = process_executable_path(pid)?;
            let bundle_path = containing_app_bundle(&executable_path)?;
            let canonical_bundle = bundle_path.canonicalize().ok()?;
            trusted_candidates
                .iter()
                .any(|candidate| *candidate == canonical_bundle)
                .then(|| ProcessIdentity {
                    pid,
                    bundle_id: identity.bundle_id.to_string(),
                    bundle_path: canonical_bundle,
                })
        })
        .collect())
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

    let end = buffer
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(len as usize);
    let path = String::from_utf8_lossy(&buffer[..end]).trim().to_string();
    (!path.is_empty()).then(|| PathBuf::from(path))
}

#[cfg(target_os = "macos")]
fn containing_app_bundle(path: &Path) -> Option<PathBuf> {
    path.ancestors()
        .find(|candidate| candidate.extension().is_some_and(|ext| ext == "app"))
        .map(Path::to_path_buf)
}

#[cfg(target_os = "macos")]
fn verify_signed_bundle(path: &Path, identity: TrustedIdentity) -> anyhow::Result<bool> {
    let canonical_path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let cache_key = signature_cache_key(&canonical_path, identity)?;

    let cache = SIGNATURE_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(cache) = cache.lock() {
        if let Some(entry) = cache.get(&cache_key) {
            if entry.verified_at.elapsed() < SIGNATURE_CACHE_TTL {
                return Ok(true);
            }
        }
    }

    let requirement = format!(
        "=designated => anchor apple generic and certificate leaf[subject.OU] = {} and identifier \"{}\"",
        identity.team_id, identity.bundle_id
    );
    let output = run_command_with_timeout(
        Command::new("/usr/bin/codesign")
            .args(["--verify", "--strict", "--requirement", &requirement])
            .arg(&canonical_path),
        Duration::from_secs(5),
    )?;
    let trusted = output.status.success();

    if trusted {
        if let Ok(mut cache) = cache.lock() {
            cache.insert(
                cache_key,
                SignatureCacheEntry {
                    verified_at: Instant::now(),
                },
            );
        }
    }

    Ok(trusted)
}

#[cfg(target_os = "macos")]
fn signature_cache_key(path: &Path, identity: TrustedIdentity) -> anyhow::Result<String> {
    let mut parts = vec![metadata_cache_component("bundle", path)?];
    for relative in [
        "Contents/Info.plist",
        "Contents/_CodeSignature/CodeResources",
    ] {
        let child = path.join(relative);
        if child.exists() {
            parts.push(metadata_cache_component(relative, &child)?);
        }
    }

    let executable_dir = path.join("Contents/MacOS");
    if let Ok(entries) = std::fs::read_dir(executable_dir) {
        let mut executable_paths = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.is_file())
            .collect::<Vec<_>>();
        executable_paths.sort();
        for executable_path in executable_paths {
            parts.push(metadata_cache_component(
                "Contents/MacOS",
                &executable_path,
            )?);
        }
    }

    Ok(format!(
        "{}|team:{}|bundle:{}|{}",
        path.display(),
        identity.team_id,
        identity.bundle_id,
        parts.join("|")
    ))
}

#[cfg(target_os = "macos")]
fn metadata_cache_component(label: &str, path: &Path) -> anyhow::Result<String> {
    let metadata = std::fs::metadata(path)?;
    let modified_nanos = metadata
        .modified()
        .ok()
        .and_then(|modified| modified.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(format!(
            "{}:{}|dev:{}|ino:{}|len:{}|mtime:{}",
            label,
            path.display(),
            metadata.dev(),
            metadata.ino(),
            metadata.len(),
            modified_nanos
        ))
    }

    #[cfg(not(unix))]
    {
        Ok(format!(
            "{}:{}|len:{}|mtime:{}",
            label,
            path.display(),
            metadata.len(),
            modified_nanos
        ))
    }
}

#[cfg(target_os = "macos")]
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
        signature_cache_key, trusted_process_ids_from_identities, ProcessIdentity, TrustedIdentity,
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

        let trusted =
            trusted_process_ids_from_identities("Windows App", &processes, |_path, _identity| {
                verifier_called = true;
                Ok(true)
            })
            .unwrap();

        assert!(trusted.is_empty());
        assert!(!verifier_called);
    }

    #[test]
    fn unsupported_app_identity_is_rejected() {
        let error =
            trusted_process_ids_from_identities("Lookalike App", &[], |_path, _identity| Ok(true))
                .unwrap_err();

        assert_eq!(
            error.to_string(),
            "unsupported app identity for secure automation: Lookalike App"
        );
    }

    #[test]
    fn codesign_verifier_failure_rejects_process() {
        let processes = vec![ProcessIdentity {
            pid: 4242,
            bundle_id: "com.microsoft.rdc.macos".to_string(),
            bundle_path: PathBuf::from("/Applications/Windows App.app"),
        }];

        let trusted =
            trusted_process_ids_from_identities("Windows App", &processes, |_path, _identity| {
                Ok(false)
            })
            .unwrap();

        assert!(trusted.is_empty());
    }

    #[test]
    fn signature_cache_key_includes_nested_executable_metadata() {
        let bundle_path = unique_temp_bundle_path();
        let macos_dir = bundle_path.join("Contents/MacOS");
        std::fs::create_dir_all(&macos_dir).unwrap();
        std::fs::create_dir_all(bundle_path.join("Contents/_CodeSignature")).unwrap();
        std::fs::write(bundle_path.join("Contents/Info.plist"), b"plist").unwrap();
        std::fs::write(
            bundle_path.join("Contents/_CodeSignature/CodeResources"),
            b"codesign",
        )
        .unwrap();
        let executable = macos_dir.join("Windows App");
        std::fs::write(&executable, b"one").unwrap();

        let identity = TrustedIdentity {
            bundle_id: "com.microsoft.rdc.macos",
            team_id: "UBF8T346G9",
        };
        let first = signature_cache_key(&bundle_path, identity).unwrap();

        std::fs::write(&executable, b"changed executable").unwrap();
        let second = signature_cache_key(&bundle_path, identity).unwrap();

        assert_ne!(first, second);
        let _ = std::fs::remove_dir_all(bundle_path);
    }

    fn unique_temp_bundle_path() -> PathBuf {
        let unique = format!(
            "windows-app-autologin-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        std::env::temp_dir().join(unique).join("Windows App.app")
    }
}
