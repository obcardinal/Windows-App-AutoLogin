//! Install the pinned Node.js tools privately when this Mac has no usable runtime.
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

// SHA-256 values published by nodejs.org for this exact LTS release.
const VERSION: &str = "24.22.3";
#[cfg(target_arch = "aarch64")]
const ARCH: &str = "arm64";
#[cfg(target_arch = "aarch64")]
const ARCHIVE_SHA256: &str = "ff6e17d4874b76d272212b908cc020d6e815fba5a6c7eaaa06add725840307fd";
#[cfg(target_arch = "x86_64")]
const ARCH: &str = "x64";
#[cfg(target_arch = "x86_64")]
const ARCHIVE_SHA256: &str = "977614af0504c81045e7fd85596dbca0e5f951b96681516dadafedcca8c447f7";

const CANCELLED: &str = "Automation setup cancelled.";
const DOWNLOAD_FAILED: &str =
    "Couldn’t download the helper tools from nodejs.org. Check your internet connection and retry.";
const INSTALL_FAILED: &str = "Couldn’t install the helper tools in AutoLogin’s private folder. Check available disk space and retry.";

fn tools_root() -> anyhow::Result<PathBuf> {
    Ok(crate::user_paths::config_dir()?
        .join("iphone-automation")
        .join("toolchains"))
}

fn distribution() -> String {
    format!("node-v{VERSION}-darwin-{ARCH}")
}

fn private_directory(path: &Path) -> anyhow::Result<()> {
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => crate::private_permissions::strip_macos_acl(path)?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = fs::symlink_metadata(path)?;
    anyhow::ensure!(
        metadata.is_dir()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0
            && !crate::private_permissions::path_has_macos_acl(path)?,
        "private helper directory required"
    );
    Ok(())
}

fn node_in(directory: &Path) -> Option<PathBuf> {
    let node = directory.join("bin/node");
    let metadata = fs::symlink_metadata(&node).ok()?;
    (metadata.is_file()
        && metadata.uid() == unsafe { libc::geteuid() }
        && metadata.mode() & 0o022 == 0
        && metadata.mode() & 0o100 != 0
        && directory.join("bin/npm").is_file()
        && directory
            .join("lib/node_modules/npm/bin/npm-cli.js")
            .is_file())
    .then_some(node)
}

pub(crate) fn cached_node() -> Option<PathBuf> {
    let root = tools_root().ok()?;
    let metadata = fs::symlink_metadata(&root).ok()?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return None;
    }
    let directory = root.join(distribution());
    let metadata = fs::symlink_metadata(&directory).ok()?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o022 != 0
    {
        return None;
    }
    node_in(&directory)
}

fn run(
    command: &mut Command,
    cancelled: &AtomicBool,
    timeout: Duration,
    failure: &str,
) -> Result<(), String> {
    if cancelled.load(Ordering::Relaxed) {
        return Err(CANCELLED.into());
    }
    let mut child = command
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| failure.to_owned())?;
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return if status.success() {
                    Ok(())
                } else {
                    Err(failure.into())
                }
            }
            Ok(None) if !cancelled.load(Ordering::Relaxed) && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(if cancelled.load(Ordering::Relaxed) {
                    CANCELLED
                } else {
                    failure
                }
                .into());
            }
        }
    }
}

fn verify_archive(path: &Path, expected: &str, cancelled: &AtomicBool) -> Result<(), String> {
    let mut archive = File::open(path).map_err(|_| DOWNLOAD_FAILED.to_owned())?;
    let size = archive
        .metadata()
        .map_err(|_| DOWNLOAD_FAILED.to_owned())?
        .len();
    if size == 0 || size > 100 * 1024 * 1024 {
        return Err(DOWNLOAD_FAILED.into());
    }
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        if cancelled.load(Ordering::Relaxed) {
            return Err(CANCELLED.into());
        }
        let count = archive
            .read(&mut buffer)
            .map_err(|_| DOWNLOAD_FAILED.to_owned())?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    if format!("{:x}", digest.finalize()) != expected {
        return Err(
            "The helper tools download failed verification. Retry to download a fresh copy.".into(),
        );
    }
    Ok(())
}

struct Staging(PathBuf);
impl Drop for Staging {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub(crate) fn install(cancelled: &AtomicBool) -> Result<PathBuf, String> {
    // The caller already rejected unavailable or unusable installed runtimes.
    // A fresh install also repairs a damaged cached copy.
    let root = tools_root().map_err(|_| INSTALL_FAILED.to_owned())?;
    private_directory(root.parent().ok_or(INSTALL_FAILED)?)
        .map_err(|_| INSTALL_FAILED.to_owned())?;
    private_directory(&root).map_err(|_| INSTALL_FAILED.to_owned())?;
    let staging = Staging(root.join(format!(".install-{}", uuid::Uuid::new_v4())));
    private_directory(&staging.0).map_err(|_| INSTALL_FAILED.to_owned())?;
    let archive = staging.0.join("node.tar.gz");
    let name = distribution();
    let url = format!("https://nodejs.org/dist/v{VERSION}/{name}.tar.gz");
    run(
        Command::new("/usr/bin/curl")
            .args([
                "-q",
                "--fail",
                "--silent",
                "--proto",
                "=https",
                "--connect-timeout",
                "10",
                "--max-time",
                "180",
                "--max-filesize",
                "104857600",
                "--output",
            ])
            .arg(&archive)
            .arg(url),
        cancelled,
        Duration::from_secs(185),
        DOWNLOAD_FAILED,
    )?;
    verify_archive(&archive, ARCHIVE_SHA256, cancelled)?;
    // The complete archive is pinned before any of its paths are extracted.
    run(
        Command::new("/usr/bin/tar")
            .arg("-xzf")
            .arg(&archive)
            .arg("-C")
            .arg(&staging.0),
        cancelled,
        Duration::from_secs(60),
        INSTALL_FAILED,
    )?;
    let extracted = staging.0.join(&name);
    node_in(&extracted).ok_or(INSTALL_FAILED)?;
    if cancelled.load(Ordering::Relaxed) {
        return Err(CANCELLED.into());
    }
    let destination = root.join(name);
    if destination.exists() {
        let metadata = fs::symlink_metadata(&destination).map_err(|_| INSTALL_FAILED.to_owned())?;
        if !metadata.is_dir() || metadata.uid() != unsafe { libc::geteuid() } {
            return Err(INSTALL_FAILED.into());
        }
        fs::remove_dir_all(&destination).map_err(|_| INSTALL_FAILED.to_owned())?;
    }
    fs::rename(extracted, &destination).map_err(|_| INSTALL_FAILED.to_owned())?;
    node_in(&destination).ok_or_else(|| INSTALL_FAILED.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_corrupt_or_cancelled_downloads_before_extraction() {
        let path = std::env::temp_dir().join(format!("waal-node-{}", uuid::Uuid::new_v4()));
        fs::write(&path, b"fixture").unwrap();
        let digest = format!("{:x}", Sha256::digest(b"fixture"));
        assert!(verify_archive(&path, &digest, &AtomicBool::new(false)).is_ok());
        assert!(verify_archive(&path, ARCHIVE_SHA256, &AtomicBool::new(false)).is_err());
        assert_eq!(
            verify_archive(&path, &digest, &AtomicBool::new(true)).unwrap_err(),
            CANCELLED
        );
        fs::remove_file(path).unwrap();
    }
}
