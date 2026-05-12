use std::path::{Path, PathBuf};

pub(crate) struct SingleInstanceGuard {
    lock_dir: PathBuf,
}

impl SingleInstanceGuard {
    pub(crate) fn acquire() -> anyhow::Result<Self> {
        let lock_dir = lock_root()?.join("WindowsAppAutoLogin.lock");
        match create_lock(&lock_dir) {
            Ok(()) => Ok(Self { lock_dir }),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if existing_process_is_alive(&lock_dir) || lock_dir_looks_fresh(&lock_dir) {
                    anyhow::bail!("Windows App AutoLogin is already running");
                }

                std::fs::remove_dir_all(&lock_dir).ok();
                create_lock(&lock_dir)?;
                Ok(Self { lock_dir })
            }
            Err(e) => Err(e.into()),
        }
    }
}

impl Drop for SingleInstanceGuard {
    fn drop(&mut self) {
        if lock_pid(&self.lock_dir) == Some(std::process::id()) {
            std::fs::remove_dir_all(&self.lock_dir).ok();
        }
    }
}

fn create_lock(lock_dir: &Path) -> std::io::Result<()> {
    if let Some(parent) = lock_dir.parent() {
        std::fs::create_dir_all(parent)?;
        secure_dir_permissions(parent)?;
    }
    std::fs::create_dir(lock_dir)?;
    secure_dir_permissions(lock_dir)?;
    write_private_file(
        &lock_dir.join("pid"),
        std::process::id().to_string().as_bytes(),
    )?;
    Ok(())
}

fn lock_root() -> anyhow::Result<PathBuf> {
    if let Some(cache_dir) = dirs::cache_dir() {
        return Ok(cache_dir.join("WindowsAppAutoLogin"));
    }
    if let Some(home) = dirs::home_dir() {
        return Ok(home
            .join("Library")
            .join("Caches")
            .join("WindowsAppAutoLogin"));
    }
    anyhow::bail!("unable to resolve a private lock directory")
}

fn existing_process_is_alive(lock_dir: &Path) -> bool {
    let Some(pid) = lock_pid(lock_dir) else {
        return false;
    };

    pid == std::process::id() || process_looks_like_this_app(pid)
}

fn lock_dir_looks_fresh(lock_dir: &Path) -> bool {
    const STARTUP_RACE_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

    lock_pid(lock_dir).is_none()
        && std::fs::metadata(lock_dir)
            .and_then(|metadata| metadata.modified())
            .ok()
            .and_then(|modified| modified.elapsed().ok())
            .is_some_and(|age| age <= STARTUP_RACE_GRACE)
}

#[cfg(unix)]
fn process_looks_like_this_app(pid: u32) -> bool {
    let Ok(output) = std::process::Command::new("/bin/ps")
        .args(["-p", &pid.to_string(), "-o", "command="])
        .output()
    else {
        return false;
    };
    if !output.status.success() {
        return false;
    }

    let command = String::from_utf8_lossy(&output.stdout);
    let current_exe = std::env::current_exe()
        .ok()
        .and_then(|path| path.canonicalize().ok())
        .map(|path| path.to_string_lossy().to_string());

    current_exe.is_some_and(|path| {
        let command = command.trim();
        command == path || command.starts_with(&(path + " "))
    })
}

#[cfg(not(unix))]
fn process_looks_like_this_app(_pid: u32) -> bool {
    false
}

fn lock_pid(lock_dir: &Path) -> Option<u32> {
    std::fs::read_to_string(lock_dir.join("pid"))
        .ok()
        .and_then(|pid| pid.trim().parse::<u32>().ok())
}

#[cfg(unix)]
fn secure_dir_permissions(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = std::fs::metadata(path)?.permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(path, permissions)
}

#[cfg(not(unix))]
fn secure_dir_permissions(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

fn write_private_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(bytes)?;
    }

    #[cfg(not(unix))]
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        file.write_all(bytes)?;
    }

    Ok(())
}
