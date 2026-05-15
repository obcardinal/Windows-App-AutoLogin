use std::path::PathBuf;

const APP_DIR_NAME: &str = "WindowsAppAutoLogin";

#[cfg(not(target_os = "macos"))]
#[cfg_attr(target_os = "windows", allow(dead_code))]
pub(crate) fn cache_dir() -> anyhow::Result<PathBuf> {
    if let Some(cache_dir) = dirs::cache_dir() {
        return Ok(cache_dir.join(APP_DIR_NAME));
    }
    if let Some(home) = dirs::home_dir() {
        return Ok(home.join("Library").join("Caches").join(APP_DIR_NAME));
    }
    anyhow::bail!("unable to resolve a private cache directory")
}

pub(crate) fn runtime_dir() -> anyhow::Result<PathBuf> {
    Ok(config_dir()?.join("Runtime"))
}

pub(crate) fn config_dir() -> anyhow::Result<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        return Ok(canonical_home_dir()?
            .join("Library")
            .join("Application Support")
            .join(APP_DIR_NAME));
    }

    #[cfg(not(target_os = "macos"))]
    {
        if let Some(dir) = dirs::config_dir() {
            return Ok(dir.join(APP_DIR_NAME));
        }
        if let Some(home) = dirs::home_dir() {
            return Ok(home.join(".config").join(APP_DIR_NAME));
        }
        anyhow::bail!("unable to resolve a private config directory")
    }
}

#[cfg_attr(target_os = "windows", allow(dead_code))]
pub(crate) fn home_dir() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        canonical_home_dir().ok()
    }

    #[cfg(not(target_os = "macos"))]
    {
        dirs::home_dir()
    }
}

pub(crate) fn redacted_path(value: &str) -> String {
    let value = value.trim();
    if value.is_empty() {
        return String::new();
    }

    "[path]".to_string()
}

#[cfg(target_os = "macos")]
fn canonical_home_dir() -> anyhow::Result<PathBuf> {
    use std::ffi::CStr;
    use std::mem;
    use std::os::unix::ffi::OsStringExt;
    use std::ptr;

    unsafe {
        let uid = libc::geteuid();
        let buf_size = match libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) {
            n if n > 0 => n as usize,
            _ => 16 * 1024,
        };
        let mut buf = vec![0_u8; buf_size];
        let mut passwd: libc::passwd = mem::zeroed();
        let mut result = ptr::null_mut();
        let status = libc::getpwuid_r(
            uid,
            &mut passwd,
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut result,
        );
        if status != 0 || result.is_null() || passwd.pw_dir.is_null() {
            anyhow::bail!("unable to resolve canonical home directory for current user");
        }
        let bytes = CStr::from_ptr(passwd.pw_dir).to_bytes();
        if bytes.is_empty() {
            anyhow::bail!("canonical home directory for current user is empty");
        }
        Ok(PathBuf::from(std::ffi::OsString::from_vec(bytes.to_vec())))
    }
}

#[cfg(test)]
mod tests {
    use super::{config_dir, redacted_path, runtime_dir};

    #[test]
    fn redacted_path_omits_leaf_name() {
        let redacted = redacted_path("/Users/alice/customer-secret.db");

        assert_eq!(redacted, "[path]");
        assert!(!redacted.contains("customer-secret.db"));
        assert!(!redacted.contains("alice"));
    }

    #[test]
    fn runtime_dir_is_config_runtime_child() {
        assert_eq!(
            runtime_dir().unwrap(),
            config_dir().unwrap().join("Runtime")
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn runtime_dir_is_outside_macos_caches() {
        use std::ffi::OsStr;

        let runtime = runtime_dir().unwrap();

        assert!(!runtime
            .components()
            .any(|component| component.as_os_str() == OsStr::new("Caches")));
    }
}
