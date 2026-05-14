use std::path::Path;

#[cfg(target_os = "macos")]
pub(crate) fn strip_macos_acl(path: &Path) -> anyhow::Result<()> {
    let path = path_to_cstring(path)?;
    let empty_acl = MacosAcl::empty()?;
    let ret = unsafe { acl_set_link_np(path.as_ptr(), ACL_TYPE_EXTENDED, empty_acl.as_ptr()) };
    if ret == 0 {
        Ok(())
    } else {
        let error = std::io::Error::last_os_error();
        Err(anyhow::anyhow!(
            "failed to remove macOS ACL from private app data path: {error}"
        ))
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn path_has_macos_acl(path: &Path) -> anyhow::Result<bool> {
    let path = path_to_cstring(path)?;
    let acl = unsafe { acl_get_link_np(path.as_ptr(), ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOENT) {
            return Ok(false);
        }
        anyhow::bail!("failed to inspect macOS ACL on private app data path");
    }

    let acl = MacosAcl(acl);
    Ok(acl.has_entries())
}

#[cfg(target_os = "macos")]
pub(crate) fn strip_macos_acl_fd(file: &std::fs::File) -> anyhow::Result<()> {
    use std::os::fd::AsRawFd;

    let empty_acl = MacosAcl::empty()?;
    let ret = unsafe { acl_set_fd_np(file.as_raw_fd(), empty_acl.as_ptr(), ACL_TYPE_EXTENDED) };
    if ret == 0 {
        Ok(())
    } else {
        let error = std::io::Error::last_os_error();
        Err(anyhow::anyhow!(
            "failed to remove macOS ACL from private app data path: {error}"
        ))
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn file_has_macos_acl_fd(file: &std::fs::File) -> anyhow::Result<bool> {
    use std::os::fd::AsRawFd;

    let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOENT) {
            return Ok(false);
        }
        anyhow::bail!("failed to inspect macOS ACL on private app data path");
    }

    let acl = MacosAcl(acl);
    Ok(acl.has_entries())
}

#[cfg(target_os = "macos")]
fn path_to_cstring(path: &Path) -> anyhow::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;

    std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| anyhow::anyhow!("private app data path contains an interior NUL byte"))
}

#[cfg(target_os = "macos")]
struct MacosAcl(AclT);

#[cfg(target_os = "macos")]
impl MacosAcl {
    fn empty() -> anyhow::Result<Self> {
        let acl = unsafe { acl_init(0) };
        if acl.is_null() {
            anyhow::bail!("failed to allocate empty macOS ACL");
        }
        Ok(Self(acl))
    }

    fn as_ptr(&self) -> AclT {
        self.0
    }

    fn has_entries(&self) -> bool {
        let mut entry: AclEntryT = std::ptr::null_mut();
        let result = unsafe { acl_get_entry(self.0, ACL_FIRST_ENTRY, &mut entry) };
        result == 0 && !entry.is_null()
    }
}

#[cfg(target_os = "macos")]
impl Drop for MacosAcl {
    fn drop(&mut self) {
        let _ = unsafe { acl_free(self.0.cast()) };
    }
}

#[cfg(target_os = "macos")]
type AclT = *mut libc::c_void;

#[cfg(target_os = "macos")]
type AclEntryT = *mut libc::c_void;

#[cfg(target_os = "macos")]
const ACL_TYPE_EXTENDED: libc::c_int = 0x0000_0100;

#[cfg(target_os = "macos")]
const ACL_FIRST_ENTRY: libc::c_int = 0;

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn acl_init(count: libc::c_int) -> AclT;
    fn acl_free(obj_p: *mut libc::c_void) -> libc::c_int;
    fn acl_get_entry(acl: AclT, entry_id: libc::c_int, entry_p: *mut AclEntryT) -> libc::c_int;
    fn acl_get_fd_np(fd: libc::c_int, acl_type: libc::c_int) -> AclT;
    fn acl_get_link_np(path_p: *const libc::c_char, acl_type: libc::c_int) -> AclT;
    fn acl_set_fd_np(fd: libc::c_int, acl: AclT, acl_type: libc::c_int) -> libc::c_int;
    fn acl_set_link_np(
        path_p: *const libc::c_char,
        acl_type: libc::c_int,
        acl: AclT,
    ) -> libc::c_int;
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn strip_macos_acl(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn path_has_macos_acl(_path: &Path) -> anyhow::Result<bool> {
    Ok(false)
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn strip_macos_acl_fd(_file: &std::fs::File) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn file_has_macos_acl_fd(_file: &std::fs::File) -> anyhow::Result<bool> {
    Ok(false)
}
