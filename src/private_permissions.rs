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

#[cfg(target_os = "windows")]
pub(crate) fn secure_windows_private_dir(path: &Path) -> anyhow::Result<()> {
    secure_windows_private_path(path, WindowsPrivatePathKind::Directory)
}

#[cfg(target_os = "windows")]
pub(crate) fn secure_windows_private_file(path: &Path) -> anyhow::Result<()> {
    secure_windows_private_path(path, WindowsPrivatePathKind::File)
}

#[cfg(target_os = "windows")]
pub(crate) fn validate_windows_private_file_handle(file: &std::fs::File) -> anyhow::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::HANDLE;

    let handle = HANDLE(file.as_raw_handle());
    let info = windows_file_attribute_tag_info(handle)?;
    reject_windows_reparse_attributes(info.FileAttributes)?;
    if info.FileAttributes & windows_dir_attribute_mask() != 0 {
        anyhow::bail!("private app data path must be a regular file");
    }
    validate_windows_private_path_owner(handle)?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn secure_windows_private_path(path: &Path, kind: WindowsPrivatePathKind) -> anyhow::Result<()> {
    let handle = open_windows_private_path(path, kind)?;
    apply_windows_private_dacl(handle.0, kind)?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn open_windows_private_path(
    path: &Path,
    kind: WindowsPrivatePathKind,
) -> anyhow::Result<WindowsHandle> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, OPEN_EXISTING, READ_CONTROL, WRITE_DAC,
    };

    let mut wide = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    if wide[..wide.len().saturating_sub(1)].contains(&0) {
        anyhow::bail!("private app data path contains an interior NUL byte");
    }

    let flags = match kind {
        WindowsPrivatePathKind::Directory => {
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS
        }
        WindowsPrivatePathKind::File => FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAGS_AND_ATTRIBUTES(0),
    };
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_mut_ptr()),
            FILE_READ_ATTRIBUTES.0 | READ_CONTROL.0 | WRITE_DAC.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            flags,
            None,
        )
    }
    .map_err(|error| {
        anyhow::anyhow!(
            "failed to open private app data path for Windows security hardening: {error}"
        )
    })?;
    let handle = WindowsHandle(handle);

    let info = windows_file_attribute_tag_info(handle.0)?;
    reject_windows_reparse_attributes(info.FileAttributes)?;
    let is_dir = info.FileAttributes & windows_dir_attribute_mask() != 0;
    match (kind, is_dir) {
        (WindowsPrivatePathKind::Directory, true) | (WindowsPrivatePathKind::File, false) => {}
        (WindowsPrivatePathKind::Directory, false) => {
            anyhow::bail!("private app data path must be a directory");
        }
        (WindowsPrivatePathKind::File, true) => {
            anyhow::bail!("private app data path must be a regular file");
        }
    }
    validate_windows_private_path_owner(handle.0)?;

    Ok(handle)
}

#[cfg(target_os = "windows")]
fn apply_windows_private_dacl(
    handle: windows::Win32::Foundation::HANDLE,
    kind: WindowsPrivatePathKind,
) -> anyhow::Result<()> {
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SetSecurityInfo, SE_FILE_OBJECT,
    };
    use windows::Win32::Security::{
        GetSecurityDescriptorDacl, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR,
    };

    let sddl = windows_private_sddl(kind)?;
    let wide = sddl
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            windows::core::PCWSTR(wide.as_ptr()),
            1,
            &mut sd,
            None,
        )
    }
    .map_err(|error| {
        anyhow::anyhow!("failed to build private Windows security descriptor: {error}")
    })?;
    let sd = LocalSecurityDescriptor(sd);

    let mut dacl_present = windows::core::BOOL(0);
    let mut dacl_defaulted = windows::core::BOOL(0);
    let mut dacl = std::ptr::null_mut();
    unsafe { GetSecurityDescriptorDacl(sd.0, &mut dacl_present, &mut dacl, &mut dacl_defaulted) }
        .map_err(|error| {
        anyhow::anyhow!("failed to inspect private Windows security descriptor: {error}")
    })?;
    if !dacl_present.as_bool() || dacl.is_null() {
        anyhow::bail!("private Windows security descriptor has no DACL");
    }

    unsafe {
        SetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(dacl.cast_const()),
            None,
        )
        .ok()
    }
    .map_err(|error| anyhow::anyhow!("failed to apply private Windows DACL: {error}"))?;

    Ok(())
}

#[cfg(target_os = "windows")]
fn windows_private_sddl(kind: WindowsPrivatePathKind) -> anyhow::Result<String> {
    let user_sid = current_windows_user_sid_string()?;
    let inheritance = match kind {
        WindowsPrivatePathKind::Directory => "OICI",
        WindowsPrivatePathKind::File => "",
    };
    Ok(format!(
        "D:P(A;{inheritance};FA;;;SY)(A;{inheritance};FA;;;BA)(A;{inheritance};FA;;;{user_sid})"
    ))
}

#[cfg(target_os = "windows")]
pub(crate) fn current_windows_user_sid_string() -> anyhow::Result<String> {
    use windows::core::PWSTR;
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;

    let user_sid = current_windows_user_sid()?;

    let mut sid = PWSTR::null();
    unsafe { ConvertSidToStringSidW(user_sid.psid(), &mut sid) }
        .map_err(|error| anyhow::anyhow!("failed to stringify Windows user SID: {error}"))?;
    let sid = LocalWideString(sid);
    unsafe { sid.0.to_string() }.map_err(|_| anyhow::anyhow!("failed to decode Windows user SID"))
}

#[cfg(target_os = "windows")]
fn current_windows_user_sid() -> anyhow::Result<WindowsSid> {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = HANDLE::default();
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
        .map_err(|error| anyhow::anyhow!("failed to open Windows process token: {error}"))?;
    let token = WindowsHandle(token);

    let mut required = 0;
    let _ = unsafe { GetTokenInformation(token.0, TokenUser, None, 0, &mut required) };
    if required == 0 {
        anyhow::bail!("failed to query Windows token user size");
    }

    let mut buffer = vec![0u8; required as usize];
    unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            Some(buffer.as_mut_ptr().cast()),
            required,
            &mut required,
        )
    }
    .map_err(|error| anyhow::anyhow!("failed to query Windows token user: {error}"))?;

    let token_user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
    windows_copy_sid(token_user.User.Sid)
}

#[cfg(target_os = "windows")]
fn validate_windows_private_path_owner(
    handle: windows::Win32::Foundation::HANDLE,
) -> anyhow::Result<()> {
    if windows_private_path_owner_is_current_user(handle)? {
        Ok(())
    } else {
        anyhow::bail!("private app data path must be owned by the current user");
    }
}

#[cfg(target_os = "windows")]
fn windows_private_path_owner_is_current_user(
    handle: windows::Win32::Foundation::HANDLE,
) -> anyhow::Result<bool> {
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows::Win32::Security::{OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID};

    let mut owner = PSID::default();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            None,
            None,
            Some(&mut sd),
        )
    };
    if status != ERROR_SUCCESS || sd.is_invalid() || owner.is_invalid() {
        anyhow::bail!("failed to inspect private Windows path owner");
    }
    let _sd = LocalSecurityDescriptor(sd);

    windows_private_owner_sid_is_current_user(owner)
}

#[cfg(target_os = "windows")]
fn windows_private_owner_sid_is_current_user(
    owner: windows::Win32::Security::PSID,
) -> anyhow::Result<bool> {
    let current_user = current_windows_user_sid()?;
    Ok(windows_sids_equal(owner, current_user.psid()))
}

#[cfg(target_os = "windows")]
fn windows_sids_equal(
    left: windows::Win32::Security::PSID,
    right: windows::Win32::Security::PSID,
) -> bool {
    if left.is_invalid() || right.is_invalid() {
        return false;
    }
    unsafe { windows::Win32::Security::EqualSid(left, right).is_ok() }
}

#[cfg(target_os = "windows")]
fn windows_copy_sid(sid: windows::Win32::Security::PSID) -> anyhow::Result<WindowsSid> {
    use windows::Win32::Security::{CopySid, GetLengthSid, PSID};

    if sid.is_invalid() {
        anyhow::bail!("Windows SID is invalid");
    }
    let size = unsafe { GetLengthSid(sid) };
    if size == 0 {
        anyhow::bail!("Windows SID length is invalid");
    }
    let mut buffer = vec![0u8; size as usize];
    unsafe { CopySid(size, PSID(buffer.as_mut_ptr().cast()), sid) }
        .map_err(|error| anyhow::anyhow!("failed to copy Windows SID: {error}"))?;
    Ok(WindowsSid { buffer })
}

#[cfg(target_os = "windows")]
fn windows_file_attribute_tag_info(
    handle: windows::Win32::Foundation::HANDLE,
) -> anyhow::Result<windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_TAG_INFO> {
    use windows::Win32::Storage::FileSystem::{
        FileAttributeTagInfo, GetFileInformationByHandleEx, FILE_ATTRIBUTE_TAG_INFO,
    };

    let mut info = FILE_ATTRIBUTE_TAG_INFO::default();
    unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileAttributeTagInfo,
            std::ptr::addr_of_mut!(info).cast(),
            std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    }
    .map_err(|error| anyhow::anyhow!("failed to inspect private Windows path: {error}"))?;
    Ok(info)
}

#[cfg(target_os = "windows")]
fn reject_windows_reparse_attributes(attributes: u32) -> anyhow::Result<()> {
    use windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    if attributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        anyhow::bail!("private app data path must not be a Windows reparse point");
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn windows_dir_attribute_mask() -> u32 {
    windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_DIRECTORY.0
}

#[cfg(target_os = "windows")]
#[derive(Clone, Copy)]
enum WindowsPrivatePathKind {
    Directory,
    File,
}

#[cfg(target_os = "windows")]
struct WindowsHandle(windows::Win32::Foundation::HANDLE);

#[cfg(target_os = "windows")]
impl Drop for WindowsHandle {
    fn drop(&mut self) {
        let _ = unsafe { windows::Win32::Foundation::CloseHandle(self.0) };
    }
}

#[cfg(target_os = "windows")]
struct LocalSecurityDescriptor(windows::Win32::Security::PSECURITY_DESCRIPTOR);

#[cfg(target_os = "windows")]
impl Drop for LocalSecurityDescriptor {
    fn drop(&mut self) {
        let _ = unsafe {
            windows::Win32::Foundation::LocalFree(Some(windows::Win32::Foundation::HLOCAL(
                self.0 .0,
            )))
        };
    }
}

#[cfg(target_os = "windows")]
struct LocalWideString(windows::core::PWSTR);

#[cfg(target_os = "windows")]
impl Drop for LocalWideString {
    fn drop(&mut self) {
        let _ = unsafe {
            windows::Win32::Foundation::LocalFree(Some(windows::Win32::Foundation::HLOCAL(
                self.0.as_ptr().cast(),
            )))
        };
    }
}

#[cfg(target_os = "windows")]
struct WindowsSid {
    buffer: Vec<u8>,
}

#[cfg(target_os = "windows")]
impl WindowsSid {
    fn psid(&self) -> windows::Win32::Security::PSID {
        windows::Win32::Security::PSID(self.buffer.as_ptr().cast_mut().cast())
    }
}

#[cfg(all(test, target_os = "windows"))]
mod windows_tests {
    use super::{
        current_windows_user_sid, windows_copy_sid, windows_private_owner_sid_is_current_user,
    };
    use windows::Win32::Security::{CreateWellKnownSid, WinWorldSid, PSID, SECURITY_MAX_SID_SIZE};

    fn well_known_world_sid() -> super::WindowsSid {
        let mut buffer = vec![0u8; SECURITY_MAX_SID_SIZE as usize];
        let mut size = buffer.len() as u32;
        unsafe {
            CreateWellKnownSid(
                WinWorldSid,
                None,
                Some(PSID(buffer.as_mut_ptr().cast())),
                &mut size,
            )
        }
        .expect("world SID should be created");
        buffer.truncate(size as usize);
        windows_copy_sid(PSID(buffer.as_mut_ptr().cast())).unwrap()
    }

    #[test]
    fn windows_private_owner_sid_must_be_current_user() {
        let current = current_windows_user_sid().unwrap();
        assert!(windows_private_owner_sid_is_current_user(current.psid()).unwrap());

        let world = well_known_world_sid();
        assert!(!windows_private_owner_sid_is_current_user(world.psid()).unwrap());
    }
}

#[cfg(not(target_os = "macos"))]
#[allow(dead_code)]
pub(crate) fn strip_macos_acl(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(not(target_os = "macos"))]
#[allow(dead_code)]
pub(crate) fn path_has_macos_acl(_path: &Path) -> anyhow::Result<bool> {
    Ok(false)
}

#[cfg(not(target_os = "macos"))]
#[allow(dead_code)]
pub(crate) fn strip_macos_acl_fd(_file: &std::fs::File) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(not(target_os = "macos"))]
#[allow(dead_code)]
pub(crate) fn file_has_macos_acl_fd(_file: &std::fs::File) -> anyhow::Result<bool> {
    Ok(false)
}
