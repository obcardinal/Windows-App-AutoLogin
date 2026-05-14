#[cfg(target_os = "macos")]
use crate::macos_identity;
#[cfg(target_os = "macos")]
use std::sync::OnceLock;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AccessibilityStatus {
    pub(crate) trusted: bool,
    pub(crate) raw_trusted: bool,
    pub(crate) identity_trusted: bool,
    pub(crate) current_process_path: String,
    pub(crate) app_bundle_path: String,
}

pub(crate) fn accessibility_status() -> AccessibilityStatus {
    let current_process_path = std::env::current_exe()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let raw_trusted = raw_accessibility_is_trusted();
    let identity_trusted = current_app_identity_is_trusted();
    AccessibilityStatus {
        trusted: raw_trusted && identity_trusted,
        raw_trusted,
        identity_trusted,
        app_bundle_path: app_bundle_path_for_process(&current_process_path).unwrap_or_default(),
        current_process_path,
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn accessibility_is_trusted() -> bool {
    raw_accessibility_is_trusted() && current_app_identity_is_trusted()
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn accessibility_is_trusted() -> bool {
    true
}

#[cfg(target_os = "macos")]
fn raw_accessibility_is_trusted() -> bool {
    unsafe { AXIsProcessTrusted() != 0 }
}

#[cfg(not(target_os = "macos"))]
fn raw_accessibility_is_trusted() -> bool {
    true
}

#[cfg(target_os = "macos")]
static CURRENT_APP_IDENTITY_TRUSTED: OnceLock<bool> = OnceLock::new();

#[cfg(target_os = "macos")]
pub(crate) fn current_app_identity_is_trusted() -> bool {
    *CURRENT_APP_IDENTITY_TRUSTED.get_or_init(current_app_identity_is_trusted_uncached)
}

#[cfg(target_os = "macos")]
fn current_app_identity_is_trusted_uncached() -> bool {
    let Ok(exe_path) = std::env::current_exe() else {
        return false;
    };
    if crate::macos_identity::path_has_symlink_component(&exe_path) {
        return false;
    }
    let Some(bundle_path) = containing_app_bundle(&exe_path) else {
        return false;
    };
    if crate::macos_identity::path_has_symlink_component(&bundle_path) {
        return false;
    }
    app_bundle_identity_is_trusted(&bundle_path)
}

#[cfg(target_os = "macos")]
pub(crate) fn trusted_app_bundle_identity_is_trusted(bundle_path: &std::path::Path) -> bool {
    app_bundle_identity_is_trusted(bundle_path)
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn current_app_identity_is_trusted() -> bool {
    true
}

#[cfg(target_os = "macos")]
fn app_bundle_identity_is_trusted(bundle_path: &std::path::Path) -> bool {
    let Ok(bundle_path) = bundle_path.canonicalize() else {
        return false;
    };
    if crate::macos_identity::path_has_symlink_component(&bundle_path) {
        return false;
    }
    if bundle_identifier(&bundle_path).as_deref() != Some(crate::app_identity::macos_bundle_id()) {
        return false;
    }

    if crate::app_identity::macos_development_identity() {
        return development_app_bundle_identity_is_trusted(&bundle_path);
    }

    bundle_path == std::path::Path::new(crate::app_identity::TRUSTED_MACOS_BUNDLE_PATH)
        && app_bundle_signature_is_trusted(&bundle_path)
}

#[cfg(target_os = "macos")]
fn development_app_bundle_identity_is_trusted(bundle_path: &std::path::Path) -> bool {
    if !development_app_bundle_path_is_trusted(bundle_path) {
        return false;
    }
    crate::macos_identity::static_code_path_has_valid_internal_signature(bundle_path)
}

#[cfg(target_os = "macos")]
fn development_app_bundle_path_is_trusted(bundle_path: &std::path::Path) -> bool {
    [
        crate::app_identity::TRUSTED_MACOS_BUNDLE_PATH,
        crate::app_identity::DEVELOPMENT_MACOS_BUNDLE_PATH,
    ]
    .into_iter()
    .filter_map(|path| std::path::Path::new(path).canonicalize().ok())
    .any(|candidate| candidate == bundle_path)
}

#[cfg(target_os = "macos")]
fn app_bundle_signature_is_trusted(bundle_path: &std::path::Path) -> bool {
    let Some(team_id) = crate::app_identity::macos_team_id()
        .filter(|team_id| macos_identity::valid_team_id(team_id))
    else {
        return false;
    };

    macos_identity::verify_bundle_designated_requirement(
        bundle_path,
        crate::app_identity::macos_bundle_id(),
        team_id,
    )
    .unwrap_or(false)
}

#[cfg(target_os = "macos")]
fn bundle_identifier(bundle_path: &std::path::Path) -> Option<String> {
    let output = std::process::Command::new("/usr/libexec/PlistBuddy")
        .args(["-c", "Print :CFBundleIdentifier"])
        .arg(bundle_path.join("Contents/Info.plist"))
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
        .filter(|value| !value.is_empty())
}

#[cfg(target_os = "macos")]
pub(crate) fn request_accessibility_access_prompt() -> bool {
    unsafe {
        let keys = [kAXTrustedCheckOptionPrompt];
        let values = [kCFBooleanTrue];
        let options = CFDictionaryCreate(
            std::ptr::null(),
            keys.as_ptr(),
            values.as_ptr(),
            1,
            std::ptr::null(),
            std::ptr::null(),
        );
        if options.is_null() {
            return accessibility_is_trusted();
        }
        let trusted = AXIsProcessTrustedWithOptions(options) != 0;
        CFRelease(options);
        trusted && current_app_identity_is_trusted()
    }
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn request_accessibility_access_prompt() -> bool {
    true
}

pub(crate) fn open_accessibility_settings() -> anyhow::Result<()> {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("/usr/bin/open")
            .arg("x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility")
            .status()?;
    }
    Ok(())
}

fn app_bundle_path_for_process(process_path: &str) -> Option<String> {
    containing_app_bundle(std::path::Path::new(process_path)).map(|path| path.display().to_string())
}

fn containing_app_bundle(process_path: &std::path::Path) -> Option<std::path::PathBuf> {
    process_path
        .ancestors()
        .find(|path| path.extension().is_some_and(|ext| ext == "app"))
        .map(std::path::Path::to_path_buf)
}

#[cfg(target_os = "macos")]
#[link(name = "ApplicationServices", kind = "framework")]
unsafe extern "C" {
    fn AXIsProcessTrusted() -> u8;
    static kAXTrustedCheckOptionPrompt: *const std::ffi::c_void;
    fn AXIsProcessTrustedWithOptions(options: *const std::ffi::c_void) -> u8;
}

#[cfg(target_os = "macos")]
#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    static kCFBooleanTrue: *const std::ffi::c_void;
    fn CFDictionaryCreate(
        allocator: *const std::ffi::c_void,
        keys: *const *const std::ffi::c_void,
        values: *const *const std::ffi::c_void,
        num_values: isize,
        key_callbacks: *const std::ffi::c_void,
        value_callbacks: *const std::ffi::c_void,
    ) -> *const std::ffi::c_void;
    fn CFRelease(cf: *const std::ffi::c_void);
}

#[cfg(test)]
mod accessibility_tests {
    use super::app_bundle_path_for_process;

    #[test]
    fn app_bundle_path_is_derived_from_bundled_executable() {
        let path = "/tmp/WindowsAppAutoLogin.app/Contents/MacOS/windows-app-autologin";

        assert_eq!(
            app_bundle_path_for_process(path).as_deref(),
            Some("/tmp/WindowsAppAutoLogin.app")
        );
    }

    #[test]
    fn app_bundle_path_is_empty_for_raw_debug_binary() {
        let path = "/tmp/project/target/debug/windows-app-autologin";

        assert_eq!(app_bundle_path_for_process(path), None);
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::app_bundle_signature_is_trusted;

    #[test]
    fn own_app_signature_requires_configured_valid_team_id() {
        assert!(!app_bundle_signature_is_trusted(std::path::Path::new(
            "/Applications/WindowsAppAutoLogin.app"
        )));
    }
}
