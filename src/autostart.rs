#[cfg(target_os = "windows")]
use anyhow::Context;
#[cfg(not(target_os = "macos"))]
use auto_launch::{AutoLaunchBuilder, MacOSLaunchMode};
#[cfg(target_os = "macos")]
use std::path::PathBuf;
#[cfg(target_os = "macos")]
use std::process::{Command, Stdio};
#[cfg(target_os = "windows")]
use windows_registry::{Type, CURRENT_USER};

const APP_NAME: &str = crate::app_identity::APP_NAME;
#[cfg(target_os = "macos")]
const MACOS_TRUSTED_AUTOSTART_BUNDLE: &str = "/Applications/WindowsAppAutoLogin.app";
#[cfg(target_os = "windows")]
const WINDOWS_RUN_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
#[cfg(target_os = "windows")]
const WINDOWS_STARTUP_APPROVED_RUN_KEY: &str =
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
#[cfg(target_os = "windows")]
const WINDOWS_STARTUP_APPROVED_ENABLED_VALUE: [u8; 12] = [
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
#[cfg(target_os = "windows")]
const WINDOWS_FILE_NOT_FOUND_HRESULT: u32 = 0x80070002;

#[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
fn build() -> anyhow::Result<auto_launch::AutoLaunch> {
    let app_path = current_launch_path()?;
    build_for_path(&app_path)
}

#[cfg(not(target_os = "macos"))]
fn build_for_path(app_path: &str) -> anyhow::Result<auto_launch::AutoLaunch> {
    #[cfg(target_os = "windows")]
    let auto_launch_path = windows_startup_command(app_path);
    #[cfg(not(target_os = "windows"))]
    let auto_launch_path = app_path.to_string();

    let mut builder = AutoLaunchBuilder::new();
    builder
        .set_app_name(APP_NAME)
        .set_app_path(&auto_launch_path)
        .set_macos_launch_mode(macos_launch_mode_for_path(app_path))
        .set_bundle_identifiers(&["dev.codex.windows-app-autologin"]);

    #[cfg(target_os = "windows")]
    builder.set_windows_enable_mode(auto_launch::WindowsEnableMode::CurrentUser);

    let auto = builder.build()?;

    Ok(auto)
}

fn current_launch_path() -> anyhow::Result<String> {
    #[cfg(target_os = "macos")]
    {
        let exe_path = std::env::current_exe()?;
        if let Some(bundle_path) = containing_app_bundle(&exe_path) {
            return Ok(bundle_path.to_string_lossy().to_string());
        }
        Ok(exe_path.to_string_lossy().to_string())
    }

    #[cfg(not(target_os = "macos"))]
    Ok(std::env::current_exe()?.to_string_lossy().to_string())
}

#[cfg(target_os = "macos")]
fn containing_app_bundle(path: &std::path::Path) -> Option<PathBuf> {
    path.ancestors()
        .find(|ancestor| ancestor.extension().is_some_and(|ext| ext == "app"))
        .map(PathBuf::from)
}

#[cfg(not(target_os = "macos"))]
fn macos_launch_mode_for_path(_app_path: &str) -> MacOSLaunchMode {
    MacOSLaunchMode::LaunchAgent
}

fn enable() -> anyhow::Result<()> {
    let app_path = current_launch_path()?;
    ensure_stable_autostart_path(&app_path)?;

    #[cfg(target_os = "windows")]
    {
        windows_enable_current_user(&app_path)?;
        if !windows_registered_command_matches_path(&app_path) {
            anyhow::bail!(
                "Open at Login was written, but Windows Startup does not point to this app."
            );
        }
        if !windows_startup_approved_enabled() {
            let _ = windows_disable_current_user();
            anyhow::bail!(
                "Open at Login was written, but Windows Startup Apps still marks this app disabled."
            );
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    {
        remove_macos_login_items_by_name()?;
        remove_legacy_launch_agent_file()?;
        write_macos_launch_agent(&app_path)?;
        if !launch_agent_matches_current_exe() {
            let _ = remove_launch_agent_file();
            anyhow::bail!(
                "Open at Login was written, but the LaunchAgent does not point to this app."
            );
        }
        return Ok(());
    }

    #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
    {
        let auto = build_for_path(&app_path)?;
        if !auto.is_enabled()? {
            auto.enable()?;
        }
        Ok(())
    }
}

fn disable() -> anyhow::Result<()> {
    #[cfg(target_os = "windows")]
    {
        if let Ok(app_path) = current_launch_path() {
            if let Ok(auto) = build_for_path(&app_path) {
                let _ = auto.disable();
            }
        }
        windows_disable_current_user()?;
        Ok(())
    }

    #[cfg(target_os = "macos")]
    {
        remove_launch_agent_file()?;
        remove_legacy_launch_agent_file()?;
        remove_macos_login_items_by_name()?;
        return Ok(());
    }

    #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
    {
        let auto = build()?;
        if auto.is_enabled()? {
            auto.disable()?;
        }
        remove_launch_agent_file()?;
        Ok(())
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn is_enabled() -> bool {
    current_launch_path().is_ok()
        && current_autostart_path_is_stable()
        && launch_agent_file_exists()
        && launch_agent_matches_current_exe()
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn is_enabled() -> bool {
    let Ok(app_path) = current_launch_path() else {
        return false;
    };

    #[cfg(target_os = "windows")]
    {
        current_autostart_path_is_stable()
            && windows_registered_command_matches_path(&app_path)
            && windows_startup_approved_enabled()
    }

    #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
    {
        let enabled = build_for_path(&app_path)
            .and_then(|auto| Ok(auto.is_enabled()?))
            .unwrap_or(false);
        if !enabled || !current_autostart_path_is_stable() {
            return false;
        }
        launch_agent_matches_current_exe()
    }
}

pub(crate) fn set_enabled(enabled: bool) -> anyhow::Result<()> {
    if enabled {
        enable()
    } else {
        disable()
    }
}

pub(crate) fn cleanup_stale() -> anyhow::Result<()> {
    #[cfg(target_os = "windows")]
    {
        windows_cleanup_stale()?;
        Ok(())
    }

    #[cfg(target_os = "macos")]
    {
        remove_macos_login_items_by_name()?;
        remove_legacy_launch_agent_file()?;
        if !launch_agent_matches_current_exe() || !current_autostart_path_is_stable() {
            remove_launch_agent_file()?;
        }
        return Ok(());
    }

    #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
    {
        let auto = build()?;
        if auto.is_enabled()?
            && (!launch_agent_matches_current_exe() || !current_autostart_path_is_stable())
        {
            let _ = auto.disable();
            remove_launch_agent_file()?;
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn remove_macos_login_items_by_name() -> anyhow::Result<()> {
    let script = format!(
        r#"tell application "System Events"
    repeat while exists login item "{}"
        delete login item "{}"
    end repeat
end tell"#,
        applescript_string_contents(APP_NAME),
        applescript_string_contents(APP_NAME)
    );

    let output = Command::new("/usr/bin/osascript")
        .arg("-e")
        .arg(script)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    if !output.status.success() {
        anyhow::bail!("failed to remove stale macOS login items");
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn applescript_string_contents(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace(['\r', '\n'], " ")
}

#[cfg(target_os = "macos")]
fn write_macos_launch_agent(app_path: &str) -> anyhow::Result<()> {
    let Some(path) = launch_agent_path() else {
        anyhow::bail!("could not resolve LaunchAgent path");
    };
    let current_exe = std::env::current_exe()?;
    if crate::macos_identity::path_has_symlink_component(&current_exe) {
        anyhow::bail!("Open at Login cannot be enabled from a symlinked app path");
    }
    let Some(bundle_path) = containing_app_bundle(&current_exe) else {
        anyhow::bail!("Open at Login can only be enabled from the trusted app bundle");
    };
    if crate::macos_identity::path_has_symlink_component(&bundle_path) {
        anyhow::bail!("Open at Login cannot be enabled from a symlinked app bundle");
    }
    if bundle_path.to_string_lossy() != app_path {
        anyhow::bail!("Open at Login bundle path does not match the running executable");
    }
    if let Some(parent) = path.parent() {
        prepare_launch_agent_dir(parent)?;
    }

    let trusted_exe = current_exe
        .canonicalize()
        .unwrap_or_else(|_| current_exe.clone());
    let plist = macos_launch_agent_plist(&trusted_exe.to_string_lossy());
    write_private_launch_agent_file(&path, plist.as_bytes())?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn macos_launch_agent_plist(program_path: &str) -> String {
    format!(
        "{}\n{}\n<plist version=\"1.0\">\n<dict>\n  <key>Label</key>\n  <string>{}</string>\n  <key>AssociatedBundleIdentifiers</key>\n  <array><string>{}</string></array>\n  <key>ProgramArguments</key>\n  <array><string>{}</string></array>\n  <key>RunAtLoad</key>\n  <true/>\n</dict>\n</plist>\n",
        r#"<?xml version="1.0" encoding="UTF-8"?>"#,
        r#"<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">"#,
        xml_escape(macos_launch_agent_label()),
        xml_escape(crate::app_identity::macos_bundle_id()),
        xml_escape(program_path),
    )
}

#[cfg(target_os = "macos")]
fn macos_launch_agent_label() -> &'static str {
    crate::app_identity::macos_bundle_id()
}

#[cfg(target_os = "macos")]
fn legacy_macos_launch_agent_label() -> &'static str {
    APP_NAME
}

#[cfg(target_os = "macos")]
fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(all(target_os = "macos", unix))]
fn prepare_launch_agent_dir(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "LaunchAgents directory must not be a symlink",
            ));
        }
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "LaunchAgents path must be a directory",
            ));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => std::fs::create_dir_all(path)?,
        Err(e) => return Err(e),
    }

    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "LaunchAgents directory must be owned by the current user",
        ));
    }
    let mut permissions = metadata.permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(path, permissions)?;
    strip_private_path_acl(path)
}

#[cfg(all(target_os = "macos", unix))]
fn write_private_launch_agent_file(path: &std::path::Path, content: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp_path = path.with_extension(format!("plist.tmp.{}.{nonce}", std::process::id()));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temp_path)?;
    if let Err(error) = strip_private_path_acl(&temp_path)
        .and_then(|_| file.write_all(content))
        .and_then(|_| file.sync_all())
        .and_then(|_| std::fs::rename(&temp_path, path))
    {
        let _ = std::fs::remove_file(&temp_path);
        return Err(error);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn launch_agent_path() -> Option<PathBuf> {
    launch_agent_path_for_label(macos_launch_agent_label())
}

#[cfg(target_os = "macos")]
fn legacy_launch_agent_path() -> Option<PathBuf> {
    launch_agent_path_for_label(legacy_macos_launch_agent_label())
}

#[cfg(target_os = "macos")]
fn launch_agent_path_for_label(label: &str) -> Option<PathBuf> {
    crate::user_paths::home_dir().map(|home| launch_agent_path_for_home_and_label(&home, label))
}

#[cfg(target_os = "macos")]
fn launch_agent_path_for_home_and_label(home: &std::path::Path, label: &str) -> PathBuf {
    home.join("Library")
        .join("LaunchAgents")
        .join(format!("{label}.plist"))
}

#[cfg(target_os = "macos")]
fn launch_agent_matches_current_exe() -> bool {
    let Some(path) = launch_agent_path() else {
        return false;
    };
    if !launch_agent_file_is_regular(&path) {
        return false;
    }

    let Ok(current_exe) = std::env::current_exe() else {
        return false;
    };
    let Some(program_path) = launch_agent_program_path(&path) else {
        return false;
    };

    let program_path = PathBuf::from(program_path);
    if crate::macos_identity::path_has_symlink_component(&program_path) {
        return false;
    }
    if crate::macos_identity::path_has_symlink_component(&current_exe) {
        return false;
    }

    launch_agent_program_path_matches_current_exe(&program_path, &current_exe)
}

#[cfg(target_os = "macos")]
fn launch_agent_program_path_matches_current_exe(
    program_path: &std::path::Path,
    current_exe: &std::path::Path,
) -> bool {
    if crate::macos_identity::path_has_symlink_component(program_path)
        || crate::macos_identity::path_has_symlink_component(current_exe)
    {
        return false;
    }
    if program_path == current_exe {
        return true;
    }

    match (
        std::fs::canonicalize(current_exe),
        std::fs::canonicalize(program_path),
    ) {
        (Ok(current), Ok(program)) => current == program,
        _ => false,
    }
}

#[cfg(target_os = "macos")]
fn launch_agent_file_exists() -> bool {
    launch_agent_path()
        .as_deref()
        .is_some_and(launch_agent_file_is_regular)
}

#[cfg(target_os = "macos")]
fn launch_agent_file_is_regular(path: &std::path::Path) -> bool {
    launch_agent_file_metadata_is_trusted(path)
        .map(|metadata| metadata.file_type().is_file())
        .unwrap_or(false)
}

#[cfg(all(target_os = "macos", unix))]
fn launch_agent_file_metadata_is_trusted(
    path: &std::path::Path,
) -> std::io::Result<std::fs::Metadata> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    if let Some(parent) = path.parent() {
        let parent_metadata = std::fs::symlink_metadata(parent)?;
        if !parent_metadata.file_type().is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "LaunchAgent parent must be a directory",
            ));
        }
        if parent_metadata.uid() != unsafe { libc::geteuid() } {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "LaunchAgent parent must be owned by the current user",
            ));
        }
        if parent_metadata.permissions().mode() & 0o022 != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "LaunchAgent parent must not be group/world writable",
            ));
        }
        if private_path_has_acl(parent)? {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "LaunchAgent parent must not have ACL entries",
            ));
        }
    }

    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Ok(metadata);
    }
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "LaunchAgent plist must be owned by the current user",
        ));
    }
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "LaunchAgent plist must not be group/world writable",
        ));
    }
    if private_path_has_acl(path)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "LaunchAgent plist must not have ACL entries",
        ));
    }
    Ok(metadata)
}

#[cfg(all(target_os = "macos", unix))]
fn strip_private_path_acl(path: &std::path::Path) -> std::io::Result<()> {
    crate::private_permissions::strip_macos_acl(path)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::PermissionDenied, error))
}

#[cfg(all(target_os = "macos", unix))]
fn private_path_has_acl(path: &std::path::Path) -> std::io::Result<bool> {
    crate::private_permissions::path_has_macos_acl(path)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::PermissionDenied, error))
}

#[cfg(all(target_os = "macos", not(unix)))]
fn launch_agent_file_metadata_is_trusted(
    path: &std::path::Path,
) -> std::io::Result<std::fs::Metadata> {
    std::fs::symlink_metadata(path)
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn launch_agent_matches_current_exe() -> bool {
    true
}

#[cfg(target_os = "macos")]
fn remove_launch_agent_file() -> anyhow::Result<()> {
    if let Some(path) = launch_agent_path() {
        remove_launch_agent_file_at(&path)?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn remove_legacy_launch_agent_file() -> anyhow::Result<()> {
    let Some(path) = legacy_launch_agent_path() else {
        return Ok(());
    };
    let Some(current_path) = launch_agent_path() else {
        return Ok(());
    };
    if path == current_path {
        return Ok(());
    }
    remove_launch_agent_file_at(&path)
}

#[cfg(target_os = "macos")]
fn remove_launch_agent_file_at(path: &std::path::Path) -> anyhow::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => std::fs::remove_file(path)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn ensure_stable_autostart_path(app_path: &str) -> anyhow::Result<()> {
    #[cfg(target_os = "macos")]
    {
        if !macos_trusted_autostart_path(app_path) {
            anyhow::bail!("{}", stable_autostart_path_message());
        }
        Ok(())
    }

    #[cfg(target_os = "windows")]
    {
        if !windows_trusted_autostart_path(app_path) {
            anyhow::bail!("{}", stable_autostart_path_message());
        }
        Ok(())
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        if is_transient_path(app_path) {
            anyhow::bail!("{}", stable_autostart_path_message());
        }
        Ok(())
    }
}

fn stable_autostart_path_message() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "Open at Login can only be enabled from /Applications/WindowsAppAutoLogin.app."
    }
    #[cfg(target_os = "windows")]
    {
        "Open at Login can only be enabled from a protected install folder such as Program Files."
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        "Open at Login cannot be enabled from a temporary or build folder. Move the app to a stable install folder first."
    }
}

fn current_autostart_path_is_stable() -> bool {
    let Ok(path) = current_launch_path() else {
        return false;
    };

    #[cfg(target_os = "macos")]
    {
        macos_trusted_autostart_path(&path)
    }

    #[cfg(target_os = "windows")]
    {
        windows_trusted_autostart_path(&path)
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        !is_transient_path(&path)
    }
}

#[cfg(target_os = "macos")]
fn macos_trusted_autostart_path(app_path: &str) -> bool {
    let path = PathBuf::from(app_path);
    if !macos_autostart_bundle_path_has_safe_spelling(&path) {
        return false;
    }
    let Ok(canonical_path) = path.canonicalize() else {
        return false;
    };
    macos_trusted_autostart_canonical_path(&canonical_path)
        && macos_autostart_bundle_identifier_is_trusted(&canonical_path)
        && crate::autologin::trusted_app_bundle_identity_is_trusted(&canonical_path)
}

#[cfg(target_os = "macos")]
fn macos_autostart_bundle_name_is_trusted(path: &std::path::Path) -> bool {
    path.extension().is_some_and(|ext| ext == "app")
        && path
            .file_name()
            .is_some_and(|name| name == "WindowsAppAutoLogin.app")
}

#[cfg(target_os = "macos")]
fn macos_autostart_bundle_path_has_safe_spelling(path: &std::path::Path) -> bool {
    macos_autostart_bundle_name_is_trusted(path)
        && !crate::macos_identity::path_has_symlink_component(path)
}

#[cfg(target_os = "macos")]
fn macos_trusted_autostart_canonical_path(path: &std::path::Path) -> bool {
    path == std::path::Path::new(MACOS_TRUSTED_AUTOSTART_BUNDLE)
}

#[cfg(target_os = "macos")]
fn macos_autostart_bundle_identifier_is_trusted(path: &std::path::Path) -> bool {
    let output = Command::new("/usr/libexec/PlistBuddy")
        .args(["-c", "Print :CFBundleIdentifier"])
        .arg(path.join("Contents/Info.plist"))
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output();
    let Ok(output) = output else {
        return false;
    };
    output.status.success()
        && String::from_utf8_lossy(&output.stdout).trim() == crate::app_identity::macos_bundle_id()
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AutostartPlatform {
    Macos,
    Windows,
    Other,
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn is_transient_path(path: &str) -> bool {
    is_transient_path_for_platform(path, current_autostart_platform())
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn current_autostart_platform() -> AutostartPlatform {
    #[cfg(target_os = "macos")]
    {
        return AutostartPlatform::Macos;
    }
    #[cfg(target_os = "windows")]
    {
        AutostartPlatform::Windows
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        AutostartPlatform::Other
    }
}

#[cfg_attr(target_os = "macos", allow(dead_code))]
fn is_transient_path_for_platform(path: &str, platform: AutostartPlatform) -> bool {
    let normalized = path.replace('\\', "/").to_lowercase();
    if has_path_segment(&normalized, "target") {
        return true;
    }
    if platform == AutostartPlatform::Macos && has_path_segment(&normalized, "dist") {
        return true;
    }

    match platform {
        AutostartPlatform::Macos => {
            normalized.starts_with("/tmp/")
                || normalized.starts_with("/private/tmp/")
                || normalized.contains("/var/folders/")
                || has_path_segment(&normalized, "temp")
                || has_path_segment(&normalized, "tmp")
        }
        AutostartPlatform::Windows => {
            has_path_segment(&normalized, "temp")
                || has_path_segment(&normalized, "tmp")
                || normalized.contains("/appdata/local/temp/")
        }
        AutostartPlatform::Other => {
            has_path_segment(&normalized, "temp") || has_path_segment(&normalized, "tmp")
        }
    }
}

#[cfg_attr(target_os = "macos", allow(dead_code))]
fn has_path_segment(path: &str, segment: &str) -> bool {
    path.split('/').any(|part| part == segment)
}

#[cfg(target_os = "windows")]
fn windows_trusted_autostart_path(app_path: &str) -> bool {
    let path = std::path::Path::new(app_path);
    if !path.is_file() {
        return false;
    }
    let Ok(canonical_path) = path.canonicalize() else {
        return false;
    };
    windows_trusted_autostart_path_for_roots(
        &canonical_path.to_string_lossy(),
        &windows_protected_autostart_roots(),
    )
}

#[cfg(target_os = "windows")]
fn windows_protected_autostart_roots() -> Vec<String> {
    let mut roots: Vec<String> = Vec::new();
    for var in ["ProgramW6432", "ProgramFiles", "ProgramFiles(x86)"] {
        let Some(root) = std::env::var_os(var) else {
            continue;
        };
        let root = root.to_string_lossy().to_string();
        if root.trim().is_empty() {
            continue;
        }
        if !roots
            .iter()
            .any(|existing| windows_paths_equal(existing, &root))
        {
            roots.push(root);
        }
    }
    roots
}

#[cfg(any(target_os = "windows", test))]
fn windows_trusted_autostart_path_for_roots(app_path: &str, protected_roots: &[String]) -> bool {
    if is_transient_path_for_platform(app_path, AutostartPlatform::Windows) {
        return false;
    }
    if !windows_autostart_executable_name_is_trusted(app_path) {
        return false;
    }

    let path = normalize_windows_path_for_compare(app_path);
    protected_roots
        .iter()
        .any(|root| windows_path_is_under_root(&path, root))
}

#[cfg(any(target_os = "windows", test))]
fn windows_autostart_executable_name_is_trusted(app_path: &str) -> bool {
    normalize_windows_path_for_compare(app_path).ends_with(r"\windowsappautologin.exe")
}

#[cfg(any(target_os = "windows", test))]
fn windows_path_is_under_root(normalized_path: &str, root: &str) -> bool {
    let root = normalize_windows_path_for_compare(root);
    normalized_path
        .strip_prefix(&root)
        .is_some_and(|rest| rest.starts_with('\\'))
}

#[cfg(any(target_os = "windows", test))]
fn windows_startup_command(app_path: &str) -> String {
    windows_quote_command_arg(&windows_registry_path(app_path))
}

#[cfg(any(target_os = "windows", test))]
fn windows_registry_path(path: &str) -> String {
    if let Some(rest) = path.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{}", rest).replace('/', r"\")
    } else if let Some(rest) = path.strip_prefix(r"\\?\") {
        rest.replace('/', r"\")
    } else {
        path.replace('/', r"\")
    }
}

#[cfg(any(target_os = "windows", test))]
fn windows_quote_command_arg(arg: &str) -> String {
    let mut quoted = String::with_capacity(arg.len() + 2);
    quoted.push('"');

    let mut backslashes = 0;
    for ch in arg.chars() {
        if ch == '\\' {
            backslashes += 1;
            continue;
        }

        if ch == '"' {
            quoted.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
            quoted.push('"');
        } else {
            quoted.extend(std::iter::repeat_n('\\', backslashes));
            quoted.push(ch);
        }
        backslashes = 0;
    }

    quoted.extend(std::iter::repeat_n('\\', backslashes * 2));
    quoted.push('"');
    quoted
}

#[cfg(any(target_os = "windows", test))]
fn windows_command_executable_path(command: &str) -> Option<String> {
    let command = command.trim_start();
    if command.is_empty() {
        return None;
    }
    if let Some(rest) = command.strip_prefix('"') {
        let end = rest.find('"')?;
        return Some(windows_registry_path(&rest[..end]));
    }

    command.split_whitespace().next().map(windows_registry_path)
}

#[cfg(any(target_os = "windows", test))]
fn windows_paths_equal(left: &str, right: &str) -> bool {
    normalize_windows_path_for_compare(left) == normalize_windows_path_for_compare(right)
}

#[cfg(any(target_os = "windows", test))]
fn normalize_windows_path_for_compare(path: &str) -> String {
    let mut normalized = windows_registry_path(path.trim());
    while normalized.ends_with('\\') && normalized.len() > 3 {
        normalized.pop();
    }
    normalized.to_lowercase()
}

#[cfg(any(target_os = "windows", test))]
fn windows_startup_approved_value_is_enabled(bytes: &[u8]) -> bool {
    bytes.first().is_none_or(|state| *state == 0x02)
}

#[cfg(target_os = "windows")]
fn windows_enable_current_user(app_path: &str) -> anyhow::Result<()> {
    let command = windows_startup_command(app_path);
    CURRENT_USER
        .create(WINDOWS_RUN_KEY)
        .context("open Windows Startup registry key")?
        .set_string(APP_NAME, &command)
        .context("write Windows Startup registry value")?;

    match CURRENT_USER
        .options()
        .write()
        .open(WINDOWS_STARTUP_APPROVED_RUN_KEY)
    {
        Ok(key) => key
            .set_bytes(
                APP_NAME,
                Type::Bytes,
                &WINDOWS_STARTUP_APPROVED_ENABLED_VALUE,
            )
            .context("enable Windows Startup Apps entry")?,
        Err(error) if error.code().0 as u32 == WINDOWS_FILE_NOT_FOUND_HRESULT => {}
        Err(error) => return Err(error).context("open Windows Startup Apps approval key"),
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn windows_disable_current_user() -> anyhow::Result<()> {
    match CURRENT_USER.options().write().open(WINDOWS_RUN_KEY) {
        Ok(key) => match key.remove_value(APP_NAME) {
            Ok(()) => {}
            Err(error) if error.code().0 as u32 == WINDOWS_FILE_NOT_FOUND_HRESULT => {}
            Err(error) => return Err(error).context("remove Windows Startup registry value"),
        },
        Err(error) if error.code().0 as u32 == WINDOWS_FILE_NOT_FOUND_HRESULT => {}
        Err(error) => return Err(error).context("open Windows Startup registry key"),
    };

    if let Ok(key) = CURRENT_USER
        .options()
        .write()
        .open(WINDOWS_STARTUP_APPROVED_RUN_KEY)
    {
        let _ = key.remove_value(APP_NAME);
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn windows_cleanup_stale() -> anyhow::Result<()> {
    let Some(command) = windows_registered_command() else {
        return Ok(());
    };
    let Some(app_path) = windows_command_executable_path(&command) else {
        windows_disable_current_user()?;
        return Ok(());
    };

    if !windows_trusted_autostart_path(&app_path) {
        windows_disable_current_user()?;
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn windows_registered_command_matches_path(app_path: &str) -> bool {
    windows_registered_command()
        .as_deref()
        .and_then(windows_command_executable_path)
        .is_some_and(|registered_path| windows_paths_equal(&registered_path, app_path))
}

#[cfg(target_os = "windows")]
fn windows_registered_command() -> Option<String> {
    CURRENT_USER
        .open(WINDOWS_RUN_KEY)
        .and_then(|key| key.get_string(APP_NAME))
        .ok()
}

#[cfg(target_os = "windows")]
fn windows_startup_approved_enabled() -> bool {
    match CURRENT_USER.open(WINDOWS_STARTUP_APPROVED_RUN_KEY) {
        Ok(key) => match key.get_value(APP_NAME) {
            Ok(value) => windows_startup_approved_value_is_enabled(&value),
            Err(error) if error.code().0 as u32 == WINDOWS_FILE_NOT_FOUND_HRESULT => true,
            Err(_) => false,
        },
        Err(error) if error.code().0 as u32 == WINDOWS_FILE_NOT_FOUND_HRESULT => true,
        Err(_) => false,
    }
}

#[cfg(target_os = "macos")]
fn launch_agent_program_path(path: &std::path::Path) -> Option<String> {
    if plist_has_duplicate_launch_agent_keys(path) {
        return None;
    }
    let plist = launch_agent_plist_value(path)?;
    let dict = plist.as_object()?;
    if dict.keys().any(|key| {
        !matches!(
            key.as_str(),
            "Label" | "AssociatedBundleIdentifiers" | "ProgramArguments" | "RunAtLoad"
        )
    }) {
        return None;
    }

    if dict.get("Label")?.as_str()? != macos_launch_agent_label() {
        return None;
    }
    if dict.get("RunAtLoad")?.as_bool()? != true {
        return None;
    }
    let bundle_ids = dict.get("AssociatedBundleIdentifiers")?.as_array()?;
    let [bundle_id] = bundle_ids.as_slice() else {
        return None;
    };
    if bundle_id.as_str()? != crate::app_identity::macos_bundle_id() {
        return None;
    }

    let program_args = dict.get("ProgramArguments")?.as_array()?;
    let [program_path] = program_args.as_slice() else {
        return None;
    };
    let program_path = program_path.as_str()?.to_string();
    (!program_path.trim().is_empty()).then_some(program_path)
}

#[cfg(target_os = "macos")]
fn launch_agent_plist_value(path: &std::path::Path) -> Option<serde_json::Value> {
    let output = Command::new("/usr/bin/plutil")
        .args(["-convert", "json", "-o", "-"])
        .arg(path)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    serde_json::from_slice(&output.stdout).ok()
}

#[cfg(target_os = "macos")]
fn plist_has_duplicate_launch_agent_keys(path: &std::path::Path) -> bool {
    let Ok(content) = std::fs::read_to_string(path) else {
        return false;
    };
    let content = strip_xml_comments(&content);
    [
        "Label",
        "AssociatedBundleIdentifiers",
        "Program",
        "BundleProgram",
        "ProgramArguments",
        "RunAtLoad",
    ]
    .iter()
    .any(|key| content.matches(&format!("<key>{key}</key>")).count() > 1)
}

#[cfg(target_os = "macos")]
fn strip_xml_comments(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find("<!--") {
        output.push_str(&rest[..start]);
        let comment = &rest[start + 4..];
        let Some(end) = comment.find("-->") else {
            return output;
        };
        rest = &comment[end + 3..];
    }
    output.push_str(rest);
    output
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn remove_launch_agent_file() -> anyhow::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_transient_path_does_not_define_trust_for_dist_artifact() {
        assert!(!is_transient_path_for_platform(
            r"C:\Users\me\repo\dist\WindowsAppAutoLogin-windows-x86_64\WindowsAppAutoLogin.exe",
            AutostartPlatform::Windows
        ));
        assert!(!windows_trusted_autostart_path_for_roots(
            r"C:\Users\me\repo\dist\WindowsAppAutoLogin-windows-x86_64\WindowsAppAutoLogin.exe",
            &[r"C:\Program Files".to_string()]
        ));
    }

    #[test]
    fn windows_transient_path_rejects_build_and_temp_locations() {
        assert!(is_transient_path_for_platform(
            r"C:\Users\me\repo\target\release\WindowsAppAutoLogin.exe",
            AutostartPlatform::Windows
        ));
        assert!(is_transient_path_for_platform(
            r"C:\Users\me\AppData\Local\Temp\WindowsAppAutoLogin.exe",
            AutostartPlatform::Windows
        ));
        assert!(is_transient_path_for_platform(
            r"C:\tmp\WindowsAppAutoLogin.exe",
            AutostartPlatform::Windows
        ));
    }

    #[test]
    fn windows_transient_path_classifier_allows_non_temp_install_locations() {
        assert!(!is_transient_path_for_platform(
            r"C:\Program Files\Windows App AutoLogin\WindowsAppAutoLogin.exe",
            AutostartPlatform::Windows
        ));
        assert!(!is_transient_path_for_platform(
            r"C:\Users\me\AppData\Local\Programs\WindowsAppAutoLogin\WindowsAppAutoLogin.exe",
            AutostartPlatform::Windows
        ));
    }

    #[test]
    fn windows_autostart_trust_requires_protected_install_root() {
        let protected_roots = vec![
            r"C:\Program Files".to_string(),
            r"C:\Program Files (x86)".to_string(),
        ];

        assert!(windows_trusted_autostart_path_for_roots(
            r"C:\Program Files\Windows App AutoLogin\WindowsAppAutoLogin.exe",
            &protected_roots
        ));
        assert!(windows_trusted_autostart_path_for_roots(
            r"C:\Program Files (x86)\Windows App AutoLogin\WindowsAppAutoLogin.exe",
            &protected_roots
        ));
        assert!(!windows_trusted_autostart_path_for_roots(
            r"C:\Users\me\AppData\Local\Programs\WindowsAppAutoLogin\WindowsAppAutoLogin.exe",
            &protected_roots
        ));
        assert!(!windows_trusted_autostart_path_for_roots(
            r"C:\Users\me\repo\dist\WindowsAppAutoLogin-windows-x86_64\WindowsAppAutoLogin.exe",
            &protected_roots
        ));
        assert!(!windows_trusted_autostart_path_for_roots(
            r"C:\Users\me\Program Files\Windows App AutoLogin\WindowsAppAutoLogin.exe",
            &protected_roots
        ));
        assert!(!windows_trusted_autostart_path_for_roots(
            r"C:\Program Files\Windows App AutoLogin\Other.exe",
            &protected_roots
        ));
    }

    #[test]
    fn transient_path_uses_segment_boundaries() {
        assert!(!is_transient_path_for_platform(
            r"C:\Apps\targeted\WindowsAppAutoLogin.exe",
            AutostartPlatform::Windows
        ));
        assert!(!is_transient_path_for_platform(
            r"C:\Apps\distinguished\WindowsAppAutoLogin.exe",
            AutostartPlatform::Windows
        ));
        assert!(!is_transient_path_for_platform(
            r"C:\Tempest\WindowsAppAutoLogin.exe",
            AutostartPlatform::Windows
        ));
    }

    #[test]
    fn macos_transient_path_still_rejects_dist_artifact() {
        assert!(is_transient_path_for_platform(
            "/Users/me/repo/dist/WindowsAppAutoLogin.app",
            AutostartPlatform::Macos
        ));
        assert!(!is_transient_path_for_platform(
            "/Applications/WindowsAppAutoLogin.app",
            AutostartPlatform::Macos
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_autostart_trust_requires_exact_applications_bundle() {
        assert!(macos_autostart_bundle_name_is_trusted(
            std::path::Path::new("/Applications/WindowsAppAutoLogin.app")
        ));
        assert!(macos_trusted_autostart_canonical_path(
            std::path::Path::new("/Applications/WindowsAppAutoLogin.app")
        ));
        assert!(!macos_autostart_bundle_name_is_trusted(
            std::path::Path::new("/Applications/WindowsAppAutoLogin-copy.app")
        ));
        assert!(!macos_autostart_bundle_name_is_trusted(
            std::path::Path::new("/Applications/Other.app")
        ));
        assert!(!macos_trusted_autostart_canonical_path(
            std::path::Path::new("/Users/me/Downloads/WindowsAppAutoLogin.app")
        ));
        assert!(!macos_trusted_autostart_canonical_path(
            std::path::Path::new("/Users/me/Applications/WindowsAppAutoLogin.app")
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_autostart_rejects_symlinked_bundle_path() {
        let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "windows-app-autologin-autostart-symlink-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let real_parent = root.join("real");
        let link_parent = root.join("link");
        let real_bundle = real_parent.join("WindowsAppAutoLogin.app");
        std::fs::create_dir_all(&real_bundle).unwrap();
        std::os::unix::fs::symlink(&real_parent, &link_parent).unwrap();

        let link_bundle = link_parent.join("WindowsAppAutoLogin.app");
        assert!(macos_autostart_bundle_name_is_trusted(&link_bundle));
        assert!(!macos_autostart_bundle_path_has_safe_spelling(&link_bundle));
        assert!(macos_autostart_bundle_path_has_safe_spelling(&real_bundle));

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_launch_agent_matching_rejects_symlink_program_argument() {
        let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "windows-app-autologin-launch-agent-symlink-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let real_dir = root.join("real").join("Contents").join("MacOS");
        let link_dir = root.join("link").join("Contents").join("MacOS");
        std::fs::create_dir_all(&real_dir).unwrap();
        std::fs::write(real_dir.join("windows-app-autologin"), b"exe").unwrap();
        std::os::unix::fs::symlink(root.join("real"), root.join("link")).unwrap();

        let current_exe = real_dir.join("windows-app-autologin");
        let symlink_program = link_dir.join("windows-app-autologin");
        assert!(launch_agent_program_path_matches_current_exe(
            &current_exe,
            &current_exe
        ));
        assert!(!launch_agent_program_path_matches_current_exe(
            &symlink_program,
            &current_exe
        ));

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_launch_agent_program_path_uses_structured_plist() {
        let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "windows-app-autologin-launch-agent-plist-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let program_path =
            "/Applications/WindowsAppAutoLogin.app/Contents/MacOS/windows-app-autologin";
        let plist_path = root.join("valid.plist");
        std::fs::write(&plist_path, macos_launch_agent_plist(program_path)).unwrap();

        assert_eq!(
            launch_agent_program_path(&plist_path).as_deref(),
            Some(program_path)
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_launch_agent_identity_uses_bundle_id_label() {
        let program_path =
            "/Applications/WindowsAppAutoLogin.app/Contents/MacOS/windows-app-autologin";
        let plist = macos_launch_agent_plist(program_path);
        let bundle_id = crate::app_identity::macos_bundle_id();

        assert_eq!(macos_launch_agent_label(), bundle_id);
        assert!(plist.contains(&format!(
            "<key>Label</key>\n  <string>{}</string>",
            xml_escape(bundle_id)
        )));
        assert!(plist.contains(&format!(
            "<key>AssociatedBundleIdentifiers</key>\n  <array><string>{}</string></array>",
            xml_escape(bundle_id)
        )));
        assert!(!plist.contains(&format!(
            "<key>Label</key>\n  <string>{}</string>",
            xml_escape(APP_NAME)
        )));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_launch_agent_path_uses_bundle_id_plist_name() {
        let home = std::path::Path::new("/Users/example");
        let path = launch_agent_path_for_home_and_label(home, macos_launch_agent_label());

        assert_eq!(
            path,
            home.join("Library")
                .join("LaunchAgents")
                .join(format!("{}.plist", crate::app_identity::macos_bundle_id()))
        );
        assert_ne!(
            path.file_name().and_then(|name| name.to_str()),
            Some("WindowsAppAutoLogin.plist")
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_launch_agent_program_path_rejects_legacy_app_name_label() {
        let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "windows-app-autologin-launch-agent-legacy-label-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let program_path =
            "/Applications/WindowsAppAutoLogin.app/Contents/MacOS/windows-app-autologin";
        let plist_path = root.join("legacy-label.plist");
        let legacy_label = macos_launch_agent_plist(program_path).replace(
            &format!(
                "<key>Label</key>\n  <string>{}</string>",
                xml_escape(macos_launch_agent_label())
            ),
            &format!(
                "<key>Label</key>\n  <string>{}</string>",
                xml_escape(APP_NAME)
            ),
        );
        std::fs::write(&plist_path, legacy_label).unwrap();

        assert_eq!(launch_agent_program_path(&plist_path), None);

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_legacy_launch_agent_cleanup_preserves_current_plist() {
        let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "windows-app-autologin-launch-agent-cleanup-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let current_path = launch_agent_path_for_home_and_label(&root, macos_launch_agent_label());
        let legacy_path =
            launch_agent_path_for_home_and_label(&root, legacy_macos_launch_agent_label());
        std::fs::create_dir_all(current_path.parent().unwrap()).unwrap();
        std::fs::write(&current_path, macos_launch_agent_plist("/tmp/current")).unwrap();
        std::fs::write(&legacy_path, b"legacy").unwrap();

        remove_launch_agent_file_at(&legacy_path).unwrap();

        assert!(current_path.exists());
        assert!(!legacy_path.exists());

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_launch_agent_program_path_ignores_spoofed_comment() {
        let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "windows-app-autologin-launch-agent-comment-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let trusted_program =
            "/Applications/WindowsAppAutoLogin.app/Contents/MacOS/windows-app-autologin";
        let real_program = "/tmp/evil";
        let plist_path = root.join("spoofed.plist");
        let content = macos_launch_agent_plist(real_program).replace(
            "<dict>",
            &format!(
                "<dict>\n  <!-- <key>ProgramArguments</key><array><string>{}</string></array> -->",
                xml_escape(trusted_program)
            ),
        );
        std::fs::write(&plist_path, content).unwrap();

        assert_eq!(
            launch_agent_program_path(&plist_path).as_deref(),
            Some(real_program)
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_launch_agent_program_path_requires_exact_generated_shape() {
        let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "windows-app-autologin-launch-agent-shape-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let program_path =
            "/Applications/WindowsAppAutoLogin.app/Contents/MacOS/windows-app-autologin";
        let extra_arg_path = root.join("extra-arg.plist");
        let extra_arg = macos_launch_agent_plist(program_path).replace(
            &format!(
                "<key>ProgramArguments</key>\n  <array><string>{}</string></array>",
                xml_escape(program_path)
            ),
            &format!(
                "<key>ProgramArguments</key>\n  <array><string>{}</string><string>--unexpected</string></array>",
                xml_escape(program_path)
            ),
        );
        std::fs::write(&extra_arg_path, extra_arg).unwrap();

        assert_eq!(launch_agent_program_path(&extra_arg_path), None);

        let program_key_path = root.join("program-key.plist");
        let program_key = macos_launch_agent_plist(program_path).replace(
            "<key>ProgramArguments</key>",
            "<key>Program</key>\n  <string>/tmp/evil</string>\n  <key>ProgramArguments</key>",
        );
        std::fs::write(&program_key_path, program_key).unwrap();

        assert_eq!(launch_agent_program_path(&program_key_path), None);

        let duplicate_args_path = root.join("duplicate-args.plist");
        let duplicate_args = macos_launch_agent_plist(program_path).replace(
            "<key>ProgramArguments</key>",
            "<key>ProgramArguments</key>\n  <array><string>/tmp/evil</string></array>\n  <key>ProgramArguments</key>",
        );
        std::fs::write(&duplicate_args_path, duplicate_args).unwrap();

        assert_eq!(launch_agent_program_path(&duplicate_args_path), None);

        let string_run_at_load_path = root.join("string-run-at-load.plist");
        let string_run_at_load =
            macos_launch_agent_plist(program_path).replace("<true/>", "<string>true</string>");
        std::fs::write(&string_run_at_load_path, string_run_at_load).unwrap();

        assert_eq!(launch_agent_program_path(&string_run_at_load_path), None);

        let integer_program_path = root.join("integer-program.plist");
        let integer_program = macos_launch_agent_plist(program_path).replace(
            &format!(
                "<array><string>{}</string></array>",
                xml_escape(program_path)
            ),
            "<array><integer>7</integer></array>",
        );
        std::fs::write(&integer_program_path, integer_program).unwrap();

        assert_eq!(launch_agent_program_path(&integer_program_path), None);

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_launch_agent_file_trust_rejects_writable_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let root = macos_temp_root("launch-agent-mode");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let plist_path = root.join("mode.plist");
        std::fs::write(&plist_path, macos_launch_agent_plist("/tmp/app")).unwrap();
        std::fs::set_permissions(&plist_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(launch_agent_file_is_regular(&plist_path));

        std::fs::set_permissions(&plist_path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(!launch_agent_file_is_regular(&plist_path));

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_prepare_launch_agent_dir_strips_inherited_acl() {
        use std::os::unix::fs::PermissionsExt;

        let root = macos_temp_root("launch-agent-dir-acl");
        std::fs::create_dir_all(&root).unwrap();
        if !add_macos_acl(
            &root,
            "everyone allow list,search,readattr,readextattr,readsecurity,file_inherit,directory_inherit",
        ) {
            let _ = std::fs::remove_dir_all(root);
            return;
        }

        let launch_agents = root.join("LaunchAgents");
        prepare_launch_agent_dir(&launch_agents).unwrap();

        assert_eq!(
            std::fs::metadata(&launch_agents)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert!(!path_has_macos_acl(&launch_agents));
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_write_private_launch_agent_file_strips_inherited_acl() {
        use std::os::unix::fs::PermissionsExt;

        let root = macos_temp_root("launch-agent-file-acl");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        if !add_macos_acl(
            &root,
            "everyone allow read,readattr,readextattr,readsecurity,file_inherit",
        ) {
            let _ = std::fs::remove_dir_all(root);
            return;
        }

        let plist_path = root.join("agent.plist");
        write_private_launch_agent_file(
            &plist_path,
            macos_launch_agent_plist("/tmp/app").as_bytes(),
        )
        .unwrap();

        assert_eq!(
            std::fs::metadata(&plist_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(!path_has_macos_acl(&plist_path));
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_launch_agent_file_trust_rejects_acl_entries() {
        use std::os::unix::fs::PermissionsExt;

        let parent_acl_root = macos_temp_root("launch-agent-parent-acl");
        std::fs::create_dir_all(&parent_acl_root).unwrap();
        std::fs::set_permissions(&parent_acl_root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let parent_acl_plist = parent_acl_root.join("parent-acl.plist");
        std::fs::write(&parent_acl_plist, macos_launch_agent_plist("/tmp/app")).unwrap();
        std::fs::set_permissions(&parent_acl_plist, std::fs::Permissions::from_mode(0o600))
            .unwrap();
        if !add_macos_acl(
            &parent_acl_root,
            "everyone allow list,search,readattr,readextattr,readsecurity",
        ) {
            let _ = std::fs::remove_dir_all(parent_acl_root);
            return;
        }
        assert!(!launch_agent_file_is_regular(&parent_acl_plist));
        let _ = std::fs::remove_dir_all(parent_acl_root);

        let plist_acl_root = macos_temp_root("launch-agent-plist-acl");
        std::fs::create_dir_all(&plist_acl_root).unwrap();
        std::fs::set_permissions(&plist_acl_root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let plist_acl_path = plist_acl_root.join("plist-acl.plist");
        std::fs::write(&plist_acl_path, macos_launch_agent_plist("/tmp/app")).unwrap();
        std::fs::set_permissions(&plist_acl_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        if !add_macos_acl(
            &plist_acl_path,
            "everyone allow read,readattr,readextattr,readsecurity",
        ) {
            let _ = std::fs::remove_dir_all(plist_acl_root);
            return;
        }
        assert!(!launch_agent_file_is_regular(&plist_acl_path));
        let _ = std::fs::remove_dir_all(plist_acl_root);
    }

    #[cfg(target_os = "macos")]
    fn macos_temp_root(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().canonicalize().unwrap().join(format!(
            "windows-app-autologin-{name}-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[cfg(target_os = "macos")]
    fn add_macos_acl(path: &std::path::Path, acl: &str) -> bool {
        let output = std::process::Command::new("/bin/chmod")
            .arg("+a")
            .arg(acl)
            .arg(path)
            .output();
        match output {
            Ok(output) if output.status.success() => true,
            Ok(output) => {
                eprintln!(
                    "skipping macOS ACL assertion; chmod +a failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                false
            }
            Err(error) => {
                eprintln!("skipping macOS ACL assertion; chmod unavailable: {error}");
                false
            }
        }
    }

    #[cfg(target_os = "macos")]
    fn path_has_macos_acl(path: &std::path::Path) -> bool {
        crate::private_permissions::path_has_macos_acl(path).unwrap()
    }

    #[test]
    fn windows_startup_command_quotes_exe_path_with_spaces() {
        let command = windows_startup_command(
            r"C:\Program Files\Windows App AutoLogin\WindowsAppAutoLogin.exe",
        );
        assert_eq!(
            command,
            r#""C:\Program Files\Windows App AutoLogin\WindowsAppAutoLogin.exe""#
        );
        assert_eq!(
            windows_command_executable_path(&command).as_deref(),
            Some(r"C:\Program Files\Windows App AutoLogin\WindowsAppAutoLogin.exe")
        );
    }

    #[test]
    fn windows_startup_command_strips_verbatim_prefixes() {
        assert_eq!(
            windows_startup_command(r"\\?\C:\Apps\WindowsAppAutoLogin.exe"),
            r#""C:\Apps\WindowsAppAutoLogin.exe""#
        );
        assert_eq!(
            windows_startup_command(r"\\?\UNC\server\share\WindowsAppAutoLogin.exe"),
            r#""\\server\share\WindowsAppAutoLogin.exe""#
        );
    }

    #[test]
    fn windows_path_compare_normalizes_slashes_and_case() {
        assert!(windows_paths_equal(
            r"C:\Apps\WindowsAppAutoLogin.exe",
            r"c:/apps/WindowsAppAutoLogin.exe"
        ));
    }

    #[test]
    fn windows_command_executable_path_handles_args_and_bad_quotes() {
        assert_eq!(
            windows_command_executable_path(
                r#""C:\Program Files\Windows App AutoLogin\WindowsAppAutoLogin.exe" --full-ui"#
            )
            .as_deref(),
            Some(r"C:\Program Files\Windows App AutoLogin\WindowsAppAutoLogin.exe")
        );
        assert_eq!(
            windows_command_executable_path(
                r#""C:\Program Files\Windows App AutoLogin\WindowsAppAutoLogin.exe"#
            ),
            None
        );
    }

    #[test]
    fn windows_startup_approved_value_reads_task_manager_state() {
        assert!(windows_startup_approved_value_is_enabled(&[]));
        assert!(windows_startup_approved_value_is_enabled(&[
            0x02, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0
        ]));
        assert!(!windows_startup_approved_value_is_enabled(&[
            0x03, 0x00, 0x00, 0x00, 1, 0, 0, 0, 0, 0, 0, 0
        ]));
        assert!(!windows_startup_approved_value_is_enabled(&[
            0x03, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0
        ]));
    }
}
