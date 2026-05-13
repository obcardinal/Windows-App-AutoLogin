#[cfg(target_os = "windows")]
use anyhow::Context;
use auto_launch::{AutoLaunchBuilder, MacOSLaunchMode};
#[cfg(target_os = "macos")]
use std::path::PathBuf;
#[cfg(target_os = "macos")]
use std::process::{Command, Stdio};
#[cfg(target_os = "windows")]
use windows_registry::{Type, CURRENT_USER};

const APP_NAME: &str = "WindowsAppAutoLogin";
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

#[cfg(not(target_os = "windows"))]
fn build() -> anyhow::Result<auto_launch::AutoLaunch> {
    let app_path = current_launch_path()?;
    build_for_path(&app_path)
}

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

fn macos_launch_mode_for_path(_app_path: &str) -> MacOSLaunchMode {
    #[cfg(target_os = "macos")]
    {
        if _app_path.ends_with(".app") {
            return MacOSLaunchMode::AppleScript;
        }
    }

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
        return Ok(());
    }

    #[cfg(not(target_os = "windows"))]
    {
        if macos_launch_mode_for_path(&app_path) == MacOSLaunchMode::AppleScript {
            remove_launch_agent_file()?;
        }
        let auto = build_for_path(&app_path)?;
        if macos_launch_mode_for_path(&app_path) == MacOSLaunchMode::AppleScript
            && auto.is_enabled()?
            && !login_item_matches_path(&app_path)
        {
            let _ = auto.disable();
        }
        if macos_launch_mode_for_path(&app_path) == MacOSLaunchMode::LaunchAgent
            && auto.is_enabled()?
            && !launch_agent_matches_current_exe()
        {
            let _ = auto.disable();
            remove_launch_agent_file()?;
        }
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
        return Ok(());
    }

    #[cfg(not(target_os = "windows"))]
    {
        let auto = build()?;
        if auto.is_enabled()? {
            auto.disable()?;
        }
        remove_launch_agent_file()?;
        Ok(())
    }
}

pub(crate) fn is_enabled() -> bool {
    let Ok(app_path) = current_launch_path() else {
        return false;
    };

    #[cfg(target_os = "windows")]
    {
        return current_autostart_path_is_stable()
            && windows_registered_command_matches_path(&app_path)
            && windows_startup_approved_enabled();
    }

    #[cfg(not(target_os = "windows"))]
    {
        let enabled = build_for_path(&app_path)
            .and_then(|auto| Ok(auto.is_enabled()?))
            .unwrap_or(false);
        if !enabled || !current_autostart_path_is_stable() {
            return false;
        }

        if macos_launch_mode_for_path(&app_path) == MacOSLaunchMode::AppleScript {
            login_item_matches_path(&app_path)
        } else {
            launch_agent_matches_current_exe()
        }
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
        return Ok(());
    }

    #[cfg(not(target_os = "windows"))]
    {
        let auto = build()?;
        if current_launch_path()
            .map(|path| macos_launch_mode_for_path(&path) == MacOSLaunchMode::AppleScript)
            .unwrap_or(false)
        {
            remove_launch_agent_file()?;
        }
        if let Ok(app_path) = current_launch_path() {
            if macos_launch_mode_for_path(&app_path) == MacOSLaunchMode::AppleScript
                && auto.is_enabled()?
                && !login_item_matches_path(&app_path)
            {
                let _ = auto.disable();
            }
        }
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
fn login_item_matches_path(app_path: &str) -> bool {
    let expected = canonical_string(app_path);
    let script = format!(
        r#"tell application "System Events"
    set output to ""
    repeat with itemRef in (every login item whose name is "{}")
        try
            set output to output & (path of itemRef as string) & linefeed
        end try
    end repeat
    return output
end tell"#,
        applescript_string_contents(APP_NAME)
    );

    let Ok(output) = Command::new("/usr/bin/osascript")
        .arg("-e")
        .arg(script)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
    else {
        return false;
    };
    if !output.status.success() {
        return false;
    }

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .any(|path| canonical_string(path.trim()) == expected)
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn login_item_matches_path(_app_path: &str) -> bool {
    true
}

#[cfg(target_os = "macos")]
fn canonical_string(path: &str) -> String {
    std::fs::canonicalize(path)
        .unwrap_or_else(|_| PathBuf::from(path))
        .to_string_lossy()
        .to_string()
}

#[cfg(target_os = "macos")]
fn applescript_string_contents(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace(['\r', '\n'], " ")
}

#[cfg(target_os = "macos")]
fn launch_agent_path() -> Option<PathBuf> {
    dirs::home_dir().map(|home| {
        home.join("Library")
            .join("LaunchAgents")
            .join(format!("{APP_NAME}.plist"))
    })
}

#[cfg(target_os = "macos")]
fn launch_agent_matches_current_exe() -> bool {
    let Some(path) = launch_agent_path() else {
        return true;
    };
    if !path.exists() {
        return true;
    }

    let Ok(content) = std::fs::read_to_string(&path) else {
        return false;
    };
    let Ok(current_exe) = std::env::current_exe() else {
        return false;
    };
    let Some(program_path) = launch_agent_program_path(&content) else {
        return false;
    };

    if program_path == current_exe.to_string_lossy() {
        return true;
    }

    match (
        std::fs::canonicalize(current_exe),
        std::fs::canonicalize(&program_path),
    ) {
        (Ok(current), Ok(program)) => current == program,
        _ => false,
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn launch_agent_matches_current_exe() -> bool {
    true
}

#[cfg(target_os = "macos")]
fn remove_launch_agent_file() -> anyhow::Result<()> {
    if let Some(path) = launch_agent_path() {
        if path.exists() {
            std::fs::remove_file(path)?;
        }
    }
    Ok(())
}

fn ensure_stable_autostart_path(app_path: &str) -> anyhow::Result<()> {
    if is_transient_path(app_path) {
        anyhow::bail!("{}", stable_autostart_path_message());
    }
    Ok(())
}

fn stable_autostart_path_message() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "Open at Login cannot be enabled from a temporary or build folder. Move the app bundle to Applications first."
    }
    #[cfg(target_os = "windows")]
    {
        "Open at Login cannot be enabled from a temporary or build folder. Move the app to a stable install folder first."
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        "Open at Login cannot be enabled from a temporary or build folder. Move the app to a stable install folder first."
    }
}

fn current_autostart_path_is_stable() -> bool {
    current_launch_path()
        .map(|path| !is_transient_path(&path))
        .unwrap_or(false)
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AutostartPlatform {
    Macos,
    Windows,
    Other,
}

fn is_transient_path(path: &str) -> bool {
    is_transient_path_for_platform(path, current_autostart_platform())
}

fn current_autostart_platform() -> AutostartPlatform {
    #[cfg(target_os = "macos")]
    {
        return AutostartPlatform::Macos;
    }
    #[cfg(target_os = "windows")]
    {
        return AutostartPlatform::Windows;
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        AutostartPlatform::Other
    }
}

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

fn has_path_segment(path: &str, segment: &str) -> bool {
    path.split('/').any(|part| part == segment)
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

    if is_transient_path_for_platform(&app_path, AutostartPlatform::Windows)
        || !std::path::Path::new(&app_path).exists()
    {
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
fn launch_agent_program_path(content: &str) -> Option<String> {
    let program_args = content.split("<key>ProgramArguments</key>").nth(1)?;
    let start = program_args.find("<string>")? + "<string>".len();
    let rest = &program_args[start..];
    let end = rest.find("</string>")?;
    Some(unescape_plist_string(&rest[..end]))
}

#[cfg(target_os = "macos")]
fn unescape_plist_string(value: &str) -> String {
    value
        .replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn remove_launch_agent_file() -> anyhow::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_transient_path_allows_dist_artifact() {
        assert!(!is_transient_path_for_platform(
            r"C:\Users\me\repo\dist\WindowsAppAutoLogin-windows-x86_64\WindowsAppAutoLogin.exe",
            AutostartPlatform::Windows
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
    fn windows_transient_path_allows_stable_install_locations() {
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
