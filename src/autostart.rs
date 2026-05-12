use auto_launch::{AutoLaunchBuilder, MacOSLaunchMode};
#[cfg(target_os = "macos")]
use std::path::PathBuf;
#[cfg(target_os = "macos")]
use std::process::{Command, Stdio};

const APP_NAME: &str = "WindowsAppAutoLogin";

fn build() -> anyhow::Result<auto_launch::AutoLaunch> {
    let app_path = current_launch_path()?;
    build_for_path(&app_path)
}

fn build_for_path(app_path: &str) -> anyhow::Result<auto_launch::AutoLaunch> {
    let auto = AutoLaunchBuilder::new()
        .set_app_name(APP_NAME)
        .set_app_path(app_path)
        .set_macos_launch_mode(macos_launch_mode_for_path(app_path))
        .set_bundle_identifiers(&["dev.codex.windows-app-autologin"])
        .build()?;

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

fn macos_launch_mode_for_path(app_path: &str) -> MacOSLaunchMode {
    #[cfg(target_os = "macos")]
    {
        if app_path.ends_with(".app") {
            return MacOSLaunchMode::AppleScript;
        }
    }

    MacOSLaunchMode::LaunchAgent
}

fn enable() -> anyhow::Result<()> {
    let app_path = current_launch_path()?;
    ensure_stable_autostart_path(&app_path)?;
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

fn disable() -> anyhow::Result<()> {
    let auto = build()?;
    if auto.is_enabled()? {
        auto.disable()?;
    }
    remove_launch_agent_file()?;
    Ok(())
}

pub(crate) fn is_enabled() -> bool {
    let Ok(app_path) = current_launch_path() else {
        return false;
    };
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

pub(crate) fn set_enabled(enabled: bool) -> anyhow::Result<()> {
    if enabled {
        enable()
    } else {
        disable()
    }
}

pub(crate) fn cleanup_stale() -> anyhow::Result<()> {
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

#[cfg(not(target_os = "macos"))]
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

#[cfg(not(target_os = "macos"))]
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
        anyhow::bail!(
            "Open at Login cannot be enabled from a temporary or build folder. Move the app bundle to Applications first."
        );
    }
    Ok(())
}

fn current_autostart_path_is_stable() -> bool {
    current_launch_path()
        .map(|path| !is_transient_path(&path))
        .unwrap_or(false)
}

fn is_transient_path(path: &str) -> bool {
    path.contains("/target/")
        || path.contains("/dist/")
        || path.starts_with("/tmp/")
        || path.starts_with("/private/tmp/")
        || path.contains("/var/folders/")
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

#[cfg(not(target_os = "macos"))]
fn remove_launch_agent_file() -> anyhow::Result<()> {
    Ok(())
}
