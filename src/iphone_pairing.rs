//! Open Apple's device pairing interface for the active Xcode installation.
use objc2_foundation::{NSBundle, NSString};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const XCODE_ID: &str = "com.apple.dt.Xcode";
const DEVICE_HUB_ID: &str = "com.apple.dt.Devices";

pub(crate) fn open_pairing_window() -> Result<(), String> {
    let active = Command::new("/usr/bin/xcode-select")
        .arg("--print-path")
        .env_remove("DEVELOPER_DIR")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok());
    let app = active.as_deref().and_then(|path| {
        pairing_app(Path::new(path.trim_end()), |candidate, id| {
            candidate
                .to_str()
                .and_then(|p| NSBundle::bundleWithPath(&NSString::from_str(p)))
                .and_then(|bundle| bundle.bundleIdentifier())
                .is_some_and(|identifier| identifier.to_string() == id)
        })
    });
    let mut open = Command::new("/usr/bin/open");
    match &app {
        Some(path) => open.arg(path),
        None => open.args(["-b", XCODE_ID]),
    };
    let opened = open
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if !opened {
        return Err(
            "Couldn’t open device pairing. Install Xcode and open it to finish setup.".into(),
        );
    }
    if app.is_none() {
        return Err("In Xcode → Settings → Locations, select your Xcode under Command Line Tools, then try again.".into());
    }
    Ok(())
}

fn pairing_app(
    developer_dir: &Path,
    bundle_matches: impl Fn(&Path, &str) -> bool,
) -> Option<PathBuf> {
    if !developer_dir.is_absolute() || !developer_dir.ends_with("Contents/Developer") {
        return None;
    }
    let xcode = developer_dir.parent()?.parent()?;
    if xcode.extension()? != "app" || !bundle_matches(xcode, XCODE_ID) {
        return None;
    }
    let hub = xcode.join("Contents/Applications/DeviceHub.app");
    Some(if bundle_matches(&hub, DEVICE_HUB_ID) {
        hub
    } else {
        xcode.to_owned()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opens_the_selected_xcode_installations_device_ui() {
        let xcode = Path::new("/Volumes/Tools/Xcode Beta.app");
        let developer = xcode.join("Contents/Developer");
        let hub = xcode.join("Contents/Applications/DeviceHub.app");
        for has_hub in [false, true] {
            assert_eq!(
                pairing_app(&developer, |path, id| {
                    (path == xcode && id == XCODE_ID)
                        || (path == hub && id == DEVICE_HUB_ID && has_hub)
                }),
                Some(if has_hub { hub.clone() } else { xcode.into() })
            );
        }
        assert!(pairing_app(&developer, |_, _| false).is_none());
    }

    #[test]
    fn command_line_tools_and_relative_paths_require_selecting_xcode() {
        for path in [
            "/Library/Developer/CommandLineTools",
            "/Tools/Contents/Developer",
            "Xcode.app/Contents/Developer",
        ] {
            assert!(pairing_app(Path::new(path), |_, _| true).is_none());
        }
    }
}
