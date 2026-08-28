pub(crate) const APP_NAME: &str = env!("WAAL_APP_NAME");

#[cfg(any(target_os = "windows", test))]
const WINDOWS_SUPERVISOR_CARGO_BIN: &str = "windows-app-autologin";
#[cfg(any(target_os = "windows", test))]
const WINDOWS_FULL_UI_CARGO_BIN: &str = "windows-app-autologin-ui";
#[cfg(any(target_os = "windows", test))]
const WINDOWS_SUPERVISOR_CARGO_EXE: &str = "windows-app-autologin.exe";
#[cfg(any(target_os = "windows", test))]
const WINDOWS_FULL_UI_CARGO_EXE: &str = "windows-app-autologin-ui.exe";
#[cfg(any(target_os = "windows", test))]
const WINDOWS_SUPERVISOR_INSTALLED_EXE: &str = "WindowsAppAutoLogin.exe";
#[cfg(any(target_os = "windows", test))]
const WINDOWS_FULL_UI_INSTALLED_EXE: &str = "WindowsAppAutoLoginUI.exe";

#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WindowsBinaryRole {
    Supervisor,
    FullUi,
}

#[cfg(target_os = "windows")]
pub(crate) fn windows_binary_role() -> anyhow::Result<WindowsBinaryRole> {
    windows_binary_role_for_cargo_bin(env!("CARGO_BIN_NAME")).ok_or_else(|| {
        anyhow::anyhow!(
            "the Windows process has an unsupported Cargo binary identity: {}",
            env!("CARGO_BIN_NAME")
        )
    })
}

#[cfg(any(target_os = "windows", test))]
fn windows_binary_role_for_cargo_bin(cargo_bin: &str) -> Option<WindowsBinaryRole> {
    match cargo_bin {
        WINDOWS_SUPERVISOR_CARGO_BIN => Some(WindowsBinaryRole::Supervisor),
        WINDOWS_FULL_UI_CARGO_BIN => Some(WindowsBinaryRole::FullUi),
        _ => None,
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn windows_full_ui_executable_path() -> anyhow::Result<std::path::PathBuf> {
    if windows_binary_role()? != WindowsBinaryRole::Supervisor {
        anyhow::bail!("only the Windows supervisor may resolve the full UI helper");
    }
    windows_counterpart_executable_path(
        &std::env::current_exe()?,
        WindowsBinaryRole::Supervisor,
        WindowsBinaryRole::FullUi,
    )
}

#[cfg(target_os = "windows")]
pub(crate) fn windows_supervisor_executable_path() -> anyhow::Result<std::path::PathBuf> {
    let current = std::env::current_exe()?;
    match windows_binary_role()? {
        WindowsBinaryRole::Supervisor => canonical_regular_windows_executable(&current),
        WindowsBinaryRole::FullUi => windows_counterpart_executable_path(
            &current,
            WindowsBinaryRole::FullUi,
            WindowsBinaryRole::Supervisor,
        ),
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn windows_local_ipc_peer_path_is_trusted(
    current_path: &std::path::Path,
    peer_path: &std::path::Path,
) -> bool {
    let Ok(current_path) = canonical_regular_windows_executable(current_path) else {
        return false;
    };
    let Ok(peer_path) = canonical_regular_windows_executable(peer_path) else {
        return false;
    };
    if current_path == peer_path {
        return true;
    }

    let Ok(current_role) = windows_binary_role() else {
        return false;
    };
    let peer_role = match current_role {
        WindowsBinaryRole::Supervisor => WindowsBinaryRole::FullUi,
        WindowsBinaryRole::FullUi => WindowsBinaryRole::Supervisor,
    };
    windows_counterpart_path(&current_path, current_role, peer_role)
        .is_some_and(|expected| expected == peer_path)
}

#[cfg(any(target_os = "windows", test))]
fn windows_counterpart_path(
    current_path: &std::path::Path,
    current_role: WindowsBinaryRole,
    counterpart_role: WindowsBinaryRole,
) -> Option<std::path::PathBuf> {
    if current_role == counterpart_role {
        return None;
    }
    let current_leaf = current_path.file_name()?.to_str()?;
    let counterpart_leaf = match (current_role, counterpart_role) {
        (WindowsBinaryRole::Supervisor, WindowsBinaryRole::FullUi)
            if current_leaf.eq_ignore_ascii_case(WINDOWS_SUPERVISOR_CARGO_EXE) =>
        {
            WINDOWS_FULL_UI_CARGO_EXE
        }
        (WindowsBinaryRole::Supervisor, WindowsBinaryRole::FullUi)
            if current_leaf.eq_ignore_ascii_case(WINDOWS_SUPERVISOR_INSTALLED_EXE) =>
        {
            WINDOWS_FULL_UI_INSTALLED_EXE
        }
        (WindowsBinaryRole::FullUi, WindowsBinaryRole::Supervisor)
            if current_leaf.eq_ignore_ascii_case(WINDOWS_FULL_UI_CARGO_EXE) =>
        {
            WINDOWS_SUPERVISOR_CARGO_EXE
        }
        (WindowsBinaryRole::FullUi, WindowsBinaryRole::Supervisor)
            if current_leaf.eq_ignore_ascii_case(WINDOWS_FULL_UI_INSTALLED_EXE) =>
        {
            WINDOWS_SUPERVISOR_INSTALLED_EXE
        }
        _ => return None,
    };
    Some(current_path.with_file_name(counterpart_leaf))
}

#[cfg(target_os = "windows")]
fn windows_counterpart_executable_path(
    current_path: &std::path::Path,
    current_role: WindowsBinaryRole,
    counterpart_role: WindowsBinaryRole,
) -> anyhow::Result<std::path::PathBuf> {
    let current_path = canonical_regular_windows_executable(current_path)?;
    let candidate = windows_counterpart_path(&current_path, current_role, counterpart_role)
        .ok_or_else(|| anyhow::anyhow!("the Windows executable has an unexpected file name"))?;
    let candidate = canonical_regular_windows_executable(&candidate)?;
    if candidate.parent() != current_path.parent() {
        anyhow::bail!("the Windows companion executable is not an exact sibling");
    }
    Ok(candidate)
}

#[cfg(target_os = "windows")]
fn canonical_regular_windows_executable(
    path: &std::path::Path,
) -> anyhow::Result<std::path::PathBuf> {
    use std::fs::OpenOptions;
    use std::os::windows::fs::MetadataExt;
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

    if !path.is_absolute() {
        anyhow::bail!("the Windows executable path is not absolute");
    }

    // Hold every component open without FILE_SHARE_DELETE while resolving the
    // final path. This both rejects ancestor junctions/symlinks and prevents a
    // checked component from being swapped before canonicalization completes.
    let mut component_handles = Vec::new();
    let mut components = path.ancestors().collect::<Vec<_>>();
    components.reverse();
    for (index, component) in components.iter().enumerate() {
        let handle = OpenOptions::new()
            .access_mode(0)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(component)?;
        let metadata = handle.metadata()?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            anyhow::bail!("the Windows executable path contains a reparse component");
        }
        let is_leaf = index + 1 == components.len();
        if (is_leaf && !metadata.file_type().is_file())
            || (!is_leaf && !metadata.file_type().is_dir())
        {
            anyhow::bail!("the Windows executable path has an unexpected component type");
        }
        component_handles.push(handle);
    }

    let canonical = path.canonicalize()?;
    drop(component_handles);
    Ok(canonical)
}

#[cfg(target_os = "macos")]
const DEVELOPMENT_MACOS_BUNDLE_ID: &str = "obcardinal.windows-app-autologin";

#[cfg(target_os = "macos")]
pub(crate) const TRUSTED_MACOS_BUNDLE_PATH: &str = env!("WAAL_TRUSTED_MACOS_BUNDLE_PATH");

#[cfg(target_os = "macos")]
pub(crate) const DEVELOPMENT_MACOS_BUNDLE_PATH: &str = env!("WAAL_DEVELOPMENT_MACOS_BUNDLE_PATH");

#[cfg(target_os = "macos")]
pub(crate) fn macos_bundle_id() -> &'static str {
    env!("WAAL_TRUSTED_APP_BUNDLE_ID")
}

#[cfg(target_os = "macos")]
pub(crate) fn macos_team_id() -> Option<&'static str> {
    let team_id = env!("WAAL_TRUSTED_APP_TEAM_ID").trim();
    (!team_id.is_empty()).then_some(team_id)
}

#[cfg(target_os = "macos")]
pub(crate) fn macos_development_identity() -> bool {
    macos_bundle_id() == DEVELOPMENT_MACOS_BUNDLE_ID && macos_team_id().is_none()
}

#[cfg(test)]
mod tests {
    use super::{windows_binary_role_for_cargo_bin, windows_counterpart_path, WindowsBinaryRole};
    use std::path::Path;

    #[test]
    fn windows_binary_roles_are_fixed_to_the_two_declared_cargo_bins() {
        assert_eq!(
            windows_binary_role_for_cargo_bin("windows-app-autologin"),
            Some(WindowsBinaryRole::Supervisor)
        );
        assert_eq!(
            windows_binary_role_for_cargo_bin("windows-app-autologin-ui"),
            Some(WindowsBinaryRole::FullUi)
        );
        assert_eq!(windows_binary_role_for_cargo_bin("copied-helper"), None);
    }

    #[test]
    fn windows_companion_mapping_accepts_only_fixed_cargo_and_installed_siblings() {
        assert_eq!(
            windows_counterpart_path(
                Path::new("C:/build/windows-app-autologin.exe"),
                WindowsBinaryRole::Supervisor,
                WindowsBinaryRole::FullUi,
            )
            .as_deref(),
            Some(Path::new("C:/build/windows-app-autologin-ui.exe"))
        );
        assert_eq!(
            windows_counterpart_path(
                Path::new("C:/Program Files/WindowsAppAutoLogin/WindowsAppAutoLogin.exe"),
                WindowsBinaryRole::Supervisor,
                WindowsBinaryRole::FullUi,
            )
            .as_deref(),
            Some(Path::new(
                "C:/Program Files/WindowsAppAutoLogin/WindowsAppAutoLoginUI.exe"
            ))
        );
        assert_eq!(
            windows_counterpart_path(
                Path::new("C:/Program Files/WindowsAppAutoLogin/WindowsAppAutoLoginUI.exe"),
                WindowsBinaryRole::FullUi,
                WindowsBinaryRole::Supervisor,
            )
            .as_deref(),
            Some(Path::new(
                "C:/Program Files/WindowsAppAutoLogin/WindowsAppAutoLogin.exe"
            ))
        );
        assert!(windows_counterpart_path(
            Path::new("C:/Temp/renamed.exe"),
            WindowsBinaryRole::Supervisor,
            WindowsBinaryRole::FullUi,
        )
        .is_none());
        assert!(windows_counterpart_path(
            Path::new("C:/build/windows-app-autologin.exe"),
            WindowsBinaryRole::Supervisor,
            WindowsBinaryRole::Supervisor,
        )
        .is_none());
    }

    #[test]
    fn windows_executable_resolution_checks_every_ancestor_before_canonicalization() {
        let implementation = include_str!("app_identity.rs");
        let resolver = implementation
            .split("fn canonical_regular_windows_executable(")
            .nth(1)
            .and_then(|tail| tail.split("#[cfg(target_os = \"macos\")]").next())
            .unwrap();

        assert!(resolver.contains("path.ancestors().collect::<Vec<_>>()"));
        assert!(resolver.contains("FILE_FLAG_OPEN_REPARSE_POINT"));
        assert!(resolver.contains("FILE_ATTRIBUTE_REPARSE_POINT"));
        assert!(resolver.contains(".share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)"));
        assert!(
            resolver.find("component_handles.push(handle)").unwrap()
                < resolver.find("path.canonicalize()?").unwrap()
        );
        assert!(
            resolver.find("path.canonicalize()?").unwrap()
                < resolver.find("drop(component_handles)").unwrap()
        );
    }
}
