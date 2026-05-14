pub(crate) const APP_NAME: &str = env!("WAAL_APP_NAME");

#[cfg(target_os = "macos")]
const DEVELOPMENT_MACOS_BUNDLE_ID: &str = "dev.codex.windows-app-autologin";

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
