use anyhow::{ensure, Context, Result};
use uuid::Uuid;
use windows::core::HSTRING;
use windows::Foundation::Uri;
use windows::System::{Launcher, LauncherOptions};
use windows::Win32::System::WinRT::{RoInitialize, RoUninitialize, RO_INIT_MULTITHREADED};

const WINDOWS_APP_FAMILY: &str = "MicrosoftCorporationII.Windows365_8wekyb3d8bbwe";

struct LauncherApartment;

impl LauncherApartment {
    fn initialize() -> Result<Self> {
        unsafe { RoInitialize(RO_INIT_MULTITHREADED) }
            .context("Could not initialize the Windows App launcher.")?;
        Ok(Self)
    }
}

impl Drop for LauncherApartment {
    fn drop(&mut self) {
        unsafe { RoUninitialize() };
    }
}

fn resource_id(value: &str) -> Option<Uuid> {
    let id = Uuid::try_parse(value.trim()).ok()?;
    (!id.is_nil()).then_some(id)
}

pub(crate) fn validate_target(value: &str) -> bool {
    resource_id(value).is_some()
}

fn connection_uri(resource: Uuid, username: &str) -> Result<Uri> {
    let username = username.trim();
    let valid_upn = username.split_once('@').is_some_and(|(user, domain)| {
        !user.is_empty() && !domain.is_empty() && !domain.contains('@')
    }) && !username
        .chars()
        .any(|c| c.is_whitespace() || c.is_control());
    ensure!(
        valid_upn,
        "Enter the account’s work email before opening its desktop."
    );

    let user = Uri::EscapeComponent(&HSTRING::from(username))?;
    Uri::CreateUri(&HSTRING::from(format!(
        "ms-avd:connect?resourceid={resource}&user={user}"
    )))
    .context("Could not create the Azure Virtual Desktop connection link.")
}

/// Called on the launch worker so waiting for Windows to dispatch the URI leaves the UI responsive.
pub(crate) fn open_device(value: &str, username: &str) -> Result<()> {
    let resource =
        resource_id(value).context("Enter a valid Azure Virtual Desktop resource ID.")?;
    let _apartment = LauncherApartment::initialize()?;
    let uri = connection_uri(resource, username)?;
    let options = LauncherOptions::new()?;
    options.SetTargetApplicationPackageFamilyName(&HSTRING::from(WINDOWS_APP_FAMILY))?;
    let launched = Launcher::LaunchUriWithOptionsAsync(&uri, &options)
        .and_then(|operation| operation.join())
        .context("Could not open the desktop in Microsoft Windows App.")?;
    ensure!(
        launched,
        "Install or update Microsoft Windows App to open this Azure Virtual Desktop resource."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launch_target_requires_a_resource_id() {
        assert!(validate_target(" 1638e073-63b2-46d8-bd84-ea02ea905467 "));
        for other in [
            "",
            "desktop.example.com",
            "00000000-0000-0000-0000-000000000000",
            "ms-avd:connect?resourceid=1638e073-63b2-46d8-bd84-ea02ea905467",
        ] {
            assert!(!validate_target(other));
        }
    }

    #[test]
    fn only_the_selected_accounts_upn_and_resource_are_in_the_link() {
        let _apartment = LauncherApartment::initialize().unwrap();
        let resource = Uuid::from_u128(1);
        let link = connection_uri(resource, "user+external@example.com").unwrap();
        let pairs = link.QueryParsed().unwrap();
        assert_eq!(
            pairs.GetFirstValueByName(&"resourceid".into()).unwrap(),
            resource.to_string().as_str()
        );
        assert_eq!(
            pairs.GetFirstValueByName(&"user".into()).unwrap(),
            "user+external@example.com"
        );
        assert!(connection_uri(resource, "").is_err());
    }
}
