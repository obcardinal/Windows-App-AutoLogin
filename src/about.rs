#[cfg(target_os = "macos")]
#[path = "about/macos.rs"]
mod platform;
#[cfg(target_os = "windows")]
#[path = "about/windows.rs"]
mod platform;

const APP_NAME: &str = "Windows App AutoLogin";
const VERSION: &str = env!("CARGO_PKG_VERSION");
const AUTHOR: &str = "Oleksandr Beschasnyi";
const HOMEPAGE: &str = "https://obcardinal.com";
#[cfg(target_os = "windows")]
const APP_ICON: &[u8] = include_bytes!("../assets/icon.png");

struct ContactLink {
    label: &'static str,
    url: &'static str,
    icon_svg: &'static [u8],
}

const CONTACTS: &[ContactLink] = &[
    ContactLink {
        label: "Telegram",
        url: "https://t.me/ob_cardinal",
        icon_svg: include_bytes!("../assets/about/contact-telegram.svg"),
    },
    ContactLink {
        label: "X",
        url: "https://x.com/obcardinal",
        icon_svg: include_bytes!("../assets/about/contact-x.svg"),
    },
    ContactLink {
        label: "LinkedIn",
        url: "https://linkedin.com/in/oleksandr-beschasnyi",
        icon_svg: include_bytes!("../assets/about/contact-linkedin.svg"),
    },
    ContactLink {
        label: "GitHub",
        url: "https://github.com/obcardinal",
        icon_svg: include_bytes!("../assets/about/contact-github.svg"),
    },
    ContactLink {
        label: "Email",
        url: "mailto:ob.cardinal@icloud.com",
        icon_svg: include_bytes!("../assets/about/contact-email.svg"),
    },
];

pub(crate) fn show() -> anyhow::Result<()> {
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    return platform::show();

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    anyhow::bail!("About is available on macOS and Windows");
}
