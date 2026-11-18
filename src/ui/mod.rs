pub(crate) mod accounts;
#[cfg(target_os = "macos")]
pub(super) mod iphone_sign_in;
#[cfg(target_os = "macos")]
mod iphone_setup_guide;
pub(crate) mod diagnose;
pub(crate) mod settings;
#[cfg(target_os = "macos")]
pub(crate) mod telegram;
pub(crate) mod theme;
pub(crate) mod toggle;
