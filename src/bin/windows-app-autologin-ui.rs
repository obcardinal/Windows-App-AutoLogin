#![cfg_attr(
    all(target_os = "windows", not(debug_assertions)),
    windows_subsystem = "windows"
)]

#[cfg(target_os = "windows")]
#[path = "../main.rs"]
#[allow(unused_attributes)]
mod application;

#[cfg(target_os = "windows")]
pub(crate) use application::windows_ui;
#[cfg(target_os = "windows")]
pub(crate) use application::{
    app, app_identity, autologin, autostart, background, config, debug_fill, models, monitor,
    private_permissions, single_instance, storage, tray, ui, user_paths,
};

#[cfg(target_os = "windows")]
fn main() -> anyhow::Result<()> {
    application::main()
}

#[cfg(not(target_os = "windows"))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("the Windows full UI helper is unavailable on this platform")
}
