#[path = "macos_device_catalog.rs"]
mod catalog;
pub(super) use catalog::verify_card_identity_in;
pub(crate) use catalog::{saved_devices, saved_remote_pc, SavedDevice};
