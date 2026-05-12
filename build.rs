use std::{fs, path::Path};

fn main() {
    let icon = Path::new("assets/icon.png");
    let tray_icon = Path::new("assets/icon_tray.png");

    println!("cargo:rerun-if-changed={}", icon.display());
    println!("cargo:rerun-if-changed={}", tray_icon.display());

    let fingerprint = [icon, tray_icon]
        .into_iter()
        .map(asset_fingerprint)
        .collect::<Vec<_>>()
        .join(":");

    println!("cargo:rustc-env=WAAL_ICON_ASSET_FINGERPRINT={fingerprint}");
}

fn asset_fingerprint(path: &Path) -> String {
    let bytes = fs::read(path).unwrap_or_default();
    format!("{}-{:016x}", path.display(), fnv1a64(&bytes))
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}
