use std::{
    env,
    error::Error,
    fs,
    path::{Path, PathBuf},
};

const DEVELOPMENT_MACOS_BUNDLE_ID: &str = "dev.codex.windows-app-autologin";
const PRODUCTION_APP_NAME: &str = "WindowsAppAutoLogin";
const DIAGNOSTICS_APP_NAME: &str = "WindowsAppAutoLoginDiagnostics";

fn main() {
    let icon = Path::new("assets/icon.png");
    let tray_icon = Path::new("assets/icon_tray.png");
    let inter_font = Path::new("assets/fonts/InterVariable.ttf");

    println!("cargo:rerun-if-changed={}", icon.display());
    println!("cargo:rerun-if-changed={}", tray_icon.display());
    println!("cargo:rerun-if-changed={}", inter_font.display());
    println!("cargo:rerun-if-env-changed=WAAL_RELEASE_BUNDLE_ID");
    println!("cargo:rerun-if-env-changed=WAAL_DIAGNOSTICS_BUNDLE_ID");
    println!("cargo:rerun-if-env-changed=WAAL_MACOS_TEAM_ID");
    println!("cargo:rerun-if-env-changed=WAAL_DEVELOPMENT_RELEASE");
    println!("cargo:rerun-if-env-changed=WAAL_EMBED_DEVELOPMENT_MACOS_BUNDLE_PATH");
    println!("cargo:rerun-if-env-changed=WAAL_DEVELOPMENT_MACOS_BUNDLE_PATH");
    println!("cargo:rustc-check-cfg=cfg(waal_release_profile)");
    if env::var("PROFILE").as_deref() == Ok("release") {
        println!("cargo:rustc-cfg=waal_release_profile");
    }
    embed_windows_resources(icon).expect("embed Windows resources");

    let macos_identity = macos_identity();
    let macos_bundle_id = macos_identity.bundle_id.clone();
    let macos_team_id = macos_team_id();
    let app_name = app_name();
    let trusted_bundle_path = format!("/Applications/{app_name}.app");
    let development_bundle_path =
        development_bundle_path(&macos_identity, &macos_team_id, app_name);
    println!("cargo:rustc-env=WAAL_APP_NAME={app_name}");
    println!("cargo:rustc-env=WAAL_TRUSTED_MACOS_BUNDLE_PATH={trusted_bundle_path}");
    println!("cargo:rustc-env=WAAL_DEVELOPMENT_MACOS_BUNDLE_PATH={development_bundle_path}");
    println!("cargo:rustc-env=WAAL_TRUSTED_APP_BUNDLE_ID={macos_bundle_id}");
    println!("cargo:rustc-env=WAAL_TRUSTED_APP_TEAM_ID={macos_team_id}");

    let fingerprint = [icon, tray_icon]
        .into_iter()
        .map(asset_fingerprint)
        .collect::<Vec<_>>()
        .join(":");

    println!("cargo:rustc-env=WAAL_ICON_ASSET_FINGERPRINT={fingerprint}");
    write_build_metadata(&macos_identity, &macos_team_id);
}

fn embed_windows_resources(icon: &Path) -> Result<(), Box<dyn Error>> {
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return Ok(());
    }

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").ok_or("OUT_DIR is set")?);
    let ico_path = out_dir.join("WindowsAppAutoLogin.ico");
    let rc_path = out_dir.join("WindowsAppAutoLogin.rc");
    write_windows_icon(icon, &ico_path)?;

    let rc = format!("1 ICON \"{}\"\n", rc_escaped_path(&ico_path));
    fs::write(&rc_path, rc)?;
    let result = embed_resource::compile(&rc_path, embed_resource::NONE);
    let result = if env::var("PROFILE").as_deref() == Ok("release") {
        result.manifest_required()
    } else {
        result.manifest_optional()
    };
    result.map_err(|err| format!("failed to compile Windows resources: {err}"))?;
    Ok(())
}

fn write_windows_icon(png_path: &Path, ico_path: &Path) -> Result<(), Box<dyn Error>> {
    let icon = image::open(png_path)?;
    let sizes = [16, 24, 32, 48, 64, 128, 256];
    let mut frames = Vec::with_capacity(sizes.len());
    for size in sizes {
        let rgba = icon
            .resize_exact(size, size, image::imageops::FilterType::Lanczos3)
            .to_rgba8();
        frames.push(image::codecs::ico::IcoFrame::as_png(
            rgba.as_raw(),
            size,
            size,
            image::ColorType::Rgba8.into(),
        )?);
    }
    let ico = fs::File::create(ico_path)?;
    image::codecs::ico::IcoEncoder::new(ico).encode_images(&frames)?;
    if fs::metadata(ico_path)?.len() == 0 {
        return Err(format!("generated Windows icon is empty: {}", ico_path.display()).into());
    }
    Ok(())
}

fn rc_escaped_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "\\\\")
}

struct MacosIdentity {
    bundle_id: String,
    production_bundle_id: String,
    non_production_identity: bool,
}

fn build_metadata(
    macos_identity: &MacosIdentity,
    macos_team_id: &str,
    debug_assertions: bool,
) -> String {
    let artifact_kind = if env::var_os("CARGO_FEATURE_RELEASE_DIAGNOSTICS").is_some() {
        "release-diagnostics"
    } else if macos_identity.non_production_identity {
        "development"
    } else {
        "release"
    };
    format!(
        "WAAL_BUILD_METADATA_V1;artifact-kind={};profile={};debug-assertions={};debug-fill={};dev-tools={};diagnostics-ui={};release-diagnostics={};macos-bundle-id={};production-macos-bundle-id={};non-production-macos-identity={};macos-team-id={};",
        artifact_kind,
        env::var("PROFILE").unwrap_or_else(|_| "unknown".to_string()),
        debug_assertions,
        env::var_os("CARGO_FEATURE_DEBUG_FILL").is_some(),
        env::var_os("CARGO_FEATURE_DEV_TOOLS").is_some(),
        env::var_os("CARGO_FEATURE_DIAGNOSTICS_UI").is_some(),
        env::var_os("CARGO_FEATURE_RELEASE_DIAGNOSTICS").is_some(),
        macos_identity.bundle_id.as_str(),
        macos_identity.production_bundle_id.as_str(),
        macos_identity.non_production_identity,
        macos_team_id,
    )
}

fn write_build_metadata(macos_identity: &MacosIdentity, macos_team_id: &str) {
    // Keep the marker separated from neighboring printable constants after LTO so
    // release packaging can reliably extract it with `strings`.
    let debug_metadata = format!(
        "\0{}\0",
        build_metadata(macos_identity, macos_team_id, true)
    );
    let release_metadata = format!(
        "\0{}\0",
        build_metadata(macos_identity, macos_team_id, false)
    );
    let debug_bytes = rust_byte_array(&debug_metadata);
    let release_bytes = rust_byte_array(&release_metadata);
    let source = format!(
        r#"#[cfg(target_os = "macos")]
#[used]
#[cfg(debug_assertions)]
#[cfg_attr(target_os = "macos", unsafe(link_section = "__TEXT,__const"))]
static WAAL_BUILD_METADATA_DEBUG: [u8; {}] = [{}];

#[cfg(target_os = "macos")]
#[used]
#[cfg(not(debug_assertions))]
#[cfg_attr(target_os = "macos", unsafe(link_section = "__TEXT,__const"))]
static WAAL_BUILD_METADATA_RELEASE: [u8; {}] = [{}];
"#,
        debug_metadata.len(),
        debug_bytes,
        release_metadata.len(),
        release_bytes
    );

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by Cargo"));
    fs::write(out_dir.join("waal_build_metadata.rs"), source)
        .expect("write WAAL build metadata source");
}

fn rust_byte_array(value: &str) -> String {
    value
        .as_bytes()
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn macos_identity() -> MacosIdentity {
    let release_diagnostics = env::var_os("CARGO_FEATURE_RELEASE_DIAGNOSTICS").is_some();
    let release_profile = is_macos_release_profile();
    let development_release = development_release_allowed();
    if release_diagnostics {
        let Some(bundle_id) = trimmed_env("WAAL_DIAGNOSTICS_BUNDLE_ID") else {
            if release_profile {
                panic!("WAAL_DIAGNOSTICS_BUNDLE_ID must be set for release diagnostics builds");
            }
            return MacosIdentity {
                bundle_id: DEVELOPMENT_MACOS_BUNDLE_ID.to_string(),
                production_bundle_id: trimmed_env("WAAL_RELEASE_BUNDLE_ID").unwrap_or_default(),
                non_production_identity: true,
            };
        };
        validate_non_development_bundle_id(&bundle_id, "WAAL_DIAGNOSTICS_BUNDLE_ID");
        let Some(release_bundle_id) = trimmed_env("WAAL_RELEASE_BUNDLE_ID") else {
            if release_profile {
                panic!(
                    "WAAL_RELEASE_BUNDLE_ID must be set for release diagnostics identity separation"
                );
            }
            return MacosIdentity {
                bundle_id,
                production_bundle_id: String::new(),
                non_production_identity: true,
            };
        };
        validate_non_development_bundle_id(&release_bundle_id, "WAAL_RELEASE_BUNDLE_ID");
        if bundle_id == release_bundle_id {
            panic!(
                "WAAL_DIAGNOSTICS_BUNDLE_ID must differ from WAAL_RELEASE_BUNDLE_ID for release diagnostics artifacts"
            );
        }
        return MacosIdentity {
            bundle_id,
            production_bundle_id: release_bundle_id,
            non_production_identity: true,
        };
    }

    let Some(bundle_id) = trimmed_env("WAAL_RELEASE_BUNDLE_ID") else {
        if release_profile && !development_release {
            panic!(
                "WAAL_RELEASE_BUNDLE_ID must be set for macOS release builds; use WAAL_DEVELOPMENT_RELEASE=1 only for local non-production release-profile bundles"
            );
        }
        return MacosIdentity {
            bundle_id: DEVELOPMENT_MACOS_BUNDLE_ID.to_string(),
            production_bundle_id: String::new(),
            non_production_identity: true,
        };
    };
    validate_non_development_bundle_id(&bundle_id, "WAAL_RELEASE_BUNDLE_ID");
    MacosIdentity {
        bundle_id: bundle_id.clone(),
        production_bundle_id: bundle_id,
        non_production_identity: false,
    }
}

fn validate_non_development_bundle_id(bundle_id: &str, env_name: &str) {
    if bundle_id == DEVELOPMENT_MACOS_BUNDLE_ID {
        panic!("{env_name} must not use the development bundle identifier");
    }
    if !valid_bundle_id(bundle_id) {
        panic!("{env_name} is not a valid bundle identifier");
    }
}

fn macos_team_id() -> String {
    let Some(team_id) = trimmed_env("WAAL_MACOS_TEAM_ID") else {
        if is_macos_release_profile() && !development_release_allowed() {
            panic!(
                "WAAL_MACOS_TEAM_ID must be set for macOS release builds; use WAAL_DEVELOPMENT_RELEASE=1 only for local non-production release-profile bundles"
            );
        }
        return String::new();
    };
    if !valid_team_id(&team_id) {
        panic!("WAAL_MACOS_TEAM_ID is not a valid Apple Team ID");
    }
    team_id
}

fn is_macos_release_profile() -> bool {
    env::var("PROFILE").as_deref() == Ok("release")
        && env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos")
}

fn development_release_allowed() -> bool {
    truthy_env("WAAL_DEVELOPMENT_RELEASE")
}

fn development_bundle_path_embedding_allowed() -> bool {
    truthy_env("WAAL_EMBED_DEVELOPMENT_MACOS_BUNDLE_PATH")
}

fn truthy_env(name: &str) -> bool {
    matches!(
        trimmed_env(name).as_deref(),
        Some("1" | "true" | "TRUE" | "yes" | "YES")
    )
}

fn development_bundle_path(
    macos_identity: &MacosIdentity,
    macos_team_id: &str,
    app_name: &str,
) -> String {
    if macos_identity.bundle_id != DEVELOPMENT_MACOS_BUNDLE_ID
        || !macos_team_id.is_empty()
        || !development_bundle_path_embedding_allowed()
    {
        return String::new();
    }

    if let Some(configured_path) = trimmed_env("WAAL_DEVELOPMENT_MACOS_BUNDLE_PATH") {
        return configured_path;
    }

    PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set"))
        .join("dist")
        .join(format!("{app_name}.app"))
        .to_string_lossy()
        .to_string()
}

fn app_name() -> &'static str {
    if env::var_os("CARGO_FEATURE_RELEASE_DIAGNOSTICS").is_some() {
        DIAGNOSTICS_APP_NAME
    } else {
        PRODUCTION_APP_NAME
    }
}

fn trimmed_env(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn valid_bundle_id(value: &str) -> bool {
    value.len() <= 255
        && value.contains('.')
        && value
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(valid_bundle_id_byte))
}

fn valid_bundle_id_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-'
}

fn valid_team_id(value: &str) -> bool {
    value.len() == 10
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
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
