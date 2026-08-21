use std::{
    env,
    error::Error,
    fs,
    path::{Path, PathBuf},
};

const DEVELOPMENT_MACOS_BUNDLE_ID: &str = "obcardinal.windows-app-autologin";
const PRODUCTION_APP_NAME: &str = "WindowsAppAutoLogin";
const DIAGNOSTICS_APP_NAME: &str = "WindowsAppAutoLoginDiagnostics";
const RELEASE_GIT_COMMIT_ENV: &str = "WAAL_RELEASE_GIT_COMMIT";
const RELEASE_GIT_TREE_ENV: &str = "WAAL_RELEASE_GIT_TREE";
const RELEASE_CARGO_VERSION_ENV: &str = "WAAL_RELEASE_CARGO_VERSION";
const RELEASE_RUSTC_VERSION_ENV: &str = "WAAL_RELEASE_RUSTC_VERSION";
const RELEASE_CARGO_SHA256_ENV: &str = "WAAL_RELEASE_CARGO_SHA256";
const RELEASE_RUSTC_SHA256_ENV: &str = "WAAL_RELEASE_RUSTC_SHA256";
const RELEASE_RUST_SYSROOT_SHA256_ENV: &str = "WAAL_RELEASE_RUST_SYSROOT_SHA256";
const RELEASE_NATIVE_TOOLCHAIN_SHA256_ENV: &str = "WAAL_RELEASE_NATIVE_TOOLCHAIN_SHA256";
const RELEASE_MATERIALS_SHA256_ENV: &str = "WAAL_RELEASE_MATERIALS_SHA256";
const WINDOWS_AUTHENTICODE_PUBLISHER_ENV: &str = "WAAL_WINDOWS_AUTHENTICODE_PUBLISHER";
const WINDOWS_AUTHENTICODE_CERT_SHA256_ENV: &str = "WAAL_WINDOWS_AUTHENTICODE_CERT_SHA256";

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
    println!("cargo:rerun-if-env-changed={RELEASE_GIT_COMMIT_ENV}");
    println!("cargo:rerun-if-env-changed={RELEASE_GIT_TREE_ENV}");
    println!("cargo:rerun-if-env-changed={RELEASE_CARGO_VERSION_ENV}");
    println!("cargo:rerun-if-env-changed={RELEASE_RUSTC_VERSION_ENV}");
    println!("cargo:rerun-if-env-changed={RELEASE_CARGO_SHA256_ENV}");
    println!("cargo:rerun-if-env-changed={RELEASE_RUSTC_SHA256_ENV}");
    println!("cargo:rerun-if-env-changed={RELEASE_RUST_SYSROOT_SHA256_ENV}");
    println!("cargo:rerun-if-env-changed={RELEASE_NATIVE_TOOLCHAIN_SHA256_ENV}");
    println!("cargo:rerun-if-env-changed={RELEASE_MATERIALS_SHA256_ENV}");
    println!("cargo:rerun-if-env-changed=WAAL_PUBLISHABLE_RELEASE");
    println!("cargo:rerun-if-env-changed={WINDOWS_AUTHENTICODE_PUBLISHER_ENV}");
    println!("cargo:rerun-if-env-changed={WINDOWS_AUTHENTICODE_CERT_SHA256_ENV}");
    println!("cargo:rustc-check-cfg=cfg(waal_release_profile)");
    println!("cargo:rustc-check-cfg=cfg(waal_publishable_release)");
    if env::var("PROFILE").as_deref() == Ok("release") {
        println!("cargo:rustc-cfg=waal_release_profile");
    }
    if publishable_release_requested() {
        println!("cargo:rustc-cfg=waal_publishable_release");
    }
    embed_windows_resources(icon).expect("embed Windows resources");

    let macos_identity = macos_identity();
    let macos_bundle_id = macos_identity.bundle_id.clone();
    let macos_team_id = macos_team_id();
    let release_provenance = release_provenance();
    let windows_authenticode_publisher = windows_authenticode_publisher();
    let windows_authenticode_cert_sha256 = windows_authenticode_cert_sha256();
    let app_name = app_name();
    let trusted_bundle_path = format!("/Applications/{app_name}.app");
    let development_bundle_path =
        development_bundle_path(&macos_identity, &macos_team_id, app_name);
    println!("cargo:rustc-env=WAAL_APP_NAME={app_name}");
    println!("cargo:rustc-env=WAAL_TRUSTED_MACOS_BUNDLE_PATH={trusted_bundle_path}");
    println!("cargo:rustc-env=WAAL_DEVELOPMENT_MACOS_BUNDLE_PATH={development_bundle_path}");
    println!("cargo:rustc-env=WAAL_TRUSTED_APP_BUNDLE_ID={macos_bundle_id}");
    println!("cargo:rustc-env=WAAL_TRUSTED_APP_TEAM_ID={macos_team_id}");
    println!(
        "cargo:rustc-env={WINDOWS_AUTHENTICODE_PUBLISHER_ENV}={windows_authenticode_publisher}"
    );
    println!(
        "cargo:rustc-env={WINDOWS_AUTHENTICODE_CERT_SHA256_ENV}={windows_authenticode_cert_sha256}"
    );

    let fingerprint = [icon, tray_icon]
        .into_iter()
        .map(asset_fingerprint)
        .collect::<Vec<_>>()
        .join(":");

    println!("cargo:rustc-env=WAAL_ICON_ASSET_FINGERPRINT={fingerprint}");
    write_build_metadata(
        &macos_identity,
        &macos_team_id,
        &windows_authenticode_publisher,
        &windows_authenticode_cert_sha256,
        &release_provenance,
    );
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

struct ReleaseProvenance {
    git_commit: String,
    git_tree: String,
    cargo_version: String,
    rustc_version: String,
    cargo_sha256: String,
    rustc_sha256: String,
    rust_sysroot_sha256: String,
    native_toolchain_sha256: String,
    materials_sha256: String,
}

fn build_metadata(
    macos_identity: &MacosIdentity,
    macos_team_id: &str,
    windows_authenticode_publisher: &str,
    windows_authenticode_cert_sha256: &str,
    release_provenance: &ReleaseProvenance,
    debug_assertions: bool,
) -> String {
    let publishable_release = publishable_release_requested();
    let artifact_kind = if env::var_os("CARGO_FEATURE_RELEASE_DIAGNOSTICS").is_some() {
        "release-diagnostics"
    } else if publishable_release || !macos_identity.non_production_identity {
        "release"
    } else {
        "development"
    };
    format!(
        "WAAL_BUILD_METADATA_V1;artifact-kind={};profile={};target-os={};target-arch={};debug-assertions={};debug-fill={};dev-tools={};diagnostics-ui={};release-diagnostics={};macos-bundle-id={};production-macos-bundle-id={};non-production-macos-identity={};macos-team-id={};windows-authenticode-publisher={};windows-authenticode-cert-sha256={};source-git-commit={};source-git-tree={};release-cargo-version={};release-rustc-version={};release-cargo-sha256={};release-rustc-sha256={};release-rust-sysroot-sha256={};release-native-toolchain-sha256={};release-materials-sha256={};",
        artifact_kind,
        env::var("PROFILE").unwrap_or_else(|_| "unknown".to_string()),
        metadata_component_env("CARGO_CFG_TARGET_OS"),
        metadata_component_env("CARGO_CFG_TARGET_ARCH"),
        debug_assertions,
        env::var_os("CARGO_FEATURE_DEBUG_FILL").is_some(),
        env::var_os("CARGO_FEATURE_DEV_TOOLS").is_some(),
        env::var_os("CARGO_FEATURE_DIAGNOSTICS_UI").is_some(),
        env::var_os("CARGO_FEATURE_RELEASE_DIAGNOSTICS").is_some(),
        macos_identity.bundle_id.as_str(),
        macos_identity.production_bundle_id.as_str(),
        macos_identity.non_production_identity,
        macos_team_id,
        windows_authenticode_publisher,
        windows_authenticode_cert_sha256,
        release_provenance.git_commit,
        release_provenance.git_tree,
        release_provenance.cargo_version,
        release_provenance.rustc_version,
        release_provenance.cargo_sha256,
        release_provenance.rustc_sha256,
        release_provenance.rust_sysroot_sha256,
        release_provenance.native_toolchain_sha256,
        release_provenance.materials_sha256,
    )
}

fn write_build_metadata(
    macos_identity: &MacosIdentity,
    macos_team_id: &str,
    windows_authenticode_publisher: &str,
    windows_authenticode_cert_sha256: &str,
    release_provenance: &ReleaseProvenance,
) {
    // Keep the marker separated from neighboring printable constants after LTO so
    // release packaging can reliably extract it with `strings`.
    let debug_metadata = format!(
        "\0{}\0",
        build_metadata(
            macos_identity,
            macos_team_id,
            windows_authenticode_publisher,
            windows_authenticode_cert_sha256,
            release_provenance,
            true,
        )
    );
    let release_metadata = format!(
        "\0{}\0",
        build_metadata(
            macos_identity,
            macos_team_id,
            windows_authenticode_publisher,
            windows_authenticode_cert_sha256,
            release_provenance,
            false,
        )
    );
    let debug_bytes = rust_byte_array(&debug_metadata);
    let release_bytes = rust_byte_array(&release_metadata);
    let source = format!(
        r#"#[cfg(any(target_os = "macos", target_os = "windows"))]
#[used]
#[cfg(debug_assertions)]
#[cfg_attr(target_os = "macos", unsafe(link_section = "__TEXT,__const"))]
static WAAL_BUILD_METADATA_DEBUG: [u8; {}] = [{}];

#[cfg(any(target_os = "macos", target_os = "windows"))]
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

fn release_provenance() -> ReleaseProvenance {
    let git_commit = trimmed_env(RELEASE_GIT_COMMIT_ENV);
    let git_tree = trimmed_env(RELEASE_GIT_TREE_ENV);
    let cargo_version = trimmed_env(RELEASE_CARGO_VERSION_ENV);
    let rustc_version = trimmed_env(RELEASE_RUSTC_VERSION_ENV);
    let cargo_sha256 = trimmed_env(RELEASE_CARGO_SHA256_ENV);
    let rustc_sha256 = trimmed_env(RELEASE_RUSTC_SHA256_ENV);
    let rust_sysroot_sha256 = trimmed_env(RELEASE_RUST_SYSROOT_SHA256_ENV);
    let native_toolchain_sha256 = trimmed_env(RELEASE_NATIVE_TOOLCHAIN_SHA256_ENV);
    let materials_sha256 = trimmed_env(RELEASE_MATERIALS_SHA256_ENV);
    let publishable_release = publishable_release_requested();
    if publishable_release && development_release_allowed() {
        panic!("WAAL_PUBLISHABLE_RELEASE and WAAL_DEVELOPMENT_RELEASE are mutually exclusive");
    }
    let provenance_required =
        (is_macos_release_profile() && !development_release_allowed()) || publishable_release;

    if provenance_required
        && [
            git_commit.as_ref(),
            git_tree.as_ref(),
            cargo_version.as_ref(),
            rustc_version.as_ref(),
            cargo_sha256.as_ref(),
            rustc_sha256.as_ref(),
            rust_sysroot_sha256.as_ref(),
            native_toolchain_sha256.as_ref(),
            materials_sha256.as_ref(),
        ]
        .into_iter()
        .any(|value| value.is_none())
    {
        panic!(
            "publishable release provenance must include Git commit/tree and Cargo/rustc version/hash fields"
        );
    }
    let supplied_count = [
        git_commit.is_some(),
        git_tree.is_some(),
        cargo_version.is_some(),
        rustc_version.is_some(),
        cargo_sha256.is_some(),
        rustc_sha256.is_some(),
        rust_sysroot_sha256.is_some(),
        native_toolchain_sha256.is_some(),
        materials_sha256.is_some(),
    ]
    .into_iter()
    .filter(|supplied| *supplied)
    .count();
    if supplied_count != 0 && supplied_count != 9 {
        panic!("release provenance fields must either all be set or all be absent");
    }

    let git_commit = git_commit.unwrap_or_default();
    let git_tree = git_tree.unwrap_or_default();
    let cargo_version = cargo_version.unwrap_or_default();
    let rustc_version = rustc_version.unwrap_or_default();
    let cargo_sha256 = cargo_sha256.unwrap_or_default();
    let rustc_sha256 = rustc_sha256.unwrap_or_default();
    let rust_sysroot_sha256 = rust_sysroot_sha256.unwrap_or_default();
    let native_toolchain_sha256 = native_toolchain_sha256.unwrap_or_default();
    let materials_sha256 = materials_sha256.unwrap_or_default();
    if !git_commit.is_empty() && !valid_git_sha1(&git_commit) {
        panic!("{RELEASE_GIT_COMMIT_ENV} must be an exact lowercase 40-hex Git object ID");
    }
    if !git_tree.is_empty() && !valid_git_sha1(&git_tree) {
        panic!("{RELEASE_GIT_TREE_ENV} must be an exact lowercase 40-hex Git object ID");
    }
    if !cargo_version.is_empty() && !valid_toolchain_version(&cargo_version) {
        panic!("{RELEASE_CARGO_VERSION_ENV} must be a numeric Rust toolchain version");
    }
    if !rustc_version.is_empty() && !valid_toolchain_version(&rustc_version) {
        panic!("{RELEASE_RUSTC_VERSION_ENV} must be a numeric Rust toolchain version");
    }
    if !cargo_version.is_empty() && cargo_version != rustc_version {
        panic!("release Cargo and rustc versions must match exactly");
    }
    if !cargo_sha256.is_empty() && !valid_sha256(&cargo_sha256) {
        panic!("{RELEASE_CARGO_SHA256_ENV} must be an exact lowercase SHA-256 digest");
    }
    if !rustc_sha256.is_empty() && !valid_sha256(&rustc_sha256) {
        panic!("{RELEASE_RUSTC_SHA256_ENV} must be an exact lowercase SHA-256 digest");
    }
    if !rust_sysroot_sha256.is_empty() && !valid_sha256(&rust_sysroot_sha256) {
        panic!("{RELEASE_RUST_SYSROOT_SHA256_ENV} must be an exact lowercase SHA-256 digest");
    }
    if !native_toolchain_sha256.is_empty() && !valid_sha256(&native_toolchain_sha256) {
        panic!("{RELEASE_NATIVE_TOOLCHAIN_SHA256_ENV} must be an exact lowercase SHA-256 digest");
    }
    if !materials_sha256.is_empty() && !valid_sha256(&materials_sha256) {
        panic!("{RELEASE_MATERIALS_SHA256_ENV} must be an exact lowercase SHA-256 digest");
    }

    ReleaseProvenance {
        git_commit,
        git_tree,
        cargo_version,
        rustc_version,
        cargo_sha256,
        rustc_sha256,
        rust_sysroot_sha256,
        native_toolchain_sha256,
        materials_sha256,
    }
}

fn publishable_release_requested() -> bool {
    truthy_env("WAAL_PUBLISHABLE_RELEASE")
}

fn windows_authenticode_publisher() -> String {
    let configured = trimmed_env(WINDOWS_AUTHENTICODE_PUBLISHER_ENV);
    let windows_target = env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows");
    let required = windows_target && publishable_release_requested();

    if required && configured.is_none() {
        panic!(
            "{WINDOWS_AUTHENTICODE_PUBLISHER_ENV} must identify the Authenticode certificate subject for a publishable Windows release"
        );
    }
    if configured.is_some() && !required {
        panic!(
            "{WINDOWS_AUTHENTICODE_PUBLISHER_ENV} is accepted only for publishable Windows releases"
        );
    }

    let publisher = configured.unwrap_or_default();
    if publisher.len() > 512
        || publisher
            .chars()
            .any(|ch| matches!(ch, '\0' | '\r' | '\n' | ';'))
    {
        panic!(
            "{WINDOWS_AUTHENTICODE_PUBLISHER_ENV} contains characters that are unsafe in build metadata"
        );
    }
    publisher
}

fn windows_authenticode_cert_sha256() -> String {
    let configured = trimmed_env(WINDOWS_AUTHENTICODE_CERT_SHA256_ENV);
    let windows_target = env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows");
    let required = windows_target && publishable_release_requested();

    if required && configured.is_none() {
        panic!(
            "{WINDOWS_AUTHENTICODE_CERT_SHA256_ENV} must pin the signer certificate for a publishable Windows release"
        );
    }
    if configured.is_some() && !required {
        panic!(
            "{WINDOWS_AUTHENTICODE_CERT_SHA256_ENV} is accepted only for publishable Windows releases"
        );
    }

    let fingerprint = configured.unwrap_or_default();
    if !fingerprint.is_empty() && !valid_sha256(&fingerprint) {
        panic!(
            "{WINDOWS_AUTHENTICODE_CERT_SHA256_ENV} must be an exact lowercase SHA-256 certificate fingerprint"
        );
    }
    fingerprint
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

fn valid_git_sha1(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_toolchain_version(value: &str) -> bool {
    let components = value.split('.').collect::<Vec<_>>();
    (2..=3).contains(&components.len())
        && components.into_iter().all(|component| {
            !component.is_empty() && component.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn metadata_component_env(name: &str) -> String {
    let value = trimmed_env(name).unwrap_or_else(|| "unknown".to_string());
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        panic!("{name} contains characters that are unsafe in build metadata");
    }
    value
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
