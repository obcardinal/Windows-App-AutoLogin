#[cfg(all(waal_release_profile, debug_assertions))]
compile_error!("release profile must not enable debug assertions; diagnostics support artifacts must be release-safe");
#[cfg(all(
    feature = "diagnostics-ui",
    not(debug_assertions),
    not(feature = "release-diagnostics")
))]
compile_error!("diagnostics-ui is development-only in release builds; enable release-diagnostics only for intentional support artifacts");

#[cfg(feature = "diagnostics-ui")]
pub mod diagnose;
#[cfg(all(target_os = "macos", feature = "diagnostics-ui"))]
mod macos_identity;
