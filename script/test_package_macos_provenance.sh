#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 0 ]; then
  echo "This test does not accept arguments." >&2
  exit 2
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST_RUSTUP_BIN="$(command -v rustup)"
REAL_RELEASE_CARGO_BIN="$($HOST_RUSTUP_BIN which cargo)"
REAL_RELEASE_RUSTC_BIN="$($HOST_RUSTUP_BIN which rustc)"
REAL_RELEASE_RUST_SYSROOT="$($REAL_RELEASE_RUSTC_BIN --print sysroot)"
REAL_RELEASE_RUST_VERSION="$($REAL_RELEASE_RUSTC_BIN --version --verbose \
  | /usr/bin/awk -F ': ' '$1 == "release" { print $2 }')"
REAL_RELEASE_RUST_MINOR="${REAL_RELEASE_RUST_VERSION%.*}"
# shellcheck source=script/package_macos.sh
source "$ROOT_DIR/script/package_macos.sh"

export WAAL_RELEASE_CARGO_PATH="$REAL_RELEASE_CARGO_BIN"
export WAAL_RELEASE_RUSTC_PATH="$REAL_RELEASE_RUSTC_BIN"
export WAAL_RELEASE_RUST_SYSROOT="$REAL_RELEASE_RUST_SYSROOT"
export WAAL_RELEASE_EXPECTED_CARGO_SHA256="$(release_tool_sha256 "$REAL_RELEASE_CARGO_BIN")"
export WAAL_RELEASE_EXPECTED_RUSTC_SHA256="$(release_tool_sha256 "$REAL_RELEASE_RUSTC_BIN")"
export WAAL_RELEASE_EXPECTED_RUST_SYSROOT_SHA256="$(directory_tree_sha256 "$REAL_RELEASE_RUST_SYSROOT")"
export WAAL_RELEASE_EXPECTED_CLANG_SHA256="$(release_tool_sha256 /usr/bin/clang)"
export WAAL_RELEASE_EXPECTED_CLANGXX_SHA256="$(release_tool_sha256 /usr/bin/clang++)"
export WAAL_RELEASE_EXPECTED_AR_SHA256="$(release_tool_sha256 /usr/bin/ar)"
export WAAL_RELEASE_EXPECTED_NATIVE_TOOLCHAIN_SHA256="$(
  /usr/bin/printf '%s\0%s\0%s\0' \
    "$WAAL_RELEASE_EXPECTED_CLANG_SHA256" \
    "$WAAL_RELEASE_EXPECTED_CLANGXX_SHA256" \
    "$WAAL_RELEASE_EXPECTED_AR_SHA256" \
    | /usr/bin/shasum -a 256 \
    | /usr/bin/awk '{ print $1; exit }'
)"

fail() {
  echo "release provenance test failed: $1" >&2
  exit 1
}

assert_env_value() {
  local env_file="$1"
  local name="$2"
  local expected="$3"
  local actual
  actual="$(/usr/bin/awk -F= -v name="$name" '$1 == name { sub(/^[^=]*=/, ""); print; exit }' "$env_file")"
  [ "$actual" = "$expected" ] || fail "unexpected $name in sanitized build environment"
}

TEST_TMP_ROOT="${TMPDIR:-/tmp}"
TEST_ROOT="$(/usr/bin/mktemp -d "${TEST_TMP_ROOT%/}/waal-release-provenance.XXXXXX")"
TEST_ROOT="$(cd "$TEST_ROOT" && /bin/pwd -P)"
cleanup_test_root() {
  if [ -n "${TEST_ROOT:-}" ] && [ -d "$TEST_ROOT" ]; then
    /bin/rm -rf -- "$TEST_ROOT"
  fi
}
trap cleanup_test_root EXIT

REPO_DIR="$TEST_ROOT/source"
/bin/mkdir -p "$REPO_DIR/src" "$REPO_DIR/assets"
/usr/bin/git init --quiet "$REPO_DIR"
/usr/bin/git -C "$REPO_DIR" config user.name "Release Provenance Test"
/usr/bin/git -C "$REPO_DIR" config user.email "release-provenance@example.invalid"
/usr/bin/git -C "$REPO_DIR" config commit.gpgSign false
/usr/bin/printf 'tracked\n' >"$REPO_DIR/tracked.txt"
/usr/bin/printf '/ignored-injection\n' >"$REPO_DIR/.gitignore"
/usr/bin/printf '[package]\nname="fixture"\nversion="1.0.0"\nedition="2021"\nrust-version="%s"\n' \
  "$REAL_RELEASE_RUST_MINOR" >"$REPO_DIR/Cargo.toml"
/usr/bin/printf 'version = 4\n\n[[package]]\nname = "fixture"\nversion = "1.0.0"\n' >"$REPO_DIR/Cargo.lock"
/usr/bin/printf 'fn main() { assert!(std::env::var_os("WAAL_HOSTILE_CARGO_CONFIG").is_none(), "hostile Cargo config was loaded"); }\n' >"$REPO_DIR/build.rs"
/usr/bin/printf 'pub fn fixture() {}\n' >"$REPO_DIR/src/lib.rs"
/usr/bin/printf 'asset\n' >"$REPO_DIR/assets/fixture.txt"
/usr/bin/git -C "$REPO_DIR" add -- .gitignore Cargo.toml Cargo.lock build.rs src assets tracked.txt
/usr/bin/git -C "$REPO_DIR" commit --quiet -m "fixture"

capture_release_provenance_for_root "$REPO_DIR"
EXPECTED_COMMIT="$(/usr/bin/git -C "$REPO_DIR" rev-parse --verify 'HEAD^{commit}')"
EXPECTED_TREE="$(/usr/bin/git -C "$REPO_DIR" rev-parse --verify 'HEAD^{tree}')"
[ "$RELEASE_GIT_COMMIT" = "$EXPECTED_COMMIT" ] || fail "captured commit does not match HEAD"
[ "$RELEASE_GIT_TREE" = "$EXPECTED_TREE" ] || fail "captured tree does not match HEAD tree"
valid_git_object_id "$RELEASE_GIT_COMMIT" || fail "captured commit is not exact lowercase 40-hex"
valid_git_object_id "$RELEASE_GIT_TREE" || fail "captured tree is not exact lowercase 40-hex"
if valid_git_object_id "${RELEASE_GIT_COMMIT}0"; then
  fail "overlong Git object ID was accepted"
fi
UPPERCASE_COMMIT="$(/usr/bin/printf '%s' "$RELEASE_GIT_COMMIT" | /usr/bin/tr '[:lower:]' '[:upper:]')"
if valid_git_object_id "$UPPERCASE_COMMIT"; then
  fail "uppercase Git object ID was accepted"
fi

/usr/bin/printf 'dirty\n' >>"$REPO_DIR/tracked.txt"
if capture_release_provenance_for_root "$REPO_DIR" 2>/dev/null; then
  fail "dirty tracked worktree was accepted"
fi
/usr/bin/printf 'tracked\n' >"$REPO_DIR/tracked.txt"
/usr/bin/git -C "$REPO_DIR" update-index --assume-unchanged tracked.txt
/usr/bin/printf 'hidden dirty content\n' >"$REPO_DIR/tracked.txt"
if capture_release_provenance_for_root "$REPO_DIR" 2>/dev/null; then
  fail "assume-unchanged tracked worktree entry was accepted"
fi
/usr/bin/printf 'tracked\n' >"$REPO_DIR/tracked.txt"
/usr/bin/git -C "$REPO_DIR" update-index --no-assume-unchanged tracked.txt
/usr/bin/printf 'untracked\n' >"$REPO_DIR/untracked.txt"
if capture_release_provenance_for_root "$REPO_DIR" 2>/dev/null; then
  fail "untracked worktree entry was accepted"
fi
/bin/rm -f -- "$REPO_DIR/untracked.txt"
capture_release_provenance_for_root "$REPO_DIR"

SYMLINK_REPO="$TEST_ROOT/symlink-source"
/usr/bin/git clone --quiet "$REPO_DIR" "$SYMLINK_REPO"
/usr/bin/git -C "$SYMLINK_REPO" config user.name "Release Provenance Test"
/usr/bin/git -C "$SYMLINK_REPO" config user.email "release-provenance@example.invalid"
/bin/ln -s "$TEST_ROOT/external-source" "$SYMLINK_REPO/committed-link"
/usr/bin/git -C "$SYMLINK_REPO" add -- committed-link
/usr/bin/git -C "$SYMLINK_REPO" commit --quiet -m "link fixture"
capture_release_provenance_for_root "$SYMLINK_REPO"
if materialize_release_source_for_root \
  "$SYMLINK_REPO" \
  "$TEST_ROOT/symlink-snapshot" \
  "$RELEASE_GIT_COMMIT" \
  "$RELEASE_GIT_TREE" 2>/dev/null; then
  fail "committed symbolic link was accepted in a release snapshot"
fi
capture_release_provenance_for_root "$REPO_DIR"

/usr/bin/printf 'ignored build injection\n' >"$REPO_DIR/ignored-injection"
capture_release_provenance_for_root "$REPO_DIR"
SNAPSHOT_DIR="$TEST_ROOT/snapshot"
materialize_release_source_for_root \
  "$REPO_DIR" \
  "$SNAPSHOT_DIR" \
  "$RELEASE_GIT_COMMIT" \
  "$RELEASE_GIT_TREE"
[ "$(/bin/cat "$SNAPSHOT_DIR/tracked.txt")" = "tracked" ] \
  || fail "materialized source does not match the captured commit"
[ ! -e "$SNAPSHOT_DIR/ignored-injection" ] \
  || fail "ignored working-copy content leaked into the release source snapshot"
RELEASE_SOURCE_DIR="$SNAPSHOT_DIR"

HASH_FIXTURE="$TEST_ROOT/tree-hash"
/bin/mkdir -p "$HASH_FIXTURE/subdirectory"
/usr/bin/printf 'alpha\n' >"$HASH_FIXTURE/a"
/usr/bin/printf 'beta\n' >"$HASH_FIXTURE/subdirectory/b"
FIRST_TREE_HASH="$(directory_tree_sha256 "$HASH_FIXTURE")"
SECOND_TREE_HASH="$(directory_tree_sha256 "$HASH_FIXTURE")"
[ "$FIRST_TREE_HASH" = "$SECOND_TREE_HASH" ] \
  || fail "directory tree hash is not deterministic"
/usr/bin/printf 'changed\n' >"$HASH_FIXTURE/subdirectory/b"
[ "$(directory_tree_sha256 "$HASH_FIXTURE")" != "$FIRST_TREE_HASH" ] \
  || fail "directory tree hash did not detect changed content"
/bin/ln -s "$HASH_FIXTURE/a" "$HASH_FIXTURE/link"
if directory_tree_sha256 "$HASH_FIXTURE" >/dev/null 2>&1; then
  fail "directory tree hash accepted a symbolic link"
fi
/bin/rm -f -- "$HASH_FIXTURE/link"

SAFE_ROOT_DIR="$ROOT_DIR"
ROOT_DIR="${SAFE_ROOT_DIR}"$'\x1f''--cfg=waal_injected'
if release_encoded_rustflags >/dev/null 2>&1; then
  fail "CARGO_ENCODED_RUSTFLAGS delimiter in a remap path was accepted"
fi
ROOT_DIR="$SAFE_ROOT_DIR"
SAFE_HOME="${HOME:-}"
HOME="$TEST_ROOT/home-must-not-be-remapped"
case "$(release_encoded_rustflags)" in
  *home-must-not-be-remapped*) fail "ambient HOME leaked into release rustflags" ;;
esac
HOME="$SAFE_HOME"

ENV_CAPTURE="$TEST_ROOT/sanitized-env"
STAGE_DIR="$TEST_ROOT/stage"
BUILD_TARGET_DIR="$TEST_ROOT/target"
RELEASE_SOURCE_ROOT="$TEST_ROOT/release-environment"
PRODUCTION_BUNDLE_ID="com.example.WindowsAppAutoLogin"
DIAGNOSTICS_BUNDLE_ID=""
EXPECTED_TEAM_ID="ABCDE12345"
/bin/mkdir -p "$STAGE_DIR" "$RELEASE_SOURCE_ROOT"
prepare_isolated_release_cargo_home
SAVED_CARGO_SHA256="$WAAL_RELEASE_EXPECTED_CARGO_SHA256"
export WAAL_RELEASE_EXPECTED_CARGO_SHA256="$(/usr/bin/printf '0%.0s' {1..64})"
if resolve_and_verify_release_toolchain >/dev/null 2>&1; then
  fail "incorrect expected Cargo SHA-256 was accepted"
fi
export WAAL_RELEASE_EXPECTED_CARGO_SHA256="$SAVED_CARGO_SHA256"
resolve_and_verify_release_toolchain
VERIFIED_RELEASE_CARGO_BIN="$RELEASE_CARGO_BIN"
VERIFIED_RELEASE_RUSTC_BIN="$RELEASE_RUSTC_BIN"
VERIFY_TOOLCHAIN_FUNCTION="$(declare -f verify_release_toolchain_integrity)"
verify_release_toolchain_integrity() { return 0; }
RELEASE_CARGO_BIN=/usr/bin/env
RELEASE_RUSTC_BIN=/usr/bin/true
export RUSTFLAGS="--cfg ambient_injection"
export RUSTC_WRAPPER="$TEST_ROOT/ambient-wrapper"
export RUSTC_WORKSPACE_WRAPPER="$TEST_ROOT/ambient-workspace-wrapper"
export CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER="$TEST_ROOT/ambient-linker"
export CC="$TEST_ROOT/ambient-cc"
export CFLAGS="-Dambient_injection"
export LDFLAGS="-Wl,-ambient-injection"
export DYLD_INSERT_LIBRARIES="$TEST_ROOT/ambient.dylib"
run_sanitized_release_cargo >"$ENV_CAPTURE"

for forbidden in RUSTFLAGS CFLAGS LDFLAGS DYLD_INSERT_LIBRARIES; do
  if /usr/bin/grep -q "^${forbidden}=" "$ENV_CAPTURE"; then
    fail "$forbidden leaked into sanitized build environment"
  fi
done
assert_env_value "$ENV_CAPTURE" RUSTC_WRAPPER ""
assert_env_value "$ENV_CAPTURE" RUSTC_WORKSPACE_WRAPPER ""
assert_env_value "$ENV_CAPTURE" CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER "/usr/bin/clang"
assert_env_value "$ENV_CAPTURE" CC "/usr/bin/clang"
assert_env_value "$ENV_CAPTURE" HOME "$RELEASE_BUILD_HOME"
assert_env_value "$ENV_CAPTURE" CARGO_HOME "$RELEASE_CARGO_HOME"
assert_env_value "$ENV_CAPTURE" TMPDIR "$RELEASE_BUILD_TMPDIR"
assert_env_value "$ENV_CAPTURE" PATH "/usr/bin:/bin:/usr/sbin:/sbin"
assert_env_value "$ENV_CAPTURE" CARGO_ENCODED_RUSTFLAGS "$(release_encoded_rustflags)"
assert_env_value "$ENV_CAPTURE" WAAL_PUBLISHABLE_RELEASE "1"
assert_env_value "$ENV_CAPTURE" WAAL_RELEASE_GIT_COMMIT "$EXPECTED_COMMIT"
assert_env_value "$ENV_CAPTURE" WAAL_RELEASE_GIT_TREE "$EXPECTED_TREE"
assert_env_value "$ENV_CAPTURE" WAAL_RELEASE_CARGO_VERSION "$RELEASE_CARGO_VERSION"
assert_env_value "$ENV_CAPTURE" WAAL_RELEASE_RUSTC_VERSION "$RELEASE_RUSTC_VERSION"
assert_env_value "$ENV_CAPTURE" WAAL_RELEASE_CARGO_SHA256 "$RELEASE_CARGO_SHA256"
assert_env_value "$ENV_CAPTURE" WAAL_RELEASE_RUSTC_SHA256 "$RELEASE_RUSTC_SHA256"
assert_env_value "$ENV_CAPTURE" WAAL_RELEASE_RUST_SYSROOT_SHA256 "$RELEASE_RUST_SYSROOT_SHA256"
assert_env_value "$ENV_CAPTURE" WAAL_RELEASE_NATIVE_TOOLCHAIN_SHA256 "$RELEASE_NATIVE_TOOLCHAIN_SHA256"

eval "$VERIFY_TOOLCHAIN_FUNCTION"

HOSTILE_HOME="$TEST_ROOT/hostile-home"
/bin/mkdir -p "$HOSTILE_HOME/.cargo"
/bin/cat >"$HOSTILE_HOME/.cargo/config.toml" <<HOSTILE_CARGO_CONFIG
[env]
WAAL_HOSTILE_CARGO_CONFIG = { value = "loaded", force = true }

[build]
rustc-wrapper = "$TEST_ROOT/hostile-rustc-wrapper"
HOSTILE_CARGO_CONFIG
export HOME="$HOSTILE_HOME"
export CARGO_HOME="$HOSTILE_HOME/.cargo"
RELEASE_CARGO_BIN="$VERIFIED_RELEASE_CARGO_BIN"
RELEASE_RUSTC_BIN="$VERIFIED_RELEASE_RUSTC_BIN"
run_sanitized_release_cargo build \
  --locked \
  --release \
  --manifest-path "$RELEASE_SOURCE_DIR/Cargo.toml" \
  --lib
verify_release_dependency_graph
[ ! -e "$TEST_ROOT/hostile-rustc-wrapper" ] \
  || fail "hostile user Cargo wrapper affected the isolated build"

DIST_FIXTURE_ROOT="$TEST_ROOT/dist-root"
/bin/mkdir -p "$DIST_FIXTURE_ROOT" "$TEST_ROOT/redirected-dist"
/bin/ln -s "$TEST_ROOT/redirected-dist" "$DIST_FIXTURE_ROOT/dist"
if prepare_dist_root_for_root "$DIST_FIXTURE_ROOT" 2>/dev/null; then
  fail "symlinked dist root was accepted"
fi

ADHOC_BINARY="$TEST_ROOT/development-signature-test"
/bin/cp /usr/bin/true "$ADHOC_BINARY"
waal_codesign_development_bundle "$ADHOC_BINARY" "obcardinal.windows-app-autologin"
ADHOC_REQUIREMENT="$(/usr/bin/codesign -d -r- "$ADHOC_BINARY" 2>&1)"
case "$ADHOC_REQUIREMENT" in
  *'designated => cdhash H"'*) ;;
  *) fail "development ad-hoc signature is not cdhash-bound" ;;
esac
case "$ADHOC_REQUIREMENT" in
  *'designated => identifier "obcardinal.windows-app-autologin"'*)
    fail "development ad-hoc signature still trusts only the public bundle identifier"
    ;;
esac

/usr/bin/grep -Fq 'source-git-commit={};source-git-tree={};' "$ROOT_DIR/build.rs" \
  || fail "build metadata does not embed both provenance fields"
/usr/bin/grep -Fq 'release-cargo-sha256={};release-rustc-sha256={};' "$ROOT_DIR/build.rs" \
  || fail "build metadata does not embed release toolchain hashes"
/usr/bin/grep -Fq 'release-rust-sysroot-sha256={};release-native-toolchain-sha256={};' "$ROOT_DIR/build.rs" \
  || fail "build metadata does not embed sysroot and native toolchain hashes"
/usr/bin/grep -Fq '"source-git-commit" "$RELEASE_GIT_COMMIT"' "$ROOT_DIR/script/package_macos.sh" \
  || fail "packager does not verify the embedded source commit"
/usr/bin/grep -Fq '"source-git-tree" "$RELEASE_GIT_TREE"' "$ROOT_DIR/script/package_macos.sh" \
  || fail "packager does not verify the embedded source tree"
/usr/bin/grep -Fq 'materialize_release_source' "$ROOT_DIR/script/package_macos.sh" \
  || fail "packager does not build from a Git-materialized source snapshot"
/usr/bin/grep -Fq 'CARGO_HOME="$RELEASE_CARGO_HOME"' "$ROOT_DIR/script/package_macos.sh" \
  || fail "packager does not force an isolated Cargo home"
/usr/bin/grep -Fq 'WAAL_PUBLISHABLE_RELEASE = "1"' "$ROOT_DIR/script/build_windows_dist.ps1" \
  || fail "Windows packager does not mark publishable builds at compile time"
/usr/bin/grep -Fq 'Get-AuthenticodeSignature' "$ROOT_DIR/script/build_windows_dist.ps1" \
  || fail "Windows packager does not verify Authenticode after signing"
/usr/bin/grep -Fq 'SHA256SUMS.txt' "$ROOT_DIR/script/build_windows_dist.ps1" \
  || fail "Windows packager does not publish a SHA-256 manifest"
/usr/bin/grep -Fq '[IO.FileAttributes]::ReparsePoint' "$ROOT_DIR/script/build_windows_dist.ps1" \
  || fail "Windows packager does not reject reparse-point dist paths"
/usr/bin/grep -Fq 'Assert-CommitContainsOnlyRegularFiles' "$ROOT_DIR/script/build_windows_dist.ps1" \
  || fail "Windows packager does not reject committed links and gitlinks"
/usr/bin/grep -Fq 'WAAL_WINDOWS_AUTHENTICODE_CERT_SHA256' "$ROOT_DIR/script/build_windows_dist.ps1" \
  || fail "Windows packager does not embed the signing certificate SHA-256 fingerprint"
/usr/bin/grep -Fq '[switch]$Development' "$ROOT_DIR/script/build_windows_dist.ps1" \
  || fail "Windows packager does not expose an explicit non-production mode"
if /usr/bin/grep -Fq 'WAAL_WINDOWS_SIGNTOOL' "$ROOT_DIR/script/build_windows_dist.ps1"; then
  fail "Windows packager still accepts an arbitrary late signtool override"
fi
for pin_name in \
  WAAL_WINDOWS_RELEASE_EXPECTED_GIT_SHA256 \
  WAAL_WINDOWS_RELEASE_EXPECTED_TAR_SHA256 \
  WAAL_RELEASE_EXPECTED_CARGO_SHA256 \
  WAAL_RELEASE_EXPECTED_RUSTC_SHA256 \
  WAAL_RELEASE_EXPECTED_RUST_SYSROOT_SHA256 \
  WAAL_WINDOWS_RELEASE_EXPECTED_LINK_SHA256 \
  WAAL_WINDOWS_RELEASE_EXPECTED_RC_SHA256 \
  WAAL_WINDOWS_RELEASE_EXPECTED_SIGNTOOL_SHA256 \
  WAAL_RELEASE_EXPECTED_NATIVE_TOOLCHAIN_SHA256; do
  /usr/bin/grep -Fq "$pin_name" "$ROOT_DIR/script/build_windows_dist.ps1" \
    || fail "Windows packager is missing required hash pin $pin_name"
done
for sanitized_name in 'LIB$' 'INCLUDE$' 'LIBPATH$' 'CL$' '_CL_$' 'LINK$' '_LINK_$'; do
  /usr/bin/grep -Fq "$sanitized_name" "$ROOT_DIR/script/build_windows_dist.ps1" \
    || fail "Windows packager does not sanitize $sanitized_name"
done
/usr/bin/grep -Fq 'WAAL_RELEASE_RUST_SYSROOT_SHA256 = $RustSysrootSha256' "$ROOT_DIR/script/build_windows_dist.ps1" \
  || fail "Windows packager does not pass the Rust sysroot hash to Cargo"
/usr/bin/grep -Fq 'WAAL_RELEASE_NATIVE_TOOLCHAIN_SHA256 = $NativeToolchainSha256' "$ROOT_DIR/script/build_windows_dist.ps1" \
  || fail "Windows packager does not pass the native toolchain hash to Cargo"
/usr/bin/grep -Fq 'New-PublicationCandidate' "$ROOT_DIR/script/build_windows_dist.ps1" \
  || fail "Windows packager does not stage an in-dist publication candidate"
/usr/bin/grep -Fq 'Activate-PublicationCandidate' "$ROOT_DIR/script/build_windows_dist.ps1" \
  || fail "Windows packager does not atomically activate its candidate"
/usr/bin/grep -Fq 'Restore-PublicationAfterFailure' "$ROOT_DIR/script/build_windows_dist.ps1" \
  || fail "Windows packager does not roll back a failed publication"
if /usr/bin/grep -Fq 'Reset-DistDirectory' "$ROOT_DIR/script/build_windows_dist.ps1"; then
  fail "Windows packager still deletes the previous distribution before candidate validation"
fi

echo "release provenance tests passed"
