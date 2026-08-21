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
REAL_DEVELOPER_DIR="/Applications/Xcode.app/Contents/Developer"
REAL_GIT_BIN="$REAL_DEVELOPER_DIR/usr/bin/git"
REAL_CLANG_BIN="$REAL_DEVELOPER_DIR/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang"
REAL_CLANGXX_BIN="$REAL_DEVELOPER_DIR/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang++"
REAL_AR_BIN="$REAL_DEVELOPER_DIR/Toolchains/XcodeDefault.xctoolchain/usr/bin/ar"
REAL_LD_BIN="$REAL_DEVELOPER_DIR/Toolchains/XcodeDefault.xctoolchain/usr/bin/ld"
REAL_LD_TAPI_BIN="$REAL_DEVELOPER_DIR/Toolchains/XcodeDefault.xctoolchain/usr/lib/libtapi.dylib"
REAL_LD_CODEDIRECTORY_BIN="$REAL_DEVELOPER_DIR/Toolchains/XcodeDefault.xctoolchain/usr/lib/libcodedirectory.dylib"
REAL_LD_LTO_BIN="$REAL_DEVELOPER_DIR/Toolchains/XcodeDefault.xctoolchain/usr/lib/libLTO.dylib"
REAL_LD_SWIFT_DEMANGLE_BIN="$REAL_DEVELOPER_DIR/Toolchains/XcodeDefault.xctoolchain/usr/lib/libswiftDemangle.dylib"
REAL_NOTARYTOOL_BIN="$REAL_DEVELOPER_DIR/usr/bin/notarytool"
REAL_STAPLER_BIN="$REAL_DEVELOPER_DIR/usr/bin/stapler"
REAL_MACOS_SDKROOT="$REAL_DEVELOPER_DIR/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk"
REAL_CLANG_RESOURCE_DIR="$($REAL_CLANG_BIN -print-resource-dir)"
# shellcheck source=script/package_macos.sh
source "$ROOT_DIR/script/package_macos.sh"

export WAAL_RELEASE_CARGO_PATH="$REAL_RELEASE_CARGO_BIN"
export WAAL_RELEASE_RUSTC_PATH="$REAL_RELEASE_RUSTC_BIN"
export WAAL_RELEASE_RUST_SYSROOT="$REAL_RELEASE_RUST_SYSROOT"
export WAAL_MACOS_DEVELOPER_DIR="$REAL_DEVELOPER_DIR"
export WAAL_MACOS_SDKROOT="$REAL_MACOS_SDKROOT"
export WAAL_MACOS_CLANG_RESOURCE_DIR="$REAL_CLANG_RESOURCE_DIR"
export WAAL_RELEASE_EXPECTED_GIT_SHA256="$(release_tool_sha256 "$REAL_GIT_BIN")"
export WAAL_RELEASE_EXPECTED_CARGO_SHA256="$(release_tool_sha256 "$REAL_RELEASE_CARGO_BIN")"
export WAAL_RELEASE_EXPECTED_RUSTC_SHA256="$(release_tool_sha256 "$REAL_RELEASE_RUSTC_BIN")"
export WAAL_RELEASE_EXPECTED_RUST_SYSROOT_SHA256="$(directory_tree_sha256 "$REAL_RELEASE_RUST_SYSROOT")"
export WAAL_RELEASE_EXPECTED_CLANG_SHA256="$(release_tool_sha256 "$REAL_CLANG_BIN")"
export WAAL_RELEASE_EXPECTED_CLANGXX_SHA256="$(release_tool_sha256 "$REAL_CLANGXX_BIN")"
export WAAL_RELEASE_EXPECTED_AR_SHA256="$(release_tool_sha256 "$REAL_AR_BIN")"
export WAAL_RELEASE_EXPECTED_LD_SHA256="$(release_tool_sha256 "$REAL_LD_BIN")"
export WAAL_RELEASE_EXPECTED_LD_TAPI_SHA256="$(release_tool_sha256 "$REAL_LD_TAPI_BIN")"
export WAAL_RELEASE_EXPECTED_LD_CODEDIRECTORY_SHA256="$(release_tool_sha256 "$REAL_LD_CODEDIRECTORY_BIN")"
export WAAL_RELEASE_EXPECTED_LD_LTO_SHA256="$(release_tool_sha256 "$REAL_LD_LTO_BIN")"
export WAAL_RELEASE_EXPECTED_LD_SWIFT_DEMANGLE_SHA256="$(release_tool_sha256 "$REAL_LD_SWIFT_DEMANGLE_BIN")"
export WAAL_RELEASE_EXPECTED_NOTARYTOOL_SHA256="$(release_tool_sha256 "$REAL_NOTARYTOOL_BIN")"
export WAAL_RELEASE_EXPECTED_STAPLER_SHA256="$(release_tool_sha256 "$REAL_STAPLER_BIN")"
export WAAL_RELEASE_EXPECTED_MACOS_SDK_SHA256="$(directory_tree_with_internal_symlinks_sha256 "$REAL_MACOS_SDKROOT")"
export WAAL_RELEASE_EXPECTED_CLANG_RESOURCE_DIR_SHA256="$(directory_tree_with_internal_symlinks_sha256 "$REAL_CLANG_RESOURCE_DIR")"
export WAAL_RELEASE_EXPECTED_NATIVE_TOOLCHAIN_SHA256="$(
  /usr/bin/printf '%s\0%s\0%s\0%s\0%s\0%s\0%s\0%s\0%s\0%s\0' \
    "$WAAL_RELEASE_EXPECTED_CLANG_SHA256" \
    "$WAAL_RELEASE_EXPECTED_CLANGXX_SHA256" \
    "$WAAL_RELEASE_EXPECTED_AR_SHA256" \
    "$WAAL_RELEASE_EXPECTED_LD_SHA256" \
    "$WAAL_RELEASE_EXPECTED_LD_TAPI_SHA256" \
    "$WAAL_RELEASE_EXPECTED_LD_CODEDIRECTORY_SHA256" \
    "$WAAL_RELEASE_EXPECTED_LD_LTO_SHA256" \
    "$WAAL_RELEASE_EXPECTED_LD_SWIFT_DEMANGLE_SHA256" \
    "$WAAL_RELEASE_EXPECTED_MACOS_SDK_SHA256" \
    "$WAAL_RELEASE_EXPECTED_CLANG_RESOURCE_DIR_SHA256" \
    | /usr/bin/shasum -a 256 \
    | /usr/bin/awk '{ print $1; exit }'
)"
EXPECTED_MACOS_RELEASE_MATERIALS_SHA256="$(
  /usr/bin/printf '%s\0%s\0%s\0%s\0%s\0%s\0%s\0' \
    "$WAAL_RELEASE_EXPECTED_GIT_SHA256" \
    "$WAAL_RELEASE_EXPECTED_CARGO_SHA256" \
    "$WAAL_RELEASE_EXPECTED_RUSTC_SHA256" \
    "$WAAL_RELEASE_EXPECTED_RUST_SYSROOT_SHA256" \
    "$WAAL_RELEASE_EXPECTED_NATIVE_TOOLCHAIN_SHA256" \
    "$WAAL_RELEASE_EXPECTED_NOTARYTOOL_SHA256" \
    "$WAAL_RELEASE_EXPECTED_STAPLER_SHA256" \
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

TEST_TMP_ROOT="/private/tmp"
if [ -L "$TEST_TMP_ROOT" ] \
  || [ "$(cd "$TEST_TMP_ROOT" 2>/dev/null && /bin/pwd -P)" != "$TEST_TMP_ROOT" ]; then
  fail "physical test temporary parent is unavailable"
fi
TEST_ROOT="$(/usr/bin/mktemp -d "$TEST_TMP_ROOT/waal-release-provenance.XXXXXX")"
TEST_ROOT="$(cd "$TEST_ROOT" && /bin/pwd -P)"
TEST_ROOT_ID="$(directory_identity "$TEST_ROOT")"
cleanup_test_root() {
  local actual_id

  if [ -n "${TEST_ROOT:-}" ] && [ -d "$TEST_ROOT" ] && [ ! -L "$TEST_ROOT" ]; then
    if (
      cd "$TEST_ROOT" || exit 1
      [ "$(directory_identity .)" = "$TEST_ROOT_ID" ] || exit 1
      /usr/bin/find -x . -depth -mindepth 1 -delete
    ); then
      actual_id="$(directory_identity "$TEST_ROOT" 2>/dev/null || true)"
      if [ "$actual_id" = "$TEST_ROOT_ID" ]; then
        /bin/rmdir "$TEST_ROOT" || true
      fi
    fi
  fi
}
trap cleanup_test_root EXIT

PRIVATE_TEMP_OWNER="$TEST_ROOT/private-temp-owner"
/bin/mkdir -m 700 "$PRIVATE_TEMP_OWNER"
create_private_release_root_for_root "$PRIVATE_TEMP_OWNER"
TEST_FUNCTION_PRIVATE_ROOT="$RELEASE_PRIVATE_ROOT"
TEST_FUNCTION_PRIVATE_ROOT_PARENT="$RELEASE_PRIVATE_ROOT_PARENT"
TEST_FUNCTION_PRIVATE_ROOT_ID="$RELEASE_PRIVATE_ROOT_ID"
TEST_FUNCTION_PRIVATE_ROOT_PARENT_ID="$RELEASE_PRIVATE_ROOT_PARENT_ID"
TEST_FUNCTION_TEMP_DIR="$RELEASE_TEMP_DIR"
TEST_FUNCTION_STAGE_DIR="$STAGE_DIR"
TEST_FUNCTION_SOURCE_ROOT="$RELEASE_SOURCE_ROOT"

UNSAFE_PARENT_OWNER="$TEST_ROOT/unsafe-parent-owner"
/bin/mkdir -m 700 "$UNSAFE_PARENT_OWNER"
prepare_dist_root_for_root "$UNSAFE_PARENT_OWNER"
/bin/chmod 777 "$UNSAFE_PARENT_OWNER/dist"
if create_private_release_root_for_root "$UNSAFE_PARENT_OWNER" 2>/dev/null; then
  fail "group- and world-writable private release parent was accepted"
fi
/bin/chmod 700 "$UNSAFE_PARENT_OWNER/dist"

HOSTILE_TMPDIR_WAS_SET=false
SAVED_HOSTILE_TMPDIR=""
if [ "${TMPDIR+x}" = x ]; then
  HOSTILE_TMPDIR_WAS_SET=true
  SAVED_HOSTILE_TMPDIR="$TMPDIR"
fi
HOSTILE_TMP_VICTIM="$TEST_ROOT/hostile-tmp-victim"
HOSTILE_TMP_LINK="$TEST_ROOT/caller-controlled-tmp"
HOSTILE_PRIVATE_OWNER="$TEST_ROOT/hostile-private-owner"
/bin/mkdir -m 700 "$HOSTILE_TMP_VICTIM" "$HOSTILE_PRIVATE_OWNER"
/usr/bin/printf 'must survive cleanup\n' >"$HOSTILE_TMP_VICTIM/victim-marker"
/bin/ln -s "$HOSTILE_TMP_VICTIM" "$HOSTILE_TMP_LINK"
export TMPDIR="$HOSTILE_TMP_LINK"

create_private_release_root_for_root "$HOSTILE_PRIVATE_OWNER"
case "$RELEASE_PRIVATE_ROOT" in
  "$HOSTILE_PRIVATE_OWNER/dist"/.package_macos.*) ;;
  *) fail "caller-controlled TMPDIR redirected the private release root" ;;
esac
[ "$RELEASE_TEMP_DIR" != "$HOSTILE_TMP_LINK" ] \
  || fail "caller-controlled TMPDIR became the release temporary directory"
NORMAL_CLEANUP_ROOT="$RELEASE_PRIVATE_ROOT"
/usr/bin/printf 'private\n' >"$NORMAL_CLEANUP_ROOT/private-marker"
/bin/ln -s "$HOSTILE_TMP_VICTIM" "$NORMAL_CLEANUP_ROOT/nested-redirect"
cleanup
[ ! -e "$NORMAL_CLEANUP_ROOT" ] \
  || fail "anchored cleanup did not remove an unchanged private release root"
[ -f "$HOSTILE_TMP_VICTIM/victim-marker" ] \
  || fail "private release cleanup followed caller-controlled TMPDIR or a nested symlink"

create_private_release_root_for_root "$HOSTILE_PRIVATE_OWNER"
REDIRECTED_CLEANUP_ROOT="$RELEASE_PRIVATE_ROOT"
QUARANTINED_PRIVATE_ROOT="$TEST_ROOT/quarantined-private-root"
/usr/bin/printf 'must remain quarantined\n' >"$REDIRECTED_CLEANUP_ROOT/private-marker"
/bin/mv "$REDIRECTED_CLEANUP_ROOT" "$QUARANTINED_PRIVATE_ROOT"
/bin/ln -s "$HOSTILE_TMP_VICTIM" "$REDIRECTED_CLEANUP_ROOT"
cleanup 2>/dev/null
[ -f "$HOSTILE_TMP_VICTIM/victim-marker" ] \
  || fail "redirected private-root cleanup deleted victim content"
[ -f "$QUARANTINED_PRIVATE_ROOT/private-marker" ] \
  || fail "redirected private-root cleanup traversed the renamed original tree"
/bin/rm -f -- "$REDIRECTED_CLEANUP_ROOT" "$HOSTILE_TMP_LINK"

if [ "$HOSTILE_TMPDIR_WAS_SET" = true ]; then
  export TMPDIR="$SAVED_HOSTILE_TMPDIR"
else
  unset TMPDIR
fi
RELEASE_PRIVATE_ROOT="$TEST_FUNCTION_PRIVATE_ROOT"
RELEASE_PRIVATE_ROOT_PARENT="$TEST_FUNCTION_PRIVATE_ROOT_PARENT"
RELEASE_PRIVATE_ROOT_ID="$TEST_FUNCTION_PRIVATE_ROOT_ID"
RELEASE_PRIVATE_ROOT_PARENT_ID="$TEST_FUNCTION_PRIVATE_ROOT_PARENT_ID"
RELEASE_TEMP_DIR="$TEST_FUNCTION_TEMP_DIR"
STAGE_DIR="$TEST_FUNCTION_STAGE_DIR"
RELEASE_SOURCE_ROOT="$TEST_FUNCTION_SOURCE_ROOT"

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

FSMONITOR_MARKER="$TEST_ROOT/fsmonitor-executed"
FSMONITOR_HOOK="$TEST_ROOT/hostile-fsmonitor"
/usr/bin/printf '#!/bin/sh\n/usr/bin/touch %s\nexit 0\n' "$FSMONITOR_MARKER" >"$FSMONITOR_HOOK"
/bin/chmod 700 "$FSMONITOR_HOOK"
/usr/bin/git -C "$REPO_DIR" config core.fsmonitor "$FSMONITOR_HOOK"
capture_release_provenance_for_root "$REPO_DIR"
[ ! -e "$FSMONITOR_MARKER" ] || fail "repo-local core.fsmonitor executed during sanitized provenance capture"
/usr/bin/git -C "$REPO_DIR" config --unset core.fsmonitor
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

ATTRIBUTE_REPO="$TEST_ROOT/archive-attribute-source"
/usr/bin/git clone --quiet "$REPO_DIR" "$ATTRIBUTE_REPO"
/usr/bin/git -C "$ATTRIBUTE_REPO" config user.name "Release Provenance Test"
/usr/bin/git -C "$ATTRIBUTE_REPO" config user.email "release-provenance@example.invalid"
/usr/bin/printf '$Format:%%H$\n' >"$ATTRIBUTE_REPO/tracked.txt"
/usr/bin/printf 'tracked.txt export-subst\n' >"$ATTRIBUTE_REPO/.gitattributes"
/usr/bin/git -C "$ATTRIBUTE_REPO" add -- .gitattributes tracked.txt
/usr/bin/git -C "$ATTRIBUTE_REPO" commit --quiet -m "archive attribute fixture"
capture_release_provenance_for_root "$ATTRIBUTE_REPO"
if materialize_release_source_for_root \
  "$ATTRIBUTE_REPO" \
  "$TEST_ROOT/archive-attribute-snapshot" \
  "$RELEASE_GIT_COMMIT" \
  "$RELEASE_GIT_TREE" 2>/dev/null; then
  fail "git archive export-subst mutation was accepted as exact committed source"
fi
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
/usr/bin/printf 'mutated after materialization\n' >"$SNAPSHOT_DIR/tracked.txt"
if verify_release_snapshot_unchanged 2>/dev/null; then
  fail "release snapshot mutation after materialization was accepted"
fi
/usr/bin/printf 'tracked\n' >"$SNAPSHOT_DIR/tracked.txt"
verify_release_snapshot_unchanged

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

/bin/ln -s a "$HASH_FIXTURE/internal-link"
INTERNAL_LINK_HASH="$(directory_tree_with_internal_symlinks_sha256 "$HASH_FIXTURE")"
[ "$INTERNAL_LINK_HASH" = "$(directory_tree_with_internal_symlinks_sha256 "$HASH_FIXTURE")" ] \
  || fail "internal-symlink tree hash is not deterministic"
/bin/rm -f -- "$HASH_FIXTURE/internal-link"
/bin/ln -s "$TEST_ROOT" "$HASH_FIXTURE/escaping-link"
if directory_tree_with_internal_symlinks_sha256 "$HASH_FIXTURE" >/dev/null 2>&1; then
  fail "Xcode directory hash accepted a symbolic link escaping its pinned root"
fi
/bin/rm -f -- "$HASH_FIXTURE/escaping-link"

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
[ "$RELEASE_MATERIALS_SHA256" = "$EXPECTED_MACOS_RELEASE_MATERIALS_SHA256" ] \
  || fail "release materials aggregate does not use the documented ordered inputs"
VERIFIED_RELEASE_CARGO_BIN="$RELEASE_CARGO_BIN"
VERIFIED_RELEASE_RUSTC_BIN="$RELEASE_RUSTC_BIN"
VERIFY_TOOLCHAIN_FUNCTION="$(declare -f verify_release_toolchain_integrity)"
verify_release_toolchain_integrity() { return 0; }

EXPECTED_ARCHIVE_NAME="Fixture-macos-$EXPECTED_COMMIT.zip"
[ "$(release_archive_filename Fixture-macos "$EXPECTED_COMMIT")" = "$EXPECTED_ARCHIVE_NAME" ] \
  || fail "macOS release archive is not commit-addressed"
if release_archive_filename '../escape' "$EXPECTED_COMMIT" >/dev/null 2>&1; then
  fail "unsafe release archive base was accepted"
fi
if release_archive_filename Fixture-macos "${EXPECTED_COMMIT}0" >/dev/null 2>&1; then
  fail "invalid commit was accepted in a release archive filename"
fi

prepare_atomic_no_replace_rename_helper
PUBLICATION_DIST="$RELEASE_PRIVATE_ROOT_PARENT"
OLDER_COMMIT="$(/usr/bin/printf '0%.0s' {1..40})"
OLDER_RELEASE="$PUBLICATION_DIST/Fixture-macos-$OLDER_COMMIT.zip"
/usr/bin/printf 'older immutable release\n' >"$OLDER_RELEASE"
OLDER_RELEASE_SHA256="$(release_tool_sha256 "$OLDER_RELEASE")"

PUBLICATION_CANDIDATE="$STAGE_DIR/publication-candidate.zip"
PUBLISHED_RELEASE="$PUBLICATION_DIST/$EXPECTED_ARCHIVE_NAME"
ZIP_PATH="$PUBLISHED_RELEASE"
ZIP_SHA256_PATH="$PUBLISHED_RELEASE.sha256"
/usr/bin/printf 'verified candidate\n' >"$PUBLICATION_CANDIDATE"
PUBLISHED_RELEASE_SHA256="$(release_tool_sha256 "$PUBLICATION_CANDIDATE")"
atomic_publish_file_no_replace "$PUBLICATION_CANDIDATE" "$PUBLISHED_RELEASE"
[ ! -e "$PUBLICATION_CANDIDATE" ] || fail "published candidate remained in staging"
[ "$(release_tool_sha256 "$PUBLISHED_RELEASE")" = "$PUBLISHED_RELEASE_SHA256" ] \
  || fail "atomic publication changed candidate bytes"
[ "$(release_tool_sha256 "$OLDER_RELEASE")" = "$OLDER_RELEASE_SHA256" ] \
  || fail "publishing a new commit changed an older release"

COLLISION_CANDIDATE="$STAGE_DIR/collision-candidate.zip"
/usr/bin/printf 'must not replace\n' >"$COLLISION_CANDIDATE"
if atomic_publish_file_no_replace "$COLLISION_CANDIDATE" "$PUBLISHED_RELEASE" 2>/dev/null; then
  fail "atomic publication overwrote an existing release"
fi
[ -f "$COLLISION_CANDIDATE" ] \
  || fail "failed no-replace publication consumed its candidate"
[ "$(release_tool_sha256 "$PUBLISHED_RELEASE")" = "$PUBLISHED_RELEASE_SHA256" ] \
  || fail "collision changed the existing immutable release"
[ "$(release_tool_sha256 "$OLDER_RELEASE")" = "$OLDER_RELEASE_SHA256" ] \
  || fail "collision handling changed an older release"

SIDECAR_CANDIDATE="$STAGE_DIR/release.sha256.candidate"
PUBLISHED_SIDECAR="$PUBLISHED_RELEASE.sha256"
write_release_sha256_sidecar_candidate \
  "$SIDECAR_CANDIDATE" "$PUBLISHED_RELEASE" "$PUBLISHED_RELEASE_SHA256"
verify_release_sha256_sidecar \
  "$SIDECAR_CANDIDATE" "$PUBLISHED_RELEASE" "$PUBLISHED_RELEASE_SHA256"
atomic_publish_file_no_replace "$SIDECAR_CANDIDATE" "$PUBLISHED_SIDECAR"
verify_published_release_hash_evidence \
  "$PUBLISHED_RELEASE" "$PUBLISHED_SIDECAR" "$PUBLISHED_RELEASE_SHA256"

SIDECAR_COLLISION="$STAGE_DIR/sidecar-collision"
/usr/bin/printf 'must not replace sidecar\n' >"$SIDECAR_COLLISION"
PUBLISHED_SIDECAR_SHA256="$(release_tool_sha256 "$PUBLISHED_SIDECAR")"
if atomic_publish_file_no_replace "$SIDECAR_COLLISION" "$PUBLISHED_SIDECAR" 2>/dev/null; then
  fail "atomic publication overwrote an existing SHA-256 sidecar"
fi
[ "$(release_tool_sha256 "$PUBLISHED_SIDECAR")" = "$PUBLISHED_SIDECAR_SHA256" ] \
  || fail "sidecar collision changed existing hash evidence"

/usr/bin/printf 'tampered after publication\n' >"$PUBLISHED_RELEASE"
if verify_published_release_hash_evidence \
  "$PUBLISHED_RELEASE" "$PUBLISHED_SIDECAR" "$PUBLISHED_RELEASE_SHA256" 2>/dev/null; then
  fail "final destination hash verification accepted modified bytes"
fi
/usr/bin/printf 'verified candidate\n' >"$PUBLISHED_RELEASE"
verify_published_release_hash_evidence \
  "$PUBLISHED_RELEASE" "$PUBLISHED_SIDECAR" "$PUBLISHED_RELEASE_SHA256"

CRASH_COMMIT="$(/usr/bin/printf '1%.0s' {1..40})"
CRASH_ARCHIVE="$PUBLICATION_DIST/Fixture-macos-$CRASH_COMMIT.zip"
CRASH_SIDECAR="$CRASH_ARCHIVE.sha256"
CRASH_CANDIDATE="$STAGE_DIR/crash-candidate.zip"
CRASH_SIDECAR_CANDIDATE="$STAGE_DIR/crash-candidate.zip.sha256"
/usr/bin/printf 'verified crash-recovery candidate\n' >"$CRASH_CANDIDATE"
CRASH_SHA256="$(release_tool_sha256 "$CRASH_CANDIDATE")"
ZIP_PATH="$CRASH_ARCHIVE"
ZIP_SHA256_PATH="$CRASH_SIDECAR"
atomic_publish_file_no_replace "$CRASH_CANDIDATE" "$CRASH_ARCHIVE"
[ "$(release_publication_state)" = archive-only ] \
  || fail "crash after ZIP publication was not recognized as repairable"
RESTART_CANDIDATE="$STAGE_DIR/restart-candidate.zip"
/bin/cp "$CRASH_ARCHIVE" "$RESTART_CANDIDATE"
publish_verified_release_pair \
  "$RESTART_CANDIDATE" "$CRASH_SIDECAR_CANDIDATE" "$CRASH_SHA256"
verify_published_release_hash_evidence \
  "$CRASH_ARCHIVE" "$CRASH_SIDECAR" "$CRASH_SHA256"
[ "$(release_publication_state)" = complete ] \
  || fail "exact-byte restart did not repair the orphan ZIP"

REPAIR_VALIDATE_FUNCTION="$(declare -f validate_archive_entries)"
REPAIR_EXTRACT_FUNCTION="$(declare -f extract_and_verify_archive)"
REPAIR_SOURCE_FUNCTION="$(declare -f verify_release_source_unchanged)"
REPAIR_VALIDATE_CALLED=false
REPAIR_EXTRACT_CALLED=false
REPAIR_SOURCE_CALLED=false
REPAIR_COMMIT="$(/usr/bin/printf '4%.0s' {1..40})"
REPAIR_ARCHIVE="$PUBLICATION_DIST/Fixture-macos-$REPAIR_COMMIT.zip"
REPAIR_SIDECAR="$REPAIR_ARCHIVE.sha256"
TMP_ZIP_SHA256="$STAGE_DIR/repair-candidate.zip.sha256"
/usr/bin/printf 'rigorously verified orphan archive\n' >"$REPAIR_ARCHIVE"
ZIP_PATH="$REPAIR_ARCHIVE"
ZIP_SHA256_PATH="$REPAIR_SIDECAR"
validate_archive_entries() {
  [ "$1" = "$REPAIR_ARCHIVE" ] || return 1
  REPAIR_VALIDATE_CALLED=true
}
extract_and_verify_archive() {
  [ "$1" = "$REPAIR_ARCHIVE" ] \
    && [ "$2" = existing-published-extracted ] || return 1
  REPAIR_EXTRACT_CALLED=true
}
verify_release_source_unchanged() {
  REPAIR_SOURCE_CALLED=true
}
repair_or_adopt_existing_release archive-only
[ "$REPAIR_VALIDATE_CALLED" = true ] \
  || fail "archive-only repair skipped archive entry validation"
[ "$REPAIR_EXTRACT_CALLED" = true ] \
  || fail "archive-only repair skipped extracted bundle verification"
[ "$REPAIR_SOURCE_CALLED" = true ] \
  || fail "archive-only repair skipped exact source revalidation"
verify_published_release_hash_evidence \
  "$REPAIR_ARCHIVE" "$REPAIR_SIDECAR" "$PUBLISHED_ZIP_SHA256"
eval "$REPAIR_VALIDATE_FUNCTION"
eval "$REPAIR_EXTRACT_FUNCTION"
eval "$REPAIR_SOURCE_FUNCTION"

ADOPTION_COMMIT="$(/usr/bin/printf '2%.0s' {1..40})"
ADOPTION_ARCHIVE="$PUBLICATION_DIST/Fixture-macos-$ADOPTION_COMMIT.zip"
ADOPTION_SIDECAR="$ADOPTION_ARCHIVE.sha256"
ADOPTION_CANDIDATE="$STAGE_DIR/adoption-candidate.zip"
ADOPTION_SIDECAR_CANDIDATE="$STAGE_DIR/adoption-candidate.zip.sha256"
/usr/bin/printf 'published bytes differ\n' >"$ADOPTION_ARCHIVE"
/usr/bin/printf 'verified candidate bytes\n' >"$ADOPTION_CANDIDATE"
ADOPTION_ARCHIVE_SHA256="$(release_tool_sha256 "$ADOPTION_ARCHIVE")"
ADOPTION_CANDIDATE_SHA256="$(release_tool_sha256 "$ADOPTION_CANDIDATE")"
ZIP_PATH="$ADOPTION_ARCHIVE"
ZIP_SHA256_PATH="$ADOPTION_SIDECAR"
if publish_verified_release_pair \
  "$ADOPTION_CANDIDATE" "$ADOPTION_SIDECAR_CANDIDATE" "$ADOPTION_CANDIDATE_SHA256" \
  2>/dev/null; then
  fail "different orphan ZIP bytes were adopted"
fi
[ "$(release_tool_sha256 "$ADOPTION_ARCHIVE")" = "$ADOPTION_ARCHIVE_SHA256" ] \
  || fail "failed orphan adoption changed immutable archive bytes"
[ ! -e "$ADOPTION_SIDECAR" ] \
  || fail "failed orphan adoption published misleading hash evidence"

SIDECAR_ONLY_COMMIT="$(/usr/bin/printf '3%.0s' {1..40})"
SIDECAR_ONLY_ARCHIVE="$PUBLICATION_DIST/Fixture-macos-$SIDECAR_ONLY_COMMIT.zip"
SIDECAR_ONLY_SIDECAR="$SIDECAR_ONLY_ARCHIVE.sha256"
/usr/bin/printf 'orphan sidecar\n' >"$SIDECAR_ONLY_SIDECAR"
ZIP_PATH="$SIDECAR_ONLY_ARCHIVE"
ZIP_SHA256_PATH="$SIDECAR_ONLY_SIDECAR"
if release_publication_state >/dev/null 2>&1; then
  fail "unsupported sidecar-only publication state was accepted"
fi

ZIP_PATH="$PUBLISHED_RELEASE"
ZIP_SHA256_PATH="$PUBLISHED_SIDECAR"

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
assert_env_value "$ENV_CAPTURE" CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER "$REAL_CLANG_BIN"
assert_env_value "$ENV_CAPTURE" CC "$REAL_CLANG_BIN"
assert_env_value "$ENV_CAPTURE" CXX "$REAL_CLANGXX_BIN"
assert_env_value "$ENV_CAPTURE" AR "$REAL_AR_BIN"
assert_env_value "$ENV_CAPTURE" LD "$REAL_LD_BIN"
assert_env_value "$ENV_CAPTURE" DEVELOPER_DIR "$REAL_DEVELOPER_DIR"
assert_env_value "$ENV_CAPTURE" SDKROOT "$REAL_MACOS_SDKROOT"
assert_env_value "$ENV_CAPTURE" HOME "$RELEASE_BUILD_HOME"
assert_env_value "$ENV_CAPTURE" CARGO_HOME "$RELEASE_CARGO_HOME"
assert_env_value "$ENV_CAPTURE" TMPDIR "$RELEASE_BUILD_TMPDIR"
assert_env_value "$ENV_CAPTURE" PATH "/usr/bin:/bin:/usr/sbin:/sbin"
assert_env_value "$ENV_CAPTURE" CARGO_ENCODED_RUSTFLAGS "$(release_encoded_rustflags)"
CAPTURED_RUSTFLAGS="$(/usr/bin/awk -F= '$1 == "CARGO_ENCODED_RUSTFLAGS" { sub(/^[^=]*=/, ""); print; exit }' "$ENV_CAPTURE")"
case "$CAPTURED_RUSTFLAGS" in
  *$'\x1f-C\x1f'"link-arg=-fuse-ld=$REAL_LD_BIN") ;;
  *) fail "sanitized release rustflags do not force the pinned physical ld" ;;
esac
assert_env_value "$ENV_CAPTURE" WAAL_PUBLISHABLE_RELEASE "1"
assert_env_value "$ENV_CAPTURE" WAAL_RELEASE_GIT_COMMIT "$EXPECTED_COMMIT"
assert_env_value "$ENV_CAPTURE" WAAL_RELEASE_GIT_TREE "$EXPECTED_TREE"
assert_env_value "$ENV_CAPTURE" WAAL_RELEASE_CARGO_VERSION "$RELEASE_CARGO_VERSION"
assert_env_value "$ENV_CAPTURE" WAAL_RELEASE_RUSTC_VERSION "$RELEASE_RUSTC_VERSION"
assert_env_value "$ENV_CAPTURE" WAAL_RELEASE_CARGO_SHA256 "$RELEASE_CARGO_SHA256"
assert_env_value "$ENV_CAPTURE" WAAL_RELEASE_RUSTC_SHA256 "$RELEASE_RUSTC_SHA256"
assert_env_value "$ENV_CAPTURE" WAAL_RELEASE_RUST_SYSROOT_SHA256 "$RELEASE_RUST_SYSROOT_SHA256"
assert_env_value "$ENV_CAPTURE" WAAL_RELEASE_NATIVE_TOOLCHAIN_SHA256 "$RELEASE_NATIVE_TOOLCHAIN_SHA256"
assert_env_value "$ENV_CAPTURE" WAAL_RELEASE_MATERIALS_SHA256 "$RELEASE_MATERIALS_SHA256"

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
/usr/bin/grep -Fq 'verify_release_snapshot_unchanged' "$ROOT_DIR/script/package_macos.sh" \
  || fail "packager does not continuously verify its materialized source snapshot"
/usr/bin/grep -Fq 'core.fsmonitor=false' "$ROOT_DIR/script/package_macos.sh" \
  || fail "packager does not disable repo-local Git filesystem monitor execution"
/usr/bin/grep -Fq 'Contents/Developer/usr/bin/git' "$ROOT_DIR/script/package_macos.sh" \
  || fail "packager does not use the physical Xcode Git executable"
/usr/bin/grep -Fq 'CARGO_HOME="$RELEASE_CARGO_HOME"' "$ROOT_DIR/script/package_macos.sh" \
  || fail "packager does not force an isolated Cargo home"
/usr/bin/grep -Fq 'renameatx_np' "$ROOT_DIR/script/package_macos.sh" \
  || fail "macOS packager does not use an atomic rename syscall"
/usr/bin/grep -Fq 'RENAME_EXCL' "$ROOT_DIR/script/package_macos.sh" \
  || fail "macOS packager does not make publication no-replace"
/usr/bin/grep -Fq 'verify_published_release_hash_evidence' "$ROOT_DIR/script/package_macos.sh" \
  || fail "macOS packager does not re-verify final ZIP hash evidence"
/usr/bin/grep -Fq 'repair_or_adopt_existing_release' "$ROOT_DIR/script/package_macos.sh" \
  || fail "macOS packager does not repair a verified archive-only publication"
/usr/bin/grep -Fq 'create_private_release_root' "$ROOT_DIR/script/package_macos.sh" \
  || fail "macOS packager does not create one private release staging root"
/usr/bin/grep -Fq '/usr/bin/find -x . -depth -mindepth 1 -delete' "$ROOT_DIR/script/package_macos.sh" \
  || fail "macOS packager cleanup is not anchored to the verified private root"
if /usr/bin/grep -Fq '${TMPDIR:-' "$ROOT_DIR/script/package_macos.sh"; then
  fail "macOS packager still creates release files under caller-controlled TMPDIR"
fi
if /usr/bin/grep -E '/bin/rm[[:space:]]+-rf[[:space:]].*\$(STAGE_DIR|RELEASE_SOURCE_ROOT|RELEASE_PRIVATE_ROOT)' \
  "$ROOT_DIR/script/package_macos.sh" >/dev/null; then
  fail "macOS packager recursively deletes a redirectable release path"
fi
if /usr/bin/grep -E '/bin/(rm|mv)[[:space:]].*\$ZIP_PATH' "$ROOT_DIR/script/package_macos.sh" >/dev/null; then
  fail "macOS packager can delete or replace an immutable published ZIP"
fi
/usr/bin/grep -Fq 'WAAL_PUBLISHABLE_RELEASE = "1"' "$ROOT_DIR/script/build_windows_dist.ps1" \
  || fail "Windows packager does not mark publishable builds at compile time"
/usr/bin/grep -Fq 'Get-AuthenticodeSignature' "$ROOT_DIR/script/build_windows_dist.ps1" \
  || fail "Windows packager does not verify Authenticode after signing"
/usr/bin/grep -Fq 'SHA256SUMS.txt' "$ROOT_DIR/script/build_windows_dist.ps1" \
  || fail "Windows packager does not publish a SHA-256 manifest"
/usr/bin/grep -Fq '$hashes["BUILD-PROVENANCE.txt"]' "$ROOT_DIR/script/build_windows_dist.ps1" \
  || fail "Windows SHA-256 manifest does not cover BUILD-PROVENANCE.txt"
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
  WAAL_WINDOWS_RELEASE_EXPECTED_GIT_ROOT_SHA256 \
  WAAL_WINDOWS_RELEASE_EXPECTED_TAR_SHA256 \
  WAAL_RELEASE_EXPECTED_CARGO_SHA256 \
  WAAL_RELEASE_EXPECTED_RUSTC_SHA256 \
  WAAL_RELEASE_EXPECTED_RUST_SYSROOT_SHA256 \
  WAAL_WINDOWS_RELEASE_EXPECTED_CL_SHA256 \
  WAAL_WINDOWS_RELEASE_EXPECTED_LIB_EXE_SHA256 \
  WAAL_WINDOWS_RELEASE_EXPECTED_LINK_SHA256 \
  WAAL_WINDOWS_RELEASE_EXPECTED_MSVC_BIN_SHA256 \
  WAAL_WINDOWS_RELEASE_EXPECTED_RC_SHA256 \
  WAAL_WINDOWS_RELEASE_EXPECTED_SDK_BIN_SHA256 \
  WAAL_WINDOWS_RELEASE_EXPECTED_SIGNTOOL_SHA256 \
  WAAL_WINDOWS_RELEASE_EXPECTED_LIB_SHA256 \
  WAAL_WINDOWS_RELEASE_EXPECTED_INCLUDE_SHA256 \
  WAAL_WINDOWS_RELEASE_EXPECTED_LIBPATH_SHA256 \
  WAAL_RELEASE_EXPECTED_NATIVE_TOOLCHAIN_SHA256; do
  /usr/bin/grep -Fq "$pin_name" "$ROOT_DIR/script/build_windows_dist.ps1" \
    || fail "Windows packager is missing required hash pin $pin_name"
done
/usr/bin/grep -Fq 'Assert-PathWithinPinnedDirectory $Git $GitRoot "Git executable"' "$ROOT_DIR/script/build_windows_dist.ps1" \
  || fail "Windows packager does not bind Git to its pinned runtime tree"
/usr/bin/grep -Fq 'Invoke-SanitizedGit @("--exec-path")' "$ROOT_DIR/script/build_windows_dist.ps1" \
  || fail "Windows packager does not inspect the physical Git exec-path"
/usr/bin/grep -Fq 'Assert-PathWithinPinnedDirectory $reportedGitExecPath $GitRoot "Git exec-path"' "$ROOT_DIR/script/build_windows_dist.ps1" \
  || fail "Windows packager does not bind Git exec-path to its pinned runtime tree"
/usr/bin/grep -Fq 'Assert-PathWithinPinnedDirectory $ResourceCompiler $SdkBin "rc.exe"' "$ROOT_DIR/script/build_windows_dist.ps1" \
  || fail "Windows packager does not bind rc.exe to the pinned SDK executable tree"
/usr/bin/grep -Fq 'Assert-PathWithinPinnedDirectory $SignTool $SdkBin "signtool.exe"' "$ROOT_DIR/script/build_windows_dist.ps1" \
  || fail "Windows packager does not bind signtool.exe to the pinned SDK executable tree"
/usr/bin/grep -Fq '@($CompilerSha256, $LibrarianSha256, $LinkerSha256, $CompilerBinSha256, $ResourceCompilerSha256, $SdkBinSha256, $SignToolSha256)' "$ROOT_DIR/script/build_windows_dist.ps1" \
  || fail "Windows native aggregate does not include the ordered SDK runtime inputs"
if ! /usr/bin/perl -0777 -e '
  my $text = <>;
  exit($text =~ /\$script:ReleaseMaterialsSha256\s*=\s*Get-OrderedHashAggregate\s*\@\(\s*
    \$GitSha256,\s*\$GitRootSha256,\s*\$TarSha256,\s*\$CargoSha256,\s*
    \$RustcSha256,\s*\$RustSysrootSha256,\s*\$NativeToolchainSha256,\s*
    \$TrustedLibSha256,\s*\$TrustedIncludeSha256,\s*\$TrustedLibPathSha256\s*\)/xms ? 0 : 1);
' "$ROOT_DIR/script/build_windows_dist.ps1"; then
  fail "Windows release materials aggregate does not use the documented ordered inputs"
fi
/usr/bin/grep -Fq 'WAAL_RELEASE_MATERIALS_SHA256 = $ReleaseMaterialsSha256' "$ROOT_DIR/script/build_windows_dist.ps1" \
  || fail "Windows packager does not pass the release materials aggregate to Cargo"
/usr/bin/grep -Fq 'Require-MetadataField $metadata "release-materials-sha256" $ReleaseMaterialsSha256' "$ROOT_DIR/script/build_windows_dist.ps1" \
  || fail "Windows packager does not verify embedded release materials metadata"
for sanitized_name in 'CC(?:$|_)' 'HOST_(?:CC' 'TARGET_(?:CC' 'LIB$' 'INCLUDE$' 'LIBPATH$' 'CL$' '_CL_$' 'LINK$' '_LINK_$'; do
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
/usr/bin/grep -Fq '"$DistName-$ReleaseGitCommit"' "$ROOT_DIR/script/build_windows_dist.ps1" \
  || fail "Windows packager does not publish to an immutable commit-addressed directory"
if /usr/bin/grep -E 'Remove-Item.*(Publication|DistDir|DistName)' "$ROOT_DIR/script/build_windows_dist.ps1" >/dev/null; then
  fail "Windows packager recursively deletes a publication tree"
fi
/usr/bin/grep -Fq '#[cfg(any(target_os = "macos", target_os = "windows"))]' "$ROOT_DIR/src/main.rs" \
  || fail "Windows executable does not include generated release metadata"

echo "release provenance tests passed"
