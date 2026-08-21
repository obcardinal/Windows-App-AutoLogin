#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 0 ]; then
  echo "This test does not accept arguments." >&2
  exit 2
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=script/package_macos.sh
source "$ROOT_DIR/script/package_macos.sh"

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

TEST_ROOT="$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/waal-release-provenance.XXXXXX")"
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
/usr/bin/printf '[package]\nname="fixture"\nversion="1.0.0"\n' >"$REPO_DIR/Cargo.toml"
/usr/bin/printf '# lock fixture\n' >"$REPO_DIR/Cargo.lock"
/usr/bin/printf 'fn main() {}\n' >"$REPO_DIR/build.rs"
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
/usr/bin/printf 'untracked\n' >"$REPO_DIR/untracked.txt"
if capture_release_provenance_for_root "$REPO_DIR" 2>/dev/null; then
  fail "untracked worktree entry was accepted"
fi
/bin/rm -f -- "$REPO_DIR/untracked.txt"
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

ENV_CAPTURE="$TEST_ROOT/sanitized-env"
BUILD_TARGET_DIR="$TEST_ROOT/target"
PRODUCTION_BUNDLE_ID="com.example.WindowsAppAutoLogin"
DIAGNOSTICS_BUNDLE_ID=""
EXPECTED_TEAM_ID="ABCDE12345"
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
assert_env_value "$ENV_CAPTURE" CARGO_ENCODED_RUSTFLAGS "$(release_encoded_rustflags)"
assert_env_value "$ENV_CAPTURE" WAAL_RELEASE_GIT_COMMIT "$EXPECTED_COMMIT"
assert_env_value "$ENV_CAPTURE" WAAL_RELEASE_GIT_TREE "$EXPECTED_TREE"

/usr/bin/grep -Fq 'source-git-commit={};source-git-tree={};' "$ROOT_DIR/build.rs" \
  || fail "build metadata does not embed both provenance fields"
/usr/bin/grep -Fq '"source-git-commit" "$RELEASE_GIT_COMMIT"' "$ROOT_DIR/script/package_macos.sh" \
  || fail "packager does not verify the embedded source commit"
/usr/bin/grep -Fq '"source-git-tree" "$RELEASE_GIT_TREE"' "$ROOT_DIR/script/package_macos.sh" \
  || fail "packager does not verify the embedded source tree"
/usr/bin/grep -Fq 'materialize_release_source' "$ROOT_DIR/script/package_macos.sh" \
  || fail "packager does not build from a Git-materialized source snapshot"

echo "release provenance tests passed"
