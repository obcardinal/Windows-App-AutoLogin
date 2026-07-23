#!/usr/bin/env bash
set -euo pipefail
export PATH="/usr/bin:/bin:/usr/sbin:/sbin:${HOME:-}/.cargo/bin"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=script/macos_bundle.sh
source "$ROOT_DIR/script/macos_bundle.sh"
PRODUCTION_APP_NAME="WindowsAppAutoLogin"
DIAGNOSTICS_APP_NAME="WindowsAppAutoLoginDiagnostics"
APP_NAME="$PRODUCTION_APP_NAME"
APP_DISPLAY_NAME="Windows App AutoLogin"
DEVELOPMENT_BUNDLE_ID="dev.codex.windows-app-autologin"
ZIP_PATH=""
BINARY_NAME="windows-app-autologin"
PRODUCTION_BUNDLE_ID="${WAAL_RELEASE_BUNDLE_ID:-}"
DIAGNOSTICS_BUNDLE_ID="${WAAL_DIAGNOSTICS_BUNDLE_ID:-}"
EXPECTED_BUNDLE_ID=""
EXPECTED_BUNDLE_ID_ENV=""
EXPECTED_TEAM_ID="${WAAL_MACOS_TEAM_ID:-}"
CODESIGN_IDENTITY="${WAAL_CODESIGN_IDENTITY:-}"
NOTARY_PROFILE="${WAAL_NOTARY_PROFILE:-}"
RELEASE=false
RELEASE_DIAGNOSTICS_ARTIFACT=false
STAGE_DIR=""
BUILD_TARGET_DIR=""
TARGET_EXECUTABLE=""
CARGO_VERSION="$(waal_cargo_version "$ROOT_DIR")"
BUILD_VERSION="$(waal_build_version "$CARGO_VERSION")"

for arg in "$@"; do
  case "$arg" in
    --release) RELEASE=true ;;
    --release-diagnostics-artifact) RELEASE=true; RELEASE_DIAGNOSTICS_ARTIFACT=true ;;
    *) echo "Unknown argument: $arg" >&2; exit 2 ;;
  esac
done

if [ "$RELEASE_DIAGNOSTICS_ARTIFACT" = true ]; then
  APP_NAME="$DIAGNOSTICS_APP_NAME"
  APP_DISPLAY_NAME="Windows App AutoLogin Diagnostics"
  ZIP_PATH="$ROOT_DIR/dist/$APP_NAME-macos-release-diagnostics.zip"
  EXPECTED_BUNDLE_ID="$DIAGNOSTICS_BUNDLE_ID"
  EXPECTED_BUNDLE_ID_ENV="WAAL_DIAGNOSTICS_BUNDLE_ID"
else
  APP_NAME="$PRODUCTION_APP_NAME"
  ZIP_PATH="$ROOT_DIR/dist/$APP_NAME-macos.zip"
  EXPECTED_BUNDLE_ID="$PRODUCTION_BUNDLE_ID"
  EXPECTED_BUNDLE_ID_ENV="WAAL_RELEASE_BUNDLE_ID"
fi

require_tool() {
  waal_require_tool "$1"
}

valid_bundle_id() {
  waal_valid_bundle_id "$1"
}

valid_team_id() {
  case "$1" in
    [A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9]) return 0 ;;
    *) return 1 ;;
  esac
}

validate_release_environment() {
  if [ "$RELEASE" != true ]; then
    echo "Refusing to create macOS ZIP without --release." >&2
    echo "Local ad-hoc bundles are for development only; release packaging must pass signing and notarization checks." >&2
    exit 1
  fi
  if [ -z "$EXPECTED_TEAM_ID" ]; then
    echo "WAAL_MACOS_TEAM_ID must be set for release packaging." >&2
    exit 1
  fi
  if ! valid_team_id "$EXPECTED_TEAM_ID"; then
    echo "WAAL_MACOS_TEAM_ID is not a valid Apple Team ID." >&2
    exit 1
  fi
  if [ -z "$CODESIGN_IDENTITY" ]; then
    echo "WAAL_CODESIGN_IDENTITY must be set so release packaging can sign the freshly assembled app." >&2
    exit 1
  fi
  if [ -z "$NOTARY_PROFILE" ]; then
    echo "WAAL_NOTARY_PROFILE must be set so release packaging can notarize and staple the freshly signed app." >&2
    exit 1
  fi
  if [ -z "$EXPECTED_BUNDLE_ID" ]; then
    echo "$EXPECTED_BUNDLE_ID_ENV must be set for release packaging." >&2
    exit 1
  fi
  if ! valid_bundle_id "$EXPECTED_BUNDLE_ID"; then
    echo "$EXPECTED_BUNDLE_ID_ENV is not a valid bundle identifier." >&2
    exit 1
  fi
  if [ "$EXPECTED_BUNDLE_ID" = "$DEVELOPMENT_BUNDLE_ID" ]; then
    echo "$EXPECTED_BUNDLE_ID_ENV must not use the development bundle identifier $DEVELOPMENT_BUNDLE_ID." >&2
    exit 1
  fi
  if [ "$RELEASE_DIAGNOSTICS_ARTIFACT" = true ]; then
    if [ -z "$PRODUCTION_BUNDLE_ID" ]; then
      echo "WAAL_RELEASE_BUNDLE_ID must be set so diagnostics packaging can verify it is separate from production." >&2
      exit 1
    fi
    if ! valid_bundle_id "$PRODUCTION_BUNDLE_ID"; then
      echo "WAAL_RELEASE_BUNDLE_ID is not a valid bundle identifier." >&2
      exit 1
    fi
    if [ "$PRODUCTION_BUNDLE_ID" = "$DEVELOPMENT_BUNDLE_ID" ]; then
      echo "WAAL_RELEASE_BUNDLE_ID must not use the development bundle identifier $DEVELOPMENT_BUNDLE_ID." >&2
      exit 1
    fi
    if [ "$EXPECTED_BUNDLE_ID" = "$PRODUCTION_BUNDLE_ID" ]; then
      echo "WAAL_DIAGNOSTICS_BUNDLE_ID must differ from WAAL_RELEASE_BUNDLE_ID for release diagnostics artifacts." >&2
      exit 1
    fi
  fi
}

cleanup() {
  if [ -n "${STAGE_DIR:-}" ]; then
    /bin/rm -rf "$STAGE_DIR"
  fi
}

build_release_executable() {
  BUILD_TARGET_DIR="$STAGE_DIR/target"
  TARGET_EXECUTABLE="$BUILD_TARGET_DIR/release/$BINARY_NAME"
  local release_rustflags="${RUSTFLAGS:-}"
  release_rustflags="${release_rustflags:+$release_rustflags }--remap-path-prefix=$ROOT_DIR=."
  if [ -n "${HOME:-}" ] && [ "${HOME:-}" != "/" ]; then
    release_rustflags="$release_rustflags --remap-path-prefix=$HOME=~"
  fi

  (
    cd "$ROOT_DIR"
    if [ "$RELEASE_DIAGNOSTICS_ARTIFACT" = true ]; then
      env \
        -u CARGO_ENCODED_RUSTFLAGS \
        -u WAAL_DEVELOPMENT_RELEASE \
        -u WAAL_EMBED_DEVELOPMENT_MACOS_BUNDLE_PATH \
        -u WAAL_DEVELOPMENT_MACOS_BUNDLE_PATH \
        WAAL_RELEASE_BUNDLE_ID="$PRODUCTION_BUNDLE_ID" \
        WAAL_DIAGNOSTICS_BUNDLE_ID="$DIAGNOSTICS_BUNDLE_ID" \
        WAAL_MACOS_TEAM_ID="$EXPECTED_TEAM_ID" \
        RUSTFLAGS="$release_rustflags" \
        CARGO_TARGET_DIR="$BUILD_TARGET_DIR" cargo build \
        --locked \
        --release \
        --no-default-features \
        --features release-diagnostics \
        --bin "$BINARY_NAME"
    else
      env \
        -u CARGO_ENCODED_RUSTFLAGS \
        -u WAAL_DEVELOPMENT_RELEASE \
        -u WAAL_EMBED_DEVELOPMENT_MACOS_BUNDLE_PATH \
        -u WAAL_DEVELOPMENT_MACOS_BUNDLE_PATH \
        WAAL_RELEASE_BUNDLE_ID="$PRODUCTION_BUNDLE_ID" \
        WAAL_MACOS_TEAM_ID="$EXPECTED_TEAM_ID" \
        RUSTFLAGS="$release_rustflags" \
        CARGO_TARGET_DIR="$BUILD_TARGET_DIR" cargo build --locked --release --bin "$BINARY_NAME"
    fi
  )

  if [ ! -x "$TARGET_EXECUTABLE" ]; then
    echo "Release build did not produce expected executable: $TARGET_EXECUTABLE" >&2
    exit 1
  fi
}

assemble_release_bundle() {
  local bundle_dir="$1"
  waal_assemble_app_bundle \
    "$ROOT_DIR" \
    "$bundle_dir" \
    "$BINARY_NAME" \
    "$TARGET_EXECUTABLE" \
    "$EXPECTED_BUNDLE_ID" \
    "$APP_DISPLAY_NAME" \
    "$CARGO_VERSION" \
    "$BUILD_VERSION"
}

remove_signature_breaking_xattrs() {
  local bundle_dir="$1"
  local candidates_file="$STAGE_DIR/signature-xattr-candidates.bin"
  local candidate
  local listed_xattrs
  local attribute

  if ! /usr/bin/find "$bundle_dir" -print0 >"$candidates_file"; then
    echo "Failed to enumerate the staged bundle while removing signature-breaking extended attributes." >&2
    exit 1
  fi

  while IFS= read -r -d '' candidate; do
    if ! listed_xattrs="$(/usr/bin/xattr "$candidate")"; then
      echo "Failed to inspect extended attributes: $candidate" >&2
      exit 1
    fi

    for attribute in com.apple.FinderInfo com.apple.ResourceFork; do
      if /usr/bin/printf '%s\n' "$listed_xattrs" | /usr/bin/grep -Fx "$attribute" >/dev/null; then
        /usr/bin/xattr -d "$attribute" "$candidate"
      fi
    done
  done <"$candidates_file"
}

sign_release_bundle() {
  local bundle_dir="$1"
  /usr/bin/codesign \
    --force \
    --options runtime \
    --timestamp \
    --sign "$CODESIGN_IDENTITY" \
    "$bundle_dir"
}

notarize_and_staple_bundle() {
  local bundle_dir="$1"
  local notary_zip="$STAGE_DIR/notary-submit.zip"

  (
    cd "$STAGE_DIR"
    COPYFILE_DISABLE=1 /usr/bin/zip -r -X "$(/usr/bin/basename "$notary_zip")" "$APP_NAME.app" \
      -x "*/.DS_Store" "*/._*" "__MACOSX/*" "*/__MACOSX/*" >/dev/null
  )

  /usr/bin/xcrun notarytool submit "$notary_zip" --keychain-profile "$NOTARY_PROFILE" --wait
  /usr/bin/xcrun stapler staple "$bundle_dir"
}

write_empty_entitlements_plist() {
  /bin/cat <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict/>
</plist>
PLIST
}

verify_release_entitlements() {
  local bundle_dir="$1"
  local actual_raw="$STAGE_DIR/entitlements.actual.raw.plist"
  local actual_norm="$STAGE_DIR/entitlements.actual.xml.plist"
  local expected_raw="$STAGE_DIR/entitlements.expected.raw.plist"
  local expected_norm="$STAGE_DIR/entitlements.expected.xml.plist"
  local codesign_err="$STAGE_DIR/entitlements.codesign.stderr"

  if ! /usr/bin/codesign -d --entitlements - --xml "$bundle_dir" >"$actual_raw" 2>"$codesign_err"; then
    /bin/cat "$codesign_err" >&2
    echo "Unable to extract release bundle entitlements." >&2
    exit 1
  fi

  if [ ! -s "$actual_raw" ]; then
    write_empty_entitlements_plist >"$actual_raw"
  fi
  write_empty_entitlements_plist >"$expected_raw"

  /usr/bin/plutil -convert xml1 -o "$actual_norm" -- "$actual_raw"
  /usr/bin/plutil -convert xml1 -o "$expected_norm" -- "$expected_raw"

  if ! /usr/bin/cmp -s "$expected_norm" "$actual_norm"; then
    echo "Release bundle entitlements do not match allowlist; no entitlements are expected." >&2
    /usr/bin/diff -u "$expected_norm" "$actual_norm" >&2 || true
    exit 1
  fi
}

file_has_macho_magic() {
  local file_path="$1"
  local magic

  if ! magic="$(/usr/bin/od -An -N4 -tx1 "$file_path" 2>/dev/null | /usr/bin/tr -d '[:space:]')"; then
    echo "Failed to inspect file magic: $file_path" >&2
    exit 1
  fi
  case "$magic" in
    feedface|cefaedfe|feedfacf|cffaedfe|cafebabe|bebafeca|cafebabf|bfbafeca) return 0 ;;
    *) return 1 ;;
  esac
}

append_nested_code_candidate() {
  local candidate="$1"
  local main_executable="$2"
  local nested_list="$3"

  if [ "$candidate" != "$main_executable" ]; then
    /usr/bin/printf '%s\n' "$candidate" >>"$nested_list"
  fi
}

verify_no_nested_code() {
  local bundle_dir="$1"
  local bundle_executable
  bundle_executable="$(/usr/bin/plutil -extract CFBundleExecutable raw "$bundle_dir/Contents/Info.plist")"
  local main_executable="$bundle_dir/Contents/MacOS/$bundle_executable"
  local raw_nested="$STAGE_DIR/nested-code.raw.txt"
  local nested_list="$STAGE_DIR/nested-code.txt"
  local structural_candidates="$STAGE_DIR/nested-code-structural-candidates.bin"
  local macho_candidates="$STAGE_DIR/nested-code-macho-candidates.bin"

  : >"$raw_nested"

  if ! /usr/bin/find "$bundle_dir" -mindepth 1 \
    \( -type d \( -name '*.app' -o -name '*.framework' -o -name '*.xpc' -o -name '*.appex' -o -name '*.bundle' -o -name '*.plugin' -o -name '*.qlgenerator' -o -name '*.mdimporter' -o -name '*.saver' -o -name '*.prefPane' \) -print0 -prune \) -o \
    \( -type f \( -perm -100 -o -perm -010 -o -perm -001 \) -print0 \) -o \
    \( -type l -print0 \) >"$structural_candidates"; then
    echo "Failed to enumerate nested executable candidates." >&2
    exit 1
  fi

  while IFS= read -r -d '' candidate; do
    append_nested_code_candidate "$candidate" "$main_executable" "$raw_nested"
  done <"$structural_candidates"

  if ! /usr/bin/find "$bundle_dir" -mindepth 1 \
    \( -type d \( -name '*.app' -o -name '*.framework' -o -name '*.xpc' -o -name '*.appex' -o -name '*.bundle' -o -name '*.plugin' -o -name '*.qlgenerator' -o -name '*.mdimporter' -o -name '*.saver' -o -name '*.prefPane' \) -prune \) -o \
    \( -type f -print0 \) >"$macho_candidates"; then
    echo "Failed to enumerate Mach-O scan candidates." >&2
    exit 1
  fi

  while IFS= read -r -d '' candidate; do
    if file_has_macho_magic "$candidate"; then
      append_nested_code_candidate "$candidate" "$main_executable" "$raw_nested"
    fi
  done <"$macho_candidates"

  if ! LC_ALL=C /usr/bin/sort -u "$raw_nested" >"$nested_list"; then
    echo "Failed to sort nested-code findings." >&2
    exit 1
  fi

  if [ -s "$nested_list" ]; then
    echo "Release bundle contains nested executable code or Mach-O payloads that are not covered by the entitlement allowlist:" >&2
    /bin/cat "$nested_list" >&2
    exit 1
  fi
}

verify_release_build_metadata() {
  local bundle_dir="$1"
  local bundle_executable
  bundle_executable="$(/usr/bin/plutil -extract CFBundleExecutable raw "$bundle_dir/Contents/Info.plist")"
  local executable="$bundle_dir/Contents/MacOS/$bundle_executable"
  local metadata_file="$STAGE_DIR/build-metadata.txt"
  local metadata

  if [ ! -x "$executable" ]; then
    echo "Release bundle executable is missing or not executable: $executable" >&2
    exit 1
  fi

  /usr/bin/strings -a "$executable" | /usr/bin/grep '^WAAL_BUILD_METADATA_V1;' >"$metadata_file" || true
  if [ ! -s "$metadata_file" ]; then
    echo "Release executable is missing WAAL build metadata." >&2
    exit 1
  fi
  if [ "$(/usr/bin/wc -l <"$metadata_file" | /usr/bin/tr -d ' ')" != "1" ]; then
    echo "Release executable contains ambiguous WAAL build metadata." >&2
    exit 1
  fi

  metadata="$(/bin/cat "$metadata_file")"
  require_metadata_field "$metadata" "profile" "release" "Release executable was not built with the release profile."
  require_metadata_field "$metadata" "debug-assertions" "false" "Release executable was built with debug assertions enabled."
  require_metadata_field "$metadata" "macos-bundle-id" "$EXPECTED_BUNDLE_ID" "Release executable runtime bundle identifier does not match $EXPECTED_BUNDLE_ID_ENV."
  require_metadata_field "$metadata" "macos-team-id" "$EXPECTED_TEAM_ID" "Release executable runtime Team ID does not match WAAL_MACOS_TEAM_ID."
  if [ "$RELEASE_DIAGNOSTICS_ARTIFACT" = true ]; then
    require_metadata_field "$metadata" "artifact-kind" "release-diagnostics" "Release diagnostics artifact metadata kind is not release-diagnostics."
    require_metadata_field "$metadata" "debug-fill" "false" "Release diagnostics artifact must not include debug-fill."
    require_metadata_field "$metadata" "dev-tools" "false" "Release diagnostics artifact must not include dev-tools."
    require_metadata_field "$metadata" "diagnostics-ui" "true" "Release diagnostics artifact requires diagnostics-ui metadata."
    require_metadata_field "$metadata" "release-diagnostics" "true" "Release diagnostics artifact requires release-diagnostics metadata."
    require_metadata_field "$metadata" "production-macos-bundle-id" "$PRODUCTION_BUNDLE_ID" "Release diagnostics artifact metadata does not record WAAL_RELEASE_BUNDLE_ID."
    require_metadata_field "$metadata" "non-production-macos-identity" "true" "Release diagnostics artifact must prove it uses a non-production macOS identity."
  else
    require_metadata_field "$metadata" "artifact-kind" "release" "Publishable release bundle metadata kind is not release."
    require_metadata_field "$metadata" "debug-fill" "false" "Publishable release bundle was built with debug-fill enabled."
    require_metadata_field "$metadata" "dev-tools" "false" "Publishable release bundle was built with dev-tools enabled."
    require_metadata_field "$metadata" "diagnostics-ui" "false" "Publishable release bundle was built with diagnostics-ui enabled."
    require_metadata_field "$metadata" "release-diagnostics" "false" "Publishable release bundle was built with release-diagnostics enabled."
    require_metadata_field "$metadata" "production-macos-bundle-id" "$EXPECTED_BUNDLE_ID" "Publishable release metadata production bundle ID does not match WAAL_RELEASE_BUNDLE_ID."
    require_metadata_field "$metadata" "non-production-macos-identity" "false" "Publishable release bundle must not be built with a non-production macOS identity."
  fi
}

verify_no_developer_path_strings() {
  local bundle_dir="$1"
  local bundle_executable
  bundle_executable="$(/usr/bin/plutil -extract CFBundleExecutable raw "$bundle_dir/Contents/Info.plist")"
  local executable="$bundle_dir/Contents/MacOS/$bundle_executable"
  local strings_file="$STAGE_DIR/release-executable-strings.txt"
  local findings_file="$STAGE_DIR/release-developer-path-strings.txt"
  local unique_findings="$STAGE_DIR/release-developer-path-strings.unique.txt"
  local pattern

  /usr/bin/strings -a "$executable" >"$strings_file"
  : >"$findings_file"

  for pattern in \
    "$ROOT_DIR" \
    "${HOME:-}" \
    "/Users/" \
    "/private/var/folders/" \
    "/var/folders/" \
    "CARGO_MANIFEST_DIR" \
    "WAAL_DEVELOPMENT_MACOS_BUNDLE_PATH"; do
    if [ -n "$pattern" ]; then
      /usr/bin/grep -F "$pattern" "$strings_file" >>"$findings_file" || true
    fi
  done

  LC_ALL=C /usr/bin/sort -u "$findings_file" >"$unique_findings"
  if [ -s "$unique_findings" ]; then
    echo "Release executable contains developer-local path strings:" >&2
    /usr/bin/head -n 20 "$unique_findings" >&2
    exit 1
  fi
}

require_metadata_field() {
  local metadata="$1"
  local key="$2"
  local expected="$3"
  local message="$4"

  case "$metadata" in
    *";$key=$expected;"*) ;;
    *)
      echo "$message" >&2
      echo "Build metadata: $metadata" >&2
      exit 1
      ;;
  esac
}

require_info_plist_string() {
  local bundle_dir="$1"
  local key="$2"
  local plist="$bundle_dir/Contents/Info.plist"
  local value

  if ! value="$(/usr/bin/plutil -extract "$key" raw -expect string "$plist" 2>/dev/null)"; then
    echo "Release bundle Info.plist is missing required string key: $key" >&2
    exit 1
  fi
  if [ -z "$(/usr/bin/printf '%s' "$value" | /usr/bin/tr -d '[:space:]')" ]; then
    echo "Release bundle Info.plist has an empty required string key: $key" >&2
    exit 1
  fi
}

verify_release_bundle() {
  local bundle_dir="$1"

  require_tool codesign
  require_tool lipo
  require_tool plutil
  require_tool spctl
  require_tool xcrun

  local bundle_id
  bundle_id="$(/usr/bin/plutil -extract CFBundleIdentifier raw "$bundle_dir/Contents/Info.plist")"
  if [ "$bundle_id" = "$DEVELOPMENT_BUNDLE_ID" ]; then
    echo "Release bundle uses the development CFBundleIdentifier $DEVELOPMENT_BUNDLE_ID." >&2
    exit 1
  fi
  if [ "$bundle_id" != "$EXPECTED_BUNDLE_ID" ]; then
    echo "Unexpected CFBundleIdentifier: $bundle_id" >&2
    exit 1
  fi
  require_info_plist_string "$bundle_dir" NSAppleEventsUsageDescription

  local bundle_executable
  local executable
  local architectures
  bundle_executable="$(/usr/bin/plutil -extract CFBundleExecutable raw "$bundle_dir/Contents/Info.plist")"
  executable="$bundle_dir/Contents/MacOS/$bundle_executable"
  if ! architectures="$(/usr/bin/lipo -archs "$executable" 2>/dev/null)"; then
    echo "Unable to inspect release executable architecture: $executable" >&2
    exit 1
  fi
  if [ "$architectures" != "arm64" ]; then
    echo "Release executable must contain exactly the arm64 architecture; found: $architectures" >&2
    exit 1
  fi

  local requirement
  requirement="=anchor apple generic and certificate leaf[subject.OU] = \"$EXPECTED_TEAM_ID\" and identifier \"$EXPECTED_BUNDLE_ID\""
  /usr/bin/codesign --verify --strict --deep --test-requirement "$requirement" "$bundle_dir"

  local signature
  signature="$(/usr/bin/codesign -dv "$bundle_dir" 2>&1)"
  if echo "$signature" | /usr/bin/grep -q 'Signature=adhoc'; then
    echo "Release bundle is ad-hoc signed." >&2
    exit 1
  fi
  if ! echo "$signature" | /usr/bin/grep -q 'Authority=Developer ID Application:'; then
    echo "Release bundle is not signed with Developer ID Application." >&2
    exit 1
  fi
  if ! echo "$signature" | /usr/bin/grep -q "TeamIdentifier=$EXPECTED_TEAM_ID"; then
    echo "Release bundle TeamIdentifier does not match WAAL_MACOS_TEAM_ID." >&2
    exit 1
  fi
  if ! echo "$signature" | /usr/bin/grep -Eq 'flags=.*runtime'; then
    echo "Release bundle is missing hardened runtime." >&2
    exit 1
  fi

  verify_release_build_metadata "$bundle_dir"
  verify_no_developer_path_strings "$bundle_dir"
  verify_no_nested_code "$bundle_dir"
  verify_release_entitlements "$bundle_dir"

  /usr/sbin/spctl --assess --type execute --verbose "$bundle_dir"
  /usr/bin/xcrun stapler validate "$bundle_dir"
}

validate_archive_entries() {
  local zip_path="$1"
  local entries_file="$STAGE_DIR/zip.entries"

  /usr/bin/unzip -tq "$zip_path"
  if ! /usr/bin/zipinfo -1 "$zip_path" >"$entries_file"; then
    echo "Failed to inspect archive entries: $zip_path" >&2
    exit 1
  fi
  if /usr/bin/grep -E '(^|/)__MACOSX(/|$)|(^|/)\._|(^|/)\.DS_Store$' "$entries_file" >/dev/null; then
    echo "Archive contains macOS metadata sidecars" >&2
    exit 1
  fi
  if /usr/bin/grep -Ev "^$APP_NAME[.]app(/|$)" "$entries_file" >/dev/null; then
    echo "Archive contains entries outside $APP_NAME.app" >&2
    exit 1
  fi
}

extract_and_verify_archive() {
  local zip_path="$1"
  local extract_dir="$STAGE_DIR/extracted"
  local extracted_bundle="$extract_dir/$APP_NAME.app"

  /bin/mkdir -p "$extract_dir"
  /usr/bin/ditto -x -k "$zip_path" "$extract_dir"
  if [ ! -d "$extracted_bundle" ]; then
    echo "Archive does not contain $APP_NAME.app" >&2
    exit 1
  fi
  verify_release_bundle "$extracted_bundle"
}

require_tool codesign
require_tool ditto
require_tool cargo
require_tool iconutil
require_tool lipo
require_tool mktemp
require_tool od
require_tool plutil
require_tool sips
require_tool sort
require_tool spctl
require_tool strings
require_tool tr
require_tool unzip
require_tool xcrun
require_tool xattr
require_tool zip
require_tool zipinfo

validate_release_environment

/bin/mkdir -p "$ROOT_DIR/dist"
/bin/rm -f -- "$ZIP_PATH"

STAGE_DIR="$(/usr/bin/mktemp -d "$ROOT_DIR/dist/.package_macos.XXXXXX")"
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

STAGED_BUNDLE="$STAGE_DIR/$APP_NAME.app"
TMP_ZIP="$STAGE_DIR/$(/usr/bin/basename "$ZIP_PATH")"

build_release_executable
assemble_release_bundle "$STAGED_BUNDLE"
verify_release_build_metadata "$STAGED_BUNDLE"
remove_signature_breaking_xattrs "$STAGED_BUNDLE"
sign_release_bundle "$STAGED_BUNDLE"
notarize_and_staple_bundle "$STAGED_BUNDLE"

/usr/bin/find "$STAGED_BUNDLE" \( -name .DS_Store -o -name '._*' \) -type f -delete
/usr/bin/find "$STAGED_BUNDLE" -type d -name __MACOSX -prune -exec /bin/rm -rf {} +

verify_release_bundle "$STAGED_BUNDLE"

(
  cd "$STAGE_DIR"
  COPYFILE_DISABLE=1 /usr/bin/zip -r -X "$(/usr/bin/basename "$TMP_ZIP")" "$APP_NAME.app" \
    -x "*/.DS_Store" "*/._*" "__MACOSX/*" "*/__MACOSX/*" >/dev/null
)

validate_archive_entries "$TMP_ZIP"
extract_and_verify_archive "$TMP_ZIP"

/bin/mv -f "$TMP_ZIP" "$ZIP_PATH"

echo "$ZIP_PATH"
