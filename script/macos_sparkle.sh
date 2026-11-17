#!/usr/bin/env bash
# Sparkle is loaded from the signed app bundle, never from an ambient search path.
# Keep the framework and release tools pinned to the same upstream distribution.

waal_fetch_sparkle_archive() {
  local archive="$1"
  local expected="cb6fdbdc8884f15d62a616e79face92b08322410fd2d425edc6596ccbf4ba3b0"
  local actual=""
  if [ -f "$archive" ] && [ ! -L "$archive" ]; then
    actual="$(/usr/bin/shasum -a 256 "$archive" | /usr/bin/awk '{print $1}')"
  fi
  if [ "$actual" != "$expected" ]; then
    /bin/mkdir -p "$(/usr/bin/dirname "$archive")" || return 1
    local download
    download="$(/usr/bin/mktemp "${archive}.XXXXXX")" || return 1
    if ! /usr/bin/curl --fail --location --silent --show-error --proto '=https' \
      --tlsv1.2 --retry 2 --max-time 120 \
      'https://github.com/sparkle-project/Sparkle/releases/download/2.9.4/Sparkle-for-Swift-Package-Manager.zip' \
      --output "$download"; then
      /bin/rm -f "$download"
      return 1
    fi
    actual="$(/usr/bin/shasum -a 256 "$download" | /usr/bin/awk '{print $1}')"
    if [ "$actual" != "$expected" ]; then
      echo "Sparkle archive checksum does not match the pinned 2.9.4 distribution." >&2
      /bin/rm -f "$download"
      return 1
    fi
    /bin/mv -f "$download" "$archive" || return 1
  fi
}

waal_stage_sparkle() (
  set -euo pipefail
  local root_dir="$1" bundle_dir="$2"
  local archive="${3:-$root_dir/target/sparkle/Sparkle-2.9.4.zip}"
  local temporary_root
  temporary_root="$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/waal-sparkle.XXXXXX")"
  trap '/bin/rm -rf "$temporary_root"' EXIT
  waal_fetch_sparkle_archive "$archive"
  # Always extract verified archive bytes anew; do not trust a mutable cache of
  # framework files or execute tools supplied by a different installed app.
  /usr/bin/ditto -xk "$archive" "$temporary_root"
  local source="$temporary_root/Sparkle.xcframework/macos-arm64_x86_64/Sparkle.framework"
  local destination="$bundle_dir/Contents/Frameworks/Sparkle.framework"
  test -f "$source/Sparkle"
  test -x "$source/Versions/B/Updater.app/Contents/MacOS/Updater"
  test -d "$source/Versions/B/XPCServices/Installer.xpc"
  /bin/mkdir -p "$bundle_dir/Contents/Frameworks"
  /bin/rm -rf "$destination"
  /usr/bin/ditto --noqtn "$source" "$destination"

  /usr/bin/python3 - "$root_dir" "$bundle_dir" <<'PY'
import base64
import pathlib
import plistlib
import sys

root, bundle = map(pathlib.Path, sys.argv[1:])
key = (root / 'macos/SparklePublicKey.txt').read_text().strip()
if len(base64.b64decode(key, validate=True)) != 32:
    raise SystemExit('Sparkle public key must contain 32 bytes')
path = bundle / 'Contents/Info.plist'
info = plistlib.loads(path.read_bytes())
identity = info['CFBundleIdentifier']
base = 'https://obcardinal.com/assets/downloads/windows-app-autologin/macos/'
if identity == 'obcardinal.windows-app-autologin':
    feed = base + 'development/appcast.xml'
    automatic = False
elif identity == 'com.obcardinal.WindowsAppAutoLogin':
    feed = base + 'appcast.xml'
    automatic = True
else:
    raise SystemExit('No Sparkle update channel configured for this bundle identity')
info.update({
    'SUFeedURL': feed,
    'SUPublicEDKey': key,
    'SUEnableAutomaticChecks': automatic,
    'SUScheduledCheckInterval': 21600,
    'SUAutomaticallyUpdate': False,
    'SUAllowsAutomaticUpdates': False,
    'WAALSparkleVersion': '2.9.4',
    'WAALSupportsCheckForUpdatesURL': True,
    'CFBundleURLTypes': [{
        'CFBundleURLName': 'Windows App AutoLogin update check',
        'CFBundleURLSchemes': ['windows-app-autologin'],
        'CFBundleTypeRole': 'Viewer',
    }],
})
path.write_bytes(plistlib.dumps(info, sort_keys=False))
PY
)

waal_sign_sparkle() {
  local bundle_dir="$1" identity="$2" timestamp="${3:---timestamp=none}"
  local frameworks="$bundle_dir/Contents/Frameworks"
  [ -d "$frameworks/Sparkle.framework" ] || return 0
  local entry
  while IFS= read -r -d '' entry; do
    if /usr/bin/file -b "$entry" | /usr/bin/grep -q 'Mach-O'; then
      /usr/bin/codesign --force --options runtime "$timestamp" --sign "$identity" \
        --preserve-metadata=identifier,entitlements "$entry" || return 1
    fi
  done < <(/usr/bin/find "$frameworks/Sparkle.framework" -type f -print0)
  while IFS= read -r -d '' entry; do
    /usr/bin/codesign --force --options runtime "$timestamp" --sign "$identity" \
      --preserve-metadata=identifier,entitlements "$entry" || return 1
  done < <(/usr/bin/find "$frameworks/Sparkle.framework" -depth -type d \
    \( -name '*.xpc' -o -name '*.app' -o -name '*.framework' \) -print0)
  /usr/bin/codesign --verify --deep --strict "$frameworks/Sparkle.framework"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  if [ "$#" -ne 1 ]; then
    echo 'Usage: script/macos_sparkle.sh /absolute/path/to/WindowsAppAutoLogin.app' >&2
    exit 2
  fi
  root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  waal_stage_sparkle "$root_dir" "$1"
fi
