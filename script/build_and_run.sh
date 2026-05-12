#!/usr/bin/env bash
set -euo pipefail
export PATH="/usr/bin:/bin:/usr/sbin:/sbin:${HOME:-}/.cargo/bin"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_NAME="WindowsAppAutoLogin"
APP_DISPLAY_NAME="Windows App AutoLogin"
BUNDLE_ID="dev.codex.windows-app-autologin"
BINARY_NAME="windows-app-autologin"
BUNDLE_DIR="$ROOT_DIR/dist/$APP_NAME.app"
CONTENTS_DIR="$BUNDLE_DIR/Contents"
MACOS_DIR="$CONTENTS_DIR/MacOS"
RESOURCES_DIR="$CONTENTS_DIR/Resources"
APP_ICON="$ROOT_DIR/assets/icon.png"
APP_EXECUTABLE="$MACOS_DIR/$BINARY_NAME"
TARGET_EXECUTABLE="$ROOT_DIR/target/release/$BINARY_NAME"
DEFAULT_CACHE_ROOT="${HOME:-/tmp}/Library/Caches"
LOCK_ROOT="${XDG_CACHE_HOME:-$DEFAULT_CACHE_ROOT}/WindowsAppAutoLogin"
LOCK_DIR="$LOCK_ROOT/WindowsAppAutoLogin.lock"
CARGO_VERSION="$(awk -F '"' '/^version = / { print $2; exit }' "$ROOT_DIR/Cargo.toml")"
BUILD_VERSION="${CARGO_VERSION}.$(date +%Y%m%d%H%M%S)"

VERIFY=false
FULL_UI=false
DEV_UI=false
for arg in "$@"; do
  case "$arg" in
    --verify) VERIFY=true ;;
    --full-ui) FULL_UI=true ;;
    --dev-ui) DEV_UI=true; FULL_UI=true ;;
    *) echo "Unknown argument: $arg" >&2; exit 2 ;;
  esac
done

app_pids() {
  ps -axo pid=,command= | awk -v app="$APP_EXECUTABLE" -v target="$TARGET_EXECUTABLE" '
    {
      pid = $1
      sub(/^[[:space:]]*[0-9]+[[:space:]]+/, "", $0)
      if ($0 == app || index($0, app " ") == 1 || $0 == target || index($0, target " ") == 1) {
        print pid
      }
    }
  '
}

for pid in $(app_pids); do
  pkill -P "$pid" 2>/dev/null || true
  kill "$pid" 2>/dev/null || true
done

lock_pid=""
if [ -f "$LOCK_DIR/pid" ]; then
  lock_pid="$(cat "$LOCK_DIR/pid" 2>/dev/null || true)"
  if [ -n "$lock_pid" ] && app_pids | grep -qx "$lock_pid"; then
    pkill -P "$lock_pid" 2>/dev/null || true
    kill "$lock_pid" 2>/dev/null || true
  fi
fi

for _ in 1 2 3 4 5; do
  if [ -z "$(app_pids)" ]; then
    break
  fi
  sleep 0.2
done

if [ -n "$lock_pid" ]; then
  for _ in 1 2 3 4 5; do
    if ! ps -p "$lock_pid" >/dev/null 2>&1; then
      break
    fi
    sleep 0.2
  done
  if app_pids | grep -qx "$lock_pid"; then
    kill -9 "$lock_pid" 2>/dev/null || true
  fi
fi

for pid in $(app_pids); do
  kill -9 "$pid" 2>/dev/null || true
done
rm -rf "$LOCK_DIR"

cd "$ROOT_DIR"
if [ "$DEV_UI" = true ]; then
  cargo build --release --features dev-tools --bin "$BINARY_NAME"
else
  cargo build --release --bin "$BINARY_NAME"
fi

rm -rf "$BUNDLE_DIR"
mkdir -p "$MACOS_DIR" "$RESOURCES_DIR"
cp "$TARGET_EXECUTABLE" "$APP_EXECUTABLE"
chmod +x "$MACOS_DIR/$BINARY_NAME"

if [ ! -f "$APP_ICON" ]; then
  echo "Missing app icon: $APP_ICON" >&2
  exit 1
fi
if ! command -v sips >/dev/null 2>&1 || ! command -v iconutil >/dev/null 2>&1; then
  echo "sips and iconutil are required to build the macOS app icon" >&2
  exit 1
fi

ICONSET_DIR="$RESOURCES_DIR/AppIcon.iconset"
rm -rf "$ICONSET_DIR"
mkdir -p "$ICONSET_DIR"
for size in 16 32 128 256 512; do
  sips -z "$size" "$size" "$APP_ICON" --out "$ICONSET_DIR/icon_${size}x${size}.png" >/dev/null
  retina_size=$((size * 2))
  sips -z "$retina_size" "$retina_size" "$APP_ICON" --out "$ICONSET_DIR/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil -c icns "$ICONSET_DIR" -o "$RESOURCES_DIR/AppIcon.icns" >/dev/null
rm -rf "$ICONSET_DIR"
if [ ! -s "$RESOURCES_DIR/AppIcon.icns" ]; then
  echo "Failed to build AppIcon.icns" >&2
  exit 1
fi

cat > "$CONTENTS_DIR/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleExecutable</key>
  <string>$BINARY_NAME</string>
  <key>CFBundleIdentifier</key>
  <string>$BUNDLE_ID</string>
  <key>CFBundleName</key>
  <string>$APP_DISPLAY_NAME</string>
  <key>CFBundleDisplayName</key>
  <string>$APP_DISPLAY_NAME</string>
  <key>CFBundleIconFile</key>
  <string>AppIcon</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>$CARGO_VERSION</string>
  <key>CFBundleVersion</key>
  <string>$BUILD_VERSION</string>
  <key>LSMinimumSystemVersion</key>
  <string>11.0</string>
  <key>LSApplicationCategoryType</key>
  <string>public.app-category.utilities</string>
  <key>NSHighResolutionCapable</key>
  <true/>
  <key>NSPrincipalClass</key>
  <string>NSApplication</string>
  <key>LSUIElement</key>
  <true/>
</dict>
</plist>
PLIST

if command -v codesign >/dev/null 2>&1; then
  codesign --force --sign - "$BUNDLE_DIR"
  codesign --verify --strict "$BUNDLE_DIR"
fi

LSREGISTER="/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"
if [ -x "$LSREGISTER" ]; then
  for stale_bundle in "/tmp/$APP_NAME.app" "/private/tmp/$APP_NAME.app"; do
    if [ "$stale_bundle" != "$BUNDLE_DIR" ]; then
      "$LSREGISTER" -u "$stale_bundle" >/dev/null 2>&1 || true
      rm -rf "$stale_bundle"
    fi
  done
  "$LSREGISTER" -u "$BUNDLE_DIR" >/dev/null 2>&1 || true
  /usr/bin/touch "$BUNDLE_DIR"
  "$LSREGISTER" -f "$BUNDLE_DIR" >/dev/null 2>&1 || true
fi

if [ "$FULL_UI" = true ]; then
  /usr/bin/open -n "$BUNDLE_DIR" --args --full-ui
else
  /usr/bin/open -n "$BUNDLE_DIR"
fi

if [ "$VERIFY" = true ]; then
  sleep 2
  test -n "$(app_pids)"
fi
