#!/usr/bin/env bash
set -euo pipefail
export PATH="/usr/bin:/bin:/usr/sbin:/sbin:${HOME:-}/.cargo/bin"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=script/macos_bundle.sh
source "$ROOT_DIR/script/macos_bundle.sh"
APP_NAME="WindowsAppAutoLogin"
APP_DISPLAY_NAME="Windows App AutoLogin"
BUNDLE_ID="dev.codex.windows-app-autologin"
BINARY_NAME="windows-app-autologin"
BUNDLE_DIR="$ROOT_DIR/dist/$APP_NAME.app"
CONTENTS_DIR="$BUNDLE_DIR/Contents"
MACOS_DIR="$CONTENTS_DIR/MacOS"
APP_EXECUTABLE="$MACOS_DIR/$BINARY_NAME"
TARGET_EXECUTABLE="$ROOT_DIR/target/release/$BINARY_NAME"
DEFAULT_RUNTIME_ROOT="${HOME:-/tmp}/Library/Application Support/WindowsAppAutoLogin/Runtime"
LOCK_ROOT="${WAAL_RUNTIME_ROOT:-$DEFAULT_RUNTIME_ROOT}"
LOCK_DIR="$LOCK_ROOT/WindowsAppAutoLogin.lock"
FULL_UI_LOCK_DIR="$LOCK_ROOT/WindowsAppAutoLogin.full-ui.lock"
MONITOR_STATUS_FILE="$LOCK_ROOT/monitor-status"
CARGO_VERSION="$(waal_cargo_version "$ROOT_DIR")"
BUILD_VERSION="$(waal_build_version "$CARGO_VERSION")"

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
  ps -axo pid=,command= | awk \
    -v app="$APP_EXECUTABLE" \
    -v target="$TARGET_EXECUTABLE" \
    -v app_name="$APP_NAME" \
    -v binary_name="$BINARY_NAME" '
    {
      pid = $1
      sub(/^[[:space:]]*[0-9]+[[:space:]]+/, "", $0)
      exe = $1
      bundle_suffix = "/" app_name ".app/Contents/MacOS/" binary_name
      if (exe == app || exe == target || substr(exe, length(exe) - length(bundle_suffix) + 1) == bundle_suffix) {
        print pid
      }
    }
  '
}

cleanup_app_instances() {
  for pid in $(app_pids); do
    pkill -P "$pid" 2>/dev/null || true
    kill "$pid" 2>/dev/null || true
  done

  local lock_pid=""
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
  rm -rf "$FULL_UI_LOCK_DIR"
  if [ -f "$MONITOR_STATUS_FILE" ]; then
    /usr/bin/printf 'idle\n' >"$MONITOR_STATUS_FILE" 2>/dev/null || true
  fi
}

read_monitor_status_file() {
  if [ ! -f "$MONITOR_STATUS_FILE" ]; then
    return 1
  fi
  /usr/bin/head -n 1 "$MONITOR_STATUS_FILE" 2>/dev/null | /usr/bin/tr -d '[:space:]'
}

wait_for_monitor_status() {
  local status=""
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    status="$(read_monitor_status_file || true)"
    case "$status" in
      running|idle)
        /usr/bin/printf 'Monitor status: %s\n' "$status"
        return 0
        ;;
    esac
    sleep 0.5
  done
  echo "Monitor status was not published by the launched app." >&2
  return 1
}

cleanup_app_instances
rm -f "$MONITOR_STATUS_FILE"

cd "$ROOT_DIR"
if [ "$DEV_UI" = true ]; then
  env -u WAAL_RELEASE_BUNDLE_ID -u WAAL_MACOS_TEAM_ID WAAL_DEVELOPMENT_RELEASE=1 cargo build --release --features dev-tools --bin "$BINARY_NAME"
else
  env -u WAAL_RELEASE_BUNDLE_ID -u WAAL_MACOS_TEAM_ID WAAL_DEVELOPMENT_RELEASE=1 cargo build --release --bin "$BINARY_NAME"
fi

waal_assemble_app_bundle \
  "$ROOT_DIR" \
  "$BUNDLE_DIR" \
  "$BINARY_NAME" \
  "$TARGET_EXECUTABLE" \
  "$BUNDLE_ID" \
  "$APP_DISPLAY_NAME" \
  "$CARGO_VERSION" \
  "$BUILD_VERSION"

if command -v codesign >/dev/null 2>&1; then
  waal_codesign_development_bundle "$BUNDLE_DIR" "$BUNDLE_ID"
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
  trap cleanup_app_instances EXIT
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    if [ -n "$(app_pids)" ]; then
      break
    fi
    sleep 0.5
  done
  test -n "$(app_pids)"
  if [ "$FULL_UI" != true ]; then
    wait_for_monitor_status
  fi
fi
