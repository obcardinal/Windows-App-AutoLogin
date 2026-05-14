#!/usr/bin/env bash

waal_require_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required tool: $1" >&2
    exit 1
  fi
}

waal_valid_bundle_id() {
  case "$1" in
    ""|.*|*..*|*.) return 1 ;;
  esac
  case "$1" in
    *.*) ;;
    *) return 1 ;;
  esac
  case "$1" in
    *[!A-Za-z0-9.-]*|*-.*|*.-*) return 1 ;;
  esac
  [ "${#1}" -le 255 ]
}

waal_cargo_version() {
  local root_dir="$1"
  /usr/bin/awk -F '"' '/^version = / { print $2; exit }' "$root_dir/Cargo.toml"
}

waal_build_version() {
  local cargo_version="$1"
  /usr/bin/printf '%s.%s\n' "$cargo_version" "$(/bin/date +%Y%m%d%H%M%S)"
}

waal_xml_escape() {
  /usr/bin/sed \
    -e 's/&/\&amp;/g' \
    -e 's/</\&lt;/g' \
    -e 's/>/\&gt;/g' \
    -e 's/"/\&quot;/g' \
    -e "s/'/\&apos;/g"
}

waal_build_app_icon() {
  local app_icon="$1"
  local resources_dir="$2"

  if [ ! -f "$app_icon" ]; then
    echo "Missing app icon: $app_icon" >&2
    exit 1
  fi
  waal_require_tool sips
  waal_require_tool iconutil

  local iconset_dir="$resources_dir/AppIcon.iconset"
  /bin/rm -rf "$iconset_dir"
  /bin/mkdir -p "$iconset_dir"
  local size
  for size in 16 32 128 256 512; do
    /usr/bin/sips -z "$size" "$size" "$app_icon" --out "$iconset_dir/icon_${size}x${size}.png" >/dev/null
    local retina_size=$((size * 2))
    /usr/bin/sips -z "$retina_size" "$retina_size" "$app_icon" --out "$iconset_dir/icon_${size}x${size}@2x.png" >/dev/null
  done
  /usr/bin/iconutil -c icns "$iconset_dir" -o "$resources_dir/AppIcon.icns" >/dev/null
  /bin/rm -rf "$iconset_dir"
  if [ ! -s "$resources_dir/AppIcon.icns" ]; then
    echo "Failed to build AppIcon.icns" >&2
    exit 1
  fi
}

waal_write_info_plist() {
  local contents_dir="$1"
  local binary_name="$2"
  local bundle_id="$3"
  local app_display_name="$4"
  local cargo_version="$5"
  local build_version="$6"

  local escaped_binary_name
  local escaped_bundle_id
  local escaped_app_display_name
  local escaped_cargo_version
  local escaped_build_version
  escaped_binary_name="$(/usr/bin/printf '%s' "$binary_name" | waal_xml_escape)"
  escaped_bundle_id="$(/usr/bin/printf '%s' "$bundle_id" | waal_xml_escape)"
  escaped_app_display_name="$(/usr/bin/printf '%s' "$app_display_name" | waal_xml_escape)"
  escaped_cargo_version="$(/usr/bin/printf '%s' "$cargo_version" | waal_xml_escape)"
  escaped_build_version="$(/usr/bin/printf '%s' "$build_version" | waal_xml_escape)"

  /bin/cat >"$contents_dir/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleExecutable</key>
  <string>$escaped_binary_name</string>
  <key>CFBundleIdentifier</key>
  <string>$escaped_bundle_id</string>
  <key>CFBundleName</key>
  <string>$escaped_app_display_name</string>
  <key>CFBundleDisplayName</key>
  <string>$escaped_app_display_name</string>
  <key>CFBundleIconFile</key>
  <string>AppIcon</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>$escaped_cargo_version</string>
  <key>CFBundleVersion</key>
  <string>$escaped_build_version</string>
  <key>LSMinimumSystemVersion</key>
  <string>11.0</string>
  <key>LSApplicationCategoryType</key>
  <string>public.app-category.utilities</string>
  <key>NSHighResolutionCapable</key>
  <true/>
  <key>NSPrincipalClass</key>
  <string>NSApplication</string>
  <key>NSAppleEventsUsageDescription</key>
  <string>Windows App AutoLogin uses System Events only to manage Open at Login cleanup and inspect trusted Windows App sign-in controls for guarded autofill or diagnostics.</string>
  <key>LSUIElement</key>
  <true/>
</dict>
</plist>
PLIST
}

waal_assemble_app_bundle() {
  local root_dir="$1"
  local bundle_dir="$2"
  local binary_name="$3"
  local source_executable="$4"
  local bundle_id="$5"
  local app_display_name="$6"
  local cargo_version="$7"
  local build_version="$8"

  local contents_dir="$bundle_dir/Contents"
  local macos_dir="$contents_dir/MacOS"
  local resources_dir="$contents_dir/Resources"

  if [ ! -x "$source_executable" ]; then
    echo "Missing built executable: $source_executable" >&2
    exit 1
  fi
  if ! waal_valid_bundle_id "$bundle_id"; then
    echo "Invalid macOS bundle identifier: $bundle_id" >&2
    exit 1
  fi

  /bin/rm -rf "$bundle_dir"
  /bin/mkdir -p "$macos_dir" "$resources_dir"
  /bin/cp "$source_executable" "$macos_dir/$binary_name"
  /bin/chmod +x "$macos_dir/$binary_name"

  waal_build_app_icon "$root_dir/assets/icon.png" "$resources_dir"
  waal_write_info_plist \
    "$contents_dir" \
    "$binary_name" \
    "$bundle_id" \
    "$app_display_name" \
    "$cargo_version" \
    "$build_version"
}

waal_codesign_development_bundle() {
  local bundle_dir="$1"
  local bundle_id="$2"

  /usr/bin/codesign \
    --force \
    --sign - \
    --identifier "$bundle_id" \
    --requirements "=designated => identifier \"$bundle_id\"" \
    "$bundle_dir"
}
