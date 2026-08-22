#!/usr/bin/env bash
set -euo pipefail
umask 022

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

write_crafted_stored_zip() {
  local archive_path="$1"
  shift
  /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin \
    /usr/bin/perl -MCompress::Raw::Zlib=crc32 -e '
      use strict;
      use warnings;
      use bytes;
      my $archive = shift @ARGV;
      my $local_bytes = "";
      my $central_bytes = "";
      my $offset = 0;
      my $count = 0;
      for my $spec (@ARGV) {
        my ($mode_text, $central_hex, $local_hex, $data_hex, $method_text,
            $compressed_text, $uncompressed_text) = split(/\|/, $spec, -1);
        die "invalid crafted ZIP spec\n" unless defined $data_hex;
        my $mode = oct($mode_text);
        my $central_name = pack("H*", $central_hex);
        my $local_name = $local_hex eq "-" ? $central_name : pack("H*", $local_hex);
        my $data = $data_hex =~ /^z([0-9]+)$/
          ? "\0" x $1
          : pack("H*", $data_hex);
        my $method = defined($method_text) && $method_text ne "" ? 0 + $method_text : 0;
        my $needed = $method == 8 ? 20 : 10;
        my $compressed_size = defined($compressed_text) && $compressed_text ne ""
          ? 0 + $compressed_text : length($data);
        my $uncompressed_size = defined($uncompressed_text) && $uncompressed_text ne ""
          ? 0 + $uncompressed_text : length($data);
        my $crc = crc32($data);
        my $external = ($mode << 16) | (($mode & 0170000) == 0040000 ? 0x10 : 0);
        my $local = pack("VvvvvvVVVvv",
          0x04034b50, $needed, 0, $method, 0, 0x21, $crc,
          $compressed_size, $uncompressed_size,
          length($local_name), 0) . $local_name . $data;
        my $central = pack("VvvvvvvVVVvvvvvVV",
          0x02014b50, (3 << 8) | 30, $needed, 0, $method, 0, 0x21, $crc,
          $compressed_size, $uncompressed_size, length($central_name), 0, 0, 0, 0,
          $external, $offset) . $central_name;
        $local_bytes .= $local;
        $central_bytes .= $central;
        $offset += length($local);
        ++$count;
      }
      my $eocd = pack("VvvvvVVv", 0x06054b50, 0, 0, $count, $count,
        length($central_bytes), length($local_bytes), 0);
      open my $out, ">:raw", $archive or die "create crafted ZIP: $!\n";
      print {$out} $local_bytes, $central_bytes, $eocd
        or die "write crafted ZIP: $!\n";
      close $out or die "close crafted ZIP: $!\n";
    ' "$archive_path" "$@"
}

write_crafted_raw_deflate_zip() {
  local archive_path="$1"
  local actual_size="$2"
  local declared_size="$3"
  local crc_mode="${4:-matching}"

  /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin \
    /usr/bin/perl \
      -MCompress::Raw::Zlib=crc32,MAX_WBITS,Z_OK,Z_STREAM_END \
      -e '
        use strict;
        use warnings;
        use bytes;
        my ($archive, $actual_size, $declared_size, $crc_mode) = @ARGV;
        die "invalid raw Deflate fixture size\n"
          unless $actual_size =~ /\A[0-9]+\z/ && $declared_size =~ /\A[0-9]+\z/;
        die "invalid raw Deflate fixture CRC mode\n"
          unless $crc_mode eq "matching" || $crc_mode eq "mismatch";

        my $root = "WindowsAppAutoLogin.app/";
        my $name = "WindowsAppAutoLogin.app/Contents/file";
        my $payload = "\0" x $actual_size;
        my ($deflater, $status) = Compress::Raw::Zlib::Deflate->new(
          -WindowBits => -MAX_WBITS,
        );
        die "create raw Deflate fixture: $status\n"
          unless defined($deflater) && $status == Z_OK;
        my $compressed_head = "";
        $status = $deflater->deflate($payload, $compressed_head);
        die "compress raw Deflate fixture: $status\n" unless $status == Z_OK;
        my $compressed_tail = "";
        $status = $deflater->flush($compressed_tail);
        die "finish raw Deflate fixture: $status\n" unless $status == Z_OK;
        my $compressed = $compressed_head . $compressed_tail;
        die "raw Deflate fixture is empty\n" unless length($compressed) > 0;

        my $actual_crc = crc32($payload);
        my $declared_crc = $crc_mode eq "mismatch"
          ? (($actual_crc ^ 0xffffffff) & 0xffffffff)
          : $actual_crc;
        my $root_mode = 040755;
        my $file_mode = 0100644;
        my $root_external = ($root_mode << 16) | 0x10;
        my $file_external = $file_mode << 16;

        my $root_local = pack("VvvvvvVVVvv",
          0x04034b50, 10, 0, 0, 0, 0x21, 0, 0, 0,
          length($root), 0) . $root;
        my $file_offset = length($root_local);
        my $file_local = pack("VvvvvvVVVvv",
          0x04034b50, 20, 0, 8, 0, 0x21, $declared_crc,
          length($compressed), $declared_size, length($name), 0)
          . $name . $compressed;
        my $local_bytes = $root_local . $file_local;
        my $root_central = pack("VvvvvvvVVVvvvvvVV",
          0x02014b50, (3 << 8) | 30, 10, 0, 0, 0, 0x21,
          0, 0, 0, length($root), 0, 0, 0, 0,
          $root_external, 0) . $root;
        my $file_central = pack("VvvvvvvVVVvvvvvVV",
          0x02014b50, (3 << 8) | 30, 20, 0, 8, 0, 0x21,
          $declared_crc, length($compressed), $declared_size,
          length($name), 0, 0, 0, 0, $file_external, $file_offset) . $name;
        my $central_bytes = $root_central . $file_central;
        my $eocd = pack("VvvvvVVv", 0x06054b50, 0, 0, 2, 2,
          length($central_bytes), length($local_bytes), 0);

        open my $out, ">:raw", $archive or die "create raw Deflate ZIP: $!\n";
        print {$out} $local_bytes, $central_bytes, $eocd
          or die "write raw Deflate ZIP: $!\n";
        close $out or die "close raw Deflate ZIP: $!\n";
      ' "$archive_path" "$actual_size" "$declared_size" "$crc_mode"
}

hex_bytes() {
  /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin \
    /usr/bin/perl -e 'use bytes; print unpack("H*", shift @ARGV)' -- "$1"
}

write_crafted_entry_count_limit_zip() {
  local archive_path="$1"
  local entry_limit="$2"
  /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin \
    /usr/bin/perl -MCompress::Raw::Zlib=crc32 -e '
      use strict;
      use warnings;
      use bytes;
      my ($archive, $limit) = @ARGV;
      my $root = "WindowsAppAutoLogin.app/";
      my $local_bytes = "";
      my $central_bytes = "";
      my $offset = 0;
      for my $number (0 .. $limit) {
        my $directory = $number == 0;
        my $name = $directory
          ? $root
          : sprintf("%sContents/entry-%05d", $root, $number);
        my $mode = $directory ? 040755 : 0100644;
        my $external = ($mode << 16) | ($directory ? 0x10 : 0);
        my $local = pack("VvvvvvVVVvv",
          0x04034b50, 10, 0, 0, 0, 0x21, 0, 0, 0, length($name), 0) . $name;
        my $central = pack("VvvvvvvVVVvvvvvVV",
          0x02014b50, (3 << 8) | 30, 10, 0, 0, 0, 0x21,
          0, 0, 0, length($name), 0, 0, 0, 0, $external, $offset) . $name;
        $local_bytes .= $local;
        $central_bytes .= $central;
        $offset += length($local);
      }
      my $count = $limit + 1;
      my $eocd = pack("VvvvvVVv", 0x06054b50, 0, 0, $count, $count,
        length($central_bytes), length($local_bytes), 0);
      open my $out, ">:raw", $archive or die "create count-limit ZIP: $!\n";
      print {$out} $local_bytes, $central_bytes, $eocd
        or die "write count-limit ZIP: $!\n";
      close $out or die "close count-limit ZIP: $!\n";
    ' "$archive_path" "$entry_limit"
}

assert_archive_resource_limit_rejected() {
  local label="$1"
  local archive_path="$2"
  local expected_diagnostic="$3"
  local extract_label="resource-limit-$label-extracted"
  local diagnostics="$STAGE_DIR/resource-limit-$label.stderr"

  if validate_archive_entries "$archive_path" >"$diagnostics" 2>&1; then
    fail "$label ZIP resource limit was accepted by structural preflight"
  fi
  /usr/bin/grep -Fq \
    "ZIP resource limit exceeded: $expected_diagnostic" "$diagnostics" \
    || fail "$label ZIP rejection did not report its exact resource-limit diagnostic"
  if extract_and_verify_archive \
    "$archive_path" "$extract_label" >"$diagnostics" 2>&1; then
    fail "$label ZIP resource limit was accepted for extraction"
  fi
  /usr/bin/grep -Fq \
    "ZIP resource limit exceeded: $expected_diagnostic" "$diagnostics" \
    || fail "$label ZIP extraction rejection lost its exact resource-limit diagnostic"
  [ ! -e "$STAGE_DIR/$extract_label" ] \
    || fail "$label ZIP created an extraction directory before its resource check"
}

assert_archive_rejected_before_extraction() {
  local label="$1"
  shift
  local archive_path="$STAGE_DIR/rejected-$label.zip"
  local extract_label="rejected-$label-extracted"

  write_crafted_stored_zip "$archive_path" "$@"
  if validate_archive_entries "$archive_path" >/dev/null 2>&1; then
    fail "unsafe $label ZIP passed structural preflight"
  fi
  if extract_and_verify_archive "$archive_path" "$extract_label" >/dev/null 2>&1; then
    fail "unsafe $label ZIP was extracted"
  fi
  [ ! -e "$STAGE_DIR/$extract_label" ] \
    || fail "unsafe $label ZIP created an extraction directory before validation"
}

assert_archive_payload_rejected_before_extraction() {
  local label="$1"
  local archive_path="$2"
  local expected_diagnostic="$3"
  local extract_label="payload-$label-extracted"
  local diagnostics="$STAGE_DIR/payload-$label.stderr"

  if validate_archive_entries "$archive_path" >"$diagnostics" 2>&1; then
    fail "$label ZIP payload mismatch passed descriptor-bound validation"
  fi
  /usr/bin/grep -Fq "$expected_diagnostic" "$diagnostics" \
    || fail "$label ZIP payload rejection did not report its exact diagnostic"
  if extract_and_verify_archive \
    "$archive_path" "$extract_label" >"$diagnostics" 2>&1; then
    fail "$label ZIP payload mismatch was extracted"
  fi
  /usr/bin/grep -Fq "$expected_diagnostic" "$diagnostics" \
    || fail "$label ZIP extraction rejection lost its exact diagnostic"
  [ ! -e "$STAGE_DIR/$extract_label" ] \
    || fail "$label ZIP created an extraction directory before payload validation"
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
      /usr/bin/chflags -R -P nouchg . || exit 1
      /bin/chmod -R u+w . || exit 1
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

EARLY_GUARD_TOOL="$TEST_ROOT/publishable-entry-point-tool"
EARLY_GUARD_MARKER="$TEST_ROOT/publishable-entry-point-tool.ran"
EARLY_GUARD_HOSTILE_PATH="$TEST_ROOT/publishable-entry-point-hostile-path"
EARLY_GUARD_HOSTILE_BASH_MARKER="$TEST_ROOT/hostile-path-bash.ran"
EARLY_GUARD_BASH_ENV="$TEST_ROOT/publishable-entry-point-bash-env"
EARLY_GUARD_BASH_ENV_MARKER="$TEST_ROOT/publishable-entry-point-bash-env.ran"
EARLY_GUARD_FUNCTION_MARKER="$TEST_ROOT/publishable-entry-point-function.ran"
/bin/mkdir "$EARLY_GUARD_HOSTILE_PATH"
/usr/bin/printf '%s\n' \
  '#!/bin/sh' \
  '/usr/bin/touch "$0.ran"' \
  'exit 99' \
  >"$EARLY_GUARD_TOOL"
/bin/chmod 700 "$EARLY_GUARD_TOOL"
/usr/bin/printf '%s\n' \
  '#!/bin/sh' \
  '/usr/bin/touch "$WAAL_TEST_HOSTILE_BASH_MARKER"' \
  'exit 98' \
  >"$EARLY_GUARD_HOSTILE_PATH/bash"
/bin/chmod 700 "$EARLY_GUARD_HOSTILE_PATH/bash"
/usr/bin/printf '%s\n' \
  '/usr/bin/touch "$WAAL_TEST_BASH_ENV_MARKER"' \
  >"$EARLY_GUARD_BASH_ENV"
for publishable_argument in --release --release-diagnostics-artifact; do
  publishable_label="${publishable_argument#--}"
  publishable_diagnostics="$TEST_ROOT/$publishable_label.stderr"
  publishable_status=0
  if (
    echo() {
      /usr/bin/touch "$WAAL_TEST_EXPORTED_FUNCTION_MARKER"
      builtin echo "$@"
    }
    export -f echo
    export PATH="$EARLY_GUARD_HOSTILE_PATH:/usr/bin:/bin:/usr/sbin:/sbin"
    export BASH_ENV="$EARLY_GUARD_BASH_ENV"
    export HOME="$TEST_ROOT"
    export WAAL_TEST_HOSTILE_BASH_MARKER="$EARLY_GUARD_HOSTILE_BASH_MARKER"
    export WAAL_TEST_BASH_ENV_MARKER="$EARLY_GUARD_BASH_ENV_MARKER"
    export WAAL_TEST_EXPORTED_FUNCTION_MARKER="$EARLY_GUARD_FUNCTION_MARKER"
    export WAAL_RELEASE_CARGO_PATH="$EARLY_GUARD_TOOL"
    export WAAL_RELEASE_RUSTC_PATH="$EARLY_GUARD_TOOL"
    "$ROOT_DIR/script/package_macos.sh" "$publishable_argument"
  ) >"$TEST_ROOT/$publishable_label.stdout" 2>"$publishable_diagnostics"; then
    fail "$publishable_argument unexpectedly entered local macOS packaging"
  else
    publishable_status=$?
  fi
  [ "$publishable_status" -eq 1 ] \
    || fail "$publishable_argument did not use the fail-closed publishable-mode status"
  /usr/bin/grep -Fq \
    'Publishable macOS packaging is disabled in the local packager.' \
    "$publishable_diagnostics" \
    || fail "$publishable_argument did not report the local publishable-build boundary"
  [ ! -e "$EARLY_GUARD_MARKER" ] \
    || fail "$publishable_argument resolved a caller-supplied build tool before rejection"
  [ ! -e "$EARLY_GUARD_HOSTILE_BASH_MARKER" ] \
    || fail "$publishable_argument resolved bash through caller-controlled PATH"
  [ ! -e "$EARLY_GUARD_BASH_ENV_MARKER" ] \
    || fail "$publishable_argument executed caller-controlled BASH_ENV before rejection"
  [ ! -e "$EARLY_GUARD_FUNCTION_MARKER" ] \
    || fail "$publishable_argument imported a caller-controlled shell function before rejection"
done

NO_ARGUMENT_DIAGNOSTICS="$TEST_ROOT/no-argument.stderr"
no_argument_status=0
if (
  echo() {
    /usr/bin/touch "$WAAL_TEST_EXPORTED_FUNCTION_MARKER"
    builtin echo "$@"
  }
  export -f echo
  export PATH="$EARLY_GUARD_HOSTILE_PATH:/usr/bin:/bin:/usr/sbin:/sbin"
  export BASH_ENV="$EARLY_GUARD_BASH_ENV"
  export HOME="$TEST_ROOT"
  export WAAL_TEST_HOSTILE_BASH_MARKER="$EARLY_GUARD_HOSTILE_BASH_MARKER"
  export WAAL_TEST_BASH_ENV_MARKER="$EARLY_GUARD_BASH_ENV_MARKER"
  export WAAL_TEST_EXPORTED_FUNCTION_MARKER="$EARLY_GUARD_FUNCTION_MARKER"
  export WAAL_RELEASE_CARGO_PATH="$EARLY_GUARD_TOOL"
  export WAAL_RELEASE_RUSTC_PATH="$EARLY_GUARD_TOOL"
  "$ROOT_DIR/script/package_macos.sh"
) >"$TEST_ROOT/no-argument.stdout" 2>"$NO_ARGUMENT_DIAGNOSTICS"; then
  fail "macOS packager entered local signed packaging without explicit opt-in"
else
  no_argument_status=$?
fi
[ "$no_argument_status" -eq 2 ] \
  || fail "macOS packager did not reject the missing local-signed argument with usage status"
/usr/bin/grep -Fq 'Usage: script/package_macos.sh --local-signed-release' \
  "$NO_ARGUMENT_DIAGNOSTICS" \
  || fail "macOS packager did not report the required local-signed entry point"
for forbidden_early_marker in \
  "$EARLY_GUARD_MARKER" \
  "$EARLY_GUARD_HOSTILE_BASH_MARKER" \
  "$EARLY_GUARD_BASH_ENV_MARKER" \
  "$EARLY_GUARD_FUNCTION_MARKER"; do
  [ ! -e "$forbidden_early_marker" ] \
    || fail "missing-argument rejection executed caller-controlled code"
done

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
for preallocated_release_directory in \
  "$RELEASE_PRIVATE_ROOT/build-toolchain" \
  "$RELEASE_SOURCE_ROOT/build-home" \
  "$RELEASE_SOURCE_ROOT/cargo-home" \
  "$RELEASE_SOURCE_ROOT/cargo-work" \
  "$RELEASE_SOURCE_ROOT/tmp"; do
  [ -d "$preallocated_release_directory" ] \
    && [ ! -L "$preallocated_release_directory" ] \
    && [ "$(/usr/bin/stat -f '%Lp' "$preallocated_release_directory")" = 700 ] \
    || fail "release identity-anchor child was not securely preallocated: $preallocated_release_directory"
done

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

SAVED_RELEASE_SOURCE_DIR="$RELEASE_SOURCE_DIR"
SAVED_RELEASE_SOURCE_IDENTITY_SHA256="$RELEASE_SOURCE_IDENTITY_SHA256"
SAVED_RELEASE_GIT_SOURCE_ROOT="$RELEASE_GIT_SOURCE_ROOT"
SOURCE_IDENTITY_SNAPSHOT="$TEST_ROOT/source-identity-snapshot"
materialize_release_source_for_root \
  "$REPO_DIR" \
  "$SOURCE_IDENTITY_SNAPSHOT" \
  "$RELEASE_GIT_COMMIT" \
  "$RELEASE_GIT_TREE"
RELEASE_SOURCE_DIR="$SOURCE_IDENTITY_SNAPSHOT"
RELEASE_GIT_SOURCE_ROOT="$REPO_DIR"
capture_release_source_identity_baseline
# Reproduce the live release order: Cargo directories are prepared and the
# toolchain snapshot is populated only after the committed source baseline is
# captured. Because their anchor children were preallocated, these legitimate
# nested writes must not mutate the guarded private-root/source-parent records.
prepare_isolated_release_cargo_home
/usr/bin/printf 'anchor regression\n' \
  >"$RELEASE_PRIVATE_ROOT/build-toolchain/anchor-regression"
/usr/bin/printf 'source-parent regression\n' \
  >"$RELEASE_CARGO_HOME/anchor-regression"
verify_release_source_identity_baseline \
  || fail "post-freeze Cargo/toolchain setup changed a release identity anchor"
/bin/rm -f -- \
  "$RELEASE_PRIVATE_ROOT/build-toolchain/anchor-regression" \
  "$RELEASE_CARGO_HOME/anchor-regression"
verify_release_source_identity_baseline \
  || fail "toolchain snapshot cleanup changed a release identity anchor"
SOURCE_IDENTITY_ORIGINAL="$TEST_ROOT/source-identity-tracked-original"
if /bin/mv \
  "$SOURCE_IDENTITY_SNAPSHOT/tracked.txt" "$SOURCE_IDENTITY_ORIGINAL" \
  2>/dev/null; then
  fail "immutable source guard allowed a tracked file to be renamed"
fi
/usr/bin/chflags -R -P nouchg "$SOURCE_IDENTITY_SNAPSHOT"
/bin/chmod -R u+w "$SOURCE_IDENTITY_SNAPSHOT"
/bin/mv "$SOURCE_IDENTITY_SNAPSHOT/tracked.txt" "$SOURCE_IDENTITY_ORIGINAL"
/bin/cp "$SOURCE_IDENTITY_ORIGINAL" "$SOURCE_IDENTITY_SNAPSHOT/tracked.txt"
verify_materialized_release_source \
  "$SOURCE_IDENTITY_SNAPSHOT" "$REPO_DIR" "$RELEASE_GIT_COMMIT"
if verify_release_source_identity_baseline 2>/dev/null; then
  fail "same-byte source pathname replacement escaped the source identity guard"
fi
# The fixture deliberately thawed the immutable tree in order to replace one
# inode, so its synthetic freeze state must not leak into later cleanup tests.
RELEASE_SOURCE_FREEZE_ATTEMPTED=false
RELEASE_SOURCE_FROZEN=false
RELEASE_SOURCE_FREEZE_ROOT_ID=""
RELEASE_SOURCE_DIR="$SAVED_RELEASE_SOURCE_DIR"
RELEASE_SOURCE_IDENTITY_SHA256="$SAVED_RELEASE_SOURCE_IDENTITY_SHA256"
RELEASE_GIT_SOURCE_ROOT="$SAVED_RELEASE_GIT_SOURCE_ROOT"

PARTIAL_FREEZE_SAVED_PRIVATE_ROOT="$RELEASE_PRIVATE_ROOT"
PARTIAL_FREEZE_SAVED_PRIVATE_ROOT_PARENT="$RELEASE_PRIVATE_ROOT_PARENT"
PARTIAL_FREEZE_SAVED_PRIVATE_ROOT_ID="$RELEASE_PRIVATE_ROOT_ID"
PARTIAL_FREEZE_SAVED_PRIVATE_ROOT_PARENT_ID="$RELEASE_PRIVATE_ROOT_PARENT_ID"
PARTIAL_FREEZE_SAVED_TEMP_DIR="$RELEASE_TEMP_DIR"
PARTIAL_FREEZE_SAVED_STAGE_DIR="$STAGE_DIR"
PARTIAL_FREEZE_SAVED_SOURCE_ROOT="$RELEASE_SOURCE_ROOT"
PARTIAL_FREEZE_SAVED_SOURCE_DIR="$RELEASE_SOURCE_DIR"
PARTIAL_FREEZE_SAVED_SOURCE_IDENTITY="$RELEASE_SOURCE_IDENTITY_SHA256"
PARTIAL_FREEZE_SAVED_GIT_SOURCE_ROOT="$RELEASE_GIT_SOURCE_ROOT"
PARTIAL_FREEZE_OWNER="$TEST_ROOT/partial-freeze-owner"
/bin/mkdir -m 700 "$PARTIAL_FREEZE_OWNER"
create_private_release_root_for_root "$PARTIAL_FREEZE_OWNER"
PARTIAL_FREEZE_PRIVATE_ROOT="$RELEASE_PRIVATE_ROOT"
RELEASE_SOURCE_DIR="$RELEASE_SOURCE_ROOT/source"
/bin/mkdir -p "$RELEASE_SOURCE_DIR/partially-locked"
/usr/bin/printf 'must be safely thawed\n' \
  >"$RELEASE_SOURCE_DIR/partially-locked/file"
RELEASE_SOURCE_FREEZE_ROOT_ID="$(directory_identity "$RELEASE_SOURCE_DIR")"
RELEASE_SOURCE_FREEZE_ATTEMPTED=true
RELEASE_SOURCE_FROZEN=false
RELEASE_SOURCE_IDENTITY_SHA256=""
/usr/bin/chflags uchg "$RELEASE_SOURCE_DIR/partially-locked/file"
cleanup
[ ! -e "$PARTIAL_FREEZE_PRIVATE_ROOT" ] \
  || fail "cleanup did not safely thaw and remove a partially frozen private source tree"
RELEASE_PRIVATE_ROOT="$PARTIAL_FREEZE_SAVED_PRIVATE_ROOT"
RELEASE_PRIVATE_ROOT_PARENT="$PARTIAL_FREEZE_SAVED_PRIVATE_ROOT_PARENT"
RELEASE_PRIVATE_ROOT_ID="$PARTIAL_FREEZE_SAVED_PRIVATE_ROOT_ID"
RELEASE_PRIVATE_ROOT_PARENT_ID="$PARTIAL_FREEZE_SAVED_PRIVATE_ROOT_PARENT_ID"
RELEASE_TEMP_DIR="$PARTIAL_FREEZE_SAVED_TEMP_DIR"
STAGE_DIR="$PARTIAL_FREEZE_SAVED_STAGE_DIR"
RELEASE_SOURCE_ROOT="$PARTIAL_FREEZE_SAVED_SOURCE_ROOT"
RELEASE_SOURCE_DIR="$PARTIAL_FREEZE_SAVED_SOURCE_DIR"
RELEASE_SOURCE_IDENTITY_SHA256="$PARTIAL_FREEZE_SAVED_SOURCE_IDENTITY"
RELEASE_GIT_SOURCE_ROOT="$PARTIAL_FREEZE_SAVED_GIT_SOURCE_ROOT"
RELEASE_SOURCE_FREEZE_ATTEMPTED=false
RELEASE_SOURCE_FROZEN=false
RELEASE_SOURCE_FREEZE_ROOT_ID=""

PACKAGER_BINDING_SNAPSHOT="$TEST_ROOT/packager-binding-snapshot"
/bin/mkdir -p "$PACKAGER_BINDING_SNAPSHOT/script"
/bin/cp "$ROOT_DIR/script/package_macos.sh" \
  "$PACKAGER_BINDING_SNAPSHOT/script/package_macos.sh"
/bin/cp "$ROOT_DIR/script/macos_bundle.sh" \
  "$PACKAGER_BINDING_SNAPSHOT/script/macos_bundle.sh"
verify_packager_source_hashes_match_snapshot \
  "$PACKAGER_BINDING_SNAPSHOT" \
  "$LOADED_PACKAGE_MACOS_SHA256" \
  "$LOADED_MACOS_BUNDLE_SHA256"
/bin/mv "$PACKAGER_BINDING_SNAPSHOT/script/package_macos.sh" \
  "$PACKAGER_BINDING_SNAPSHOT/script/package_macos.loaded-a"
/usr/bin/printf '# checkout B package logic\n' \
  >"$PACKAGER_BINDING_SNAPSHOT/script/package_macos.sh"
if verify_packager_source_hashes_match_snapshot \
  "$PACKAGER_BINDING_SNAPSHOT" \
  "$LOADED_PACKAGE_MACOS_SHA256" \
  "$LOADED_MACOS_BUNDLE_SHA256" 2>/dev/null; then
  fail "loaded package logic from checkout A was accepted with checkout B provenance"
fi
/bin/mv "$PACKAGER_BINDING_SNAPSHOT/script/package_macos.loaded-a" \
  "$PACKAGER_BINDING_SNAPSHOT/script/package_macos.sh"
/bin/mv "$PACKAGER_BINDING_SNAPSHOT/script/macos_bundle.sh" \
  "$PACKAGER_BINDING_SNAPSHOT/script/macos_bundle.loaded-a"
/usr/bin/printf '# checkout B bundle helper\n' \
  >"$PACKAGER_BINDING_SNAPSHOT/script/macos_bundle.sh"
if verify_packager_source_hashes_match_snapshot \
  "$PACKAGER_BINDING_SNAPSHOT" \
  "$LOADED_PACKAGE_MACOS_SHA256" \
  "$LOADED_MACOS_BUNDLE_SHA256" 2>/dev/null; then
  fail "loaded macOS bundle helper from checkout A was accepted with checkout B provenance"
fi

COMMITTED_BOOTSTRAP_SOURCE="$TEST_ROOT/committed-release-bootstrap.sh"
/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin \
  /usr/bin/perl -0777 -e '
    use strict;
    use warnings;
    my $text = <>;
    my $command = "/bin/bash --noprofile --norc -p -c ";
    my $start = index($text, $command);
    die "committed bootstrap command not found\n" if $start < 0;
    $start = index($text, "\n", $start);
    die "committed bootstrap body not found\n" if $start < 0;
    ++$start;
    my $label = index($text, "waal-committed-release-bootstrap", $start);
    die "committed bootstrap label not found\n" if $label < 0;
    my $end = rindex($text, "\n    ", $label);
    die "committed bootstrap terminator not found\n" if $end <= $start;
    print substr($text, $start, $end - $start), "\n";
  ' "$ROOT_DIR/script/package_macos.sh" >"$COMMITTED_BOOTSTRAP_SOURCE"
/usr/bin/grep -Fq 'descriptor_identity()' "$COMMITTED_BOOTSTRAP_SOURCE" \
  || fail "unable to extract descriptor-bound committed release bootstrap"
/usr/bin/grep -Fq 'builtin source /dev/fd/8' "$COMMITTED_BOOTSTRAP_SOURCE" \
  || fail "extracted bootstrap does not load the committed packager descriptor"
COMMITTED_BOOTSTRAP_TEXT="$(/bin/cat "$COMMITTED_BOOTSTRAP_SOURCE")"

run_committed_bootstrap_fixture() {
  local package_execution_path="$1"
  local package_verification_path="$2"
  local bundle_execution_path="$3"
  local bundle_verification_path="$4"
  local expected_package_sha256="$5"
  local expected_bundle_sha256="$6"
  local marker_path="$7"
  local status=0

  exec 8<"$package_execution_path"
  exec 9<"$package_verification_path"
  exec 7<"$bundle_execution_path"
  exec 6<"$bundle_verification_path"
  /bin/rm -f -- \
    "$package_execution_path" "$package_verification_path" \
    "$bundle_execution_path" "$bundle_verification_path"
  BOOTSTRAP_MARKER="$marker_path" /bin/bash --noprofile --norc -p -c \
    "$COMMITTED_BOOTSTRAP_TEXT" \
    waal-committed-release-bootstrap \
    "$expected_package_sha256" "$expected_bundle_sha256" \
    1111111111111111111111111111111111111111 \
    2222222222222222222222222222222222222222 \
    /private/tmp/waal-bootstrap-source \
    /private/tmp/waal-bootstrap-checkout \
    /private/tmp/waal-bootstrap-private-root \
    /private/tmp/waal-bootstrap-private-parent \
    private-root-id private-parent-id \
    3333333333333333333333333333333333333333 \
    4444444444444444444444444444444444444444 \
    --local-signed-release || status=$?
  exec 6<&- 7<&- 8<&- 9<&-
  return "$status"
}

write_bootstrap_package_fixture() {
  local path="$1"
  /usr/bin/printf '%s\n' \
    '[ "${1:-}" = --internal-committed-snapshot ] || exit 91' \
    '[ "${!#}" = --local-signed-release ] || exit 92' \
    'package_macos_main() { /usr/bin/touch "$BOOTSTRAP_MARKER"; }' \
    >"$path"
}

write_bootstrap_bundle_fixture() {
  local path="$1"
  /usr/bin/printf '%s\n' \
    'waal_require_tool() { :; }' \
    'waal_cargo_version() { :; }' \
    'waal_assemble_app_bundle() { :; }' \
    >"$path"
}

write_bootstrap_shared_offset_package_fixture() {
  local path="$1"
  local expected_bundle_oid="$2"

  {
    /usr/bin/printf '%s\n' \
      '[ "${1:-}" = --internal-committed-snapshot ] || exit 91' \
      '[ "${!#}" = --local-signed-release ] || exit 92' \
      'LOADED_MACOS_BUNDLE_SHA256="$5"' \
      "LOADED_MACOS_BUNDLE_OID=$expected_bundle_oid" \
      'RELEASE_GIT_SOURCE_ROOT=/' \
      'sanitized_git() {' \
      '  shift 2' \
      "  \"$REAL_GIT_BIN\" \"\$@\"" \
      '}'
    /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin \
      /usr/bin/perl -0777 -e '
        use strict;
        use warnings;
        my $text = <>;
        my $start = index($text, "load_authenticated_bundle_helper() {");
        my $end = index($text, "canonical_executable_path() {", $start);
        die "authenticated bundle-helper loader not found\n"
          if $start < 0 || $end <= $start;
        print substr($text, $start, $end - $start);
      ' "$ROOT_DIR/script/package_macos.sh"
    /usr/bin/printf '%s\n' \
      'package_macos_main() {' \
      '  load_authenticated_bundle_helper' \
      '  declare -F waal_require_tool >/dev/null' \
      '  declare -F waal_cargo_version >/dev/null' \
      '  declare -F waal_assemble_app_bundle >/dev/null' \
      '  /usr/bin/touch "$BOOTSTRAP_MARKER"' \
      '}'
  } >"$path"
}

BOOTSTRAP_POSITIVE_PACKAGE="$TEST_ROOT/bootstrap-positive-package.sh"
BOOTSTRAP_POSITIVE_BUNDLE="$TEST_ROOT/bootstrap-positive-bundle.sh"
BOOTSTRAP_POSITIVE_MARKER="$TEST_ROOT/bootstrap-positive.ran"
write_bootstrap_package_fixture "$BOOTSTRAP_POSITIVE_PACKAGE"
write_bootstrap_bundle_fixture "$BOOTSTRAP_POSITIVE_BUNDLE"
BOOTSTRAP_PACKAGE_SHA256="$(release_tool_sha256 "$BOOTSTRAP_POSITIVE_PACKAGE")"
BOOTSTRAP_BUNDLE_SHA256="$(release_tool_sha256 "$BOOTSTRAP_POSITIVE_BUNDLE")"
run_committed_bootstrap_fixture \
  "$BOOTSTRAP_POSITIVE_PACKAGE" "$BOOTSTRAP_POSITIVE_PACKAGE" \
  "$BOOTSTRAP_POSITIVE_BUNDLE" "$BOOTSTRAP_POSITIVE_BUNDLE" \
  "$BOOTSTRAP_PACKAGE_SHA256" "$BOOTSTRAP_BUNDLE_SHA256" \
  "$BOOTSTRAP_POSITIVE_MARKER" \
  || fail "descriptor-bound committed bootstrap rejected its positive control"
[ -f "$BOOTSTRAP_POSITIVE_MARKER" ] \
  || fail "descriptor-bound committed bootstrap did not invoke the verified package"

# The real bootstrap hashes descriptor 6 before sourcing the committed
# packager. On macOS that /dev/fd/6 read advances the descriptor's shared
# offset to EOF. Exercise the real helper-loader function in that state so a
# missing pre-hash rewind cannot be hidden by the lightweight positive fixture.
BOOTSTRAP_SHARED_OFFSET_PACKAGE="$TEST_ROOT/bootstrap-shared-offset-package.sh"
BOOTSTRAP_SHARED_OFFSET_BUNDLE="$TEST_ROOT/bootstrap-shared-offset-bundle.sh"
BOOTSTRAP_SHARED_OFFSET_MARKER="$TEST_ROOT/bootstrap-shared-offset.ran"
write_bootstrap_bundle_fixture "$BOOTSTRAP_SHARED_OFFSET_BUNDLE"
BOOTSTRAP_SHARED_OFFSET_BUNDLE_OID="$($REAL_GIT_BIN hash-object -- "$BOOTSTRAP_SHARED_OFFSET_BUNDLE")"
write_bootstrap_shared_offset_package_fixture \
  "$BOOTSTRAP_SHARED_OFFSET_PACKAGE" "$BOOTSTRAP_SHARED_OFFSET_BUNDLE_OID"
run_committed_bootstrap_fixture \
  "$BOOTSTRAP_SHARED_OFFSET_PACKAGE" "$BOOTSTRAP_SHARED_OFFSET_PACKAGE" \
  "$BOOTSTRAP_SHARED_OFFSET_BUNDLE" "$BOOTSTRAP_SHARED_OFFSET_BUNDLE" \
  "$(release_tool_sha256 "$BOOTSTRAP_SHARED_OFFSET_PACKAGE")" \
  "$(release_tool_sha256 "$BOOTSTRAP_SHARED_OFFSET_BUNDLE")" \
  "$BOOTSTRAP_SHARED_OFFSET_MARKER" \
  || fail "authenticated bundle-helper loader did not rewind bootstrap-consumed descriptor 6"
[ -f "$BOOTSTRAP_SHARED_OFFSET_MARKER" ] \
  || fail "shared-offset bootstrap regression did not load the authenticated helper"

BOOTSTRAP_WRONG_DIGEST_PACKAGE="$TEST_ROOT/bootstrap-wrong-digest-package.sh"
BOOTSTRAP_WRONG_DIGEST_BUNDLE="$TEST_ROOT/bootstrap-wrong-digest-bundle.sh"
BOOTSTRAP_WRONG_DIGEST_MARKER="$TEST_ROOT/bootstrap-wrong-digest.ran"
write_bootstrap_package_fixture "$BOOTSTRAP_WRONG_DIGEST_PACKAGE"
write_bootstrap_bundle_fixture "$BOOTSTRAP_WRONG_DIGEST_BUNDLE"
if run_committed_bootstrap_fixture \
  "$BOOTSTRAP_WRONG_DIGEST_PACKAGE" "$BOOTSTRAP_WRONG_DIGEST_PACKAGE" \
  "$BOOTSTRAP_WRONG_DIGEST_BUNDLE" "$BOOTSTRAP_WRONG_DIGEST_BUNDLE" \
  "$(/usr/bin/printf '0%.0s' {1..64})" \
  "$(release_tool_sha256 "$BOOTSTRAP_WRONG_DIGEST_BUNDLE")" \
  "$BOOTSTRAP_WRONG_DIGEST_MARKER" >/dev/null 2>&1; then
  fail "descriptor-bound committed bootstrap accepted an incorrect package digest"
fi
[ ! -e "$BOOTSTRAP_WRONG_DIGEST_MARKER" ] \
  || fail "wrong package digest reached committed package execution"

BOOTSTRAP_FORGED_PACKAGE="$TEST_ROOT/bootstrap-forged-package.sh"
BOOTSTRAP_FORGED_BUNDLE="$TEST_ROOT/bootstrap-forged-bundle.sh"
BOOTSTRAP_FORGED_MARKER="$TEST_ROOT/bootstrap-forged.ran"
write_bootstrap_package_fixture "$BOOTSTRAP_FORGED_PACKAGE"
write_bootstrap_bundle_fixture "$BOOTSTRAP_FORGED_BUNDLE"
BOOTSTRAP_CLEAN_PACKAGE_SHA256="$(release_tool_sha256 "$BOOTSTRAP_FORGED_PACKAGE")"
{
  /usr/bin/printf '/usr/bin/touch "$BOOTSTRAP_MARKER"\n'
  /bin/cat "$BOOTSTRAP_FORGED_PACKAGE"
} >"$BOOTSTRAP_FORGED_PACKAGE.prepended"
/bin/mv "$BOOTSTRAP_FORGED_PACKAGE.prepended" "$BOOTSTRAP_FORGED_PACKAGE"
if run_committed_bootstrap_fixture \
  "$BOOTSTRAP_FORGED_PACKAGE" "$BOOTSTRAP_FORGED_PACKAGE" \
  "$BOOTSTRAP_FORGED_BUNDLE" "$BOOTSTRAP_FORGED_BUNDLE" \
  "$BOOTSTRAP_CLEAN_PACKAGE_SHA256" \
  "$(release_tool_sha256 "$BOOTSTRAP_FORGED_BUNDLE")" \
  "$BOOTSTRAP_FORGED_MARKER" >/dev/null 2>&1; then
  fail "descriptor-bound committed bootstrap accepted prepended package logic"
fi
[ ! -e "$BOOTSTRAP_FORGED_MARKER" ] \
  || fail "prepended package logic executed before descriptor verification"

BOOTSTRAP_SPLIT_PACKAGE_EXEC="$TEST_ROOT/bootstrap-split-package-exec.sh"
BOOTSTRAP_SPLIT_PACKAGE_VERIFY="$TEST_ROOT/bootstrap-split-package-verify.sh"
BOOTSTRAP_SPLIT_BUNDLE="$TEST_ROOT/bootstrap-split-bundle.sh"
BOOTSTRAP_SPLIT_MARKER="$TEST_ROOT/bootstrap-split.ran"
write_bootstrap_package_fixture "$BOOTSTRAP_SPLIT_PACKAGE_EXEC"
/bin/cp "$BOOTSTRAP_SPLIT_PACKAGE_EXEC" "$BOOTSTRAP_SPLIT_PACKAGE_VERIFY"
write_bootstrap_bundle_fixture "$BOOTSTRAP_SPLIT_BUNDLE"
if run_committed_bootstrap_fixture \
  "$BOOTSTRAP_SPLIT_PACKAGE_EXEC" "$BOOTSTRAP_SPLIT_PACKAGE_VERIFY" \
  "$BOOTSTRAP_SPLIT_BUNDLE" "$BOOTSTRAP_SPLIT_BUNDLE" \
  "$(release_tool_sha256 "$BOOTSTRAP_SPLIT_PACKAGE_EXEC")" \
  "$(release_tool_sha256 "$BOOTSTRAP_SPLIT_BUNDLE")" \
  "$BOOTSTRAP_SPLIT_MARKER" >/dev/null 2>&1; then
  fail "descriptor-bound committed bootstrap accepted different execution and verification inodes"
fi
[ ! -e "$BOOTSTRAP_SPLIT_MARKER" ] \
  || fail "split execution/verification inodes reached committed package execution"

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
EXPECTED_LOCAL_SIGNED_ARCHIVE_NAME="WindowsAppAutoLogin-macos-local-signed-$EXPECTED_COMMIT.zip"
[ "$(release_archive_filename "$RELEASE_ARCHIVE_BASE" "$EXPECTED_COMMIT")" \
  = "$EXPECTED_LOCAL_SIGNED_ARCHIVE_NAME" ] \
  || fail "local signed macOS archive is not explicitly named and commit-addressed"
if release_archive_filename '../escape' "$EXPECTED_COMMIT" >/dev/null 2>&1; then
  fail "unsafe release archive base was accepted"
fi
if release_archive_filename Fixture-macos "${EXPECTED_COMMIT}0" >/dev/null 2>&1; then
  fail "invalid commit was accepted in a release archive filename"
fi

prepare_atomic_no_replace_rename_helper

ZIP_ENV_ROOT="$STAGE_DIR/zip-environment-fixture"
/bin/mkdir -p "$ZIP_ENV_ROOT/WindowsAppAutoLogin.app/Contents"
/usr/bin/printf 'ZIP environment fixture\n' \
  >"$ZIP_ENV_ROOT/WindowsAppAutoLogin.app/Contents/file"
ZIPOPT_MARKER_HELPER="$STAGE_DIR/zipopt-marker-helper"
ZIPOPT_MARKER="$ZIPOPT_MARKER_HELPER.ran"
/usr/bin/printf '%s\n' \
  '#!/bin/sh' \
  '/usr/bin/touch "$0.ran"' \
  'exit 0' \
  >"$ZIPOPT_MARKER_HELPER"
/bin/chmod 700 "$ZIPOPT_MARKER_HELPER"
(
  cd "$ZIP_ENV_ROOT"
  export ZIPOPT="-T -TT $ZIPOPT_MARKER_HELPER"
  sanitized_zip -r -X "$STAGE_DIR/hostile-zipopt-command.zip" \
    WindowsAppAutoLogin.app >/dev/null
)
[ ! -e "$ZIPOPT_MARKER" ] \
  || fail "caller ZIPOPT executed an external test command"
validate_archive_entries "$STAGE_DIR/hostile-zipopt-command.zip"
(
  cd "$ZIP_ENV_ROOT"
  export ZIPOPT=-j
  export ZIP=-j
  sanitized_zip -r -X "$STAGE_DIR/hostile-zipopt-j.zip" \
    WindowsAppAutoLogin.app >/dev/null
)
(
  cd "$ZIP_ENV_ROOT"
  export ZIPOPT=-m
  export ZIP=-m
  sanitized_zip -r -X "$STAGE_DIR/hostile-zipopt-m.zip" \
    WindowsAppAutoLogin.app >/dev/null
)
[ -f "$ZIP_ENV_ROOT/WindowsAppAutoLogin.app/Contents/file" ] \
  || fail "hostile ZIPOPT=-m removed release source content"
/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin \
  /usr/bin/zipinfo -1 "$STAGE_DIR/hostile-zipopt-j.zip" \
  >"$STAGE_DIR/hostile-zipopt-j.entries"
/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin \
  /usr/bin/zipinfo -1 "$STAGE_DIR/hostile-zipopt-m.zip" \
  >"$STAGE_DIR/hostile-zipopt-m.entries"
/usr/bin/cmp -s \
  "$STAGE_DIR/hostile-zipopt-j.entries" \
  "$STAGE_DIR/hostile-zipopt-m.entries" \
  || fail "caller ZIP/ZIPOPT changed the sanitized ZIP entry set"
/usr/bin/grep -Fxq 'WindowsAppAutoLogin.app/Contents/file' \
  "$STAGE_DIR/hostile-zipopt-j.entries" \
  || fail "hostile ZIPOPT flattened the sanitized ZIP"
validate_archive_entries "$STAGE_DIR/hostile-zipopt-j.zip"
validate_archive_entries "$STAGE_DIR/hostile-zipopt-m.zip"

ARCHIVE_SESSION_VALIDATE_FUNCTION="$(declare -f validate_archive_entries)"
ARCHIVE_SESSION_VERIFY_BUNDLE_FUNCTION="$(declare -f verify_release_bundle)"
eval "$(
  /usr/bin/printf '%s\n' "$ARCHIVE_SESSION_VALIDATE_FUNCTION" \
    | /usr/bin/sed '1s/^validate_archive_entries /archive_session_original_validate_archive_entries /'
)"
ARCHIVE_SESSION_ROOT="$STAGE_DIR/archive-session-fixture"
ARCHIVE_SESSION_A="$STAGE_DIR/archive-session-a.zip"
ARCHIVE_SESSION_A_ASIDE="$STAGE_DIR/archive-session-a.aside.zip"
ARCHIVE_SESSION_B="$STAGE_DIR/archive-session-b.zip"
ARCHIVE_SESSION_B_ASIDE="$STAGE_DIR/archive-session-b.aside.zip"
/bin/mkdir -p "$ARCHIVE_SESSION_ROOT/WindowsAppAutoLogin.app/Contents"
/usr/bin/printf 'archive session A\n' \
  >"$ARCHIVE_SESSION_ROOT/WindowsAppAutoLogin.app/Contents/file"
(
  cd "$ARCHIVE_SESSION_ROOT"
  sanitized_zip -r -X "$ARCHIVE_SESSION_A" WindowsAppAutoLogin.app >/dev/null
)
/usr/bin/printf 'archive session B\n' \
  >"$ARCHIVE_SESSION_ROOT/WindowsAppAutoLogin.app/Contents/file"
(
  cd "$ARCHIVE_SESSION_ROOT"
  sanitized_zip -r -X "$ARCHIVE_SESSION_B" WindowsAppAutoLogin.app >/dev/null
)
ARCHIVE_SESSION_A_SHA256="$(release_tool_sha256 "$ARCHIVE_SESSION_A")"
ARCHIVE_SESSION_B_SHA256="$(release_tool_sha256 "$ARCHIVE_SESSION_B")"
ARCHIVE_SESSION_SWAP_CALLED=false
ARCHIVE_SESSION_RESTORE_CALLED=false
validate_archive_entries() {
  archive_session_original_validate_archive_entries "$@" || return 1
  if [ "$ARCHIVE_SESSION_SWAP_CALLED" = false ]; then
    ARCHIVE_SESSION_SWAP_CALLED=true
    /bin/mv "$ARCHIVE_SESSION_A" "$ARCHIVE_SESSION_A_ASIDE"
    /bin/mv "$ARCHIVE_SESSION_B" "$ARCHIVE_SESSION_A"
    [ "$(release_tool_sha256 "$ARCHIVE_SESSION_A")" = "$ARCHIVE_SESSION_B_SHA256" ] \
      || return 1
    /bin/mv "$ARCHIVE_SESSION_A" "$ARCHIVE_SESSION_B_ASIDE"
    /bin/mv "$ARCHIVE_SESSION_A_ASIDE" "$ARCHIVE_SESSION_A"
    ARCHIVE_SESSION_RESTORE_CALLED=true
  fi
}
verify_release_bundle() { return 0; }
if extract_and_verify_archive \
  "$ARCHIVE_SESSION_A" archive-session-a-b-a-extracted \
  "$ARCHIVE_SESSION_A_SHA256" >/dev/null 2>&1; then
  fail "ZIP pathname A-to-B-to-A mutation was accepted during one archive session"
fi
[ "$ARCHIVE_SESSION_SWAP_CALLED" = true ] \
  || fail "ZIP A-to-B-to-A regression did not install pathname B"
[ "$ARCHIVE_SESSION_RESTORE_CALLED" = true ] \
  || fail "ZIP A-to-B-to-A regression did not restore pathname A before the next check"
eval "$ARCHIVE_SESSION_VALIDATE_FUNCTION"

ARCHIVE_SESSION_MUTATION="$STAGE_DIR/archive-session-in-place.zip"
/bin/cp "$ARCHIVE_SESSION_A" "$ARCHIVE_SESSION_MUTATION"
ARCHIVE_SESSION_MUTATION_SHA256="$(release_tool_sha256 "$ARCHIVE_SESSION_MUTATION")"
ARCHIVE_SESSION_MUTATION_CALLED=false
verify_release_bundle() {
  ARCHIVE_SESSION_MUTATION_CALLED=true
  /usr/bin/printf 'in-place mutation during archive verification\n' \
    >"$ARCHIVE_SESSION_MUTATION"
}
if extract_and_verify_archive \
  "$ARCHIVE_SESSION_MUTATION" archive-session-in-place-extracted \
  "$ARCHIVE_SESSION_MUTATION_SHA256" >/dev/null 2>&1; then
  fail "in-place ZIP mutation was accepted during one archive session"
fi
[ "$ARCHIVE_SESSION_MUTATION_CALLED" = true ] \
  || fail "in-place ZIP regression did not reach its post-extraction mutation"
eval "$ARCHIVE_SESSION_VERIFY_BUNDLE_FUNCTION"

HARDLINK_BUNDLE="$STAGE_DIR/hardlink-safety.app"
/bin/mkdir -p "$HARDLINK_BUNDLE/Contents"
/usr/bin/printf 'single inode\n' >"$HARDLINK_BUNDLE/Contents/original"
verify_bundle_tree_entry_safety "$HARDLINK_BUNDLE"
/bin/ln "$HARDLINK_BUNDLE/Contents/original" "$HARDLINK_BUNDLE/Contents/alias"
if verify_bundle_tree_entry_safety "$HARDLINK_BUNDLE" 2>/dev/null; then
  fail "multiply linked bundle files were accepted"
fi

MODE_BUNDLE="$STAGE_DIR/mode-safety.app"
MODE_EXECUTABLE="$MODE_BUNDLE/Contents/MacOS/$BINARY_NAME"
MODE_RESOURCE="$MODE_BUNDLE/Contents/Resources/payload.txt"
/bin/mkdir -p \
  "$MODE_BUNDLE/Contents/MacOS" "$MODE_BUNDLE/Contents/Resources"
/usr/bin/printf 'executable fixture\n' >"$MODE_EXECUTABLE"
/usr/bin/printf 'resource fixture\n' >"$MODE_RESOURCE"
/usr/bin/printf 'plist fixture\n' >"$MODE_BUNDLE/Contents/Info.plist"
/usr/bin/chgrp "$(/usr/bin/id -gn)" "$MODE_EXECUTABLE"
/usr/bin/find "$MODE_BUNDLE" -type d -exec /bin/chmod 755 {} +
/usr/bin/find "$MODE_BUNDLE" -type f -exec /bin/chmod 644 {} +
/bin/chmod 755 "$MODE_EXECUTABLE"
verify_bundle_tree_entry_safety "$MODE_BUNDLE"

assert_bundle_mode_rejected() {
  local label="$1"
  local path="$2"
  local rejected_mode="$3"
  local restored_mode="$4"

  /bin/chmod "$rejected_mode" "$path"
  if verify_bundle_tree_entry_safety "$MODE_BUNDLE" >/dev/null 2>&1; then
    fail "non-canonical $label bundle mode $rejected_mode was accepted"
  fi
  /bin/chmod "$restored_mode" "$path"
  verify_bundle_tree_entry_safety "$MODE_BUNDLE"
}

assert_bundle_mode_rejected directory-world-writable "$MODE_BUNDLE/Contents" 0777 0755
assert_bundle_mode_rejected directory-group-writable "$MODE_BUNDLE/Contents" 0775 0755
assert_bundle_mode_rejected resource-world-writable "$MODE_RESOURCE" 0666 0644
assert_bundle_mode_rejected resource-group-writable "$MODE_RESOURCE" 0664 0644
assert_bundle_mode_rejected resource-executable "$MODE_RESOURCE" 0755 0644
assert_bundle_mode_rejected main-setuid "$MODE_EXECUTABLE" 04755 0755
assert_bundle_mode_rejected main-setgid "$MODE_EXECUTABLE" 02755 0755
assert_bundle_mode_rejected main-non-executable "$MODE_EXECUTABLE" 0644 0755

/bin/chmod +a \
  'everyone allow add_file,add_subdirectory,file_inherit,directory_inherit' \
  "$MODE_BUNDLE"
if verify_bundle_tree_entry_safety "$MODE_BUNDLE" >/dev/null 2>&1; then
  fail "bundle root with an inherited-write ACL was accepted"
fi
/bin/chmod -RN "$MODE_BUNDLE"
verify_bundle_tree_entry_safety "$MODE_BUNDLE"

ASSEMBLY_ICON_FUNCTION="$(declare -f waal_build_app_icon)"
ASSEMBLY_PLIST_FUNCTION="$(declare -f waal_write_info_plist)"
waal_build_app_icon() {
  /usr/bin/printf 'icon fixture\n' >"$2/AppIcon.icns"
}
waal_write_info_plist() {
  /usr/bin/printf 'plist fixture\n' >"$1/Info.plist"
}
ASSEMBLY_SOURCE="$STAGE_DIR/assembly-source"
/usr/bin/printf 'assembly executable\n' >"$ASSEMBLY_SOURCE"
/bin/chmod 0777 "$ASSEMBLY_SOURCE"
for assembly_umask in 002 000; do
  ASSEMBLY_BUNDLE="$STAGE_DIR/assembly-$assembly_umask.app"
  (
    umask "$assembly_umask"
    waal_assemble_app_bundle \
      "$ROOT_DIR" "$ASSEMBLY_BUNDLE" "$BINARY_NAME" "$ASSEMBLY_SOURCE" \
      "$PRODUCTION_BUNDLE_ID" "Windows App AutoLogin" 1.0.0 1.0.0
  )
  verify_bundle_tree_entry_safety "$ASSEMBLY_BUNDLE"
done
ASSEMBLY_ACL_PARENT="$STAGE_DIR/assembly-acl-parent"
ASSEMBLY_ACL_BUNDLE="$ASSEMBLY_ACL_PARENT/assembly-acl.app"
/bin/mkdir -p "$ASSEMBLY_ACL_PARENT"
/bin/chmod +a \
  'everyone allow add_file,add_subdirectory,file_inherit,directory_inherit' \
  "$ASSEMBLY_ACL_PARENT"
waal_assemble_app_bundle \
  "$ROOT_DIR" "$ASSEMBLY_ACL_BUNDLE" "$BINARY_NAME" "$ASSEMBLY_SOURCE" \
  "$PRODUCTION_BUNDLE_ID" "Windows App AutoLogin" 1.0.0 1.0.0
verify_bundle_tree_entry_safety "$ASSEMBLY_ACL_BUNDLE"
/bin/chmod -RN "$ASSEMBLY_ACL_PARENT"
eval "$ASSEMBLY_ICON_FUNCTION"
eval "$ASSEMBLY_PLIST_FUNCTION"

ZIP_ROOT_HEX=57696e646f77734170704175746f4c6f67696e2e6170702f
ZIP_CONTENTS_HEX=57696e646f77734170704175746f4c6f67696e2e6170702f436f6e74656e74732f
ZIP_FILE_HEX=57696e646f77734170704175746f4c6f67696e2e6170702f436f6e74656e74732f66696c65
ZIP_FILE_UPPER_HEX=57696e646f77734170704175746f4c6f67696e2e6170702f436f6e74656e74732f46494c45
ZIP_EXECUTABLE_HEX=57696e646f77734170704175746f4c6f67696e2e6170702f436f6e74656e74732f4d61634f532f77696e646f77732d6170702d6175746f6c6f67696e
CANONICAL_MODE_ZIP="$STAGE_DIR/canonical-modes.zip"
write_crafted_stored_zip "$CANONICAL_MODE_ZIP" \
  "040755|$ZIP_ROOT_HEX|-|" \
  "0100755|$ZIP_EXECUTABLE_HEX|-|78" \
  "0100644|$ZIP_FILE_HEX|-|79"
validate_archive_entries "$CANONICAL_MODE_ZIP"
assert_archive_rejected_before_extraction root-world-writable-mode \
  "040777|$ZIP_ROOT_HEX|-|" \
  "0100644|$ZIP_FILE_HEX|-|78"
assert_archive_rejected_before_extraction directory-group-writable-mode \
  "040755|$ZIP_ROOT_HEX|-|" \
  "040775|$ZIP_CONTENTS_HEX|-|"
assert_archive_rejected_before_extraction resource-world-writable-mode \
  "040755|$ZIP_ROOT_HEX|-|" \
  "0100666|$ZIP_FILE_HEX|-|78"
assert_archive_rejected_before_extraction resource-group-writable-mode \
  "040755|$ZIP_ROOT_HEX|-|" \
  "0100664|$ZIP_FILE_HEX|-|78"
assert_archive_rejected_before_extraction resource-executable-mode \
  "040755|$ZIP_ROOT_HEX|-|" \
  "0100755|$ZIP_FILE_HEX|-|78"
assert_archive_rejected_before_extraction main-setuid-mode \
  "040755|$ZIP_ROOT_HEX|-|" \
  "0104755|$ZIP_EXECUTABLE_HEX|-|78"
assert_archive_rejected_before_extraction main-setgid-mode \
  "040755|$ZIP_ROOT_HEX|-|" \
  "0102755|$ZIP_EXECUTABLE_HEX|-|78"
assert_archive_rejected_before_extraction main-non-executable-mode \
  "040755|$ZIP_ROOT_HEX|-|" \
  "0100644|$ZIP_EXECUTABLE_HEX|-|78"
assert_archive_rejected_before_extraction traversal \
  "040755|$ZIP_ROOT_HEX|-|" \
  '0100644|57696e646f77734170704175746f4c6f67696e2e6170702f2e2e2f657363617065|-|78'
assert_archive_rejected_before_extraction absolute \
  "040755|$ZIP_ROOT_HEX|-|" \
  '0100644|2f57696e646f77734170704175746f4c6f67696e2e6170702f66696c65|-|78'
assert_archive_rejected_before_extraction backslash \
  "040755|$ZIP_ROOT_HEX|-|" \
  '0100644|57696e646f77734170704175746f4c6f67696e2e6170702f436f6e74656e74735c66696c65|-|78'
assert_archive_rejected_before_extraction dot-component \
  "040755|$ZIP_ROOT_HEX|-|" \
  '0100644|57696e646f77734170704175746f4c6f67696e2e6170702f2e2f66696c65|-|78'
assert_archive_rejected_before_extraction empty-component \
  "040755|$ZIP_ROOT_HEX|-|" \
  '0100644|57696e646f77734170704175746f4c6f67696e2e6170702f436f6e74656e74732f2f66696c65|-|78'
assert_archive_rejected_before_extraction control-character \
  "040755|$ZIP_ROOT_HEX|-|" \
  '0100644|57696e646f77734170704175746f4c6f67696e2e6170702f436f6e74656e74732f0a66696c65|-|78'
assert_archive_rejected_before_extraction exact-duplicate \
  "040755|$ZIP_ROOT_HEX|-|" \
  "0100644|$ZIP_FILE_HEX|-|78" \
  "0100644|$ZIP_FILE_HEX|-|78"
assert_archive_rejected_before_extraction case-duplicate \
  "040755|$ZIP_ROOT_HEX|-|" \
  "0100644|$ZIP_FILE_HEX|-|78" \
  "0100644|$ZIP_FILE_UPPER_HEX|-|78"
assert_archive_rejected_before_extraction file-directory-collision \
  "040755|$ZIP_ROOT_HEX|-|" \
  '0100644|57696e646f77734170704175746f4c6f67696e2e6170702f436f6e74656e7473|-|78' \
  "0100644|$ZIP_FILE_HEX|-|78"
assert_archive_rejected_before_extraction symlink \
  "040755|$ZIP_ROOT_HEX|-|" \
  "0120777|$ZIP_FILE_HEX|-|746172676574"
assert_archive_rejected_before_extraction fifo \
  "040755|$ZIP_ROOT_HEX|-|" \
  "0010644|$ZIP_FILE_HEX|-|"
assert_archive_rejected_before_extraction central-local-name-mismatch \
  "040755|$ZIP_ROOT_HEX|-|" \
  "0100644|$ZIP_FILE_HEX|$ZIP_FILE_UPPER_HEX|78"
assert_archive_rejected_before_extraction implicit-directory-case-collision \
  "040755|$ZIP_ROOT_HEX|-|" \
  '0100644|57696e646f77734170704175746f4c6f67696e2e6170702f436f6e74656e74732f466f6f2f6f6e65|-|31' \
  '0100644|57696e646f77734170704175746f4c6f67696e2e6170702f436f6e74656e74732f666f6f2f74776f|-|32'

TEST_ZIP_MAX_ARCHIVE_BYTES=536870912
TEST_ZIP_MAX_ENTRY_COUNT=16384
TEST_ZIP_MAX_ENTRY_UNCOMPRESSED_BYTES=536870912
TEST_ZIP_MAX_TOTAL_UNCOMPRESSED_BYTES=1073741824
TEST_ZIP_MAX_COMPRESSION_RATIO=200
TEST_ZIP_COMPRESSION_RATIO_SLACK=1048576
TEST_ZIP_MAX_NAME_BYTES=1024
TEST_ZIP_MAX_COMPONENT_BYTES=255
TEST_ZIP_MAX_PATH_DEPTH=64

RESOURCE_ARCHIVE_SIZE="$STAGE_DIR/resource-limit-archive-size.zip"
write_crafted_stored_zip "$RESOURCE_ARCHIVE_SIZE" \
  "040755|$ZIP_ROOT_HEX|-|" \
  "0100644|$ZIP_FILE_HEX|-|78"
/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin \
  /usr/bin/perl -e '
    truncate($ARGV[0], $ARGV[1]) or die "extend sparse ZIP: $!\n";
  ' "$RESOURCE_ARCHIVE_SIZE" "$((TEST_ZIP_MAX_ARCHIVE_BYTES + 1))"
assert_archive_resource_limit_rejected \
  archive-size "$RESOURCE_ARCHIVE_SIZE" 'archive bytes'

RESOURCE_ENTRY_COUNT="$STAGE_DIR/resource-limit-entry-count.zip"
write_crafted_entry_count_limit_zip \
  "$RESOURCE_ENTRY_COUNT" "$TEST_ZIP_MAX_ENTRY_COUNT"
assert_archive_resource_limit_rejected \
  entry-count "$RESOURCE_ENTRY_COUNT" 'entry count'

# The following fixtures deliberately make the declared Deflate sizes cross
# one limit at a time while keeping the files small. Their payload is only a
# header/preflight sentinel, not a valid Deflate stream: the exact diagnostic
# assertions prove resource rejection happens before CRC/inflate or extraction.
RESOURCE_ENTRY_SIZE="$STAGE_DIR/resource-limit-entry-size.zip"
RESOURCE_ENTRY_SIZE_COMPRESSED=2679112
write_crafted_stored_zip "$RESOURCE_ENTRY_SIZE" \
  "040755|$ZIP_ROOT_HEX|-|" \
  "0100644|$ZIP_FILE_HEX|-|z$RESOURCE_ENTRY_SIZE_COMPRESSED|8|$RESOURCE_ENTRY_SIZE_COMPRESSED|$((TEST_ZIP_MAX_ENTRY_UNCOMPRESSED_BYTES + 1))"
assert_archive_resource_limit_rejected \
  entry-size "$RESOURCE_ENTRY_SIZE" 'single entry size'

RESOURCE_TOTAL_SIZE="$STAGE_DIR/resource-limit-total-size.zip"
RESOURCE_TOTAL_ENTRY_UNCOMPRESSED=400000000
RESOURCE_TOTAL_ENTRY_COMPRESSED=2000000
write_crafted_stored_zip "$RESOURCE_TOTAL_SIZE" \
  "040755|$ZIP_ROOT_HEX|-|" \
  "0100644|${ZIP_CONTENTS_HEX}6f6e65|-|z$RESOURCE_TOTAL_ENTRY_COMPRESSED|8|$RESOURCE_TOTAL_ENTRY_COMPRESSED|$RESOURCE_TOTAL_ENTRY_UNCOMPRESSED" \
  "0100644|${ZIP_CONTENTS_HEX}74776f|-|z$RESOURCE_TOTAL_ENTRY_COMPRESSED|8|$RESOURCE_TOTAL_ENTRY_COMPRESSED|$RESOURCE_TOTAL_ENTRY_UNCOMPRESSED" \
  "0100644|${ZIP_CONTENTS_HEX}7468726565|-|z$RESOURCE_TOTAL_ENTRY_COMPRESSED|8|$RESOURCE_TOTAL_ENTRY_COMPRESSED|$RESOURCE_TOTAL_ENTRY_UNCOMPRESSED"
[ "$((RESOURCE_TOTAL_ENTRY_UNCOMPRESSED * 3))" -gt "$TEST_ZIP_MAX_TOTAL_UNCOMPRESSED_BYTES" ] \
  || fail "total-size ZIP fixture does not exceed the intended limit"
[ "$RESOURCE_TOTAL_ENTRY_UNCOMPRESSED" \
  -le "$((RESOURCE_TOTAL_ENTRY_COMPRESSED * TEST_ZIP_MAX_COMPRESSION_RATIO + TEST_ZIP_COMPRESSION_RATIO_SLACK))" ] \
  || fail "total-size ZIP fixture accidentally exceeds the ratio limit"
assert_archive_resource_limit_rejected \
  total-size "$RESOURCE_TOTAL_SIZE" 'total uncompressed size'

RESOURCE_RATIO="$STAGE_DIR/resource-limit-ratio.zip"
RESOURCE_RATIO_UNCOMPRESSED="$((TEST_ZIP_MAX_COMPRESSION_RATIO + TEST_ZIP_COMPRESSION_RATIO_SLACK + 1))"
write_crafted_stored_zip "$RESOURCE_RATIO" \
  "040755|$ZIP_ROOT_HEX|-|" \
  "0100644|$ZIP_FILE_HEX|-|00|8|1|$RESOURCE_RATIO_UNCOMPRESSED"
assert_archive_resource_limit_rejected \
  compression-ratio "$RESOURCE_RATIO" 'expansion ratio'

# Header-only checks cannot trust declared sizes. These are valid raw Deflate
# streams whose actual output is measured from the descriptor before unzip or
# ditto receives any bytes.
RESOURCE_ACTUAL_RATIO="$STAGE_DIR/resource-limit-actual-ratio.zip"
write_crafted_raw_deflate_zip \
  "$RESOURCE_ACTUAL_RATIO" 2097152 1000000 matching
assert_archive_resource_limit_rejected \
  actual-compression-ratio "$RESOURCE_ACTUAL_RATIO" 'actual expansion ratio'

PAYLOAD_SIZE_MISMATCH="$STAGE_DIR/payload-size-mismatch.zip"
write_crafted_raw_deflate_zip \
  "$PAYLOAD_SIZE_MISMATCH" 4096 4095 matching
assert_archive_payload_rejected_before_extraction \
  size-mismatch "$PAYLOAD_SIZE_MISMATCH" \
  'ZIP payload actual size differs from declared size'

PAYLOAD_CRC_MISMATCH="$STAGE_DIR/payload-crc-mismatch.zip"
write_crafted_raw_deflate_zip \
  "$PAYLOAD_CRC_MISMATCH" 4096 4096 mismatch
assert_archive_payload_rejected_before_extraction \
  crc-mismatch "$PAYLOAD_CRC_MISMATCH" \
  'ZIP payload CRC differs from declared CRC'

RESOURCE_LONG_NAME="$APP_NAME.app"
RESOURCE_NAME_COMPONENT="$(/usr/bin/printf 'a%.0s' {1..200})"
for _ in 1 2 3 4 5; do
  RESOURCE_LONG_NAME="$RESOURCE_LONG_NAME/$RESOURCE_NAME_COMPONENT"
done
RESOURCE_LONG_NAME="$RESOURCE_LONG_NAME/file"
[ "${#RESOURCE_LONG_NAME}" -gt "$TEST_ZIP_MAX_NAME_BYTES" ] \
  || fail "long-name ZIP fixture does not exceed the intended limit"
RESOURCE_LONG_NAME_ZIP="$STAGE_DIR/resource-limit-name.zip"
write_crafted_stored_zip "$RESOURCE_LONG_NAME_ZIP" \
  "040755|$ZIP_ROOT_HEX|-|" \
  "0100644|$(hex_bytes "$RESOURCE_LONG_NAME")|-|78"
assert_archive_resource_limit_rejected \
  name-length "$RESOURCE_LONG_NAME_ZIP" 'path length'

RESOURCE_LONG_COMPONENT="$(/usr/bin/printf 'b%.0s' {1..256})"
[ "${#RESOURCE_LONG_COMPONENT}" -gt "$TEST_ZIP_MAX_COMPONENT_BYTES" ] \
  || fail "long-component ZIP fixture does not exceed the intended limit"
RESOURCE_COMPONENT_ZIP="$STAGE_DIR/resource-limit-component.zip"
write_crafted_stored_zip "$RESOURCE_COMPONENT_ZIP" \
  "040755|$ZIP_ROOT_HEX|-|" \
  "0100644|$(hex_bytes "$APP_NAME.app/$RESOURCE_LONG_COMPONENT")|-|78"
assert_archive_resource_limit_rejected \
  component-length "$RESOURCE_COMPONENT_ZIP" 'component length'

RESOURCE_DEEP_NAME="$APP_NAME.app"
for _ in $(/usr/bin/seq 1 "$((TEST_ZIP_MAX_PATH_DEPTH + 1))"); do
  RESOURCE_DEEP_NAME="$RESOURCE_DEEP_NAME/d"
done
RESOURCE_DEEP_NAME="$RESOURCE_DEEP_NAME/file"
RESOURCE_DEPTH_ZIP="$STAGE_DIR/resource-limit-depth.zip"
write_crafted_stored_zip "$RESOURCE_DEPTH_ZIP" \
  "040755|$ZIP_ROOT_HEX|-|" \
  "0100644|$(hex_bytes "$RESOURCE_DEEP_NAME")|-|78"
assert_archive_resource_limit_rejected \
  path-depth "$RESOURCE_DEPTH_ZIP" 'path depth'

PUBLICATION_DIST="$RELEASE_PRIVATE_ROOT_PARENT"
UMASK_ZIP_SOURCE="$STAGE_DIR/umask-zip-source"
/bin/mkdir -p "$UMASK_ZIP_SOURCE"
/usr/bin/printf 'outer ZIP mode fixture\n' >"$UMASK_ZIP_SOURCE/payload.txt"
for archive_umask in 002 000; do
  UMASK_ZIP="$STAGE_DIR/umask-$archive_umask.zip"
  (
    umask "$archive_umask"
    cd "$UMASK_ZIP_SOURCE"
    sanitized_zip -q "$UMASK_ZIP" payload.txt
  )
  [ "$(/usr/bin/stat -f '%Lp' "$UMASK_ZIP")" = 644 ] \
    || fail "outer ZIP inherited ambient umask $archive_umask"
  require_public_release_file "$UMASK_ZIP" "Ambient-umask ZIP fixture"

  UMASK_SIDECAR="$STAGE_DIR/umask-$archive_umask.zip.sha256"
  UMASK_ZIP_SHA256="$(release_tool_sha256 "$UMASK_ZIP")"
  (
    umask "$archive_umask"
    write_release_sha256_sidecar_candidate \
      "$UMASK_SIDECAR" "$UMASK_ZIP" "$UMASK_ZIP_SHA256"
  )
  [ "$(/usr/bin/stat -f '%Lp' "$UMASK_SIDECAR")" = 644 ] \
    || fail "SHA-256 sidecar inherited ambient umask $archive_umask"
done

UNSAFE_MODE_CANDIDATE="$STAGE_DIR/unsafe-mode-publication-candidate.zip"
UNSAFE_MODE_DESTINATION="$PUBLICATION_DIST/unsafe-mode-publication.zip"
/usr/bin/printf 'unsafe publication mode fixture\n' >"$UNSAFE_MODE_CANDIDATE"
UNSAFE_MODE_SHA256="$(release_tool_sha256 "$UNSAFE_MODE_CANDIDATE")"
/bin/chmod 0666 "$UNSAFE_MODE_CANDIDATE"
if atomic_publish_file_no_replace \
  "$UNSAFE_MODE_CANDIDATE" "$UNSAFE_MODE_DESTINATION" \
  "$UNSAFE_MODE_SHA256" >/dev/null 2>&1; then
  fail "world-writable publication candidate was accepted"
fi
[ ! -e "$UNSAFE_MODE_DESTINATION" ] \
  || fail "unsafe-mode candidate reached the publication directory"
/bin/chmod 0644 "$UNSAFE_MODE_CANDIDATE"

UNSAFE_ACL_CANDIDATE="$STAGE_DIR/unsafe-acl-publication-candidate.zip"
UNSAFE_ACL_DESTINATION="$PUBLICATION_DIST/unsafe-acl-publication.zip"
/usr/bin/printf 'unsafe publication ACL fixture\n' >"$UNSAFE_ACL_CANDIDATE"
UNSAFE_ACL_SHA256="$(release_tool_sha256 "$UNSAFE_ACL_CANDIDATE")"
/bin/chmod +a 'everyone allow write' "$UNSAFE_ACL_CANDIDATE"
if atomic_publish_file_no_replace \
  "$UNSAFE_ACL_CANDIDATE" "$UNSAFE_ACL_DESTINATION" \
  "$UNSAFE_ACL_SHA256" >/dev/null 2>&1; then
  fail "ACL-bearing publication candidate was accepted"
fi
[ ! -e "$UNSAFE_ACL_DESTINATION" ] \
  || fail "ACL-bearing candidate reached the publication directory"
/bin/chmod -N "$UNSAFE_ACL_CANDIDATE"

HARDLINK_CANDIDATE="$STAGE_DIR/hardlink-publication-candidate.zip"
HARDLINK_CANDIDATE_ALIAS="$STAGE_DIR/hardlink-publication-candidate.alias"
HARDLINK_DESTINATION="$PUBLICATION_DIST/hardlink-publication-destination.zip"
/usr/bin/printf 'multiply linked publication candidate\n' >"$HARDLINK_CANDIDATE"
/bin/ln "$HARDLINK_CANDIDATE" "$HARDLINK_CANDIDATE_ALIAS"
HARDLINK_CANDIDATE_SHA256="$(release_tool_sha256 "$HARDLINK_CANDIDATE")"
if atomic_publish_file_no_replace \
  "$HARDLINK_CANDIDATE" "$HARDLINK_DESTINATION" \
  "$HARDLINK_CANDIDATE_SHA256" 2>/dev/null; then
  fail "multiply linked publication candidate was published"
fi
[ -f "$HARDLINK_CANDIDATE" ] && [ -f "$HARDLINK_CANDIDATE_ALIAS" ] \
  || fail "rejected multiply linked candidate was consumed"
[ ! -e "$HARDLINK_DESTINATION" ] \
  || fail "rejected multiply linked candidate reached the publication directory"
/bin/rm -f -- "$HARDLINK_CANDIDATE" "$HARDLINK_CANDIDATE_ALIAS"

HARDLINK_SIDECAR_ARCHIVE="$PUBLICATION_DIST/hardlink-sidecar-candidate-archive.zip"
HARDLINK_SIDECAR_CANDIDATE="$STAGE_DIR/hardlink-sidecar-candidate.sha256"
HARDLINK_SIDECAR_CANDIDATE_ALIAS="$STAGE_DIR/hardlink-sidecar-candidate.alias"
HARDLINK_SIDECAR_DESTINATION="$HARDLINK_SIDECAR_ARCHIVE.sha256"
/usr/bin/printf 'archive for hard-linked sidecar candidate\n' \
  >"$HARDLINK_SIDECAR_ARCHIVE"
HARDLINK_SIDECAR_ARCHIVE_SHA256="$(release_tool_sha256 "$HARDLINK_SIDECAR_ARCHIVE")"
write_release_sha256_sidecar_candidate \
  "$HARDLINK_SIDECAR_CANDIDATE" \
  "$HARDLINK_SIDECAR_ARCHIVE" \
  "$HARDLINK_SIDECAR_ARCHIVE_SHA256"
/bin/ln "$HARDLINK_SIDECAR_CANDIDATE" "$HARDLINK_SIDECAR_CANDIDATE_ALIAS"
if publish_sidecar_candidate_no_replace_or_adopt \
  "$HARDLINK_SIDECAR_CANDIDATE" \
  "$HARDLINK_SIDECAR_ARCHIVE" \
  "$HARDLINK_SIDECAR_DESTINATION" \
  "$HARDLINK_SIDECAR_ARCHIVE_SHA256" 2>/dev/null; then
  fail "multiply linked SHA-256 sidecar candidate was published"
fi
[ ! -e "$HARDLINK_SIDECAR_DESTINATION" ] \
  || fail "rejected multiply linked sidecar candidate reached publication"
/bin/rm -f -- \
  "$HARDLINK_SIDECAR_CANDIDATE_ALIAS" \
  "$HARDLINK_SIDECAR_CANDIDATE" \
  "$HARDLINK_SIDECAR_ARCHIVE"

HARDLINK_PUBLISHED_ARCHIVE="$PUBLICATION_DIST/hardlink-published-archive.zip"
HARDLINK_PUBLISHED_ARCHIVE_ALIAS="$PUBLICATION_DIST/hardlink-published-archive.alias"
ZIP_PATH="$HARDLINK_PUBLISHED_ARCHIVE"
ZIP_SHA256_PATH="$HARDLINK_PUBLISHED_ARCHIVE.sha256"
/usr/bin/printf 'multiply linked published archive\n' >"$HARDLINK_PUBLISHED_ARCHIVE"
/bin/ln "$HARDLINK_PUBLISHED_ARCHIVE" "$HARDLINK_PUBLISHED_ARCHIVE_ALIAS"
if release_publication_state >/dev/null 2>&1; then
  fail "multiply linked published archive was accepted"
fi
/bin/rm -f -- "$HARDLINK_PUBLISHED_ARCHIVE_ALIAS" "$HARDLINK_PUBLISHED_ARCHIVE"

HARDLINK_PUBLISHED_SIDECAR_ARCHIVE="$PUBLICATION_DIST/hardlink-sidecar-archive.zip"
HARDLINK_PUBLISHED_SIDECAR="$HARDLINK_PUBLISHED_SIDECAR_ARCHIVE.sha256"
HARDLINK_PUBLISHED_SIDECAR_ALIAS="$PUBLICATION_DIST/hardlink-sidecar.alias"
ZIP_PATH="$HARDLINK_PUBLISHED_SIDECAR_ARCHIVE"
ZIP_SHA256_PATH="$HARDLINK_PUBLISHED_SIDECAR"
/usr/bin/printf 'published archive with multiply linked sidecar\n' \
  >"$HARDLINK_PUBLISHED_SIDECAR_ARCHIVE"
/usr/bin/printf 'multiply linked sidecar\n' >"$HARDLINK_PUBLISHED_SIDECAR"
/bin/ln "$HARDLINK_PUBLISHED_SIDECAR" "$HARDLINK_PUBLISHED_SIDECAR_ALIAS"
if release_publication_state >/dev/null 2>&1; then
  fail "multiply linked published SHA-256 sidecar was accepted"
fi
/bin/rm -f -- \
  "$HARDLINK_PUBLISHED_SIDECAR_ALIAS" \
  "$HARDLINK_PUBLISHED_SIDECAR" \
  "$HARDLINK_PUBLISHED_SIDECAR_ARCHIVE"

HARDLINK_SNAPSHOT_SOURCE="$PUBLICATION_DIST/hardlink-snapshot-source.zip"
HARDLINK_SNAPSHOT_SOURCE_ALIAS="$PUBLICATION_DIST/hardlink-snapshot-source.alias"
HARDLINK_SNAPSHOT_PATH="$STAGE_DIR/hardlink-private-snapshot.zip"
ZIP_PATH="$HARDLINK_SNAPSHOT_SOURCE"
ZIP_SHA256_PATH="$HARDLINK_SNAPSHOT_SOURCE.sha256"
/usr/bin/printf 'multiply linked snapshot source\n' >"$HARDLINK_SNAPSHOT_SOURCE"
/bin/ln "$HARDLINK_SNAPSHOT_SOURCE" "$HARDLINK_SNAPSHOT_SOURCE_ALIAS"
if capture_published_archive_snapshot \
  "$HARDLINK_SNAPSHOT_SOURCE" "$HARDLINK_SNAPSHOT_PATH" >/dev/null 2>&1; then
  fail "multiply linked published archive was copied into a private snapshot"
fi
[ ! -e "$HARDLINK_SNAPSHOT_PATH" ] \
  || fail "rejected multiply linked source left private snapshot evidence"
/bin/rm -f -- "$HARDLINK_SNAPSHOT_SOURCE_ALIAS"
HARDLINK_SNAPSHOT_IDENTITY="$(
  capture_published_archive_snapshot \
    "$HARDLINK_SNAPSHOT_SOURCE" "$HARDLINK_SNAPSHOT_PATH"
)"
HARDLINK_SNAPSHOT_SHA256="$(release_tool_sha256 "$HARDLINK_SNAPSHOT_PATH")"
HARDLINK_SNAPSHOT_ALIAS="$STAGE_DIR/hardlink-private-snapshot.alias"
/bin/ln "$HARDLINK_SNAPSHOT_PATH" "$HARDLINK_SNAPSHOT_ALIAS"
if verify_published_archive_matches_snapshot \
  "$HARDLINK_SNAPSHOT_SOURCE" \
  "$HARDLINK_SNAPSHOT_PATH" \
  "$HARDLINK_SNAPSHOT_IDENTITY" \
  "$HARDLINK_SNAPSHOT_SHA256" 2>/dev/null; then
  fail "multiply linked private archive snapshot was accepted"
fi
/bin/rm -f -- "$HARDLINK_SNAPSHOT_ALIAS"
/bin/chmod 600 "$HARDLINK_SNAPSHOT_PATH"
/bin/rm -f -- "$HARDLINK_SNAPSHOT_PATH" "$HARDLINK_SNAPSHOT_SOURCE"

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
atomic_publish_file_no_replace \
  "$PUBLICATION_CANDIDATE" "$PUBLISHED_RELEASE" "$PUBLISHED_RELEASE_SHA256"
[ ! -e "$PUBLICATION_CANDIDATE" ] || fail "published candidate remained in staging"
[ "$(release_tool_sha256 "$PUBLISHED_RELEASE")" = "$PUBLISHED_RELEASE_SHA256" ] \
  || fail "atomic publication changed candidate bytes"
[ "$(release_tool_sha256 "$OLDER_RELEASE")" = "$OLDER_RELEASE_SHA256" ] \
  || fail "publishing a new commit changed an older release"

COLLISION_CANDIDATE="$STAGE_DIR/collision-candidate.zip"
/usr/bin/printf 'must not replace\n' >"$COLLISION_CANDIDATE"
COLLISION_CANDIDATE_SHA256="$(release_tool_sha256 "$COLLISION_CANDIDATE")"
if atomic_publish_file_no_replace \
  "$COLLISION_CANDIDATE" "$PUBLISHED_RELEASE" \
  "$COLLISION_CANDIDATE_SHA256" 2>/dev/null; then
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
SIDECAR_CANDIDATE_SHA256="$(release_tool_sha256 "$SIDECAR_CANDIDATE")"
atomic_publish_file_no_replace \
  "$SIDECAR_CANDIDATE" "$PUBLISHED_SIDECAR" "$SIDECAR_CANDIDATE_SHA256"
verify_published_release_hash_evidence \
  "$PUBLISHED_RELEASE" "$PUBLISHED_SIDECAR" "$PUBLISHED_RELEASE_SHA256"

/bin/chmod 0666 "$PUBLISHED_RELEASE"
if verify_published_release_hash_evidence \
  "$PUBLISHED_RELEASE" "$PUBLISHED_SIDECAR" \
  "$PUBLISHED_RELEASE_SHA256" >/dev/null 2>&1; then
  fail "published archive with a mutable mode passed final hash evidence"
fi
/bin/chmod 0644 "$PUBLISHED_RELEASE"
/bin/chmod +a 'everyone allow write' "$PUBLISHED_SIDECAR"
if verify_published_release_hash_evidence \
  "$PUBLISHED_RELEASE" "$PUBLISHED_SIDECAR" \
  "$PUBLISHED_RELEASE_SHA256" >/dev/null 2>&1; then
  fail "published sidecar with an ACL passed final hash evidence"
fi
/bin/chmod -N "$PUBLISHED_SIDECAR"
verify_published_release_hash_evidence \
  "$PUBLISHED_RELEASE" "$PUBLISHED_SIDECAR" "$PUBLISHED_RELEASE_SHA256"

SIDECAR_COLLISION="$STAGE_DIR/sidecar-collision"
/usr/bin/printf 'must not replace sidecar\n' >"$SIDECAR_COLLISION"
PUBLISHED_SIDECAR_SHA256="$(release_tool_sha256 "$PUBLISHED_SIDECAR")"
SIDECAR_COLLISION_SHA256="$(release_tool_sha256 "$SIDECAR_COLLISION")"
if atomic_publish_file_no_replace \
  "$SIDECAR_COLLISION" "$PUBLISHED_SIDECAR" \
  "$SIDECAR_COLLISION_SHA256" 2>/dev/null; then
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
atomic_publish_file_no_replace \
  "$CRASH_CANDIDATE" "$CRASH_ARCHIVE" "$CRASH_SHA256"
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

REPAIR_EXTRACT_FUNCTION="$(declare -f extract_and_verify_archive)"
REPAIR_SOURCE_FUNCTION="$(declare -f verify_release_source_unchanged)"
REPAIR_EXTRACT_CALLED=false
REPAIR_SOURCE_CALLED=false
REPAIR_COMMIT="$(/usr/bin/printf '4%.0s' {1..40})"
REPAIR_ARCHIVE="$PUBLICATION_DIST/Fixture-macos-$REPAIR_COMMIT.zip"
REPAIR_SIDECAR="$REPAIR_ARCHIVE.sha256"
TMP_ZIP_SHA256="$STAGE_DIR/repair-candidate.zip.sha256"
/usr/bin/printf 'rigorously verified orphan archive\n' >"$REPAIR_ARCHIVE"
ZIP_PATH="$REPAIR_ARCHIVE"
ZIP_SHA256_PATH="$REPAIR_SIDECAR"
extract_and_verify_archive() {
  [ "$1" = "$STAGE_DIR/existing-published-archive.zip" ] \
    && [ "$1" != "$REPAIR_ARCHIVE" ] \
    && [ "$(/bin/cat "$1")" = 'rigorously verified orphan archive' ] \
    && [ "$2" = existing-published-extracted ] \
    && [ "$3" = "$(release_tool_sha256 "$1")" ] || return 1
  REPAIR_EXTRACT_CALLED=true
}
verify_release_source_unchanged() {
  REPAIR_SOURCE_CALLED=true
}
repair_or_adopt_existing_release archive-only
[ "$REPAIR_EXTRACT_CALLED" = true ] \
  || fail "archive-only repair skipped extracted bundle verification"
[ "$REPAIR_SOURCE_CALLED" = true ] \
  || fail "archive-only repair skipped exact source revalidation"
verify_published_release_hash_evidence \
  "$REPAIR_ARCHIVE" "$REPAIR_SIDECAR" "$PUBLISHED_ZIP_SHA256"
eval "$REPAIR_EXTRACT_FUNCTION"
eval "$REPAIR_SOURCE_FUNCTION"
if [ -e "$STAGE_DIR/existing-published-archive.zip" ]; then
  /bin/chmod 600 "$STAGE_DIR/existing-published-archive.zip"
  /bin/rm -f -- "$STAGE_DIR/existing-published-archive.zip"
fi

RACE_EXTRACT_FUNCTION="$(declare -f extract_and_verify_archive)"
RACE_SOURCE_FUNCTION="$(declare -f verify_release_source_unchanged)"
RACE_ARCHIVE="$PUBLICATION_DIST/Fixture-macos-$(/usr/bin/printf '5%.0s' {1..40}).zip"
RACE_SIDECAR="$RACE_ARCHIVE.sha256"
RACE_ARCHIVE_ASIDE="$STAGE_DIR/race-original-aside.zip"
RACE_SUBSTITUTE="$STAGE_DIR/race-substitute.zip"
RACE_SUBSTITUTE_ASIDE="$STAGE_DIR/race-substitute-aside.zip"
RACE_SIDECAR_CANDIDATE="$STAGE_DIR/race-sidecar-candidate.sha256"
/usr/bin/printf 'initial archive A\n' >"$RACE_ARCHIVE"
/usr/bin/printf 'substitute archive B\n' >"$RACE_SUBSTITUTE"
ZIP_PATH="$RACE_ARCHIVE"
ZIP_SHA256_PATH="$RACE_SIDECAR"
TMP_ZIP_SHA256="$RACE_SIDECAR_CANDIDATE"
RACE_SWAP_CALLED=false
RACE_RESTORE_CALLED=false
extract_and_verify_archive() {
  [ "$1" = "$STAGE_DIR/existing-published-archive.zip" ] \
    && [ "$2" = existing-published-extracted ] \
    && [ "$(/bin/cat "$1")" = 'initial archive A' ] \
    && [ "$3" = "$(release_tool_sha256 "$1")" ] || return 1
  RACE_SWAP_CALLED=true
  /bin/mv "$RACE_ARCHIVE" "$RACE_ARCHIVE_ASIDE"
  /bin/mv "$RACE_SUBSTITUTE" "$RACE_ARCHIVE"
  [ "$(/bin/cat "$RACE_ARCHIVE")" = 'substitute archive B' ] || return 1
  /bin/mv "$RACE_ARCHIVE" "$RACE_SUBSTITUTE_ASIDE"
  /bin/mv "$RACE_ARCHIVE_ASIDE" "$RACE_ARCHIVE"
  RACE_RESTORE_CALLED=true
}
verify_release_source_unchanged() { return 0; }
if repair_or_adopt_existing_release archive-only 2>/dev/null; then
  fail "published archive A-to-B-to-A pathname race was accepted"
fi
[ ! -e "$RACE_SIDECAR" ] \
  || fail "A-to-B-to-A archive race published misleading hash evidence"
[ "$RACE_SWAP_CALLED" = true ] \
  || fail "published archive A-to-B-to-A regression did not install B"
[ "$RACE_RESTORE_CALLED" = true ] \
  || fail "published archive A-to-B-to-A regression did not restore A before verification"
eval "$RACE_EXTRACT_FUNCTION"
eval "$RACE_SOURCE_FUNCTION"
if [ -e "$STAGE_DIR/existing-published-archive.zip" ]; then
  /bin/chmod 600 "$STAGE_DIR/existing-published-archive.zip"
  /bin/rm -f -- "$STAGE_DIR/existing-published-archive.zip"
fi

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

UNSAFE_ADOPTION_COMMIT="$(/usr/bin/printf '6%.0s' {1..40})"
UNSAFE_ADOPTION_ARCHIVE="$PUBLICATION_DIST/Fixture-macos-$UNSAFE_ADOPTION_COMMIT.zip"
UNSAFE_ADOPTION_SIDECAR="$UNSAFE_ADOPTION_ARCHIVE.sha256"
UNSAFE_ADOPTION_CANDIDATE="$STAGE_DIR/unsafe-adoption-candidate.zip"
UNSAFE_ADOPTION_SIDECAR_CANDIDATE="$STAGE_DIR/unsafe-adoption-candidate.zip.sha256"
/usr/bin/printf 'same bytes but unsafe published mode\n' >"$UNSAFE_ADOPTION_ARCHIVE"
/bin/cp "$UNSAFE_ADOPTION_ARCHIVE" "$UNSAFE_ADOPTION_CANDIDATE"
/bin/chmod 0666 "$UNSAFE_ADOPTION_ARCHIVE"
UNSAFE_ADOPTION_SHA256="$(release_tool_sha256 "$UNSAFE_ADOPTION_CANDIDATE")"
ZIP_PATH="$UNSAFE_ADOPTION_ARCHIVE"
ZIP_SHA256_PATH="$UNSAFE_ADOPTION_SIDECAR"
if publish_verified_release_pair \
  "$UNSAFE_ADOPTION_CANDIDATE" "$UNSAFE_ADOPTION_SIDECAR_CANDIDATE" \
  "$UNSAFE_ADOPTION_SHA256" >/dev/null 2>&1; then
  fail "unsafe-mode pre-existing archive was adopted"
fi
[ ! -e "$UNSAFE_ADOPTION_SIDECAR" ] \
  || fail "unsafe-mode pre-existing archive received a sidecar"
/bin/chmod 0644 "$UNSAFE_ADOPTION_ARCHIVE"

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

SOURCE_IDENTITY_GUARD_FUNCTION="$(declare -f verify_release_source_identity_guard)"
SOURCE_IDENTITY_GUARD_CALLS=0
verify_release_source_identity_guard() {
  SOURCE_IDENTITY_GUARD_CALLS=$((SOURCE_IDENTITY_GUARD_CALLS + 1))
}
RELEASE_CARGO_BIN=/usr/bin/false
RELEASE_RUSTC_BIN=/usr/bin/true
if run_sanitized_release_cargo >/dev/null 2>&1; then
  fail "failing release Cargo fixture unexpectedly succeeded"
fi
[ "$SOURCE_IDENTITY_GUARD_CALLS" = 2 ] \
  || fail "release Cargo failure did not run both source identity checks"
verify_release_source_identity_guard() { return 0; }

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
assert_env_value "$ENV_CAPTURE" WAAL_PUBLISHABLE_RELEASE "0"
assert_env_value "$ENV_CAPTURE" WAAL_LOCAL_SIGNED_RELEASE "1"
assert_env_value "$ENV_CAPTURE" WAAL_RELEASE_GIT_COMMIT "$EXPECTED_COMMIT"
assert_env_value "$ENV_CAPTURE" WAAL_RELEASE_GIT_TREE "$EXPECTED_TREE"
assert_env_value "$ENV_CAPTURE" WAAL_RELEASE_CARGO_VERSION "$RELEASE_CARGO_VERSION"
assert_env_value "$ENV_CAPTURE" WAAL_RELEASE_RUSTC_VERSION "$RELEASE_RUSTC_VERSION"
assert_env_value "$ENV_CAPTURE" WAAL_RELEASE_CARGO_SHA256 "$RELEASE_CARGO_SHA256"
assert_env_value "$ENV_CAPTURE" WAAL_RELEASE_RUSTC_SHA256 "$RELEASE_RUSTC_SHA256"
assert_env_value "$ENV_CAPTURE" WAAL_RELEASE_RUST_SYSROOT_SHA256 "$RELEASE_RUST_SYSROOT_SHA256"
assert_env_value "$ENV_CAPTURE" WAAL_RELEASE_NATIVE_TOOLCHAIN_SHA256 "$RELEASE_NATIVE_TOOLCHAIN_SHA256"
assert_env_value "$ENV_CAPTURE" WAAL_RELEASE_MATERIALS_SHA256 "$RELEASE_MATERIALS_SHA256"

LOCAL_SIGNED_INFO_BUNDLE="$STAGE_DIR/local-signed-info.app"
LOCAL_SIGNED_INFO_FILE="$LOCAL_SIGNED_INFO_BUNDLE/Contents/Resources/BUILD-INFO.txt"
/bin/mkdir -p "$LOCAL_SIGNED_INFO_BUNDLE/Contents/Resources"
write_macos_release_provenance "$LOCAL_SIGNED_INFO_BUNDLE"
[ -f "$LOCAL_SIGNED_INFO_FILE" ] && [ ! -L "$LOCAL_SIGNED_INFO_FILE" ] \
  || fail "local signed bundle information is not a regular BUILD-INFO.txt file"
[ ! -e "$LOCAL_SIGNED_INFO_BUNDLE/Contents/Resources/BUILD-PROVENANCE.txt" ] \
  || fail "local signed bundle still emits a producer-attested BUILD-PROVENANCE.txt file"
for expected_local_info_line in \
  WAAL_MACOS_LOCAL_SIGNED_BUILD_INFO_V1 \
  publishable=false \
  attestation=none-local-shared-security-context \
  producer-attribution=unavailable-local-shared-security-context; do
  /usr/bin/grep -Fxq "$expected_local_info_line" "$LOCAL_SIGNED_INFO_FILE" \
    || fail "BUILD-INFO.txt is missing local-only disclaimer: $expected_local_info_line"
done
if /usr/bin/grep -Eq \
  '^(publishable=true|attestation=.*authenticated|producer-attribution=(available|authenticated).*)$' \
  "$LOCAL_SIGNED_INFO_FILE"; then
  fail "BUILD-INFO.txt makes a false publishability or producer-attestation claim"
fi
verify_macos_release_provenance "$LOCAL_SIGNED_INFO_BUNDLE"
/usr/bin/sed \
  's/^producer-attribution=unavailable-local-shared-security-context$/producer-attribution=authenticated-builder/' \
  "$LOCAL_SIGNED_INFO_FILE" >"$STAGE_DIR/tampered-local-signed-build-info.txt"
/bin/mv "$STAGE_DIR/tampered-local-signed-build-info.txt" "$LOCAL_SIGNED_INFO_FILE"
if (verify_macos_release_provenance "$LOCAL_SIGNED_INFO_BUNDLE" >/dev/null 2>&1); then
  fail "local signed BUILD-INFO verification accepted false producer attribution"
fi
write_macos_release_provenance "$LOCAL_SIGNED_INFO_BUNDLE"

SAVED_EXPECTED_BUNDLE_ID="$EXPECTED_BUNDLE_ID"
SAVED_EXPECTED_BUNDLE_ID_ENV="$EXPECTED_BUNDLE_ID_ENV"
EXPECTED_BUNDLE_ID="$PRODUCTION_BUNDLE_ID"
EXPECTED_BUNDLE_ID_ENV="WAAL_RELEASE_BUNDLE_ID"
LOCAL_SIGNED_METADATA_BUNDLE="$STAGE_DIR/local-signed-metadata.app"
LOCAL_SIGNED_METADATA_EXECUTABLE="$LOCAL_SIGNED_METADATA_BUNDLE/Contents/MacOS/metadata-fixture"
/bin/mkdir -p "$LOCAL_SIGNED_METADATA_BUNDLE/Contents/MacOS"
/usr/bin/printf '%s\n' \
  '<?xml version="1.0" encoding="UTF-8"?>' \
  '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">' \
  '<plist version="1.0"><dict>' \
  '<key>CFBundleExecutable</key><string>metadata-fixture</string>' \
  '</dict></plist>' \
  >"$LOCAL_SIGNED_METADATA_BUNDLE/Contents/Info.plist"
LOCAL_SIGNED_METADATA="WAAL_BUILD_METADATA_V1;artifact-kind=local-signed-release;publishable=false;attestation=none-local-shared-security-context;producer-attribution=unavailable-local-shared-security-context;"
LOCAL_SIGNED_METADATA+="profile=release;target-os=macos;target-arch=aarch64;debug-assertions=false;debug-fill=false;dev-tools=false;diagnostics-ui=false;release-diagnostics=false;"
LOCAL_SIGNED_METADATA+="macos-bundle-id=$EXPECTED_BUNDLE_ID;production-macos-bundle-id=$EXPECTED_BUNDLE_ID;non-production-macos-identity=false;macos-team-id=$EXPECTED_TEAM_ID;"
LOCAL_SIGNED_METADATA+="windows-authenticode-publisher=;windows-authenticode-cert-sha256=;"
LOCAL_SIGNED_METADATA+="source-git-commit=$RELEASE_GIT_COMMIT;source-git-tree=$RELEASE_GIT_TREE;release-cargo-version=$RELEASE_CARGO_VERSION;release-rustc-version=$RELEASE_RUSTC_VERSION;"
LOCAL_SIGNED_METADATA+="release-cargo-sha256=$RELEASE_CARGO_SHA256;release-rustc-sha256=$RELEASE_RUSTC_SHA256;release-rust-sysroot-sha256=$RELEASE_RUST_SYSROOT_SHA256;release-native-toolchain-sha256=$RELEASE_NATIVE_TOOLCHAIN_SHA256;release-materials-sha256=$RELEASE_MATERIALS_SHA256;"
/usr/bin/printf '%s\n' "$LOCAL_SIGNED_METADATA" >"$LOCAL_SIGNED_METADATA_EXECUTABLE"
/bin/chmod 700 "$LOCAL_SIGNED_METADATA_EXECUTABLE"
verify_release_build_metadata "$LOCAL_SIGNED_METADATA_BUNDLE"
for false_claim in \
  'publishable=false|publishable=true' \
  'attestation=none-local-shared-security-context|attestation=external-authenticated-builder' \
  'producer-attribution=unavailable-local-shared-security-context|producer-attribution=authenticated-builder'; do
  false_claim_from="${false_claim%%|*}"
  false_claim_to="${false_claim#*|}"
  /usr/bin/printf '%s\n' "${LOCAL_SIGNED_METADATA/$false_claim_from/$false_claim_to}" \
    >"$LOCAL_SIGNED_METADATA_EXECUTABLE"
  if (verify_release_build_metadata "$LOCAL_SIGNED_METADATA_BUNDLE" >/dev/null 2>&1); then
    fail "local signed executable metadata accepted false claim: $false_claim_to"
  fi
done
for duplicate_claim in \
  'publishable=false;|publishable=false;publishable=true;' \
  'attestation=none-local-shared-security-context;|attestation=none-local-shared-security-context;attestation=external-authenticated-builder;' \
  'producer-attribution=unavailable-local-shared-security-context;|producer-attribution=unavailable-local-shared-security-context;producer-attribution=authenticated-builder;' \
  'profile=release;|profile=release;unknown-release-claim=true;'; do
  duplicate_claim_from="${duplicate_claim%%|*}"
  duplicate_claim_to="${duplicate_claim#*|}"
  /usr/bin/printf '%s\n' "${LOCAL_SIGNED_METADATA/$duplicate_claim_from/$duplicate_claim_to}" \
    >"$LOCAL_SIGNED_METADATA_EXECUTABLE"
  if (verify_release_build_metadata "$LOCAL_SIGNED_METADATA_BUNDLE" >/dev/null 2>&1); then
    fail "local signed executable metadata accepted duplicate or unknown claim: $duplicate_claim_to"
  fi
done
/usr/bin/printf '%s\n' "$LOCAL_SIGNED_METADATA" >"$LOCAL_SIGNED_METADATA_EXECUTABLE"
EXPECTED_BUNDLE_ID="$SAVED_EXPECTED_BUNDLE_ID"
EXPECTED_BUNDLE_ID_ENV="$SAVED_EXPECTED_BUNDLE_ID_ENV"

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
eval "$SOURCE_IDENTITY_GUARD_FUNCTION"

DIST_FIXTURE_ROOT="$TEST_ROOT/dist-root"
/bin/mkdir -p "$DIST_FIXTURE_ROOT" "$TEST_ROOT/redirected-dist"
/bin/ln -s "$TEST_ROOT/redirected-dist" "$DIST_FIXTURE_ROOT/dist"
if prepare_dist_root_for_root "$DIST_FIXTURE_ROOT" 2>/dev/null; then
  fail "symlinked dist root was accepted"
fi

ACL_DIST_FIXTURE_ROOT="$TEST_ROOT/acl-dist-root"
/bin/mkdir -p "$ACL_DIST_FIXTURE_ROOT/dist"
/bin/chmod +a \
  'everyone allow add_file,add_subdirectory,file_inherit,directory_inherit' \
  "$ACL_DIST_FIXTURE_ROOT/dist"
if verify_private_release_parent_security \
  "$ACL_DIST_FIXTURE_ROOT/dist" >/dev/null 2>&1; then
  fail "release dist parent with an inherited-write ACL was accepted"
fi
if (create_private_release_root_for_root "$ACL_DIST_FIXTURE_ROOT") \
  >/dev/null 2>&1; then
  fail "private release root was created below an ACL-bearing dist parent"
fi
/bin/chmod -RN "$ACL_DIST_FIXTURE_ROOT/dist"

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

GUARDED_TREE_FIXTURE="$TEST_ROOT/guarded-tool-tree"
/bin/mkdir -p "$GUARDED_TREE_FIXTURE/bin"
/bin/cp /usr/bin/true "$GUARDED_TREE_FIXTURE/bin/tool"
GUARDED_TREE_IDENTITY_A="$(guarded_tree_identity_sha256 "$GUARDED_TREE_FIXTURE")"
/bin/mv "$GUARDED_TREE_FIXTURE/bin/tool" "$GUARDED_TREE_FIXTURE/bin/tool.original"
/bin/cp "$GUARDED_TREE_FIXTURE/bin/tool.original" "$GUARDED_TREE_FIXTURE/bin/tool"
GUARDED_TREE_IDENTITY_B="$(guarded_tree_identity_sha256 "$GUARDED_TREE_FIXTURE")"
[ "$GUARDED_TREE_IDENTITY_A" != "$GUARDED_TREE_IDENTITY_B" ] \
  || fail "same-byte tool pathname replacement escaped the guarded-tree inode identity"
/bin/rm -f -- "$GUARDED_TREE_FIXTURE/bin/tool.original"
/bin/ln "$GUARDED_TREE_FIXTURE/bin/tool" "$GUARDED_TREE_FIXTURE/bin/tool.alias"
if guarded_tree_identity_sha256 "$GUARDED_TREE_FIXTURE" >/dev/null 2>&1; then
  fail "alternate hard link was accepted in a guarded tool tree"
fi
/bin/rm -f -- "$GUARDED_TREE_FIXTURE/bin/tool.alias"

BUNDLE_GUARD_SOURCE_A="$TEST_ROOT/bundle-guard-a.c"
BUNDLE_GUARD_SOURCE_B="$TEST_ROOT/bundle-guard-b.c"
BUNDLE_GUARD_BINARY_A="$TEST_ROOT/bundle-guard-a"
BUNDLE_GUARD_BINARY_B="$TEST_ROOT/bundle-guard-b"
/usr/bin/printf '%s\n' 'int main(void) { return 0; }' >"$BUNDLE_GUARD_SOURCE_A"
/usr/bin/printf '%s\n' 'int main(void) { return 73; }' >"$BUNDLE_GUARD_SOURCE_B"
/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin \
  DEVELOPER_DIR="$REAL_DEVELOPER_DIR" SDKROOT="$REAL_MACOS_SDKROOT" \
  "$REAL_CLANG_BIN" -arch arm64 -isysroot "$REAL_MACOS_SDKROOT" \
  -o "$BUNDLE_GUARD_BINARY_A" "$BUNDLE_GUARD_SOURCE_A"
/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin \
  DEVELOPER_DIR="$REAL_DEVELOPER_DIR" SDKROOT="$REAL_MACOS_SDKROOT" \
  "$REAL_CLANG_BIN" -arch arm64 -isysroot "$REAL_MACOS_SDKROOT" \
  -o "$BUNDLE_GUARD_BINARY_B" "$BUNDLE_GUARD_SOURCE_B"
BUNDLE_GUARD_CANONICAL_A="$(canonical_unsigned_macho_sha256 "$BUNDLE_GUARD_BINARY_A")"
BUNDLE_GUARD_CANONICAL_B="$(canonical_unsigned_macho_sha256 "$BUNDLE_GUARD_BINARY_B")"
[ "$BUNDLE_GUARD_CANONICAL_A" != "$BUNDLE_GUARD_CANONICAL_B" ] \
  || fail "different arm64 Mach-O payloads produced one canonical signing digest"

BUNDLE_GUARD_BUNDLE="$TEST_ROOT/BundleGuard.app"
SAVED_BINARY_NAME="$BINARY_NAME"
BINARY_NAME=BundleGuard
/bin/mkdir -p \
  "$BUNDLE_GUARD_BUNDLE/Contents/MacOS" \
  "$BUNDLE_GUARD_BUNDLE/Contents/Resources"
/bin/cp "$BUNDLE_GUARD_BINARY_A" "$BUNDLE_GUARD_BUNDLE/Contents/MacOS/BundleGuard"
/usr/bin/printf '%s\n' \
  '<?xml version="1.0" encoding="UTF-8"?>' \
  '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">' \
  '<plist version="1.0"><dict>' \
  '<key>CFBundleExecutable</key><string>BundleGuard</string>' \
  '<key>CFBundleIdentifier</key><string>com.example.BundleGuard</string>' \
  '<key>CFBundlePackageType</key><string>APPL</string>' \
  '<key>CFBundleShortVersionString</key><string>1.0</string>' \
  '<key>CFBundleVersion</key><string>1</string>' \
  '</dict></plist>' >"$BUNDLE_GUARD_BUNDLE/Contents/Info.plist"
/usr/bin/printf 'payload resource\n' \
  >"$BUNDLE_GUARD_BUNDLE/Contents/Resources/payload.txt"
capture_release_bundle_payload_baseline "$BUNDLE_GUARD_BUNDLE"
BUNDLE_GUARD_BASELINE="$RELEASE_BUNDLE_PAYLOAD_SHA256"
/bin/cp "$BUNDLE_GUARD_BINARY_B" "$BUNDLE_GUARD_BUNDLE/Contents/MacOS/BundleGuard"
if verify_release_bundle_payload_baseline "$BUNDLE_GUARD_BUNDLE" >/dev/null 2>&1; then
  fail "different staged Mach-O payload was accepted by the signing baseline"
fi
/bin/cp "$BUNDLE_GUARD_BINARY_A" "$BUNDLE_GUARD_BUNDLE/Contents/MacOS/BundleGuard"
verify_release_bundle_payload_baseline "$BUNDLE_GUARD_BUNDLE"
/bin/ln "$BUNDLE_GUARD_BUNDLE/Contents/MacOS/BundleGuard" \
  "$BUNDLE_GUARD_BUNDLE/Contents/MacOS/BundleGuard.alias"
if verify_release_bundle_payload_baseline "$BUNDLE_GUARD_BUNDLE" >/dev/null 2>&1; then
  fail "hard-linked staged Mach-O payload was accepted by the signing baseline"
fi
/bin/rm -f -- "$BUNDLE_GUARD_BUNDLE/Contents/MacOS/BundleGuard.alias"
/usr/bin/codesign --force --sign - "$BUNDLE_GUARD_BUNDLE"
verify_release_bundle_payload_baseline "$BUNDLE_GUARD_BUNDLE"
[ "$(canonical_unsigned_macho_sha256 \
  "$BUNDLE_GUARD_BUNDLE/Contents/MacOS/BundleGuard")" = "$BUNDLE_GUARD_CANONICAL_A" ] \
  || fail "codesign changed executable bytes outside normalized signature metadata"
RELEASE_BUNDLE_PAYLOAD_SHA256=""
BINARY_NAME="$SAVED_BINARY_NAME"

[ "$(/usr/bin/head -n 1 "$ROOT_DIR/script/package_macos.sh")" = '#!/bin/bash -p' ] \
  || fail "macOS local packager does not enter privileged Bash through an absolute shebang"
[ -x "$ROOT_DIR/script/package_macos.sh" ] \
  || fail "macOS local packager is not directly executable through its protected shebang"
if ! /usr/bin/perl -0777 -e '
  my $text = <>;
  my $guard_start = index($text, q{if [ "${BASH_SOURCE[0]}" = "$0" ]; then});
  my $guard_end = index($text, "RELEASE_SNAPSHOT_REEXECUTED=false", $guard_start);
  exit 1 if $guard_start < 0 || $guard_end <= $guard_start;
  my $guard = substr($text, $guard_start, $guard_end - $guard_start);
  exit 1 if index($guard, q{--release|--release-diagnostics-artifact)}) < 0;
  exit 1 if index(
    $guard,
    q{Publishable macOS packaging is disabled in the local packager.}) < 0;
  exit 1 if index($guard, q{exit 1}) < 0;
  for my $post_guard_input (
    q{LOADED_PACKAGE_MACOS_SHA256="$(},
    q{LOADED_MACOS_BUNDLE_SHA256="$(},
    q{RELEASE_GIT_BIN="/Applications/Xcode.app/Contents/Developer/usr/bin/git"},
    q{CODESIGN_IDENTITY="${WAAL_CODESIGN_IDENTITY:-}"},
    q{NOTARY_PROFILE="${WAAL_NOTARY_PROFILE:-}"}) {
    my $position = index($text, $post_guard_input);
    exit 1 if $position < $guard_end;
  }
' "$ROOT_DIR/script/package_macos.sh"; then
  fail "publishable macOS entry points are not rejected before release-input resolution"
fi
/usr/bin/grep -Fq 'BUILD-INFO.txt' "$ROOT_DIR/script/package_macos.sh" \
  || fail "local signed macOS packaging does not include BUILD-INFO.txt"
if /usr/bin/grep -Fq 'BUILD-PROVENANCE.txt' "$ROOT_DIR/script/package_macos.sh"; then
  fail "local signed macOS packaging still claims a producer-attested provenance file"
fi
/usr/bin/grep -Fq 'source-git-commit={};source-git-tree={};' "$ROOT_DIR/build.rs" \
  || fail "build metadata does not embed both provenance fields"
/usr/bin/grep -Fq 'artifact-kind={};publishable={};attestation={};producer-attribution={};' \
  "$ROOT_DIR/build.rs" \
  || fail "build metadata does not encode publishability and producer-attestation status"
/usr/bin/grep -Fq 'require_canonical_release_metadata "$metadata"' \
  "$ROOT_DIR/script/package_macos.sh" \
  || fail "macOS packager does not require the exact unique build-metadata schema"
/usr/bin/grep -Fq '"none-local-shared-security-context"' "$ROOT_DIR/build.rs" \
  || fail "local build metadata does not disclaim attestation"
/usr/bin/grep -Fq '"unavailable-local-shared-security-context"' "$ROOT_DIR/build.rs" \
  || fail "local build metadata does not disclaim producer attribution"
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
/usr/bin/grep -Fq 'SYS_FCLONEFILEAT' "$ROOT_DIR/script/package_macos.sh" \
  || fail "macOS packager does not use descriptor-bound atomic clone publication"
/usr/bin/grep -Fq 'atomic no-replace publication clone' "$ROOT_DIR/script/package_macos.sh" \
  || fail "macOS packager does not make clone publication no-replace"
/usr/bin/grep -Fq 'verify_published_release_hash_evidence' "$ROOT_DIR/script/package_macos.sh" \
  || fail "macOS packager does not re-verify final ZIP hash evidence"
/usr/bin/grep -Fq 'repair_or_adopt_existing_release' "$ROOT_DIR/script/package_macos.sh" \
  || fail "macOS packager does not repair a verified archive-only publication"
for immutable_toolchain_contract in \
  'materialize_immutable_release_toolchain_snapshot' \
  '/bin/cp -cR -P "$original_rust_sysroot" "$rust_snapshot"' \
  'capture_release_toolchain_snapshot_baseline' \
  'guarded_tree_identity_sha256 "$RELEASE_TOOLCHAIN_SNAPSHOT_ROOT"' \
  'verify_release_toolchain_snapshot_guard' \
  'DEVELOPER_DIR="${RELEASE_BUILD_DEVELOPER_DIR:-$RELEASE_DEVELOPER_DIR}"'; do
  /usr/bin/grep -Fq "$immutable_toolchain_contract" "$ROOT_DIR/script/package_macos.sh" \
    || fail "macOS immutable build-toolchain contract changed: $immutable_toolchain_contract"
done
for bundle_signing_contract in \
  'canonical_unsigned_macho_sha256' \
  'release_bundle_payload_sha256' \
  'capture_release_bundle_payload_baseline "$STAGED_BUNDLE"' \
  'verify_release_bundle_payload_baseline "$bundle_dir"' \
  'substr($bytes, $signature_command + 12, 4, pack("V", 0))' \
  'pack("Q<", $unsigned_linkedit_vm_size)' \
  'pack("Q<", $unsigned_linkedit_size)'; do
  /usr/bin/grep -Fq "$bundle_signing_contract" "$ROOT_DIR/script/package_macos.sh" \
    || fail "macOS staged-bundle signing contract changed: $bundle_signing_contract"
done
if ! /usr/bin/perl -0777 -e '
  my $text = <>;
  my $cargo_start = index($text, "run_sanitized_release_cargo() {");
  my $cargo_end = index($text, "verify_release_dependency_graph() {", $cargo_start);
  exit 1 if $cargo_start < 0 || $cargo_end <= $cargo_start;
  my $cargo = substr($text, $cargo_start, $cargo_end - $cargo_start);
  my $first_guard = index($cargo, "verify_release_build_toolchain_guard");
  my $execute = index($cargo, q{"$RELEASE_CARGO_BIN" "$@"});
  my $second_guard = index($cargo, "verify_release_build_toolchain_guard", $first_guard + 1);
  exit 1 unless $first_guard >= 0 && $execute > $first_guard && $second_guard > $execute;

  my $main_start = index($text, "package_macos_main() {");
  exit 1 if $main_start < 0;
  my $main = substr($text, $main_start);
  my @main_order = (
    q{capture_release_bundle_payload_baseline "$STAGED_BUNDLE"},
    q{sign_release_bundle "$STAGED_BUNDLE"},
    q{notarize_and_staple_bundle "$STAGED_BUNDLE"},
    q{verify_release_bundle "$STAGED_BUNDLE"},
    q{sanitized_zip -r -X}
  );
  my $cursor = -1;
  for my $needle (@main_order) {
    my $next = index($main, $needle, $cursor + 1);
    exit 1 if $next < 0;
    $cursor = $next;
  }

  my $sign_start = index($text, "sign_release_bundle() {");
  my $sign_end = index($text, "notarize_and_staple_bundle() {", $sign_start);
  exit 1 if $sign_start < 0 || $sign_end <= $sign_start;
  my $sign = substr($text, $sign_start, $sign_end - $sign_start);
  my $sign_guard_before = index($sign, "verify_release_bundle_payload_baseline");
  my $codesign = index($sign, "/usr/bin/codesign");
  my $sign_guard_after = index($sign, "verify_release_bundle_payload_baseline", $sign_guard_before + 1);
  exit 1 unless $sign_guard_before >= 0 && $codesign > $sign_guard_before
    && $sign_guard_after > $codesign;
' "$ROOT_DIR/script/package_macos.sh"; then
  fail "macOS tool execution or bundle signing is no longer enclosed by exact guards"
fi
/usr/bin/grep -Fq 'package_script_base64="$(' "$ROOT_DIR/script/package_macos.sh" \
  || fail "macOS packager does not capture committed package logic into memory"
/usr/bin/grep -Fq 'bundle_script_base64="$(' "$ROOT_DIR/script/package_macos.sh" \
  || fail "macOS packager does not capture its committed bundle helper into memory"
/usr/bin/grep -Fq 'memory_package_oid="$(' "$ROOT_DIR/script/package_macos.sh" \
  || fail "macOS packager does not bind in-memory package logic to its Git blob"
/usr/bin/grep -Fq 'memory_bundle_oid="$(' "$ROOT_DIR/script/package_macos.sh" \
  || fail "macOS packager does not bind its in-memory helper to its Git blob"
for descriptor_contract in \
  'exec 8<"$package_descriptor_path"' \
  'exec 9<"$package_descriptor_path"' \
  'exec 7<"$bundle_descriptor_path"' \
  'exec 6<"$bundle_descriptor_path"' \
  '/bin/rm -f -- "$package_descriptor_path" "$bundle_descriptor_path"' \
  '/bin/bash --noprofile --norc -p -c' \
  'package_execution_identity="$(descriptor_identity /dev/fd/8)"' \
  'package_verification_identity="$(descriptor_identity /dev/fd/9)"' \
  'bundle_execution_identity="$(descriptor_identity /dev/fd/7)"' \
  'bundle_verification_identity="$(descriptor_identity /dev/fd/6)"' \
  '[ "$package_nlink" = 0 ] && [ "$bundle_nlink" = 0 ]' \
  'actual_package_sha256="$(' \
  'actual_bundle_sha256="$('; do
  /usr/bin/grep -Fq "$descriptor_contract" "$ROOT_DIR/script/package_macos.sh" \
    || fail "macOS committed-script descriptor contract changed: $descriptor_contract"
done
if ! /usr/bin/perl -0777 -e '
  my $text = <>;
  my $start = index($text, "reexecute_release_from_materialized_snapshot() {");
  my $end = index($text, "restore_and_verify_snapshot_execution() {", $start);
  exit 1 if $start < 0 || $end <= $start;
  my $reexec = substr($text, $start, $end - $start);
  exit 1 if index($reexec, q{local reexec_argument="--local-signed-release"}) < 0;
  exit 1 if $reexec =~ /reexec_argument="--release(?:-diagnostics-artifact)?"/;
  exit 1 if index($reexec, q{RELEASE_DIAGNOSTICS_ARTIFACT}) >= 0;
  exit 1 if index(
    $reexec,
    q{"$RELEASE_GIT_COMMIT" "$RELEASE_GIT_TREE" "$reexec_argument"}) < 0;
  my @ordered = (
    q{package_execution_identity="$(descriptor_identity /dev/fd/8)"},
    q{bundle_execution_identity="$(descriptor_identity /dev/fd/7)"},
    q{actual_package_sha256="$(},
    q{actual_bundle_sha256="$(},
    q{builtin source /dev/fd/8},
    q{exec 8<&- 9<&-},
    q{package_macos_main}
  );
  my $cursor = -1;
  for my $needle (@ordered) {
    my $next = index($reexec, $needle, $cursor + 1);
    exit 1 if $next < 0;
    $cursor = $next;
  }

  my $helper_start = index($text, "load_authenticated_bundle_helper() {");
  my $helper_end = index($text, "canonical_executable_path() {", $helper_start);
  exit 1 if $helper_start < 0 || $helper_end <= $helper_start;
  my $helper = substr($text, $helper_start, $helper_end - $helper_start);
  my @helper_ordered = (
    q{bundle_execution_identity="$(descriptor_identity /dev/fd/7)"},
    q{bundle_verification_identity="$(descriptor_identity /dev/fd/6)"},
    q{rewind helper descriptor before hashing},
    q{actual_bundle_sha256="$(},
    q{rewind helper descriptor:},
    q{actual_bundle_oid="$(},
    q{builtin source /dev/fd/7},
    q{exec 6<&- 7<&-}
  );
  $cursor = -1;
  for my $needle (@helper_ordered) {
    my $next = index($helper, $needle, $cursor + 1);
    exit 1 if $next < 0;
    $cursor = $next;
  }

  my $restore_start = index($text, "restore_and_verify_snapshot_execution() {");
  my $restore_end = index($text, "package_macos_main() {", $restore_start);
  exit 1 if $restore_start < 0 || $restore_end <= $restore_start;
  my $restore = substr($text, $restore_start, $restore_end - $restore_start);
  my @restore_ordered = (
    q{verify_loaded_packager_matches_snapshot},
    q{capture_release_provenance_for_root},
    q{load_authenticated_bundle_helper},
    q{capture_release_source_identity_baseline}
  );
  $cursor = -1;
  for my $needle (@restore_ordered) {
    my $next = index($restore, $needle, $cursor + 1);
    exit 1 if $next < 0;
    $cursor = $next;
  }
' "$ROOT_DIR/script/package_macos.sh"; then
  fail "macOS packager does not preserve local-only mode while authenticating package and helper descriptors"
fi
/usr/bin/grep -Fq -- '--internal-committed-snapshot' "$ROOT_DIR/script/package_macos.sh" \
  || fail "macOS packager does not enter an explicit committed-snapshot child mode"
/usr/bin/grep -Fq 'declare -F waal_assemble_app_bundle' "$ROOT_DIR/script/package_macos.sh" \
  || fail "macOS packager does not require the stream-preloaded committed bundle helper"
/usr/bin/grep -Fq 'capture_published_archive_snapshot' "$ROOT_DIR/script/package_macos.sh" \
  || fail "macOS packager does not verify orphan ZIPs through a private inode-bound snapshot"
/usr/bin/grep -Fq 'run_archive_session "$zip_path" extract "$extract_dir" "$expected_sha256" 7<"$zip_path"' \
  "$ROOT_DIR/script/package_macos.sh" \
  || fail "macOS packager does not bind validation and extraction to one archive descriptor"
/usr/bin/grep -Fq '/usr/bin/unzip -tq /dev/fd/0 <&7' \
  "$ROOT_DIR/script/package_macos.sh" \
  || fail "macOS packager does not CRC-test its bound archive descriptor"
/usr/bin/grep -Fq '/usr/bin/ditto -x -k /dev/fd/0 "$extract_dir" <&7' \
  "$ROOT_DIR/script/package_macos.sh" \
  || fail "macOS packager does not extract its bound archive descriptor"
for resource_contract in \
  '$size > 536_870_912' \
  '$entry_count > 16_384' \
  '$uncompressed_size > 536_870_912' \
  '$total_uncompressed > 1_073_741_824' \
  '($compressed_size * 200) + 1_048_576' \
  '$actual_size > 536_870_912' \
  '$actual_total_uncompressed > 1_073_741_824' \
  '$actual_size > ($compressed_size * 200) + 1_048_576' \
  '$actual_size != $declared_size' \
  '$actual_crc != $declared_crc' \
  '-LimitOutput => 1' \
  '$name_length > 1024' \
  'length($component) > 255' \
  '@components > 64'; do
  /usr/bin/grep -Fq -- "$resource_contract" "$ROOT_DIR/script/package_macos.sh" \
    || fail "macOS packager ZIP resource contract changed: $resource_contract"
done
DIRECT_ZIP_CALLS="$(
  /usr/bin/grep -Ec '/usr/bin/zip([[:space:]]|$)' "$ROOT_DIR/script/package_macos.sh"
)"
[ "$DIRECT_ZIP_CALLS" = 1 ] \
  || fail "macOS packager invokes /usr/bin/zip outside its single sanitized helper"
/usr/bin/grep -Fq '/usr/bin/env -i \' "$ROOT_DIR/script/package_macos.sh" \
  || fail "macOS packager does not construct sanitized process environments"
/usr/bin/grep -Fq '/usr/bin/zip "$@"' "$ROOT_DIR/script/package_macos.sh" \
  || fail "macOS packager ZIP helper does not forward only explicit arguments"
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
/usr/bin/grep -Fq 'Publishable Windows packaging is disabled in the local packager.' \
  "$ROOT_DIR/script/build_windows_dist.ps1" \
  || fail "Windows local packager does not fail closed for publishable builds"
/usr/bin/grep -Fq 'The development-only Windows packager rejects certificate and timestamp inputs.' \
  "$ROOT_DIR/script/build_windows_dist.ps1" \
  || fail "Windows development packager does not reject signing inputs"
if /usr/bin/grep -Fq 'Invoke-Checked $SignTool @(' "$ROOT_DIR/script/build_windows_dist.ps1"; then
  fail "Windows local packager still contains an executable signtool signing path"
fi
if /usr/bin/grep -Fq 'Get-AuthenticodeSignature' "$ROOT_DIR/script/build_windows_dist.ps1"; then
  fail "Windows local packager still accesses Authenticode certificate state"
fi
if /usr/bin/grep -Fq 'WAAL_PUBLISHABLE_RELEASE' "$ROOT_DIR/script/build_windows_dist.ps1"; then
  fail "Windows local packager still marks any locally built executable as publishable"
fi
/usr/bin/grep -Fq 'SHA256SUMS.txt' "$ROOT_DIR/script/build_windows_dist.ps1" \
  || fail "Windows packager does not publish a SHA-256 manifest"
/usr/bin/grep -Fq '$hashes["BUILD-METADATA.txt"]' "$ROOT_DIR/script/build_windows_dist.ps1" \
  || fail "Windows SHA-256 manifest does not cover BUILD-METADATA.txt"
/usr/bin/grep -Fq '"attestation=none-local-shared-security-context"' \
  "$ROOT_DIR/script/build_windows_dist.ps1" \
  || fail "Windows local build metadata does not disclaim attestation"
/usr/bin/grep -Fq '"producer-attribution=unavailable-local-shared-security-context"' \
  "$ROOT_DIR/script/build_windows_dist.ps1" \
  || fail "Windows local build metadata does not disclaim producer attribution"
if ! /usr/bin/perl -0777 -e '
  my $text = <>;
  my $parser_start = index($text, "function ConvertFrom-ExecutableBuildMetadata {");
  my $require_start = index($text, "function Require-MetadataField {", $parser_start);
  my $self_test_start = index(
    $text,
    "function Assert-ExecutableBuildMetadataValidationSelfTest {",
    $require_start);
  my $verify_start = index($text, "function Verify-ExecutableMetadataBytes {", $self_test_start);
  my $verify_end = index($text, "function Get-ByteArraySha256 {", $verify_start);
  exit 1 if $parser_start < 0 || $require_start <= $parser_start ||
    $self_test_start <= $require_start || $verify_start <= $self_test_start ||
    $verify_end <= $verify_start;

  my $parser = substr($text, $parser_start, $require_start - $parser_start);
  for my $needle (
    q{[Collections.Generic.Dictionary[string,string]]::new(},
    q{[Collections.Generic.HashSet[string]]::new(},
    q{[StringComparer]::Ordinal},
    q{$allowedFields.Contains($name)},
    q{Executable build metadata contains an unknown field},
    q{$fields.ContainsKey($name)},
    q{Executable build metadata contains a duplicate field}) {
    exit 1 if index($parser, $needle) < 0;
  }

  my $require = substr($text, $require_start, $self_test_start - $require_start);
  exit 1 if index($require, q{$Metadata.ContainsKey($Name)}) < 0;
  exit 1 if index(
    $require,
    q{[StringComparer]::Ordinal.Equals($Metadata[$Name], $Expected)}) < 0;
  exit 1 if $require =~ /\.Contains\(\s*";\$Name=/;

  my $self_test = substr($text, $self_test_start, $verify_start - $self_test_start);
  for my $needle (
    q{Assert-ExecutableBuildMetadataValidationSelfTest},
    q{publishable=true;},
    q{publishable=false;publishable=true;},
    q{attestation=authenticated-builder;},
    q{producer-attribution=authenticated-builder;},
    q{authenticated-producer=true;},
    q{Executable build metadata validation accepted an adversarial disclaimer marker.}) {
    exit 1 if index($self_test, $needle) < 0;
  }
  my $self_test_calls = () = $text =~ /^Assert-ExecutableBuildMetadataValidationSelfTest\s*$/mg;
  exit 1 if $self_test_calls != 1;

  my $verify = substr($text, $verify_start, $verify_end - $verify_start);
  for my $required (
    q{$metadata = ConvertFrom-ExecutableBuildMetadata $markers[0]},
    q{if ($metadata.Count -ne 27)},
    q{Require-MetadataField $metadata "publishable" "false"},
    q{Require-MetadataField $metadata "attestation" "none-local-shared-security-context"},
    q{Require-MetadataField $metadata "producer-attribution" "unavailable-local-shared-security-context"}) {
    exit 1 if index($verify, $required) < 0;
  }
  exit 0;
' "$ROOT_DIR/script/build_windows_dist.ps1"; then
  fail "Windows executable metadata validation does not reject missing, contradictory, or duplicate disclaimer fields"
fi
/usr/bin/grep -Fq '[IO.FileAttributes]::ReparsePoint' "$ROOT_DIR/script/build_windows_dist.ps1" \
  || fail "Windows packager does not reject reparse-point dist paths"
/usr/bin/grep -Fq 'Assert-CommitContainsOnlyRegularFiles' "$ROOT_DIR/script/build_windows_dist.ps1" \
  || fail "Windows packager does not reject committed links and gitlinks"
/usr/bin/grep -Fq '[switch]$Development' "$ROOT_DIR/script/build_windows_dist.ps1" \
  || fail "Windows packager does not expose an explicit non-production mode"
/usr/bin/grep -Fq '$executingPackagerSource = $MyInvocation.MyCommand.ScriptBlock.Ast.Extent.Text' \
  "$ROOT_DIR/script/build_windows_dist.ps1" \
  || fail "Windows packager does not capture the source already parsed into the clean child"
/usr/bin/grep -Fq '"-EncodedCommand"' "$ROOT_DIR/script/build_windows_dist.ps1" \
  || fail "Windows packager clean child does not use its deterministic encoded bootstrap"
/usr/bin/grep -Fq '$source = [Console]::In.ReadToEnd()' \
  "$ROOT_DIR/script/build_windows_dist.ps1" \
  || fail "Windows clean-shell bootstrap does not read the complete redirected source"
/usr/bin/grep -Fq '$scriptBlock = [System.Management.Automation.ScriptBlock]::Create($source)' \
  "$ROOT_DIR/script/build_windows_dist.ps1" \
  || fail "Windows clean-shell bootstrap does not parse one complete root ScriptBlock"
/usr/bin/grep -Fq '$childInputStream.Write($sourceBytes, 0, $sourceBytes.Length)' \
  "$ROOT_DIR/script/build_windows_dist.ps1" \
  || fail "Windows packager re-entry does not write exact ASCII bytes to the redirected stdin pipe"
/usr/bin/grep -Fq '$startInfo.WorkingDirectory = $RootDir' \
  "$ROOT_DIR/script/build_windows_dist.ps1" \
  || fail "Windows raw Git blob capture still depends on the caller working directory"
/usr/bin/grep -Fq '"-InternalRepositoryRoot", $RepositoryRoot' \
  "$ROOT_DIR/script/build_windows_dist.ps1" \
  || fail "Windows stream child does not receive an explicit physical repository root"
if /usr/bin/grep -Fq '"-File", $PSCommandPath' "$ROOT_DIR/script/build_windows_dist.ps1"; then
  fail "Windows packager still reopens a raceable script pathname for clean-shell execution"
fi
if /usr/bin/grep -Fq '"-File", "-"' "$ROOT_DIR/script/build_windows_dist.ps1"; then
  fail "Windows packager still uses statement-at-a-time PowerShell 5.1 stdin execution"
fi
/usr/bin/grep -Fq '"packager-source-sha256=$PackagerSourceSha256"' \
  "$ROOT_DIR/script/build_windows_dist.ps1" \
  || fail "Windows informational metadata does not record the loaded packager-source digest"
if ! /usr/bin/perl -0777 -e '
  my $text = <>;
  my $source_start = index($text, "function Resolve-AndVerify-SourceTools {");
  my $build_start = index($text, "function Resolve-AndVerify-Toolchain {");
  exit 1 if $source_start < 0 || $build_start <= $source_start;
  my $source_tools = substr($text, $source_start, $build_start - $source_start);
  exit 1 if $source_tools =~ /(?:Resolve-RustTool|Get-RustToolVersion|rustup|cargo|rustc|Compiler|Librarian|Linker|ResourceCompiler)/i;

  my $source_integrity_start = index($text, "function Assert-ReleaseSourceToolIntegrity {");
  my $build_integrity_start = index($text, "function Assert-ReleaseToolchainIntegrity {");
  exit 1 if $source_integrity_start < 0 || $build_integrity_start <= $source_integrity_start;
  my $source_integrity = substr(
    $text,
    $source_integrity_start,
    $build_integrity_start - $source_integrity_start
  );
  exit 1 if $source_integrity =~ /(?:Resolve-RustTool|Get-RustToolVersion|rustup|cargo|rustc|Compiler|Librarian|Linker|ResourceCompiler)/i;

  my @digest_contract = (
    q{$Source.IndexOf([char]0)},
    q{[int]$Source[$index] -gt 0x7f},
    q{$Source.Replace("`r`n", "`n").Replace("`r", "`n")},
    q{[Text.Encoding]::ASCII.GetBytes($canonicalSource)}
  );
  for my $needle (@digest_contract) {
    exit 1 if index($text, $needle) < 0;
  }

  my $bootstrap_start = index($text, q{$cleanShellArgumentPayloadName =});
  my $bootstrap_end = index($text, "function Test-OrdinalArgumentVector {", $bootstrap_start);
  exit 1 if $bootstrap_start < 0 || $bootstrap_end <= $bootstrap_start;
  my $bootstrap = substr($text, $bootstrap_start, $bootstrap_end - $bootstrap_start);
  my @bootstrap_contract = (
    q{$source = [Console]::In.ReadToEnd()},
    q{[System.Management.Automation.ScriptBlock]::Create($source)},
    q{& $scriptBlock @parameters},
    q{$utf8.GetBytes(($Arguments -join [char]0))},
    q{[Text.Encoding]::Unicode.GetBytes($cleanShellBootstrapSource)},
    q{"-EncodedCommand"}
  );
  for my $needle (@bootstrap_contract) {
    exit 1 if index($bootstrap, $needle) < 0;
  }
  exit 1 if index($bootstrap, q{"-File", "-"}) >= 0;
  exit 1 if $bootstrap =~ /\$PSCommandPath\s*(?:,|\))/;

  my $reentry_start = index($text, q!if (-not $cleanShellVerified) {!);
  my $reentry_end = index($text, q{# Do not leak the one-shot bootstrap capability}, $reentry_start);
  exit 1 if $reentry_start < 0 || $reentry_end <= $reentry_start;
  my $reentry = substr($text, $reentry_start, $reentry_end - $reentry_start);
  my @reentry_contract = (
    q{$startInfo.FileName = $enginePath},
    q{$startInfo.UseShellExecute = $false},
    q{$startInfo.RedirectStandardInput = $true},
    q{$startInfo.EnvironmentVariables[$cleanShellArgumentPayloadName] = $childArgumentPayload},
    q{$sourceBytes = [Text.Encoding]::ASCII.GetBytes($executingPackagerSource)},
    q{$childProcess.Start()},
    q{$childInputStream = $childProcess.StandardInput.BaseStream},
    q{$childInputStream.Write($sourceBytes, 0, $sourceBytes.Length)},
    q{$childInputStream.Flush()},
    q{$childInputStream.Close()},
    q{$childProcess.WaitForExit()},
    q{$childExitCode = $childProcess.ExitCode}
  );
  my $reentry_cursor = -1;
  for my $needle (@reentry_contract) {
    my $next = index($reentry, $needle, $reentry_cursor + 1);
    exit 1 if $next < 0;
    $reentry_cursor = $next;
  }
  exit 1 if $reentry =~ /\$executingPackagerSource\s*\|\s*&/;
  exit 1 if $reentry =~ /\$startInfo\.StandardInputEncoding\s*=/;

  my $attest_start = index($text, "function Assert-ExecutingPackagerMatchesReleaseCommit {");
  my $attest_end = index($text, "function Resolve-RustTool {", $attest_start);
  exit 1 if $attest_start < 0 || $attest_end <= $attest_start;
  my $attest = substr($text, $attest_start, $attest_end - $attest_start);
  my @attest_contract = (
    q{$relativePath = "script/build_windows_dist.ps1"},
    q{foreach ($entry in $ReleaseTreeEntries)},
    q{$snapshotBytes = Invoke-SanitizedGit @("cat-file", "blob", $matchingEntry.Blob) -RawBytes},
    q{Get-GitBlobSha1FromBytes $snapshotBytes},
    q{$snapshotSource = [Text.Encoding]::ASCII.GetString($snapshotBytes)},
    q{[System.Management.Automation.Language.Parser]::ParseInput(},
    q{Get-PackagerSourceSha256 $snapshotAst.Extent.Text},
    q{$snapshotSha256 -cne $ExecutingPackagerSourceSha256}
  );
  my $cursor = -1;
  for my $needle (@attest_contract) {
    my $next = index($attest, $needle, $cursor + 1);
    exit 1 if $next < 0;
    $cursor = $next;
  }
  my $attestation_name_count = () =
    $attest =~ /Assert-ExecutingPackagerMatchesReleaseCommit/g;
  exit 1 if $attestation_name_count != 1;
  exit 1 if $attest =~ /(?:Start-Process|PSCommandPath|powershell\.exe|pwsh\.exe)/i;

  my $main = index($text, q{$primaryFailure = $null});
  exit 1 if $main < 0;
  my $flow = substr($text, $main);
  my @flow_contract = (
    "Initialize-PreAttestationGitHome",
    "Resolve-AndVerify-SourceTools",
    q{$sourceState = Get-ReleaseSourceState $Git},
    "Get-CommittedReleaseTreeEntries \$Git",
    "Assert-ExecutingPackagerMatchesReleaseCommit",
    "Resolve-AndLock-CodeDomCompiler",
    q{$ReleaseRoot = New-ReleaseRoot},
    "Materialize-ReleaseSource \$Git \$Tar",
    "Resolve-AndVerify-Toolchain",
    "Invoke-SanitizedCargo"
  );
  $cursor = -1;
  for my $needle (@flow_contract) {
    my $next = index($flow, $needle, $cursor + 1);
    exit 1 if $next < 0;
    $cursor = $next;
  }
  my $attest_call = index($flow, "Assert-ExecutingPackagerMatchesReleaseCommit");
  my $codedom_call = index($flow, "Resolve-AndLock-CodeDomCompiler", $attest_call);
  my $new_root_call = index($flow, q{$ReleaseRoot = New-ReleaseRoot});
  exit 1 if $attest_call < 0 || $codedom_call <= $attest_call ||
    $new_root_call <= $codedom_call;
  my $pre_attestation_flow = substr($flow, 0, $attest_call);
  exit 1 if $pre_attestation_flow =~ /(?:Add-Type|Initialize-ReleaseTreeCleanup|New-ReleaseRoot)/;
  exit 0;
' "$ROOT_DIR/script/build_windows_dist.ps1"; then
  fail "Windows packager attestation is not a one-buffer commit binding before all Rust/build-tool resolution"
fi
for windows_handle_contract in \
  'NtCreateFile(' \
  'CreateTrackedRoot(' \
  '$script:ReleaseRootParentHandle = $handles[0]' \
  '$script:ReleaseRootHandle = $handles[1]' \
  '$script:ReleaseSourceHandle = [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::TrackRoot(' \
  'LockTrackedBuildOutputAfterBuild(' \
  'Copy-SingleLinkExecutableFromHandleAndCaptureBytes `' \
  'Copy-CommittedReleasePayloadFiles $stagedDist' \
  'Assert-StagedExecutableHandle $stagedExe' \
  'Lock-PublicationCandidateDirectory' \
  '$PublicationPayloadHandles = Open-DistributionPayloadHandles $PublicationCandidateHandle' \
  'Lock-DistributionPayloadHandlesAfterRename `' \
  'AssertTrackedRegularPath(' \
  'HashTrackedRegularSingleLinkSha256(' \
  'CopyTrackedRegularSingleLink(' \
  'CopyRegularSingleLinkAndCaptureBytes(' \
  'CopyTrackedRegularSingleLinkAndCaptureBytes(' \
  'Lock-SourceToolInputs' \
  'Resolve-AndLock-CodeDomCompiler' \
  'Assert-CodeDomCompilerIntegrity' \
  'Lock-ToolchainDirectories' \
  '$completeDistributionHashes = Get-CompleteDistributionFileHashes $stagedDist'; do
  /usr/bin/grep -Fq "$windows_handle_contract" \
    "$ROOT_DIR/script/build_windows_dist.ps1" \
    || fail "Windows handle-bound release contract changed: $windows_handle_contract"
done
if ! /usr/bin/perl -0777 -e '
  my $text = <>;
  my $open_start = index($text, "function Open-DistributionPayloadHandles {");
  my $open_end = index($text, "function Assert-DistributionPayloadHandles {", $open_start);
  exit 1 if $open_start < 0 || $open_end <= $open_start;
  my $open = substr($text, $open_start, $open_end - $open_start);
  exit 1 unless $open =~ /foreach\s*\(\$fileName\s+in\s+\@\(\s*
    \$ExeName\s*,\s*"README\.md"\s*,\s*"LICENSE"\s*,\s*"config\.example\.json"\s*,\s*
    "SHA256SUMS\.txt"\s*,\s*"BUILD-METADATA\.txt"\s*\)\s*\)/xms;
  my $open_count = () = $open =~ /OpenTrackedRegularSingleLinkForRename\s*\(/g;
  exit 1 if $open_count != 1;

  my $normalized = $text;
  $normalized =~ s/`\r?\n\s*/ /g;
  $normalized =~ s/\s+/ /g;
  my $candidate_assertions = () = $normalized =~ /
    Assert-DistributionPayloadHandles\s+
    \$PublicationCandidateHandle\s+
    \$PublicationPayloadHandles\s+
    \$completeDistributionHashes
  /gx;
  my $final_assertions = () = $normalized =~ /
    Assert-DistributionPayloadHandles\s+
    \$PublicationFinalHandle\s+
    \$PublicationPayloadHandles\s+
    \$completeDistributionHashes
  /gx;
  exit 1 if $candidate_assertions < 2 || $final_assertions < 2;

  my $cleanup_start = index($text, "function Remove-ReleaseRootSafely {");
  my $cleanup_end = index($text, "function Assert-CommitContainsOnlyRegularFiles {", $cleanup_start);
  exit 1 if $cleanup_start < 0 || $cleanup_end <= $cleanup_start;
  my $cleanup = substr($text, $cleanup_start, $cleanup_end - $cleanup_start);
  exit 1 unless $cleanup =~ /DeleteTrackedTree\s*\(\s*\$ReleaseRootHandle\s*\)/ms;
  exit 1 if index($cleanup, q{$ReleaseRootParentHandle.Dispose()}) < 0;
  my $source_assert = index($cleanup, q{AssertPhysicalDirectory(});
  my $source_dispose = index($cleanup, q{$ReleaseSourceHandle.Dispose()}, $source_assert);
  my $root_delete = index($cleanup, q{DeleteTrackedTree(}, $source_dispose);
  exit 1 if $source_assert < 0 || $source_dispose <= $source_assert ||
    $root_delete <= $source_dispose;
  exit 1 if index($cleanup, "finally {", $source_assert) < 0;

  my $cargo_start = index($text, "function Invoke-SanitizedCargo {");
  my $cargo_end = index($text, "function Write-Utf8NoBom {", $cargo_start);
  exit 1 if $cargo_start < 0 || $cargo_end <= $cargo_start;
  my $cargo = substr($text, $cargo_start, $cargo_end - $cargo_start);
  exit 1 if index($cargo, q{Open-MaterializedReleaseSourceHandles}) < 0;
  exit 1 if index($cargo, q{Assert-AndCloseMaterializedReleaseSourceHandles}) < 0;
  my $cargo_invoke = index($cargo, q{Invoke-Checked $Cargo $Arguments});
  my $cargo_output_lock = index($cargo, q{LockTrackedBuildOutputAfterBuild(}, $cargo_invoke);
  exit 1 if $cargo_invoke < 0 || $cargo_output_lock <= $cargo_invoke;

  my $source_open_start = index($text, "function Open-MaterializedReleaseSourceHandles {");
  my $source_assert_start = index(
    $text,
    "function Assert-MaterializedReleaseSourceHandleState {",
    $source_open_start);
  my $source_close_start = index(
    $text,
    "function Assert-AndCloseMaterializedReleaseSourceHandles {",
    $source_assert_start);
  my $materialize_start = index($text, "function Materialize-ReleaseSource {", $source_close_start);
  exit 1 if $source_open_start < 0 || $source_assert_start <= $source_open_start ||
    $source_close_start <= $source_assert_start || $materialize_start <= $source_close_start;
  my $source_open = substr(
    $text,
    $source_open_start,
    $source_assert_start - $source_open_start);
  my $source_assert = substr(
    $text,
    $source_assert_start,
    $source_close_start - $source_assert_start);
  my $source_close = substr(
    $text,
    $source_close_start,
    $materialize_start - $source_close_start);
  for my $needle (
    q{RelativePath = $entry.Path},
    q{ExpectedBlob = $entry.Blob},
    q{Assert-MaterializedReleaseSourceHandleState $result}) {
    exit 1 if index($source_open, $needle) < 0;
  }
  for my $needle (
    q{$expectedFiles.Add($entry.Path, $entry.Blob)},
    q{AssertTrackedDirectoryPath(},
    q{AssertTrackedRegularPath(},
    q{HashTrackedRegularSingleLinkGitBlobSha1(},
    q{if ($handleBlob -cne $expectedFiles[$relativePath])},
    q{Assert-MaterializedReleaseSource}) {
    exit 1 if index($source_assert, $needle) < 0;
  }
  my $post_cargo_assert = index(
    $source_close,
    q{Assert-MaterializedReleaseSourceHandleState $Handles});
  my $first_source_dispose = index($source_close, q{$state.Handle.Dispose()});
  exit 1 if $post_cargo_assert < 0 || $first_source_dispose <= $post_cargo_assert;

  my $tracked_blob_start = index(
    $text,
    "public static string HashTrackedRegularSingleLinkGitBlobSha1(");
  my $tracked_blob_end = index(
    $text,
    "public static void AssertPhysicalDirectory(",
    $tracked_blob_start);
  exit 1 if $tracked_blob_start < 0 || $tracked_blob_end <= $tracked_blob_start;
  my $tracked_blob = substr(
    $text,
    $tracked_blob_start,
    $tracked_blob_end - $tracked_blob_start);
  for my $needle (
    q{DuplicateHandle(},
    q{"blob " + before.FileSize + "\0"},
    q{EnsureStableSingleLinkFile(before, after, "tracked Git-blob input")}) {
    exit 1 if index($tracked_blob, $needle) < 0;
  }

  my $lock_build_start = index(
    $text,
    "public static SafeFileHandle LockTrackedBuildOutputAfterBuild(");
  my $regular_assert_start = index(
    $text,
    "public static void AssertRegularSingleLink(",
    $lock_build_start);
  exit 1 if $lock_build_start < 0 || $regular_assert_start <= $lock_build_start;
  my $lock_build = substr(
    $text,
    $lock_build_start,
    $regular_assert_start - $lock_build_start);
  exit 1 if $text =~ /
    CreateTrackedBuildOutput|
    BuiltExecutableConstructionHandle|
    RetainBuiltExecutableConstructionHandle|
    ConstructionHandleTransferred
  /x;
  for my $needle (
    q{Identity directoryBefore = GetIdentity(},
    q{OpenChildNoFollow(},
    q{GenericRead | FileReadAttributes | Synchronize},
    q{FileShareRead},
    q{output.FileSize == 0},
    q{directoryBefore.SameObjectAndKind(directoryAfter)},
    q{Build-output directory changed while locking the completed child.}) {
    exit 1 if index($lock_build, $needle) < 0;
  }
  exit 1 if index($lock_build, q{FileShareWrite}) >= 0 ||
    index($lock_build, q{FileShareDelete}) >= 0;

  my $tracked_copy_start = index(
    $text,
    "private static byte[] CopyTrackedRegularSingleLinkCore(");
  my $tracked_copy_end = index(
    $text,
    "public static void DeleteTrackedTree(",
    $tracked_copy_start);
  exit 1 if $tracked_copy_start < 0 || $tracked_copy_end <= $tracked_copy_start;
  my $tracked_copy = substr(
    $text,
    $tracked_copy_start,
    $tracked_copy_end - $tracked_copy_start);
  for my $needle (
    q{DuplicateHandle(},
    q{sourceStream.CopyTo(destinationStream)},
    q{destinationStream.Flush(true)},
    q{Identity destinationWritten = GetIdentity(},
    q{EnsureSameSingleLinkFileIdentity(},
    q{destinationWritten.FileSize != sourceBefore.FileSize},
    q{EnsureStableSingleLinkFile(sourceBefore, sourceAfter, "tracked copy source")},
    q{EnsureStableSingleLinkFile(destinationWritten, destinationAfter, "copy destination")},
    q{destinationWritten,},
    q{ConstantTimeEquals(sourceDigest, destinationDigest)},
    q{sourceStream.Position = 0}) {
    exit 1 if index($tracked_copy, $needle) < 0;
  }
  my $destination_flush = index($tracked_copy, q{destinationStream.Flush(true)});
  my $destination_snapshot = index(
    $tracked_copy,
    q{Identity destinationWritten = GetIdentity(},
    $destination_flush);
  my $destination_hash = index(
    $tracked_copy,
    q{byte[] destinationDigest = destinationSha256.ComputeHash(destinationStream)},
    $destination_snapshot);
  exit 1 if $destination_flush < 0 || $destination_snapshot <= $destination_flush ||
    $destination_hash <= $destination_snapshot;
  exit 1 if $tracked_copy =~ /EnsureStableSingleLinkFile\s*\(\s*
    destinationCreated\s*,/xms;
  my $same_identity_start = index(
    $text,
    "private static void EnsureSameSingleLinkFileIdentity(");
  my $constant_time_start = index(
    $text,
    "private static bool ConstantTimeEquals(",
    $same_identity_start);
  exit 1 if $same_identity_start < 0 || $constant_time_start <= $same_identity_start;
  my $same_identity = substr(
    $text,
    $same_identity_start,
    $constant_time_start - $same_identity_start);
  for my $needle (
    q{before.SameObjectAndKind(after)},
    q{before.NumberOfLinks != 1},
    q{after.NumberOfLinks != 1}) {
    exit 1 if index($same_identity, $needle) < 0;
  }
  exit 1 if index($same_identity, q{FileSize}) >= 0;

  # Deterministic share-mode adversary contract: Cargo owns destination
  # creation/replacement while it runs. The exact post-build child is then
  # opened relative to the retained directory without write/delete sharing;
  # staged committed payload handles use the same no-mutation boundary.
  exit 1 if $lock_build =~ /FileShareWrite|FileShareDelete/;

  my $committed_copy_start = index(
    $text,
    "function Copy-CommittedReleasePayloadFiles {");
  my $committed_assert_start = index(
    $text,
    "function Assert-CommittedReleasePayloadHashes {",
    $committed_copy_start);
  my $committed_copy_end = index(
    $text,
    "function Materialize-ReleaseSource {",
    $committed_assert_start);
  exit 1 if $committed_copy_start < 0 ||
    $committed_assert_start <= $committed_copy_start ||
    $committed_copy_end <= $committed_assert_start;
  my $committed_copy = substr(
    $text,
    $committed_copy_start,
    $committed_assert_start - $committed_copy_start);
  my $committed_assert = substr(
    $text,
    $committed_assert_start,
    $committed_copy_end - $committed_assert_start);
  exit 1 unless $committed_copy =~ /\$fileNames\s*=\s*\@\(
    "README\.md"\s*,\s*"LICENSE"\s*,\s*"config\.example\.json"\s*\)/xms;
  for my $needle (
    q{"cat-file", "blob", ([string]$matches[0].Blob)},
    q{Get-GitBlobSha1FromBytes $committedBytes},
    q{OpenRegularSingleLink(},
    q{HashTrackedRegularSingleLinkGitBlobSha1(},
    q{HashTrackedRegularSingleLinkSha256(},
    q{Copy-SingleLinkFileFromHandle $state.Handle $destinationPath},
    q{Handle = $destinationHandle},
    q{$expectedHashes[$fileName] = $state.ExpectedSha256}) {
    exit 1 if index($committed_copy, $needle) < 0;
  }
  my $staged_assert_start = index(
    $text,
    "function Assert-StagedPayloadHandles {",
    $committed_assert_start);
  my $staged_close_start = index(
    $text,
    "function Close-StagedPayloadHandles {",
    $staged_assert_start);
  exit 1 if $staged_assert_start < 0 || $staged_close_start <= $staged_assert_start;
  my $staged_assert = substr(
    $text,
    $staged_assert_start,
    $staged_close_start - $staged_assert_start);
  for my $needle (
    q{AssertTrackedRegularPath(},
    q{HashTrackedRegularSingleLinkSha256(},
    q{$handleHash -cne $ExpectedHashes[$state.Name]}) {
    exit 1 if index($staged_assert, $needle) < 0;
  }
  for my $needle (
    q{$ActualHashes[$fileName] -cne $ExpectedHashes[$fileName]},
    q{captured commit ${ReleaseGitCommit}}) {
    exit 1 if index($committed_assert, $needle) < 0;
  }

  my $main_start = index($text, q{$primaryFailure = $null});
  exit 1 if $main_start < 0;
  my $main = substr($text, $main_start);
  my @build_flow = (
    q{$BuiltExecutableDirectoryHandle = [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::TrackRoot(},
    q{$targetExe = Microsoft.PowerShell.Management\Join-Path `},
    q{$builtExecutableState = Invoke-SanitizedCargo @(},
    q{-RetainBuiltExecutableDirectoryHandle $BuiltExecutableDirectoryHandle},
    q{$BuiltExecutableHandle = $builtExecutableState.Handle},
    q{Copy-SingleLinkExecutableFromHandleAndCaptureBytes `},
    q{Verify-ExecutableMetadataBytes $UnsignedExecutableBytes},
    q{HashTrackedRegularSingleLinkSha256(},
    q{$committedPayloadState = Copy-CommittedReleasePayloadFiles $stagedDist},
    q{$StagedPayloadHandles = @($committedPayloadState.Handles)},
    q{$StagedExecutableHandle = [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::OpenRegularSingleLink(},
    q{Assert-StagedExecutableHandle $stagedExe},
    q{Close-BuiltExecutableHandles},
    q{Assert-StagedPayloadHandles $stagedDist $StagedPayloadHandles $CommittedPayloadHashes},
    q{Assert-CommittedReleasePayloadHashes $corePayloadHashes $CommittedPayloadHashes}
  );
  my $build_cursor = -1;
  for my $needle (@build_flow) {
    my $next = index($main, $needle, $build_cursor + 1);
    exit 1 if $next < 0;
    $build_cursor = $next;
  }
  exit 1 if index(
    $main,
    q{Copy-SingleLinkExecutableAndCaptureBytes $targetExe $stagedExe}) >= 0;
  my $copy_exe = index(
    $main,
    q{Copy-SingleLinkExecutableFromHandleAndCaptureBytes `});
  my $retain_staged_exe = index(
    $main,
    q{$StagedExecutableHandle = [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::OpenRegularSingleLink(},
    $copy_exe);
  my $assert_staged_exe = index(
    $main,
    q{Assert-StagedExecutableHandle $stagedExe},
    $retain_staged_exe);
  my $close_exe = index($main, q{Close-BuiltExecutableHandles}, $assert_staged_exe);
  exit 1 if $copy_exe < 0 ||
    $retain_staged_exe <= $copy_exe || $assert_staged_exe <= $retain_staged_exe ||
    $close_exe <= $assert_staged_exe;
  exit 1 if index($main, q{Sign-AndVerify-Executable}) >= 0 ||
    index($main, q{Assert-AuthenticodeExecutable}) >= 0;
  my $copy_docs = index($main, q{$committedPayloadState = Copy-CommittedReleasePayloadFiles $stagedDist});
  my $candidate_docs = index($main, q{Copy-SingleLinkFile `}, $copy_docs);
  my $assert_staged_docs = index(
    $main,
    q{Assert-StagedPayloadHandles $stagedDist $StagedPayloadHandles $CommittedPayloadHashes},
    $candidate_docs);
  my $close_staged_docs = index($main, q{Close-StagedPayloadHandles}, $assert_staged_docs);
  my $assert_candidate_exe = index(
    $main,
    q{Assert-StagedExecutableHandle $stagedExe},
    $candidate_docs);
  my $close_staged_exe = index(
    $main,
    q{Close-StagedExecutableHandle},
    $assert_candidate_exe);
  exit 1 if $copy_docs < 0 || $candidate_docs <= $copy_docs ||
    $assert_candidate_exe <= $candidate_docs || $close_staged_exe <= $assert_candidate_exe ||
    $assert_staged_docs <= $candidate_docs || $close_staged_docs <= $assert_staged_docs;
  exit 1 if $main =~ /foreach\s*\(\$fileName\s+in\s+\@\(
    "README\.md"\s*,\s*"LICENSE"\s*,\s*"config\.example\.json"\s*\)\s*\)\s*\{
    \s*Copy-SingleLinkFile/xms;

  my $child_start = index($text, "public static void AssertTrackedChild(");
  my $child_end = index($text, "public static byte[] ReadRegularSingleLinkBytes(", $child_start);
  exit 1 if $child_start < 0 || $child_end <= $child_start;
  my $child = substr($text, $child_start, $child_end - $child_start);
  exit 1 unless $child =~ /OpenChildNoFollow\s*\(\s*
    directory\s*,\s*leafName\s*,\s*
    FileReadAttributes\s*\|\s*Synchronize\s*,\s*
    FileShareRead\s*\|\s*FileShareWrite\s*\|\s*FileShareDelete\s*
  \)/xms;

  my $root_start = index($text, "function New-ReleaseRoot {");
  my $root_end = index($text, "function Remove-ReleaseRootSafely {", $root_start);
  exit 1 if $root_start < 0 || $root_end <= $root_start;
  my $root = substr($text, $root_start, $root_end - $root_start);
  exit 1 unless $root =~ /\.compiler-anchor.*?\[IO\.FileAccess\]::ReadWrite\s*,\s*
    \s*\[IO\.FileShare\]::Read/xms;
  exit 1 if $root =~ /\.compiler-anchor.*?\[IO\.FileShare\]::None/xms;
  for my $needle (
    q![IO.FileOptions]::DeleteOnClose!,
    q!if ($compilerSentinel) {!,
    q!"Unable to close cleanup compiler sentinel:!,
    q!("Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner" -as [type])!,
    q!$compilerDirectoryHandle = [Obcardinal.WindowsAppAutoLogin.ReleaseTreeCleaner]::TrackRoot(!,
    q![IO.Directory]::Delete($compilerTemp, $false)!,
    q!"Leaving non-empty unverified cleanup compiler directory in place:!) {
    exit 1 if index($root, $needle) < 0;
  }

  my $complete_start = index($text, "function Complete-DevelopmentPublication {");
  my $complete_end = index($text, "function Stop-DistProcesses {", $complete_start);
  exit 1 if $complete_start < 0 || $complete_end <= $complete_start;
  my $complete = substr($text, $complete_start, $complete_end - $complete_start);
  my $final_enumeration = index(
    $complete,
    q{Assert-WindowsDistribution $Directory $ExpectedPayloadHashes $ExpectedMetadata});
  my $complete_flag = index($complete, q{$script:PublicationComplete = $true});
  exit 1 if $final_enumeration < 0 || $complete_flag <= $final_enumeration;
  exit 1 if index($complete, q{mutable, non-attested development output}) < 0;
' "$ROOT_DIR/script/build_windows_dist.ps1"; then
  fail "Windows packager no longer holds exact single-link source and six-file publication handles"
fi
for forbidden_git_input in \
  GIT_ALLOW_PROTOCOL \
  GIT_CONFIG_PARAMETERS \
  SSH_ \
  HTTP_PROXY \
  BASH_ENV; do
  /usr/bin/grep -Fq "$forbidden_git_input" "$ROOT_DIR/script/build_windows_dist.ps1" \
    || fail "Windows pre-attestation Git environment does not cover $forbidden_git_input"
done
/usr/bin/grep -Fq 'GIT_PROTOCOL_FROM_USER = "0"' "$ROOT_DIR/script/build_windows_dist.ps1" \
  || fail "Windows Git invocation does not disable user-requested protocols"
/usr/bin/grep -Fq 'TAR_OPTIONS$' "$ROOT_DIR/script/build_windows_dist.ps1" \
  || fail "Windows source extraction does not sanitize inherited tar options"
if ! /usr/bin/perl -0777 -e '
  my $text = <>;

  my $tree_start = index($text, "function Open-DirectoryTreeReadLocks {");
  my $tree_end = index($text, "function Get-OrderedHashAggregate {", $tree_start);
  exit 1 if $tree_start < 0 || $tree_end <= $tree_start;
  my $tree = substr($text, $tree_start, $tree_end - $tree_start);
  my @tree_contract = (
    q{[IO.FileShare]::Read},
    q{Get-LockedFileSha256 $entry.Stream},
    q{AssertRegularSingleLink(},
    q{AssertTrackedRegularPath(},
    q{($expectedPaths -join "`n") -cne ($currentPaths -join "`n")}
  );
  for my $needle (@tree_contract) {
    exit 1 if index($tree, $needle) < 0;
  }
  exit 1 if $tree =~ /LastWriteTimeUtc|Get-Sha256\s+\$filePath/;

  my $source_lock = index($text, "function Lock-SourceToolInputs {");
  my $source_assert = index($text, "function Assert-SourceToolLocks {", $source_lock);
  my $codedom_lock = index($text, "function Resolve-AndLock-CodeDomCompiler {", $source_assert);
  my $codedom_assert = index($text, "function Assert-CodeDomCompilerIntegrity {", $codedom_lock);
  my $tool_lock = index($text, "function Lock-ToolchainDirectories {", $codedom_assert);
  my $close_lock = index($text, "function Close-AllReleaseInputLocks {", $tool_lock);
  exit 1 if $source_lock < 0 || $source_assert <= $source_lock ||
    $codedom_lock <= $source_assert || $codedom_assert <= $codedom_lock ||
    $tool_lock <= $codedom_assert || $close_lock <= $tool_lock;

  exit 1 if $text =~ /function\s+(?:Sign-AndVerify-Executable|Assert-AuthenticodeExecutable)\b/;
  exit 1 if $text =~ /Invoke-Checked\s+\$SignTool\s+\@\(/;
  my $guard = index(
    $text,
    q{Publishable Windows packaging is disabled in the local packager.});
  my $source_capture = index(
    $text,
    q{$executingPackagerSource = $MyInvocation.MyCommand.ScriptBlock.Ast.Extent.Text});
  my $engine_resolution = index(
    $text,
    q{$enginePath = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName});
  my $child_start = index($text, q{if (-not $childProcess.Start())});
  exit 1 if $guard < 0 || $source_capture <= $guard ||
    $engine_resolution <= $guard || $child_start <= $guard;

  my $publish_start = index($text, "function Assert-DistributionPayloadHandles {");
  my $publish_end = index($text, "function Close-DistributionPayloadHandles {", $publish_start);
  exit 1 if $publish_start < 0 || $publish_end <= $publish_start;
  my $publish = substr($text, $publish_start, $publish_end - $publish_start);
  exit 1 if index($publish, q{$Handles.Count -ne $expectedNames.Count}) < 0;
  exit 1 if index($publish, q{HashTrackedRegularSingleLinkSha256(}) < 0;
  exit 1 if index($publish, q{$handleHash -cne $ExpectedFileHashes[$state.Name]}) < 0;

  my $hash_start = index($text, "public static string HashTrackedRegularSingleLinkSha256(");
  my $hash_end = index($text, "public static void AssertPhysicalDirectory(", $hash_start);
  exit 1 if $hash_start < 0 || $hash_end <= $hash_start;
  my $hash = substr($text, $hash_start, $hash_end - $hash_start);
  my $rewinds = () = $hash =~ /stream\.Position\s*=\s*0\s*;/g;
  exit 1 if $rewinds < 2;
' "$ROOT_DIR/script/build_windows_dist.ps1"; then
  fail "Windows local-only guard, non-write-sharing tree, or publication identity contract changed"
fi
if /usr/bin/grep -Fq 'WAAL_WINDOWS_SIGNTOOL' "$ROOT_DIR/script/build_windows_dist.ps1"; then
  fail "Windows packager still accepts an arbitrary late signtool override"
fi
for pin_name in \
  WAAL_WINDOWS_RELEASE_EXPECTED_GIT_SHA256 \
  WAAL_WINDOWS_RELEASE_EXPECTED_GIT_ROOT_SHA256 \
  WAAL_WINDOWS_RELEASE_EXPECTED_TAR_SHA256 \
  WAAL_WINDOWS_RELEASE_EXPECTED_CODEDOM_CSC_SHA256 \
  WAAL_WINDOWS_RELEASE_EXPECTED_CODEDOM_RUNTIME_SHA256 \
  WAAL_RELEASE_EXPECTED_CARGO_SHA256 \
  WAAL_RELEASE_EXPECTED_RUSTC_SHA256 \
  WAAL_RELEASE_EXPECTED_RUST_SYSROOT_SHA256 \
  WAAL_WINDOWS_RELEASE_EXPECTED_CL_SHA256 \
  WAAL_WINDOWS_RELEASE_EXPECTED_LIB_EXE_SHA256 \
  WAAL_WINDOWS_RELEASE_EXPECTED_LINK_SHA256 \
  WAAL_WINDOWS_RELEASE_EXPECTED_MSVC_BIN_SHA256 \
  WAAL_WINDOWS_RELEASE_EXPECTED_RC_SHA256 \
  WAAL_WINDOWS_RELEASE_EXPECTED_SDK_BIN_SHA256 \
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
if ! /usr/bin/perl -0777 -e '
  my $text = <>;
  exit($text =~ /\$script:ReleaseMaterialsSha256\s*=\s*Get-OrderedHashAggregate\s*\@\(\s*
    \$PackagerSourceSha256,\s*\$GitSha256,\s*\$GitRootSha256,\s*\$TarSha256,\s*
    \$CodeDomCompilerSha256,\s*\$CodeDomRuntimeSha256,\s*\$CargoSha256,\s*
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
/usr/bin/grep -Fq \
  'WAAL_PUBLISHABLE_RELEASE is disabled: source-controlled build metadata cannot authenticate its own producer' \
  "$ROOT_DIR/build.rs" \
  || fail "build metadata still permits caller-selected publishability"
if /usr/bin/grep -Eq \
  'attestation=(external|authenticated)|producer-attribution=(available|authenticated)' \
  "$ROOT_DIR/build.rs"; then
  fail "build.rs still embeds a self-asserted producer attestation"
fi

echo "release provenance tests passed"
