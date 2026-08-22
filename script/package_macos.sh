#!/bin/bash -p
set -euo pipefail
# Release packaging never searches a user-controlled HOME for executables.
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

# A process running as the current user cannot prove that another same-user
# process did not replace Cargo output before Developer ID signing. Refuse the
# old publishable entry points before resolving Git, Cargo, signing identities,
# or notarization credentials. The local signed mode below is intentionally
# non-publishable and disclaims producer attribution in both embedded and
# signed bundle metadata.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  case "${1:-}" in
    --release|--release-diagnostics-artifact)
      echo "Publishable macOS packaging is disabled in the local packager. Use an isolated authenticated builder; use --local-signed-release only for an explicitly non-publishable local artifact." >&2
      exit 1
      ;;
    --local-signed-release)
      if [ "$#" -ne 1 ]; then
        echo "Usage: script/package_macos.sh --local-signed-release" >&2
        exit 2
      fi
      ;;
    *)
      echo "Usage: script/package_macos.sh --local-signed-release" >&2
      exit 2
      ;;
  esac
fi

RELEASE_SNAPSHOT_REEXECUTED=false
if [ "${1:-}" = --internal-committed-snapshot ]; then
  RELEASE_SNAPSHOT_REEXECUTED=true
  shift
  if [ "$#" -ne 13 ]; then
    echo "Invalid argument count for committed macOS release execution." >&2
    exit 1
  fi
  EXECUTION_SOURCE_ROOT="$1"
  ROOT_DIR="$2"
  LOADED_PACKAGE_MACOS_SHA256="$3"
  LOADED_MACOS_BUNDLE_SHA256="$4"
  LOADED_PACKAGE_MACOS_OID="$5"
  LOADED_MACOS_BUNDLE_OID="$6"
  INHERITED_RELEASE_PRIVATE_ROOT="$7"
  INHERITED_RELEASE_PRIVATE_ROOT_PARENT="$8"
  INHERITED_RELEASE_PRIVATE_ROOT_ID="$9"
  shift 9
  INHERITED_RELEASE_PRIVATE_ROOT_PARENT_ID="$1"
  shift
  INHERITED_RELEASE_GIT_COMMIT="$1"
  shift
  INHERITED_RELEASE_GIT_TREE="$1"
  shift
  REEXEC_RELEASE_ARGUMENT="$1"
  shift
  PACKAGE_MACOS_SOURCE_PATH="${BASH_SOURCE[0]}"
  case "$ROOT_DIR:$EXECUTION_SOURCE_ROOT:$PACKAGE_MACOS_SOURCE_PATH:$REEXEC_RELEASE_ARGUMENT" in
    /*:/*:/dev/fd/8:--local-signed-release) ;;
    *) echo "Invalid paths for macOS release snapshot execution." >&2; exit 1 ;;
  esac
  # Do not interpret the helper yet. Its FD is authenticated against the
  # captured commit inside restore_and_verify_snapshot_execution before any
  # waal_* function can run.
  set -- "$REEXEC_RELEASE_ARGUMENT"
else
  EXECUTION_SOURCE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && /bin/pwd -P)"
  ROOT_DIR="$EXECUTION_SOURCE_ROOT"
  PACKAGE_MACOS_SOURCE_PATH="$EXECUTION_SOURCE_ROOT/script/package_macos.sh"
  MACOS_BUNDLE_SOURCE_PATH="$EXECUTION_SOURCE_ROOT/script/macos_bundle.sh"
  LOADED_PACKAGE_MACOS_SHA256="$(
    /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin \
      /usr/bin/shasum -a 256 "$PACKAGE_MACOS_SOURCE_PATH" \
      | /usr/bin/awk '{ print $1; exit }'
  )"
  LOADED_MACOS_BUNDLE_SHA256="$(
    /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin \
      /usr/bin/shasum -a 256 "$MACOS_BUNDLE_SOURCE_PATH" \
      | /usr/bin/awk '{ print $1; exit }'
  )"
  if [ -L "$PACKAGE_MACOS_SOURCE_PATH" ] || [ ! -f "$PACKAGE_MACOS_SOURCE_PATH" ] \
    || [ -L "$MACOS_BUNDLE_SOURCE_PATH" ] || [ ! -f "$MACOS_BUNDLE_SOURCE_PATH" ]; then
    echo "macOS release scripts must be regular files in the physical checkout." >&2
    exit 1
  fi
  INHERITED_RELEASE_PRIVATE_ROOT=""
  INHERITED_RELEASE_PRIVATE_ROOT_PARENT=""
  INHERITED_RELEASE_PRIVATE_ROOT_ID=""
  INHERITED_RELEASE_PRIVATE_ROOT_PARENT_ID=""
  INHERITED_RELEASE_GIT_COMMIT=""
  INHERITED_RELEASE_GIT_TREE=""
  LOADED_PACKAGE_MACOS_OID=""
  LOADED_MACOS_BUNDLE_OID=""
  # Sourced test/library use may load helper functions. A release-capable direct
  # invocation never executes the mutable worktree helper before provenance is
  # captured and committed bytes are moved into the anonymous child stream.
  if [ "${BASH_SOURCE[0]}" != "$0" ]; then
    # shellcheck source=script/macos_bundle.sh
    source "$MACOS_BUNDLE_SOURCE_PATH"
  fi
fi
# The release-capable invocation is re-executed from a materialized Git tree.
# These digests then attest that its package and already-sourced bundle helper
# are still the exact files in that private snapshot.
if [ "${#LOADED_PACKAGE_MACOS_SHA256}" -ne 64 ] \
  || [ "${#LOADED_MACOS_BUNDLE_SHA256}" -ne 64 ]; then
  echo "Invalid macOS release-script digests." >&2
  exit 1
fi
case "$LOADED_PACKAGE_MACOS_SHA256$LOADED_MACOS_BUNDLE_SHA256" in
  *[!0-9a-f]*) echo "Invalid macOS release-script digests." >&2; exit 1 ;;
esac
readonly LOADED_PACKAGE_MACOS_SHA256
readonly LOADED_MACOS_BUNDLE_SHA256
if [ "$RELEASE_SNAPSHOT_REEXECUTED" = true ]; then
  valid_git_object_id_bootstrap_value="$LOADED_PACKAGE_MACOS_OID$LOADED_MACOS_BUNDLE_OID"
  if [ "${#valid_git_object_id_bootstrap_value}" -ne 80 ]; then
    echo "Invalid committed macOS release-script blob IDs." >&2
    exit 1
  fi
  case "$valid_git_object_id_bootstrap_value" in
    *[!0-9a-f]*) echo "Invalid committed macOS release-script blob IDs." >&2; exit 1 ;;
  esac
  unset valid_git_object_id_bootstrap_value
fi
readonly LOADED_PACKAGE_MACOS_OID
readonly LOADED_MACOS_BUNDLE_OID
PRODUCTION_APP_NAME="WindowsAppAutoLogin"
APP_NAME="$PRODUCTION_APP_NAME"
APP_DISPLAY_NAME="Windows App AutoLogin"
DEVELOPMENT_BUNDLE_ID="obcardinal.windows-app-autologin"
ZIP_PATH=""
ZIP_SHA256_PATH=""
RELEASE_ARCHIVE_BASE=""
BINARY_NAME="windows-app-autologin"
PRODUCTION_BUNDLE_ID="${WAAL_RELEASE_BUNDLE_ID:-}"
EXPECTED_BUNDLE_ID=""
EXPECTED_BUNDLE_ID_ENV=""
EXPECTED_TEAM_ID="${WAAL_MACOS_TEAM_ID:-}"
CODESIGN_IDENTITY="${WAAL_CODESIGN_IDENTITY:-}"
NOTARY_PROFILE="${WAAL_NOTARY_PROFILE:-}"
RELEASE=false
LOCAL_SIGNED_RELEASE=false
RELEASE_PRIVATE_ROOT=""
RELEASE_PRIVATE_ROOT_PARENT=""
RELEASE_PRIVATE_ROOT_ID=""
RELEASE_PRIVATE_ROOT_PARENT_ID=""
RELEASE_TEMP_DIR=""
STAGE_DIR=""
BUILD_TARGET_DIR=""
TARGET_EXECUTABLE=""
RELEASE_GIT_COMMIT=""
RELEASE_GIT_TREE=""
RELEASE_GIT_SOURCE_ROOT=""
RELEASE_GIT_BIN="/Applications/Xcode.app/Contents/Developer/usr/bin/git"
RELEASE_GIT_SHA256=""
RELEASE_SOURCE_ROOT=""
RELEASE_SOURCE_DIR=""
RELEASE_SOURCE_IDENTITY_SHA256=""
RELEASE_SOURCE_FREEZE_ATTEMPTED=false
RELEASE_SOURCE_FROZEN=false
RELEASE_SOURCE_FREEZE_ROOT_ID=""
RELEASE_TOOLCHAIN_SNAPSHOT_ROOT=""
RELEASE_TOOLCHAIN_SNAPSHOT_ROOT_ID=""
RELEASE_TOOLCHAIN_SNAPSHOT_IDENTITY_SHA256=""
RELEASE_TOOLCHAIN_SNAPSHOT_FREEZE_ATTEMPTED=false
RELEASE_TOOLCHAIN_SNAPSHOT_FROZEN=false
RELEASE_BUILD_DEVELOPER_DIR=""
RELEASE_CARGO_BIN=""
RELEASE_RUSTC_BIN=""
RELEASE_RUST_SYSROOT=""
RELEASE_DEVELOPER_DIR=""
RELEASE_SDKROOT=""
RELEASE_CLANG_RESOURCE_DIR=""
RELEASE_CLANG_BIN=""
RELEASE_CLANGXX_BIN=""
RELEASE_AR_BIN=""
RELEASE_LD_BIN=""
RELEASE_LD_TAPI_BIN=""
RELEASE_LD_CODEDIRECTORY_BIN=""
RELEASE_LD_LTO_BIN=""
RELEASE_LD_SWIFT_DEMANGLE_BIN=""
RELEASE_NOTARYTOOL_BIN=""
RELEASE_STAPLER_BIN=""
RELEASE_BUILD_HOME=""
RELEASE_CARGO_HOME=""
RELEASE_CARGO_WORK_DIR=""
RELEASE_BUILD_TMPDIR=""
RELEASE_CARGO_VERSION=""
RELEASE_RUSTC_VERSION=""
RELEASE_CARGO_SHA256=""
RELEASE_RUSTC_SHA256=""
RELEASE_RUST_SYSROOT_SHA256=""
RELEASE_CLANG_SHA256=""
RELEASE_CLANGXX_SHA256=""
RELEASE_AR_SHA256=""
RELEASE_LD_SHA256=""
RELEASE_LD_TAPI_SHA256=""
RELEASE_LD_CODEDIRECTORY_SHA256=""
RELEASE_LD_LTO_SHA256=""
RELEASE_LD_SWIFT_DEMANGLE_SHA256=""
RELEASE_NOTARYTOOL_SHA256=""
RELEASE_STAPLER_SHA256=""
RELEASE_MACOS_SDK_SHA256=""
RELEASE_CLANG_RESOURCE_DIR_SHA256=""
RELEASE_NATIVE_TOOLCHAIN_SHA256=""
RELEASE_MATERIALS_SHA256=""
LAST_VERIFIED_ARCHIVE_SHA256=""
ARCHIVE_SESSION_ACTIVE=false
ARCHIVE_SESSION_PATH=""
ARCHIVE_SESSION_IDENTITY=""
RELEASE_BUNDLE_PAYLOAD_SHA256=""
CARGO_VERSION=""
BUILD_VERSION=""

for arg in "$@"; do
  case "$arg" in
    --local-signed-release) RELEASE=true; LOCAL_SIGNED_RELEASE=true ;;
    --release|--release-diagnostics-artifact)
      echo "Publishable macOS packaging is disabled in the local packager. Use an isolated authenticated builder." >&2
      exit 1
      ;;
    *) echo "Unknown argument: $arg" >&2; exit 2 ;;
  esac
done

APP_NAME="$PRODUCTION_APP_NAME"
RELEASE_ARCHIVE_BASE="$APP_NAME-macos-local-signed"
EXPECTED_BUNDLE_ID="$PRODUCTION_BUNDLE_ID"
EXPECTED_BUNDLE_ID_ENV="WAAL_RELEASE_BUNDLE_ID"

require_tool() {
  if ! declare -F waal_require_tool >/dev/null; then
    echo "Committed macOS bundle helper is not authenticated and loaded." >&2
    return 1
  fi
  waal_require_tool "$1"
}

valid_bundle_id() {
  if ! declare -F waal_valid_bundle_id >/dev/null; then
    return 1
  fi
  waal_valid_bundle_id "$1"
}

valid_team_id() {
  case "$1" in
    [A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9][A-Z0-9]) return 0 ;;
    *) return 1 ;;
  esac
}

valid_git_object_id() {
  local value="$1"
  [ "${#value}" -eq 40 ] || return 1
  case "$value" in
    *[!0-9a-f]*) return 1 ;;
  esac
}

# Git provenance must not inherit caller-controlled repository, index,
# replacement-ref, alternate-object, or configuration environment. Repository
# attributes can still affect `git archive`, so the materialized bytes are
# independently checked against every tree blob below.
sanitized_git() {
  verify_release_git_integrity || return 1
  /usr/bin/env -i \
    PATH=/usr/bin:/bin:/usr/sbin:/sbin \
    HOME=/var/empty \
    GIT_CONFIG_NOSYSTEM=1 \
    GIT_CONFIG_SYSTEM=/dev/null \
    GIT_CONFIG_GLOBAL=/dev/null \
    GIT_NO_REPLACE_OBJECTS=1 \
    "$RELEASE_GIT_BIN" --no-replace-objects \
      -c core.attributesFile=/dev/null \
      -c core.fsmonitor=false \
      -c core.untrackedCache=false \
      -c core.hooksPath=/dev/null \
      "$@"
}

verify_release_git_integrity() {
  local expected
  local actual
  local canonical

  if [ -z "$RELEASE_GIT_SHA256" ]; then
    expected="$(required_expected_sha256 WAAL_RELEASE_EXPECTED_GIT_SHA256)" || return 1
    if [ ! -f "$RELEASE_GIT_BIN" ] || [ ! -x "$RELEASE_GIT_BIN" ] || [ -L "$RELEASE_GIT_BIN" ]; then
      echo "Pinned physical Xcode Git is unavailable: $RELEASE_GIT_BIN" >&2
      return 1
    fi
    canonical="$(canonical_executable_path "$RELEASE_GIT_BIN")" || return 1
    if [ "$canonical" != "$RELEASE_GIT_BIN" ]; then
      echo "Pinned Git path contains a symbolic-link component." >&2
      return 1
    fi
    actual="$(release_tool_sha256 "$RELEASE_GIT_BIN")"
    if [ "$actual" != "$expected" ]; then
      echo "Physical Xcode Git SHA-256 does not match WAAL_RELEASE_EXPECTED_GIT_SHA256." >&2
      return 1
    fi
    RELEASE_GIT_SHA256="$expected"
    return 0
  fi

  actual="$(release_tool_sha256 "$RELEASE_GIT_BIN")"
  if [ "$actual" != "$RELEASE_GIT_SHA256" ]; then
    echo "Physical Xcode Git changed after release provenance initialization." >&2
    return 1
  fi
}

capture_release_provenance_for_root() {
  local requested_root="$1"
  local source_root
  local git_root
  local git_commit
  local git_tree
  local confirmed_commit
  local confirmed_tree
  local worktree_status
  local index_flags

  if ! source_root="$(cd "$requested_root" 2>/dev/null && /bin/pwd -P)"; then
    echo "Release source directory is unavailable." >&2
    return 1
  fi
  if ! git_root="$(sanitized_git -C "$source_root" rev-parse --show-toplevel 2>/dev/null)"; then
    echo "Release source is not a Git checkout." >&2
    return 1
  fi
  if ! git_root="$(cd "$git_root" 2>/dev/null && /bin/pwd -P)"; then
    echo "Release Git root directory is unavailable." >&2
    return 1
  fi
  if [ "$git_root" != "$source_root" ]; then
    echo "Release source must be the root of its Git checkout." >&2
    return 1
  fi
  if ! git_commit="$(sanitized_git -C "$source_root" rev-parse --verify 'HEAD^{commit}' 2>/dev/null)" \
    || ! valid_git_object_id "$git_commit"; then
    echo "Release source HEAD must resolve to an exact lowercase 40-hex commit ID." >&2
    return 1
  fi
  if ! git_tree="$(sanitized_git -C "$source_root" rev-parse --verify 'HEAD^{tree}' 2>/dev/null)" \
    || ! valid_git_object_id "$git_tree"; then
    echo "Release source HEAD must resolve to an exact lowercase 40-hex tree ID." >&2
    return 1
  fi
  if ! worktree_status="$(sanitized_git -C "$source_root" status \
    --porcelain=v1 \
    --untracked-files=all \
    --ignore-submodules=none 2>/dev/null)"; then
    echo "Unable to verify release source worktree state." >&2
    return 1
  fi
  if [ -n "$worktree_status" ]; then
    echo "Release source must have no tracked or untracked worktree changes." >&2
    return 1
  fi
  if ! index_flags="$(sanitized_git -C "$source_root" ls-files -v 2>/dev/null)"; then
    echo "Unable to verify release source index flags." >&2
    return 1
  fi
  if /usr/bin/printf '%s\n' "$index_flags" | /usr/bin/grep -E '^[a-zS] ' >/dev/null; then
    echo "Release source contains assume-unchanged or skip-worktree index entries." >&2
    return 1
  fi
  if ! confirmed_commit="$(sanitized_git -C "$source_root" rev-parse --verify 'HEAD^{commit}' 2>/dev/null)" \
    || ! confirmed_tree="$(sanitized_git -C "$source_root" rev-parse --verify 'HEAD^{tree}' 2>/dev/null)" \
    || [ "$confirmed_commit" != "$git_commit" ] \
    || [ "$confirmed_tree" != "$git_tree" ]; then
    echo "Release source HEAD changed while provenance was being captured." >&2
    return 1
  fi

  RELEASE_GIT_COMMIT="$git_commit"
  RELEASE_GIT_TREE="$git_tree"
  RELEASE_GIT_SOURCE_ROOT="$source_root"
}

capture_release_provenance() {
  capture_release_provenance_for_root "$ROOT_DIR"
}

verify_release_source_unchanged() {
  local expected_commit="$RELEASE_GIT_COMMIT"
  local expected_tree="$RELEASE_GIT_TREE"

  if ! valid_git_object_id "$expected_commit" || ! valid_git_object_id "$expected_tree"; then
    echo "Release source provenance was not initialized." >&2
    return 1
  fi
  if ! capture_release_provenance_for_root "$ROOT_DIR"; then
    return 1
  fi
  if [ "$RELEASE_GIT_COMMIT" != "$expected_commit" ] || [ "$RELEASE_GIT_TREE" != "$expected_tree" ]; then
    echo "Release source HEAD or tree changed during packaging." >&2
    return 1
  fi
}

verify_release_tree_contains_only_regular_files() {
  local requested_root="$1"
  local expected_commit="$2"
  local listing
  local entry
  local header
  local mode
  local remainder
  local object_type

  listing="$(private_release_mktemp waal-release-tree)" || return 1
  if ! sanitized_git -C "$requested_root" ls-tree -rz --full-tree "$expected_commit" >"$listing"; then
    /bin/rm -f -- "$listing"
    echo "Unable to inspect release source tree entry modes." >&2
    return 1
  fi

  while IFS= read -r -d '' entry; do
    case "$entry" in
      *$'\t'*) ;;
      *)
        /bin/rm -f -- "$listing"
        echo "Release source tree contains an unparseable entry." >&2
        return 1
        ;;
    esac
    header="${entry%%$'\t'*}"
    mode="${header%% *}"
    remainder="${header#* }"
    object_type="${remainder%% *}"
    case "$mode:$object_type" in
      100644:blob|100755:blob) ;;
      *)
        /bin/rm -f -- "$listing"
        echo "Release source tree contains a link, gitlink, or unsupported entry mode." >&2
        return 1
        ;;
    esac
  done <"$listing"
  /bin/rm -f -- "$listing"
}

verify_materialized_release_source() {
  local destination="$1"
  local requested_root="$2"
  local expected_commit="$3"
  local required_path
  local link_path
  local listing

  while IFS= read -r -d '' link_path; do
    echo "Release source snapshot contains a symbolic link and is not self-contained." >&2
    return 1
  done < <(/usr/bin/find "$destination" -type l -print0)

  for required_path in Cargo.toml Cargo.lock build.rs; do
    if [ ! -f "$destination/$required_path" ] || [ -L "$destination/$required_path" ]; then
      echo "Release source snapshot is missing a regular tracked file: $required_path" >&2
      return 1
    fi
  done
  for required_path in src assets; do
    if [ ! -d "$destination/$required_path" ] || [ -L "$destination/$required_path" ]; then
      echo "Release source snapshot is missing a real tracked directory: $required_path" >&2
      return 1
    fi
  done

  listing="$(private_release_mktemp waal-release-tree-bytes)" || return 1
  if ! sanitized_git -C "$requested_root" ls-tree -rz --full-tree "$expected_commit" >"$listing"; then
    /bin/rm -f -- "$listing"
    echo "Unable to capture the expected release tree for byte verification." >&2
    return 1
  fi
  if ! /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin \
    /usr/bin/perl -MDigest::SHA=sha1_hex -MFile::Find -e '
      use strict;
      use warnings;
      use bytes;
      my ($root, $listing) = @ARGV;
      open my $tree, "<:raw", $listing or die "open tree listing: $!\n";
      local $/;
      my $raw = <$tree>;
      close $tree or die "close tree listing: $!\n";
      my %expected;
      for my $entry (split /\0/, $raw, -1) {
        next if $entry eq "";
        $entry =~ /\A(100644|100755) blob ([0-9a-f]{40})\t(.+)\z/s
          or die "unparseable or unsupported tree entry\n";
        my ($mode, $oid, $path) = ($1, $2, $3);
        die "unsafe tree path\n" if $path =~ m{(?:\A/|\A\.\.?/|/\.\.?/|/\.\.?\z)};
        die "duplicate tree path\n" if exists $expected{$path};
        $expected{$path} = [$mode, $oid];
      }
      my %actual;
      File::Find::find({
        no_chdir => 1,
        wanted => sub {
          my $path = $File::Find::name;
          my @status = lstat($path);
          @status or die "lstat failed: $!\n";
          die "snapshot contains a symbolic link\n" if -l _;
          return if -d _;
          die "snapshot contains a non-regular node\n" unless -f _;
          die "snapshot file has an additional hard link\n" unless $status[3] == 1;
          my $relative = substr($path, length($root) + 1);
          $actual{$relative} = $path;
        },
      }, $root);
      die "snapshot file set differs from Git tree\n"
        unless keys(%actual) == keys(%expected);
      for my $path (keys %expected) {
        die "snapshot is missing a Git tree path\n" unless exists $actual{$path};
        my ($mode, $oid) = @{$expected{$path}};
        my $full = $actual{$path};
        my @before = lstat($full);
        die "lstat snapshot file: $!\n" unless @before;
        die "snapshot file is not single-link regular content\n"
          unless (($before[2] & 0170000) == 0100000) && $before[3] == 1;
        open my $file, "<:raw", $full or die "open snapshot file: $!\n";
        my @opened_before = stat($file);
        die "fstat snapshot file: $!\n" unless @opened_before;
        local $/;
        my $content = <$file>;
        my @opened_after = stat($file);
        die "fstat snapshot file after read: $!\n" unless @opened_after;
        close $file or die "close snapshot file: $!\n";
        my @path_after = lstat($full);
        die "lstat snapshot file after read: $!\n" unless @path_after;
        for my $index (0, 1, 2, 3, 7, 9, 10) {
          die "snapshot file identity changed while reading\n"
            unless $before[$index] == $opened_before[$index]
              && $before[$index] == $opened_after[$index]
              && $before[$index] == $path_after[$index];
        }
        my $actual_oid = sha1_hex("blob " . length($content) . "\0" . $content);
        die "snapshot blob differs from Git tree\n" unless $actual_oid eq $oid;
        my $executable = ((stat($full))[2] & 0111) != 0;
        die "snapshot executable mode differs from Git tree\n"
          unless $executable == ($mode eq "100755");
      }
    ' -- "$destination" "$listing"; then
    /bin/rm -f -- "$listing"
    echo "Release source snapshot bytes or modes differ from the captured Git tree." >&2
    return 1
  fi
  /bin/rm -f -- "$listing"
}

release_source_identity_sha256() {
  local requested_root="$1"
  local root
  local digest
  local anchor_name
  local anchor_path
  local anchor_metadata

  if ! root="$(cd "$requested_root" 2>/dev/null && /bin/pwd -P)" \
    || [ "$root" != "${requested_root%/}" ]; then
    echo "Release source identity input must be a physical directory." >&2
    return 1
  fi

  # Contract: SHA-256 over anchor and byte-sorted path records containing path,
  # NUL, and exact Darwin lstat identity (device, inode, type/mode, link count,
  # uid/gid, size, flags, nanosecond mtime, nanosecond ctime), NUL. File hard
  # links are forbidden.
  if ! digest="$(
    set -o pipefail
    {
      for anchor_name in private-parent private-root source-parent; do
        # Bash 3.2 can misparse case-pattern closing parentheses nested inside
        # this command substitution. Keep the anchor mapping parenthesis-free
        # so the exact same code is interpreted correctly by the system Bash.
        if [ "$anchor_name" = private-parent ]; then
          anchor_path="$RELEASE_PRIVATE_ROOT_PARENT"
        elif [ "$anchor_name" = private-root ]; then
          anchor_path="$RELEASE_PRIVATE_ROOT"
        else
          anchor_path="$RELEASE_SOURCE_ROOT"
        fi
        if [ ! -d "$anchor_path" ] || [ -L "$anchor_path" ] \
          || [ "$(cd "$anchor_path" 2>/dev/null && /bin/pwd -P)" != "$anchor_path" ]; then
          echo "Release source identity anchor is not a physical directory." >&2
          return 1
        fi
        anchor_metadata="$(/usr/bin/stat -f '%d:%i:%p:%l:%u:%g:%z:%f:%Fm:%Fc' "$anchor_path")" \
          || return 1
        /usr/bin/printf '@%s\0%s\0' "$anchor_name" "$anchor_metadata"
      done
      while IFS= read -r -d '' identity_path; do
        local relative
        local link_count
        local metadata
        if [ -L "$identity_path" ]; then
          echo "Release source identity contains a symbolic link." >&2
          return 1
        fi
        if [ -f "$identity_path" ]; then
          link_count="$(/usr/bin/stat -f '%l' "$identity_path")" || return 1
          if [ "$link_count" != 1 ]; then
            echo "Release source identity contains a hard-linked file." >&2
            return 1
          fi
        elif [ ! -d "$identity_path" ]; then
          echo "Release source identity contains an unsupported filesystem node." >&2
          return 1
        fi
        metadata="$(/usr/bin/stat -f '%d:%i:%p:%l:%u:%g:%z:%f:%Fm:%Fc' "$identity_path")" \
          || return 1
        if [ "$identity_path" = "$root" ]; then
          relative=.
        else
          relative="${identity_path#"$root"/}"
        fi
        /usr/bin/printf '%s\0%s\0' "$relative" "$metadata"
      done < <(/usr/bin/find -x -s "$root" -print0)
    } | /usr/bin/shasum -a 256 | /usr/bin/awk '{ print $1; exit }'
  )" || ! valid_sha256 "$digest"; then
    echo "Unable to capture exact release source filesystem identity." >&2
    return 1
  fi
  /usr/bin/printf '%s\n' "$digest"
}

capture_release_source_identity_baseline() {
  local first_identity
  local second_identity
  local freeze_root_id

  freeze_root_id="$(directory_identity "$RELEASE_SOURCE_DIR")" || return 1
  RELEASE_SOURCE_FREEZE_ROOT_ID="$freeze_root_id"
  RELEASE_SOURCE_FREEZE_ATTEMPTED=true
  RELEASE_SOURCE_FROZEN=false
  /bin/chmod -R a-w "$RELEASE_SOURCE_DIR" || return 1
  /usr/bin/chflags -R -P uchg "$RELEASE_SOURCE_DIR" || return 1
  RELEASE_SOURCE_FROZEN=true
  verify_materialized_release_source \
    "$RELEASE_SOURCE_DIR" "$RELEASE_GIT_SOURCE_ROOT" "$RELEASE_GIT_COMMIT" || return 1
  first_identity="$(release_source_identity_sha256 "$RELEASE_SOURCE_DIR")" || return 1
  verify_materialized_release_source \
    "$RELEASE_SOURCE_DIR" "$RELEASE_GIT_SOURCE_ROOT" "$RELEASE_GIT_COMMIT" || return 1
  second_identity="$(release_source_identity_sha256 "$RELEASE_SOURCE_DIR")" || return 1
  if [ "$first_identity" != "$second_identity" ]; then
    echo "Release source identity changed while its baseline was captured." >&2
    return 1
  fi
  RELEASE_SOURCE_IDENTITY_SHA256="$first_identity"
}

verify_release_source_freeze_anchor() {
  local physical_source_root
  local physical_source_dir
  local actual_root_id

  if [ "$RELEASE_SOURCE_FREEZE_ATTEMPTED" != true ] \
    || [ -z "$RELEASE_SOURCE_FREEZE_ROOT_ID" ]; then
    echo "Release source freeze state is not initialized." >&2
    return 1
  fi
  verify_private_release_root || return 1
  if [ "$RELEASE_SOURCE_ROOT" != "$RELEASE_PRIVATE_ROOT/source-environment" ] \
    || [ "$RELEASE_SOURCE_DIR" != "$RELEASE_SOURCE_ROOT/source" ]; then
    echo "Frozen release source escaped its recorded private root." >&2
    return 1
  fi
  if ! physical_source_root="$(cd "$RELEASE_SOURCE_ROOT" 2>/dev/null && /bin/pwd -P)" \
    || [ "$physical_source_root" != "$RELEASE_SOURCE_ROOT" ] \
    || ! physical_source_dir="$(cd "$RELEASE_SOURCE_DIR" 2>/dev/null && /bin/pwd -P)" \
    || [ "$physical_source_dir" != "$RELEASE_SOURCE_DIR" ]; then
    echo "Frozen release source path is no longer physical." >&2
    return 1
  fi
  actual_root_id="$(directory_identity "$RELEASE_SOURCE_DIR")" || return 1
  if [ "$actual_root_id" != "$RELEASE_SOURCE_FREEZE_ROOT_ID" ]; then
    echo "Frozen release source root identity changed." >&2
    return 1
  fi
}

thaw_release_source_if_anchored() {
  local expected_root_id="$RELEASE_SOURCE_FREEZE_ROOT_ID"

  [ "$RELEASE_SOURCE_FREEZE_ATTEMPTED" = true ] || return 0
  verify_release_source_freeze_anchor || return 1
  if ! (
    cd "$RELEASE_SOURCE_DIR" || exit 1
    [ "$(directory_identity .)" = "$expected_root_id" ] || exit 1
    /usr/bin/chflags -R -P nouchg . || exit 1
    [ "$(directory_identity .)" = "$expected_root_id" ] || exit 1
  ); then
    echo "Unable to thaw the anchored release source snapshot." >&2
    return 1
  fi
  verify_release_source_freeze_anchor || return 1
  RELEASE_SOURCE_FROZEN=false
  RELEASE_SOURCE_FREEZE_ATTEMPTED=false
  RELEASE_SOURCE_FREEZE_ROOT_ID=""
  RELEASE_SOURCE_IDENTITY_SHA256=""
}

verify_release_source_identity_baseline() {
  local actual_identity

  if ! valid_sha256 "$RELEASE_SOURCE_IDENTITY_SHA256"; then
    echo "Release source identity baseline is not initialized." >&2
    return 1
  fi
  actual_identity="$(release_source_identity_sha256 "$RELEASE_SOURCE_DIR")" || return 1
  if [ "$actual_identity" != "$RELEASE_SOURCE_IDENTITY_SHA256" ]; then
    echo "Release source inode or nanosecond metadata changed during packaging." >&2
    return 1
  fi
}

verify_release_source_identity_guard() {
  verify_release_source_identity_baseline || return 1
  verify_materialized_release_source \
    "$RELEASE_SOURCE_DIR" "$RELEASE_GIT_SOURCE_ROOT" "$RELEASE_GIT_COMMIT" || return 1
  verify_release_source_identity_baseline || return 1
}

finalize_release_source_identity_guard() {
  verify_release_source_identity_guard || return 1
  thaw_release_source_if_anchored
}

guarded_tree_identity_sha256() {
  local requested_root="$1"
  local root
  local digest

  if ! root="$(cd "$requested_root" 2>/dev/null && /bin/pwd -P)" \
    || [ "$root" != "${requested_root%/}" ]; then
    echo "Guarded tree identity input must be a physical directory." >&2
    return 1
  fi

  if ! digest="$(
    /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin \
      /usr/bin/perl -MCwd=abs_path -MDigest::SHA -MFile::Find \
      -MTime::HiRes=lstat -e '
        use strict;
        use warnings;
        use bytes;
        my $root = shift @ARGV;
        my @records;
        File::Find::find({
          no_chdir => 1,
          follow => 0,
          wanted => sub {
            my $path = $File::Find::name;
            my @status = lstat($path);
            die "lstat guarded tree entry: $!\n" unless @status;
            my $relative = $path eq $root
              ? "." : substr($path, length($root) + 1);
            my $kind;
            my $extra = "";
            if (-l _) {
              $kind = "link";
              my $target = readlink($path);
              die "read guarded tree link: $!\n" unless defined $target;
              die "guarded tree link target contains a control byte\n"
                if $target =~ /[\x00-\x1f\x7f]/;
              my $resolved = abs_path($path);
              die "guarded tree contains a broken link\n" unless defined $resolved;
              die "guarded tree link escapes its root\n"
                unless $resolved eq $root || index($resolved, "$root/") == 0;
              $extra = $target;
            } elsif (-d _) {
              $kind = "directory";
            } elsif (-f _) {
              $kind = "file";
              die "guarded tree contains a multiply linked file\n"
                unless $status[3] == 1;
            } else {
              die "guarded tree contains an unsupported node\n";
            }
            my $metadata = join(":", @status[0, 1, 2, 3, 4, 5, 7],
              sprintf("%.9f", $status[9]), sprintf("%.9f", $status[10]));
            push @records, [$relative, $kind, $metadata, $extra];
          },
        }, $root);
        @records = sort { $a->[0] cmp $b->[0] } @records;
        my $aggregate = Digest::SHA->new(256);
        for my $record (@records) {
          $aggregate->add($record->[0], "\0", $record->[1], "\0",
            $record->[2], "\0", $record->[3], "\0");
        }
        print $aggregate->hexdigest, "\n";
      ' -- "$root"
  )" || ! valid_sha256 "$digest"; then
    echo "Unable to capture exact guarded tree identity." >&2
    return 1
  fi
  /usr/bin/printf '%s\n' "$digest"
}

verify_release_toolchain_snapshot_anchor() {
  local physical_root
  local actual_id

  if [ -z "$RELEASE_TOOLCHAIN_SNAPSHOT_ROOT" ] \
    || [ -z "$RELEASE_TOOLCHAIN_SNAPSHOT_ROOT_ID" ] \
    || [ "$RELEASE_TOOLCHAIN_SNAPSHOT_FREEZE_ATTEMPTED" != true ]; then
    echo "Release toolchain snapshot identity is not initialized." >&2
    return 1
  fi
  verify_private_release_root || return 1
  case "$RELEASE_TOOLCHAIN_SNAPSHOT_ROOT" in
    "$RELEASE_PRIVATE_ROOT"/build-toolchain) ;;
    *) echo "Release toolchain snapshot escaped its private root." >&2; return 1 ;;
  esac
  if ! physical_root="$(cd "$RELEASE_TOOLCHAIN_SNAPSHOT_ROOT" 2>/dev/null && /bin/pwd -P)" \
    || [ "$physical_root" != "$RELEASE_TOOLCHAIN_SNAPSHOT_ROOT" ]; then
    echo "Release toolchain snapshot path is no longer physical." >&2
    return 1
  fi
  actual_id="$(directory_identity "$RELEASE_TOOLCHAIN_SNAPSHOT_ROOT")" || return 1
  if [ "$actual_id" != "$RELEASE_TOOLCHAIN_SNAPSHOT_ROOT_ID" ]; then
    echo "Release toolchain snapshot root identity changed." >&2
    return 1
  fi
}

verify_release_toolchain_snapshot_identity() {
  local actual_identity

  verify_release_toolchain_snapshot_anchor || return 1
  if ! valid_sha256 "$RELEASE_TOOLCHAIN_SNAPSHOT_IDENTITY_SHA256"; then
    echo "Release toolchain snapshot baseline is not initialized." >&2
    return 1
  fi
  actual_identity="$(
    guarded_tree_identity_sha256 "$RELEASE_TOOLCHAIN_SNAPSHOT_ROOT"
  )" || return 1
  if [ "$actual_identity" != "$RELEASE_TOOLCHAIN_SNAPSHOT_IDENTITY_SHA256" ]; then
    echo "Release toolchain snapshot inode or nanosecond metadata changed." >&2
    return 1
  fi
}

verify_release_toolchain_snapshot_guard() {
  verify_release_toolchain_snapshot_identity || return 1
  verify_release_toolchain_integrity || return 1
  verify_release_toolchain_snapshot_identity
}

capture_release_toolchain_snapshot_baseline() {
  local first_identity
  local second_identity

  RELEASE_TOOLCHAIN_SNAPSHOT_ROOT_ID="$(
    directory_identity "$RELEASE_TOOLCHAIN_SNAPSHOT_ROOT"
  )" || return 1
  RELEASE_TOOLCHAIN_SNAPSHOT_FREEZE_ATTEMPTED=true
  RELEASE_TOOLCHAIN_SNAPSHOT_FROZEN=false
  /usr/bin/find -x "$RELEASE_TOOLCHAIN_SNAPSHOT_ROOT" ! -type l \
    -exec /bin/chmod a-w '{}' + || return 1
  /usr/bin/chflags -R -P uchg "$RELEASE_TOOLCHAIN_SNAPSHOT_ROOT" || return 1
  RELEASE_TOOLCHAIN_SNAPSHOT_FROZEN=true
  verify_release_toolchain_integrity || return 1
  first_identity="$(
    guarded_tree_identity_sha256 "$RELEASE_TOOLCHAIN_SNAPSHOT_ROOT"
  )" || return 1
  verify_release_toolchain_integrity || return 1
  second_identity="$(
    guarded_tree_identity_sha256 "$RELEASE_TOOLCHAIN_SNAPSHOT_ROOT"
  )" || return 1
  if [ "$first_identity" != "$second_identity" ]; then
    echo "Release toolchain snapshot changed while its baseline was captured." >&2
    return 1
  fi
  RELEASE_TOOLCHAIN_SNAPSHOT_IDENTITY_SHA256="$first_identity"
  verify_release_toolchain_snapshot_guard
}

thaw_release_toolchain_snapshot_if_anchored() {
  local expected_root_id="$RELEASE_TOOLCHAIN_SNAPSHOT_ROOT_ID"

  [ "$RELEASE_TOOLCHAIN_SNAPSHOT_FREEZE_ATTEMPTED" = true ] || return 0
  verify_release_toolchain_snapshot_anchor || return 1
  if ! (
    cd "$RELEASE_TOOLCHAIN_SNAPSHOT_ROOT" || exit 1
    [ "$(directory_identity .)" = "$expected_root_id" ] || exit 1
    /usr/bin/chflags -R -P nouchg . || exit 1
    /usr/bin/find -x . ! -type l -exec /bin/chmod u+w '{}' + || exit 1
    [ "$(directory_identity .)" = "$expected_root_id" ] || exit 1
  ); then
    echo "Unable to thaw the anchored release toolchain snapshot." >&2
    return 1
  fi
  RELEASE_TOOLCHAIN_SNAPSHOT_FROZEN=false
  RELEASE_TOOLCHAIN_SNAPSHOT_FREEZE_ATTEMPTED=false
  RELEASE_TOOLCHAIN_SNAPSHOT_ROOT_ID=""
  RELEASE_TOOLCHAIN_SNAPSHOT_IDENTITY_SHA256=""
}

materialize_release_source_for_root() {
  local requested_root="$1"
  local destination="$2"
  local expected_commit="$3"
  local expected_tree="$4"
  local actual_tree

  if ! valid_git_object_id "$expected_commit" || ! valid_git_object_id "$expected_tree"; then
    echo "Release source provenance must be initialized before materializing source." >&2
    return 1
  fi
  if [ -e "$destination" ]; then
    echo "Release source snapshot destination already exists." >&2
    return 1
  fi
  if ! actual_tree="$(sanitized_git -C "$requested_root" rev-parse --verify "$expected_commit^{tree}" 2>/dev/null)" \
    || [ "$actual_tree" != "$expected_tree" ]; then
    echo "Release commit does not resolve to the captured source tree." >&2
    return 1
  fi
  verify_release_tree_contains_only_regular_files "$requested_root" "$expected_commit" || return 1

  /bin/mkdir -p "$destination"
  if ! sanitized_git -C "$requested_root" archive --format=tar "$expected_commit" \
    | /usr/bin/tar -xf - -C "$destination"; then
    echo "Failed to materialize the release source snapshot from Git." >&2
    return 1
  fi
  verify_materialized_release_source "$destination" "$requested_root" "$expected_commit"
}

materialize_release_source() {
  if [ -z "$RELEASE_PRIVATE_ROOT" ] || [ -z "$RELEASE_SOURCE_ROOT" ] \
    || [ ! -d "$RELEASE_SOURCE_ROOT" ] || [ -L "$RELEASE_SOURCE_ROOT" ]; then
    echo "Private release source staging is not initialized." >&2
    return 1
  fi
  RELEASE_SOURCE_DIR="$RELEASE_SOURCE_ROOT/source"
  materialize_release_source_for_root \
    "$ROOT_DIR" \
    "$RELEASE_SOURCE_DIR" \
    "$RELEASE_GIT_COMMIT" \
    "$RELEASE_GIT_TREE"
}

verify_release_snapshot_unchanged() {
  if [ -z "$RELEASE_SOURCE_DIR" ] || [ -z "$RELEASE_GIT_COMMIT" ]; then
    echo "Release source snapshot provenance is not initialized." >&2
    return 1
  fi
  verify_materialized_release_source \
    "$RELEASE_SOURCE_DIR" \
    "$RELEASE_GIT_SOURCE_ROOT" \
    "$RELEASE_GIT_COMMIT"
}

verify_packager_source_hashes_match_snapshot() {
  local snapshot_root="$1"
  local expected_package_sha256="$2"
  local expected_bundle_sha256="$3"
  local expected_package_oid="${4:-}"
  local expected_bundle_oid="${5:-}"
  local snapshot_package="$snapshot_root/script/package_macos.sh"
  local snapshot_bundle="$snapshot_root/script/macos_bundle.sh"
  local actual_package_sha256
  local actual_bundle_sha256
  local actual_package_oid
  local actual_bundle_oid

  if ! valid_sha256 "$expected_package_sha256" \
    || ! valid_sha256 "$expected_bundle_sha256"; then
    echo "Loaded macOS release-script provenance is invalid." >&2
    return 1
  fi
  if [ ! -f "$snapshot_package" ] || [ -L "$snapshot_package" ] \
    || [ ! -f "$snapshot_bundle" ] || [ -L "$snapshot_bundle" ]; then
    echo "Captured release tree is missing regular macOS release scripts." >&2
    return 1
  fi
  actual_package_sha256="$(release_tool_sha256 "$snapshot_package")"
  actual_bundle_sha256="$(release_tool_sha256 "$snapshot_bundle")"
  if [ "$actual_package_sha256" != "$expected_package_sha256" ] \
    || [ "$actual_bundle_sha256" != "$expected_bundle_sha256" ]; then
    echo "Loaded macOS release logic does not match the captured Git tree." >&2
    return 1
  fi
  if [ -n "$expected_package_oid$expected_bundle_oid" ]; then
    if ! valid_git_object_id "$expected_package_oid" \
      || ! valid_git_object_id "$expected_bundle_oid"; then
      echo "Loaded macOS release-script blob provenance is invalid." >&2
      return 1
    fi
    actual_package_oid="$(
      sanitized_git -C "$RELEASE_GIT_SOURCE_ROOT" hash-object -- "$snapshot_package"
    )" || return 1
    actual_bundle_oid="$(
      sanitized_git -C "$RELEASE_GIT_SOURCE_ROOT" hash-object -- "$snapshot_bundle"
    )" || return 1
    if [ "$actual_package_oid" != "$expected_package_oid" ] \
      || [ "$actual_bundle_oid" != "$expected_bundle_oid" ]; then
      echo "Interpreted macOS release logic does not match its committed Git blobs." >&2
      return 1
    fi
  fi
}

verify_loaded_packager_matches_snapshot() {
  verify_packager_source_hashes_match_snapshot \
    "$RELEASE_SOURCE_DIR" \
    "$LOADED_PACKAGE_MACOS_SHA256" \
    "$LOADED_MACOS_BUNDLE_SHA256" \
    "$LOADED_PACKAGE_MACOS_OID" \
    "$LOADED_MACOS_BUNDLE_OID"
}

load_authenticated_bundle_helper() {
  local bundle_execution_identity
  local bundle_verification_identity
  local bundle_nlink
  local actual_bundle_sha256
  local actual_bundle_oid
  local waal_function

  descriptor_identity() {
    /usr/bin/stat -f '%d:%i:%p:%l:%z' "$1"
  }
  bundle_execution_identity="$(descriptor_identity /dev/fd/7)" || return 1
  bundle_verification_identity="$(descriptor_identity /dev/fd/6)" || return 1
  IFS=: read -r _ _ _ bundle_nlink _ <<<"$bundle_execution_identity"
  if [ ! -f /dev/fd/7 ] || [ ! -f /dev/fd/6 ] \
    || [ "$bundle_nlink" != 0 ] \
    || [ "$bundle_execution_identity" != "$bundle_verification_identity" ]; then
    echo "Committed macOS bundle-helper descriptors are not one anonymous regular inode." >&2
    unset -f descriptor_identity
    return 1
  fi
  actual_bundle_sha256="$(
    /usr/bin/shasum -a 256 /dev/fd/6 | /usr/bin/awk '{ print $1; exit }'
  )"
  /usr/bin/perl -e '
    use strict;
    use warnings;
    defined(sysseek(STDIN, 0, 0)) or die "rewind helper descriptor: $!\n";
  ' <&6 || return 1
  actual_bundle_oid="$(
    sanitized_git -C "$RELEASE_GIT_SOURCE_ROOT" hash-object --stdin <&6
  )" || return 1
  if [ "$actual_bundle_sha256" != "$LOADED_MACOS_BUNDLE_SHA256" ] \
    || [ "$actual_bundle_oid" != "$LOADED_MACOS_BUNDLE_OID" ] \
    || [ "$(descriptor_identity /dev/fd/7)" != "$bundle_execution_identity" ]; then
    echo "Committed macOS bundle-helper descriptor changed before interpretation." >&2
    unset -f descriptor_identity
    return 1
  fi
  while IFS= read -r waal_function; do
    unset -f "$waal_function"
  done < <(builtin declare -F | /usr/bin/awk '$3 ~ /^waal_/ { print $3 }')
  builtin source /dev/fd/7
  if ! builtin declare -F waal_require_tool >/dev/null \
    || ! builtin declare -F waal_cargo_version >/dev/null \
    || ! builtin declare -F waal_assemble_app_bundle >/dev/null \
    || [ "$(descriptor_identity /dev/fd/7)" != "$bundle_execution_identity" ]; then
    echo "Committed macOS bundle helper was not loaded from its authenticated descriptor." >&2
    unset -f descriptor_identity
    return 1
  fi
  exec 6<&- 7<&-
  unset -f descriptor_identity
}

canonical_executable_path() {
  local requested_path="$1"
  local directory
  local leaf

  directory="$(/usr/bin/dirname "$requested_path")"
  leaf="$(/usr/bin/basename "$requested_path")"
  if ! directory="$(cd "$directory" 2>/dev/null && /bin/pwd -P)"; then
    return 1
  fi
  /usr/bin/printf '%s/%s\n' "$directory" "$leaf"
}

valid_sha256() {
  local value="$1"
  [ "${#value}" -eq 64 ] || return 1
  case "$value" in
    *[!0-9a-f]*) return 1 ;;
  esac
}

resolve_explicit_release_tool() {
  local env_name="$1"
  local description="$2"
  local requested_path="${!env_name:-}"
  local canonical_path

  case "$requested_path" in
    /*) ;;
    *)
      echo "$env_name must be an explicit absolute path to $description." >&2
      return 1
      ;;
  esac
  if [ ! -f "$requested_path" ] || [ ! -x "$requested_path" ] || [ -L "$requested_path" ]; then
    echo "$env_name must identify a regular executable, not a symbolic link: $requested_path" >&2
    return 1
  fi
  if ! canonical_path="$(canonical_executable_path "$requested_path")" \
    || [ "$canonical_path" != "$requested_path" ]; then
    echo "$env_name must not contain symbolic-link path components: $requested_path" >&2
    return 1
  fi
  /usr/bin/printf '%s\n' "$canonical_path"
}

resolve_explicit_release_directory() {
  local env_name="$1"
  local description="$2"
  local requested_path="${!env_name:-}"
  local canonical_path

  case "$requested_path" in
    /*) ;;
    *)
      echo "$env_name must be an explicit absolute path to $description." >&2
      return 1
      ;;
  esac
  if [ ! -d "$requested_path" ] || [ -L "$requested_path" ]; then
    echo "$env_name must identify a real directory, not a symbolic link: $requested_path" >&2
    return 1
  fi
  if ! canonical_path="$(cd "$requested_path" 2>/dev/null && /bin/pwd -P)" \
    || [ "$canonical_path" != "${requested_path%/}" ]; then
    echo "$env_name must not contain symbolic-link path components: $requested_path" >&2
    return 1
  fi
  /usr/bin/printf '%s\n' "$canonical_path"
}

canonical_existing_path() {
  local requested_path="$1"
  /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin \
    /usr/bin/perl -MCwd=abs_path -e '
      use strict;
      use warnings;
      my $path = shift @ARGV;
      my $resolved = abs_path($path);
      die "unable to resolve path\n" unless defined $resolved;
      print $resolved, "\n";
    ' -- "$requested_path"
}

verify_release_tool_under_root() {
  local path="$1"
  local trusted_root="$2"
  local expected="$3"
  local description="$4"
  local resolved
  local actual

  case "$path" in
    "$trusted_root"/*) ;;
    *)
      echo "$description is not inside the explicitly selected Xcode Developer directory." >&2
      return 1
      ;;
  esac
  if [ ! -f "$path" ] || [ ! -x "$path" ]; then
    echo "$description is not an executable Xcode tool: $path" >&2
    return 1
  fi
  if ! resolved="$(canonical_existing_path "$path")"; then
    echo "$description cannot be resolved to a physical Xcode tool." >&2
    return 1
  fi
  case "$resolved" in
    "$trusted_root"/*) ;;
    *)
      echo "$description resolves outside the explicitly selected Xcode Developer directory." >&2
      return 1
      ;;
  esac
  if [ ! -f "$resolved" ] || [ ! -x "$resolved" ]; then
    echo "$description does not resolve to a regular executable." >&2
    return 1
  fi
  actual="$(release_tool_sha256 "$path")"
  if [ "$actual" != "$expected" ]; then
    echo "$description SHA-256 does not match its required release pin." >&2
    return 1
  fi
}

resolve_release_directory_under_root() {
  local requested_path="$1"
  local trusted_root="$2"
  local description="$3"
  local resolved

  if ! resolved="$(canonical_existing_path "$requested_path")"; then
    echo "$description cannot be resolved." >&2
    return 1
  fi
  case "$resolved" in
    "$trusted_root"/*) ;;
    *)
      echo "$description resolves outside the explicitly selected Xcode Developer directory." >&2
      return 1
      ;;
  esac
  if [ ! -d "$resolved" ] || [ -L "$resolved" ]; then
    echo "$description must resolve to a physical directory." >&2
    return 1
  fi
  /usr/bin/printf '%s\n' "$resolved"
}

required_expected_sha256() {
  local env_name="$1"
  local value="${!env_name:-}"
  if ! valid_sha256 "$value"; then
    echo "$env_name must be an exact lowercase SHA-256 digest." >&2
    return 1
  fi
  /usr/bin/printf '%s\n' "$value"
}

release_tool_version() {
  local tool_path="$1"
  /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin "$tool_path" --version --verbose \
    | /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin \
      /usr/bin/awk -F ': ' '$1 == "release" { print $2 }'
}

release_tool_sha256() {
  local tool_path="$1"
  /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin \
    /usr/bin/shasum -a 256 "$tool_path" \
    | /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin \
      /usr/bin/awk '{ print $1 }'
}

directory_tree_sha256() {
  local requested_root="$1"
  local root
  local digest

  if ! root="$(cd "$requested_root" 2>/dev/null && /bin/pwd -P)" \
    || [ "$root" != "${requested_root%/}" ]; then
    echo "Hash input must be a physical directory without symbolic-link path components: $requested_root" >&2
    return 1
  fi
  # Contract: SHA-256 over ordinal byte-sorted entries containing relative
  # path, NUL, lowercase file SHA-256, NUL. A single process keeps this
  # practical for a Rust sysroot with tens of thousands of files.
  if ! digest="$(/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin \
    /usr/bin/perl -MDigest::SHA -MFile::Find -e '
    use strict;
    use warnings;
    use bytes;
    my $root = shift @ARGV;
    my @files;
    File::Find::find({
      no_chdir => 1,
      wanted => sub {
        my $path = $File::Find::name;
        lstat($path) or die "lstat failed for $path: $!\n";
        die "symbolic link rejected: $path\n" if -l _;
        return if -d _;
        die "unsupported filesystem node rejected: $path\n" unless -f _;
        push @files, $path;
      },
    }, $root);
    @files = sort { $a cmp $b } @files;
    my $aggregate = Digest::SHA->new(256);
    for my $path (@files) {
      my @before = lstat($path);
      die "lstat failed for $path: $!\n" unless @before;
      die "file changed type before hashing: $path\n" unless -f _ && !-l _;
      open my $file, "<:raw", $path or die "open failed for $path: $!\n";
      my $file_hash = Digest::SHA->new(256)->addfile($file)->hexdigest;
      close $file or die "close failed for $path: $!\n";
      my @after = lstat($path);
      die "file disappeared while hashing: $path\n" unless @after;
      for my $index (0, 1, 2, 7, 9, 10) {
        die "file changed while hashing: $path\n"
          if $before[$index] != $after[$index];
      }
      my $relative = substr($path, length($root) + 1);
      $aggregate->add($relative, "\0", $file_hash, "\0");
    }
    print $aggregate->hexdigest, "\n";
  ' -- "$root")"; then
    echo "Unable to hash release sysroot: $requested_root" >&2
    return 1
  fi
  if ! valid_sha256 "$digest"; then
    echo "Unable to hash release sysroot: $requested_root" >&2
    return 1
  fi
  /usr/bin/printf '%s\n' "$digest"
}

directory_tree_with_internal_symlinks_sha256() {
  local requested_root="$1"
  local root
  local digest

  if ! root="$(cd "$requested_root" 2>/dev/null && /bin/pwd -P)" \
    || [ "$root" != "${requested_root%/}" ]; then
    echo "Hash input must be a physical directory without symbolic-link path components: $requested_root" >&2
    return 1
  fi
  # Xcode SDKs and Clang resource directories contain intentional aliases.
  # Hash link text as part of the tree and accept a link only when its fully
  # resolved target remains inside the same pinned root.
  if ! digest="$(/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin \
    /usr/bin/perl -MCwd=abs_path -MDigest::SHA -MFile::Find -e '
      use strict;
      use warnings;
      use bytes;
      my $root = shift @ARGV;
      my @entries;
      File::Find::find({
        no_chdir => 1,
        follow => 0,
        wanted => sub {
          my $path = $File::Find::name;
          return if $path eq $root;
          my @before = lstat($path);
          die "lstat failed for $path: $!\n" unless @before;
          my $relative = substr($path, length($root) + 1);
          if (-l _) {
            my $target = readlink($path);
            die "readlink failed for $path: $!\n" unless defined $target;
            my $resolved = abs_path($path);
            die "broken symbolic link rejected: $path\n" unless defined $resolved;
            die "symbolic link escapes pinned root: $path\n"
              unless $resolved eq $root || index($resolved, "$root/") == 0;
            push @entries, [$relative, "link", $target, \@before];
            return;
          }
          return if -d _;
          die "unsupported filesystem node rejected: $path\n" unless -f _;
          push @entries, [$relative, "file", $path, \@before];
        },
      }, $root);
      @entries = sort { $a->[0] cmp $b->[0] } @entries;
      my $aggregate = Digest::SHA->new(256);
      for my $entry (@entries) {
        my ($relative, $kind, $value, $before) = @$entry;
        my $path = "$root/$relative";
        if ($kind eq "link") {
          my @after = lstat($path);
          die "symbolic link disappeared while hashing: $path\n" unless @after && -l _;
          my $target = readlink($path);
          die "symbolic link changed while hashing: $path\n"
            unless defined $target && $target eq $value;
          for my $index (0, 1, 2, 7, 9, 10) {
            die "symbolic link metadata changed while hashing: $path\n"
              if $before->[$index] != $after[$index];
          }
          $aggregate->add($relative, "\0link\0", $target, "\0");
          next;
        }
        my @current = lstat($path);
        die "file disappeared while hashing: $path\n" unless @current && -f _ && !-l _;
        open my $file, "<:raw", $path or die "open failed for $path: $!\n";
        my $file_hash = Digest::SHA->new(256)->addfile($file)->hexdigest;
        close $file or die "close failed for $path: $!\n";
        my @after = lstat($path);
        die "file disappeared while hashing: $path\n" unless @after && -f _ && !-l _;
        for my $index (0, 1, 2, 7, 9, 10) {
          die "file changed while hashing: $path\n"
            if $before->[$index] != $after[$index];
        }
        $aggregate->add($relative, "\0file\0", $file_hash, "\0");
      }
      print $aggregate->hexdigest, "\n";
    ' -- "$root")"; then
    echo "Unable to hash pinned Xcode directory: $requested_root" >&2
    return 1
  fi
  if ! valid_sha256 "$digest"; then
    echo "Unable to hash pinned Xcode directory: $requested_root" >&2
    return 1
  fi
  /usr/bin/printf '%s\n' "$digest"
}

macos_native_toolchain_sha256() {
  /usr/bin/printf '%s\0%s\0%s\0%s\0%s\0%s\0%s\0%s\0%s\0%s\0' \
    "$RELEASE_CLANG_SHA256" \
    "$RELEASE_CLANGXX_SHA256" \
    "$RELEASE_AR_SHA256" \
    "$RELEASE_LD_SHA256" \
    "$RELEASE_LD_TAPI_SHA256" \
    "$RELEASE_LD_CODEDIRECTORY_SHA256" \
    "$RELEASE_LD_LTO_SHA256" \
    "$RELEASE_LD_SWIFT_DEMANGLE_SHA256" \
    "$RELEASE_MACOS_SDK_SHA256" \
    "$RELEASE_CLANG_RESOURCE_DIR_SHA256" \
    | /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin /usr/bin/shasum -a 256 \
    | /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin /usr/bin/awk '{ print $1 }'
}

macos_release_materials_sha256() {
  /usr/bin/printf '%s\0%s\0%s\0%s\0%s\0%s\0%s\0' \
    "$RELEASE_GIT_SHA256" \
    "$RELEASE_CARGO_SHA256" \
    "$RELEASE_RUSTC_SHA256" \
    "$RELEASE_RUST_SYSROOT_SHA256" \
    "$RELEASE_NATIVE_TOOLCHAIN_SHA256" \
    "$RELEASE_NOTARYTOOL_SHA256" \
    "$RELEASE_STAPLER_SHA256" \
    | /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin /usr/bin/shasum -a 256 \
    | /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin /usr/bin/awk '{ print $1 }'
}

verify_release_file_sha256() {
  local path="$1"
  local expected="$2"
  local description="$3"
  local actual
  local canonical_path

  if [ ! -f "$path" ] || [ ! -x "$path" ] || [ -L "$path" ]; then
    echo "$description is no longer the pinned regular executable: $path" >&2
    return 1
  fi
  if ! canonical_path="$(canonical_executable_path "$path")" \
    || [ "$canonical_path" != "$path" ]; then
    echo "$description path now contains a symbolic-link component: $path" >&2
    return 1
  fi
  actual="$(release_tool_sha256 "$path")"
  if [ "$actual" != "$expected" ]; then
    echo "$description SHA-256 does not match its required release pin." >&2
    return 1
  fi
}

verify_release_toolchain_integrity() {
  local actual_sysroot
  local actual_sysroot_sha256
  local actual_sdk_sha256
  local actual_clang_resource_dir_sha256
  local actual_clang_resource_dir
  local actual_native_toolchain_sha256
  local actual_materials_sha256
  local build_developer_root="${RELEASE_BUILD_DEVELOPER_DIR:-$RELEASE_DEVELOPER_DIR}"

  verify_release_git_integrity || return 1
  verify_release_file_sha256 "$RELEASE_CARGO_BIN" "$RELEASE_CARGO_SHA256" "Cargo" || return 1
  verify_release_file_sha256 "$RELEASE_RUSTC_BIN" "$RELEASE_RUSTC_SHA256" "rustc" || return 1
  verify_release_tool_under_root "$RELEASE_CLANG_BIN" "$build_developer_root" "$RELEASE_CLANG_SHA256" "clang" || return 1
  verify_release_tool_under_root "$RELEASE_CLANGXX_BIN" "$build_developer_root" "$RELEASE_CLANGXX_SHA256" "clang++" || return 1
  verify_release_tool_under_root "$RELEASE_AR_BIN" "$build_developer_root" "$RELEASE_AR_SHA256" "ar" || return 1
  verify_release_tool_under_root "$RELEASE_LD_BIN" "$build_developer_root" "$RELEASE_LD_SHA256" "ld" || return 1
  verify_release_tool_under_root "$RELEASE_LD_TAPI_BIN" "$build_developer_root" "$RELEASE_LD_TAPI_SHA256" "ld libtapi" || return 1
  verify_release_tool_under_root "$RELEASE_LD_CODEDIRECTORY_BIN" "$build_developer_root" "$RELEASE_LD_CODEDIRECTORY_SHA256" "ld libcodedirectory" || return 1
  verify_release_tool_under_root "$RELEASE_LD_LTO_BIN" "$build_developer_root" "$RELEASE_LD_LTO_SHA256" "ld libLTO" || return 1
  verify_release_tool_under_root "$RELEASE_LD_SWIFT_DEMANGLE_BIN" "$build_developer_root" "$RELEASE_LD_SWIFT_DEMANGLE_SHA256" "ld libswiftDemangle" || return 1
  verify_release_tool_under_root "$RELEASE_NOTARYTOOL_BIN" "$RELEASE_DEVELOPER_DIR" "$RELEASE_NOTARYTOOL_SHA256" "notarytool" || return 1
  verify_release_tool_under_root "$RELEASE_STAPLER_BIN" "$RELEASE_DEVELOPER_DIR" "$RELEASE_STAPLER_SHA256" "stapler" || return 1

  if [ ! -d "$RELEASE_DEVELOPER_DIR" ] || [ -L "$RELEASE_DEVELOPER_DIR" ] \
    || [ "$(cd "$RELEASE_DEVELOPER_DIR" 2>/dev/null && /bin/pwd -P)" != "$RELEASE_DEVELOPER_DIR" ]; then
    echo "The explicitly selected Xcode Developer directory is no longer physical." >&2
    return 1
  fi
  if [ ! -d "$build_developer_root" ] || [ -L "$build_developer_root" ] \
    || [ "$(cd "$build_developer_root" 2>/dev/null && /bin/pwd -P)" != "$build_developer_root" ]; then
    echo "The build-time Xcode Developer snapshot is no longer physical." >&2
    return 1
  fi
  if [ "$(resolve_release_directory_under_root "$RELEASE_SDKROOT" "$build_developer_root" 'macOS SDK')" != "$RELEASE_SDKROOT" ]; then
    echo "The pinned macOS SDK path changed after release initialization." >&2
    return 1
  fi
  if [ "$(resolve_release_directory_under_root "$RELEASE_CLANG_RESOURCE_DIR" "$build_developer_root" 'Clang resource directory')" != "$RELEASE_CLANG_RESOURCE_DIR" ]; then
    echo "The pinned Clang resource directory changed after release initialization." >&2
    return 1
  fi

  actual_sysroot="$(/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin \
    "$RELEASE_RUSTC_BIN" --print sysroot)"
  if [ "$actual_sysroot" != "$RELEASE_RUST_SYSROOT" ]; then
    echo "rustc no longer reports the explicitly pinned Rust sysroot." >&2
    return 1
  fi
  actual_sysroot_sha256="$(directory_tree_sha256 "$RELEASE_RUST_SYSROOT")"
  if [ "$actual_sysroot_sha256" != "$RELEASE_RUST_SYSROOT_SHA256" ]; then
    echo "Rust sysroot SHA-256 does not match its required release pin." >&2
    return 1
  fi
  actual_sdk_sha256="$(directory_tree_with_internal_symlinks_sha256 "$RELEASE_SDKROOT")"
  if [ "$actual_sdk_sha256" != "$RELEASE_MACOS_SDK_SHA256" ]; then
    echo "macOS SDK SHA-256 does not match its required release pin." >&2
    return 1
  fi
  actual_clang_resource_dir_sha256="$(directory_tree_with_internal_symlinks_sha256 "$RELEASE_CLANG_RESOURCE_DIR")"
  if [ "$actual_clang_resource_dir_sha256" != "$RELEASE_CLANG_RESOURCE_DIR_SHA256" ]; then
    echo "Clang resource directory SHA-256 does not match its required release pin." >&2
    return 1
  fi
  actual_clang_resource_dir="$(/usr/bin/env -i \
    PATH=/usr/bin:/bin:/usr/sbin:/sbin \
    DEVELOPER_DIR="$build_developer_root" \
    SDKROOT="$RELEASE_SDKROOT" \
    "$RELEASE_CLANG_BIN" -print-resource-dir)" || return 1
  if [ "$(canonical_existing_path "$actual_clang_resource_dir")" != "$RELEASE_CLANG_RESOURCE_DIR" ]; then
    echo "Pinned build clang no longer reports its immutable resource snapshot." >&2
    return 1
  fi
  actual_native_toolchain_sha256="$(macos_native_toolchain_sha256)"
  if [ "$actual_native_toolchain_sha256" != "$RELEASE_NATIVE_TOOLCHAIN_SHA256" ]; then
    echo "Native toolchain aggregate SHA-256 no longer matches its required release pin." >&2
    return 1
  fi
  actual_materials_sha256="$(macos_release_materials_sha256)"
  if [ "$actual_materials_sha256" != "$RELEASE_MATERIALS_SHA256" ]; then
    echo "Release materials aggregate SHA-256 changed after release initialization." >&2
    return 1
  fi
}

verify_release_notarization_tools_integrity() {
  verify_release_tool_under_root "$RELEASE_NOTARYTOOL_BIN" "$RELEASE_DEVELOPER_DIR" "$RELEASE_NOTARYTOOL_SHA256" "notarytool" || return 1
  verify_release_tool_under_root "$RELEASE_STAPLER_BIN" "$RELEASE_DEVELOPER_DIR" "$RELEASE_STAPLER_SHA256" "stapler" || return 1
}

materialize_immutable_release_toolchain_snapshot() {
  local original_cargo="$RELEASE_CARGO_BIN"
  local original_rustc="$RELEASE_RUSTC_BIN"
  local original_rust_sysroot="$RELEASE_RUST_SYSROOT"
  local original_developer_dir="$RELEASE_DEVELOPER_DIR"
  local original_sdkroot="$RELEASE_SDKROOT"
  local original_clang_resource_dir="$RELEASE_CLANG_RESOURCE_DIR"
  local original_clang="$RELEASE_CLANG_BIN"
  local original_clangxx="$RELEASE_CLANGXX_BIN"
  local original_ar="$RELEASE_AR_BIN"
  local original_ld="$RELEASE_LD_BIN"
  local original_ld_tapi="$RELEASE_LD_TAPI_BIN"
  local original_ld_codedirectory="$RELEASE_LD_CODEDIRECTORY_BIN"
  local original_ld_lto="$RELEASE_LD_LTO_BIN"
  local original_ld_swift_demangle="$RELEASE_LD_SWIFT_DEMANGLE_BIN"
  local rust_snapshot
  local native_snapshot
  local source_path
  local relative_path
  local destination_path

  if [ -z "$RELEASE_PRIVATE_ROOT" ] || ! verify_private_release_root; then
    echo "Private release root is required before snapshotting the build toolchain." >&2
    return 1
  fi
  RELEASE_TOOLCHAIN_SNAPSHOT_ROOT="$RELEASE_PRIVATE_ROOT/build-toolchain"
  if [ -e "$RELEASE_TOOLCHAIN_SNAPSHOT_ROOT" ] \
    || [ -L "$RELEASE_TOOLCHAIN_SNAPSHOT_ROOT" ]; then
    echo "Release toolchain snapshot destination already exists." >&2
    return 1
  fi
  case "$original_cargo:$original_rustc" in
    "$original_rust_sysroot"/*:"$original_rust_sysroot"/*) ;;
    *) echo "Cargo and rustc must be inside the pinned Rust sysroot." >&2; return 1 ;;
  esac

  /bin/mkdir -m 700 "$RELEASE_TOOLCHAIN_SNAPSHOT_ROOT" || return 1
  rust_snapshot="$RELEASE_TOOLCHAIN_SNAPSHOT_ROOT/rust-sysroot"
  native_snapshot="$RELEASE_TOOLCHAIN_SNAPSHOT_ROOT/xcode-developer"
  /bin/cp -cR -P "$original_rust_sysroot" "$rust_snapshot" || return 1
  /bin/mkdir -p "$native_snapshot" || return 1

  for source_path in \
    "$original_clang" \
    "$original_clangxx" \
    "$original_ar" \
    "$original_ld" \
    "$original_ld_tapi" \
    "$original_ld_codedirectory" \
    "$original_ld_lto" \
    "$original_ld_swift_demangle"; do
    case "$source_path" in
      "$original_developer_dir"/*) ;;
      *) echo "Pinned native tool escaped the Xcode Developer directory." >&2; return 1 ;;
    esac
    relative_path="${source_path#"$original_developer_dir"/}"
    destination_path="$native_snapshot/$relative_path"
    /bin/mkdir -p "$(/usr/bin/dirname "$destination_path")" || return 1
    if [ -L "$source_path" ]; then
      /bin/cp -P "$source_path" "$destination_path" || return 1
    else
      /bin/cp -cP "$source_path" "$destination_path" || return 1
    fi
  done

  for source_path in "$original_sdkroot" "$original_clang_resource_dir"; do
    case "$source_path" in
      "$original_developer_dir"/*) ;;
      *) echo "Pinned native directory escaped the Xcode Developer directory." >&2; return 1 ;;
    esac
    relative_path="${source_path#"$original_developer_dir"/}"
    destination_path="$native_snapshot/$relative_path"
    /bin/mkdir -p "$(/usr/bin/dirname "$destination_path")" || return 1
    /bin/cp -cR -P "$source_path" "$destination_path" || return 1
  done

  RELEASE_CARGO_BIN="$rust_snapshot/${original_cargo#"$original_rust_sysroot"/}"
  RELEASE_RUSTC_BIN="$rust_snapshot/${original_rustc#"$original_rust_sysroot"/}"
  RELEASE_RUST_SYSROOT="$rust_snapshot"
  RELEASE_BUILD_DEVELOPER_DIR="$native_snapshot"
  RELEASE_SDKROOT="$native_snapshot/${original_sdkroot#"$original_developer_dir"/}"
  RELEASE_CLANG_RESOURCE_DIR="$native_snapshot/${original_clang_resource_dir#"$original_developer_dir"/}"
  RELEASE_CLANG_BIN="$native_snapshot/${original_clang#"$original_developer_dir"/}"
  RELEASE_CLANGXX_BIN="$native_snapshot/${original_clangxx#"$original_developer_dir"/}"
  RELEASE_AR_BIN="$native_snapshot/${original_ar#"$original_developer_dir"/}"
  RELEASE_LD_BIN="$native_snapshot/${original_ld#"$original_developer_dir"/}"
  RELEASE_LD_TAPI_BIN="$native_snapshot/${original_ld_tapi#"$original_developer_dir"/}"
  RELEASE_LD_CODEDIRECTORY_BIN="$native_snapshot/${original_ld_codedirectory#"$original_developer_dir"/}"
  RELEASE_LD_LTO_BIN="$native_snapshot/${original_ld_lto#"$original_developer_dir"/}"
  RELEASE_LD_SWIFT_DEMANGLE_BIN="$native_snapshot/${original_ld_swift_demangle#"$original_developer_dir"/}"

  capture_release_toolchain_snapshot_baseline
}

resolve_and_verify_release_toolchain() {
  local expected_rust_version
  local cargo_dir
  local rustc_dir
  local reported_sysroot
  local expected_developer_dir
  local expected_sdkroot
  local expected_clang_resource_dir
  local reported_clang_resource_dir

  RELEASE_CARGO_BIN="$(resolve_explicit_release_tool WAAL_RELEASE_CARGO_PATH Cargo)"
  RELEASE_RUSTC_BIN="$(resolve_explicit_release_tool WAAL_RELEASE_RUSTC_PATH rustc)"
  RELEASE_RUST_SYSROOT="$(resolve_explicit_release_directory WAAL_RELEASE_RUST_SYSROOT 'the Rust sysroot')"
  RELEASE_DEVELOPER_DIR="$(resolve_explicit_release_directory WAAL_MACOS_DEVELOPER_DIR 'the Xcode Developer directory')"
  expected_developer_dir="/Applications/Xcode.app/Contents/Developer"
  if [ "$RELEASE_DEVELOPER_DIR" != "$expected_developer_dir" ]; then
    echo "WAAL_MACOS_DEVELOPER_DIR must select the system Xcode Developer directory: $expected_developer_dir" >&2
    return 1
  fi
  RELEASE_CLANG_BIN="$RELEASE_DEVELOPER_DIR/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang"
  RELEASE_CLANGXX_BIN="$RELEASE_DEVELOPER_DIR/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang++"
  RELEASE_AR_BIN="$RELEASE_DEVELOPER_DIR/Toolchains/XcodeDefault.xctoolchain/usr/bin/ar"
  RELEASE_LD_BIN="$RELEASE_DEVELOPER_DIR/Toolchains/XcodeDefault.xctoolchain/usr/bin/ld"
  RELEASE_LD_TAPI_BIN="$RELEASE_DEVELOPER_DIR/Toolchains/XcodeDefault.xctoolchain/usr/lib/libtapi.dylib"
  RELEASE_LD_CODEDIRECTORY_BIN="$RELEASE_DEVELOPER_DIR/Toolchains/XcodeDefault.xctoolchain/usr/lib/libcodedirectory.dylib"
  RELEASE_LD_LTO_BIN="$RELEASE_DEVELOPER_DIR/Toolchains/XcodeDefault.xctoolchain/usr/lib/libLTO.dylib"
  RELEASE_LD_SWIFT_DEMANGLE_BIN="$RELEASE_DEVELOPER_DIR/Toolchains/XcodeDefault.xctoolchain/usr/lib/libswiftDemangle.dylib"
  RELEASE_NOTARYTOOL_BIN="$RELEASE_DEVELOPER_DIR/usr/bin/notarytool"
  RELEASE_STAPLER_BIN="$RELEASE_DEVELOPER_DIR/usr/bin/stapler"
  expected_sdkroot="${WAAL_MACOS_SDKROOT:-}"
  case "$expected_sdkroot" in
    /*) ;;
    *)
      echo "WAAL_MACOS_SDKROOT must be an explicit absolute path to a physical macOS SDK." >&2
      return 1
      ;;
  esac
  RELEASE_SDKROOT="$(resolve_release_directory_under_root "$expected_sdkroot" "$RELEASE_DEVELOPER_DIR" 'macOS SDK')"
  expected_clang_resource_dir="${WAAL_MACOS_CLANG_RESOURCE_DIR:-}"
  case "$expected_clang_resource_dir" in
    /*) ;;
    *)
      echo "WAAL_MACOS_CLANG_RESOURCE_DIR must be an explicit absolute path to the Clang resource directory." >&2
      return 1
      ;;
  esac
  RELEASE_CLANG_RESOURCE_DIR="$(resolve_release_directory_under_root "$expected_clang_resource_dir" "$RELEASE_DEVELOPER_DIR" 'Clang resource directory')"
  RELEASE_CARGO_SHA256="$(required_expected_sha256 WAAL_RELEASE_EXPECTED_CARGO_SHA256)"
  RELEASE_RUSTC_SHA256="$(required_expected_sha256 WAAL_RELEASE_EXPECTED_RUSTC_SHA256)"
  RELEASE_RUST_SYSROOT_SHA256="$(required_expected_sha256 WAAL_RELEASE_EXPECTED_RUST_SYSROOT_SHA256)"
  RELEASE_CLANG_SHA256="$(required_expected_sha256 WAAL_RELEASE_EXPECTED_CLANG_SHA256)"
  RELEASE_CLANGXX_SHA256="$(required_expected_sha256 WAAL_RELEASE_EXPECTED_CLANGXX_SHA256)"
  RELEASE_AR_SHA256="$(required_expected_sha256 WAAL_RELEASE_EXPECTED_AR_SHA256)"
  RELEASE_LD_SHA256="$(required_expected_sha256 WAAL_RELEASE_EXPECTED_LD_SHA256)"
  RELEASE_LD_TAPI_SHA256="$(required_expected_sha256 WAAL_RELEASE_EXPECTED_LD_TAPI_SHA256)"
  RELEASE_LD_CODEDIRECTORY_SHA256="$(required_expected_sha256 WAAL_RELEASE_EXPECTED_LD_CODEDIRECTORY_SHA256)"
  RELEASE_LD_LTO_SHA256="$(required_expected_sha256 WAAL_RELEASE_EXPECTED_LD_LTO_SHA256)"
  RELEASE_LD_SWIFT_DEMANGLE_SHA256="$(required_expected_sha256 WAAL_RELEASE_EXPECTED_LD_SWIFT_DEMANGLE_SHA256)"
  RELEASE_NOTARYTOOL_SHA256="$(required_expected_sha256 WAAL_RELEASE_EXPECTED_NOTARYTOOL_SHA256)"
  RELEASE_STAPLER_SHA256="$(required_expected_sha256 WAAL_RELEASE_EXPECTED_STAPLER_SHA256)"
  RELEASE_MACOS_SDK_SHA256="$(required_expected_sha256 WAAL_RELEASE_EXPECTED_MACOS_SDK_SHA256)"
  RELEASE_CLANG_RESOURCE_DIR_SHA256="$(required_expected_sha256 WAAL_RELEASE_EXPECTED_CLANG_RESOURCE_DIR_SHA256)"
  RELEASE_NATIVE_TOOLCHAIN_SHA256="$(required_expected_sha256 WAAL_RELEASE_EXPECTED_NATIVE_TOOLCHAIN_SHA256)"
  RELEASE_CARGO_VERSION="$(release_tool_version "$RELEASE_CARGO_BIN")"
  RELEASE_RUSTC_VERSION="$(release_tool_version "$RELEASE_RUSTC_BIN")"
  expected_rust_version="$(/usr/bin/awk -F '"' '/^[[:space:]]*rust-version[[:space:]]*=/ { print $2; exit }' "$RELEASE_SOURCE_DIR/Cargo.toml")"

  if [ -z "$expected_rust_version" ]; then
    echo "Release source Cargo.toml must pin rust-version." >&2
    return 1
  fi
  if [ "$RELEASE_CARGO_VERSION" != "$RELEASE_RUSTC_VERSION" ]; then
    echo "Release Cargo and rustc versions must match exactly." >&2
    return 1
  fi
  case "$RELEASE_RUSTC_VERSION" in
    "$expected_rust_version"|"$expected_rust_version".*) ;;
    *)
      echo "Release toolchain $RELEASE_RUSTC_VERSION does not match Cargo.toml rust-version $expected_rust_version." >&2
      return 1
      ;;
  esac

  cargo_dir="$(/usr/bin/dirname "$RELEASE_CARGO_BIN")"
  rustc_dir="$(/usr/bin/dirname "$RELEASE_RUSTC_BIN")"
  if [ "$cargo_dir" != "$rustc_dir" ]; then
    echo "Release Cargo and rustc must come from the same pinned toolchain directory." >&2
    return 1
  fi
  reported_sysroot="$(/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin \
    "$RELEASE_RUSTC_BIN" --print sysroot)"
  if [ "$reported_sysroot" != "$RELEASE_RUST_SYSROOT" ]; then
    echo "WAAL_RELEASE_RUST_SYSROOT does not match the sysroot reported by the pinned rustc." >&2
    return 1
  fi
  if [ ! -d "$RELEASE_RUST_SYSROOT/lib/rustlib/aarch64-apple-darwin/lib" ]; then
    echo "Pinned Rust sysroot does not contain the aarch64-apple-darwin standard library." >&2
    return 1
  fi
  reported_clang_resource_dir="$(/usr/bin/env -i \
    PATH=/usr/bin:/bin:/usr/sbin:/sbin \
    DEVELOPER_DIR="$RELEASE_DEVELOPER_DIR" \
    SDKROOT="$RELEASE_SDKROOT" \
    "$RELEASE_CLANG_BIN" -print-resource-dir)"
  if [ "$(canonical_existing_path "$reported_clang_resource_dir")" != "$RELEASE_CLANG_RESOURCE_DIR" ]; then
    echo "Pinned clang does not report WAAL_MACOS_CLANG_RESOURCE_DIR as its resource directory." >&2
    return 1
  fi
  if [ "$(macos_native_toolchain_sha256)" != "$RELEASE_NATIVE_TOOLCHAIN_SHA256" ]; then
    echo "WAAL_RELEASE_EXPECTED_NATIVE_TOOLCHAIN_SHA256 does not match the ordered clang/clang++/ar/ld/ld-runtime/SDK/resource-dir hash aggregate." >&2
    return 1
  fi
  RELEASE_MATERIALS_SHA256="$(macos_release_materials_sha256)"
  if ! valid_sha256 "$RELEASE_MATERIALS_SHA256"; then
    echo "Unable to compute the release materials aggregate SHA-256." >&2
    return 1
  fi

  verify_release_toolchain_integrity
}

resolve_and_verify_release_toolchain_guarded() {
  local resolution_status

  verify_release_source_identity_guard || return 1
  if resolve_and_verify_release_toolchain \
    && materialize_immutable_release_toolchain_snapshot; then
    resolution_status=0
  else
    resolution_status=$?
  fi
  verify_release_source_identity_guard || return 1
  if [ "$resolution_status" -ne 0 ]; then
    return "$resolution_status"
  fi
}

verify_release_build_toolchain_guard() {
  if [ "$RELEASE_TOOLCHAIN_SNAPSHOT_FREEZE_ATTEMPTED" = true ]; then
    verify_release_toolchain_snapshot_guard
    return
  fi
  if [ "$RELEASE_SNAPSHOT_REEXECUTED" = true ]; then
    echo "Release builds require an immutable private toolchain snapshot." >&2
    return 1
  fi
  # Sourced unit fixtures can exercise environment construction without
  # materializing the multi-gigabyte release snapshot.
  verify_release_toolchain_integrity
}

reject_cargo_config_in_ancestors() {
  local requested_dir="$1"
  local current
  local parent
  local candidate

  if ! current="$(cd "$requested_dir" 2>/dev/null && /bin/pwd -P)"; then
    echo "Unable to resolve isolated Cargo working directory." >&2
    return 1
  fi
  while :; do
    for candidate in "$current/.cargo/config" "$current/.cargo/config.toml"; do
      if [ -e "$candidate" ] || [ -L "$candidate" ]; then
        echo "External Cargo configuration is not allowed in a release build: $candidate" >&2
        return 1
      fi
    done
    parent="$(/usr/bin/dirname "$current")"
    [ "$parent" != "$current" ] || break
    current="$parent"
  done
}

prepare_isolated_release_cargo_home() {
  local candidate

  RELEASE_BUILD_HOME="$RELEASE_SOURCE_ROOT/build-home"
  RELEASE_CARGO_HOME="$RELEASE_SOURCE_ROOT/cargo-home"
  RELEASE_CARGO_WORK_DIR="$RELEASE_SOURCE_ROOT/cargo-work"
  RELEASE_BUILD_TMPDIR="$RELEASE_SOURCE_ROOT/tmp"

  /bin/mkdir -p \
    "$RELEASE_BUILD_HOME" \
    "$RELEASE_CARGO_HOME" \
    "$RELEASE_CARGO_WORK_DIR" \
    "$RELEASE_BUILD_TMPDIR"
  /bin/chmod 700 \
    "$RELEASE_BUILD_HOME" \
    "$RELEASE_CARGO_HOME" \
    "$RELEASE_CARGO_WORK_DIR" \
    "$RELEASE_BUILD_TMPDIR"

  reject_cargo_config_in_ancestors "$RELEASE_CARGO_WORK_DIR"
  for candidate in \
    "$RELEASE_CARGO_HOME/config" \
    "$RELEASE_CARGO_HOME/config.toml" \
    "$RELEASE_SOURCE_DIR/.cargo/config" \
    "$RELEASE_SOURCE_DIR/.cargo/config.toml"; do
    if [ -e "$candidate" ] || [ -L "$candidate" ]; then
      echo "Release builds do not accept Cargo configuration outside packager-owned flags: $candidate" >&2
      return 1
    fi
  done
}

release_encoded_rustflags() {
  local source_root="${RELEASE_SOURCE_DIR:-$ROOT_DIR}"
  local remap_source
  local encoded="--remap-path-prefix=$source_root=."

  for remap_source in "$source_root" "$ROOT_DIR"; do
    case "$remap_source" in
      ""|*$'\x1f'*|*$'\r'*|*$'\n'*)
        echo "Release source path contains a character unsafe for CARGO_ENCODED_RUSTFLAGS." >&2
        return 1
        ;;
    esac
  done
  if [ "$source_root" != "$ROOT_DIR" ]; then
    encoded+=$'\x1f'
    encoded+="--remap-path-prefix=$ROOT_DIR=."
  fi
  if [ -n "$RELEASE_LD_BIN" ]; then
    case "$RELEASE_LD_BIN" in
      *$'\x1f'*|*$'\r'*|*$'\n'*)
        echo "Pinned ld path contains a character unsafe for CARGO_ENCODED_RUSTFLAGS." >&2
        return 1
        ;;
    esac
    encoded+=$'\x1f-C\x1f'
    encoded+="link-arg=-fuse-ld=$RELEASE_LD_BIN"
  fi
  /usr/bin/printf '%s' "$encoded"
}

run_sanitized_release_cargo() {
  local encoded_rustflags
  local cargo_status
  encoded_rustflags="$(release_encoded_rustflags)"

  if [ -z "$RELEASE_BUILD_HOME" ] \
    || [ -z "$RELEASE_CARGO_HOME" ] \
    || [ -z "$RELEASE_CARGO_WORK_DIR" ] \
    || [ -z "$RELEASE_BUILD_TMPDIR" ]; then
    echo "The isolated release Cargo environment must be prepared before building." >&2
    return 1
  fi
  if [ ! -x "$RELEASE_CARGO_BIN" ] || [ ! -x "$RELEASE_RUSTC_BIN" ]; then
    echo "Release Cargo and rustc executables must be resolved before building." >&2
    return 1
  fi
  if ! valid_git_object_id "$RELEASE_GIT_COMMIT" || ! valid_git_object_id "$RELEASE_GIT_TREE"; then
    echo "Release Git provenance must be initialized before building." >&2
    return 1
  fi
  reject_cargo_config_in_ancestors "$RELEASE_CARGO_WORK_DIR"
  verify_release_source_identity_guard
  verify_release_build_toolchain_guard

  if (
    cd "$RELEASE_CARGO_WORK_DIR"
    /usr/bin/env -i \
      HOME="$RELEASE_BUILD_HOME" \
      CARGO_HOME="$RELEASE_CARGO_HOME" \
      TMPDIR="$RELEASE_BUILD_TMPDIR" \
      PATH=/usr/bin:/bin:/usr/sbin:/sbin \
      DEVELOPER_DIR="${RELEASE_BUILD_DEVELOPER_DIR:-$RELEASE_DEVELOPER_DIR}" \
      SDKROOT="$RELEASE_SDKROOT" \
      RUSTC="$RELEASE_RUSTC_BIN" \
      RUSTC_WRAPPER= \
      RUSTC_WORKSPACE_WRAPPER= \
      CARGO_ENCODED_RUSTFLAGS="$encoded_rustflags" \
      CARGO_TARGET_DIR="$BUILD_TARGET_DIR" \
      CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER="$RELEASE_CLANG_BIN" \
      CC="$RELEASE_CLANG_BIN" \
      CXX="$RELEASE_CLANGXX_BIN" \
      AR="$RELEASE_AR_BIN" \
      LD="$RELEASE_LD_BIN" \
      WAAL_PUBLISHABLE_RELEASE=0 \
      WAAL_LOCAL_SIGNED_RELEASE=1 \
      WAAL_RELEASE_BUNDLE_ID="$PRODUCTION_BUNDLE_ID" \
      WAAL_MACOS_TEAM_ID="$EXPECTED_TEAM_ID" \
      WAAL_RELEASE_GIT_COMMIT="$RELEASE_GIT_COMMIT" \
      WAAL_RELEASE_GIT_TREE="$RELEASE_GIT_TREE" \
      WAAL_RELEASE_CARGO_VERSION="$RELEASE_CARGO_VERSION" \
      WAAL_RELEASE_RUSTC_VERSION="$RELEASE_RUSTC_VERSION" \
      WAAL_RELEASE_CARGO_SHA256="$RELEASE_CARGO_SHA256" \
      WAAL_RELEASE_RUSTC_SHA256="$RELEASE_RUSTC_SHA256" \
      WAAL_RELEASE_RUST_SYSROOT_SHA256="$RELEASE_RUST_SYSROOT_SHA256" \
      WAAL_RELEASE_NATIVE_TOOLCHAIN_SHA256="$RELEASE_NATIVE_TOOLCHAIN_SHA256" \
      WAAL_RELEASE_MATERIALS_SHA256="$RELEASE_MATERIALS_SHA256" \
      "$RELEASE_CARGO_BIN" "$@"
  ); then
    cargo_status=0
  else
    cargo_status=$?
  fi
  verify_release_source_identity_guard || return 1
  verify_release_build_toolchain_guard || return 1
  if [ "$cargo_status" -ne 0 ]; then
    return "$cargo_status"
  fi
}

verify_release_dependency_graph() {
  local metadata_file="$STAGE_DIR/cargo-metadata.json"
  local unexpected_sources="$STAGE_DIR/cargo-metadata-unexpected-sources.txt"
  local path_package_count

  run_sanitized_release_cargo metadata \
    --locked \
    --format-version 1 \
    --filter-platform aarch64-apple-darwin \
    --manifest-path "$RELEASE_SOURCE_DIR/Cargo.toml" \
    >"$metadata_file"

  path_package_count="$(/usr/bin/grep -o '"source":null' "$metadata_file" | /usr/bin/wc -l | /usr/bin/tr -d ' ')"
  if [ "$path_package_count" != "1" ]; then
    echo "Release dependency graph contains an external or additional path package." >&2
    return 1
  fi

  /usr/bin/grep -o '"source":"[^"]*"' "$metadata_file" \
    | /usr/bin/grep -v '^"source":"registry+https://github.com/rust-lang/crates.io-index"$' \
    >"$unexpected_sources" || true
  if [ -s "$unexpected_sources" ]; then
    echo "Release dependency graph contains a non-crates.io source:" >&2
    /bin/cat "$unexpected_sources" >&2
    return 1
  fi
}

validate_release_environment() {
  if [ "$RELEASE" != true ] || [ "$LOCAL_SIGNED_RELEASE" != true ]; then
    echo "Refusing to create a local signed macOS ZIP without --local-signed-release." >&2
    echo "The local packager never produces a publishable or producer-attested artifact." >&2
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
}

prepare_dist_root_for_root() {
  local requested_root="$1"
  local physical_root
  local dist_root
  local physical_dist_root

  if ! physical_root="$(cd "$requested_root" 2>/dev/null && /bin/pwd -P)"; then
    echo "Unable to resolve release output root." >&2
    return 1
  fi
  dist_root="$physical_root/dist"
  if [ -L "$dist_root" ]; then
    echo "Refusing to use a symlinked dist directory: $dist_root" >&2
    return 1
  fi
  if [ -e "$dist_root" ] && [ ! -d "$dist_root" ]; then
    echo "Release dist path must be a real directory: $dist_root" >&2
    return 1
  fi

  /bin/mkdir -p "$dist_root"
  if [ -L "$dist_root" ]; then
    echo "Refusing to use a symlinked dist directory: $dist_root" >&2
    return 1
  fi
  if ! physical_dist_root="$(cd "$dist_root" 2>/dev/null && /bin/pwd -P)" \
    || [ "$physical_dist_root" != "$dist_root" ]; then
    echo "Release dist directory does not resolve to the expected physical path." >&2
    return 1
  fi
}

prepare_dist_root() {
  prepare_dist_root_for_root "$ROOT_DIR"
}

directory_identity() {
  local path="$1"

  if [ ! -d "$path" ] || [ -L "$path" ]; then
    return 1
  fi
  /usr/bin/stat -f '%d:%i' "$path"
}

require_no_acl() {
  local path="$1"
  local description="${2:-Release path}"
  local listing

  if ! listing="$(/usr/bin/env -i \
    PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C \
    /bin/ls -lde "$path" 2>/dev/null)"; then
    echo "Unable to inspect access controls for $description: $path" >&2
    return 1
  fi
  if /usr/bin/printf '%s\n' "$listing" \
    | /usr/bin/grep -Eq '^[[:space:]]+[0-9]+:'; then
    echo "$description must not have an access control list: $path" >&2
    return 1
  fi
}

verify_private_release_parent_security() {
  local path="$1"
  local owner_uid
  local current_uid
  local mode
  local without_other
  local group_digit
  local other_digit

  if [ ! -d "$path" ] || [ -L "$path" ]; then
    echo "Private release parent must be a physical directory: $path" >&2
    return 1
  fi
  require_no_acl "$path" "Private release parent" || return 1
  owner_uid="$(/usr/bin/stat -f '%u' "$path")"
  current_uid="$(/usr/bin/id -u)"
  mode="$(/usr/bin/stat -f '%Lp' "$path")"
  other_digit="${mode#${mode%?}}"
  without_other="${mode%?}"
  group_digit="${without_other#${without_other%?}}"
  if [ "$owner_uid" != "$current_uid" ]; then
    echo "Private release parent is not owned by the current user: $path" >&2
    return 1
  fi
  case "$group_digit:$other_digit" in
    [2367]:*|*:[2367])
      echo "Private release parent must not be group- or world-writable: $path" >&2
      return 1
      ;;
  esac
}

verify_private_release_root() {
  local physical_parent
  local physical_root
  local parent_id
  local root_id
  local leaf
  local suffix

  if [ -z "$RELEASE_PRIVATE_ROOT" ] \
    || [ -z "$RELEASE_PRIVATE_ROOT_PARENT" ] \
    || [ -z "$RELEASE_PRIVATE_ROOT_ID" ] \
    || [ -z "$RELEASE_PRIVATE_ROOT_PARENT_ID" ]; then
    echo "Private release root identity is not initialized." >&2
    return 1
  fi
  case "$RELEASE_PRIVATE_ROOT:$RELEASE_PRIVATE_ROOT_PARENT" in
    /*:/*) ;;
    *)
      echo "Private release root paths must be absolute." >&2
      return 1
      ;;
  esac
  leaf="$(/usr/bin/basename "$RELEASE_PRIVATE_ROOT")"
  suffix="${leaf#.package_macos.}"
  case "$leaf:$suffix" in
    .package_macos.*:[A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9]) ;;
    *)
      echo "Private release root has an unexpected leaf name." >&2
      return 1
      ;;
  esac
  if [ "$(/usr/bin/dirname "$RELEASE_PRIVATE_ROOT")" != "$RELEASE_PRIVATE_ROOT_PARENT" ]; then
    echo "Private release root is outside its recorded parent." >&2
    return 1
  fi
  if ! physical_parent="$(cd "$RELEASE_PRIVATE_ROOT_PARENT" 2>/dev/null && /bin/pwd -P)" \
    || [ "$physical_parent" != "$RELEASE_PRIVATE_ROOT_PARENT" ]; then
    echo "Private release root parent is no longer a physical path." >&2
    return 1
  fi
  if ! parent_id="$(directory_identity "$RELEASE_PRIVATE_ROOT_PARENT")" \
    || [ "$parent_id" != "$RELEASE_PRIVATE_ROOT_PARENT_ID" ]; then
    echo "Private release root parent identity changed." >&2
    return 1
  fi
  verify_private_release_parent_security "$RELEASE_PRIVATE_ROOT_PARENT" || return 1
  if ! physical_root="$(cd "$RELEASE_PRIVATE_ROOT" 2>/dev/null && /bin/pwd -P)" \
    || [ "$physical_root" != "$RELEASE_PRIVATE_ROOT" ]; then
    echo "Private release root is no longer a physical path." >&2
    return 1
  fi
  if ! root_id="$(directory_identity "$RELEASE_PRIVATE_ROOT")" \
    || [ "$root_id" != "$RELEASE_PRIVATE_ROOT_ID" ]; then
    echo "Private release root identity changed." >&2
    return 1
  fi
  require_no_acl "$RELEASE_PRIVATE_ROOT" "Private release root" || return 1
}

create_private_release_root_for_root() {
  local requested_root="$1"
  local physical_root
  local private_parent
  local private_root
  local previous_umask
  local owner_uid
  local current_uid
  local mode

  prepare_dist_root_for_root "$requested_root" || return 1
  if ! physical_root="$(cd "$requested_root" 2>/dev/null && /bin/pwd -P)"; then
    echo "Unable to resolve the private release root owner." >&2
    return 1
  fi
  private_parent="$physical_root/dist"
  if [ -L "$private_parent" ] \
    || [ "$(cd "$private_parent" 2>/dev/null && /bin/pwd -P)" != "$private_parent" ]; then
    echo "Private release root parent must be a physical directory." >&2
    return 1
  fi
  verify_private_release_parent_security "$private_parent" || return 1

  RELEASE_PRIVATE_ROOT_PARENT="$private_parent"
  RELEASE_PRIVATE_ROOT_PARENT_ID="$(directory_identity "$private_parent")" || return 1
  previous_umask="$(umask)"
  umask 077
  if ! private_root="$(/usr/bin/mktemp -d "$private_parent/.package_macos.XXXXXX")"; then
    umask "$previous_umask"
    return 1
  fi
  umask "$previous_umask"

  RELEASE_PRIVATE_ROOT="$private_root"
  /bin/chmod -N "$RELEASE_PRIVATE_ROOT"
  /bin/chmod 700 "$RELEASE_PRIVATE_ROOT"
  if [ -L "$RELEASE_PRIVATE_ROOT" ] \
    || [ "$(cd "$RELEASE_PRIVATE_ROOT" 2>/dev/null && /bin/pwd -P)" != "$RELEASE_PRIVATE_ROOT" ]; then
    echo "mktemp did not create a physical private release directory." >&2
    return 1
  fi
  RELEASE_PRIVATE_ROOT_ID="$(directory_identity "$RELEASE_PRIVATE_ROOT")" || return 1
  owner_uid="$(/usr/bin/stat -f '%u' "$RELEASE_PRIVATE_ROOT")"
  current_uid="$(/usr/bin/id -u)"
  mode="$(/usr/bin/stat -f '%Lp' "$RELEASE_PRIVATE_ROOT")"
  if [ "$owner_uid" != "$current_uid" ] || [ "$mode" != "700" ]; then
    echo "Private release root ownership or mode is unsafe." >&2
    return 1
  fi
  verify_private_release_root || return 1

  STAGE_DIR="$RELEASE_PRIVATE_ROOT/stage"
  RELEASE_TEMP_DIR="$RELEASE_PRIVATE_ROOT/tmp"
  RELEASE_SOURCE_ROOT="$RELEASE_PRIVATE_ROOT/source-environment"
  /bin/mkdir -m 700 "$STAGE_DIR" "$RELEASE_TEMP_DIR" "$RELEASE_SOURCE_ROOT"
}

create_private_release_root() {
  create_private_release_root_for_root "$ROOT_DIR"
}

private_release_mktemp() {
  local label="$1"
  local physical_temp
  local candidate

  case "$label" in
    ""|*[!A-Za-z0-9._-]*|.|..)
      echo "Private temporary-file label is unsafe: $label" >&2
      return 1
      ;;
  esac
  verify_private_release_root || return 1
  case "$RELEASE_TEMP_DIR" in
    "$RELEASE_PRIVATE_ROOT"/*) ;;
    *)
      echo "Private temporary directory is outside the release root." >&2
      return 1
      ;;
  esac
  if ! physical_temp="$(cd "$RELEASE_TEMP_DIR" 2>/dev/null && /bin/pwd -P)" \
    || [ "$physical_temp" != "$RELEASE_TEMP_DIR" ]; then
    echo "Private temporary directory is not a physical path." >&2
    return 1
  fi
  candidate="$(/usr/bin/mktemp "$RELEASE_TEMP_DIR/$label.XXXXXX")" || return 1
  /bin/chmod 600 "$candidate"
  if [ ! -f "$candidate" ] || [ -L "$candidate" ]; then
    echo "mktemp did not create a regular private temporary file." >&2
    return 1
  fi
  /usr/bin/printf '%s\n' "$candidate"
}

release_archive_filename() {
  local archive_base="$1"
  local commit="$2"

  case "$archive_base" in
    ""|.|..|*/*|*$'\r'*|*$'\n'*)
      echo "Release archive base is not a safe filename: $archive_base" >&2
      return 1
      ;;
  esac
  if ! valid_git_object_id "$commit"; then
    echo "Release archive filename requires an exact lowercase 40-hex commit." >&2
    return 1
  fi
  /usr/bin/printf '%s-%s.zip\n' "$archive_base" "$commit"
}

initialize_release_publication_paths() {
  local archive_filename

  archive_filename="$(release_archive_filename "$RELEASE_ARCHIVE_BASE" "$RELEASE_GIT_COMMIT")"
  ZIP_PATH="$ROOT_DIR/dist/$archive_filename"
  ZIP_SHA256_PATH="$ZIP_PATH.sha256"
}

verify_release_publication_parent() {
  local expected_parent="$RELEASE_PRIVATE_ROOT_PARENT"
  local archive_parent
  local sidecar_parent
  local physical_parent
  local parent_id

  if [ -z "$ZIP_PATH" ] || [ -z "$ZIP_SHA256_PATH" ] || [ -z "$expected_parent" ]; then
    echo "Release publication paths are not initialized." >&2
    return 1
  fi
  archive_parent="$(/usr/bin/dirname "$ZIP_PATH")"
  sidecar_parent="$(/usr/bin/dirname "$ZIP_SHA256_PATH")"
  if [ "$archive_parent" != "$expected_parent" ] || [ "$sidecar_parent" != "$expected_parent" ]; then
    echo "Release publication paths escaped the verified dist directory." >&2
    return 1
  fi
  if ! physical_parent="$(cd "$expected_parent" 2>/dev/null && /bin/pwd -P)" \
    || [ "$physical_parent" != "$expected_parent" ]; then
    echo "Release publication parent is no longer a physical path." >&2
    return 1
  fi
  if ! parent_id="$(directory_identity "$expected_parent")" \
    || [ "$parent_id" != "$RELEASE_PRIVATE_ROOT_PARENT_ID" ]; then
    echo "Release publication parent identity changed." >&2
    return 1
  fi
  verify_private_release_parent_security "$expected_parent" || return 1
}

release_publication_state() {
  local archive_exists=false
  local sidecar_exists=false
  local path

  verify_release_publication_parent || return 1
  for path in "$ZIP_PATH" "$ZIP_SHA256_PATH"; do
    if [ -L "$path" ]; then
      echo "Immutable release artifact must not be a symbolic link: $path" >&2
      return 1
    fi
    if [ -e "$path" ]; then
      require_public_release_file "$path" \
        "Immutable release artifact" || return 1
      if [ "$path" = "$ZIP_PATH" ]; then
        archive_exists=true
      else
        sidecar_exists=true
      fi
    fi
  done

  if [ "$archive_exists" = false ] && [ "$sidecar_exists" = true ]; then
    echo "Refusing unsupported sidecar-only immutable release state: $ZIP_SHA256_PATH" >&2
    return 1
  fi
  if [ "$archive_exists" = true ] && [ "$sidecar_exists" = true ]; then
    /usr/bin/printf 'complete\n'
  elif [ "$archive_exists" = true ]; then
    /usr/bin/printf 'archive-only\n'
  else
    /usr/bin/printf 'empty\n'
  fi
}

require_single_link_regular_file() {
  local path="$1"
  local description="${2:-Release file}"

  if [ ! -f "$path" ] || [ -L "$path" ] \
    || [ "$(/usr/bin/stat -f '%l' "$path" 2>/dev/null)" != 1 ]; then
    echo "$description must be a single-link regular file: $path" >&2
    return 1
  fi
}

require_public_release_file() {
  local path="$1"
  local description="${2:-Release artifact}"
  local mode

  require_single_link_regular_file "$path" "$description" || return 1
  require_no_acl "$path" "$description" || return 1
  mode="$(/usr/bin/stat -f '%Mp%Lp' "$path" 2>/dev/null)" || return 1
  if [ "$mode" != 0644 ]; then
    echo "$description must have mode 0644: $path" >&2
    return 1
  fi
}

ensure_release_publication_state_supported() {
  release_publication_state >/dev/null
}

prepare_atomic_no_replace_rename_helper() {
  # Publication is performed by pinned /usr/bin/perl syscalls below. Keeping
  # the operation in the already-running interpreter removes the former
  # hash-then-exec race on a freshly compiled helper pathname.
  verify_release_build_toolchain_guard
  prepare_archive_snapshot_helper
}

prepare_archive_snapshot_helper() {
  # Archive inode operations run as fixed Perl source in the already pinned
  # system interpreter. No mutable, freshly compiled pathname is executed.
  verify_release_build_toolchain_guard
}

verify_archive_snapshot_helper_integrity() {
  if [ ! -f /usr/bin/perl ] || [ ! -x /usr/bin/perl ] || [ -L /usr/bin/perl ]; then
    echo "Pinned system interpreter for inode-bound archive operations is unavailable." >&2
    return 1
  fi
}

run_archive_snapshot_operation() {
  local operation="$1"
  shift

  verify_archive_snapshot_helper_integrity || return 1
  /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin \
    /usr/bin/perl -MFcntl=:DEFAULT,:mode -MTime::HiRes=stat -e '
      use strict;
      use warnings;
      my $operation = shift @ARGV;
      my $O_DIRECTORY = 0x00100000;
      my $O_CLOEXEC = 0x01000000;
      my $O_NOFOLLOW = 0x00000100;
      my $SYS_OPENAT = 463;
      my $SYS_FSYNC = 95;
      sub valid_leaf {
        my ($leaf) = @_;
        return length($leaf) && $leaf ne "." && $leaf ne ".."
          && index($leaf, "/") < 0 && index($leaf, "\0") < 0;
      }
      sub directory_id {
        my ($handle) = @_;
        my @status = stat($handle);
        die "inspect archive directory: $!\n" unless @status && S_ISDIR($status[2]);
        return "$status[0]:$status[1]";
      }
      sub open_directory {
        my ($path, $expected) = @_;
        sysopen(my $handle, $path,
          O_RDONLY | $O_DIRECTORY | $O_NOFOLLOW | $O_CLOEXEC)
          or die "open archive directory: $!\n";
        die "archive directory identity changed\n"
          unless directory_id($handle) eq $expected;
        return $handle;
      }
      sub open_regular_at {
        my ($directory, $leaf, $flags, $mode) = @_;
        die "unsafe archive leaf\n" unless valid_leaf($leaf);
        my $fd = syscall($SYS_OPENAT, fileno($directory), $leaf, $flags, $mode // 0);
        die "open archive file: $!\n" if $fd < 0;
        my $direction = ($flags & O_WRONLY) ? ">&=$fd" : "<&=$fd";
        open(my $handle, $direction) or die "adopt archive descriptor: $!\n";
        return $handle;
      }
      sub regular_status {
        my ($handle) = @_;
        my @status = stat($handle);
        die "archive file is not single-link regular content\n"
          unless @status && S_ISREG($status[2]) && $status[3] == 1;
        return @status;
      }
      sub public_status {
        my ($handle) = @_;
        my @status = regular_status($handle);
        die "published archive does not have mode 0644\n"
          unless (($status[2] & 07777) == 0644);
        return @status;
      }
      sub same_status {
        my ($left, $right) = @_;
        return $left->[0] == $right->[0] && $left->[1] == $right->[1]
          && $left->[2] == $right->[2] && $left->[3] == $right->[3]
          && $left->[4] == $right->[4] && $left->[5] == $right->[5]
          && $left->[7] == $right->[7] && $left->[9] == $right->[9]
          && $left->[10] == $right->[10];
      }
      sub identity {
        my ($status) = @_;
        return join(":", @$status[0, 1, 2, 3, 7],
          sprintf("%.9f", $status->[9]), sprintf("%.9f", $status->[10]));
      }
      sub compare_streams {
        my ($left, $right) = @_;
        while (1) {
          my ($left_bytes, $right_bytes) = ("", "");
          my $left_count = sysread($left, $left_bytes, 65536);
          my $right_count = sysread($right, $right_bytes, 65536);
          die "read archive comparison: $!\n"
            unless defined($left_count) && defined($right_count);
          die "archive bytes differ\n"
            unless $left_count == $right_count && $left_bytes eq $right_bytes;
          last if $left_count == 0;
        }
      }
      if ($operation eq "rewind-fd") {
        defined(sysseek(STDIN, 0, 0)) or die "rewind archive descriptor: $!\n";
        exit 0;
      }
      if ($operation eq "check-fd") {
        my ($expected) = @ARGV;
        my @status = regular_status(*STDIN);
        die "archive descriptor identity changed\n" unless identity(\@status) eq $expected;
        exit 0;
      }
      if ($operation eq "bind-fd") {
        my ($path, $leaf, $directory_id) = @ARGV;
        my $directory = open_directory($path, $directory_id);
        my @descriptor = regular_status(*STDIN);
        my $path_handle = open_regular_at($directory, $leaf,
          O_RDONLY | $O_NOFOLLOW | $O_CLOEXEC);
        my @path_status = regular_status($path_handle);
        die "archive descriptor does not match its pathname\n"
          unless same_status(\@descriptor, \@path_status);
        print identity(\@descriptor), "\n";
        exit 0;
      }
      if ($operation eq "copy") {
        my ($source_path, $source_leaf, $source_id,
            $destination_path, $destination_leaf, $destination_id) = @ARGV;
        my $source_directory = open_directory($source_path, $source_id);
        my $destination_directory = open_directory($destination_path, $destination_id);
        my $source = open_regular_at($source_directory, $source_leaf,
          O_RDONLY | $O_NOFOLLOW | $O_CLOEXEC);
        my @source_initial = public_status($source);
        my $destination = open_regular_at($destination_directory, $destination_leaf,
          O_WRONLY | O_CREAT | O_EXCL | $O_NOFOLLOW | $O_CLOEXEC, 0600);
        while (1) {
          my $bytes = "";
          my $count = sysread($source, $bytes, 65536);
          die "read archive snapshot: $!\n" unless defined($count);
          last if $count == 0;
          my $offset = 0;
          while ($offset < $count) {
            my $written = syswrite($destination, $bytes, $count - $offset, $offset);
            die "write archive snapshot: $!\n" unless defined($written) && $written > 0;
            $offset += $written;
          }
        }
        syscall($SYS_FSYNC, fileno($destination)) == 0
          or die "flush archive snapshot: $!\n";
        my @source_final = public_status($source);
        my $source_path_check = open_regular_at($source_directory, $source_leaf,
          O_RDONLY | $O_NOFOLLOW | $O_CLOEXEC);
        my @source_path_status = public_status($source_path_check);
        die "published archive changed during snapshot\n"
          unless same_status(\@source_initial, \@source_final)
            && same_status(\@source_initial, \@source_path_status);
        print identity(\@source_initial), "\n";
        exit 0;
      }
      if ($operation eq "verify") {
        my ($source_path, $source_leaf, $source_id,
            $snapshot_path, $snapshot_leaf, $snapshot_id, $expected) = @ARGV;
        my $source_directory = open_directory($source_path, $source_id);
        my $snapshot_directory = open_directory($snapshot_path, $snapshot_id);
        my $source = open_regular_at($source_directory, $source_leaf,
          O_RDONLY | $O_NOFOLLOW | $O_CLOEXEC);
        my $snapshot = open_regular_at($snapshot_directory, $snapshot_leaf,
          O_RDONLY | $O_NOFOLLOW | $O_CLOEXEC);
        my @source_initial = public_status($source);
        my @snapshot_initial = regular_status($snapshot);
        die "published archive identity changed\n"
          unless identity(\@source_initial) eq $expected
            && $source_initial[7] == $snapshot_initial[7];
        compare_streams($source, $snapshot);
        my @source_final = public_status($source);
        my @snapshot_final = regular_status($snapshot);
        my $source_path_check = open_regular_at($source_directory, $source_leaf,
          O_RDONLY | $O_NOFOLLOW | $O_CLOEXEC);
        my $snapshot_path_check = open_regular_at($snapshot_directory, $snapshot_leaf,
          O_RDONLY | $O_NOFOLLOW | $O_CLOEXEC);
        my @source_path_status = public_status($source_path_check);
        my @snapshot_path_status = regular_status($snapshot_path_check);
        die "archive changed during final comparison\n"
          unless same_status(\@source_initial, \@source_final)
            && same_status(\@source_initial, \@source_path_status)
            && same_status(\@snapshot_initial, \@snapshot_final)
            && same_status(\@snapshot_initial, \@snapshot_path_status);
        exit 0;
      }
      die "invalid inode-bound archive operation\n";
    ' -- "$operation" "$@"
}

capture_published_archive_snapshot() {
  local published_path="$1"
  local snapshot_path="$2"
  local published_parent
  local snapshot_parent
  local identity

  verify_release_publication_parent || return 1
  verify_private_release_root || return 1
  verify_archive_snapshot_helper_integrity || return 1
  require_public_release_file "$published_path" \
    "Published archive" || return 1
  published_parent="$(/usr/bin/dirname "$published_path")"
  snapshot_parent="$(/usr/bin/dirname "$snapshot_path")"
  if [ "$published_parent" != "$RELEASE_PRIVATE_ROOT_PARENT" ] \
    || [ "$snapshot_parent" != "$STAGE_DIR" ] \
    || [ -e "$snapshot_path" ] || [ -L "$snapshot_path" ]; then
    echo "Published archive snapshot paths are not securely anchored." >&2
    return 1
  fi
  if ! identity="$(
    run_archive_snapshot_operation copy \
      "$published_parent" "$(/usr/bin/basename "$published_path")" \
      "$(directory_identity "$published_parent")" \
      "$snapshot_parent" "$(/usr/bin/basename "$snapshot_path")" \
      "$(directory_identity "$snapshot_parent")"
  )"; then
    return 1
  fi
  case "$identity" in
    *[!0-9:.]*)
      echo "Published archive snapshot returned an invalid inode identity." >&2
      return 1
      ;;
  esac
  if [ ! -f "$snapshot_path" ] || [ -L "$snapshot_path" ] \
    || [ "$(/usr/bin/stat -f '%l' "$snapshot_path")" != 1 ]; then
    echo "Private published-archive snapshot is not a single-link regular file." >&2
    return 1
  fi
  /bin/chmod 400 "$snapshot_path"
  /usr/bin/printf '%s\n' "$identity"
}

verify_published_archive_matches_snapshot() {
  local published_path="$1"
  local snapshot_path="$2"
  local expected_identity="$3"
  local expected_sha256="$4"
  local snapshot_sha256
  local published_parent
  local snapshot_parent

  verify_release_publication_parent || return 1
  verify_archive_snapshot_helper_integrity || return 1
  if ! valid_sha256 "$expected_sha256"; then
    echo "Verified archive snapshot evidence is invalid." >&2
    return 1
  fi
  require_single_link_regular_file "$snapshot_path" \
    "Verified archive snapshot" || return 1
  require_public_release_file "$published_path" \
    "Published archive" || return 1
  snapshot_sha256="$(release_tool_sha256 "$snapshot_path")"
  if [ "$snapshot_sha256" != "$expected_sha256" ]; then
    echo "Private published-archive snapshot changed after verification." >&2
    return 1
  fi
  published_parent="$(/usr/bin/dirname "$published_path")"
  snapshot_parent="$(/usr/bin/dirname "$snapshot_path")"
  run_archive_snapshot_operation verify \
    "$published_parent" "$(/usr/bin/basename "$published_path")" \
    "$(directory_identity "$published_parent")" \
    "$snapshot_parent" "$(/usr/bin/basename "$snapshot_path")" \
    "$(directory_identity "$snapshot_parent")" "$expected_identity"
}

atomic_publish_file_no_replace() {
  local source_path="$1"
  local destination_path="$2"
  local expected_sha256="$3"
  local source_parent
  local destination_parent
  local physical_source_parent
  local physical_destination_parent
  local source_parent_id
  local destination_parent_id

  require_public_release_file "$source_path" \
    "Publication candidate" || return 1
  if ! valid_sha256 "$expected_sha256"; then
    echo "Publication candidate requires an exact expected SHA-256." >&2
    return 1
  fi
  case "$source_path:$destination_path" in
    /*:/*) ;;
    *)
      echo "Publication paths must be absolute." >&2
      return 1
      ;;
  esac

  source_parent="$(/usr/bin/dirname "$source_path")"
  destination_parent="$(/usr/bin/dirname "$destination_path")"
  if ! physical_source_parent="$(cd "$source_parent" 2>/dev/null && /bin/pwd -P)" \
    || [ "$physical_source_parent" != "$source_parent" ]; then
    echo "Publication candidate directory must be a physical path." >&2
    return 1
  fi
  if ! physical_destination_parent="$(cd "$destination_parent" 2>/dev/null && /bin/pwd -P)" \
    || [ "$physical_destination_parent" != "$destination_parent" ]; then
    echo "Publication destination directory must be a physical path." >&2
    return 1
  fi
  source_parent_id="$(directory_identity "$source_parent")" || return 1
  destination_parent_id="$(directory_identity "$destination_parent")" || return 1

  if ! /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin \
    /usr/bin/perl -MDigest::SHA -MFcntl=:DEFAULT,:mode -e '
      use strict;
      use warnings;
      my ($source_dir, $source_leaf, $source_dir_id, $expected_sha,
          $destination_dir, $destination_leaf, $destination_dir_id) = @ARGV;
      my $O_DIRECTORY = 0x00100000;
      my $O_CLOEXEC = 0x01000000;
      my $O_NOFOLLOW = 0x00000100;
      my $CLONE_NOFOLLOW = 0x0001;
      my $SYS_OPENAT = 463;
      my $SYS_UNLINKAT = 472;
      my $SYS_FCLONEFILEAT = 517;
      my $SYS_FSYNC = 95;
      sub valid_leaf {
        my ($leaf) = @_;
        return length($leaf) && $leaf ne "." && $leaf ne ".."
          && index($leaf, "/") < 0 && index($leaf, "\0") < 0;
      }
      sub directory_id {
        my ($handle) = @_;
        my @status = stat($handle);
        die "inspect publication directory: $!\n" unless @status && S_ISDIR($status[2]);
        return "$status[0]:$status[1]";
      }
      sub open_at {
        my ($directory_fd, $leaf, $flags) = @_;
        my $fd = syscall($SYS_OPENAT, $directory_fd, $leaf, $flags, 0);
        die "open publication file: $!\n" if $fd < 0;
        open(my $handle, "<&=$fd") or die "adopt publication descriptor: $!\n";
        return $handle;
      }
      sub file_status {
        my ($handle) = @_;
        my @status = stat($handle);
        die "publication file is not single-link regular mode-0644 content\n"
          unless @status && S_ISREG($status[2]) && $status[3] == 1
            && (($status[2] & 07777) == 0644);
        return @status;
      }
      sub same_file {
        my ($left, $right) = @_;
        return $left->[0] == $right->[0] && $left->[1] == $right->[1]
          && $left->[2] == $right->[2] && $left->[3] == $right->[3]
          && $left->[7] == $right->[7] && $left->[9] == $right->[9]
          && $left->[10] == $right->[10];
      }
      die "unsafe publication leaf\n"
        unless valid_leaf($source_leaf) && valid_leaf($destination_leaf);
      sysopen(my $source_directory, $source_dir,
        O_RDONLY | $O_DIRECTORY | $O_NOFOLLOW | $O_CLOEXEC)
        or die "open source publication directory: $!\n";
      sysopen(my $destination_directory, $destination_dir,
        O_RDONLY | $O_DIRECTORY | $O_NOFOLLOW | $O_CLOEXEC)
        or die "open destination publication directory: $!\n";
      die "publication directory identity changed\n"
        unless directory_id($source_directory) eq $source_dir_id
          && directory_id($destination_directory) eq $destination_dir_id;
      my $source = open_at(fileno($source_directory), $source_leaf,
        O_RDONLY | $O_NOFOLLOW | $O_CLOEXEC);
      my @source_initial = file_status($source);
      my $digest = Digest::SHA->new(256)->addfile($source)->hexdigest;
      die "publication candidate bytes changed before publication\n"
        unless $digest eq $expected_sha;
      defined(sysseek($source, 0, 0)) or die "rewind publication candidate: $!\n";
      my $source_check = open_at(fileno($source_directory), $source_leaf,
        O_RDONLY | $O_NOFOLLOW | $O_CLOEXEC);
      my @source_path = file_status($source_check);
      die "publication candidate pathname changed\n"
        unless same_file(\@source_initial, \@source_path);
      syscall($SYS_FCLONEFILEAT, fileno($source), fileno($destination_directory),
        $destination_leaf, $CLONE_NOFOLLOW) == 0
        or die "atomic no-replace publication clone: $!\n";
      my $destination = open_at(fileno($destination_directory), $destination_leaf,
        O_RDONLY | $O_NOFOLLOW | $O_CLOEXEC);
      my @destination_status = file_status($destination);
      my $destination_digest = Digest::SHA->new(256)->addfile($destination)->hexdigest;
      die "published destination differs from the pinned candidate\n"
        unless $destination_digest eq $expected_sha
          && $destination_status[7] == $source_initial[7];
      syscall($SYS_FSYNC, fileno($destination)) == 0
        or die "flush published destination: $!\n";
      syscall($SYS_FSYNC, fileno($destination_directory)) == 0
        or die "flush publication directory: $!\n";
      my $source_final = open_at(fileno($source_directory), $source_leaf,
        O_RDONLY | $O_NOFOLLOW | $O_CLOEXEC);
      my @source_final_status = file_status($source_final);
      die "publication candidate changed before cleanup\n"
        unless same_file(\@source_initial, \@source_final_status);
      syscall($SYS_UNLINKAT, fileno($source_directory), $source_leaf, 0) == 0
        or die "remove published candidate: $!\n";
    ' -- \
      "$source_parent" "$(/usr/bin/basename "$source_path")" "$source_parent_id" \
      "$expected_sha256" \
      "$destination_parent" "$(/usr/bin/basename "$destination_path")" \
      "$destination_parent_id"; then
    return 1
  fi

  if [ -e "$source_path" ] || [ -L "$source_path" ]; then
    echo "Atomic publication left the candidate at its staging path." >&2
    return 1
  fi
  require_public_release_file "$destination_path" \
    "Atomic publication destination" || return 1
}

release_sha256_sidecar_contents() {
  local archive_sha256="$1"
  local archive_path="$2"

  if ! valid_sha256 "$archive_sha256"; then
    echo "Release archive SHA-256 is not an exact lowercase digest." >&2
    return 1
  fi
  /usr/bin/printf '%s  %s\n' "$archive_sha256" "$(/usr/bin/basename "$archive_path")"
}

write_release_sha256_sidecar_candidate() {
  local sidecar_path="$1"
  local archive_path="$2"
  local archive_sha256="$3"

  if [ -e "$sidecar_path" ] || [ -L "$sidecar_path" ]; then
    echo "Refusing to replace a staged SHA-256 sidecar: $sidecar_path" >&2
    return 1
  fi
  release_sha256_sidecar_contents "$archive_sha256" "$archive_path" >"$sidecar_path"
  /bin/chmod 644 "$sidecar_path"
  require_public_release_file "$sidecar_path" \
    "SHA-256 sidecar candidate" || return 1
}

verify_release_sha256_sidecar() {
  local sidecar_path="$1"
  local archive_path="$2"
  local archive_sha256="$3"
  local expected_sidecar_sha256
  local actual_sidecar_sha256

  require_public_release_file "$sidecar_path" \
    "Published release SHA-256 sidecar" || return 1
  expected_sidecar_sha256="$(
    release_sha256_sidecar_contents "$archive_sha256" "$archive_path" \
      | /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin /usr/bin/shasum -a 256 \
      | /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin /usr/bin/awk '{ print $1 }'
  )"
  actual_sidecar_sha256="$(release_tool_sha256 "$sidecar_path")"
  if [ "$actual_sidecar_sha256" != "$expected_sidecar_sha256" ]; then
    echo "Published release SHA-256 sidecar does not match the archive." >&2
    return 1
  fi
}

verify_published_release_hash_evidence() {
  local archive_path="$1"
  local sidecar_path="$2"
  local expected_sha256="$3"
  local actual_sha256

  require_public_release_file "$archive_path" \
    "Published release archive" || return 1
  actual_sha256="$(release_tool_sha256 "$archive_path")"
  if [ "$actual_sha256" != "$expected_sha256" ]; then
    echo "Published release archive changed after verification." >&2
    return 1
  fi
  verify_release_sha256_sidecar "$sidecar_path" "$archive_path" "$actual_sha256"
}

verify_published_archive_matches_candidate() {
  local candidate_path="$1"
  local archive_path="$2"
  local expected_sha256="$3"
  local actual_sha256

  if ! valid_sha256 "$expected_sha256"; then
    echo "Exact immutable archive adoption requires two regular files and a valid digest." >&2
    return 1
  fi
  require_public_release_file "$candidate_path" \
    "Verified archive candidate" || return 1
  require_public_release_file "$archive_path" \
    "Existing immutable archive" || return 1
  actual_sha256="$(release_tool_sha256 "$archive_path")"
  if [ "$actual_sha256" != "$expected_sha256" ] \
    || ! /usr/bin/cmp -s "$candidate_path" "$archive_path"; then
    echo "Existing immutable release archive differs from the verified candidate." >&2
    return 1
  fi
}

publish_sidecar_candidate_no_replace_or_adopt() {
  local candidate_path="$1"
  local archive_path="$2"
  local sidecar_path="$3"
  local archive_sha256="$4"
  local sidecar_sha256

  if [ -e "$sidecar_path" ] || [ -L "$sidecar_path" ]; then
    if ! require_public_release_file "$sidecar_path" \
      "Existing immutable SHA-256 sidecar" \
      || ! require_public_release_file "$candidate_path" \
        "Verified SHA-256 sidecar candidate" \
      || ! /usr/bin/cmp -s "$candidate_path" "$sidecar_path"; then
      echo "Existing immutable SHA-256 sidecar differs from the verified candidate." >&2
      return 1
    fi
    return 0
  fi

  sidecar_sha256="$(
    release_sha256_sidecar_contents "$archive_sha256" "$archive_path" \
      | /usr/bin/shasum -a 256 | /usr/bin/awk '{ print $1; exit }'
  )" || return 1
  if atomic_publish_file_no_replace \
    "$candidate_path" "$sidecar_path" "$sidecar_sha256"; then
    return 0
  fi
  # The helper can report a directory-fsync failure after the no-replace
  # rename has already happened, or another publisher can win the race. Only
  # exact expected bytes are adoptable; no existing file is ever replaced.
  if require_public_release_file "$candidate_path" \
    "Verified SHA-256 sidecar candidate" 2>/dev/null; then
    if ! require_public_release_file "$sidecar_path" \
      "Published SHA-256 sidecar" \
      || ! /usr/bin/cmp -s "$candidate_path" "$sidecar_path"; then
      return 1
    fi
  elif ! verify_release_sha256_sidecar "$sidecar_path" "$archive_path" "$archive_sha256"; then
    return 1
  fi
}

publish_verified_release_pair() {
  local archive_candidate="$1"
  local sidecar_candidate="$2"
  local expected_sha256="$3"
  local state

  if ! valid_sha256 "$expected_sha256" \
    || ! require_public_release_file "$archive_candidate" \
      "Verified release archive candidate"; then
    echo "Verified release archive candidate is unavailable." >&2
    return 1
  fi
  write_release_sha256_sidecar_candidate \
    "$sidecar_candidate" "$ZIP_PATH" "$expected_sha256"
  verify_release_sha256_sidecar \
    "$sidecar_candidate" "$ZIP_PATH" "$expected_sha256"

  state="$(release_publication_state)" || return 1
  case "$state" in
    empty)
      if ! atomic_publish_file_no_replace \
        "$archive_candidate" "$ZIP_PATH" "$expected_sha256"; then
        if require_public_release_file "$archive_candidate" \
          "Verified release archive candidate" 2>/dev/null; then
          verify_published_archive_matches_candidate \
            "$archive_candidate" "$ZIP_PATH" "$expected_sha256" || return 1
        elif ! require_public_release_file "$ZIP_PATH" \
          "Published release archive" \
          || [ "$(release_tool_sha256 "$ZIP_PATH")" != "$expected_sha256" ]; then
          return 1
        fi
      fi
      ;;
    archive-only|complete)
      verify_published_archive_matches_candidate \
        "$archive_candidate" "$ZIP_PATH" "$expected_sha256" || return 1
      ;;
    *)
      echo "Unsupported immutable release publication state: $state" >&2
      return 1
      ;;
  esac

  if ! require_public_release_file "$ZIP_PATH" \
      "Published release archive" \
    || [ "$(release_tool_sha256 "$ZIP_PATH")" != "$expected_sha256" ]; then
    echo "Published release archive does not match the verified candidate digest." >&2
    return 1
  fi
  publish_sidecar_candidate_no_replace_or_adopt \
    "$sidecar_candidate" "$ZIP_PATH" "$ZIP_SHA256_PATH" "$expected_sha256"
  verify_published_release_hash_evidence \
    "$ZIP_PATH" "$ZIP_SHA256_PATH" "$expected_sha256"
}

repair_or_adopt_existing_release() {
  local state="$1"
  local snapshot_path="$STAGE_DIR/existing-published-archive.zip"
  local published_identity
  local verified_sha256

  case "$state" in
    archive-only|complete) ;;
    *)
      echo "Only an existing archive can be repaired or adopted." >&2
      return 1
      ;;
  esac
  if ! published_identity="$(
    capture_published_archive_snapshot "$ZIP_PATH" "$snapshot_path"
  )"; then
    echo "Unable to capture the existing immutable release archive by inode." >&2
    return 1
  fi
  verified_sha256="$(release_tool_sha256 "$snapshot_path")"
  if ! valid_sha256 "$verified_sha256"; then
    echo "Unable to hash the private published-archive snapshot." >&2
    return 1
  fi
  if [ "$state" = complete ]; then
    verify_release_sha256_sidecar \
      "$ZIP_SHA256_PATH" "$ZIP_PATH" "$verified_sha256" || return 1
  fi

  # The orphan is not trusted merely because it has the right filename. Run
  # the same archive, signature, notarization, bundle metadata, commit/tree,
  # source snapshot, and toolchain verification used for a new candidate.
  extract_and_verify_archive \
    "$snapshot_path" existing-published-extracted "$verified_sha256" || return 1
  verify_release_source_unchanged || return 1
  verify_release_build_toolchain_guard || return 1
  verify_published_archive_matches_snapshot \
    "$ZIP_PATH" "$snapshot_path" "$published_identity" "$verified_sha256" || return 1

  if [ "$state" = archive-only ]; then
    write_release_sha256_sidecar_candidate \
      "$TMP_ZIP_SHA256" "$ZIP_PATH" "$verified_sha256" || return 1
    verify_release_sha256_sidecar \
      "$TMP_ZIP_SHA256" "$ZIP_PATH" "$verified_sha256" || return 1
    # This inode- and byte-bound comparison is deliberately the last operation
    # before publishing hash evidence for a previously orphaned archive.
    verify_published_archive_matches_snapshot \
      "$ZIP_PATH" "$snapshot_path" "$published_identity" "$verified_sha256" || return 1
    publish_sidecar_candidate_no_replace_or_adopt \
      "$TMP_ZIP_SHA256" "$ZIP_PATH" "$ZIP_SHA256_PATH" "$verified_sha256" || return 1
  fi
  verify_published_archive_matches_snapshot \
    "$ZIP_PATH" "$snapshot_path" "$published_identity" "$verified_sha256" || return 1
  verify_release_sha256_sidecar \
    "$ZIP_SHA256_PATH" "$ZIP_PATH" "$verified_sha256" || return 1
  PUBLISHED_ZIP_SHA256="$verified_sha256"
}

cleanup() {
  local private_root="${RELEASE_PRIVATE_ROOT:-}"
  local expected_root_id="${RELEASE_PRIVATE_ROOT_ID:-}"
  local actual_root_id

  [ -n "$private_root" ] || return 0
  if ! verify_private_release_root >/dev/null 2>&1; then
    echo "Warning: refusing cleanup because the private release root path or identity changed: $private_root" >&2
    return 0
  fi

  if [ "${RELEASE_SOURCE_FREEZE_ATTEMPTED:-false}" = true ]; then
    if valid_sha256 "${RELEASE_SOURCE_IDENTITY_SHA256:-}" \
      && ! verify_release_source_identity_guard >/dev/null 2>&1; then
      echo "Warning: refusing cleanup because frozen release source identity changed." >&2
      return 0
    fi
    if ! thaw_release_source_if_anchored; then
      echo "Warning: refusing cleanup because the attempted source freeze could not be safely thawed." >&2
      return 0
    fi
  fi
  if [ "${RELEASE_TOOLCHAIN_SNAPSHOT_FREEZE_ATTEMPTED:-false}" = true ]; then
    if valid_sha256 "${RELEASE_TOOLCHAIN_SNAPSHOT_IDENTITY_SHA256:-}" \
      && ! verify_release_toolchain_snapshot_guard >/dev/null 2>&1; then
      echo "Warning: refusing cleanup because immutable toolchain snapshot identity changed." >&2
      return 0
    fi
    if ! thaw_release_toolchain_snapshot_if_anchored; then
      echo "Warning: refusing cleanup because the toolchain snapshot could not be safely thawed." >&2
      return 0
    fi
  fi
  if [ -n "${RELEASE_SOURCE_DIR:-}" ] && [ -d "$RELEASE_SOURCE_DIR" ] \
    && [ ! -L "$RELEASE_SOURCE_DIR" ] \
    && [ "$(cd "$RELEASE_SOURCE_DIR" 2>/dev/null && /bin/pwd -P)" = "$RELEASE_SOURCE_DIR" ]; then
    case "$RELEASE_SOURCE_DIR" in
      "$private_root"/*) /bin/chmod -R u+w "$RELEASE_SOURCE_DIR" || return 0 ;;
      *)
        echo "Warning: refusing cleanup because release source escaped the private root." >&2
        return 0
        ;;
    esac
  fi

  # Anchor traversal to the already-verified directory inode. If an attacker
  # renames or redirects the recorded pathname after `cd`, the working
  # directory still names the original private tree. BSD find is physical by
  # default; -x also refuses to cross into a mounted filesystem. Symlinks are
  # unlinked as nodes and are never followed.
  if ! (
    cd "$private_root" || exit 1
    actual_root_id="$(directory_identity .)" || exit 1
    [ "$actual_root_id" = "$expected_root_id" ] || exit 1
    /usr/bin/find -x . -depth -mindepth 1 -delete
  ); then
    echo "Warning: private release cleanup could not safely empty: $private_root" >&2
    return 0
  fi

  # The only pathname-based removal is a non-recursive rmdir. Re-checking the
  # inode prevents deleting a substituted leaf; a race after this check can at
  # worst remove another empty directory, never recursively erase its content.
  if ! actual_root_id="$(directory_identity "$private_root" 2>/dev/null)" \
    || [ "$actual_root_id" != "$expected_root_id" ]; then
    echo "Warning: private release root moved during cleanup; refusing pathname removal: $private_root" >&2
    return 0
  fi
  if ! /bin/rmdir "$private_root"; then
    echo "Warning: private release root could not be removed after safe cleanup: $private_root" >&2
  fi
}

build_release_executable() {
  BUILD_TARGET_DIR="$STAGE_DIR/target"
  TARGET_EXECUTABLE="$BUILD_TARGET_DIR/aarch64-apple-darwin/release/$BINARY_NAME"

  verify_release_dependency_graph
  run_sanitized_release_cargo build \
    --locked \
    --release \
    --target aarch64-apple-darwin \
    --manifest-path "$RELEASE_SOURCE_DIR/Cargo.toml" \
    --bin "$BINARY_NAME"

  if [ ! -x "$TARGET_EXECUTABLE" ]; then
    echo "Release build did not produce expected executable: $TARGET_EXECUTABLE" >&2
    exit 1
  fi
  verify_release_source_unchanged
}

assemble_release_bundle() {
  local bundle_dir="$1"
  local assembly_status

  verify_release_source_identity_guard
  if waal_assemble_app_bundle \
    "$RELEASE_SOURCE_DIR" \
    "$bundle_dir" \
    "$BINARY_NAME" \
    "$TARGET_EXECUTABLE" \
    "$EXPECTED_BUNDLE_ID" \
    "$APP_DISPLAY_NAME" \
    "$CARGO_VERSION" \
    "$BUILD_VERSION"; then
    assembly_status=0
  else
    assembly_status=$?
  fi
  verify_release_source_identity_guard || return 1
  if [ "$assembly_status" -ne 0 ]; then
    return "$assembly_status"
  fi
}

macos_release_provenance_contents() {
  /usr/bin/printf '%s\n' \
    'WAAL_MACOS_LOCAL_SIGNED_BUILD_INFO_V1' \
    'publishable=false' \
    'attestation=none-local-shared-security-context' \
    'producer-attribution=unavailable-local-shared-security-context' \
    "captured-source-git-commit=$RELEASE_GIT_COMMIT" \
    "captured-source-git-tree=$RELEASE_GIT_TREE" \
    "observed-git-sha256=$RELEASE_GIT_SHA256" \
    "observed-cargo-version=$RELEASE_CARGO_VERSION" \
    "observed-cargo-sha256=$RELEASE_CARGO_SHA256" \
    "observed-rustc-version=$RELEASE_RUSTC_VERSION" \
    "observed-rustc-sha256=$RELEASE_RUSTC_SHA256" \
    "observed-rust-sysroot-sha256=$RELEASE_RUST_SYSROOT_SHA256" \
    "observed-native-toolchain-sha256=$RELEASE_NATIVE_TOOLCHAIN_SHA256" \
    "observed-materials-sha256=$RELEASE_MATERIALS_SHA256" \
    "observed-clang-sha256=$RELEASE_CLANG_SHA256" \
    "observed-clangxx-sha256=$RELEASE_CLANGXX_SHA256" \
    "observed-ar-sha256=$RELEASE_AR_SHA256" \
    "observed-ld-sha256=$RELEASE_LD_SHA256" \
    "observed-ld-libtapi-sha256=$RELEASE_LD_TAPI_SHA256" \
    "observed-ld-libcodedirectory-sha256=$RELEASE_LD_CODEDIRECTORY_SHA256" \
    "observed-ld-liblto-sha256=$RELEASE_LD_LTO_SHA256" \
    "observed-ld-libswift-demangle-sha256=$RELEASE_LD_SWIFT_DEMANGLE_SHA256" \
    "observed-notarytool-sha256=$RELEASE_NOTARYTOOL_SHA256" \
    "observed-stapler-sha256=$RELEASE_STAPLER_SHA256" \
    "observed-macos-sdk-sha256=$RELEASE_MACOS_SDK_SHA256" \
    "observed-clang-resource-dir-sha256=$RELEASE_CLANG_RESOURCE_DIR_SHA256"
}

write_macos_release_provenance() {
  local bundle_dir="$1"
  local provenance_file="$bundle_dir/Contents/Resources/BUILD-INFO.txt"

  if [ -L "$provenance_file" ]; then
    echo "Refusing to replace a symlinked macOS provenance file." >&2
    exit 1
  fi
  macos_release_provenance_contents >"$provenance_file"
  /bin/chmod 644 "$provenance_file"
}

verify_macos_release_provenance() {
  local bundle_dir="$1"
  local provenance_file="$bundle_dir/Contents/Resources/BUILD-INFO.txt"
  local expected_file="$STAGE_DIR/macos-local-signed-build-info.expected.txt"

  if [ ! -f "$provenance_file" ] || [ -L "$provenance_file" ]; then
    echo "Local signed bundle is missing its regular BUILD-INFO.txt file." >&2
    exit 1
  fi
  macos_release_provenance_contents >"$expected_file"
  if ! /usr/bin/cmp -s "$expected_file" "$provenance_file"; then
    echo "Local signed bundle information does not match the captured source and observed toolchain." >&2
    exit 1
  fi
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

canonical_unsigned_macho_sha256() {
  local executable="$1"
  local digest

  if ! digest="$(
    /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin \
      /usr/bin/perl -MDigest::SHA=sha256_hex -MFcntl=:mode \
      -MTime::HiRes=lstat,stat -e '
        use strict;
        use warnings;
        use bytes;
        my $path = shift @ARGV;
        my @path_before = lstat($path);
        die "lstat Mach-O: $!\n" unless @path_before
          && S_ISREG($path_before[2]) && $path_before[3] == 1;
        open my $file, "<:raw", $path or die "open Mach-O: $!\n";
        my @opened_before = stat($file);
        die "fstat Mach-O: $!\n" unless @opened_before;
        local $/;
        my $bytes = <$file>;
        my @opened_after = stat($file);
        die "fstat Mach-O after read: $!\n" unless @opened_after;
        close $file or die "close Mach-O: $!\n";
        my @path_after = lstat($path);
        die "lstat Mach-O after read: $!\n" unless @path_after;
        for my $index (0, 1, 2, 3, 4, 5, 7, 9, 10) {
          die "Mach-O identity changed while reading\n"
            unless $path_before[$index] == $opened_before[$index]
              && $path_before[$index] == $opened_after[$index]
              && $path_before[$index] == $path_after[$index];
        }
        die "Mach-O size changed while reading\n"
          unless length($bytes) == $path_before[7];
        die "unsupported release Mach-O header\n" if length($bytes) < 32;
        my ($magic, $cpu_type, $cpu_subtype, $file_type, $command_count,
            $command_bytes, $flags, $reserved) = unpack("V8", substr($bytes, 0, 32));
        die "release executable is not a thin little-endian arm64 Mach-O\n"
          unless $magic == 0xfeedfacf && $cpu_type == 0x0100000c && $file_type == 2;
        die "invalid Mach-O load-command region\n"
          if $command_count == 0 || $command_count > 4096
            || $command_bytes > length($bytes) - 32;
        my $offset = 32;
        my ($signature_offset, $signature_size, $signature_command, $linkedit_command);
        for (1 .. $command_count) {
          die "truncated Mach-O load command\n" if $offset + 8 > 32 + $command_bytes;
          my ($command, $command_size) = unpack("VV", substr($bytes, $offset, 8));
          die "invalid Mach-O load command size\n"
            if $command_size < 8 || $offset + $command_size > 32 + $command_bytes;
          if ($command == 0x1d) {
            die "ambiguous Mach-O code-signature command\n"
              if defined $signature_command || $command_size != 16;
            ($signature_offset, $signature_size) =
              unpack("VV", substr($bytes, $offset + 8, 8));
            $signature_command = $offset;
          }
          if ($command == 0x19 && $command_size >= 72
              && unpack("Z16", substr($bytes, $offset + 8, 16)) eq "__LINKEDIT") {
            die "ambiguous Mach-O __LINKEDIT segment\n" if defined $linkedit_command;
            $linkedit_command = $offset;
          }
          $offset += $command_size;
        }
        die "Mach-O load commands do not exactly fill their header region\n"
          unless $offset == 32 + $command_bytes;
        die "release Mach-O is missing terminal code-signature metadata\n"
          unless defined($signature_command) && defined($linkedit_command)
            && $signature_offset >= $offset && $signature_size > 0
            && $signature_offset + $signature_size == length($bytes);
        my $linkedit_file_offset =
          unpack("Q<", substr($bytes, $linkedit_command + 40, 8));
        die "Mach-O code signature is outside __LINKEDIT\n"
          if $signature_offset < $linkedit_file_offset;
        my $unsigned_linkedit_size = $signature_offset - $linkedit_file_offset;
        my $unsigned_linkedit_vm_size = ($unsigned_linkedit_size + 16_383) & ~16_383;

        # Developer-ID replacement legitimately changes only the terminal
        # signature blob, LC_CODE_SIGNATURE.datasize, and __LINKEDIT sizing.
        # Normalize those fields to the exact unsigned payload boundary while
        # hashing every load command and every executable byte before it.
        substr($bytes, $signature_command + 12, 4, pack("V", 0));
        substr($bytes, $linkedit_command + 32, 8,
          pack("Q<", $unsigned_linkedit_vm_size));
        substr($bytes, $linkedit_command + 48, 8,
          pack("Q<", $unsigned_linkedit_size));
        print sha256_hex(substr($bytes, 0, $signature_offset)), "\n";
      ' -- "$executable"
  )" || ! valid_sha256 "$digest"; then
    echo "Unable to hash the canonical unsigned release Mach-O payload." >&2
    return 1
  fi
  /usr/bin/printf '%s\n' "$digest"
}

release_bundle_payload_sha256() {
  local bundle_dir="$1"
  local bundle_executable
  local executable
  local executable_sha256
  local first_identity
  local second_identity
  local digest

  verify_bundle_tree_entry_safety "$bundle_dir" || return 1
  bundle_executable="$(
    /usr/bin/plutil -extract CFBundleExecutable raw \
      "$bundle_dir/Contents/Info.plist"
  )" || return 1
  case "$bundle_executable" in
    ""|.|..|*/*|*$'\r'*|*$'\n'*)
      echo "Release bundle executable name is unsafe." >&2
      return 1
      ;;
  esac
  executable="$bundle_dir/Contents/MacOS/$bundle_executable"
  first_identity="$(guarded_tree_identity_sha256 "$bundle_dir")" || return 1
  executable_sha256="$(canonical_unsigned_macho_sha256 "$executable")" || return 1
  if ! digest="$(
    /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin \
      /usr/bin/perl -MDigest::SHA -MFile::Find -MFcntl=:mode \
      -MTime::HiRes=lstat,stat -e '
        use strict;
        use warnings;
        use bytes;
        my ($root, $main_relative, $main_sha256) = @ARGV;
        my @records;
        File::Find::find({
          no_chdir => 1,
          follow => 0,
          wanted => sub {
            my $path = $File::Find::name;
            my $relative = $path eq $root
              ? "." : substr($path, length($root) + 1);
            if ($relative eq "Contents/_CodeSignature"
                || index($relative, "Contents/_CodeSignature/") == 0) {
              $File::Find::prune = 1 if -d $path;
              return;
            }
            my @before = lstat($path);
            die "lstat bundle payload: $!\n" unless @before;
            if (S_ISDIR($before[2])) {
              push @records, [$relative, "directory", sprintf("%o", $before[2]), ""];
              return;
            }
            die "bundle payload contains a non-regular node\n"
              unless S_ISREG($before[2]) && $before[3] == 1;
            my $file_sha256;
            if ($relative eq $main_relative) {
              $file_sha256 = $main_sha256;
            } else {
              open my $file, "<:raw", $path or die "open bundle payload: $!\n";
              my @opened_before = stat($file);
              die "fstat bundle payload: $!\n" unless @opened_before;
              $file_sha256 = Digest::SHA->new(256)->addfile($file)->hexdigest;
              my @opened_after = stat($file);
              die "fstat bundle payload after hash: $!\n" unless @opened_after;
              close $file or die "close bundle payload: $!\n";
              my @after = lstat($path);
              die "lstat bundle payload after hash: $!\n" unless @after;
              for my $index (0, 1, 2, 3, 4, 5, 7, 9, 10) {
                die "bundle payload identity changed while hashing\n"
                  unless $before[$index] == $opened_before[$index]
                    && $before[$index] == $opened_after[$index]
                    && $before[$index] == $after[$index];
              }
            }
            push @records, [$relative, "file", sprintf("%o", $before[2]), $file_sha256];
          },
        }, $root);
        @records = sort { $a->[0] cmp $b->[0] } @records;
        my $aggregate = Digest::SHA->new(256);
        for my $record (@records) {
          $aggregate->add($record->[0], "\0", $record->[1], "\0",
            $record->[2], "\0", $record->[3], "\0");
        }
        print $aggregate->hexdigest, "\n";
      ' -- "$bundle_dir" "Contents/MacOS/$bundle_executable" "$executable_sha256"
  )" || ! valid_sha256 "$digest"; then
    echo "Unable to hash the canonical release bundle payload tree." >&2
    return 1
  fi
  second_identity="$(guarded_tree_identity_sha256 "$bundle_dir")" || return 1
  if [ "$first_identity" != "$second_identity" ]; then
    echo "Release bundle identity changed while its payload was hashed." >&2
    return 1
  fi
  /usr/bin/printf '%s\n' "$digest"
}

capture_release_bundle_payload_baseline() {
  local first_digest
  local second_digest

  first_digest="$(release_bundle_payload_sha256 "$1")" || return 1
  second_digest="$(release_bundle_payload_sha256 "$1")" || return 1
  if [ "$first_digest" != "$second_digest" ]; then
    echo "Release bundle payload changed while its signing baseline was captured." >&2
    return 1
  fi
  RELEASE_BUNDLE_PAYLOAD_SHA256="$first_digest"
}

verify_release_bundle_payload_baseline() {
  local actual_digest

  if ! valid_sha256 "$RELEASE_BUNDLE_PAYLOAD_SHA256"; then
    echo "Release bundle signing payload baseline is not initialized." >&2
    return 1
  fi
  actual_digest="$(release_bundle_payload_sha256 "$1")" || return 1
  if [ "$actual_digest" != "$RELEASE_BUNDLE_PAYLOAD_SHA256" ]; then
    echo "Release bundle executable or resource payload changed after signing approval." >&2
    return 1
  fi
}

sign_release_bundle() {
  local bundle_dir="$1"
  verify_release_bundle_payload_baseline "$bundle_dir" || return 1
  /usr/bin/codesign \
    --force \
    --options runtime \
    --timestamp \
    --sign "$CODESIGN_IDENTITY" \
    "$bundle_dir" || return 1
  verify_release_bundle_payload_baseline "$bundle_dir"
}

notarize_and_staple_bundle() {
  local bundle_dir="$1"
  local notary_zip="$STAGE_DIR/notary-submit.zip"

  verify_release_bundle_payload_baseline "$bundle_dir" || return 1
  (
    cd "$STAGE_DIR"
    sanitized_zip -r -X "$(/usr/bin/basename "$notary_zip")" "$APP_NAME.app" \
      -x "*/.DS_Store" "*/._*" "__MACOSX/*" "*/__MACOSX/*" >/dev/null
  ) || return 1
  verify_release_bundle_payload_baseline "$bundle_dir" || return 1

  verify_release_notarization_tools_integrity
  verify_release_bundle_payload_baseline "$bundle_dir" || return 1
  DEVELOPER_DIR="$RELEASE_DEVELOPER_DIR" \
    "$RELEASE_NOTARYTOOL_BIN" submit "$notary_zip" --keychain-profile "$NOTARY_PROFILE" --wait \
    || return 1
  verify_release_bundle_payload_baseline "$bundle_dir" || return 1
  verify_release_notarization_tools_integrity
  DEVELOPER_DIR="$RELEASE_DEVELOPER_DIR" \
    "$RELEASE_STAPLER_BIN" staple "$bundle_dir" || return 1
  verify_release_bundle_payload_baseline "$bundle_dir" || return 1
  verify_release_notarization_tools_integrity
}

sanitized_zip() (
  umask 022
  /usr/bin/env -i \
    PATH=/usr/bin:/bin:/usr/sbin:/sbin \
    COPYFILE_DISABLE=1 \
    /usr/bin/zip "$@"
)

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
  require_metadata_field "$metadata" "target-os" "macos" "Release executable target OS metadata is not macOS."
  require_metadata_field "$metadata" "target-arch" "aarch64" "Release executable target architecture metadata is not aarch64."
  require_metadata_field "$metadata" "debug-assertions" "false" "Release executable was built with debug assertions enabled."
  require_metadata_field "$metadata" "macos-bundle-id" "$EXPECTED_BUNDLE_ID" "Release executable runtime bundle identifier does not match $EXPECTED_BUNDLE_ID_ENV."
  require_metadata_field "$metadata" "macos-team-id" "$EXPECTED_TEAM_ID" "Release executable runtime Team ID does not match WAAL_MACOS_TEAM_ID."
  require_metadata_field "$metadata" "source-git-commit" "$RELEASE_GIT_COMMIT" "Release executable source commit does not match the verified Git HEAD."
  require_metadata_field "$metadata" "source-git-tree" "$RELEASE_GIT_TREE" "Release executable source tree does not match the verified Git HEAD tree."
  require_metadata_field "$metadata" "release-cargo-version" "$RELEASE_CARGO_VERSION" "Release executable Cargo version does not match the verified toolchain."
  require_metadata_field "$metadata" "release-rustc-version" "$RELEASE_RUSTC_VERSION" "Release executable rustc version does not match the verified toolchain."
  require_metadata_field "$metadata" "release-cargo-sha256" "$RELEASE_CARGO_SHA256" "Release executable Cargo hash does not match the verified toolchain."
  require_metadata_field "$metadata" "release-rustc-sha256" "$RELEASE_RUSTC_SHA256" "Release executable rustc hash does not match the verified toolchain."
  require_metadata_field "$metadata" "release-rust-sysroot-sha256" "$RELEASE_RUST_SYSROOT_SHA256" "Release executable Rust sysroot hash does not match the verified toolchain."
  require_metadata_field "$metadata" "release-native-toolchain-sha256" "$RELEASE_NATIVE_TOOLCHAIN_SHA256" "Release executable native toolchain hash does not match the verified toolchain."
  require_metadata_field "$metadata" "release-materials-sha256" "$RELEASE_MATERIALS_SHA256" "Release executable materials aggregate does not match the verified release inputs."
  require_metadata_field "$metadata" "artifact-kind" "local-signed-release" "Local signed bundle metadata kind is not local-signed-release."
  require_metadata_field "$metadata" "publishable" "false" "Local signed bundle must not carry a publishable marker."
  require_metadata_field "$metadata" "attestation" "none-local-shared-security-context" "Local signed bundle must disclaim build attestation."
  require_metadata_field "$metadata" "producer-attribution" "unavailable-local-shared-security-context" "Local signed bundle must disclaim producer attribution."
  require_metadata_field "$metadata" "debug-fill" "false" "Local signed bundle was built with debug-fill enabled."
  require_metadata_field "$metadata" "dev-tools" "false" "Local signed bundle was built with dev-tools enabled."
  require_metadata_field "$metadata" "diagnostics-ui" "false" "Local signed bundle was built with diagnostics-ui enabled."
  require_metadata_field "$metadata" "release-diagnostics" "false" "Local signed bundle was built with release-diagnostics enabled."
  require_metadata_field "$metadata" "production-macos-bundle-id" "$EXPECTED_BUNDLE_ID" "Local signed metadata production bundle ID does not match WAAL_RELEASE_BUNDLE_ID."
  require_metadata_field "$metadata" "non-production-macos-identity" "false" "Local signed bundle must use the intended production runtime identity."
  require_canonical_release_metadata "$metadata"
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
    "$RELEASE_SOURCE_DIR" \
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

require_canonical_release_metadata() {
  local metadata="$1"
  local expected_metadata

  # Presence checks alone are insufficient here: a substituted Cargo output
  # could carry both the required local-only disclaimer and a contradictory
  # duplicate claim. Match the complete build.rs schema, including order and
  # the empty macOS-inapplicable Authenticode fields, so duplicates, omissions,
  # additions, and unknown keys all fail closed before signing.
  expected_metadata="WAAL_BUILD_METADATA_V1;artifact-kind=local-signed-release;publishable=false;attestation=none-local-shared-security-context;producer-attribution=unavailable-local-shared-security-context;"
  expected_metadata+="profile=release;target-os=macos;target-arch=aarch64;debug-assertions=false;debug-fill=false;dev-tools=false;diagnostics-ui=false;release-diagnostics=false;"
  expected_metadata+="macos-bundle-id=$EXPECTED_BUNDLE_ID;production-macos-bundle-id=$EXPECTED_BUNDLE_ID;non-production-macos-identity=false;macos-team-id=$EXPECTED_TEAM_ID;"
  expected_metadata+="windows-authenticode-publisher=;windows-authenticode-cert-sha256=;"
  expected_metadata+="source-git-commit=$RELEASE_GIT_COMMIT;source-git-tree=$RELEASE_GIT_TREE;release-cargo-version=$RELEASE_CARGO_VERSION;release-rustc-version=$RELEASE_RUSTC_VERSION;"
  expected_metadata+="release-cargo-sha256=$RELEASE_CARGO_SHA256;release-rustc-sha256=$RELEASE_RUSTC_SHA256;release-rust-sysroot-sha256=$RELEASE_RUST_SYSROOT_SHA256;release-native-toolchain-sha256=$RELEASE_NATIVE_TOOLCHAIN_SHA256;release-materials-sha256=$RELEASE_MATERIALS_SHA256;"

  if [ "$metadata" != "$expected_metadata" ]; then
    echo "Release executable build metadata does not match the exact canonical local-signed schema." >&2
    exit 1
  fi
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

verify_bundle_tree_entry_safety() {
  local bundle_dir="$1"
  local unsafe_entries="$STAGE_DIR/unsafe-bundle-entries.bin"
  local directory_entries="$STAGE_DIR/directory-bundle-entries.bin"
  local regular_entries="$STAGE_DIR/regular-bundle-entries.bin"
  local expected_executable="$bundle_dir/Contents/MacOS/$BINARY_NAME"
  local entry
  local mode

  if [ ! -d "$bundle_dir" ] || [ -L "$bundle_dir" ]; then
    echo "Release bundle root must be a physical directory." >&2
    return 1
  fi
  require_no_acl "$bundle_dir" "Release bundle root" || return 1
  if ! /usr/bin/find "$bundle_dir" -mindepth 1 \
    ! -type d ! -type f -print0 >"$unsafe_entries"; then
    echo "Unable to inspect release bundle entry types." >&2
    return 1
  fi
  if [ -s "$unsafe_entries" ]; then
    echo "Release bundle contains a link or special filesystem entry." >&2
    return 1
  fi
  if ! /usr/bin/find "$bundle_dir" -type d -print0 >"$directory_entries"; then
    echo "Unable to inspect release bundle directories." >&2
    return 1
  fi
  while IFS= read -r -d '' entry; do
    require_no_acl "$entry" "Release bundle directory" || return 1
    mode="$(/usr/bin/stat -f '%Mp%Lp' "$entry" 2>/dev/null)" || return 1
    if [ "$mode" != 0755 ]; then
      echo "Release bundle directory does not have mode 0755: $entry" >&2
      return 1
    fi
  done <"$directory_entries"
  if ! /usr/bin/find "$bundle_dir" -mindepth 1 -type f -print0 >"$regular_entries"; then
    echo "Unable to inspect release bundle regular files." >&2
    return 1
  fi
  while IFS= read -r -d '' entry; do
    require_no_acl "$entry" "Release bundle file" || return 1
    if [ "$(/usr/bin/stat -f '%l' "$entry")" != 1 ]; then
      echo "Release bundle contains a multiply linked regular file: $entry" >&2
      return 1
    fi
    mode="$(/usr/bin/stat -f '%Mp%Lp' "$entry" 2>/dev/null)" || return 1
    if [ "$entry" = "$expected_executable" ]; then
      if [ "$mode" != 0755 ]; then
        echo "Release bundle main executable does not have mode 0755: $entry" >&2
        return 1
      fi
    elif [ "$mode" != 0644 ]; then
      echo "Release bundle non-executable file does not have mode 0644: $entry" >&2
      return 1
    fi
  done <"$regular_entries"
}

verify_release_bundle() {
  local bundle_dir="$1"

  require_tool codesign
  require_tool lipo
  require_tool plutil
  require_tool spctl
  verify_bundle_tree_entry_safety "$bundle_dir"
  if valid_sha256 "$RELEASE_BUNDLE_PAYLOAD_SHA256"; then
    verify_release_bundle_payload_baseline "$bundle_dir"
  fi

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
  signature="$(/usr/bin/codesign -dv --verbose=4 "$bundle_dir" 2>&1)"
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
  verify_macos_release_provenance "$bundle_dir"
  verify_no_developer_path_strings "$bundle_dir"
  verify_no_nested_code "$bundle_dir"
  verify_release_entitlements "$bundle_dir"

  /usr/sbin/spctl --assess --type execute --verbose "$bundle_dir"
  verify_release_notarization_tools_integrity
  DEVELOPER_DIR="$RELEASE_DEVELOPER_DIR" \
    "$RELEASE_STAPLER_BIN" validate "$bundle_dir"
  verify_release_notarization_tools_integrity
  if valid_sha256 "$RELEASE_BUNDLE_PAYLOAD_SHA256"; then
    verify_release_bundle_payload_baseline "$bundle_dir"
  fi
}

archive_session_rewind() {
  verify_archive_snapshot_helper_integrity || return 1
  run_archive_snapshot_operation rewind-fd <&7 || return 1
  verify_archive_snapshot_helper_integrity
}

archive_session_check_identity() {
  verify_archive_snapshot_helper_integrity || return 1
  run_archive_snapshot_operation \
    check-fd "$ARCHIVE_SESSION_IDENTITY" <&7 || return 1
  verify_archive_snapshot_helper_integrity
}

archive_session_bind_path() {
  local zip_path="$1"
  local parent
  local identity

  parent="$(/usr/bin/dirname "$zip_path")"
  verify_archive_snapshot_helper_integrity || return 1
  identity="$(
    run_archive_snapshot_operation bind-fd \
      "$parent" "$(/usr/bin/basename "$zip_path")" \
      "$(directory_identity "$parent")" <&7
  )" || return 1
  verify_archive_snapshot_helper_integrity || return 1
  case "$identity" in
    ""|*[!0-9:.]*)
      echo "Archive session returned an invalid descriptor identity." >&2
      return 1
      ;;
  esac
  /usr/bin/printf '%s\n' "$identity"
}

archive_session_sha256() {
  local digest

  archive_session_rewind || return 1
  digest="$(
    /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin \
      /usr/bin/shasum -a 256 <&7 | /usr/bin/awk '{ print $1; exit }'
  )" || return 1
  archive_session_check_identity || return 1
  archive_session_rewind || return 1
  if ! valid_sha256 "$digest"; then
    echo "Archive session could not compute an exact SHA-256 digest." >&2
    return 1
  fi
  /usr/bin/printf '%s\n' "$digest"
}

validate_archive_entries_from_open_session() {
  local expected_root="$APP_NAME.app"

  # Parse both the central directory and every local header from the already
  # bound descriptor. Fixed resource limits run before CRC or extraction.
  if ! archive_session_rewind \
    || ! /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin \
      /usr/bin/perl \
      -MCompress::Raw::Zlib=crc32,MAX_WBITS,Z_OK,Z_STREAM_END,Z_BUF_ERROR \
      -e '
        use strict;
        use warnings;
        use bytes;

        my ($root, $binary_name) = @ARGV;
        open my $zip, "<&=0" or die "open ZIP descriptor: $!\n";
        binmode($zip);
        my $size = -s $zip;
        die "truncated ZIP\n" if !defined($size) || $size < 22;
        die "ZIP resource limit exceeded: archive bytes\n" if $size > 536_870_912;

        sub read_at {
          my ($handle, $offset, $length, $label) = @_;
          seek($handle, $offset, 0) or die "seek $label: $!\n";
          my $buffer = "";
          my $count = read($handle, $buffer, $length);
          die "truncated $label\n" if !defined($count) || $count != $length;
          return $buffer;
        }

        my $tail_start = $size > 65_557 ? $size - 65_557 : 0;
        my $tail = read_at($zip, $tail_start, $size - $tail_start, "ZIP tail");
        my $eocd_index = -1;
        for (my $index = length($tail) - 22; $index >= 0; --$index) {
          next unless substr($tail, $index, 4) eq "PK\x05\x06";
          my $comment_length = unpack("v", substr($tail, $index + 20, 2));
          if ($tail_start + $index + 22 + $comment_length == $size) {
            $eocd_index = $index;
            last;
          }
        }
        die "missing exact end-of-central-directory record\n" if $eocd_index < 0;
        my $eocd_offset = $tail_start + $eocd_index;
        my ($signature, $disk, $central_disk, $disk_entries, $entry_count,
            $central_size, $central_offset, $comment_length) =
          unpack("VvvvvVVv", substr($tail, $eocd_index, 22));
        die "multi-disk, ZIP64, or commented ZIP is unsupported\n"
          if $signature != 0x06054b50 || $disk != 0 || $central_disk != 0
            || $disk_entries != $entry_count || $entry_count == 0
            || $entry_count == 0xffff || $central_size == 0xffffffff
            || $central_offset == 0xffffffff || $comment_length != 0;
        die "ZIP resource limit exceeded: entry count\n" if $entry_count > 16_384;
        die "central directory is not an exact terminal region\n"
          if $central_offset + $central_size != $eocd_offset;

        my %explicit_entry;
        my %spelling;
        my %node_kind;
        my %local_offset;
        my @regions;
        my @payloads;
        my $position = $central_offset;
        my $total_uncompressed = 0;
        for (my $number = 0; $number < $entry_count; ++$number) {
          die "central directory entry escapes its region\n"
            if $position + 46 > $central_offset + $central_size;
          my $fixed = read_at($zip, $position, 46, "central directory header");
          my ($central_signature, $made_by, $needed, $flags, $method, $time, $date,
              $crc, $compressed_size, $uncompressed_size, $name_length,
              $extra_length, $file_comment_length, $start_disk, $internal_attributes,
              $external_attributes, $offset) = unpack("VvvvvvvVVVvvvvvVV", $fixed);
          die "invalid central directory signature\n" if $central_signature != 0x02014b50;
          die "unsupported ZIP metadata or encoding\n"
            if ($made_by >> 8) != 3 || $start_disk != 0 || $extra_length != 0
              || $file_comment_length != 0 || ($flags & ~0x0800) != 0
              || ($method != 0 && $method != 8)
              || $compressed_size == 0xffffffff || $uncompressed_size == 0xffffffff
              || $offset == 0xffffffff;
          die "empty ZIP entry name\n" if $name_length == 0;
          die "ZIP resource limit exceeded: path length\n" if $name_length > 1024;
          die "ZIP resource limit exceeded: single entry size\n"
            if $uncompressed_size > 536_870_912;
          $total_uncompressed += $uncompressed_size;
          die "ZIP resource limit exceeded: total uncompressed size\n"
            if $total_uncompressed > 1_073_741_824;
          die "invalid stored ZIP size relationship\n"
            if $method == 0 && $compressed_size != $uncompressed_size;
          die "invalid empty compressed ZIP stream\n"
            if $method == 8 && $uncompressed_size > 0 && $compressed_size == 0;
          die "ZIP resource limit exceeded: expansion ratio\n"
            if $uncompressed_size > ($compressed_size * 200) + 1_048_576;

          my $name = read_at($zip, $position + 46, $name_length, "central entry name");
          $position += 46 + $name_length + $extra_length + $file_comment_length;
          die "ZIP entry name is not safe printable ASCII\n"
            if $name =~ /[^\x20-\x7e]/ || $name =~ /[\\:]/ || $name =~ m{^/};
          die "ZIP entry is outside the expected app bundle\n"
            unless $name eq "$root/" || index($name, "$root/") == 0;
          die "macOS metadata sidecar is forbidden\n"
            if $name =~ m{(?:^|/)__MACOSX(?:/|$)}
              || $name =~ m{(?:^|/)\._} || $name =~ m{(?:^|/)\.DS_Store$};

          my $directory = $name =~ m{/$};
          my $logical_name = $directory ? substr($name, 0, -1) : $name;
          my @components = split(m{/}, $logical_name, -1);
          die "ZIP resource limit exceeded: path depth\n" if @components > 64;
          for my $component (@components) {
            die "ZIP entry has an unsafe path component\n"
              if $component eq "" || $component eq "." || $component eq ".."
                || $component =~ /[. ]$/;
            die "ZIP resource limit exceeded: component length\n"
              if length($component) > 255;
          }

          my $canonical = lc($logical_name);
          die "duplicate or case-normalized ZIP entry\n"
            if exists $explicit_entry{$canonical};
          $explicit_entry{$canonical} = $directory ? "directory" : "file";
          my $original_prefix = "";
          for my $index (0 .. $#components) {
            $original_prefix .= ($original_prefix eq "" ? "" : "/") . $components[$index];
            my $canonical_prefix = lc($original_prefix);
            die "case-conflicting implicit ZIP directory\n"
              if exists($spelling{$canonical_prefix})
                && $spelling{$canonical_prefix} ne $original_prefix;
            $spelling{$canonical_prefix} = $original_prefix;
            my $required_kind = $index == $#components
              ? ($directory ? "directory" : "file") : "directory";
            die "ZIP file/directory ancestor or descendant collision\n"
              if exists($node_kind{$canonical_prefix})
                && $node_kind{$canonical_prefix} ne $required_kind;
            $node_kind{$canonical_prefix} = $required_kind;
          }

          my $mode = ($external_attributes >> 16) & 0xffff;
          my $file_type = $mode & 0170000;
          die "ZIP entry is a link or unsupported special file\n"
            unless ($directory && $file_type == 0040000)
              || (!$directory && $file_type == 0100000);
          my $expected_mode = $directory ? 0040755
            : ($logical_name eq "$root/Contents/MacOS/$binary_name"
              ? 0100755 : 0100644);
          die "ZIP entry has a non-canonical mode\n"
            unless $mode == $expected_mode;
          die "directory ZIP entry contains data\n"
            if $directory && ($compressed_size != 0 || $uncompressed_size != 0 || $crc != 0);

          die "duplicate local-header offset\n" if $local_offset{$offset}++;
          die "local header points into the central directory\n"
            if $offset + 30 > $central_offset;
          my $local = read_at($zip, $offset, 30, "local file header");
          my ($local_signature, $local_needed, $local_flags, $local_method,
              $local_time, $local_date, $local_crc, $local_compressed_size,
              $local_uncompressed_size, $local_name_length, $local_extra_length) =
            unpack("VvvvvvVVVvv", $local);
          die "invalid local file header\n" if $local_signature != 0x04034b50;
          die "central/local ZIP metadata mismatch\n"
            if $local_needed != $needed || $local_flags != $flags
              || $local_method != $method || $local_time != $time || $local_date != $date
              || $local_crc != $crc || $local_compressed_size != $compressed_size
              || $local_uncompressed_size != $uncompressed_size || $local_extra_length != 0;
          my $local_name = read_at($zip, $offset + 30, $local_name_length, "local entry name");
          die "central/local ZIP entry name mismatch\n"
            if $local_name_length != $name_length || $local_name ne $name;
          my $data_end = $offset + 30 + $local_name_length + $local_extra_length
            + $compressed_size;
          die "ZIP entry data overlaps the central directory\n"
            if $data_end > $central_offset;
          push @regions, [$offset, $data_end];
          push @payloads, [
            $method,
            $offset + 30 + $local_name_length + $local_extra_length,
            $compressed_size,
            $uncompressed_size,
            $crc,
          ];
        }
        die "central directory has trailing or missing records\n"
          if $position != $central_offset + $central_size;
        die "archive is missing its exact root directory entry\n"
          unless ($explicit_entry{lc($root)} // "") eq "directory";

        @regions = sort { $a->[0] <=> $b->[0] } @regions;
        my $expected_offset = 0;
        for my $region (@regions) {
          die "ZIP local records overlap or contain unparsed gaps\n"
            if $region->[0] != $expected_offset || $region->[1] < $region->[0];
          $expected_offset = $region->[1];
        }
        die "ZIP contains unparsed bytes before the central directory\n"
          if $expected_offset != $central_offset;

        # Header values are attacker-controlled and therefore cannot bound
        # system unzip/ditto by themselves. Stream every payload from this
        # same descriptor, cap actual output as it is produced, and require
        # exact actual size and CRC before either system extractor is called.
        my $actual_total_uncompressed = 0;
        for my $payload (@payloads) {
          my ($method, $data_offset, $compressed_size, $declared_size, $declared_crc) =
            @$payload;
          my $actual_size = 0;
          my $actual_crc = 0;
          my $account_output = sub {
            my ($output) = @_;
            my $output_size = length($output);
            return if $output_size == 0;
            $actual_size += $output_size;
            $actual_total_uncompressed += $output_size;
            die "ZIP resource limit exceeded: actual single entry size\n"
              if $actual_size > 536_870_912;
            die "ZIP resource limit exceeded: actual total uncompressed size\n"
              if $actual_total_uncompressed > 1_073_741_824;
            die "ZIP resource limit exceeded: actual expansion ratio\n"
              if $actual_size > ($compressed_size * 200) + 1_048_576;
            $actual_crc = crc32($output, $actual_crc);
          };

          seek($zip, $data_offset, 0) or die "seek ZIP entry payload: $!\n";
          if ($method == 0) {
            my $remaining = $compressed_size;
            while ($remaining > 0) {
              my $wanted = $remaining > 65_536 ? 65_536 : $remaining;
              my $chunk = "";
              my $count = read($zip, $chunk, $wanted);
              die "truncated stored ZIP payload\n"
                if !defined($count) || $count != $wanted;
              $remaining -= $count;
              $account_output->($chunk);
            }
          } else {
            my ($inflater, $inflate_status) = Compress::Raw::Zlib::Inflate->new(
              -WindowBits => -MAX_WBITS,
              -LimitOutput => 1,
              -ConsumeInput => 1,
              -Bufsize => 65_536,
            );
            die "unable to initialize bounded raw Deflate validation\n"
              if !defined($inflater) || $inflate_status != Z_OK;
            my $remaining = $compressed_size;
            my $stream_ended = 0;
            while ($remaining > 0 && !$stream_ended) {
              my $wanted = $remaining > 65_536 ? 65_536 : $remaining;
              my $input = "";
              my $count = read($zip, $input, $wanted);
              die "truncated Deflate ZIP payload\n"
                if !defined($count) || $count != $wanted;
              $remaining -= $count;
              while (1) {
                my $input_before = length($input);
                my $output = "";
                $inflate_status = $inflater->inflate(
                  $input,
                  $output,
                  $remaining == 0 ? 1 : 0,
                );
                $account_output->($output);
                if ($inflate_status == Z_STREAM_END) {
                  die "Deflate stream has trailing compressed bytes\n"
                    if length($input) != 0 || $remaining != 0;
                  $stream_ended = 1;
                  last;
                }
                die "invalid Deflate stream in ZIP payload\n"
                  if $inflate_status != Z_OK && $inflate_status != Z_BUF_ERROR;
                die "Deflate validation made no progress\n"
                  if length($input) == $input_before && length($output) == 0
                    && length($input) != 0;
                last if length($input) == 0 && length($output) == 0;
              }
            }
            die "truncated Deflate stream in ZIP payload\n" unless $stream_ended;
          }
          die "ZIP payload actual size differs from declared size\n"
            if $actual_size != $declared_size;
          die "ZIP payload CRC differs from declared CRC\n"
            if $actual_crc != $declared_crc;
        }
        close $zip or die "close ZIP descriptor: $!\n";
      ' "$expected_root" "$BINARY_NAME" <&7; then
    echo "Release archive failed structural preflight: $ARCHIVE_SESSION_PATH" >&2
    return 1
  fi
  archive_session_check_identity
}

validate_archive_entries() {
  local zip_path="$1"

  if [ "$ARCHIVE_SESSION_ACTIVE" = true ]; then
    if [ "$zip_path" != "$ARCHIVE_SESSION_PATH" ]; then
      echo "Archive validator escaped its bound descriptor session." >&2
      return 1
    fi
    validate_archive_entries_from_open_session
    return
  fi
  run_archive_session "$zip_path" validate "" "" 7<"$zip_path"
}

run_archive_session() {
  local zip_path="$1"
  local operation="$2"
  local extract_dir="$3"
  local expected_sha256="$4"
  local initial_digest
  local final_digest
  local final_identity
  local extracted_bundle
  local identity_dev identity_ino identity_mode identity_nlink archive_size
  local identity_mtime_sec identity_mtime_nsec identity_ctime_sec identity_ctime_nsec
  local status=0

  case "$operation" in validate|extract) ;;
    *) echo "Invalid archive session operation." >&2; return 1 ;;
  esac
  require_single_link_regular_file "$zip_path" "Release archive" || return 1
  if [ -n "$expected_sha256" ] && ! valid_sha256 "$expected_sha256"; then
    echo "Archive session expected SHA-256 is invalid." >&2
    return 1
  fi
  ARCHIVE_SESSION_PATH="$zip_path"
  ARCHIVE_SESSION_IDENTITY="$(archive_session_bind_path "$zip_path")" || return 1
  IFS=: read -r identity_dev identity_ino identity_mode identity_nlink archive_size \
    identity_mtime_sec identity_mtime_nsec identity_ctime_sec identity_ctime_nsec \
    <<<"$ARCHIVE_SESSION_IDENTITY"
  if [ -z "$archive_size" ] || [ "$archive_size" -gt 536870912 ]; then
    echo "ZIP resource limit exceeded: archive bytes" >&2
    ARCHIVE_SESSION_ACTIVE=false
    ARCHIVE_SESSION_PATH=""
    ARCHIVE_SESSION_IDENTITY=""
    return 1
  fi
  ARCHIVE_SESSION_ACTIVE=true

  initial_digest="$(archive_session_sha256)" || status=1
  if [ "$status" -eq 0 ] && [ -n "$expected_sha256" ] \
    && [ "$initial_digest" != "$expected_sha256" ]; then
    echo "Archive session bytes do not match the expected SHA-256." >&2
    status=1
  fi
  if [ "$status" -eq 0 ] && ! validate_archive_entries "$zip_path"; then
    status=1
  fi
  if [ "$status" -eq 0 ]; then
    archive_session_rewind || status=1
  fi
  if [ "$status" -eq 0 ] \
    && ! /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin \
      /usr/bin/unzip -tq /dev/fd/0 <&7 >/dev/null; then
    echo "Release archive failed CRC/inflate preflight: $zip_path" >&2
    status=1
  fi
  if [ "$status" -eq 0 ] && ! archive_session_check_identity; then
    status=1
  fi

  if [ "$status" -eq 0 ] && [ "$operation" = extract ]; then
    /bin/mkdir -m 700 "$extract_dir" || status=1
    extracted_bundle="$extract_dir/$APP_NAME.app"
    if [ "$status" -eq 0 ]; then
      archive_session_rewind || status=1
    fi
    if [ "$status" -eq 0 ] \
      && ! /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin \
        /usr/bin/ditto -x -k /dev/fd/0 "$extract_dir" <&7; then
      echo "Release archive extraction failed: $zip_path" >&2
      status=1
    fi
    if [ "$status" -eq 0 ] && ! archive_session_check_identity; then
      status=1
    fi
    if [ "$status" -eq 0 ] && [ ! -d "$extracted_bundle" ]; then
      echo "Archive does not contain $APP_NAME.app" >&2
      status=1
    fi
    if [ "$status" -eq 0 ] && ! verify_release_bundle "$extracted_bundle"; then
      status=1
    fi
    if [ "$status" -eq 0 ] && ! archive_session_check_identity; then
      status=1
    fi
  fi

  if [ "$status" -eq 0 ]; then
    final_digest="$(archive_session_sha256)" || status=1
  fi
  if [ "$status" -eq 0 ] && [ "$final_digest" != "$initial_digest" ]; then
    echo "Archive descriptor bytes changed during validation or extraction." >&2
    status=1
  fi
  if [ "$status" -eq 0 ]; then
    final_identity="$(archive_session_bind_path "$zip_path")" || status=1
  fi
  if [ "$status" -eq 0 ] && [ "$final_identity" != "$ARCHIVE_SESSION_IDENTITY" ]; then
    echo "Archive pathname changed during its descriptor-bound session." >&2
    status=1
  fi
  if [ "$status" -eq 0 ]; then
    LAST_VERIFIED_ARCHIVE_SHA256="$initial_digest"
  fi
  ARCHIVE_SESSION_ACTIVE=false
  ARCHIVE_SESSION_PATH=""
  ARCHIVE_SESSION_IDENTITY=""
  return "$status"
}

extract_and_verify_archive() {
  local zip_path="$1"
  local extract_label="${2:-extracted}"
  local expected_sha256="${3:-}"
  local extract_dir

  case "$extract_label" in
    ""|.|..|*/*|*$'\r'*|*$'\n'*)
      echo "Archive verification label is not a safe directory name." >&2
      return 1
      ;;
  esac
  extract_dir="$STAGE_DIR/$extract_label"
  if [ -e "$extract_dir" ] || [ -L "$extract_dir" ]; then
    echo "Archive verification directory already exists: $extract_dir" >&2
    return 1
  fi
  run_archive_session "$zip_path" extract "$extract_dir" "$expected_sha256" 7<"$zip_path"
}

reexecute_release_from_materialized_snapshot() {
  local reexec_script="$RELEASE_SOURCE_DIR/script/package_macos.sh"
  local reexec_bundle="$RELEASE_SOURCE_DIR/script/macos_bundle.sh"
  local reexec_argument="--local-signed-release"
  local package_memory_sha256
  local bundle_memory_sha256
  local committed_package_oid
  local committed_bundle_oid
  local memory_package_oid
  local memory_bundle_oid
  local package_script_base64
  local bundle_script_base64
  local bundle_last_byte
  local package_descriptor_path
  local bundle_descriptor_path
  local -a clean_child_environment

  if [ "$RELEASE" != true ] || [ "$LOCAL_SIGNED_RELEASE" != true ]; then
    echo "Refusing macOS snapshot re-execution without explicit --local-signed-release opt-in." >&2
    return 1
  fi
  verify_release_snapshot_unchanged || return 1
  if [ ! -f "$reexec_script" ] || [ -L "$reexec_script" ] \
    || [ ! -f "$reexec_bundle" ] || [ -L "$reexec_bundle" ]; then
    echo "Materialized release scripts are unavailable for pinned re-execution." >&2
    return 1
  fi

  committed_package_oid="$(
    sanitized_git -C "$ROOT_DIR" rev-parse --verify \
      "$RELEASE_GIT_COMMIT:script/package_macos.sh"
  )"
  committed_bundle_oid="$(
    sanitized_git -C "$ROOT_DIR" rev-parse --verify \
      "$RELEASE_GIT_COMMIT:script/macos_bundle.sh"
  )"
  valid_git_object_id "$committed_package_oid" \
    && valid_git_object_id "$committed_bundle_oid" || {
      echo "Unable to resolve committed macOS release-script blobs." >&2
      return 1
    }

  # Read both committed scripts completely into base64 shell memory and verify
  # both Git blob IDs. They are then written into private files, opened twice,
  # and unlinked. A fixed `bash -c` bootstrap authenticates and sources only the
  # packager. That committed packager binds its helper descriptor to the captured
  # Git snapshot by SHA-256 and blob ID before it interprets any helper bytes.
  package_script_base64="$(
    set -o pipefail
    sanitized_git -C "$ROOT_DIR" show "$RELEASE_GIT_COMMIT:script/package_macos.sh" \
      | /usr/bin/base64 | /usr/bin/tr -d '\r\n'
  )" || return 1
  bundle_script_base64="$(
    set -o pipefail
    sanitized_git -C "$ROOT_DIR" show "$RELEASE_GIT_COMMIT:script/macos_bundle.sh" \
      | /usr/bin/base64 | /usr/bin/tr -d '\r\n'
  )" || return 1
  package_memory_sha256="$(
    /usr/bin/printf '%s' "$package_script_base64" \
      | /usr/bin/base64 -D \
      | /usr/bin/shasum -a 256 \
      | /usr/bin/awk '{ print $1; exit }'
  )"
  bundle_memory_sha256="$(
    /usr/bin/printf '%s' "$bundle_script_base64" \
      | /usr/bin/base64 -D \
      | /usr/bin/shasum -a 256 \
      | /usr/bin/awk '{ print $1; exit }'
  )"
  memory_package_oid="$(
    /usr/bin/printf '%s' "$package_script_base64" \
      | /usr/bin/base64 -D \
      | sanitized_git -C "$ROOT_DIR" hash-object --stdin
  )"
  memory_bundle_oid="$(
    /usr/bin/printf '%s' "$bundle_script_base64" \
      | /usr/bin/base64 -D \
      | sanitized_git -C "$ROOT_DIR" hash-object --stdin
  )"
  bundle_last_byte="$(
    /usr/bin/printf '%s' "$bundle_script_base64" \
      | /usr/bin/base64 -D \
      | /usr/bin/tail -c 1 \
      | /usr/bin/od -An -tu1 \
      | /usr/bin/tr -d ' '
  )"
  if ! valid_sha256 "$package_memory_sha256" \
    || ! valid_sha256 "$bundle_memory_sha256" \
    || [ "$memory_package_oid" != "$committed_package_oid" ] \
    || [ "$memory_bundle_oid" != "$committed_bundle_oid" ] \
    || [ "$bundle_last_byte" != 10 ]; then
    echo "In-memory macOS release-script bytes do not match the captured commit." >&2
    return 1
  fi
  verify_release_snapshot_unchanged || return 1
  package_descriptor_path="$(private_release_mktemp committed-package-macos)" || return 1
  bundle_descriptor_path="$(private_release_mktemp committed-macos-bundle)" || return 1
  /usr/bin/printf '%s' "$package_script_base64" \
    | /usr/bin/base64 -D >"$package_descriptor_path" || return 1
  /usr/bin/printf '%s' "$bundle_script_base64" \
    | /usr/bin/base64 -D >"$bundle_descriptor_path" || return 1
  /bin/chmod 400 "$package_descriptor_path" "$bundle_descriptor_path" || return 1
  require_single_link_regular_file "$package_descriptor_path" \
    "Committed packager descriptor source" || return 1
  require_single_link_regular_file "$bundle_descriptor_path" \
    "Committed bundle-helper descriptor source" || return 1
  if [ "$(release_tool_sha256 "$package_descriptor_path")" != "$package_memory_sha256" ] \
    || [ "$(release_tool_sha256 "$bundle_descriptor_path")" != "$bundle_memory_sha256" ]; then
    echo "Materialized descriptor bytes changed before anonymous execution." >&2
    return 1
  fi
  exec 8<"$package_descriptor_path"
  exec 9<"$package_descriptor_path"
  exec 7<"$bundle_descriptor_path"
  exec 6<"$bundle_descriptor_path"
  /bin/rm -f -- "$package_descriptor_path" "$bundle_descriptor_path" || return 1
  if [ -e "$package_descriptor_path" ] || [ -L "$package_descriptor_path" ] \
    || [ -e "$bundle_descriptor_path" ] || [ -L "$bundle_descriptor_path" ]; then
    echo "Committed release descriptors retained mutable pathnames." >&2
    return 1
  fi

  # No ambient internal state reaches the child. Only explicitly whitelisted
  # public release inputs survive; private paths and identities are positional
  # arguments consumed before the committed packager parses public arguments.
  clean_child_environment=(
    /usr/bin/env -i
    PATH=/usr/bin:/bin:/usr/sbin:/sbin
    "HOME=${HOME:-/var/empty}"
    "WAAL_BUILD_VERSION=${WAAL_BUILD_VERSION:-}"
    "WAAL_RELEASE_BUNDLE_ID=${WAAL_RELEASE_BUNDLE_ID:-}"
    "WAAL_MACOS_TEAM_ID=${WAAL_MACOS_TEAM_ID:-}"
    "WAAL_CODESIGN_IDENTITY=${WAAL_CODESIGN_IDENTITY:-}"
    "WAAL_NOTARY_PROFILE=${WAAL_NOTARY_PROFILE:-}"
    "WAAL_RELEASE_CARGO_PATH=${WAAL_RELEASE_CARGO_PATH:-}"
    "WAAL_RELEASE_RUSTC_PATH=${WAAL_RELEASE_RUSTC_PATH:-}"
    "WAAL_RELEASE_RUST_SYSROOT=${WAAL_RELEASE_RUST_SYSROOT:-}"
    "WAAL_MACOS_DEVELOPER_DIR=${WAAL_MACOS_DEVELOPER_DIR:-}"
    "WAAL_MACOS_SDKROOT=${WAAL_MACOS_SDKROOT:-}"
    "WAAL_MACOS_CLANG_RESOURCE_DIR=${WAAL_MACOS_CLANG_RESOURCE_DIR:-}"
    "WAAL_RELEASE_EXPECTED_GIT_SHA256=${WAAL_RELEASE_EXPECTED_GIT_SHA256:-}"
    "WAAL_RELEASE_EXPECTED_CARGO_SHA256=${WAAL_RELEASE_EXPECTED_CARGO_SHA256:-}"
    "WAAL_RELEASE_EXPECTED_RUSTC_SHA256=${WAAL_RELEASE_EXPECTED_RUSTC_SHA256:-}"
    "WAAL_RELEASE_EXPECTED_RUST_SYSROOT_SHA256=${WAAL_RELEASE_EXPECTED_RUST_SYSROOT_SHA256:-}"
    "WAAL_RELEASE_EXPECTED_CLANG_SHA256=${WAAL_RELEASE_EXPECTED_CLANG_SHA256:-}"
    "WAAL_RELEASE_EXPECTED_CLANGXX_SHA256=${WAAL_RELEASE_EXPECTED_CLANGXX_SHA256:-}"
    "WAAL_RELEASE_EXPECTED_AR_SHA256=${WAAL_RELEASE_EXPECTED_AR_SHA256:-}"
    "WAAL_RELEASE_EXPECTED_LD_SHA256=${WAAL_RELEASE_EXPECTED_LD_SHA256:-}"
    "WAAL_RELEASE_EXPECTED_LD_TAPI_SHA256=${WAAL_RELEASE_EXPECTED_LD_TAPI_SHA256:-}"
    "WAAL_RELEASE_EXPECTED_LD_CODEDIRECTORY_SHA256=${WAAL_RELEASE_EXPECTED_LD_CODEDIRECTORY_SHA256:-}"
    "WAAL_RELEASE_EXPECTED_LD_LTO_SHA256=${WAAL_RELEASE_EXPECTED_LD_LTO_SHA256:-}"
    "WAAL_RELEASE_EXPECTED_LD_SWIFT_DEMANGLE_SHA256=${WAAL_RELEASE_EXPECTED_LD_SWIFT_DEMANGLE_SHA256:-}"
    "WAAL_RELEASE_EXPECTED_NOTARYTOOL_SHA256=${WAAL_RELEASE_EXPECTED_NOTARYTOOL_SHA256:-}"
    "WAAL_RELEASE_EXPECTED_STAPLER_SHA256=${WAAL_RELEASE_EXPECTED_STAPLER_SHA256:-}"
    "WAAL_RELEASE_EXPECTED_MACOS_SDK_SHA256=${WAAL_RELEASE_EXPECTED_MACOS_SDK_SHA256:-}"
    "WAAL_RELEASE_EXPECTED_CLANG_RESOURCE_DIR_SHA256=${WAAL_RELEASE_EXPECTED_CLANG_RESOURCE_DIR_SHA256:-}"
    "WAAL_RELEASE_EXPECTED_NATIVE_TOOLCHAIN_SHA256=${WAAL_RELEASE_EXPECTED_NATIVE_TOOLCHAIN_SHA256:-}"
  )
  exec "${clean_child_environment[@]}" \
    /bin/bash --noprofile --norc -p -c '
      set -euo pipefail
      expected_package_sha256="$1"
      expected_bundle_sha256="$2"
      expected_package_oid="$3"
      expected_bundle_oid="$4"
      shift 4

      descriptor_identity() {
        /usr/bin/stat -f "%d:%i:%p:%l:%z" "$1"
      }
      package_execution_identity="$(descriptor_identity /dev/fd/8)"
      package_verification_identity="$(descriptor_identity /dev/fd/9)"
      bundle_execution_identity="$(descriptor_identity /dev/fd/7)"
      bundle_verification_identity="$(descriptor_identity /dev/fd/6)"
      IFS=: read -r package_device package_inode package_mode package_nlink package_size \
        <<<"$package_execution_identity"
      IFS=: read -r bundle_device bundle_inode bundle_mode bundle_nlink bundle_size \
        <<<"$bundle_execution_identity"
      [ -f /dev/fd/8 ] && [ -f /dev/fd/9 ] \
        && [ -f /dev/fd/7 ] && [ -f /dev/fd/6 ] \
        && [ "$package_nlink" = 0 ] && [ "$bundle_nlink" = 0 ] \
        && [ "$package_execution_identity" = "$package_verification_identity" ] \
        && [ "$bundle_execution_identity" = "$bundle_verification_identity" ] || {
          echo "Committed release-script descriptor pairs are not exact anonymous regular inodes." >&2
          exit 1
        }
      actual_package_sha256="$(
        /usr/bin/shasum -a 256 /dev/fd/9 | /usr/bin/awk "{ print \$1; exit }"
      )"
      actual_bundle_sha256="$(
        /usr/bin/shasum -a 256 /dev/fd/6 | /usr/bin/awk "{ print \$1; exit }"
      )"
      [ "$actual_package_sha256" = "$expected_package_sha256" ] \
        && [ "$actual_bundle_sha256" = "$expected_bundle_sha256" ] \
        && [ "$(descriptor_identity /dev/fd/8)" = "$package_execution_identity" ] \
        && [ "$(descriptor_identity /dev/fd/7)" = "$bundle_execution_identity" ] || {
          echo "Committed release-script descriptor bytes changed before interpretation." >&2
          exit 1
        }

      execution_source_root="$1"
      checkout_root="$2"
      shift 2
      builtin source /dev/fd/8 \
        --internal-committed-snapshot \
        "$execution_source_root" "$checkout_root" \
        "$expected_package_sha256" "$expected_bundle_sha256" \
        "$expected_package_oid" "$expected_bundle_oid" "$@"
      exec 8<&- 9<&-
      package_macos_main
    ' waal-committed-release-bootstrap \
    "$package_memory_sha256" "$bundle_memory_sha256" \
    "$committed_package_oid" "$committed_bundle_oid" \
    "$RELEASE_SOURCE_DIR" "$ROOT_DIR" \
    "$RELEASE_PRIVATE_ROOT" "$RELEASE_PRIVATE_ROOT_PARENT" \
    "$RELEASE_PRIVATE_ROOT_ID" "$RELEASE_PRIVATE_ROOT_PARENT_ID" \
    "$RELEASE_GIT_COMMIT" "$RELEASE_GIT_TREE" "$reexec_argument"
}

restore_and_verify_snapshot_execution() {
  local expected_commit="$INHERITED_RELEASE_GIT_COMMIT"
  local expected_tree="$INHERITED_RELEASE_GIT_TREE"
  local expected_source_dir

  RELEASE_PRIVATE_ROOT="$INHERITED_RELEASE_PRIVATE_ROOT"
  RELEASE_PRIVATE_ROOT_PARENT="$INHERITED_RELEASE_PRIVATE_ROOT_PARENT"
  RELEASE_PRIVATE_ROOT_ID="$INHERITED_RELEASE_PRIVATE_ROOT_ID"
  RELEASE_PRIVATE_ROOT_PARENT_ID="$INHERITED_RELEASE_PRIVATE_ROOT_PARENT_ID"
  STAGE_DIR="$RELEASE_PRIVATE_ROOT/stage"
  RELEASE_TEMP_DIR="$RELEASE_PRIVATE_ROOT/tmp"
  RELEASE_SOURCE_ROOT="$RELEASE_PRIVATE_ROOT/source-environment"
  expected_source_dir="$RELEASE_SOURCE_ROOT/source"
  RELEASE_SOURCE_DIR="$EXECUTION_SOURCE_ROOT"

  if ! valid_git_object_id "$expected_commit" || ! valid_git_object_id "$expected_tree" \
    || [ "$RELEASE_PRIVATE_ROOT_PARENT" != "$ROOT_DIR/dist" ] \
    || [ "$RELEASE_SOURCE_DIR" != "$expected_source_dir" ]; then
    echo "Invalid state for materialized macOS release execution." >&2
    return 1
  fi
  verify_private_release_root || return 1
  if [ ! -d "$STAGE_DIR" ] || [ -L "$STAGE_DIR" ] \
    || [ ! -d "$RELEASE_TEMP_DIR" ] || [ -L "$RELEASE_TEMP_DIR" ] \
    || [ ! -d "$RELEASE_SOURCE_ROOT" ] || [ -L "$RELEASE_SOURCE_ROOT" ]; then
    echo "Private release snapshot directories changed before re-execution." >&2
    return 1
  fi

  RELEASE_GIT_COMMIT="$expected_commit"
  RELEASE_GIT_TREE="$expected_tree"
  RELEASE_GIT_SOURCE_ROOT="$ROOT_DIR"
  RELEASE_SOURCE_IDENTITY_SHA256=""
  RELEASE_SOURCE_FREEZE_ATTEMPTED=false
  RELEASE_SOURCE_FROZEN=false
  RELEASE_SOURCE_FREEZE_ROOT_ID=""
  verify_loaded_packager_matches_snapshot || return 1
  verify_release_snapshot_unchanged || return 1
  capture_release_provenance_for_root "$ROOT_DIR" || return 1
  if [ "$RELEASE_GIT_COMMIT" != "$expected_commit" ] \
    || [ "$RELEASE_GIT_TREE" != "$expected_tree" ]; then
    echo "Release checkout changed before pinned packager execution." >&2
    return 1
  fi
  verify_loaded_packager_matches_snapshot || return 1
  verify_release_snapshot_unchanged || return 1
  load_authenticated_bundle_helper || return 1
  capture_release_source_identity_baseline || return 1
  verify_release_source_identity_guard || return 1
  CARGO_VERSION="$(waal_cargo_version "$RELEASE_SOURCE_DIR")"
  BUILD_VERSION="$(waal_build_version "$CARGO_VERSION")"
  verify_release_source_identity_guard || return 1
  initialize_release_publication_paths
  ensure_release_publication_state_supported
}

package_macos_main() {
  # Every release-capable execution, including the committed snapshot child,
  # starts from a deterministic creation mask. Exact mode allowlists below
  # remain authoritative for staged, archived, extracted, and published data.
  umask 022
  trap cleanup EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
  if [ "$RELEASE_SNAPSHOT_REEXECUTED" = false ]; then
    prepare_dist_root
    create_private_release_root
    capture_release_provenance
    initialize_release_publication_paths
    ensure_release_publication_state_supported
    materialize_release_source
    verify_release_source_unchanged
    reexecute_release_from_materialized_snapshot
    echo "Pinned macOS release packager re-execution unexpectedly returned." >&2
    return 1
  fi

  restore_and_verify_snapshot_execution

  require_tool codesign
  require_tool ditto
  require_tool iconutil
  require_tool lipo
  require_tool mktemp
  require_tool od
  require_tool perl
  require_tool plutil
  require_tool shasum
  require_tool sips
  require_tool sort
  require_tool spctl
  require_tool stat
  require_tool strings
  require_tool tar
  require_tool tr
  require_tool unzip
  require_tool xattr
  require_tool zip
  require_tool zipinfo

  validate_release_environment

  prepare_isolated_release_cargo_home
  resolve_and_verify_release_toolchain_guarded
  verify_release_source_unchanged
  verify_loaded_packager_matches_snapshot

  STAGED_BUNDLE="$STAGE_DIR/$APP_NAME.app"
  TMP_ZIP="$STAGE_DIR/$(/usr/bin/basename "$ZIP_PATH")"
  TMP_ZIP_SHA256="$STAGE_DIR/$(/usr/bin/basename "$ZIP_SHA256_PATH")"
  prepare_atomic_no_replace_rename_helper

  EXISTING_PUBLICATION_STATE="$(release_publication_state)"
  case "$EXISTING_PUBLICATION_STATE" in
    archive-only|complete)
      finalize_release_source_identity_guard
      repair_or_adopt_existing_release "$EXISTING_PUBLICATION_STATE"
      /usr/bin/printf 'Local signed ZIP (NOT PUBLISHABLE): %s\nSHA-256 sidecar: %s\nSHA-256: %s\n' \
        "$ZIP_PATH" "$ZIP_SHA256_PATH" "$PUBLISHED_ZIP_SHA256"
      return 0
      ;;
    empty) ;;
    *)
      echo "Unsupported immutable release publication state: $EXISTING_PUBLICATION_STATE" >&2
      return 1
      ;;
  esac

  build_release_executable
  assemble_release_bundle "$STAGED_BUNDLE"
  finalize_release_source_identity_guard
  write_macos_release_provenance "$STAGED_BUNDLE"
  verify_release_build_metadata "$STAGED_BUNDLE"
  remove_signature_breaking_xattrs "$STAGED_BUNDLE"

  /usr/bin/find "$STAGED_BUNDLE" \( -name .DS_Store -o -name '._*' \) -type f -delete
  /usr/bin/find "$STAGED_BUNDLE" -type d -name __MACOSX -prune -exec /bin/rm -rf {} +

  capture_release_bundle_payload_baseline "$STAGED_BUNDLE"
  sign_release_bundle "$STAGED_BUNDLE"
  notarize_and_staple_bundle "$STAGED_BUNDLE"

  verify_release_bundle "$STAGED_BUNDLE"

  verify_release_bundle_payload_baseline "$STAGED_BUNDLE"
  (
    cd "$STAGE_DIR"
    sanitized_zip -r -X "$(/usr/bin/basename "$TMP_ZIP")" "$APP_NAME.app" \
      -x "*/.DS_Store" "*/._*" "__MACOSX/*" "*/__MACOSX/*" >/dev/null
  )
  /bin/chmod 644 "$TMP_ZIP"
  require_public_release_file "$TMP_ZIP" \
    "Verified release archive candidate"
  verify_release_bundle_payload_baseline "$STAGED_BUNDLE"

  extract_and_verify_archive "$TMP_ZIP" candidate-extracted
  verify_release_source_unchanged
  verify_release_build_toolchain_guard

  CANDIDATE_ZIP_SHA256="$LAST_VERIFIED_ARCHIVE_SHA256"
  if ! valid_sha256 "$CANDIDATE_ZIP_SHA256"; then
    echo "Unable to compute the verified release archive SHA-256." >&2
    exit 1
  fi

  publish_verified_release_pair \
    "$TMP_ZIP" "$TMP_ZIP_SHA256" "$CANDIDATE_ZIP_SHA256"
  PUBLISHED_ZIP_SHA256="$CANDIDATE_ZIP_SHA256"
  extract_and_verify_archive \
    "$ZIP_PATH" published-extracted "$CANDIDATE_ZIP_SHA256"
  verify_release_source_unchanged
  verify_release_build_toolchain_guard

  /usr/bin/printf 'Local signed ZIP (NOT PUBLISHABLE): %s\nSHA-256 sidecar: %s\nSHA-256: %s\n' \
    "$ZIP_PATH" "$ZIP_SHA256_PATH" "$PUBLISHED_ZIP_SHA256"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  package_macos_main
fi
