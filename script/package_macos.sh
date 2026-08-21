#!/usr/bin/env bash
set -euo pipefail
# Release packaging never searches a user-controlled HOME for executables.
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && /bin/pwd -P)"
# shellcheck source=script/macos_bundle.sh
source "$ROOT_DIR/script/macos_bundle.sh"
PRODUCTION_APP_NAME="WindowsAppAutoLogin"
DIAGNOSTICS_APP_NAME="WindowsAppAutoLoginDiagnostics"
APP_NAME="$PRODUCTION_APP_NAME"
APP_DISPLAY_NAME="Windows App AutoLogin"
DEVELOPMENT_BUNDLE_ID="obcardinal.windows-app-autologin"
ZIP_PATH=""
ZIP_SHA256_PATH=""
RELEASE_ARCHIVE_BASE=""
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
ATOMIC_RENAME_HELPER=""
ATOMIC_RENAME_HELPER_SHA256=""
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
  RELEASE_ARCHIVE_BASE="$APP_NAME-macos-release-diagnostics"
  EXPECTED_BUNDLE_ID="$DIAGNOSTICS_BUNDLE_ID"
  EXPECTED_BUNDLE_ID_ENV="WAAL_DIAGNOSTICS_BUNDLE_ID"
else
  APP_NAME="$PRODUCTION_APP_NAME"
  RELEASE_ARCHIVE_BASE="$APP_NAME-macos"
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
          lstat($path) or die "lstat failed: $!\n";
          die "snapshot contains a symbolic link\n" if -l _;
          return if -d _;
          die "snapshot contains a non-regular node\n" unless -f _;
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
        open my $file, "<:raw", $full or die "open snapshot file: $!\n";
        local $/;
        my $content = <$file>;
        close $file or die "close snapshot file: $!\n";
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
  CARGO_VERSION="$(waal_cargo_version "$RELEASE_SOURCE_DIR")"
  BUILD_VERSION="$(waal_build_version "$CARGO_VERSION")"
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
  local actual_native_toolchain_sha256
  local actual_materials_sha256

  verify_release_git_integrity || return 1
  verify_release_file_sha256 "$RELEASE_CARGO_BIN" "$RELEASE_CARGO_SHA256" "Cargo" || return 1
  verify_release_file_sha256 "$RELEASE_RUSTC_BIN" "$RELEASE_RUSTC_SHA256" "rustc" || return 1
  verify_release_tool_under_root "$RELEASE_CLANG_BIN" "$RELEASE_DEVELOPER_DIR" "$RELEASE_CLANG_SHA256" "clang" || return 1
  verify_release_tool_under_root "$RELEASE_CLANGXX_BIN" "$RELEASE_DEVELOPER_DIR" "$RELEASE_CLANGXX_SHA256" "clang++" || return 1
  verify_release_tool_under_root "$RELEASE_AR_BIN" "$RELEASE_DEVELOPER_DIR" "$RELEASE_AR_SHA256" "ar" || return 1
  verify_release_tool_under_root "$RELEASE_LD_BIN" "$RELEASE_DEVELOPER_DIR" "$RELEASE_LD_SHA256" "ld" || return 1
  verify_release_tool_under_root "$RELEASE_LD_TAPI_BIN" "$RELEASE_DEVELOPER_DIR" "$RELEASE_LD_TAPI_SHA256" "ld libtapi" || return 1
  verify_release_tool_under_root "$RELEASE_LD_CODEDIRECTORY_BIN" "$RELEASE_DEVELOPER_DIR" "$RELEASE_LD_CODEDIRECTORY_SHA256" "ld libcodedirectory" || return 1
  verify_release_tool_under_root "$RELEASE_LD_LTO_BIN" "$RELEASE_DEVELOPER_DIR" "$RELEASE_LD_LTO_SHA256" "ld libLTO" || return 1
  verify_release_tool_under_root "$RELEASE_LD_SWIFT_DEMANGLE_BIN" "$RELEASE_DEVELOPER_DIR" "$RELEASE_LD_SWIFT_DEMANGLE_SHA256" "ld libswiftDemangle" || return 1
  verify_release_tool_under_root "$RELEASE_NOTARYTOOL_BIN" "$RELEASE_DEVELOPER_DIR" "$RELEASE_NOTARYTOOL_SHA256" "notarytool" || return 1
  verify_release_tool_under_root "$RELEASE_STAPLER_BIN" "$RELEASE_DEVELOPER_DIR" "$RELEASE_STAPLER_SHA256" "stapler" || return 1

  if [ ! -d "$RELEASE_DEVELOPER_DIR" ] || [ -L "$RELEASE_DEVELOPER_DIR" ] \
    || [ "$(cd "$RELEASE_DEVELOPER_DIR" 2>/dev/null && /bin/pwd -P)" != "$RELEASE_DEVELOPER_DIR" ]; then
    echo "The explicitly selected Xcode Developer directory is no longer physical." >&2
    return 1
  fi
  if [ "$(resolve_release_directory_under_root "$RELEASE_SDKROOT" "$RELEASE_DEVELOPER_DIR" 'macOS SDK')" != "$RELEASE_SDKROOT" ]; then
    echo "The pinned macOS SDK path changed after release initialization." >&2
    return 1
  fi
  if [ "$(resolve_release_directory_under_root "$RELEASE_CLANG_RESOURCE_DIR" "$RELEASE_DEVELOPER_DIR" 'Clang resource directory')" != "$RELEASE_CLANG_RESOURCE_DIR" ]; then
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
  verify_release_snapshot_unchanged
  verify_release_toolchain_integrity

  if ! (
    cd "$RELEASE_CARGO_WORK_DIR"
    /usr/bin/env -i \
      HOME="$RELEASE_BUILD_HOME" \
      CARGO_HOME="$RELEASE_CARGO_HOME" \
      TMPDIR="$RELEASE_BUILD_TMPDIR" \
      PATH=/usr/bin:/bin:/usr/sbin:/sbin \
      DEVELOPER_DIR="$RELEASE_DEVELOPER_DIR" \
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
      WAAL_PUBLISHABLE_RELEASE=1 \
      WAAL_RELEASE_BUNDLE_ID="$PRODUCTION_BUNDLE_ID" \
      WAAL_DIAGNOSTICS_BUNDLE_ID="$DIAGNOSTICS_BUNDLE_ID" \
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
    return 1
  fi
  verify_release_snapshot_unchanged
  verify_release_toolchain_integrity
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
      if [ ! -f "$path" ]; then
        echo "Immutable release artifact must be a regular file: $path" >&2
        return 1
      fi
      if [ "$(/usr/bin/stat -f '%l' "$path")" != "1" ]; then
        echo "Immutable release artifact must not have additional hard links: $path" >&2
        return 1
      fi
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

ensure_release_publication_state_supported() {
  release_publication_state >/dev/null
}

atomic_no_replace_helper_source() {
  /usr/bin/printf '%s\n' \
    '#define _DARWIN_C_SOURCE 1' \
    '#include <errno.h>' \
    '#include <fcntl.h>' \
    '#include <stdio.h>' \
    '#include <string.h>' \
    '#include <sys/stat.h>' \
    '#include <sys/stdio.h>' \
    '#include <unistd.h>' \
    '' \
    'static int report_error(const char *operation, int error_number) {' \
    '    (void)fprintf(stderr, "%s: %s\n", operation, strerror(error_number));' \
    '    return 1;' \
    '}' \
    '' \
    'static int valid_leaf(const char *leaf) {' \
    '    return leaf[0] != 0 && strcmp(leaf, ".") != 0 && strcmp(leaf, "..") != 0' \
    '        && strchr(leaf, (char)47) == NULL;' \
    '}' \
    '' \
    'int main(int argc, char **argv) {' \
    '    struct stat source_directory_status;' \
    '    struct stat destination_directory_status;' \
    '    struct stat source_status;' \
    '    struct stat opened_source_status;' \
    '    struct stat destination_status;' \
    '    int source_directory = -1;' \
    '    int destination_directory = -1;' \
    '    int source_file = -1;' \
    '    int saved_errno;' \
    '' \
    '    if (argc != 5 || !valid_leaf(argv[2]) || !valid_leaf(argv[4])) {' \
    '        (void)fprintf(stderr, "usage: atomic-no-replace SOURCE_DIR SOURCE_NAME DEST_DIR DEST_NAME\n");' \
    '        return 2;' \
    '    }' \
    '    source_directory = open(argv[1], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);' \
    '    if (source_directory < 0) {' \
    '        return report_error("open source directory", errno);' \
    '    }' \
    '    destination_directory = open(argv[3], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);' \
    '    if (destination_directory < 0) {' \
    '        saved_errno = errno;' \
    '        (void)close(source_directory);' \
    '        return report_error("open destination directory", saved_errno);' \
    '    }' \
    '    if (fstat(source_directory, &source_directory_status) != 0' \
    '            || fstat(destination_directory, &destination_directory_status) != 0) {' \
    '        saved_errno = errno;' \
    '        (void)close(source_directory);' \
    '        (void)close(destination_directory);' \
    '        return report_error("inspect publication directories", saved_errno);' \
    '    }' \
    '    if (source_directory_status.st_dev != destination_directory_status.st_dev) {' \
    '        (void)close(source_directory);' \
    '        (void)close(destination_directory);' \
    '        return report_error("publication requires one filesystem", EXDEV);' \
    '    }' \
    '    if (fstatat(source_directory, argv[2], &source_status, AT_SYMLINK_NOFOLLOW) != 0) {' \
    '        saved_errno = errno;' \
    '        (void)close(source_directory);' \
    '        (void)close(destination_directory);' \
    '        return report_error("inspect publication candidate", saved_errno);' \
    '    }' \
    '    if (!S_ISREG(source_status.st_mode)) {' \
    '        (void)close(source_directory);' \
    '        (void)close(destination_directory);' \
    '        return report_error("publication candidate is not regular", EINVAL);' \
    '    }' \
    '    source_file = openat(source_directory, argv[2], O_RDONLY | O_NOFOLLOW | O_CLOEXEC);' \
    '    if (source_file < 0 || fstat(source_file, &opened_source_status) != 0) {' \
    '        saved_errno = errno;' \
    '        if (source_file >= 0) (void)close(source_file);' \
    '        (void)close(source_directory);' \
    '        (void)close(destination_directory);' \
    '        return report_error("open publication candidate", saved_errno);' \
    '    }' \
    '    if (source_status.st_dev != opened_source_status.st_dev' \
    '            || source_status.st_ino != opened_source_status.st_ino' \
    '            || !S_ISREG(opened_source_status.st_mode)) {' \
    '        (void)close(source_file);' \
    '        (void)close(source_directory);' \
    '        (void)close(destination_directory);' \
    '        return report_error("publication candidate changed", EBUSY);' \
    '    }' \
    '    if (fsync(source_file) != 0) {' \
    '        saved_errno = errno;' \
    '        (void)close(source_file);' \
    '        (void)close(source_directory);' \
    '        (void)close(destination_directory);' \
    '        return report_error("flush publication candidate", saved_errno);' \
    '    }' \
    '    (void)close(source_file);' \
    '    if (fstatat(destination_directory, argv[4], &destination_status, AT_SYMLINK_NOFOLLOW) == 0) {' \
    '        (void)close(source_directory);' \
    '        (void)close(destination_directory);' \
    '        return report_error("immutable destination already exists", EEXIST);' \
    '    }' \
    '    if (errno != ENOENT) {' \
    '        saved_errno = errno;' \
    '        (void)close(source_directory);' \
    '        (void)close(destination_directory);' \
    '        return report_error("inspect immutable destination", saved_errno);' \
    '    }' \
    '    if (renameatx_np(source_directory, argv[2], destination_directory, argv[4], RENAME_EXCL) != 0) {' \
    '        saved_errno = errno;' \
    '        (void)close(source_directory);' \
    '        (void)close(destination_directory);' \
    '        return report_error("atomic no-replace rename", saved_errno);' \
    '    }' \
    '    if (fsync(destination_directory) != 0) {' \
    '        saved_errno = errno;' \
    '        (void)close(source_directory);' \
    '        (void)close(destination_directory);' \
    '        return report_error("flush publication directory", saved_errno);' \
    '    }' \
    '    (void)close(source_directory);' \
    '    (void)close(destination_directory);' \
    '    return 0;' \
    '}'
}

prepare_atomic_no_replace_rename_helper() {
  local helper_source="$STAGE_DIR/atomic-no-replace.c"

  ATOMIC_RENAME_HELPER="$STAGE_DIR/atomic-no-replace"
  atomic_no_replace_helper_source >"$helper_source"
  /bin/chmod 600 "$helper_source"
  verify_release_toolchain_integrity
  /usr/bin/env -i \
    PATH=/usr/bin:/bin:/usr/sbin:/sbin \
    HOME="$RELEASE_BUILD_HOME" \
    TMPDIR="$RELEASE_BUILD_TMPDIR" \
    DEVELOPER_DIR="$RELEASE_DEVELOPER_DIR" \
    SDKROOT="$RELEASE_SDKROOT" \
    "$RELEASE_CLANG_BIN" \
      -std=c11 -Os -Wall -Wextra -Werror \
      -isysroot "$RELEASE_SDKROOT" \
      "--ld-path=$RELEASE_LD_BIN" \
      -o "$ATOMIC_RENAME_HELPER" "$helper_source"
  if [ ! -f "$ATOMIC_RENAME_HELPER" ] || [ -L "$ATOMIC_RENAME_HELPER" ]; then
    echo "Failed to build the atomic no-replace publication helper." >&2
    return 1
  fi
  /bin/chmod 700 "$ATOMIC_RENAME_HELPER"
  ATOMIC_RENAME_HELPER_SHA256="$(release_tool_sha256 "$ATOMIC_RENAME_HELPER")"
  if ! valid_sha256 "$ATOMIC_RENAME_HELPER_SHA256"; then
    echo "Failed to hash the atomic no-replace publication helper." >&2
    return 1
  fi
  verify_release_toolchain_integrity
}

atomic_publish_file_no_replace() {
  local source_path="$1"
  local destination_path="$2"
  local source_parent
  local destination_parent
  local physical_source_parent
  local physical_destination_parent

  if [ ! -f "$ATOMIC_RENAME_HELPER" ] || [ ! -x "$ATOMIC_RENAME_HELPER" ] \
    || [ -L "$ATOMIC_RENAME_HELPER" ] \
    || [ "$(release_tool_sha256 "$ATOMIC_RENAME_HELPER")" != "$ATOMIC_RENAME_HELPER_SHA256" ]; then
    echo "Atomic no-replace publication helper is missing or changed." >&2
    return 1
  fi
  if [ ! -f "$source_path" ] || [ -L "$source_path" ]; then
    echo "Publication candidate must be a regular file: $source_path" >&2
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

  if ! "$ATOMIC_RENAME_HELPER" \
    "$source_parent" "$(/usr/bin/basename "$source_path")" \
    "$destination_parent" "$(/usr/bin/basename "$destination_path")"; then
    return 1
  fi

  if [ -e "$source_path" ] || [ -L "$source_path" ]; then
    echo "Atomic publication left the candidate at its staging path." >&2
    return 1
  fi
  if [ ! -f "$destination_path" ] || [ -L "$destination_path" ]; then
    echo "Atomic publication did not create a regular destination file." >&2
    return 1
  fi
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
  if [ ! -f "$sidecar_path" ] || [ -L "$sidecar_path" ]; then
    echo "Failed to create a regular SHA-256 sidecar candidate." >&2
    return 1
  fi
}

verify_release_sha256_sidecar() {
  local sidecar_path="$1"
  local archive_path="$2"
  local archive_sha256="$3"
  local expected_sidecar_sha256
  local actual_sidecar_sha256

  if [ ! -f "$sidecar_path" ] || [ -L "$sidecar_path" ]; then
    echo "Published release is missing its regular SHA-256 sidecar." >&2
    return 1
  fi
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

  if [ ! -f "$archive_path" ] || [ -L "$archive_path" ]; then
    echo "Published release archive is not a regular file." >&2
    return 1
  fi
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

  if ! valid_sha256 "$expected_sha256" \
    || [ ! -f "$candidate_path" ] || [ -L "$candidate_path" ] \
    || [ ! -f "$archive_path" ] || [ -L "$archive_path" ]; then
    echo "Exact immutable archive adoption requires two regular files and a valid digest." >&2
    return 1
  fi
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

  if [ -e "$sidecar_path" ] || [ -L "$sidecar_path" ]; then
    if [ ! -f "$sidecar_path" ] || [ -L "$sidecar_path" ] \
      || [ "$(/usr/bin/stat -f '%l' "$sidecar_path")" != "1" ] \
      || [ ! -f "$candidate_path" ] || [ -L "$candidate_path" ] \
      || ! /usr/bin/cmp -s "$candidate_path" "$sidecar_path"; then
      echo "Existing immutable SHA-256 sidecar differs from the verified candidate." >&2
      return 1
    fi
    return 0
  fi

  if atomic_publish_file_no_replace "$candidate_path" "$sidecar_path"; then
    return 0
  fi
  # The helper can report a directory-fsync failure after the no-replace
  # rename has already happened, or another publisher can win the race. Only
  # exact expected bytes are adoptable; no existing file is ever replaced.
  if [ -f "$candidate_path" ] && [ ! -L "$candidate_path" ]; then
    if [ ! -f "$sidecar_path" ] || [ -L "$sidecar_path" ] \
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
    || [ ! -f "$archive_candidate" ] || [ -L "$archive_candidate" ]; then
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
      if ! atomic_publish_file_no_replace "$archive_candidate" "$ZIP_PATH"; then
        if [ -f "$archive_candidate" ] && [ ! -L "$archive_candidate" ]; then
          verify_published_archive_matches_candidate \
            "$archive_candidate" "$ZIP_PATH" "$expected_sha256" || return 1
        elif [ ! -f "$ZIP_PATH" ] || [ -L "$ZIP_PATH" ] \
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

  if [ ! -f "$ZIP_PATH" ] || [ -L "$ZIP_PATH" ] \
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
  local initial_sha256
  local verified_sha256

  case "$state" in
    archive-only|complete) ;;
    *)
      echo "Only an existing archive can be repaired or adopted." >&2
      return 1
      ;;
  esac
  initial_sha256="$(release_tool_sha256 "$ZIP_PATH")"
  if ! valid_sha256 "$initial_sha256"; then
    echo "Unable to hash the existing immutable release archive." >&2
    return 1
  fi
  if [ "$state" = complete ]; then
    verify_published_release_hash_evidence \
      "$ZIP_PATH" "$ZIP_SHA256_PATH" "$initial_sha256"
  fi

  # The orphan is not trusted merely because it has the right filename. Run
  # the same archive, signature, notarization, bundle metadata, commit/tree,
  # source snapshot, and toolchain verification used for a new candidate.
  validate_archive_entries "$ZIP_PATH"
  extract_and_verify_archive "$ZIP_PATH" existing-published-extracted
  verify_release_source_unchanged
  verify_release_toolchain_integrity
  verified_sha256="$(release_tool_sha256 "$ZIP_PATH")"
  if [ "$verified_sha256" != "$initial_sha256" ]; then
    echo "Existing immutable release archive changed while it was being verified." >&2
    return 1
  fi

  if [ "$state" = archive-only ]; then
    write_release_sha256_sidecar_candidate \
      "$TMP_ZIP_SHA256" "$ZIP_PATH" "$verified_sha256"
    verify_release_sha256_sidecar \
      "$TMP_ZIP_SHA256" "$ZIP_PATH" "$verified_sha256"
    publish_sidecar_candidate_no_replace_or_adopt \
      "$TMP_ZIP_SHA256" "$ZIP_PATH" "$ZIP_SHA256_PATH" "$verified_sha256"
  fi
  verify_published_release_hash_evidence \
    "$ZIP_PATH" "$ZIP_SHA256_PATH" "$verified_sha256"
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
  if [ "$RELEASE_DIAGNOSTICS_ARTIFACT" = true ]; then
    run_sanitized_release_cargo build \
      --locked \
      --release \
      --target aarch64-apple-darwin \
      --manifest-path "$RELEASE_SOURCE_DIR/Cargo.toml" \
      --no-default-features \
      --features release-diagnostics \
      --bin "$BINARY_NAME"
  else
    run_sanitized_release_cargo build \
      --locked \
      --release \
      --target aarch64-apple-darwin \
      --manifest-path "$RELEASE_SOURCE_DIR/Cargo.toml" \
      --bin "$BINARY_NAME"
  fi

  if [ ! -x "$TARGET_EXECUTABLE" ]; then
    echo "Release build did not produce expected executable: $TARGET_EXECUTABLE" >&2
    exit 1
  fi
  verify_release_source_unchanged
}

assemble_release_bundle() {
  local bundle_dir="$1"
  verify_release_snapshot_unchanged
  waal_assemble_app_bundle \
    "$RELEASE_SOURCE_DIR" \
    "$bundle_dir" \
    "$BINARY_NAME" \
    "$TARGET_EXECUTABLE" \
    "$EXPECTED_BUNDLE_ID" \
    "$APP_DISPLAY_NAME" \
    "$CARGO_VERSION" \
    "$BUILD_VERSION"
  verify_release_snapshot_unchanged
}

macos_release_provenance_contents() {
  /usr/bin/printf '%s\n' \
    'WAAL_MACOS_BUILD_PROVENANCE_V1' \
    "source-git-commit=$RELEASE_GIT_COMMIT" \
    "source-git-tree=$RELEASE_GIT_TREE" \
    "git-sha256=$RELEASE_GIT_SHA256" \
    "cargo-version=$RELEASE_CARGO_VERSION" \
    "cargo-sha256=$RELEASE_CARGO_SHA256" \
    "rustc-version=$RELEASE_RUSTC_VERSION" \
    "rustc-sha256=$RELEASE_RUSTC_SHA256" \
    "rust-sysroot-sha256=$RELEASE_RUST_SYSROOT_SHA256" \
    "native-toolchain-sha256=$RELEASE_NATIVE_TOOLCHAIN_SHA256" \
    "release-materials-sha256=$RELEASE_MATERIALS_SHA256" \
    "clang-sha256=$RELEASE_CLANG_SHA256" \
    "clangxx-sha256=$RELEASE_CLANGXX_SHA256" \
    "ar-sha256=$RELEASE_AR_SHA256" \
    "ld-sha256=$RELEASE_LD_SHA256" \
    "ld-libtapi-sha256=$RELEASE_LD_TAPI_SHA256" \
    "ld-libcodedirectory-sha256=$RELEASE_LD_CODEDIRECTORY_SHA256" \
    "ld-liblto-sha256=$RELEASE_LD_LTO_SHA256" \
    "ld-libswift-demangle-sha256=$RELEASE_LD_SWIFT_DEMANGLE_SHA256" \
    "notarytool-sha256=$RELEASE_NOTARYTOOL_SHA256" \
    "stapler-sha256=$RELEASE_STAPLER_SHA256" \
    "macos-sdk-sha256=$RELEASE_MACOS_SDK_SHA256" \
    "clang-resource-dir-sha256=$RELEASE_CLANG_RESOURCE_DIR_SHA256"
}

write_macos_release_provenance() {
  local bundle_dir="$1"
  local provenance_file="$bundle_dir/Contents/Resources/BUILD-PROVENANCE.txt"

  if [ -L "$provenance_file" ]; then
    echo "Refusing to replace a symlinked macOS provenance file." >&2
    exit 1
  fi
  macos_release_provenance_contents >"$provenance_file"
  /bin/chmod 644 "$provenance_file"
}

verify_macos_release_provenance() {
  local bundle_dir="$1"
  local provenance_file="$bundle_dir/Contents/Resources/BUILD-PROVENANCE.txt"
  local expected_file="$STAGE_DIR/macos-build-provenance.expected.txt"

  if [ ! -f "$provenance_file" ] || [ -L "$provenance_file" ]; then
    echo "Release bundle is missing its regular BUILD-PROVENANCE.txt file." >&2
    exit 1
  fi
  macos_release_provenance_contents >"$expected_file"
  if ! /usr/bin/cmp -s "$expected_file" "$provenance_file"; then
    echo "Release bundle provenance does not match the pinned source and toolchain." >&2
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

  verify_release_notarization_tools_integrity
  DEVELOPER_DIR="$RELEASE_DEVELOPER_DIR" \
    "$RELEASE_NOTARYTOOL_BIN" submit "$notary_zip" --keychain-profile "$NOTARY_PROFILE" --wait
  verify_release_notarization_tools_integrity
  DEVELOPER_DIR="$RELEASE_DEVELOPER_DIR" \
    "$RELEASE_STAPLER_BIN" staple "$bundle_dir"
  verify_release_notarization_tools_integrity
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
  local extract_label="${2:-extracted}"
  local extract_dir
  local extracted_bundle

  case "$extract_label" in
    ""|.|..|*/*|*$'\r'*|*$'\n'*)
      echo "Archive verification label is not a safe directory name." >&2
      exit 1
      ;;
  esac
  extract_dir="$STAGE_DIR/$extract_label"
  extracted_bundle="$extract_dir/$APP_NAME.app"

  if [ -e "$extract_dir" ] || [ -L "$extract_dir" ]; then
    echo "Archive verification directory already exists: $extract_dir" >&2
    exit 1
  fi
  /bin/mkdir -p "$extract_dir"
  /usr/bin/ditto -x -k "$zip_path" "$extract_dir"
  if [ ! -d "$extracted_bundle" ]; then
    echo "Archive does not contain $APP_NAME.app" >&2
    exit 1
  fi
  verify_release_bundle "$extracted_bundle"
}

package_macos_main() {
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
  prepare_dist_root
  trap cleanup EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
  create_private_release_root

  capture_release_provenance
  initialize_release_publication_paths
  ensure_release_publication_state_supported

  materialize_release_source
  prepare_isolated_release_cargo_home
  resolve_and_verify_release_toolchain
  verify_release_source_unchanged

  STAGED_BUNDLE="$STAGE_DIR/$APP_NAME.app"
  TMP_ZIP="$STAGE_DIR/$(/usr/bin/basename "$ZIP_PATH")"
  TMP_ZIP_SHA256="$STAGE_DIR/$(/usr/bin/basename "$ZIP_SHA256_PATH")"
  prepare_atomic_no_replace_rename_helper

  EXISTING_PUBLICATION_STATE="$(release_publication_state)"
  case "$EXISTING_PUBLICATION_STATE" in
    archive-only|complete)
      repair_or_adopt_existing_release "$EXISTING_PUBLICATION_STATE"
      /usr/bin/printf 'Release ZIP: %s\nSHA-256 sidecar: %s\nSHA-256: %s\n' \
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
  verify_release_snapshot_unchanged
  write_macos_release_provenance "$STAGED_BUNDLE"
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
  extract_and_verify_archive "$TMP_ZIP" candidate-extracted
  verify_release_source_unchanged
  verify_release_toolchain_integrity

  CANDIDATE_ZIP_SHA256="$(release_tool_sha256 "$TMP_ZIP")"
  if ! valid_sha256 "$CANDIDATE_ZIP_SHA256"; then
    echo "Unable to compute the verified release archive SHA-256." >&2
    exit 1
  fi

  publish_verified_release_pair \
    "$TMP_ZIP" "$TMP_ZIP_SHA256" "$CANDIDATE_ZIP_SHA256"
  PUBLISHED_ZIP_SHA256="$CANDIDATE_ZIP_SHA256"
  validate_archive_entries "$ZIP_PATH"
  extract_and_verify_archive "$ZIP_PATH" published-extracted
  verify_release_source_unchanged
  verify_release_toolchain_integrity

  /usr/bin/printf 'Release ZIP: %s\nSHA-256 sidecar: %s\nSHA-256: %s\n' \
    "$ZIP_PATH" "$ZIP_SHA256_PATH" "$PUBLISHED_ZIP_SHA256"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  package_macos_main
fi
