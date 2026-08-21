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
RELEASE_GIT_COMMIT=""
RELEASE_GIT_TREE=""
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
RELEASE_MACOS_SDK_SHA256=""
RELEASE_CLANG_RESOURCE_DIR_SHA256=""
RELEASE_NATIVE_TOOLCHAIN_SHA256=""
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
  /usr/bin/env -i \
    PATH=/usr/bin:/bin:/usr/sbin:/sbin \
    HOME=/var/empty \
    GIT_CONFIG_NOSYSTEM=1 \
    GIT_CONFIG_SYSTEM=/dev/null \
    GIT_CONFIG_GLOBAL=/dev/null \
    GIT_NO_REPLACE_OBJECTS=1 \
    /usr/bin/git --no-replace-objects \
      -c core.attributesFile=/dev/null \
      -c core.hooksPath=/dev/null \
      "$@"
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

  listing="$(/usr/bin/mktemp "${TMPDIR:-/tmp}/waal-release-tree.XXXXXX")" || return 1
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

  listing="$(/usr/bin/mktemp "${TMPDIR:-/tmp}/waal-release-tree-bytes.XXXXXX")" || return 1
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
  RELEASE_SOURCE_ROOT="$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/waal-release-source.XXXXXX")"
  RELEASE_SOURCE_DIR="$RELEASE_SOURCE_ROOT/source"
  materialize_release_source_for_root \
    "$ROOT_DIR" \
    "$RELEASE_SOURCE_DIR" \
    "$RELEASE_GIT_COMMIT" \
    "$RELEASE_GIT_TREE"
  CARGO_VERSION="$(waal_cargo_version "$RELEASE_SOURCE_DIR")"
  BUILD_VERSION="$(waal_build_version "$CARGO_VERSION")"
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

macos_native_toolchain_sha256() {
  /usr/bin/printf '%s\0%s\0%s\0' \
    "$RELEASE_CLANG_SHA256" \
    "$RELEASE_CLANGXX_SHA256" \
    "$RELEASE_AR_SHA256" \
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
  local actual_native_toolchain_sha256

  verify_release_file_sha256 "$RELEASE_CARGO_BIN" "$RELEASE_CARGO_SHA256" "Cargo" || return 1
  verify_release_file_sha256 "$RELEASE_RUSTC_BIN" "$RELEASE_RUSTC_SHA256" "rustc" || return 1
  verify_release_file_sha256 "$RELEASE_CLANG_BIN" "$RELEASE_CLANG_SHA256" "clang" || return 1
  verify_release_file_sha256 "$RELEASE_CLANGXX_BIN" "$RELEASE_CLANGXX_SHA256" "clang++" || return 1
  verify_release_file_sha256 "$RELEASE_AR_BIN" "$RELEASE_AR_SHA256" "ar" || return 1

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
  actual_native_toolchain_sha256="$(macos_native_toolchain_sha256)"
  if [ "$actual_native_toolchain_sha256" != "$RELEASE_NATIVE_TOOLCHAIN_SHA256" ]; then
    echo "Native toolchain aggregate SHA-256 no longer matches its required release pin." >&2
    return 1
  fi
}

resolve_and_verify_release_toolchain() {
  local expected_rust_version
  local cargo_dir
  local rustc_dir
  local reported_sysroot

  RELEASE_CARGO_BIN="$(resolve_explicit_release_tool WAAL_RELEASE_CARGO_PATH Cargo)"
  RELEASE_RUSTC_BIN="$(resolve_explicit_release_tool WAAL_RELEASE_RUSTC_PATH rustc)"
  RELEASE_RUST_SYSROOT="$(resolve_explicit_release_directory WAAL_RELEASE_RUST_SYSROOT 'the Rust sysroot')"
  RELEASE_CARGO_SHA256="$(required_expected_sha256 WAAL_RELEASE_EXPECTED_CARGO_SHA256)"
  RELEASE_RUSTC_SHA256="$(required_expected_sha256 WAAL_RELEASE_EXPECTED_RUSTC_SHA256)"
  RELEASE_RUST_SYSROOT_SHA256="$(required_expected_sha256 WAAL_RELEASE_EXPECTED_RUST_SYSROOT_SHA256)"
  RELEASE_CLANG_SHA256="$(required_expected_sha256 WAAL_RELEASE_EXPECTED_CLANG_SHA256)"
  RELEASE_CLANGXX_SHA256="$(required_expected_sha256 WAAL_RELEASE_EXPECTED_CLANGXX_SHA256)"
  RELEASE_AR_SHA256="$(required_expected_sha256 WAAL_RELEASE_EXPECTED_AR_SHA256)"
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
  if [ "$(macos_native_toolchain_sha256)" != "$RELEASE_NATIVE_TOOLCHAIN_SHA256" ]; then
    echo "WAAL_RELEASE_EXPECTED_NATIVE_TOOLCHAIN_SHA256 does not match the ordered clang/clang++/ar hash aggregate." >&2
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
  verify_release_toolchain_integrity

  if ! (
    cd "$RELEASE_CARGO_WORK_DIR"
    /usr/bin/env -i \
      HOME="$RELEASE_BUILD_HOME" \
      CARGO_HOME="$RELEASE_CARGO_HOME" \
      TMPDIR="$RELEASE_BUILD_TMPDIR" \
      PATH=/usr/bin:/bin:/usr/sbin:/sbin \
      RUSTC="$RELEASE_RUSTC_BIN" \
      RUSTC_WRAPPER= \
      RUSTC_WORKSPACE_WRAPPER= \
      CARGO_ENCODED_RUSTFLAGS="$encoded_rustflags" \
      CARGO_TARGET_DIR="$BUILD_TARGET_DIR" \
      CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER="$RELEASE_CLANG_BIN" \
      CC="$RELEASE_CLANG_BIN" \
      CXX="$RELEASE_CLANGXX_BIN" \
      AR="$RELEASE_AR_BIN" \
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
      "$RELEASE_CARGO_BIN" "$@"
  ); then
    return 1
  fi
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

cleanup() {
  if [ -n "${STAGE_DIR:-}" ]; then
    /bin/rm -rf "$STAGE_DIR"
  fi
  if [ -n "${RELEASE_SOURCE_ROOT:-}" ]; then
    /bin/rm -rf "$RELEASE_SOURCE_ROOT"
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
  waal_assemble_app_bundle \
    "$RELEASE_SOURCE_DIR" \
    "$bundle_dir" \
    "$BINARY_NAME" \
    "$TARGET_EXECUTABLE" \
    "$EXPECTED_BUNDLE_ID" \
    "$APP_DISPLAY_NAME" \
    "$CARGO_VERSION" \
    "$BUILD_VERSION"
}

macos_release_provenance_contents() {
  /usr/bin/printf '%s\n' \
    'WAAL_MACOS_BUILD_PROVENANCE_V1' \
    "source-git-commit=$RELEASE_GIT_COMMIT" \
    "source-git-tree=$RELEASE_GIT_TREE" \
    "cargo-version=$RELEASE_CARGO_VERSION" \
    "cargo-sha256=$RELEASE_CARGO_SHA256" \
    "rustc-version=$RELEASE_RUSTC_VERSION" \
    "rustc-sha256=$RELEASE_RUSTC_SHA256" \
    "rust-sysroot-sha256=$RELEASE_RUST_SYSROOT_SHA256" \
    "native-toolchain-sha256=$RELEASE_NATIVE_TOOLCHAIN_SHA256" \
    "clang-sha256=$RELEASE_CLANG_SHA256" \
    "clangxx-sha256=$RELEASE_CLANGXX_SHA256" \
    "ar-sha256=$RELEASE_AR_SHA256"
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

package_macos_main() {
  require_tool codesign
  require_tool ditto
  require_tool git
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
  require_tool strings
  require_tool tar
  require_tool tr
  require_tool unzip
  require_tool xcrun
  require_tool xattr
  require_tool zip
  require_tool zipinfo

  validate_release_environment
  capture_release_provenance

  prepare_dist_root
  /bin/rm -f -- "$ZIP_PATH"

  STAGE_DIR="$(/usr/bin/mktemp -d "$ROOT_DIR/dist/.package_macos.XXXXXX")"
  trap cleanup EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM

  materialize_release_source
  prepare_isolated_release_cargo_home
  resolve_and_verify_release_toolchain
  verify_release_source_unchanged

  STAGED_BUNDLE="$STAGE_DIR/$APP_NAME.app"
  TMP_ZIP="$STAGE_DIR/$(/usr/bin/basename "$ZIP_PATH")"

  build_release_executable
  assemble_release_bundle "$STAGED_BUNDLE"
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
  extract_and_verify_archive "$TMP_ZIP"
  verify_release_source_unchanged
  verify_release_toolchain_integrity

  /bin/mv -f "$TMP_ZIP" "$ZIP_PATH"

  echo "$ZIP_PATH"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  package_macos_main
fi
