#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 2 ]]; then
  echo "Usage: WAAL_CODESIGN_IDENTITY=… WAAL_NOTARY_PROFILE=… $0 <hosted executable> <new release ZIP>" >&2
  exit 2
fi
: "${WAAL_CODESIGN_IDENTITY:?Specify the Developer ID Application signing identity}"
: "${WAAL_NOTARY_PROFILE:?Specify the notarytool Keychain profile}"
repo=obcardinal/Windows-App-AutoLogin
root=$(cd "$(dirname "$0")/.." && pwd -P)
commit=$(git -C "$root" rev-parse HEAD)
tree=$(git -C "$root" rev-parse 'HEAD^{tree}')
destination=$2
[[ ! -e "$destination" && ! -L "$destination" ]] || { echo "Release ZIP already exists" >&2; exit 1; }
work=$(mktemp -d "$(dirname "$destination")/.waal-sign.XXXXXXXX")
trap 'rm -rf "$work"' EXIT
mkdir "$work/source"
git -C "$root" archive "$commit" | tar -x -C "$work/source"
source "$work/source/script/macos_bundle.sh"
source "$work/source/script/macos_sparkle.sh"

binary=windows-app-autologin
name="$(waal_macos_bundle_name "$work/source")"
app="$work/$name.app"
identifier=com.obcardinal.WindowsAppAutoLogin
version=$(waal_cargo_version "$work/source")
build=$(waal_build_version "$version")
install -m 755 "$1" "$work/$binary"
waal_assemble_app_bundle "$work/source" "$app" "$binary" "$work/$binary" \
  "$identifier" "$name" "$version" "$build"
waal_stage_sparkle "$work/source" "$app"

# Verify the bytes inside the bundle against the hosted workflow and commit
# before granting them the project's Developer ID signature.
executable="$app/Contents/MacOS/$binary"
gh attestation verify "$executable" --repo "$repo" --deny-self-hosted-runners \
  --signer-workflow "$repo/.github/workflows/macos-release.yml" \
  --source-ref refs/heads/main --source-digest "$commit" --signer-digest "$commit"
[[ "$(lipo -archs "$executable")" == arm64 ]]
python3 - "$work/source" "$app" "$commit" "$tree" <<'PY'
from pathlib import Path
import plistlib
import sys
src, app = map(Path, sys.argv[1:3])
sys.path.insert(0, str(src / "script"))
import prepare_sparkle_update as updates
info = plistlib.loads((app / "Contents/Info.plist").read_bytes())
metadata = updates.parse_metadata(updates.run(["/usr/bin/strings", "-a", str(app / "Contents/MacOS/windows-app-autologin")]))
updates.validate_identity(info, metadata, "production", (src / "macos/SparklePublicKey.txt").read_text().strip())
if (metadata["source-git-commit"], metadata["source-git-tree"]) != tuple(sys.argv[3:5]):
    sys.exit("Executable records a different source revision")
PY

waal_sign_sparkle "$app" "$WAAL_CODESIGN_IDENTITY" --timestamp
codesign --force --options runtime --timestamp --identifier "$identifier" \
  --sign "$WAAL_CODESIGN_IDENTITY" "$app"
codesign --verify --deep --strict -R '=anchor apple generic and certificate leaf[subject.OU] = "76C2QW8JV3" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists' "$app"
ditto -c -k --sequesterRsrc --keepParent "$app" "$work/submission.zip"
xcrun notarytool submit "$work/submission.zip" --keychain-profile "$WAAL_NOTARY_PROFILE" --wait \
  --output-format json > "$work/notarization.json"
python3 - "$work/notarization.json" <<'PY'
import json, sys
with open(sys.argv[1]) as result:
    submission = json.load(result)
print(f"Notarization {submission['id']}: {submission['status']}", flush=True)
if submission["status"] != "Accepted":
    sys.exit("Apple did not accept the submitted app")
PY
xcrun stapler staple "$app"
xcrun stapler validate "$app"
spctl --assess --type execute --verbose=2 "$app"
codesign --verify --deep --strict "$app"
ditto -c -k --sequesterRsrc --keepParent "$app" "$work/final.zip"
ln "$work/final.zip" "$destination"
shasum -a 256 "$destination"
