# macOS update preparation and hosting

Sparkle 2.9.4 downloads, verifies and installs updates. The app bundles the
framework, including its installer, downloader and updater helpers. Only the
public Ed25519 key in `SparklePublicKey.txt` is embedded. The private signing key
stays in the operator's Keychain under the dedicated `windows-app-autologin`
account; these scripts never export it or accept a private key argument.

## Separate distribution channels

| Channel | Bundle identifier | Feed |
| --- | --- | --- |
| Production | `com.obcardinal.WindowsAppAutoLogin` | `https://obcardinal.com/assets/downloads/windows-app-autologin/macos/appcast.xml` |
| Development | `obcardinal.windows-app-autologin` | `https://obcardinal.com/assets/downloads/windows-app-autologin/macos/development/appcast.xml` |

Each feed lists only releases for its channel. Development builds use their
own identity and feed, including
when signed with Developer ID. Instance Control's feed, signing account and
release metadata are independent and must not be reused.

## Prepare an existing development archive

Start with a complete Developer ID signed development bundle produced by the
ordinary local build route. Archive the whole bundle with `ditto` so framework
symlinks and macOS metadata are preserved. Use new paths for both the ZIP and
output directory:

```sh
ditto -c -k --sequesterRsrc --keepParent \
  "dist/Windows App AutoLogin.app" /tmp/WindowsAppAutoLogin-development.zip
python3 script/prepare_sparkle_update.py \
  --channel development \
  /tmp/WindowsAppAutoLogin-development.zip \
  /tmp/WindowsAppAutoLogin-development-update
```

For a later release, pass `--existing-appcast /path/to/previous/appcast.xml`.
The previous feed and input ZIP are read-only inputs. Existing nonempty feeds
must have a valid appcast signature, belong to the same channel, and contain
only older build numbers. The new output path must not exist. Each successful
run publishes one completed local directory atomically containing:

- an immutable ZIP named with the channel, version, build and archive hash;
- `appcast.xml`, including the signed archive enclosure and a signed feed.

The utility checks ZIP paths and framework symlinks before extraction, bundle
identity/feed/public key, release build metadata, the complete embedded Sparkle
framework, and Developer ID signatures from team `76C2QW8JV3`. It downloads and
verifies the pinned Sparkle tools via `script/macos_sparkle.sh`, reads only the
dedicated Keychain account's public key for comparison, and uses the official
`generate_appcast` and `sign_update` tools for signing and verification. Archive
length and generated version/URL fields are checked again before publication.
It never contacts the hosting server or modifies an installed app.

## Build and sign a production release

Dispatch the **macOS release build** workflow on `main`. The GitHub-hosted Apple
silicon runner builds the executable from that revision. A separate job issues
its GitHub artifact attestation. Download the `macos-arm64-executable` artifact
after both jobs succeed and check out the same commit locally.

```sh
gh workflow run macos-release.yml --ref main
gh run download "$RUN_ID" -n macos-arm64-executable -D "$RELEASE_DIR/input"
WAAL_CODESIGN_IDENTITY="$DEVELOPER_ID" WAAL_NOTARY_PROFILE="$NOTARY_PROFILE" \
  script/sign_hosted_macos_release.sh "$RELEASE_DIR/input/windows-app-autologin" "$FINAL_ARCHIVE"
```

The signing script verifies GitHub's detached attestation against the executable,
repository, workflow, hosted runner and exact commit. It assembles the bundle
from that commit, signs Sparkle and the app with Developer ID, submits the app
to Apple, staples the accepted ticket and checks Gatekeeper before creating the
final ZIP. Apple signing and notarization credentials stay on the signing Mac.
The separate local development packager produces artifacts for local use.

Use the same final ZIP for GitHub and Sparkle. Write plain-text release notes and
pass the current public feed to retain its earlier entries. The notes are signed
as part of the new appcast.

```sh
python3 script/prepare_sparkle_update.py --channel production \
  --existing-appcast "$PREVIOUS_APPCAST" --release-notes "$RELEASE_NOTES" \
  "$FINAL_ARCHIVE" "$NEW_OUTPUT_DIRECTORY"
```

## Hosting and publication

Mac mini already serves both feeds through the existing `obcardinal.com` HTTPS
site. Files live in the website's
`assets/downloads/windows-app-autologin/macos/` subtree; development files use
its `development/` child. No new listener or tunnel route is needed.

Publication is a separate operator action. Add the prepared immutable ZIP and
new feed bytes to the website repository. Update its exact asset inventory in
`deploy/site/validate-site.py` and the corresponding hashes in
`deploy/site/manifest.sha256`. Keep all previously published archives. Use the
website's reviewed root-owned staging/installation contract; an untracked
server copy would break a later exact-inventory deployment.

Upload and independently verify the archive's HTTPS bytes/length first, then
atomically replace the feed as the final publication step. Verify the public
feed matches the reviewed file and carries usable XML without stale caching.
The host needs only public feeds and signed archives; the signing private key
never belongs on the website or in its deployment payload.

Tests:

```sh
python3 -m unittest discover -s script -p test_prepare_sparkle_update.py -v
```
