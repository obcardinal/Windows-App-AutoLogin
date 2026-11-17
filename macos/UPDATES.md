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

The feeds initially contain no update items. Creating them does not publish a
release. Development builds must use their own identity and feed, including
when signed with Developer ID. Instance Control's feed, signing account and
release metadata are independent and must not be reused.

## Prepare an existing development archive

Start with a complete Developer ID signed development bundle produced by the
ordinary local build route. Archive the whole bundle with `ditto` so framework
symlinks and macOS metadata are preserved. Use new paths for both the ZIP and
output directory:

```sh
ditto -c -k --sequesterRsrc --keepParent \
  dist/WindowsAppAutoLogin.app /tmp/WindowsAppAutoLogin-development.zip
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

## Production builder boundary

The existing local `script/package_macos.sh` deliberately produces only
nonpublishable local artifacts. Its output is not eligible for the production
feed, even when it uses the production runtime bundle identifier and carries a
Developer ID signature. Current source-controlled build metadata explicitly
marks local artifacts nonpublishable; this utility does not rewrite it or
provide an override.

A production pipeline must first obtain an artifact from a separately
authenticated, isolated builder and verify its detached provenance through
that builder's trusted release process. That infrastructure is a prerequisite,
not supplied by this local preparation utility. Signing and metadata checks
alone do not authenticate a build producer. The production preparation gate
requires an admitted release record (`artifact-kind=release`,
`publishable=true`, production identity, and authenticated provenance fields),
plus valid Apple notarization, a stapled ticket and Gatekeeper acceptance.

Within that trusted builder, stage Sparkle **before** the final app signature:

```sh
source script/macos_sparkle.sh
waal_stage_sparkle "$SOURCE_ROOT" "$APP_BUNDLE"
waal_sign_sparkle "$APP_BUNDLE" "$WAAL_CODESIGN_IDENTITY" --timestamp
codesign --force --options runtime --timestamp \
  --sign "$WAAL_CODESIGN_IDENTITY" \
  --identifier com.obcardinal.WindowsAppAutoLogin "$APP_BUNDLE"
codesign --verify --deep --strict "$APP_BUNDLE"
```

Submit an archive through the builder's existing `notarytool` Keychain profile,
then staple and validate the resulting bundle before creating the **final**
archive. Do not sign an archive and subsequently modify/staple its contents.

```sh
xcrun stapler staple "$APP_BUNDLE"
xcrun stapler validate "$APP_BUNDLE"
spctl --assess --type execute --verbose=2 "$APP_BUNDLE"
ditto -c -k --sequesterRsrc --keepParent "$APP_BUNDLE" "$FINAL_ARCHIVE"
python3 script/prepare_sparkle_update.py --channel production \
  --existing-appcast "$PREVIOUS_APPCAST" "$FINAL_ARCHIVE" "$NEW_OUTPUT_DIRECTORY"
```

The destination archive and output directory must be new. Never manufacture
production provenance by changing the metadata marker of a local executable.

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
