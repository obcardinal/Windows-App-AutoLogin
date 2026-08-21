# Windows App AutoLogin

![Accounts screen](docs/images/accounts-screen.webp)

Windows App AutoLogin is a small desktop tray/menu-bar utility for macOS and Windows that fills Microsoft Windows App credential prompts only when the visible prompt clearly belongs to one saved account.

It is designed for the narrow case where Windows App shows a password prompt with a visible email address. The app verifies the running Microsoft client, reads the visible email, matches exactly one enabled account, loads only that account's password, fills the password field, and submits the prompt.

This project is not affiliated with Microsoft.

## What It Does

- Runs as a lightweight tray/menu-bar app by default.
- Opens the full settings window only on demand.
- Stores account metadata in a local config file.
- Stores passwords in the system secure store by default: macOS Keychain on macOS, Windows Credential Manager on Windows.
- Detects Windows App credential prompts.
- Auto-fills password prompts only after a visible email matches exactly one enabled account.
- Handles native secure password fields only inside a verified credential prompt.
- Keeps internal diagnostic logs bounded and redacted.
- Provides a standalone sanitized macOS UI diagnostic tool for development.

## Safety Model

The app is intentionally conservative. It should do nothing unless the current state is unambiguous.

Before loading a password, it requires:

1. Platform automation access for the exact running app: macOS Accessibility, or the current Windows desktop UI Automation session.
2. A trusted Windows App process/window.
3. The expected Microsoft app/process identity.
4. The target app to be frontmost.
5. A visible credential prompt.
6. A visible email address in that prompt.
7. Exactly one enabled saved account matching that email.

Before typing or submitting, it revalidates the target process, PID/window context, prompt contents, visible email, and password field.

Diagnostics use the same trusted target constraints as autofill: supported Microsoft identity, expected install path, signing identity, and verified live PID. App names, process names, and window titles are labels, not sufficient authority for diagnostic traversal.

The app does not:

- preload all saved passwords;
- cache decrypted passwords long-term;
- type when the email is missing, mismatched, duplicated, or ambiguous;
- type into an untrusted or background app;
- use the clipboard for password insertion;
- expose secrets through argv, environment variables, temp files, sockets, or HTTP APIs;
- log passwords, OTPs, tokens, recovery codes, clipboard contents, or raw secure-field values.

## Supported Target App

The runtime trust check currently supports:

- `Windows App`

On Windows, the native implementation uses Windows UI Automation and targets the known Microsoft Windows App process identity.

On macOS, the trusted Microsoft app identity is:

- Bundle ID: `com.microsoft.rdc.macos`
- Microsoft Team ID: `UBF8T346G9`

On macOS, the app expects the Microsoft client bundle to be installed in `/Applications`:

- `/Applications/Windows App.app`

Other app names, copied bundles, unsigned bundles, modified bundles, or unexpected Windows process/path identities are rejected.

## Requirements

- macOS 11 or newer, or Windows 10/11.
- Rust matching the version in `Cargo.toml` (`rust-version = "1.93"`).
- Windows App installed on the same desktop session.
- macOS Accessibility permission for the exact app or binary you launch on macOS.
- macOS may also ask for Automation permission to control System Events; approve it only for the expected Windows App AutoLogin bundle.
- For macOS bundle creation: `sips` and `iconutil`.
- For macOS release packaging: a Developer ID Application signing identity available to `codesign`, plus an `xcrun notarytool` keychain profile.
- For a publishable Windows distribution: an x64 MSVC Rust toolchain, a Visual Studio Developer PowerShell environment with `link.exe` and `rc.exe`, Windows SDK `signtool.exe`, and an installed code-signing certificate with an accessible private key.

## Build

Create a production macOS release ZIP with a freshly built, signed, notarized, and stapled app bundle:

```bash
RELEASE_CARGO="$(rustup which cargo)"
RELEASE_RUSTC="$(rustup which rustc)"
RELEASE_SYSROOT="$($RELEASE_RUSTC --print sysroot)"
export WAAL_RELEASE_CARGO_PATH="$RELEASE_CARGO"
export WAAL_RELEASE_RUSTC_PATH="$RELEASE_RUSTC"
export WAAL_RELEASE_RUST_SYSROOT="$RELEASE_SYSROOT"
export WAAL_RELEASE_EXPECTED_CARGO_SHA256="$(shasum -a 256 "$RELEASE_CARGO" | awk '{print $1}')"
export WAAL_RELEASE_EXPECTED_RUSTC_SHA256="$(shasum -a 256 "$RELEASE_RUSTC" | awk '{print $1}')"
export WAAL_RELEASE_EXPECTED_CLANG_SHA256="$(shasum -a 256 /usr/bin/clang | awk '{print $1}')"
export WAAL_RELEASE_EXPECTED_CLANGXX_SHA256="$(shasum -a 256 /usr/bin/clang++ | awk '{print $1}')"
export WAAL_RELEASE_EXPECTED_AR_SHA256="$(shasum -a 256 /usr/bin/ar | awk '{print $1}')"
# Compute WAAL_RELEASE_EXPECTED_RUST_SYSROOT_SHA256 with directory_tree_sha256
# from script/package_macos.sh, and compute the native aggregate as documented below.
export WAAL_RELEASE_EXPECTED_RUST_SYSROOT_SHA256=<reviewed-sysroot-tree-sha256>
export WAAL_RELEASE_EXPECTED_NATIVE_TOOLCHAIN_SHA256=<reviewed-native-aggregate-sha256>
WAAL_RELEASE_BUNDLE_ID=com.example.WindowsAppAutoLogin \
WAAL_MACOS_TEAM_ID=ABCDE12345 \
WAAL_CODESIGN_IDENTITY="Developer ID Application: Example Corp (ABCDE12345)" \
WAAL_NOTARY_PROFILE=your-notary-profile \
script/package_macos.sh --release
```

For a local macOS development bundle, use `./script/build_and_run.sh --verify` instead.

Build-check the Windows implementation from another host when the target is installed:

```bash
cargo check --target x86_64-pc-windows-gnu --all-targets --all-features
```

Create a publishable Windows x86-64 distribution from a Visual Studio Developer PowerShell prompt. The certificate thumbprint is not a password or private key:

```powershell
$env:WAAL_WINDOWS_SIGN_CERT_THUMBPRINT = "0123456789ABCDEF0123456789ABCDEF01234567"
$env:WAAL_WINDOWS_RELEASE_GIT_PATH = "C:\Program Files\Git\cmd\git.exe"
$env:WAAL_WINDOWS_RELEASE_TAR_PATH = "C:\Windows\System32\tar.exe"
$env:WAAL_RELEASE_CARGO_PATH = "C:\Users\me\.rustup\toolchains\stable-x86_64-pc-windows-msvc\bin\cargo.exe"
$env:WAAL_RELEASE_RUSTC_PATH = "C:\Users\me\.rustup\toolchains\stable-x86_64-pc-windows-msvc\bin\rustc.exe"
$env:WAAL_RELEASE_RUST_SYSROOT = "C:\Users\me\.rustup\toolchains\stable-x86_64-pc-windows-msvc"
$env:WAAL_WINDOWS_RELEASE_LINK_PATH = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\<version>\bin\Hostx64\x64\link.exe"
$env:WAAL_WINDOWS_RELEASE_RC_PATH = "C:\Program Files (x86)\Windows Kits\10\bin\<version>\x64\rc.exe"
$env:WAAL_WINDOWS_RELEASE_SIGNTOOL_PATH = "C:\Program Files (x86)\Windows Kits\10\bin\<version>\x64\signtool.exe"
$env:WAAL_WINDOWS_RELEASE_LIB = "<reviewed semicolon-separated absolute MSVC/SDK library directories>"
$env:WAAL_WINDOWS_RELEASE_INCLUDE = "<reviewed semicolon-separated absolute MSVC/SDK include directories>"
$env:WAAL_WINDOWS_RELEASE_LIBPATH = "<reviewed semicolon-separated absolute MSVC/SDK reference directories>"
# Set each corresponding WAAL_*_EXPECTED_*_SHA256 value to a reviewed lowercase
# (Get-FileHash -Algorithm SHA256 -LiteralPath <path>).Hash.ToLowerInvariant().
# Also set WAAL_RELEASE_EXPECTED_RUST_SYSROOT_SHA256 and
# WAAL_RELEASE_EXPECTED_NATIVE_TOOLCHAIN_SHA256 as documented below.
.\script\build_windows_dist.ps1
```

The corresponding Windows hash variables are `WAAL_WINDOWS_RELEASE_EXPECTED_GIT_SHA256`, `WAAL_WINDOWS_RELEASE_EXPECTED_TAR_SHA256`, `WAAL_RELEASE_EXPECTED_CARGO_SHA256`, `WAAL_RELEASE_EXPECTED_RUSTC_SHA256`, `WAAL_RELEASE_EXPECTED_RUST_SYSROOT_SHA256`, `WAAL_WINDOWS_RELEASE_EXPECTED_LINK_SHA256`, `WAAL_WINDOWS_RELEASE_EXPECTED_RC_SHA256`, `WAAL_WINDOWS_RELEASE_EXPECTED_SIGNTOOL_SHA256`, and `WAAL_RELEASE_EXPECTED_NATIVE_TOOLCHAIN_SHA256`.

The default Windows command is fail-closed: it requires a clean Git checkout, rejects links/gitlinks in the committed source tree, builds a fresh self-contained snapshot with an isolated Cargo home, verifies the locked dependency graph and every pinned build/materialization/signing tool, sanitizes MSVC injection variables, embeds the exact Git commit/tree plus signer name and certificate SHA-256 fingerprint, signs and RFC 3161 timestamps the executable, verifies Authenticode against that exact certificate, and writes `SHA256SUMS.txt` plus `BUILD-PROVENANCE.txt`. Publication uses a verified candidate plus rollback backup inside `dist`; the previous package remains recoverable until the activated package passes its final metadata, hash, provenance, and Authenticode checks.

For an unsigned local VM test artifact only, opt in explicitly. This uses a separate directory name and is never a publishable release:

```powershell
.\script\build_windows_dist.ps1 -Development
```

Build and launch the local macOS development app bundle. This path uses the development bundle identity and ad-hoc signing; it is not a production release build:

```bash
./script/build_and_run.sh --verify
```

The bundle is created at:

```text
dist/WindowsAppAutoLogin.app
```

For a permanent local install, copy the built app to `/Applications` and launch that copy:

```bash
cp -R dist/WindowsAppAutoLogin.app /Applications/
open /Applications/WindowsAppAutoLogin.app
```

macOS grants Accessibility and Keychain access to a specific app identity/path. If you grant access to the app in `dist/` and later move it to `/Applications`, you may need to grant permission again.

## First Run

1. Build and open the app bundle.
2. Use the menu-bar icon and choose **Open Accounts**.
3. If Accessibility is missing, click **Request Accessibility Access** or **Open Accessibility Settings**.
4. Enable Windows App AutoLogin in:

```text
System Settings -> Privacy & Security -> Accessibility
```

5. Return to the app. It checks Accessibility status every second.
6. If macOS prompts for Automation permission to control System Events, approve it for the expected Windows App AutoLogin bundle. The app uses that only for Open at Login cleanup and guarded diagnostics/prompt inspection.
7. Add an account in the **Accounts** tab.
8. Save the email and password.
9. Keep the account enabled.
10. Start the monitor from the menu-bar item if it is not already running.

When the matching Windows App credential prompt is visible and Windows App is frontmost, the background worker attempts one guarded fill and submit sequence.

## Menu-Bar App

The default launch mode is a lightweight supervisor with no always-on egui window. The menu contains:

- **Open Accounts**
- **Open Settings**
- **Start Monitor** / **Stop Monitor**
- **Request Accessibility Access**
- **Open Accessibility Settings**
- Accessibility status
- Password storage status
- Last fill result
- **Quit**

The heavier settings UI is launched only when needed. Closing the settings window returns the app to the lightweight menu-bar process.

## Settings Window

The settings window includes:

- **Accounts**: add, edit, pause, enable, or delete saved accounts.
- **Settings**: adjust Open at Login and storage mode.
- **Diagnose**: only when built with development diagnostics features.

Existing accounts can be edited without re-entering a password. Leave the password field blank to keep the saved password.

Enabled accounts must have:

- a non-empty email;
- a saved password;
- no other enabled account with the same email, ignoring case and surrounding whitespace.

## Configuration

The app stores configuration in the user's macOS config directory, typically:

```text
~/Library/Application Support/WindowsAppAutoLogin/config.json
```

The file contains account metadata and settings only. It does not contain plaintext passwords.

Example:

```json
{
  "accounts": [],
  "settings": {
    "auto_start": false,
    "start_minimized": false,
    "use_keyring": true
  }
}
```

Password records are keyed by account ID and bound to account metadata. Manually editing account IDs or email can disconnect metadata from the saved password and fail closed.

## Password Storage

By default, passwords are stored in the system secure store:

- Service: `WindowsAppAutoLogin`
- Account: the saved account ID

If **Use system secure storage** is disabled, passwords are stored in an encrypted local fallback file:

```text
passwords.json
```

That fallback uses AES-256-GCM. Every account and every saved password revision receives a fresh independent 256-bit key. The scoped keys are stored in the system secure store under:

- Service: `WindowsAppAutoLoginFallbackKey`
- Account: `fallback-account-key:<random-key-id>`

The former shared `fallback-encryption-key` entry is accepted only while migrating legacy records and is retired after the independently keyed ciphertext map is durably committed. The fallback file is not independent of Keychain or Credential Manager: if a referenced scoped key cannot be created or read from the current user's system secure store, fallback password save/load will fail. On Windows, each key is stored in Credential Manager and protected by user-bound DPAPI. The key envelope binds its random key ID to the account ID; the service name, account metadata, purpose, and normalized email hash are validation and routing metadata, not a guarantee that only this executable can decrypt it. Manual metadata edits fail closed.

Recent builds migrate saved passwords when switching storage mode. The app copies and verifies passwords in the new storage before saving the setting, then attempts to remove old copies from the previous backend. If copying or verification fails, the setting is left unchanged. If only old-copy cleanup fails after a save or migration succeeds, passwords remain available in the selected storage and cleanup remains pending for the next launch instead of being forgotten.

During storage-mode and account metadata changes, the app writes a private pending-operation journal so a restart can finish cleanup or restore a consistent config after a crash. A separate durable staged-key journal is committed before a new scoped fallback key is created; startup reconciliation preserves keys referenced by committed `passwords.json` records and removes only uncommitted crash orphans. Cleanup warnings mean a migration target was verified or an account save completed in the selected backend, but stale old material may remain until recovery succeeds. While a pending operation exists, stored credential changes are blocked and the app retries cleanup on startup. Manual cleanup targets, if the warning persists, are the old `WindowsAppAutoLogin` account-ID secure-store entries, stale `passwords.json` records, and retired fallback key material under `WindowsAppAutoLoginFallbackKey`, including legacy `fallback-encryption-key` or `fallback.key` material. Do not manually delete a scoped or legacy fallback key while a fallback password record may still reference it.

If Keychain asks for permission repeatedly, make sure you are launching the same app bundle each time and choose **Always Allow** only for the intended app identity. Local ad-hoc development signatures are intentionally bound to the executable cdhash, so rebuilding the development bundle changes its identity and can require a new prompt. A stable Developer ID release identity is the appropriate choice when permissions must survive rebuilds.

## How Autofill Works

The autofill path is shared by the background worker and the one-shot debug command.

At a high level:

1. Resolve trusted Windows App processes.
2. Verify bundle ID, Team ID, path, and code signature.
3. Require the target app to be frontmost.
4. Detect the visible credential prompt.
5. Collect visible prompt text while excluding secure/password-like fields.
6. Extract the visible email.
7. Match that email against enabled accounts.
8. Revalidate the same frontmost prompt and target process before password load.
9. Load only the matching account password.
10. Detect the intended password field.
11. Focus the field and set the password on that exact AX element with a target-bound `AXValue` update after fresh prompt/focus checks.
12. Submit only with a bounded `AXPress` action on the verified submit button.
13. Post-check whether the app reached an authenticated/normal state, still shows the prompt, or ended in an unknown state.

For password insertion, the app requires a native secure password field: macOS `AXSecureTextField` or Windows UI Automation `IsPassword`. Password-like plain text controls such as macOS `AXTextField` or Windows plain `Edit` are not accepted as insertion targets, even inside a verified Windows App prompt.

## Diagnostics

Run a sanitized macOS UI diagnostic report:

```bash
cargo run --quiet --features diagnostics-ui --bin diagnose-macos-ui
```

The diagnostic binary prints JSON describing visible target processes, windows, controls, and selected system dialogs. Sensitive values are redacted. Raw AppleScript output is not printed.

Diagnostic target discovery uses the same trusted-target constraints as autofill: supported Microsoft identity, expected install path, signing identity, and verified live PID. App names, process names, and window titles are treated only as report labels; they are not enough to select or traverse an arbitrary process.

`release-diagnostics` is reserved for intentional support artifacts, not general releases. Diagnostic output is redacted and capped; signing identities, signing identifiers, Team IDs, and app bundle IDs are reduced to coarse status values before display or export. It can still include process IDs and timing data; review it before sharing with support.

Run one guarded fill attempt from a development build compiled with `debug-fill` or `dev-tools` and launched from the trusted app bundle:

```bash
/Applications/WindowsAppAutoLogin.app/Contents/MacOS/windows-app-autologin --debug-fill-once
```

The one-shot command is intended for development and troubleshooting. It is available only in debug builds with the explicit debug-fill feature enabled and requires Accessibility permission for the trusted `/Applications/WindowsAppAutoLogin.app` bundle identity. Do not package, distribute, or leave a debug-fill build installed as the production app.

## Development Features

Default features:

```text
none
```

Optional features:

```text
debug-fill
diagnostics-ui
dev-tools (enables debug-fill and diagnostics-ui)
release-diagnostics (explicitly permits diagnostics-ui in release support artifacts)
```

Build and launch the full UI with diagnostics enabled:

```bash
./script/build_and_run.sh --dev-ui
```

Launch the packaged app directly into the full settings UI:

```bash
./script/build_and_run.sh --full-ui
```

## Test And Verification

Common local gates:

```bash
cargo fmt --check
cargo check --all-targets
cargo clippy --all-targets -- -D warnings
cargo test
./script/build_and_run.sh --verify
```

Additional feature coverage:

```bash
cargo check --all-targets --all-features
```

The test suite covers the main safety decisions: visible-email matching, missing/mismatched/duplicate accounts, disabled accounts, PID/window drift, settings-generation cancellation, bounded logs, redaction, diagnostic output caps, diagnostics name-spoof rejection, and target identity checks.

## Packaging Notes

`script/build_and_run.sh` creates a local app bundle and ad-hoc signs it when `codesign` is available. The development signature uses the default cdhash-bound designated requirement; it does not trust every ad-hoc application that copies the public bundle identifier. Because the cdhash changes after a rebuild, Accessibility, Automation, and Keychain approval may need to be granted again.

Current development bundle ID:

```text
obcardinal.windows-app-autologin
```

The development script does not perform Developer ID signing or notarization. It opts into `WAAL_DEVELOPMENT_RELEASE=1` only for local non-production release-profile bundles.

Use `script/package_macos.sh --release` only for a publishable macOS zip. The package script requires the Git checkout to have no tracked, untracked, assume-unchanged, or skip-worktree changes; records the exact 40-hex `HEAD` commit and tree IDs; materializes an isolated source snapshot directly from that commit; and rechecks both the checkout and embedded values before publishing. Cargo runs with a new packager-owned `HOME`, `CARGO_HOME`, temporary directory, target directory, fixed system-tool path, and no Cargo configuration in its working-directory ancestors. The dependency graph must contain only the archived root package and locked crates.io packages—external path, Git, alternate-registry, and source-replacement inputs are rejected. Cargo, rustc, the complete Rust sysroot, `/usr/bin/clang`, `/usr/bin/clang++`, and `/usr/bin/ar` must be explicitly selected and match reviewed SHA-256 pins; their provenance is embedded in the executable and signed `BUILD-PROVENANCE.txt`. The script assembles the `.app` from snapshot assets, signs it with `WAAL_CODESIGN_IDENTITY`, notarizes it with `WAAL_NOTARY_PROFILE`, staples the ticket, and zips only the verified staged bundle. Pre-existing `dist/*.app` bundles and ignored working-copy files are excluded as inputs, and `dist` must be a real directory rather than a symlink.

The sysroot tree digest is SHA-256 over ordinal byte-sorted regular-file entries encoded as `relative/path`, NUL, lowercase file SHA-256, NUL; symbolic links and special nodes are rejected. The macOS native aggregate is SHA-256 over the NUL-terminated lowercase hashes of `clang`, `clang++`, and `ar`, in exactly that order. The Windows native aggregate uses `link.exe`, `rc.exe`, and `signtool.exe`, in exactly that order. These ordered aggregate values are the `WAAL_RELEASE_EXPECTED_NATIVE_TOOLCHAIN_SHA256` pins.

The current release pipeline intentionally produces an ARM64 macOS binary. `CFBundleVersion` defaults to the numeric Cargo package version and can be overridden with a valid one-to-three-component `WAAL_BUILD_VERSION`.

Packaging refuses to continue unless `WAAL_RELEASE_BUNDLE_ID`, `WAAL_MACOS_TEAM_ID`, `WAAL_CODESIGN_IDENTITY`, and `WAAL_NOTARY_PROFILE` are set, the source checkout is clean and unchanged throughout packaging, the release bundle ID is a reverse-DNS identifier that differs from the development bundle ID, the executable metadata was compiled with the same bundle ID, Team ID, source commit/tree, target, and toolchain hashes, and the bundle passes production trust checks: expected production bundle ID, Developer ID Application signature, matching Team ID, hardened runtime, empty release entitlements, non-diagnostics build metadata, Gatekeeper assessment, and stapled notarization. It removes any stale output ZIP only after source validation, strips `.DS_Store`, AppleDouble `._*`, and `__MACOSX` entries from the staged copy, then validates the staged bundle and the extracted ZIP artifact before publishing the ZIP.

The project previously used development bundle ID `dev.codex.windows-app-autologin`; the current ID is `obcardinal.windows-app-autologin`. Release and development scripts do not reset privacy databases or alter Keychain access lists automatically. If an obsolete grant remains, remove only the old app entry from **System Settings → Privacy & Security → Accessibility** and **Automation**. If you deliberately want command-line cleanup, run the bundle-scoped `tccutil reset Accessibility dev.codex.windows-app-autologin` and `tccutil reset AppleEvents dev.codex.windows-app-autologin` yourself after reviewing the target. In Keychain Access, inspect the `WindowsAppAutoLogin` and `WindowsAppAutoLoginFallbackKey` items and remove only a stale application entry from Access Control; do not delete password items or the fallback key while fallback records exist. For the current ad-hoc development ID, prefer removing and re-adding the exact rebuilt app in System Settings rather than resetting unrelated applications.

Use `script/package_macos.sh --release-diagnostics-artifact` only for an intentional support artifact. A release diagnostics artifact is built by the package script with `--features release-diagnostics`, a separate `WAAL_DIAGNOSTICS_BUNDLE_ID`, and the diagnostics app name `WindowsAppAutoLoginDiagnostics.app`; the package script requires both `WAAL_RELEASE_BUNDLE_ID` and `WAAL_DIAGNOSTICS_BUNDLE_ID` and refuses to package if the diagnostics bundle ID matches the production or development bundle ID. `script/build_and_run.sh --dev-ui` is not a release diagnostics path because it builds `dev-tools`, which includes `debug-fill` and is rejected by packaging.

Example release diagnostics packaging command:

```bash
WAAL_RELEASE_BUNDLE_ID=com.example.WindowsAppAutoLogin \
WAAL_DIAGNOSTICS_BUNDLE_ID=com.example.WindowsAppAutoLogin.Diagnostics \
WAAL_MACOS_TEAM_ID=ABCDE12345 \
WAAL_CODESIGN_IDENTITY="Developer ID Application: Example Corp (ABCDE12345)" \
WAAL_NOTARY_PROFILE=your-notary-profile \
script/package_macos.sh --release-diagnostics-artifact
```

The app bundle sets `LSUIElement=true`, so it behaves like a menu-bar utility rather than a Dock-first application.

On macOS, Open at Login is trusted only for the exact canonical bundle path `/Applications/WindowsAppAutoLogin.app` with the expected bundle identifier; the app intentionally refuses autostart from other bundle locations, including transient build locations such as `target/`, `dist/`, `/tmp`, and `/var/folders`. On Windows, Open at Login registers the current executable path wherever the user runs it from; the app still requires the saved Startup command to exactly match the command it generated, with no extra arguments.

## Troubleshooting

### Autofill does not run

Check:

- The exact launched app has Accessibility permission.
- Windows App is installed in `/Applications`.
- Windows App is frontmost.
- The credential prompt contains a visible email.
- Exactly one enabled saved account matches that email.
- The matching account has a saved password.
- There is no duplicate enabled account with the same email.
- The Microsoft app bundle has not been copied, modified, or re-signed.

### Keychain is slow or prompts every time

Keychain approval time is counted as password load time. If macOS prompts, approve the intended app and choose **Always Allow**.

Repeated prompts usually mean macOS sees a different client identity, for example:

- launching from `target/debug` instead of the `.app`;
- rebuilding an ad-hoc signed bundle repeatedly;
- moving the app after granting permission;
- granting permission to Terminal instead of the bundled app.

### Prompt is visible but password is not typed

The app fails closed if:

- the email is hidden;
- the prompt email does not match an enabled account;
- multiple enabled accounts match;
- the target app is not frontmost;
- the target PID/window changed;
- the platform exposes the password box only as a non-secure plain text field;
- the password field cannot be verified or focused;
- Accessibility returns an error or times out.

### Diagnosis times out

The diagnostic tool uses bounded Accessibility traversal and discards raw output on timeout. A timeout should not expose field values. Try closing unrelated modal dialogs and rerun:

```bash
cargo run --quiet --features diagnostics-ui --bin diagnose-macos-ui
```

## Limitations

- Supports only the Microsoft Windows App identity.
- UI detection depends on macOS Accessibility data on macOS and Windows UI Automation data on Windows.
- Prompts with hidden emails, unusual localization, MFA-only flows, SSO web views, or nonstandard controls may not be fillable.
- The app intentionally prefers doing nothing over guessing.

## License

MIT
