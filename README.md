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
- Handles native secure/password fields and password-like text fields only inside a verified credential prompt.
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
- For bundle creation: `sips`, `iconutil`, and optionally `codesign`.

## Build

Build the release binary:

```bash
cargo build --release
```

Build-check the Windows implementation from another host when the target is installed:

```bash
cargo check --target x86_64-pc-windows-gnu --all-targets --all-features
```

Build and launch the macOS app bundle:

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
6. Add an account in the **Accounts** tab.
7. Save the email and password.
8. Keep the account enabled.
9. Start the monitor from the menu-bar item if it is not already running.

When the matching Windows App credential prompt is visible and Windows App is frontmost, the background worker attempts one guarded fill and submit sequence.

## Menu-Bar App

The default launch mode is a lightweight supervisor with no always-on egui window. The menu contains:

- **Open Accounts**
- **Open Settings**
- **Start Monitor** / **Stop Monitor**
- **Request Accessibility Access**
- **Open Accessibility Settings**
- Accessibility status
- Keychain status
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

Password records are keyed by account ID. Manually editing account IDs can disconnect metadata from the saved password.

## Password Storage

By default, passwords are stored in the system secure store:

- Service: `WindowsAppAutoLogin`
- Account: the saved account UUID

If **Use system secure storage** is disabled, passwords are stored in an encrypted local fallback file:

```text
passwords.json
```

That fallback uses AES-256-GCM. Its encryption key is still stored in the system secure store under:

- Service: `WindowsAppAutoLoginFallbackKey`
- Account: `fallback-encryption-key`

Switching storage mode does not automatically migrate existing passwords. Re-save each account password after changing the storage setting.

If Keychain asks for permission repeatedly, make sure you are launching the same app bundle each time and choose **Always Allow** for the intended app identity.

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
8. Load only the matching account password.
9. Revalidate the same prompt and target process.
10. Detect the intended password field.
11. Focus the field and type the password through guarded keyboard input.
12. Submit with a bounded `AXPress` action or a guarded Enter fallback.
13. Post-check whether the app reached an authenticated/normal state, still shows the prompt, or ended in an unknown state.

Windows App may expose its password box as `AXTextField` rather than `AXSecureTextField`. The app treats password-like `AXTextField` controls as password fields only inside a verified credential prompt context.

## Diagnostics

Run a sanitized macOS UI diagnostic report:

```bash
cargo run --quiet --bin diagnose-macos-ui
```

The diagnostic binary prints JSON describing visible target processes, windows, controls, and selected system dialogs. Sensitive values are redacted. Raw AppleScript output is not printed.

Run one guarded fill attempt from the current process:

```bash
cargo run --bin windows-app-autologin -- --debug-fill-once
```

Optional fill method:

```bash
cargo run --bin windows-app-autologin -- --debug-fill-once --fill-method=keyboard
cargo run --bin windows-app-autologin -- --debug-fill-once --fill-method=direct
```

The one-shot command is intended for development and troubleshooting. Accessibility permission must belong to the exact process you run. If you run it from Cargo, macOS may require permission for Terminal, your IDE, or the generated debug binary instead of the bundled app.

## Development Features

Default features:

```text
none
```

Optional features:

```text
diagnostics-ui
dev-tools
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

The test suite covers the main safety decisions: visible-email matching, missing/mismatched/duplicate accounts, disabled accounts, PID/window drift, settings-generation cancellation, bounded logs, redaction, diagnostic output caps, and target identity checks.

## Packaging Notes

`script/build_and_run.sh` creates a local app bundle and ad-hoc signs it when `codesign` is available.

Current development bundle ID:

```text
dev.codex.windows-app-autologin
```

The script does not perform Developer ID signing or notarization. For distribution outside local development, replace the development bundle ID/signing setup with a stable production identity and add a proper notarization flow.

The app bundle sets `LSUIElement=true`, so it behaves like a menu-bar utility rather than a Dock-first application.

On macOS, Open at Login should be enabled only from a stable app location such as `/Applications`; the app intentionally refuses autostart from transient build locations such as `target/`, `dist/`, `/tmp`, and `/var/folders`. On Windows, the portable `dist/WindowsAppAutoLogin-windows-x86_64` build can register itself for Startup, while `target/` and temporary folders are still rejected.

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
- the password field cannot be verified or focused;
- Accessibility returns an error or times out.

### Diagnosis times out

The diagnostic tool uses bounded Accessibility traversal and discards raw output on timeout. A timeout should not expose field values. Try closing unrelated modal dialogs and rerun:

```bash
cargo run --quiet --bin diagnose-macos-ui
```

## Limitations

- Supports only the Microsoft Windows App identity.
- UI detection depends on macOS Accessibility data on macOS and Windows UI Automation data on Windows.
- Prompts with hidden emails, unusual localization, MFA-only flows, SSO web views, or nonstandard controls may not be fillable.
- The app intentionally prefers doing nothing over guessing.

## License

MIT
