# iPhone Authenticator helper

This optional macOS integration assists Microsoft Authenticator number matching
for an account's Windows App sign-in. In **Settings → iPhone Authentication**,
click **Set up iPhone…**, choose a paired device by name, and click **Save iPhone**.
All participating accounts use this phone. The choice is saved on this Mac by
device identifier. Open **Sign-in details… → iPhone setup…** to change it later. In **Accounts**, open an account and choose
**Microsoft Authenticator** from the **2FA → iPhone app** dropdown, then save.
Choose **Off** to handle sign-in requests manually. New accounts default to
**Off**. This feature requires macOS and Xcode.

The Mac recognizes a supported number-matching prompt from Windows App and binds
it to the enabled account and the current sign-in window. It passes the account
and number to the local helper through its private standard-input pipe, never
through command-line arguments, environment variables, logs, or temporary files.
The helper waits for the selected iPhone to be unlocked, opens Microsoft
Authenticator, and waits for the supported request screen for that exact account.
It enters the number and submits that request only after the Mac rechecks that
the original challenge is still current. Unknown, ambiguous, changed, or expired
screens stop assistance. The field check has up to ten seconds. If it takes
more than two seconds, the Mac rechecks the request before entry and asks
you to review it and tap **Approve** on the iPhone.

The user enters the iPhone passcode and performs Face ID on the phone. Developer
Mode, Appium, and XCUITest do not bypass either. A submitted request is not reported
as a verified successful sign-in: complete any required confirmation on the iPhone.
The Mac progress panel has **Cancel**. Stopping Monitor, opening Settings, or
editing account configuration cancels current assistance and waits for its helper
to finish closing before making the configuration available to another attempt.

### Diagnose a stopped attempt

Once Monitor recognizes a sign-in request and starts iPhone assistance, it updates
`~/Library/Application Support/WindowsAppAutoLogin/Runtime/last-iphone-attempt.json`.
The file holds only the latest attempt. It records the UTC time, elapsed milliseconds,
stage, outcome and, when available, a reason such as `account_mismatch`,
`screen_changed` or `authorization_expired`. If the app exits during an attempt,
the last recorded stage can still show `in_progress`. `submitted_unverified`
means that the iPhone helper reported submission. It does not confirm desktop sign-in.
`manual_approval_required` means the helper entered the number and handed the
request back to you. `field_verification_timeout` means the ten-second field
check expired before entry.
The report is private to the local user and contains no account or device identifiers,
sign-in numbers, passwords, or screen contents.

`milestones_ms` gives elapsed milliseconds from the start of assistance to the
first time the Mac observes each event. `helper_spawned` marks the Mac helper process
starting. `runner_starting` marks the Xcode
launch request, `runner_ready` marks the iPhone runner answering, and
`phone_connected` marks the Appium session ready after the lock check.
`authenticator_open_requested` and `field_check_requested` record when the Mac
receives the requests to open Authenticator and check the number field.
`number_entry_starting` marks the start of entry. An attempt that ends earlier
omits the later milestones. The clock starts after Monitor recognizes the sign-in
request. A separate `detection_scan_ms` field measures how long the Mac spent
scanning the Windows App window on the pass that recognized the request. The
time between the number appearing on screen and that scan starting is unknown.

Supported Authenticator UI is pinned to the observed selectors in
`script/iphone-automation/authenticator.mjs`. A missing profile fails before a
phone session starts; an unexpected language, alert, account label, or
input layout is not accepted through a generic fallback.

The verified profile is the English **Approve this sign-in?** screen observed on
a physical iPhone 16 Pro with iOS 27.2. It has the instruction **Enter the number
shown on the sign-in screen. Only approve if you’re trying to sign in.**, the
field **Enter the number shown to sign in.**, and an initially disabled
**Approve** button. The request's account label must match the configured account
exactly. Microsoft Authenticator's installed app version was not independently
confirmed; support is based on the observed control structure, not a claimed
version range. Inspection did not enter a number or approve a sign-in.

## Host setup

Requirements: macOS, Xcode, Node.js compatible with the pinned Appium release,
npm 10+, and an Apple Development signing identity for team `76C2QW8JV3`.

From the repository root:

```sh
node script/iphone-automation/cli.mjs setup
node script/iphone-automation/cli.mjs status
node script/iphone-automation/cli.mjs devices
```

Setup installs **Appium 4.0.0** and **XCUITest driver 13.1.1** using the committed
npm lockfile. It uses a dedicated versioned directory under:

```text
~/Library/Application Support/WindowsAppAutoLogin/iphone-automation/
```

No global npm packages or existing Appium installation are modified. Dependencies
remain outside the source repository. The directory is private to the current
user; `config.json` is mode `0600`. Setup copies the helper's `.mjs` modules there;
rerun it after updating helper source. Repeated setup preserves the selected
device and reuses an already installed matching runtime.

### What happens before a sign-in

When at least one enabled account uses Microsoft Authenticator and an installed
helper has a selected iPhone, AutoLogin checks for an existing XCTest build on
this Mac. It does this at startup and after a configuration change, including
saving a phone in Settings. If a build is needed, AutoLogin runs its own
`xcodebuild build-for-testing` in the background using the local signing setup.
The signed product stays on disk across app restarts. A failed preparation can
retry after a password write. Turning off the last eligible account or quitting
AutoLogin cancels an in-progress build.

The Xcode app can stay open for other projects. Each real sign-in starts a
private Appium server and a fresh XCTest session on the selected iPhone. Both
are closed at the end of the attempt. Preparing the build uses no phone session
and does not open Authenticator.

## Select and prepare the physical iPhone

1. Keep this Mac and the previously paired iPhone on the same trusted Wi-Fi
   network, and unlock the iPhone manually. This helper uses Wi-Fi only; it does
   not require or fall back to USB. The selected phone must already be paired
   with this Mac in Xcode's Devices and Simulators window.
2. Enable Developer Mode and enable
   **Settings → Developer → Enable UI Automation**.
3. Ensure Microsoft Authenticator is installed and its required account is set up.
4. In **Settings → iPhone Authentication**, open **Set up iPhone…**. Choose a
   phone from **Paired iPhone** and click **Save iPhone**. If the phone is missing,
   check pairing in Xcode, then click **Refresh iPhones**. You can save the phone
   before installing the host helper. Setup uses the saved choice on this Mac.

   For command-line setup, `node script/iphone-automation/cli.mjs select-device`
   selects the sole paired physical iPhone. With multiple paired phones, pass
   `--udid IDENTIFIER` from Xcode’s **Window → Devices and Simulators**.

5. After the device is connected and unlocked, deliberately prepare WDA:

   ```sh
   node script/iphone-automation/cli.mjs prepare-device
   ```

   This builds/signs the dedicated WebDriverAgent runner using the existing Apple
   Development identity when needed, then installs/launches it through Xcode over
   Wi-Fi. The build cache is scoped to the pinned WDA version. It does not open
   Authenticator, submit a
   number, or request an authentication approval. Missing provisioning requires
   completing Xcode signing setup; the helper does not silently change developer
   account registration or device security settings.

The Appium WDA bundle identifier is
`com.obcardinal.WindowsAppAutoLogin.WebDriverAgentRunner`. Authenticator's bundle
identifier is `com.microsoft.azureauthenticator`, verified against its Apple App
Store entry.

`status` is read-only. It does not start WDA or an Appium session, so `wda_ready`
is `null` (not checked). `device_locked: null` means the lock state is unknown;
it does **not** authorize automation. Status may wake the selected paired phone's
dormant CoreDevice Wi-Fi tunnel; an unreachable phone remains unavailable.
The `devicectl lockState` response must be recognized before a session can start.

## Runtime transport contract

`bridge.mjs` exports:

```js
const session = await createIphoneSession({
  signal,
  timeoutMs: 150000,
  onStatus: ({ phase }) => reportStatus(phase),
});
try {
  // Only verified, account-specific screen logic may use these primitives.
  await session.execute('mobile: launchApp', {
    bundleId: 'com.microsoft.azureauthenticator',
    asAppUnderTest: true,
  });
  // session.request(method, sessionRelativePath, body)
} finally {
  await session.close();
}
```

The wrapper that calls this API must supply cancellation on its parent process
disconnect, SIGTERM/SIGINT, or protocol EOF. The bridge enforces a maximum
three-minute lifetime, closes its session on cancellation, and terminates its
own Appium and Xcode process groups, including descendants whose leader already
exited. It then resolves the dedicated signed WDA bundle on the selected phone to
its exact executable, terminates only matching processes, and verifies that both
the runner and its listener have stopped. It never terminates Authenticator.
A private process lock prevents overlapping assistance
sessions. Appium runs only on `127.0.0.1`, on an ephemeral port, with an ephemeral
base path; no persistent daemon is installed.

Phone-side cleanup has one shared 6.5-second deadline. Including Appium session
deletion and host process-group shutdown, closing is bounded to about 11 seconds
plus removal of the small private test-result directory. A lost connection that
prevents verifying cleanup is returned as `wda_cleanup_unverified`; it is not
silently reported as success. Reconnect the selected iPhone to finish stopping
its dedicated test runner before another attempt.

Once the bridge has checked the selected iPhone, its lock state, and the Wi-Fi
tunnel, it starts the local Appium server while Xcode launches the signed XCTest
runner. The bridge waits for both to be ready before creating a session.
`wda.mjs` uses Apple's existing trusted CoreDevice Wi-Fi tunnel.
Its WDA listener binds only to that tunnel's IPv6
address, not all Wi-Fi interfaces. Appium attaches to that exact endpoint using
the selected device's explicit iOS version. This avoids Appium's separate
USB/RemoteXPC tunnel discovery and does not require a privileged tunnel daemon.
The initial Appium session omits an application bundle ID; verified screen logic
launches the fixed Authenticator bundle only after the lock checks pass.

The transport does not automatically launch Authenticator. It pins the selected
physical device and performs both a pre-session lock check and a WDA lock check.
It never sends an unlock command. Neither XCUITest nor Developer Mode bypasses a
passcode or Face ID.

Sessions preserve application data, disable automatic alert acceptance and
dismissal, disable automatic screenshots/page-source-on-failure, skip device log
capture, and discard Appium/Xcode output. XCTest result bundles remain in a private
temporary session directory that is removed when the owned runner closes;
automatic system/user test attachments are configured for deletion.
Server exception bodies are not exposed
to callers because they can include app content or entered values. Runtime code
must never log or persist entered numbers, raw UI content, or screenshots. No
general-purpose command execution is exposed by the CLI.

## Validation

```sh
node --test --experimental-test-module-mocks script/iphone-automation/*.test.mjs
```

The synthetic tests cover physical-device selection, ambiguous/unknown state,
configuration boundaries, request-path containment, private error handling, and
cancellation while resources are being created or after session handoff. They
also cover exact phone-runner ownership and cleanup when a host group leader has
already exited. One deliberate physical-device preparation verified native WDA
and Appium attachment over Wi-Fi, the unlocked-phone check, and runner/listener
shutdown, without opening Authenticator or initiating authentication.

Transport tests do not prove compatibility with a live Authenticator screen or a
successful MFA login. Those require the user's connected iPhone and a fresh known
sign-in request. Authentication numbers, account identifiers, raw UI trees, and
screenshots must not be captured in validation output.

References:

- [Appium dependency management](https://appium.io/docs/en/latest/guides/managing-exts/)
- [XCUITest device setup](https://appium.github.io/appium-xcuitest-driver/latest/getting-started/device-setup/)
- [WDA provisioning](https://appium.github.io/appium-xcuitest-driver/latest/getting-started/provisioning-profile/)
- [XCUITest capabilities](https://appium.github.io/appium-xcuitest-driver/latest/reference/capabilities/)
- [Lock and application commands](https://appium.github.io/appium-xcuitest-driver/latest/reference/execute-methods/)
- [Microsoft Authenticator on the App Store](https://apps.apple.com/us/app/microsoft-authenticator/id983156458)
