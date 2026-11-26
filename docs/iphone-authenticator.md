# iPhone Authenticator helper

This optional macOS integration assists Microsoft Authenticator number matching
for an account's Windows App sign-in. In **Settings → 2FA → Devices**,
click **Connect iPhone…**, choose your phone by name, and click **Connect iPhone**.
AutoLogin checks that this phone responds over Wi-Fi, saves its device identifier
on this Mac, and starts helper setup if needed. All participating accounts use
that phone. To change the selection, return to **Settings → 2FA → Devices**.
In **Accounts**, open an account, turn on **2FA → Use iPhone**, and save.
AutoLogin identifies Microsoft Authenticator from the instructions next to the
two-digit number in Windows App. Other methods require manual sign-in.
The switch defaults to off for new accounts. This feature requires macOS and Xcode.

The Mac recognizes a supported number-matching prompt from Windows App and binds
it to the enabled account and the current sign-in window. It passes the account
and number to the local helper through its private standard-input pipe, never
through command-line arguments, environment variables, logs, or temporary files.
The helper waits for the selected iPhone to be unlocked, opens Microsoft
Authenticator, and waits for the supported request screen for that exact account.
It enters the number and submits that request only after the Mac rechecks that
the original challenge is still current. Unknown, ambiguous, changed, or expired
screens stop assistance. The field check has up to ten seconds. After successful
entry verification and a fresh desktop permit, the helper checks the account,
number, and enabled button again, then clicks **Approve** once. Each action permit
allows up to ten seconds for its phone checks.

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
`field_verification_timeout` means the ten-second field
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
`number_entry_starting` marks the start of entry. The later milestones separate
three intervals:

- From `submit_requested` to `submission_acknowledged`, the Mac and iPhone
  complete the final checks and the helper reports that its Approve tap returned.
- From `submission_acknowledged` to `cleanup_requested`, the Mac waits until it
  observes that the desktop challenge is no longer pending. This interval can
  include Face ID and the desktop response.
- From `cleanup_requested` to the final `elapsed_ms` of a submitted attempt,
  the helper closes the session and its process exits.

An attempt that ends earlier omits the later milestones. The clock starts after
Monitor recognizes the sign-in request. A separate `detection_scan_ms` field
measures how long the Mac spent
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

To pair an iPhone and verify its Wi-Fi connection, install Xcode and open it once
to finish setup. This step uses Apple’s device tools and requires no signing team.

**Connect iPhone** checks whether the helper is ready for the selected phone.
If setup is needed, it continues with your saved Xcode signing account or the
only available account. If there are several and no saved choice, select the
account you want to use.

Earlier releases did not record which iPhone completed setup. The first time
you click **Connect iPhone** after upgrading, AutoLogin runs preparation once
and reuses matching tools already on this Mac.

1. On the iPhone, enable **Developer Mode** under **Settings → Privacy & Security**
   and **Enable UI Automation** under **Settings → Developer**. Add your work
   account to Microsoft Authenticator.
2. In **Xcode → Settings → Accounts**, add your own Apple Account. Select its
   personal or organization team and create an **Apple Development** certificate
   under **Manage Certificates → +**. AutoLogin can open Xcode from the setup screen.
3. Return to AutoLogin and keep the selected iPhone unlocked on the same Wi-Fi.
   AutoLogin installs the tools, asks Xcode to sign the helper for this device,
   and checks a UI Automation session. Follow any developer trust prompts on
   the iPhone.

Xcode uses the selected user's signing identity and keeps its private key in
Keychain. Personal Team provisioning is time-limited by Apple, typically to seven
days. AutoLogin checks the profile before reuse and asks Xcode to refresh expired
provisioning. If Xcode requires account attention, return to setup and retry after
completing its prompts.

AutoLogin uses a compatible local Node.js with npm when available. Otherwise it
downloads Node.js **24.22.3 LTS** from **nodejs.org** into its private tools folder
and verifies the archive against a SHA-256 value embedded in the app before
extracting it. The installed app contains the helper source used by setup.

Developers can also prepare the helper from the repository root. Choose a local
team explicitly with `setup --team TEAM_ID`, or use `setup` to retain the configured
team or select the only available team.

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

The directory is private to the current user and `config.json` is mode `0600`.
Repeated setup preserves the selected iPhone and reuses a matching installed
runtime. Setup publishes the helper modules and selected signing team together
with the configuration. To run setup again manually, open
**Sign-in details… → Set up automation…**.

### What happens before a sign-in

When at least one enabled account uses Microsoft Authenticator and an installed
helper has a selected iPhone, AutoLogin checks for an existing XCTest build on
this Mac. It does this at startup and after a configuration change, including
saving a phone in Settings. If a build is needed, AutoLogin runs its own
`xcodebuild build-for-testing` in the background using the local signing setup.
The signed product stays on disk across app restarts. A failed preparation can
retry after a password write. Turning off the last eligible account or quitting
AutoLogin cancels an in-progress build.

When **Enter** starts a new desktop connection for an enabled account with
**Use iPhone** turned on, AutoLogin starts connecting to the selected iPhone
over Wi-Fi while Windows App opens the desktop. Bringing an existing desktop
to the front skips this step. AutoLogin can also wake the connection when it
fills the password. Both paths share a single in-flight Wi-Fi check. The
sign-in request verifies the device, Wi-Fi transport and lock state again.

The Xcode app can stay open for other projects. Each real sign-in starts a
private Appium server and a fresh XCTest session on the selected iPhone. Both
are closed at the end of the attempt. Preparing the build uses no phone session
and does not open Authenticator.

## Select and prepare the physical iPhone

1. Unlock the iPhone and connect it and the Mac to the same Wi-Fi network.
   Open **Settings → 2FA → Devices → Connect iPhone…** in AutoLogin.
2. If the phone has never been paired with this Mac, click **Open device pairing…**.
   In Xcode 27’s Device Hub, an iPhone running iOS 27 or later can pair wirelessly
   using **+ → Pair Nearby Device…**. Confirm the trust prompt on the iPhone.
   With an earlier iOS version, connect the iPhone by cable for initial pairing.
   Older versions of Xcode manage devices under **Window → Devices and Simulators**.
   [Apple’s device pairing guide](https://developer.apple.com/documentation/xcode/managing-your-simulated-and-physical-devices-in-device-hub)
3. Disconnect the cable if you used one. Return to AutoLogin, select your phone
   and click **Connect iPhone**. If it hasn't appeared, click **Refresh iPhones**.
   Once the Wi-Fi check succeeds, AutoLogin saves your choice and checks the
   helper. If the helper is ready for this iPhone, setup is complete.

   For command-line setup, `node script/iphone-automation/cli.mjs select-device`
   selects the sole paired physical iPhone. With multiple paired phones, pass
   `--udid IDENTIFIER` from Xcode’s **Window → Devices and Simulators**.

4. If preparation is needed, keep the phone unlocked and follow any signing or
   device prompts in AutoLogin. Developers using the command line can run:

   ```sh
   node script/iphone-automation/cli.mjs prepare-device
   ```

   This signs the dedicated WebDriverAgent runner with the selected user's Apple
   Development identity, permits Xcode to provision the selected device, and
   verifies a UI Automation session over Wi-Fi. The build cache is scoped to the
   WDA version, signing team and helper bundle ID. The preparation session closes
   after verification.

New installations use the WDA bundle identifier
`com.obcardinal.WindowsAppAutoLogin.<TEAM_ID>.WebDriverAgentRunner`.
Existing installations retain their original bundle when keeping the same team.
Authenticator's bundle
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
