import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import net from 'node:net';
import { setTimeout as delay } from 'node:timers/promises';
import {
  AutomationError, acquireSessionLock, cleanEnvironment,
  deviceLockState, listPhysicalDevices, probePhysicalDevice, readConfig, runtimeReady,
} from './support.mjs';
import { startNativeWda, stopOwnedProcessGroup, tunnelEndpoint } from './wda.mjs';

const MAX_RESPONSE_BYTES = 1024 * 1024;

export function startupFailureCode(message) {
  if (typeof message !== 'string') return 'session_start_failed';
  if (/unknown device or simulator|device.*not found|could not find.*device|no device.*found/i.test(message)) return 'iphone_not_available_to_appium';
  if (/no profiles for|provisioning profile|no signing certificate|requires a development team|code signing|codesign|invalid code signature/i.test(message)) return 'wda_signing_required';
  if (/ui automation.*(?:disabled|enable)|enable ui automation/i.test(message)) return 'ui_automation_required';
  if (/device.*locked|unlock.*device|passcode/i.test(message)) return 'phone_locked';
  if (/could not find a driver|driver.*not installed/i.test(message)) return 'driver_unavailable';
  if (/not installed.*(?:device|application)|application.*not installed/i.test(message)) return 'authenticator_not_installed';
  if (/xcodebuild.*(?:code|exit|fail)/i.test(message)) return 'wda_build_failed';
  if (/timed out|timeout|ECONNREFUSED|socket hang up/i.test(message)) return 'wda_connection_failed';
  return 'session_start_failed';
}

export function sessionCapabilities(config, wdaPort, nativeWda) {
  return {
    platformName: 'iOS',
    'appium:automationName': 'XCUITest',
    'appium:udid': config.device_udid,
    // Supplying bundleId here invokes Appium's separate RemoteXPC transport.
    // The verified account flow launches Authenticator through the attached WDA.
    'appium:webDriverAgentUrl': nativeWda.url,
    'appium:platformVersion': nativeWda.platformVersion,
    'appium:xcodeOrgId': config.development_team,
    'appium:xcodeSigningId': 'Apple Development',
    'appium:updatedWDABundleId': config.wda_bundle_id,
    'appium:noReset': true,
    'appium:fullReset': false,
    'appium:autoLaunch': false,
    'appium:forceAppLaunch': false,
    'appium:shouldTerminateApp': false,
    'appium:autoAcceptAlerts': false,
    'appium:autoDismissAlerts': false,
    'appium:disableAutomaticScreenshots': true,
    'appium:printPageSourceOnFindFailure': false,
    'appium:showXcodeLog': false,
    'appium:showIOSLog': false,
    'appium:skipLogCapture': true,
    'appium:clearSystemFiles': true,
    'appium:useNewWDA': false,
    'appium:wdaLocalPort': wdaPort,
    'appium:wdaLaunchTimeout': 45000,
    'appium:wdaConnectionTimeout': 15000,
    'appium:wdaStartupRetries': 1,
    'appium:newCommandTimeout': 60,
    'appium:waitForIdleTimeout': 3,
  };
}

export function validateSessionPath(value) {
  if (typeof value !== 'string' || !/^\/[a-zA-Z0-9_/-]*$/.test(value)
      || value.includes('//') || value.includes('..') || value.length > 512) {
    throw new AutomationError('invalid_request', 'The iPhone helper request is invalid.');
  }
  return value;
}

async function freePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}

async function requestJson(base, method, route, body, signal, timeoutMs = 15000) {
  const timer = AbortSignal.timeout(timeoutMs);
  try {
    const response = await fetch(`${base}${route}`, {
      method, redirect: 'error',
      headers: { 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: signal ? AbortSignal.any([signal, timer]) : timer,
    });
    const reader = response.body.getReader();
    const chunks = [];
    let length = 0;
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > MAX_RESPONSE_BYTES) { await reader.cancel(); throw new Error('oversize'); }
      chunks.push(value);
    }
    const document = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    if (!response.ok || document?.value?.error) {
      // Appium error strings can contain entered text or app content. Never
      // propagate the server's body or exception message to logs/status.
      const error = document?.value?.error;
      const code = route === '/session' ? startupFailureCode(document?.value?.message)
        : error === 'no such element' ? 'element_unavailable'
        : error === 'stale element reference' ? 'screen_changed' : 'device_command_failed';
      throw new AutomationError(code, 'The requested iPhone action could not complete.');
    }
    return document.value;
  } catch (error) {
    if (error instanceof AutomationError) throw error;
    throw new AutomationError(signal?.aborted ? 'cancelled' : 'transport_failed', 'The local iPhone connection is unavailable.');
  }
}

/** Owns one ephemeral local server and device session. Never unlocks a phone. */
export async function createIphoneSession({ signal, timeoutMs = 150000, onStatus = () => {} } = {}) {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 180000) {
    throw new AutomationError('invalid_timeout', 'The iPhone session timeout is invalid.');
  }
  const controller = new AbortController();
  const activeSignal = signal ? AbortSignal.any([signal, controller.signal]) : controller.signal;
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  timer.unref();
  let server;
  let nativeWda;
  let base;
  let sessionId;
  let releaseLock;
  let closePromise;
  let lastPhase;
  const status = phase => { if (phase !== lastPhase) { lastPhase = phase; onStatus({ phase }); } };
  const close = () => closePromise ??= Promise.resolve().then(async () => {
    clearTimeout(timer);
    activeSignal.removeEventListener('abort', onAbort);
    controller.abort();
    if (sessionId && base) {
      try { await requestJson(base, 'DELETE', `/session/${sessionId}`, undefined, undefined, 2000); } catch {}
    }
    try {
      await stopOwnedProcessGroup(server);
      await nativeWda?.close();
    } finally {
      if (releaseLock) await releaseLock();
    }
  });
  const onAbort = () => { void close().catch(() => {}); };
  try {
    const config = await readConfig();
    if (!config.device_udid) throw new AutomationError('device_selection_required', 'Select your iPhone during helper setup first.');
    if (!await runtimeReady(config)) throw new AutomationError('runtime_missing', 'Install the pinned iPhone helper runtime first.');
    releaseLock = await acquireSessionLock();
    activeSignal.throwIfAborted();
    let selectedDevice;
    for (;;) {
      const pollStarted = performance.now();
      const devices = await listPhysicalDevices({ signal: activeSignal });
      const candidate = devices.find(item => item.udid === config.device_udid);
      const device = await probePhysicalDevice(candidate, { signal: activeSignal });
      if (!device?.connected || !device.paired) status('waiting_for_device');
      else if (!device.developerMode) throw new AutomationError('developer_mode_required', 'Enable Developer Mode on your iPhone.');
      else {
        const locked = await deviceLockState(config.device_udid, { signal: activeSignal });
        if (locked === false) { selectedDevice = device; break; }
        status(locked === true ? 'waiting_for_unlock' : 'lock_state_unavailable');
      }
      // A Wi-Fi probe can itself take longer than the retry interval.
      // Keep one probe in flight and check cancellation even if no sleep is due.
      activeSignal.throwIfAborted();
      const remaining = Math.ceil(pollStarted + 1500 - performance.now());
      if (remaining > 0) await delay(remaining, undefined, { signal: activeSignal });
    }
    activeSignal.throwIfAborted();
    tunnelEndpoint(selectedDevice, config.device_udid);
    const port = await freePort();
    const wdaPort = await freePort();
    activeSignal.throwIfAborted();
    const basePath = `/waal-${randomBytes(16).toString('hex')}`;
    base = `http://127.0.0.1:${port}${basePath}`;
    server = spawn(config.node_path, [config.appium_main, '--address', '127.0.0.1', '--port', String(port),
      '--base-path', basePath, '--use-drivers', 'xcuitest', '--log-level', 'error', '--log-no-colors'], {
      cwd: config.runtime_dir, env: { ...cleanEnvironment(), APPIUM_XCUITEST_PREFER_DEVICECTL: 'true' }, detached: true, stdio: 'ignore',
    });
    // Appium boots locally while Xcode starts the runner. The first session
    // request still follows both readiness checks.
    const serverFailure = new AutomationError('server_start_failed', 'The local iPhone server could not start.');
    const serverEnded = () => controller.abort(serverFailure);
    server.once('error', serverEnded);
    server.once('exit', serverEnded);
    try {
      nativeWda = await startNativeWda(config, selectedDevice, { signal: activeSignal, onStatus: status });
    } catch (error) {
      if (activeSignal.reason === serverFailure && error?.code !== 'wda_cleanup_unverified') throw serverFailure;
      throw error;
    } finally {
      server.removeListener('exit', serverEnded);
    }
    activeSignal.throwIfAborted();
    status('starting_iphone_connection');
    const startupDeadline = Date.now() + 15000;
    for (;;) {
      activeSignal.throwIfAborted();
      if (server.exitCode !== null || server.signalCode !== null || Date.now() >= startupDeadline) throw serverFailure;
      try {
        const reply = await requestJson(base, 'GET', '/status', undefined, activeSignal, 1500);
        if (reply?.ready === true) break;
      } catch (error) { if (activeSignal.aborted) throw error; }
      await delay(200, undefined, { signal: activeSignal });
    }
    const result = await requestJson(base, 'POST', '/session', {
      capabilities: { alwaysMatch: sessionCapabilities(config, wdaPort, nativeWda), firstMatch: [{}] },
    }, activeSignal, 70000);
    if (!/^[a-zA-Z0-9-]{1,128}$/.test(result?.sessionId ?? '')) {
      throw new AutomationError('session_start_failed', 'The iPhone automation session could not start.');
    }
    sessionId = result.sessionId;
    activeSignal.throwIfAborted();
    const locked = await requestJson(base, 'POST', `/session/${sessionId}/execute/sync`, { script: 'mobile: isLocked', args: [{}] }, activeSignal);
    if (locked !== false) throw new AutomationError('phone_locked', 'Unlock your iPhone before continuing.');
    // Startup failures are cleaned up by catch. Once ownership is returned,
    // cancellation must also close a session while its caller is idle.
    activeSignal.addEventListener('abort', onAbort, { once: true });
    activeSignal.throwIfAborted();
    status('iphone_connected');
    return {
      request: async (method, route, body) => {
        activeSignal.throwIfAborted();
        if (closePromise || !['GET', 'POST', 'DELETE'].includes(method)) throw new AutomationError('session_closed', 'The iPhone session is closed.');
        return requestJson(base, method, `/session/${sessionId}${validateSessionPath(route)}`, body, activeSignal);
      },
      execute: async (name, args = {}) => {
        activeSignal.throwIfAborted();
        if (closePromise) throw new AutomationError('session_closed', 'The iPhone session is closed.');
        return requestJson(base, 'POST', `/session/${sessionId}/execute/sync`, { script: name, args: [args] }, activeSignal);
      },
      close,
    };
  } catch (error) {
    await close();
    if (error instanceof AutomationError) throw error;
    throw new AutomationError(activeSignal.aborted ? 'cancelled' : 'session_start_failed', 'The iPhone assistance session did not complete.');
  }
}
