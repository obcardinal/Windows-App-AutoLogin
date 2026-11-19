import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { AutomationError, cleanEnvironment, ensurePrivateDirectory, paths, runQuiet, validRunnerBundle } from './support.mjs';

export function tunnelEndpoint(device, expectedUdid) {
  if (device?.udid !== expectedUdid || !device.paired || !device.connected
      || device.transport !== 'localNetwork' || net.isIP(device.tunnelAddress) !== 6
      || !/^\d+\.\d+(?:\.\d+)?$/.test(device.osVersion ?? '')) {
    throw new AutomationError('wifi_device_required', 'Connect the selected trusted iPhone over Wi-Fi.');
  }
  return `http://[${device.tunnelAddress}]:8100`;
}

export function configureTestRun(document, tunnelAddress) {
  if (net.isIP(tunnelAddress) !== 6 || !document?.WebDriverAgentRunner?.EnvironmentVariables) {
    throw new AutomationError('wda_build_failed', 'The iPhone automation runner is not ready.');
  }
  const result = structuredClone(document);
  Object.assign(result.WebDriverAgentRunner.EnvironmentVariables, {
    // WDA must not listen on all phone Wi-Fi interfaces.
    USE_IP: tunnelAddress, USE_PORT: '8100', MJPEG_SERVER_PORT: '0',
  });
  result.WebDriverAgentRunner.SystemAttachmentLifetime = 'keepNever';
  result.WebDriverAgentRunner.UserAttachmentLifetime = 'keepNever';
  return result;
}

export function dedicatedRunnerExecutable(document, bundleId) {
  if (!Array.isArray(document?.result?.apps)) {
    throw new AutomationError('wda_cleanup_unverified', 'The iPhone test runner could not be verified.');
  }
  const matches = document.result.apps.filter(app => app.bundleIdentifier === `${bundleId}.xctrunner`);
  if (matches.length === 0) return null;
  if (matches.length !== 1 || matches[0].builtByDeveloper !== true
      || typeof matches[0].url !== 'string'
      || !/^file:\/\/\/private\/var\/containers\/Bundle\/Application\/[A-Fa-f0-9-]+\/WebDriverAgentRunner-Runner\.app\/$/.test(matches[0].url)) {
    throw new AutomationError('wda_cleanup_unverified', 'The iPhone test runner could not be verified.');
  }
  return `${matches[0].url}WebDriverAgentRunner-Runner`;
}

export function dedicatedRunnerPids(document, executable) {
  if (!Array.isArray(document?.result?.runningProcesses)) {
    throw new AutomationError('wda_cleanup_unverified', 'The iPhone test runner could not be verified.');
  }
  return document.result.runningProcesses.filter(item => item.executable === executable
    && Number.isSafeInteger(item.processIdentifier) && item.processIdentifier > 0).map(item => item.processIdentifier);
}

async function deviceDocument(config, command, signal) {
  const data = await runQuiet('/usr/bin/xcrun', ['devicectl', 'device', ...command,
    '--device', config.device_udid, '--timeout', '5', '--json-output', '-'], { timeout: 6000, signal });
  return JSON.parse(data);
}

async function runnerIsListening(url, signal) {
  try {
    const response = await fetch(`${url}/status`, { redirect: 'error', signal: AbortSignal.any([signal, AbortSignal.timeout(1500)]) });
    return response.ok;
  } catch { signal.throwIfAborted(); return false; }
}

async function stopPhoneRunner(config, url) {
  const signal = AbortSignal.timeout(6500);
  try {
    // XCTest's host process can exit while its device-side runner stays alive.
    // Resolve our exact signed bundle to its executable before selecting a PID;
    // a generic WebDriverAgent name never authorizes terminating another app.
    const apps = await deviceDocument(config, ['info', 'apps', '--search', config.wda_bundle_id], signal);
    const executable = dedicatedRunnerExecutable(apps, config.wda_bundle_id);
    if (executable) {
      const processes = await deviceDocument(config, ['info', 'processes', '--search', 'WebDriverAgent'], signal);
      for (const pid of dedicatedRunnerPids(processes, executable)) {
        await deviceDocument(config, ['process', 'terminate', '--pid', String(pid), '--kill'], signal);
      }
      const remaining = await deviceDocument(config, ['info', 'processes', '--search', 'WebDriverAgent'], signal);
      if (dedicatedRunnerPids(remaining, executable).length !== 0) throw new Error('runner_still_running');
    }
    if (await runnerIsListening(url, signal)) throw new Error('listener_still_running');
  } catch {
    throw new AutomationError('wda_cleanup_unverified', 'Reconnect the selected iPhone to finish stopping its test runner.');
  }
}

export async function stopOwnedProcessGroup(child) {
  if (!child?.pid) return;
  // A detached group can outlive its leader. Never infer descendant cleanup
  // from the Appium/xcodebuild leader's exitCode or its `exit` event.
  const alive = () => { try { process.kill(-child.pid, 0); return true; } catch { return false; } };
  if (!alive()) return;
  try { process.kill(-child.pid, 'SIGTERM'); } catch {}
  const deadline = performance.now() + 1200;
  while (alive()) {
    const remaining = deadline - performance.now();
    if (remaining <= 0) {
      try { process.kill(-child.pid, 'SIGKILL'); } catch {}
      return;
    }
    await delay(Math.min(50, Math.ceil(remaining)));
  }
}

async function buildRunner(args, signal, detached, timeoutMs = 100000) {
  signal.throwIfAborted();
  const child = spawn('/usr/bin/xcodebuild', args, { env: cleanEnvironment(), detached, stdio: 'ignore' });
  let succeeded = false;
  let closePromise;
  let forceKill;
  const closeGroup = () => closePromise ??= stopOwnedProcessGroup(child);
  const abort = () => {
    if (detached) { void closeGroup().catch(() => {}); return; }
    // The Mac supervisor owns our group, including this compiler's descendants.
    // Never address a synthetic group at the non-detached compiler's PID.
    if (!forceKill && child.pid && child.exitCode === null && child.signalCode === null) {
      child.kill('SIGTERM');
      forceKill = setTimeout(() => child.kill('SIGKILL'), 1200);
      forceKill.unref();
    }
  };
  signal.addEventListener('abort', abort, { once: true });
  const timeout = setTimeout(abort, timeoutMs);
  try {
    succeeded = await new Promise(resolve => {
      child.once('error', () => resolve(false));
      child.once('exit', (code, termination) => resolve(code === 0 && termination === null));
    });
  } finally {
    clearTimeout(timeout);
    signal.removeEventListener('abort', abort);
    clearTimeout(forceKill);
    if (detached) await closeGroup();
  }
  signal.throwIfAborted();
  if (!succeeded) throw new AutomationError('wda_build_failed', 'Prepare Xcode signing for the selected iPhone, then retry.');
}

async function findTestRun(products) {
  try {
    const entries = await fs.readdir(products, { withFileTypes: true });
    const manifests = entries.filter(entry => entry.isFile() && entry.name.endsWith('.xctestrun') && !entry.name.startsWith('private-'));
    if (manifests.length !== 1) return null;
    const runner = path.join(products, 'Debug-iphoneos', 'WebDriverAgentRunner-Runner.app');
    await Promise.all([
      fs.access(path.join(runner, 'WebDriverAgentRunner-Runner'), fs.constants.X_OK),
      fs.access(path.join(runner, 'PlugIns', 'WebDriverAgentRunner.xctest', 'WebDriverAgentRunner'), fs.constants.X_OK),
    ]);
    return { original: path.join(products, manifests[0].name), privateFile: path.join(products, 'private-wifi.xctestrun') };
  } catch (error) {
    if (['ENOENT', 'ENOTDIR', 'EACCES'].includes(error.code)) return null;
    throw error;
  }
}

async function buildTestRun(config, upstream, source, derived, signal, hostOnly, registerDevice = false) {
  signal.throwIfAborted();
  await ensurePrivateDirectory(source);
  await fs.cp(upstream, source, { recursive: true, force: true });
  signal.throwIfAborted();
  const projectFile = path.join(source, 'WebDriverAgent.xcodeproj', 'project.pbxproj');
  const project = await fs.readFile(projectFile, 'utf8');
  const bundleBase = config.wda_bundle_id.slice(0, -'Runner'.length);
  await fs.writeFile(projectFile, project.replaceAll('com.facebook.WebDriverAgent', bundleBase), { mode: 0o600 });
  const destinationArgs = hostOnly ? ['-destination', 'generic/platform=iOS']
    : ['-destination', `id=${config.device_udid}`, '-allowProvisioningUpdates'];
  if (registerDevice) destinationArgs.push('-allowProvisioningDeviceRegistration');
  await buildRunner(['-project', path.join(source, 'WebDriverAgent.xcodeproj'),
    '-scheme', 'WebDriverAgentRunner', ...destinationArgs, '-derivedDataPath', derived,
    `DEVELOPMENT_TEAM=${config.development_team}`, 'CODE_SIGN_IDENTITY=Apple Development',
    'CODE_SIGN_STYLE=Automatic', 'build-for-testing'], signal, !hostOnly, registerDevice ? 180000 : 100000);
  const result = await findTestRun(path.join(derived, 'Build', 'Products'));
  if (!result) throw new AutomationError('wda_build_failed', 'The iPhone automation runner could not be prepared.');
  return result;
}

async function runnerPaths(config, signal) {
  signal.throwIfAborted();
  const root = path.dirname(config.runtime_dir);
  const upstream = path.join(config.runtime_dir, 'node_modules', 'appium-xcuitest-driver', 'node_modules', 'appium-webdriveragent');
  const metadata = JSON.parse(await fs.readFile(path.join(upstream, 'package.json'), 'utf8'));
  if (!/^\d+\.\d+\.\d+$/.test(metadata.version)) throw new AutomationError('runtime_missing', 'Reinstall the pinned iPhone helper runtime.');
  if (!validRunnerBundle(config.development_team, config.wda_bundle_id)) {
    throw new AutomationError('invalid_configuration', 'Choose an Apple signing team in iPhone setup.');
  }
  const signing = createHash('sha256').update(`${config.development_team}\n${config.wda_bundle_id}`).digest('hex').slice(0, 16);
  const cache = `${metadata.version}-${signing}`;
  const source = path.join(root, `wda-${cache}`);
  const derived = path.join(root, `wda-derived-data-${cache}`);
  const hostProducts = path.join(root, `wda-host-products-${cache}`);
  const existing = await findTestRun(path.join(derived, 'Build', 'Products'));
  const hosted = existing ? null : await findTestRun(hostProducts);
  signal.throwIfAborted();
  return { root, upstream, source, derived, hostProducts, existing, hosted };
}

/** Prepare only relocatable signed products on the Mac. A real request owns the device launch. */
export async function prepareHostRunner(config, signal) {
  const { root, upstream, hostProducts, existing, hosted } = await runnerPaths(config, signal);
  if (existing || hosted) return;
  const staging = await fs.mkdtemp(path.join(root, 'wda-host-build-'));
  try {
    const derived = path.join(staging, 'derived');
    await buildTestRun(config, upstream, path.join(staging, 'source'), derived, signal, true);
    signal.throwIfAborted();
    // XCTest's product paths are relative to __TESTROOT__. Publish the entire
    // set in one rename. The foreground can use its own cache throughout.
    try { await fs.rename(path.join(derived, 'Build', 'Products'), hostProducts); }
    catch (error) {
      if (!['EEXIST', 'ENOTEMPTY'].includes(error.code) || !await findTestRun(hostProducts)) throw error;
    }
  } finally {
    await fs.rm(staging, { recursive: true, force: true });
  }
}

// A generic build may choose a development profile for different devices.
// Check the local signed product during a request before handing it to XCTest.
async function hostProfileSupports(root, products, config, signal) {
  const runner = path.join(products, 'Debug-iphoneos', 'WebDriverAgentRunner-Runner.app');
  const profile = path.join(runner, 'embedded.mobileprovision');
  const directory = await fs.mkdtemp(path.join(root, 'wda-profile-'));
  try {
    const decoded = path.join(directory, 'profile.plist');
    await runQuiet('/usr/bin/security', ['cms', '-D', '-i', profile, '-o', decoded], { signal });
    const [devices, expiration, team, prefixes, application, signature] = await Promise.all([
      runQuiet('/usr/bin/plutil', ['-extract', 'ProvisionedDevices', 'json', '-o', '-', decoded], { signal }),
      runQuiet('/usr/bin/plutil', ['-extract', 'ExpirationDate', 'raw', '-o', '-', decoded], { signal }),
      runQuiet('/usr/bin/plutil', ['-extract', 'TeamIdentifier', 'json', '-o', '-', decoded], { signal }),
      runQuiet('/usr/bin/plutil', ['-extract', 'ApplicationIdentifierPrefix', 'json', '-o', '-', decoded], { signal }),
      runQuiet('/usr/bin/plutil', ['-extract', 'Entitlements.application-identifier', 'raw', '-o', '-', decoded], { signal }),
      runQuiet('/usr/bin/codesign', ['--display', '--verbose=4', runner], { signal, captureStderr: true }),
      runQuiet('/usr/bin/codesign', ['--verify', '--deep', '--strict', runner], { signal }),
    ]);
    const listed = JSON.parse(devices);
    const teamIdentifiers = JSON.parse(team);
    const appPrefixes = JSON.parse(prefixes);
    const signedFields = signature.split('\n');
    const signedTeam = signedFields.filter(line => line.startsWith('TeamIdentifier='));
    const signedBundle = signedFields.filter(line => line.startsWith('Identifier='));
    return Date.parse(expiration.trim()) > Date.now() && Array.isArray(listed)
      && listed.some(value => typeof value === 'string' && value.toLowerCase() === config.device_udid.toLowerCase())
      && Array.isArray(teamIdentifiers) && teamIdentifiers.length === 1 && teamIdentifiers[0] === config.development_team
      && signedTeam.length === 1 && signedTeam[0] === `TeamIdentifier=${config.development_team}`
      && signedBundle.length === 1 && signedBundle[0] === `Identifier=${config.wda_bundle_id}.xctrunner`
      && Array.isArray(appPrefixes) && appPrefixes.some(prefix => typeof prefix === 'string'
        && /^[A-Z0-9]{10}$/.test(prefix) && profileApplicationMatches(application.trim(), `${prefix}.${config.wda_bundle_id}.xctrunner`));
  } catch {
    signal.throwIfAborted();
    return false;
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
}

export function profileApplicationMatches(pattern, application) {
  if (pattern === application) return true;
  // Apple's automatic development profiles can cover a bundle prefix. The
  // actual signed bundle and team are verified independently above.
  return pattern.endsWith('.*') && !pattern.slice(0, -1).includes('*')
    && application.startsWith(pattern.slice(0, -1));
}

async function preparedTestRun(config, signal, onStatus) {
  const { root, upstream, source, derived, hostProducts, existing, hosted } = await runnerPaths(config, signal);
  if (existing && await hostProfileSupports(root, path.dirname(existing.original), config, signal)) return existing;
  if (hosted && await hostProfileSupports(root, hostProducts, config, signal)) return hosted;
  onStatus('preparing_iphone_runner');
  return buildTestRun(config, upstream, source, derived, signal, false);
}

/** Explicit setup may register the selected device with the user's Apple team. */
export async function prepareDeviceRunner(config, signal) {
  const { upstream, source, derived } = await runnerPaths(config, signal);
  await buildTestRun(config, upstream, source, derived, signal, false, true);
}

// XCTest prints this marker after binding its HTTP listener. We only use it
// to wake one poll. The endpoint always comes from the selected phone's tunnel.
function watchRunnerOutput(stream, hint) {
  if (!stream) return () => {};
  const marker = 'ServerURLHere->';
  let tail = '';
  const onData = chunk => {
    if (hint.signal.aborted) return;
    const text = tail + chunk.toString('latin1');
    if (text.includes(marker)) {
      tail = '';
      hint.abort();
    } else {
      tail = text.slice(1 - marker.length);
    }
  };
  stream.on('data', onData);
  return () => {
    stream.off('data', onData);
    stream.resume(); // Drain subsequent XCTest output without retaining or logging it.
  };
}

// Poll twice a second, plus one early probe on the listener announcement.
// Time spent waiting for a response counts toward the interval. Requests never overlap.
export async function waitForRunnerReady(url, child, signal) {
  const deadline = performance.now() + 45000;
  const hint = new AbortController();
  const wakeSignal = AbortSignal.any([signal, hint.signal]);
  const stopWatching = [child.stdout, child.stderr].map(stream => watchRunnerOutput(stream, hint));
  let usedHint = false;
  let spawnFailed = false;
  const onError = () => { spawnFailed = true; };
  const check = () => {
    signal.throwIfAborted();
    if (spawnFailed || child.exitCode !== null || child.signalCode !== null || performance.now() >= deadline) {
      throw new AutomationError('wda_connection_failed', 'Unlock the iPhone and enable UI Automation in Developer settings.');
    }
  };
  child.once('error', onError);
  try {
    for (;;) {
      check();
      const started = performance.now();
      const timeout = Math.max(1, Math.min(1500, Math.ceil(deadline - started)));
      let ready = false;
      try {
        const response = await fetch(`${url}/status`, { redirect: 'error', signal: AbortSignal.any([signal, AbortSignal.timeout(timeout)]) });
        ready = response.ok && (await response.json())?.value?.ready === true;
      } catch { signal.throwIfAborted(); }
      check();
      if (ready) return;
      const pause = Math.min(started + 500, deadline) - performance.now();
      if (pause > 0) {
        try {
          await delay(Math.ceil(pause), undefined, { signal: usedHint ? signal : wakeSignal });
        } catch (error) {
          signal.throwIfAborted();
          if (usedHint || !hint.signal.aborted) throw error;
        }
      }
      usedHint = hint.signal.aborted;
    }
  } finally {
    child.removeListener('error', onError);
    for (const stop of stopWatching) stop();
  }
}

/** Launch XCTest using Apple's paired Wi-Fi transport; Appium attaches afterward. */
export async function startNativeWda(config, device, { signal, onStatus = () => {} }) {
  const url = tunnelEndpoint(device, config.device_udid);
  let child;
  let resultsDirectory;
  let closePromise;
  const close = () => closePromise ??= Promise.resolve().then(async () => {
    try {
      await stopOwnedProcessGroup(child);
      if (child?.pid) await stopPhoneRunner(config, url);
    } finally {
      if (resultsDirectory) await fs.rm(resultsDirectory, { recursive: true, force: true }).catch(() => {});
    }
  });
  try {
    const files = await preparedTestRun(config, signal, onStatus);
    signal.throwIfAborted();
    const document = JSON.parse(await runQuiet('/usr/bin/plutil', ['-convert', 'json', '-o', '-', files.original], { signal }));
    await fs.writeFile(files.privateFile, JSON.stringify(configureTestRun(document, device.tunnelAddress)), { mode: 0o600 });
    await runQuiet('/usr/bin/plutil', ['-convert', 'xml1', files.privateFile], { signal });
    resultsDirectory = await fs.mkdtemp(path.join(paths().root, 'session-results-'));
    await fs.chmod(resultsDirectory, 0o700);
    signal.throwIfAborted();
    onStatus('starting_iphone_runner');
    child = spawn('/usr/bin/xcodebuild', ['test-without-building', '-xctestrun', files.privateFile,
      '-destination', `id=${config.device_udid}`, '-destination-timeout', '20', '-allowProvisioningUpdates',
      '-resultBundlePath', path.join(resultsDirectory, 'results.xcresult')], {
      env: cleanEnvironment(), detached: true, stdio: ['ignore', 'pipe', 'pipe'],
    });
    await waitForRunnerReady(url, child, signal);
    return { url, platformVersion: device.osVersion, close };
  } catch (error) {
    await close();
    throw error;
  }
}
