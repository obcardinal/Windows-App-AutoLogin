import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { AutomationError, cleanEnvironment, ensurePrivateDirectory, paths, runQuiet } from './support.mjs';

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
  result.WebDriverAgentRunner.SystemAttachmentLifetime = 'deleteAlways';
  result.WebDriverAgentRunner.UserAttachmentLifetime = 'deleteAlways';
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
  if (!alive()) return;
  await delay(1200);
  if (alive()) { try { process.kill(-child.pid, 'SIGKILL'); } catch {} }
}

async function buildRunner(args, signal) {
  signal.throwIfAborted();
  const child = spawn('/usr/bin/xcodebuild', args, { env: cleanEnvironment(), detached: true, stdio: 'ignore' });
  let succeeded = false;
  let closePromise;
  const close = () => closePromise ??= stopOwnedProcessGroup(child);
  const abort = () => { void close().catch(() => {}); };
  signal.addEventListener('abort', abort, { once: true });
  const timeout = setTimeout(abort, 100000);
  try {
    succeeded = await new Promise(resolve => {
      child.once('error', () => resolve(false));
      child.once('exit', (code, termination) => resolve(code === 0 && termination === null));
    });
  } finally {
    clearTimeout(timeout);
    signal.removeEventListener('abort', abort);
    await close();
  }
  signal.throwIfAborted();
  if (!succeeded) throw new AutomationError('wda_build_failed', 'Prepare Xcode signing for the selected iPhone, then retry.');
}

async function preparedTestRun(config, signal, onStatus) {
  const root = paths().root;
  const upstream = path.join(config.runtime_dir, 'node_modules', 'appium-xcuitest-driver', 'node_modules', 'appium-webdriveragent');
  const metadata = JSON.parse(await fs.readFile(path.join(upstream, 'package.json'), 'utf8'));
  if (!/^\d+\.\d+\.\d+$/.test(metadata.version)) throw new AutomationError('runtime_missing', 'Reinstall the pinned iPhone helper runtime.');
  const source = path.join(root, `wda-${metadata.version}`);
  const derived = path.join(root, `wda-derived-data-${metadata.version}`);
  const products = path.join(derived, 'Build', 'Products');
  const find = async () => {
    try { return (await fs.readdir(products)).filter(item => item.endsWith('.xctestrun') && !item.startsWith('private-')); }
    catch { return []; }
  };
  let files = await find();
  if (files.length !== 1) {
    signal.throwIfAborted();
    onStatus('preparing_iphone_runner');
    await ensurePrivateDirectory(source);
    await fs.cp(upstream, source, { recursive: true, force: true });
    const projectFile = path.join(source, 'WebDriverAgent.xcodeproj', 'project.pbxproj');
    const project = await fs.readFile(projectFile, 'utf8');
    await fs.writeFile(projectFile, project.replaceAll('com.facebook.WebDriverAgent', 'com.obcardinal.WindowsAppAutoLogin.WebDriverAgent'), { mode: 0o600 });
    try {
      await buildRunner(['-project', path.join(source, 'WebDriverAgent.xcodeproj'),
        '-scheme', 'WebDriverAgentRunner', '-destination', `id=${config.device_udid}`,
        '-derivedDataPath', derived, '-allowProvisioningUpdates',
        `DEVELOPMENT_TEAM=${config.development_team}`, 'CODE_SIGN_IDENTITY=Apple Development',
        'CODE_SIGN_STYLE=Automatic', 'build-for-testing'], signal);
    } catch (error) {
      if (signal.aborted) throw error;
      throw new AutomationError('wda_build_failed', 'Prepare Xcode signing for the selected iPhone, then retry.');
    }
    files = await find();
  }
  if (files.length !== 1) throw new AutomationError('wda_build_failed', 'The iPhone automation runner could not be prepared.');
  return { original: path.join(products, files[0]), privateFile: path.join(products, 'private-wifi.xctestrun') };
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
      env: cleanEnvironment(), detached: true, stdio: 'ignore',
    });
    let spawnFailed = false;
    child.once('error', () => { spawnFailed = true; });
    const deadline = Date.now() + 45000;
    for (;;) {
      signal.throwIfAborted();
      if (spawnFailed || child.exitCode !== null || child.signalCode !== null || Date.now() >= deadline) {
        throw new AutomationError('wda_connection_failed', 'Unlock the iPhone and enable UI Automation in Developer settings.');
      }
      try {
        const response = await fetch(`${url}/status`, { redirect: 'error', signal: AbortSignal.any([signal, AbortSignal.timeout(1500)]) });
        if (response.ok && (await response.json())?.value?.ready === true) break;
      } catch { signal.throwIfAborted(); }
      await delay(500, undefined, { signal });
    }
    return { url, platformVersion: device.osVersion, close };
  } catch (error) {
    await close();
    throw error;
  }
}
