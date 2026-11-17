import { execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

export const APPIUM_VERSION = '4.0.0';
export const XCUITEST_VERSION = '13.1.1';
export const AUTHENTICATOR_BUNDLE = 'com.microsoft.azureauthenticator';
export const DEVELOPMENT_TEAM = '76C2QW8JV3';
export const WDA_BUNDLE = 'com.obcardinal.WindowsAppAutoLogin.WebDriverAgentRunner';

export class AutomationError extends Error {
  constructor(code, message) { super(message); this.name = 'AutomationError'; this.code = code; }
}

export function paths() {
  const root = path.join(os.homedir(), 'Library', 'Application Support', 'WindowsAppAutoLogin', 'iphone-automation');
  return { root, config: path.join(root, 'config.json'), lock: path.join(root, 'active-session.json') };
}

export function cleanEnvironment() {
  const result = {};
  for (const key of ['PATH', 'HOME', 'TMPDIR', 'LANG', 'LC_ALL', 'DEVELOPER_DIR', 'SDKROOT']) {
    if (process.env[key]) result[key] = process.env[key];
  }
  result.PATH ??= '/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin';
  result.HOME = os.homedir();
  // APPIUM_HOME is deliberately absent: the pinned npm project owns its driver.
  return result;
}

export async function ensurePrivateDirectory(directory) {
  await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  const stat = await fs.lstat(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid()) {
    throw new AutomationError('unsafe_storage', 'The iPhone helper directory is not owned by this user.');
  }
  await fs.chmod(directory, 0o700);
}

export async function writePrivateJson(file, value) {
  const temporary = `${file}.${randomBytes(8).toString('hex')}.tmp`;
  try {
    await fs.writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
    await fs.rename(temporary, file);
  } finally { await fs.rm(temporary, { force: true }); }
}

export function validateConfig(config, root = paths().root) {
  if (config?.schema_version !== 1 || typeof config.runtime_dir !== 'string'
      || path.dirname(config.runtime_dir) !== root
      || !/^runtime-[a-f0-9]{16}$/.test(path.basename(config.runtime_dir))
      || typeof config.node_path !== 'string' || !path.isAbsolute(config.node_path)
      || config.appium_main !== path.join(config.runtime_dir, 'node_modules', 'appium', 'index.js')
      || config.development_team !== DEVELOPMENT_TEAM || config.wda_bundle_id !== WDA_BUNDLE
      || (config.device_udid !== null && !validUdid(config.device_udid))) {
    throw new AutomationError('invalid_configuration', 'Run iPhone helper setup again.');
  }
  return config;
}

export function validUdid(value) {
  return typeof value === 'string' && /^(?:[a-fA-F0-9]{40}|[a-fA-F0-9]{8}-[a-fA-F0-9]{16})$/.test(value);
}

export async function readConfig() {
  const { config, root } = paths();
  try {
    const stat = await fs.lstat(config);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== process.getuid()
        || (stat.mode & 0o077) !== 0 || stat.size > 8192) {
      throw new AutomationError('unsafe_configuration', 'The iPhone helper configuration must be private to this user.');
    }
    return validateConfig(JSON.parse(await fs.readFile(config, 'utf8')), root);
  } catch (error) {
    if (error instanceof AutomationError) throw error;
    throw new AutomationError('not_configured', 'Set up the iPhone helper before enabling it.');
  }
}

export function runQuiet(file, args, { timeout = 10000, signal, cwd, maxBuffer = 2 * 1024 * 1024, env = cleanEnvironment() } = {}) {
  return new Promise((resolve, reject) => {
    execFile(file, args, { timeout, signal, cwd, env, maxBuffer, encoding: 'utf8' }, (error, stdout) => {
      if (error) reject(new AutomationError(signal?.aborted ? 'cancelled' : 'command_failed', 'The iPhone helper command could not complete.'));
      else resolve(stdout);
    });
  });
}

export function physicalDevices(document) {
  if (!Array.isArray(document?.result?.devices)) return [];
  return document.result.devices.filter(device => {
    const h = device?.hardwareProperties;
    return h?.reality === 'physical' && h.platform === 'iOS' && h.deviceType === 'iPhone' && validUdid(h.udid);
  }).map(device => ({
    udid: device.hardwareProperties.udid,
    identifier: device.identifier,
    name: String(device.deviceProperties?.name || 'iPhone').slice(0, 80),
    connected: device.connectionProperties?.tunnelState === 'connected',
    transport: device.connectionProperties?.transportType ?? null,
    tunnelAddress: device.connectionProperties?.tunnelIPAddress ?? null,
    osVersion: device.deviceProperties?.osVersionNumber ?? null,
    paired: device.connectionProperties?.pairingState === 'paired',
    developerMode: device.deviceProperties?.developerModeStatus === 'enabled',
  }));
}

export async function listPhysicalDevices({ signal } = {}) {
  try {
    const data = await runQuiet('/usr/bin/xcrun', ['devicectl', 'list', 'devices', '--timeout', '8', '--json-output', '-'], { signal });
    return physicalDevices(JSON.parse(data));
  } catch (error) {
    if (signal?.aborted) throw error;
    throw new AutomationError('device_discovery_failed', 'Xcode could not list connected iPhones.');
  }
}

export function selectPhysicalDevice(devices, udid = null) {
  if (udid !== null && !validUdid(udid)) throw new AutomationError('invalid_device', 'The device identifier is invalid.');
  const matches = devices.filter(device => device.connected && device.paired && (udid === null || device.udid === udid));
  if (matches.length !== 1) throw new AutomationError('device_selection_required', 'Connect one trusted iPhone, or select its exact identifier explicitly.');
  if (!matches[0].developerMode) throw new AutomationError('developer_mode_required', 'Enable Developer Mode on the selected iPhone.');
  return matches[0];
}

export function pairedDeviceCandidate(devices, udid = null) {
  if (udid !== null && !validUdid(udid)) throw new AutomationError('invalid_device', 'The device identifier is invalid.');
  const matches = devices.filter(device => device.paired && (udid === null || device.udid === udid));
  if (matches.length !== 1) throw new AutomationError('device_selection_required', 'Select one previously paired iPhone by its exact identifier.');
  return matches[0];
}

export function deviceFromDetails(document, expectedUdid) {
  const device = physicalDevices({ result: { devices: [document?.result] } })[0];
  return device?.udid === expectedUdid && device.paired && device.connected ? device : null;
}

export async function probePhysicalDevice(device, { signal } = {}) {
  if (!device?.paired || !validUdid(device.udid)) return null;
  try {
    // CoreDevice's cached `disconnected` value also describes a dormant Wi-Fi
    // tunnel. A bounded read to this exact trusted device wakes that tunnel.
    // Do not discover arbitrary hosts or substitute a simulator/another phone.
    const data = await runQuiet('/usr/bin/xcrun', ['devicectl', 'device', 'info', 'details',
      '--device', device.udid, '--timeout', '8', '--json-output', '-'], { signal, timeout: 10000 });
    return deviceFromDetails(JSON.parse(data), device.udid);
  } catch (error) {
    if (signal?.aborted) throw error;
    return null;
  }
}

export function parseLockState(document) {
  const result = document?.result;
  // Treat unknown versions of Apple's response schema as unknown, never unlocked.
  if (typeof result?.isLocked === 'boolean') return result.isLocked;
  if (typeof result?.lockState?.isLocked === 'boolean') return result.lockState.isLocked;
  if (typeof result?.isScreenLocked === 'boolean') return result.isScreenLocked;
  // Observed physical iOS 27.2 CoreDevice schema. A first unlock after boot is
  // required. WDA's isLocked is checked again before any application action.
  if (result?.passcodeRequired === true) return true;
  if (result?.passcodeRequired === false && result?.unlockedSinceBoot === true) return false;
  return null;
}

export async function deviceLockState(udid, { signal } = {}) {
  try {
    const data = await runQuiet('/usr/bin/xcrun', ['devicectl', 'device', 'info', 'lockState', '--device', udid, '--timeout', '5', '--json-output', '-'], { signal, timeout: 7000 });
    return parseLockState(JSON.parse(data));
  } catch (error) {
    if (signal?.aborted) throw error;
    return null;
  }
}

export async function runtimeReady(config) {
  try {
    const appium = JSON.parse(await fs.readFile(path.join(config.runtime_dir, 'node_modules', 'appium', 'package.json'), 'utf8'));
    const xcuitest = JSON.parse(await fs.readFile(path.join(config.runtime_dir, 'node_modules', 'appium-xcuitest-driver', 'package.json'), 'utf8'));
    await fs.access(config.node_path, fs.constants.X_OK);
    await fs.access(config.appium_main);
    return appium.version === APPIUM_VERSION && xcuitest.version === XCUITEST_VERSION;
  } catch { return false; }
}

export async function status() {
  let config;
  try { config = await readConfig(); } catch (error) {
    return { configured: false, appium_ready: false, device_selected: false, code: error.code };
  }
  const result = { configured: true, appium_ready: await runtimeReady(config), device_selected: config.device_udid !== null,
    device_connected: false, device_locked: null, developer_mode: false, wda_ready: null };
  if (!config.device_udid) return result;
  let devices;
  try { devices = await listPhysicalDevices(); } catch (error) { return { ...result, code: error.code }; }
  const candidate = devices.find(item => item.udid === config.device_udid);
  const device = await probePhysicalDevice(candidate);
  if (!device) return result;
  result.device_connected = device.connected;
  result.developer_mode = device.developerMode;
  if (device.connected) result.device_locked = await deviceLockState(config.device_udid);
  // WDA is checked by a deliberate prepare-device/session operation, never by status.
  return result;
}

export async function acquireSessionLock() {
  const { root, lock } = paths();
  await ensurePrivateDirectory(root);
  const token = randomBytes(16).toString('hex');
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      await fs.writeFile(lock, JSON.stringify({ pid: process.pid, token }), { flag: 'wx', mode: 0o600 });
      return async () => {
        try { if (JSON.parse(await fs.readFile(lock, 'utf8')).token === token) await fs.unlink(lock); } catch {}
      };
    } catch (error) {
      if (error.code !== 'EEXIST') throw new AutomationError('session_lock_failed', 'The iPhone session could not be reserved.');
      try {
        const existing = JSON.parse(await fs.readFile(lock, 'utf8'));
        if (!Number.isSafeInteger(existing.pid) || existing.pid <= 0) throw new Error();
        try { process.kill(existing.pid, 0); } catch (processError) {
          if (processError.code === 'ESRCH') { await fs.unlink(lock); continue; }
        }
      } catch { /* Invalid ownership state is not safe to replace. */ }
      throw new AutomationError('session_busy', 'Another iPhone assistance session is active.');
    }
  }
  throw new AutomationError('session_busy', 'Another iPhone assistance session is active.');
}
