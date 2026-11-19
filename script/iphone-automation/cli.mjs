#!/usr/bin/env node
import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  APPIUM_VERSION, XCUITEST_VERSION, AutomationError, acquireSessionLock, teamRunnerBundle,
  cleanEnvironment, ensurePrivateDirectory, listPhysicalDevices, pairedDeviceCandidate, paths, probePhysicalDevice, readConfig,
  runQuiet, runtimeReady, selectPhysicalDevice, status,
} from './support.mjs';
import { createIphoneSession } from './bridge.mjs';
import { readSetupPreferences, saveInstalledSelection, saveSetupConfig } from './selection-config.mjs';
import { availableSigningTeams, selectSigningTeam } from './signing.mjs';
import { prepareDeviceRunner, tunnelEndpoint } from './wda.mjs';

const source = path.dirname(fileURLToPath(import.meta.url));
const emit = value => process.stdout.write(`${JSON.stringify(value)}\n`);

async function setup(args, signal) {
  const explicit = args.length === 2 && args[0] === '--team' ? args[1] : null;
  if (args.length && explicit === null) throw new AutomationError('invalid_arguments', 'Use setup or setup --team TEAM_ID.');
  if (process.platform !== 'darwin') throw new AutomationError('macos_required', 'The iPhone helper currently requires macOS.');
  const { root } = paths();
  await ensurePrivateDirectory(root);
  const release = await acquireSessionLock();
  try {
    // Validate before installing packages. Re-read the choice when saving.
    const previous = await readSetupPreferences(root);
    const team = selectSigningTeam(await availableSigningTeams(signal), explicit, previous.development_team);
    signal.throwIfAborted();
    const packagePath = path.join(source, 'package.json');
    const lockPath = path.join(source, 'package-lock.json');
    const lock = await fs.readFile(lockPath);
    const digest = createHash('sha256').update(lock).digest('hex').slice(0, 16);
    const runtime = path.join(root, `runtime-${digest}`);
    const config = {
      schema_version: 1,
      runtime_dir: runtime,
      node_path: await fs.realpath(process.execPath),
      appium_main: path.join(runtime, 'node_modules', 'appium', 'index.js'),
      device_udid: null,
      development_team: team,
      wda_bundle_id: previous.development_team === team ? previous.wda_bundle_id : teamRunnerBundle(team),
    };
    if (!await runtimeReady(config)) {
      emit({ phase: 'installing_host_dependencies', appium_version: APPIUM_VERSION, xcuitest_version: XCUITEST_VERSION });
      await ensurePrivateDirectory(runtime);
      await fs.copyFile(packagePath, path.join(runtime, 'package.json'));
      await fs.copyFile(lockPath, path.join(runtime, 'package-lock.json'));
      await runQuiet('npm', ['ci', '--ignore-scripts', '--no-audit', '--no-fund', '--engine-strict'], {
        cwd: runtime, timeout: 600000, signal, maxBuffer: 4 * 1024 * 1024, env: cleanEnvironment(),
      });
      if (!await runtimeReady(config)) throw new AutomationError('runtime_install_failed', 'The pinned iPhone runtime could not be verified.');
    }
    const helperFiles = (await fs.readdir(source)).filter(file => file.endsWith('.mjs') && !file.endsWith('.test.mjs'));
    for (const file of [...helperFiles, 'package.json', 'package-lock.json']) {
      signal.throwIfAborted();
      const destination = path.join(root, file);
      if (path.join(source, file) !== destination) await fs.copyFile(path.join(source, file), destination);
      await fs.chmod(destination, 0o600);
    }
    const saved = await saveSetupConfig(root, config);
    emit({ phase: 'host_setup_complete', appium_version: APPIUM_VERSION, xcuitest_version: XCUITEST_VERSION,
      device_selected: saved.device_udid !== null, phone_session_started: false });
  } finally { await release(); }
}

async function selectDevice(args) {
  const explicit = args.length === 2 && args[0] === '--udid' ? args[1] : null;
  if (args.length && explicit === null) throw new AutomationError('invalid_arguments', 'Use select-device or select-device --udid IDENTIFIER.');
  await readConfig();
  const candidate = pairedDeviceCandidate(await listPhysicalDevices(), explicit);
  const available = await probePhysicalDevice(candidate);
  const selected = selectPhysicalDevice(available ? [available] : [], candidate.udid);
  await saveInstalledSelection(paths().root, selected.udid);
  emit({ phase: 'device_selected', device_name: selected.name, developer_mode: selected.developerMode });
}

async function prepareDevice(signal) {
  let session;
  try {
    const release = await acquireSessionLock();
    try {
      const config = await readConfig();
      if (!config.device_udid) throw new AutomationError('device_selection_required', 'Connect an iPhone in AutoLogin before preparing it.');
      if (!await runtimeReady(config)) throw new AutomationError('runtime_missing', 'Install the iPhone helper on this Mac before preparing the phone.');
      selectSigningTeam(await availableSigningTeams(signal), config.development_team);
      const candidate = pairedDeviceCandidate(await listPhysicalDevices({ signal }), config.device_udid);
      const available = await probePhysicalDevice(candidate, { signal });
      const selected = selectPhysicalDevice(available ? [available] : [], config.device_udid);
      tunnelEndpoint(selected, config.device_udid);
      emit({ phase: 'preparing_iphone_runner' });
      await prepareDeviceRunner(config, signal);
    } finally { await release(); }
    session = await createIphoneSession({ signal, timeoutMs: 150000, onStatus: emit });
    await session.close();
    session = null;
    emit({ phase: 'device_prepared', authenticator_launched: false, authentication_requested: false });
  } finally {
    if (session) await session.close();
  }
}

async function main() {
  const argv = process.argv.slice(2);
  const parentLifetime = argv.includes('--parent-lifetime');
  const [command = 'status', ...args] = argv.filter(arg => arg !== '--parent-lifetime');
  if (parentLifetime && !['setup', 'prepare-device'].includes(command)) throw new AutomationError('invalid_arguments', 'This command does not support a parent lifetime.');
  const controller = new AbortController();
  const stop = () => controller.abort();
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);
  if (parentLifetime) {
    process.stdin.once('end', stop);
    process.stdin.once('error', stop);
    process.stdin.resume();
  }
  try {
    if (command === 'setup') await setup(args, controller.signal);
    else if (command === 'status' && !args.length) emit(await status());
    else if (command === 'devices' && !args.length) {
      const devices = await listPhysicalDevices();
      emit({ devices: devices.map(({ name, connected, paired, developerMode }) => ({ name, connected, paired, developer_mode: developerMode })) });
    } else if (command === 'select-device') await selectDevice(args);
    else if (command === 'prepare-device' && !args.length) await prepareDevice(controller.signal);
    else throw new AutomationError('invalid_arguments', 'Use setup, status, devices, select-device, or prepare-device.');
  } finally {
    controller.abort();
    process.removeListener('SIGINT', stop);
    process.removeListener('SIGTERM', stop);
    if (parentLifetime) {
      process.stdin.removeListener('end', stop);
      process.stdin.removeListener('error', stop);
      process.stdin.destroy();
    }
  }
}

main().catch(error => {
  const cancelled = error.name === 'AbortError';
  emit({ phase: 'failed', code: cancelled ? 'cancelled' : error instanceof AutomationError ? error.code : 'helper_failed',
    message: cancelled ? 'iPhone setup cancelled.' : error instanceof AutomationError ? error.message : 'The iPhone helper could not complete the operation.' });
  process.exitCode = 1;
});
