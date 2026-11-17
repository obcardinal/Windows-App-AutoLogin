#!/usr/bin/env node
import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  APPIUM_VERSION, XCUITEST_VERSION, DEVELOPMENT_TEAM, WDA_BUNDLE, AutomationError,
  cleanEnvironment, ensurePrivateDirectory, listPhysicalDevices, pairedDeviceCandidate, paths, probePhysicalDevice, readConfig,
  runQuiet, runtimeReady, selectPhysicalDevice, status, writePrivateJson,
} from './support.mjs';
import { createIphoneSession } from './bridge.mjs';

const source = path.dirname(fileURLToPath(import.meta.url));
const emit = value => process.stdout.write(`${JSON.stringify(value)}\n`);

async function setup() {
  if (process.platform !== 'darwin') throw new AutomationError('macos_required', 'The iPhone helper currently requires macOS.');
  const { root, config: configPath } = paths();
  await ensurePrivateDirectory(root);
  const packagePath = path.join(source, 'package.json');
  const lockPath = path.join(source, 'package-lock.json');
  const lock = await fs.readFile(lockPath);
  const digest = createHash('sha256').update(lock).digest('hex').slice(0, 16);
  const runtime = path.join(root, `runtime-${digest}`);
  let previous;
  try { previous = await readConfig(); } catch (error) {
    if (error.code !== 'not_configured') throw error;
  }
  const config = {
    schema_version: 1,
    runtime_dir: runtime,
    node_path: await fs.realpath(process.execPath),
    appium_main: path.join(runtime, 'node_modules', 'appium', 'index.js'),
    device_udid: previous?.device_udid ?? null,
    development_team: DEVELOPMENT_TEAM,
    wda_bundle_id: WDA_BUNDLE,
  };
  if (!await runtimeReady(config)) {
    emit({ phase: 'installing_host_dependencies', appium_version: APPIUM_VERSION, xcuitest_version: XCUITEST_VERSION });
    await ensurePrivateDirectory(runtime);
    await fs.copyFile(packagePath, path.join(runtime, 'package.json'));
    await fs.copyFile(lockPath, path.join(runtime, 'package-lock.json'));
    await runQuiet('npm', ['ci', '--ignore-scripts', '--no-audit', '--no-fund', '--engine-strict'], {
      cwd: runtime, timeout: 600000, maxBuffer: 4 * 1024 * 1024, env: cleanEnvironment(),
    });
    if (!await runtimeReady(config)) throw new AutomationError('runtime_install_failed', 'The pinned iPhone runtime could not be verified.');
  }
  const helperFiles = (await fs.readdir(source)).filter(file => file.endsWith('.mjs') && !file.endsWith('.test.mjs'));
  for (const file of [...helperFiles, 'package.json', 'package-lock.json']) {
    const destination = path.join(root, file);
    if (path.join(source, file) !== destination) await fs.copyFile(path.join(source, file), destination);
    await fs.chmod(destination, 0o600);
  }
  await writePrivateJson(configPath, config);
  emit({ phase: 'host_setup_complete', appium_version: APPIUM_VERSION, xcuitest_version: XCUITEST_VERSION,
    device_selected: config.device_udid !== null, phone_session_started: false });
}

async function selectDevice(args) {
  const explicit = args.length === 2 && args[0] === '--udid' ? args[1] : null;
  if (args.length && explicit === null) throw new AutomationError('invalid_arguments', 'Use select-device or select-device --udid IDENTIFIER.');
  const config = await readConfig();
  const candidate = pairedDeviceCandidate(await listPhysicalDevices(), explicit);
  const available = await probePhysicalDevice(candidate);
  const selected = selectPhysicalDevice(available ? [available] : [], candidate.udid);
  config.device_udid = selected.udid;
  await writePrivateJson(paths().config, config);
  emit({ phase: 'device_selected', device_name: selected.name, developer_mode: selected.developerMode });
}

async function prepareDevice() {
  const controller = new AbortController();
  const stop = () => controller.abort();
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);
  let session;
  try {
    session = await createIphoneSession({ signal: controller.signal, timeoutMs: 150000, onStatus: emit });
    await session.close();
    session = null;
    emit({ phase: 'device_prepared', authenticator_launched: false, authentication_requested: false });
  } finally {
    if (session) await session.close();
    process.removeListener('SIGINT', stop);
    process.removeListener('SIGTERM', stop);
  }
}

async function main() {
  const [command = 'status', ...args] = process.argv.slice(2);
  if (command === 'setup' && !args.length) await setup();
  else if (command === 'status' && !args.length) emit(await status());
  else if (command === 'devices' && !args.length) {
    const devices = await listPhysicalDevices();
    emit({ devices: devices.map(({ name, connected, paired, developerMode }) => ({ name, connected, paired, developer_mode: developerMode })) });
  } else if (command === 'select-device') await selectDevice(args);
  else if (command === 'prepare-device' && !args.length) await prepareDevice();
  else throw new AutomationError('invalid_arguments', 'Use setup, status, devices, select-device, or prepare-device.');
}

main().catch(error => {
  emit({ phase: 'failed', code: error instanceof AutomationError ? error.code : 'helper_failed',
    message: error instanceof AutomationError ? error.message : 'The iPhone helper could not complete the operation.' });
  process.exitCode = 1;
});
