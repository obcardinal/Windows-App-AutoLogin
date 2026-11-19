import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import { physicalDevices, selectPhysicalDevice, pairedDeviceCandidate, deviceFromDetails, parseLockState, validateConfig, teamRunnerBundle } from './support.mjs';

const udid = '00000000-0000000000000001';
const device = (reality, connected = true) => ({
  identifier: 'core-device-id',
  hardwareProperties: { reality, platform: 'iOS', deviceType: 'iPhone', udid },
  deviceProperties: { name: 'Test iPhone', developerModeStatus: 'enabled' },
  connectionProperties: { tunnelState: connected ? 'connected' : 'disconnected', pairingState: 'paired' },
});

test('selection never substitutes a simulator or disconnected phone', () => {
  const devices = physicalDevices({ result: { devices: [device('simulated'), device('physical', false)] } });
  assert.equal(devices.length, 1);
  assert.throws(() => selectPhysicalDevice(devices), { code: 'device_selection_required' });
});

test('selection requires one trusted physical phone or an exact identifier', () => {
  const devices = physicalDevices({ result: { devices: [device('physical'), device('physical')] } });
  devices[1].udid = '00000000-0000000000000002';
  assert.throws(() => selectPhysicalDevice(devices), { code: 'device_selection_required' });
  assert.equal(selectPhysicalDevice(devices, udid).udid, udid);
  assert.throws(() => selectPhysicalDevice(devices, '00000000-0000000000000003'), { code: 'device_selection_required' });
  devices[0].paired = false;
  assert.throws(() => selectPhysicalDevice(devices, udid), { code: 'device_selection_required' });
});

test('a dormant Wi-Fi tunnel is probed only for an unambiguous paired physical phone', () => {
  const candidates = physicalDevices({ result: { devices: [device('physical', false), device('simulated')] } });
  assert.equal(pairedDeviceCandidate(candidates).udid, udid);
  assert.equal(candidates[0].connected, false);
  assert.throws(() => pairedDeviceCandidate([...candidates, { ...candidates[0], udid: '00000000-0000000000000002' }]), { code: 'device_selection_required' });
  assert.equal(deviceFromDetails({ result: device('physical') }, udid)?.connected, true);
  assert.equal(deviceFromDetails({ result: device('simulated') }, udid), null);
  assert.equal(deviceFromDetails({ result: device('physical') }, '00000000-0000000000000002'), null);
});

test('unknown or failed lock responses never authorize an unlocked session', () => {
  for (const value of [{}, { result: {} }, { result: { isLocked: 'false' } }, { result: { isLocked: 0 } }]) {
    assert.equal(parseLockState(value), null);
  }
  assert.equal(parseLockState({ result: { isLocked: false } }), false);
  assert.equal(parseLockState({ result: { isLocked: true } }), true);
  assert.equal(parseLockState({ result: { passcodeRequired: false, unlockedSinceBoot: true } }), false);
  assert.equal(parseLockState({ result: { passcodeRequired: true, unlockedSinceBoot: true } }), true);
  assert.equal(parseLockState({ result: { passcodeRequired: false, unlockedSinceBoot: false } }), null);
});

test('Wi-Fi preparation reads only the selected paired phone, skips active sessions, and retains no device state', async t => {
  const phone = device('physical', false);
  let devices = [phone];
  let sessionActive = false;
  let details = 0;
  t.mock.method(fs, 'lstat', async () => {
    if (sessionActive) return {};
    throw Object.assign(new Error(), { code: 'ENOENT' });
  });
  t.mock.module('node:child_process', { namedExports: { execFile(file, args, options, callback) {
    assert.equal(file, '/usr/bin/xcrun');
    assert.equal(options.signal.aborted, false);
    if (args[1] === 'list') return callback(null, JSON.stringify({ result: { devices } }));
    assert.deepEqual(args.slice(0, 6), ['devicectl', 'device', 'info', 'details', '--device', udid]);
    details++;
    callback(null, JSON.stringify({ result: phone }));
  } } });
  const { warmSelectedWifi } = await import('./support.mjs?warm-wifi');
  const signal = new AbortController().signal;
  const warm = () => warmSelectedWifi(udid, signal);
  phone.connectionProperties.transportType = 'wired';
  await warm();
  phone.connectionProperties.transportType = 'localNetwork';
  phone.connectionProperties.pairingState = 'unpaired';
  await warm();
  phone.connectionProperties.pairingState = 'paired';
  devices = [phone, phone];
  await warm();
  devices = [phone];
  sessionActive = true;
  await warm();
  assert.equal(details, 0);
  sessionActive = false;
  assert.equal(await warm(), undefined);
  assert.equal(details, 1);
});

test('private configuration cannot redirect Appium outside its pinned runtime', () => {
  const root = '/private/test-support';
  const config = {
    schema_version: 1, runtime_dir: `${root}/runtime-0123456789abcdef`, node_path: '/usr/local/bin/node',
    appium_main: `${root}/runtime-0123456789abcdef/node_modules/appium/index.js`, device_udid: udid,
    development_team: '76C2QW8JV3', wda_bundle_id: 'com.obcardinal.WindowsAppAutoLogin.WebDriverAgentRunner',
  };
  assert.equal(validateConfig(config, root), config);
  const personal = { ...config, development_team: 'PERSONAL01', wda_bundle_id: teamRunnerBundle('PERSONAL01') };
  assert.equal(validateConfig(personal, root), personal);
  for (const changes of [{ appium_main: '/tmp/appium.js' }, { device_udid: 'auto' },
    { runtime_dir: `${root}/../arbitrary` }, { development_team: 'UNTRUSTED' },
    { development_team: 'PERSONAL01' }, { wda_bundle_id: teamRunnerBundle('PERSONAL01') },
    { development_team: '../TEAM001', wda_bundle_id: 'other.app' }]) {
    assert.throws(() => validateConfig({ ...config, ...changes }, root), { code: 'invalid_configuration' });
  }
});
