import test from 'node:test';
import assert from 'node:assert/strict';
import { configureTestRun, dedicatedRunnerExecutable, dedicatedRunnerPids, stopOwnedProcessGroup, tunnelEndpoint } from './wda.mjs';

const udid = '00000000-0000000000000001';
const device = { udid, paired: true, connected: true, transport: 'localNetwork', tunnelAddress: 'fd00::1', osVersion: '27.2' };

test('Wi-Fi WDA attachment uses only the exact paired physical-device tunnel', () => {
  assert.equal(tunnelEndpoint(device, udid), 'http://[fd00::1]:8100');
  for (const delta of [{ udid: 'other' }, { paired: false }, { connected: false }, { transport: 'usb' },
    { tunnelAddress: '192.168.1.4' }, { tunnelAddress: 'example.com' }, { osVersion: '' }]) {
    assert.throws(() => tunnelEndpoint({ ...device, ...delta }, udid), { code: 'wifi_device_required' });
  }
});

test('WDA test launch binds only the tunnel address and deletes diagnostic attachments', () => {
  const original = { WebDriverAgentRunner: { EnvironmentVariables: { KEEP: 'unchanged', USE_IP: '' } } };
  const value = configureTestRun(original, device.tunnelAddress);
  assert.equal(original.WebDriverAgentRunner.EnvironmentVariables.USE_IP, '');
  assert.deepEqual(value.WebDriverAgentRunner.EnvironmentVariables, {
    KEEP: 'unchanged', USE_IP: 'fd00::1', USE_PORT: '8100', MJPEG_SERVER_PORT: '0',
  });
  assert.equal(value.WebDriverAgentRunner.UserAttachmentLifetime, 'deleteAlways');
  assert.equal(value.WebDriverAgentRunner.SystemAttachmentLifetime, 'deleteAlways');
  assert.throws(() => configureTestRun(original, '0.0.0.0'), { code: 'wda_build_failed' });
});

test('cleanup still stops descendants after the owned group leader already exited', async t => {
  const signals = [];
  let alive = true;
  t.mock.method(process, 'kill', (pid, signal) => {
    assert.equal(pid, -99999999);
    if (!alive) throw Object.assign(new Error('missing'), { code: 'ESRCH' });
    if (signal !== 0) signals.push(signal);
    if (signal === 'SIGKILL') alive = false;
  });
  await stopOwnedProcessGroup({ pid: 99999999, exitCode: 1, signalCode: null });
  assert.deepEqual(signals, ['SIGTERM', 'SIGKILL']);
});

test('phone cleanup selects only this app dedicated signed WDA executable', () => {
  const bundle = 'com.obcardinal.WindowsAppAutoLogin.WebDriverAgentRunner';
  const url = 'file:///private/var/containers/Bundle/Application/ABC-123/WebDriverAgentRunner-Runner.app/';
  const app = { bundleIdentifier: `${bundle}.xctrunner`, builtByDeveloper: true, url };
  const executable = dedicatedRunnerExecutable({ result: { apps: [app, { ...app, bundleIdentifier: 'other.wda.xctrunner' }] } }, bundle);
  assert.equal(executable, `${url}WebDriverAgentRunner-Runner`);
  const pids = dedicatedRunnerPids({ result: { runningProcesses: [
    { executable, processIdentifier: 123 },
    { executable: executable.replace('ABC-123', 'DEF-456'), processIdentifier: 456 },
    { executable, processIdentifier: '123' },
  ] } }, executable);
  assert.deepEqual(pids, [123]);
  assert.equal(dedicatedRunnerExecutable({ result: { apps: [{ ...app, bundleIdentifier: 'other.wda.xctrunner' }] } }, bundle), null);
  assert.throws(() => dedicatedRunnerExecutable({ result: { apps: [app, app] } }, bundle), { code: 'wda_cleanup_unverified' });
  assert.throws(() => dedicatedRunnerExecutable({ result: { apps: [{ ...app, url: 'file:///another/app/' }] } }, bundle), { code: 'wda_cleanup_unverified' });
  assert.throws(() => dedicatedRunnerPids({}, executable), { code: 'wda_cleanup_unverified' });
});
