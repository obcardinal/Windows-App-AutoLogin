import test, { mock } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { AutomationError } from './support.mjs';
import { stopOwnedProcessGroup } from './wda.mjs';

const udid = '00000000-0000000000000001';
let state;
const config = { device_udid: udid, development_team: '76C2QW8JV3', wda_bundle_id: 'test.wda',
  node_path: '/test/node', appium_main: '/test/appium/index.js', runtime_dir: '/test/runtime' };

mock.module('./support.mjs', { namedExports: {
  AUTHENTICATOR_BUNDLE: 'com.microsoft.azureauthenticator', AutomationError,
  acquireSessionLock: async () => { state.acquired++; return async () => { state.released++; }; },
  cleanEnvironment: () => ({}), deviceLockState: async () => false,
  listPhysicalDevices: async () => [{ udid, paired: true, connected: true, developerMode: true }],
  probePhysicalDevice: async device => device,
  readConfig: async () => config, runtimeReady: async () => true,
} });
mock.module('./wda.mjs', { namedExports: {
  stopOwnedProcessGroup,
  startNativeWda: async () => ({ url: 'http://[fd00::1]:8100', platformVersion: '27.2',
    close: async () => { state.wdaStopped++; if (state.wdaFailure) throw state.wdaFailure; } }),
} });
mock.module('node:net', { defaultExport: { createServer() {
  const server = new EventEmitter();
  server.listen = (_port, _address, callback) => queueMicrotask(callback);
  server.address = () => ({ port: 41234 + state.ports++ });
  server.close = callback => { state.onPortClose?.(); queueMicrotask(callback); };
  return server;
} } });
mock.module('node:child_process', { namedExports: { spawn(_file, args, options) {
  state.spawned++;
  assert.ok(args.includes('127.0.0.1'));
  assert.equal(options.stdio, 'ignore');
  const child = new EventEmitter();
  Object.assign(child, { pid: 99999999, exitCode: null, signalCode: null });
  state.child = child;
  return child;
} } });
const { createIphoneSession, sessionCapabilities, validateSessionPath } = await import('./bridge.mjs');

function initialize(t) {
  state = { acquired: 0, released: 0, spawned: 0, stopped: 0, wdaStopped: 0, deleted: 0, ports: 0 };
  t.mock.method(process, 'kill', (pid, signal) => {
    assert.equal(pid, -99999999);
    if (signal === 0) {
      if (state.groupStopped) throw Object.assign(new Error('missing'), { code: 'ESRCH' });
      return true;
    }
    state.stopped++;
    state.groupStopped = true;
    state.child.signalCode = signal;
    queueMicrotask(() => state.child.emit('exit', null, signal));
    return true;
  });
  t.mock.method(globalThis, 'fetch', async (url, options) => {
    if (state.fetch) return state.fetch(url, options);
    if (url.endsWith('/status')) return Response.json({ value: { ready: true } });
    if (url.endsWith('/session') && options.method === 'POST') return Response.json({ value: { sessionId: 'test-session' } });
    if (options.method === 'DELETE') { state.deleted++; return Response.json({ value: null }); }
    if (url.endsWith('/execute/sync')) return Response.json({ value: false });
    return Response.json({ value: { error: 'unknown error', message: 'sensitive-code-42' } }, { status: 500 });
  });
}

test('abort while reserving ports never starts an orphan server or leaks ownership', async t => {
  initialize(t);
  const controller = new AbortController();
  state.onPortClose = () => controller.abort();
  await assert.rejects(createIphoneSession({ signal: controller.signal }), { code: 'cancelled' });
  assert.equal(state.spawned, 0);
  assert.equal(state.acquired, 1);
  assert.equal(state.released, 1);
  assert.equal(state.wdaStopped, 1);
});

test('abort during session creation stops the owned server and releases its lock', async t => {
  initialize(t);
  const controller = new AbortController();
  state.fetch = async (url, options) => {
    if (url.endsWith('/status')) return Response.json({ value: { ready: true } });
    assert.ok(url.endsWith('/session'));
    return new Promise((_resolve, reject) => {
      options.signal.addEventListener('abort', () => reject(new Error('private request body')), { once: true });
      queueMicrotask(() => controller.abort());
    });
  };
  await assert.rejects(createIphoneSession({ signal: controller.signal }), { code: 'cancelled' });
  assert.equal(state.spawned, 1);
  assert.equal(state.stopped, 1);
  assert.equal(state.released, 1);
  assert.equal(state.wdaStopped, 1);
});

test('abort after handoff deletes the session and closes once, including repeated close', async t => {
  initialize(t);
  const controller = new AbortController();
  const session = await createIphoneSession({ signal: controller.signal });
  controller.abort();
  await session.close();
  await session.close();
  assert.equal(state.deleted, 1);
  assert.equal(state.stopped, 1);
  assert.equal(state.released, 1);
  assert.equal(state.wdaStopped, 1);
});

test('server failures do not expose page content or entered values', async t => {
  initialize(t);
  const session = await createIphoneSession();
  await assert.rejects(session.request('POST', '/element/test/value', { text: '42' }), error => {
    assert.equal(error.code, 'device_command_failed');
    assert.ok(!error.message.includes('42'));
    assert.ok(!error.message.includes('sensitive'));
    return true;
  });
  await session.close();
});

test('unverified phone cleanup releases host ownership and returns its safe error', async t => {
  initialize(t);
  const session = await createIphoneSession();
  state.wdaFailure = new AutomationError('wda_cleanup_unverified', 'Reconnect the selected iPhone to finish stopping its test runner.');
  await assert.rejects(session.close(), { code: 'wda_cleanup_unverified' });
  assert.equal(state.stopped, 1);
  assert.equal(state.wdaStopped, 1);
  assert.equal(state.released, 1);
});

test('abort cleanup failure is handled immediately and remains visible to the owner', async t => {
  initialize(t);
  const controller = new AbortController();
  const session = await createIphoneSession({ signal: controller.signal });
  state.wdaFailure = new AutomationError('wda_cleanup_unverified', 'Reconnect the selected iPhone to finish stopping its test runner.');
  controller.abort();
  // Let the fire-and-forget abort listener finish before the owner awaits close.
  // An unhandled rejection here fails node:test instead of disappearing.
  await new Promise(resolve => setImmediate(resolve));
  await assert.rejects(session.close(), { code: 'wda_cleanup_unverified' });
  assert.equal(state.wdaStopped, 1);
  assert.equal(state.released, 1);
});

test('capabilities preserve app data, manual biometric/alert control and private diagnostics', () => {
  const caps = sessionCapabilities(config, 41235, { url: 'http://[fd00::1]:8100', platformVersion: '27.2' });
  assert.equal(caps['appium:udid'], udid);
  assert.equal(caps['appium:noReset'], true);
  for (const key of ['fullReset', 'autoLaunch', 'forceAppLaunch', 'shouldTerminateApp', 'autoAcceptAlerts',
    'autoDismissAlerts', 'showXcodeLog', 'showIOSLog', 'printPageSourceOnFindFailure']) {
    assert.equal(caps[`appium:${key}`], false);
  }
  assert.equal(caps['appium:disableAutomaticScreenshots'], true);
  assert.ok(!Object.hasOwn(caps, 'appium:app'));
  assert.ok(!Object.hasOwn(caps, 'appium:bundleId'));
  assert.equal(caps['appium:webDriverAgentUrl'], 'http://[fd00::1]:8100');
  assert.equal(caps['appium:platformVersion'], '27.2');
});

test('session request paths cannot escape the owned session', () => {
  for (const path of ['../session', '/../../session', '//status', '/status?x=1', '/status#x', '/%2e%2e']) {
    assert.throws(() => validateSessionPath(path), { code: 'invalid_request' });
  }
  assert.equal(validateSessionPath('/element/test-id/attribute/value'), '/element/test-id/attribute/value');
});
