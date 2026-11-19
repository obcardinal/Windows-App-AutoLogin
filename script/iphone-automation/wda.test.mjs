import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import timers from 'node:timers/promises';
import * as support from './support.mjs';
import { configureTestRun, dedicatedRunnerExecutable, dedicatedRunnerPids, tunnelEndpoint, profileApplicationMatches } from './wda.mjs';

const udid = '00000000-0000000000000001';
const device = { udid, paired: true, connected: true, transport: 'localNetwork', tunnelAddress: 'fd00::1', osVersion: '27.2' };

test('only the remainder of the polling interval is spent asleep after a readiness probe', async t => {
  let now = 0;
  const sleeps = [];
  const starts = [];
  t.mock.method(performance, 'now', () => now);
  t.mock.module('node:timers/promises', { namedExports: { setTimeout: async ms => { sleeps.push(ms); now += ms; } } });
  const { waitForRunnerReady } = await import('./wda.mjs?readiness-cadence');
  const child = Object.assign(new EventEmitter(), { exitCode: null, signalCode: null });
  t.mock.method(globalThis, 'fetch', async (url, options) => {
    assert.equal(url, 'http://[::1]:8100/status');
    assert.equal(options.redirect, 'error');
    starts.push(now);
    if (starts.length === 1) { now += 100; throw new Error('unavailable'); }
    if (starts.length === 2) { now += 800; return Response.json({ value: { ready: false } }); }
    return Response.json({ value: { ready: true } });
  });
  await waitForRunnerReady('http://[::1]:8100', child, new AbortController().signal);
  assert.deepEqual(starts, [0, 500, 1300]);
  assert.deepEqual(sleeps, [400]);
});

for (const duringFetch of [false, true]) {
  const scenario = duringFetch ? 'during a status request' : 'during the polling interval';
  test(`an XCTest server marker ${scenario} wakes one sequential status probe`, async t => {
    t.mock.timers.enable({ apis: ['Date', 'setTimeout'], now: 0 });
    t.mock.method(performance, 'now', () => Date.now());
    t.mock.module('node:timers/promises', { namedExports: { setTimeout: timers.setTimeout } });
    const { waitForRunnerReady } = await import(`./wda.mjs?marker-during-fetch=${duringFetch}`);
    const child = Object.assign(new EventEmitter(), {
      exitCode: null, signalCode: null, stdout: new PassThrough(), stderr: new PassThrough(),
    });
    const output = duringFetch ? child.stderr : child.stdout;
    const otherOutput = duringFetch ? child.stdout : child.stderr;
    const firstReply = Promise.withResolvers();
    const starts = [];
    t.mock.method(globalThis, 'fetch', async (url, options) => {
      assert.equal(url, 'http://[::1]:8100/status');
      assert.equal(options.redirect, 'error');
      starts.push(performance.now());
      if (duringFetch && starts.length === 1) await firstReply.promise;
      return Response.json({ value: { ready: starts.length === 3 } });
    });
    const controller = new AbortController();
    const ready = waitForRunnerReady('http://[::1]:8100', child, controller.signal);
    t.after(async () => {
      firstReply.resolve();
      controller.abort();
      await ready.catch(() => {});
      child.stdout.destroy();
      child.stderr.destroy();
    });

    await timers.setImmediate();
    output.write(Buffer.from('ServerURL'));
    otherOutput.write(Buffer.from('Here->'));
    await timers.setImmediate();
    assert.deepEqual(starts, [0]);
    output.write(Buffer.from('Here->'));
    await timers.setImmediate();
    if (duringFetch) {
      assert.deepEqual(starts, [0]);
      firstReply.resolve();
      await timers.setImmediate();
    }
    assert.deepEqual(starts, [0, 0]);
    otherOutput.write(Buffer.from('ServerURLHere->'));
    await timers.setImmediate();
    t.mock.timers.tick(499);
    await timers.setImmediate();
    assert.deepEqual(starts, [0, 0]);
    t.mock.timers.tick(1);
    await timers.setImmediate();
    assert.deepEqual(starts, [0, 0, 500]);
    await ready;
  });
}

test('a ready reply is rejected if the runner exited, the deadline expired, or the caller cancelled', async t => {
  const { waitForRunnerReady } = await import('./wda.mjs');
  let now = 0;
  t.mock.method(performance, 'now', () => now);
  for (const cause of ['exit', 'deadline', 'abort']) {
    const child = Object.assign(new EventEmitter(), { exitCode: null, signalCode: null, stdout: new PassThrough() });
    const controller = new AbortController();
    const fetch = t.mock.method(globalThis, 'fetch', async () => {
      child.stdout.write(Buffer.from('ServerURLHere->'));
      if (cause === 'exit') child.exitCode = 1;
      if (cause === 'deadline') now += 45000;
      if (cause === 'abort') controller.abort();
      return Response.json({ value: { ready: true } });
    });
    await assert.rejects(waitForRunnerReady('http://[::1]:8100', child, controller.signal),
      cause === 'abort' ? { name: 'AbortError' } : { code: 'wda_connection_failed' });
    fetch.mock.restore();
  }
});

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
  assert.equal(value.WebDriverAgentRunner.UserAttachmentLifetime, 'keepNever');
  assert.equal(value.WebDriverAgentRunner.SystemAttachmentLifetime, 'keepNever');
  assert.throws(() => configureTestRun(original, '0.0.0.0'), { code: 'wda_build_failed' });
});

for (const groupExitAt of [75, Infinity]) {
  const graceful = Number.isFinite(groupExitAt);
  test(graceful ? 'cleanup returns promptly when the owned group exits on TERM'
    : 'cleanup gives surviving descendants the full grace period after their leader exits', async t => {
    let now = 0;
    const signals = [];
    t.mock.method(performance, 'now', () => now);
    t.mock.module('node:timers/promises', { namedExports: { setTimeout: async ms => { now += ms; } } });
    t.mock.method(process, 'kill', (pid, signal) => {
      assert.equal(pid, -99999999);
      if (now >= groupExitAt) throw Object.assign(new Error('missing'), { code: 'ESRCH' });
      if (signal !== 0) signals.push([signal, now]);
    });
    const { stopOwnedProcessGroup } = await import(`./wda.mjs?cleanup=${groupExitAt}`);
    await stopOwnedProcessGroup({ pid: 99999999, exitCode: 1, signalCode: null });
    if (graceful) {
      assert.deepEqual(signals, [['SIGTERM', 0]]);
      assert.ok(now >= groupExitAt && now <= groupExitAt + 50);
    } else {
      assert.deepEqual(signals, [['SIGTERM', 0], ['SIGKILL', 1200]]);
    }
  });
}

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

const manifestName = 'WebDriverAgentRunner_iphoneos-arm64.xctestrun';

async function writeProducts(products) {
  const app = path.join(products, 'Debug-iphoneos', 'WebDriverAgentRunner-Runner.app');
  const plugin = path.join(app, 'PlugIns', 'WebDriverAgentRunner.xctest');
  await fs.mkdir(plugin, { recursive: true });
  await fs.writeFile(path.join(app, 'WebDriverAgentRunner-Runner'), 'fixture', { mode: 0o700 });
  await fs.writeFile(path.join(plugin, 'WebDriverAgentRunner'), 'fixture', { mode: 0o700 });
  await fs.writeFile(path.join(products, manifestName), 'fixture');
}

async function buildFixture(t) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'waal-wda-test-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const config = { runtime_dir: path.join(root, 'runtime'), development_team: 'TESTTEAM01', wda_bundle_id: support.teamRunnerBundle('TESTTEAM01'), device_udid: udid };
  const upstream = path.join(config.runtime_dir, 'node_modules/appium-xcuitest-driver/node_modules/appium-webdriveragent');
  await fs.mkdir(path.join(upstream, 'WebDriverAgent.xcodeproj'), { recursive: true });
  await fs.writeFile(path.join(upstream, 'package.json'), '{"version":"1.2.3"}');
  await fs.writeFile(path.join(upstream, 'WebDriverAgent.xcodeproj/project.pbxproj'), 'com.facebook.WebDriverAgentRunner');
  const fixture = { builds: [], readManifests: [], profileDevices: [udid], profileExpiry: '2099-01-01T00:00:00Z', build: async (_args, products) => {
    await writeProducts(products);
    return 0;
  } };
  t.mock.module('node:child_process', { namedExports: { spawn(file, args, options) {
    assert.equal(file, '/usr/bin/xcodebuild');
    assert.equal(options.detached, !args.includes('generic/platform=iOS'));
    assert.equal(args.at(-1), 'build-for-testing');
    const child = new EventEmitter();
    Object.assign(child, { pid: 99999998, exitCode: null, signalCode: null,
      kill: signal => { fixture.onChildSignal?.(signal); return true; } });
    fixture.builds.push(args);
    const products = path.join(args[args.indexOf('-derivedDataPath') + 1], 'Build/Products');
    Promise.resolve().then(() => fixture.build(args, products)).then(
      code => { child.exitCode = code; child.emit('exit', code, null); }, cause => child.emit('error', cause));
    return child;
  } } });
  t.mock.method(process, 'kill', (_pid, _signal) => { throw Object.assign(new Error(), { code: 'ESRCH' }); });
  // Stop foreground requests at their first plist read, before XCTest or device access.
  t.mock.module('./support.mjs', { namedExports: { ...support, runQuiet: async (file, args) => {
    if (file === '/usr/bin/security') { assert.deepEqual(args.slice(0, 3), ['cms', '-D', '-i']); return ''; }
    if (file === '/usr/bin/codesign') return `Identifier=${config.wda_bundle_id}.xctrunner\nTeamIdentifier=${config.development_team}\n`;
    assert.equal(file, '/usr/bin/plutil');
    if (args[0] === '-extract') {
      if (args[1] === 'ProvisionedDevices') return JSON.stringify(fixture.profileDevices);
      if (args[1] === 'TeamIdentifier') return JSON.stringify([fixture.profileTeam ?? config.development_team]);
      if (args[1] === 'ApplicationIdentifierPrefix') return JSON.stringify([config.development_team]);
      if (args[1] === 'Entitlements.application-identifier') return fixture.profileBundle ?? `${config.development_team}.${config.wda_bundle_id}.xctrunner`;
      return fixture.profileExpiry;
    }
    fixture.readManifests.push(args.at(-1));
    throw new Error('fixture plist');
  } } });
  const api = await import(`./wda.mjs?fixture=${path.basename(root)}`);
  const signing = createHash('sha256').update(`${config.development_team}\n${config.wda_bundle_id}`).digest('hex').slice(0, 16);
  const host = path.join(root, `wda-host-products-1.2.3-${signing}`);
  const existing = path.join(root, `wda-derived-data-1.2.3-${signing}/Build/Products`);
  return Object.assign(fixture, { ...api, config, host, existing, root });
}

test('host preparation reuses existing signed products and requires no selected phone', async t => {
  const f = await buildFixture(t);
  await writeProducts(f.existing);
  const hostConfig = { ...f.config, get device_udid() { throw new Error('host preparation used phone selection'); } };
  await f.prepareHostRunner(hostConfig, new AbortController().signal);
  assert.deepEqual(f.builds, []);
  assert.deepEqual(f.readManifests, []);
});

test('Apple development wildcard profiles match only their own bundle prefix', () => {
  const application = 'PERSONAL01.com.obcardinal.WindowsAppAutoLogin.PERSONAL01.WebDriverAgentRunner.xctrunner';
  assert.equal(profileApplicationMatches(application, application), true);
  assert.equal(profileApplicationMatches('PERSONAL01.*', application), true);
  assert.equal(profileApplicationMatches('PERSONAL01.com.obcardinal.*', application), true);
  for (const pattern of ['OTHERTEAM1.*', 'PERSONAL01.com.other.*', '*', 'PERSONAL01.*.xctrunner', 'PERSONAL01..*']) {
    assert.equal(profileApplicationMatches(pattern, application), false);
  }
});

test('host build uses local signing and publishes complete products for foreground reuse', async t => {
  const f = await buildFixture(t);
  const signal = new AbortController().signal;
  const hostConfig = { ...f.config, get device_udid() { throw new Error('host preparation used phone selection'); } };
  await f.prepareHostRunner(hostConfig, signal);
  await f.prepareHostRunner(hostConfig, signal);
  const [args] = f.builds;
  assert.equal(args[args.indexOf('-destination') + 1], 'generic/platform=iOS');
  assert.ok(args.includes('DEVELOPMENT_TEAM=TESTTEAM01'));
  assert.ok(args.includes('CODE_SIGN_IDENTITY=Apple Development'));
  assert.ok(!args.includes('-allowProvisioningUpdates'));
  assert.ok(!args.includes('-allowProvisioningDeviceRegistration'));
  assert.ok(!args.some(arg => arg.includes(udid)));
  await assert.rejects(f.startNativeWda(f.config, device, { signal }), /fixture plist/);
  assert.equal(f.builds.length, 1);
  assert.deepEqual(f.readManifests, [path.join(f.host, manifestName)]);
  assert.ok(!(await fs.readdir(f.root)).some(item => item.startsWith('wda-host-build-')));
});

test('generic signing for another device or an expired profile falls back to the targeted build', async t => {
  const f = await buildFixture(t);
  const signal = new AbortController().signal;
  await f.prepareHostRunner(f.config, signal);
  f.profileDevices = ['different-device'];
  await assert.rejects(f.startNativeWda(f.config, device, { signal }), /fixture plist/);
  await fs.rm(f.existing, { recursive: true });
  f.profileDevices = [udid];
  f.profileExpiry = '2000-01-01T00:00:00Z';
  await assert.rejects(f.startNativeWda(f.config, device, { signal }), /fixture plist/);
  assert.equal(f.builds.length, 3);
  assert.deepEqual(f.readManifests, [path.join(f.existing, manifestName), path.join(f.existing, manifestName)]);
});

test('foreground fallback never consumes an unfinished optional build or waits for it', async t => {
  const f = await buildFixture(t);
  const staged = Promise.withResolvers();
  const release = Promise.withResolvers();
  const signal = new AbortController().signal;
  f.build = async (args, products) => {
    await writeProducts(products);
    if (!args.includes('generic/platform=iOS')) return 0;
    staged.resolve();
    await release.promise;
    return 1;
  };
  const background = f.prepareHostRunner(f.config, signal);
  try {
    await staged.promise;
    await assert.rejects(fs.stat(f.host), { code: 'ENOENT' });
    await assert.rejects(f.startNativeWda(f.config, device, { signal }), /fixture plist/);
    assert.deepEqual(f.readManifests, [path.join(f.existing, manifestName)]);
    assert.ok(f.builds[1].includes(`id=${udid}`));
    assert.ok(f.builds[1].includes('-allowProvisioningUpdates'));
  } finally {
    release.resolve();
    await assert.rejects(background, { code: 'wda_build_failed' });
  }
  assert.ok(!(await fs.readdir(f.root)).some(item => item.startsWith('wda-host-build-')));
});

test('device registration happens during explicit preparation and signing caches follow the selected team', async t => {
  const f = await buildFixture(t);
  const signal = new AbortController().signal;
  await f.prepareDeviceRunner(f.config, signal);
  const first = f.builds[0];
  assert.ok(first.includes('-allowProvisioningDeviceRegistration'));
  assert.ok(first.includes('-allowProvisioningUpdates'));
  const other = { ...f.config, development_team: 'PERSONAL01', wda_bundle_id: support.teamRunnerBundle('PERSONAL01') };
  await f.prepareDeviceRunner(other, signal);
  const second = f.builds[1];
  assert.ok(second.includes('DEVELOPMENT_TEAM=PERSONAL01'));
  assert.notEqual(first[first.indexOf('-derivedDataPath') + 1], second[second.indexOf('-derivedDataPath') + 1]);
  const project = await fs.readFile(path.join(second[second.indexOf('-project') + 1], 'project.pbxproj'), 'utf8');
  assert.equal(project, other.wda_bundle_id);
});

test('expired targeted profiles and profiles for another signing team are rebuilt', async t => {
  const f = await buildFixture(t);
  const signal = new AbortController().signal;
  await writeProducts(f.existing);
  f.profileExpiry = '2000-01-01T00:00:00Z';
  await assert.rejects(f.startNativeWda(f.config, device, { signal }), /fixture plist/);
  f.profileExpiry = '2099-01-01T00:00:00Z';
  f.profileTeam = 'OTHERTEAM1';
  await assert.rejects(f.startNativeWda(f.config, device, { signal }), /fixture plist/);
  assert.equal(f.builds.length, 2);
  assert.ok(f.builds.every(args => !args.includes('-allowProvisioningDeviceRegistration')));
});

test('aborted preparation stops the compiler in the supervisor group and discards staging products', async t => {
  const f = await buildFixture(t);
  const staged = Promise.withResolvers();
  const terminated = Promise.withResolvers();
  const controller = new AbortController();
  const signals = [];
  t.mock.method(process, 'kill', () => { assert.fail('host build attempted to signal a separate process group'); });
  f.onChildSignal = signal => { signals.push(signal); terminated.resolve(); };
  f.build = async (_args, products) => {
    await writeProducts(products);
    staged.resolve();
    await terminated.promise;
    return 0;
  };
  const prepared = f.prepareHostRunner(f.config, controller.signal);
  await staged.promise;
  controller.abort();
  await assert.rejects(prepared, { name: 'AbortError' });
  assert.deepEqual(signals, ['SIGTERM']);
  assert.deepEqual((await fs.readdir(f.root)).sort(), ['runtime']);
});
