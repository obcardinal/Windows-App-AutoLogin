import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { LEGACY_DEVELOPMENT_TEAM, WDA_BUNDLE, writePrivateJson } from './support.mjs';
import { saveInstalledSelection, saveSetupConfig } from './selection-config.mjs';

const first = 'AAAAAAAA-0000000000000001';
const second = 'AAAAAAAA-0000000000000002';

test('setup promotes a preselected phone, keeps subsequent choices, and preserves unrelated config', { skip: process.platform !== 'darwin' }, async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'autologin-selection-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  await fs.chmod(root, 0o700);
  const runtime = path.join(root, 'runtime-0123456789abcdef');
  const installed = { schema_version: 1, runtime_dir: runtime, node_path: '/vendor/node',
    appium_main: path.join(runtime, 'node_modules', 'appium', 'index.js'), device_udid: null,
    development_team: LEGACY_DEVELOPMENT_TEAM, wda_bundle_id: WDA_BUNDLE };
  const pending = path.join(root, 'pending-device.json');
  const config = path.join(root, 'config.json');
  await writePrivateJson(pending, { schema_version: 1, device_udid: first });
  assert.equal((await saveSetupConfig(root, installed)).device_udid, first);
  await assert.rejects(fs.stat(pending), { code: 'ENOENT' });

  await writePrivateJson(config, { ...installed, device_udid: first, future_setting: 'keep' });
  // Simulates interruption after promotion and before removal of the old choice.
  await writePrivateJson(pending, { schema_version: 1, device_udid: first });
  await Promise.all([saveInstalledSelection(root, second), saveSetupConfig(root, installed)]);
  const actual = JSON.parse(await fs.readFile(config, 'utf8'));
  assert.equal(actual.device_udid, second);
  assert.equal(actual.future_setting, 'keep');
  assert.equal((await fs.stat(config)).mode & 0o777, 0o600);
  await assert.rejects(fs.stat(pending), { code: 'ENOENT' });

  await writePrivateJson(config, { ...actual, device_udid: 'invalid' });
  await assert.rejects(saveSetupConfig(root, installed));
  assert.equal(JSON.parse(await fs.readFile(config, 'utf8')).device_udid, 'invalid');
});
