// The account editor and this setup tool share a BSD flock only while changing
// host preferences. No device operation runs under the lock.
import { spawn } from 'node:child_process';
import { constants } from 'node:fs';
import fs from 'node:fs/promises';
import path from 'node:path';
import { AutomationError, validateConfig, validUdid, writePrivateJson } from './support.mjs';

const unsafeFile = () => new AutomationError('unsafe_configuration', 'The iPhone preferences could not be read safely.');
const busy = () => new AutomationError('selection_busy', 'The iPhone selection is being saved. Try again.');

async function readJson(root, filename) {
  let file;
  try {
    file = await fs.open(path.join(root, filename), constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch (error) {
    if (error.code === 'ENOENT') return undefined;
    throw unsafeFile();
  }
  try {
    const stat = await file.stat();
    if (!stat.isFile() || stat.uid !== process.getuid() || (stat.mode & 0o077) !== 0 || stat.size > 8192) throw unsafeFile();
    const data = Buffer.alloc(8193);
    let used = 0;
    while (used < data.length) {
      const { bytesRead } = await file.read(data, used, data.length - used, used);
      if (!bytesRead) break;
      used += bytesRead;
    }
    if (used > 8192) throw unsafeFile();
    return JSON.parse(data.toString('utf8', 0, used));
  } catch { throw unsafeFile(); }
  finally { await file.close(); }
}

async function withSelectionLock(root, action) {
  const dir = await fs.lstat(root);
  if (!dir.isDirectory() || dir.uid !== process.getuid() || (dir.mode & 0o077) !== 0) throw unsafeFile();
  const file = await fs.open(path.join(root, '.selection.lock'),
    constants.O_RDWR | constants.O_CREAT | constants.O_NOFOLLOW | constants.O_NONBLOCK, 0o600);
  try {
    const stat = await file.stat();
    if (!stat.isFile() || stat.uid !== process.getuid() || (stat.mode & 0o077) !== 0) throw unsafeFile();
    // Descriptor mode keeps the lock on our open file description after lockf
    // exits. Closing this fd releases it, including when Node terminates.
    await new Promise((resolve, reject) => {
      const proc = spawn('/usr/bin/lockf', ['-s', '-t', '2', '3'], { stdio: ['ignore', 'ignore', 'ignore', file.fd] });
      proc.on('error', () => reject(busy()));
      proc.on('close', code => code === 0 ? resolve() : reject(busy()));
    });
    return await action();
  } finally { await file.close(); }
}

export async function readSetupPreferences(root) {
  const current = await readJson(root, 'config.json');
  if (current !== undefined) return validateConfig(current, root);
  const pending = await readJson(root, 'pending-device.json');
  if (pending !== undefined && (pending?.schema_version !== 1 || !validUdid(pending.device_udid))) throw unsafeFile();
  return { device_udid: pending?.device_udid ?? null };
}

export async function saveSetupConfig(root, config) {
  return withSelectionLock(root, async () => {
    const current = await readSetupPreferences(root);
    const merged = validateConfig({ ...current, ...config, device_udid: current.device_udid }, root);
    await writePrivateJson(path.join(root, 'config.json'), merged);
    // Installed config is authoritative even if interrupted before removal.
    await fs.rm(path.join(root, 'pending-device.json'), { force: true });
    return merged;
  });
}

export async function saveInstalledSelection(root, udid) {
  return withSelectionLock(root, async () => {
    if (!validUdid(udid)) throw unsafeFile();
    const current = validateConfig(await readJson(root, 'config.json'), root);
    await writePrivateJson(path.join(root, 'config.json'), { ...current, device_udid: udid });
  });
}
