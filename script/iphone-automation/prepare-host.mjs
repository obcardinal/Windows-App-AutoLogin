import { readConfig, runtimeReady, warmSelectedWifi } from './support.mjs';
import { prepareHostRunner } from './wda.mjs';

// The supervisor holds this pipe open only while the configuration is eligible.
const controller = new AbortController();
const cancel = () => controller.abort();
process.stdin.once('end', cancel);
process.stdin.once('error', cancel);
process.once('SIGTERM', cancel);
process.once('SIGINT', cancel);
process.stdin.resume();
try {
  const config = await readConfig();
  if (!config.device_udid || !await runtimeReady(config)) {
    process.exitCode = 1;
  } else {
    await Promise.all([
      prepareHostRunner(config, controller.signal),
      process.argv[1] === 'warm-wifi' && warmSelectedWifi(config.device_udid, controller.signal),
    ]);
  }
} catch {
  process.exitCode = 1;
} finally {
  controller.abort();
  process.stdin.destroy();
  process.removeListener('SIGTERM', cancel);
  process.removeListener('SIGINT', cancel);
}
