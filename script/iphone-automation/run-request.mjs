#!/usr/bin/env node
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createIphoneSession } from './bridge.mjs';
import { assistNumberMatch, verifiedAuthenticatorLayout } from './authenticator.mjs';
import { AutomationError } from './support.mjs';

const MAX_LINE_BYTES = 4096;
const ACTIONS_BY_STEP = [['open_authenticator'], ['enter_number'], ['submit_number', 'enter_number_for_manual_approval']];
const PHASES = new Set(['waiting_for_device', 'waiting_for_unlock', 'lock_state_unavailable',
  'preparing_iphone_runner', 'starting_iphone_runner', 'starting_iphone_connection', 'iphone_connected', 'waiting_for_authenticator',
  'manual_confirmation_required', 'waiting_for_number_request', 'entering_number',
  'complete_confirmation_on_iphone']);
const ERROR_CODES = new Set(['invalid_request', 'invalid_protocol', 'request_too_large', 'parent_disconnected',
  'authorization_timeout', 'authorization_expired', 'field_verification_timeout', 'cancelled', 'challenge_expired', 'helper_failed',
  'unsupported_authenticator_layout', 'invalid_device_response', 'ambiguous_authenticator_screen',
  'phone_locked', 'account_mismatch', 'number_field_not_empty', 'screen_changed', 'number_entry_unconfirmed',
  'unsafe_storage', 'unsafe_configuration', 'invalid_configuration', 'not_configured', 'runtime_missing',
  'device_selection_required', 'developer_mode_required', 'device_discovery_failed', 'session_lock_failed',
  'session_busy', 'server_start_failed', 'session_start_failed', 'session_closed', 'element_unavailable',
  'device_command_failed', 'transport_failed', 'wifi_device_required', 'iphone_not_available_to_appium',
  'wda_signing_required', 'ui_automation_required', 'driver_unavailable', 'authenticator_not_installed',
  'wda_build_failed', 'wda_connection_failed', 'wda_cleanup_unverified', 'invalid_timeout', 'invalid_device', 'command_failed']);

function error(code) { return new AutomationError(code, 'The iPhone assistance request did not complete.'); }
function exactKeys(value, keys) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
}

export function validateRequest(value) {
  if (!exactKeys(value, ['version', 'account', 'number', 'expires_in_ms']) || value.version !== 1
      || typeof value.account !== 'string' || value.account.length > 254
      || !/^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$/.test(value.account)
      || typeof value.number !== 'string' || !/^[0-9]{2}$/.test(value.number)
      || !Number.isSafeInteger(value.expires_in_ms) || value.expires_in_ms < 1000 || value.expires_in_ms > 120000) {
    throw error('invalid_request');
  }
  return value;
}

/** Strict sequential protocol: permits cannot be queued in advance or reused. */
export class RequestProtocol {
  constructor(input, output, controller) {
    this.input = input;
    this.output = output;
    this.controller = controller;
    this.state = 'request';
    this.sequence = 0;
    this.pendingOutput = new Set();
    this.buffer = Buffer.alloc(0);
    this.requestPromise = new Promise((resolve, reject) => { this.resolveRequest = resolve; this.rejectRequest = reject; });
    this.onData = chunk => {
      if (this.failure) return;
      try {
        const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        let offset = 0;
        while (offset < bytes.length) {
          const newline = bytes.indexOf(10, offset);
          const end = newline < 0 ? bytes.length : newline;
          if (this.buffer.length + end - offset > MAX_LINE_BYTES) throw error('request_too_large');
          this.buffer = Buffer.concat([this.buffer, bytes.subarray(offset, end)]);
          if (newline < 0) break;
          const line = this.buffer;
          this.buffer = Buffer.alloc(0);
          this.receive(JSON.parse(line.toString('utf8')));
          offset = newline + 1;
        }
      } catch (cause) { this.fail(cause instanceof AutomationError ? cause.code : 'invalid_protocol'); }
    };
    this.onEnd = () => { if (this.state !== 'finished') this.fail('parent_disconnected'); };
    this.onInputError = () => this.fail('parent_disconnected');
    this.onAbort = () => this.fail(this.failure?.code ?? 'cancelled');
    input.on('data', this.onData);
    input.once('end', this.onEnd);
    input.once('error', this.onInputError);
    output.on('error', this.onInputError);
    controller.signal.addEventListener('abort', this.onAbort, { once: true });
  }

  receive(value) {
    if (this.state === 'request') {
      const request = validateRequest(value);
      this.state = 'running';
      this.resolveRequest(request);
      return;
    }
    if (this.state === 'permission' && exactKeys(value, ['permit']) && value.permit === this.sequence) {
      clearTimeout(this.permissionTimer);
      this.state = 'running';
      const resolve = this.resolvePermit;
      this.resolvePermit = this.rejectPermit = undefined;
      resolve();
      return;
    }
    if (this.state === 'submitted' && exactKeys(value, ['finish']) && value.finish === true) {
      this.state = 'finished';
      this.resolveFinish();
      return;
    }
    throw error('invalid_protocol');
  }

  emit(value) {
    if (this.output.destroyed) return;
    let complete;
    const pending = new Promise(resolve => { complete = resolve; });
    this.pendingOutput.add(pending);
    const done = cause => {
      if (cause) this.fail('parent_disconnected');
      this.pendingOutput.delete(pending);
      complete();
    };
    try { this.output.write(`${JSON.stringify(value)}\n`, done); } catch (cause) { done(cause); }
  }

  async flush() { await Promise.allSettled(this.pendingOutput); }

  status(phase) {
    if (PHASES.has(phase) && phase !== this.lastPhase && !this.failure) {
      this.lastPhase = phase;
      this.emit({ type: 'status', phase });
    }
  }

  authorize(action) {
    if (this.failure) return Promise.reject(this.failure);
    if (this.state !== 'running' || !ACTIONS_BY_STEP[this.sequence]?.includes(action)) return Promise.reject(error('invalid_protocol'));
    this.sequence++;
    this.lastAction = action;
    this.state = 'permission';
    const promise = new Promise((resolve, reject) => { this.resolvePermit = resolve; this.rejectPermit = reject; });
    this.permissionTimer = setTimeout(() => this.fail('authorization_timeout'), 5000);
    this.emit({ type: 'authorize', sequence: this.sequence, action });
    return promise;
  }

  complete(result) {
    if (this.failure) return Promise.reject(this.failure);
    if (this.state !== 'running' || this.sequence !== 3) return Promise.reject(error('invalid_protocol'));
    if (this.lastAction === 'enter_number_for_manual_approval' && result === 'manual_approval_required') {
      this.state = 'manual_cleanup';
      return;
    }
    if (this.lastAction !== 'submit_number' || result !== undefined) return Promise.reject(error('invalid_protocol'));
    this.state = 'submitted';
    const promise = new Promise((resolve, reject) => { this.resolveFinish = resolve; this.rejectFinish = reject; });
    this.emit({ type: 'submitted' });
    return promise;
  }

  fail(code) {
    if (this.failure) return;
    this.failure = error(ERROR_CODES.has(code) ? code : 'helper_failed');
    clearTimeout(this.permissionTimer);
    this.rejectRequest(this.failure);
    this.rejectPermit?.(this.failure);
    this.rejectFinish?.(this.failure);
    this.controller.abort();
  }

  dispose() {
    clearTimeout(this.permissionTimer);
    this.input.removeListener('data', this.onData);
    this.input.removeListener('end', this.onEnd);
    this.input.removeListener('error', this.onInputError);
    this.input.pause();
    this.output.removeListener('error', this.onInputError);
    this.controller.signal.removeEventListener('abort', this.onAbort);
    this.buffer.fill(0);
    this.buffer = Buffer.alloc(0);
  }
}

/** Returns a process exit status; output is bounded status/error codes only. */
export async function runRequest({ input = process.stdin, output = process.stdout, signal,
  sessionFactory = createIphoneSession, layout = verifiedAuthenticatorLayout(),
  assist = assistNumberMatch } = {}) {
  const controller = new AbortController();
  const protocol = new RequestProtocol(input, output, controller);
  const abort = () => protocol.fail('cancelled');
  signal?.addEventListener('abort', abort, { once: true });
  let timer = setTimeout(() => protocol.fail('invalid_protocol'), 10000);
  let session;
  let request;
  let terminalError;
  try {
    if (signal?.aborted) abort();
    request = await protocol.requestPromise;
    if (protocol.failure) throw protocol.failure;
    clearTimeout(timer);
    const deadline = performance.now() + request.expires_in_ms;
    timer = setTimeout(() => protocol.fail('challenge_expired'), request.expires_in_ms);
    // No connection or app launch is attempted for an unverified UI layout.
    if (!layout) throw error('unsupported_authenticator_layout');
    session = await sessionFactory({ signal: controller.signal, timeoutMs: request.expires_in_ms,
      onStatus: ({ phase }) => protocol.status(phase) });
    const remaining = Math.floor(deadline - performance.now());
    if (remaining < 1000 || protocol.failure) throw protocol.failure ?? error('challenge_expired');
    const result = await assist({ session, layout, request: { ...request, expires_in_ms: remaining },
      authorize: action => protocol.authorize(action), onStatus: phase => protocol.status(phase), signal: controller.signal });
    await protocol.complete(result);
  } catch (cause) {
    const code = protocol.failure?.code ?? cause?.code;
    terminalError = ERROR_CODES.has(code) ? code : 'helper_failed';
  } finally {
    clearTimeout(timer);
    if (session) {
      try { await session.close(); } catch {
        terminalError = 'wda_cleanup_unverified';
      }
    }
    terminalError ??= protocol.failure?.code;
    // One terminal event follows cleanup, so the parent never mistakes an
    // earlier request failure for confirmation that the phone runner stopped.
    if (terminalError) {
      protocol.emit({ type: 'error', code: terminalError });
    } else if (protocol.state === 'manual_cleanup') {
      protocol.state = 'finished';
      protocol.emit({ type: 'manual_approval_required' });
    } else if (protocol.state === 'finished') {
      protocol.emit({ type: 'closed' });
    }
    if (request) { request.number = ''; request.account = ''; }
    await protocol.flush();
    protocol.dispose();
    signal?.removeEventListener('abort', abort);
  }
  return terminalError ? 1 : 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const controller = new AbortController();
  const stop = () => controller.abort();
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);
  process.exitCode = await runRequest({ signal: controller.signal });
  process.removeListener('SIGINT', stop);
  process.removeListener('SIGTERM', stop);
}
