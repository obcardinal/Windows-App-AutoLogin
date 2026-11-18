import test from 'node:test';
import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';
import { AutomationError } from './support.mjs';
import { runRequest, validateRequest } from './run-request.mjs';

const request = () => ({ version: 1, account: 'fixture@example.com', number: '42', expires_in_ms: 2000 });
const turn = () => new Promise(resolve => setImmediate(resolve));

function harness(options = {}) {
  const input = new PassThrough();
  const output = new PassThrough();
  const state = { messages: [], created: 0, closed: 0, mutations: 0 };
  let pending = '';
  output.on('data', bytes => {
    pending += bytes.toString();
    for (;;) {
      const newline = pending.indexOf('\n');
      if (newline < 0) break;
      const message = JSON.parse(pending.slice(0, newline));
      pending = pending.slice(newline + 1);
      state.messages.push(message);
      state.onMessage?.(message);
    }
  });
  const sessionFactory = async () => { state.created++; return { close: async () => { state.closed++; } }; };
  const assist = async ({ authorize, signal, onStatus }) => {
    onStatus('waiting_for_number_request');
    for (const action of ['open_authenticator', 'enter_number', 'submit_number']) {
      await authorize(action);
      signal.throwIfAborted();
      state.mutations++;
    }
  };
  const result = runRequest({ input, output, layout: { synthetic: true }, sessionFactory, assist, ...options });
  return { input, state, result, send: value => input.write(`${JSON.stringify(value)}\n`) };
}

function assertPrivate(state) {
  const text = JSON.stringify(state.messages);
  for (const value of ['fixture@example.com', '42', 'private-server-body']) assert.ok(!text.includes(value));
}

test('request permits only a bounded fixed challenge, never commands or alternate targets', () => {
  assert.deepEqual(validateRequest(request()), request());
  for (const change of [{ version: 2 }, { number: 42 }, { number: '123456' }, { number: '４２' },
    { number: '4\n2' }, { account: 'fixture@example.com\n' }, { account: 'x'.repeat(300) },
    { expires_in_ms: 120001 }, { expires_in_ms: 0 }, { command: 'approve-everything' }]) {
    assert.throws(() => validateRequest({ ...request(), ...change }), { code: 'invalid_request' });
  }
});

test('an unverified layout fails before any phone connection and emits no input data', async () => {
  const h = harness({ layout: null });
  h.send(request());
  assert.equal(await h.result, 1);
  assert.equal(h.state.created, 0);
  assert.deepEqual(h.state.messages, [{ type: 'error', code: 'unsupported_authenticator_layout' }]);
  assertPrivate(h.state);
});

test('separate permits are required and session stays open until desktop explicitly finishes', async () => {
  const h = harness();
  h.state.onMessage = message => { if (message.type === 'authorize') h.send({ permit: message.sequence }); };
  h.send(request());
  await turn();
  assert.deepEqual(h.state.messages.filter(item => item.type === 'authorize').map(item => [item.sequence, item.action]),
    [[1, 'open_authenticator'], [2, 'enter_number'], [3, 'submit_number']]);
  assert.equal(h.state.messages.at(-1).type, 'submitted');
  assert.equal(h.state.closed, 0);
  h.send({ finish: true });
  h.input.end();
  assert.equal(await h.result, 0);
  assert.equal(h.state.closed, 1);
  assert.deepEqual(h.state.messages.at(-1), { type: 'closed' });
  assertPrivate(h.state);
});

test('incomplete, unexpected, or repeated action sequences cannot report submission', async () => {
  for (const [actions, result] of [
    [['open_authenticator', 'enter_number'], undefined],
    [['open_authenticator', 'enter_number', 'submit_number'], 'unexpected-result'],
    [['open_authenticator', 'enter_number', 'submit_number', 'submit_number'], undefined],
    [['open_authenticator', 'enter_number', 'submit_number', undefined], undefined],
  ]) {
    const h = harness({ assist: async ({ authorize }) => {
      for (const action of actions) await authorize(action);
      return result;
    } });
    h.state.onMessage = message => { if (message.type === 'authorize') h.send({ permit: message.sequence }); };
    h.send(request());
    assert.equal(await h.result, 1);
    assert.deepEqual(h.state.messages.filter(message => message.type !== 'authorize'),
      [{ type: 'error', code: 'invalid_protocol' }]);
    assert.equal(h.state.closed, 1);
  }
});

test('permits cannot be sent in advance with the initial request', async () => {
  const h = harness();
  h.input.write(`${JSON.stringify(request())}\n{"permit":1}\n`);
  assert.equal(await h.result, 1);
  assert.equal(h.state.created, 0);
  assert.deepEqual(h.state.messages, [{ type: 'error', code: 'invalid_protocol' }]);
  assertPrivate(h.state);
});

test('duplicate or wrong permits cancel before the next phone mutation', async () => {
  for (const response of ['{"permit":1}\n{"permit":1}\n', '{"permit":2}\n']) {
    const h = harness();
    h.state.onMessage = message => { if (message.type === 'authorize') h.input.write(response); };
    h.send(request());
    assert.equal(await h.result, 1);
    assert.equal(h.state.mutations, 0);
    assert.equal(h.state.closed, 1);
    assert.equal(h.state.messages.at(-1).code, 'invalid_protocol');
  }
});

test('EOF after submission cancels and cleans up rather than claiming a successful login', async () => {
  const h = harness();
  h.state.onMessage = message => {
    if (message.type === 'authorize') h.send({ permit: message.sequence });
    if (message.type === 'submitted') h.input.end();
  };
  h.send(request());
  assert.equal(await h.result, 1);
  assert.equal(h.state.closed, 1);
  assert.equal(h.state.messages.at(-1).code, 'parent_disconnected');
  assert.ok(!h.state.messages.some(message => message.type === 'success' || message.type === 'completed'));
});

test('cleanup failure after the desktop finishes is reported with a fixed error and failure exit status', async () => {
  const h = harness({ sessionFactory: async () => ({ close: async () => {
    throw new Error('private-server-body');
  } }) });
  h.state.onMessage = message => {
    if (message.type === 'authorize') h.send({ permit: message.sequence });
    if (message.type === 'submitted') h.send({ finish: true });
  };
  h.send(request());
  assert.equal(await h.result, 1);
  assert.deepEqual(h.state.messages.at(-1), { type: 'error', code: 'wda_cleanup_unverified' });
  assert.ok(!h.state.messages.some(message => message.type === 'closed'));
  assertPrivate(h.state);
});

test('cleanup failure replaces an earlier operation failure with one final error after close', async () => {
  let cleanupStarted = false;
  const h = harness({
    sessionFactory: async () => ({ close: async () => {
      cleanupStarted = true;
      await turn();
      throw new Error('private-server-body');
    } }),
    assist: async () => { throw new AutomationError('account_mismatch', 'private-server-body'); },
  });
  h.state.onMessage = message => {
    if (message.type === 'error') assert.equal(cleanupStarted, true);
  };
  h.send(request());
  assert.equal(await h.result, 1);
  assert.deepEqual(h.state.messages, [{ type: 'error', code: 'wda_cleanup_unverified' }]);
  assertPrivate(h.state);
});

test('request lifetime includes device setup and aborts outstanding preparation', async () => {
  let aborted = false;
  const h = harness({ sessionFactory: ({ signal }) => new Promise((_resolve, reject) => {
    signal.addEventListener('abort', () => { aborted = true; reject(new Error('private-server-body')); }, { once: true });
  }) });
  h.send({ ...request(), expires_in_ms: 1000 });
  assert.equal(await h.result, 1);
  assert.equal(aborted, true);
  assert.deepEqual(h.state.messages, [{ type: 'error', code: 'challenge_expired' }]);
  assertPrivate(h.state);
});

test('oversized lines are rejected even before a newline arrives', async () => {
  const h = harness();
  h.input.write(Buffer.alloc(4097, 65));
  assert.equal(await h.result, 1);
  assert.equal(h.state.created, 0);
  assert.deepEqual(h.state.messages, [{ type: 'error', code: 'request_too_large' }]);
});

test('unknown errors and status values cannot leak request or phone content', async () => {
  const h = harness({ sessionFactory: async ({ onStatus }) => {
    onStatus({ phase: 'private-server-body fixture@example.com 42' });
    throw new AutomationError('private-server-body 42', 'fixture@example.com');
  } });
  h.send(request());
  assert.equal(await h.result, 1);
  assert.deepEqual(h.state.messages, [{ type: 'error', code: 'helper_failed' }]);
  assertPrivate(h.state);
});

test('known runner preparation phases and setup failures remain actionable without raw text', async () => {
  const h = harness({ sessionFactory: async ({ onStatus }) => {
    onStatus({ phase: 'preparing_iphone_runner' });
    onStatus({ phase: 'starting_iphone_runner' });
    throw new AutomationError('wda_signing_required', 'private-server-body');
  } });
  h.send(request());
  assert.equal(await h.result, 1);
  assert.deepEqual(h.state.messages, [
    { type: 'status', phase: 'preparing_iphone_runner' },
    { type: 'status', phase: 'starting_iphone_runner' },
    { type: 'error', code: 'wda_signing_required' },
  ]);
  assertPrivate(h.state);
});

test('caller cannot reorder actions or request approval without entering the number', async () => {
  const h = harness({ assist: async ({ authorize }) => { await authorize('submit_number'); } });
  h.send(request());
  assert.equal(await h.result, 1);
  assert.equal(h.state.closed, 1);
  assert.deepEqual(h.state.messages, [{ type: 'error', code: 'invalid_protocol' }]);
});

test('external cancellation while awaiting permission closes the session without mutating', async () => {
  const controller = new AbortController();
  const h = harness({ signal: controller.signal });
  h.state.onMessage = message => { if (message.type === 'authorize') controller.abort(); };
  h.send(request());
  assert.equal(await h.result, 1);
  assert.equal(h.state.mutations, 0);
  assert.equal(h.state.closed, 1);
  assert.equal(h.state.messages.at(-1).code, 'cancelled');
});
