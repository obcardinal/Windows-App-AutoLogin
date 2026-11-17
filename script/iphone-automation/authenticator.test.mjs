import test from 'node:test';
import assert from 'node:assert/strict';
import { AUTHENTICATOR_BUNDLE, AutomationError } from './support.mjs';
import { assistNumberMatch, observeNumberMatch, verifiedAuthenticatorLayout } from './authenticator.mjs';

// Synthetic selectors deliberately cannot match a real Authenticator screen.
const layout = { bundle_id: AUTHENTICATOR_BUNDLE, evidence: 'synthetic unit fixture',
  headings: [{ attribute: 'label', value: 'Synthetic number matching heading' }],
  number_field: { attribute: 'name', value: 'syntheticNumberInput' },
  submit_button: { attribute: 'name', value: 'syntheticSubmit' }, empty_values: [''] };
const request = () => ({ account: 'test@example.com', number: '42', expires_in_ms: 2000 });
const element = id => ({ 'element-6066-11e4-a52e-4f735466cecf': id });

function fixture() {
  const state = { locked: false, activeBundle: AUTHENTICATOR_BUNDLE, alerts: 0, headings: 1, accounts: 1,
    fields: 1, buttons: 1, enabled: true, field: 'number-field', submit: 'submit-button', value: '', writes: 0, clicks: 0,
    scripts: [], mutations: [], permits: [], statuses: [] };
  const session = {
    execute: async (script, args) => {
      state.scripts.push(script);
      state.beforeRead?.();
      if (script === 'mobile: isLocked') return state.locked;
      if (script === 'mobile: activeAppInfo') return { bundleId: state.activeBundle };
      assert.equal(script, 'mobile: launchApp');
      assert.equal(args.bundleId, AUTHENTICATOR_BUNDLE);
      state.mutations.push('open');
    },
    request: async (method, route, body) => {
      state.beforeRead?.();
      if (route === '/elements') {
        assert.equal(method, 'POST');
        assert.equal(body.using, '-ios predicate string');
        const predicate = body.value;
        let ids;
        if (predicate.includes("type == 'XCUIElementTypeAlert'")) ids = Array(state.alerts).fill('alert');
        else if (predicate.includes('Synthetic number matching heading')) ids = Array(state.headings).fill('heading');
        else if (predicate.includes('test@example.com')) {
          const suffix = ', test@example.com';
          const matching = state.accountLabel === undefined || (predicate.includes('ENDSWITH')
            ? state.accountLabel.endsWith(suffix) && state.accountLabel !== suffix
            : state.accountLabel === 'test@example.com');
          ids = matching ? Array(state.accounts).fill('account') : [];
          state.accountPredicate = predicate;
        }
        else if (predicate.includes('XCUIElementTypeSecureTextField')) ids = Array(state.fields).fill(state.field);
        else if (predicate.includes('syntheticNumberInput')) ids = [state.field];
        else if (predicate.includes('syntheticSubmit')) ids = Array(state.buttons).fill(state.submit);
        else assert.fail('Unexpected selector');
        return ids.map(element);
      }
      if (route === `/element/${state.field}/attribute/value`) return state.value;
      if (route === `/element/${state.submit}/enabled`) return state.enabled;
      if (route === `/element/${state.field}/value`) {
        assert.equal(method, 'POST');
        state.writes++;
        state.mutations.push('write');
        state.value = state.alterWrittenValue ? '99' : body.text;
        if (state.enableAfterInput) state.enabled = true;
        return null;
      }
      assert.equal(route, `/element/${state.submit}/click`);
      assert.equal(method, 'POST');
      state.clicks++;
      state.mutations.push('submit');
      if (state.clickFailure) throw new AutomationError('transport_failed', 'private server text');
      return null;
    },
  };
  const run = extras => assistNumberMatch({ session, layout, request: request(),
    authorize: async action => { state.permits.push(action); await state.onPermit?.(action); },
    onStatus: phase => state.statuses.push(phase), ...extras });
  return { state, session, run };
}

test('a missing UI profile is rejected before any phone mutation', async () => {
  const { state, run } = fixture();
  await assert.rejects(run({ layout: null }), { code: 'unsupported_authenticator_layout' });
  assert.deepEqual(state.mutations, []);
});

test('observed account group matches only the complete expected email after its delimiter', async () => {
  const profile = { ...layout, account_label_format: verifiedAuthenticatorLayout().account_label_format };
  const valid = fixture();
  valid.state.accountLabel = 'Synthetic Organization, test@example.com';
  await valid.run({ layout: profile });
  assert.equal(valid.state.clicks, 1);
  assert.ok(valid.state.accountPredicate.includes("type == 'XCUIElementTypeOther'"));

  for (const accountLabel of ['Synthetic Organization, another-test@example.com',
    'Synthetic Organization, test@example.com.evil', ', test@example.com',
    'Synthetic Organization test@example.com']) {
    const wrong = fixture();
    wrong.state.accountLabel = accountLabel;
    await assert.rejects(wrong.run({ layout: profile }), { code: 'account_mismatch' });
    assert.equal(wrong.state.writes, 0);
    assert.equal(wrong.state.clicks, 0);
  }
});

test('matching request requires separate permits and submits exactly once, leaving Face ID manual', async () => {
  const { state, run } = fixture();
  await run();
  assert.deepEqual(state.permits, ['open_authenticator', 'enter_number', 'submit_number']);
  assert.deepEqual(state.mutations, ['open', 'write', 'submit']);
  assert.equal(state.clicks, 1);
  assert.equal(state.statuses.at(-1), 'complete_confirmation_on_iphone');
  assert.ok(state.scripts.every(value => ['mobile: isLocked', 'mobile: activeAppInfo', 'mobile: launchApp'].includes(value)));
});

test('locked or unknown lock state never launches Authenticator', async () => {
  for (const locked of [true, null, undefined]) {
    const { state, run } = fixture();
    state.locked = locked;
    await assert.rejects(run(), { code: 'phone_locked' });
    assert.deepEqual(state.mutations, []);
  }
});

test('wrong account, multiple fields or multiple submit buttons cannot receive a number', async () => {
  for (const change of [{ accounts: 0 }, { accounts: 2 }, { fields: 2 }, { buttons: 2 }]) {
    const { state, run } = fixture();
    Object.assign(state, change);
    await assert.rejects(run(), error => ['account_mismatch', 'ambiguous_authenticator_screen'].includes(error.code));
    assert.equal(state.writes, 0);
    assert.equal(state.clicks, 0);
  }
});

test('background app and alerts are wait states, never automatic acceptance', async () => {
  const { state, session } = fixture();
  state.activeBundle = 'com.apple.springboard';
  assert.deepEqual(await observeNumberMatch(session, layout, request().account), { kind: 'waiting', phase: 'waiting_for_authenticator' });
  state.activeBundle = AUTHENTICATOR_BUNDLE;
  state.alerts = 1;
  assert.deepEqual(await observeNumberMatch(session, layout, request().account), { kind: 'waiting', phase: 'manual_confirmation_required' });
  assert.deepEqual(state.mutations, []);
});

test('screen and account are checked again after parent permission, before entering a number', async () => {
  const { state, run } = fixture();
  state.onPermit = action => { if (action === 'enter_number') state.accounts = 0; };
  await assert.rejects(run(), { code: 'account_mismatch' });
  assert.equal(state.writes, 0);
  assert.equal(state.clicks, 0);
});

test('preexisting text and unconfirmed input are never submitted', async () => {
  const first = fixture();
  first.state.value = '99';
  await assert.rejects(first.run(), { code: 'number_field_not_empty' });
  assert.equal(first.state.writes, 0);
  const second = fixture();
  second.state.alterWrittenValue = true;
  await assert.rejects(second.run(), { code: 'number_entry_unconfirmed' });
  assert.equal(second.state.clicks, 0);
});

test('a null empty-field value requires an observed profile and becomes the exact number after entry', async () => {
  const allowed = fixture();
  allowed.state.value = null;
  await allowed.run({ layout: { ...layout, empty_values: ['', null] } });
  assert.equal(allowed.state.writes, 1);
  assert.equal(allowed.state.clicks, 1);

  const unknown = fixture();
  unknown.state.value = null;
  await assert.rejects(unknown.run(), { code: 'invalid_device_response' });
  assert.equal(unknown.state.writes, 0);
  assert.equal(unknown.state.clicks, 0);
});

test('submit may start disabled, but must be enabled immediately before clicking', async () => {
  const first = fixture();
  first.state.enabled = false;
  first.state.enableAfterInput = true;
  await first.run();
  assert.equal(first.state.writes, 1);
  assert.equal(first.state.clicks, 1);

  const second = fixture();
  second.state.onPermit = action => { if (action === 'submit_number') second.state.enabled = false; };
  await assert.rejects(second.run(), { code: 'screen_changed' });
  assert.equal(second.state.clicks, 0);

  const third = fixture();
  third.state.enabled = null;
  await assert.rejects(third.run(), { code: 'invalid_device_response' });
  assert.equal(third.state.writes, 0);
});

test('cancellation before submit and stale parent permissions prevent the click', async () => {
  const first = fixture();
  const controller = new AbortController();
  first.state.onPermit = action => { if (action === 'submit_number') controller.abort(); };
  await assert.rejects(first.run({ signal: controller.signal }), { code: 'cancelled' });
  assert.equal(first.state.clicks, 0);
  const second = fixture();
  let clock = 0;
  second.state.onPermit = action => {
    if (action === 'submit_number') second.state.beforeRead = () => { clock += 400; };
  };
  await assert.rejects(second.run({ request: { ...request(), expires_in_ms: 120000 }, now: () => clock }), { code: 'authorization_expired' });
  assert.equal(second.state.clicks, 0);
});

test('ambiguous network failure after approval click is not retried', async () => {
  const { state, run } = fixture();
  state.clickFailure = true;
  await assert.rejects(run(), { code: 'transport_failed' });
  assert.equal(state.clicks, 1);
});
