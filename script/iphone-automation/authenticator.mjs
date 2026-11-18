import { setTimeout as delay } from 'node:timers/promises';
import { AUTHENTICATOR_BUNDLE, AutomationError } from './support.mjs';

const ELEMENT_KEY = 'element-6066-11e4-a52e-4f735466cecf';
const PERMIT_MAX_AGE_MS = 2000;
const FIELD_VERIFICATION_LIMIT_MS = 10000;

// Observed on a physical iPhone on 2026-11-17. The account is exposed as one
// accessibility group, labelled "<organization>, <email>". The organization's
// display name is not an account identifier and can vary between accounts.
const VERIFIED_LAYOUT = Object.freeze({
  bundle_id: AUTHENTICATOR_BUNDLE,
  evidence: 'Observed English Microsoft Authenticator number-matching form, 2026-11-17',
  headings: [
    { attribute: 'label', value: 'Approve this sign-in?' },
    { attribute: 'label', value: "Enter the number shown on the sign-in screen. Only approve if you're trying to sign in." },
  ],
  account_label_format: 'organization_email',
  number_field: { attribute: 'label', value: 'Enter the number shown to sign in.' },
  submit_button: { attribute: 'label', value: 'Approve' },
  empty_values: ['', null],
});

export function verifiedAuthenticatorLayout() {
  return VERIFIED_LAYOUT;
}

function failure(code) {
  return new AutomationError(code, 'The iPhone sign-in request could not be verified.');
}

function quoted(value) {
  return `'${value.replaceAll('\\', '\\\\').replaceAll("'", "\\'")}'`;
}

function exactSelector(type, attribute, value, insensitive = false) {
  return `type == ${quoted(type)} AND visible == 1 AND ${attribute} ==${insensitive ? '[c]' : ''} ${quoted(value)}`;
}

function accountSelector(layout, account) {
  if (layout.account_label_format === 'organization_email') {
    const suffix = quoted(`, ${account}`);
    return `type == 'XCUIElementTypeOther' AND visible == 1 AND label ENDSWITH[c] ${suffix} AND label !=[c] ${suffix}`;
  }
  return exactSelector('XCUIElementTypeStaticText', 'label', account, true);
}

function requireLayout(layout) {
  if (!layout || layout.bundle_id !== AUTHENTICATOR_BUNDLE
      || typeof layout.evidence !== 'string' || !layout.evidence.trim()
      || !Array.isArray(layout.headings) || layout.headings.length < 1 || layout.headings.length > 3
      || ![undefined, 'email', 'organization_email'].includes(layout.account_label_format)
      || !Array.isArray(layout.empty_values) || !layout.empty_values.includes('')) {
    throw failure('unsupported_authenticator_layout');
  }
  for (const selector of [...layout.headings, layout.number_field, layout.submit_button]) {
    if (!selector || !['label', 'name'].includes(selector.attribute)
        || typeof selector.value !== 'string' || selector.value.length < 1
        || selector.value.length > 128 || /[\x00-\x1f\x7f]/.test(selector.value)) {
      throw failure('unsupported_authenticator_layout');
    }
  }
  if (layout.empty_values.some(value => value !== null && (typeof value !== 'string' || value.length > 128))) {
    throw failure('unsupported_authenticator_layout');
  }
}

function elementId(value) {
  const id = value?.[ELEMENT_KEY];
  if (typeof id !== 'string' || !/^[a-zA-Z0-9_-]{1,128}$/.test(id)) throw failure('invalid_device_response');
  return id;
}

async function matches(session, predicate) {
  const values = await session.request('POST', '/elements', { using: '-ios predicate string', value: predicate });
  if (!Array.isArray(values) || values.length > 32) throw failure('ambiguous_authenticator_screen');
  return values.map(elementId);
}

async function unlocked(session) {
  if (await session.execute('mobile: isLocked') !== false) throw failure('phone_locked');
}

/** Reads only the specific account/challenge controls; never requests page source. */
export async function observeNumberMatch(session, layout, account) {
  requireLayout(layout);
  await unlocked(session);
  const active = await session.execute('mobile: activeAppInfo');
  if (active?.bundleId !== AUTHENTICATOR_BUNDLE) return { kind: 'waiting', phase: 'waiting_for_authenticator' };
  // These are independent reads of the foreground screen. Batching them keeps
  // the parent's short-lived permission useful over Wi-Fi without weakening
  // any of the account, control, or ambiguity checks.
  const [alerts, headings, accounts, fields, numberFields, buttons] = await Promise.all([
    matches(session, "type == 'XCUIElementTypeAlert' AND visible == 1"),
    Promise.all(layout.headings.map(heading => matches(session,
      exactSelector('XCUIElementTypeStaticText', heading.attribute, heading.value)))),
    matches(session, accountSelector(layout, account)),
    matches(session, "(type == 'XCUIElementTypeTextField' OR type == 'XCUIElementTypeSecureTextField') AND visible == 1"),
    matches(session, exactSelector('XCUIElementTypeTextField', layout.number_field.attribute, layout.number_field.value)),
    matches(session, exactSelector('XCUIElementTypeButton', layout.submit_button.attribute, layout.submit_button.value)),
  ]);
  if (alerts.length) {
    return { kind: 'waiting', phase: 'manual_confirmation_required' };
  }
  for (const found of headings) {
    if (found.length === 0) return { kind: 'waiting', phase: 'waiting_for_number_request' };
    if (found.length !== 1) throw failure('ambiguous_authenticator_screen');
  }
  if (accounts.length !== 1) throw failure(accounts.length ? 'ambiguous_authenticator_screen' : 'account_mismatch');
  if (fields.length !== 1 || numberFields.length !== 1 || fields[0] !== numberFields[0] || buttons.length !== 1) {
    throw failure('ambiguous_authenticator_screen');
  }
  const [value, enabled] = await Promise.all([
    session.request('GET', `/element/${fields[0]}/attribute/value`),
    session.request('GET', `/element/${buttons[0]}/enabled`),
  ]);
  // UIKit can expose an untouched field as null. Accept that only when the
  // observed profile explicitly identifies it as an empty-field value.
  if (value === null ? !layout.empty_values.includes(null) : typeof value !== 'string' || value.length > 128) {
    throw failure('invalid_device_response');
  }
  if (typeof enabled !== 'boolean') throw failure('invalid_device_response');
  return { kind: 'number_match', field: fields[0], submit: buttons[0], submitEnabled: enabled, value };
}

function sameControls(before, after) {
  return after.kind === 'number_match' && before.field === after.field && before.submit === after.submit;
}

async function verifyFieldBeforeEntry(session, layout, account) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(failure('field_verification_timeout')), FIELD_VERIFICATION_LIMIT_MS);
  });
  try {
    return await Promise.race([observeNumberMatch(session, layout, account), timeout]);
  } finally {
    clearTimeout(timer);
  }
}

/** A single attempt. Mutating operations are never automatically retried. */
export async function assistNumberMatch({ session, layout, request, authorize, onStatus = () => {}, signal,
  now = () => performance.now(), wait = milliseconds => delay(milliseconds, undefined, { signal }) }) {
  requireLayout(layout);
  const deadline = now() + request.expires_in_ms;
  const current = () => {
    if (signal?.aborted) throw failure('cancelled');
    if (now() >= deadline) throw failure('challenge_expired');
  };
  const permit = async action => { current(); await authorize(action); current(); return now(); };
  const freshPermit = grantedAt => {
    current();
    if (now() - grantedAt > PERMIT_MAX_AGE_MS) throw failure('authorization_expired');
  };
  current();
  await unlocked(session);
  const openPermit = await permit('open_authenticator');
  await unlocked(session);
  freshPermit(openPermit);
  await session.execute('mobile: launchApp', { bundleId: AUTHENTICATOR_BUNDLE, asAppUnderTest: true });
  let screen;
  for (;;) {
    current();
    screen = await observeNumberMatch(session, layout, request.account);
    current();
    if (screen.kind === 'number_match') break;
    onStatus(screen.phase);
    await wait(300);
  }
  if (!layout.empty_values.includes(screen.value)) throw failure('number_field_not_empty');
  const writePermit = await permit('enter_number');
  const beforeWrite = await verifyFieldBeforeEntry(session, layout, request.account);
  current();
  const fieldVerifiedAt = now();
  const fieldCheckMs = fieldVerifiedAt - writePermit;
  if (fieldCheckMs > FIELD_VERIFICATION_LIMIT_MS) throw failure('field_verification_timeout');
  if (!sameControls(screen, beforeWrite) || !layout.empty_values.includes(beforeWrite.value)) throw failure('screen_changed');
  const manualApproval = fieldCheckMs > PERMIT_MAX_AGE_MS;
  if (manualApproval) {
    // The earlier permit expired during a read. Bind entry to a new desktop
    // check and to the recently observed phone controls. This branch can only
    // hand off to the person using the phone.
    await permit('enter_number_for_manual_approval');
    await unlocked(session);
    const [active, value, accounts] = await Promise.all([
      session.execute('mobile: activeAppInfo'),
      session.request('GET', `/element/${beforeWrite.field}/attribute/value`),
      matches(session, accountSelector(layout, request.account)),
    ]);
    if (active?.bundleId !== AUTHENTICATOR_BUNDLE || !layout.empty_values.includes(value) || accounts.length !== 1) {
      throw failure('screen_changed');
    }
    freshPermit(fieldVerifiedAt);
  } else {
    freshPermit(writePermit);
  }
  onStatus('entering_number');
  await session.request('POST', `/element/${beforeWrite.field}/value`, { text: request.number });
  current();
  const afterWrite = await observeNumberMatch(session, layout, request.account);
  current();
  if (!sameControls(beforeWrite, afterWrite) || afterWrite.value !== request.number) throw failure('number_entry_unconfirmed');
  if (manualApproval) return 'manual_approval_required';
  const submitPermit = await permit('submit_number');
  const beforeSubmit = await observeNumberMatch(session, layout, request.account);
  current();
  if (!sameControls(afterWrite, beforeSubmit) || beforeSubmit.value !== request.number || !beforeSubmit.submitEnabled) {
    throw failure('screen_changed');
  }
  freshPermit(submitPermit);
  // Exactly one click. An ambiguous response is an error, never a reason to
  // retry approval. Face ID and all system alerts remain entirely manual.
  await session.request('POST', `/element/${beforeSubmit.submit}/click`, {});
  onStatus('complete_confirmation_on_iphone');
}
