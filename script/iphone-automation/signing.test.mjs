import test from 'node:test';
import assert from 'node:assert/strict';
import { developmentTeams, selectSigningTeam } from './signing.mjs';

const personal = { id: 'PERSONAL01', name: 'Personal Team' };
const company = { id: 'COMPANY001', name: 'Company Team' };

test('setup selects the explicit or saved local signing team and requires a choice when ambiguous', () => {
  assert.equal(selectSigningTeam([personal], null), personal.id);
  assert.equal(selectSigningTeam([personal, company], null, company.id), company.id);
  assert.equal(selectSigningTeam([personal, company], personal.id, company.id), personal.id);
  assert.equal(selectSigningTeam([personal], null, company.id), personal.id);
  assert.throws(() => selectSigningTeam([personal, company], null), { code: 'signing_team_required' });
  assert.throws(() => selectSigningTeam([personal], company.id), { code: 'wda_signing_required' });
  assert.throws(() => selectSigningTeam([], null), { code: 'wda_signing_required' });
  assert.throws(() => selectSigningTeam([personal], 'invalid'), { code: 'invalid_signing_team' });
});

test('a certificate label by itself does not prove a local Apple Development identity', () => {
  assert.deepEqual(developmentTeams('1) AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA "Apple Development: Someone (PERSONAL01)"', ''), []);
  assert.deepEqual(developmentTeams('', '-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----'), []);
});
