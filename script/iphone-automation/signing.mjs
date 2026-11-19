// Only setup reads signing identities. Private keys stay in the login keychain.
import { X509Certificate } from 'node:crypto';
import { AutomationError, runQuiet, validDevelopmentTeam } from './support.mjs';

export function developmentTeams(identities, certificates) {
  const valid = new Set();
  for (const line of identities.split('\n')) {
    const match = /^\s*\d+\)\s+([A-Fa-f0-9]{40})\s+"Apple Development: /.exec(line);
    if (match) valid.add(match[1].toUpperCase());
  }
  const teams = new Map();
  for (const pem of certificates.matchAll(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g)) {
    let certificate;
    try { certificate = new X509Certificate(pem[0]); } catch { continue; }
    if (!valid.has(certificate.fingerprint.replaceAll(':', '').toUpperCase())) continue;
    const fields = certificate.subject.split('\n');
    const values = name => fields.filter(field => field.startsWith(`${name}=`)).map(field => field.slice(name.length + 1));
    const team = values('OU');
    const name = values('O');
    const commonName = values('CN');
    if (team.length !== 1 || !validDevelopmentTeam(team[0]) || name.length !== 1
      || commonName.length !== 1 || !commonName[0].startsWith('Apple Development: ')) continue;
    teams.set(team[0], { id: team[0], name: name[0] });
  }
  return [...teams.values()].sort((a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id));
}

export async function availableSigningTeams(signal) {
  try {
    const identities = await runQuiet('/usr/bin/security', ['find-identity', '-v', '-p', 'codesigning'], { signal });
    const certificates = await runQuiet('/usr/bin/security', ['find-certificate', '-a', '-c', 'Apple Development:', '-p'], { signal });
    return developmentTeams(identities, certificates);
  } catch {
    signal?.throwIfAborted();
    throw new AutomationError('wda_signing_required', 'Open Xcode → Settings → Accounts, add your Apple Account, and create an Apple Development certificate in Manage Certificates.');
  }
}

export function selectSigningTeam(teams, explicit, configured) {
  if (explicit !== null && !validDevelopmentTeam(explicit)) {
    throw new AutomationError('invalid_signing_team', 'Choose a signing team from Xcode.');
  }
  const preferred = explicit ?? configured;
  if (teams.some(team => team.id === preferred)) return preferred;
  if (explicit !== null || teams.length === 0) {
    throw new AutomationError('wda_signing_required', 'Create an Apple Development certificate for the selected team in Xcode → Settings → Accounts → Manage Certificates.');
  }
  if (teams.length === 1) return teams[0].id;
  throw new AutomationError('signing_team_required', 'Choose which Apple signing team to use for your iPhone.');
}
