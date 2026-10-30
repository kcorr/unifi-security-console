import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { IpIntel } from '../../shared/types.ts';
import { classifyIp, computeVerdict, knownScanner, ownerName } from './ipintel.ts';

function intel(p: Partial<IpIntel>): IpIntel {
  return {
    ip: '198.51.100.7', version: 4, scope: 'public', scopeLabel: 'Public internet address', local: null, insideNetwork: null,
    reverseDns: [], reverseDnsVerified: [], geo: null, network: null, registration: null, exposure: null,
    reputation: { tor: null, abuseipdb: null, greynoise: null }, knownScanner: null, verdict: { level: 'unknown', score: 0, summary: '', reasons: [] },
    activity: { events: 0, blocked: 0, firstSeen: null, lastSeen: null, directions: { inbound: 0, outbound: 0, internal: 0, unknown: 0 }, signatures: [], peers: [], recent: [] },
    blocking: null, sources: [], fetchedAt: 0,
    ...p,
  };
}

test('private, CGNAT and reserved addresses are classified locally', () => {
  assert.equal(classifyIp('192.168.1.10').scope, 'private');
  assert.equal(classifyIp('100.100.1.1').scope, 'cgnat');
  assert.equal(classifyIp('169.254.3.3').scope, 'link-local');
  assert.equal(classifyIp('::ffff:10.0.0.1').scope, 'private');
  assert.equal(classifyIp('2001:db8::1').scope, 'documentation');
  assert.equal(classifyIp('8.8.8.8').scope, 'public');
});

test('an unverified reverse DNS name never makes an address look like a harmless scanner', () => {
  assert.equal(knownScanner([], ['Some Hosting Ltd']), null, 'spoofed PTR "scanner.censys-scanner.com" is ignored when unverified');
  assert.equal(knownScanner(['scanner-21.ch1.censys-scanner.com'], [])?.name, 'Censys', 'forward-confirmed name counts');
  assert.equal(knownScanner([], ['Censys, Inc.'])?.name, 'Censys', 'registry / ASN owner counts');
});

test('your own WAN address is labelled as yours, not as a threat', () => {
  const v = computeVerdict(intel({ local: { ip: '198.51.100.7', mac: null, name: 'Your public IP (gateway WAN)', network: 'WAN', networkId: null, vlan: null, known: true } }));
  assert.equal(v.level, 'internal');
  assert.match(v.summary, /never sent to outside lookup services/);
});

test('the network owner is presented as the owner, not as the attacker', () => {
  const v = computeVerdict(intel({ network: { asn: 64500, asName: 'EXAMPLE-AS', org: 'Example Hosting', isp: null, hosting: true, proxy: null, mobile: null } }));
  assert.match(v.summary, /^Network owner: Example Hosting \(AS64500\)/);
  assert.equal(v.level, 'cloud');
});

test('a registry contact such as "Abuse" is never shown as the network owner', () => {
  for (const contact of ['Abuse', 'Abuse-C', 'ABUSE CONTACT', 'NOC', 'Hostmaster', 'Technical Contact']) assert.equal(ownerName(contact), null, contact);
  for (const owner of ['Contabo GmbH', 'Security Corp', 'Technical University of Munich', 'Abusive Name Holdings']) assert.equal(ownerName(owner), owner);
});
