import { test } from 'node:test';
import assert from 'node:assert/strict';
import { FakeConsole } from '../testing/fakeConsole.ts';
import { UniFiClient } from '../unifi/client.ts';
import { collect } from '../unifi/collect.ts';
import { buildModel, zoneMemberNames } from './normalize.ts';
import { buildMatrix } from './segmentation.ts';
import { analyzeHygiene } from './hygiene.ts';
import type { FwModel } from './model.ts';
import type { RawSnapshot } from '../unifi/collect.ts';
import { expectedReach, inferRole } from './roles.ts';
import { analyzeExposure, computePosture } from './posture.ts';
import { assessTemplates } from './hardening/planner.ts';
import { TEMPLATES } from './hardening/templates.ts';
import type { ThreatSummary } from '../../shared/types.ts';

async function simModel() {
  const transport = new FakeConsole();
  const client = new UniFiClient(transport, 'default');
  await client.connect();
  const raw = await collect(client);
  return { raw, model: buildModel(raw, new Map()), client, transport };
}

test('the simulated console connects through both APIs', async () => {
  const { raw, client } = await simModel();
  assert.equal(client.info.integration, true);
  assert.equal(client.info.internal, true);
  assert.equal(client.info.version, '10.6.109');
  assert.equal(raw.firewallSource, 'integration');
  assert.equal(raw.firewallMode, 'zone');
  const failed = raw.capabilities.filter((c) => !c.ok && c.key !== 'internal.trafficrules');
  assert.deepEqual(failed, []);
});

test('model resolves networks, zones and rules', async () => {
  const { model } = await simModel();
  assert.equal(model.networks.length, 6);
  const iot = model.networks.find((n) => n.name === 'IoT')!;
  assert.equal(iot.subnet, '192.168.30.0/24');
  assert.equal(iot.role, 'iot');
  assert.equal(model.networks.find((n) => n.name === 'Guest')!.role, 'guest');
  assert.equal(model.networks.find((n) => n.name === 'Default')!.dhcpDns[0], '192.168.20.53');
  assert.ok(model.rules.length > 30);
  const bad = model.rules.find((r) => r.name === 'Block known bad IPs')!;
  assert.ok(bad.exact);
  assert.match(bad.srcDesc, /Known bad IPs/);
});

test('segmentation matrix explains reachability', async () => {
  const { model } = await simModel();
  const m = buildMatrix(model);
  const id = (name: string) => model.networks.find((n) => n.name === name)!.id;
  const cell = (a: string, b: string) => m.cells.find((c) => c.from === id(a) && c.to === (b === 'internet' || b === 'gateway' ? b : id(b)))!;

  const iotMain = cell('IoT', 'Default');
  assert.equal(iotMain.verdict, 'allowed');
  assert.equal(iotMain.risk, 'risk');
  assert.equal(iotMain.fix?.templateId, 'isolate-networks');

  const camMain = cell('Cameras', 'Default');
  assert.equal(camMain.verdict, 'blocked');
  assert.match(camMain.summary, /Block Cameras to LAN/);

  const guestMain = cell('Guest', 'Default');
  assert.equal(guestMain.verdict, 'blocked');
  assert.equal(guestMain.risk, 'ok');

  const serversIot = cell('Servers', 'IoT');
  assert.equal(serversIot.verdict, 'allowed');

  const guestGw = cell('Guest', 'gateway');
  assert.equal(guestGw.verdict, 'partial', 'only DNS/DHCP allowed to the gateway');

  const iotNet = cell('IoT', 'internet');
  assert.equal(iotNet.verdict, 'partial', 'UDP 53 blocked, rest allowed');
});

test('hygiene finds the duplicate written differently and the disabled rule', async () => {
  const { model } = await simModel();
  const issues = analyzeHygiene(model);
  const dup = issues.find((i) => i.kind === 'duplicate');
  assert.ok(dup, 'duplicate detected');
  assert.deepEqual(dup!.ruleNames.slice(0, 2), ['IoT no public DNS', 'Block IoT DNS']);
  assert.ok(issues.some((i) => i.kind === 'disabled' && i.ruleNames[0] === 'Old test rule'));
  assert.ok(!issues.some((i) => i.kind === 'broad-allow' && i.severity === 'critical'));
});

test('zone members are named even when the official API only gives ids for WAN / VPN networks', () => {
  const model = {
    networks: [{ id: 'uuid-lan', name: 'Default', raw: { _legacyId: 'lan1' } }],
    zones: [
      { id: 'z-ext', name: 'External', key: 'external', networkIds: ['uuid-wan1', 'uuid-wan2'] },
      { id: 'z-int', name: 'Internal', key: 'internal', networkIds: ['uuid-lan'] },
      { id: 'z-vpn', name: 'Vpn', key: 'vpn', networkIds: ['uuid-vpn'] },
    ],
  } as unknown as FwModel;
  const raw = {
    networkconf: [{ _id: 'wan1', name: 'Internet 1' }, { _id: 'wan2', name: 'Internet 2' }, { _id: 'lan1', name: 'Default' }],
    v2Zones: [{ _id: 'x', name: 'External', zone_key: 'external', network_ids: ['wan1', 'wan2'] }],
  } as unknown as RawSnapshot;
  const names = zoneMemberNames(model, raw);
  assert.deepEqual(names.get('z-ext'), ['Internet 1', 'Internet 2']);
  assert.deepEqual(names.get('z-int'), ['Default']);
  assert.deepEqual(names.get('z-vpn'), ['1 other'], 'never a bare "?"');
});

test('storage, lab and DMZ networks are told apart and get their own expectations', async () => {
  assert.equal(inferRole('iSCSI', 'corporate'), 'storage');
  assert.equal(inferRole('SAN', 'corporate'), 'storage');
  assert.equal(inferRole('DMZ', 'corporate'), 'dmz');
  assert.equal(inferRole('Lab', 'corporate'), 'lab');
  assert.equal(inferRole('SC-Test', 'corporate'), 'lab');
  assert.equal(expectedReach('iot', 'storage').expected, 'block');
  assert.equal(expectedReach('trusted', 'storage').expected, 'either');
  assert.equal(expectedReach('storage', 'trusted').expected, 'block');
  assert.equal(expectedReach('dmz', 'trusted').expected, 'block');
  assert.equal(expectedReach('lab', 'trusted').expected, 'either', 'an internal lab is not treated like an exposed DMZ');
  assert.equal(expectedReach('lab', 'management').expected, 'block');

  const { raw, model } = await simModel();
  const servers = model.networks.find((n) => n.name === 'Servers')!;
  const m = buildMatrix(buildModel(raw, new Map([[servers.id, 'storage']])));
  assert.equal(m.cells.find((c) => c.from === servers.id && c.to === 'internet')!.fix?.templateId, 'block-internet', 'storage needs no internet');
  assert.equal(m.cells.find((c) => c.from === servers.id && c.to === 'gateway')!.fix?.templateId, 'protect-gateway', 'storage devices stay off the gateway admin login');
});

test('accepted risks leave the to-do list and stop counting against the score', async () => {
  const { raw, model, client } = await simModel();
  const empty: ThreatSummary = {
    range: { from: 0, to: 0 }, total: 0, blocked: 0, alerted: 0, uniqueSources: 0,
    bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, byDirection: { inbound: 0, outbound: 0, internal: 0, unknown: 0 },
    byCategory: [], topSignatures: [], topSources: [], topTargets: [], byCountry: [], timeline: [], bucketMs: 0, suspects: [],
  };
  const input = { raw, model, matrix: buildMatrix(model), hygiene: analyzeHygiene(model), exposure: analyzeExposure(raw, model, () => null), templates: assessTemplates({ raw, model, client }), threats7d: empty };
  const before = computePosture(input);
  const dns = before.findings.find((f) => f.checkId === 'dns-bypass')!;
  assert.equal(dns.key, 'protection:block-external-dns', 'an issue shares the key of the hardening action that fixes it');
  const accepted = { key: dns.key, kind: 'finding' as const, title: dns.title, reason: 'Our IoT hub needs Google DNS', acceptedAt: 1 };
  const after = computePosture({ ...input, accepted: new Map([[dns.key, accepted]]) });
  assert.equal(after.failed, before.failed - 1);
  assert.equal(after.accepted, 1);
  assert.ok(after.score > before.score);
  assert.equal(after.findings.find((f) => f.key === dns.key)!.acceptance?.reason, 'Our IoT hub needs Google DNS');
});

test('accepting one isolation issue hides only that one; accepting the protection hides them all', async () => {
  const { raw, model, client } = await simModel();
  const empty: ThreatSummary = {
    range: { from: 0, to: 0 }, total: 0, blocked: 0, alerted: 0, uniqueSources: 0,
    bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, byDirection: { inbound: 0, outbound: 0, internal: 0, unknown: 0 },
    byCategory: [], topSignatures: [], topSources: [], topTargets: [], byCountry: [], timeline: [], bucketMs: 0, suspects: [],
  };
  const input = { raw, model, matrix: buildMatrix(model), hygiene: analyzeHygiene(model), exposure: analyzeExposure(raw, model, () => null), templates: assessTemplates({ raw, model, client }), threats7d: empty };
  const before = computePosture(input);
  const seg = before.findings.filter((f) => f.checkId === 'segmentation');
  assert.ok(seg.length >= 2, 'the simulated network has several isolation issues');
  assert.equal(new Set(seg.map((f) => f.key)).size, seg.length, 'each network has its own key');

  const one = computePosture({ ...input, accepted: new Map([[seg[0].key, { key: seg[0].key, kind: 'finding' as const, title: seg[0].title, reason: 'The servers manage the switches', acceptedAt: 1 }]]) });
  assert.equal(one.failed, before.failed - 1);
  assert.equal(one.findings.filter((f) => f.checkId === 'segmentation' && f.acceptance).length, 1);

  const key = 'protection:isolate-networks';
  const all = computePosture({ ...input, accepted: new Map([[key, { key, kind: 'protection' as const, title: 'Isolate networks', reason: 'A flat network, by design', acceptedAt: 1 }]]) });
  assert.equal(all.failed, before.failed - seg.length, 'accepting the whole protection on Hardening covers every issue it fixes');
  assert.equal(all.accepted, 1, 'one decision, however many issues it covers');
});

test('role names match whole words only', () => {
  assert.equal(inferRole('VLAN 20', 'corporate'), 'other');
  assert.equal(inferRole('Printer network', 'corporate'), 'other');
  assert.equal(inferRole('Plant floor', 'corporate'), 'other');
  assert.equal(inferRole('Main LAN', 'corporate'), 'trusted');
  assert.equal(inferRole('Work', 'corporate'), 'trusted');
});

test('an issue that a protection fixes goes by the name of that protection everywhere', async () => {
  const { raw, model, client } = await simModel();
  const empty: ThreatSummary = {
    range: { from: 0, to: 0 }, total: 0, blocked: 0, alerted: 0, uniqueSources: 0,
    bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, byDirection: { inbound: 0, outbound: 0, internal: 0, unknown: 0 },
    byCategory: [], topSignatures: [], topSources: [], topTargets: [], byCountry: [], timeline: [], bucketMs: 0, suspects: [],
  };
  const p = computePosture({ raw, model, matrix: buildMatrix(model), hygiene: analyzeHygiene(model), exposure: analyzeExposure(raw, model, () => null), templates: assessTemplates({ raw, model, client }), threats7d: empty });
  for (const id of ['dns-bypass', 'ips-mode']) {
    const f = p.findings.find((x) => x.checkId === id && x.fix)!;
    assert.ok(f.protection, id);
    assert.equal(f.fix!.label, f.protection.title, `${id}: the button, the preview and Hardening use one name`);
  }
  assert.equal(p.findings.find((x) => x.fix?.templateId === 'port-forward')?.protection ?? null, null, 'one-off actions have no Hardening row to link to');
});

const NO_THREATS: ThreatSummary = {
  range: { from: 0, to: 0 }, total: 0, blocked: 0, alerted: 0, uniqueSources: 0,
  bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, byDirection: { inbound: 0, outbound: 0, internal: 0, unknown: 0 },
  byCategory: [], topSignatures: [], topSources: [], topTargets: [], byCountry: [], timeline: [], bucketMs: 0, suspects: [],
};

function postureWith(d: Awaited<ReturnType<typeof simModel>>, ips: Record<string, unknown> | null, accepted?: Map<string, { key: string; kind: 'finding' | 'protection'; title: string; reason: string; acceptedAt: number }>) {
  const raw: RawSnapshot = ips ? { ...d.raw, settings: { ...d.raw.settings, ips: { ...d.raw.settings.ips, ...ips } } } : d.raw;
  const templates = assessTemplates({ raw, model: d.model, client: d.client });
  return { templates, posture: computePosture({ raw, model: d.model, matrix: buildMatrix(d.model), hygiene: analyzeHygiene(d.model), exposure: analyzeExposure(raw, d.model, () => null), templates, threats7d: NO_THREATS, accepted }) };
}

test('IPS detections are counted the way UniFi’s Active Detections list shows them', async () => {
  const d = await simModel();
  // A UDR7 on Network 10.6: 11 of its 13 switches on, only peer to peer and Tor off.
  const real = ['botcc', 'emerging-dns', 'dshield', 'emerging-exploit', 'emerging-malware', 'emerging-mobile', 'emerging-shellcode', 'emerging-useragent', 'emerging-worm', 'dark-web-blocker-list', 'malicious-hosts'];
  const mine = postureWith(d, { ips_mode: 'ips', enabled_categories: real, memory_optimized: true }).posture.findings.filter((x) => x.checkId === 'ips-categories');
  assert.deepEqual(mine.map((x) => x.status), ['pass'], 'peer to peer and Tor are usage policies, not missing protection');
  assert.equal(mine[0].summary, 'Active Detections in UniFi: Botnets and Threat Intelligence 3 of 3 · Viruses, Malware and Spyware 3 of 3 · Hacking and Exploits 3 of 3 · Peer to Peer and Dark Web 1 of 3 · Protocol Vulnerabilities 1 of 1.');

  const sim = postureWith(d, null).posture.findings.find((x) => x.checkId === 'ips-categories')!;
  assert.equal(sim.title, '5 recommended detections are off');
  assert.equal(sim.summary, "Intrusion prevention doesn't check for: Malicious hosts, Mobile malware, Shellcode, Malicious user agents and Dark web blocker.");
  assert.match(sim.evidence[0], /Hacking and Exploits 1 of 3/);
  assert.match(sim.howTo ?? '', /Active Detections and switch on the rest of Botnets and Threat Intelligence, Viruses, Malware and Spyware, Hacking and Exploits and Peer to Peer and Dark Web/);

  // Before Network 9 there are no groups: the classic categories that matter most are checked instead.
  const classic = postureWith(d, { enabled_categories: ['emerging-scan', 'emerging-exploit', 'emerging-malware', 'botcc', 'compromised', 'dshield'], memory_optimized: undefined }).posture.findings.find((x) => x.checkId === 'ips-categories')!;
  assert.equal(classic.title, '5 recommended threat categories aren’t checked');
  assert.match(classic.summary, /Worms, Phishing, Crypto miners, Web server attacks and Signs of a successful attack/);
});

test('every protection Hardening calls worth doing is also among the things to fix', async () => {
  const d = await simModel();
  const { templates, posture } = postureWith(d, null);
  const worth = templates.filter((t) => (t.state === 'partial' || t.state === 'not-applied') && !TEMPLATES.find((x) => x.id === t.templateId)?.hidden);
  assert.ok(worth.length > 3);
  for (const t of worth) assert.ok(posture.findings.some((f) => f.status !== 'pass' && f.fix?.templateId === t.templateId), `${t.templateId} is missing from the things to fix`);

  const own = posture.findings.find((f) => f.checkId === 'protection-block-risky-outbound')!;
  assert.equal(own.title, 'Block risky outbound services');
  assert.equal(own.key, 'protection:block-risky-outbound', 'the same key as on Hardening, so accepting it in one place hides it in both');
  assert.match(own.summary, /Not done yet for /);
  const accepted = postureWith(d, null, new Map([[own.key, { key: own.key, kind: 'protection' as const, title: own.title, reason: 'Mail server on purpose', acceptedAt: 1 }]])).posture;
  assert.ok(accepted.findings.find((f) => f.checkId === 'protection-block-risky-outbound')?.acceptance);
  assert.equal(accepted.failed, posture.failed - 1);
});
