import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { FakeConsole } from '../../testing/fakeConsole.ts';
import { UniFiClient } from '../../unifi/client.ts';
import { collect } from '../../unifi/collect.ts';
import { buildModel } from '../normalize.ts';
import { buildPlan, assessTemplates, assignLegacyIndexes } from './planner.ts';
import { withService } from './payloads.ts';
import { ChangeExecutor, pastTense } from './executor.ts';
import { UniFiHttpError } from '../../unifi/http.ts';
import { buildMatrix, reachableGatewayMgmt } from '../segmentation.ts';

async function setup() {
  const transport = new FakeConsole();
  const client = new UniFiClient(transport, 'default');
  await client.connect();
  const db = new DatabaseSync(':memory:');
  db.exec('CREATE TABLE changes (id TEXT PRIMARY KEY, ts INTEGER NOT NULL, data TEXT NOT NULL)');
  const executor = new ChangeExecutor(db);
  const ctx = async () => {
    const raw = await collect(client);
    return { raw, model: buildModel(raw, new Map()), client };
  };
  return { transport, client, executor, ctx };
}

const netId = (model: Awaited<ReturnType<Awaited<ReturnType<typeof setup>>['ctx']>>['model'], name: string) => model.networks.find((n) => n.name === name)!.id;

test('DNS hardening reuses existing rules and does not pile up on re-run', async () => {
  const { executor, ctx, client, transport } = await setup();
  let c = await ctx();
  const before = transport.state.policies.length;
  const params = { networks: ['IoT', 'Guest', 'Default'].map((n) => netId(c.model, n)), includeDot: true, allowedServers: ['192.168.20.53'] };
  const plan = buildPlan(c, 'block-external-dns', params);

  const status = (t: string) => plan.analysis.find((a) => a.target === t)?.status;
  assert.equal(status('IoT'), 'will-update', 'IoT is partially covered by a UDP-only rule that gets widened');
  assert.equal(status('Default'), 'will-extend', 'Default is added to the same rule instead of a new one');
  assert.equal(status('Guest'), 'will-create', 'Guest lives in another zone pair, so it needs its own rule');
  const updates = plan.operations.filter((o) => o.kind === 'update');
  const creates = plan.operations.filter((o) => o.kind === 'create');
  assert.equal(updates.length, 1, 'widen + extend merged into a single update');
  assert.match(updates[0].description, /Block IoT DNS/);
  assert.equal(creates.length, 1);

  executor.remember(plan);
  const rec = await executor.apply(plan.id, client);
  assert.equal(rec.status, 'applied', rec.error ?? '');
  assert.equal(transport.state.policies.length, before + 1);

  c = await ctx();
  const again = buildPlan(c, 'block-external-dns', params);
  assert.equal(again.noop, true, `second run should be a no-op, got: ${again.summary}`);
  assert.ok(again.analysis.every((a) => a.status === 'already-covered' || a.status === 'exception'));

  const undone = await executor.undo(rec.id, client);
  assert.equal(undone.status, 'undone', undone.error ?? '');
  assert.equal(transport.state.policies.length, before);
  c = await ctx();
  assert.equal(buildPlan(c, 'block-external-dns', params).noop, false, 'after undo the gap is back');
});

test('isolation keeps intentional exceptions working', async () => {
  const { executor, ctx, client } = await setup();
  let c = await ctx();
  const params = { sources: [netId(c.model, 'IoT')], destinations: [netId(c.model, 'Default'), netId(c.model, 'Servers')] };
  const plan = buildPlan(c, 'isolate-networks', params);
  assert.ok(plan.analysis.some((a) => a.status === 'exception' && /Allow IoT to Plex/.test(a.message)), 'Plex exception is recognised');
  assert.ok(plan.warnings.some((w) => /Block Cameras to LAN/.test(w)), 'explains why the cameras rule is not extended');
  assert.equal(plan.operations.filter((o) => o.kind === 'create').length, 1);

  executor.remember(plan);
  const rec = await executor.apply(plan.id, client);
  assert.equal(rec.status, 'applied', rec.error ?? '');
  c = await ctx();
  assert.equal(buildPlan(c, 'isolate-networks', params).noop, true);
});

test('isolating another source extends the managed rule instead of adding one', async () => {
  const { executor, ctx, client, transport } = await setup();
  let c = await ctx();
  const first = buildPlan(c, 'isolate-networks', { sources: [netId(c.model, 'Guest')], destinations: [netId(c.model, 'Default')] });
  assert.equal(first.noop, true, 'guest → default is already blocked by the hotspot defaults');

  const p1 = buildPlan(c, 'isolate-networks', { sources: [netId(c.model, 'Management')], destinations: [netId(c.model, 'IoT')] });
  executor.remember(p1);
  assert.equal((await executor.apply(p1.id, client)).status, 'applied');
  const count = transport.state.policies.length;
  c = await ctx();
  const p2 = buildPlan(c, 'isolate-networks', { sources: [netId(c.model, 'Servers')], destinations: [netId(c.model, 'IoT')] });
  assert.equal(p2.operations.filter((o) => o.kind === 'create').length, 0, 'no new rule');
  assert.ok(p2.analysis.some((a) => a.status === 'will-extend'));
  executor.remember(p2);
  assert.equal((await executor.apply(p2.id, client)).status, 'applied');
  assert.equal(transport.state.policies.length, count);
});

test('blocklist: first block creates list + rules, later blocks only add members', async () => {
  const { executor, ctx, client, transport } = await setup();
  let c = await ctx();
  const p1 = buildPlan(c, 'block-ip', { ips: ['45.142.193.6'], direction: 'both' });
  assert.ok(p1.operations.some((o) => o.objectType === 'firewall-group' && o.kind === 'create'));
  executor.remember(p1);
  const r1 = await executor.apply(p1.id, client);
  assert.equal(r1.status, 'applied', r1.error ?? '');
  const policies = transport.state.policies.length;

  c = await ctx();
  const p2 = buildPlan(c, 'block-ip', { ips: ['45.142.193.6', '218.92.0.112'], direction: 'both' });
  assert.equal(p2.analysis.find((a) => a.target === '45.142.193.6')?.status, 'already-covered');
  assert.equal(p2.operations.length, 2, 'only the inbound and outbound lists are updated');
  assert.ok(p2.operations.every((o) => o.objectType === 'firewall-group' && o.kind === 'update'));
  executor.remember(p2);
  assert.equal((await executor.apply(p2.id, client)).status, 'applied');
  assert.equal(transport.state.policies.length, policies);
});

test('blocking shared cloud / CDN addresses or large ranges comes with a warning', async () => {
  const { ctx } = await setup();
  const c = { ...(await ctx()), ownerOf: (ip: string) => (ip.startsWith('104.16.') ? 'Cloudflare, Inc.' : null) };
  const cdn = buildPlan(c, 'block-ip', { ips: ['104.16.1.1'], direction: 'both' });
  assert.ok(cdn.warnings.some((w) => /Cloudflare/.test(w) && /CDN/.test(w)));
  const wide = buildPlan(c, 'block-ip', { ips: ['198.51.100.0/22'], direction: 'inbound' });
  assert.ok(wide.warnings.some((w) => /1,024 addresses|1024 addresses/.test(w)));
  const single = buildPlan(c, 'block-ip', { ips: ['45.142.193.6'], direction: 'both' });
  assert.deepEqual(single.warnings, []);
});

test('a duplicate rule can be removed safely and the removal undone', async () => {
  const { executor, ctx, client, transport } = await setup();
  let c = await ctx();
  const dup = c.model.rules.find((r) => r.name === 'IoT no public DNS')!;
  const plan = buildPlan(c, 'remove-rule', { ruleId: dup.id });
  assert.equal(plan.operations.length, 1);
  assert.equal(plan.operations[0].method, 'DELETE');
  const keep = c.model.rules.find((r) => r.name === 'Block IoT DNS')!;
  assert.equal(buildPlan(c, 'remove-rule', { ruleId: keep.id }).operations.length, 0, 'the rule that does the work is never offered for removal');

  const before = transport.state.policies.length;
  executor.remember(plan);
  const rec = await executor.apply(plan.id, client);
  assert.equal(rec.status, 'applied', rec.error ?? '');
  assert.equal(transport.state.policies.length, before - 1);
  const undone = await executor.undo(rec.id, client);
  assert.equal(undone.status, 'undone', undone.error ?? '');
  assert.equal(transport.state.policies.length, before);
  c = await ctx();
  assert.ok(c.model.rules.some((r) => r.name === 'IoT no public DNS'));
});

test('test-network mode only ever touches the dedicated test network', async () => {
  const { executor, ctx, client, transport } = await setup();
  let c = { ...(await ctx()), testOnly: true };
  assert.ok(buildPlan(c, 'isolate-networks', { sources: [netId(c.model, 'IoT')], destinations: [netId(c.model, 'Default')] }).blockedReason, 'real source networks are refused');
  assert.ok(buildPlan(c, 'ips-mode', { mode: 'ips' }).blockedReason, 'site settings are refused');
  assert.ok(buildPlan(c, 'block-ip', { ips: ['45.142.193.6'] }).blockedReason, 'site-wide blocklists are refused');

  const create = buildPlan(c, 'create-test-network', {});
  assert.equal(create.blockedReason, null);
  assert.deepEqual(create.operations.map((o) => o.path.split('/').slice(-2).join('/')), ['firewall/zones', `${client.info.siteId}/networks`], 'zone first: a network must be created inside one');
  executor.remember(create);
  const rec = await executor.apply(create.id, client, 'test-network');
  assert.equal(rec.status, 'applied', rec.error ?? '');

  c = { ...(await ctx()), testOnly: true };
  const test = c.model.networks.find((n) => n.isTest)!;
  assert.ok(test, 'test network exists');
  assert.ok(!c.model.internal.subtract(test.addrs).overlaps(test.addrs), 'subnet does not overlap a real network');
  const policiesBefore = JSON.stringify(transport.state.policies.filter((p) => (p.metadata as { origin: string }).origin === 'USER_DEFINED'));

  const dns = buildPlan(c, 'block-external-dns', { networks: [test.id], includeDot: true });
  assert.equal(dns.blockedReason, null);
  assert.ok(dns.operations.every((o) => o.kind === 'create'), 'never modifies existing rules');
  executor.remember(dns);
  assert.equal((await executor.apply(dns.id, client, 'test-network')).status, 'applied');

  const iso = buildPlan({ ...(await ctx()), testOnly: true }, 'isolate-networks', { sources: [test.id], destinations: [netId(c.model, 'Default'), netId(c.model, 'Servers')] });
  assert.equal(iso.blockedReason, null);
  assert.equal(iso.noop, true, "the test network's own zone already blocks it from the real networks");
  executor.remember(iso);
  await assert.rejects(executor.apply(iso.id, client, 'test-network'), /nothing to change/, 'an empty plan is not recorded as a change');

  const gw = buildPlan({ ...(await ctx()), testOnly: true }, 'protect-gateway', { networks: [test.id] });
  assert.ok(gw.operations.length && gw.operations.every((o) => o.kind === 'create'));
  executor.remember(gw);
  assert.equal((await executor.apply(gw.id, client, 'test-network')).status, 'applied');

  const after = transport.state.policies.filter((p) => (p.metadata as { origin: string }).origin === 'USER_DEFINED');
  assert.equal(JSON.stringify(after.slice(0, JSON.parse(policiesBefore).length)), policiesBefore, 'pre-existing rules are byte-for-byte unchanged');
});

test('gateway management counts as protected once SSH, HTTP and HTTPS are blocked', async () => {
  const { executor, ctx, client } = await setup();
  let c = await ctx();
  const iot = netId(c.model, 'IoT');
  const reach = () => reachableGatewayMgmt(c.model, c.model.networks.find((n) => n.id === iot)!);
  assert.deepEqual(reach(), ['SSH (22)', 'HTTP (80)', 'the web UI (443)']);

  const plan = buildPlan(c, 'protect-gateway', { networks: [iot] });
  executor.remember(plan);
  const rec = await executor.apply(plan.id, client);
  assert.equal(rec.status, 'applied', rec.error ?? '');
  c = await ctx();
  assert.deepEqual(reach(), [], 'port 8443 staying open is not reachable management');
  assert.equal(buildMatrix(c.model).cells.find((x) => x.from === iot && x.to === 'gateway')!.fix, null);
  const card = assessTemplates(c).find((s) => s.templateId === 'protect-gateway')!;
  assert.equal(card.targets.find((t) => t.id === iot)!.state, 'covered');
});

test('coverage messages keep protocol names in capitals', async () => {
  const { ctx } = await setup();
  const c = await ctx();
  const dns = assessTemplates(c).find((s) => s.templateId === 'block-external-dns')!;
  const iot = dns.targets.find((t) => t.name === 'IoT')!;
  assert.match(iot.detail, /still allowed/);
  assert.doesNotMatch(iot.detail, /— [a-z][A-Z]/, iot.detail);
});

test('the test network avoids subnets reached through a site-to-site VPN', async () => {
  const { ctx, transport } = await setup();
  transport.state.networkconf.push({ _id: 'vpn-site', name: 'Remote office', purpose: 'site-vpn', remote_vpn_subnets: ['10.254.254.0/24'] });
  const net = buildPlan(await ctx(), 'create-test-network', {}).operations.find((o) => o.id === 'NET')!;
  assert.match(net.description, /10\.253\.253\.0\/24/, net.description);
});

test('a button that needs a TCP and a UDP rule describes both parts', async () => {
  const { executor, ctx, client } = await setup();
  let c = await ctx();
  const iot = netId(c.model, 'IoT');
  const plan = buildPlan(c, 'block-risky-outbound', { networks: [iot] });
  const row = plan.analysis.find((a) => a.target === 'IoT')!;
  assert.equal(plan.operations.filter((o) => o.kind === 'create').length, 2);
  assert.match(row.message, /TCP .* and UDP .* are still allowed\. New rules will block it\./, row.message);

  executor.remember(plan);
  assert.equal((await executor.apply(plan.id, client)).status, 'applied');
  c = await ctx();
  const again = buildPlan(c, 'block-risky-outbound', { networks: [iot] }).analysis.find((a) => a.target === 'IoT')!;
  assert.equal(again.rules.length, 2, 'both new rules are named');
  assert.match(again.message, /\(TCP\)”, “.*\(UDP\)”/, again.message);
});

test('undoing the test network first undoes the later changes that use it', async () => {
  const { executor, ctx, client, transport } = await setup();
  const before = { policies: transport.state.policies.length, networks: transport.state.networks.length, zones: transport.state.zones.length };
  const run = async (templateId: string, params: Record<string, unknown>) => {
    const plan = buildPlan({ ...(await ctx()), testOnly: true }, templateId, params);
    executor.remember(plan);
    const rec = await executor.apply(plan.id, client, 'test-network');
    assert.equal(rec.status, 'applied', rec.error ?? '');
    return rec;
  };
  const net = await run('create-test-network', {});
  const test = (await ctx()).model.networks.find((n) => n.isTest)!;
  const dns = await run('block-external-dns', { networks: [test.id], includeDot: false });
  const widen = await run('block-external-dns', { networks: [test.id], includeDot: true });
  const ips = buildPlan(await ctx(), 'ips-mode', { mode: 'ips' });
  executor.remember(ips);
  const unrelated = await executor.apply(ips.id, client);

  assert.deepEqual(executor.dependents(net.id).map((r) => r.id), [widen.id, dns.id], 'newest first; the widen counts through the rule it updates; the IPS change is not involved');
  const rec = await executor.undoCascade(net.id, client);
  assert.equal(rec.status, 'undone', rec.error ?? '');
  assert.ok([dns.id, widen.id].every((id) => executor.get(id)!.status === 'undone'));
  assert.equal(executor.get(unrelated.id)!.status, 'applied');
  assert.deepEqual({ policies: transport.state.policies.length, networks: transport.state.networks.length, zones: transport.state.zones.length }, before);
});

test('settings changes carry only the changed fields, never the whole document', async () => {
  const { executor, ctx, client, transport } = await setup();
  const ips = transport.state.settings.find((s) => s.key === 'ips')!;
  ips.utm_token = 'secret-token';
  const plan = buildPlan(await ctx(), 'ips-mode', { mode: 'ips' });
  assert.deepEqual(plan.operations[0].body, { ips_mode: 'ips' });
  assert.deepEqual(plan.operations[0].before, { ips_mode: 'ids' });
  executor.remember(plan);
  const rec = await executor.apply(plan.id, client);
  assert.equal(rec.status, 'applied', rec.error ?? '');
  assert.ok(!JSON.stringify(executor.get(rec.id)).includes('secret-token'), 'the Change Log never stores secrets from the settings document');
  assert.equal(ips.ips_mode, 'ips');
  assert.equal(ips.utm_token, 'secret-token', 'fields outside the change are kept');
  assert.equal((await executor.undo(rec.id, client)).status, 'undone');
  assert.equal(ips.ips_mode, 'ids');
});

test('country rules grow their own rule instead of piling up rules', async () => {
  const { executor, ctx, client, transport } = await setup();
  let c = await ctx();
  const exposed = assessTemplates(c).find((s) => s.templateId === 'block-countries')!;
  assert.ok(exposed.targets.length > 0, 'the simulated network exposes services through port forwards');
  const zone = exposed.targets[0].id;

  const p1 = buildPlan(c, 'block-countries', { countries: ['ru', 'CN'], zones: [zone] }, 'create');
  assert.equal(p1.operations.length, 1);
  const body = p1.operations[0].body as { source: { trafficFilter: unknown }; connectionStateFilter: string[] };
  assert.deepEqual(body.source.trafficFilter, { type: 'REGION', regionFilter: { regions: ['CN', 'RU'] } });
  assert.deepEqual(body.connectionStateFilter, ['NEW', 'INVALID'], 'replies to connections your devices start keep working');
  executor.remember(p1);
  assert.equal((await executor.apply(p1.id, client)).status, 'applied');

  c = await ctx();
  assert.equal(buildPlan(c, 'block-countries', { countries: ['CN'], zones: [zone] }, 'create').noop, true, 'already blocked');
  const count = transport.state.policies.length;
  const p2 = buildPlan(c, 'block-countries', { countries: ['CN', 'KP'], zones: [zone] }, 'create');
  assert.equal(p2.operations[0].kind, 'update', 'KP is added to the existing rule');
  executor.remember(p2);
  assert.equal((await executor.apply(p2.id, client)).status, 'applied');
  assert.equal(transport.state.policies.length, count);

  c = await ctx();
  const card = assessTemplates(c).find((s) => s.templateId === 'block-countries')!;
  assert.equal(card.targets.find((t) => t.id === zone)!.state, 'covered');
  assert.match(card.targets.find((t) => t.id === zone)!.detail, /CN, KP, RU/);
  assert.ok(buildPlan({ ...c, testOnly: true }, 'block-countries', { countries: ['CN'], zones: [zone] }, 'create').blockedReason, 'test-network mode refuses real zones');
});

test('country blocking uses UniFi Region Blocking first, without duplicate rules', async () => {
  const { executor, ctx, client, transport } = await setup();
  const geo = () => transport.state.settings.find((x) => x.key === 'usg_geo')!;
  const filtering = (o: { body?: unknown }) => (o.body as { ip_filtering: unknown }).ip_filtering;
  const card = async () => assessTemplates(await ctx()).find((x) => x.templateId === 'block-countries')!;
  let c = await ctx();
  assert.equal((await card()).state, 'not-applied');
  assert.match((await card()).detail, /Region Blocking is off/);

  // Off: turned on for incoming connections, with just the countries picked.
  const p1 = buildPlan(c, 'block-countries', { countries: ['ru', 'KP'], zones: [] });
  assert.equal(p1.operations.length, 1);
  assert.equal(p1.operations[0].objectType, 'setting');
  assert.deepEqual(filtering(p1.operations[0]), { action: 'block', countries: 'KP,RU', enabled: true, traffic_direction: 'ingress' });
  assert.deepEqual(p1.alternatives.map((a) => a.strategy), ['update', 'create'], 'rules per zone stay available');
  assert.match(buildPlan({ ...c, testOnly: true }, 'block-countries', { countries: ['RU'] }).blockedReason ?? '', /whole network/, 'test-network mode never changes a site-wide setting');
  executor.remember(p1);
  const rec = await executor.apply(p1.id, client);
  assert.equal(rec.status, 'applied', rec.error ?? '');

  const on = await card();
  assert.equal(on.state, 'applied', 'Region Blocking covers every zone the internet can reach');
  assert.equal(on.targets[0].id, 'region-blocking');
  assert.match(on.targets[0].detail, /incoming connections from 2 countries .KP, RU./);
  assert.ok(on.targets.length > 1 && on.targets.every((t) => t.state === 'covered'));
  c = await ctx();
  const again = buildPlan(c, 'block-countries', { countries: ['RU'], zones: [] });
  assert.equal(again.noop, true, 'already blocked, so nothing (and no duplicate rule) is added');
  assert.equal(again.alternatives.length, 0);
  assert.equal((await executor.undo(rec.id, client)).status, 'undone');
  assert.equal((geo().ip_filtering as { enabled: boolean }).enabled, false, 'undo turns it back off');

  // On: missing countries go after yours, and the direction stays.
  geo().ip_filtering = { action: 'block', countries: 'RU,KP', enabled: true, traffic_direction: 'both' };
  c = await ctx();
  const p2 = buildPlan(c, 'block-countries', { countries: ['CN', 'KP'] });
  assert.deepEqual(filtering(p2.operations[0]), { action: 'block', countries: 'RU,KP,CN', enabled: true, traffic_direction: 'both' });
  assert.match(p2.analysis[0].message, /won't reach CN either/);
  // An edit made in UniFi after the preview is never overwritten.
  executor.remember(p2);
  geo().ip_filtering = { action: 'block', countries: 'RU,KP,IR', enabled: true, traffic_direction: 'both' };
  const stale = await executor.apply(p2.id, client);
  assert.equal(stale.status, 'failed');
  assert.match(stale.error ?? '', /changed in UniFi/);
  assert.equal((geo().ip_filtering as { countries: string }).countries, 'RU,KP,IR');

  // Outgoing only: it is made to filter incoming connections too.
  geo().ip_filtering = { action: 'block', countries: 'CN', enabled: true, traffic_direction: 'egress' };
  c = await ctx();
  assert.equal((await card()).state, 'not-applied', 'outgoing-only Region Blocking does not protect what you expose');
  assert.deepEqual(filtering(buildPlan(c, 'block-countries', { countries: ['CN'] }).operations[0]), { action: 'block', countries: 'CN', enabled: true, traffic_direction: 'both' });

  // An allow list already blocks every other country; one on the list is left to you.
  geo().ip_filtering = { action: 'allow', countries: 'US,CA', enabled: true, traffic_direction: 'ingress' };
  c = await ctx();
  assert.equal(buildPlan(c, 'block-countries', { countries: ['CN'] }).noop, true);
  const p3 = buildPlan(c, 'block-countries', { countries: ['US'] });
  assert.equal(p3.state, 'unavailable');
  assert.equal(p3.operations.length, 0);
  assert.equal(p3.alternatives.length, 2);

  // Rules per zone on request, with a warning when Region Blocking already does the job.
  const zone = (await card()).targets.find((t) => t.id !== 'region-blocking')!.id;
  const rules = buildPlan(c, 'block-countries', { countries: ['CN'], zones: [zone] }, 'create');
  assert.equal(rules.operations[0].objectType, 'firewall-policy');
  assert.match(rules.warnings.join(' '), /already blocks CN/);
});

test('a preview applies once, stale previews are refused, and changes undo safely', async () => {
  const { executor, ctx, client, transport } = await setup();
  let c = await ctx();
  const p = buildPlan(c, 'block-internet', { networks: [netId(c.model, 'Cameras')] });
  const stale = buildPlan(c, 'protect-gateway', { networks: [netId(c.model, 'IoT')] });
  executor.remember(p);
  executor.remember(stale);
  const rec = await executor.apply(p.id, client);
  assert.equal(rec.status, 'applied', rec.error ?? '');
  await assert.rejects(executor.apply(p.id, client), /expired/, 'a double click does not create the rule twice');
  await assert.rejects(executor.apply(stale.id, client), /changed after this preview/);

  // Two changes to the same setting: the older one can only be undone after the newer one.
  const ips = transport.state.settings.find((s) => s.key === 'ips')!;
  c = await ctx();
  const up = buildPlan(c, 'ips-mode', { mode: 'ips' });
  executor.remember(up);
  const a = await executor.apply(up.id, client);
  c = await ctx();
  const down = buildPlan(c, 'ips-mode', { mode: 'ids' });
  executor.remember(down);
  const b = await executor.apply(down.id, client);
  assert.deepEqual(executor.dependents(a.id).map((r) => r.id), [b.id]);
  assert.equal((await executor.undoCascade(a.id, client)).status, 'undone');
  assert.equal(ips.ips_mode, 'ids', 'back to the original value');

  // The rule was deleted in UniFi meanwhile: undoing its creation still completes.
  transport.state.policies = transport.state.policies.filter((x) => x.id !== rec.operations[0].resultId);
  assert.equal((await executor.undo(rec.id, client)).status, 'undone');

  // A step fails halfway: the steps that already ran are rolled back.
  c = await ctx();
  const before = transport.state.policies.length;
  const two = buildPlan(c, 'block-internet', { networks: [netId(c.model, 'IoT')] });
  two.operations.push({ ...two.operations[0], id: 'broken', body: { name: 'missing required fields' } });
  executor.remember(two);
  const failed = await executor.apply(two.id, client);
  assert.equal(failed.status, 'failed');
  assert.match(failed.error ?? '', /rolled back/);
  assert.equal(transport.state.policies.length, before);
});

test('settings templates and status cards', async () => {
  const { executor, ctx, client, transport } = await setup();
  let c = await ctx();
  const cards = assessTemplates(c);
  assert.equal(cards.find((s) => s.templateId === 'ips-mode')?.state, 'partial');
  assert.equal(cards.find((s) => s.templateId === 'disable-upnp')?.state, 'not-applied');
  const iso = cards.find((s) => s.templateId === 'isolate-networks')!;
  assert.ok(iso.targets.some((t) => t.name === 'IoT → Default' && t.state === 'missing'));

  const plan = buildPlan(c, 'ips-mode', { mode: 'ips' });
  executor.remember(plan);
  assert.equal((await executor.apply(plan.id, client)).status, 'applied');
  assert.equal(transport.state.settings.find((s) => s.key === 'ips')!.ips_mode, 'ips');
  c = await ctx();
  assert.equal(buildPlan(c, 'ips-mode', { mode: 'ips' }).noop, true);
});

test('the test network never counts toward a status card, and a block you chose yourself shows as done', async () => {
  const { executor, ctx, client } = await setup();
  const apply = async (templateId: string, params: Record<string, unknown>, mode?: 'test-network') => {
    const plan = buildPlan({ ...(await ctx()), testOnly: mode === 'test-network' }, templateId, params);
    executor.remember(plan);
    const rec = await executor.apply(plan.id, client, mode);
    assert.equal(rec.status, 'applied', rec.error ?? '');
    return rec;
  };
  const card = async (id: string) => assessTemplates(await ctx()).find((s) => s.templateId === id)!;
  const before = await card('block-external-dns');
  await apply('create-test-network', {}, 'test-network');
  const test = (await ctx()).model.networks.find((n) => n.isTest)!;
  await apply('block-external-dns', { networks: [test.id], includeDot: true }, 'test-network');
  const dns = await card('block-external-dns');
  assert.equal(dns.state, before.state, 'protecting only the test network changes nothing for the real networks');
  assert.equal(dns.label, before.label);
  assert.ok(dns.targets.some((t) => t.id === test.id && t.test && t.state === 'covered'), 'the page can still say "Done on SC-Test"');
  assert.ok(!(dns.suggestedParams.networks as string[]).includes(test.id), 'suggested fixes name real networks only');

  const iot = netId((await ctx()).model, 'IoT');
  assert.ok(!(await card('block-internet')).targets.some((t) => t.id === iot));
  await apply('block-internet', { networks: [iot] });
  assert.ok((await card('block-internet')).targets.some((t) => t.id === iot && t.state === 'covered'), 'IoT is not a camera network, but its block shows');
});

test('an incomplete choice asks for input, and the Change Log keeps what happened in the past tense', async () => {
  const { executor, ctx, client } = await setup();
  const c = await ctx();
  const empty = buildPlan(c, 'block-internet', { networks: [] });
  assert.equal(empty.noop, true);
  assert.equal(empty.state, 'needs-input', 'not "already protected"');
  assert.equal(buildPlan(c, 'remove-rule', { ruleId: 'no-such-rule' }).state, 'unavailable');
  assert.equal(buildPlan(c, 'disable-upnp', {}).state, undefined);

  const plan = buildPlan(c, 'block-internet', { networks: [netId(c.model, 'IoT')] });
  assert.equal(plan.summary, 'IoT will be handled by updating existing rules.');
  executor.remember(plan);
  const rec = await executor.apply(plan.id, client);
  assert.equal(rec.summary, 'Existing rules were updated to cover IoT.');
});

test('widening a rule to every port drops its old port filter', () => {
  const portFilter = { type: 'PORTS', matchOpposite: false, items: [{ type: 'PORT_NUMBER', value: 53 }] };
  const base = { id: 'p1', source: { zoneId: 'a' }, ipProtocolScope: { ipVersion: 'IPV4', protocolFilter: { type: 'NAMED_PROTOCOL', protocol: { name: 'UDP' } } } };
  const portOnly = withService('integration', { ...base, destination: { zoneId: 'b', trafficFilter: { type: 'PORT', portFilter } } }, { protocol: 'all', ports: null });
  assert.equal((portOnly.destination as Record<string, unknown>).trafficFilter, undefined);
  assert.equal((portOnly.ipProtocolScope as Record<string, unknown>).protocolFilter, undefined);
  const withIps = withService('integration', { ...base, destination: { zoneId: 'b', trafficFilter: { type: 'IP_ADDRESS', ipAddressFilter: { type: 'IP_ADDRESSES', items: [] }, portFilter } } }, { protocol: 'tcp_udp', ports: null });
  const tf = (withIps.destination as Record<string, Record<string, unknown>>).trafficFilter;
  assert.equal(tf.type, 'IP_ADDRESS', 'the address part stays');
  assert.equal(tf.portFilter, undefined);
  const v2 = withService('internal-v2', { destination: { port_matching_type: 'SPECIFIC', port: '53' } }, { protocol: 'all', ports: null });
  assert.deepEqual(v2.destination, { port_matching_type: 'ANY' });
});

test('blocking an address inbound never also blocks your devices from reaching it', async () => {
  const { executor, ctx, client } = await setup();
  const run = async (ips: string[], direction: string) => {
    const plan = buildPlan(await ctx(), 'block-ip', { ips, direction });
    executor.remember(plan);
    const rec = await executor.apply(plan.id, client);
    assert.equal(rec.status, 'applied', rec.error ?? '');
  };
  await run(['45.142.193.6'], 'inbound');
  await run(['218.92.0.112'], 'outbound');
  const c = await ctx();
  assert.equal(buildPlan(c, 'block-ip', { ips: ['45.142.193.6'], direction: 'outbound' }).noop, false, 'the inbound block did not spread to outbound');
  assert.equal(buildPlan(c, 'block-ip', { ips: ['218.92.0.112'], direction: 'inbound' }).noop, false, 'nor the outbound one to inbound');
  assert.equal(buildPlan(c, 'block-ip', { ips: ['45.142.193.6'], direction: 'inbound' }).noop, true);
  assert.equal(buildPlan(c, 'block-ip', { ips: ['218.92.0.112'], direction: 'outbound' }).noop, true);
});

test('legacy rules: a DNS server exception is numbered before the blocks it has to survive', () => {
  const body = () => ({}) as Record<string, number>;
  const model = (indexes: number[]) => ({ rules: indexes.map((index) => ({ chain: 'LAN_IN', index })) }) as unknown as Parameters<typeof assignLegacyIndexes>[0];

  // The reported case: an empty ruleset, two new blocks created before the exception in the plan.
  const [a, b, ex] = [body(), body(), body()];
  assert.equal(assignLegacyIndexes(model([]), [
    { chain: 'LAN_IN', kind: 'block', bound: Infinity, body: a },
    { chain: 'LAN_IN', kind: 'block', bound: Infinity, body: b },
    { chain: 'LAN_IN', kind: 'exception', bound: Infinity, body: ex },
  ]), null);
  assert.ok(ex.rule_index < a.rule_index && ex.rule_index < b.rule_index, `exception ${ex.rule_index}, blocks ${a.rule_index}/${b.rule_index}`);

  // A block that must override an allow at 2005 lands just below it, still after the exception.
  const [ex2, before] = [body(), body()];
  assert.equal(assignLegacyIndexes(model([2005]), [
    { chain: 'LAN_IN', kind: 'block', bound: 2005, body: before },
    { chain: 'LAN_IN', kind: 'exception', bound: Infinity, body: ex2 },
  ]), null);
  assert.ok(ex2.rule_index < before.rule_index && before.rule_index < 2005);

  // No room before a rule at 2000: refused, never quietly placed after it.
  assert.match(assignLegacyIndexes(model([2000]), [{ chain: 'LAN_IN', kind: 'exception', bound: 2000, body: body() }]) ?? '', /no free rule index/);
  assert.match(assignLegacyIndexes(model([2000]), [{ chain: 'LAN_IN', kind: 'block', bound: 2000, body: body() }]) ?? '', /before rule index 2000/);
});

test('an IPv4-only rule is never "extended" to close an IPv6 gap', async () => {
  const { ctx, transport } = await setup();
  transport.state.networkconf.find((n) => n.name === 'Cameras')!.ipv6_subnet = '2001:db8:40::1/64';
  const c0 = await ctx();
  const cams = c0.model.networks.find((n) => n.name === 'Cameras')!;
  const ext = c0.model.zones.find((z) => z.key === 'external')!;
  const v4Only = '00000000-0000-4000-8000-0000000000aa';
  transport.state.policies.push({
    id: v4Only, name: 'No internet for cameras (IPv4)', description: '', enabled: true, action: { type: 'BLOCK' },
    source: { zoneId: cams.zoneId, trafficFilter: { type: 'NETWORK', networkFilter: { networkIds: [cams.id], matchOpposite: false } } },
    destination: { zoneId: ext.id }, ipProtocolScope: { ipVersion: 'IPV4' }, loggingEnabled: false, index: 9000, metadata: { origin: 'USER_DEFINED' },
  });
  const plan = buildPlan(await ctx(), 'block-internet', { networks: [cams.id] });
  const row = plan.analysis.find((a) => a.target === 'Cameras')!;
  assert.notEqual(row.status, 'will-extend', row.message);
  assert.ok(!plan.operations.some((o) => o.targetId === v4Only), 'the IPv4-only rule is left alone: changing it would not close the gap');
  assert.ok(plan.operations.some((o) => o.kind === 'create'), 'a new rule closes the IPv6 gap');
});

test('change records saved in the future tense read in the past tense; newer ones are left alone', () => {
  assert.equal(pastTense('SC-Test will get a new rule.'), 'SC-Test got a new rule.');
  assert.equal(pastTense('IoT is already protected; Default will be handled by updating existing rules; Guest will get a new rule.'), 'IoT was already protected; existing rules were updated to cover Default; Guest got a new rule.');
  assert.equal(pastTense('Switch Intrusion Prevention to Notify and Block.'), 'Switched Intrusion Prevention to Notify and Block.');
  assert.equal(pastTense('45.142.193.6 will be blocked with a managed blocklist and 6 rules. Later blocks only add addresses to the list.'), 'Blocked 45.142.193.6 with a managed blocklist and 6 rules.');
  for (const current of ['IoT got a new rule.', 'Disabled port forward “RDP”.', 'Existing rules were updated to cover IoT.', 'Added 1.2.3.4 to your managed inbound blocklist.']) assert.equal(pastTense(current), current);
});

test('every rule in a preview comes with a field-by-field view of how it will look in UniFi', async () => {
  const { ctx } = await setup();
  const c = await ctx();
  const plan = buildPlan(c, 'block-external-dns', { networks: ['IoT', 'Guest', 'Default'].map((n) => netId(c.model, n)), includeDot: true, allowedServers: [] });
  const changed = plan.operations.find((o) => o.kind === 'update')!.detail!;
  assert.deepEqual(changed.changes?.map((x) => x.field), ['Source', 'Destination ports', 'Protocol'], 'a changed rule lists exactly what changes');
  assert.deepEqual(changed.changes?.[0], { field: 'Source', from: 'Networks: IoT', to: 'Networks: IoT, Default' });
  const created = plan.operations.find((o) => o.kind === 'create')!.detail!;
  assert.deepEqual([created.action, created.source.zone, created.source.match, created.destination.ports, created.protocol], ['Block', 'Hotspot', 'Networks: Guest', '53, 853', 'TCP and UDP']);
  assert.match(created.position ?? '', /After your existing rules in Hotspot → External/);

  const blocklist = buildPlan(c, 'block-ip', { ips: ['45.142.193.6'], direction: 'inbound' });
  const inbound = blocklist.operations.find((o) => o.detail?.change === 'create')!.detail!;
  assert.equal(inbound.source.match, 'IP group: “[SC] Blocklist (inbound) (new)”', 'a list created by the same change is named');
});

test('a rule this app made is renamed when reusing it changes its job; your own rules keep their names', async () => {
  const { executor, ctx, client } = await setup();
  const run = async (templateId: string, params: Record<string, unknown>) => {
    const plan = buildPlan({ ...(await ctx()), testOnly: true }, templateId, params);
    executor.remember(plan);
    assert.equal((await executor.apply(plan.id, client, 'test-network')).status, 'applied');
  };
  await run('create-test-network', {});
  const test = (await ctx()).model.networks.find((n) => n.isTest)!;
  await run('block-external-dns', { networks: [test.id], includeDot: true });
  const internet = buildPlan({ ...(await ctx()), testOnly: true }, 'block-internet', { networks: [test.id] });
  const widen = internet.operations.find((o) => o.kind === 'update' && o.detail)!;
  assert.equal(widen.detail!.name, `[SC] No internet: ${test.name}`);
  assert.deepEqual(widen.detail!.changes?.find((c) => c.field === 'Name'), { field: 'Name', from: '[SC] Block external DNS', to: `[SC] No internet: ${test.name}` });

  const own = buildPlan(await ctx(), 'block-external-dns', { networks: [netId((await ctx()).model, 'IoT')], includeDot: true });
  assert.equal(own.operations.find((o) => o.kind === 'update')!.detail!.name, 'Block IoT DNS', 'your rule is widened but never renamed');
});

test('undo is not fooled by UniFi storing a list in its own order, but still stops for a real edit', async () => {
  const { executor, ctx, client, transport } = await setup();
  const apply = async () => {
    const c = await ctx();
    const plan = buildPlan(c, 'block-external-dns', { networks: [netId(c.model, 'IoT')], includeDot: true });
    const update = plan.operations.find((o) => o.kind === 'update')!;
    executor.remember(plan);
    const rec = await executor.apply(plan.id, client);
    assert.equal(rec.status, 'applied', rec.error ?? '');
    const ports = () => (transport.state.policies.find((p) => p.id === update.targetId)!.destination as { trafficFilter: { portFilter: { items: { value: number }[] } } }).trafficFilter.portFilter.items;
    return { rec, ports };
  };

  const first = await apply();
  assert.deepEqual(first.ports().map((p) => p.value), [53, 853]);
  first.ports().reverse(); // what the real controller does: same ports, its own order
  const undone = await executor.undo(first.rec.id, client);
  assert.equal(undone.status, 'undone', undone.error ?? '');

  const second = await apply();
  second.ports().splice(1, 1); // someone removed port 853 in UniFi
  const refused = await executor.undo(second.rec.id, client);
  assert.notEqual(refused.status, 'undone');
  assert.match(JSON.stringify(refused), /changed in UniFi after this change/);
});

test('removing a test zone waits while UniFi is still letting go of its network', async () => {
  const db = new DatabaseSync(':memory:');
  db.exec('CREATE TABLE changes (id TEXT PRIMARY KEY, ts INTEGER NOT NULL, data TEXT NOT NULL)');
  const executor = new ChangeExecutor(db);
  executor.retryDelayMs = 1;
  let attempts = 0;
  const client = {
    request: async (method: string, path: string) => {
      if (method === 'DELETE' && path.endsWith('/firewall/zones/z1') && attempts++ === 0) throw new UniFiHttpError(422, path, '', 'UniFi API 422: api.firewall.zone.network-does-not-exist: Configured network does not exist');
      return {};
    },
  } as unknown as UniFiClient;
  const rec = {
    id: 'c1', ts: 1, planId: 'p', templateId: 'create-test-network', title: 'Create a test network', summary: '', status: 'applied', undoable: true, undoneAt: null, error: null,
    operations: [{ id: 'ZONE', kind: 'create', objectType: 'network', method: 'POST', api: 'integration', path: '/proxy/network/integration/v1/sites/s/firewall/zones', description: 'zone', status: 'ok', resultId: 'z1' }],
  };
  db.prepare('INSERT INTO changes (id, ts, data) VALUES (?, ?, ?)').run(rec.id, rec.ts, JSON.stringify(rec));
  const out = await executor.undo('c1', client);
  assert.equal(out.status, 'undone', out.error ?? '');
  assert.equal(attempts, 2, 'refused once, then deleted on the retry');
});

test('"Log matches" turns on logging for every rule a change creates or changes', async () => {
  const { executor, ctx, client, transport } = await setup();
  const c = await ctx();
  const params = { networks: ['IoT', 'Guest', 'Default'].map((n) => netId(c.model, n)), includeDot: true, allowedServers: ['192.168.20.53'] };
  const isOrdering = (o: { path: string }) => o.path.includes('/ordering') || o.path.includes('batch-reorder');
  const body = (o: { body?: unknown }) => o.body as Record<string, unknown>;
  const plain = buildPlan(c, 'block-external-dns', params);
  assert.ok(plain.operations.filter((o) => o.kind === 'create').every((o) => body(o).loggingEnabled === false), 'off unless asked');

  const logged = buildPlan(c, 'block-external-dns', { ...params, log: true });
  const rules = logged.operations.filter((o) => !isOrdering(o));
  assert.deepEqual(rules.map((o) => o.kind).sort(), ['create', 'update'], 'the new rule and the widened one');
  assert.ok(rules.every((o) => body(o).loggingEnabled === true && o.detail?.logging === true));
  assert.ok(rules.find((o) => o.kind === 'update')!.detail?.changes?.some((x) => x.field === 'Logging' && x.to === 'On'), 'the preview shows the change');
  assert.ok(logged.operations.filter(isOrdering).every((o) => !('loggingEnabled' in body(o))), 'rule ordering steps are left alone');

  executor.remember(logged);
  assert.equal((await executor.apply(logged.id, client)).status, 'applied');
  const created = transport.state.policies.filter((x) => String(x.name ?? '').startsWith('[SC]') && x.loggingEnabled === true);
  assert.ok(created.length > 0, 'UniFi gets the logging flag');

  // Region Blocking is a setting, not a rule: nothing to log, and the preview says so.
  assert.match(buildPlan(c, 'block-countries', { countries: ['RU'], log: true }).warnings.join(' '), /only applies to rules/);
});
