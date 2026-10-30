import { test } from 'node:test';
import assert from 'node:assert/strict';
import { FakeConsole } from '../testing/fakeConsole.ts';
import { UniFiClient } from '../unifi/client.ts';
import { collect } from '../unifi/collect.ts';
import { buildModel } from './normalize.ts';
import { buildMatrix } from './segmentation.ts';
import { fetchBlockedFlows, parseBlockedFlow, summarizeBlocked } from './blockedFlows.ts';

async function sim() {
  const client = new UniFiClient(new FakeConsole(), 'default');
  await client.connect();
  const raw = await collect(client);
  return { client, model: buildModel(raw, new Map()) };
}

test('only connections the firewall blocked from your own networks are read', () => {
  const base = {
    action: 'blocked', direction: 'local', protocol: 'TCP', time: 1, count: 2, policies: [{ type: 'FIREWALL' }],
    source: { ip: '192.168.40.100', client_name: 'aa:bb:cc:00:11:22' }, destination: { ip: '192.168.10.130', port: 7655, client_name: 'monitor' },
  };
  const f = parseBlockedFlow(base)!;
  assert.deepEqual([f.srcName, f.dstName, f.port, f.count], [null, 'monitor', 7655, 2], 'a MAC address is not a name');
  assert.equal(parseBlockedFlow({ ...base, action: 'allowed' }), null);
  assert.equal(parseBlockedFlow({ ...base, policies: [{ type: 'INTRUSION_PREVENTION' }] }), null, 'intrusion prevention has its own page');
  assert.equal(parseBlockedFlow({ ...base, direction: 'incoming' }), null, 'traffic from the internet is not a matrix row');
});

test('blocked traffic lands in its matrix cell, and a rule with the wrong port stands out', async () => {
  const { client, model } = await sim();
  const now = Date.now();
  const { flows, truncated } = await fetchBlockedFlows(client, now - 86400e3, now);
  assert.equal(truncated, false);
  const names = new Map([['192.168.20.30', 'Synology-NAS']]);
  const b = summarizeBlocked(model, flows, { from: now - 86400e3, to: now }, (ip) => names.get(ip) ?? null);
  const m = buildMatrix(model);
  const id = (n: string) => m.endpoints.find((e) => e.name === n)!.id;

  const cams = b.cells[`${id('Cameras')}>${id('Servers')}`];
  assert.equal(cams.nearMisses, 1);
  const doorbell = cams.groups[0];
  assert.deepEqual([doorbell.source.name, doorbell.destination?.name, doorbell.protocol, doorbell.port], ['Doorbell', 'Synology-NAS', 'TCP', 445]);
  assert.ok(doorbell.count >= 140);
  assert.match(doorbell.nearMiss?.reason ?? '', /“Allow Doorbell to NAS” allows these devices, but not TCP 445: it allows TCP 21/);
  assert.equal(cams.groups[1].nearMiss, null, 'the camera asking Pi-hole has no rule it almost matches');

  const dns = b.cells[`${id('IoT')}>internet`];
  assert.deepEqual(dns.groups.map((g) => g.examples[0]).sort(), ['8.8.4.4', '8.8.8.8'], 'towards the internet, destinations are examples');
  assert.equal(dns.groups[0].destination, null);
  assert.ok(b.cells[`${id('Guest')}>${id('Default')}`].total >= 12);
  for (const key of Object.keys(b.cells)) assert.ok(m.cells.some((c) => `${c.from}>${c.to}` === key), `${key} is a matrix cell`);
});

test('a rule that allows the port but to another address is a near miss too', async () => {
  const { model } = await sim();
  // The Plex rule lets IoT reach 192.168.20.20 on TCP 32400; this TV asks another server on that port.
  const flow = { srcIp: '192.168.30.21', srcName: null, srcNet: null, dstIp: '192.168.20.99', dstName: null, dstNet: null, dstZone: 'Internal', port: 32400, protocol: 'TCP', direction: 'local', time: 1, count: 3 };
  const g = Object.values(summarizeBlocked(model, [flow], { from: 0, to: 2 }).cells)[0].groups[0];
  assert.match(g.nearMiss?.reason ?? '', /“Allow IoT to Plex” allows TCP 32400 from this device, but only to .*192\.168\.20\.20/);
  // A VPN client (no matrix row) is left out rather than guessed.
  assert.deepEqual(summarizeBlocked(model, [{ ...flow, srcIp: '10.99.100.5' }], { from: 0, to: 2 }).cells, {});
});
