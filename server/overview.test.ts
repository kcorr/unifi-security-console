import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { ExposureItem } from '../shared/types.ts';
import type { RawSnapshot } from './unifi/collect.ts';
import { deviceIssues, newDevices, waysIn } from './overview.ts';

const raw = (p: Partial<RawSnapshot>): RawSnapshot => ({
  fetchedAt: 0, firewallMode: 'zone', firewallSource: 'integration', iNetworks: [], iZones: [], iPolicies: [], iLists: [], iWifi: [], iDevices: [], iClients: [],
  networkconf: [], v2Zones: [], v2Policies: [], legacyRules: [], firewallGroups: [], trafficRules: [], portForwards: [], wlans: [], settings: {}, devices: [],
  clients: [], health: [], vpnSessions: null, capabilities: [], errors: [],
  ...p,
});

const forward = (id: string, p: Partial<ExposureItem>): ExposureItem => ({
  id, kind: 'port-forward', name: id, enabled: true, externalPort: '443', internalTarget: '10.0.0.5:443', internalName: null, protocol: 'TCP', sourceRestriction: null,
  severity: 'low', risk: '', services: [], fix: null,
  ...p,
});

test('ways in: open port forwards with their attacks and VPN servers, never outgoing VPN clients or disabled doors', () => {
  const r = raw({
    portForwards: [{ _id: 'pf1', fwd: '192.168.40.6' }, { _id: 'pf2', fwd: '192.168.40.7' }, { _id: 'pf3', fwd: '192.168.40.8' }],
    networkconf: [
      { _id: 'n1', name: 'Home VPN', purpose: 'remote-user-vpn', vpn_type: 'wireguard-server', enabled: true },
      { _id: 'n2', name: 'Provider VPN', purpose: 'vpn-client', vpn_type: 'openvpn-client', enabled: true },
      { _id: 'n3', name: 'Old office', purpose: 'site-vpn', vpn_type: 'ipsec-vpn', enabled: false },
    ],
    health: [{ subsystem: 'vpn', remote_user_num_active: 2 }],
  });
  const doors = waysIn(
    r,
    [
      forward('pf1', { name: 'Proxy', services: ['HTTPS (443)'], internalName: 'Web server', severity: 'medium' }),
      forward('pf2', { name: 'Switched off', enabled: false }),
      forward('pf3', { name: 'Game server', sourceRestriction: '203.0.113.0/24' }),
    ],
    (ip) => (ip === '192.168.40.6' ? 14 : 0),
  );
  assert.deepEqual(doors.map((d) => d.name), ['Proxy', 'Game server', 'Home VPN'], 'riskiest first; disabled doors and outgoing VPN clients left out');
  assert.equal(doors[0].detail, 'HTTPS (443) → Web server (192.168.40.6)');
  assert.equal(doors[0].attacks, 14);
  assert.equal(doors[1].limited, true);
  assert.equal(doors[2].detail, 'WireGuard server for remote access · 2 connected now');

  // WireGuard users are only in the session list; the health summary says 0 for them.
  const wg = waysIn(
    { ...r, health: [{ subsystem: 'vpn', remote_user_num_active: 0 }], vpnSessions: [{ network_id: 'n1', up: true, vpn_type: 'wireguard-server' }, { network_id: 'n1', up: false }] },
    [],
    () => 0,
  );
  assert.equal(wg[0].detail, 'WireGuard server for remote access · 1 connected now');

  const named = waysIn(r, [forward('pf3', { name: 'Game server' })], () => 0, (ip) => (ip === '192.168.40.8' ? 'Linux f8:d9' : null));
  assert.equal(named[0].detail, 'TCP 443 → Linux f8:d9 (192.168.40.8)', 'a name known from detections fills in for a device that is not connected now');
});

test('new devices: connected ones first seen in the last 7 days, newest first', () => {
  const now = Date.UTC(2026, 9, 29);
  const ago = (days: number) => (now - days * 86400e3) / 1000;
  const list = newDevices(
    raw({
      clients: [
        { mac: 'a', hostname: 'old-laptop', first_seen: ago(30) },
        { mac: 'b', name: 'Doorbell', oui: 'Amcrest', network: 'IoT', ip: '192.168.30.9', first_seen: ago(2) },
        { mac: 'c', first_seen: ago(0.5), is_wired: true, ip: '192.168.1.77' },
      ],
    }),
    now,
  )!;
  assert.deepEqual(list.map((d) => d.name), [null, 'Doorbell']);
  assert.deepEqual([list[0].wired, list[1].vendor, list[1].network], [true, 'Amcrest', 'IoT']);
  assert.equal(newDevices(raw({}), now), null, 'no client data at all is not the same as "nothing new"');
});

test('UniFi devices: offline ones and waiting updates, never devices you disabled on purpose', () => {
  const issues = deviceIssues(
    raw({
      devices: [
        { name: 'Garage AP', model: 'U7PG2', state: 0, last_seen: 1_700_000_000 },
        { name: 'Spare AP', state: 0, disabled: true },
        { name: 'Switch', state: 1, upgradable: true, version: '7.1.26', upgrade_to_firmware: '7.2.1' },
        { name: 'Gateway', state: 1 },
      ],
    }),
  );
  assert.deepEqual(issues.map((d) => `${d.name}:${d.issue}`), ['Garage AP:offline', 'Switch:update']);
  assert.equal(issues[0].since, 1_700_000_000_000);
  assert.equal(issues[1].detail, '7.1.26 → 7.2.1');
});
