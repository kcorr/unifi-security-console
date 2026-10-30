import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { RawSnapshot } from './unifi/collect.ts';
import { clientConnection, unifiDeviceDetail, unifiDevices } from './devices.ts';
import { identifyDevice, isPrivateMac } from './security/identify.ts';
import { csvFields, makerOf, parseRegistry } from './security/makers.ts';

const raw = (p: Partial<RawSnapshot>): RawSnapshot => ({
  fetchedAt: 0, firewallMode: 'zone', firewallSource: 'integration', iNetworks: [], iZones: [], iPolicies: [], iLists: [], iWifi: [], iDevices: [], iClients: [],
  networkconf: [], v2Zones: [], v2Policies: [], legacyRules: [], firewallGroups: [], trafficRules: [], portForwards: [], wlans: [], settings: {}, devices: [],
  clients: [], health: [], vpnSessions: null, capabilities: [], errors: [],
  ...p,
});

test('the IEEE register is read correctly, and the most specific block names the maker', () => {
  assert.deepEqual(csvFields('MA-L,286FB9,"Nokia Shanghai Bell Co., Ltd.","No.388 ""Ning"" Road"'), ['MA-L', '286FB9', 'Nokia Shanghai Bell Co., Ltd.', 'No.388 "Ning" Road']);
  const entries = parseRegistry('Registry,Assignment,Organization Name,Organization Address\nMA-L,BC2411,Proxmox Server Solutions GmbH,Vienna\nMA-L,70B3D5,IEEE Registration Authority,x\nMA-S,70B3D5123,Tiny Sensors Ltd,y\n');
  assert.equal(makerOf(entries, 'bc:24:11:e7:f8:d9'), 'Proxmox Server Solutions GmbH');
  assert.equal(makerOf(entries, '70:b3:d5:12:34:56'), 'Tiny Sensors Ltd', 'a small (MA-S) block wins over the large one it sits in');
  assert.equal(makerOf(entries, '70:b3:d5:99:00:00'), 'IEEE Registration Authority');
  assert.equal(makerOf(entries, '00:00:00:00:00:01'), null);
});

test('identification combines clues and says why', () => {
  const base = { name: null, hostname: null, maker: null, makerSource: null, fingerprint: null, fingerprintConfidence: null, wired: true, network: 'DMZ' } as const;
  const vm = identifyDevice({ ...base, mac: 'bc:24:11:e7:f8:d9', fingerprint: 'Linux', fingerprintConfidence: 90 });
  assert.equal(vm.guess, 'a virtual machine or container on Proxmox');
  assert.equal(vm.confidence, 'high');
  assert.ok(vm.clues.some((c) => /Proxmox/.test(c)) && vm.clues.some((c) => /Linux/.test(c)));
  assert.ok(vm.lookups.every((l) => !/e7.?f8.?d9/i.test(l.url)), 'only the maker half of the address leaves in a lookup link');

  const phone = identifyDevice({ ...base, mac: '2a:5c:91:4e:0b:37', wired: false, network: 'Default' });
  assert.equal(phone.privateAddress, true);
  assert.equal(phone.guess, 'a phone, tablet, laptop or watch');
  assert.equal(phone.lookups.length, 0, 'a randomized address names no maker, so there is nothing to look up');

  const plug = identifyDevice({ ...base, mac: 'e4:b3:23:00:00:01', maker: 'Espressif Inc.', makerSource: 'registry', wired: false, network: 'IoT' });
  assert.match(plug.guess ?? '', /Espressif/);
  assert.equal(plug.confidence, 'medium');
  assert.equal(identifyDevice({ ...base, mac: '00:11:22:33:44:55', hostname: 'DESKTOP-4KQ2J9' }).guess, 'a Windows PC (it still has the name Windows gave it)');
  assert.equal(isPrivateMac('64:1a:2b:3c:4d:5e'), false);
});

test('UniFi devices: gateway first, states and updates read plainly, ports, PoE and who is connected', () => {
  const r = raw({
    devices: [
      { mac: 'AA:00:00:00:00:03', name: 'Garage AP', type: 'uap', shortname: 'U6-LR', state: 0, last_seen: 1_700_000_000, uplink: { type: 'wire', uplink_device_name: 'Switch', uplink_remote_port: 3 } },
      { mac: 'AA:00:00:00:00:02', name: 'Switch', type: 'usw', shortname: 'USL24P', state: 1, version: '7.5.15', upgradable: true, upgrade_to_firmware: '7.6.1', num_sta: 2, total_max_power: 95, 'system-stats': { cpu: '18.7', mem: '38.3' },
        port_table: [
          { port_idx: 2, name: 'NAS', up: true, speed: 1000, poe_enable: false, 'tx_bytes-r': 1000, 'rx_bytes-r': 10 },
          { port_idx: 1, up: true, speed: 1000, is_uplink: true },
          { port_idx: 3, up: false, poe_enable: true, poe_power: '4.5' },
        ] },
      { mac: 'AA:00:00:00:00:01', name: 'UDR7', type: 'udm', shortname: 'UDR7', state: 1, uplink: { type: 'wire', port_idx: 4, speed: 1000 }, temperatures: [{ name: 'CPU', value: 70.1 }] },
      { mac: 'AA:00:00:00:00:04', name: 'Extender', type: 'uap', state: 0, disabled: true },
    ],
    clients: [
      { mac: 'cc:00:00:00:00:01', hostname: 'nas', ip: '10.0.0.5', is_wired: true, sw_port: 2, last_uplink_mac: 'aa:00:00:00:00:02' },
      { mac: 'cc:00:00:00:00:02', hostname: 'phone', is_wired: false, essid: 'Home', last_uplink_mac: 'aa:00:00:00:00:01' },
    ],
  });
  const list = unifiDevices(r);
  assert.deepEqual(list.map((d) => `${d.kind}:${d.name}:${d.state}`), ['gateway:UDR7:online', 'switch:Switch:online', 'ap:Extender:disabled', 'ap:Garage AP:offline']);
  assert.equal(list[1].update, '7.6.1');
  assert.deepEqual(list[0].uplink, { name: 'Internet', port: 4, speedMbps: 1000, wireless: false });
  assert.equal(list[0].tempC, 70.1);

  const sw = unifiDeviceDetail(r, 'aa:00:00:00:00:02')!;
  assert.deepEqual(sw.ports.map((p) => p.idx), [1, 2, 3]);
  assert.deepEqual([sw.ports[1].downBps, sw.ports[1].upBps], [8000, 80], 'what the port sends is the download of the device behind it');
  assert.deepEqual(sw.poe, { usedW: 4.5, maxW: 95 });
  assert.deepEqual(sw.connected.map((c) => `${c.name}@${c.port}`), ['nas@2']);
  assert.equal(unifiDeviceDetail(r, 'aa:00:00:00:00:99'), null);
});

test('a Wi-Fi connection is described in plain terms', () => {
  const c = clientConnection({ is_wired: false, essid: 'HomeIoT', radio: 'na', radio_proto: 'ac', channel: 104, channel_width: 80, signal: -76, rx_rate: 117000, tx_rate: 390000, nss: 2, wifi_tx_retries_percentage: 15.08, satisfaction: 100, last_uplink_name: 'UDR7' });
  assert.deepEqual([c.band, c.standard, c.streams, c.rxRateMbps, c.txRateMbps, c.retriesPct, c.via], ['5 GHz', 'Wi-Fi 5', '2x2', 117, 390, 15.1, 'UDR7']);
  const w = clientConnection({ is_wired: true, sw_port: 7, wired_rate_mbps: 1000, last_uplink_name: 'USW 24 PoE' });
  assert.deepEqual([w.port, w.linkMbps, w.band, w.via], [7, 1000, null, 'USW 24 PoE']);
  assert.equal(c.experience, 100);
  assert.equal(clientConnection({ is_wired: false, satisfaction: -1 }).experience, null, 'UniFi reports -1 when it has nothing to measure');
});
