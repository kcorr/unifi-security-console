// A simulated UniFi OS console for the tests. It answers the same official + internal API calls a real console
// does, keeps state, and accepts writes, so hardening actions can be applied, re-analysed and undone end to end.
// Test-only: it is not part of the app or its Docker image.

import { randomUUID } from 'node:crypto';
import type { HttpRequest, HttpResponse, Transport } from '../unifi/http.ts';

type Obj = Record<string, unknown>;

let seq = 0;
function uuid(n?: number): string {
  const x = (n ?? ++seq).toString(16).padStart(12, '0');
  return `5e1f0000-0000-4000-8000-${x}`;
}
function oid(n: number): string {
  return `65a0${n.toString(16).padStart(20, '0')}`;
}

function rng(seed: number) {
  let s = seed >>> 0;
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s / 0x100000000;
  };
}

export interface FakeState {
  zones: Obj[];
  networks: Obj[];
  policies: Obj[];
  lists: Obj[];
  networkconf: Obj[];
  settings: Obj[];
  portforward: Obj[];
  wlanconf: Obj[];
  devices: Obj[];
  clients: Obj[];
  threats: Obj[];
  wifi: Obj[];
}

const Z = {
  internal: uuid(1),
  external: uuid(2),
  gateway: uuid(3),
  vpn: uuid(4),
  hotspot: uuid(5),
  dmz: uuid(6),
};

const NET = [
  { key: 'main', name: 'Default', vlan: 1, host: '192.168.1.1', prefix: 24, zone: Z.internal, purpose: 'corporate', dns: ['192.168.20.53'] },
  { key: 'servers', name: 'Servers', vlan: 20, host: '192.168.20.1', prefix: 24, zone: Z.internal, purpose: 'corporate', dns: [] },
  { key: 'iot', name: 'IoT', vlan: 30, host: '192.168.30.1', prefix: 24, zone: Z.internal, purpose: 'corporate', dns: [] },
  { key: 'cameras', name: 'Cameras', vlan: 40, host: '192.168.40.1', prefix: 24, zone: Z.internal, purpose: 'corporate', dns: [] },
  { key: 'guest', name: 'Guest', vlan: 50, host: '192.168.50.1', prefix: 24, zone: Z.hotspot, purpose: 'guest', dns: [] },
  { key: 'mgmt', name: 'Management', vlan: 99, host: '10.99.0.1', prefix: 24, zone: Z.internal, purpose: 'corporate', dns: [] },
];

export function netUuid(key: string): string {
  return uuid(100 + NET.findIndex((n) => n.key === key));
}
function netOid(key: string): string {
  return oid(100 + NET.findIndex((n) => n.key === key));
}

function policy(p: {
  id?: string;
  name: string;
  index: number;
  src: string;
  dst: string;
  action: 'ALLOW' | 'BLOCK' | 'REJECT';
  srcFilter?: Obj;
  dstFilter?: Obj;
  proto?: Obj | null;
  states?: string[] | null;
  origin?: string;
  enabled?: boolean;
  description?: string;
  ipVersion?: string;
}): Obj {
  return {
    id: p.id ?? uuid(),
    name: p.name,
    description: p.description ?? '',
    enabled: p.enabled ?? true,
    action: p.action === 'ALLOW' ? { type: 'ALLOW', allowReturnTraffic: false } : { type: p.action },
    source: { zoneId: p.src, ...(p.srcFilter ? { trafficFilter: p.srcFilter } : {}) },
    destination: { zoneId: p.dst, ...(p.dstFilter ? { trafficFilter: p.dstFilter } : {}) },
    ipProtocolScope: { ipVersion: p.ipVersion ?? 'IPV4_AND_IPV6', ...(p.proto ? { protocolFilter: p.proto } : {}) },
    ...(p.states ? { connectionStateFilter: p.states } : {}),
    loggingEnabled: false,
    reportFlowEnabled: true,
    index: p.index,
    metadata: { origin: p.origin ?? 'USER_DEFINED' },
  };
}

const netFilter = (keys: string[]) => ({ type: 'NETWORK', networkFilter: { networkIds: keys.map(netUuid), matchOpposite: false } });
const ports = (...ps: (number | [number, number])[]) => ({
  type: 'PORTS',
  matchOpposite: false,
  items: ps.map((p) => (Array.isArray(p) ? { type: 'PORT_NUMBER_RANGE', start: p[0], stop: p[1] } : { type: 'PORT_NUMBER', value: p })),
});
const TCP = { type: 'NAMED_PROTOCOL', matchOpposite: false, protocol: { name: 'TCP' } };
const UDP = { type: 'NAMED_PROTOCOL', matchOpposite: false, protocol: { name: 'UDP' } };

function systemPolicies(): Obj[] {
  const zoneKeys = Object.keys(Z) as (keyof typeof Z)[];
  const out: Obj[] = [];
  let idx = 30000;
  const add = (s: keyof typeof Z, d: keyof typeof Z, name: string, action: 'ALLOW' | 'BLOCK', states?: string[], proto?: Obj, dstFilter?: Obj) =>
    out.push(policy({ name, index: idx++, src: Z[s], dst: Z[d], action, states, proto, dstFilter, origin: 'SYSTEM_DEFINED' }));
  for (const s of zoneKeys) {
    for (const d of zoneKeys) {
      if (s === 'external' && d === 'external') continue;
      if (s === 'gateway' || d === 'external' || s === 'internal' || s === 'vpn' || (s === 'dmz' && d === 'dmz')) {
        add(s, d, 'Allow All Traffic', 'ALLOW');
      } else if (s === 'hotspot' && d === 'gateway') {
        add(s, d, 'Allow DNS', 'ALLOW', undefined, undefined, { type: 'PORT', portFilter: ports(53) });
        add(s, d, 'Allow DHCP', 'ALLOW', undefined, UDP, { type: 'PORT', portFilter: ports(67) });
        add(s, d, 'Block All Traffic', 'BLOCK');
      } else {
        add(s, d, 'Allow Return Traffic', 'ALLOW', ['ESTABLISHED', 'RELATED']);
        add(s, d, 'Block All Traffic', 'BLOCK');
      }
    }
  }
  return out;
}

/** Default policies a console creates for a new custom zone. */
function customZonePolicies(zoneId: string): Obj[] {
  const out: Obj[] = [];
  let idx = 31000 + Math.floor(Math.random() * 500) * 10;
  const add = (s: string, d: string, name: string, action: 'ALLOW' | 'BLOCK', states?: string[]) =>
    out.push(policy({ name, index: idx++, src: s, dst: d, action, states, origin: 'SYSTEM_DEFINED' }));
  for (const other of Object.values(Z)) {
    if (other === Z.external || other === Z.gateway) {
      add(zoneId, other, 'Allow All Traffic', 'ALLOW');
    } else {
      add(zoneId, other, 'Allow Return Traffic', 'ALLOW', ['ESTABLISHED', 'RELATED']);
      add(zoneId, other, 'Block All Traffic', 'BLOCK');
    }
    if (other === Z.internal || other === Z.gateway) add(other, zoneId, 'Allow All Traffic', 'ALLOW');
    else if (other !== zoneId) {
      add(other, zoneId, 'Allow Return Traffic', 'ALLOW', ['ESTABLISHED', 'RELATED']);
      add(other, zoneId, 'Block All Traffic', 'BLOCK');
    }
  }
  add(zoneId, zoneId, 'Allow All Traffic', 'ALLOW');
  return out;
}

function seedThreatSigs() {
  return [
    { sig: 'ET SCAN Suspicious inbound to mySQL port 3306', cls: 'Potentially Bad Traffic', cat: 'emerging-scan', pri: 2, port: 3306, dir: 'in', w: 14 },
    { sig: 'ET SCAN Suspicious inbound to MSSQL port 1433', cls: 'Potentially Bad Traffic', cat: 'emerging-scan', pri: 2, port: 1433, dir: 'in', w: 10 },
    { sig: 'ET SCAN Potential SSH Scan', cls: 'Attempted Information Leak', cat: 'emerging-scan', pri: 2, port: 22, dir: 'in', w: 12 },
    { sig: 'ET SCAN MS Terminal Server Traffic on Non-standard Port', cls: 'Attempted Information Leak', cat: 'emerging-scan', pri: 2, port: 3389, dir: 'in-rdp', w: 16 },
    { sig: 'ET CINS Active Threat Intelligence Poor Reputation IP group 43', cls: 'Misc Attack', cat: 'ciarmy', pri: 2, port: 8080, dir: 'in', w: 18 },
    { sig: 'ET DROP Spamhaus DROP Listed Traffic Inbound group 12', cls: 'Misc Attack', cat: 'drop', pri: 2, port: 443, dir: 'in', w: 8 },
    { sig: 'ET DSHIELD Block Listed Source group 1', cls: 'Misc Attack', cat: 'dshield', pri: 2, port: 23, dir: 'in', w: 9 },
    { sig: 'ET TOR Known Tor Exit Node Traffic group 47', cls: 'Misc Attack', cat: 'tor', pri: 2, port: 3389, dir: 'in-rdp', w: 4 },
    { sig: 'ET EXPLOIT Apache log4j RCE Attempt (http ldap) (CVE-2021-44228)', cls: 'Attempted Administrator Privilege Gain', cat: 'emerging-exploit', pri: 1, port: 32400, dir: 'in-plex', w: 3 },
    { sig: 'ET EXPLOIT Possible Hikvision IP Camera RCE Attempt (CVE-2021-36260)', cls: 'Attempted Administrator Privilege Gain', cat: 'emerging-exploit', pri: 1, port: 80, dir: 'in', w: 2 },
    { sig: 'ET VOIP Modified Sipvicious Asterisk PBX User-Agent', cls: 'Attempted Information Leak', cat: 'emerging-voip', pri: 2, port: 5060, dir: 'in', w: 6 },
    { sig: 'ET POLICY Possible External IP Lookup ipinfo.io', cls: 'Device Retrieving External IP Address Detected', cat: 'emerging-policy', pri: 2, port: 443, dir: 'out', w: 5 },
    { sig: 'ET INFO Observed DNS Query to .top TLD', cls: 'Potentially Bad Traffic', cat: 'emerging-info', pri: 3, port: 53, dir: 'out', w: 4 },
    { sig: 'ET MALWARE Win32/Lumma Stealer Related CnC Domain in DNS Lookup', cls: 'Domain Observed Used for C2 Detected', cat: 'emerging-malware', pri: 1, port: 53, dir: 'out-bad', w: 1 },
    { sig: 'SURICATA STREAM ESTABLISHED packet out of window', cls: 'Generic Protocol Command Decode', cat: 'stream-events', pri: 3, port: 443, dir: 'in', w: 3 },
    { sig: 'ET SCAN Mirai Variant User-Agent (Inbound)', cls: 'Attempted Administrator Privilege Gain', cat: 'emerging-scan', pri: 1, port: 8080, dir: 'in', w: 3 },
  ];
}

/** A day of connections the simulated firewall blocks, as UniFi's traffic log reports them. */
function fakeBlockedFlows(now: number): Obj[] {
  const ZONE: Record<string, string> = { [Z.internal]: 'Internal', [Z.hotspot]: 'Hotspot', [Z.dmz]: 'Dmz' };
  const side = (ip: string, port: number) => {
    const c = CLIENT_DEFS.find((x) => x.ip === ip);
    const n = NET.find((x) => ip.startsWith(x.host.replace(/1$/, '')));
    return n
      ? { ip, port, client_name: c?.name ?? ip, network_id: netOid(n.key), network_name: n.name, zone_name: ZONE[n.zone] ?? 'Internal' }
      : { ip, port, zone_name: 'External' };
  };
  const streams: [src: string, dst: string, port: number, protocol: string, everyMin: number][] = [
    ['192.168.40.20', '192.168.20.30', 445, 'TCP', 10], // the doorbell uploading over SMB; its rule only allows FTP
    ['192.168.40.12', '192.168.20.53', 53, 'UDP', 15], // a camera set to use Pi-hole, which cameras may not reach
    ['192.168.30.31', '8.8.8.8', 53, 'UDP', 12], // smart plugs with hard-coded DNS
    ['192.168.30.32', '8.8.4.4', 53, 'UDP', 20],
    ['192.168.50.23', '192.168.1.50', 445, 'TCP', 120], // a guest looking for file shares
  ];
  const out: Obj[] = [];
  streams.forEach(([src, dst, port, protocol, every], i) => {
    for (let t = now - 86400e3 + i * 60e3; t <= now; t += every * 60e3) {
      out.push({
        id: `blk${i}-${t}`,
        action: 'blocked',
        count: 1,
        direction: side(dst, port).zone_name === 'External' ? 'outgoing' : 'local',
        protocol,
        risk: 'low',
        service: 'OTHER',
        time: t,
        source: side(src, 40000 + i),
        destination: side(dst, port),
        policies: [{ id: oid(900 + i), internal_type: 'PREDEFINED_FIREWALL_RULE', type: 'FIREWALL' }],
      });
    }
  });
  return out.sort((a, b) => Number(b.time) - Number(a.time));
}

const ATTACKERS = [
  '167.94.138.44', '167.94.146.58', '162.142.125.212', '45.142.193.6', '45.142.193.72', '185.220.101.33', '218.92.0.112', '61.177.172.140', '194.26.29.120',
  '103.145.13.24', '193.32.162.157', '89.248.165.52', '89.248.163.112', '141.98.11.87', '198.235.24.19', '5.188.206.14',
];

const CLIENT_DEFS: { name: string; net: string; ip: string; wired: boolean; oui: string; essid?: string }[] = [
  { name: 'Alex-MacBook', net: 'main', ip: '192.168.1.21', wired: false, oui: 'Apple', essid: 'Home' },
  { name: 'Gaming-PC', net: 'main', ip: '192.168.1.50', wired: true, oui: 'ASUSTek' },
  { name: 'iPhone-15', net: 'main', ip: '192.168.1.33', wired: false, oui: 'Apple', essid: 'Home' },
  { name: 'Pixel-8', net: 'main', ip: '192.168.1.34', wired: false, oui: 'Google', essid: 'Home' },
  { name: 'Work-Laptop', net: 'main', ip: '192.168.1.40', wired: false, oui: 'Dell', essid: 'Home' },
  { name: 'iPad', net: 'main', ip: '192.168.1.36', wired: false, oui: 'Apple', essid: 'Home' },
  { name: 'Synology-NAS', net: 'servers', ip: '192.168.20.30', wired: true, oui: 'Synology' },
  { name: 'Plex-Server', net: 'servers', ip: '192.168.20.20', wired: true, oui: 'Intel' },
  { name: 'pihole', net: 'servers', ip: '192.168.20.53', wired: true, oui: 'Raspberry Pi' },
  { name: 'home-assistant', net: 'servers', ip: '192.168.20.10', wired: true, oui: 'Raspberry Pi' },
  { name: 'Living-Room-TV', net: 'iot', ip: '192.168.30.21', wired: false, oui: 'Samsung', essid: 'Home-IoT' },
  { name: 'Hue-Bridge', net: 'iot', ip: '192.168.30.10', wired: true, oui: 'Philips' },
  { name: 'Smart-Plug-Office', net: 'iot', ip: '192.168.30.31', wired: false, oui: 'Espressif', essid: 'Home-IoT' },
  { name: 'Smart-Plug-Garage', net: 'iot', ip: '192.168.30.32', wired: false, oui: 'Espressif', essid: 'Home-IoT' },
  { name: 'Robot-Vacuum', net: 'iot', ip: '192.168.30.40', wired: false, oui: 'Roborock', essid: 'Home-IoT' },
  { name: 'Thermostat', net: 'iot', ip: '192.168.30.45', wired: false, oui: 'Google', essid: 'Home-IoT' },
  { name: 'Echo-Kitchen', net: 'iot', ip: '192.168.30.50', wired: false, oui: 'Amazon', essid: 'Home-IoT' },
  { name: 'Driveway-Cam', net: 'cameras', ip: '192.168.40.11', wired: true, oui: 'Reolink' },
  { name: 'Backyard-Cam', net: 'cameras', ip: '192.168.40.12', wired: true, oui: 'Reolink' },
  { name: 'Doorbell', net: 'cameras', ip: '192.168.40.20', wired: false, oui: 'Amcrest', essid: 'Home-IoT' },
  { name: 'Guest-Android', net: 'guest', ip: '192.168.50.101', wired: false, oui: 'Samsung', essid: 'Guest' },
  { name: 'Guest-iPhone', net: 'guest', ip: '192.168.50.102', wired: false, oui: 'Apple', essid: 'Guest' },
  { name: 'USW-Pro-24', net: 'mgmt', ip: '10.99.0.10', wired: true, oui: 'Ubiquiti' },
];

function mac(i: number): string {
  return `f4:92:bf:${(0x10 + i).toString(16).padStart(2, '0')}:${((i * 37) % 256).toString(16).padStart(2, '0')}:${((i * 91) % 256).toString(16).padStart(2, '0')}`;
}

export function createFakeState(now = Date.now()): FakeState {
  seq = 1000;
  const zones = [
    { id: Z.internal, name: 'Internal', networkIds: NET.filter((n) => n.zone === Z.internal).map((n) => netUuid(n.key)), metadata: { origin: 'SYSTEM_DEFINED', configurable: true } },
    { id: Z.external, name: 'External', networkIds: [], metadata: { origin: 'SYSTEM_DEFINED', configurable: false } },
    { id: Z.gateway, name: 'Gateway', networkIds: [], metadata: { origin: 'SYSTEM_DEFINED', configurable: false } },
    { id: Z.vpn, name: 'Vpn', networkIds: [], metadata: { origin: 'SYSTEM_DEFINED', configurable: true } },
    { id: Z.hotspot, name: 'Hotspot', networkIds: [netUuid('guest')], metadata: { origin: 'SYSTEM_DEFINED', configurable: true } },
    { id: Z.dmz, name: 'Dmz', networkIds: [], metadata: { origin: 'SYSTEM_DEFINED', configurable: true } },
  ];
  const networks = NET.map((n, i) => ({
    id: netUuid(n.key),
    name: n.name,
    management: 'GATEWAY',
    enabled: true,
    default: i === 0,
    vlanId: n.vlan,
    metadata: { origin: i === 0 ? 'SYSTEM_DEFINED' : 'USER_DEFINED' },
    zoneId: n.zone,
    internetAccessEnabled: true,
    isolationEnabled: false,
    mdnsForwardingEnabled: n.key === 'iot',
    ipv4Configuration: {
      autoScaleEnabled: false,
      hostIpAddress: n.host,
      prefixLength: n.prefix,
      dhcpConfiguration: { mode: 'SERVER', ...(n.dns.length ? { dnsServerIpAddressesOverride: n.dns } : {}), ipAddressRange: { start: n.host.replace(/\.1$/, '.6'), stop: n.host.replace(/\.1$/, '.254') } },
    },
  }));
  const badList = { id: uuid(500), name: 'Known bad IPs', type: 'IPV4_ADDRESSES', items: [{ type: 'IP_ADDRESS', value: '194.26.29.120' }, { type: 'SUBNET', value: '5.188.206.0/24' }] };
  const user: Obj[] = [
    // Lets the doorbell save clips over FTP, but it uploads over SMB: a near miss in the blocked-traffic view.
    policy({
      name: 'Allow Doorbell to NAS',
      index: 9999,
      src: Z.internal,
      dst: Z.internal,
      action: 'ALLOW',
      srcFilter: { type: 'IP_ADDRESS', ipAddressFilter: { type: 'IP_ADDRESSES', matchOpposite: false, items: [{ type: 'IP_ADDRESS', value: '192.168.40.20' }] } },
      dstFilter: { type: 'IP_ADDRESS', ipAddressFilter: { type: 'IP_ADDRESSES', matchOpposite: false, items: [{ type: 'IP_ADDRESS', value: '192.168.20.30' }] }, portFilter: ports(21) },
      proto: TCP,
    }),
    policy({ name: 'Block Cameras to LAN', index: 10000, src: Z.internal, dst: Z.internal, action: 'BLOCK', srcFilter: netFilter(['cameras']), dstFilter: netFilter(['main', 'servers']), states: ['NEW'] }),
    policy({
      name: 'Allow Home Assistant to IoT',
      index: 10001,
      src: Z.internal,
      dst: Z.internal,
      action: 'ALLOW',
      srcFilter: { type: 'IP_ADDRESS', ipAddressFilter: { type: 'IP_ADDRESSES', matchOpposite: false, items: [{ type: 'IP_ADDRESS', value: '192.168.20.10' }] } },
      dstFilter: netFilter(['iot']),
    }),
    policy({ name: 'Block IoT DNS', index: 10002, src: Z.internal, dst: Z.external, action: 'BLOCK', srcFilter: netFilter(['iot']), dstFilter: { type: 'PORT', portFilter: ports(53) }, proto: UDP }),
    policy({
      name: 'IoT no public DNS',
      index: 10003,
      src: Z.internal,
      dst: Z.external,
      action: 'BLOCK',
      srcFilter: { type: 'IP_ADDRESS', ipAddressFilter: { type: 'IP_ADDRESSES', matchOpposite: false, items: [{ type: 'SUBNET', value: '192.168.30.0/24' }] } },
      dstFilter: { type: 'PORT', portFilter: ports(53) },
      proto: UDP,
    }),
    policy({
      name: 'Allow IoT to Plex',
      index: 10004,
      src: Z.internal,
      dst: Z.internal,
      action: 'ALLOW',
      srcFilter: netFilter(['iot']),
      dstFilter: { type: 'IP_ADDRESS', ipAddressFilter: { type: 'IP_ADDRESSES', matchOpposite: false, items: [{ type: 'IP_ADDRESS', value: '192.168.20.20' }] }, portFilter: ports(32400) },
      proto: TCP,
    }),
    policy({
      name: 'Block known bad IPs',
      index: 10005,
      src: Z.external,
      dst: Z.internal,
      action: 'BLOCK',
      srcFilter: { type: 'IP_ADDRESS', ipAddressFilter: { type: 'TRAFFIC_MATCHING_LIST', matchOpposite: false, trafficMatchingListId: badList.id } },
    }),
    policy({
      name: 'Old test rule',
      index: 10006,
      src: Z.internal,
      dst: Z.external,
      action: 'BLOCK',
      enabled: false,
      dstFilter: { type: 'IP_ADDRESS', ipAddressFilter: { type: 'IP_ADDRESSES', matchOpposite: false, items: [{ type: 'IP_ADDRESS', value: '1.2.3.4' }] } },
    }),
    policy({
      name: 'Allow Plex port forward',
      index: 10007,
      src: Z.external,
      dst: Z.internal,
      action: 'ALLOW',
      dstFilter: { type: 'IP_ADDRESS', ipAddressFilter: { type: 'IP_ADDRESSES', matchOpposite: false, items: [{ type: 'IP_ADDRESS', value: '192.168.20.20' }] }, portFilter: ports(32400) },
      proto: TCP,
      origin: 'DERIVED',
    }),
  ];
  const networkconf: Obj[] = [
    { _id: oid(90), name: 'Internet 1', purpose: 'wan', wan_type: 'dhcp', wan_networkgroup: 'WAN' },
    ...NET.map((n) => ({
      _id: netOid(n.key),
      name: n.name,
      purpose: n.purpose,
      vlan_enabled: n.vlan !== 1,
      ...(n.vlan !== 1 ? { vlan: n.vlan } : {}),
      ip_subnet: `${n.host}/${n.prefix}`,
      dhcpd_enabled: true,
      dhcpd_dns_enabled: n.dns.length > 0,
      ...(n.dns.length ? { dhcpd_dns_1: n.dns[0] } : {}),
      networkgroup: 'LAN',
      enabled: true,
      internet_access_enabled: true,
      network_isolation_enabled: false,
      igmp_snooping: n.key === 'iot',
    })),
  ];
  const settings: Obj[] = [
    {
      _id: oid(200),
      key: 'ips',
      ips_mode: 'ids',
      // Active Detections as Network 10 stores them, with a few recommended ones left off.
      enabled_categories: ['botcc', 'dshield', 'emerging-malware', 'emerging-worm', 'emerging-exploit', 'emerging-dns', 'tor'],
      memory_optimized: false,
      honeypot_enabled: false,
      ad_blocking_enabled: false,
      advanced_filtering_preference: 'manual',
    },
    { _id: oid(201), key: 'usg', upnp_enabled: true, upnp_nat_pmp_enabled: true, upnp_secure_mode: true, mdns_enabled: true, dns_verification: { setting_preference: 'auto' } },
    { _id: oid(202), key: 'mgmt', x_ssh_enabled: true, x_ssh_auth_password_enabled: true, advanced_feature_enabled: true },
    { _id: oid(203), key: 'country', code: 840 },
    // Region Blocking, off as on a new console.
    { _id: oid(204), key: 'usg_geo', ip_filtering: { action: 'block', countries: '', enabled: false, traffic_direction: 'both' } },
  ];
  const portforward: Obj[] = [
    { _id: oid(300), name: 'Plex', enabled: true, pfwd_interface: 'wan', fwd: '192.168.20.20', fwd_port: '32400', dst_port: '32400', proto: 'tcp', src: 'any', log: false },
    { _id: oid(301), name: 'Gaming PC Remote Desktop', enabled: true, pfwd_interface: 'wan', fwd: '192.168.1.50', fwd_port: '3389', dst_port: '3389', proto: 'tcp_udp', src: 'any', log: false },
    { _id: oid(302), name: 'NAS DSM', enabled: false, pfwd_interface: 'wan', fwd: '192.168.20.30', fwd_port: '5001', dst_port: '5001', proto: 'tcp', src: 'any', log: false },
  ];
  const wlanconf: Obj[] = [
    { _id: oid(400), name: 'Home', enabled: true, security: 'wpapsk', wpa_mode: 'wpa2', wpa3_support: true, wpa3_transition: true, pmf_mode: 'optional', networkconf_id: netOid('main'), is_guest: false, hide_ssid: false, l2_isolation: false },
    { _id: oid(401), name: 'Home-IoT', enabled: true, security: 'wpapsk', wpa_mode: 'wpa2', wpa3_support: false, pmf_mode: 'disabled', networkconf_id: netOid('iot'), is_guest: false, hide_ssid: true, l2_isolation: false },
    { _id: oid(402), name: 'Guest', enabled: true, security: 'open', wpa_mode: 'wpa2', networkconf_id: netOid('guest'), is_guest: true, hide_ssid: false, l2_isolation: false },
  ];
  const wifi = wlanconf.map((w, i) => ({
    id: uuid(600 + i),
    name: w.name,
    enabled: true,
    type: 'STANDARD',
    metadata: { origin: 'USER_DEFINED' },
    network: { type: 'SPECIFIC', networkId: netUuid(NET.find((n) => netOid(n.key) === w.networkconf_id)!.key) },
    securityConfiguration: { type: w.security === 'open' ? 'OPEN' : w.wpa3_support ? 'WPA2_WPA3_PERSONAL' : 'WPA2_PERSONAL' },
    clientIsolationEnabled: false,
    hideName: w.hide_ssid,
  }));
  const devices: Obj[] = [
    {
      _id: oid(700), mac: 'e4:38:83:aa:10:01', name: 'Dream Machine Pro', model: 'UDMPRO', type: 'udm', ip: '203.0.113.47', version: '4.3.6', upgradable: true, upgrade_to_firmware: '4.4.2', state: 1, adopted: true,
      uptime: 1_987_654, 'system-stats': { cpu: '14.2', mem: '46.8', uptime: '1987654' }, temperatures: [{ name: 'CPU', type: 'cpu', value: 54.5 }],
      wan1: { ip: '203.0.113.47', name: 'wan', up: true }, uplink: { name: 'eth8', type: 'wire', up: true },
    },
    { _id: oid(701), mac: 'e4:38:83:aa:10:02', name: 'USW-Pro-24', model: 'USWPRO24', type: 'usw', ip: '10.99.0.10', version: '7.1.26', upgradable: false, state: 1, adopted: true, uptime: 1_987_000 },
    { _id: oid(702), mac: 'e4:38:83:aa:10:03', name: 'AP Living Room', model: 'U7PRO', type: 'uap', ip: '10.99.0.21', version: '7.0.66', upgradable: true, upgrade_to_firmware: '7.0.76', state: 1, adopted: true, uptime: 980_000 },
    { _id: oid(703), mac: 'e4:38:83:aa:10:04', name: 'AP Office', model: 'U6LR', type: 'uap', ip: '10.99.0.22', version: '6.6.77', upgradable: false, state: 1, adopted: true, uptime: 980_000 },
    { _id: oid(704), mac: 'e4:38:83:aa:10:05', name: 'AP Garage', model: 'U6MESH', type: 'uap', ip: '10.99.0.23', version: '6.6.77', upgradable: false, state: 0, adopted: true, uptime: 0 },
  ];
  const r = rng(7);
  const clients = CLIENT_DEFS.map((c, i) => {
    const n = NET.find((x) => x.key === c.net)!;
    return {
      mac: mac(i), name: c.name, hostname: c.name.toLowerCase(), ip: c.ip, oui: c.oui, network: n.name, network_id: netOid(n.key), vlan: n.vlan,
      is_wired: c.wired, is_guest: n.purpose === 'guest', essid: c.essid, signal: c.wired ? undefined : -45 - Math.round(r() * 30),
      'rx_bytes-r': 0, 'tx_bytes-r': 0, rx_bytes: Math.round(r() * 5e10), tx_bytes: Math.round(r() * 1e10), uptime: Math.round(3600 + r() * 600000),
      first_seen: Math.round((now - 86400e3 * (5 + r() * 200)) / 1000), last_seen: Math.round(now / 1000),
    };
  });
  return { zones, networks, policies: [...user, ...systemPolicies()], lists: [badList], networkconf, settings, portforward, wlanconf, devices, clients, threats: [], wifi };
}

// ---------------------------------------------------------------------------------
// Threat generation
// ---------------------------------------------------------------------------------

function makeThreat(t: number, r: () => number, ipsMode: string, forced?: ReturnType<typeof seedThreatSigs>[number]): Obj {
  const sigs = seedThreatSigs();
  let s = forced;
  if (!s) {
    const total = sigs.reduce((a, x) => a + x.w, 0);
    let pick = r() * total;
    s = sigs.find((x) => (pick -= x.w) <= 0) ?? sigs[0];
  }
  const attacker = ATTACKERS[Math.floor(r() * ATTACKERS.length)];
  const wan = '203.0.113.47';
  let src = attacker;
  let dst = wan;
  let srcPort = 1024 + Math.floor(r() * 60000);
  let dstPort = s.port;
  let srcMac: string | undefined;
  if (s.dir === 'in-rdp') dst = '192.168.1.50';
  if (s.dir === 'in-plex') dst = '192.168.20.20';
  if (s.dir === 'out' || s.dir === 'out-bad') {
    const insider = s.dir === 'out-bad' ? CLIENT_DEFS.findIndex((c) => c.name === 'Smart-Plug-Garage') : Math.floor(r() * 10);
    src = CLIENT_DEFS[insider].ip;
    srcMac = mac(insider);
    dst = s.port === 53 ? '1.1.1.1' : ATTACKERS[Math.floor(r() * ATTACKERS.length)];
    dstPort = s.port;
    srcPort = 40000 + Math.floor(r() * 20000);
  }
  const blocked = ipsMode === 'ips' || ipsMode === 'ipsInline';
  const inbound = !(s.dir === 'out' || s.dir === 'out-bad');
  const client = CLIENT_DEFS.find((c) => c.ip === (inbound ? dst : src));
  const net = client ? NET.find((x) => x.key === client.net) : null;
  const localSide = { ip: inbound ? dst : src, port: inbound ? dstPort : srcPort, mac: srcMac, client_name: client?.name, network_name: net?.name, network_id: net ? netOid(net.key) : undefined, zone_name: 'Internal' };
  const remoteSide = { ip: inbound ? src : dst, port: inbound ? srcPort : dstPort, region: REGION[inbound ? src : dst] ?? 'US', zone_name: 'External' };
  const proto = s.port === 53 || s.port === 5060 ? 'UDP' : 'TCP';
  const cves = /CVE-\d{4}-\d+/.exec(s.sig)?.[0];
  return {
    id: randomUUID().replace(/-/g, '').slice(0, 24),
    time: t,
    flow_start_time: t,
    flow_end_time: t + 400,
    count: 1,
    action: blocked ? 'blocked' : 'allowed',
    direction: inbound ? 'incoming' : 'outgoing',
    protocol: proto,
    service: s.port === 443 ? 'HTTPS' : s.port === 53 ? 'DNS' : s.port === 22 ? 'SSH' : s.port === 3389 ? 'RDP' : s.port === 5060 ? 'SIP' : 'Other',
    risk: s.pri === 1 ? 'high' : s.pri === 2 ? 'medium' : 'low',
    source: inbound ? remoteSide : localSide,
    destination: inbound ? localSide : remoteSide,
    policies: [{ id: `ips-${hash(s.sig)}`, name: s.sig, type: 'INTRUSION_PREVENTION', internal_type: 'SIGNATURE', ips_category: s.cat.toUpperCase().replace(/-/g, '_') }],
    ips: {
      signature: s.sig,
      signature_id: 2000000 + (Math.abs(hash(s.sig)) % 50000),
      category_name: s.cat,
      signature_class: s.cls,
      ...(cves ? { cve_reference: cves } : {}),
    },
    traffic_data: { bytes_total: 60 + Math.floor(r() * 4000), packets_total: 1 + Math.floor(r() * 6) },
  };
}

const REGION: Record<string, string> = {
  '167.94.138.44': 'US', '167.94.146.58': 'US', '162.142.125.212': 'US', '45.142.193.6': 'NL', '45.142.193.72': 'NL', '185.220.101.33': 'DE', '218.92.0.112': 'CN',
  '61.177.172.140': 'CN', '194.26.29.120': 'RU', '103.145.13.24': 'VN', '193.32.162.157': 'NL', '89.248.165.52': 'NL', '89.248.163.112': 'NL', '141.98.11.87': 'LT',
  '198.235.24.19': 'US', '5.188.206.14': 'RU', '1.1.1.1': 'AU',
};

function hash(s: string): number {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) | 0;
  return h;
}

export function seedThreats(state: FakeState, now = Date.now(), seed = 42): void {
  const r = rng(seed);
  const mode = String(state.settings.find((s) => s.key === 'ips')?.ips_mode ?? 'ids');
  const out: Obj[] = [];
  for (let i = 0; i < 900; i++) {
    // More recent hours are busier, with a couple of bursts.
    const ageH = Math.pow(r(), 1.6) * 24 * 7;
    out.push(makeThreat(now - ageH * 3600e3 - r() * 60e3, r, mode));
  }
  const burstSig = seedThreatSigs().find((x) => x.sig.includes('Potential SSH Scan'))!;
  for (let i = 0; i < 60; i++) out.push(makeThreat(now - 5 * 3600e3 + i * 20e3, r, mode, burstSig));
  const malware = seedThreatSigs().find((x) => x.dir === 'out-bad')!;
  for (let i = 0; i < 6; i++) out.push(makeThreat(now - (2 + i * 7) * 3600e3, r, mode, malware));
  state.threats = out.sort((a, b) => Number(b.time) - Number(a.time));
}

// ---------------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------------

function ok(json: unknown, status = 200): HttpResponse {
  // A copy, like a real response: callers must never hold (and change) the simulator's live state.
  const text = JSON.stringify(json);
  return { status, json: text === undefined ? json : JSON.parse(text), text: text ?? '' };
}
function notFound(path: string): HttpResponse {
  return ok({ statusCode: 404, statusName: 'NOT_FOUND', code: 'api.resource-not-found', message: `Not found: ${path}` }, 404);
}
function page(list: Obj[], q: HttpRequest['query']): HttpResponse {
  const offset = Number(q?.offset ?? 0);
  const limit = Number(q?.limit ?? 25);
  const data = list.slice(offset, offset + limit);
  return ok({ offset, limit, count: data.length, totalCount: list.length, data });
}
function v1(data: Obj[]): HttpResponse {
  return ok({ meta: { rc: 'ok' }, data });
}
const strip = (o: Obj) => {
  const { id: _id, index: _index, metadata: _metadata, ...rest } = o;
  return rest;
};

export class FakeConsole implements Transport {
  readonly state: FakeState;
  private readonly r: () => number;
  private wanRx = 180e6;
  private wanTx = 22e6;
  private lastThreat = Date.now();

  /** `seed` varies the simulated history and traffic, so several simulated consoles differ. */
  constructor(state?: FakeState, seed = 42) {
    this.state = state ?? createFakeState();
    this.r = rng(seed + 57);
    if (!state) seedThreats(this.state, Date.now(), seed);
    if (seed !== 42) {
      this.wanRx = 60e6;
      this.wanTx = 9e6;
    }
  }

  /** Advance simulated live state: traffic random walk and the occasional new attack. */
  tick(now = Date.now()): void {
    const r = this.r;
    this.wanRx = Math.max(4e6, Math.min(900e6, this.wanRx * (0.82 + r() * 0.38) + (r() < 0.05 ? 300e6 : 0)));
    this.wanTx = Math.max(1e6, Math.min(300e6, this.wanTx * (0.8 + r() * 0.4) + (r() < 0.04 ? 60e6 : 0)));
    for (const c of this.state.clients) {
      const heavy = /PC|TV|Plex|NAS|MacBook/.test(String(c.name));
      const base = heavy ? 4e6 : 6e4;
      c['rx_bytes-r'] = Math.round(base * r() * (r() < 0.1 ? 40 : 1));
      c['tx_bytes-r'] = Math.round(base * 0.2 * r() * (r() < 0.1 ? 20 : 1));
    }
    if (now - this.lastThreat > 9000 && r() < 0.35) {
      const mode = String(this.state.settings.find((s) => s.key === 'ips')?.ips_mode ?? 'ids');
      this.state.threats.unshift(makeThreat(now, r, mode));
      this.lastThreat = now;
    }
    const gw = this.state.devices[0];
    gw['system-stats'] = { cpu: (8 + r() * 20).toFixed(1), mem: (44 + r() * 6).toFixed(1), uptime: String(Number(gw.uptime) + 5) };
    gw.uptime = Number(gw.uptime) + 5;
  }

  async close(): Promise<void> {}

  async send(input: HttpRequest): Promise<HttpResponse> {
    // Like a real server, read a query string that came inside the path (the ordering request carries one).
    const [rawPath, inlineQuery] = input.path.split('?');
    const req: HttpRequest = inlineQuery ? { ...input, path: rawPath, query: { ...Object.fromEntries(new URLSearchParams(inlineQuery)), ...input.query } } : input;
    const path = req.path.replace(/^\/proxy\/network/, '');
    const m = req.method;
    const st = this.state;
    const body = (req.body ?? {}) as Obj;

    // ---- official API ----
    if (path === '/integration/v1/info') return ok({ applicationVersion: '10.6.109' });
    if (path === '/integration/v1/sites') return page([{ id: uuid(9), internalReference: 'default', name: 'Default' }], req.query);
    const im = /^\/integration\/v1\/sites\/[^/]+(\/.*)$/.exec(path);
    if (im) {
      const sub = im[1];
      const coll = (list: Obj[], base: string, validate?: (b: Obj) => string | null): HttpResponse | null => {
        if (sub === base) {
          if (m === 'GET') return page(list, req.query);
          if (m === 'POST') {
            const err = validate?.(body);
            if (err) return ok({ statusCode: 400, code: 'api.validation', message: err }, 400);
            const created = { ...body, id: randomUUID(), metadata: { origin: 'USER_DEFINED' } } as Obj;
            if (base === '/firewall/policies') {
              const pair = list.filter((p) => (p.source as Obj).zoneId === (body.source as Obj)?.zoneId && (p.destination as Obj).zoneId === (body.destination as Obj)?.zoneId && (p.metadata as Obj).origin === 'USER_DEFINED');
              created.index = Math.max(10000, ...pair.map((p) => Number(p.index) + 1), ...list.filter((p) => (p.metadata as Obj).origin === 'USER_DEFINED').map((p) => Number(p.index) + 1));
              created.reportFlowEnabled = body.reportFlowEnabled ?? true;
            }
            list.push(created);
            return ok(created, 201);
          }
        }
        const idm = new RegExp(`^${base.replace(/\//g, '\\/')}\\/([^/]+)$`).exec(sub);
        if (idm && idm[1] !== 'ordering') {
          const i = list.findIndex((x) => x.id === idm[1]);
          if (i < 0) return notFound(path);
          if (m === 'GET') return ok(list[i]);
          if (m === 'DELETE') {
            if ((list[i].metadata as Obj | undefined)?.origin === 'SYSTEM_DEFINED') return ok({ statusCode: 400, message: 'System policies cannot be deleted' }, 400);
            list.splice(i, 1);
            return ok(null);
          }
          if (m === 'PUT') {
            if ('id' in body || 'metadata' in body) return ok({ statusCode: 422, message: "Unknown request body property '$.id'" }, 422);
            list[i] = { ...body, id: list[i].id, index: list[i].index, metadata: list[i].metadata };
            return ok(list[i]);
          }
          if (m === 'PATCH') {
            list[i] = { ...list[i], ...body };
            return ok(list[i]);
          }
        }
        return null;
      };
      const validatePolicy = (b: Obj) => {
        for (const k of ['name', 'enabled', 'action', 'source', 'destination', 'ipProtocolScope', 'loggingEnabled']) if (!(k in b)) return `Missing required property '${k}'`;
        if ('id' in b || 'index' in b || 'metadata' in b) return 'Unknown request body property';
        return null;
      };
      // Network 10.6 rejects a DHCP server config that leaves any of these out.
      const validateNetwork = (b: Obj) => {
        for (const k of ['management', 'name', 'enabled', 'vlanId']) if (!(k in b)) return `Missing required property '${k}'`;
        if (!st.zones.some((z) => z.id === b.zoneId)) return 'zoneId must not be null';
        const dhcp = (b.ipv4Configuration as Obj | undefined)?.dhcpConfiguration as Obj | undefined;
        if (dhcp?.mode === 'SERVER') {
          for (const k of ['ipAddressRange', 'leaseTimeSeconds', 'domainName', 'pingConflictDetectionEnabled']) if (dhcp[k] === undefined || dhcp[k] === null) return `ipv4Configuration.dhcpConfiguration.${k} must not be null`;
        }
        return null;
      };
      // Zone / network side effects a real console applies (membership moves, default policies).
      const zoneDel = m === 'DELETE' ? /^\/firewall\/zones\/([^/]+)$/.exec(sub)?.[1] : undefined;
      const zoneBefore = zoneDel ? st.zones.find((z) => z.id === zoneDel) : undefined;
      const res =
        coll(st.zones, '/firewall/zones') ??
        coll(st.policies, '/firewall/policies', validatePolicy) ??
        coll(st.lists, '/traffic-matching-lists') ??
        coll(st.networks, '/networks', validateNetwork) ??
        coll(st.wifi, '/wifi/broadcasts');
      if (res && res.status < 300) {
        const created = res.json as Obj;
        if (m === 'POST' && sub === '/networks') (st.zones.find((z) => z.id === created.zoneId)!.networkIds as string[]).push(String(created.id));
        if (m === 'POST' && sub === '/firewall/zones') {
          for (const nid of (created.networkIds as string[]) ?? []) {
            for (const z of st.zones) if (z !== created) z.networkIds = (z.networkIds as string[]).filter((x) => x !== nid);
            const n = st.networks.find((x) => x.id === nid);
            if (n) n.zoneId = created.id;
          }
          st.policies.push(...customZonePolicies(String(created.id)));
        }
        if (zoneBefore) {
          for (const nid of zoneBefore.networkIds as string[]) {
            (st.zones.find((z) => z.id === Z.internal)!.networkIds as string[]).push(nid);
            const n = st.networks.find((x) => x.id === nid);
            if (n) n.zoneId = Z.internal;
          }
          st.policies = st.policies.filter((p) => (p.source as Obj).zoneId !== zoneDel && (p.destination as Obj).zoneId !== zoneDel);
        }
        if (m === 'DELETE' && /^\/networks\/[^/]+$/.test(sub)) {
          const nid = sub.split('/').pop();
          for (const z of st.zones) z.networkIds = (z.networkIds as string[]).filter((x) => x !== nid);
        }
      }
      if (res) return res;
      if (sub === '/firewall/policies/ordering') {
        const s = String(req.query?.sourceFirewallZoneId);
        const d = String(req.query?.destinationFirewallZoneId);
        const pair = st.policies.filter((p) => (p.source as Obj).zoneId === s && (p.destination as Obj).zoneId === d && (p.metadata as Obj).origin === 'USER_DEFINED');
        if (m === 'GET') return ok({ orderedFirewallPolicyIds: { beforeSystemDefined: pair.sort((a, b) => Number(a.index) - Number(b.index)).map((p) => p.id), afterSystemDefined: [] } });
        if (m === 'PUT') {
          const ids = ((body.orderedFirewallPolicyIds as Obj)?.beforeSystemDefined as string[]) ?? [];
          ids.forEach((id, i) => {
            const p = st.policies.find((x) => x.id === id);
            if (p) p.index = 10000 + i;
          });
          return ok(body);
        }
      }
      if (sub === '/devices') {
        return page(
          st.devices.map((d) => ({
            id: uuid(800 + st.devices.indexOf(d)), name: d.name, model: d.model, macAddress: d.mac, ipAddress: d.ip, state: d.state === 1 ? 'ONLINE' : 'OFFLINE',
            supported: true, firmwareVersion: d.version, firmwareUpdatable: d.upgradable, features: d.type === 'udm' ? ['gateway', 'switching'] : d.type === 'uap' ? ['accessPoint'] : ['switching'], interfaces: ['ports'],
          })),
          req.query,
        );
      }
      return notFound(path);
    }

    // ---- internal API ----
    const lm = /^\/api\/s\/[^/]+(\/.*)$/.exec(path);
    if (lm) {
      const sub = lm[1];
      if (sub === '/stat/health') {
        const clients = st.clients;
        return v1([
          { subsystem: 'wan', status: 'ok', wan_ip: '203.0.113.47', gw_name: 'Dream Machine Pro', gw_mac: 'e4:38:83:aa:10:01', isp_name: 'Example Fiber', 'rx_bytes-r': Math.round(this.wanRx / 8), 'tx_bytes-r': Math.round(this.wanTx / 8), num_sta: clients.length, uptime_stats: { WAN: { availability: 100, latency_average: 9 } } },
          { subsystem: 'www', status: 'ok', latency: Math.round(8 + this.r() * 8), uptime: 1987654, xput_down: 941.2, xput_up: 512.7, speedtest_lastrun: Math.round(Date.now() / 1000) - 3600 },
          { subsystem: 'lan', status: 'ok', num_user: clients.filter((c) => c.is_wired).length, num_guest: 0, num_sw: 1 },
          { subsystem: 'wlan', status: 'ok', num_user: clients.filter((c) => !c.is_wired && !c.is_guest).length, num_guest: clients.filter((c) => c.is_guest).length, num_ap: 3, num_disconnected: 1 },
        ]);
      }
      if (sub === '/stat/sysinfo') return v1([{ version: '10.6.109', hostname: 'udm-pro', timezone: 'America/Chicago' }]);
      if (sub === '/stat/device') return v1(st.devices);
      if (sub === '/stat/sta') return v1(st.clients);
      if (sub === '/stat/remoteuservpn') return v1([]);
      if (sub === '/stat/report/hourly.user') return v1(st.clients.map((c) => ({ user: c.mac, time: Date.now() - 3600e3, rx_bytes: Math.round(Number(c.rx_bytes ?? 0) / 40), tx_bytes: Math.round(Number(c.tx_bytes ?? 0) / 40) })));
      if (sub === '/get/setting') return v1(st.settings);
      if (sub === '/rest/firewallgroup') return v1([]);
      if (sub === '/rest/firewallrule') return v1([]);
      // Network 10.3+ removed stat/ips/event (detections moved to v2 traffic-flows / system-log).
      const restColl = (name: string, list: Obj[]): HttpResponse | null => {
        if (sub === `/rest/${name}` && m === 'GET') return v1(list);
        const idm = new RegExp(`^\\/rest\\/${name}\\/([^/]+)$`).exec(sub);
        if (idm) {
          const item = list.find((x) => x._id === idm[1]);
          if (!item) return ok({ meta: { rc: 'error', msg: 'api.err.IdInvalid' }, data: [] }, 400);
          if (m === 'PUT') {
            Object.assign(item, body, { _id: item._id });
            return v1([item]);
          }
          if (m === 'GET') return v1([item]);
        }
        return null;
      };
      const r2 = restColl('networkconf', st.networkconf) ?? restColl('portforward', st.portforward) ?? restColl('wlanconf', st.wlanconf);
      if (r2) {
        // Keep the official-API mirror in sync for things it exposes.
        if (m === 'PUT' && sub.startsWith('/rest/wlanconf/')) {
          const w = st.wlanconf.find((x) => sub.endsWith(String(x._id)));
          const wb = st.wifi.find((x) => x.name === w?.name);
          if (w && wb) wb.clientIsolationEnabled = !!w.l2_isolation;
        }
        return r2;
      }
      const sm = /^\/rest\/setting\/([^/]+)\/([^/]+)$/.exec(sub);
      if (sm && m === 'PUT') {
        const s = st.settings.find((x) => x.key === sm[1] && x._id === sm[2]);
        if (!s) return ok({ meta: { rc: 'error', msg: 'api.err.IdInvalid' }, data: [] }, 400);
        Object.assign(s, body, { _id: s._id, key: s.key });
        return v1([s]);
      }
      return notFound(path);
    }
    const v2m = /^\/v2\/api\/site\/[^/]+(\/.*)$/.exec(path);
    if (v2m) {
      const sub = v2m[1];
      if (sub === '/trafficrules') return ok([]);
      const from = Number(body.timestampFrom ?? 0);
      const to = Number(body.timestampTo ?? Date.now());
      const pageNumber = Number(body.pageNumber ?? 0);
      if (sub === '/traffic-flows' && m === 'POST') {
        const types = (body.policy_type as string[] | undefined) ?? [];
        const size = Math.min(5000, Number(body.pageSize ?? 50));
        const actions = (body.action as string[] | undefined) ?? [];
        const directions = (body.direction as string[] | undefined) ?? [];
        // Asked for blocked traffic rather than intrusion prevention: the firewall's own blocks.
        const rows = (actions.includes('blocked') && !types.length ? fakeBlockedFlows(Date.now()) : st.threats).filter(
          (t) => Number(t.time) >= from && Number(t.time) <= to && (!types.length || types.includes('INTRUSION_PREVENTION')) && (!directions.length || directions.includes(String(t.direction))),
        );
        const data = rows.slice(pageNumber * size, (pageNumber + 1) * size);
        return ok({ data, has_next: (pageNumber + 1) * size < rows.length, or_more: false, page_number: pageNumber, total_element_count: rows.length, total_page_count: Math.ceil(rows.length / size) });
      }
      if (sub === '/system-log/threat-alert' && m === 'POST') {
        const size = Math.min(100, Number(body.pageSize ?? 50));
        const rows = st.threats
          .filter((t) => Number(t.time) >= from && Number(t.time) <= to)
          .map((t) => {
            const blocked = t.action === 'blocked';
            const src = (t.source as Obj).ip;
            const dst = (t.destination as Obj).ip;
            return {
              id: `a${t.id}`, category: 'SECURITY', subcategory: 'SECURITY_INTRUSION_PREVENTION', event: blocked ? 'THREAT_BLOCKED' : 'THREAT_DETECTED', key: blocked ? 'THREAT_BLOCKED_V3' : 'THREAT_DETECTED_V3',
              type: 'THREAT_DETECTION_AND_PREVENTION', severity: String(t.risk).toUpperCase(), status: 'NEW', timestamp: t.time, show_on_dashboard: false,
              title_raw: blocked ? 'Threat Detected and Blocked' : 'Threat Detected', message: `A network intrusion attempt from ${src} to ${dst} has been detected${blocked ? ' and blocked' : ''}.`,
              parameters: { SRC_IP: { id: src, name: src }, DST_IP: { id: dst, name: dst } },
            };
          });
        const data = rows.slice(pageNumber * size, (pageNumber + 1) * size);
        return ok({ data, page_number: pageNumber, total_element_count: rows.length, total_page_count: Math.ceil(rows.length / size) });
      }
      return notFound(path);
    }
    return notFound(path);
  }
}
