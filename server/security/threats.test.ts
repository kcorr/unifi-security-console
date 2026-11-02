import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { UniFiClient } from '../unifi/client.ts';
import { fetchThreats, parseIpsEvent, parseThreatAlert, parseTrafficFlow } from '../unifi/threats.ts';
import { analyzeSignature, assessSeverity } from './threatKb.ts';
import { toThreatEvent, type Directory } from './threats.ts';
import { AddrSet } from './sets.ts';
import type { NetInfo } from './model.ts';

// Shapes below are real captures from public UniFi client test fixtures (see research notes).
const LEGACY_IPS_EVENT = {
  _id: '5d2416c78f0385ccf1c6df44', archived: false, timestamp: 1562646211, flow_id: 1591464006222389, in_iface: 'eth1', event_type: 'alert',
  src_ip: '196.196.244.84', src_port: 51413, dest_ip: '192.168.3.2', dest_port: 36881, proto: 'UDP', app_proto: 'failed',
  srcipCountry: 'SE', srcipASN: 'AS42607 Internet Carrier Limited', catname: 'spamhaus', inner_alert_action: 'allowed',
  inner_alert_gid: 1, inner_alert_signature_id: 2400022, inner_alert_rev: 2673,
  inner_alert_signature: 'ET DROP Spamhaus DROP Listed Traffic Inbound group 23', inner_alert_category: 'Misc Attack',
  inner_alert_severity: 2, key: 'EVT_IPS_IpsAlert', subsystem: 'www', time: 1562646211000,
};

const FLOW_ROW = {
  id: '69fb51c955d0f00238bbabd5', action: 'blocked', count: 1, direction: 'outgoing', protocol: 'UDP', service: 'NTP', risk: 'low', time: 1778078152066,
  source: { ip: '192.168.2.253', port: 4162, mac: 'aa:bb:cc:dd:ee:03', client_name: 'Insteon', network_id: 'n1', network_name: 'IOT' },
  destination: { ip: '203.0.113.100', port: 123, region: 'US' },
  policies: [{ id: 'p1', internal_type: 'SIGNATURE', name: 'ET MALWARE Possible Mirai Variant CnC', type: 'INTRUSION_PREVENTION', ips_category: 'EMERGING_MALWARE' }],
  ips: { signature: 'ET MALWARE Possible Mirai Variant CnC', signature_id: 2027000, category_name: 'emerging-malware', signature_class: 'A Network Trojan was detected' },
};

const THREAT_ALERT = {
  category: 'SECURITY', subcategory: 'SECURITY_INTRUSION_PREVENTION', event: 'THREAT_BLOCKED', key: 'THREAT_BLOCKED_V3', id: '69fb4e3255d0f00238bba8c0',
  severity: 'LOW', timestamp: 1778077234330, title_raw: 'Threat Detected and Blocked',
  message: 'A network intrusion attempt from 192.168.3.62 to 100.126.147.59 has been detected and blocked.',
  parameters: { SRC_IP: { id: '192.168.3.62', name: '192.168.3.62' }, DST_IP: { id: '100.126.147.59', name: '100.126.147.59' } },
};

// Honeypot hits, modelled on UniFi's documented key names and the Security export of a live 10.6 console:
// the device that touched the decoy is named (CLIENT), with no address; DEVICE is the gateway.
const HONEYPOT_ALERT = {
  category: 'SECURITY', subcategory: 'SECURITY_HONEYPOT', event: 'HONEYPOT_HIT_DETECTED', key: 'HONEYPOT_HIT_DETECTED_KNOWN_CLIENT', id: 'a-honeypot-1',
  severity: 'HIGH', timestamp: 1793600030000, title_raw: 'Honeypot Triggered', message: 'Honeypot triggered by Laptop-01 00:07.',
  parameters: { CLIENT: { id: '02:00:00:00:00:07', name: 'Laptop-01 00:07', hostname: 'Laptop-01' }, DEVICE: { id: '02:00:00:00:00:06', ip: '192.168.3.1', name: 'Gateway' } },
};

// UniFi's Flows view shows the same hit with the policy "Honeypot" and no destination.
const HONEYPOT_FLOW = {
  id: 'f-honeypot-1', action: 'allowed', count: 1, direction: 'local', protocol: 'TCP', service: 'SSH', risk: 'low', time: 1793600000000,
  source: { ip: '192.168.3.40', port: 51522, mac: '02:00:00:00:00:07', client_name: 'Laptop-01', network_id: 'n0', network_name: 'LAN' },
  destination: {},
  policies: [{ id: 'p-hp', name: 'Honeypot' }],
};

function dir(): Directory {
  const net = { id: 'n1', name: 'IOT', vlan: 2, addrs: AddrSet.parse('192.168.2.0/24')!, raw: {} } as unknown as NetInfo;
  const lan = { id: 'n0', name: 'LAN', vlan: 1, addrs: AddrSet.parse('192.168.3.0/24')!, raw: {} } as unknown as NetInfo;
  return {
    networks: [net, lan],
    wanIps: new Set(['203.0.113.1']),
    byIp: new Map([
      ['192.168.3.2', { mac: null, name: 'NAS', networkId: 'n0' }],
      ['192.168.3.40', { mac: '02:00:00:00:00:07', name: 'Laptop-01', networkId: 'n0' }],
      ['192.168.3.20', { mac: '02:00:00:00:00:08', name: 'Phone-01', networkId: 'n0' }],
    ]),
    byMac: new Map([
      ['02:00:00:00:00:07', { ip: '192.168.3.40', name: 'Laptop-01' }],
      ['02:00:00:00:00:08', { ip: '192.168.3.20', name: 'Phone-01' }],
    ]),
    honeypots: ['192.168.2.2', '192.168.3.250'],
  };
}

test('legacy stat/ips/event documents parse (timestamp in seconds, time in ms)', () => {
  const r = parseIpsEvent(LEGACY_IPS_EVENT)!;
  assert.equal(r.ts, 1562646211000);
  assert.equal(r.action, 'alerted');
  assert.equal(r.srcCountry, 'SE');
  assert.equal(r.srcOrg, 'AS42607 Internet Carrier Limited');
  const e = toThreatEvent(r, dir());
  assert.equal(e.direction, 'inbound');
  assert.equal(e.categoryKey, 'reputation');
  assert.equal(e.local?.name, 'NAS');
  assert.equal(e.remoteIp, '196.196.244.84');
});

test('v2 traffic-flow IPS rows parse and outbound malware is critical', () => {
  const r = parseTrafficFlow(FLOW_ROW)!;
  assert.equal(r.action, 'blocked');
  assert.equal(r.srcName, 'Insteon');
  const e = toThreatEvent(r, dir());
  assert.equal(e.direction, 'outbound');
  assert.equal(e.categoryKey, 'malware');
  assert.equal(e.severity, 'critical');
  assert.equal(e.local?.name, 'Insteon');
  assert.equal(e.remoteCountry, 'US');
});

test('v2 system-log threat alerts parse without a signature', () => {
  const r = parseThreatAlert(THREAT_ALERT)!;
  assert.equal(r.action, 'blocked');
  assert.equal(r.srcIp, '192.168.3.62');
  const e = toThreatEvent(r, dir());
  assert.equal(e.direction, 'outbound', '100.64/10 is CGNAT, but the destination is not one of our networks');
});

test('a honeypot hit that names only the device becomes a serious detection by that device', () => {
  const r = parseThreatAlert(HONEYPOT_ALERT)!;
  assert.ok(r, 'it used to be dropped for having no addresses');
  assert.equal(r.category, 'honeypot');
  assert.equal(r.srcMac, '02:00:00:00:00:07');
  assert.equal(r.dstIp, '', "the gateway's own address is not the decoy's");
  const e = toThreatEvent(r, dir());
  assert.equal(e.srcIp, '192.168.3.40', 'its address comes from the device list');
  assert.equal(e.dstIp, '192.168.3.250', 'the decoy on its own network');
  assert.equal(e.direction, 'internal');
  assert.equal(e.categoryKey, 'honeypot');
  assert.equal(e.severity, 'critical', 'UniFi rated it high, and it came from inside');
  assert.equal(e.local?.name, 'Laptop-01');
  assert.match(e.advice, /scanner|monitoring/);
});

test('a honeypot hit by a device that has left still shows who it was', () => {
  const gone = { ...HONEYPOT_ALERT, id: 'a-honeypot-2', parameters: { CLIENT: { id: '02:00:00:00:00:09', name: 'Tablet 00:09' } } };
  const e = toThreatEvent(parseThreatAlert(gone)!, dir());
  assert.equal(e.srcIp, '');
  assert.equal(e.dstIp, '', 'two decoys and no address: which one is unknown');
  assert.equal(e.direction, 'internal');
  assert.equal(e.local?.name, 'Tablet 00:09');
  assert.equal(e.local?.mac, '02:00:00:00:00:09');
  assert.equal(e.localIp, null);
  assert.equal(e.remoteIp, null);
});

test('a honeypot hit with addresses keeps them', () => {
  const r = parseThreatAlert({ ...HONEYPOT_ALERT, key: 'HONEYPOT_HIT_DETECTED', parameters: { SRC_IP: { id: '192.168.2.50', name: '192.168.2.50' }, DST_IP: { id: '192.168.2.2', name: '192.168.2.2' } } })!;
  const e = toThreatEvent(r, dir());
  assert.deepEqual([e.srcIp, e.dstIp, e.direction, e.local?.network], ['192.168.2.50', '192.168.2.2', 'internal', 'IOT']);
});

test('a honeypot flow without a destination is read, and the decoy is filled in', () => {
  const r = parseTrafficFlow(HONEYPOT_FLOW)!;
  assert.ok(r, 'it used to be dropped for having no destination');
  assert.equal(r.signature, 'UniFi internal honeypot triggered');
  const e = toThreatEvent(r, dir());
  assert.deepEqual([e.srcIp, e.dstIp, e.dstPort, e.appProto], ['192.168.3.40', '192.168.3.250', null, 'SSH']);
  assert.equal(e.categoryKey, 'honeypot');
  assert.equal(e.severity, 'high');
  assert.equal(parseTrafficFlow({ ...FLOW_ROW, destination: {} }), null, 'other flows still need a destination');
});

test('an alert about a device UniFi knows by name gets its address from the device list', () => {
  const alert = {
    ...THREAT_ALERT, id: 'a-known-1', key: 'THREAT_BLOCKED_KNOWN_DESTINATION_CLIENT',
    message: 'A network intrusion attempt from 203.0.113.10 to Phone-01 00:08 has been detected and blocked.',
    parameters: { SRC_IP: { id: '203.0.113.10', name: '203.0.113.10' }, DST_CLIENT: { id: '02:00:00:00:00:08', name: 'Phone-01 00:08', hostname: 'Phone-01' } },
  };
  const e = toThreatEvent(parseThreatAlert(alert)!, dir());
  assert.deepEqual([e.srcIp, e.dstIp, e.direction, e.local?.name], ['203.0.113.10', '192.168.3.20', 'inbound', 'Phone-01']);
});

test('a honeypot hit in both the flows and the system log is counted once', async () => {
  const other = { ...HONEYPOT_ALERT, id: 'a-honeypot-3', parameters: { CLIENT: { id: '02:00:00:00:00:0a', name: 'Printer 00:0a' } } };
  // A detection of the same device's traffic by the intrusion prevention engine does not hide a honeypot hit.
  const ips = { ...FLOW_ROW, id: 'f-ips-1', time: 1793600010000, source: HONEYPOT_FLOW.source, destination: { ip: '192.168.3.250', port: 22 } };
  const client = {
    v2: async (_m: string, p: string, body: { pageNumber: number }) => {
      if (body.pageNumber > 0) return { data: [] };
      if (p === '/traffic-flows') return { data: [HONEYPOT_FLOW, ips], has_next: false };
      if (p === '/system-log/threat-alert') return { data: [HONEYPOT_ALERT, other], total_page_count: 1 };
      throw new Error(`404 ${p}`);
    },
    v1: async () => {
      throw new Error('404 not found');
    },
  } as unknown as UniFiClient;
  const res = await fetchThreats(client, 0, Date.now());
  const pots = res.events.filter((e) => e.category === 'honeypot');
  assert.deepEqual(pots.map((e) => e.id).sort(), ['alert:a-honeypot-3', 'flow:f-honeypot-1']);
  assert.equal(res.events.length, 3);
  assert.match(res.sources.find((s) => s.name === 'System log threat alerts')!.detail, /2 alerts \(2 honeypot\), 1 not covered/);
});

test('signature classification', () => {
  assert.equal(analyzeSignature('ET SCAN Potential SSH Scan').categoryKey, 'bruteforce');
  assert.equal(analyzeSignature('ET SCAN Suspicious inbound to mySQL port 3306').headline, 'Database service probe');
  assert.equal(analyzeSignature('ET TROJAN Win32/Agent telnet beacon').categoryKey, 'malware', 'keywords never downgrade malware');
  assert.equal(analyzeSignature('ET TROJAN Win32/Agent telnet beacon').headline, 'Malware / command-and-control');
  assert.deepEqual(analyzeSignature('ET EXPLOIT Apache log4j RCE Attempt (CVE-2021-44228)').cves, ['CVE-2021-44228']);
  assert.equal(analyzeSignature('SURICATA STREAM ESTABLISHED packet out of window').categoryKey, 'anomaly');
  assert.equal(analyzeSignature('Something odd', { catname: 'DARK_WEB_BLOCKER_LIST' }).categoryKey, 'reputation');
  assert.equal(assessSeverity({ categoryKey: 'scan', priority: 3, direction: 'inbound', blocked: true }), 'info');
  assert.equal(assessSeverity({ categoryKey: 'scan', priority: 2, direction: 'outbound', blocked: false }), 'high', 'your own device scanning others is escalated');
});
