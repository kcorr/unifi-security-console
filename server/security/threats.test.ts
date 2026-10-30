import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseIpsEvent, parseThreatAlert, parseTrafficFlow } from '../unifi/threats.ts';
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

function dir(): Directory {
  const net = { id: 'n1', name: 'IOT', vlan: 2, addrs: AddrSet.parse('192.168.2.0/24')!, raw: {} } as unknown as NetInfo;
  const lan = { id: 'n0', name: 'LAN', vlan: 1, addrs: AddrSet.parse('192.168.3.0/24')!, raw: {} } as unknown as NetInfo;
  return { networks: [net, lan], wanIps: new Set(['203.0.113.1']), byIp: new Map([['192.168.3.2', { mac: null, name: 'NAS', networkId: 'n0' }]]), byMac: new Map() };
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
