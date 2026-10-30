import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  AddrSet, RangeSet, ServiceSet, parsePorts, parseIPv6, formatIPv6, makeSpace, spaceContains, spaceSubtract, spaceIsEmpty,
  ST_ALL, ST_NEW, ST_EST, PORTS_ALL,
} from './sets.ts';

test('RangeSet union/intersect/subtract', () => {
  const a = new RangeSet([[1n, 10n], [20n, 30n]]);
  const b = new RangeSet([[5n, 25n]]);
  assert.equal(a.union(b).key(), '1-30');
  assert.equal(a.intersect(b).key(), '5-10,20-25');
  assert.equal(a.subtract(b).key(), '1-4,26-30');
  assert.equal(b.subtract(a).key(), '11-19');
  assert.ok(a.union(b).contains(a));
  assert.ok(!a.contains(b));
  assert.equal(new RangeSet([[1n, 2n], [3n, 4n]]).key(), '1-4', 'adjacent intervals merge');
});

test('AddrSet parsing masks host bits like UniFi subnets', () => {
  const net = AddrSet.parse('192.168.30.1/24')!;
  assert.deepEqual(net.toStrings(), ['192.168.30.0/24']);
  assert.ok(net.has('192.168.30.200'));
  assert.ok(!net.has('192.168.31.1'));
  const range = AddrSet.parse('10.0.0.0-10.0.0.255')!;
  assert.ok(range.equals(AddrSet.parse('10.0.0.0/24')!));
  assert.ok(AddrSet.parse('10.0.0.0/8')!.contains(net.union(AddrSet.parse('10.1.2.3')!)) === false);
  assert.equal(AddrSet.parse('nonsense'), null);
  assert.ok(AddrSet.parse('any')!.isAny());
});

test('IPv6 parse/format round trip', () => {
  for (const ip of ['::1', 'fe80::1', '2001:db8::', '2001:db8:0:1::5', '::ffff:192.168.1.1', '64:ff9b::1.2.3.4']) {
    const n = parseIPv6(ip);
    assert.notEqual(n, null, ip);
  }
  assert.equal(formatIPv6(parseIPv6('2001:0db8:0000:0000:0000:0000:0000:0001')!), '2001:db8::1');
  assert.equal(formatIPv6(parseIPv6('::ffff:192.168.1.1')!), '::ffff:c0a8:101');
  assert.equal(parseIPv6('1::2::3'), null);
  assert.deepEqual(AddrSet.parse('fd00:10::/64')!.toStrings(), ['fd00:10::/64']);
});

test('ports and services', () => {
  assert.equal(parsePorts('53,853')!.key(), '53,853');
  assert.equal(parsePorts('8000-8100')!.key(), '8000-8100');
  assert.equal(parsePorts('8000:8100')!.key(), '8000-8100');
  assert.equal(parsePorts('abc'), null);
  const dns = ServiceSet.fromProtocol('tcp_udp', parsePorts('53'))!;
  const udpDns = ServiceSet.fromProtocol('udp', parsePorts('53'))!;
  assert.ok(dns.contains(udpDns));
  assert.ok(!udpDns.contains(dns));
  assert.equal(dns.describe(), 'TCP/UDP 53');
  assert.equal(dns.subtract(udpDns).describe(), 'TCP 53');
  assert.ok(ServiceSet.ALL.contains(dns));
  assert.equal(ServiceSet.fromProtocol('all', null)!.describe(), 'all traffic');
  assert.ok(ServiceSet.fromProtocol('all', PORTS_ALL)!.isAll());
});

test('space containment detects equivalent rules written differently', () => {
  const iot = AddrSet.parse('192.168.30.1/24')!;
  const internet = AddrSet.parse('192.168.0.0/16')!.invert().intersect(AddrSet.V4_ANY);
  // Rule A: block TCP+UDP 53 from IoT subnet to the internet, all states.
  const a = makeSpace(iot, internet, ServiceSet.tcpUdp(parsePorts('53')!), ST_ALL);
  // Rule B: same thing expressed as UDP 53 + TCP 53 split, new connections only, from a range.
  const b = [
    ...makeSpace(AddrSet.parse('192.168.30.0-192.168.30.255')!, internet, ServiceSet.udp(parsePorts('53')!), ST_NEW),
    ...makeSpace(AddrSet.parse('192.168.30.0/24')!, internet, ServiceSet.tcp(parsePorts('53')!), ST_NEW),
  ];
  assert.ok(spaceContains(a, b), 'A covers B');
  assert.ok(!spaceContains(b, a), 'B does not cover established/related states');
  const newOnlyA = makeSpace(iot, internet, ServiceSet.tcpUdp(parsePorts('53')!), ST_NEW);
  assert.ok(spaceContains(b, newOnlyA) && spaceContains(newOnlyA, b), 'equivalent for new connections');
  const leftover = spaceSubtract(a, b);
  assert.ok(!spaceIsEmpty(leftover));
  assert.ok(leftover.every((x) => (x.st & ST_NEW) === 0 && (x.st & ST_EST) !== 0));
});
