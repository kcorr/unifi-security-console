// Builds the normalized firewall model (networks, zones, groups, rules) from a raw snapshot.

import { TEST_NETWORK_PREFIX, type NetworkRole, type RuleAction } from '../../shared/types.ts';
import type { RawSnapshot } from '../unifi/collect.ts';
import type { FwModel, GroupInfo, NetInfo, NormRule, ZoneInfo } from './model.ts';
import { inferRole } from './roles.ts';
import {
  AddrSet, PORTS_ALL, RangeSet, ServiceSet, ST_ALL, ST_EST, ST_INV, ST_NEW, ST_REL, describeStates, formatPorts, makeSpace, parsePorts, type Space,
} from './sets.ts';

type Obj = Record<string, unknown>;

export const MANAGED_PREFIX = '[SC]';
export const MANAGED_MARKER = 'usc:';

const str = (v: unknown): string => (typeof v === 'string' ? v : v === undefined || v === null ? '' : String(v));
const arr = <T = unknown>(v: unknown): T[] => (Array.isArray(v) ? (v as T[]) : []);
const obj = (v: unknown): Obj => (v && typeof v === 'object' && !Array.isArray(v) ? (v as Obj) : {});

const SPECIAL_RANGES = AddrSet.parseList([
  '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.168.0.0/16', '198.18.0.0/15', '224.0.0.0/3',
  '::/8', 'fc00::/7', 'fe80::/10', 'ff00::/8',
]).set;

export function isManagedRule(name: string, description: string): boolean {
  return name.startsWith(MANAGED_PREFIX) || description.includes(MANAGED_MARKER);
}

// ---------------------------------------------------------------------------------
// Networks & zones
// ---------------------------------------------------------------------------------

function subnetFromHost(host: string, prefix: number | null | undefined): string | null {
  if (!host || prefix === null || prefix === undefined) return null;
  return `${host}/${prefix}`;
}

function zoneKey(name: string, explicit?: string | null): string | null {
  if (explicit) return explicit.toLowerCase();
  const n = name.toLowerCase().trim();
  if (['internal', 'external', 'gateway', 'vpn', 'hotspot', 'dmz'].includes(n)) return n;
  return null;
}

function mergeNetworkconf(nc: Obj[], name: string, vlan: number | null): Obj | undefined {
  return (
    nc.find((n) => str(n.name) === name && (vlan === null || Number(n.vlan ?? (n.vlan_enabled ? NaN : 1)) === vlan || (!n.vlan_enabled && vlan === 1))) ??
    nc.find((n) => str(n.name) === name)
  );
}

function dhcpDnsFromConf(nc: Obj | undefined): string[] {
  if (!nc) return [];
  if (nc.dhcpd_dns_enabled === false) return [];
  return [nc.dhcpd_dns_1, nc.dhcpd_dns_2, nc.dhcpd_dns_3, nc.dhcpd_dns_4].map(str).filter(Boolean);
}

function buildNetworks(raw: RawSnapshot, roles: Map<string, NetworkRole>): NetInfo[] {
  const out: NetInfo[] = [];
  const make = (p: {
    id: string;
    name: string;
    vlan: number | null;
    purpose: string;
    subnet: string | null;
    subnet6: string | null;
    zoneId: string | null;
    isolated: boolean;
    internetAccess: boolean;
    enabled: boolean;
    dhcpDns: string[];
    raw: Obj;
    legacyId?: string;
  }) => {
    const v4 = p.subnet ? AddrSet.parse(p.subnet) : null;
    const v6 = p.subnet6 ? AddrSet.parse(p.subnet6) : null;
    const gw = p.subnet ? p.subnet.split('/')[0] : null;
    const override = roles.get(p.id) ?? (p.legacyId ? roles.get(p.legacyId) : undefined);
    out.push({
      id: p.id,
      name: p.name,
      vlan: p.vlan,
      purpose: p.purpose,
      addrs: (v4 ?? AddrSet.EMPTY).union(v6 ?? AddrSet.EMPTY),
      subnet: v4 ? v4.toStrings()[0] : null,
      subnet6: v6 ? v6.toStrings()[0] : null,
      gatewayAddrs: gw ? AddrSet.parse(gw) ?? AddrSet.EMPTY : AddrSet.EMPTY,
      gatewayIp: gw,
      zoneId: p.zoneId,
      role: override ?? inferRole(p.name, p.purpose),
      roleSource: override ? 'user' : 'auto',
      isolated: p.isolated,
      internetAccess: p.internetAccess,
      enabled: p.enabled,
      dhcpDns: p.dhcpDns,
      ipv6: !!v6,
      isTest: p.name.startsWith(TEST_NETWORK_PREFIX),
      raw: { ...p.raw, ...(p.legacyId ? { _legacyId: p.legacyId } : {}) },
    });
  };

  if (raw.firewallSource === 'integration' && raw.iNetworks.length) {
    for (const n of raw.iNetworks) {
      if (str(n.management) && str(n.management) !== 'GATEWAY') continue;
      const v4c = obj(n.ipv4Configuration);
      const name = str(n.name);
      const vlan = n.vlanId === undefined ? null : Number(n.vlanId);
      const nc = mergeNetworkconf(raw.networkconf, name, vlan);
      const dhcp = obj(v4c.dhcpConfiguration);
      const dnsOverride = arr<string>(dhcp.dnsServerIpAddressesOverride);
      make({
        id: str(n.id),
        name,
        vlan,
        purpose: str(nc?.purpose) || (str(n.default) === 'true' ? 'corporate' : 'corporate'),
        subnet: subnetFromHost(str(v4c.hostIpAddress), v4c.prefixLength as number) ?? (str(nc?.ip_subnet) || null),
        subnet6: str(nc?.ipv6_subnet) || null,
        zoneId: str(n.zoneId) || null,
        isolated: n.isolationEnabled === true || nc?.network_isolation_enabled === true,
        internetAccess: n.internetAccessEnabled !== false && nc?.internet_access_enabled !== false,
        enabled: n.enabled !== false,
        dhcpDns: dnsOverride.length ? dnsOverride : dhcpDnsFromConf(nc),
        raw: n,
        legacyId: nc ? str(nc._id) : undefined,
      });
    }
  } else {
    for (const n of raw.networkconf) {
      const purpose = str(n.purpose);
      if (!['corporate', 'guest', 'vlan-only'].includes(purpose)) continue;
      if (!n.ip_subnet && purpose !== 'vlan-only') continue;
      if (purpose === 'vlan-only' && !n.ip_subnet) continue;
      const vlan = n.vlan_enabled ? Number(n.vlan) : n.vlan !== undefined && n.vlan !== '' ? Number(n.vlan) : 1;
      make({
        id: str(n._id),
        name: str(n.name),
        vlan: Number.isFinite(vlan) ? vlan : null,
        purpose,
        subnet: str(n.ip_subnet) || null,
        subnet6: str(n.ipv6_subnet) || null,
        zoneId: str(n.firewall_zone_id) || null,
        isolated: n.network_isolation_enabled === true,
        internetAccess: n.internet_access_enabled !== false,
        enabled: n.enabled !== false,
        dhcpDns: dhcpDnsFromConf(n),
        raw: n,
      });
    }
  }
  return out.sort((a, b) => (a.vlan ?? 0) - (b.vlan ?? 0) || a.name.localeCompare(b.name));
}

function buildZones(raw: RawSnapshot, networks: NetInfo[]): ZoneInfo[] {
  let zones: ZoneInfo[] = [];
  if (raw.firewallSource === 'integration') {
    zones = raw.iZones.map((z) => ({ id: str(z.id), name: str(z.name), key: zoneKey(str(z.name)), networkIds: arr<string>(z.networkIds) }));
  } else if (raw.firewallSource === 'internal-v2') {
    zones = raw.v2Zones.map((z) => ({ id: str(z._id ?? z.id), name: str(z.name), key: zoneKey(str(z.name), str(z.zone_key) || null), networkIds: arr<string>(z.network_ids ?? z.networkIds) }));
  }
  // Fill network.zoneId from zone membership when the network object does not carry it.
  for (const n of networks) {
    if (n.zoneId && zones.some((z) => z.id === n.zoneId)) continue;
    const z = zones.find((x) => x.networkIds.includes(n.id) || (n.raw._legacyId && x.networkIds.includes(str(n.raw._legacyId))));
    if (z) n.zoneId = z.id;
    else if (zones.length) {
      const fallback = zones.find((x) => x.key === (n.purpose === 'guest' ? 'hotspot' : 'internal'));
      if (fallback) n.zoneId = fallback.id;
    }
  }
  return zones;
}

/** Display names of each zone's members, including WAN and VPN networks that the model itself does not track. */
export function zoneMemberNames(model: FwModel, raw: RawSnapshot): Map<string, string[]> {
  const byId = new Map<string, string>();
  for (const c of raw.networkconf) byId.set(str(c._id), str(c.name));
  for (const n of model.networks) {
    byId.set(n.id, n.name);
    if (n.raw._legacyId) byId.set(str(n.raw._legacyId), n.name);
  }
  const out = new Map<string, string[]>();
  for (const z of model.zones) {
    let names = z.networkIds.map((id) => byId.get(id));
    if (names.includes(undefined)) {
      // The official API refers to WAN / VPN members by ids it never lists; the internal zone list uses networkconf ids.
      const alt = raw.v2Zones.find((v) => (z.key !== null && str(v.zone_key) === z.key) || str(v.name).toLowerCase() === z.name.toLowerCase());
      const altNames = alt ? arr<string>(alt.network_ids).map((id) => byId.get(str(id))) : [];
      if (altNames.length && !altNames.includes(undefined)) names = altNames;
    }
    const known = names.filter((x) => x !== undefined);
    out.set(z.id, known.length < names.length ? [...known, `${names.length - known.length} other`] : known);
  }
  return out;
}

function buildGroups(raw: RawSnapshot): Map<string, GroupInfo> {
  const m = new Map<string, GroupInfo>();
  for (const l of raw.iLists) {
    const type = str(l.type);
    const items = arr<Obj>(l.items);
    if (type === 'PORTS') {
      const ivs = items.map((it) => (str(it.type) === 'PORT_NUMBER_RANGE' ? `${it.start}-${it.stop}` : str(it.value)));
      m.set(str(l.id), { id: str(l.id), name: str(l.name), type: 'port', members: ivs, addrs: null, ports: parsePorts(ivs.join(',')) ?? new RangeSet() });
    } else {
      const members = items.map((it) => (str(it.type) === 'IP_ADDRESS_RANGE' ? `${it.start}-${it.stop}` : str(it.value)));
      m.set(str(l.id), { id: str(l.id), name: str(l.name), type: type === 'IPV6_ADDRESSES' ? 'ipv6-address' : 'address', members, addrs: AddrSet.parseList(members).set, ports: null });
    }
  }
  for (const g of raw.firewallGroups) {
    const gt = str(g.group_type);
    const members = arr<string>(g.group_members).map(str);
    const id = str(g._id);
    if (gt === 'port-group') m.set(id, { id, name: str(g.name), type: 'port', members, addrs: null, ports: parsePorts(members.join(',')) ?? new RangeSet() });
    else m.set(id, { id, name: str(g.name), type: gt === 'ipv6-address-group' ? 'ipv6-address' : gt === 'address-group' ? 'address' : 'other', members, addrs: AddrSet.parseList(members).set, ports: null });
  }
  return m;
}

// ---------------------------------------------------------------------------------
// Rule conversion helpers
// ---------------------------------------------------------------------------------

interface Endpoint {
  addrs: AddrSet;
  ports: RangeSet | null;
  exact: boolean;
  desc: string;
  networkIds: string[] | null;
  any: boolean;
  notes: string[];
  /** ISO country codes when the endpoint matches by country (GeoIP). */
  regions?: string[];
}

function netAddrs(model: { networks: NetInfo[] }, ids: string[]): { set: AddrSet; names: string[]; missing: string[] } {
  let set = AddrSet.EMPTY;
  const names: string[] = [];
  const missing: string[] = [];
  for (const id of ids) {
    const n = model.networks.find((x) => x.id === id || x.raw._legacyId === id);
    if (n) {
      set = set.union(n.addrs);
      names.push(n.name);
    } else missing.push(id);
  }
  return { set, names, missing };
}

function joinNames(xs: string[], max = 4): string {
  if (xs.length <= max) return xs.join(', ');
  return `${xs.slice(0, max).join(', ')} +${xs.length - max} more`;
}

function portsFromIntegrationFilter(pf: Obj, groups: Map<string, GroupInfo>, notes: string[]): { ports: RangeSet | null; desc: string; exact: boolean } {
  if (!pf || !pf.type) return { ports: null, desc: '', exact: true };
  let set: RangeSet;
  let desc: string;
  if (str(pf.type) === 'TRAFFIC_MATCHING_LIST') {
    const g = groups.get(str(pf.trafficMatchingListId));
    if (!g || !g.ports) {
      notes.push('References a port list that could not be found.');
      return { ports: PORTS_ALL, desc: '(unknown list)', exact: false };
    }
    // Read after "port": `… port list "DNS Ports"`.
    set = g.ports;
    desc = `list "${g.name}"`;
  } else {
    const items = arr<Obj>(pf.items).map((it) => (str(it.type) === 'PORT_NUMBER_RANGE' ? `${it.start}-${it.stop}` : str(it.value)));
    set = parsePorts(items.join(',')) ?? new RangeSet();
    desc = formatPorts(set);
  }
  if (pf.matchOpposite === true) {
    set = PORTS_ALL.subtract(set);
    desc = `not ${desc}`;
  }
  return { ports: set, desc, exact: true };
}

function integrationEndpoint(ep: Obj, side: 'src' | 'dst', model: { networks: NetInfo[]; zones: ZoneInfo[] }, groups: Map<string, GroupInfo>): Endpoint {
  const zone = model.zones.find((z) => z.id === str(ep.zoneId));
  const zoneName = zone?.name ?? 'Unknown zone';
  const tf = obj(ep.trafficFilter);
  const notes: string[] = [];
  const type = str(tf.type);
  let addrs = AddrSet.ANY;
  let exact = true;
  let what = '';
  let networkIds: string[] | null = null;
  let regions: string[] | undefined;
  let any = !type;

  const portRes = portsFromIntegrationFilter(obj(tf.portFilter), groups, notes);
  if (!portRes.exact) exact = false;

  switch (type) {
    case '':
      break;
    case 'PORT':
      any = true;
      break;
    case 'NETWORK': {
      const nf = obj(tf.networkFilter);
      const ids = arr<string>(nf.networkIds);
      const r = netAddrs(model, ids);
      if (r.missing.length) notes.push(`References ${r.missing.length} network(s) that no longer exist.`);
      if (nf.matchOpposite === true) {
        addrs = AddrSet.ANY.subtract(r.set);
        what = `all networks except ${joinNames(r.names)}`;
      } else {
        addrs = r.set;
        what = joinNames(r.names) || 'no networks';
        networkIds = ids;
      }
      break;
    }
    case 'IP_ADDRESS': {
      const f = obj(tf.ipAddressFilter);
      if (str(f.type) === 'TRAFFIC_MATCHING_LIST') {
        const g = groups.get(str(f.trafficMatchingListId));
        if (g?.addrs) {
          addrs = g.addrs;
          what = `address list "${g.name}"`;
        } else {
          exact = false;
          what = 'unknown address list';
          notes.push('References an address list that could not be found.');
        }
      } else {
        const items = arr<Obj>(f.items).map((it) => (str(it.type) === 'IP_ADDRESS_RANGE' ? `${it.start}-${it.stop}` : str(it.value)));
        const parsed = AddrSet.parseList(items);
        addrs = parsed.set;
        what = joinNames(items);
        if (parsed.invalid.length) notes.push(`Unparseable addresses: ${parsed.invalid.join(', ')}`);
      }
      if (f.matchOpposite === true) {
        addrs = AddrSet.ANY.subtract(addrs);
        what = `anything except ${what}`;
      }
      break;
    }
    case 'MAC_ADDRESS': {
      const macs = arr<string>(obj(tf.macAddressFilter).macAddresses);
      exact = false;
      what = `device${macs.length === 1 ? '' : 's'} ${joinNames(macs, 2)}`;
      notes.push('Matches specific devices by MAC address; analysed as "may apply".');
      break;
    }
    case 'REGION': {
      regions = arr<string>(obj(tf.regionFilter).regions).map((r) => r.toUpperCase());
      exact = false;
      what = `region${regions.length === 1 ? '' : 's'} ${joinNames(regions, 6)}`;
      notes.push('Matches by country (GeoIP); analysed as "may apply".');
      break;
    }
    case 'DOMAIN': {
      const domains = arr<string>(obj(tf.domainFilter).domains);
      exact = false;
      what = `domain${domains.length === 1 ? '' : 's'} ${joinNames(domains, 3)}`;
      notes.push('Matches by domain name; analysed as "may apply".');
      break;
    }
    case 'APPLICATION':
    case 'APPLICATION_CATEGORY':
      exact = false;
      what = type === 'APPLICATION' ? 'specific applications' : 'application categories';
      notes.push('Matches by application (DPI); analysed as "may apply".');
      break;
    case 'VPN_SERVER':
    case 'SITE_TO_SITE_VPN_TUNNEL':
      exact = false;
      what = type === 'VPN_SERVER' ? 'VPN server clients' : 'site-to-site VPN';
      notes.push('Matches VPN traffic; analysed as "may apply".');
      break;
    case 'IPV6_IID':
      exact = false;
      what = 'IPv6 interface identifier';
      notes.push('Matches IPv6 interface identifiers; analysed as "may apply".');
      break;
    default:
      exact = false;
      what = type.toLowerCase();
      notes.push(`Unrecognised filter type ${type}.`);
  }
  // A MAC filter can also be attached to IP/NETWORK source filters.
  if (side === 'src' && (type === 'IP_ADDRESS' || type === 'NETWORK') && tf.macAddressFilter) {
    exact = false;
    notes.push('Additionally restricted to a MAC address.');
  }
  if (side === 'src' && portRes.ports && !portRes.ports.equals(PORTS_ALL)) {
    exact = false;
    notes.push('Restricts source ports; analysed as "may apply".');
  }
  const portsDesc = side === 'dst' && portRes.ports && !portRes.ports.equals(PORTS_ALL) ? ` port ${portRes.desc}` : '';
  const desc = `${what || (zone?.key === 'external' ? 'the internet' : `anything in ${zoneName}`)}${what ? ` (${zoneName})` : ''}${portsDesc}`;
  return { addrs, ports: side === 'dst' ? portRes.ports : null, exact, desc, networkIds, any, notes, regions };
}

function serviceFromIntegrationScope(scope: Obj, dstPorts: RangeSet | null, notes: string[]): { svc: ServiceSet; exact: boolean; families: AddrSet } {
  const ipv = str(scope.ipVersion);
  const families = ipv === 'IPV4' ? AddrSet.V4_ANY : ipv === 'IPV6' ? AddrSet.V6_ANY : AddrSet.ANY;
  const pf = obj(scope.protocolFilter);
  let svc: ServiceSet | null;
  let exact = true;
  const ports = dstPorts && !dstPorts.equals(PORTS_ALL) ? dstPorts : null;
  switch (str(pf.type)) {
    case '':
      svc = ports ? ServiceSet.tcpUdp(ports) : ServiceSet.ALL;
      break;
    case 'PRESET':
      svc = ServiceSet.tcpUdp(ports ?? PORTS_ALL);
      break;
    case 'NAMED_PROTOCOL': {
      const name = str(obj(pf.protocol).name).toLowerCase();
      svc = ServiceSet.fromProtocol(name === 'icmpv6' ? 'icmpv6' : name, ports);
      if (obj(pf.protocol).typenameFilter || pf.typenameFilter) {
        exact = false;
        notes.push('Restricted to specific ICMP types.');
      }
      if (svc && pf.matchOpposite === true) svc = svc.invert();
      break;
    }
    case 'PROTOCOL_NUMBER':
      svc = ServiceSet.fromProtocol(Number(pf.protocolNumber), ports);
      if (svc && pf.matchOpposite === true) svc = svc.invert();
      break;
    default:
      svc = null;
  }
  if (!svc) {
    notes.push('Unrecognised protocol filter.');
    return { svc: ServiceSet.ALL, exact: false, families };
  }
  return { svc, exact, families };
}

function statesFromList(list: unknown): number {
  const xs = arr<string>(list).map((s) => s.toUpperCase());
  if (!xs.length) return ST_ALL;
  let st = 0;
  if (xs.includes('NEW')) st |= ST_NEW;
  if (xs.includes('ESTABLISHED')) st |= ST_EST;
  if (xs.includes('RELATED')) st |= ST_REL;
  if (xs.includes('INVALID')) st |= ST_INV;
  return st || ST_ALL;
}

function famLabel(f: AddrSet): NormRule['ipVersion'] {
  if (f.v4.isEmpty()) return 'IPv6';
  if (f.v6.isEmpty()) return 'IPv4';
  return 'IPv4 + IPv6';
}

function scheduleText(s: Obj): string | null {
  const mode = str(s.mode);
  if (!mode || mode === 'ALWAYS') return null;
  const tf = obj(s.timeFilter ?? s.time_range);
  const time = tf.startTime ? ` ${tf.startTime}–${tf.stopTime}` : '';
  const days = arr<string>(s.repeatOnDays ?? s.repeat_on_days);
  return `${mode.toLowerCase().replace(/_/g, ' ')}${days.length ? ` (${days.map((d) => d.slice(0, 3).toLowerCase()).join(', ')})` : ''}${time}`;
}

// ---------------------------------------------------------------------------------
// Official API zone policies
// ---------------------------------------------------------------------------------

function convertIntegrationPolicy(p: Obj, model: { networks: NetInfo[]; zones: ZoneInfo[] }, groups: Map<string, GroupInfo>): NormRule {
  const notes: string[] = [];
  const src = integrationEndpoint(obj(p.source), 'src', model, groups);
  const dst = integrationEndpoint(obj(p.destination), 'dst', model, groups);
  notes.push(...src.notes, ...dst.notes);
  const svcRes = serviceFromIntegrationScope(obj(p.ipProtocolScope), dst.ports, notes);
  const st = statesFromList(p.connectionStateFilter);
  const actionType = str(obj(p.action).type).toUpperCase();
  const action: RuleAction = actionType === 'ALLOW' ? 'allow' : actionType === 'REJECT' ? 'reject' : 'block';
  let exact = src.exact && dst.exact && svcRes.exact;
  const schedule = p.schedule ? scheduleText(obj(p.schedule)) : null;
  if (schedule) {
    exact = false;
    notes.push(`Only active on a schedule (${schedule}).`);
  }
  if (p.ipsecFilter) {
    exact = false;
    notes.push(`Only matches ${str(p.ipsecFilter) === 'MATCH_ENCRYPTED' ? 'IPsec-encrypted' : 'non-IPsec'} traffic.`);
  }
  const space: Space = makeSpace(src.addrs.intersect(svcRes.families), dst.addrs.intersect(svcRes.families), svcRes.svc, st);
  const origin = str(obj(p.metadata).origin);
  const name = str(p.name);
  const description = str(p.description);
  const srcZone = str(obj(p.source).zoneId);
  const dstZone = str(obj(p.destination).zoneId);
  return {
    id: str(p.id),
    name,
    system: 'zone',
    enabled: p.enabled !== false,
    predefined: origin === 'SYSTEM_DEFINED' || origin === 'DERIVED',
    managed: isManagedRule(name, description),
    action,
    order: Number(p.index ?? 0),
    index: Number(p.index ?? 0),
    chain: `${srcZone}>${dstZone}`,
    srcZoneId: srcZone,
    dstZoneId: dstZone,
    space,
    exact,
    notes,
    srcDesc: src.desc,
    dstDesc: dst.desc,
    svcDesc: svcRes.svc.describe(),
    stDesc: describeStates(st),
    ipVersion: famLabel(svcRes.families),
    srcNetworkIds: src.networkIds,
    dstNetworkIds: dst.networkIds,
    srcRegions: src.regions ?? null,
    srcAny: src.any,
    dstAny: dst.any,
    schedule,
    logging: p.loggingEnabled === true,
    raw: p,
  };
}

// ---------------------------------------------------------------------------------
// Internal v2 zone policies (Network 9.x / 10.0 where the official API lacks policies)
// ---------------------------------------------------------------------------------

function v2Endpoint(ep: Obj, side: 'src' | 'dst', model: { networks: NetInfo[]; zones: ZoneInfo[] }, groups: Map<string, GroupInfo>): Endpoint {
  const zone = model.zones.find((z) => z.id === str(ep.zone_id));
  const zoneName = zone?.name ?? 'Unknown zone';
  const notes: string[] = [];
  const target = str(ep.matching_target).toUpperCase();
  const targetType = str(ep.matching_target_type).toUpperCase();
  let addrs = AddrSet.ANY;
  let exact = true;
  let what = '';
  let networkIds: string[] | null = null;
  let any = target === '' || target === 'ANY';

  switch (target) {
    case '':
    case 'ANY':
      break;
    case 'NETWORK': {
      const ids = arr<string>(ep.network_ids);
      const r = netAddrs(model, ids);
      if (r.missing.length) notes.push(`References ${r.missing.length} network(s) that no longer exist.`);
      addrs = r.set;
      what = joinNames(r.names) || 'no networks';
      networkIds = ids;
      break;
    }
    case 'IP': {
      if (targetType === 'OBJECT' && ep.ip_group_id) {
        const g = groups.get(str(ep.ip_group_id));
        if (g?.addrs) {
          addrs = g.addrs;
          what = `group "${g.name}"`;
        } else {
          exact = false;
          what = 'unknown address group';
        }
      } else {
        const ips = arr<string>(ep.ips);
        const parsed = AddrSet.parseList(ips);
        addrs = parsed.set;
        what = joinNames(ips);
      }
      break;
    }
    case 'CLIENT':
    case 'MAC': {
      const macs = arr<string>(ep.client_macs);
      exact = false;
      what = `device${macs.length === 1 ? '' : 's'} ${joinNames(macs, 2)}`;
      notes.push('Matches specific devices by MAC address; analysed as "may apply".');
      break;
    }
    case 'REGION':
      exact = false;
      what = `regions ${joinNames(arr<string>(ep.regions), 6)}`;
      notes.push('Matches by country (GeoIP); analysed as "may apply".');
      break;
    case 'WEB':
    case 'DOMAIN':
      exact = false;
      what = `domains ${joinNames(arr<string>(ep.web_domains ?? ep.domains), 3)}`;
      notes.push('Matches by domain name; analysed as "may apply".');
      break;
    case 'APP':
    case 'APP_CATEGORY':
      exact = false;
      what = 'applications';
      notes.push('Matches by application (DPI); analysed as "may apply".');
      break;
    default:
      exact = false;
      what = target.toLowerCase();
      notes.push(`Unrecognised matching target ${target}.`);
  }
  if (ep.match_opposite_ips === true || ep.match_opposite_networks === true) {
    addrs = AddrSet.ANY.subtract(addrs);
    what = `anything except ${what}`;
    networkIds = null;
  }
  if (side === 'src' && ep.match_mac === true) {
    exact = false;
    notes.push('Additionally restricted to a MAC address.');
  }
  let ports: RangeSet | null = null;
  const pmt = str(ep.port_matching_type).toUpperCase();
  if (pmt === 'SPECIFIC') ports = parsePorts(str(ep.port)) ?? null;
  else if (pmt === 'OBJECT') ports = groups.get(str(ep.port_group_id))?.ports ?? null;
  if (ports && ep.match_opposite_ports === true) ports = PORTS_ALL.subtract(ports);
  if (side === 'src' && ports && !ports.equals(PORTS_ALL)) {
    exact = false;
    notes.push('Restricts source ports; analysed as "may apply".');
  }
  const portsDesc = side === 'dst' && ports && !ports.equals(PORTS_ALL) ? ` port ${formatPorts(ports)}` : '';
  const desc = `${what || (zone?.key === 'external' ? 'the internet' : `anything in ${zoneName}`)}${what ? ` (${zoneName})` : ''}${portsDesc}`;
  return { addrs, ports: side === 'dst' ? ports : null, exact, desc, networkIds, any, notes };
}

function convertV2Policy(p: Obj, model: { networks: NetInfo[]; zones: ZoneInfo[] }, groups: Map<string, GroupInfo>): NormRule {
  const notes: string[] = [];
  const srcObj = obj(p.source);
  const dstObj = obj(p.destination);
  const src = v2Endpoint(srcObj, 'src', model, groups);
  const dst = v2Endpoint(dstObj, 'dst', model, groups);
  notes.push(...src.notes, ...dst.notes);
  const ipv = str(p.ip_version).toUpperCase();
  const families = ipv === 'IPV4' ? AddrSet.V4_ANY : ipv === 'IPV6' ? AddrSet.V6_ANY : AddrSet.ANY;
  let svc = ServiceSet.fromProtocol(str(p.protocol) || 'all', dst.ports);
  let exact = src.exact && dst.exact;
  if (!svc) {
    svc = ServiceSet.ALL;
    exact = false;
    notes.push(`Unrecognised protocol ${str(p.protocol)}.`);
  } else if (p.match_opposite_protocol === true) svc = svc.invert();
  const cst = str(p.connection_state_type).toUpperCase();
  const st = cst === 'RESPOND_ONLY' ? ST_EST | ST_REL : cst === 'CUSTOM' ? statesFromList(p.connection_states) : ST_ALL;
  const schedule = p.schedule ? scheduleText(obj(p.schedule)) : null;
  if (schedule) {
    exact = false;
    notes.push(`Only active on a schedule (${schedule}).`);
  }
  if (p.match_ip_sec === true) {
    exact = false;
    notes.push('Only matches IPsec traffic.');
  }
  const action = str(p.action).toUpperCase();
  const name = str(p.name);
  const description = str(p.description);
  return {
    id: str(p._id ?? p.id),
    name,
    system: 'zone',
    enabled: p.enabled !== false,
    predefined: p.predefined === true,
    managed: isManagedRule(name, description),
    action: action === 'ALLOW' ? 'allow' : action === 'REJECT' ? 'reject' : 'block',
    order: Number(p.index ?? 0),
    index: Number(p.index ?? 0),
    chain: `${str(srcObj.zone_id)}>${str(dstObj.zone_id)}`,
    srcZoneId: str(srcObj.zone_id),
    dstZoneId: str(dstObj.zone_id),
    space: makeSpace(src.addrs.intersect(families), dst.addrs.intersect(families), svc, st),
    exact,
    notes,
    srcDesc: src.desc,
    dstDesc: dst.desc,
    svcDesc: svc.describe(),
    stDesc: describeStates(st),
    ipVersion: famLabel(families),
    srcNetworkIds: src.networkIds,
    dstNetworkIds: dst.networkIds,
    srcRegions: src.regions ?? null,
    srcAny: src.any,
    dstAny: dst.any,
    schedule,
    logging: p.logging === true,
    raw: p,
  };
}

// ---------------------------------------------------------------------------------
// Legacy (pre zone-based) firewall rules
// ---------------------------------------------------------------------------------

function legacySide(r: Obj, side: 'src' | 'dst', model: { networks: NetInfo[] }, groups: Map<string, GroupInfo>, notes: string[]) {
  let addrs = AddrSet.ANY;
  let ports: RangeSet | null = null;
  let exact = true;
  const parts: string[] = [];
  let networkIds: string[] | null = null;
  let any = true;
  for (const gid of arr<string>(r[`${side}_firewallgroup_ids`])) {
    const g = groups.get(gid);
    if (!g) {
      notes.push('References a firewall group that no longer exists.');
      exact = false;
      continue;
    }
    any = false;
    if (g.type === 'port') {
      ports = (ports ?? new RangeSet()).union(g.ports ?? new RangeSet());
      parts.push(`ports "${g.name}"`);
    } else if (g.addrs) {
      addrs = addrs.intersect(g.addrs);
      parts.push(`group "${g.name}"`);
    }
  }
  const netId = str(r[`${side}_networkconf_id`]);
  if (netId) {
    any = false;
    const n = model.networks.find((x) => x.id === netId || x.raw._legacyId === netId);
    const type = str(r[`${side}_networkconf_type`]) || 'NETv4';
    if (!n) {
      notes.push('References a network that no longer exists.');
      exact = false;
    } else if (type === 'ADDRv4') {
      addrs = addrs.intersect(n.gatewayAddrs);
      parts.push(`${n.name} gateway address`);
    } else {
      addrs = addrs.intersect(n.addrs);
      parts.push(n.name);
      networkIds = [n.id];
    }
  }
  const address = str(r[`${side}_address`]);
  if (address) {
    any = false;
    const a = AddrSet.parse(address);
    if (a) addrs = addrs.intersect(a);
    else exact = false;
    parts.push(address);
  }
  if (str(r[`${side}_mac_address`])) {
    any = false;
    exact = false;
    parts.push(`MAC ${str(r[`${side}_mac_address`])}`);
    notes.push('Matches a specific device by MAC address; analysed as "may apply".');
  }
  const portStr = str(r[`${side}_port`]);
  if (portStr) {
    const p = parsePorts(portStr);
    if (p) ports = ports ? ports.intersect(p) : p;
    else exact = false;
  }
  if (side === 'src' && ports && !ports.equals(PORTS_ALL)) {
    exact = false;
    notes.push('Restricts source ports; analysed as "may apply".');
  }
  return { addrs, ports, exact, desc: parts.join(' + ') || 'any', networkIds, any };
}

function convertLegacyRule(r: Obj, model: { networks: NetInfo[] }, groups: Map<string, GroupInfo>): NormRule {
  const notes: string[] = [];
  const ruleset = str(r.ruleset);
  const v6 = /v6/i.test(ruleset);
  const families = v6 ? AddrSet.V6_ANY : AddrSet.V4_ANY;
  const src = legacySide(r, 'src', model, groups, notes);
  const dst = legacySide(r, 'dst', model, groups, notes);
  let svc = ServiceSet.fromProtocol(str(r.protocol) || 'all', dst.ports);
  let exact = src.exact && dst.exact;
  if (!svc) {
    svc = ServiceSet.ALL;
    exact = false;
    notes.push(`Unrecognised protocol ${str(r.protocol)}.`);
  } else if (r.protocol_match_excepted === true) svc = svc.invert();
  let st = 0;
  if (r.state_new) st |= ST_NEW;
  if (r.state_established) st |= ST_EST;
  if (r.state_related) st |= ST_REL;
  if (r.state_invalid) st |= ST_INV;
  if (!st) st = ST_ALL;
  if (str(r.ipsec)) {
    exact = false;
    notes.push('Only matches IPsec / non-IPsec traffic.');
  }
  const action = str(r.action).toLowerCase();
  const name = str(r.name);
  return {
    id: str(r._id),
    name,
    system: 'legacy',
    enabled: r.enabled !== false,
    predefined: false,
    managed: isManagedRule(name, ''),
    action: action === 'accept' ? 'allow' : action === 'reject' ? 'reject' : 'block',
    order: Number(r.rule_index ?? 0),
    index: Number(r.rule_index ?? 0),
    chain: ruleset,
    srcZoneId: null,
    dstZoneId: null,
    space: makeSpace(src.addrs.intersect(families), dst.addrs.intersect(families), svc, st),
    exact,
    notes,
    srcDesc: src.desc,
    dstDesc: dst.desc + (dst.ports && !dst.ports.equals(PORTS_ALL) ? ` port ${formatPorts(dst.ports)}` : ''),
    svcDesc: svc.describe(),
    stDesc: describeStates(st),
    ipVersion: v6 ? 'IPv6' : 'IPv4',
    srcNetworkIds: src.networkIds,
    dstNetworkIds: dst.networkIds,
    srcRegions: null,
    srcAny: src.any,
    dstAny: dst.any,
    schedule: null,
    logging: r.logging === true,
    raw: r,
  };
}

/** Synthetic rules for legacy behaviour that is not stored as firewall rules. */
function legacySyntheticRules(model: { networks: NetInfo[]; internal: AddrSet; external: AddrSet; gatewayAddrs: AddrSet }): NormRule[] {
  const out: NormRule[] = [];
  const base = (p: Partial<NormRule> & Pick<NormRule, 'id' | 'name' | 'chain' | 'space' | 'action' | 'srcDesc' | 'dstDesc' | 'svcDesc'>): NormRule => ({
    system: 'legacy',
    enabled: true,
    predefined: true,
    managed: false,
    order: 3000,
    index: 3000,
    srcZoneId: null,
    dstZoneId: null,
    exact: true,
    notes: ['Built-in behaviour (not a stored rule).'],
    stDesc: describeStates(ST_ALL),
    ipVersion: 'IPv4',
    srcNetworkIds: null,
    dstNetworkIds: null,
    srcAny: false,
    dstAny: false,
    schedule: null,
    logging: false,
    raw: {},
    ...p,
  });
  const rfc1918 = AddrSet.parseList(['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']).set;
  for (const n of model.networks) {
    if (n.purpose === 'guest') {
      out.push(
        base({
          id: `synthetic:guest-restrict:${n.id}`,
          name: 'Guest network restrictions (built-in)',
          chain: 'GUEST_IN',
          action: 'block',
          space: makeSpace(n.addrs, rfc1918, ServiceSet.ALL, ST_ALL),
          srcDesc: n.name,
          dstDesc: 'private address ranges',
          svcDesc: 'all traffic',
          srcNetworkIds: [n.id],
        }),
      );
    }
    if (n.isolated) {
      const others = model.internal.subtract(n.addrs);
      out.push(
        base({
          id: `synthetic:isolation:${n.id}`,
          name: `"Isolate network" setting on ${n.name}`,
          chain: n.purpose === 'guest' ? 'GUEST_IN' : 'LAN_IN',
          action: 'block',
          space: makeSpace(n.addrs, others, ServiceSet.ALL, ST_NEW | ST_INV),
          srcDesc: n.name,
          dstDesc: 'other networks',
          svcDesc: 'all traffic',
          srcNetworkIds: [n.id],
        }),
      );
    }
    if (!n.internetAccess) {
      out.push(
        base({
          id: `synthetic:no-internet:${n.id}`,
          name: `Internet access disabled on ${n.name}`,
          chain: 'WAN_OUT',
          action: 'block',
          space: makeSpace(n.addrs, model.external, ServiceSet.ALL, ST_ALL),
          srcDesc: n.name,
          dstDesc: 'the internet',
          svcDesc: 'all traffic',
          srcNetworkIds: [n.id],
        }),
      );
    }
  }
  return out;
}

/** Zone-based networks with "Isolate network" / "Internet access" toggles also get synthetic rules. */
function zoneSyntheticRules(model: { networks: NetInfo[]; zones: ZoneInfo[]; internal: AddrSet; external: AddrSet }): NormRule[] {
  const out: NormRule[] = [];
  const ext = model.zones.find((z) => z.key === 'external');
  for (const n of model.networks) {
    if (!n.zoneId) continue;
    const common = {
      system: 'zone' as const,
      enabled: true,
      predefined: true,
      managed: false,
      order: -1,
      index: 0,
      exact: true,
      notes: ['Built-in behaviour of a network setting (not a firewall policy).'],
      stDesc: describeStates(ST_ALL),
      ipVersion: 'IPv4 + IPv6' as const,
      srcNetworkIds: [n.id],
      dstNetworkIds: null,
      srcAny: false,
      dstAny: false,
      schedule: null,
      logging: false,
      raw: {},
      srcZoneId: n.zoneId,
    };
    if (n.isolated) {
      for (const z of model.zones.filter((x) => x.key !== 'external' && x.key !== 'gateway')) {
        out.push({
          ...common,
          id: `synthetic:isolation:${n.id}:${z.id}`,
          name: `"Isolate network" setting on ${n.name}`,
          action: 'block',
          chain: `${n.zoneId}>${z.id}`,
          dstZoneId: z.id,
          space: makeSpace(n.addrs, model.internal.subtract(n.addrs), ServiceSet.ALL, ST_NEW | ST_INV),
          srcDesc: n.name,
          dstDesc: 'other networks',
          svcDesc: 'all traffic',
        });
      }
    }
    if (!n.internetAccess && ext) {
      out.push({
        ...common,
        id: `synthetic:no-internet:${n.id}`,
        name: `Internet access disabled on ${n.name}`,
        action: 'block',
        chain: `${n.zoneId}>${ext.id}`,
        dstZoneId: ext.id,
        space: makeSpace(n.addrs, model.external, ServiceSet.ALL, ST_ALL),
        srcDesc: n.name,
        dstDesc: 'the internet',
        svcDesc: 'all traffic',
      });
    }
  }
  return out;
}

// ---------------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------------

export function buildModel(raw: RawSnapshot, roles: Map<string, NetworkRole>): FwModel {
  const networks = buildNetworks(raw, roles);
  const zones = buildZones(raw, networks);
  // Networks in UniFi's own DMZ zone are internet-facing, whatever their name.
  for (const n of networks) if (n.roleSource === 'auto' && zones.find((z) => z.id === n.zoneId)?.key === 'dmz') n.role = 'dmz';
  const groups = buildGroups(raw);
  const internal = networks.reduce((acc, n) => acc.union(n.addrs), AddrSet.EMPTY);
  const external = AddrSet.ANY.subtract(internal).subtract(SPECIAL_RANGES);
  const gatewayAddrs = networks.reduce((acc, n) => acc.union(n.gatewayAddrs), AddrSet.EMPTY);
  const warnings: string[] = [];
  const partial = { networks, zones, internal, external, gatewayAddrs };

  let rules: NormRule[] = [];
  if (raw.firewallSource === 'integration') rules = raw.iPolicies.map((p) => convertIntegrationPolicy(p, partial, groups));
  else if (raw.firewallSource === 'internal-v2') rules = raw.v2Policies.map((p) => convertV2Policy(p, partial, groups));
  else if (raw.firewallSource === 'legacy') rules = [...raw.legacyRules.map((r) => convertLegacyRule(r, partial, groups)), ...legacySyntheticRules(partial)];

  if (raw.firewallMode === 'zone') rules.push(...zoneSyntheticRules(partial));
  if (raw.firewallSource === 'none') warnings.push('Firewall configuration could not be read from the controller, so segmentation results are unavailable.');
  if (!networks.length) warnings.push('No gateway-managed networks were found.');
  return { mode: raw.firewallMode, networks, zones, groups, rules, internal, external, gatewayAddrs, warnings };
}
