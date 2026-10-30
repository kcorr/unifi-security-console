// What the firewall actually blocked between your networks, per segmentation cell, from UniFi's traffic log.
//
// A blocked connection that an allow rule almost matches is called out as a near miss: the same devices on another
// port, or the same port to another address. That is usually a rule with a wrong port or an old address, such as a
// monitoring agent whose server moved.

import type { BlockedGroup, BlockedTraffic } from '../../shared/types.ts';
import type { UniFiClient } from '../unifi/client.ts';
import { EMPTY_FLOW_FILTERS } from '../unifi/threats.ts';
import type { FwModel, NetInfo, NormRule } from './model.ts';
import { AddrSet, RangeSet, ServiceSet, ST_NEW, makeSpace, spaceIntersect, spaceIsEmpty, spaceSvc } from './sets.ts';

type Obj = Record<string, unknown>;
const obj = (v: unknown): Obj => (v && typeof v === 'object' && !Array.isArray(v) ? (v as Obj) : {});
const str = (v: unknown) => (typeof v === 'string' && v.trim() ? v : null);
const num = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : typeof v === 'string' && v.trim() && Number.isFinite(Number(v)) ? Number(v) : null);
const MAC = /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/i;

export interface BlockedFlow {
  srcIp: string;
  srcName: string | null;
  srcNet: string | null;
  dstIp: string;
  dstName: string | null;
  dstNet: string | null;
  dstZone: string | null;
  port: number | null;
  protocol: string;
  direction: string;
  time: number;
  count: number;
}

/** A connection the firewall blocked; intrusion prevention blocks and traffic from the internet are left out. */
export function parseBlockedFlow(f: Obj): BlockedFlow | null {
  if (f.action !== 'blocked') return null;
  const policies = Array.isArray(f.policies) ? (f.policies as Obj[]) : [];
  if (policies.length && !policies.some((p) => p.type === 'FIREWALL')) return null;
  const direction = String(f.direction ?? '');
  if (direction !== 'local' && direction !== 'outgoing') return null;
  const s = obj(f.source);
  const d = obj(f.destination);
  const srcIp = str(s.ip);
  const dstIp = str(d.ip);
  if (!srcIp || !dstIp) return null;
  // UniFi names unnamed devices by their MAC address.
  const name = (o: Obj) => {
    const n = str(o.client_name);
    return n && !MAC.test(n) ? n : null;
  };
  return {
    srcIp,
    srcName: name(s),
    srcNet: str(s.network_id),
    dstIp,
    dstName: name(d),
    dstNet: str(d.network_id),
    dstZone: str(d.zone_name),
    port: num(d.port),
    protocol: String(f.protocol ?? '').toUpperCase(),
    direction,
    time: num(f.time) ?? 0,
    count: num(f.count) ?? 1,
  };
}

/** Blocked connections from your networks (to each other, the gateway and the internet) in [from, to]. */
export async function fetchBlockedFlows(client: UniFiClient, from: number, to: number, maxFlows = 10_000): Promise<{ flows: BlockedFlow[]; truncated: boolean }> {
  const flows: BlockedFlow[] = [];
  const page = async (pageNumber: number, direction: string[]) =>
    client.v2<{ data?: Obj[]; has_next?: boolean; total_page_count?: number }>('POST', '/traffic-flows', {
      ...EMPTY_FLOW_FILTERS,
      action: ['blocked'],
      direction,
      timestampFrom: from,
      timestampTo: to,
      pageNumber,
      pageSize: 1000,
      skip_count: false,
    });
  // Leaving out traffic from the internet saves most of the reading; older versions may not filter by direction.
  let direction = ['local', 'outgoing'];
  for (let n = 0; n < 20; n++) {
    const res = await page(n, direction).catch((e) => {
      if (n === 0 && direction.length) {
        direction = [];
        return page(0, direction);
      }
      throw e;
    });
    const data = res?.data ?? [];
    for (const f of data) {
      const b = parseBlockedFlow(f);
      if (b) flows.push(b);
    }
    const more = res?.has_next ?? (res?.total_page_count !== undefined ? n + 1 < res.total_page_count : data.length === 1000);
    if (!more || !data.length) return { flows, truncated: false };
    if (flows.length >= maxFlows) return { flows, truncated: true };
  }
  return { flows, truncated: true };
}

/** Groups blocked flows by matrix cell and device, busiest first, near misses before everything else. */
export function summarizeBlocked(
  model: FwModel,
  flows: BlockedFlow[],
  range: { from: number; to: number },
  nameOf: (ip: string) => string | null = () => null,
  truncated = false,
): BlockedTraffic {
  const nets = model.networks.filter((n) => n.enabled && !n.addrs.isEmpty());
  const netOf = (id: string | null, ip: string) => (id ? nets.find((n) => n.id === id || String(n.raw._legacyId ?? '') === id) : undefined) ?? nets.find((n) => n.addrs.has(ip)) ?? null;
  const groups = new Map<string, BlockedGroup & { src: NetInfo }>();
  for (const f of flows) {
    // Devices outside the matrix (VPN clients, for example) have no row to show them in.
    const src = netOf(f.srcNet, f.srcIp);
    if (!src) continue;
    let to: string;
    if (f.dstZone === 'Gateway' || model.gatewayAddrs.has(f.dstIp)) to = 'gateway';
    else if (f.direction === 'outgoing' || model.external.has(f.dstIp)) to = 'internet';
    else {
      const d = netOf(f.dstNet, f.dstIp);
      if (!d) continue;
      to = d.id;
    }
    if (to === src.id) continue;
    const internet = to === 'internet';
    const key = `${src.id}>${to}|${f.srcIp}|${internet ? '*' : f.dstIp}|${f.protocol}|${f.port ?? ''}`;
    let g = groups.get(key);
    if (!g) {
      g = {
        from: src.id,
        to,
        src,
        source: { ip: f.srcIp, name: nameOf(f.srcIp) ?? f.srcName },
        destination: internet ? null : { ip: f.dstIp, name: nameOf(f.dstIp) ?? f.dstName },
        examples: [],
        protocol: f.protocol,
        port: f.port,
        count: 0,
        lastSeen: 0,
        nearMiss: null,
      };
      groups.set(key, g);
    }
    g.count += f.count;
    g.lastSeen = Math.max(g.lastSeen, f.time);
    if (internet && g.examples.length < 3 && !g.examples.includes(f.dstIp)) g.examples.push(f.dstIp);
  }

  const cells: BlockedTraffic['cells'] = {};
  for (const { src, ...g } of groups.values()) {
    g.nearMiss = nearMiss(model, src, g);
    const cell = (cells[`${g.from}>${g.to}`] ??= { total: 0, nearMisses: 0, groups: [] });
    cell.total += g.count;
    if (g.nearMiss) cell.nearMisses++;
    cell.groups.push(g);
  }
  for (const c of Object.values(cells)) c.groups = c.groups.sort((a, b) => Number(!a.nearMiss) - Number(!b.nearMiss) || b.count - a.count).slice(0, 12);
  return { from: range.from, to: range.to, available: true, truncated, cells };
}

/** The allow rule this blocked connection almost matches, if any. */
function nearMiss(model: FwModel, srcNet: NetInfo, g: BlockedGroup): BlockedGroup['nearMiss'] {
  if (g.port === null || (g.protocol !== 'TCP' && g.protocol !== 'UDP')) return null;
  const src = AddrSet.parse(g.source.ip);
  const dst = AddrSet.parse(g.destination?.ip ?? g.examples[0] ?? '');
  if (!src || !dst) return null;
  const port = RangeSet.of(BigInt(g.port), BigInt(g.port));
  const svc = g.protocol === 'TCP' ? ServiceSet.tcp(port) : ServiceSet.udp(port);
  const service = `${g.protocol} ${g.port}`;
  const zone = (key: string) => model.zones.find((z) => z.key === key)?.id ?? null;
  const dstZone = g.to === 'internet' ? zone('external') : g.to === 'gateway' ? zone('gateway') : (model.networks.find((n) => n.id === g.to)?.zoneId ?? null);
  // Only the rules for this path, and only ones that name a destination: an "allow anything" rule is not a near miss.
  const candidates = model.rules.filter(
    (r: NormRule) =>
      r.enabled && !r.predefined && r.action === 'allow' && !r.dstAny && (!r.srcZoneId || !srcNet.zoneId || r.srcZoneId === srcNet.zoneId) && (!r.dstZoneId || !dstZone || r.dstZoneId === dstZone),
  );
  const hits = (r: NormRule, space: ReturnType<typeof makeSpace>) => !spaceIsEmpty(spaceIntersect(r.space, space));
  // A rule that matches exactly but was overruled by an earlier one is about order, not a typo.
  const exact = makeSpace(src, dst, svc, ST_NEW);
  const sameDevices = makeSpace(src, dst, ServiceSet.tcpUdp(), ST_NEW);
  const port1 = candidates.find((r) => !hits(r, exact) && hits(r, sameDevices));
  if (port1) return { ruleId: port1.id, ruleName: port1.name, reason: `“${port1.name}” allows these devices, but not ${service}: it allows ${port1.svcDesc}.` };
  const samePort = makeSpace(src, model.internal.union(model.external), svc, ST_NEW);
  const addr = candidates.find((r) => !hits(r, exact) && !spaceSvc(r.space).isAll() && hits(r, samePort));
  if (addr) return { ruleId: addr.id, ruleName: addr.name, reason: `“${addr.name}” allows ${service} from this device, but only to ${addr.dstDesc}.` };
  return null;
}
