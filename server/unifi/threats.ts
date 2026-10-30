// Fetches IPS/IDS detections from whichever source the controller supports:
//   1. v2 traffic-flows filtered to INTRUSION_PREVENTION (Network 9.1+; the main source on 10.x/11.x,
//      includes signature / category / CVE in its `ips` object)
//   2. legacy stat/ips/event (Network 8.x-10.2; removed in 10.3+/11)
//   3. v2 system-log/threat-alert (9.x+; no signature, used to fill gaps)

import type { UniFiClient } from './client.ts';

type Obj = Record<string, unknown>;

export interface RawThreat {
  id: string;
  ts: number;
  source: 'traffic-flow' | 'ips-event' | 'threat-alert';
  signature: string | null;
  signatureId: number | null;
  category: string | null;
  classtype: string | null;
  description: string | null;
  cves: string[];
  priority: number | null;
  risk: string | null;
  action: 'blocked' | 'alerted' | 'unknown';
  directionHint: 'incoming' | 'outgoing' | 'local' | null;
  srcIp: string;
  srcPort: number | null;
  dstIp: string;
  dstPort: number | null;
  proto: string | null;
  appProto: string | null;
  srcMac: string | null;
  dstMac: string | null;
  srcName: string | null;
  dstName: string | null;
  srcNetworkId: string | null;
  dstNetworkId: string | null;
  srcCountry: string | null;
  dstCountry: string | null;
  srcOrg: string | null;
  dstOrg: string | null;
  count: number;
}

const s = (v: unknown): string | null => (typeof v === 'string' && v ? v : typeof v === 'number' ? String(v) : null);
const n = (v: unknown): number | null => {
  const x = typeof v === 'string' ? Number(v) : typeof v === 'number' ? v : NaN;
  return Number.isFinite(x) ? x : null;
};
const o = (v: unknown): Obj => (v && typeof v === 'object' && !Array.isArray(v) ? (v as Obj) : {});

function tsMs(v: unknown): number {
  const x = n(v) ?? 0;
  return x > 0 && x < 1e12 ? x * 1000 : x;
}

/** Parse one legacy stat/ips/event (or list/alarm) document. */
export function parseIpsEvent(e: Obj): RawThreat | null {
  const src = s(e.src_ip);
  const dst = s(e.dest_ip ?? e.dst_ip);
  if (!src || !dst) return null;
  const geo = (k: string) => o(e[k]);
  const action = String(e.inner_alert_action ?? '').toLowerCase();
  const catname = Array.isArray(e.catname) ? (e.catname as unknown[]).map(String).join(', ') : s(e.catname);
  const sig = s(e.inner_alert_signature);
  return {
    id: `ips:${s(e._id) ?? s(e.unique_alertid) ?? `${e.time ?? e.timestamp}-${src}-${dst}`}`,
    ts: n(e.time) ?? tsMs(e.timestamp ?? e.datetime),
    source: 'ips-event',
    signature: sig,
    signatureId: n(e.inner_alert_signature_id),
    category: catname,
    classtype: s(e.inner_alert_category),
    description: null,
    cves: [],
    priority: n(e.inner_alert_severity),
    risk: null,
    action: action === 'blocked' || action === 'drop' || action === 'dropped' ? 'blocked' : action === 'allowed' || action === 'alert' ? 'alerted' : 'unknown',
    directionHint: null,
    srcIp: src,
    srcPort: n(e.src_port),
    dstIp: dst,
    dstPort: n(e.dest_port ?? e.dst_port),
    proto: s(e.proto),
    appProto: s(e.app_proto) === 'failed' ? null : s(e.app_proto),
    srcMac: s(e.src_mac),
    dstMac: s(e.dst_mac),
    srcName: null,
    dstName: null,
    srcNetworkId: null,
    dstNetworkId: null,
    srcCountry: (typeof e.srcipCountry === 'string' && e.srcipCountry) || s(geo('srcipGeo').country_code),
    dstCountry: (typeof e.dstipCountry === 'string' && e.dstipCountry) || s(geo('dstipGeo').country_code),
    srcOrg: (typeof e.srcipASN === 'string' && e.srcipASN) || s(geo('srcipGeo').organization),
    dstOrg: (typeof e.dstipASN === 'string' && e.dstipASN) || s(geo('dstipGeo').organization),
    count: 1,
  };
}

/** Parse one v2 traffic-flow row that was matched by the intrusion prevention engine. */
export function parseTrafficFlow(f: Obj): RawThreat | null {
  const src = o(f.source);
  const dst = o(f.destination);
  const srcIp = s(src.ip);
  const dstIp = s(dst.ip);
  if (!srcIp || !dstIp) return null;
  const ips = o(f.ips);
  const policies = Array.isArray(f.policies) ? (f.policies as Obj[]) : [];
  const ipsPolicy = policies.find((p) => String(p.type ?? '').toUpperCase() === 'INTRUSION_PREVENTION') ?? null;
  const signature = s(ips.signature) ?? s(ips.description) ?? (ipsPolicy ? s(ipsPolicy.name) : null);
  const cves = [ips.cve_reference, ips.relevant_cve]
    .flatMap((v) => (Array.isArray(v) ? v : typeof v === 'string' ? v.split(/[,\s]+/) : []))
    .map(String)
    .filter((x) => /^CVE-\d{4}-\d+$/i.test(x));
  const risk = s(f.risk)?.toLowerCase() ?? null;
  const action = String(f.action ?? '').toLowerCase();
  const dir = String(f.direction ?? '').toLowerCase();
  return {
    id: `flow:${s(f.id) ?? `${f.time}-${srcIp}-${dstIp}`}`,
    ts: tsMs(f.time ?? f.flow_start_time),
    source: 'traffic-flow',
    signature,
    signatureId: n(ips.signature_id),
    category: s(ips.category_name) ?? (ipsPolicy ? s(ipsPolicy.ips_category) : null),
    classtype: s(ips.signature_class),
    description: s(ips.description) ?? s(ips.advanced_information),
    cves,
    priority: risk === 'high' ? 1 : risk === 'medium' ? 2 : risk === 'low' ? 3 : null,
    risk,
    action: action === 'blocked' ? 'blocked' : action === 'allowed' ? 'alerted' : 'unknown',
    directionHint: dir === 'incoming' || dir === 'outgoing' || dir === 'local' ? dir : null,
    srcIp,
    srcPort: n(src.port),
    dstIp,
    dstPort: n(dst.port),
    proto: s(f.protocol),
    appProto: s(f.service),
    srcMac: s(src.mac),
    dstMac: s(dst.mac),
    srcName: s(src.client_name) ?? s(src.device_name) ?? s(src.host_name),
    dstName: s(dst.client_name) ?? s(dst.device_name) ?? s(dst.host_name),
    srcNetworkId: s(src.network_id),
    dstNetworkId: s(dst.network_id),
    srcCountry: s(src.region),
    dstCountry: s(dst.region),
    srcOrg: null,
    dstOrg: null,
    count: n(f.count) ?? 1,
  };
}

/** Parse a v2 system-log threat-alert row (has no signature; used when flows are unavailable). */
export function parseThreatAlert(a: Obj): RawThreat | null {
  const p = o(a.parameters);
  const srcIp = s(o(p.SRC_IP).id) ?? s(o(p.SRC_IP).name);
  const dstIp = s(o(p.DST_IP).id) ?? s(o(p.DST_IP).name);
  if (!srcIp || !dstIp) return null;
  const key = String(a.key ?? a.event ?? '').toUpperCase();
  const honeypot = key.includes('HONEYPOT');
  const sev = String(a.severity ?? '').toUpperCase();
  return {
    id: `alert:${s(a.id) ?? `${a.timestamp}-${srcIp}-${dstIp}`}`,
    ts: tsMs(a.timestamp),
    source: 'threat-alert',
    signature: honeypot ? 'UniFi internal honeypot triggered' : s(a.title_raw) ?? 'Threat detected',
    signatureId: null,
    category: honeypot ? 'honeypot' : null,
    classtype: null,
    description: s(a.message),
    cves: [],
    priority: sev === 'VERY_HIGH' || sev === 'HIGH' ? 1 : sev === 'MEDIUM' ? 2 : sev === 'LOW' ? 3 : null,
    risk: sev.toLowerCase() || null,
    action: key.includes('BLOCKED') ? 'blocked' : key.includes('DETECTED') || honeypot ? 'alerted' : 'unknown',
    directionHint: null,
    srcIp,
    srcPort: null,
    dstIp,
    dstPort: null,
    proto: null,
    appProto: null,
    srcMac: null,
    dstMac: null,
    srcName: null,
    dstName: null,
    srcNetworkId: null,
    dstNetworkId: null,
    srcCountry: null,
    dstCountry: null,
    srcOrg: null,
    dstOrg: null,
    count: 1,
  };
}

export interface ThreatFetchResult {
  events: RawThreat[];
  sources: { name: string; ok: boolean; count: number; detail: string }[];
}

export const EMPTY_FLOW_FILTERS = {
  risk: [], action: [], direction: [], protocol: [], policy: [], service: [],
  source_host: [], source_mac: [], source_ip: [], source_port: [], source_network_id: [], source_domain: [], source_zone_id: [], source_region: [],
  destination_host: [], destination_mac: [], destination_ip: [], destination_port: [], destination_network_id: [], destination_domain: [], destination_zone_id: [], destination_region: [],
  in_network_id: [], out_network_id: [], next_ai_query: [], except_for: [], search_text: '',
};

export async function fetchThreats(client: UniFiClient, from: number, to: number, maxEvents = 20000): Promise<ThreatFetchResult> {
  const sources: ThreatFetchResult['sources'] = [];
  const events: RawThreat[] = [];
  const err = (e: unknown) => (e instanceof Error ? e.message : String(e)).slice(0, 160);

  // 1. Traffic flows (IPS)
  let flowsOk = false;
  try {
    const rows: Obj[] = [];
    for (let page = 0; page < 20 && rows.length < maxEvents; page++) {
      const res = await client.v2<{ data?: Obj[]; has_next?: boolean; total_page_count?: number }>('POST', '/traffic-flows', {
        ...EMPTY_FLOW_FILTERS,
        timestampFrom: from,
        timestampTo: to,
        pageNumber: page,
        pageSize: 1000,
        skip_count: false,
        policy_type: ['INTRUSION_PREVENTION'],
      });
      const data = res?.data ?? [];
      rows.push(...data);
      const more = res?.has_next ?? (res?.total_page_count !== undefined ? page + 1 < res.total_page_count : data.length === 1000);
      if (!more || !data.length) break;
    }
    const parsed = rows.map(parseTrafficFlow).filter((x): x is RawThreat => !!x);
    events.push(...parsed);
    flowsOk = true;
    sources.push({ name: 'Traffic flows (IPS)', ok: true, count: parsed.length, detail: `${parsed.length} detections` });
  } catch (e) {
    sources.push({ name: 'Traffic flows (IPS)', ok: false, count: 0, detail: err(e) });
  }

  // 2. Legacy IPS events (8.x - 10.2). Only trusted when it returns data; some 10.x builds return [].
  try {
    const rows = await client.v1<Obj>('POST', '/stat/ips/event', { start: from, end: to, _limit: maxEvents, _sort: '-time' });
    const parsed = rows.map(parseIpsEvent).filter((x): x is RawThreat => !!x);
    sources.push({ name: 'IPS events (legacy)', ok: true, count: parsed.length, detail: `${parsed.length} events` });
    if (parsed.length && (!flowsOk || parsed.length > events.length)) {
      events.length = 0;
      events.push(...parsed);
    }
  } catch (e) {
    const missing = /404|not.?found/i.test(err(e));
    sources.push(
      missing && flowsOk
        ? { name: 'IPS events (legacy)', ok: true, count: 0, detail: 'Removed in this Network version — not needed, traffic flows are used instead' }
        : { name: 'IPS events (legacy)', ok: false, count: 0, detail: err(e) },
    );
  }

  // 3. System log threat alerts: add only alerts that no flow/event already describes.
  try {
    const rows: Obj[] = [];
    for (let page = 0; page < 20; page++) {
      const res = await client.v2<{ data?: Obj[]; total_page_count?: number }>('POST', '/system-log/threat-alert', {
        timestampFrom: from,
        timestampTo: to,
        threatTypes: ['HONEYPOT', 'THREAT'],
        pageNumber: page,
        pageSize: 100,
      });
      const data = res?.data ?? [];
      rows.push(...data);
      if (!data.length || (res.total_page_count !== undefined && page + 1 >= res.total_page_count) || rows.length >= 5000) break;
    }
    const parsed = rows.map(parseThreatAlert).filter((x): x is RawThreat => !!x);
    const covered = (a: RawThreat) => events.some((e) => Math.abs(e.ts - a.ts) < 120_000 && ((e.srcIp === a.srcIp && e.dstIp === a.dstIp) || (e.srcIp === a.dstIp && e.dstIp === a.srcIp)));
    const extra = parsed.filter((a) => a.category === 'honeypot' || !covered(a));
    events.push(...extra);
    sources.push({ name: 'System log threat alerts', ok: true, count: parsed.length, detail: `${parsed.length} alerts, ${extra.length} not covered by flows` });
  } catch (e) {
    sources.push({ name: 'System log threat alerts', ok: false, count: 0, detail: err(e) });
  }

  return { events, sources };
}
