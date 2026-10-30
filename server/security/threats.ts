// Turns raw detections into explained ThreatEvents: direction, the local device involved,
// category, context-aware severity and advice.

import type { LocalEndpoint, ThreatDirection, ThreatEvent } from '../../shared/types.ts';
import type { RawThreat } from '../unifi/threats.ts';
import type { NetInfo } from './model.ts';
import { classifyIp } from './ipintel.ts';
import { analyzeSignature, assessSeverity, explainEvent } from './threatKb.ts';

export interface Directory {
  networks: NetInfo[];
  wanIps: Set<string>;
  byIp: Map<string, { mac: string | null; name: string | null; networkId: string | null }>;
  byMac: Map<string, { ip: string | null; name: string | null }>;
}

export function networkOf(dir: Directory, ip: string): NetInfo | null {
  return dir.networks.find((n) => n.addrs.has(ip)) ?? null;
}

export function resolveLocal(dir: Directory, ip: string, hint?: { name?: string | null; mac?: string | null }): LocalEndpoint | null {
  const net = networkOf(dir, ip);
  const known = dir.byIp.get(ip);
  if (dir.wanIps.has(ip)) return { ip, mac: null, name: 'Your public IP (gateway WAN)', network: 'WAN', networkId: null, vlan: null, known: true };
  if (!net && !known) {
    // CGNAT (100.64/10) is ISP NAT or a VPN like Tailscale - only "ours" when it is one of our networks.
    const scope = classifyIp(ip).scope;
    if (scope !== 'private' && scope !== 'link-local') return null;
  }
  const name = known?.name ?? hint?.name ?? (hint?.mac ? dir.byMac.get(hint.mac.toLowerCase())?.name : null) ?? null;
  return {
    ip,
    mac: known?.mac ?? hint?.mac ?? null,
    name,
    network: net?.name ?? null,
    networkId: net?.id ?? known?.networkId ?? null,
    vlan: net?.vlan ?? null,
    known: !!known || !!name,
  };
}

function isOurs(dir: Directory, ip: string): boolean {
  if (dir.wanIps.has(ip) || networkOf(dir, ip)) return true;
  const scope = classifyIp(ip).scope;
  return scope === 'private' || scope === 'link-local';
}

export function toThreatEvent(raw: RawThreat, dir: Directory): ThreatEvent {
  const srcOurs = isOurs(dir, raw.srcIp);
  const dstOurs = isOurs(dir, raw.dstIp);
  let direction: ThreatDirection;
  if (!srcOurs && dstOurs) direction = 'inbound';
  else if (srcOurs && !dstOurs) direction = 'outbound';
  else if (srcOurs && dstOurs) direction = dir.wanIps.has(raw.dstIp) && !networkOf(dir, raw.srcIp) ? 'inbound' : 'internal';
  else direction = raw.directionHint === 'incoming' ? 'inbound' : raw.directionHint === 'outgoing' ? 'outbound' : raw.directionHint === 'local' ? 'internal' : 'unknown';

  const localIp = direction === 'inbound' ? raw.dstIp : direction === 'outbound' || direction === 'internal' ? raw.srcIp : null;
  const remoteIp = direction === 'inbound' ? raw.srcIp : direction === 'outbound' ? raw.dstIp : direction === 'internal' ? raw.srcIp : null;
  const localHint = localIp === raw.srcIp ? { name: raw.srcName, mac: raw.srcMac } : { name: raw.dstName, mac: raw.dstMac };
  const local = localIp ? resolveLocal(dir, localIp, localHint) : null;

  const signature = raw.signature ?? 'Threat detected (signature details unavailable)';
  const sa = analyzeSignature(signature, { catname: raw.category, classtype: raw.classtype });
  const blocked = raw.action === 'blocked' ? true : raw.action === 'alerted' ? false : null;
  const severity = assessSeverity({ categoryKey: sa.categoryKey, priority: raw.priority, direction, blocked });
  const { meaning, action: advice } = explainEvent({ categoryKey: sa.categoryKey, direction, blocked });
  const remoteIsSrc = remoteIp === raw.srcIp;

  return {
    id: raw.id,
    ts: raw.ts,
    source: raw.source,
    signature,
    signatureId: raw.signatureId,
    headline: sa.headline,
    detail: sa.detail ?? raw.description,
    categoryKey: sa.categoryKey,
    categoryRaw: raw.category,
    classtype: raw.classtype,
    cves: [...new Set([...sa.cves, ...raw.cves.map((c) => c.toUpperCase())])],
    priority: raw.priority,
    severity,
    action: raw.action,
    direction,
    srcIp: raw.srcIp,
    srcPort: raw.srcPort,
    dstIp: raw.dstIp,
    dstPort: raw.dstPort,
    proto: raw.proto,
    appProto: raw.appProto,
    remoteIp,
    localIp,
    local,
    remoteCountry: remoteIp ? (remoteIsSrc ? raw.srcCountry : raw.dstCountry) ?? null : null,
    remoteOrg: remoteIp ? (remoteIsSrc ? raw.srcOrg : raw.dstOrg) ?? null : null,
    meaning,
    advice,
    count: raw.count,
  };
}
