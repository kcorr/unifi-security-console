// Normalized firewall model shared by the zone-based (Network 9+) and legacy rule
// converters, the segmentation analyzer, the hygiene checks and the hardening planner.

import type { FirewallMode, NetworkRole, RuleAction } from '../../shared/types.ts';
import type { AddrSet, Box, RangeSet, Space } from './sets.ts';

export interface NetInfo {
  id: string;
  name: string;
  vlan: number | null;
  purpose: string;
  /** Client address space of the network (v4 + v6). */
  addrs: AddrSet;
  subnet: string | null;
  subnet6: string | null;
  /** The gateway's own address(es) on this network. */
  gatewayAddrs: AddrSet;
  gatewayIp: string | null;
  zoneId: string | null;
  role: NetworkRole;
  roleSource: 'auto' | 'user';
  isolated: boolean;
  internetAccess: boolean;
  enabled: boolean;
  dhcpDns: string[];
  ipv6: boolean;
  /** A dedicated test network ("SC-Test…") that test-network write mode may change. */
  isTest: boolean;
  raw: Record<string, unknown>;
}

export interface ZoneInfo {
  id: string;
  name: string;
  /** internal | external | gateway | vpn | hotspot | dmz | null (custom) */
  key: string | null;
  networkIds: string[];
}

export interface GroupInfo {
  id: string;
  name: string;
  type: 'address' | 'port' | 'ipv6-address' | 'other';
  members: string[];
  addrs: AddrSet | null;
  ports: RangeSet | null;
}

export interface NormRule {
  id: string;
  name: string;
  system: 'zone' | 'legacy' | 'traffic';
  enabled: boolean;
  predefined: boolean;
  managed: boolean;
  action: RuleAction;
  /** Evaluation order inside its chain (lower first). */
  order: number;
  /** Display index (UniFi's own index / rule_index). */
  index: number;
  /** Zone pair "srcZoneId>dstZoneId", or a legacy ruleset name such as "LAN_IN", or "TRAFFIC". */
  chain: string;
  srcZoneId: string | null;
  dstZoneId: string | null;
  /** Traffic matched. When `exact` is false this is an over-approximation. */
  space: Space;
  exact: boolean;
  notes: string[];
  srcDesc: string;
  dstDesc: string;
  svcDesc: string;
  stDesc: string;
  ipVersion: 'IPv4' | 'IPv6' | 'IPv4 + IPv6';
  /** Set when the source is expressed purely as a list of networks (enables "extend" plans). */
  srcNetworkIds: string[] | null;
  dstNetworkIds: string[] | null;
  /** ISO country codes when the source matches by country (official API REGION filter). */
  srcRegions?: string[] | null;
  /** Source/destination expressed as "any" within their zone. */
  srcAny: boolean;
  dstAny: boolean;
  schedule: string | null;
  logging: boolean;
  raw: Record<string, unknown>;
}

export interface FwModel {
  mode: FirewallMode;
  networks: NetInfo[];
  zones: ZoneInfo[];
  groups: Map<string, GroupInfo>;
  rules: NormRule[];
  /** Union of all internal network address space. */
  internal: AddrSet;
  /** Everything that is not internal: what "the internet" means for analysis. */
  external: AddrSet;
  /** The gateway's own addresses (all LAN-side IPs). */
  gatewayAddrs: AddrSet;
  warnings: string[];
}

export function zoneByKey(m: FwModel, key: string): ZoneInfo | undefined {
  return m.zones.find((z) => z.key === key);
}

export function zoneOfNetwork(m: FwModel, networkId: string): ZoneInfo | undefined {
  const net = m.networks.find((n) => n.id === networkId);
  if (net?.zoneId) {
    const z = m.zones.find((x) => x.id === net.zoneId);
    if (z) return z;
  }
  return m.zones.find((z) => z.networkIds.includes(networkId));
}

export type SegVerdict = 'allow' | 'block' | 'unknown';

export interface Segment {
  box: Box;
  verdict: SegVerdict;
  /** Rule that produced the verdict (null = chain default). */
  rule: NormRule | null;
  chain: string;
  /** Rules that allowed the traffic in earlier chains (legacy LAN_IN → LAN_OUT). */
  trail: NormRule[];
}

export interface Chain {
  label: string;
  rules: NormRule[];
  defaultAction: SegVerdict;
  /** Human description of the default (e.g. "predefined Allow All", "implicit accept"). */
  defaultLabel: string;
}

export interface EvalResult {
  segments: Segment[];
  conditional: { rule: NormRule; box: Box; chain: string }[];
  truncated: boolean;
}
