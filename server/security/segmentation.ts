// Reachability between networks, the internet and the gateway, explained in plain English.

import type { FixAction, MatrixCell, MatrixEndpoint, ReachVerdict, RuleDirection, RuleView, SegmentationMatrix } from '../../shared/types.ts';
import { evaluateChains, summarize, type Summary } from './evaluate.ts';
import type { Chain, EvalResult, FwModel, NetInfo, NormRule, SegVerdict, ZoneInfo } from './model.ts';
import { expectedReach, keepOffGatewayAdmin, label as roleLabel } from './roles.ts';
import { AddrSet, ServiceSet, ST_NEW, makeSpace, parsePorts, type Space } from './sets.ts';

export type Dest = { kind: 'network'; net: NetInfo } | { kind: 'internet' } | { kind: 'gateway' } | { kind: 'addrs'; addrs: AddrSet; label: string; zoneKey?: string };

export interface PathAnalysis {
  verdict: ReachVerdict;
  summary: Summary;
  result: EvalResult;
  chains: Chain[];
  probe: Space;
  notes: string[];
}

function zoneDefault(src: ZoneInfo | undefined, dst: ZoneInfo | undefined): { action: SegVerdict; label: string } {
  const s = src?.key ?? null;
  const d = dst?.key ?? null;
  if (!s || !d) return { action: 'unknown', label: 'no default known for custom zones' };
  if (s === 'external') return { action: 'block', label: 'traffic from the internet is blocked by default' };
  if (s === 'gateway') return { action: 'allow', label: 'gateway traffic is allowed by default' };
  if (d === 'external') return { action: 'allow', label: `${src!.name} → External is allowed by default` };
  if (s === 'internal' || s === 'vpn') return { action: 'allow', label: `${src!.name} → ${dst!.name} is allowed by default` };
  if (s === 'hotspot') return d === 'gateway' ? { action: 'allow', label: 'Hotspot → Gateway is allowed by default (DNS/DHCP)' } : { action: 'block', label: `Hotspot → ${dst!.name} is blocked by default` };
  if (s === 'dmz') return d === 'dmz' ? { action: 'allow', label: 'DMZ → DMZ is allowed by default' } : { action: 'block', label: `DMZ → ${dst!.name} is blocked by default` };
  return { action: 'unknown', label: 'unknown default' };
}

function legacyChain(model: FwModel, name: string, label: string): Chain {
  return { label, rules: model.rules.filter((r) => r.chain.replace('v6', '') === name), defaultAction: 'allow', defaultLabel: `no ${name} rule matches (accepted by default)` };
}

export function chainsFor(model: FwModel, src: NetInfo, dst: Dest): Chain[] | null {
  if (model.mode === 'zone') {
    const zs = model.zones.find((z) => z.id === src.zoneId);
    let zd: ZoneInfo | undefined;
    if (dst.kind === 'network') zd = model.zones.find((z) => z.id === dst.net.zoneId);
    else if (dst.kind === 'internet') zd = model.zones.find((z) => z.key === 'external');
    else if (dst.kind === 'gateway') zd = model.zones.find((z) => z.key === 'gateway');
    else zd = model.zones.find((z) => z.key === (dst.zoneKey ?? 'external'));
    if (!zs || !zd) return null;
    const def = zoneDefault(zs, zd);
    return [{ label: `${zs.name} → ${zd.name}`, rules: model.rules.filter((r) => r.chain === `${zs.id}>${zd.id}`), defaultAction: def.action, defaultLabel: def.label }];
  }
  if (model.mode === 'legacy') {
    const guest = src.purpose === 'guest';
    const inName = guest ? 'GUEST_IN' : 'LAN_IN';
    if (dst.kind === 'network') {
      const outName = dst.net.purpose === 'guest' ? 'GUEST_OUT' : 'LAN_OUT';
      return [legacyChain(model, inName, inName), legacyChain(model, outName, outName)];
    }
    if (dst.kind === 'gateway') {
      const local = guest ? 'GUEST_LOCAL' : 'LAN_LOCAL';
      return [legacyChain(model, local, local)];
    }
    return [legacyChain(model, inName, inName), legacyChain(model, 'WAN_OUT', 'WAN_OUT')];
  }
  return null;
}

export function destAddrs(model: FwModel, src: NetInfo, dst: Dest): AddrSet {
  const fam = src.ipv6 ? AddrSet.ANY : AddrSet.V4_ANY;
  if (dst.kind === 'network') return dst.net.addrs.intersect(fam);
  if (dst.kind === 'internet') return model.external.intersect(fam);
  if (dst.kind === 'gateway') return model.gatewayAddrs.intersect(fam);
  return dst.addrs;
}

export function analyzePath(model: FwModel, src: NetInfo, dst: Dest, svc: ServiceSet = ServiceSet.ALL, st = ST_NEW, srcAddrs?: AddrSet): PathAnalysis | null {
  const chains = chainsFor(model, src, dst);
  if (!chains) return null;
  const probe = makeSpace(srcAddrs ?? src.addrs, destAddrs(model, src, dst), svc, st);
  if (!probe.length) return null;
  const result = evaluateChains(probe, chains);
  const summary = summarize(probe, result);
  const notes: string[] = [];
  if (result.truncated) notes.push('Analysis was simplified because the rule set is very large.');
  return { verdict: summary.verdict, summary, result, chains, probe, notes };
}

export function ruleRef(r: NormRule): string {
  return `“${r.name || 'Unnamed rule'}”`;
}

/** "allows TCP 32400 to 192.168.20.20" - destination without the port suffix (the service already names it). */
export function ruleWhat(r: NormRule): string {
  return `${r.svcDesc} to ${r.dstDesc.replace(/ port [^)]*$/, '')}`;
}

export function describePath(a: PathAnalysis): { summary: string; explanation: string[] } {
  const s = a.summary;
  const explanation: string[] = [];
  const defaults = a.chains.map((c) => c.defaultLabel);
  const named = (rs: NormRule[]) => rs.map(ruleRef).join(', ');
  const realAllow = s.allowRules.filter((r) => !r.predefined);
  const realBlock = s.blockRules.filter((r) => !r.predefined);
  const sysAllow = s.allowRules.filter((r) => r.predefined);
  const sysBlock = s.blockRules.filter((r) => r.predefined);
  const defaultAllowed = s.defaultVerdicts.some((d) => d.verdict === 'allow');
  const defaultBlocked = s.defaultVerdicts.some((d) => d.verdict === 'block');
  let summary: string;
  switch (s.verdict) {
    case 'allowed': {
      const decisive = s.decisive;
      if (decisive && !decisive.predefined) {
        summary = `Allowed by ${ruleRef(decisive)}`;
        explanation.push(`New connections are explicitly allowed by ${ruleRef(decisive)}.`);
      } else if (decisive || sysAllow.length) {
        const d = decisive ?? sysAllow[0];
        summary = `Allowed by the built-in ${ruleRef(d)}`;
        explanation.push(`No custom rule blocks it, so the built-in policy ${ruleRef(d)} allows it.`);
      } else if (realAllow.length && !defaultAllowed) {
        summary = `Allowed by ${named(realAllow)}`;
        explanation.push(`New connections are explicitly allowed by ${named(realAllow)}.`);
      } else {
        summary = 'Allowed — no rule blocks it';
        explanation.push(`No rule applies: ${defaults.join('; ')}.`);
      }
      for (const r of realAllow.filter((x) => x !== decisive)) explanation.push(`Also explicitly allowed: ${ruleRef(r)} (${ruleWhat(r)}).`);
      break;
    }
    case 'blocked':
      if (realBlock.length) {
        summary = `Blocked by ${named(realBlock)}`;
        explanation.push(`New connections are blocked by ${named(realBlock)}.`);
      } else {
        summary = sysBlock.length ? `Blocked by the built-in ${named(sysBlock)}` : 'Blocked by default';
        explanation.push(sysBlock.length ? `Blocked by the built-in policy ${named(sysBlock)}.` : `Blocked by default: ${defaults.join('; ')}.`);
      }
      break;
    case 'partial': {
      const decisive = s.decisive;
      if (decisive && decisive.action !== 'allow') {
        summary = `Mostly blocked by ${ruleRef(decisive)}, with exceptions`;
        explanation.push(`Blocked by ${ruleRef(decisive)}…`);
        if (s.allowRules.length) explanation.push(`…except what ${named(s.allowRules)} allow${s.allowRules.length === 1 ? 's' : ''} first.`);
      } else if (decisive || defaultAllowed) {
        summary = `Mostly allowed; only part is blocked`;
        explanation.push(decisive ? `Allowed by ${ruleRef(decisive)} overall.` : `Allowed by default (${defaults.join('; ')}).`);
        if (s.blockRules.length) explanation.push(`${named(s.blockRules)} block${s.blockRules.length === 1 ? 's' : ''} part of the traffic.`);
      } else {
        summary = 'Partially allowed';
        if (s.allowRules.length) explanation.push(`Allowed by ${named(s.allowRules)}.`);
        if (s.blockRules.length) explanation.push(`Blocked by ${named(s.blockRules)}.`);
        if (defaultBlocked) explanation.push(`Everything else is blocked by default.`);
      }
      for (const r of s.allowRules.filter((x) => x !== decisive)) explanation.push(`Exception: ${ruleRef(r)} allows ${ruleWhat(r)}.`);
      for (const r of s.blockRules.filter((x) => x !== decisive)) explanation.push(`Restriction: ${ruleRef(r)} blocks ${ruleWhat(r)}.`);
      break;
    }
    default:
      summary = 'Unknown — no applicable policy found';
      explanation.push('No policy covers this path and there is no known default for it.');
  }
  for (const r of s.conditional) explanation.push(`${ruleRef(r)} may also apply (${r.notes[r.notes.length - 1] ?? 'conditional match'}).`);
  explanation.push(...a.notes);
  return { summary, explanation };
}

// Services that give a login prompt on the gateway itself. 8443 is left out: UniFi OS consoles serve their UI on 443
// (8443 only redirects there), and a self-hosted controller never runs on the gateway.
const GATEWAY_MGMT = [
  { ports: parsePorts('22')!, label: 'SSH (22)' },
  { ports: parsePorts('80')!, label: 'HTTP (80)' },
  { ports: parsePorts('443')!, label: 'the web UI (443)' },
];

/** The gateway management services that devices on `src` can open connections to. */
export function reachableGatewayMgmt(model: FwModel, src: NetInfo): string[] {
  return GATEWAY_MGMT.filter((m) => {
    const a = analyzePath(model, src, { kind: 'gateway' }, ServiceSet.tcp(m.ports));
    return a !== null && a.verdict !== 'blocked';
  }).map((m) => m.label);
}

export function buildMatrix(model: FwModel): SegmentationMatrix {
  const nets = model.networks.filter((n) => n.enabled && !n.addrs.isEmpty());
  const endpoints: MatrixEndpoint[] = [
    ...nets.map((n) => ({ id: n.id, name: n.name, kind: 'network' as const, vlan: n.vlan, role: n.role, subnet: n.subnet })),
    { id: 'internet', name: 'Internet', kind: 'internet', vlan: null, role: null, subnet: null },
    { id: 'gateway', name: 'Gateway', kind: 'gateway', vlan: null, role: null, subnet: null },
  ];
  const cells: MatrixCell[] = [];
  const notes: string[] = [...model.warnings];

  for (const src of nets) {
    for (const ep of endpoints) {
      if (ep.id === src.id) {
        cells.push({ from: src.id, to: ep.id, verdict: 'self', expected: 'either', risk: 'none', summary: 'Same network — traffic between devices on one network does not pass the firewall.', explanation: [], rules: [], fix: null });
        continue;
      }
      const dst: Dest = ep.kind === 'network' ? { kind: 'network', net: nets.find((n) => n.id === ep.id)! } : ep.kind === 'internet' ? { kind: 'internet' } : { kind: 'gateway' };
      const a = analyzePath(model, src, dst);
      if (!a) {
        cells.push({ from: src.id, to: ep.id, verdict: 'unknown', expected: 'either', risk: 'none', summary: 'Could not analyse this path.', explanation: [], rules: [], fix: null });
        continue;
      }
      const { summary, explanation } = describePath(a);
      const rules: MatrixCell['rules'] = [];
      const push = (r: NormRule, effect: MatrixCell['rules'][number]['effect']) => {
        if (!rules.some((x) => x.id === r.id)) rules.push({ id: r.id, name: r.name, action: r.action, effect });
      };
      if (a.summary.decisive) push(a.summary.decisive, 'decides');
      for (const r of [...a.summary.blockRules, ...a.summary.allowRules]) push(r, a.summary.verdict === 'partial' ? 'exception' : 'decides');
      for (const r of a.summary.conditional) push(r, 'conditional');

      let expected: MatrixCell['expected'] = 'either';
      let risk: MatrixCell['risk'] = 'ok';
      let fix: FixAction | null = null;
      if (ep.kind === 'network') {
        const exp = expectedReach(src.role, dst.kind === 'network' ? dst.net.role : 'other');
        expected = exp.expected;
        if (exp.expected === 'block' && a.verdict !== 'blocked') {
          risk = a.verdict === 'allowed' ? 'risk' : 'warn';
          explanation.unshift(exp.reason);
          fix = { templateId: 'isolate-networks', params: { sources: [src.id], destinations: [ep.id] }, label: `Block ${src.name} → ${ep.name}` };
        } else if (exp.expected === 'either' && a.verdict === 'allowed' && (src.role === 'media' || src.role === 'voip' || src.role === 'lab')) {
          explanation.push(exp.reason);
        }
      } else if (ep.kind === 'gateway') {
        if (keepOffGatewayAdmin(src.role)) {
          const open = reachableGatewayMgmt(model, src);
          if (open.length) {
            risk = 'warn';
            expected = 'block';
            explanation.unshift(`${roleLabel(src.role)} devices can reach the gateway's management: ${open.join(', ')}. DNS, DHCP and NTP must stay reachable, but management should not.`);
            fix = { templateId: 'protect-gateway', params: { networks: [src.id] }, label: `Protect gateway from ${src.name}` };
          }
        }
      } else if (ep.kind === 'internet') {
        if ((src.role === 'cameras' || src.role === 'storage') && a.verdict === 'allowed') {
          explanation.push(
            src.role === 'cameras'
              ? 'Cameras that are only used locally do not need internet access; blocking it stops them phoning home and closes remote attack paths.'
              : 'Storage networks only carry disk traffic between your servers and storage; they do not need the internet. Blocking it stops data leaving if a storage device is compromised.',
          );
          fix = { templateId: 'block-internet', params: { networks: [src.id] }, label: `Block internet for ${src.name}` };
        }
      }
      cells.push({ from: src.id, to: ep.id, verdict: a.verdict, expected, risk, summary, explanation, rules, fix });
    }
  }
  if (model.mode === 'legacy') notes.push('Legacy firewall: analysis follows LAN_IN → LAN_OUT / WAN_OUT / LAN_LOCAL rulesets, plus guest restrictions and network-isolation settings.');
  return { firewallMode: model.mode, endpoints, cells, notes };
}

// ---------------------------------------------------------------------------------
// Rule views (plain English)
// ---------------------------------------------------------------------------------

const LEGACY_LABEL: Record<string, string> = {
  LAN_IN: 'LAN in (between networks / to internet)',
  LAN_OUT: 'LAN out',
  LAN_LOCAL: 'LAN local (to the gateway)',
  WAN_IN: 'WAN in (internet → your networks)',
  WAN_OUT: 'WAN out (to the internet)',
  WAN_LOCAL: 'WAN local (internet → gateway)',
  GUEST_IN: 'Guest in',
  GUEST_OUT: 'Guest out',
  GUEST_LOCAL: 'Guest local (to the gateway)',
};

export function chainLabel(model: FwModel, r: NormRule): string {
  if (r.system === 'zone') {
    const s = model.zones.find((z) => z.id === r.srcZoneId)?.name ?? '?';
    const d = model.zones.find((z) => z.id === r.dstZoneId)?.name ?? '?';
    return `${s} → ${d}`;
  }
  const base = r.chain.replace('v6', '');
  return `${LEGACY_LABEL[base] ?? r.chain}${r.chain.includes('v6') ? ' (IPv6)' : ''}`;
}

export function ruleSentence(r: NormRule): string {
  const verb = r.action === 'allow' ? 'Allow' : r.action === 'reject' ? 'Reject' : 'Block';
  const what = r.svcDesc === 'all traffic' ? 'all traffic' : r.svcDesc;
  const states = r.stDesc === 'all connection states' ? '' : ` (${r.stDesc} only)`;
  const ver = r.ipVersion === 'IPv4 + IPv6' ? '' : ` [${r.ipVersion}]`;
  // The service already names the ports ("TCP/UDP 53, 853"), so don't repeat them after the destination.
  const dst = what === 'all traffic' ? r.dstDesc : r.dstDesc.replace(/ port [^)]*$/, '');
  return `${verb} ${what} from ${r.srcDesc} to ${dst}${states}${ver}`;
}

export function ruleDirection(model: FwModel, r: NormRule): RuleDirection {
  if (r.system === 'zone') {
    const s = model.zones.find((z) => z.id === r.srcZoneId)?.key;
    const d = model.zones.find((z) => z.id === r.dstZoneId)?.key;
    if (s === 'external') return 'inbound';
    if (d === 'external') return 'outbound';
    if (d === 'gateway') return 'gateway';
    return 'internal';
  }
  if (r.system === 'legacy') {
    const c = r.chain.replace('v6', '');
    if (c === 'WAN_IN' || c === 'WAN_LOCAL') return 'inbound';
    if (c === 'WAN_OUT') return 'outbound';
    if (c.endsWith('_LOCAL')) return 'gateway';
    return 'internal';
  }
  return 'other';
}

export function toRuleView(model: FwModel, r: NormRule): RuleView {
  const zoneName = (id: string | null) => (r.system === 'zone' ? (model.zones.find((z) => z.id === id)?.name ?? null) : null);
  return {
    id: r.id,
    name: r.name || '(unnamed)',
    system: r.system,
    srcZone: zoneName(r.srcZoneId),
    dstZone: zoneName(r.dstZoneId),
    direction: ruleDirection(model, r),
    enabled: r.enabled,
    predefined: r.predefined,
    managed: r.managed,
    action: r.action,
    index: r.index,
    group: chainLabel(model, r),
    source: r.srcDesc,
    destination: r.dstDesc,
    service: r.svcDesc,
    states: r.stDesc,
    ipVersion: r.ipVersion,
    sentence: ruleSentence(r),
    logging: r.logging,
    schedule: r.schedule,
    exact: r.exact,
    notes: r.notes,
    raw: r.raw,
  };
}
