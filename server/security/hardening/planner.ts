// Turns a hardening request into a minimal, explained change plan.
//
// Order of preference for every piece of traffic that should be blocked:
//   1. already enforced            → nothing to do (cite the rules)
//   2. a narrower rule exists      → widen it  (e.g. UDP 53 → TCP/UDP 53, 853)
//   3. an equivalent rule exists   → extend it with the extra networks
//   4. otherwise                   → create one new rule for all remaining networks
// Narrow custom ALLOW rules (e.g. your Pi-hole) are kept as exceptions; broad ALLOW rules
// that would shadow the new block are reported and the new rule is ordered above them.

import { randomUUID } from 'node:crypto';
import { TEST_NETWORK_PREFIX, type ChangePlan, type PlanAnalysisItem, type PlanOperation, type TemplateStatus, type TemplateTarget } from '../../../shared/types.ts';
import type { UniFiClient } from '../../unifi/client.ts';
import type { RawSnapshot } from '../../unifi/collect.ts';
import { evaluateChains } from '../evaluate.ts';
import type { FwModel, NetInfo, NormRule, ZoneInfo } from '../model.ts';
import { MANAGED_MARKER, MANAGED_PREFIX } from '../normalize.ts';
import { expectedReach, keepOffGatewayAdmin } from '../roles.ts';
import { analyzeHygiene } from '../hygiene.ts';
import { analyzePath, ruleRef, ruleSentence, ruleWhat, type Dest } from '../segmentation.ts';
import { AddrSet, ServiceSet, ST_ALL, ST_EST, ST_NEW, ST_REL, makeSpace, parsePorts, spaceContains, spaceDst, spaceIntersect, spaceIsEmpty, spaceSvc } from '../sets.ts';
import { assessIntent, coverageSummary, type Coverage, type Intent } from './intents.ts';
import {
  forPut, ruleBody, rulePath, withDestinationNetworks, withRegions, withService, withSourceNetworks, type Dialect, type EndpointSpec, type RuleSpec, type SvcPart,
} from './payloads.ts';
import { RISKY_OUTBOUND, TEMPLATES, getTemplate } from './templates.ts';
import { attachRuleDetails } from './ruleDetail.ts';
import { ipsCoverage } from '../ipsCategories.ts';

type Obj = Record<string, unknown>;

export interface PlannerCtx {
  model: FwModel;
  raw: RawSnapshot;
  client: UniFiClient;
  /** Test-network write mode: never modify anything outside the dedicated test network. */
  testOnly?: boolean;
  /** Network owner of a public address from local data (offline database / cache), if known. */
  ownerOf?: (ip: string) => string | null;
}

const SHARED_INFRA_RE = /cloudflare|akamai|fastly|amazon|aws|cloudfront|google|microsoft|azure|apple|meta platforms|facebook|edgecast|edgio|limelight|stackpath|bunny|cdn77|g-core|gcore|oracle|digitalocean|linode|ovh|hetzner|vultr/i;

// "This host", loopback, link-local, carrier-grade NAT, multicast, reserved and broadcast: never an internet attacker.
const SPECIAL_V4 = AddrSet.parseList(['0.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16', '100.64.0.0/10', '224.0.0.0/4', '240.0.0.0/4']).set;

/** May this existing rule be modified (widened / extended / reordered / removed)? */
export function canModify(ctx: PlannerCtx, r: NormRule): boolean {
  if (!ctx.testOnly) return true;
  if (!r.managed) return false;
  const ids = r.srcNetworkIds ?? [];
  return ids.length > 0 && ids.every((id) => ctx.model.networks.find((n) => n.id === id || n.raw._legacyId === id)?.isTest === true);
}

export function dialectOf(raw: RawSnapshot): Dialect | null {
  return raw.firewallSource === 'integration' ? 'integration' : raw.firewallSource === 'internal-v2' ? 'internal-v2' : raw.firewallSource === 'legacy' ? 'legacy' : null;
}

const describe = (date = new Date()) => `${MANAGED_MARKER}managed – created by Security Console on ${date.toISOString().slice(0, 10)}`;
const opId = () => randomUUID().slice(0, 8);
const names = (nets: NetInfo[], max = 3) => (nets.length <= max ? nets.map((n) => n.name).join(', ') : `${nets.slice(0, max).map((n) => n.name).join(', ')} +${nets.length - max}`);
const list = (xs: string[]) => (xs.length <= 1 ? xs.join('') : `${xs.slice(0, -1).join(', ')} and ${xs[xs.length - 1]}`);
const arr = <T = string>(v: unknown): T[] => (Array.isArray(v) ? (v as T[]) : []);
/** A parameter list of strings; numbers are accepted as text and anything else is dropped, never trusted blindly. */
const strs = (v: unknown): string[] => arr<unknown>(v).flatMap((x) => (typeof x === 'string' ? [x.trim()] : typeof x === 'number' ? [String(x)] : [])).filter(Boolean);

/** "22, 80, 443" or "8000-8100": ports 1–65535, ranges ascending. */
export function validPorts(s: string): boolean {
  const parts = s.split(',').map((p) => p.trim());
  return (
    parts.length > 0 &&
    parts.every((p) => {
      const m = /^(\d{1,5})(?:-(\d{1,5}))?$/.exec(p);
      if (!m) return false;
      const a = Number(m[1]);
      const b = m[2] === undefined ? a : Number(m[2]);
      return a >= 1 && b <= 65535 && a <= b;
    })
  );
}

function plan(templateId: string, title: string, params: Record<string, unknown>): ChangePlan {
  return { id: randomUUID(), templateId, title, summary: '', params, analysis: [], operations: [], warnings: [], noop: true, strategy: 'none', alternatives: [], blockedReason: null, createdAt: Date.now() };
}

// ---------------------------------------------------------------------------------
// Template → intents
// ---------------------------------------------------------------------------------

function partsFor(templateId: string, params: Record<string, unknown>): SvcPart[] {
  switch (templateId) {
    case 'block-external-dns':
      return [{ protocol: 'tcp_udp', ports: params.includeDot === false ? '53' : '53,853' }];
    case 'protect-gateway':
      return [{ protocol: 'tcp', ports: String(params.ports || '22,80,443').replace(/\s+/g, '') }];
    case 'block-risky-outbound': {
      const sel = strs(params.services).length ? strs(params.services) : ['smtp', 'smb', 'telnet', 'irc'];
      const tcp = sel.map((k) => RISKY_OUTBOUND[k]?.tcp).filter(Boolean).join(',');
      const udp = sel.map((k) => RISKY_OUTBOUND[k]?.udp).filter(Boolean).join(',');
      return [...(tcp ? [{ protocol: 'tcp' as const, ports: tcp }] : []), ...(udp ? [{ protocol: 'udp' as const, ports: udp }] : [])];
    }
    default:
      return [{ protocol: 'all', ports: null }];
  }
}

export function svcOf(p: SvcPart): ServiceSet {
  return ServiceSet.fromProtocol(p.protocol, p.ports ? parsePorts(p.ports) : null) ?? ServiceSet.ALL;
}

function pickNetworks(model: FwModel, ids: unknown): NetInfo[] {
  const set = new Set(arr(ids));
  return model.networks.filter((n) => set.has(n.id) && n.enabled && !n.addrs.isEmpty());
}

interface TargetIntent extends Intent {
  part: SvcPart;
  key: string;
  label: string;
  dstNet: NetInfo | null;
}

function buildIntents(model: FwModel, templateId: string, params: Record<string, unknown>): TargetIntent[] {
  const parts = partsFor(templateId, params);
  const out: TargetIntent[] = [];
  const push = (src: NetInfo, dst: Dest, dstLabel: string, dstNet: NetInfo | null, exempt = AddrSet.EMPTY, statesMatter = false) => {
    for (const part of parts) {
      out.push({ src, dst, dstLabel, svc: svcOf(part), st: ST_NEW, exempt, statesMatter, part, key: dstNet ? `${src.id}>${dstNet.id}` : src.id, label: dstNet ? `${src.name} → ${dstNet.name}` : src.name, dstNet });
    }
  };
  if (templateId === 'isolate-networks') {
    const dsts = pickNetworks(model, params.destinations);
    for (const s of pickNetworks(model, params.sources)) for (const d of dsts) if (s.id !== d.id) push(s, { kind: 'network', net: d }, d.name, d, AddrSet.EMPTY, true);
    return out;
  }
  const nets = pickNetworks(model, params.networks);
  if (templateId === 'block-external-dns') {
    const exempt = AddrSet.parseList(strs(params.allowedServers)).set;
    for (const n of nets) push(n, { kind: 'internet' }, 'the internet', null, exempt.intersect(n.addrs));
  } else if (templateId === 'block-internet' || templateId === 'block-risky-outbound') {
    for (const n of nets) push(n, { kind: 'internet' }, 'the internet', null);
  } else if (templateId === 'protect-gateway') {
    for (const n of nets) push(n, { kind: 'gateway' }, 'the gateway', null);
  }
  return out;
}

// ---------------------------------------------------------------------------------
// Matching existing rules
// ---------------------------------------------------------------------------------

function chainKey(model: FwModel, i: TargetIntent): string | null {
  if (model.mode === 'zone') {
    const dz =
      i.dst.kind === 'network' ? i.dst.net.zoneId : i.dst.kind === 'gateway' ? model.zones.find((z) => z.key === 'gateway')?.id : model.zones.find((z) => z.key === 'external')?.id;
    return i.src.zoneId && dz ? `${i.src.zoneId}>${dz}` : null;
  }
  const guest = i.src.purpose === 'guest';
  if (i.dst.kind === 'internet') return 'WAN_OUT';
  if (i.dst.kind === 'gateway') return guest ? 'GUEST_LOCAL' : 'LAN_LOCAL';
  return guest ? 'GUEST_IN' : 'LAN_IN';
}

function statesOk(r: NormRule, statesMatter: boolean): boolean {
  const st = r.space[0]?.st ?? ST_ALL;
  if (!(st & ST_NEW)) return false;
  return statesMatter ? (st & (ST_EST | ST_REL)) === 0 : true;
}

function dstMatches(model: FwModel, r: NormRule, i: TargetIntent): boolean {
  const d = spaceDst(r.space);
  if (i.dst.kind === 'internet') return d.contains(model.external.intersect(AddrSet.V4_ANY)) && (model.mode !== 'zone' || r.dstAny || d.isAny());
  if (i.dst.kind === 'gateway') return d.contains(model.gatewayAddrs.intersect(AddrSet.V4_ANY));
  return false;
}

const isDeny = (r: NormRule) => r.action === 'block' || r.action === 'reject';
const FAMILIES: Record<NormRule['ipVersion'], number[]> = { IPv4: [4], IPv6: [6], 'IPv4 + IPv6': [4, 6] };
/** Can this rule, once changed, close the whole gap? An IPv4-only rule never closes an IPv6 gap. */
const coversFamilies = (r: NormRule, covs: Coverage[]) => covs.every((c) => c.gapSpace.every((b) => FAMILIES[r.ipVersion].includes(b.fam)));
const editableBase = (r: NormRule) => r.enabled && !r.predefined && r.exact && !r.id.startsWith('synthetic:') && Object.keys(r.raw).length > 0;

// ---------------------------------------------------------------------------------
// Ordering helpers
// ---------------------------------------------------------------------------------

interface OrderingNeed {
  srcZoneId: string;
  dstZoneId: string;
  /** Placeholders/ids that must come first (exceptions). */
  first: string[];
  /** New rule placeholders that must come before the given existing rule ids. */
  before: { id: string; beforeIds: string[] }[];
  /** All new user rules created in this pair (placeholders). */
  created: string[];
}

function userPolicies(ctx: PlannerCtx, dialect: Dialect, s: string, d: string): { before: string[]; after: string[] } {
  const rows: { id: string; index: number }[] = [];
  if (dialect === 'integration') {
    for (const p of ctx.raw.iPolicies) {
      if ((p.metadata as Obj | undefined)?.origin !== 'USER_DEFINED') continue;
      if ((p.source as Obj)?.zoneId !== s || (p.destination as Obj)?.zoneId !== d) continue;
      rows.push({ id: String(p.id), index: Number(p.index ?? 0) });
    }
  } else {
    for (const p of ctx.raw.v2Policies) {
      if (p.predefined === true) continue;
      if ((p.source as Obj)?.zone_id !== s || (p.destination as Obj)?.zone_id !== d) continue;
      rows.push({ id: String(p._id), index: Number(p.index ?? 0) });
    }
  }
  rows.sort((a, b) => a.index - b.index);
  return { before: rows.filter((r) => r.index < 30000).map((r) => r.id), after: rows.filter((r) => r.index >= 30000).map((r) => r.id) };
}

function orderingOp(ctx: PlannerCtx, dialect: Dialect, need: OrderingNeed): PlanOperation | null {
  if (dialect === 'legacy') return null;
  const current = userPolicies(ctx, dialect, need.srcZoneId, need.dstZoneId);
  let before = [...current.before, ...need.created.filter((c) => !need.first.includes(c))];
  for (const b of need.before) {
    before = before.filter((x) => x !== b.id);
    const pos = Math.min(...b.beforeIds.map((id) => before.indexOf(id)).filter((p) => p >= 0), before.length);
    before.splice(pos, 0, b.id);
  }
  before = [...need.first, ...before.filter((x) => !need.first.includes(x))];
  const zoneName = (id: string) => ctx.model.zones.find((z) => z.id === id)?.name ?? id;
  const deps = [...need.first, ...need.created].filter((x) => x.startsWith('$created:')).map((x) => x.slice(9));
  if (dialect === 'integration') {
    return {
      id: opId(),
      kind: 'update',
      objectType: 'firewall-policy',
      method: 'PUT',
      api: 'integration',
      path: ctx.client.fullPath('integration', `/firewall/policies/ordering?sourceFirewallZoneId=${need.srcZoneId}&destinationFirewallZoneId=${need.dstZoneId}`),
      body: { orderedFirewallPolicyIds: { beforeSystemDefined: before, afterSystemDefined: current.after } },
      before: { orderedFirewallPolicyIds: { beforeSystemDefined: current.before, afterSystemDefined: current.after } },
      description: `Order rules in ${zoneName(need.srcZoneId)} → ${zoneName(need.dstZoneId)} so the new rule takes effect`,
      dependsOn: deps,
    };
  }
  return {
    id: opId(),
    kind: 'update',
    objectType: 'firewall-policy',
    method: 'PUT',
    api: 'internal',
    path: ctx.client.fullPath('v2', '/firewall-policies/batch-reorder'),
    body: { source_zone_id: need.srcZoneId, destination_zone_id: need.dstZoneId, before_predefined_ids: before, after_predefined_ids: current.after },
    before: { source_zone_id: need.srcZoneId, destination_zone_id: need.dstZoneId, before_predefined_ids: current.before, after_predefined_ids: current.after },
    description: `Order rules in ${zoneName(need.srcZoneId)} → ${zoneName(need.dstZoneId)} so the new rule takes effect`,
    dependsOn: deps,
  };
}

function legacyIndex(model: FwModel, ruleset: string, opts: { first?: boolean; beforeIndex?: number; taken: Set<number> }): number {
  const used = new Set(model.rules.filter((r) => r.chain === ruleset).map((r) => r.index));
  for (const t of opts.taken) used.add(t);
  let idx: number;
  if (opts.first || opts.beforeIndex !== undefined) {
    const limit = opts.beforeIndex ?? Math.min(...[...used].filter((i) => i >= 2000 && i < 3000), 3000);
    idx = limit - 1;
    while (used.has(idx) && idx > 2000) idx--;
    if (idx < 2000) idx = 2000;
  } else {
    idx = Math.max(1999, ...[...used].filter((i) => i >= 2000 && i < 3000)) + 1;
  }
  while (used.has(idx)) idx++;
  opts.taken.add(idx);
  return idx;
}

export interface LegacyWant {
  chain: string;
  /** An exception must land before every block it would otherwise be caught by; a block before the allow it overrides. */
  kind: 'exception' | 'block';
  /** The rule index this rule has to stay below (Infinity: anywhere after your existing rules). */
  bound: number;
  body: Obj;
}

/**
 * Rule indexes for one plan's new legacy rules, handed out once the whole plan is known, so an exception always lands
 * before the blocks it has to survive (legacy rules run in rule_index order, 2000–2999 before the built-in ones).
 * Returns why a rule can't be placed without renumbering your existing rules.
 */
export function assignLegacyIndexes(model: FwModel, wants: LegacyWant[]): string | null {
  for (const chain of new Set(wants.map((w) => w.chain))) {
    const mine = wants.filter((w) => w.chain === chain);
    const used = new Set(model.rules.filter((r) => r.chain === chain).map((r) => r.index));
    const take = (i: number | null) => {
      if (i !== null) used.add(i);
      return i;
    };
    const append = () => {
      const i = Math.max(1999, ...[...used].filter((x) => x >= 2000 && x < 3000)) + 1;
      return i < 3000 ? i : null;
    };
    const lowestFree = (below: number) => {
      for (let i = 2000; i < Math.min(below, 3000); i++) if (!used.has(i)) return i;
      return null;
    };
    const highestFree = (below: number, above: number) => {
      for (let i = Math.min(below, 3000) - 1; i > above && i >= 2000; i--) if (!used.has(i)) return i;
      return null;
    };
    const renumber = 'Renumber your rules in UniFi (leave gaps between the rule indexes) and try again.';
    // An exception also has to precede every new block, and so whatever those blocks have to precede.
    const exceptionBound = Math.min(...mine.map((w) => w.bound));
    let floor = 1999;
    for (const w of mine.filter((x) => x.kind === 'exception')) {
      const i = take(Number.isFinite(exceptionBound) ? lowestFree(exceptionBound) : append());
      if (i === null) return `There is no free rule index in ${chain} to put the DNS server exception before the rules that would block it. ${renumber}`;
      w.body.rule_index = i;
      floor = Math.max(floor, i);
    }
    for (const w of mine.filter((x) => x.kind === 'block')) {
      const i = take(Number.isFinite(w.bound) ? highestFree(w.bound, floor) : append());
      if (i === null) return `There is no free rule index in ${chain} to put the new rule ${Number.isFinite(w.bound) ? `before rule index ${w.bound}` : 'after your existing rules'}. ${renumber}`;
      w.body.rule_index = i;
    }
  }
  return null;
}

// ---------------------------------------------------------------------------------
// Firewall templates
// ---------------------------------------------------------------------------------

interface Group {
  chain: string;
  srcZoneId: string | null;
  dstZoneId: string | null;
  part: SvcPart;
  srcs: NetInfo[];
  dsts: NetInfo[];
  dstKind: Dest['kind'];
  covs: Coverage[];
}

function ruleTitle(templateId: string, g: Group): string {
  switch (templateId) {
    case 'block-external-dns':
      return `${MANAGED_PREFIX} Block external DNS`;
    case 'isolate-networks':
      return `${MANAGED_PREFIX} Isolate ${names(g.srcs, 2)} → ${names(g.dsts, 2)}`;
    case 'block-internet':
      return `${MANAGED_PREFIX} No internet: ${names(g.srcs, 3)}`;
    case 'protect-gateway':
      return `${MANAGED_PREFIX} Protect gateway management`;
    case 'block-risky-outbound':
      return `${MANAGED_PREFIX} Block risky outbound (${g.part.protocol.toUpperCase()})`;
    default:
      return `${MANAGED_PREFIX} ${templateId}`;
  }
}

function netIdFor(dialect: Dialect, n: NetInfo): string {
  // Legacy/v2 policies reference networkconf _ids; the official API uses UUIDs.
  return dialect === 'integration' ? n.id : String(n.raw._legacyId ?? n.id);
}

export function buildFirewallPlan(ctx: PlannerCtx, templateId: string, params: Record<string, unknown>, strategyPref?: string): ChangePlan {
  const t = getTemplate(templateId)!;
  const p = plan(templateId, t.title, params);
  const { model } = ctx;
  const dialect = dialectOf(ctx.raw);
  const editable = (r: NormRule) => editableBase(r) && canModify(ctx, r);
  // An unreadable port list must never turn into "any port".
  if (params.ports !== undefined && params.ports !== '' && !validPorts(String(params.ports))) {
    p.summary = 'Enter ports like 22, 80, 443 or a range like 8000-8100 (1–65535).';
    p.state = 'needs-input';
    return p;
  }
  if (!dialect) {
    p.summary = 'The firewall configuration could not be read, so no changes can be planned safely.';
    p.state = 'unavailable';
    p.warnings.push('Check the Settings → Diagnostics page for which API calls failed.');
    return p;
  }
  const intents = buildIntents(model, templateId, params);
  if (!intents.length) {
    p.summary = templateId === 'isolate-networks' ? 'Choose at least one source and one destination network.' : 'Choose at least one network.';
    p.state = 'needs-input';
    return p;
  }

  const covs = intents.map((i) => ({ i, c: assessIntent(model, i) }));
  const ops: PlanOperation[] = [];
  const analysis: PlanAnalysisItem[] = [];
  const handled = new Map<string, { status: PlanAnalysisItem['status']; message: string; rules: { id: string; name: string }[] }>();
  // Coverage of each target across all parts that get a new rule (e.g. TCP and UDP), for one combined message.
  const createdCovs = new Map<string, Coverage[]>();
  const selectedSrcIds = new Set(intents.map((i) => i.src.id));
  const orderings = new Map<string, OrderingNeed>();
  const legacyWants: LegacyWant[] = [];
  let usedExtend = false;
  let usedCreate = false;
  let extendAvailable = false;

  const needOrdering = (srcZoneId: string, dstZoneId: string) => {
    const k = `${srcZoneId}>${dstZoneId}`;
    if (!orderings.has(k)) orderings.set(k, { srcZoneId, dstZoneId, first: [], before: [], created: [] });
    return orderings.get(k)!;
  };

  // Pending modifications of existing rules: widening and extending the same rule are merged
  // into a single update, so one request never produces two edits (or two rules).
  interface Pending {
    rule: NormRule;
    part?: SvcPart;
    srcIds?: string[];
    dstIds?: string[];
    added: string[];
  }
  const pending = new Map<string, Pending>();
  const pend = (r: NormRule) => {
    const pe = pending.get(r.id) ?? { rule: r, added: [] };
    pending.set(r.id, pe);
    return pe;
  };
  const effSvc = (r: NormRule) => {
    const part = pending.get(r.id)?.part;
    return part ? svcOf(part) : spaceSvc(r.space);
  };
  // Extending a rule that is evaluated BEFORE a narrow allow exception would silently break that exception.
  const shadowsException = (r: NormRule, cs: Coverage[]) => cs.some((c) => c.exceptions.some((ex) => ex.chain === r.chain && ex.order > r.order));
  const firstOps: PlanOperation[] = [];
  const createOps: PlanOperation[] = [];

  // 1. Widen narrower rules that already target exactly these networks.
  for (const { i, c } of covs) {
    if (c.state !== 'partial' || strategyPref === 'create') continue;
    const w = c.blockers.find(
      (r) =>
        editable(r) &&
        isDeny(r) &&
        r.srcNetworkIds?.includes(netIdFor(dialect, i.src)) &&
        r.srcNetworkIds.every((id) => selectedSrcIds.has(id) || model.networks.some((n) => n.raw._legacyId === id && selectedSrcIds.has(n.id))) &&
        (i.dst.kind === 'network' ? false : dstMatches(model, r, i)) &&
        i.svc.contains(spaceSvc(r.space)) &&
        !spaceSvc(r.space).equals(i.svc) &&
        statesOk(r, i.statesMatter) &&
        !shadowsException(r, [c]) &&
        coversFamilies(r, [c]),
    );
    if (!w) continue;
    pend(w).part = i.part;
    handled.set(`${i.key}|${i.part.protocol}${i.part.ports}`, {
      status: 'will-update',
      message: `${c.gap}. Your rule ${ruleRef(w)} only covers ${w.svcDesc}; it will be widened to ${svcOf(i.part).describe()} instead of adding a second rule.`,
      rules: [{ id: w.id, name: w.name }],
    });
    usedExtend = true;
  }

  // 2. Group what is still missing by rule shape.
  const groups = new Map<string, Group>();
  for (const { i, c } of covs) {
    if (c.state === 'covered' || c.state === 'n/a') continue;
    if (handled.has(`${i.key}|${i.part.protocol}${i.part.ports}`)) continue;
    const chain = chainKey(model, i);
    if (!chain) continue;
    const [sz, dz] = model.mode === 'zone' ? chain.split('>') : [null, null];
    const k = `${chain}|${i.dst.kind}|${i.part.protocol}|${i.part.ports}`;
    const g = groups.get(k) ?? { chain, srcZoneId: sz, dstZoneId: dz, part: i.part, srcs: [], dsts: [], dstKind: i.dst.kind, covs: [] };
    if (!g.srcs.includes(i.src)) g.srcs.push(i.src);
    if (i.dstNet && !g.dsts.includes(i.dstNet)) g.dsts.push(i.dstNet);
    g.covs.push(c);
    groups.set(k, g);
  }

  // Isolation: split groups so every rule is "these sources → these destinations" without
  // re-blocking pairs that are already covered.
  const finalGroups: Group[] = [];
  for (const g of groups.values()) {
    if (g.dstKind !== 'network') {
      finalGroups.push(g);
      continue;
    }
    const bySrc = new Map<string, { src: NetInfo; dsts: NetInfo[]; covs: Coverage[] }>();
    for (const c of g.covs) {
      const e = bySrc.get(c.intent.src.id) ?? { src: c.intent.src, dsts: [], covs: [] };
      const dn = (c.intent.dst as { net: NetInfo }).net;
      if (!e.dsts.includes(dn)) e.dsts.push(dn);
      e.covs.push(c);
      bySrc.set(c.intent.src.id, e);
    }
    const byDstSet = new Map<string, Group>();
    for (const e of bySrc.values()) {
      const key = e.dsts.map((d) => d.id).sort().join(',');
      const ng = byDstSet.get(key) ?? { ...g, srcs: [], dsts: e.dsts, covs: [] };
      ng.srcs.push(e.src);
      ng.covs.push(...e.covs);
      byDstSet.set(key, ng);
    }
    finalGroups.push(...byDstSet.values());
  }

  for (const g of finalGroups) {
    const conflicts = [...new Map(g.covs.flatMap((c) => c.conflicts).map((r) => [r.id, r])).values()];
    const sampleIntent = intents.find((i) => i.src === g.srcs[0] && i.part === g.part && (g.dstKind !== 'network' || g.dsts.includes(i.dstNet!)))!;
    const svc = svcOf(g.part);

    // Candidate: an equivalent rule we can extend with more networks.
    let extendTarget: { rule: NormRule; axis: 'src' | 'dst'; ids: string[] } | null = null;
    let skippedForException: NormRule | null = null;
    if (dialect !== 'legacy') {
      const candidates = model.rules.filter((r) => editable(r) && isDeny(r) && r.chain === g.chain && effSvc(r).equals(svc) && statesOk(r, sampleIntent.statesMatter) && coversFamilies(r, g.covs));
      const srcIdsOf = (r: NormRule) => pending.get(r.id)?.srcIds ?? r.srcNetworkIds;
      const dstIdsOf = (r: NormRule) => pending.get(r.id)?.dstIds ?? r.dstNetworkIds;
      // A rule that already names every one of these networks wouldn't change, and the gap would stay open.
      const hasAll = (ids: string[] | null, nets: NetInfo[]) => !!ids && nets.every((n) => ids.includes(netIdFor(dialect, n)));
      const srcMatches = candidates
        .filter((r) => srcIdsOf(r) && !hasAll(srcIdsOf(r), g.srcs) && (g.dstKind === 'network' ? sameSet(dstIdsOf(r), g.dsts.map((d) => netIdFor(dialect, d))) : dstMatches(model, r, sampleIntent)))
        .sort((a, b) => Number(pending.has(b.id)) - Number(pending.has(a.id)) || Number(b.managed) - Number(a.managed) || (b.srcNetworkIds?.length ?? 0) - (a.srcNetworkIds?.length ?? 0));
      const srcExt = srcMatches.find((r) => !shadowsException(r, g.covs));
      if (!srcExt && srcMatches.length) skippedForException = srcMatches[0];
      if (srcExt) extendTarget = { rule: srcExt, axis: 'src', ids: [...new Set([...(srcIdsOf(srcExt) ?? []), ...g.srcs.map((n) => netIdFor(dialect, n))])] };
      else if (g.dstKind === 'network') {
        const dstMatchesList = candidates.filter((r) => dstIdsOf(r) && !hasAll(dstIdsOf(r), g.dsts) && sameSet(srcIdsOf(r), g.srcs.map((n) => netIdFor(dialect, n))));
        const dstExt = dstMatchesList.find((r) => !shadowsException(r, g.covs));
        if (!dstExt && dstMatchesList.length) skippedForException = dstMatchesList[0];
        if (dstExt) extendTarget = { rule: dstExt, axis: 'dst', ids: [...new Set([...(dstIdsOf(dstExt) ?? []), ...g.dsts.map((n) => netIdFor(dialect, n))])] };
      }
    }
    if (extendTarget) extendAvailable = true;
    const blockedByConflict = conflicts.length > 0 && extendTarget && conflicts.some((c) => c.order < extendTarget!.rule.order);
    const doExtend = !!extendTarget && strategyPref !== 'create' && !blockedByConflict;
    const targetLabels = g.dstKind === 'network' ? g.srcs.flatMap((s) => g.dsts.map((d) => `${s.name} → ${d.name}`)) : g.srcs.map((s) => s.name);

    if (doExtend && extendTarget) {
      const r = extendTarget.rule;
      const pe = pend(r);
      if (extendTarget.axis === 'src') pe.srcIds = extendTarget.ids;
      else pe.dstIds = extendTarget.ids;
      pe.added.push(...(extendTarget.axis === 'src' ? g.srcs : g.dsts).map((n) => n.name));
      for (const lbl of targetLabels) handled.set(lbl, { status: 'will-extend', message: `Will be added to your existing rule ${ruleRef(r)} instead of creating a duplicate rule.`, rules: [{ id: r.id, name: r.name }] });
      usedExtend = true;
      continue;
    }
    if (skippedForException) {
      p.warnings.push(
        `${ruleRef(skippedForException)} could have been extended, but it is evaluated before an allow exception for the same traffic — extending it would break that exception. A separate rule is created after the exception instead.`,
      );
    }

    // Create a new rule (legacy rules hold one source network each).
    const srcBatches = dialect === 'legacy' ? g.srcs.map((s) => [s]) : [g.srcs];
    for (const batch of srcBatches) {
      const dstBatches: (NetInfo | null)[] = dialect === 'legacy' && g.dstKind === 'network' ? g.dsts : [null];
      for (const dstOne of dstBatches) {
        const id = opId();
        const spec: RuleSpec = {
          name: ruleTitle(templateId, { ...g, srcs: batch, dsts: dstOne ? [dstOne] : g.dsts }),
          description: describe(),
          action: 'BLOCK',
          srcZoneId: g.srcZoneId,
          dstZoneId: g.dstZoneId,
          src: { kind: 'networks', ids: batch.map((n) => netIdFor(dialect, n)) },
          dst: g.dstKind === 'network' ? { kind: 'networks', ids: (dstOne ? [dstOne] : g.dsts).map((n) => netIdFor(dialect, n)) } : { kind: 'any' },
          svc: g.part,
          states: 'new',
          ipVersion: dialect === 'legacy' ? 'v4' : 'both',
        };
        if (dialect === 'legacy') spec.ruleset = g.chain;
        const path = rulePath(dialect);
        const body = ruleBody(dialect, spec);
        if (dialect === 'legacy') {
          const firstConflict = conflicts.filter((c) => c.chain === g.chain).sort((a, b) => a.order - b.order)[0];
          legacyWants.push({ chain: g.chain, kind: 'block', bound: firstConflict?.index ?? Infinity, body });
        }
        createOps.push({
          id,
          kind: 'create',
          objectType: dialect === 'legacy' ? 'firewall-rule' : 'firewall-policy',
          method: 'POST',
          api: path.kind === 'integration' ? 'integration' : 'internal',
          path: ctx.client.fullPath(path.kind, path.sub),
          body,
          description: `Create rule “${spec.name}”`,
          sentence: `Block ${svc.isAll() ? 'new connections' : `new ${svc.describe()} connections`} from ${names(batch, 4)} to ${g.dstKind === 'network' ? names(dstOne ? [dstOne] : g.dsts, 4) : g.dstKind === 'gateway' ? 'the gateway' : 'the internet'}`,
        });
        if (g.srcZoneId && g.dstZoneId) {
          const need = needOrdering(g.srcZoneId, g.dstZoneId);
          need.created.push(`$created:${id}`);
          if (conflicts.length) need.before.push({ id: `$created:${id}`, beforeIds: conflicts.map((c) => c.id) });
        }
      }
    }
    usedCreate = true;
    for (const lbl of targetLabels) {
      const cov = g.covs.find((c) => (g.dstKind === 'network' ? `${c.intent.src.name} → ${(c.intent.dst as { net: NetInfo }).net.name}` : c.intent.src.name) === lbl);
      const covs = [...(createdCovs.get(lbl) ?? []), ...(cov ? [cov] : [])];
      createdCovs.set(lbl, covs);
      handled.set(lbl, {
        status: 'will-create',
        message: `${covs.length ? `${coverageSummary(covs)} ` : ''}${covs.length > 1 ? 'New rules will block it.' : 'A new rule will block it.'}`,
        rules: [...new Map(covs.flatMap((c) => c.blockers).map((r) => [r.id, { id: r.id, name: r.name }])).values()],
      });
    }
    if (conflicts.length) {
      p.warnings.push(
        `${conflicts.map(ruleRef).join(', ')} currently allow${conflicts.length === 1 ? 's' : ''} all of this traffic. ${dialect === 'legacy' ? 'The new rule gets a lower rule index so it is evaluated first.' : 'The new rule will be ordered above it so it takes effect.'} If that allow rule is intentional, cancel and narrow it instead.`,
      );
    }
  }

  // 3. Exempt hosts (your own DNS servers) need an allow rule evaluated before the block.
  if (templateId === 'block-external-dns') {
    const exemptHosts = strs(params.allowedServers).filter((ip) => AddrSet.parse(ip));
    for (const n of pickNetworks(model, params.networks)) {
      const hosts = exemptHosts.filter((ip) => n.addrs.has(ip));
      if (!hosts.length) continue;
      const hostSet = AddrSet.parseList(hosts).set;
      const a = analyzePath(model, n, { kind: 'internet' }, svcOf(partsFor(templateId, params)[0]), ST_NEW, hostSet);
      const allowChain = chainKey(model, intents.find((i) => i.src === n)!);
      // An allow only keeps the server working if it is evaluated before every block that would catch its lookups,
      // including blocks this plan extends; otherwise a new allow is created and ordered first.
      const probe = a?.probe ?? [];
      const firstBlock = Math.min(...model.rules.filter((r) => r.enabled && r.action !== 'allow' && r.chain === allowChain && !spaceIsEmpty(spaceIntersect(r.space, probe))).map((r) => r.order));
      const extendsBefore = (allow: NormRule) => [...pending.values()].some((pe) => pe.rule.action !== 'allow' && pe.rule.chain === allow.chain && pe.rule.order < allow.order);
      const existingAllow = model.rules.find((r) => r.enabled && r.exact && r.action === 'allow' && !r.predefined && r.chain === allowChain && spaceContains(r.space, probe) && r.order < firstBlock && !extendsBefore(r));
      if (existingAllow) {
        analysis.push({ target: `${hosts.join(', ')} (${n.name})`, status: 'exception', message: `Keeps working: ${ruleRef(existingAllow)} lets your DNS server reach its upstream resolvers.`, rules: [{ id: existingAllow.id, name: existingAllow.name }] });
        continue;
      }
      const chain = chainKey(model, intents.find((i) => i.src === n)!);
      if (!chain) continue;
      const [sz, dz] = model.mode === 'zone' ? chain.split('>') : [null, null];
      const id = opId();
      const spec: RuleSpec = {
        name: `${MANAGED_PREFIX} Allow DNS server upstream`,
        description: describe(),
        action: 'ALLOW',
        srcZoneId: sz,
        dstZoneId: dz,
        src: { kind: 'ips', values: hosts },
        dst: { kind: 'any' },
        svc: partsFor(templateId, params)[0],
        states: 'all',
        ipVersion: dialect === 'legacy' ? 'v4' : 'both',
      };
      if (dialect === 'legacy') spec.ruleset = chain;
      const path = rulePath(dialect);
      const body = ruleBody(dialect, spec);
      if (dialect === 'legacy') {
        // Before every rule of yours that blocks these lookups, and every rule this plan changes in the same ruleset.
        const blocking = model.rules.filter((r) => r.enabled && !r.predefined && r.action !== 'allow' && r.chain === chain && !spaceIsEmpty(spaceIntersect(r.space, probe)));
        const changed = [...pending.values()].filter((pe) => pe.rule.action !== 'allow' && pe.rule.chain === chain).map((pe) => pe.rule);
        legacyWants.push({ chain, kind: 'exception', bound: Math.min(...[...blocking, ...changed].map((r) => r.index)), body });
      }
      firstOps.push({
        id,
        kind: 'create',
        objectType: dialect === 'legacy' ? 'firewall-rule' : 'firewall-policy',
        method: 'POST',
        api: path.kind === 'integration' ? 'integration' : 'internal',
        path: ctx.client.fullPath(path.kind, path.sub),
        body,
        description: `Create exception “${spec.name}” for ${hosts.join(', ')}`,
        sentence: `Allow DNS from ${hosts.join(', ')} to the internet (evaluated before the block)`,
      });
      if (sz && dz) needOrdering(sz, dz).first.push(`$created:${id}`);
      analysis.push({ target: `${hosts.join(', ')} (${n.name})`, status: 'exception', message: 'Your own DNS server stays allowed to reach upstream resolvers via a new exception rule placed first.', rules: [] });
    }
  }

  // 4. Assemble: exceptions first, then merged updates of existing rules, new rules, ordering.
  ops.push(...firstOps);
  for (const pe of pending.values()) {
    const r = pe.rule;
    let body = forPut(dialect, r.raw);
    if (pe.part) body = withService(dialect, body, pe.part);
    if (pe.srcIds) body = withSourceNetworks(dialect, body, pe.srcIds);
    if (pe.dstIds) body = withDestinationNetworks(dialect, body, pe.dstIds);
    // A rule this app made that now does another job (DNS-only widened to all traffic) gets that job's name.
    // Your own rules keep their names.
    const netsOf = (ids: string[] | null | undefined) => (ids ?? []).map((id) => model.networks.find((n) => n.id === id || n.raw._legacyId === id)).filter((n): n is NetInfo => !!n);
    const rename = r.managed && pe.part ? ruleTitle(templateId, { chain: r.chain, srcZoneId: null, dstZoneId: null, part: pe.part, srcs: netsOf(pe.srcIds ?? r.srcNetworkIds), dsts: netsOf(pe.dstIds ?? r.dstNetworkIds), dstKind: r.dstNetworkIds ? 'network' : 'internet', covs: [] }) : null;
    if (rename && rename !== r.name) body = { ...body, name: rename };
    const what = [pe.part ? `widen ${r.svcDesc} → ${svcOf(pe.part).describe()}` : '', pe.added.length ? `add ${list([...new Set(pe.added)])}` : '', rename && rename !== r.name ? `rename it “${rename}”` : ''].filter(Boolean).join(' and ');
    const path = rulePath(dialect, r.id);
    const newSvc = pe.part ? svcOf(pe.part).describe() : r.svcDesc;
    const srcNames = (pe.srcIds ?? r.srcNetworkIds ?? []).map((id) => model.networks.find((n) => n.id === id || n.raw._legacyId === id)?.name ?? id);
    ops.push({
      id: opId(),
      kind: 'update',
      objectType: dialect === 'legacy' ? 'firewall-rule' : 'firewall-policy',
      method: 'PUT',
      api: path.kind === 'integration' ? 'integration' : 'internal',
      path: ctx.client.fullPath(path.kind, path.sub),
      body,
      before: forPut(dialect, r.raw),
      targetId: r.id,
      description: `Update your rule ${ruleRef(r)}: ${what}`,
      sentence: `${r.action === 'reject' ? 'Reject' : 'Block'} ${newSvc} from ${srcNames.length ? list(srcNames) : r.srcDesc} to ${pe.dstIds ? list(pe.dstIds.map((id) => model.networks.find((n) => n.id === id || n.raw._legacyId === id)?.name ?? id)) : r.dstDesc}`,
    });
  }
  ops.push(...createOps);
  const unplaceable = dialect === 'legacy' ? assignLegacyIndexes(model, legacyWants) : null;
  if (unplaceable) {
    p.summary = unplaceable;
    p.state = 'unavailable';
    return p;
  }
  for (const need of orderings.values()) {
    if (!need.first.length && !need.before.length) continue;
    if (ctx.testOnly) {
      const pair = userPolicies(ctx, dialect, need.srcZoneId, need.dstZoneId);
      const foreign = [...pair.before, ...pair.after].some((id) => {
        const r = model.rules.find((x) => x.id === id);
        return !r || !canModify(ctx, r);
      });
      if (foreign) {
        p.warnings.push('Test-network mode never reorders your existing rules, so the new rules keep the default position (after your existing rules in this zone pair).');
        continue;
      }
    }
    const op = orderingOp(ctx, dialect, need);
    if (op) ops.push(op);
  }

  // 5. Per-target analysis rows.
  const seen = new Set<string>();
  for (const { i, c } of covs) {
    const label = i.label;
    const h = handled.get(`${i.key}|${i.part.protocol}${i.part.ports}`) ?? handled.get(label);
    const key = `${label}|${h?.status ?? c.state}`;
    if (seen.has(key)) continue;
    seen.add(key);
    if (c.state === 'covered' && !h) {
      const parts = covs.filter((x) => x.i.label === label && x.c.state === 'covered').map((x) => x.c);
      analysis.push({ target: label, status: 'already-covered', message: coverageSummary(parts), rules: [...new Map(parts.flatMap((x) => x.blockers).map((r) => [r.id, { id: r.id, name: r.name }])).values()] });
    } else if (h) {
      analysis.push({ target: label, status: h.status, message: h.message, rules: h.rules });
    } else if (c.state === 'n/a') {
      analysis.push({ target: label, status: 'skipped', message: c.gap, rules: [] });
    }
    for (const ex of c.exceptions) {
      const k = `ex:${ex.id}`;
      if (seen.has(k)) continue;
      seen.add(k);
      analysis.push({ target: label, status: 'exception', message: `Exception kept: ${ruleRef(ex)} allows ${ruleWhat(ex)}. It stays in front of the block.`, rules: [{ id: ex.id, name: ex.name }] });
    }
  }
  // Collapse "already covered" duplicates for multi-part templates.
  p.analysis = analysis.filter((a, idx) => !(a.status === 'already-covered' && analysis.some((b, j) => j !== idx && b.target === a.target && b.status !== 'already-covered' && b.status !== 'exception')));

  p.operations = ops;
  p.noop = ops.length === 0;
  p.strategy = !ops.length ? 'none' : usedExtend && usedCreate ? 'mixed' : usedExtend ? 'extend' : 'create';
  if (extendAvailable || usedExtend) {
    p.alternatives = [
      { strategy: 'extend', label: 'Reuse existing rules', description: 'Extend or widen rules you already have, so no duplicate rules are created (recommended).' },
      { strategy: 'create', label: 'Create a separate rule', description: 'Leave existing rules untouched and add a new managed rule.' },
    ];
  }
  const covered = p.analysis.filter((a) => a.status === 'already-covered').map((a) => a.target);
  const extended = p.analysis.filter((a) => a.status === 'will-extend' || a.status === 'will-update').map((a) => a.target);
  const created = p.analysis.filter((a) => a.status === 'will-create').map((a) => a.target);
  const parts: string[] = [];
  if (covered.length) parts.push(`${list(covered)} ${covered.length === 1 ? 'is' : 'are'} already protected`);
  if (extended.length) parts.push(`${list(extended)} will be handled by updating existing rules`);
  if (created.length) parts.push(`${list(created)} will get a new rule`);
  p.summary = p.noop ? (covered.length ? `Everything selected is already protected (${list(covered)}).` : 'Nothing to change.') : `${parts.join('; ')}.`;
  p.summary = p.summary.charAt(0).toUpperCase() + p.summary.slice(1);
  // The Change Log keeps what happened, in the past tense.
  const done: string[] = [];
  if (covered.length) done.push(`${list(covered)} ${covered.length === 1 ? 'was' : 'were'} already protected`);
  if (extended.length) done.push(`existing rules were updated to cover ${list(extended)}`);
  if (created.length) done.push(`${list(created)} got a new rule`);
  const doneText = `${done.join('; ')}.`;
  if (!p.noop) p.doneSummary = doneText.charAt(0).toUpperCase() + doneText.slice(1);
  return p;
}

function sameSet(a: string[] | null, b: string[]): boolean {
  if (!a) return false;
  const A = new Set(a);
  return A.size === new Set(b).size && b.every((x) => A.has(x));
}

// ---------------------------------------------------------------------------------
// Block an IP (managed blocklist)
// ---------------------------------------------------------------------------------

const BLOCKLIST_NAME = `${MANAGED_PREFIX} Blocklist`;
type BlockDir = 'in' | 'out';
const DIR_WORD: Record<BlockDir, string> = { in: 'inbound', out: 'outbound' };

export function buildBlockIpPlan(ctx: PlannerCtx, params: Record<string, unknown>): ChangePlan {
  const p = plan('block-ip', 'Block an IP address or range', params);
  const dialect = dialectOf(ctx.raw);
  const { model } = ctx;
  const direction = String(params.direction ?? 'both');
  const requested = strs(params.ips);
  // The gateway's own public addresses, as the controller reports them.
  const wanIps = ctx.raw.health.filter((h) => String(h.subsystem ?? '').startsWith('wan')).map((h) => String(h.wan_ip ?? '')).filter((x) => !!AddrSet.parse(x));
  if (!dialect) {
    p.summary = 'The firewall configuration could not be read, so the block cannot be planned safely.';
    p.state = 'unavailable';
    return p;
  }
  if (!requested.length) {
    p.summary = 'Enter at least one IP address or CIDR range.';
    p.state = 'needs-input';
    return p;
  }
  const valid: string[] = [];
  for (const ip of requested) {
    const set = AddrSet.parse(ip);
    if (!set) {
      p.analysis.push({ target: ip, status: 'skipped', message: 'Not a valid IP address or range.', rules: [] });
      continue;
    }
    if (!set.v6.isEmpty()) {
      p.analysis.push({ target: ip, status: 'skipped', message: 'IPv6 blocklisting is not supported yet.', rules: [] });
      continue;
    }
    if (set.v4.size() > 16_777_216n) {
      p.analysis.push({ target: ip, status: 'skipped', message: 'Too broad: more than a /8 would cut off large parts of the internet.', rules: [] });
      continue;
    }
    if (set.overlaps(SPECIAL_V4)) {
      p.analysis.push({ target: ip, status: 'skipped', message: 'A special-purpose address (loopback, link-local, multicast, broadcast or carrier-grade NAT), not an attacker on the internet.', rules: [] });
      continue;
    }
    if (wanIps.some((w) => set.has(w))) {
      p.analysis.push({ target: ip, status: 'skipped', message: 'This is your own public IP address.', rules: [] });
      continue;
    }
    if (model.internal.overlaps(set)) {
      p.analysis.push({ target: ip, status: 'skipped', message: 'This address is inside one of your own networks — use network isolation instead.', rules: [] });
      continue;
    }
    // Never block shared infrastructure without saying so: one IP can front thousands of sites.
    const size = set.v4.size();
    if (size > 256n) p.warnings.push(`${ip} covers ${size.toLocaleString()} addresses. Large ranges often include legitimate services — make sure you mean to block all of them.`);
    const first = ip.split(/[/-]/)[0];
    const owner = ctx.ownerOf?.(first) ?? null;
    if (owner && SHARED_INFRA_RE.test(owner)) {
      p.warnings.push(`${ip} belongs to ${owner}, a large cloud / CDN provider. Many unrelated websites and services can share these addresses, so blocking it may break things you use. Prefer blocking only if the attacks keep coming from it.`);
    }
    valid.push(ip);
  }

  // One managed list per direction: "block inbound" must never also stop your own devices reaching an address, which a
  // shared list would do as soon as it had outbound rules.
  const isIntegration = dialect === 'integration';
  const dirs: BlockDir[] = direction === 'inbound' ? ['in'] : direction === 'outbound' ? ['out'] : ['in', 'out'];
  const lists = dirs.map((d) => {
    const name = `${BLOCKLIST_NAME} (${DIR_WORD[d]})`;
    const found = isIntegration
      ? ctx.raw.iLists.find((l) => l.name === name && l.type === 'IPV4_ADDRESSES')
      : ctx.raw.firewallGroups.find((g) => g.name === name && g.group_type === 'address-group');
    const id = found ? String(isIntegration ? found.id : found._id) : null;
    const members = found ? (isIntegration ? arr<Obj>(found.items).map((it) => (it.type === 'IP_ADDRESS_RANGE' ? `${it.start}-${it.stop}` : String(it.value))) : arr(found.group_members)) : [];
    return { d, name, found, id, members, set: AddrSet.parseList(members).set, add: [] as string[], opId: `LIST-${d.toUpperCase()}` };
  });

  const internalNets = model.networks.filter((n) => n.enabled && !n.addrs.isEmpty());
  const coveredBy = (ip: string, dir: BlockDir): NormRule[] | null => {
    const ipSet = AddrSet.parse(ip)!;
    const blockers = new Map<string, NormRule>();
    for (const n of internalNets) {
      const a =
        dir === 'out'
          ? analyzePath(model, n, { kind: 'addrs', addrs: ipSet, label: ip, zoneKey: 'external' }, ServiceSet.ALL, ST_NEW)
          : analyzeInbound(model, n, ipSet);
      if (!a) return null;
      for (const s of a.result.segments) {
        if (s.verdict !== 'block' || !s.rule || s.rule.predefined) return null;
        blockers.set(s.rule.id, s.rule);
      }
    }
    return [...blockers.values()];
  };

  const toAdd: string[] = [];
  for (const ip of valid) {
    const blockers = new Map<string, NormRule>();
    for (const l of lists) {
      if (l.set.contains(AddrSet.parse(ip)!)) continue;
      const rules = coveredBy(ip, l.d);
      if (rules) for (const r of rules) blockers.set(r.id, r);
      else l.add.push(ip);
    }
    const goesOn = lists.filter((l) => l.add.includes(ip));
    if (!goesOn.length) {
      const rules = [...blockers.values()];
      p.analysis.push({ target: ip, status: 'already-covered', message: rules.length ? `Already blocked by ${rules.map(ruleRef).join(', ')}.` : 'Already on your managed blocklist.', rules: rules.map((r) => ({ id: r.id, name: r.name })) });
      continue;
    }
    toAdd.push(ip);
    const existed = goesOn.every((l) => l.found);
    const where = `managed ${goesOn.map((l) => DIR_WORD[l.d]).join(' and ')} blocklist${goesOn.length > 1 ? 's' : ''}`;
    p.analysis.push({ target: ip, status: existed ? 'will-extend' : 'will-create', message: existed ? `Added to your ${where} — no new rules needed.` : `Goes on a new ${where}; future blocks only add to it.`, rules: [] });
  }

  const zoneOf = (key: string) => model.zones.find((z) => z.key === key);
  const ext = zoneOf('external');
  const ops: PlanOperation[] = [];
  const taken = new Set<number>();
  for (const l of lists) {
    const refsList = (r: NormRule) => l.id !== null && JSON.stringify(r.raw).includes(l.id);
    const existing = model.rules.filter((r) => r.enabled && refsList(r));
    const rulesMissing = !!l.id && existing.length === 0 && l.set.v4.ivs.length > 0;
    if (!l.add.length && !rulesMissing) continue;

    if (l.add.length && l.found) {
      const members = [...l.members, ...l.add];
      if (isIntegration) {
        const { id: _id, metadata: _m, ...rest } = l.found as Obj;
        ops.push({
          id: opId(), kind: 'update', objectType: 'firewall-group', method: 'PUT', api: 'integration',
          path: ctx.client.fullPath('integration', `/traffic-matching-lists/${l.id}`),
          body: { ...rest, items: members.map(listItem) }, before: rest, targetId: l.id!,
          description: `Add ${l.add.join(', ')} to “${l.name}”`,
        });
      } else {
        ops.push({
          id: opId(), kind: 'update', objectType: 'firewall-group', method: 'PUT', api: 'internal',
          path: ctx.client.fullPath('v1', `/rest/firewallgroup/${l.id}`),
          body: { ...l.found, group_members: members }, before: l.found, targetId: l.id!,
          description: `Add ${l.add.join(', ')} to “${l.name}”`,
        });
      }
    } else if (l.add.length) {
      ops.push(
        isIntegration
          ? { id: l.opId, kind: 'create', objectType: 'firewall-group', method: 'POST', api: 'integration', path: ctx.client.fullPath('integration', '/traffic-matching-lists'), body: { name: l.name, type: 'IPV4_ADDRESSES', items: l.add.map(listItem) }, description: `Create address list “${l.name}” with ${l.add.join(', ')}` }
          : { id: l.opId, kind: 'create', objectType: 'firewall-group', method: 'POST', api: 'internal', path: ctx.client.fullPath('v1', '/rest/firewallgroup'), body: { name: l.name, group_type: 'address-group', group_members: l.add }, description: `Create address group “${l.name}” with ${l.add.join(', ')}` },
      );
    }

    // Block rules that use this list, one per zone pair (or legacy ruleset) that is not covered yet.
    const specs: { spec: RuleSpec; label: string }[] = [];
    const zonesWithNets = model.mode === 'zone' ? [...new Set(internalNets.map((n) => n.zoneId).filter(Boolean) as string[])] : [];
    const listEp: EndpointSpec = { kind: 'list', id: l.id ?? `$created:${l.opId}` };
    const has = (pred: (r: NormRule) => boolean) => existing.some(pred);
    if (model.mode === 'zone' && ext) {
      const gw = zoneOf('gateway');
      if (l.d === 'in') {
        for (const zid of [...zonesWithNets, ...(gw ? [gw.id] : [])]) {
          if (has((r) => r.chain === `${ext.id}>${zid}`)) continue;
          specs.push({ spec: { name: l.name, description: describe(), action: 'BLOCK', srcZoneId: ext.id, dstZoneId: zid, src: listEp, dst: { kind: 'any' }, svc: { protocol: 'all', ports: null }, states: 'all', ipVersion: 'v4' }, label: `inbound to ${model.zones.find((z) => z.id === zid)?.name}` });
        }
      } else {
        for (const zid of zonesWithNets) {
          if (has((r) => r.chain === `${zid}>${ext.id}`)) continue;
          specs.push({ spec: { name: l.name, description: describe(), action: 'BLOCK', srcZoneId: zid, dstZoneId: ext.id, src: { kind: 'any' }, dst: listEp, svc: { protocol: 'all', ports: null }, states: 'all', ipVersion: 'v4' }, label: `outbound from ${model.zones.find((z) => z.id === zid)?.name}` });
        }
      }
    } else if (model.mode === 'legacy') {
      const add = (ruleset: string, src: EndpointSpec, dst: EndpointSpec, label: string) => {
        if (has((r) => r.chain === ruleset)) return;
        specs.push({ spec: { name: label === 'to gateway' ? `${l.name} – to gateway` : l.name, description: '', action: 'BLOCK', srcZoneId: null, dstZoneId: null, src, dst, svc: { protocol: 'all', ports: null }, states: 'all', ipVersion: 'v4', ruleset, ruleIndex: legacyIndex(model, ruleset, { first: true, taken }) }, label });
      };
      if (l.d === 'in') {
        add('WAN_IN', listEp, { kind: 'any' }, 'inbound');
        add('WAN_LOCAL', listEp, { kind: 'any' }, 'to gateway');
      } else add('LAN_IN', { kind: 'any' }, listEp, 'outbound');
    }
    for (const { spec, label } of specs) {
      const path = rulePath(dialect);
      ops.push({
        id: opId(), kind: 'create', objectType: dialect === 'legacy' ? 'firewall-rule' : 'firewall-policy', method: 'POST',
        api: path.kind === 'integration' ? 'integration' : 'internal', path: ctx.client.fullPath(path.kind, path.sub), body: ruleBody(dialect, spec),
        description: `Create rule “${spec.name}” (${label})`, dependsOn: l.id ? [] : [l.opId],
        sentence: `Block all traffic ${l.d === 'in' ? 'from' : 'to'} addresses on “${l.name}”`,
      });
    }
    if (specs.length && rulesMissing) p.warnings.push(`“${l.name}” existed but some of its block rules were missing; they will be recreated.`);
  }

  const used = lists.filter((l) => l.add.length);
  const where = `managed ${used.map((l) => DIR_WORD[l.d]).join(' and ')} blocklist${used.length > 1 ? 's' : ''}`;
  const newRules = ops.filter((o) => o.objectType !== 'firewall-group').length;
  p.operations = ops;
  p.noop = ops.length === 0;
  p.strategy = !ops.length ? 'none' : used.every((l) => l.found) ? 'extend' : 'create';
  p.summary = p.noop
    ? valid.length
      ? 'Everything you entered is already blocked.'
      : 'Nothing to change.'
    : !toAdd.length
      ? `Recreate the missing block rules for your managed blocklist.`
      : !newRules
        ? `${list(toAdd)} will be added to your ${where}. Existing rules already use it, so no new rules are needed.`
        : `${list(toAdd)} will be blocked with a ${where} and ${newRules} rule${newRules === 1 ? '' : 's'}. Later blocks only add addresses to the list.`;
  if (!p.noop) p.doneSummary = !toAdd.length ? 'Recreated the missing block rules for your managed blocklist.' : !newRules ? `Added ${list(toAdd)} to your ${where}.` : `Blocked ${list(toAdd)} with a ${where} and ${newRules} rule${newRules === 1 ? '' : 's'}.`;
  return p;
}

function listItem(v: string): Obj {
  if (v.includes('-')) {
    const [start, stop] = v.split('-');
    return { type: 'IP_ADDRESS_RANGE', start, stop };
  }
  return v.includes('/') ? { type: 'SUBNET', value: v } : { type: 'IP_ADDRESS', value: v };
}

/** External → network path for inbound blocking checks (all states, so return traffic counts too). */
function analyzeInbound(model: FwModel, net: NetInfo, src: AddrSet) {
  const ext = model.zones.find((z) => z.key === 'external');
  if (model.mode === 'zone') {
    if (!ext || !net.zoneId) return null;
    const rules = model.rules.filter((r) => r.chain === `${ext.id}>${net.zoneId}`);
    const probe = makeSpace(src, net.addrs, ServiceSet.ALL, ST_ALL);
    return { result: evaluateLite(probe, rules) };
  }
  const rules = model.rules.filter((r) => r.chain === 'WAN_IN');
  return { result: evaluateLite(makeSpace(src, net.addrs, ServiceSet.ALL, ST_ALL), rules) };
}

function evaluateLite(probe: ReturnType<typeof makeSpace>, rules: NormRule[]) {
  return evaluateChains(probe, [{ label: 'inbound', rules, defaultAction: 'block', defaultLabel: 'default' }]);
}

// ---------------------------------------------------------------------------------
// Setting templates
// ---------------------------------------------------------------------------------

export function buildSettingPlan(ctx: PlannerCtx, templateId: string, params: Record<string, unknown>): ChangePlan {
  const t = getTemplate(templateId)!;
  const p = plan(templateId, t.title, params);
  const { raw, client } = ctx;
  const ops: PlanOperation[] = [];
  // Only the changed fields and their previous values are kept: settings documents also hold secrets (device SSH
  // password, adoption key, service tokens) that must never end up in a plan or the Change Log. The executor merges
  // the change into a freshly read document when it applies or undoes it.
  const settingOp = (key: string, changes: Obj, description: string) => {
    const s = raw.settings[key];
    if (!s) return null;
    const before = Object.fromEntries(Object.keys(changes).map((k) => [k, s[k] ?? null]));
    ops.push({ id: opId(), kind: 'update', objectType: 'setting', method: 'PUT', api: 'internal', path: client.fullPath('v1', `/rest/setting/${key}/${s._id}`), body: changes, before, targetId: String(s._id), description });
    return s;
  };

  if (templateId === 'ips-mode') {
    const s = raw.settings.ips;
    // This action only ever turns protection up: "ids" (detect) or "ips" (block), never off.
    const want = params.mode === 'ids' ? 'ids' : 'ips';
    if (!s) {
      p.summary = 'IPS settings could not be read from the controller (they are only available through the internal API).';
      p.state = 'unavailable';
      return p;
    }
    const cur = String(s.ips_mode ?? 'disabled');
    const label = (m: string) => (m === 'ips' || m === 'ipsInline' ? 'Notify and Block' : m === 'ids' ? 'Notify' : 'Off');
    if (cur === want || (want === 'ips' && cur === 'ipsInline')) {
      p.analysis.push({ target: 'Intrusion Prevention', status: 'already-covered', message: `Already set to ${label(cur)}.`, rules: [] });
      p.summary = `Intrusion Prevention is already in ${label(cur)} mode.`;
      return p;
    }
    settingOp('ips', { ips_mode: want }, `Change IPS mode from ${label(cur)} to ${label(want)}`);
    p.analysis.push({ target: 'Intrusion Prevention', status: 'will-update', message: `Currently ${label(cur)} — ${cur === 'ids' ? 'threats are detected but allowed through' : 'threat detection is off'}.`, rules: [] });
    const gap = ipsCoverage(s).missing;
    if (gap.length) {
      p.warnings.push(`${gap.length} recommended detection${gap.length === 1 ? ' is' : 's are'} off (${gap.map((m) => m.name).join(', ')}). Switch them on under UniFi → Settings → CyberSecure → Protection → Intrusion Prevention → Active Detections.`);
    }
    p.summary = `Switch Intrusion Prevention to ${label(want)}.`;
    p.doneSummary = `Switched Intrusion Prevention to ${label(want)}.`;
  } else if (templateId === 'disable-upnp') {
    const s = raw.settings.usg;
    if (!s) {
      p.summary = 'Gateway settings could not be read from the controller.';
      p.state = 'unavailable';
      return p;
    }
    if (s.upnp_enabled !== true) {
      p.analysis.push({ target: 'UPnP', status: 'already-covered', message: 'UPnP is already disabled.', rules: [] });
      p.summary = 'UPnP is already disabled.';
      return p;
    }
    settingOp('usg', { upnp_enabled: false, upnp_nat_pmp_enabled: false }, 'Disable UPnP and NAT-PMP');
    p.analysis.push({ target: 'UPnP', status: 'will-update', message: 'UPnP is enabled: any device can open ports on your firewall.', rules: [] });
    p.summary = 'Disable UPnP so only port forwards you create are exposed.';
    p.doneSummary = 'Disabled UPnP, so only port forwards you create are exposed.';
  } else if (templateId === 'guest-wifi-isolation') {
    const guestNetIds = new Set(ctx.model.networks.filter((n) => n.role === 'guest').flatMap((n) => [n.id, String(n.raw._legacyId ?? '')]));
    const guests = raw.wlans.filter((w) => w.enabled !== false && (w.is_guest === true || guestNetIds.has(String(w.networkconf_id))));
    if (!guests.length) {
      p.summary = 'No guest Wi-Fi networks were found.';
      p.state = 'unavailable';
      return p;
    }
    for (const w of guests) {
      if (w.l2_isolation === true) {
        p.analysis.push({ target: String(w.name), status: 'already-covered', message: 'Client isolation is already on.', rules: [] });
        continue;
      }
      ops.push({ id: opId(), kind: 'update', objectType: 'wlan', method: 'PUT', api: 'internal', path: client.fullPath('v1', `/rest/wlanconf/${w._id}`), body: { l2_isolation: true }, before: { l2_isolation: false }, targetId: String(w._id), description: `Enable client isolation on “${w.name}”` });
      p.analysis.push({ target: String(w.name), status: 'will-update', message: 'Guests can currently see and attack each other on this Wi-Fi.', rules: [] });
    }
    p.summary = ops.length ? `Enable client isolation on ${ops.length} guest Wi-Fi network${ops.length === 1 ? '' : 's'}.` : 'All guest Wi-Fi networks already isolate clients.';
    if (ops.length) p.doneSummary = `Enabled client isolation on ${ops.length} guest Wi-Fi network${ops.length === 1 ? '' : 's'}.`;
  } else if (templateId === 'port-forward') {
    const pf = raw.portForwards.find((x) => String(x._id) === String(params.portForwardId));
    if (!pf) {
      p.summary = 'Port forward not found.';
      p.state = 'unavailable';
      return p;
    }
    const mode = String(params.mode ?? 'disable');
    const label = `“${pf.name}” (port ${pf.dst_port} → ${pf.fwd}:${pf.fwd_port})`;
    if (mode === 'disable') {
      if (pf.enabled === false) {
        p.analysis.push({ target: String(pf.name), status: 'already-covered', message: 'This port forward is already disabled.', rules: [] });
        p.summary = 'Already disabled.';
        return p;
      }
      ops.push({ id: opId(), kind: 'update', objectType: 'port-forward', method: 'PUT', api: 'internal', path: client.fullPath('v1', `/rest/portforward/${pf._id}`), body: { ...pf, enabled: false }, before: pf, targetId: String(pf._id), description: `Disable port forward ${label}` });
      p.summary = `Disable port forward ${label}.`;
      p.doneSummary = `Disabled port forward ${label}.`;
    } else {
      const src = String(params.source ?? '').trim();
      const allowed = AddrSet.parse(src);
      if (!allowed) {
        p.summary = 'Enter the IP address or CIDR range that should be allowed to use this port forward.';
        p.state = 'needs-input';
        return p;
      }
      // A "restriction" to (most of) the internet would only look like a fix.
      if (allowed.v4.size() > 16_777_216n || !allowed.v6.isEmpty()) {
        p.summary = 'Enter a specific IPv4 address or a small range (a /8 or smaller). 0.0.0.0/0 would still be the whole internet.';
        p.state = 'needs-input';
        return p;
      }
      if (pf.src_limiting_enabled === true && String(pf.src ?? '') === src && pf.enabled !== false) {
        p.analysis.push({ target: String(pf.name), status: 'already-covered', message: `Already limited to ${src}.`, rules: [] });
        p.summary = 'Already restricted.';
        return p;
      }
      ops.push({
        id: opId(), kind: 'update', objectType: 'port-forward', method: 'PUT', api: 'internal', path: client.fullPath('v1', `/rest/portforward/${pf._id}`),
        body: { ...pf, src, src_limiting_enabled: true, src_limiting_type: 'ip' }, before: pf, targetId: String(pf._id), description: `Only allow ${src} to use port forward ${label}`,
      });
      p.summary = `Restrict port forward ${label} to ${src}.`;
      p.doneSummary = `Restricted port forward ${label} to ${src}.`;
    }
    p.analysis.push({ target: String(pf.name), status: 'will-update', message: 'Currently reachable from the entire internet.', rules: [] });
  }
  p.operations = ops;
  p.noop = !ops.length;
  p.strategy = ops.length ? 'update' : 'none';
  return p;
}

// ---------------------------------------------------------------------------------
// Remove a rule with no effect
// ---------------------------------------------------------------------------------

export function buildRemoveRulePlan(ctx: PlannerCtx, params: Record<string, unknown>): ChangePlan {
  const p = plan('remove-rule', 'Remove a rule that has no effect', params);
  const dialect = dialectOf(ctx.raw);
  const r = ctx.model.rules.find((x) => x.id === String(params.ruleId));
  if (!dialect || !r) {
    p.summary = 'Rule not found.';
    p.state = 'unavailable';
    return p;
  }
  const origin = String((r.raw.metadata as Obj | undefined)?.origin ?? '');
  if (r.predefined || r.id.startsWith('synthetic:') || origin === 'DERIVED' || origin === 'SYSTEM_DEFINED') {
    p.summary = `${ruleRef(r)} is a built-in or derived rule and cannot be removed here.`;
    p.state = 'unavailable';
    return p;
  }
  const issue = analyzeHygiene(ctx.model).find((h) => h.ruleIds[0] === r.id && (h.kind === 'duplicate' || h.kind === 'redundant' || h.kind === 'disabled'));
  if (!issue) {
    p.summary = `${ruleRef(r)} affects your traffic, so it is not offered for automatic removal.`;
    p.state = 'unavailable';
    return p;
  }
  const path = rulePath(dialect, r.id);
  // What undo needs to POST to recreate the rule (server-assigned fields removed).
  const readOnly = ['_id', 'index', 'predefined', 'origin_type', 'origin_id', 'site_id', 'hits', 'last_hit'];
  const recreate = dialect === 'integration' ? forPut(dialect, r.raw) : Object.fromEntries(Object.entries(r.raw).filter(([k]) => !readOnly.includes(k)));
  p.operations = [
    {
      id: opId(),
      kind: 'delete',
      objectType: dialect === 'legacy' ? 'firewall-rule' : 'firewall-policy',
      method: 'DELETE',
      api: path.kind === 'integration' ? 'integration' : 'internal',
      path: ctx.client.fullPath(path.kind, path.sub),
      before: recreate,
      targetId: r.id,
      description: `Delete rule ${ruleRef(r)}`,
      sentence: ruleSentence(r),
    },
  ];
  p.analysis = [{ target: r.name, status: 'will-update', message: issue.detail, rules: issue.ruleIds.slice(1).map((id, i) => ({ id, name: issue.ruleNames[i + 1] })) }];
  p.summary = issue.kind === 'disabled' ? `${ruleRef(r)} is disabled and does nothing.` : `Removing ${ruleRef(r)} changes nothing — ${issue.kind === 'duplicate' ? 'an identical rule already does the same job' : 'earlier rules already handle all of its traffic'}.`;
  p.doneSummary = `Removed ${ruleRef(r)}${issue.kind === 'disabled' ? ', which was disabled and did nothing' : issue.kind === 'duplicate' ? ', which duplicated another rule' : ', whose traffic earlier rules already handled'}.`;
  p.noop = false;
  p.strategy = 'update';
  return p;
}

// ---------------------------------------------------------------------------------
// Test network (a dummy VLAN to try hardening on a live controller safely)
// ---------------------------------------------------------------------------------

const TEST_SUBNETS = ['10.254.254.0/24', '10.253.253.0/24', '172.31.254.0/24', '192.168.254.0/24', '10.252.252.0/24'];

export function buildCreateTestNetworkPlan(ctx: PlannerCtx, params: Record<string, unknown>): ChangePlan {
  const p = plan('create-test-network', 'Create a test network', params);
  const { model, raw, client } = ctx;
  const existing = model.networks.find((n) => n.isTest);
  if (existing) {
    p.analysis.push({ target: existing.name, status: 'already-covered', message: `Already exists: ${existing.subnet ?? 'no subnet'}${existing.vlan !== null ? `, VLAN ${existing.vlan}` : ''}.`, rules: [] });
    p.summary = `Your test network “${existing.name}” already exists — select it in any hardening action.`;
    return p;
  }
  const usedVlans = new Set<number>([...model.networks.map((n) => n.vlan ?? 1), ...raw.networkconf.map((n) => Number(n.vlan ?? 1))]);
  const vlan = Array.from({ length: 100 }, (_, i) => 3999 - i).find((v) => !usedVlans.has(v));
  // Own subnets plus the remote side of site-to-site VPNs, so the test network never shadows a remote site.
  const taken = raw.networkconf
    .flatMap((n) => [n.ip_subnet, ...(Array.isArray(n.remote_vpn_subnets) ? n.remote_vpn_subnets : [])])
    .reduce((acc: AddrSet, s) => (typeof s === 'string' ? acc.union(AddrSet.parse(s) ?? AddrSet.EMPTY) : acc), model.internal);
  const subnet = TEST_SUBNETS.find((s) => !AddrSet.parse(s)!.overlaps(taken));
  if (!vlan || !subnet) {
    p.summary = 'Could not find a free VLAN id and subnet for the test network.';
    p.state = 'unavailable';
    return p;
  }
  const base = subnet.replace(/\.0\/24$/, '');
  const name = TEST_NETWORK_PREFIX;
  const zoneBased = model.mode === 'zone';
  if (raw.firewallSource === 'integration' || raw.iNetworks.length) {
    // On zone-based sites every network must be created inside a zone (Network 10.6 rejects a missing zoneId), so the
    // empty zone comes first. Undo runs in reverse: network, then zone.
    const ownZone = zoneBased && raw.firewallSource === 'integration';
    if (ownZone) {
      p.operations.push({
        id: 'ZONE',
        kind: 'create',
        objectType: 'network',
        method: 'POST',
        api: 'integration',
        path: client.fullPath('integration', '/firewall/zones'),
        body: { name, networkIds: [] },
        description: `Create firewall zone “${name}” for the test network only`,
      });
    }
    p.operations.push({
      id: 'NET',
      kind: 'create',
      objectType: 'network',
      method: 'POST',
      api: 'integration',
      path: client.fullPath('integration', '/networks'),
      ...(ownZone ? { dependsOn: ['ZONE'] } : {}),
      body: {
        management: 'GATEWAY',
        name,
        enabled: true,
        vlanId: vlan,
        ...(ownZone ? { zoneId: '$created:ZONE' } : {}),
        cellularBackupEnabled: false,
        internetAccessEnabled: true,
        isolationEnabled: false,
        mdnsForwardingEnabled: false,
        ipv4Configuration: {
          autoScaleEnabled: false,
          hostIpAddress: `${base}.1`,
          prefixLength: 24,
          // Same shape as the console's own networks; Network 10.6 rejects the request if any field is missing.
          dhcpConfiguration: { mode: 'SERVER', ipAddressRange: { start: `${base}.100`, stop: `${base}.200` }, leaseTimeSeconds: 86400, domainName: '', pingConflictDetectionEnabled: true },
        },
      },
      description: `Create network “${name}” (VLAN ${vlan}, ${subnet})${ownZone ? ` in zone “${name}”` : ''}`,
    });
  } else if (client.info.internal) {
    p.operations.push({
      id: 'NET',
      kind: 'create',
      objectType: 'network',
      method: 'POST',
      api: 'internal',
      path: client.fullPath('v1', '/rest/networkconf'),
      body: { name, purpose: 'corporate', networkgroup: 'LAN', enabled: true, vlan_enabled: true, vlan, ip_subnet: `${base}.1/24`, dhcpd_enabled: true, dhcpd_start: `${base}.100`, dhcpd_stop: `${base}.200`, internet_access_enabled: true },
      description: `Create network “${name}” (VLAN ${vlan}, ${subnet})`,
    });
  } else {
    p.summary = 'Networks cannot be created through the APIs this controller exposes.';
    p.state = 'unavailable';
    return p;
  }
  p.analysis.push({
    target: name,
    status: 'will-create',
    message: `VLAN ${vlan}, subnet ${subnet}, DHCP ${base}.100–200. No Wi-Fi is attached and no switch port uses it, so no device can join it unless you put one there.${zoneBased && raw.firewallSource === 'integration' ? ' It gets its own firewall zone, so rules created for it never share a zone pair with your existing rules.' : ''}`,
    rules: [],
  });
  p.summary = `Create an empty “${name}” network to try hardening actions on, without touching your real networks. Remove it from the Change Log when you are done.`;
  p.doneSummary = `Created the empty “${name}” network for trying hardening actions. Remove it from the Change Log when you are done.`;
  p.noop = false;
  p.strategy = 'create';
  return p;
}

// ---------------------------------------------------------------------------------
// Block countries (inbound)
// ---------------------------------------------------------------------------------

/** Enabled block rules from the internet that match by country and cover all traffic into their zone. */
function countryBlocks(model: FwModel, externalZoneId: string): NormRule[] {
  return model.rules.filter((r) => r.system === 'zone' && r.enabled && r.action !== 'allow' && r.srcZoneId === externalZoneId && (r.srcRegions?.length ?? 0) > 0 && r.dstAny && spaceSvc(r.space).isAll());
}

/** UniFi's own Region Blocking (Settings → Security), kept in the usg_geo site setting. */
export interface RegionBlocking {
  enabled: boolean;
  /** "block" drops the listed countries; "allow" lets through only the listed countries. */
  action: 'block' | 'allow';
  /** "ingress" (UniFi's "Incoming"), "egress" (outgoing) or "both". */
  direction: string;
  countries: string[];
}

/** Region Blocking as configured, or null when the console doesn't have it or it couldn't be read. */
export function regionBlocking(raw: RawSnapshot): RegionBlocking | null {
  const f = raw.settings.usg_geo?.ip_filtering;
  if (!f || typeof f !== 'object' || Array.isArray(f)) return null;
  const o = f as Record<string, unknown>;
  // Network 10 keeps the list as text ("RU,KP,CN"); accept an array too.
  const list = Array.isArray(o.countries) ? o.countries.map(String) : typeof o.countries === 'string' ? o.countries.split(',') : [];
  return {
    enabled: o.enabled === true,
    action: o.action === 'allow' ? 'allow' : 'block',
    direction: String(o.traffic_direction ?? 'both'),
    countries: [...new Set(list.map((c) => c.trim().toUpperCase()).filter((c) => /^[A-Z]{2}$/.test(c)))],
  };
}

/** Whether Region Blocking filters connections coming in from the internet. */
const filtersInbound = (g: RegionBlocking) => g.enabled && (g.direction === 'ingress' || g.direction === 'both') && (g.action === 'allow' || g.countries.length > 0);

/** Region Blocking in words, e.g. "blocks incoming connections from 2 countries (RU, KP)". */
export function regionText(g: RegionBlocking): string {
  if (!g.enabled) return 'is off';
  const n = g.countries.length;
  const what = !n ? 'no countries' : g.action === 'block' ? `${n} ${n === 1 ? 'country' : 'countries'} (${g.countries.join(', ')})` : g.countries.join(', ');
  if (g.action === 'allow') return g.direction === 'ingress' ? `only lets in connections from ${what}` : g.direction === 'egress' ? `only lets your devices reach ${what}` : `only allows connections to and from ${what}`;
  return g.direction === 'ingress' ? `blocks incoming connections from ${what}` : g.direction === 'egress' ? `blocks outgoing connections to ${what}` : `blocks connections to and from ${what}`;
}

const COUNTRY_ALTERNATIVES = [
  { strategy: 'update', label: 'UniFi Region Blocking', description: 'Add the countries to Region Blocking (UniFi → Settings → Security): one list that filters connections for your whole network (recommended).' },
  { strategy: 'create', label: 'Firewall rules per zone', description: 'Leave Region Blocking as it is and add a block rule for each zone you pick under advanced options.' },
];

/** Block countries with UniFi's Region Blocking: add them to its list, or turn it on for incoming connections. */
function regionBlockingPlan(ctx: PlannerCtx, p: ChangePlan, geo: RegionBlocking, codes: string[]): void {
  const s = ctx.raw.settings.usg_geo;
  const target = 'Region Blocking';
  const listed = new Set(geo.countries);
  const inbound = geo.direction === 'ingress' || geo.direction === 'both';
  const are = (xs: string[]) => `${xs.join(', ')} ${xs.length === 1 ? 'is' : 'are'}`;
  const covered = (message: string) => {
    p.analysis.push({ target, status: 'already-covered', message, rules: [] });
    p.summary = `UniFi's Region Blocking already blocks ${codes.join(', ')}.`;
  };
  if (geo.enabled && geo.action === 'allow') {
    // An allow list: every country that isn't on it is already blocked.
    const onList = codes.filter((c) => listed.has(c));
    if (inbound && !onList.length) return covered(`Region Blocking only lets in connections from ${geo.countries.join(', ') || 'no countries'}, so ${are(codes)} already blocked.`);
    p.state = 'unavailable';
    p.summary = inbound
      ? `Region Blocking is set to allow only the countries on its list, and ${are(onList)} on it. Take ${onList.length === 1 ? 'it' : 'them'} off that list in UniFi (Settings → Security → Region Blocking), or use firewall rules per zone.`
      : 'Region Blocking is set to allow only the countries on its list, for outgoing connections. Making it filter incoming connections too would block every other country from reaching you, so use firewall rules per zone instead.';
    return;
  }
  const missing = codes.filter((c) => !listed.has(c));
  if (geo.enabled && inbound && !missing.length) return covered(`Region Blocking already ${regionText(geo)}.`);
  const cur = s.ip_filtering as Record<string, unknown>;
  const update = (next: Record<string, unknown>, description: string) =>
    p.operations.push({
      id: opId(), kind: 'update', objectType: 'setting', method: 'PUT', api: 'internal', path: ctx.client.fullPath('v1', `/rest/setting/usg_geo/${s._id}`),
      body: { ip_filtering: { ...cur, ...next } }, before: { ip_filtering: cur }, targetId: String(s._id), description,
    });
  if (!geo.enabled) {
    // Off: turn it on for incoming connections, with just the countries picked here.
    update({ enabled: true, action: 'block', traffic_direction: 'ingress', countries: codes.join(',') }, `Turn on Region Blocking for incoming connections from ${codes.join(', ')}`);
    const old = geo.countries.filter((c) => !codes.includes(c));
    p.analysis.push({
      target,
      status: 'will-update',
      message: `Region Blocking is off. It will be turned on for incoming connections from ${codes.join(', ')}.${old.length ? ` This replaces its saved list (${geo.countries.join(', ')}); undo brings that back.` : ''}`,
      rules: [],
    });
    p.summary = `Turn on UniFi's Region Blocking for incoming connections from ${codes.join(', ')}.`;
    p.doneSummary = `Turned on UniFi's Region Blocking for incoming connections from ${codes.join(', ')}.`;
  } else {
    // Block list: add the missing countries after yours, and make sure incoming connections are filtered too.
    const direction = inbound ? geo.direction : 'both';
    update({ countries: [...geo.countries, ...missing].join(','), traffic_direction: direction }, missing.length ? `Add ${missing.join(', ')} to Region Blocking` : 'Make Region Blocking filter incoming connections too');
    const both = direction === 'both' && missing.length ? ` UniFi uses one list for both directions, so your devices won't reach ${missing.join(', ')} either.` : '';
    p.analysis.push({
      target,
      status: 'will-update',
      message: inbound
        ? `Region Blocking ${regionText(geo)}; ${missing.join(', ')} will be added to its list.${both}`
        : `Region Blocking only filters outgoing connections now. It will filter incoming ones too${missing.length ? `, with ${missing.join(', ')} added to its list` : ''}.${both}`,
      rules: [],
    });
    const what = missing.length ? `add ${missing.join(', ')} to UniFi's Region Blocking` : "make UniFi's Region Blocking filter incoming connections";
    p.summary = `${what.charAt(0).toUpperCase()}${what.slice(1)}.`;
    p.doneSummary = missing.length ? `Added ${missing.join(', ')} to UniFi's Region Blocking.` : "Made UniFi's Region Blocking filter incoming connections too.";
  }
  p.noop = false;
  p.strategy = 'update';
}

/** Zones the internet can reach: targets of enabled port forwards, and the gateway when it runs a VPN server. */
export function exposedZones(model: FwModel, raw: RawSnapshot): ZoneInfo[] {
  const ids = new Set<string>();
  for (const pf of raw.portForwards) {
    if (pf.enabled === false) continue;
    const net = model.networks.find((n) => n.addrs.has(String(pf.fwd ?? '')));
    if (net?.zoneId) ids.add(net.zoneId);
  }
  if (raw.networkconf.some((n) => n.purpose === 'remote-user-vpn' || n.purpose === 'site-vpn')) {
    const gw = model.zones.find((z) => z.key === 'gateway');
    if (gw) ids.add(gw.id);
  }
  return model.zones.filter((z) => ids.has(z.id));
}

export function buildBlockCountriesPlan(ctx: PlannerCtx, params: Record<string, unknown>, strategyPref?: string): ChangePlan {
  const p = plan('block-countries', getTemplate('block-countries')!.title, params);
  const { model, raw, client } = ctx;
  const geo = regionBlocking(raw);
  const ext = model.zones.find((z) => z.key === 'external');
  const rulesOk = raw.firewallSource === 'integration' && !!ext;
  if (!geo && !rulesOk) {
    p.summary = 'Country blocking needs UniFi Region Blocking, or the zone-based firewall through the official UniFi API (Network 10.1 or newer).';
    p.state = 'unavailable';
    return p;
  }
  const codes = [...new Set(strs(params.countries).map((c) => c.toUpperCase()).filter((c) => /^[A-Z]{2}$/.test(c)))].sort();
  if (!codes.length) {
    p.summary = 'Pick at least one country to block.';
    p.state = 'needs-input';
    return p;
  }
  // UniFi's own Region Blocking filters every connection from the internet with one list, so it comes first;
  // per-zone rules remain for consoles without it, or for anyone who picks them instead.
  if (geo && (strategyPref !== 'create' || !rulesOk)) {
    regionBlockingPlan(ctx, p, geo, codes);
    if (rulesOk && (!p.noop || p.state === 'unavailable')) p.alternatives = COUNTRY_ALTERNATIVES;
    return p;
  }
  if (geo) p.alternatives = COUNTRY_ALTERNATIVES;
  const zoneIds = new Set(strs(params.zones));
  const zones = model.zones.filter((z) => zoneIds.has(z.id) && z.id !== ext!.id);
  if (!zones.length) {
    p.summary = 'Pick at least one zone to protect (under advanced options).';
    p.state = 'needs-input';
    return p;
  }
  const dup = geo && filtersInbound(geo) ? codes.filter((c) => geo.action === 'allow' ? !geo.countries.includes(c) : geo.countries.includes(c)) : [];
  if (dup.length) p.warnings.push(`UniFi's Region Blocking already blocks ${dup.join(', ')} for your whole network, so rules for ${dup.length === 1 ? 'it' : 'them'} only duplicate it.`);
  const existing = countryBlocks(model, ext!.id);
  const ref = (r: NormRule) => ({ id: r.id, name: r.name });
  for (const z of zones) {
    const label = `Internet → ${z.name}`;
    const here = existing.filter((r) => r.dstZoneId === z.id);
    const covered = new Set(here.flatMap((r) => r.srcRegions ?? []));
    const missing = codes.filter((c) => !covered.has(c));
    if (!missing.length) {
      p.analysis.push({ target: label, status: 'already-covered', message: `Already blocked by ${here.map(ruleRef).join(', ')}.`, rules: here.map(ref) });
      continue;
    }
    // Grow this console's own country rule for the zone instead of adding another one.
    const mine = here.find((r) => r.managed);
    if (mine) {
      const before = forPut('integration', mine.raw);
      const regions = [...new Set([...(mine.srcRegions ?? []), ...missing])].sort();
      p.operations.push({
        id: opId(), kind: 'update', objectType: 'firewall-policy', method: 'PUT', api: 'integration', path: client.fullPath('integration', `/firewall/policies/${mine.id}`),
        body: withRegions(before, regions), before, targetId: mine.id, description: `Add ${missing.join(', ')} to your rule ${ruleRef(mine)}`,
      });
      p.analysis.push({ target: label, status: 'will-update', message: `${ruleRef(mine)} will also block ${missing.join(', ')} instead of adding another rule.`, rules: [ref(mine)] });
      continue;
    }
    const spec: RuleSpec = {
      name: `${MANAGED_PREFIX} Block countries → ${z.name}`, description: describe(), action: 'BLOCK', srcZoneId: ext!.id, dstZoneId: z.id,
      src: { kind: 'regions', codes: missing }, dst: { kind: 'any' }, svc: { protocol: 'all', ports: null }, states: 'new', ipVersion: 'both',
    };
    p.operations.push({
      id: opId(), kind: 'create', objectType: 'firewall-policy', method: 'POST', api: 'integration', path: client.fullPath('integration', '/firewall/policies'),
      body: ruleBody('integration', spec), description: `Create rule “${spec.name}”`, sentence: `Block new connections from ${missing.join(', ')} to ${z.name}`,
    });
    p.analysis.push({
      target: label,
      status: 'will-create',
      message: covered.size ? `${[...covered].sort().join(', ')} already blocked by ${here.map(ruleRef).join(', ')}; a new rule adds ${missing.join(', ')}.` : 'Nothing blocks these countries yet; a new rule will.',
      rules: here.map(ref),
    });
  }
  p.noop = !p.operations.length;
  p.strategy = p.operations.some((o) => o.kind === 'create') ? 'create' : p.operations.length ? 'update' : 'none';
  p.summary = p.noop ? `Every selected zone already blocks ${codes.join(', ')}.` : `Block new connections from ${codes.join(', ')} to ${zones.map((z) => z.name).join(', ')}.`;
  if (!p.noop) p.doneSummary = `Blocked new connections from ${codes.join(', ')} to ${zones.map((z) => z.name).join(', ')}.`;
  return p;
}

/** Test-network write mode: decide whether a plan stays inside the test network. */
function applyTestGuard(ctx: PlannerCtx, templateId: string, params: Record<string, unknown>, p: ChangePlan): void {
  if (!ctx.testOnly || templateId === 'create-test-network') return;
  const t = getTemplate(templateId)!;
  if (t.kind === 'setting' || templateId === 'block-ip') {
    p.blockedReason = 'Test-network mode only allows changes scoped to your test network. This action changes site-wide settings or rules that apply to every network.';
    return;
  }
  if (templateId === 'remove-rule') {
    const r = ctx.model.rules.find((x) => x.id === String(params.ruleId));
    if (!r || !canModify(ctx, r)) p.blockedReason = 'Test-network mode only removes rules this console created for your test network.';
    return;
  }
  if (templateId === 'block-countries') {
    if (p.operations.some((o) => o.objectType === 'setting')) {
      p.blockedReason = 'Test-network mode: Region Blocking is one setting for your whole network, so changing it needs Full access (Settings). To try country blocking on your test network, choose “Firewall rules per zone” and pick its zone under advanced options.';
      return;
    }
    // Country rules only affect the zones they point at; in test mode that may only be the test network's own zone.
    const testOnly = (zoneId: string) => {
      const members = ctx.model.networks.filter((n) => n.zoneId === zoneId);
      return members.length > 0 && members.every((n) => n.isTest);
    };
    const wanted = new Set(strs(params.zones));
    const bad = ctx.model.zones.filter((z) => wanted.has(z.id) && !testOnly(z.id));
    if (bad.length) p.blockedReason = `Test-network mode: country rules may only protect your test network's own zone, so they can never affect your real networks. Deselect ${bad.map((z) => z.name).join(', ')}.`;
    return;
  }
  const srcIds = arr(templateId === 'isolate-networks' ? params.sources : params.networks);
  const offending = ctx.model.networks.filter((n) => srcIds.includes(n.id) && !n.isTest);
  if (offending.length) {
    p.blockedReason = `Test-network mode: new rules may only start from a test network (named “${TEST_NETWORK_PREFIX}…”), so they can never match traffic from your real networks. Deselect ${names(offending, 4)}${ctx.model.networks.some((n) => n.isTest) ? '' : ' and create a test network first'}.`;
  }
  // Rule updates were already restricted to managed test-network rules; anything else is out of bounds.
  if (p.operations.some((o) => o.kind !== 'create' && o.objectType !== 'firewall-policy' && o.objectType !== 'firewall-rule')) p.blockedReason ??= 'This plan would modify existing objects outside the test network.';
}

export function buildPlan(ctx: PlannerCtx, templateId: string, params: Record<string, unknown>, strategy?: string): ChangePlan {
  const t = getTemplate(templateId);
  if (!t) throw new Error(`Unknown template ${templateId}`);
  let p: ChangePlan;
  if (templateId === 'block-ip') p = buildBlockIpPlan(ctx, params);
  else if (templateId === 'block-countries') p = buildBlockCountriesPlan(ctx, params, strategy);
  else if (templateId === 'remove-rule') p = buildRemoveRulePlan(ctx, params);
  else if (templateId === 'create-test-network') p = buildCreateTestNetworkPlan(ctx, params);
  else if (t.kind === 'setting') p = buildSettingPlan(ctx, templateId, params);
  else p = buildFirewallPlan(ctx, templateId, params, strategy);
  applyLogging(p, params);
  applyTestGuard(ctx, templateId, params, p);
  attachRuleDetails(ctx.model, ctx.raw, p);
  return p;
}

/** "Log matches": every firewall rule the plan creates or changes logs the connections it matches. */
function applyLogging(p: ChangePlan, params: Record<string, unknown>): void {
  if (params.log !== true) return;
  // Ordering steps are firewall-policy updates too, but their bodies are rule lists, not rules.
  const rules = p.operations.filter(
    (o) =>
      (o.kind === 'create' || o.kind === 'update') &&
      (o.objectType === 'firewall-policy' || o.objectType === 'firewall-rule') &&
      !o.path.includes('/ordering') &&
      !o.path.includes('batch-reorder') &&
      !!o.body &&
      typeof o.body === 'object' &&
      !Array.isArray(o.body),
  );
  for (const o of rules) o.body = { ...(o.body as Record<string, unknown>), ...(o.api === 'integration' ? { loggingEnabled: true } : { logging: true }) };
  if (!p.noop && !rules.length) p.warnings.push('“Log matches” only applies to rules this change creates or changes, and it changes none: existing rules keep their own logging setting.');
}

// ---------------------------------------------------------------------------------
// Template status cards
// ---------------------------------------------------------------------------------

export function detectDnsServers(model: FwModel): string[] {
  const servers = new Set<string>();
  for (const n of model.networks) for (const d of n.dhcpDns) if (model.internal.has(d) && !model.gatewayAddrs.has(d)) servers.add(d);
  return [...servers];
}

export function assessTemplates(ctx: PlannerCtx): TemplateStatus[] {
  const { model, raw } = ctx;
  const nets = model.networks.filter((n) => n.enabled && !n.addrs.isEmpty());
  const out: TemplateStatus[] = [];
  const canAnalyse = model.mode !== 'unknown';
  const testIds = new Set(model.networks.filter((n) => n.isTest).map((n) => n.id));
  // A target is a network id, or "source>destination" for isolation pairs.
  const isTestTarget = (id: string) => id.split('>').some((x) => testIds.has(x));

  const fwStatus = (templateId: string, targets: { id: string; name: string; intents: TargetIntent[] }[], suggested: Record<string, unknown>, emptyDetail: string): TemplateStatus => {
    if (!canAnalyse) return { templateId, state: 'unknown', label: 'Unknown', detail: 'Firewall configuration unavailable.', targets: [], suggestedParams: suggested };
    if (!targets.length) return { templateId, state: 'not-applicable', label: 'Not applicable', detail: emptyDetail, targets: [], suggestedParams: suggested };
    const rows: TemplateTarget[] = targets.map((tg) => {
      const covs = tg.intents.map((i) => assessIntent(model, i));
      const state = covs.every((c) => c.state === 'covered') ? 'covered' : covs.some((c) => c.state === 'covered' || c.state === 'partial') ? 'partial' : 'missing';
      const rules = [...new Map(covs.flatMap((c) => c.blockers).map((r) => [r.id, { id: r.id, name: r.name }])).values()];
      const detail = coverageSummary(covs);
      return { id: tg.id, name: tg.name, state: state as 'covered' | 'partial' | 'missing', detail, rules, ...(isTestTarget(tg.id) ? { test: true } : {}) };
    });
    // Test networks are listed (so the page can say "Done on SC-Test") but never count toward the real status.
    const real = rows.filter((r) => !r.test);
    if (!real.length) return { templateId, state: 'not-applicable', label: 'Not applicable', detail: emptyDetail, targets: rows, suggestedParams: suggested };
    const done = real.filter((r) => r.state === 'covered').length;
    const state = done === real.length ? 'applied' : done || real.some((r) => r.state === 'partial') ? 'partial' : 'not-applied';
    return { templateId, state, label: state === 'applied' ? 'Applied' : state === 'partial' ? `${done} of ${real.length}` : 'Not applied', detail: `${done} of ${real.length} protected`, targets: rows, suggestedParams: suggested };
  };
  // Suggested fixes only name real networks; in test-network mode the preview swaps in the test network itself.
  const todo = (st: TemplateStatus) => st.targets.filter((t) => !t.test && t.state !== 'covered').map((t) => t.id);

  // DNS
  {
    const servers = detectDnsServers(model);
    const params = { networks: nets.map((n) => n.id), includeDot: true, allowedServers: servers };
    const intents = buildIntents(model, 'block-external-dns', params);
    const st = fwStatus('block-external-dns', nets.map((n) => ({ id: n.id, name: n.name, intents: intents.filter((i) => i.src === n) })), {}, 'No networks found.');
    st.suggestedParams = { networks: todo(st), includeDot: true, allowedServers: servers };
    out.push(st);
  }
  // Isolation (pairs the roles say should be blocked)
  {
    const pairs = nets.flatMap((s) => nets.filter((d) => d.id !== s.id && expectedReach(s.role, d.role).expected === 'block').map((d) => ({ s, d })));
    const targets = pairs.map(({ s, d }) => ({ id: `${s.id}>${d.id}`, name: `${s.name} → ${d.name}`, intents: buildIntents(model, 'isolate-networks', { sources: [s.id], destinations: [d.id] }) }));
    const st = fwStatus('isolate-networks', targets, {}, 'No untrusted → trusted network pairs found. Set network roles on the Firewall page.');
    const missing = todo(st).map((id) => pairs.find((p) => `${p.s.id}>${p.d.id}` === id)!);
    // One source at a time, with exactly the destinations its role says to block: every source × every destination
    // would also block pairs that are meant to stay open.
    const bySource = new Map<string, string[]>();
    for (const m of missing) bySource.set(m.s.id, [...(bySource.get(m.s.id) ?? []), m.d.id]);
    const [source, destinations] = [...bySource.entries()].sort((a, b) => b[1].length - a[1].length)[0] ?? [null, []];
    st.suggestedParams = { sources: source ? [source] : [], destinations };
    out.push(st);
  }
  // Internet for local-only networks: cameras and storage, plus any other network you already cut off (so a block you
  // chose yourself shows as done here).
  {
    const intentsFor = (n: NetInfo) => buildIntents(model, 'block-internet', { networks: [n.id] });
    const cutOff = (n: NetInfo) => {
      const ints = intentsFor(n);
      return ints.length > 0 && ints.every((i) => assessIntent(model, i).state === 'covered');
    };
    const local = nets.filter((n) => n.role === 'cameras' || n.role === 'storage' || cutOff(n));
    const st = fwStatus('block-internet', local.map((n) => ({ id: n.id, name: n.name, intents: intentsFor(n) })), {}, 'No camera or storage networks detected — pick any local-only network manually.');
    st.suggestedParams = { networks: todo(st) };
    out.push(st);
  }
  // Gateway management
  {
    const restricted = nets.filter((n) => keepOffGatewayAdmin(n.role));
    const st = fwStatus('protect-gateway', restricted.map((n) => ({ id: n.id, name: n.name, intents: buildIntents(model, 'protect-gateway', { networks: [n.id] }) })), {}, 'No networks that need it.');
    st.suggestedParams = { networks: todo(st) };
    out.push(st);
  }
  // Countries (inbound): UniFi's Region Blocking covers the whole network at once; otherwise rules for each zone the
  // internet can reach
  {
    const ext = model.zones.find((z) => z.key === 'external');
    const official = !!ext && raw.firewallSource === 'integration';
    const geo = regionBlocking(raw);
    const geoIn = !!geo && filtersInbound(geo);
    const blocks = official ? countryBlocks(model, ext!.id) : [];
    const own = new Set(blocks.map((r) => r.dstZoneId));
    const zoneRows: TemplateTarget[] = official
      ? exposedZones(model, raw).map((z) => {
          const here = blocks.filter((r) => r.dstZoneId === z.id);
          const codes = [...new Set(here.flatMap((r) => r.srcRegions ?? []))].sort();
          return {
            id: z.id,
            name: `Internet → ${z.name}`,
            state: codes.length || geoIn ? 'covered' : 'missing',
            detail: !codes.length ? (geoIn ? 'Covered by Region Blocking.' : 'No countries blocked.') : geoIn ? `Covered by Region Blocking; its own rules also block ${codes.join(', ')}.` : `Blocks ${codes.join(', ')}.`,
            rules: here.map((r) => ({ id: r.id, name: r.name })),
          };
        })
      : [];
    const said = geo ? ` UniFi's Region Blocking ${regionText(geo)}.` : '';
    // Without zones, exposure is judged from the port forwards and VPN servers alone.
    const exposed = official ? zoneRows.length > 0 : raw.portForwards.some((pf) => pf.enabled !== false) || raw.networkconf.some((n) => n.purpose === 'remote-user-vpn' || n.purpose === 'site-vpn');
    // Rule suggestions skip zones that already have their own country rule, for anyone choosing rules over Region Blocking.
    const st: TemplateStatus = { templateId: 'block-countries', state: 'not-applicable', label: 'Not applicable', detail: '', targets: [], suggestedParams: { countries: [], zones: zoneRows.filter((t) => !own.has(t.id)).map((t) => t.id) } };
    if (geoIn) {
      const what = regionText(geo!);
      st.state = 'applied';
      st.label = 'Region Blocking';
      st.detail = said.trim();
      st.targets.push({ id: 'region-blocking', name: 'UniFi Region Blocking', state: 'covered', detail: `${what.charAt(0).toUpperCase()}${what.slice(1)}, for your whole network.`, rules: [] });
    } else if (official && exposed) {
      const done = zoneRows.filter((t) => t.state === 'covered').length;
      st.state = done === zoneRows.length ? 'applied' : done ? 'partial' : 'not-applied';
      st.label = `${done} of ${zoneRows.length}`;
      st.detail = `${done} of ${zoneRows.length} zones reachable from the internet block countries.${said}`;
    } else if (geo && exposed) {
      st.state = 'not-applied';
      st.label = 'Not applied';
      st.detail = said.trim();
    } else {
      st.detail = official || geo ? `Nothing is reachable from the internet through port forwards or a VPN server.${said}` : 'Needs UniFi Region Blocking, or the zone-based firewall through the official UniFi API (Network 10.1 or newer).';
    }
    st.targets.push(...zoneRows);
    out.push(st);
  }
  // Risky outbound
  {
    const st = fwStatus('block-risky-outbound', nets.map((n) => ({ id: n.id, name: n.name, intents: buildIntents(model, 'block-risky-outbound', { networks: [n.id] }) })), {}, 'No networks found.');
    st.suggestedParams = { networks: todo(st), services: ['smtp', 'smb', 'telnet', 'irc'] };
    out.push(st);
  }
  // IPS mode
  {
    const s = raw.settings.ips;
    const mode = s ? String(s.ips_mode ?? 'disabled') : null;
    out.push({
      templateId: 'ips-mode',
      state: !s ? 'unknown' : mode === 'ips' || mode === 'ipsInline' ? 'applied' : mode === 'ids' ? 'partial' : 'not-applied',
      label: !s ? 'Unknown' : mode === 'ips' || mode === 'ipsInline' ? 'Notify and Block' : mode === 'ids' ? 'Notify (detect only)' : 'Off',
      detail: !s ? 'IPS settings not readable.' : mode === 'ids' ? 'Threats are detected but allowed through.' : mode === 'disabled' ? 'Intrusion prevention is turned off.' : 'Malicious traffic is blocked.',
      targets: [],
      suggestedParams: { mode: 'ips' },
    });
  }
  // UPnP
  {
    const s = raw.settings.usg;
    out.push({
      templateId: 'disable-upnp',
      state: !s ? 'unknown' : s.upnp_enabled === true ? 'not-applied' : 'applied',
      label: !s ? 'Unknown' : s.upnp_enabled === true ? 'UPnP on' : 'Disabled',
      detail: !s ? 'Gateway settings not readable.' : s.upnp_enabled === true ? 'Devices can open ports without asking.' : 'Only your own port forwards are exposed.',
      targets: [],
      suggestedParams: {},
    });
  }
  // Guest Wi-Fi isolation
  {
    const guestNetIds = new Set(model.networks.filter((n) => n.role === 'guest').flatMap((n) => [n.id, String(n.raw._legacyId ?? '')]));
    const guests = raw.wlans.filter((w) => w.enabled !== false && (w.is_guest === true || guestNetIds.has(String(w.networkconf_id))));
    const isolated = guests.filter((w) => w.l2_isolation === true).length;
    out.push({
      templateId: 'guest-wifi-isolation',
      state: !raw.wlans.length ? 'unknown' : !guests.length ? 'not-applicable' : isolated === guests.length ? 'applied' : isolated ? 'partial' : 'not-applied',
      label: !guests.length ? 'No guest Wi-Fi' : `${isolated} of ${guests.length}`,
      detail: !guests.length ? 'No guest Wi-Fi networks found.' : `${isolated} of ${guests.length} guest Wi-Fi networks isolate clients.`,
      targets: guests.map((w) => ({ id: String(w._id), name: String(w.name), state: w.l2_isolation === true ? 'covered' : 'missing', detail: w.l2_isolation === true ? 'Isolated' : 'Not isolated', rules: [] })),
      suggestedParams: {},
    });
  }
  return out.filter((s) => TEMPLATES.some((t) => t.id === s.templateId));
}
