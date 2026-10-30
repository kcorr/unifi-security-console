// Intents: "traffic X from network N should be blocked", and how well the current rules
// already enforce each one.

import type { CoverageState } from '../../../shared/types.ts';
import type { FwModel, NetInfo, NormRule, Segment } from '../model.ts';
import { analyzePath, ruleRef, type Dest } from '../segmentation.ts';
import { AddrSet, ServiceSet, boxIsEmpty, spaceContains, spaceSrc, spaceSvc, type Space } from '../sets.ts';

export interface Intent {
  /** Source network the intent protects (used as the "target" in the UI). */
  src: NetInfo;
  dst: Dest;
  dstLabel: string;
  svc: ServiceSet;
  st: number;
  /** Addresses inside `src` that are deliberately exempt (e.g. your own DNS server). */
  exempt: AddrSet;
  /** States must match exactly when extending existing rules (isolation needs NEW-only). */
  statesMatter: boolean;
}

export interface Coverage {
  intent: Intent;
  state: CoverageState;
  /** Rules that already block (part of) this traffic. */
  blockers: NormRule[];
  /** Custom allow rules that carve out a narrow exception (kept, evaluated before a new block). */
  exceptions: NormRule[];
  /** Custom allow rules that allow ALL of this traffic and would shadow a new block placed after them. */
  conflicts: NormRule[];
  /** Plain-English description of what is still allowed. */
  gap: string;
  /** Just the traffic in `gap` ("TCP/UDP 853"), for joining several parts into one sentence. */
  gapWhat: string;
  probe: Space;
  /** The probe minus exceptions: what a new rule must cover. */
  gapSpace: Space;
}

function describeGap(probe: Space, gapSegs: Segment[]): string {
  if (!gapSegs.length) return '';
  const gapSpace = gapSegs.map((s) => s.box);
  const probeSvc = spaceSvc(probe);
  const gapSvc = spaceSvc(gapSpace);
  const parts: string[] = [];
  parts.push(gapSvc.equals(probeSvc) ? (probeSvc.isAll() ? 'All traffic' : probeSvc.describe()) : gapSvc.describe());
  const fams = new Set(gapSpace.map((b) => b.fam));
  const probeFams = new Set(probe.map((b) => b.fam));
  if (probeFams.size === 2 && fams.size === 1) parts.push(fams.has(6) ? 'over IPv6' : 'over IPv4');
  const srcAll = spaceSrc(probe);
  const srcGap = spaceSrc(gapSpace);
  if (!srcGap.equals(srcAll)) parts.push(`from ${srcGap.toStrings(3).join(', ')}`);
  return parts.join(' ');
}

export function assessIntent(model: FwModel, intent: Intent): Coverage {
  const srcAddrs = intent.src.addrs.subtract(intent.exempt);
  const a = analyzePath(model, intent.src, intent.dst, intent.svc, intent.st, srcAddrs);
  if (!a) {
    return { intent, state: 'n/a', blockers: [], exceptions: [], conflicts: [], gap: 'This path could not be analysed.', gapWhat: '', probe: [], gapSpace: [] };
  }
  const blockSegs = a.result.segments.filter((s) => s.verdict === 'block');
  const allowSegs = a.result.segments.filter((s) => s.verdict === 'allow');
  const unknownSegs = a.result.segments.filter((s) => s.verdict === 'unknown');
  const blockers = uniq(blockSegs.map((s) => s.rule).filter((r): r is NormRule => !!r));
  const exceptions: NormRule[] = [];
  const conflicts: NormRule[] = [];
  const gapSegs: Segment[] = [...unknownSegs];
  for (const s of allowSegs) {
    const r = s.rule;
    if (!r || r.predefined) {
      gapSegs.push(s);
      continue;
    }
    // A custom allow covering the whole probe is a conflict; a narrower one is an intentional exception.
    if (spaceContains(r.space, a.probe)) {
      if (!conflicts.includes(r)) conflicts.push(r);
      gapSegs.push(s);
    } else if (!exceptions.includes(r)) exceptions.push(r);
  }
  let state: CoverageState;
  if (!gapSegs.length) state = 'covered';
  else if (blockSegs.length) state = 'partial';
  else state = 'missing';
  const gapWhat = describeGap(a.probe, gapSegs);
  return {
    intent,
    state,
    blockers,
    exceptions,
    conflicts,
    gap: gapWhat && `${gapWhat} is still allowed`,
    gapWhat,
    probe: a.probe,
    gapSpace: gapSegs.map((s) => s.box).filter((b) => !boxIsEmpty(b)),
  };
}

function uniq<T extends { id: string }>(xs: T[]): T[] {
  return [...new Map(xs.map((x) => [x.id, x])).values()];
}

/** "All traffic" → "all traffic" mid-sentence, while "TCP/UDP 53" keeps its capitals. */
const lowerFirst = (s: string) => (/^[A-Z][a-z]/.test(s) ? s.charAt(0).toLowerCase() + s.slice(1) : s);

/** ['a', 'b', 'c'] → "a, b and c". */
const joinAnd = (xs: string[]) => (xs.length > 1 ? `${xs.slice(0, -1).join(', ')} and ${xs[xs.length - 1]}` : (xs[0] ?? ''));

/** One sentence for several parts of the same target, e.g. the TCP and UDP halves of a template. */
export function coverageSummary(cs: Coverage[]): string {
  const known = cs.filter((c) => c.state !== 'n/a');
  if (known.length <= 1) return known.length ? coverageMessage(known[0]) : (cs[0]?.gap ?? '');
  const via = uniq(known.flatMap((c) => c.blockers));
  const open = [...new Set(known.filter((c) => c.state === 'partial' || c.state === 'missing').map((c) => c.gapWhat).filter(Boolean))];
  if (!open.length) return via.length ? `Already blocked by ${via.map(ruleRef).join(', ')}.` : 'Already blocked by default.';
  const still = `${lowerFirst(joinAnd(open))} ${open.length > 1 ? 'are' : 'is'} still allowed`;
  return via.length ? `Partly blocked by ${via.map(ruleRef).join(', ')} — ${still}.` : `Not blocked today — ${still}.`;
}

export function coverageMessage(c: Coverage): string {
  const via = c.blockers;
  switch (c.state) {
    case 'covered':
      return via.length ? `Already blocked by ${via.map(ruleRef).join(', ')}.` : 'Already blocked by default.';
    case 'partial':
      return `Partly blocked by ${via.map(ruleRef).join(', ')} — ${lowerFirst(c.gap)}.`;
    case 'missing':
      return `Not blocked today — ${lowerFirst(c.gap)}.`;
    default:
      return c.gap;
  }
}
