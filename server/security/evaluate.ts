// First-match evaluation of ordered rule chains over a traffic space.
//
// Given a probe ("all new connections from IoT to Main LAN", "DNS from IoT to the
// internet"...), we walk the applicable rules in order and split the probe into segments,
// each attributed to the rule (or chain default) that decides it. Rules we cannot model
// exactly (schedules, MAC/domain/app matching) never consume traffic; they are reported
// as "conditional".

import type { Chain, EvalResult, NormRule, Segment, SegVerdict } from './model.ts';
import type { Box, Space } from './sets.ts';
import { boxIntersect, boxSubtract, spaceContains } from './sets.ts';

const MAX_BOXES = 3000;

export function evaluateChains(probe: Space, chains: Chain[]): EvalResult {
  const segments: Segment[] = [];
  const conditional: EvalResult['conditional'] = [];
  let truncated = false;
  let pending: { box: Box; trail: NormRule[] }[] = probe.map((box) => ({ box, trail: [] }));

  for (const chain of chains) {
    const passed: { box: Box; trail: NormRule[] }[] = [];
    let remaining = pending;
    const rules = chain.rules.filter((r) => r.enabled).sort((a, b) => a.order - b.order);
    for (const rule of rules) {
      if (remaining.length === 0) break;
      const next: { box: Box; trail: NormRule[] }[] = [];
      for (const item of remaining) {
        let rest: Box[] = [item.box];
        for (const rb of rule.space) {
          const hit = boxIntersect(item.box, rb);
          if (!hit) continue;
          if (!rule.exact) {
            conditional.push({ rule, box: hit, chain: chain.label });
            continue;
          }
          const verdict: SegVerdict = rule.action === 'allow' ? 'allow' : 'block';
          // Only the part not already claimed by an earlier box of this same rule.
          for (const r of rest) {
            const part = boxIntersect(r, rb);
            if (!part) continue;
            if (verdict === 'allow') passed.push({ box: part, trail: [...item.trail, rule] });
            else segments.push({ box: part, verdict, rule, chain: chain.label, trail: item.trail });
          }
          const nextRest: Box[] = [];
          for (const r of rest) nextRest.push(...boxSubtract(r, rb));
          rest = nextRest;
        }
        for (const r of rest) next.push({ box: r, trail: item.trail });
      }
      remaining = next;
      if (remaining.length > MAX_BOXES) {
        truncated = true;
        break;
      }
    }
    for (const item of remaining) {
      if (chain.defaultAction === 'allow') passed.push({ box: item.box, trail: item.trail });
      else segments.push({ box: item.box, verdict: chain.defaultAction, rule: null, chain: chain.label, trail: item.trail });
    }
    pending = passed;
  }
  for (const item of pending) {
    const last = item.trail[item.trail.length - 1] ?? null;
    segments.push({ box: item.box, verdict: 'allow', rule: last, chain: chains[chains.length - 1]?.label ?? '', trail: item.trail.slice(0, -1) });
  }
  return { segments, conditional: dedupeConditional(conditional), truncated };
}

function dedupeConditional(list: EvalResult['conditional']): EvalResult['conditional'] {
  const seen = new Set<string>();
  return list.filter((c) => {
    if (seen.has(c.rule.id)) return false;
    seen.add(c.rule.id);
    return true;
  });
}

export interface Summary {
  verdict: 'allowed' | 'blocked' | 'partial' | 'unknown';
  allowRules: NormRule[];
  blockRules: NormRule[];
  defaultVerdicts: { chain: string; verdict: SegVerdict }[];
  conditional: NormRule[];
  unknownChains: string[];
  /** A rule that by itself covers the whole probe (the "deciding" rule), if any. */
  decisive: NormRule | null;
}

export function summarize(probe: Space, res: EvalResult): Summary {
  const allow = res.segments.filter((s) => s.verdict === 'allow');
  const block = res.segments.filter((s) => s.verdict === 'block');
  const unknown = res.segments.filter((s) => s.verdict === 'unknown');
  const uniq = (xs: (NormRule | null)[]) => {
    const m = new Map<string, NormRule>();
    for (const x of xs) if (x) m.set(x.id, x);
    return [...m.values()];
  };
  let verdict: Summary['verdict'];
  if (unknown.length && !allow.length && !block.length) verdict = 'unknown';
  else if (allow.length && !block.length) verdict = unknown.length ? 'partial' : 'allowed';
  else if (block.length && !allow.length) verdict = unknown.length ? 'partial' : 'blocked';
  else verdict = 'partial';
  const allRules = uniq(res.segments.map((s) => s.rule));
  const decisive = allRules.find((r) => spaceContains(r.space, probe)) ?? null;
  const defaults = new Map<string, SegVerdict>();
  for (const s of res.segments) if (!s.rule) defaults.set(s.chain, s.verdict);
  return {
    verdict,
    allowRules: uniq(allow.map((s) => s.rule)),
    blockRules: uniq(block.map((s) => s.rule)),
    defaultVerdicts: [...defaults.entries()].map(([chain, v]) => ({ chain, verdict: v })),
    conditional: res.conditional.map((c) => c.rule),
    unknownChains: [...new Set(unknown.map((s) => s.chain))],
    decisive,
  };
}
