// Firewall hygiene: duplicate / redundant / shadowed / overly broad / broken rules.

import type { HygieneIssue } from '../../shared/types.ts';
import { evaluateChains } from './evaluate.ts';
import type { FwModel, NormRule } from './model.ts';
import { chainLabel, ruleRef } from './segmentation.ts';
import { ServiceSet, ST_NEW, spaceContains } from './sets.ts';

const deny = (a: string) => a === 'block' || a === 'reject';
const sameEffect = (a: string, b: string) => (deny(a) && deny(b)) || a === b;

export function analyzeHygiene(model: FwModel): HygieneIssue[] {
  const issues: HygieneIssue[] = [];
  const real = model.rules.filter((r) => !r.id.startsWith('synthetic:'));
  const byChain = new Map<string, NormRule[]>();
  for (const r of real) byChain.set(r.chain, [...(byChain.get(r.chain) ?? []), r]);

  for (const [chain, rules] of byChain) {
    const sorted = rules.filter((r) => r.enabled).sort((a, b) => a.order - b.order);
    for (let i = 0; i < sorted.length; i++) {
      const r = sorted[i];
      if (r.predefined || !r.exact) continue;
      const earlier = sorted.slice(0, i).filter((e) => e.exact);
      if (!earlier.length) continue;
      const res = evaluateChains(r.space, [{ label: chain, rules: earlier, defaultAction: 'unknown', defaultLabel: '' }]);
      if (res.segments.some((s) => !s.rule)) continue; // matches something nobody before it matches
      const covering = [...new Map(res.segments.map((s) => [s.rule!.id, s.rule!])).values()];
      const where = chainLabel(model, r);
      if (res.segments.every((s) => sameEffect(s.rule!.action, r.action))) {
        const twin = covering.length === 1 && spaceContains(r.space, covering[0].space) && spaceContains(covering[0].space, r.space) ? covering[0] : null;
        issues.push({
          id: `${twin ? 'duplicate' : 'redundant'}:${r.id}`,
          kind: twin ? 'duplicate' : 'redundant',
          severity: 'low',
          title: twin ? `${ruleRef(r)} duplicates ${ruleRef(twin)}` : `${ruleRef(r)} is redundant`,
          detail: twin
            ? `Both rules match exactly the same traffic in ${where} (even though they are written differently). The later one never does anything — it can be deleted.`
            : `Everything ${ruleRef(r)} matches is already ${r.action === 'allow' ? 'allowed' : 'blocked'} earlier in ${where} by ${covering.map(ruleRef).join(', ')}. It never matches anything new.`,
          ruleIds: [r.id, ...covering.map((c) => c.id)],
          ruleNames: [r.name, ...covering.map((c) => c.name)],
        });
      } else {
        const opposite = covering.filter((c) => !sameEffect(c.action, r.action));
        issues.push({
          id: `shadowed:${r.id}`,
          kind: 'shadowed',
          severity: r.action === 'allow' ? 'low' : 'medium',
          title: `${ruleRef(r)} never takes effect`,
          detail: `Earlier rule${opposite.length === 1 ? '' : 's'} ${opposite.map(ruleRef).join(', ')} already ${opposite[0]?.action === 'allow' ? 'allow' : 'block'} all of the traffic this rule is meant to ${r.action === 'allow' ? 'allow' : 'block'} (${where}). Move it above them, or delete it.`,
          ruleIds: [r.id, ...covering.map((c) => c.id)],
          ruleNames: [r.name, ...covering.map((c) => c.name)],
        });
      }
    }
  }

  for (const r of real) {
    if (!r.predefined && !r.enabled) {
      issues.push({
        id: `disabled:${r.id}`,
        kind: 'disabled',
        severity: 'info',
        title: `${ruleRef(r)} is disabled`,
        detail: `Disabled rules do nothing. Delete it if it is no longer needed, so the rule list stays easy to audit.`,
        ruleIds: [r.id],
        ruleNames: [r.name],
      });
    }
    if (r.notes.some((n) => /no longer exist|could not be found/.test(n))) {
      issues.push({
        id: `unresolved:${r.id}`,
        kind: 'unresolved-ref',
        severity: 'low',
        title: `${ruleRef(r)} references something that no longer exists`,
        detail: r.notes.filter((n) => /no longer exist|could not be found/.test(n)).join(' '),
        ruleIds: [r.id],
        ruleNames: [r.name],
      });
    }
    if (!r.predefined && r.enabled && r.action === 'allow' && r.srcAny && r.dstAny) {
      const allSvc = r.space.every((b) => b.svc.equals(ServiceSet.ALL));
      const newConns = r.space.some((b) => (b.st & ST_NEW) !== 0);
      if (!allSvc || !newConns) continue;
      let severity: HygieneIssue['severity'] | null = null;
      let why = '';
      if (r.system === 'zone') {
        const s = model.zones.find((z) => z.id === r.srcZoneId)?.key;
        const d = model.zones.find((z) => z.id === r.dstZoneId)?.key;
        if (s === 'external' && (d === 'internal' || d === 'gateway' || d === 'dmz')) {
          severity = 'critical';
          why = 'It lets anyone on the internet start connections into your network.';
        } else if ((s === 'hotspot' || s === 'dmz') && (d === 'internal' || d === 'gateway')) {
          severity = 'high';
          why = 'It removes the isolation that protects your internal network from this zone.';
        } else if (s === d && s === 'internal') {
          severity = 'info';
          why = 'It allows every internal network to reach every other one; any block rule placed after it is ignored.';
        }
      } else if (/^WAN(v6)?_(IN|LOCAL)$/.test(r.chain)) {
        severity = 'critical';
        why = 'It lets anyone on the internet start connections into your network or gateway.';
      }
      if (severity) {
        issues.push({
          id: `broad:${r.id}`,
          kind: 'broad-allow',
          severity,
          title: `${ruleRef(r)} allows everything (${chainLabel(model, r)})`,
          detail: why,
          ruleIds: [r.id],
          ruleNames: [r.name],
        });
      }
    }
  }
  const rank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  return issues.sort((a, b) => rank[a.severity] - rank[b.severity]);
}
