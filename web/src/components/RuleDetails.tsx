import { useEffect, useRef } from 'react';
import clsx from 'clsx';
import { ArrowRight, ListOrdered } from 'lucide-react';
import type { PlanOperation, RuleDetail, RuleOrder, RuleSide } from '@shared/types';
import { Badge, Button, Modal } from './ui';

const CHANGE = {
  create: { label: 'New rule', tone: 'cyan' },
  update: { label: 'Changed rule', tone: 'violet' },
  delete: { label: 'Removed rule', tone: 'red' },
} as const;

/** True when a change has rules worth showing in detail. */
export const hasRuleDetails = (ops: PlanOperation[]) => ops.some((o) => o.detail || o.order);

/**
 * "The rules in detail": every rule a change creates, changes or removes, laid out like UniFi's own rule editor,
 * plus the rule order it sets. `focus` scrolls to one step.
 */
export function RuleDetailsWindow({ ops, open, focus, onClose }: { ops: PlanOperation[]; open: boolean; focus: string | null; onClose: () => void }) {
  const items = ops.filter((o) => o.detail || o.order);
  const refs = useRef(new Map<string, HTMLElement>());
  useEffect(() => {
    if (!open || !focus) return;
    const t = setTimeout(() => refs.current.get(focus)?.scrollIntoView({ block: 'start' }), 50);
    return () => clearTimeout(t);
  }, [open, focus]);
  return (
    <Modal
      open={open}
      onClose={onClose}
      size="xl"
      title="The rules in detail"
      subtitle="How each rule will look in UniFi once the change is applied, in the order the changes are sent."
      footer={
        <Button variant="primary" onClick={onClose}>
          Close
        </Button>
      }
    >
      <div className="space-y-4">
        {items.map((op) => (
          <section
            key={op.id}
            ref={(el) => {
              if (el) refs.current.set(op.id, el);
            }}
            className={clsx('scroll-mt-4 rounded-xl', op.id === focus && 'ring-2 ring-cyan-500/40')}
          >
            {op.detail ? <RuleSheet d={op.detail} /> : <OrderSheet o={op.order!} />}
          </section>
        ))}
      </div>
    </Modal>
  );
}

/** One rule, field by field. For a changed rule, the fields that change are highlighted with their old value. */
export function RuleSheet({ d }: { d: RuleDetail }) {
  const was = new Map((d.changes ?? []).map((c) => [c.field, c.from]));
  const allow = d.action === 'Allow';
  return (
    <div className="rounded-xl border border-line bg-surface-2/40">
      <header className="flex flex-wrap items-center gap-2 border-b border-line px-4 py-3">
        <Badge tone={CHANGE[d.change].tone}>{CHANGE[d.change].label}</Badge>
        <span className="min-w-0 break-words font-medium text-ink">{d.name}</span>
        <span className={clsx('ml-auto rounded-md px-2 py-0.5 text-xs font-semibold', allow ? 'bg-emerald-500/15 text-emerald-200' : 'bg-rose-500/15 text-rose-200')}>{d.action}</span>
        {(was.has('Name') || was.has('Action')) && (
          <span className="w-full text-xs text-ink-3">
            Was: {[was.get('Name'), was.get('Action')].filter(Boolean).join(' · ')}
          </span>
        )}
      </header>
      {d.change === 'update' && d.changes && (
        <p className="border-b border-line/60 px-4 py-2 text-xs text-ink-3">
          {d.changes.length ? `${d.changes.length} field${d.changes.length === 1 ? '' : 's'} change, highlighted below with the old value.` : 'Nothing visible changes in this rule.'}
        </p>
      )}
      <div className="grid gap-3 p-4 md:grid-cols-[1fr_auto_1fr] md:items-stretch">
        <SideBox title="Source" side={d.source} prefix="Source" was={was} />
        <ArrowRight className="hidden h-5 w-5 self-center text-ink-3 md:block" />
        <SideBox title="Destination" side={d.destination} prefix="Destination" was={was} />
      </div>
      <dl className="grid gap-x-6 gap-y-3 border-t border-line/60 p-4 sm:grid-cols-2 lg:grid-cols-3">
        <Field label="Protocol" value={d.protocol} was={was.get('Protocol')} />
        <Field label="IP version" value={d.ipVersion} was={was.get('IP version')} />
        <Field label="Connections" value={d.states} was={was.get('Connections')} />
        <Field label="Logging" value={d.logging ? 'On' : 'Off'} was={was.get('Logging')} />
        <Field label="Enabled" value={d.enabled ? 'Yes' : 'No'} was={was.get('Enabled')} />
        {d.position && <Field label="Position" value={d.position} />}
        {d.description && <Field label="Description" value={<span className="mono break-all text-xs">{d.description}</span>} />}
      </dl>
    </div>
  );
}

function SideBox({ title, side, prefix, was }: { title: string; side: RuleSide; prefix: string; was: Map<string, string> }) {
  return (
    <div className="min-w-0 rounded-lg border border-line bg-surface/60 p-3">
      <div className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-ink-3">{title}</div>
      <dl className="space-y-2">
        {side.zone !== null && <Field label="Zone" value={side.zone} was={was.get(`${prefix} zone`)} />}
        <Field label="Matches" value={side.match} was={was.get(prefix)} />
        <Field label="Port" value={side.ports ?? 'Any'} was={was.get(`${prefix} ports`)} />
      </dl>
    </div>
  );
}

function Field({ label, value, was }: { label: string; value: React.ReactNode; was?: string }) {
  return (
    <div className="min-w-0">
      <dt className="text-[11px] text-ink-3">{label}</dt>
      <dd className={clsx('mt-0.5 break-words text-sm', was !== undefined ? 'font-medium text-amber-200' : 'text-ink')}>
        {value}
        {was !== undefined && <span className="block text-xs font-normal text-ink-3 line-through decoration-ink-3/60">{was}</span>}
      </dd>
    </div>
  );
}

/** The order an ordering step sets: rules are checked top to bottom, and the first match wins. */
export function OrderSheet({ o }: { o: RuleOrder }) {
  return (
    <div className="rounded-xl border border-line bg-surface-2/40">
      <header className="flex items-center gap-2 border-b border-line px-4 py-3">
        <ListOrdered className="h-4 w-4 text-ink-3" />
        <span className="font-medium text-ink">New rule order in {o.pair}</span>
      </header>
      <p className="px-4 pt-3 text-xs text-ink-3">Checked top to bottom; the first rule that matches decides. UniFi’s built-in rules come after these.</p>
      <ol className="space-y-1 p-4 pt-2">
        {o.rules.map((r, i) => (
          <li key={`${i}-${r.name}`} className="flex items-center gap-2 text-sm">
            <span className="w-6 shrink-0 text-right text-xs text-ink-3">{i + 1}.</span>
            <span className={clsx('min-w-0 break-words', r.isNew ? 'text-cyan-200' : 'text-ink-2')}>{r.name}</span>
            {r.isNew && <Badge tone="cyan">new</Badge>}
          </li>
        ))}
      </ol>
    </div>
  );
}
