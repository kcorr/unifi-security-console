import { useState } from 'react';
import { Link } from 'react-router';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import clsx from 'clsx';
import { ChevronDown, CircleCheck, CircleX, History, Undo2 } from 'lucide-react';
import type { ChangeRecord } from '@shared/types';
import { api } from '../lib/api';
import { hasRuleDetails, RuleDetailsWindow } from '../components/RuleDetails';
import { fmtTime, timeAgo } from '../lib/format';
import { Badge, Button, Card, EmptyState, ErrorBox, Loading, PageHeader } from '../components/ui';

export function ActivityPage() {
  const qc = useQueryClient();
  const { data, error, isLoading, refetch } = useQuery({ queryKey: ['changes'], queryFn: api.changes });
  const templates = useQuery({ queryKey: ['templates'], queryFn: api.templates });
  // Changes made by a Hardening protection link back to it; one-off actions (block an IP, remove a rule) have no row there.
  const protectionOf = (r: ChangeRecord) => templates.data?.templates.find((t) => t.id === r.templateId && !t.hidden) ?? null;
  const undo = useMutation({ mutationFn: (v: { id: string; cascade: boolean }) => api.undo(v.id, v.cascade), onSuccess: () => void qc.invalidateQueries() });
  const [open, setOpen] = useState<string | null>(null);

  // Later changes that use what this one created (e.g. rules on the test network) are undone with it, newest first.
  const askUndo = async (r: ChangeRecord) => {
    const deps = await api.undoDependents(r.id).catch(() => []);
    const msg = deps.length
      ? `Undo "${r.title}"?\n\nFirst, ${deps.length === 1 ? 'this later change uses' : `these ${deps.length} later changes use`} what it created and will be undone, newest first:\n${deps.map((d) => `  • ${d.title} (${timeAgo(d.ts)})`).join('\n')}\n\nThen everything "${r.title}" created is deleted and anything it modified is restored.`
      : `Undo "${r.title}"? This deletes what it created and restores anything it modified.`;
    if (confirm(msg)) undo.mutate({ id: r.id, cascade: deps.length > 0 });
  };

  return (
    <div>
      <PageHeader
        icon={<History className="h-5 w-5" />}
        title="Change Log"
        subtitle="Every change this console made to your UniFi configuration, with the exact API calls — and a one-click undo."
      />
      {isLoading && <Loading />}
      {error && <ErrorBox error={error} onRetry={() => void refetch()} />}
      {undo.error && (
        <div className="mb-3">
          <ErrorBox error={undo.error} />
        </div>
      )}
      {data && data.length === 0 && (
        <Card>
          <EmptyState icon={<History className="h-8 w-8" />} title="No changes yet">
            When you apply a hardening action, it shows up here with everything needed to roll it back.
          </EmptyState>
        </Card>
      )}
      {data && data.length > 0 && (
        <div className="space-y-2">
          {data.map((r) => (
            <ChangeRow key={r.id} r={r} protection={protectionOf(r)} expanded={open === r.id} onToggle={() => setOpen(open === r.id ? null : r.id)} onUndo={() => void askUndo(r)} undoing={undo.isPending && undo.variables?.id === r.id} />
          ))}
        </div>
      )}
    </div>
  );
}

/** The rule a step created or changed, while it still exists (an undone step's rule is gone; reordering touches many). */
function ruleOf(op: ChangeRecord['operations'][number]): string | null {
  if (op.status !== 'ok' || (op.objectType !== 'firewall-policy' && op.objectType !== 'firewall-rule')) return null;
  if (/ordering|reorder/.test(op.path)) return null;
  return op.kind === 'create' ? (op.resultId ?? null) : op.kind === 'update' ? (op.targetId ?? null) : null;
}

function ChangeRow({ r, protection, expanded, onToggle, onUndo, undoing }: { r: ChangeRecord; protection: { id: string; title: string } | null; expanded: boolean; onToggle: () => void; onUndo: () => void; undoing: boolean }) {
  const [details, setDetails] = useState<string | null | undefined>(undefined);
  const tone = r.status === 'applied' ? 'green' : r.status === 'undone' ? 'slate' : r.status === 'partial' ? 'amber' : 'red';
  return (
    <div className="rounded-xl border border-line bg-surface/80">
      <div className="flex cursor-pointer items-center gap-3 px-4 py-3" onClick={onToggle}>
        {r.status === 'applied' ? <CircleCheck className="h-5 w-5 text-emerald-400" /> : r.status === 'undone' ? <Undo2 className="h-5 w-5 text-ink-3" /> : <CircleX className="h-5 w-5 text-rose-400" />}
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-medium text-ink">{r.title}</span>
            <Badge tone={tone}>{r.status}</Badge>
          </div>
          <div className="truncate text-xs text-ink-3">{r.summary}</div>
          {protection && (
            <Link to={`/hardening#${protection.id}`} onClick={(e) => e.stopPropagation()} className="text-xs text-cyan-300 hover:text-cyan-200">
              {protection.title} on Hardening →
            </Link>
          )}
        </div>
        <div className="hidden text-right text-xs text-ink-3 sm:block" title={fmtTime(r.ts)}>
          {timeAgo(r.ts)}
          {r.undoneAt && <div>undone {timeAgo(r.undoneAt)}</div>}
        </div>
        {r.undoable && r.status !== 'undone' && (
          <Button
            size="sm"
            variant="secondary"
            icon={<Undo2 className="h-3.5 w-3.5" />}
            loading={undoing}
            onClick={(e) => {
              e.stopPropagation();
              onUndo();
            }}
          >
            Undo
          </Button>
        )}
        <ChevronDown className={clsx('h-4 w-4 text-ink-3 transition-transform', expanded && 'rotate-180')} />
      </div>
      {expanded && (
        <div className="border-t border-line px-4 py-3">
          <RuleDetailsWindow ops={r.operations} open={details !== undefined} focus={details ?? null} onClose={() => setDetails(undefined)} />
          {hasRuleDetails(r.operations) && (
            <button type="button" onClick={() => setDetails(null)} className="mb-3 inline-flex items-center gap-1 text-xs font-medium text-cyan-300 hover:text-cyan-200">
              See the rules in detail →
            </button>
          )}
          {r.error && <div className="mb-2 text-sm text-rose-300">{r.error}</div>}
          <ol className="space-y-3">
            {r.operations.map((op) => (
              <li key={op.id} className="text-sm">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge tone={op.status === 'ok' ? 'green' : op.status === 'undone' ? 'slate' : op.status === 'skipped' ? 'slate' : 'red'}>{op.status}</Badge>
                  <span className="text-ink">{op.description}</span>
                  {ruleOf(op) && (
                    <Link to={`/firewall/rules?rule=${encodeURIComponent(ruleOf(op)!)}`} className="text-xs text-cyan-300 hover:text-cyan-200">
                      View rule →
                    </Link>
                  )}
                </div>
                {op.error && <div className="mt-1 text-xs text-rose-300">{op.error}</div>}
                <pre className="mono mt-1.5 max-h-56 overflow-auto rounded-md bg-black/40 p-2 text-[11px] leading-relaxed text-slate-300">
                  {`${op.method} ${op.path}${op.resultId ? `   → id ${op.resultId}` : ''}\n`}
                  {op.body !== undefined ? JSON.stringify(op.body, null, 2) : ''}
                </pre>
              </li>
            ))}
          </ol>
        </div>
      )}
    </div>
  );
}
