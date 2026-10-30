import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import clsx from 'clsx';
import { ShieldOff, Undo2 } from 'lucide-react';
import type { RiskAcceptance } from '@shared/types';
import { api } from '../lib/api';
import { timeAgo } from '../lib/format';
import { Button, ErrorBox, Modal } from './ui';

type Target = { key: string; kind: RiskAcceptance['kind']; title: string };

const MIN_REASON = 10;

/** "Accept risk": the owner writes why an issue doesn't apply to them, and it leaves the to-do lists. */
export function useAcceptRisk() {
  const qc = useQueryClient();
  const [target, setTarget] = useState<Target | null>(null);
  const [reason, setReason] = useState('');
  const save = useMutation({
    mutationFn: () => api.acceptRisk({ ...target!, reason: reason.trim() }),
    onSuccess: async () => {
      setTarget(null);
      await qc.invalidateQueries();
    },
  });
  const left = MIN_REASON - reason.trim().length;
  const ok = left <= 0;
  const where = target?.kind === 'protection' ? 'Accepted risks, at the bottom of the Hardening page' : 'the accepted risks link under your security score on the Overview';
  const node = (
    <Modal
      open={!!target}
      onClose={() => setTarget(null)}
      title="Accept this risk"
      subtitle={target?.title}
      footer={
        <div className="flex justify-end gap-2">
          <Button variant="ghost" onClick={() => setTarget(null)}>
            Cancel
          </Button>
          <Button variant="primary" disabled={!ok} loading={save.isPending} onClick={() => save.mutate()}>
            Accept risk
          </Button>
        </div>
      }
    >
      <div className="space-y-3 text-sm">
        <p className="text-ink-2">
          It leaves your to-do lists and stops counting against your score. Nothing changes in UniFi. You’ll find it under {where}, where you can undo it any time.
        </p>
        <label className="block">
          <span className="mb-1 block text-xs font-medium text-ink-2">Why is this OK for your network?</span>
          <textarea
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            rows={4}
            maxLength={1000}
            autoFocus
            placeholder="e.g. Only our old printers use this Wi-Fi, and they can't do WPA3."
            className="w-full rounded-lg border border-line-2 bg-surface-2 px-3 py-2 text-sm text-ink placeholder:text-ink-3 focus:border-cyan-500/60 focus:outline-none"
          />
          <span className={clsx('mt-1 block text-xs', ok ? 'text-ink-3' : 'text-amber-300')}>
            {ok ? 'Saved together with today’s date.' : `Write a short reason to enable Accept risk: ${left} more character${left === 1 ? '' : 's'}.`}
          </span>
        </label>
        {save.error && <ErrorBox error={save.error} />}
      </div>
    </Modal>
  );
  return {
    open: (t: Target) => {
      setReason('');
      save.reset();
      setTarget(t);
    },
    node,
  };
}

/** Accepted risks with the owner's reasons, each with an undo. */
export function AcceptedList({ items }: { items: { key: string; title: string; acceptance: RiskAcceptance }[] }) {
  const qc = useQueryClient();
  const revoke = useMutation({ mutationFn: (key: string) => api.revokeRisk(key), onSuccess: () => void qc.invalidateQueries() });
  return (
    <ul className="divide-y divide-line/60">
      {items.map((x) => (
        <li key={x.key} className="flex items-start gap-3 py-2.5">
          <ShieldOff className="mt-0.5 h-4 w-4 shrink-0 text-ink-3" />
          <div className="min-w-0 flex-1">
            <div className="text-sm text-ink-2">{x.title}</div>
            <div className="mt-0.5 break-words text-xs text-ink-3">
              “{x.acceptance.reason}” · accepted {timeAgo(x.acceptance.acceptedAt)}
            </div>
          </div>
          <Button size="sm" variant="ghost" icon={<Undo2 className="h-3.5 w-3.5" />} loading={revoke.isPending && revoke.variables === x.key} onClick={() => revoke.mutate(x.key)}>
            Undo
          </Button>
        </li>
      ))}
    </ul>
  );
}
