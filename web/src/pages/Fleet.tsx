import { useNavigate } from 'react-router';
import { useQuery } from '@tanstack/react-query';
import { ArrowDown, ArrowUp, ChevronRight, Layers, Users } from 'lucide-react';
import type { FleetRow } from '@shared/types';
import { api } from '../lib/api';
import { setEnv } from '../lib/env';
import { fmtBps, fmtNum } from '../lib/format';
import { Badge, EmptyState, ErrorBox, Loading, PageHeader, gradeColor } from '../components/ui';

export function FleetPage() {
  const { data, error, isLoading, refetch } = useQuery({ queryKey: ['fleet'], queryFn: api.fleet, refetchInterval: 30_000 });
  const navigate = useNavigate();
  const open = (id: string, path = '/') => {
    setEnv(id);
    navigate(path);
  };
  return (
    <div className="space-y-5">
      <PageHeader icon={<Layers className="h-5 w-5" />} title="All environments" subtitle="Security posture and activity of every connected UniFi environment, side by side. Open one to dig in." />
      {isLoading && <Loading />}
      {error && <ErrorBox error={error} onRetry={() => void refetch()} />}
      {data && data.length === 0 && <EmptyState title="No environments yet" />}
      {data && data.length > 0 && (
        <div className="grid gap-4 md:grid-cols-2 2xl:grid-cols-3 [&>*]:min-w-0">
          {data.map((r) => (
            <FleetCard key={r.env.id} r={r} onOpen={(path) => open(r.env.id, path)} />
          ))}
        </div>
      )}
    </div>
  );
}

function FleetCard({ r, onOpen }: { r: FleetRow; onOpen: (path?: string) => void }) {
  const e = r.env;
  return (
    <div className="overflow-hidden rounded-xl border border-line bg-surface/80">
      <div className="h-1" style={{ background: e.color }} />
      <div className="p-4">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="truncate text-base font-semibold text-ink">{e.name}</div>
            <div className="truncate text-xs text-ink-3">
              {e.url}
              {e.siteName ? ` · ${e.siteName}` : ''}
            </div>
            <div className="mt-1.5 flex flex-wrap gap-1.5">
              {e.connected ? <Badge tone="green">Connected</Badge> : <Badge tone="red">{e.lastError ? 'Cannot connect' : 'Connecting'}</Badge>}
              {e.version && <Badge tone="slate">Network {e.version}</Badge>}
              <Badge tone={e.effectiveWriteMode === 'read-only' ? 'slate' : e.effectiveWriteMode === 'test-network' ? 'violet' : 'amber'}>
                {e.effectiveWriteMode === 'read-only' ? 'Read-only' : e.effectiveWriteMode === 'test-network' ? 'Test network only' : 'Full access'}
              </Badge>
            </div>
          </div>
          <div className="text-center">
            <div className="text-3xl font-bold leading-none" style={{ color: r.grade ? gradeColor(r.grade) : '#64748b' }}>
              {r.grade ?? '—'}
            </div>
            <div className="mt-1 text-[11px] text-ink-3">{r.score !== null ? `${r.score}/100` : 'no score yet'}</div>
          </div>
        </div>

        <dl className="mt-4 grid grid-cols-3 gap-3 text-sm">
          <div>
            <dt className="text-xs text-ink-3">Issues</dt>
            <dd className="text-ink">
              {r.failed ?? '—'}
              {r.critical > 0 && <span className="ml-1 text-xs text-rose-300">({r.critical} high+)</span>}
            </dd>
          </div>
          <div>
            <dt className="text-xs text-ink-3">Threats 24h</dt>
            <dd className="text-ink">
              {fmtNum(r.threats24h)}
              {r.alerted24h > 0 && <span className="ml-1 text-xs text-amber-300">{fmtNum(r.alerted24h)} allowed</span>}
            </dd>
          </div>
          <div>
            <dt className="flex items-center gap-1 text-xs text-ink-3">
              <Users className="h-3 w-3" /> Clients
            </dt>
            <dd className="text-ink">{fmtNum(r.clients)}</dd>
          </div>
        </dl>
        <div className="mt-3 flex items-center gap-3 text-xs text-ink-3">
          <span className="flex items-center gap-1">
            <ArrowDown className="h-3.5 w-3.5 text-cyan-300" /> {fmtBps(r.rxBps)}
          </span>
          <span className="flex items-center gap-1">
            <ArrowUp className="h-3.5 w-3.5 text-violet-300" /> {fmtBps(r.txBps)}
          </span>
        </div>
        {e.lastError && !e.connected && <p className="mt-3 line-clamp-2 text-xs text-rose-300">{e.lastError}</p>}

        <div className="mt-4 flex flex-wrap gap-2">
          <button onClick={() => onOpen('/')} className="inline-flex h-8 items-center gap-1 rounded-lg bg-cyan-500 px-3 text-xs font-medium text-slate-950 hover:bg-cyan-400">
            Open <ChevronRight className="h-3.5 w-3.5" />
          </button>
          <button onClick={() => onOpen('/threats')} className="inline-flex h-8 items-center rounded-lg border border-line-2 px-3 text-xs text-ink-2 hover:bg-surface-3">
            Threats
          </button>
          <button onClick={() => onOpen('/hardening')} className="inline-flex h-8 items-center rounded-lg border border-line-2 px-3 text-xs text-ink-2 hover:bg-surface-3">
            Hardening
          </button>
        </div>
      </div>
    </div>
  );
}
