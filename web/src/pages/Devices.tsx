import { useState } from 'react';
import { useSearchParams } from 'react-router';
import { useQuery } from '@tanstack/react-query';
import clsx from 'clsx';
import { CircleArrowUp, Router } from 'lucide-react';
import type { UnifiDevice } from '@shared/types';
import { api } from '../lib/api';
import { fmtDuration, plural, timeAgo } from '../lib/format';
import { Badge, Card, EmptyState, ErrorBox, Loading, PageHeader } from '../components/ui';
import { UnifiDevicePanel } from '../components/UnifiDevicePanel';
import { ClientPanel } from '../components/ClientPanel';

export const KIND_LABEL: Record<UnifiDevice['kind'], string> = { gateway: 'Gateway', switch: 'Switch', ap: 'Access point', other: 'Device' };
export const STATE: Record<UnifiDevice['state'], { label: string; dot: string }> = {
  online: { label: 'Online', dot: 'bg-emerald-400' },
  offline: { label: 'Offline', dot: 'bg-rose-400' },
  disabled: { label: 'Disabled', dot: 'bg-slate-500' },
  updating: { label: 'Updating', dot: 'bg-cyan-400' },
  adopting: { label: 'Adopting', dot: 'bg-amber-400' },
  other: { label: 'Unknown', dot: 'bg-slate-500' },
};

export function uplinkText(d: UnifiDevice): string | null {
  const u = d.uplink;
  if (!u) return null;
  if (u.wireless) return u.name ? `Wireless, through ${u.name}` : 'Wireless mesh';
  const speed = u.speedMbps ? ` · ${u.speedMbps >= 1000 ? `${u.speedMbps / 1000} Gbps` : `${u.speedMbps} Mbps`}` : '';
  if (u.name === 'Internet') return `Internet on port ${u.port ?? '?'}${speed}`;
  return `${u.name ?? 'Another device'}${u.port !== null ? `, port ${u.port}` : ''}${speed}`;
}

/** Your UniFi gear: gateway, switches and access points, with status, firmware and details on click. */
export function DevicesPage() {
  const [sp, setSp] = useSearchParams();
  const open = sp.get('device');
  const [client, setClient] = useState<string | null>(null);
  const { data, error, isLoading, refetch } = useQuery({ queryKey: ['unifi-devices'], queryFn: api.unifiDevices, refetchInterval: 15_000 });
  const setOpen = (mac: string | null) => {
    const next = new URLSearchParams(sp);
    if (mac) next.set('device', mac);
    else next.delete('device');
    setSp(next, { replace: true });
  };
  const count = (pred: (d: UnifiDevice) => boolean) => data?.filter(pred).length ?? 0;
  return (
    <div className="space-y-5">
      <UnifiDevicePanel
        mac={open}
        onClose={() => setOpen(null)}
        onClient={(mac) => {
          setOpen(null);
          setClient(mac);
        }}
      />
      <ClientPanel mac={client} onClose={() => setClient(null)} />
      <PageHeader icon={<Router className="h-5 w-5" />} title="UniFi devices" subtitle="Your gateway, switches and access points: status, firmware and details. Updates and settings stay in the UniFi app." />
      {isLoading && <Loading />}
      {error && <ErrorBox error={error} onRetry={() => void refetch()} />}
      {data && (
        <>
          <div className="flex flex-wrap gap-2 text-xs">
            <Badge tone="slate">{data.length} devices</Badge>
            <Badge tone="green">{count((d) => d.state === 'online')} online</Badge>
            {count((d) => d.state === 'offline') > 0 && <Badge tone="red">{count((d) => d.state === 'offline')} offline</Badge>}
            {count((d) => d.state === 'disabled') > 0 && <Badge tone="slate">{count((d) => d.state === 'disabled')} disabled</Badge>}
            <Badge tone={count((d) => !!d.update) ? 'amber' : 'green'}>{count((d) => !!d.update) ? `${count((d) => !!d.update)} updates waiting` : 'All firmware up to date'}</Badge>
          </div>
          <Card padded={false}>
            {data.length === 0 ? (
              <EmptyState title="No UniFi devices reported" />
            ) : (
              <ul className="divide-y divide-line/60">
                {data.map((d) => (
                  <li key={d.mac}>
                    <button type="button" onClick={() => setOpen(d.mac)} className="flex w-full flex-wrap items-center gap-x-4 gap-y-1 px-4 py-3 text-left hover:bg-surface-2/60">
                      <span className={clsx('h-2.5 w-2.5 shrink-0 rounded-full', STATE[d.state].dot)} title={STATE[d.state].label} />
                      <span className="min-w-[10rem] flex-1">
                        <span className="block font-medium text-ink">{d.name}</span>
                        <span className="block text-xs text-ink-3">
                          {KIND_LABEL[d.kind]}
                          {d.model ? ` · ${d.model}` : ''}
                          {d.ip ? ` · ${d.ip}` : ''}
                        </span>
                      </span>
                      <span className="w-40 text-xs text-ink-2">
                        {d.state === 'online' ? (d.uptime ? `Up ${fmtDuration(d.uptime)}` : 'Online') : d.state === 'offline' && d.lastSeen ? `Offline · last seen ${timeAgo(d.lastSeen)}` : STATE[d.state].label}
                        {d.clients !== null && d.state === 'online' && <span className="block text-ink-3">{plural(d.clients, 'client')}</span>}
                      </span>
                      <span className="w-44 text-xs">
                        <span className="mono text-ink-2">{d.version ?? '—'}</span>
                        {d.update ? (
                          <span className="mt-0.5 flex items-center gap-1 text-amber-300">
                            <CircleArrowUp className="h-3.5 w-3.5" /> {d.update} available
                          </span>
                        ) : d.endOfLife ? (
                          <span className="mt-0.5 block text-amber-300">No more updates (end of life)</span>
                        ) : (
                          <span className="mt-0.5 block text-ink-3">Up to date</span>
                        )}
                      </span>
                      <span className="hidden w-56 truncate text-xs text-ink-3 lg:block">{uplinkText(d)}</span>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </>
      )}
    </div>
  );
}
