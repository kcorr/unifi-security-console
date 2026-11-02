import { useEffect, useMemo, useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router';
import clsx from 'clsx';
import { Activity, ArrowDown, ArrowUp, Cable, ChevronDown, ChevronUp, Columns3, Cpu, Flame, Gauge, Search, Thermometer, Users, Wifi, X } from 'lucide-react';
import { LIVE_RANGES, type ClientRow, type LiveRange, type LiveSample, type LiveTrend } from '@shared/types';
import { api } from '../lib/api';
import { useLive } from '../lib/live';
import { fmtBps, fmtBytes, fmtDuration, fmtNum, fmtTime, timeAgo } from '../lib/format';
import { ActionBadge, Bar, Card, CountryTag, DirectionBadge, EmptyState, PageHeader, Segmented, SEVERITY_HEX, Stat } from '../components/ui';
import { MetricLine, ThroughputChart } from '../components/charts';
import { ClientPanel } from '../components/ClientPanel';

const RANGE_LABEL: Record<LiveRange, string> = { '5m': '5 min', '30m': '30 min', '1h': '1 hour', '24h': '24 hours', '7d': '7 days', '30d': '30 days' };
const RANGE_MS: Record<LiveRange, number> = { '5m': 5 * 60e3, '30m': 30 * 60e3, '1h': 3600e3, '24h': 86400e3, '7d': 7 * 86400e3, '30d': 30 * 86400e3 };

/** A per-browser preference that survives reloads. Storage can be unavailable (private windows), so it never throws. */
function useStored<T>(key: string, initial: T): [T, (v: T) => void] {
  const [value, setValue] = useState<T>(() => {
    try {
      const s = localStorage.getItem(key);
      return s ? (JSON.parse(s) as T) : initial;
    } catch {
      return initial;
    }
  });
  const set = (next: T) => {
    setValue(next);
    try {
      localStorage.setItem(key, JSON.stringify(next));
    } catch {
      // Not remembered this time; the choice still applies now.
    }
  };
  return [value, set];
}

function describeBucket(ms: number): string {
  if (ms <= 5000) return 'every 5 seconds';
  if (ms < 3600e3) return `averaged per ${Math.round(ms / 60e3)} minutes`;
  return ms === 3600e3 ? 'averaged per hour' : `averaged per ${Math.round(ms / 3600e3)} hours`;
}

export function LivePage() {
  const live = useLive();
  const navigate = useNavigate();
  const clients = useQuery({ queryKey: ['live-clients'], queryFn: api.liveClients, refetchInterval: 10_000 });
  const [stored, setRange] = useStored<LiveRange>('live.range', '1h');
  const range: LiveRange = LIVE_RANGES.includes(stored) ? stored : '1h';
  const short = RANGE_MS[range] <= 3600e3;
  const trend = useQuery({ queryKey: ['live-trend', range], queryFn: () => api.liveTrend(range), refetchInterval: short ? 60_000 : 300_000 });
  const [network, setNetwork] = useState<string | null>(null);
  const [client, setClient] = useState<string | null>(null);
  const s = live.snapshot;
  const nets = clients.data?.networks ?? [];
  const maxNet = Math.max(1, ...nets.map((n) => n.rxBps + n.txBps));

  // Up to an hour the charts keep moving: the stored history plus every sample that arrived since it was fetched.
  const points: LiveSample[] = useMemo(() => {
    const base = trend.data?.points ?? [];
    if (!short) return base;
    const last = base[base.length - 1]?.t ?? 0;
    const cutoff = Date.now() - RANGE_MS[range];
    return [...base, ...live.samples.filter((x) => x.t > last)].filter((x) => x.t >= cutoff);
  }, [trend.data, live.samples, short, range]);
  const tick = (t: number) => (RANGE_MS[range] > 86400e3 ? new Date(t).toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) : fmtTime(t, false));
  const every = trend.data ? describeBucket(trend.data.bucketMs) : '';
  const enough = points.length > 1;

  return (
    <div className="space-y-5">
      <PageHeader
        icon={<Activity className="h-5 w-5" />}
        title="Live activity"
        subtitle="Throughput, gateway health, who is using the network and threats as they happen. Updates every 5 seconds; history is kept for 30 days."
        actions={<Segmented options={LIVE_RANGES.map((r) => ({ value: r, label: r }))} value={range} onChange={setRange} />}
      />
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-6">
        <Stat label={<><ArrowDown className="h-3.5 w-3.5 text-cyan-300" /> Download</>} value={fmtBps(s?.wan?.rxBps)} sub={s?.wan?.isp ?? undefined} />
        <Stat label={<><ArrowUp className="h-3.5 w-3.5 text-violet-300" /> Upload</>} value={fmtBps(s?.wan?.txBps)} sub={s?.wan?.ip ?? undefined} />
        <Stat label={<><Gauge className="h-3.5 w-3.5" /> Latency</>} value={s?.wan?.latencyMs != null ? `${s.wan.latencyMs} ms` : '—'} sub={s?.wan?.status ? `WAN ${s.wan.status}` : undefined} />
        <Stat label={<><Users className="h-3.5 w-3.5" /> Clients</>} value={fmtNum(s?.clients.total)} sub={s ? `${s.clients.wireless} Wi-Fi · ${s.clients.wired} wired` : undefined} />
        <Stat label={<><Cpu className="h-3.5 w-3.5" /> Gateway</>} value={s?.gateway?.cpu != null ? `${s.gateway.cpu}%` : '—'} sub={s?.gateway?.mem != null ? `${s.gateway.mem}% memory` : undefined}>
          <Bar className="mt-2" value={s?.gateway?.cpu ?? 0} max={100} color={(s?.gateway?.cpu ?? 0) > 80 ? '#f43f5e' : '#22d3ee'} />
        </Stat>
        <Stat label={<><Thermometer className="h-3.5 w-3.5" /> Temperature</>} value={s?.gateway?.tempC != null ? `${s.gateway.tempC}°C` : '—'} sub={s?.gateway?.uptime ? `Up ${fmtDuration(s.gateway.uptime)}` : undefined} />
      </div>

      {trend.data && <RangeSummary t={trend.data} />}

      <Card
        title="Internet throughput"
        subtitle={`Last ${RANGE_LABEL[range]}${every ? ` · ${every}` : ''}`}
        actions={
          <span className="flex items-center gap-3 text-xs text-ink-3">
            <span className="flex items-center gap-1">
              <span className="h-2 w-2 rounded-full bg-cyan-400" /> download
            </span>
            <span className="flex items-center gap-1">
              <span className="h-2 w-2 rounded-full bg-violet-400" /> upload
            </span>
          </span>
        }
      >
        {enough ? <ThroughputChart samples={points} tickFormat={tick} /> : <EmptyState title={trend.isLoading ? 'Loading…' : 'Collecting samples…'} />}
      </Card>

      <div className="grid gap-4 lg:grid-cols-3 [&>*]:min-w-0">
        <Card title="Latency to the internet">{enough ? <MetricLine samples={points} dataKey="latencyMs" seriesName="Latency" color="#fbbf24" format={(v) => `${Math.round(v)} ms`} tickFormat={tick} /> : <EmptyState title="Collecting…" />}</Card>
        <Card title="Gateway CPU">{enough ? <MetricLine samples={points} dataKey="cpu" seriesName="CPU" color="#34d399" format={(v) => `${Math.round(v)}%`} domain={[0, 100]} tickFormat={tick} /> : <EmptyState title="Collecting…" />}</Card>
        <Card title="Clients connected">{enough ? <MetricLine samples={points} dataKey="clients" seriesName="Clients" color="#60a5fa" format={(v) => fmtNum(Math.round(v))} tickFormat={tick} /> : <EmptyState title="Collecting…" />}</Card>
      </div>

      <div className="grid gap-4 xl:grid-cols-3 [&>*]:min-w-0">
        <Card title="Networks right now" subtitle="Click one to show only its devices below">
          {nets.length ? (
            <ul className="space-y-1">
              {nets.map((n) => (
                <li key={n.id}>
                  <button
                    type="button"
                    aria-pressed={network === n.id}
                    onClick={() => setNetwork(network === n.id ? null : n.id)}
                    className={clsx('w-full rounded-lg px-2 py-1.5 text-left transition-colors', network === n.id ? 'bg-cyan-500/10 ring-1 ring-cyan-500/40' : 'hover:bg-surface-2/60')}
                  >
                    <div className="flex items-baseline justify-between gap-2 text-sm">
                      <span className="min-w-0 truncate text-ink">
                        {n.name} <span className="text-xs text-ink-3">{n.vlan !== null ? `VLAN ${n.vlan}` : ''}</span>
                      </span>
                      <span className="shrink-0 text-xs text-ink-3">
                        {n.clients} clients · <span className="mono text-ink-2">{fmtBps(n.rxBps + n.txBps)}</span>
                      </span>
                    </div>
                    <Bar className="mt-1" value={n.rxBps + n.txBps} max={maxNet} />
                  </button>
                </li>
              ))}
            </ul>
          ) : (
            <EmptyState title="No client data" />
          )}
        </Card>

        <Card className="xl:col-span-2" title="Threat feed" subtitle="Detections stream in as the IPS reports them" icon={<Flame className="h-4 w-4" />} padded={false}>
          {live.threats.length ? (
            <ul className="max-h-[360px] divide-y divide-line/50 overflow-y-auto">
              {live.threats.slice(0, 40).map((e) => (
                <li key={e.id} className={clsx('flex cursor-pointer items-center gap-3 px-4 py-2 hover:bg-surface-2/50', live.freshIds.has(e.id) && 'flash-row')} onClick={() => navigate(`/threats?id=${encodeURIComponent(e.id)}`)}>
                  <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: SEVERITY_HEX[e.severity] }} />
                  <span className="w-12 shrink-0 text-xs text-ink-3 sm:w-16">{timeAgo(e.ts)}</span>
                  <span className="min-w-0 flex-1 truncate text-sm text-ink">{e.headline}</span>
                  {e.remoteCountry && <CountryTag code={e.remoteCountry} />}
                  <span className="mono hidden text-xs text-ink-3 md:inline">{e.remoteIp ?? (e.srcIp || e.local?.name)}</span>
                  {/* On a phone the name needs the room; the direction is on the detail page. */}
                  <span className="hidden sm:contents">
                    <DirectionBadge direction={e.direction} />
                  </span>
                  <ActionBadge action={e.action} />
                </li>
              ))}
            </ul>
          ) : (
            <EmptyState title="Waiting for detections…" />
          )}
        </Card>
      </div>

      <TopTalkers rows={clients.data?.clients ?? []} networks={nets.map((n) => ({ id: n.id, name: n.name }))} network={network} onNetwork={setNetwork} onOpen={setClient} />
      <ClientPanel mac={client} onClose={() => setClient(null)} />
    </div>
  );
}

/** The range at a glance: peaks (and when), data used, and how latency, CPU and clients behaved. */
function RangeSummary({ t }: { t: LiveTrend }) {
  const s = t.summary;
  const partial = s.since !== null && s.since > t.from + 2 * t.bucketMs;
  const when = (ts: number) => (t.to - t.from > 86400e3 ? fmtTime(ts) : fmtTime(ts, false));
  const items: [string, string, string | null][] = [
    ['Peak download', s.peakRx ? fmtBps(s.peakRx.bps) : '—', s.peakRx ? when(s.peakRx.t) : null],
    ['Peak upload', s.peakTx ? fmtBps(s.peakTx.bps) : '—', s.peakTx ? when(s.peakTx.t) : null],
    ['Data used', `↓ ${fmtBytes(s.rxBytes)}`, `↑ ${fmtBytes(s.txBytes)}`],
    ['Latency', s.avgLatency !== null ? `${Math.round(s.avgLatency)} ms avg` : '—', s.maxLatency !== null ? `max ${Math.round(s.maxLatency)} ms` : null],
    ['Gateway CPU', s.avgCpu !== null ? `${Math.round(s.avgCpu)}% avg` : '—', s.maxCpu !== null ? `max ${Math.round(s.maxCpu)}%` : null],
    ['Most clients', s.maxClients !== null ? fmtNum(Math.round(s.maxClients)) : '—', null],
  ];
  return (
    <div className="rounded-xl border border-line bg-surface/80 px-4 py-3">
      <div className="grid gap-x-6 gap-y-3 sm:grid-cols-3 xl:grid-cols-6">
        {items.map(([label, value, sub]) => (
          <div key={label} className="min-w-0">
            <div className="text-[11px] text-ink-3">{label}</div>
            <div className="mono truncate text-sm text-ink">{value}</div>
            {sub && <div className="truncate text-[11px] text-ink-3">{sub}</div>}
          </div>
        ))}
      </div>
      {partial && <p className="mt-2 text-[11px] text-ink-3">History starts {fmtTime(s.since)}: the app keeps 30 days from when it began collecting, so longer ranges fill in over time.</p>}
    </div>
  );
}

// ---------------------------------------------------------------------------------
// Top talkers: sortable, filterable, with a choice of columns
// ---------------------------------------------------------------------------------

type Col = 'network' | 'ip' | 'mac' | 'vendor' | 'down' | 'up' | 'day' | 'total' | 'link' | 'ssid' | 'uptime' | 'firstSeen';
type SortKey = Col | 'name' | 'now';
type Kind = 'all' | 'wifi' | 'wired' | 'guest';

const ipNum = (ip: string | null) => (ip && /^\d+\.\d+\.\d+\.\d+$/.test(ip) ? ip.split('.').reduce((a, o) => a * 256 + Number(o), 0) : Number.MAX_SAFE_INTEGER);

// Text columns sort A→Z first; numbers biggest first.
const COLUMNS: { key: Col; label: string; hint?: string; right?: boolean; text?: boolean; sort: (c: ClientRow) => number | string; cell: (c: ClientRow) => React.ReactNode }[] = [
  { key: 'network', label: 'Network', text: true, sort: (c) => c.network ?? '', cell: (c) => <span className="text-xs text-ink-2">{c.network ?? '—'}</span> },
  { key: 'ip', label: 'IP address', text: true, sort: (c) => ipNum(c.ip), cell: (c) => <span className="mono text-xs text-ink-2">{c.ip ?? '—'}</span> },
  { key: 'mac', label: 'MAC', text: true, sort: (c) => c.mac, cell: (c) => <span className="mono text-xs text-ink-3">{c.mac || '—'}</span> },
  { key: 'vendor', label: 'Maker', text: true, sort: (c) => c.oui ?? '', cell: (c) => <span className="text-xs text-ink-2">{c.oui ?? '—'}</span> },
  { key: 'down', label: 'Down now', right: true, sort: (c) => c.rxBps, cell: (c) => <span className="mono text-xs text-cyan-200">{fmtBps(c.rxBps)}</span> },
  { key: 'up', label: 'Up now', right: true, sort: (c) => c.txBps, cell: (c) => <span className="mono text-xs text-violet-200">{fmtBps(c.txBps)}</span> },
  {
    key: 'day',
    label: 'Last 24 h',
    hint: "Everything it downloaded and uploaded in the last 24 hours, from UniFi's hourly report (whole hours). It includes traffic to your own devices, so it can be higher than UniFi's \"24H Internet Activity\", which counts internet traffic only.",
    right: true,
    sort: (c) => (c.rx24h === null ? -1 : c.rx24h + (c.tx24h ?? 0)),
    cell: (c) =>
      c.rx24h === null ? (
        <span className="text-xs text-ink-3" title={c.rxBytes + c.txBytes === 0 ? 'UniFi reports no traffic for this device (common for wired devices it cannot see)' : 'No whole hour recorded yet'}>
          —
        </span>
      ) : (
        <span className="mono text-xs text-ink-2" title={`↓ ${fmtBytes(c.rx24h)} · ↑ ${fmtBytes(c.tx24h ?? 0)}`}>
          {fmtBytes(c.rx24h + (c.tx24h ?? 0))}
        </span>
      ),
  },
  {
    key: 'total',
    label: 'Since connected',
    hint: 'All traffic since the device last connected, which can be days ago.',
    right: true,
    sort: (c) => c.rxBytes + c.txBytes,
    cell: (c) => (
      <span className="mono text-xs text-ink-3" title={`↓ ${fmtBytes(c.rxBytes)} · ↑ ${fmtBytes(c.txBytes)}`}>
        {fmtBytes(c.rxBytes + c.txBytes)}
        {c.uptime != null && <span className="font-sans"> · {fmtDuration(c.uptime)}</span>}
      </span>
    ),
  },
  {
    key: 'link',
    label: 'Link',
    sort: (c) => (c.wired ? 1000 : 0) + (c.signal ?? -200),
    cell: (c) =>
      c.wired ? (
        <span className="flex items-center gap-1 text-xs text-ink-3">
          <Cable className="h-3.5 w-3.5" /> wired
        </span>
      ) : (
        <span className="flex items-center gap-1 text-xs text-ink-3">
          <Wifi className="h-3.5 w-3.5" /> {c.signal != null ? `${c.signal} dBm` : 'Wi-Fi'}
        </span>
      ),
  },
  { key: 'ssid', label: 'Wi-Fi name', text: true, sort: (c) => c.essid ?? '', cell: (c) => <span className="text-xs text-ink-2">{c.essid ?? '—'}</span> },
  { key: 'uptime', label: 'Connected for', right: true, sort: (c) => c.uptime ?? -1, cell: (c) => <span className="text-xs text-ink-3">{c.uptime != null ? fmtDuration(c.uptime) : '—'}</span> },
  { key: 'firstSeen', label: 'First seen', right: true, sort: (c) => c.firstSeen ?? 0, cell: (c) => <span className="text-xs text-ink-3">{c.firstSeen ? timeAgo(c.firstSeen) : '—'}</span> },
];
const DEFAULT_COLS: Col[] = ['network', 'down', 'up', 'day', 'link'];
const ROW_CHOICES = [12, 25, 50, 0] as const; // 0 = all

function TopTalkers(props: { rows: ClientRow[]; networks: { id: string; name: string }[]; network: string | null; onNetwork: (id: string | null) => void; onOpen: (mac: string) => void }) {
  const [q, setQ] = useState('');
  const [kind, setKind] = useState<Kind>('all');
  const [cols, setCols] = useStored<Col[]>('live.talkers.cols', DEFAULT_COLS);
  const [sort, setSort] = useStored<{ key: SortKey; dir: 'asc' | 'desc' }>('live.talkers.sort', { key: 'now', dir: 'desc' });
  const [limit, setLimit] = useStored<number>('live.talkers.rows', 12);
  const visible = COLUMNS.filter((c) => cols.includes(c.key));

  const filtered = useMemo(() => {
    const ql = q.trim().toLowerCase();
    return props.rows.filter(
      (c) =>
        (!props.network || c.networkId === props.network) &&
        (kind === 'all' || (kind === 'wired' ? c.wired : kind === 'wifi' ? !c.wired : c.guest)) &&
        (!ql || [c.name, c.ip, c.mac, c.oui, c.essid, c.network].some((v) => v?.toLowerCase().includes(ql))),
    );
  }, [props.rows, props.network, kind, q]);

  const sorted = useMemo(() => {
    const keyOf =
      sort.key === 'now' ? (c: ClientRow) => c.rxBps + c.txBps : sort.key === 'name' ? (c: ClientRow) => c.name.toLowerCase() : (COLUMNS.find((x) => x.key === sort.key)?.sort ?? ((c: ClientRow) => c.rxBps + c.txBps));
    const dir = sort.dir === 'asc' ? 1 : -1;
    return [...filtered].sort((a, b) => {
      const x = keyOf(a);
      const y = keyOf(b);
      return (typeof x === 'string' ? x.localeCompare(String(y)) : x - (y as number)) * dir;
    });
  }, [filtered, sort]);
  const shown = limit ? sorted.slice(0, limit) : sorted;
  const filtering = !!q || kind !== 'all' || !!props.network;

  const header = (key: SortKey, label: string, right?: boolean, first?: boolean, hint?: string) => {
    const active = sort.key === key;
    return (
      <th key={key} title={hint} aria-sort={active ? (sort.dir === 'asc' ? 'ascending' : 'descending') : 'none'} className={clsx('py-2 font-medium', first ? 'px-4' : 'px-2', right && 'text-right')}>
        <button
          type="button"
          onClick={() => setSort({ key, dir: active ? (sort.dir === 'desc' ? 'asc' : 'desc') : key === 'name' || COLUMNS.find((c) => c.key === key)?.text ? 'asc' : 'desc' })}
          className={clsx('inline-flex items-center gap-1 hover:text-ink-2', active && 'text-ink-2')}
        >
          {label}
          {active && (sort.dir === 'asc' ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />)}
        </button>
      </th>
    );
  };

  return (
    <Card title="Top talkers" subtitle="Who is using the network right now. Click a column to sort; click a device for everything about it." padded={false}>
      <div className="flex flex-wrap items-center gap-2 border-b border-line/60 px-4 py-3">
        <div className="relative w-full sm:w-64">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-ink-3" />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Name, IP, MAC, maker…"
            aria-label="Search devices"
            className="h-8 w-full rounded-lg border border-line bg-surface-2 pl-9 pr-3 text-sm text-ink placeholder:text-ink-3 focus:border-cyan-500/50 focus:outline-none"
          />
        </div>
        <select
          value={props.network ?? ''}
          onChange={(e) => props.onNetwork(e.target.value || null)}
          aria-label="Filter by network"
          className="h-8 rounded-lg border border-line bg-surface-2 px-2 text-xs text-ink focus:border-cyan-500/50 focus:outline-none"
        >
          <option value="">All networks</option>
          {props.networks.map((n) => (
            <option key={n.id} value={n.id}>
              {n.name}
            </option>
          ))}
        </select>
        <Segmented
          size="sm"
          value={kind}
          onChange={setKind}
          options={[
            { value: 'all', label: 'All' },
            { value: 'wifi', label: 'Wi-Fi' },
            { value: 'wired', label: 'Wired' },
            { value: 'guest', label: 'Guests' },
          ]}
        />
        <ColumnPicker cols={cols} onChange={setCols} />
        <select
          value={limit}
          onChange={(e) => setLimit(Number(e.target.value))}
          aria-label="Rows to show"
          className="h-8 rounded-lg border border-line bg-surface-2 px-2 text-xs text-ink focus:border-cyan-500/50 focus:outline-none"
        >
          {ROW_CHOICES.map((n) => (
            <option key={n} value={n}>
              {n ? `Top ${n}` : 'All'}
            </option>
          ))}
        </select>
        <span className="ml-auto text-xs text-ink-3">
          {shown.length} of {filtered.length}
          {filtering && ` (of ${props.rows.length})`} devices
          {filtering && (
            <button
              type="button"
              onClick={() => {
                setQ('');
                setKind('all');
                props.onNetwork(null);
              }}
              className="ml-2 inline-flex items-center gap-0.5 text-cyan-300 hover:text-cyan-200"
            >
              <X className="h-3 w-3" /> clear
            </button>
          )}
        </span>
      </div>
      {shown.length ? (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-line text-left text-xs text-ink-3">
                {header('name', 'Device', false, true)}
                {visible.map((c) => header(c.key, c.label, c.right, false, c.hint))}
              </tr>
            </thead>
            <tbody className="divide-y divide-line/50">
              {shown.map((c) => (
                <tr key={c.mac || c.name} className={clsx('hover:bg-surface-2/50', c.mac && 'cursor-pointer')} onClick={() => c.mac && props.onOpen(c.mac)}>
                  <td className="px-4 py-2">
                    <div className="font-medium text-ink">{c.name}</div>
                    {!cols.includes('ip') && !cols.includes('vendor') && (
                      <div className="mono text-[11px] text-ink-3">
                        {c.ip ?? '—'} {c.oui ? <span className="font-sans">· {c.oui}</span> : null}
                      </div>
                    )}
                  </td>
                  {visible.map((col) => (
                    <td key={col.key} className={clsx('whitespace-nowrap px-2 py-2', col.right && 'text-right')}>
                      {col.cell(c)}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <EmptyState title={props.rows.length ? 'No devices match these filters' : 'No clients'} />
      )}
    </Card>
  );
}

function ColumnPicker({ cols, onChange }: { cols: Col[]; onChange: (c: Col[]) => void }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const close = (e: MouseEvent) => !ref.current?.contains(e.target as Node) && setOpen(false);
    document.addEventListener('mousedown', close);
    return () => document.removeEventListener('mousedown', close);
  }, [open]);
  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
        className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-line bg-surface-2 px-2.5 text-xs text-ink-2 hover:text-ink"
      >
        <Columns3 className="h-3.5 w-3.5" /> Columns
      </button>
      {open && (
        <div className="absolute left-0 z-20 mt-1 w-52 rounded-lg border border-line-2 bg-[#0f1729] p-2 shadow-xl">
          {COLUMNS.map((c) => (
            <label key={c.key} className="flex cursor-pointer items-center gap-2 rounded px-2 py-1 text-xs text-ink-2 hover:bg-surface-3">
              <input
                type="checkbox"
                className="accent-cyan-400"
                checked={cols.includes(c.key)}
                onChange={() => onChange(cols.includes(c.key) ? cols.filter((x) => x !== c.key) : COLUMNS.map((x) => x.key).filter((k) => k === c.key || cols.includes(k)))}
              />
              {c.label}
            </label>
          ))}
          <button type="button" onClick={() => onChange(DEFAULT_COLS)} className="mt-1 w-full rounded px-2 py-1 text-left text-[11px] text-ink-3 hover:bg-surface-3 hover:text-ink-2">
            Reset to default
          </button>
        </div>
      )}
    </div>
  );
}
