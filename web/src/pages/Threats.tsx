import { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router';
import { keepPreviousData, useQuery } from '@tanstack/react-query';
import clsx from 'clsx';
import { Ban, BookOpen, ChevronDown, ExternalLink, Flame, Globe, Radar, ScanSearch, Search, ShieldAlert, ShieldCheck, SlidersHorizontal, Target, X } from 'lucide-react';
import type { IpIntel, Severity, ThreatCategory, ThreatDirection, ThreatEvent, ThreatSummary } from '@shared/types';
import { api } from '../lib/api';
import { useLive } from '../lib/live';
import { countryName, fmtNum, fmtTime, timeAgo } from '../lib/format';
import {
  ActionBadge, Badge, Button, Callout, Card, CountryTag, DirectionBadge, Drawer, EmptyState, ErrorBox, EventEnd, InfoTip, IpLink, KV, Loading, PageHeader, Segmented, SEVERITY_HEX, SeverityBadge, Tabs,
  VerdictBadge,
} from '../components/ui';
import { HBarList, ThreatTimeline } from '../components/charts';
import { WorldMap } from '../components/WorldMap';
import { useFix } from '../components/FixFlow';

const RANGES = { '1h': 3600e3, '24h': 86400e3, '7d': 7 * 86400e3, '30d': 30 * 86400e3 } as const;
type RangeKey = keyof typeof RANGES;
type TabKey = 'events' | 'attackers' | 'signatures' | 'targets' | 'map';

export function ThreatsPage() {
  const [sp, setSp] = useSearchParams();
  const [range, setRange] = useState<RangeKey>((sp.get('range') as RangeKey) || '24h');
  const [sev, setSev] = useState<Severity[]>([]);
  const [dir, setDir] = useState<ThreatDirection[]>([]);
  const [action, setAction] = useState<('blocked' | 'alerted')[]>([]);
  const [tab, setTab] = useState<TabKey>('events');
  const [search, setSearch] = useState(sp.get('q') ?? '');
  const [page, setPage] = useState(0);
  const [filtersOpen, setFiltersOpen] = useState(false);
  // Remembered per browser: whoever likes the charts keeps seeing them.
  const [showCharts, setShowCharts] = useState(() => {
    try {
      return localStorage.getItem('threats.charts') === '1';
    } catch {
      return false;
    }
  });
  const toggleCharts = () =>
    setShowCharts((v) => {
      try {
        localStorage.setItem('threats.charts', v ? '0' : '1');
      } catch {
        // Storage can be unavailable (private window); the toggle still works for this visit.
      }
      return !v;
    });
  const category = sp.get('category') ?? undefined;
  const ip = sp.get('ip') ?? undefined;
  const openId = sp.get('id');
  const live = useLive();
  const fix = useFix();
  const cats = useQuery({ queryKey: ['threat-categories'], queryFn: api.threatCategories, staleTime: Infinity });

  // A minute-granular "now" keeps query keys stable between renders.
  const [now, setNow] = useState(() => Math.floor(Date.now() / 60e3) * 60e3 + 60e3);
  useEffect(() => {
    const t = setInterval(() => setNow(Math.floor(Date.now() / 60e3) * 60e3 + 60e3), 60e3);
    return () => clearInterval(t);
  }, []);
  useEffect(() => setPage(0), [range, sev, dir, action, category, ip, search]);

  const q = { from: now - RANGES[range], to: now, severity: sev, direction: dir, action, category: category ? [category] : undefined, ip, q: search || undefined };
  const summary = useQuery({ queryKey: ['threats', 'summary', q, live.threats[0]?.id], queryFn: () => api.threatSummary(q), placeholderData: keepPreviousData });
  const events = useQuery({ queryKey: ['threats', 'list', q, page, live.threats[0]?.id], queryFn: () => api.threats({ ...q, limit: 50, offset: page * 50 }), placeholderData: keepPreviousData });
  const selected = useQuery({ queryKey: ['threat', openId], queryFn: () => api.threat(openId!), enabled: !!openId });

  const setParam = (k: string, v: string | null) => {
    const next = new URLSearchParams(sp);
    if (v) next.set(k, v);
    else next.delete(k);
    setSp(next, { replace: true });
  };
  const toggle = <T,>(list: T[], v: T, set: (x: T[]) => void) => set(list.includes(v) ? list.filter((x) => x !== v) : [...list, v]);
  const activeCount = sev.length + dir.length + action.length + (category ? 1 : 0) + (ip ? 1 : 0);
  const clearFilters = () => {
    setSev([]);
    setDir([]);
    setAction([]);
    const next = new URLSearchParams(sp);
    next.delete('category');
    next.delete('ip');
    setSp(next, { replace: true });
  };
  const s = summary.data;
  const catName = (k: string) => cats.data?.find((c) => c.key === k)?.name ?? k;

  return (
    <div className="space-y-5">
      {fix.node}
      <PageHeader
        icon={<Flame className="h-5 w-5" />}
        title="Threats"
        subtitle="Every detection from your intrusion prevention system — explained, with who is behind it and what it was aiming at."
        actions={<Segmented options={(Object.keys(RANGES) as RangeKey[]).map((r) => ({ value: r, label: r }))} value={range} onChange={setRange} />}
      />

      <div className="flex flex-wrap items-center gap-2">
        <div className="relative w-full sm:max-w-xs">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-ink-3" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Signature, IP, device…"
            className="h-8 w-full rounded-lg border border-line bg-surface-2 pl-9 pr-3 text-sm text-ink placeholder:text-ink-3 focus:border-cyan-500/50 focus:outline-none"
          />
        </div>
        <Button size="sm" variant={filtersOpen ? 'secondary' : 'ghost'} icon={<SlidersHorizontal className="h-3.5 w-3.5" />} aria-expanded={filtersOpen} onClick={() => setFiltersOpen((o) => !o)}>
          Filter{activeCount ? ` · ${activeCount}` : ''}
        </Button>
        {sev.map((x) => (
          <ActiveFilter key={x} onRemove={() => toggle(sev, x, setSev)}>
            {x}
          </ActiveFilter>
        ))}
        {dir.map((x) => (
          <ActiveFilter key={x} onRemove={() => toggle(dir, x, setDir)}>
            {x}
          </ActiveFilter>
        ))}
        {action.map((x) => (
          <ActiveFilter key={x} onRemove={() => toggle(action, x, setAction)}>
            {x === 'alerted' ? 'allowed through' : x}
          </ActiveFilter>
        ))}
        {category && <ActiveFilter onRemove={() => setParam('category', null)}>{catName(category)}</ActiveFilter>}
        {ip && <ActiveFilter onRemove={() => setParam('ip', null)}>IP {ip}</ActiveFilter>}
        {activeCount > 1 && (
          <button type="button" onClick={clearFilters} className="text-xs text-ink-3 hover:text-ink-2">
            Clear all
          </button>
        )}
      </div>
      {filtersOpen && (
        <div className="flex flex-wrap items-center gap-2 rounded-xl border border-line bg-surface-2/40 p-3">
          <span className="w-full text-[11px] font-semibold uppercase tracking-wider text-ink-3 sm:w-auto">Severity</span>
          {(['critical', 'high', 'medium', 'low', 'info'] as Severity[]).map((x) => (
            <Chip key={x} on={sev.includes(x)} onClick={() => toggle(sev, x, setSev)} dot={SEVERITY_HEX[x]}>
              {x}
            </Chip>
          ))}
          <span className="mx-1 hidden h-5 w-px bg-line sm:block" />
          <span className="w-full text-[11px] font-semibold uppercase tracking-wider text-ink-3 sm:w-auto">Direction</span>
          {(['inbound', 'outbound', 'internal'] as ThreatDirection[]).map((x) => (
            <Chip key={x} on={dir.includes(x)} onClick={() => toggle(dir, x, setDir)}>
              {x}
            </Chip>
          ))}
          <span className="mx-1 hidden h-5 w-px bg-line sm:block" />
          <span className="w-full text-[11px] font-semibold uppercase tracking-wider text-ink-3 sm:w-auto">Result</span>
          <Chip on={action.includes('blocked')} onClick={() => toggle(action, 'blocked', setAction)}>
            blocked
          </Chip>
          <Chip on={action.includes('alerted')} onClick={() => toggle(action, 'alerted', setAction)}>
            allowed through
          </Chip>
        </div>
      )}

      {summary.error && <ErrorBox error={summary.error} />}
      {!s && summary.isLoading && <Loading />}
      {s && (
        <>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
            <SummaryLine s={s} />
            <button type="button" onClick={toggleCharts} aria-expanded={showCharts} className="ml-auto inline-flex items-center gap-1 text-xs text-ink-3 hover:text-ink-2">
              <ChevronDown className={clsx('h-3.5 w-3.5 transition-transform', showCharts && 'rotate-180')} />
              {showCharts ? 'Hide' : 'Show'} trend and threat types
            </button>
          </div>

          {s.suspects.length > 0 && (
            <div className="rounded-xl border border-rose-500/30 bg-rose-500/5 p-4">
              <div className="mb-2 flex items-center gap-2 text-sm font-medium text-rose-200">
                <ShieldAlert className="h-4 w-4" /> Devices on your network behaving like they are compromised
              </div>
              <div className="flex flex-wrap gap-2">
                {s.suspects.map((x) => (
                  <Link key={x.ip} to={`/investigate/${encodeURIComponent(x.ip)}`} className="rounded-lg border border-rose-500/30 bg-surface/70 px-3 py-2 text-sm hover:border-rose-400/60">
                    <div className="font-medium text-ink">{x.name ?? x.ip}</div>
                    <div className="text-xs text-ink-3">
                      {x.ip}
                      {x.network ? ` · ${x.network}` : ''} · {x.count} detection{x.count === 1 ? '' : 's'} · {x.categories.map(catName).join(', ')}
                    </div>
                  </Link>
                ))}
              </div>
            </div>
          )}

          {showCharts && <div className="grid gap-4 xl:grid-cols-3 [&>*]:min-w-0">
            <Card className="xl:col-span-2" title="Detections over time" subtitle={`Stacked by severity · ${s.bucketMs >= 86400e3 ? 'daily' : s.bucketMs >= 3600e3 ? `${s.bucketMs / 3600e3}-hour` : `${s.bucketMs / 60e3}-minute`} buckets`}>
              <ThreatTimeline summary={s} />
            </Card>
            <Card title="By threat type" subtitle="Click a type to filter. ⓘ explains it.">
              <CategoryBars s={s} cats={cats.data ?? []} onPick={(k) => setParam('category', k)} />
            </Card>
          </div>}

          <Card padded={false}>
            <Tabs
              className="px-2"
              value={tab}
              onChange={setTab}
              tabs={[
                { id: 'events', label: 'Events', count: events.data?.total ?? null, icon: <Flame className="h-4 w-4" /> },
                { id: 'attackers', label: 'Sources', count: s.topSources.length, icon: <Radar className="h-4 w-4" /> },
                { id: 'signatures', label: 'Signatures', count: s.topSignatures.length, icon: <BookOpen className="h-4 w-4" /> },
                { id: 'targets', label: 'Your targeted devices', count: s.topTargets.length, icon: <Target className="h-4 w-4" /> },
                { id: 'map', label: 'Map', icon: <Globe className="h-4 w-4" /> },
              ]}
            />
            {tab === 'events' && (
              <EventsTable
                events={events.data?.events ?? []}
                total={events.data?.total ?? 0}
                page={page}
                onPage={setPage}
                loading={events.isFetching}
                fresh={live.freshIds}
                onOpen={(id) => setParam('id', id)}
                catName={catName}
              />
            )}
            {tab === 'attackers' && <SourcesTable s={s} onBlock={(addr) => fix.open({ templateId: 'block-ip', params: { ips: [addr], direction: 'both' }, label: `Block ${addr}` })} catName={catName} onFilter={(x) => setParam('ip', x)} />}
            {tab === 'signatures' && <SignaturesTable s={s} catName={catName} onSearch={(x) => setSearch(x)} />}
            {tab === 'targets' && <TargetsTable s={s} onFilter={(x) => setParam('ip', x)} />}
            {tab === 'map' && (
              <div className="p-4">
                <WorldMap data={s.byCountry} />
                <div className="mt-3 flex flex-wrap gap-2 text-xs text-ink-3">
                  {s.byCountry.slice(0, 12).map((c) => (
                    <span key={c.country} className="rounded-md bg-surface-2 px-2 py-1">
                      {countryName(c.country)} · {fmtNum(c.count)}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </Card>
        </>
      )}

      <ThreatDrawer
        event={selected.data ?? null}
        open={!!openId}
        onClose={() => setParam('id', null)}
        category={cats.data?.find((c) => c.key === selected.data?.categoryKey) ?? null}
        onBlock={(addr) => fix.open({ templateId: 'block-ip', params: { ips: [addr], direction: 'both' }, label: `Block ${addr}` })}
      />
    </div>
  );
}

/** "8 detections from 3 sources · all blocked · none from your devices": the tiles' numbers as one sentence. */
function SummaryLine({ s }: { s: ThreatSummary }) {
  const fromYou = s.byDirection.outbound + s.byDirection.internal;
  const serious = s.bySeverity.critical + s.bySeverity.high;
  const sep = <span className="text-ink-3">·</span>;
  return (
    <p className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm">
      <span className="font-medium text-ink">
        {fmtNum(s.total)} detection{s.total === 1 ? '' : 's'}
      </span>
      <span className="text-ink-3">
        from {fmtNum(s.uniqueSources)} source{s.uniqueSources === 1 ? '' : 's'}
      </span>
      {s.total > 0 && (
        <>
          {sep}
          {s.alerted ? (
            <span className="flex items-center gap-1 text-amber-300">
              {fmtNum(s.alerted)} allowed through
              <InfoTip>Detected but not blocked: the IPS is in "Notify" mode for these, or the category is not set to block. The traffic reached its target.</InfoTip>
            </span>
          ) : (
            <span className="text-emerald-300">{s.blocked === s.total ? 'all blocked' : `${fmtNum(s.blocked)} blocked`}</span>
          )}
          {sep}
          <span className={fromYou ? 'text-violet-300' : 'text-ink-2'}>{fromYou ? `${fmtNum(fromYou)} from your own devices` : 'none from your devices'}</span>
          {serious > 0 && (
            <>
              {sep}
              <span className="text-rose-300">{fmtNum(serious)} critical or high</span>
            </>
          )}
        </>
      )}
    </p>
  );
}

function ActiveFilter({ onRemove, children }: { onRemove: () => void; children: React.ReactNode }) {
  return (
    <button type="button" title="Remove this filter" onClick={onRemove} className="inline-flex h-7 items-center gap-1 rounded-md border border-cyan-500/40 bg-cyan-500/10 px-2 text-xs capitalize text-cyan-100 hover:border-cyan-400/60">
      {children}
      <X className="h-3 w-3" />
    </button>
  );
}

function Chip({ on, onClick, children, dot }: { on: boolean; onClick: () => void; children: React.ReactNode; dot?: string }) {
  return (
    <button
      type="button"
      aria-pressed={on}
      onClick={onClick}
      className={clsx(
        'inline-flex h-7 items-center gap-1.5 rounded-md border px-2.5 text-xs capitalize transition-colors',
        on ? 'border-cyan-500/50 bg-cyan-500/10 text-ink' : 'border-line bg-surface-2 text-ink-3 hover:text-ink-2',
      )}
    >
      {dot && <span className="h-1.5 w-1.5 rounded-full" style={{ background: dot }} />}
      {children}
    </button>
  );
}

function CategoryBars({ s, cats, onPick }: { s: ThreatSummary; cats: ThreatCategory[]; onPick: (k: string) => void }) {
  if (!s.byCategory.length) return <div className="text-sm text-ink-3">No detections.</div>;
  const max = Math.max(...s.byCategory.map((c) => c.count));
  return (
    <ul className="space-y-2.5">
      {s.byCategory.slice(0, 9).map((c) => {
        const cat = cats.find((x) => x.key === c.key);
        return (
          <li key={c.key}>
            <div className="flex items-center justify-between gap-2 text-sm">
              <button className="flex min-w-0 items-center gap-1.5 truncate text-left text-ink-2 hover:text-cyan-200" onClick={() => onPick(c.key)}>
                <span className="h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: SEVERITY_HEX[c.severity] }} />
                <span className="truncate">{c.name}</span>
              </button>
              <span className="flex shrink-0 items-center gap-2">
                {cat && (
                  <InfoTip wide>
                    <div className="mb-1 font-medium text-ink">{cat.name}</div>
                    {cat.summary}
                    <div className="mt-1.5 text-ink-3">{cat.whyItMatters}</div>
                  </InfoTip>
                )}
                <span className="mono text-xs text-ink">{fmtNum(c.count)}</span>
              </span>
            </div>
            <div className="mt-1 flex h-1.5 overflow-hidden rounded-full bg-slate-800/80">
              <div className="h-full bg-emerald-500/70" style={{ width: `${(c.blocked / max) * 100}%` }} title={`${c.blocked} blocked`} />
              <div className="h-full bg-amber-400/80" style={{ width: `${((c.count - c.blocked) / max) * 100}%` }} title={`${c.count - c.blocked} allowed`} />
            </div>
          </li>
        );
      })}
      <li className="flex gap-3 pt-1 text-[11px] text-ink-3">
        <span className="flex items-center gap-1">
          <span className="h-2 w-2 rounded-sm bg-emerald-500/70" /> blocked
        </span>
        <span className="flex items-center gap-1">
          <span className="h-2 w-2 rounded-sm bg-amber-400/80" /> allowed through
        </span>
      </li>
    </ul>
  );
}

function EventsTable(props: { events: ThreatEvent[]; total: number; page: number; onPage: (p: number) => void; loading: boolean; fresh: Set<string>; onOpen: (id: string) => void; catName: (k: string) => string }) {
  const { events, total, page } = props;
  if (!events.length) return <EmptyState icon={<Flame className="h-8 w-8" />} title={props.loading ? 'Loading…' : 'No detections match these filters'} />;
  return (
    <div>
      <ul className="divide-y divide-line/50 sm:hidden">
        {events.map((e) => (
          <li key={e.id} onClick={() => props.onOpen(e.id)} className={clsx('cursor-pointer px-4 py-3 hover:bg-surface-2/60', props.fresh.has(e.id) && 'flash-row')}>
            <div className="flex items-center gap-2">
              <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: SEVERITY_HEX[e.severity] }} />
              <span className="min-w-0 flex-1 truncate text-sm font-medium text-ink">{e.headline}</span>
              <span className="shrink-0 text-xs text-ink-3">{timeAgo(e.ts)}</span>
            </div>
            <div className="mt-1 flex min-w-0 items-center gap-1.5 pl-4 text-xs text-ink-3">
              <EventEnd e={e} ip={e.srcIp} /> <span className="shrink-0">→</span> <EventEnd e={e} ip={e.dstIp} />
            </div>
            <div className="mt-1.5 flex flex-wrap gap-1.5 pl-4">
              <DirectionBadge direction={e.direction} />
              <ActionBadge action={e.action} />
              {e.count > 1 && <Badge tone="slate">×{e.count}</Badge>}
            </div>
          </li>
        ))}
      </ul>
      <div className="hidden overflow-x-auto sm:block">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-line text-left text-xs text-ink-3">
              <th className="px-4 py-2 font-medium">When</th>
              <th className="px-2 py-2 font-medium">Threat</th>
              <th className="px-2 py-2 font-medium">From → To</th>
              <th className="px-2 py-2 font-medium">Direction</th>
              <th className="px-2 py-2 font-medium">Result</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line/50">
            {events.map((e) => (
              <tr key={e.id} onClick={() => props.onOpen(e.id)} className={clsx('cursor-pointer hover:bg-surface-2/60', props.fresh.has(e.id) && 'flash-row')}>
                <td className="whitespace-nowrap px-4 py-2.5 text-xs text-ink-3" title={fmtTime(e.ts)}>
                  {timeAgo(e.ts)}
                </td>
                <td className="max-w-[420px] px-2 py-2.5">
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={e.severity} />
                    <span className="truncate font-medium text-ink">{e.headline}</span>
                    {e.count > 1 && <Badge tone="slate">×{e.count}</Badge>}
                  </div>
                  <div className="mt-0.5 truncate text-xs text-ink-3" title={e.signature}>
                    {props.catName(e.categoryKey)} · {e.signature}
                  </div>
                </td>
                <td className="px-2 py-2.5 text-xs">
                  <div className="flex items-center gap-1.5">
                    {e.direction === 'inbound' && e.remoteCountry && <CountryTag code={e.remoteCountry} />}
                    <span className="mono text-ink-2">{e.srcIp}</span>
                    {e.srcPort ? <span className="text-ink-3">:{e.srcPort}</span> : null}
                  </div>
                  <div className="flex items-center gap-1.5 text-ink-3">
                    → {e.direction !== 'inbound' && e.remoteCountry && <CountryTag code={e.remoteCountry} />}
                    <span className={clsx(e.local && e.localIp === e.dstIp ? 'text-ink-2' : 'mono')}>{e.local && e.localIp === e.dstIp && e.local.name ? e.local.name : e.dstIp}</span>
                    {e.dstPort ? <span>:{e.dstPort}</span> : null}
                  </div>
                </td>
                <td className="px-2 py-2.5">
                  <DirectionBadge direction={e.direction} />
                </td>
                <td className="px-2 py-2.5">
                  <ActionBadge action={e.action} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="flex items-center justify-between border-t border-line px-4 py-2.5 text-xs text-ink-3">
        <span>
          {fmtNum(page * 50 + 1)}–{fmtNum(Math.min(total, (page + 1) * 50))} of {fmtNum(total)}
        </span>
        <div className="flex gap-2">
          <Button size="xs" variant="secondary" disabled={page === 0} onClick={() => props.onPage(page - 1)}>
            Previous
          </Button>
          <Button size="xs" variant="secondary" disabled={(page + 1) * 50 >= total} onClick={() => props.onPage(page + 1)}>
            Next
          </Button>
        </div>
      </div>
    </div>
  );
}

function SourcesTable({ s, onBlock, catName, onFilter }: { s: ThreatSummary; onBlock: (ip: string) => void; catName: (k: string) => string; onFilter: (ip: string) => void }) {
  if (!s.topSources.length) return <EmptyState title="No sources" />;
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-line text-left text-xs text-ink-3">
            <th className="px-4 py-2 font-medium">Source</th>
            <th className="px-2 py-2 font-medium">Owner</th>
            <th className="px-2 py-2 font-medium">Types</th>
            <th className="px-2 py-2 text-right font-medium">Detections</th>
            <th className="px-2 py-2 font-medium">Last seen</th>
            <th className="px-4 py-2" />
          </tr>
        </thead>
        <tbody className="divide-y divide-line/50">
          {s.topSources.map((x) => (
            <tr key={x.ip} className="hover:bg-surface-2/40">
              <td className="px-4 py-2.5">
                <div className="flex items-center gap-2">
                  <CountryTag code={x.country} />
                  <IpLink ip={x.ip} />
                  <SeverityBadge severity={x.severity} />
                </div>
              </td>
              <td className="max-w-[240px] truncate px-2 py-2.5 text-xs text-ink-2">{x.org ?? (x.direction === 'inbound' ? '—' : 'Your network')}</td>
              <td className="px-2 py-2.5 text-xs text-ink-3">{x.categories.map(catName).join(', ')}</td>
              <td className="px-2 py-2.5 text-right">
                <span className="mono text-ink">{fmtNum(x.count)}</span>
                <div className="text-[11px] text-ink-3">{x.blocked ? `${fmtNum(x.blocked)} blocked` : 'none blocked'}</div>
              </td>
              <td className="whitespace-nowrap px-2 py-2.5 text-xs text-ink-3">{timeAgo(x.lastSeen)}</td>
              <td className="whitespace-nowrap px-4 py-2.5 text-right">
                <div className="flex justify-end gap-1.5">
                  <Button size="xs" variant="ghost" onClick={() => onFilter(x.ip)}>
                    Events
                  </Button>
                  <Link to={`/investigate/${encodeURIComponent(x.ip)}`} className="inline-flex h-6 items-center gap-1 rounded-lg border border-line-2 px-2 text-xs text-ink-2 hover:bg-surface-3">
                    <ScanSearch className="h-3 w-3" /> Investigate
                  </Link>
                  {x.direction === 'inbound' && (
                    <Button size="xs" variant="secondary" icon={<Ban className="h-3 w-3" />} onClick={() => onBlock(x.ip)}>
                      Block
                    </Button>
                  )}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function SignaturesTable({ s, catName, onSearch }: { s: ThreatSummary; catName: (k: string) => string; onSearch: (sig: string) => void }) {
  return (
    <ul className="divide-y divide-line/50">
      {s.topSignatures.map((x) => (
        <li key={x.signature} className="flex cursor-pointer items-center gap-3 px-4 py-2.5 hover:bg-surface-2/40" onClick={() => onSearch(x.signature)}>
          <SeverityBadge severity={x.severity} />
          <div className="min-w-0 flex-1">
            <div className="truncate text-sm text-ink">{x.headline}</div>
            <div className="truncate text-xs text-ink-3">
              {catName(x.categoryKey)} · {x.signature}
            </div>
          </div>
          <div className="text-right">
            <div className="mono text-sm text-ink">{fmtNum(x.count)}</div>
            <div className="text-[11px] text-ink-3">{timeAgo(x.lastSeen)}</div>
          </div>
        </li>
      ))}
    </ul>
  );
}

function TargetsTable({ s, onFilter }: { s: ThreatSummary; onFilter: (ip: string) => void }) {
  if (!s.topTargets.length) return <EmptyState title="No internal devices were targeted" />;
  return (
    <div className="p-4">
      <p className="mb-3 text-xs text-ink-3">
        Devices on your network that inbound attacks were aimed at. Anything here is reachable from the internet, usually through a port forward: see{' '}
        <Link to="/firewall/exposure" className="text-cyan-300 hover:text-cyan-200">
          Internet exposure
        </Link>
        , or click a device to see its attacks.
      </p>
      <HBarList
        color="#f43f5e"
        onClick={onFilter}
        items={s.topTargets.map((t) => ({
          key: t.ip,
          label: (
            <span className="flex items-center gap-2">
              <span className="font-medium text-ink">{t.name ?? t.ip}</span>
              <span className="mono text-xs text-ink-3">{t.ip}</span>
              {t.network && <span className="text-xs text-ink-3">· {t.network}</span>}
            </span>
          ),
          value: t.count,
          color: SEVERITY_HEX[t.severity],
        }))}
      />
    </div>
  );
}

/**
 * One line that answers "do I need to do anything?", so the badges, the threat type and the IP lookup further down
 * never send mixed signals.
 */
function EventVerdict({ e, who }: { e: ThreatEvent; who: IpIntel | null }) {
  const device = e.local?.name ?? e.localIp ?? 'a device on your network';
  const serious = e.severity === 'critical' || e.severity === 'high';
  const level = who?.verdict.level;
  const noise = level === 'scanner' || level === 'benign' ? ` The sender is ${who?.knownScanner?.name ?? 'a known internet scanner'}, so this is routine background noise.` : '';
  const bad = level === 'malicious' || level === 'suspicious' ? ' The sender has a bad reputation, so blocking it permanently is reasonable.' : '';
  let v: { tone: 'success' | 'warn' | 'danger' | 'info'; title: string; text: string };
  if (e.direction === 'outbound' || e.direction === 'internal') {
    v = { tone: serious ? 'danger' : 'warn', title: `Started by ${device} on your network${e.action === 'blocked' ? ', and blocked' : ''}`, text: e.advice };
  } else if (e.action === 'blocked') {
    v = { tone: 'success', title: 'Blocked — no action needed', text: `Your IPS stopped this before it reached your network. If the same source keeps coming back, you can block it permanently.${noise}${bad}` };
  } else if (e.action === 'alerted') {
    v = { tone: serious ? 'danger' : 'warn', title: `Allowed through — it reached ${device}`, text: `${e.advice}${bad}` };
  } else {
    v = { tone: 'info', title: 'Detected', text: e.advice };
  }
  return (
    <Callout tone={v.tone} icon={v.tone === 'success' ? <ShieldCheck className="h-4 w-4" /> : <ShieldAlert className="h-4 w-4" />} title={v.title}>
      {v.text}
    </Callout>
  );
}

function ThreatDrawer({ event: e, open, onClose, category, onBlock }: { event: ThreatEvent | null; open: boolean; onClose: () => void; category: ThreatCategory | null; onBlock: (ip: string) => void }) {
  const intel = useQuery({ queryKey: ['intel', e?.remoteIp], queryFn: () => api.intel(e!.remoteIp!), enabled: open && !!e?.remoteIp && e.direction !== 'internal' });
  return (
    <Drawer open={open} onClose={onClose} title={e?.headline ?? 'Detection'} subtitle={e ? fmtTime(e.ts) : undefined}>
      {!e ? (
        <Loading />
      ) : (
        <div className="space-y-5">
          <EventVerdict e={e} who={intel.data ?? null} />
          <div className="flex flex-wrap gap-2">
            <SeverityBadge severity={e.severity} />
            <ActionBadge action={e.action} />
            <DirectionBadge direction={e.direction} />
            {e.count > 1 && <Badge tone="slate">{e.count} occurrences</Badge>}
          </div>

          <section className="rounded-xl border border-line bg-surface-2/50 p-4">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-ink-3">What happened</h3>
            <p className="mt-1 text-sm leading-relaxed text-ink">{e.meaning}</p>
            {e.detail && <p className="mt-2 text-sm leading-relaxed text-ink-2">{e.detail}</p>}
          </section>

          <section>
            <h3 className="mb-1 text-xs font-semibold uppercase tracking-wider text-ink-3">Connection</h3>
            <dl>
              <KV k="Source" v={<IpLink ip={e.srcIp} name={e.local?.ip === e.srcIp ? e.local.name : null} />} />
              <KV k="Destination" v={<IpLink ip={e.dstIp} name={e.local?.ip === e.dstIp ? e.local.name : null} />} />
              <KV k="Ports" v={`${e.srcPort ?? '—'} → ${e.dstPort ?? '—'}`} mono />
              <KV k="Protocol" v={[e.proto, e.appProto].filter(Boolean).join(' / ') || '—'} />
              {e.local && <KV k="Your device" v={`${e.local.name ?? 'Unknown device'}${e.local.network ? ` · ${e.local.network}` : ''}${e.local.vlan !== null ? ` (VLAN ${e.local.vlan})` : ''}`} />}
              {e.remoteCountry && <KV k="Remote country" v={<CountryTag code={e.remoteCountry} showName />} />}
            </dl>
          </section>

          {e.remoteIp && e.direction !== 'internal' && (
            <section className="rounded-xl border border-line p-4">
              <div className="flex items-center justify-between gap-2">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-ink-3">Who is {e.remoteIp}?</h3>
                {intel.data && <VerdictBadge level={intel.data.verdict.level} />}
              </div>
              {intel.isLoading && <Loading label="Looking up…" className="py-4" />}
              {intel.data && (
                <>
                  <p className="mt-1.5 text-sm leading-relaxed text-ink-2">{intel.data.verdict.summary}</p>
                  {intel.data.verdict.reasons.length > 0 && (
                    <ul className="mt-2 ml-4 list-disc space-y-0.5 text-xs text-ink-3">
                      {intel.data.verdict.reasons.slice(0, 5).map((r) => (
                        <li key={r}>{r}</li>
                      ))}
                    </ul>
                  )}
                </>
              )}
              <div className="mt-3 flex flex-wrap gap-2">
                <Link to={`/investigate/${encodeURIComponent(e.remoteIp)}`} className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-line-2 bg-surface-2 px-3 text-xs text-ink hover:bg-surface-3">
                  <ScanSearch className="h-3.5 w-3.5" /> Full investigation
                </Link>
                {e.direction === 'inbound' && (
                  <Button size="sm" variant="secondary" icon={<Ban className="h-3.5 w-3.5" />} onClick={() => onBlock(e.remoteIp!)}>
                    Block this IP
                  </Button>
                )}
              </div>
            </section>
          )}

          <section>
            <h3 className="mb-1 text-xs font-semibold uppercase tracking-wider text-ink-3">Signature</h3>
            <div className="rounded-lg bg-black/30 p-3">
              <div className="mono text-[12px] leading-relaxed text-slate-200">{e.signature}</div>
              <div className="mt-1 text-xs text-ink-3">
                {e.signatureId ? `SID ${e.signatureId}` : 'No signature id'}
                {e.classtype ? ` · ${e.classtype}` : ''}
                {e.categoryRaw ? ` · ${e.categoryRaw}` : ''}
              </div>
            </div>
            {e.cves.length > 0 && (
              <div className="mt-2 flex flex-wrap gap-2">
                {e.cves.map((c) => (
                  <a key={c} href={`https://nvd.nist.gov/vuln/detail/${c}`} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 rounded-md bg-rose-500/10 px-2 py-0.5 text-xs text-rose-200 hover:bg-rose-500/20">
                    {c} <ExternalLink className="h-3 w-3" />
                  </a>
                ))}
              </div>
            )}
          </section>

          {category && (
            <Link to={`/learn/${encodeURIComponent(category.key)}`} className="inline-flex items-center gap-1.5 text-sm text-cyan-300 hover:text-cyan-200">
              <BookOpen className="h-4 w-4" /> More about “{category.name}” in the encyclopedia →
            </Link>
          )}
        </div>
      )}
    </Drawer>
  );
}

