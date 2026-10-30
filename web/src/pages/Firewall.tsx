import { Fragment, useEffect, useMemo, useState } from 'react';
import { Link, useNavigate, useParams, useSearchParams } from 'react-router';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import clsx from 'clsx';
import { ArrowRight, Ban, Check, CircleAlert, CircleCheck, DoorOpen, Eye, EyeOff, Globe, ListChecks, Network, Radar, Router, Search, SearchCheck, ShieldAlert, Sparkles, TriangleAlert } from 'lucide-react';
import type { BlockedGroup, BlockedTraffic, FirewallOverview, MatrixCell, NetworkRole, RuleDirection, RuleView, SegmentationMatrix } from '@shared/types';
import { NETWORK_ROLES } from '@shared/types';
import { api } from '../lib/api';
import { fmtNum, plural, timeAgo } from '../lib/format';
import { Badge, Button, Callout, Card, Drawer, EmptyState, ErrorBox, InfoTip, Loading, MatrixLegend, PageHeader, REACH_STYLE, reachLabel, Segmented, SeverityBadge, Tabs } from '../components/ui';
import { FixButton, useFix } from '../components/FixFlow';

type Tab = 'segmentation' | 'rules' | 'networks' | 'hygiene' | 'exposure';

export function FirewallPage() {
  const { tab: tabParam } = useParams();
  const navigate = useNavigate();
  const tab = (tabParam as Tab) || 'segmentation';
  const fw = useQuery({ queryKey: ['firewall'], queryFn: api.firewall });
  const matrix = useQuery({ queryKey: ['matrix'], queryFn: api.matrix });
  const fix = useFix();
  const d = fw.data;

  return (
    <div className="space-y-5">
      {fix.node}
      <PageHeader
        icon={<Radar className="h-5 w-5" />}
        title="Firewall & segmentation"
        subtitle="What your firewall actually allows — every rule decoded into plain English, and which networks can reach which."
        actions={
          d && (
            <div className="flex gap-2 text-xs text-ink-3">
              <Badge tone="slate">{d.firewallMode === 'zone' ? 'Zone-based firewall' : d.firewallMode === 'legacy' ? 'Legacy rules' : 'Unknown mode'}</Badge>
              <Badge tone="slate">{d.counts.custom} custom rules</Badge>
              {d.counts.managed > 0 && <Badge tone="cyan">{d.counts.managed} managed by this console</Badge>}
            </div>
          )
        }
      />
      {fw.error && <ErrorBox error={fw.error} onRetry={() => void fw.refetch()} />}
      {fw.isLoading && <Loading />}
      {d && (
        <>
          {d.warnings.map((w) => (
            <Callout key={w} tone="warn">
              {w}
            </Callout>
          ))}
          <Tabs
            value={tab}
            onChange={(t) => navigate(`/firewall/${t}`)}
            tabs={[
              { id: 'segmentation', label: 'Segmentation', icon: <Radar className="h-4 w-4" />, count: matrix.data?.cells.filter((c) => c.risk === 'risk').length || null },
              { id: 'rules', label: 'Rules', icon: <ListChecks className="h-4 w-4" />, count: d.counts.custom },
              { id: 'networks', label: 'Networks & roles', icon: <Network className="h-4 w-4" />, count: d.networks.length },
              { id: 'hygiene', label: 'Rule hygiene', icon: <Sparkles className="h-4 w-4" />, count: d.hygiene.filter((h) => h.kind !== 'disabled').length || null },
              { id: 'exposure', label: 'Internet exposure', icon: <DoorOpen className="h-4 w-4" />, count: d.exposure.filter((e) => e.enabled).length || null },
            ]}
          />
          {tab === 'segmentation' && (matrix.data ? <SegmentationView m={matrix.data} fw={d} onFix={fix.open} /> : matrix.error ? <ErrorBox error={matrix.error} /> : <Loading />)}
          {tab === 'rules' && <RulesView fw={d} />}
          {tab === 'networks' && <NetworksView fw={d} />}
          {tab === 'hygiene' && <HygieneView fw={d} onFix={fix.open} />}
          {tab === 'exposure' && <ExposureView fw={d} onFix={fix.open} />}
        </>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------------
// Segmentation matrix
// ---------------------------------------------------------------------------------

function cellStyle(c: MatrixCell | undefined): string {
  if (!c || c.verdict === 'self') return 'bg-slate-800/30 text-ink-3';
  if (c.risk === 'risk') return 'bg-rose-500/20 text-rose-200 ring-1 ring-inset ring-rose-500/50';
  if (c.risk === 'warn') return 'bg-amber-500/15 text-amber-200 ring-1 ring-inset ring-amber-500/40';
  if (c.verdict === 'blocked') return 'bg-emerald-500/15 text-emerald-200';
  if (c.verdict === 'partial') return 'bg-emerald-500/8 text-emerald-100/80';
  if (c.verdict === 'unknown') return 'bg-slate-700/30 text-ink-3';
  return 'bg-slate-700/25 text-ink-2';
}

function SegmentationView({ m, fw, onFix }: { m: SegmentationMatrix; fw: FirewallOverview; onFix: (f: NonNullable<MatrixCell['fix']>) => void }) {
  const [sel, setSel] = useState<MatrixCell | null>(null);
  // Read from UniFi's traffic log, which takes a moment; the matrix shows without it.
  const blocked = useQuery({ queryKey: ['blocked'], queryFn: api.blockedTraffic, staleTime: 5 * 60e3 });
  const rows = m.endpoints.filter((e) => e.kind === 'network');
  const name = (id: string) => m.endpoints.find((e) => e.id === id)?.name ?? id;
  const risky = m.cells.filter((c) => c.risk === 'risk');
  const partly = m.cells.filter((c) => c.risk === 'warn');
  const blockedOn = (c: MatrixCell) => blocked.data?.cells[`${c.from}>${c.to}`];
  const nearMisses = m.cells.flatMap((c) => (blockedOn(c)?.groups ?? []).filter((g) => g.nearMiss).map((g) => ({ c, g })));
  return (
    <div className="space-y-4">
      {risky.length > 0 ? (
        <Callout tone="danger" icon={<ShieldAlert className="h-4 w-4" />} title={`${risky.length} path${risky.length === 1 ? '' : 's'} should be blocked but ${risky.length === 1 ? 'is' : 'are'} open`}>
          Red cells are connections a less-trusted network can start towards a more-trusted one. Click a cell to see why and fix it.
        </Callout>
      ) : partly.length > 0 ? (
        <Callout tone="warn" icon={<TriangleAlert className="h-4 w-4" />} title={`${partly.length} path${partly.length === 1 ? ' is' : 's are'} only partly blocked`}>
          Nothing is fully open that should be blocked, but some traffic still gets through on{' '}
          {partly.map((c, i) => (
            <Fragment key={`${c.from}>${c.to}`}>
              {i > 0 && ', '}
              <button type="button" onClick={() => setSel(c)} className="font-medium underline decoration-amber-400/60 underline-offset-2 hover:text-ink">
                {name(c.from)} → {name(c.to)}
              </button>
            </Fragment>
          ))}
          . Open one to see what gets through, then block it or accept the risk on the Overview to-fix list.
        </Callout>
      ) : (
        <Callout tone="success" icon={<CircleCheck className="h-4 w-4" />} title="No risky paths">
          No untrusted network can start connections towards a trusted network.
        </Callout>
      )}
      {nearMisses.length > 0 && (
        <Callout
          tone="warn"
          icon={<SearchCheck className="h-4 w-4" />}
          title={`${plural(nearMisses.length, 'blocked connection')} ${nearMisses.length === 1 ? 'looks' : 'look'} like a rule with the wrong port or address`}
        >
          <ul className="mt-1 space-y-1">
            {nearMisses.slice(0, 5).map(({ c, g }) => (
              <li key={`${c.from}>${c.to}|${g.source.ip}|${g.destination?.ip}|${g.port}`}>
                <button type="button" onClick={() => setSel(c)} className="font-medium underline decoration-amber-400/60 underline-offset-2 hover:text-ink">
                  {name(c.from)} → {name(c.to)}
                </button>
                : {g.nearMiss!.reason}
              </li>
            ))}
          </ul>
        </Callout>
      )}
      <Card padded={false}>
        <div className="overflow-x-auto p-4">
          <table className="border-separate" style={{ borderSpacing: 4 }}>
            <thead>
              <tr>
                <th className="text-left text-[11px] font-normal text-ink-3">
                  FROM ↓ &nbsp; TO →
                </th>
                {m.endpoints.map((e) => (
                  <th key={e.id} className="min-w-[96px] px-1 pb-1 text-left align-bottom">
                    <div className="flex items-center gap-1 text-xs font-medium text-ink">
                      {e.kind === 'internet' ? <Globe className="h-3.5 w-3.5 text-ink-3" /> : e.kind === 'gateway' ? <Router className="h-3.5 w-3.5 text-ink-3" /> : null}
                      {e.name}
                    </div>
                    <div className="text-[10px] font-normal text-ink-3">{e.kind === 'network' ? `${e.vlan !== null ? `VLAN ${e.vlan} · ` : ''}${NETWORK_ROLES.find((r) => r.value === e.role)?.label ?? ''}` : e.kind === 'internet' ? 'outbound' : 'admin & services'}</div>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id}>
                  <th className="pr-2 text-left align-middle">
                    <div className="text-xs font-medium text-ink">{r.name}</div>
                    <div className="text-[10px] font-normal text-ink-3">
                      {r.vlan !== null ? `VLAN ${r.vlan} · ` : ''}
                      {NETWORK_ROLES.find((x) => x.value === r.role)?.label}
                    </div>
                  </th>
                  {m.endpoints.map((c) => {
                    const cell = m.cells.find((x) => x.from === r.id && x.to === c.id);
                    const b = cell && cell.verdict !== 'self' ? blockedOn(cell) : undefined;
                    return (
                      <td key={c.id}>
                        <button
                          disabled={!cell || cell.verdict === 'self'}
                          onClick={() => cell && setSel(cell)}
                          className={clsx('flex h-11 w-full min-w-[96px] flex-col items-center justify-center rounded-lg px-2 text-xs font-medium transition hover:brightness-125 disabled:cursor-default', cellStyle(cell))}
                          title={cell ? `${cell.summary}${b ? ` · ${plural(b.total, 'connection')} blocked in the last 24 hours` : ''}` : undefined}
                        >
                          {!cell || cell.verdict === 'self' ? '—' : (
                            <>
                              <span className="flex items-center gap-1">
                                {cell.risk === 'risk' && <TriangleAlert className="h-3.5 w-3.5" />}
                                {cell.verdict === 'blocked' && <Ban className="h-3.5 w-3.5" />}
                                {reachLabel(cell)}
                              </span>
                              {b && b.total > 0 && (
                                <span className={clsx('flex items-center gap-1 text-[10px] font-normal leading-tight', b.nearMisses ? 'text-amber-300' : 'opacity-70')}>
                                  {b.nearMisses > 0 && <CircleAlert className="h-3 w-3" />}
                                  {fmtNum(b.total)} blocked
                                </span>
                              )}
                            </>
                          )}
                        </button>
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="flex flex-wrap gap-4 border-t border-line px-4 py-3 text-xs text-ink-3">
          <MatrixLegend />
          <span className="flex items-center gap-1">
            Roles decide what “should” happen
            <InfoTip>Each network has a role (Trusted, IoT, Guest…). Change roles on the Networks & roles tab if a network is misclassified — recommendations update immediately.</InfoTip>
          </span>
        </div>
      </Card>
      {m.notes.map((n) => (
        <p key={n} className="text-xs text-ink-3">
          {n}
        </p>
      ))}
      <Drawer open={!!sel} onClose={() => setSel(null)} title={sel ? `${name(sel.from)} → ${name(sel.to)}` : ''} subtitle="Can devices start new connections along this path?">
        {sel && <CellDetail c={sel} fw={fw} blocked={blocked.data ?? null} loading={blocked.isLoading} onFix={(f) => { setSel(null); onFix(f); }} />}
      </Drawer>
    </div>
  );
}

/** What the firewall blocked on one path, busiest first; near misses first of all. */
function BlockedOnPath({ c, blocked, loading }: { c: MatrixCell; blocked: BlockedTraffic | null; loading: boolean }) {
  const b = blocked?.cells[`${c.from}>${c.to}`];
  const who = (x: { ip: string; name: string | null }) => (
    <>
      <span className="text-ink">{x.name ?? x.ip}</span>
      {x.name && <span className="font-mono text-[11px] text-ink-3">{x.ip}</span>}
    </>
  );
  const row = (g: BlockedGroup) => (
    <li key={`${g.source.ip}|${g.destination?.ip ?? '*'}|${g.protocol}|${g.port}`} className={clsx('rounded-lg border p-3', g.nearMiss ? 'border-amber-500/35 bg-amber-500/5' : 'border-line bg-surface-2/50')}>
      <div className="flex flex-wrap items-center gap-x-1.5 gap-y-0.5 text-sm">
        {who(g.source)}
        <ArrowRight className="h-3.5 w-3.5 text-ink-3" />
        {g.destination ? who(g.destination) : <span className="text-ink">the internet ({g.examples.join(', ')})</span>}
      </div>
      <div className="mt-0.5 text-xs text-ink-3">
        {g.protocol}
        {g.port !== null ? ` ${g.port}` : ''} · {plural(g.count, 'time')} · last seen {timeAgo(g.lastSeen)}
      </div>
      {g.nearMiss && (
        <div className="mt-2 flex items-start gap-1.5 text-xs text-amber-200">
          <CircleAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          <span>{g.nearMiss.reason} If this connection should work, correct that rule in UniFi.</span>
        </div>
      )}
    </li>
  );
  return (
    <div>
      <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-ink-3">Blocked in the last 24 hours</h3>
      {loading ? (
        <p className="text-sm text-ink-3">Reading UniFi’s traffic log…</p>
      ) : !blocked?.available ? (
        <p className="text-sm text-ink-3">UniFi’s traffic log is not available on this console, so blocked connections can’t be shown.</p>
      ) : !b ? (
        <p className="text-sm text-ink-3">UniFi logged no blocked connections on this path.</p>
      ) : (
        <>
          <p className="mb-2 text-xs text-ink-3">
            {plural(b.total, 'connection')} that devices started were blocked{blocked.truncated ? ' (at least: the log had more than could be read)' : ''}. If one of these should work, an allow
            rule is missing or doesn’t match it.
          </p>
          <ul className="space-y-2">{b.groups.map(row)}</ul>
        </>
      )}
    </div>
  );
}

function CellDetail({ c, fw, blocked, loading, onFix }: { c: MatrixCell; fw: FirewallOverview; blocked: BlockedTraffic | null; loading: boolean; onFix: (f: NonNullable<MatrixCell['fix']>) => void }) {
  const rule = (id: string) => fw.rules.find((r) => r.id === id);
  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone={REACH_STYLE[c.verdict].tone}>{reachLabel(c)}</Badge>
        {c.expected === 'block' && <Badge tone={c.risk === 'risk' ? 'red' : c.risk === 'warn' ? 'amber' : 'green'}>Should be blocked</Badge>}
      </div>
      <p className="text-sm text-ink">{c.summary}</p>
      {c.explanation.length > 0 && (
        <ul className="ml-4 list-disc space-y-1.5 text-sm leading-relaxed text-ink-2">
          {c.explanation.map((e) => (
            <li key={e}>{e}</li>
          ))}
        </ul>
      )}
      {c.rules.length > 0 && (
        <div>
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-ink-3">Rules involved</h3>
          <ul className="space-y-2">
            {c.rules.map((r) => {
              const rv = rule(r.id);
              return (
                <li key={r.id} className="rounded-lg border border-line bg-surface-2/50 p-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <ActionTag action={r.action === 'default' ? 'allow' : r.action} />
                    <span className="text-sm font-medium text-ink">{r.name}</span>
                    <Badge tone="slate">{r.effect === 'decides' ? 'decides' : r.effect === 'exception' ? 'exception' : 'may apply'}</Badge>
                    {rv?.predefined && <Badge tone="slate">built-in</Badge>}
                  </div>
                  {rv && <div className="mt-1 text-xs text-ink-2">{rv.sentence}</div>}
                </li>
              );
            })}
          </ul>
        </div>
      )}
      {c.fix && (
        <div className="rounded-xl border border-cyan-500/30 bg-cyan-500/5 p-4">
          <div className="text-sm text-ink">Fix it with one click — you will see exactly what changes first, and it can be undone.</div>
          <div className="mt-3">
            <FixButton fix={c.fix} onOpen={onFix} />
          </div>
        </div>
      )}
      <BlockedOnPath c={c} blocked={blocked} loading={loading} />
    </div>
  );
}

function ActionTag({ action }: { action: string }) {
  return <Badge tone={action === 'allow' ? 'blue' : action === 'reject' ? 'orange' : 'red'}>{action === 'allow' ? 'Allow' : action === 'reject' ? 'Reject' : 'Block'}</Badge>;
}

// ---------------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------------

type RuleDir = 'all' | RuleDirection;

const RULE_DIRS: { value: RuleDir; label: string; title: string }[] = [
  { value: 'all', label: 'All', title: 'Every rule' },
  { value: 'inbound', label: 'Inbound', title: 'From the internet into your networks or the gateway' },
  { value: 'outbound', label: 'Outbound', title: 'From your networks out to the internet' },
  { value: 'internal', label: 'Between networks', title: 'Between your own networks and zones' },
  { value: 'gateway', label: 'To gateway', title: 'From your networks to the gateway itself (DNS, DHCP, admin login…)' },
];

function RulesView({ fw }: { fw: FirewallOverview }) {
  const [sp, setSp] = useSearchParams();
  const highlight = sp.get('rule');
  // A link to one rule (from a preview or the Change Log) scrolls it into view.
  useEffect(() => {
    if (!highlight) return;
    const t = setTimeout(() => document.getElementById(`rule-${highlight}`)?.scrollIntoView({ block: 'center' }), 50);
    return () => clearTimeout(t);
  }, [highlight]);
  // Direction and zone live in the address, so a filtered view can be bookmarked or linked to.
  const dir = (RULE_DIRS.some((d) => d.value === sp.get('dir')) ? sp.get('dir') : 'all') as RuleDir;
  // An unknown zone in the address (a stale link) shows everything rather than an empty list.
  const zone = fw.zones.some((z) => z.name === sp.get('zone')) ? sp.get('zone')! : '';
  const setParam = (key: string, value: string) =>
    setSp(
      (prev) => {
        const next = new URLSearchParams(prev);
        if (value && value !== 'all') next.set(key, value);
        else next.delete(key);
        return next;
      },
      { replace: true },
    );
  const [showBuiltin, setShowBuiltin] = useState(false);
  const [q, setQ] = useState('');
  const [openRaw, setOpenRaw] = useState<string | null>(null);

  const { groups, shown, dirCounts, zoneCounts, hiddenBuiltin } = useMemo(() => {
    const ql = q.toLowerCase();
    const searched = fw.rules.filter((r) => !q || `${r.name} ${r.sentence} ${r.group}`.toLowerCase().includes(ql));
    const base = searched.filter((r) => showBuiltin || !r.predefined || r.id === highlight);
    const inZone = (r: RuleView, z: string) => !z || r.srcZone === z || r.dstZone === z;
    const inDir = (r: RuleView, d: RuleDir) => d === 'all' || r.direction === d;
    const filtered = base.filter((r) => inZone(r, zone) && inDir(r, dir));
    const m = new Map<string, RuleView[]>();
    for (const r of filtered) m.set(r.group, [...(m.get(r.group) ?? []), r]);
    return {
      groups: [...m.entries()],
      shown: filtered.length,
      dirCounts: Object.fromEntries(RULE_DIRS.map((d) => [d.value, base.filter((r) => inZone(r, zone) && inDir(r, d.value)).length])) as Record<RuleDir, number>,
      zoneCounts: Object.fromEntries(fw.zones.map((z) => [z.name, base.filter((r) => inZone(r, z.name) && inDir(r, dir)).length])) as Record<string, number>,
      hiddenBuiltin: showBuiltin ? 0 : searched.filter((r) => r.predefined && !base.includes(r) && inZone(r, zone) && inDir(r, dir)).length,
    };
  }, [fw.rules, fw.zones, showBuiltin, q, highlight, zone, dir]);

  return (
    <div className="space-y-4">
      <div className="space-y-2">
        <div className="flex flex-wrap items-center gap-2">
          <div className="max-w-full overflow-x-auto">
            <Segmented
              value={dir}
              onChange={(v) => setParam('dir', v)}
              options={RULE_DIRS.map((d) => ({
                value: d.value,
                label: (
                  <span title={d.title} className="whitespace-nowrap">
                    {d.label} <span className="text-ink-3">{dirCounts[d.value]}</span>
                  </span>
                ),
              }))}
            />
          </div>
          {fw.zones.length > 0 && (
            <select
              value={zone}
              onChange={(e) => setParam('zone', e.target.value)}
              aria-label="Filter by zone"
              className="h-8 rounded-lg border border-line bg-surface-2 px-2 text-xs text-ink focus:border-cyan-500/50 focus:outline-none"
            >
              <option value="">All zones</option>
              {fw.zones
                .filter((z) => (zoneCounts[z.name] ?? 0) > 0 || z.name === zone)
                .map((z) => (
                  <option key={z.id} value={z.name}>
                    {z.name} ({zoneCounts[z.name] ?? 0})
                  </option>
                ))}
            </select>
          )}
          <div className="relative min-w-[12rem] flex-1 sm:max-w-xs">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-ink-3" />
            <input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Search rules…"
              className="h-8 w-full rounded-lg border border-line bg-surface-2 pl-9 pr-3 text-sm text-ink placeholder:text-ink-3 focus:border-cyan-500/50 focus:outline-none"
            />
          </div>
          <Button size="sm" variant="ghost" icon={showBuiltin ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />} onClick={() => setShowBuiltin((s) => !s)}>
            {showBuiltin ? 'Hide' : 'Show'} built-in rules ({fw.counts.predefined})
          </Button>
        </div>
        <div className="text-xs text-ink-3">
          Showing {shown} rule{shown === 1 ? '' : 's'}
          {zone && (
            <>
              {' '}
              involving <strong className="font-medium text-ink-2">{zone}</strong> ·{' '}
              <button type="button" className="text-cyan-300 hover:text-cyan-200" onClick={() => setParam('zone', '')}>
                show all zones
              </button>
            </>
          )}
          . Within each group, rules run top to bottom and the first match wins.
        </div>
      </div>
      {groups.length === 0 && (
        <Card>
          <EmptyState title="No rules match">
            {hiddenBuiltin > 0 && (
              <>
                {hiddenBuiltin} built-in rule{hiddenBuiltin === 1 ? '' : 's'} match.{' '}
                <button type="button" className="text-cyan-300 hover:text-cyan-200" onClick={() => setShowBuiltin(true)}>
                  Show built-in rules
                </button>
              </>
            )}
          </EmptyState>
        </Card>
      )}
      {groups.length > 0 && (
        <Card padded={false}>
          {groups.map(([group, rules], gi) => (
            <section key={group} className={clsx(gi > 0 && 'border-t border-line')}>
              <h3 className="flex items-baseline justify-between gap-3 bg-surface-2/50 px-4 py-2 text-xs font-semibold text-ink-2">
                <span className="min-w-0 truncate">{group}</span>
                <span className="shrink-0 font-normal text-ink-3">
                  {rules.length} rule{rules.length === 1 ? '' : 's'}
                </span>
              </h3>
          <ul className="divide-y divide-line/50">
            {rules.map((r) => (
              <li key={r.id} id={`rule-${r.id}`} className={clsx('px-4 py-3', r.id === highlight && 'bg-cyan-500/5 ring-1 ring-inset ring-cyan-500/30', !r.enabled && 'opacity-55')}>
                <div className="flex flex-wrap items-center gap-2">
                  <span className="mono w-14 shrink-0 text-[11px] text-ink-3">#{r.index}</span>
                  <ActionTag action={r.action} />
                  <span className="text-sm font-medium text-ink">{r.name}</span>
                  {!r.enabled && <Badge tone="slate">disabled</Badge>}
                  {r.predefined && <Badge tone="slate">built-in</Badge>}
                  {r.managed && <Badge tone="cyan">managed</Badge>}
                  {r.logging && <Badge tone="slate">logging</Badge>}
                  {r.schedule && <Badge tone="violet">{r.schedule}</Badge>}
                  {!r.exact && (
                    <Badge tone="amber" title={r.notes.join(' ')}>
                      conditional
                    </Badge>
                  )}
                  <button className="ml-auto text-[11px] text-ink-3 hover:text-cyan-200" onClick={() => setOpenRaw(openRaw === r.id ? null : r.id)}>
                    {openRaw === r.id ? 'hide' : 'raw'}
                  </button>
                </div>
                <div className="mt-1 text-sm text-ink-2 sm:pl-16">{r.sentence}</div>
                {r.notes.length > 0 && <div className="mt-1 text-xs text-ink-3 sm:pl-16">{r.notes.join(' ')}</div>}
                {openRaw === r.id && <pre className="mono mt-2 max-h-72 overflow-auto rounded-md bg-black/40 p-2 text-[11px] text-slate-300">{JSON.stringify(r.raw, null, 2)}</pre>}
              </li>
            ))}
          </ul>
            </section>
          ))}
        </Card>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------------
// Networks & roles
// ---------------------------------------------------------------------------------

function NetworksView({ fw }: { fw: FirewallOverview }) {
  const qc = useQueryClient();
  const setRole = useMutation({
    mutationFn: ({ id, role }: { id: string; role: NetworkRole | null }) => api.setRole(id, role),
    onSuccess: () => void qc.invalidateQueries(),
  });
  return (
    <div className="space-y-4">
      <Callout title="Roles drive the recommendations">
        The console guesses each network's role from its name. If a guess is wrong (for example your "Lab" network holds trusted machines), change it here — the segmentation matrix, findings and hardening suggestions update immediately. Roles are stored locally and never sent to UniFi.
      </Callout>
      <Card padded={false}>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-line text-left text-xs text-ink-3">
                <th className="px-4 py-2 font-medium">Network</th>
                <th className="px-2 py-2 font-medium">Subnet</th>
                <th className="px-2 py-2 font-medium">Zone</th>
                <th className="px-2 py-2 font-medium">Role</th>
                <th className="px-2 py-2 text-right font-medium">Clients</th>
                <th className="px-2 py-2 font-medium">DHCP DNS</th>
                <th className="px-4 py-2 font-medium">Flags</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line/50">
              {fw.networks.map((n) => (
                <tr key={n.id}>
                  <td className="px-4 py-2.5">
                    <div className="font-medium text-ink">{n.name}</div>
                    <div className="text-xs text-ink-3">
                      {n.vlan !== null ? `VLAN ${n.vlan}` : 'untagged'} · {n.purpose}
                    </div>
                  </td>
                  <td className="mono px-2 py-2.5 text-xs text-ink-2">
                    {n.subnet ?? '—'}
                    {n.subnet6 && <div className="text-ink-3">{n.subnet6}</div>}
                  </td>
                  <td className="px-2 py-2.5 text-xs text-ink-2">{n.zoneName ?? '—'}</td>
                  <td className="px-2 py-2.5">
                    <div className="flex items-center gap-2">
                      <select
                        value={n.role}
                        onChange={(e) => setRole.mutate({ id: n.id, role: e.target.value as NetworkRole })}
                        className="h-8 rounded-lg border border-line-2 bg-surface-2 px-2 text-xs text-ink focus:border-cyan-500/50 focus:outline-none"
                      >
                        {NETWORK_ROLES.map((r) => (
                          <option key={r.value} value={r.value}>
                            {r.label}
                          </option>
                        ))}
                      </select>
                      {n.roleSource === 'user' ? (
                        <span className="whitespace-nowrap text-[11px] text-ink-3">
                          Set by you ·{' '}
                          <button className="hover:text-cyan-200" onClick={() => setRole.mutate({ id: n.id, role: null })}>
                            undo
                          </button>
                        </span>
                      ) : (
                        <span className="whitespace-nowrap text-[11px] text-ink-3">Auto-detected</span>
                      )}
                    </div>
                    <div className="mt-1 max-w-[16rem] text-[11px] leading-snug text-ink-3">{NETWORK_ROLES.find((r) => r.value === n.role)?.description}</div>
                  </td>
                  <td className="px-2 py-2.5 text-right text-ink-2">{n.clientCount}</td>
                  <td className="mono px-2 py-2.5 text-xs text-ink-2">{n.dhcpDns.length ? n.dhcpDns.join(', ') : <span className="text-ink-3">gateway</span>}</td>
                  <td className="px-4 py-2.5">
                    <div className="flex flex-wrap gap-1">
                      {n.isolated && <Badge tone="green">isolated</Badge>}
                      {!n.internetAccess && <Badge tone="amber">no internet</Badge>}
                      {!n.enabled && <Badge tone="slate">disabled</Badge>}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
      {fw.zones.length > 0 && (
        <Card title="Firewall zones" subtitle="Networks grouped into zones; policies are written between zones.">
          <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {fw.zones.map((z) => (
              <div key={z.id} className="rounded-lg border border-line bg-surface-2/40 p-3">
                <div className="text-sm font-medium text-ink">{z.name}</div>
                <div className="mt-1 text-xs text-ink-3">{z.networkNames.length ? z.networkNames.join(', ') : 'No networks'}</div>
              </div>
            ))}
          </div>
        </Card>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------------
// Hygiene & exposure
// ---------------------------------------------------------------------------------

function HygieneView({ fw, onFix }: { fw: FirewallOverview; onFix: (f: NonNullable<MatrixCell['fix']>) => void }) {
  if (!fw.hygiene.length)
    return (
      <Card>
        <EmptyState icon={<CircleCheck className="h-8 w-8 text-emerald-400" />} title="Your rule set is clean">
          No duplicate, redundant, shadowed or overly broad rules found.
        </EmptyState>
      </Card>
    );
  return (
    <div className="space-y-3">
      <Callout title="How this works">
        Rules are compared by the traffic they actually match — not by how they are written. Two rules written differently (a network vs. its subnet, “UDP+TCP” vs. two separate rules) are recognised as the same.
      </Callout>
      {fw.hygiene.map((h) => (
        <div key={h.id} className="rounded-xl border border-line bg-surface/80 p-4">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={h.severity} />
            <Badge tone="slate">{h.kind.replace('-', ' ')}</Badge>
            <span className="text-sm font-medium text-ink">{h.title}</span>
          </div>
          <p className="mt-1.5 text-sm leading-relaxed text-ink-2">{h.detail}</p>
          <div className="mt-2 flex flex-wrap items-center gap-1.5">
            {h.ruleIds.map((id, i) => (
              <Link key={id} to={`/firewall/rules?rule=${encodeURIComponent(id)}`} className="inline-flex items-center gap-1 rounded bg-surface-3 px-2 py-0.5 text-xs text-ink-2 hover:text-cyan-200">
                {h.ruleNames[i]} <ArrowRight className="h-3 w-3" />
              </Link>
            ))}
            {(h.kind === 'duplicate' || h.kind === 'redundant' || h.kind === 'disabled') && (
              <Button size="xs" variant="secondary" className="ml-auto" onClick={() => onFix({ templateId: 'remove-rule', params: { ruleId: h.ruleIds[0] }, label: `Remove “${h.ruleNames[0]}”` })}>
                Remove “{h.ruleNames[0]}”
              </Button>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}

function ExposureView({ fw, onFix }: { fw: FirewallOverview; onFix: (f: NonNullable<FirewallOverview['exposure'][number]['fix']>) => void }) {
  if (!fw.exposure.length)
    return (
      <Card>
        <EmptyState icon={<Check className="h-8 w-8 text-emerald-400" />} title="Nothing is exposed">
          No port forwards and UPnP is off.
        </EmptyState>
      </Card>
    );
  return (
    <Card padded={false} title="Services reachable from the internet" subtitle="Port forwards and UPnP — every entry is a door into your network.">
      <ul className="divide-y divide-line/50">
        {fw.exposure.map((e) => (
          <li key={e.id} className={clsx('flex flex-wrap items-start gap-3 px-4 py-3', !e.enabled && 'opacity-60')}>
            <SeverityBadge severity={e.severity} />
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-sm font-medium text-ink">{e.name}</span>
                {!e.enabled && <Badge tone="slate">disabled</Badge>}
                {e.services.map((s) => (
                  <Badge key={s} tone="slate">
                    {s}
                  </Badge>
                ))}
              </div>
              <div className="mono mt-0.5 text-xs text-ink-2">
                {e.protocol} {e.externalPort} → {e.internalTarget}
                {e.internalName && <span className="font-sans text-ink-3"> ({e.internalName})</span>}
              </div>
              <div className="mt-1 text-xs text-ink-3">
                {e.sourceRestriction ? `Only from ${e.sourceRestriction}. ` : e.enabled && e.kind === 'port-forward' ? 'Open to the entire internet. ' : ''}
                {e.risk}
              </div>
            </div>
            {e.fix && <FixButton fix={e.fix} onOpen={onFix} />}
          </li>
        ))}
      </ul>
    </Card>
  );
}
