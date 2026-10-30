import { useEffect, useRef, useState } from 'react';
import { Link, useNavigate } from 'react-router';
import { useQuery } from '@tanstack/react-query';
import clsx from 'clsx';
import {
  ArrowDown, ArrowUp, ChevronDown, CircleAlert, CircleCheck, CircleX, DoorOpen, Flame, Globe, History, Laptop, LayoutDashboard, Radar, Router, ShieldAlert, ShieldCheck, Undo2, Users,
} from 'lucide-react';
import type { Door, FixAction, Finding, NewDevice, OverviewExtras, SegmentationMatrix, Severity, ThreatEvent, ThreatSummary, UnifiDevice } from '@shared/types';
import { api } from '../lib/api';
import { useLive } from '../lib/live';
import { countryName, fmtBps, fmtNum, plural, timeAgo } from '../lib/format';
import { ActionBadge, Badge, Button, Card, CountryTag, DirectionBadge, Drawer, EmptyState, ErrorBox, EventEnd, IpLink, MatrixLegend, Loading, PageHeader, ScoreRing, SEVERITY_HEX, Stat } from '../components/ui';
import { Sparkline } from '../components/charts';
import { useFix } from '../components/FixFlow';
import { AcceptedList, useAcceptRisk } from '../components/AcceptRisk';
import { STATE as DEVICE_STATE } from './Devices';

const SEV_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

// The "to fix" button takes the colour of the most serious issue.
const FIX_TONE = {
  urgent: 'border-rose-500/30 bg-rose-500/10 text-rose-100 hover:bg-rose-500/15',
  medium: 'border-amber-500/30 bg-amber-500/10 text-amber-100 hover:bg-amber-500/15',
  low: 'border-sky-500/30 bg-sky-500/10 text-sky-100 hover:bg-sky-500/15',
};

export function OverviewPage() {
  const { data, error, isLoading, refetch } = useQuery({ queryKey: ['overview'], queryFn: api.overview, refetchInterval: 60_000 });
  const live = useLive();
  const [showFixes, setShowFixes] = useState(false);
  const [acceptedFirst, setAcceptedFirst] = useState(false);
  // A fix started from the to-fix panel returns to the panel afterwards, so you keep your place.
  const fromPanel = useRef(false);
  const fix = useFix(() => {
    if (fromPanel.current) setShowFixes(true);
    fromPanel.current = false;
  });
  const accept = useAcceptRisk();
  const openFixes = (accepted: boolean) => {
    setAcceptedFirst(accepted);
    setShowFixes(true);
  };
  const snap = live.snapshot ?? data?.live ?? null;
  const samples = live.samples.length ? live.samples : data?.history ?? [];

  if (isLoading) return <Loading label="Analysing your network…" />;
  if (error) return <ErrorBox error={error} onRetry={() => void refetch()} />;
  if (!data) return null;
  const { posture, threats } = data;
  const open = posture.findings.filter((f) => f.status === 'fail' || f.status === 'warn');
  const failing = open.filter((f) => !f.acceptance).sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity]);
  const acceptedFindings = open.filter((f) => f.acceptance);
  const worst = failing[0] ? SEV_RANK[failing[0].severity] : 4;

  return (
    <div className="space-y-5">
      {fix.node}
      {accept.node}
      <FixesDrawer
        open={showFixes}
        onClose={() => setShowFixes(false)}
        findings={failing}
        accepted={acceptedFindings}
        showAccepted={acceptedFirst}
        onFix={(x) => {
          fromPanel.current = true;
          fix.open(x);
        }}
        onAccept={(f) => accept.open({ key: f.key, kind: 'finding', title: f.title })}
      />
      <PageHeader icon={<LayoutDashboard className="h-5 w-5" />} title="Security overview" subtitle="How well your network is protected right now, what is attacking it, and what to fix first." />

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4 [&>*]:min-w-0">
        <Card className="md:row-span-1">
          <div className="flex items-center gap-4">
            <ScoreRing score={posture.score} grade={posture.grade} size={116} />
            <div className="min-w-0 space-y-2">
              <div className="text-sm font-medium text-ink">Security score</div>
              {failing.length ? (
                <button
                  type="button"
                  onClick={() => openFixes(false)}
                  className={clsx('group flex items-center gap-2.5 rounded-lg border px-3 py-2 text-left transition-colors', FIX_TONE[worst <= 1 ? 'urgent' : worst === 2 ? 'medium' : 'low'])}
                >
                  <span className="text-2xl font-semibold leading-none tabular-nums">{failing.length}</span>
                  <span className="text-xs leading-tight">
                    {failing.length === 1 ? 'thing' : 'things'} to fix
                    <span className="block opacity-70 group-hover:opacity-100">Show me →</span>
                  </span>
                </button>
              ) : (
                <div className="flex items-center gap-1.5 text-sm text-emerald-300">
                  <CircleCheck className="h-4 w-4" /> Nothing to fix
                </div>
              )}
              {posture.accepted > 0 && (
                <button type="button" onClick={() => openFixes(true)} className="block text-xs text-ink-3 hover:text-ink-2">
                  {posture.accepted} accepted risk{posture.accepted === 1 ? '' : 's'}
                </button>
              )}
            </div>
          </div>
        </Card>
        <Stat
          label={
            <>
              <Flame className="h-3.5 w-3.5" /> Threats · last 24h
            </>
          }
          value={fmtNum(threats.total)}
          sub={
            <span>
              <span className="text-emerald-300">{fmtNum(threats.blocked)} blocked</span>
              {threats.alerted > 0 && <span className="text-amber-300"> · {fmtNum(threats.alerted)} allowed through</span>}
            </span>
          }
        >
          <div className="mt-2">
            <Sparkline values={threats.timeline.map((b) => b.total)} color="#f97316" />
          </div>
        </Stat>
        <Stat
          label={
            <>
              <Globe className="h-3.5 w-3.5" /> Internet
            </>
          }
          value={
            <span className="flex items-baseline gap-3 text-xl">
              <span className="flex items-center gap-1">
                <ArrowDown className="h-4 w-4 text-cyan-300" />
                {fmtBps(snap?.wan?.rxBps)}
              </span>
              <span className="flex items-center gap-1 text-ink-2">
                <ArrowUp className="h-4 w-4 text-violet-300" />
                {fmtBps(snap?.wan?.txBps)}
              </span>
            </span>
          }
          sub={snap?.wan ? `${snap.wan.isp ?? 'WAN'}${snap.wan.latencyMs !== null ? ` · ${snap.wan.latencyMs} ms latency` : ''}` : 'No WAN data'}
        >
          <div className="mt-2">
            <Sparkline values={samples.slice(-120).map((s) => s.rxBps ?? 0)} />
          </div>
        </Stat>
        <Stat
          label={
            <>
              <Users className="h-3.5 w-3.5" /> Clients
            </>
          }
          value={fmtNum(snap?.clients.total)}
          sub={snap ? `${snap.clients.wireless} wireless · ${snap.clients.wired} wired · ${snap.clients.guest} guests` : '—'}
        >
          {snap && (
            <div className="mt-3 flex items-center gap-2 text-xs text-ink-3">
              <Router className="h-3.5 w-3.5" />
              {snap.devices.online}/{snap.devices.total - snap.devices.disabled} UniFi devices online
              {snap.devices.disabled > 0 && ` · ${snap.devices.disabled} disabled`}
              {snap.devices.upgradable > 0 && <Badge tone="amber">{snap.devices.upgradable} updates</Badge>}
            </div>
          )}
        </Stat>
      </div>

      <div className="grid gap-4 xl:grid-cols-3 [&>*]:min-w-0">
        <AttacksCard className="xl:col-span-2" threats={threats} recent={live.threats.length ? live.threats : data.recent} fresh={live.freshIds} />
        <Card title="Segmentation at a glance" icon={<Radar className="h-4 w-4" />} actions={<Link to="/firewall" className="text-xs text-cyan-300 hover:text-cyan-200">Details →</Link>}>
          {data.matrix ? <MiniMatrix m={data.matrix} /> : <div className="text-sm text-ink-3">Firewall analysis unavailable.</div>}
        </Card>
      </div>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4 [&>*]:min-w-0">
        <WaysInCard doors={data.extras.doors} upnp={data.extras.upnp} />
        <NewDevicesCard devices={data.extras.newDevices} />
        <ChangesCard changes={data.extras.changes} />
        <UnifiDevicesCard />
      </div>
    </div>
  );
}

function FixesDrawer(props: { open: boolean; onClose: () => void; findings: Finding[]; accepted: Finding[]; showAccepted: boolean; onFix: (fix: FixAction) => void; onAccept: (f: Finding) => void }) {
  const { findings } = props;
  const acceptedRef = useRef<HTMLDetailsElement>(null);
  useEffect(() => {
    if (props.open && props.showAccepted) acceptedRef.current?.scrollIntoView({ block: 'start' });
  }, [props.open, props.showAccepted]);
  // One row per decision: a protection accepted on Hardening covers every issue it would fix.
  const accepted = [...new Map(props.accepted.map((f) => [f.acceptance!.key, { key: f.acceptance!.key, title: f.acceptance!.title, acceptance: f.acceptance! }])).values()];
  const soon = findings.filter((f) => SEV_RANK[f.severity] <= SEV_RANK.medium);
  const later = findings.filter((f) => SEV_RANK[f.severity] > SEV_RANK.medium);
  const pick = (x: FixAction) => {
    props.onClose();
    props.onFix(x);
  };
  return (
    <Drawer
      open={props.open}
      onClose={props.onClose}
      width="max-w-xl"
      title={findings.length ? `${findings.length} ${findings.length === 1 ? 'thing' : 'things'} to fix` : 'Nothing to fix'}
      subtitle="Most important first. A fix always shows exactly what will change before anything is applied."
    >
      <div className="space-y-6">
        {soon.length > 0 && <FixGroup title="Fix soon" items={soon} onFix={pick} onAccept={props.onAccept} />}
        {later.length > 0 && <FixGroup title="When you have time" items={later} onFix={pick} onAccept={props.onAccept} />}
        {accepted.length > 0 && (
          <details ref={acceptedRef} className="group" open={props.showAccepted || !findings.length}>
            <summary className="cursor-pointer select-none text-[11px] font-semibold uppercase tracking-wider text-ink-3 hover:text-ink-2">Accepted risks ({accepted.length})</summary>
            <div className="mt-1">
              <AcceptedList items={accepted} />
            </div>
          </details>
        )}
      </div>
    </Drawer>
  );
}

function FixGroup({ title, items, onFix, onAccept }: { title: string; items: Finding[]; onFix: (fix: FixAction) => void; onAccept: (f: Finding) => void }) {
  return (
    <section>
      <h3 className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-ink-3">{title}</h3>
      <ul className="divide-y divide-line/60">
        {items.map((f) => (
          <FixItem key={f.id} f={f} onFix={onFix} onAccept={onAccept} />
        ))}
      </ul>
    </section>
  );
}

function FixItem({ f, onFix, onAccept }: { f: Finding; onFix: (fix: FixAction) => void; onAccept: (f: Finding) => void }) {
  const [open, setOpen] = useState(false);
  return (
    <li className="py-3">
      <div className="flex items-start gap-3">
        <span className="mt-1.5 h-2 w-2 shrink-0 rounded-full" style={{ background: SEVERITY_HEX[f.severity] }} />
        <div className="min-w-0 flex-1">
          <div className="text-sm font-medium text-ink">{f.title}</div>
          <div className="mt-0.5 text-xs leading-relaxed text-ink-2">{f.summary}</div>
          {f.protection && (
            <div className="mt-1 text-xs text-ink-3">
              Fixed by{' '}
              <Link to={`/hardening#${f.protection.id}`} className="text-cyan-300 hover:text-cyan-200">
                {f.protection.title}
              </Link>{' '}
              on Hardening
            </div>
          )}
          {f.howTo && (
            <div className="mt-1.5 rounded-md border border-line bg-surface-2/60 px-2.5 py-1.5 text-xs leading-relaxed text-ink-2">
              <span className="font-medium text-ink">How to fix it in UniFi:</span> {f.howTo}
            </div>
          )}
          <div className="mt-1.5 flex flex-wrap items-center gap-x-4 gap-y-1">
            {(f.why || f.evidence.length > 0) && (
              <button type="button" onClick={() => setOpen((o) => !o)} aria-expanded={open} className="inline-flex items-center gap-1 text-xs text-ink-3 hover:text-ink-2">
                <ChevronDown className={clsx('h-3.5 w-3.5 transition-transform', open && 'rotate-180')} /> {open ? 'Less' : 'Why it matters'}
              </button>
            )}
            <button type="button" onClick={() => onAccept(f)} className="text-xs text-ink-3 hover:text-ink-2">
              Accept risk…
            </button>
          </div>
        </div>
        <div className="shrink-0">
          {f.fix ? (
            <Button size="sm" variant="primary" title={f.fix.label} onClick={() => onFix(f.fix!)}>
              Fix
            </Button>
          ) : f.link ? (
            <Link to={f.link} className="inline-flex h-8 items-center rounded-lg border border-line-2 px-3 text-xs text-ink-2 hover:bg-surface-3">
              Review
            </Link>
          ) : null}
        </div>
      </div>
      {open && (
        <div className="ml-5 mt-2 space-y-1.5 text-xs leading-relaxed text-ink-3">
          {f.why && <p>{f.why}</p>}
          {f.evidence.length > 0 && (
            <ul className="list-disc space-y-0.5 pl-4">
              {f.evidence.slice(0, 6).map((e) => (
                <li key={e}>{e}</li>
              ))}
            </ul>
          )}
        </div>
      )}
    </li>
  );
}

/** Everything about attacks in one place: is there anything to do, the latest few, and where they come from. */
function AttacksCard({ threats, recent, fresh, className }: { threats: ThreatSummary; recent: ThreatEvent[]; fresh: Set<string>; className?: string }) {
  const templates = useQuery({ queryKey: ['templates'], queryFn: api.templates });
  const ips = templates.data?.status.find((x) => x.templateId === 'ips-mode');
  const suspects = threats.suspects.length;
  const verdict =
    suspects > 0
      ? { tone: 'text-rose-300', bad: true, text: `${suspects} of your devices behave like they are compromised. Check ${suspects === 1 ? 'it' : 'them'} first.` }
      : threats.alerted > 0
        ? { tone: 'text-amber-300', bad: true, text: `${fmtNum(threats.alerted)} of ${fmtNum(threats.total)} got through, because the IPS only reported them.` }
        : threats.total > 0
          ? { tone: 'text-emerald-300', bad: false, text: `All ${fmtNum(threats.total)} blocked — nothing to do.` }
          : { tone: 'text-emerald-300', bad: false, text: 'No attacks detected.' };
  return (
    <Card className={className} title="Attacks · last 24h" icon={<Flame className="h-4 w-4" />} actions={<Link to="/threats" className="text-xs text-cyan-300 hover:text-cyan-200">All threats →</Link>} padded={false}>
      <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2 border-b border-line/60 px-4 py-3">
        <Link to={suspects ? '/threats?range=24h' : '/threats'} className={clsx('flex min-w-0 items-center gap-2 text-sm font-medium hover:underline', verdict.tone)}>
          {verdict.bad ? <ShieldAlert className="h-4 w-4 shrink-0" /> : <ShieldCheck className="h-4 w-4 shrink-0" />}
          {verdict.text}
        </Link>
        {ips && (
          <span className="flex items-center gap-1.5 text-xs text-ink-3">
            Intrusion prevention <Badge tone={ips.state === 'applied' ? 'green' : ips.state === 'partial' ? 'amber' : 'red'}>{ips.label}</Badge>
          </span>
        )}
      </div>
      {threats.total > 0 && <RecentThreats events={recent.slice(0, 3)} fresh={fresh} />}
      {(threats.topSources.length > 0 || threats.byCountry.length > 0) && (
        <div className="space-y-1.5 border-t border-line/60 px-4 py-3 text-xs text-ink-3">
          {threats.topSources.length > 0 && (
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
              <span>Most active:</span>
              {threats.topSources.slice(0, 3).map((x) => (
                <span key={x.ip} className="flex items-center gap-1">
                  <CountryTag code={x.country} />
                  <IpLink ip={x.ip} />
                  <span>×{fmtNum(x.count)}</span>
                </span>
              ))}
            </div>
          )}
          {threats.byCountry.length > 0 && (
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
              <span>From:</span>
              {threats.byCountry.slice(0, 4).map((c) => (
                <span key={c.country} className="text-ink-2">
                  {countryName(c.country)} <span className="text-ink-3">{fmtNum(c.count)}</span>
                </span>
              ))}
            </div>
          )}
        </div>
      )}
    </Card>
  );
}

const MAX_ROWS = 5;
const linkCls = 'text-xs text-cyan-300 hover:text-cyan-200';

function AllGood({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex items-start gap-2 px-4 py-4 text-sm text-emerald-300">
      <CircleCheck className="mt-0.5 h-4 w-4 shrink-0" /> {children}
    </div>
  );
}

/** Why a way in is not open to everyone: a statement of fact, not a to-do. */
function LimitedBadge({ kind }: { kind: Door['kind'] }) {
  const [label, title] =
    kind === 'vpn-server'
      ? ['Key holders only', 'Only devices you gave a key to (a VPN profile) can connect through it. Nothing to do.']
      : kind === 'site-vpn'
        ? ['Paired site only', 'Only the other site’s gateway, which holds the matching key, can connect through it. Nothing to do.']
        : ['Allowed sources only', 'Only the source addresses you allowed in this port forward can reach it.'];
  return (
    <Badge tone="slate" title={title}>
      {label}
    </Badge>
  );
}

/** Every way in from the internet, riskiest first, with how often the device behind it was attacked in the last day. */
function WaysInCard({ doors, upnp }: { doors: Door[]; upnp: boolean | null }) {
  const more = doors.length - MAX_ROWS;
  return (
    <Card title="Ways in from the internet" icon={<DoorOpen className="h-4 w-4" />} actions={<Link to="/firewall/exposure" className={linkCls}>Details →</Link>} padded={false}>
      {doors.length === 0 ? (
        <AllGood>Nothing on your network is open to the internet.</AllGood>
      ) : (
        <ul className="divide-y divide-line/60">
          {doors.slice(0, MAX_ROWS).map((d) => (
            <li key={d.id} className="px-4 py-2.5">
              <div className="flex items-center gap-2">
                <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: SEVERITY_HEX[d.severity] }} title={`${d.severity} risk`} />
                <span className="min-w-0 flex-1 truncate text-sm text-ink">{d.name}</span>
                {d.attacks > 0 ? (
                  <Badge tone="red">{fmtNum(d.attacks)} attacks · 24h</Badge>
                ) : d.limited ? (
                  <LimitedBadge kind={d.kind} />
                ) : null}
              </div>
              <div className="mt-0.5 truncate pl-4 text-xs text-ink-3" title={d.detail}>
                {d.detail}
              </div>
            </li>
          ))}
        </ul>
      )}
      {(more > 0 || upnp === false) && (
        <div className="space-y-1 border-t border-line/60 px-4 py-2.5 text-xs text-ink-3">
          {more > 0 && (
            <Link to="/firewall/exposure" className={linkCls}>
              {more} more →
            </Link>
          )}
          {upnp === false && <p>UPnP is off, so devices can’t open ports on their own.</p>}
        </div>
      )}
    </Card>
  );
}

/** Devices connected now that joined in the last week: the quickest way to spot something you don't recognise. */
function NewDevicesCard({ devices }: { devices: NewDevice[] | null }) {
  return (
    <Card title="New devices · 7 days" icon={<Laptop className="h-4 w-4" />} actions={<Link to="/live" className={linkCls}>Live →</Link>} padded={false}>
      {devices === null ? (
        <p className="px-4 py-4 text-sm text-ink-3">This controller doesn’t report when devices first joined.</p>
      ) : devices.length === 0 ? (
        <AllGood>No new devices joined in the last 7 days.</AllGood>
      ) : (
        <ul className="divide-y divide-line/60">
          {devices.slice(0, MAX_ROWS).map((d, i) => {
            const row = (
              <>
                <span className="flex items-center gap-2">
                  <span className={clsx('min-w-0 flex-1 truncate text-sm', d.name ? 'text-ink' : 'text-amber-200')}>{d.name ?? 'Unnamed device'}</span>
                  <span className="shrink-0 text-xs text-ink-3">joined {timeAgo(d.firstSeen)}</span>
                </span>
                <span className="mt-0.5 block truncate text-xs text-ink-3">
                  {[d.vendor, d.network, d.wired ? 'wired' : 'Wi-Fi', d.guest ? 'guest' : null, d.ip].filter(Boolean).join(' · ')}
                </span>
              </>
            );
            return (
              <li key={`${d.firstSeen}-${i}`}>
                {d.ip ? (
                  <Link to={`/investigate/${encodeURIComponent(d.ip)}`} className="block px-4 py-2.5 hover:bg-surface-2/60">
                    {row}
                  </Link>
                ) : (
                  <div className="px-4 py-2.5">{row}</div>
                )}
              </li>
            );
          })}
        </ul>
      )}
      {!!devices?.length && (
        <p className="border-t border-line/60 px-4 py-2.5 text-[11px] leading-relaxed text-ink-3">
          Don’t recognise one? Look it up here, then block it in UniFi. Phones with private Wi-Fi addresses can show up again now and then.
          {devices.length > MAX_ROWS && ` ${devices.length - MAX_ROWS} more on the Live page.`}
        </p>
      )}
    </Card>
  );
}

const CHANGE_ICON: Record<OverviewExtras['changes']['recent'][number]['status'], React.ReactNode> = {
  applied: <CircleCheck className="h-4 w-4 text-emerald-400" />,
  undone: <Undo2 className="h-4 w-4 text-sky-300" />,
  partial: <CircleAlert className="h-4 w-4 text-amber-400" />,
  failed: <CircleX className="h-4 w-4 text-rose-400" />,
};

/** What this console changed lately, so nothing it did goes unnoticed. */
function ChangesCard({ changes }: { changes: OverviewExtras['changes'] }) {
  const older = changes.total - changes.recent.length;
  return (
    <Card title="Changes made here" icon={<History className="h-4 w-4" />} actions={<Link to="/activity" className={linkCls}>Change Log →</Link>} padded={false}>
      {changes.recent.length === 0 ? (
        <p className="px-4 py-4 text-sm text-ink-3">This console hasn’t changed anything on your network yet.</p>
      ) : (
        <ul className="divide-y divide-line/60">
          {changes.recent.map((c) => (
            <li key={c.id}>
              <Link to="/activity" className="flex items-start gap-2.5 px-4 py-2.5 hover:bg-surface-2/60">
                <span className="mt-0.5 shrink-0" title={c.status}>
                  {CHANGE_ICON[c.status]}
                </span>
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-sm text-ink">{c.title}</span>
                  <span className="block truncate text-xs text-ink-3" title={c.summary}>
                    {c.status === 'undone' ? 'Undone · ' : ''}
                    {c.summary}
                  </span>
                </span>
                <span className="shrink-0 text-xs text-ink-3">{timeAgo(c.ts)}</span>
              </Link>
            </li>
          ))}
        </ul>
      )}
      {changes.recent.length > 0 && (
        <p className="border-t border-line/60 px-4 py-2.5 text-xs text-ink-3">
          {older > 0 ? `${older} older in the Change Log. ` : ''}Every change can be undone there.
        </p>
      )}
    </Card>
  );
}

/** Every UniFi device at a glance, the ones that need attention first. */
function UnifiDevicesCard() {
  const navigate = useNavigate();
  const { data } = useQuery({ queryKey: ['unifi-devices'], queryFn: api.unifiDevices, refetchInterval: 30_000 });
  const needs = (d: UnifiDevice) => d.state === 'offline' || !!d.update || d.endOfLife;
  const list = [...(data ?? [])].sort((a, b) => Number(needs(b)) - Number(needs(a)));
  const updates = list.filter((d) => d.update).length;
  return (
    <Card title="UniFi devices" icon={<Router className="h-4 w-4" />} actions={<Link to="/devices" className={linkCls}>Devices →</Link>} padded={false}>
      {!data ? (
        <p className="px-4 py-4 text-sm text-ink-3">Loading…</p>
      ) : (
        <ul className="divide-y divide-line/60">
          {list.slice(0, 6).map((d) => (
            <li key={d.mac}>
              <button type="button" onClick={() => navigate(`/devices?device=${encodeURIComponent(d.mac)}`)} className="flex w-full items-start gap-2.5 px-4 py-2.5 text-left hover:bg-surface-2/60">
                <span className={clsx('mt-1.5 h-2 w-2 shrink-0 rounded-full', DEVICE_STATE[d.state].dot)} />
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-sm text-ink">
                    {d.name}
                    {d.model && d.model !== d.name && <span className="text-ink-3"> · {d.model}</span>}
                  </span>
                  <span className={clsx('block text-xs', d.state === 'offline' || d.update ? 'text-amber-300' : 'text-ink-3')}>
                    {d.state === 'offline'
                      ? `Offline${d.lastSeen ? ` · last seen ${timeAgo(d.lastSeen)}` : ''}`
                      : d.update
                        ? `Update available: ${d.version ?? '?'} → ${d.update}`
                        : d.endOfLife
                          ? 'No more firmware updates'
                          : d.state === 'online'
                            ? `Online${d.clients !== null ? ` · ${plural(d.clients, 'client')}` : ''}`
                            : DEVICE_STATE[d.state].label}
                  </span>
                </span>
              </button>
            </li>
          ))}
          {list.length > 6 && (
            <li className="px-4 py-2 text-xs">
              <Link to="/devices" className={linkCls}>
                {list.length - 6} more →
              </Link>
            </li>
          )}
        </ul>
      )}
      {updates > 0 && <p className="border-t border-line/60 px-4 py-2.5 text-[11px] text-ink-3">Install updates from the UniFi app; this console never installs firmware.</p>}
    </Card>
  );
}

function RecentThreats({ events, fresh }: { events: ThreatEvent[]; fresh: Set<string> }) {
  const navigate = useNavigate();
  if (!events.length) return <EmptyState title="No detections yet">Threats detected by your IPS will appear here in real time.</EmptyState>;
  return (
    <ul className="divide-y divide-line/60">
      {events.map((e) => (
        <li
          key={e.id}
          onClick={() => navigate(`/threats?id=${encodeURIComponent(e.id)}`)}
          className={clsx('flex cursor-pointer items-center gap-3 px-4 py-2.5 hover:bg-surface-2/60', fresh.has(e.id) && 'flash-row')}
        >
          <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: SEVERITY_HEX[e.severity] }} />
          <div className="min-w-0 flex-1">
            <div className="truncate text-sm text-ink">{e.headline}</div>
            <div className="flex min-w-0 items-center gap-1.5 text-xs text-ink-3">
              <EventEnd e={e} ip={e.srcIp} /> <span className="shrink-0">→</span> <EventEnd e={e} ip={e.dstIp} />
            </div>
          </div>
          <div className="hidden shrink-0 items-center gap-1.5 sm:flex">
            <DirectionBadge direction={e.direction} />
            <ActionBadge action={e.action} />
          </div>
          <span className="w-16 shrink-0 text-right text-xs text-ink-3">{timeAgo(e.ts)}</span>
        </li>
      ))}
    </ul>
  );
}

export function MiniMatrix({ m }: { m: SegmentationMatrix }) {
  const nets = m.endpoints.filter((e) => e.kind === 'network');
  const cols = m.endpoints;
  const cell = (from: string, to: string) => m.cells.find((c) => c.from === from && c.to === to);
  return (
    <div>
      <div className="overflow-x-auto">
        <table className="w-full border-separate" style={{ borderSpacing: 3 }}>
          <thead>
            <tr>
              <th />
              {cols.map((c) => (
                <th key={c.id} className="h-16 align-bottom">
                  <div className="mx-auto w-4 origin-bottom-left translate-x-2 -rotate-45 whitespace-nowrap text-[10px] font-normal text-ink-3">{c.name}</div>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {nets.map((r) => (
              <tr key={r.id}>
                <td className="max-w-[90px] truncate pr-1 text-right text-[11px] text-ink-2">{r.name}</td>
                {cols.map((c) => {
                  const x = cell(r.id, c.id);
                  const bg =
                    !x || x.verdict === 'self'
                      ? 'bg-slate-800/40'
                      : x.risk === 'risk'
                        ? 'bg-rose-500/80'
                        : x.risk === 'warn'
                          ? 'bg-amber-400/80'
                          : x.verdict === 'blocked'
                            ? 'bg-emerald-500/50'
                            : x.verdict === 'partial'
                              ? 'bg-emerald-500/25'
                              : 'bg-slate-500/40';
                  return (
                    <td key={c.id} title={x ? `${r.name} → ${c.name}: ${x.summary}` : ''}>
                      <Link to="/firewall" className={clsx('block h-5 min-w-5 rounded-sm', bg)} />
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="mt-3 flex flex-wrap gap-3 text-[11px] text-ink-3">
        <MatrixLegend className="gap-x-3" />
      </div>
    </div>
  );
}
