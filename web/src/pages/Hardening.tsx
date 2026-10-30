import { useEffect, useState } from 'react';
import { Link, useLocation } from 'react-router';
import { useQuery } from '@tanstack/react-query';
import clsx from 'clsx';
import { Ban, ChevronDown, CircleCheck, CircleDashed, CircleX, Flag, FlaskConical, Globe, LockKeyhole, Plug, Router, Server, Shield, Split, Wifi, Wrench } from 'lucide-react';
import type { HardeningTemplate, TemplateStatus, WriteMode } from '@shared/types';
import { api } from '../lib/api';
import { Badge, Button, Card, ErrorBox, Loading, PageHeader } from '../components/ui';
import { useFix } from '../components/FixFlow';
import { AcceptedList, useAcceptRisk } from '../components/AcceptRisk';

const ICONS: Record<string, React.ReactNode> = {
  dns: <Server className="h-4 w-4" />,
  split: <Split className="h-4 w-4" />,
  'globe-lock': <Globe className="h-4 w-4" />,
  router: <Router className="h-4 w-4" />,
  ban: <Ban className="h-4 w-4" />,
  shield: <Shield className="h-4 w-4" />,
  plug: <Plug className="h-4 w-4" />,
  wifi: <Wifi className="h-4 w-4" />,
  flag: <Flag className="h-4 w-4" />,
};

// Most important first.
const ORDER = ['ips-mode', 'isolate-networks', 'block-external-dns', 'protect-gateway', 'block-countries', 'disable-upnp', 'guest-wifi-isolation', 'block-internet', 'block-risky-outbound'];

// Plain words for each state, and the one button that goes with it.
const STATE: Record<TemplateStatus['state'], { label: string; tone: 'green' | 'amber' | 'red' | 'slate'; action: string }> = {
  applied: { label: 'Done', tone: 'green', action: 'View' },
  partial: { label: 'Partly done', tone: 'amber', action: 'Finish' },
  'not-applied': { label: 'Not done', tone: 'red', action: 'Set up' },
  'not-applicable': { label: 'Not needed', tone: 'slate', action: 'Use anyway' },
  unknown: { label: 'Unknown', tone: 'slate', action: 'View' },
};

type Row = { t: HardeningTemplate; s: TemplateStatus | undefined };
type TestNetwork = { id: string; name: string; subnet: string | null; vlan: number | null } | null;

export function HardeningPage() {
  const { data, error, isLoading, refetch } = useQuery({ queryKey: ['templates'], queryFn: api.templates });
  const fix = useFix();
  const accept = useAcceptRisk();
  const rows: Row[] = data
    ? data.templates.filter((t) => !t.hidden).sort((a, b) => ORDER.indexOf(a.id) - ORDER.indexOf(b.id)).map((t) => ({ t, s: data.status.find((x) => x.templateId === t.id) }))
    : [];
  const stateOf = (r: Row) => r.s?.state ?? 'unknown';
  const accepted = rows.filter((r) => r.s?.acceptance);
  const live = rows.filter((r) => !r.s?.acceptance);
  const todo = live.filter((r) => stateOf(r) === 'partial' || stateOf(r) === 'not-applied');
  const done = live.filter((r) => stateOf(r) === 'applied');
  const other = live.filter((r) => !todo.includes(r) && !done.includes(r));
  // In test-network mode the buttons act on the test network (or only preview), so they say so.
  const test = data?.writeMode === 'test-network' ? { id: data.testNetwork?.id ?? null, name: data.testNetwork?.name ?? '' } : null;

  // Test-network substitution of the parameters happens in the preview dialog itself, for every fix button.
  const open = ({ t, s }: Row) =>
    fix.open({ templateId: t.id, params: { ...Object.fromEntries(t.params.filter((p) => p.default !== undefined).map((p) => [p.key, p.default])), ...(s?.suggestedParams ?? {}) }, label: t.title });
  const onAccept = ({ t }: Row) => accept.open({ key: `protection:${t.id}`, kind: 'protection', title: t.title });

  return (
    <div className="space-y-5">
      {fix.node}
      {accept.node}
      <PageHeader
        icon={<Wrench className="h-5 w-5" />}
        title="Hardening"
        subtitle="Protections you can switch on. Every button shows a preview first, reuses rules you already have instead of adding duplicates, and can be undone from the Change Log."
      />
      {data && <ModeNotice mode={data.writeMode} testNetwork={data.testNetwork} onCreate={() => fix.open({ templateId: 'create-test-network', params: {}, label: 'Create test network' })} />}
      {isLoading && <Loading />}
      {error && <ErrorBox error={error} onRetry={() => void refetch()} />}
      {data && (
        <>
          <Progress on={done.length} total={todo.length + done.length} accepted={accepted.length} />
          {todo.length > 0 && <Section title="Worth doing" hint="Not fully done yet. Most important first." rows={todo} onOpen={open} onAccept={onAccept} test={test} />}
          {done.length > 0 && <Section title="Done" rows={done} onOpen={open} test={test} />}
          {other.length > 0 && <Section title="Not needed right now" hint="Nothing on your network needs these today." rows={other} onOpen={open} test={test} />}
          {accepted.length > 0 && (
            <Card id="accepted" title="Accepted risks" subtitle="You decided these are not needed. They no longer count as to-dos." padded={false}>
              <div className="px-4">
                <AcceptedList items={accepted.map((r) => ({ key: `protection:${r.t.id}`, title: r.t.title, acceptance: r.s!.acceptance! }))} />
              </div>
            </Card>
          )}
        </>
      )}
    </div>
  );
}

function ModeNotice({ mode, testNetwork, onCreate }: { mode: WriteMode; testNetwork: TestNetwork; onCreate: () => void }) {
  if (mode === 'full') return null;
  if (mode === 'read-only') {
    return (
      <div className="flex items-start gap-3 rounded-xl border border-amber-500/25 bg-amber-500/5 px-4 py-3 text-sm">
        <LockKeyhole className="mt-0.5 h-4 w-4 shrink-0 text-amber-300" />
        <span className="text-amber-100/90">
          <strong className="font-medium text-amber-100">Preview only.</strong> This environment is read-only: buttons show exactly what would change, but nothing is sent to UniFi. Change it under{' '}
          <Link to="/settings#change-safety" className="underline">
            Settings → Change safety
          </Link>
          .
        </span>
      </div>
    );
  }
  const where = testNetwork ? [testNetwork.subnet, testNetwork.vlan !== null ? `VLAN ${testNetwork.vlan}` : null].filter(Boolean).join(' · ') : '';
  return (
    <div className="flex flex-wrap items-center gap-3 rounded-xl border border-violet-500/30 bg-violet-500/5 px-4 py-3 text-sm">
      <FlaskConical className="h-4 w-4 shrink-0 text-violet-300" />
      <span className="min-w-0 flex-1 text-violet-100/90">
        <strong className="font-medium text-violet-100">Test network only.</strong>{' '}
        {testNetwork
          ? `Buttons only add rules for ${testNetwork.name}${where ? ` (${where})` : ''}. Your real networks and settings can't be changed.`
          : 'Buttons only add rules for a separate test network, so your real networks are never touched. Create one to start.'}
      </span>
      {!testNetwork && (
        <Button size="sm" variant="primary" icon={<FlaskConical className="h-4 w-4" />} onClick={onCreate}>
          Create test network
        </Button>
      )}
    </div>
  );
}

function Progress({ on, total, accepted }: { on: number; total: number; accepted: number }) {
  if (!total && !accepted) return null;
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
      {total > 0 && (
        <>
          <div className="h-2 min-w-32 flex-1 overflow-hidden rounded-full bg-slate-800">
            <div className="h-full rounded-full bg-emerald-500/80 transition-[width]" style={{ width: `${(on / total) * 100}%` }} />
          </div>
          <div className="shrink-0 text-sm text-ink-2">
            <span className="font-semibold text-ink">
              {on} of {total}
            </span>{' '}
            done
          </div>
        </>
      )}
      {/* Accepted risks sit at the bottom of the page; this is the way to them. */}
      {accepted > 0 && (
        <a href="#accepted" className="shrink-0 text-sm text-cyan-300 hover:text-cyan-200">
          {accepted} accepted risk{accepted === 1 ? '' : 's'} ↓
        </a>
      )}
    </div>
  );
}

type TestInfo = { id: string | null; name: string } | null;

function Section(props: { title: string; hint?: string; rows: Row[]; onOpen: (r: Row) => void; onAccept?: (r: Row) => void; test: TestInfo }) {
  return (
    <Card title={props.title} subtitle={props.hint} padded={false}>
      <ul className="divide-y divide-line/60">
        {props.rows.map((r) => (
          <ProtectionRow key={r.t.id} row={r} onOpen={() => props.onOpen(r)} onAccept={props.onAccept && (() => props.onAccept!(r))} test={props.test} />
        ))}
      </ul>
    </Card>
  );
}

/** What the row's button says: in test-network mode it acts on the test network (or only previews site settings). */
function actionLabel(t: HardeningTemplate, s: TemplateStatus | undefined, test: TestInfo): string {
  const state = s?.state ?? 'unknown';
  const ui = STATE[state];
  if (!test || state === 'applied') return ui.action;
  if (t.kind === 'setting') return state === 'partial' || state === 'not-applied' ? 'Preview' : ui.action;
  if (!test.id || !test.name) return ui.action;
  const onTest = (s?.targets ?? []).filter((x) => x.id === test.id || x.id.startsWith(`${test.id}>`));
  return onTest.length && onTest.every((x) => x.state === 'covered') ? `Done on ${test.name}` : `Try on ${test.name}`;
}

function ProtectionRow({ row: { t, s }, onOpen, onAccept, test }: { row: Row; onOpen: () => void; onAccept?: () => void; test: TestInfo }) {
  // A link such as /hardening#block-external-dns (from the to-fix list) lands on this row, opened and highlighted.
  const targeted = useLocation().hash === `#${t.id}`;
  const [open, setOpen] = useState(targeted);
  useEffect(() => {
    if (!targeted) return;
    setOpen(true);
    const timer = setTimeout(() => document.getElementById(t.id)?.scrollIntoView({ block: 'center' }), 50);
    return () => clearTimeout(timer);
  }, [targeted, t.id]);
  const state = s?.state ?? 'unknown';
  const ui = STATE[state];
  const missing = s?.targets.filter((x) => !x.test && x.state !== 'covered') ?? [];
  const actionable = state === 'partial' || state === 'not-applied';
  const label = actionLabel(t, s, test);
  const primary = actionable && !label.startsWith('Done on') && label !== 'Preview';
  return (
    <li id={t.id} className={clsx('scroll-mt-4', targeted && 'bg-cyan-500/5 ring-1 ring-inset ring-cyan-500/30')}>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2 px-4 py-3">
        <span
          className={clsx(
            'flex h-9 w-9 shrink-0 items-center justify-center rounded-lg',
            state === 'applied' ? 'bg-emerald-500/10 text-emerald-300' : actionable ? 'bg-cyan-500/10 text-cyan-300' : 'bg-surface-3 text-ink-3',
          )}
        >
          {ICONS[t.icon] ?? <Shield className="h-4 w-4" />}
        </span>
        <button type="button" onClick={() => setOpen((o) => !o)} aria-expanded={open} className="min-w-[12rem] flex-1 text-left">
          <span className="flex flex-wrap items-center gap-2">
            <span className="text-sm font-medium text-ink">{t.title}</span>
            <Badge tone={ui.tone}>{ui.label}</Badge>
          </span>
          <span className="mt-0.5 block text-xs leading-relaxed text-ink-3">{t.summary}</span>
          {state === 'partial' && missing.length > 0 && <span className="mt-1 block text-xs text-amber-200/90">Not done yet for {missing.map((x) => x.name).join(', ')}</span>}
        </button>
        {/* Wraps under the text on narrow screens. */}
        <div className="ml-auto flex items-center gap-1">
          {onAccept && (
            <button type="button" onClick={onAccept} className="whitespace-nowrap rounded-md px-2 py-1 text-xs text-ink-3 hover:bg-surface-3 hover:text-ink-2">
              Accept risk…
            </button>
          )}
          <Button size="sm" variant={primary ? 'primary' : 'secondary'} onClick={onOpen}>
            {label}
          </Button>
          <button
            type="button"
            onClick={() => setOpen((o) => !o)}
            aria-label={open ? 'Hide details' : 'Show details'}
            className="hidden rounded-md p-1 text-ink-3 hover:bg-surface-3 hover:text-ink sm:block"
          >
            <ChevronDown className={clsx('h-4 w-4 transition-transform', open && 'rotate-180')} />
          </button>
        </div>
      </div>
      {open && <Details t={t} s={s} />}
    </li>
  );
}

function Details({ t, s }: Row) {
  return (
    <div className="space-y-3 border-t border-line/60 bg-surface-2/30 px-4 py-3 text-xs leading-relaxed sm:pl-16">
      {s && s.targets.length > 0 && (
        <div>
          <div className="mb-1 font-medium text-ink-2">On your networks</div>
          <ul className="space-y-1">
            {s.targets.map((x) => (
              <li key={x.id} className="flex items-start gap-2">
                {x.state === 'covered' ? (
                  <CircleCheck className="mt-px h-3.5 w-3.5 shrink-0 text-emerald-400" />
                ) : x.state === 'partial' ? (
                  <CircleDashed className="mt-px h-3.5 w-3.5 shrink-0 text-amber-400" />
                ) : (
                  <CircleX className="mt-px h-3.5 w-3.5 shrink-0 text-rose-400" />
                )}
                <span>
                  <span className="text-ink">{x.name}</span>
                  {x.test && <span className="ml-1 rounded bg-violet-500/20 px-1 text-[10px] font-semibold text-violet-200">TEST</span>}{' '}
                  <span className="text-ink-3">— {x.detail}</span>
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
      {s && !s.targets.length && s.detail && <p className="text-ink-3">{s.detail}</p>}
      <div>
        <div className="mb-0.5 font-medium text-ink-2">Why it matters</div>
        <p className="text-ink-3">{t.why}</p>
      </div>
      {t.caveats.length > 0 && (
        <div>
          <div className="mb-0.5 font-medium text-ink-2">Good to know</div>
          <ul className="list-disc space-y-0.5 pl-4 text-ink-3">
            {t.caveats.map((c) => (
              <li key={c}>{c}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
