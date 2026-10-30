import { useMemo, useState } from 'react';
import { Link, useParams } from 'react-router';
import { useQuery } from '@tanstack/react-query';
import clsx from 'clsx';
import { BookOpen, ChevronRight, Search } from 'lucide-react';
import type { ThreatCategory, ThreatFamily } from '@shared/types';
import { api } from '../lib/api';
import { Badge, Card, ErrorBox, Loading, PageHeader, SeverityBadge } from '../components/ui';

const FAMILY_LABEL: Record<ThreatFamily, string> = {
  recon: 'Reconnaissance',
  credential: 'Credential attacks',
  reputation: 'Threat intelligence',
  anonymizer: 'Anonymizers',
  exploit: 'Exploitation',
  web: 'Web attacks',
  malware: 'Malware & compromise',
  dos: 'Denial of service',
  policy: 'Policy & behaviour',
  info: 'Informational',
  protocol: 'Protocol',
  other: 'Other',
};

const FAMILY_ORDER: ThreatFamily[] = ['malware', 'exploit', 'web', 'credential', 'recon', 'reputation', 'anonymizer', 'dos', 'policy', 'protocol', 'info', 'other'];

export function ThreatTypesPage() {
  const { key } = useParams();
  const { data, error, isLoading, refetch } = useQuery({ queryKey: ['threat-categories'], queryFn: api.threatCategories, staleTime: Infinity });
  const [q, setQ] = useState('');

  const grouped = useMemo(() => {
    const list = (data ?? []).filter((c) => !q || `${c.name} ${c.summary} ${c.description}`.toLowerCase().includes(q.toLowerCase()));
    return FAMILY_ORDER.map((f) => ({ family: f, items: list.filter((c) => c.family === f) })).filter((g) => g.items.length);
  }, [data, q]);

  const selected = data?.find((c) => c.key === key) ?? null;

  return (
    <div>
      <PageHeader
        icon={<BookOpen className="h-5 w-5" />}
        title="Threat Encyclopedia"
        subtitle="Plain-English explanations of every kind of detection your UniFi IPS can raise — what it is, why it matters, and what to do about it."
      />
      {isLoading && <Loading />}
      {error && <ErrorBox error={error} onRetry={() => void refetch()} />}
      {data && (
        <div className="grid gap-5 lg:grid-cols-[340px_1fr]">
          <div className="space-y-4">
            <div className="relative">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-ink-3" />
              <input
                value={q}
                onChange={(e) => setQ(e.target.value)}
                placeholder="Filter threat types…"
                className="h-9 w-full rounded-lg border border-line bg-surface-2 pl-9 pr-3 text-sm text-ink placeholder:text-ink-3 focus:border-cyan-500/50 focus:outline-none"
              />
            </div>
            {grouped.map((g) => (
              <div key={g.family}>
                <div className="mb-1.5 px-1 text-[11px] font-semibold uppercase tracking-wider text-ink-3">{FAMILY_LABEL[g.family]}</div>
                <div className="space-y-1">
                  {g.items.map((c) => (
                    <Link
                      key={c.key}
                      to={`/learn/${c.key}`}
                      className={clsx(
                        'flex items-center justify-between gap-2 rounded-lg border px-3 py-2 text-sm transition-colors',
                        selected?.key === c.key ? 'border-cyan-500/40 bg-cyan-500/10 text-ink' : 'border-transparent text-ink-2 hover:bg-surface-2',
                      )}
                    >
                      <span className="truncate">{c.name}</span>
                      <ChevronRight className="h-4 w-4 shrink-0 text-ink-3" />
                    </Link>
                  ))}
                </div>
              </div>
            ))}
          </div>
          <div>{selected ? <CategoryDetail c={selected} /> : <Intro categories={data} />}</div>
        </div>
      )}
    </div>
  );
}

function Intro({ categories }: { categories: ThreatCategory[] }) {
  return (
    <Card title="How to read IPS detections">
      <div className="space-y-3 text-sm leading-relaxed text-ink-2">
        <p>
          UniFi's Intrusion Prevention System inspects traffic with thousands of <strong className="text-ink">signatures</strong> (mostly the Proofpoint Emerging Threats
          ruleset). A signature name like <code className="mono rounded bg-surface-3 px-1 text-[12px] text-cyan-200">ET SCAN Suspicious inbound to mySQL port 3306</code> tells you the
          ruleset (<em>ET</em>), the category (<em>SCAN</em>) and what was seen.
        </p>
        <p>The same detection means very different things depending on its direction:</p>
        <ul className="ml-5 list-disc space-y-1">
          <li>
            <strong className="text-ink">Inbound</strong> — someone on the internet poked at your public IP. Usually background noise; only important if the targeted service is actually exposed.
          </li>
          <li>
            <strong className="text-ink">Outbound</strong> — a device on <em>your</em> network started the connection. Malware or exploit categories here are serious: the device may be infected.
          </li>
          <li>
            <strong className="text-ink">Internal</strong> — between your own devices. Attack-like traffic here can mean something is spreading inside your network.
          </li>
        </ul>
        <p>
          The console grades every event with this context, so a blocked inbound port scan is <SeverityBadge severity="low" /> while the same malware signature from one of your laptops is{' '}
          <SeverityBadge severity="critical" />.
        </p>
        <p className="text-ink-3">{categories.length} threat types documented. Pick one on the left.</p>
      </div>
    </Card>
  );
}

export function CategoryDetail({ c, compact }: { c: ThreatCategory; compact?: boolean }) {
  return (
    <div className="space-y-4">
      <Card
        title={
          <span className="flex items-center gap-2">
            {c.name} <Badge tone="slate">{FAMILY_LABEL[c.family]}</Badge>
          </span>
        }
        subtitle={c.summary}
        actions={<SeverityBadge severity={c.defaultSeverity} />}
      >
        <div className="space-y-4 text-sm leading-relaxed">
          <section>
            <h3 className="mb-1 text-xs font-semibold uppercase tracking-wider text-ink-3">What it is</h3>
            <p className="text-ink-2">{c.description}</p>
          </section>
          <section>
            <h3 className="mb-1 text-xs font-semibold uppercase tracking-wider text-ink-3">Why it matters</h3>
            <p className="text-ink-2">{c.whyItMatters}</p>
          </section>
          {!compact && (
            <section className="grid gap-3 md:grid-cols-3">
              {(
                [
                  ['Inbound', c.inbound],
                  ['Outbound', c.outbound],
                  ['Internal', c.internal],
                ] as const
              ).map(([k, v]) => (
                <div key={k} className="rounded-lg border border-line bg-surface-2/60 p-3">
                  <div className="mb-1 text-xs font-semibold text-ink">{k}</div>
                  <div className="text-xs leading-relaxed text-ink-2">{v}</div>
                </div>
              ))}
            </section>
          )}
          <section>
            <h3 className="mb-1 text-xs font-semibold uppercase tracking-wider text-ink-3">What to do</h3>
            <ul className="ml-5 list-disc space-y-1 text-ink-2">
              {c.recommendations.map((r) => (
                <li key={r}>{r}</li>
              ))}
            </ul>
          </section>
          {c.falsePositives && (
            <section>
              <h3 className="mb-1 text-xs font-semibold uppercase tracking-wider text-ink-3">Common false positives</h3>
              <p className="text-ink-2">{c.falsePositives}</p>
            </section>
          )}
          {c.mitre && c.mitre.length > 0 && (
            <section className="flex flex-wrap items-center gap-2">
              <span className="text-xs text-ink-3">MITRE ATT&amp;CK:</span>
              {c.mitre.map((m) => (
                <a
                  key={m.id}
                  href={`https://attack.mitre.org/techniques/${m.id.replace('.', '/')}/`}
                  target="_blank"
                  rel="noreferrer"
                  className="rounded-md bg-surface-3 px-2 py-0.5 text-xs text-cyan-200 hover:bg-surface-2"
                >
                  {m.id} · {m.name} <span className="text-ink-3">({m.tactic})</span>
                </a>
              ))}
            </section>
          )}
        </div>
      </Card>
      {!compact && (
        <Link to={`/threats?category=${c.key}`} className="inline-flex items-center gap-1 text-sm text-cyan-300 hover:text-cyan-200">
          See detections of this type on your network <ChevronRight className="h-4 w-4" />
        </Link>
      )}
    </div>
  );
}
