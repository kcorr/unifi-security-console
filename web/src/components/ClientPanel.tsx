import { Link, useNavigate } from 'react-router';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import clsx from 'clsx';
import { DoorOpen, ExternalLink, Fingerprint, ScanSearch, ShieldAlert, ShieldCheck } from 'lucide-react';
import type { ClientDetail } from '@shared/types';
import { NETWORK_ROLES } from '@shared/types';
import { api } from '../lib/api';
import { fmtBps, fmtBytes, fmtDuration, fmtNum, fmtTime, timeAgo } from '../lib/format';
import { ActionBadge, Badge, Button, Callout, DirectionBadge, Drawer, ErrorBox, EventEnd, KV, Loading, REACH_STYLE, reachLabel, SEVERITY_HEX } from './ui';
import { HourlyUsage } from './charts';

/** A detail row, left out when the value is unknown. */
function Row({ k, v, mono }: { k: string; v: React.ReactNode; mono?: boolean }) {
  return v === null || v === undefined || v === '' ? null : <KV k={k} v={v} mono={mono} />;
}

const signalWord = (dbm: number) => (dbm >= -60 ? 'excellent' : dbm >= -67 ? 'good' : dbm >= -75 ? 'fair' : 'weak');

/** Everything about one device on your network, opened from Top talkers (and anywhere else that lists clients). */
export function ClientPanel({ mac, onClose }: { mac: string | null; onClose: () => void }) {
  const q = useQuery({ queryKey: ['client', mac], queryFn: () => api.clientDetail(mac!), enabled: !!mac, refetchInterval: 15_000, retry: false });
  const d = q.data;
  return (
    <Drawer
      open={!!mac}
      onClose={onClose}
      title={d?.name ?? 'Device'}
      subtitle={d ? [d.ip, d.mac, d.identity.maker].filter(Boolean).join(' · ') : undefined}
      footer={
        d?.ip ? (
          <div className="flex flex-wrap gap-2">
            <Link to={`/investigate/${encodeURIComponent(d.ip)}`} className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-line-2 bg-surface-2 px-3 text-xs text-ink hover:bg-surface-3">
              <ScanSearch className="h-3.5 w-3.5" /> Full investigation
            </Link>
            <Link to={`/threats?ip=${encodeURIComponent(d.ip)}&range=30d`} className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-line-2 bg-surface-2 px-3 text-xs text-ink hover:bg-surface-3">
              All its detections
            </Link>
          </div>
        ) : undefined
      }
    >
      {q.isLoading && <Loading />}
      {q.error && <ErrorBox error={q.error} />}
      {d && (
        <div className="space-y-6">
          <div className="flex flex-wrap gap-1.5">
            <Badge tone="slate">{d.connection.wired ? 'Wired' : 'Wi-Fi'}</Badge>
            {d.connection.guest && <Badge tone="amber">Guest</Badge>}
            {d.firstSeen && Date.now() - d.firstSeen < 7 * 86400e3 && <Badge tone="cyan">New this week</Badge>}
            {d.network.role && <Badge tone="slate">{NETWORK_ROLES.find((r) => r.value === d.network.role)?.label} network</Badge>}
          </div>
          <Security d={d} />
          <Identify d={d} />
          <Traffic d={d} />
          <Connection d={d} />
        </div>
      )}
    </Drawer>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section>
      <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-ink-3">{title}</h3>
      {children}
    </section>
  );
}

function Security({ d }: { d: ClientDetail }) {
  const navigate = useNavigate();
  const s = d.security;
  const t = s.threats;
  return (
    <Section title="Security">
      <div className="space-y-3">
        {s.suspect && (
          <Callout tone="danger" icon={<ShieldAlert className="h-4 w-4" />} title="Behaves like it may be compromised">
            It started traffic in the last 7 days that your intrusion prevention flagged as an attack or malware. Check the detections below.
          </Callout>
        )}
        {s.exposedBy.length > 0 && (
          <Callout tone={s.exposedBy.some((e) => e.severity === 'critical' || e.severity === 'high') ? 'danger' : 'warn'} icon={<DoorOpen className="h-4 w-4" />} title="Reachable from the internet">
            {s.exposedBy.map((e) => `port forward “${e.name}” opens ${e.what}${e.limited ? ' to a limited set of addresses' : ' to anyone'}`).join('; ')}.{' '}
            <Link to="/firewall/exposure" className="underline">
              Internet exposure
            </Link>
          </Callout>
        )}
        {t.total === 0 ? (
          <div className="flex items-center gap-2 text-sm text-emerald-300">
            <ShieldCheck className="h-4 w-4" /> No intrusion-prevention detections involved it in the last 30 days.
          </div>
        ) : (
          <>
            <div className="grid grid-cols-2 gap-x-6 gap-y-2 rounded-lg border border-line bg-surface-2/40 p-3 text-sm sm:grid-cols-4">
              {[
                ['Detections · 30 days', fmtNum(t.total), 'text-ink'],
                ['Blocked', fmtNum(t.blocked), 'text-emerald-300'],
                ['Aimed at it', fmtNum(t.aimedAt), 'text-ink'],
                ['Started by it', fmtNum(t.startedBy), t.startedBy ? 'text-violet-300' : 'text-ink'],
              ].map(([k, v, cls]) => (
                <div key={k}>
                  <div className="text-[11px] text-ink-3">{k}</div>
                  <div className={clsx('mono', cls)}>{v}</div>
                </div>
              ))}
            </div>
            <ul className="divide-y divide-line/50 rounded-lg border border-line">
              {t.recent.slice(0, 10).map((e) => {
                // The other end: for traffic inside your network that is another device (or the honeypot), not this one.
                const peer = e.srcIp === d.ip ? 'dst' : 'src';
                return (
                  <li key={e.id} className="flex cursor-pointer items-center gap-2 px-3 py-2 text-sm hover:bg-surface-2/60" onClick={() => navigate(`/threats?id=${encodeURIComponent(e.id)}`)}>
                    <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: SEVERITY_HEX[e.severity] }} />
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-ink">{e.headline}</span>
                      <span className="flex min-w-0 items-center gap-1 text-xs text-ink-3">
                        <span className="shrink-0">{timeAgo(e.ts)} ·</span>
                        <EventEnd e={e} end={peer} />
                      </span>
                    </span>
                    <span className="hidden sm:contents">
                      <DirectionBadge direction={e.direction} />
                    </span>
                    <ActionBadge action={e.action} />
                  </li>
                );
              })}
            </ul>
          </>
        )}
        {s.reach.length > 0 && (
          <div>
            <div className="mb-1 text-xs text-ink-3">
              From the {d.network.name} network it can reach (
              <Link to="/firewall" className="text-cyan-300 hover:text-cyan-200">
                details
              </Link>
              ):
            </div>
            <div className="flex flex-wrap gap-1.5">
              {s.reach.map((r) => (
                <span
                  key={r.to}
                  title={r.summary}
                  className={clsx('rounded-md border px-2 py-0.5 text-xs', r.risk === 'risk' ? 'border-rose-500/50 text-rose-200' : r.risk === 'warn' ? 'border-amber-500/50 text-amber-200' : 'border-line text-ink-2')}
                >
                  {r.to}: <span className={clsx(REACH_STYLE[r.verdict].tone === 'green' ? 'text-emerald-300' : '')}>{reachLabel(r).toLowerCase()}</span>
                </span>
              ))}
            </div>
          </div>
        )}
      </div>
    </Section>
  );
}

function Identify({ d }: { d: ClientDetail }) {
  const qc = useQueryClient();
  const i = d.identity;
  const missingMaker = !i.maker && !i.privateAddress;
  const makers = useQuery({ queryKey: ['makers'], queryFn: api.makers, enabled: missingMaker });
  const download = useMutation({ mutationFn: api.downloadMakers, onSuccess: () => void qc.invalidateQueries() });
  return (
    <Section title="What is this?">
      <div className="space-y-2 rounded-lg border border-line bg-surface-2/40 p-3 text-sm">
        <div className="flex items-start gap-2">
          <Fingerprint className="mt-0.5 h-4 w-4 shrink-0 text-cyan-300" />
          <div>
            <div className="text-ink">{i.guess ? `Probably ${i.guess}` : 'No strong clue yet'}</div>
            {i.confidence && <div className="text-[11px] text-ink-3">{i.confidence === 'high' ? 'Strong clues' : i.confidence === 'medium' ? 'Likely, from its maker or fingerprint' : 'A rough guess'}</div>}
          </div>
        </div>
        {i.clues.length > 0 && (
          <ul className="ml-6 list-disc space-y-0.5 text-xs leading-relaxed text-ink-2">
            {i.clues.map((c) => (
              <li key={c}>{c}</li>
            ))}
          </ul>
        )}
        {missingMaker && makers.data && !makers.data.installed && (
          <div className="ml-6 rounded-md border border-line bg-surface/60 p-2 text-xs text-ink-2">
            UniFi doesn’t know its maker. The public IEEE register can tell from the first half of its address, entirely on this machine.
            <div className="mt-1.5">
              <Button size="xs" variant="secondary" loading={download.isPending || makers.data.downloading} onClick={() => download.mutate()}>
                Download the makers register (IEEE, about 5 MB)
              </Button>
            </div>
            {(download.data?.error ?? makers.data.error) && <div className="mt-1 text-rose-300">{download.data?.error ?? makers.data.error}</div>}
          </div>
        )}
        {i.lookups.length > 0 && (
          <div className="ml-6 flex flex-wrap gap-2 pt-1 text-xs">
            {i.lookups.map((l) => (
              <a key={l.url} href={l.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 rounded-md bg-surface-3 px-2 py-1 text-ink-2 hover:text-cyan-200">
                {l.label} <ExternalLink className="h-3 w-3" />
              </a>
            ))}
          </div>
        )}
      </div>
    </Section>
  );
}

function Traffic({ d }: { d: ClientDetail }) {
  const t = d.traffic;
  return (
    <Section title="Traffic">
      <dl className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm sm:grid-cols-3">
        <div>
          <dt className="text-[11px] text-ink-3">Right now</dt>
          <dd className="mono text-xs text-ink">
            <span className="text-cyan-200">↓ {fmtBps(t.downBps)}</span> <span className="text-violet-200">↑ {fmtBps(t.upBps)}</span>
          </dd>
        </div>
        <div>
          <dt className="text-[11px] text-ink-3">Last 24 hours</dt>
          <dd className="mono text-xs text-ink">{t.down24h === null ? '—' : `↓ ${fmtBytes(t.down24h)} ↑ ${fmtBytes(t.up24h ?? 0)}`}</dd>
        </div>
        <div>
          <dt className="text-[11px] text-ink-3">Since it connected{d.uptime ? ` (${fmtDuration(d.uptime)})` : ''}</dt>
          <dd className="mono text-xs text-ink">
            ↓ {fmtBytes(t.downSince)} ↑ {fmtBytes(t.upSince)}
          </dd>
        </div>
      </dl>
      {t.hourly.length > 1 && (
        <div className="mt-3">
          <div className="mb-1 text-[11px] text-ink-3">Per hour, last 24 hours (all traffic, including to your own devices)</div>
          <HourlyUsage hours={t.hourly} />
        </div>
      )}
    </Section>
  );
}

function Connection({ d }: { d: ClientDetail }) {
  const c = d.connection;
  return (
    <Section title="Connection">
      <dl>
        <Row k="Network" v={[d.network.name, d.network.vlan !== null ? `VLAN ${d.network.vlan}` : null].filter(Boolean).join(' · ') || null} />
        <Row k="Connected to" v={c.via ? `${c.via}${c.port !== null ? `, port ${c.port}` : ''}` : null} />
        {c.wired ? (
          <Row k="Link speed" v={c.linkMbps ? `${c.linkMbps >= 1000 ? `${c.linkMbps / 1000} Gbps` : `${c.linkMbps} Mbps`}` : null} />
        ) : (
          <>
            <Row k="Wi-Fi" v={[c.ssid, c.band, c.standard].filter(Boolean).join(' · ') || null} />
            <Row k="Channel" v={c.channel !== null ? `${c.channel}${c.channelWidth ? ` (${c.channelWidth} MHz)` : ''}` : null} />
            <Row k="Signal" v={c.signal !== null ? `${c.signal} dBm, ${signalWord(c.signal)}` : null} />
            <Row k="Link rates" v={c.rxRateMbps !== null ? `receive ${c.rxRateMbps} Mbps · send ${c.txRateMbps} Mbps` : null} />
            <Row k="Streams (MIMO)" v={c.streams} />
            <Row k="Retries" v={c.retriesPct !== null ? `${c.retriesPct}%${c.retriesPct > 10 ? ' (high: weak signal or interference)' : ''}` : null} />
          </>
        )}
        <Row k="Experience" v={c.experience !== null ? `${c.experience}%` : null} />
        <Row k="Hostname" v={d.hostname} mono />
        <Row k="MAC address" v={d.mac} mono />
        {d.ipv6.length > 0 && <Row k="IPv6" v={d.ipv6.join(', ')} mono />}
        <Row k="First seen" v={d.firstSeen ? `${fmtTime(d.firstSeen)} (${timeAgo(d.firstSeen)})` : null} />
        <Row k="Connected for" v={d.uptime ? fmtDuration(d.uptime) : null} />
      </dl>
    </Section>
  );
}
