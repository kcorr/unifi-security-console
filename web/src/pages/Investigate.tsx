import { useState, type FormEvent } from 'react';
import { Link, useNavigate, useParams } from 'react-router';
import { useQuery } from '@tanstack/react-query';
import clsx from 'clsx';
import {
  Ban, Building2, CircleAlert, DoorOpen, ExternalLink, Fingerprint, Flame, Globe, Laptop, MapPin, Network, RefreshCw, ScanSearch, Search, Server, ShieldCheck, ShieldQuestion, Skull,
} from 'lucide-react';
import type { IpIntel, ReachVerdict } from '@shared/types';
import { api } from '../lib/api';
import { countryName, fmtNum, fmtTime, timeAgo } from '../lib/format';
import { Badge, Button, Callout, Card, CopyButton, CountryTag, DirectionBadge, EmptyState, ErrorBox, IpLink, KV, Loading, PageHeader, REACH_STYLE, SeverityBadge, VerdictBadge } from '../components/ui';
import { useFix } from '../components/FixFlow';

export function InvestigatePage() {
  const { ip } = useParams();
  const navigate = useNavigate();
  const [q, setQ] = useState(ip ?? '');
  const [refresh, setRefresh] = useState(0);
  const intel = useQuery({ queryKey: ['intel', ip, refresh], queryFn: () => api.intel(ip!, refresh > 0), enabled: !!ip, retry: false });
  const fix = useFix();

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (q.trim()) navigate(`/investigate/${encodeURIComponent(q.trim())}`);
  };

  return (
    <div className="space-y-5">
      {fix.node}
      <PageHeader
        icon={<ScanSearch className="h-5 w-5" />}
        title="Investigate an IP"
        subtitle="Who owns an address, where it is, what it runs, whether it is known for abuse — and everything it has done on your network."
        actions={
          ip && (
            <Button size="sm" variant="ghost" icon={<RefreshCw className="h-3.5 w-3.5" />} loading={intel.isFetching} onClick={() => setRefresh((r) => r + 1)}>
              Refresh lookups
            </Button>
          )
        }
      />
      <form onSubmit={submit} className="flex max-w-xl gap-2">
        <div className="relative flex-1">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-ink-3" />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="e.g. 45.142.193.6 or 192.168.30.40"
            className="mono h-10 w-full rounded-lg border border-line bg-surface-2 pl-9 pr-3 text-sm text-ink placeholder:text-ink-3 focus:border-cyan-500/50 focus:outline-none"
          />
        </div>
        <Button type="submit" variant="primary" className="h-10">
          Investigate
        </Button>
      </form>

      {!ip && <Suggestions />}
      {ip && intel.isLoading && <Loading label={`Looking up ${ip}…`} />}
      {ip && intel.error && <ErrorBox error={intel.error} />}
      {intel.data && <IntelView i={intel.data} onBlock={() => fix.open({ templateId: 'block-ip', params: { ips: [intel.data!.ip], direction: 'both' }, label: `Block ${intel.data!.ip}` })} />}
    </div>
  );
}

function Suggestions() {
  const now = Math.floor(Date.now() / 60e3) * 60e3;
  const s = useQuery({ queryKey: ['threats', 'summary', 'suggest', now], queryFn: () => api.threatSummary({ from: now - 86400e3 }) });
  if (!s.data) return null;
  return (
    <Card title="Most active sources in the last 24 hours" subtitle="Pick one to see who it is." padded={false}>
      {s.data.topSources.length === 0 ? (
        <EmptyState title="No activity yet" />
      ) : (
        <ul className="divide-y divide-line/50">
          {s.data.topSources.slice(0, 12).map((x) => (
            <li key={x.ip}>
              <Link to={`/investigate/${encodeURIComponent(x.ip)}`} className="flex items-center gap-3 px-4 py-2.5 hover:bg-surface-2/50">
                <CountryTag code={x.country} />
                <span className="mono text-sm text-ink">{x.ip}</span>
                <span className="truncate text-xs text-ink-3">{x.org ?? ''}</span>
                <span className="ml-auto flex items-center gap-2">
                  <SeverityBadge severity={x.severity} />
                  <span className="mono text-xs text-ink-2">{fmtNum(x.count)}</span>
                </span>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

function IntelView({ i, onBlock }: { i: IpIntel; onBlock: () => void }) {
  const internal = i.scope !== 'public';
  const levelColor = { malicious: 'text-rose-300', suspicious: 'text-orange-300', scanner: 'text-sky-300', cloud: 'text-violet-300', benign: 'text-emerald-300', unknown: 'text-ink-2', internal: 'text-cyan-300' }[i.verdict.level];
  // Blocking is the obvious move only for addresses known to be bad; for everything else it stays a quiet option.
  const risky = i.verdict.level === 'malicious' || i.verdict.level === 'suspicious';
  const fullyBlocked = i.blocking?.inbound === 'blocked' && i.blocking.outbound === 'blocked';
  return (
    <div className="space-y-4">
      <div className="rounded-2xl border border-line bg-gradient-to-br from-surface to-surface-2 p-5">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <span className="mono break-all text-2xl font-semibold text-ink">{i.ip}</span>
              <CopyButton text={i.ip} />
              <VerdictBadge level={i.verdict.level} />
              <Badge tone="slate">{i.scopeLabel}</Badge>
              {i.geo?.countryCode && <CountryTag code={i.geo.countryCode} showName />}
            </div>
            <p className={clsx('mt-2 max-w-3xl text-sm leading-relaxed', levelColor)}>{i.verdict.summary}</p>
            {i.verdict.reasons.length > 0 && (
              <ul className="mt-2 ml-4 list-disc space-y-0.5 text-sm text-ink-2">
                {i.verdict.reasons.map((r) => (
                  <li key={r}>{r}</li>
                ))}
              </ul>
            )}
          </div>
          {!internal && (
            <div className="w-full shrink-0 sm:w-56">
              <div className="flex items-baseline justify-between text-xs text-ink-3">
                <span>Risk score</span>
                <span className="mono text-lg font-semibold text-ink">{i.verdict.score}</span>
              </div>
              <div className="mt-1 h-2 overflow-hidden rounded-full bg-slate-800">
                <div className="h-full rounded-full bg-gradient-to-r from-emerald-400 via-amber-400 to-rose-500" style={{ width: `${Math.max(3, i.verdict.score)}%` }} />
              </div>
              {!fullyBlocked && (
                <Button size="sm" variant={risky ? 'danger' : 'secondary'} icon={<Ban className="h-3.5 w-3.5" />} className="mt-3 w-full" onClick={onBlock}>
                  Block this IP
                </Button>
              )}
            </div>
          )}
        </div>
        {!internal && <FirewallLine i={i} />}
      </div>

      {internal && <InternalCard i={i} />}
      <Activity i={i} />
      {!internal && <Details i={i} />}

      <div className="flex flex-wrap items-center gap-2 text-xs text-ink-3">
        <span>Sources:</span>
        {i.sources.map((s) => (
          <span key={s.name} className={clsx('rounded-md px-2 py-0.5', s.ok ? 'bg-emerald-500/10 text-emerald-300' : 'bg-slate-700/40 text-ink-3')} title={s.at ? `Retrieved ${fmtTime(s.at)}` : 'Local database'}>
            {s.name}
            {s.at ? ` · ${s.cached ? 'cached ' : ''}${timeAgo(s.at)}` : ''}
            {!s.ok && s.error ? ` — ${s.error}` : ''}
          </span>
        ))}
        {i.sources.length === 0 && <span>local data only</span>}
        <span className="ml-auto">Looked up {timeAgo(i.fetchedAt)}</span>
      </div>
    </div>
  );
}

/** What your own firewall does with this address, in one line under the verdict. */
function FirewallLine({ i }: { i: IpIntel }) {
  const b = i.blocking;
  if (!b) return null;
  const state = (v: ReachVerdict) => (
    <Badge tone={v === 'blocked' ? 'green' : v === 'partial' ? 'amber' : 'slate'}>{v === 'allowed' ? 'not specifically blocked' : REACH_STYLE[v].label}</Badge>
  );
  return (
    <div className="mt-4 flex flex-wrap items-center gap-x-4 gap-y-1.5 border-t border-line/60 pt-3 text-sm">
      <span className="flex items-center gap-1.5 text-ink-3">
        <ShieldCheck className="h-4 w-4" /> Your firewall:
      </span>
      <span className="flex items-center gap-1.5 text-ink-2">From it {state(b.inbound)}</span>
      <span className="flex items-center gap-1.5 text-ink-2">To it {state(b.outbound)}</span>
      {b.rules.length > 0 && <span className="text-xs text-ink-3">by {b.rules.map((r) => `“${r.name}”`).join(', ')}</span>}
    </div>
  );
}

type Row = [label: string, value: React.ReactNode, mono?: boolean];
/** Only facts that are actually known: an empty row tells a non-expert nothing. */
const known = (rows: Row[]) => rows.filter(([, v]) => v !== null && v !== undefined && v !== '');

/** Everything the lookups found, in one card; sections with nothing in them are left out. */
function Details({ i }: { i: IpIntel }) {
  const reg = i.registration;
  const net = i.network;
  const geo = i.geo;
  const rep = i.reputation;
  // "Data center" from the verdict and "residential" from the network lookup must never both show.
  const hosting = net?.hosting === true || i.verdict.level === 'cloud';
  const connection = hosting || net?.proxy || net?.mobile ? (
    <span className="flex flex-wrap justify-end gap-1">
      {hosting && <Badge tone="violet">Data center / cloud</Badge>}
      {net?.proxy && <Badge tone="orange">Proxy / VPN</Badge>}
      {net?.mobile && <Badge tone="blue">Mobile</Badge>}
    </span>
  ) : net?.hosting === false && net.proxy === false && net.mobile === false ? (
    'Residential / business'
  ) : null;
  const sections: { title: string; icon: React.ReactNode; rows: Row[]; extra?: React.ReactNode }[] = [
    {
      title: 'Who owns it',
      icon: <Building2 className="h-4 w-4" />,
      rows: known([
        ['Organisation', reg?.registrant ?? net?.org ?? null],
        ['Network name', reg?.name ?? null],
        ['Address block', reg?.cidr ?? reg?.range ?? null, true],
        ['Registry', reg?.registry ?? null],
        ['Registered in', reg?.country ? countryName(reg.country) : null],
        [
          'Abuse contact',
          reg?.abuseEmail ? (
            <a className="text-cyan-300 hover:text-cyan-200" href={`mailto:${reg.abuseEmail}`}>
              {reg.abuseEmail}
            </a>
          ) : null,
        ],
        ['Since', reg?.created?.slice(0, 10) ?? null],
      ]),
    },
    {
      title: 'Network',
      icon: <Network className="h-4 w-4" />,
      rows: known([
        ['ASN', net?.asn ? `AS${net.asn}` : null, true],
        ['AS name', net?.asName ?? null],
        ['ISP', net?.isp ?? null],
        ['Connection', connection],
        [
          'Reverse DNS',
          i.reverseDns.length ? (
            <span className="flex flex-col items-end gap-1">
              {i.reverseDns.map((n) => {
                const ok = i.reverseDnsVerified.includes(n);
                return (
                  <span key={n} className="flex items-center gap-1.5" title={ok ? 'Forward-confirmed: this name resolves back to the same address.' : 'Unverified: whoever controls an address can set any reverse DNS name, so do not trust this name on its own.'}>
                    <span className="mono break-all text-[12px]">{n}</span>
                    <Badge tone={ok ? 'green' : 'slate'}>{ok ? 'verified' : 'unverified'}</Badge>
                  </span>
                );
              })}
            </span>
          ) : null,
        ],
      ]),
    },
    {
      title: 'Location (approximate)',
      icon: <MapPin className="h-4 w-4" />,
      rows: known([
        ['Country', geo?.countryCode ? <CountryTag code={geo.countryCode} showName /> : (geo?.country ?? null)],
        ['Region', geo?.region ?? null],
        ['City', geo?.city ?? null],
        ['Timezone', geo?.timezone ?? null],
        [
          'Map',
          geo && geo.lat !== null && geo.lon !== null ? (
            <a className="inline-flex items-center gap-1 text-cyan-300 hover:text-cyan-200" target="_blank" rel="noreferrer" href={`https://www.openstreetmap.org/?mlat=${geo.lat}&mlon=${geo.lon}#map=6/${geo.lat}/${geo.lon}`}>
              {geo.lat.toFixed(2)}, {geo.lon.toFixed(2)} <ExternalLink className="h-3 w-3" />
            </a>
          ) : null,
        ],
      ]),
      extra: i.sources.some((s) => s.name.startsWith('DB-IP')) ? (
        <p className="mt-1 text-[11px] text-ink-3">
          <a href="https://db-ip.com" target="_blank" rel="noreferrer" className="hover:text-cyan-200">
            IP Geolocation by DB-IP
          </a>{' '}
          (CC BY 4.0)
        </p>
      ) : null,
    },
    {
      title: 'Reputation',
      icon: <Skull className="h-4 w-4" />,
      rows: known([
        ['Known scanner', i.knownScanner ? <Badge tone="blue">{i.knownScanner.name}</Badge> : null],
        ['Tor exit node', rep.tor === null ? null : rep.tor ? <Badge tone="orange">Yes</Badge> : 'No'],
        [
          'AbuseIPDB',
          rep.abuseipdb ? (
            <span>
              <span className={clsx('font-semibold', rep.abuseipdb.score >= 75 ? 'text-rose-300' : rep.abuseipdb.score >= 25 ? 'text-amber-300' : 'text-ink')}>{rep.abuseipdb.score}%</span> confidence · {fmtNum(rep.abuseipdb.totalReports)} reports
            </span>
          ) : null,
        ],
        ['GreyNoise', rep.greynoise ? `${rep.greynoise.classification ?? 'not observed'}${rep.greynoise.name ? ` · ${rep.greynoise.name}` : ''}` : null],
      ]),
      extra: i.knownScanner ? <p className="mt-1 text-xs leading-relaxed text-ink-3">{i.knownScanner.description}</p> : null,
    },
  ];
  const exposure = i.exposure;
  const exposed = !!exposure && (exposure.ports.length > 0 || exposure.tags.length > 0 || exposure.vulns.length > 0);
  // Sources that are switched off, so the owner knows where more detail would come from.
  const used = (prefix: string) => i.sources.some((s) => s.name.startsWith(prefix));
  const off = [
    !used('RDAP') && 'regional internet registries (RDAP)',
    !used('DB-IP') && !used('ip-api.com') && 'a location database',
    !used('Shodan InternetDB') && 'Shodan InternetDB',
    !used('AbuseIPDB') && 'AbuseIPDB',
    !used('GreyNoise') && 'GreyNoise',
  ].filter(Boolean) as string[];
  const shown = sections.filter((s) => s.rows.length > 0);
  return (
    <Card title="Details" icon={<Globe className="h-4 w-4" />} subtitle="What public records and lookup services say about this address. Ownership is usually an ISP or hosting company, not necessarily whoever sent the traffic.">
      <div className="space-y-5">
        {shown.length > 0 && (
          <div className="grid gap-x-8 gap-y-5 md:grid-cols-2 [&>*]:min-w-0">
            {shown.map((s) => (
              <section key={s.title}>
                <h3 className="mb-1 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-ink-3">
                  {s.icon} {s.title}
                </h3>
                <dl>
                  {s.rows.map(([k, v, mono]) => (
                    <KV key={k} k={k} v={v} mono={mono} />
                  ))}
                </dl>
                {s.extra}
              </section>
            ))}
          </div>
        )}
        {exposure && (
          <section>
            <h3 className="mb-1.5 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-ink-3">
              <Server className="h-4 w-4" /> Open to the internet (Shodan)
            </h3>
            {exposed ? (
              <div className="space-y-2 text-sm">
                {exposure.ports.length > 0 && (
                  <div className="flex flex-wrap gap-1.5">
                    {exposure.ports.map((p) => (
                      <span key={p} className="mono rounded bg-surface-3 px-1.5 py-0.5 text-xs text-ink">
                        {p}
                      </span>
                    ))}
                  </div>
                )}
                {exposure.tags.length > 0 && (
                  <div className="flex flex-wrap gap-1.5">
                    {exposure.tags.map((t) => (
                      <Badge key={t} tone={/malware|c2|compromised/.test(t) ? 'red' : 'slate'}>
                        {t}
                      </Badge>
                    ))}
                  </div>
                )}
                {exposure.vulns.length > 0 && (
                  <div className="text-xs text-ink-2">
                    Known vulnerable services:{' '}
                    {exposure.vulns.slice(0, 8).map((v) => (
                      <a key={v} href={`https://nvd.nist.gov/vuln/detail/${v}`} target="_blank" rel="noreferrer" className="mr-1.5 text-rose-300 hover:text-rose-200">
                        {v}
                      </a>
                    ))}
                  </div>
                )}
                {exposure.hostnames.length > 0 && <div className="mono break-all text-xs text-ink-3">{exposure.hostnames.slice(0, 5).join(', ')}</div>}
              </div>
            ) : (
              <p className="text-sm text-ink-3">Nothing publicly exposed according to Shodan.</p>
            )}
          </section>
        )}
        {!shown.length && !exposure && <p className="text-sm text-ink-3">No lookup returned anything for this address.</p>}
        <div className="flex flex-wrap items-center gap-2 border-t border-line/60 pt-3 text-xs">
          <span className="text-ink-3">Look it up yourself:</span>
          {[
            ['AbuseIPDB', `https://www.abuseipdb.com/check/${i.ip}`],
            ['VirusTotal', `https://www.virustotal.com/gui/ip-address/${i.ip}`],
            ['Shodan', `https://www.shodan.io/host/${i.ip}`],
            ['GreyNoise', `https://viz.greynoise.io/ip/${i.ip}`],
          ].map(([n, u]) => (
            <a key={n} href={u} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 rounded-md bg-surface-3 px-2 py-1 text-ink-2 hover:text-cyan-200">
              {n} <ExternalLink className="h-3 w-3" />
            </a>
          ))}
        </div>
        {off.length > 0 && (
          <p className="text-xs text-ink-3">
            More detail is available from {off.join(', ')}. Turn them on under{' '}
            <Link to="/settings#intel" className="text-cyan-300 hover:text-cyan-200">
              Settings → IP intelligence
            </Link>
            .
          </p>
        )}
      </div>
    </Card>
  );
}

function InternalCard({ i }: { i: IpIntel }) {
  const l = i.local;
  const exposed = i.exposedBy ?? [];
  return (
    <Card title="Device on your network" icon={<Laptop className="h-4 w-4" />}>
      {exposed.length > 0 && (
        <Callout tone={exposed.some((e) => e.severity === 'critical' || e.severity === 'high') ? 'danger' : 'warn'} icon={<DoorOpen className="h-4 w-4" />} title="Reachable from the internet" className="mb-3">
          {exposed.map((e, n) => (
            <span key={e.id}>
              {n > 0 && '; '}port forward “{e.name}” opens {e.what}
              {e.limited ? ' to a limited set of addresses' : ' to anyone'}
            </span>
          ))}
          . That is how outside attacks reach it.{' '}
          <Link to="/firewall/exposure" className="underline">
            See Internet exposure
          </Link>
        </Callout>
      )}
      {i.insideNetwork && !l?.known && (
        <Callout tone="warn" icon={<ShieldQuestion className="h-4 w-4" />} title={i.seenAs ? 'Not in the connected clients list' : 'Unknown device'} className="mb-3">
          {i.seenAs
            ? `UniFi named it “${i.seenAs}” in its detections, but no connected client uses this address right now. It may be offline, use a static address, or sit behind another device.`
            : `This address is inside ${i.insideNetwork.name} but no connected client currently uses it. It may be a device that has since disconnected, a static IP, or something you do not recognise.`}
        </Callout>
      )}
      <dl className="grid gap-x-8 md:grid-cols-2">
        <KV k="Name" v={l?.name ?? (i.seenAs ? `${i.seenAs} (from detections)` : 'Unknown')} />
        <KV k="Network" v={i.insideNetwork ? `${i.insideNetwork.name}${i.insideNetwork.vlan !== null ? ` (VLAN ${i.insideNetwork.vlan})` : ''}` : l?.network} />
        <KV k="MAC" v={l?.mac} mono />
        <KV k="Address type" v={i.scopeLabel} />
      </dl>
    </Card>
  );
}

function Activity({ i }: { i: IpIntel }) {
  const a = i.activity;
  return (
    <Card title="Activity on your network" icon={<Flame className="h-4 w-4" />} subtitle={a.events ? `${fmtNum(a.events)} detection${a.events === 1 ? '' : 's'} · first seen ${fmtTime(a.firstSeen)} · last seen ${timeAgo(a.lastSeen)}` : 'No IPS detections involve this address.'} padded={false}>
      {a.events > 0 && (
        <div className="grid gap-0 lg:grid-cols-2 [&>*]:min-w-0">
          <div className="border-b border-line/60 p-4 lg:border-b-0 lg:border-r">
            <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-ink-3">Signatures triggered</h3>
            <ul className="space-y-2">
              {a.signatures.slice(0, 8).map((s) => (
                <li key={s.signature} className="flex items-start gap-2">
                  <SeverityBadge severity={s.severity} />
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-sm text-ink">{s.headline}</div>
                    <div className="truncate text-xs text-ink-3">{s.signature}</div>
                  </div>
                  <span className="mono text-xs text-ink-2">{s.count}</span>
                </li>
              ))}
            </ul>
            <div className="mt-3 flex flex-wrap gap-1.5">
              {(['inbound', 'outbound', 'internal'] as const).map((d) => (a.directions[d] ? <span key={d} className="flex items-center gap-1 text-xs text-ink-3"><DirectionBadge direction={d} /> {a.directions[d]}</span> : null))}
            </div>
          </div>
          <div className="p-4">
            <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-ink-3">Talked to</h3>
            <ul className="space-y-1.5">
              {a.peers.slice(0, 8).map((p) => (
                <li key={p.ip} className="flex items-center justify-between gap-2 text-sm">
                  <IpLink ip={p.ip} name={p.name} />
                  <span className="mono text-xs text-ink-3">{p.count}</span>
                </li>
              ))}
            </ul>
            <Link to={`/threats?ip=${encodeURIComponent(i.ip)}&range=30d`} className="mt-3 inline-flex items-center gap-1 text-xs text-cyan-300 hover:text-cyan-200">
              All events for this address →
            </Link>
          </div>
        </div>
      )}
      {a.events === 0 && i.scope === 'public' && (
        <div className="flex items-center gap-2 px-4 pb-4 text-sm text-ink-3">
          <CircleAlert className="h-4 w-4" /> This address has not triggered your IPS.
        </div>
      )}
      {a.events === 0 && i.scope !== 'public' && (
        <div className="flex items-center gap-2 px-4 pb-4 text-sm text-ink-3">
          <Fingerprint className="h-4 w-4" /> No detections — this device has not been involved in any IPS alert.
        </div>
      )}
      {a.events > 0 && i.scope === 'public' && (
        <div className="flex items-center gap-2 border-t border-line/60 px-4 py-2.5 text-xs text-ink-3">
          <Globe className="h-3.5 w-3.5" /> {a.blocked ? `${fmtNum(a.blocked)} of ${fmtNum(a.events)} were blocked.` : 'None of these were blocked.'}
        </div>
      )}
    </Card>
  );
}
