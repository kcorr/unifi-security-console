// IP intelligence: "who is this IP?" for addresses seen in threat events.
//
// Strictly passive: the investigated address itself is never contacted (no ping, traceroute,
// port scan or HTTP). Private/reserved addresses are classified locally and never leave the box.
// Public addresses can be looked up with (each switchable in Settings):
//   - RDAP at the responsible regional internet registry, found via the IANA bootstrap (on)
//   - the offline DB-IP Lite database for geolocation / ASN, once downloaded (local, CC BY 4.0)
//   - the Tor Project exit-node list, downloaded as a whole (on; no per-IP queries)
//   - ip-api.com and Shodan InternetDB (off by default; third-party terms apply)
//   - AbuseIPDB / GreyNoise with the user's own API keys
// Every result is cached and labelled with its source and time.

import dns from 'node:dns/promises';
import type { IpIntel, IpScope, IpVerdictLevel, LocalEndpoint } from '../../shared/types.ts';
import type { Db } from '../db.ts';
import { kvGet, kvSet } from '../db.ts';
import type { Config } from '../config.ts';
import type { GeoDb } from './geodb.ts';
import { AddrSet, parseIp } from './sets.ts';

// ---------------------------------------------------------------------------------
// Scope classification
// ---------------------------------------------------------------------------------

const SCOPES: { cidr: string; scope: IpScope; label: string }[] = [
  { cidr: '0.0.0.0/8', scope: 'unspecified', label: '"This network" (0.0.0.0/8)' },
  { cidr: '10.0.0.0/8', scope: 'private', label: 'Private network (RFC 1918)' },
  { cidr: '100.64.0.0/10', scope: 'cgnat', label: 'Carrier-grade NAT (shared ISP space, also used by Tailscale)' },
  { cidr: '127.0.0.0/8', scope: 'loopback', label: 'Loopback' },
  { cidr: '169.254.0.0/16', scope: 'link-local', label: 'Link-local (no DHCP lease)' },
  { cidr: '172.16.0.0/12', scope: 'private', label: 'Private network (RFC 1918)' },
  { cidr: '192.0.0.0/24', scope: 'reserved', label: 'IETF protocol assignments' },
  { cidr: '192.0.2.0/24', scope: 'documentation', label: 'Documentation range (TEST-NET-1)' },
  { cidr: '192.168.0.0/16', scope: 'private', label: 'Private network (RFC 1918)' },
  { cidr: '198.18.0.0/15', scope: 'reserved', label: 'Benchmarking range' },
  { cidr: '198.51.100.0/24', scope: 'documentation', label: 'Documentation range (TEST-NET-2)' },
  { cidr: '203.0.113.0/24', scope: 'documentation', label: 'Documentation range (TEST-NET-3)' },
  { cidr: '224.0.0.0/4', scope: 'multicast', label: 'Multicast' },
  { cidr: '240.0.0.0/4', scope: 'reserved', label: 'Reserved' },
  { cidr: '::/128', scope: 'unspecified', label: 'Unspecified' },
  { cidr: '::1/128', scope: 'loopback', label: 'Loopback' },
  { cidr: 'fc00::/7', scope: 'private', label: 'Unique local address (private IPv6)' },
  { cidr: 'fe80::/10', scope: 'link-local', label: 'Link-local IPv6' },
  { cidr: 'ff00::/8', scope: 'multicast', label: 'Multicast' },
  { cidr: '2001:db8::/32', scope: 'documentation', label: 'Documentation range' },
];
const SCOPE_SETS = SCOPES.map((s) => ({ ...s, set: AddrSet.parse(s.cidr)! }));
const V6_GLOBAL = AddrSet.parse('2000::/3')!;

export function classifyIp(ip: string): { scope: IpScope; label: string; version: 4 | 6 } {
  const p = parseIp(ip);
  if (!p) return { scope: 'invalid', label: 'Not a valid IP address', version: 4 };
  // IPv4-mapped IPv6 → classify the embedded IPv4 address.
  if (p.fam === 6 && p.n >> 32n === 0xffffn) {
    const v4 = Number(p.n & 0xffffffffn);
    const inner = [v4 >>> 24, (v4 >>> 16) & 255, (v4 >>> 8) & 255, v4 & 255].join('.');
    return { ...classifyIp(inner), version: 6 };
  }
  for (const s of SCOPE_SETS) if (s.set.has(ip)) return { scope: s.scope, label: s.label, version: p.fam };
  if (p.fam === 4) return { scope: 'public', label: 'Public internet address', version: 4 };
  if (V6_GLOBAL.has(ip)) return { scope: 'public', label: 'Public internet address (IPv6)', version: 6 };
  return { scope: 'reserved', label: 'Reserved IPv6 range', version: 6 };
}

export function isPublicIp(ip: string): boolean {
  return classifyIp(ip).scope === 'public';
}

// ---------------------------------------------------------------------------------
// Known scanners & hosting providers
// ---------------------------------------------------------------------------------

const KNOWN_SCANNERS: { name: string; re: RegExp; description: string }[] = [
  { name: 'Censys', re: /censys/i, description: 'Censys continuously scans the whole internet to build a searchable map of exposed services (security research / attack-surface management).' },
  { name: 'Shodan', re: /shodan/i, description: 'Shodan is a search engine for internet-connected devices. Its crawlers probe every public IP regularly.' },
  { name: 'Shadowserver', re: /shadowserver/i, description: 'The Shadowserver Foundation is a non-profit that scans for vulnerable systems and notifies network owners.' },
  { name: 'Rapid7 Project Sonar', re: /rapid7/i, description: 'Rapid7 Labs runs internet-wide surveys for security research.' },
  { name: 'BinaryEdge', re: /binaryedge/i, description: 'BinaryEdge scans the internet for exposed services (now part of Coalition).' },
  { name: 'Stretchoid', re: /stretchoid/i, description: 'Stretchoid is an internet-scanning project; it publishes an opt-out form.' },
  { name: 'Driftnet / Internet Measurement', re: /internet-measurement|driftnet/i, description: 'Driftnet (internet-measurement.com) maps internet exposure for research.' },
  { name: 'LeakIX', re: /leakix/i, description: 'LeakIX indexes exposed services and leaked data.' },
  { name: 'ONYPHE', re: /onyphe/i, description: 'ONYPHE is a cyber-defense search engine that scans the internet.' },
  { name: 'Recyber', re: /recyber/i, description: 'Recyber runs internet-wide scans for security research.' },
  { name: 'Palo Alto Cortex Xpanse', re: /xpanse|expanse|paloalto/i, description: 'Palo Alto Networks Cortex Xpanse scans for attack-surface management.' },
  { name: 'Criminal IP', re: /criminalip|criminal ip/i, description: 'Criminal IP is a threat-intelligence search engine that scans the internet.' },
  { name: 'Alpha Strike Labs', re: /alphastrike/i, description: 'Alpha Strike Labs performs internet-wide security research scans.' },
  { name: 'Bitsight', re: /bitsight/i, description: 'Bitsight scans the internet to produce security ratings.' },
  { name: 'Netcraft', re: /netcraft/i, description: 'Netcraft surveys the internet for web servers and phishing.' },
  { name: 'ipip.net', re: /ipip\.net/i, description: 'ipip.net scans for IP geolocation and network intelligence.' },
  { name: 'Modat', re: /modat/i, description: 'Modat scans for internet asset discovery.' },
  { name: 'Hadrian', re: /hadrian/i, description: 'Hadrian performs external attack-surface scanning.' },
  { name: 'University research scanner', re: /researchscan|\.eecs\.umich\.edu|\.net\.in\.tum\.de|scan.*\.(edu|ac\.[a-z]{2})$/i, description: 'An academic project measuring the internet. Usually documented and harmless.' },
  { name: 'NETSCOUT Arbor Observatory', re: /arbor-observatory|netscout/i, description: 'NETSCOUT measures DDoS-relevant exposure across the internet.' },
];

/**
 * Identify well-known research scanners. Only registry / ASN owner names and forward-confirmed
 * reverse DNS names count: anyone can put any reverse DNS name on their own address, so an
 * unverified "scanner.censys…" name must never make an attacker look harmless.
 */
export function knownScanner(verifiedNames: string[], ownerNames: (string | null | undefined)[]): { name: string; re: RegExp; description: string } | null {
  const text = [...verifiedNames, ...ownerNames.filter(Boolean)].join(' ');
  return KNOWN_SCANNERS.find((s) => s.re.test(text)) ?? null;
}

const HOSTING_RE =
  /(amazon|aws|google|microsoft|azure|digitalocean|linode|akamai|ovh|hetzner|vultr|choopa|contabo|scaleway|online s\.a\.s|leaseweb|m247|tencent|alibaba|aliyun|huawei cloud|oracle|ionos|hostinger|godaddy|hostwinds|colocrossing|psychz|quadranet|frantech|buyvm|kamatera|cloudflare|fastly|serverius|worldstream|pfcloud|aeza|stark industries|ipxo|datacamp|cdn77|g-core|gcore|constant company|interserver|zenlayer|ucloud|hosting|datacenter|data center|server|vps|cloud)/i;

// ---------------------------------------------------------------------------------
// Providers
// ---------------------------------------------------------------------------------

type ProviderName = 'rdns' | 'ipapi' | 'rdap' | 'internetdb' | 'abuseipdb' | 'greynoise';

const TTL_MS: Record<ProviderName | 'tor' | 'bootstrap', number> = {
  rdns: 24 * 3600e3,
  ipapi: 7 * 24 * 3600e3,
  rdap: 30 * 24 * 3600e3,
  internetdb: 3 * 24 * 3600e3,
  tor: 6 * 3600e3,
  abuseipdb: 24 * 3600e3,
  greynoise: 24 * 3600e3,
  bootstrap: 7 * 24 * 3600e3,
};

interface ProviderResult<T> {
  ok: boolean;
  data: T | null;
  error: string | null;
  cached: boolean;
  at: number;
}

export interface IpApiData {
  country: string | null;
  countryCode: string | null;
  regionName: string | null;
  city: string | null;
  lat: number | null;
  lon: number | null;
  timezone: string | null;
  isp: string | null;
  org: string | null;
  as: string | null;
  asname: string | null;
  reverse: string | null;
  mobile: boolean | null;
  proxy: boolean | null;
  hosting: boolean | null;
}

interface RdapData {
  name: string | null;
  handle: string | null;
  cidr: string | null;
  range: string | null;
  country: string | null;
  registrant: string | null;
  abuseEmail: string | null;
  registry: string | null;
  created: string | null;
  updated: string | null;
}

interface InternetDbData {
  ports: number[];
  tags: string[];
  vulns: string[];
  hostnames: string[];
  cpes: string[];
}

interface RdnsData {
  names: string[];
  /** Names that resolve back to the same address (forward-confirmed reverse DNS). */
  verified: string[];
}

/** A provider answered 429: pause it for Retry-After (at least a minute, at most 6 hours). */
class RateLimited extends Error {
  readonly retryAfterMs: number;
  constructor(provider: string, retryAfter: string | null) {
    const secs = !retryAfter ? 0 : /^\d+$/.test(retryAfter.trim()) ? Number(retryAfter) : Math.max(0, (Date.parse(retryAfter) - Date.now()) / 1000);
    const ms = Math.min(6 * 3600e3, Math.max(60e3, (Number.isFinite(secs) ? secs : 0) * 1000));
    super(`${provider} asked us to slow down (HTTP 429) — paused until ${new Date(Date.now() + ms).toLocaleTimeString()}`);
    this.retryAfterMs = ms;
  }
}

const UA = 'unifi-security-console/0.1 (+self-hosted)';

async function getJson(url: string, init: RequestInit = {}, timeoutMs = 8000): Promise<{ status: number; json: unknown; headers: Headers }> {
  const res = await fetch(url, { ...init, headers: { 'User-Agent': UA, Accept: 'application/json', ...(init.headers ?? {}) }, signal: AbortSignal.timeout(timeoutMs) });
  const text = await res.text();
  let json: unknown = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = { raw: text.slice(0, 500) };
  }
  return { status: res.status, json, headers: res.headers };
}

function vcardValue(vcard: unknown, field: string): string | null {
  if (!Array.isArray(vcard) || !Array.isArray(vcard[1])) return null;
  for (const entry of vcard[1] as unknown[]) {
    if (Array.isArray(entry) && entry[0] === field) {
      const v = entry[3];
      if (typeof v === 'string') return v;
      if (Array.isArray(v)) return v.filter((x) => typeof x === 'string' && x).join(', ') || null;
    }
  }
  return null;
}

interface RdapEntity {
  roles?: string[];
  vcardArray?: unknown;
  entities?: RdapEntity[];
  handle?: string;
}

function walkEntities(entities: RdapEntity[] | undefined, visit: (e: RdapEntity) => void) {
  for (const e of entities ?? []) {
    visit(e);
    walkEntities(e.entities, visit);
  }
}

/** Contact roles such as "Abuse" or "NOC" name a mailbox, not whoever holds the address block. */
// The whole name has to be a contact role ("Abuse-C", "NOC", "Technical Contact"): "Security Corp" is an owner.
const CONTACT_NAME = /^(abuse|noc|hostmaster|admin|administrator|administrative|technical|tech|support|security)(\s*[-_]?\s*(c|contact|team|role|department|dept|desk|center|centre|mailbox))*$/i;
export const ownerName = (name: string | null | undefined): string | null => (name && !CONTACT_NAME.test(name.trim()) ? name : null);

function parseRdap(json: Record<string, unknown>, url: string): RdapData {
  let registrant: string | null = null;
  let admin: string | null = null;
  let abuseEmail: string | null = null;
  walkEntities(json.entities as RdapEntity[] | undefined, (e) => {
    const roles = e.roles ?? [];
    const fn = ownerName(vcardValue(e.vcardArray, 'fn'));
    // The registrant owns the block; an administrative contact is only a fallback, and never the abuse desk.
    if (!registrant && roles.includes('registrant')) registrant = fn;
    if (!admin && roles.includes('administrative') && !roles.includes('abuse')) admin = fn;
    if (!abuseEmail && roles.includes('abuse')) abuseEmail = vcardValue(e.vcardArray, 'email');
  });
  registrant ??= admin;
  const cidrs = (json.cidr0_cidrs as { v4prefix?: string; v6prefix?: string; length?: number }[] | undefined) ?? [];
  const cidr = cidrs.length ? cidrs.map((c) => `${c.v4prefix ?? c.v6prefix}/${c.length}`).join(', ') : null;
  const events = (json.events as { eventAction?: string; eventDate?: string }[] | undefined) ?? [];
  const port43 = typeof json.port43 === 'string' ? json.port43 : '';
  const src = port43 + url;
  const registry = /arin/i.test(src) ? 'ARIN' : /ripe/i.test(src) ? 'RIPE NCC' : /apnic/i.test(src) ? 'APNIC' : /lacnic/i.test(src) ? 'LACNIC' : /afrinic/i.test(src) ? 'AFRINIC' : port43 || null;
  const remarks = (json.remarks as { description?: string[] }[] | undefined) ?? [];
  return {
    name: (json.name as string) ?? null,
    handle: (json.handle as string) ?? null,
    cidr,
    range: json.startAddress && json.endAddress ? `${json.startAddress} – ${json.endAddress}` : null,
    country: (json.country as string) ?? null,
    registrant: registrant ?? remarks[0]?.description?.[0] ?? null,
    abuseEmail,
    registry,
    created: events.find((e) => e.eventAction === 'registration')?.eventDate ?? null,
    updated: events.find((e) => e.eventAction === 'last changed')?.eventDate ?? null,
  };
}

// ---------------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------------

export interface IntelDeps {
  /** Shared cache database (lookups are cached across environments). */
  db: Db;
  geoDb: GeoDb;
  getConfig: () => Config;
  /** Your own public (WAN) addresses are never sent to outside services. */
  isOwnAddress: (ip: string) => boolean;
  resolveLocal: (ip: string) => { local: LocalEndpoint | null; network: { id: string; name: string; vlan: number | null } | null };
  activity: (ip: string) => IpIntel['activity'];
  blocking: (ip: string) => IpIntel['blocking'];
}

export class IntelService {
  private readonly deps: IntelDeps;
  private torSet: Set<string> | null = null;
  private torLoadedAt = 0;
  private ipapiBlockedUntil = 0;
  private readonly pausedUntil = new Map<ProviderName, number>();
  private rdapChain: Promise<unknown> = Promise.resolve();
  private inflight = new Map<string, Promise<IpIntel>>();

  constructor(deps: IntelDeps) {
    this.deps = deps;
  }

  private cacheGet<T>(ip: string, provider: ProviderName): ProviderResult<T> | null {
    const row = this.deps.db.prepare('SELECT ok, data, error, fetched_at FROM intel_cache WHERE ip = ? AND provider = ?').get(ip, provider) as
      | { ok: number; data: string | null; error: string | null; fetched_at: number }
      | undefined;
    if (!row) return null;
    const ttl = row.ok ? TTL_MS[provider] : Math.min(TTL_MS[provider], 3600e3);
    if (Date.now() - row.fetched_at > ttl) return null;
    return { ok: !!row.ok, data: row.data ? (JSON.parse(row.data) as T) : null, error: row.error, cached: true, at: row.fetched_at };
  }

  private cachePut(ip: string, provider: ProviderName, r: { ok: boolean; data: unknown; error: string | null }) {
    this.deps.db
      .prepare('INSERT INTO intel_cache (ip, provider, ok, data, error, fetched_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(ip, provider) DO UPDATE SET ok=excluded.ok, data=excluded.data, error=excluded.error, fetched_at=excluded.fetched_at')
      .run(ip, provider, r.ok ? 1 : 0, r.data === null || r.data === undefined ? null : JSON.stringify(r.data), r.error, Date.now());
  }

  private async cached<T>(ip: string, provider: ProviderName, refresh: boolean, fn: () => Promise<T | null>): Promise<ProviderResult<T>> {
    if (!refresh) {
      const c = this.cacheGet<T>(ip, provider);
      if (c) return c;
    }
    const pausedUntil = this.pausedUntil.get(provider) ?? 0;
    if (Date.now() < pausedUntil) {
      // Honour the provider's rate limit: do not even ask until the pause is over.
      return { ok: false, data: null, error: `paused after a rate limit until ${new Date(pausedUntil).toLocaleTimeString()}`, cached: false, at: Date.now() };
    }
    try {
      const data = await fn();
      const r: ProviderResult<T> = { ok: true, data, error: null, cached: false, at: Date.now() };
      this.cachePut(ip, provider, r);
      return r;
    } catch (e) {
      if (e instanceof RateLimited) this.pausedUntil.set(provider, Date.now() + e.retryAfterMs);
      const r: ProviderResult<T> = { ok: false, data: null, error: (e as Error).message, cached: false, at: Date.now() };
      // Rate limits and timeouts are transient - never poison the cache with them.
      if (!(e instanceof RateLimited) && !/timeout|aborted/i.test(r.error ?? '')) this.cachePut(ip, provider, r);
      return r;
    }
  }

  /** Reverse DNS via your resolver, then forward-confirm each name (FCrDNS). Never touches the IP itself. */
  private async rdns(ip: string): Promise<RdnsData> {
    let names: string[];
    try {
      names = await dns.reverse(ip);
    } catch (e) {
      const code = (e as NodeJS.ErrnoException).code;
      if (code === 'ENOTFOUND' || code === 'ENODATA') return { names: [], verified: [] };
      throw e;
    }
    const target = parseIp(ip);
    const verified: string[] = [];
    for (const name of names.slice(0, 5)) {
      try {
        const addrs = target?.fam === 6 ? await dns.resolve6(name) : await dns.resolve4(name);
        if (addrs.some((a) => parseIp(a)?.n === target?.n)) verified.push(name);
      } catch {
        /* does not resolve forward - stays unverified */
      }
    }
    return { names, verified };
  }

  /** The responsible registry's RDAP base URL, from IANA's bootstrap registry (cached a week). */
  private async rdapBase(ip: string): Promise<string | null> {
    const fam = parseIp(ip)?.fam;
    if (!fam) return null;
    const key = `rdap-bootstrap-v${fam}`;
    let boot = kvGet<{ services: [string[], string[]][] }>(this.deps.db, key);
    if (!boot || Date.now() - boot.updatedAt > TTL_MS.bootstrap) {
      const { status, json } = await getJson(`https://data.iana.org/rdap/ipv${fam}.json`, {}, 10_000);
      if (status !== 200 || !json || !Array.isArray((json as { services?: unknown }).services)) throw new Error(`IANA RDAP bootstrap HTTP ${status}`);
      kvSet(this.deps.db, key, json);
      boot = { value: json as { services: [string[], string[]][] }, updatedAt: Date.now() };
    }
    for (const [cidrs, urls] of boot.value.services) {
      if (cidrs.some((c) => AddrSet.parse(c)?.has(ip))) return urls.find((u) => u.startsWith('https://')) ?? urls[0] ?? null;
    }
    return null;
  }

  /** Registry queries are spaced out so we stay well within every RIR's fair-use limits. */
  private politely<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.rdapChain.then(fn, fn);
    this.rdapChain = run.catch(() => undefined).then(() => new Promise((r) => setTimeout(r, 1200)));
    return run;
  }

  private async rdap(ip: string): Promise<RdapData | null> {
    return this.politely(async () => {
      const base = await this.rdapBase(ip);
      if (!base) return null;
      const url = `${base.replace(/\/?$/, '/')}ip/${encodeURIComponent(ip)}`;
      const { status, json, headers } = await getJson(url, { headers: { Accept: 'application/rdap+json, application/json' } }, 12_000);
      if (status === 404) return null;
      if (status === 429) throw new RateLimited('The registry', headers.get('retry-after'));
      if (status >= 400 || !json || typeof json !== 'object') throw new Error(`RDAP HTTP ${status}`);
      return parseRdap(json as Record<string, unknown>, url);
    });
  }

  private async internetDb(ip: string): Promise<InternetDbData | null> {
    const { status, json, headers } = await getJson(`https://internetdb.shodan.io/${encodeURIComponent(ip)}`);
    if (status === 404) return { ports: [], tags: [], vulns: [], hostnames: [], cpes: [] };
    if (status === 429) throw new RateLimited('Shodan InternetDB', headers.get('retry-after'));
    if (status >= 400) throw new Error(`InternetDB HTTP ${status}`);
    const j = json as Partial<InternetDbData>;
    return { ports: j.ports ?? [], tags: j.tags ?? [], vulns: j.vulns ?? [], hostnames: j.hostnames ?? [], cpes: j.cpes ?? [] };
  }

  private async abuseIpDb(ip: string, key: string) {
    const { status, json, headers } = await getJson(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`, { headers: { Key: key } });
    if (status === 429) throw new RateLimited('AbuseIPDB', headers.get('retry-after'));
    if (status >= 400) throw new Error(`AbuseIPDB HTTP ${status}`);
    const d = (json as { data?: Record<string, unknown> }).data ?? {};
    return {
      score: Number(d.abuseConfidenceScore ?? 0),
      totalReports: Number(d.totalReports ?? 0),
      distinctUsers: d.numDistinctUsers === undefined ? null : Number(d.numDistinctUsers),
      lastReportedAt: (d.lastReportedAt as string) ?? null,
      usageType: (d.usageType as string) ?? null,
      domain: (d.domain as string) ?? null,
    };
  }

  private async greyNoise(ip: string, key: string) {
    const { status, json, headers } = await getJson(`https://api.greynoise.io/v3/community/${encodeURIComponent(ip)}`, { headers: { key } });
    if (status === 429) throw new RateLimited('GreyNoise', headers.get('retry-after'));
    if (status === 404) return { classification: null, noise: false, riot: false, name: null, lastSeen: null, link: null };
    if (status >= 400) throw new Error(`GreyNoise HTTP ${status}`);
    const d = json as Record<string, unknown>;
    return {
      classification: (d.classification as string) ?? null,
      noise: !!d.noise,
      riot: !!d.riot,
      name: (d.name as string) ?? null,
      lastSeen: (d.last_seen as string) ?? null,
      link: (d.link as string) ?? null,
    };
  }

  private async torList(): Promise<{ set: Set<string>; at: number } | null> {
    if (this.torSet && Date.now() - this.torLoadedAt < TTL_MS.tor) return { set: this.torSet, at: this.torLoadedAt };
    const cached = kvGet<string[]>(this.deps.db, 'tor-exit-list');
    if (cached && Date.now() - cached.updatedAt < TTL_MS.tor) {
      this.torSet = new Set(cached.value);
      this.torLoadedAt = cached.updatedAt;
      return { set: this.torSet, at: this.torLoadedAt };
    }
    try {
      const res = await fetch('https://check.torproject.org/torbulkexitlist', { headers: { 'User-Agent': UA }, signal: AbortSignal.timeout(10000) });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const list = (await res.text()).split(/\r?\n/).map((s) => s.trim()).filter((s) => s && !s.startsWith('#'));
      kvSet(this.deps.db, 'tor-exit-list', list);
      this.torSet = new Set(list);
      this.torLoadedAt = Date.now();
      return { set: this.torSet, at: this.torLoadedAt };
    } catch {
      return cached ? { set: new Set(cached.value), at: cached.updatedAt } : null;
    }
  }

  /** Offline database result in ip-api's shape (so callers can merge both). */
  private offline(ip: string): IpApiData | null {
    const g = this.deps.geoDb.lookup(ip);
    if (!g) return null;
    return {
      country: g.country, countryCode: g.countryCode, regionName: g.region, city: g.city, lat: g.lat, lon: g.lon, timezone: null,
      isp: null, org: g.asOrg, as: g.asn ? `AS${g.asn} ${g.asOrg ?? ''}`.trim() : null, asname: g.asOrg, reverse: null, mobile: null, proxy: null, hosting: null,
    };
  }

  /** Geo for many IPs at once: offline database first, then ip-api.com only if the user enabled it. */
  async geoBatch(ips: string[], refresh = false): Promise<Map<string, IpApiData>> {
    const out = new Map<string, IpApiData>();
    const cfg = this.deps.getConfig();
    const todo: string[] = [];
    for (const ip of new Set(ips)) {
      if (!isPublicIp(ip) || this.deps.isOwnAddress(ip)) continue;
      const off = this.offline(ip);
      const c = refresh ? null : this.cacheGet<IpApiData>(ip, 'ipapi');
      if (c?.ok && c.data) out.set(ip, c.data);
      else if (off && !cfg.intel.ipapi) out.set(ip, off);
      else {
        if (off) out.set(ip, off);
        todo.push(ip);
      }
    }
    if (!cfg.intel.ipapi || todo.length === 0 || Date.now() < this.ipapiBlockedUntil) return out;
    for (let i = 0; i < todo.length; i += 100) {
      const chunk = todo.slice(i, i + 100);
      try {
        const fields = 'status,message,country,countryCode,regionName,city,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query';
        const { status, json, headers } = await getJson(`http://ip-api.com/batch?fields=${fields}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(chunk),
        });
        const remaining = Number(headers.get('x-rl') ?? '1');
        const ttl = Number(headers.get('x-ttl') ?? '60');
        if (status === 429 || remaining <= 0) this.ipapiBlockedUntil = Date.now() + ttl * 1000;
        if (status !== 200 || !Array.isArray(json)) break;
        for (const row of json as Record<string, unknown>[]) {
          const ip = row.query as string;
          if (row.status !== 'success') continue;
          const data: IpApiData = {
            country: (row.country as string) ?? null,
            countryCode: (row.countryCode as string) ?? null,
            regionName: (row.regionName as string) ?? null,
            city: (row.city as string) ?? null,
            lat: (row.lat as number) ?? null,
            lon: (row.lon as number) ?? null,
            timezone: (row.timezone as string) ?? null,
            isp: (row.isp as string) ?? null,
            org: (row.org as string) ?? null,
            as: (row.as as string) ?? null,
            asname: (row.asname as string) ?? null,
            reverse: (row.reverse as string) || null,
            mobile: (row.mobile as boolean) ?? null,
            proxy: (row.proxy as boolean) ?? null,
            hosting: (row.hosting as boolean) ?? null,
          };
          this.cachePut(ip, 'ipapi', { ok: true, data, error: null });
          out.set(ip, data);
        }
        if (remaining <= 0) break;
      } catch {
        break;
      }
    }
    return out;
  }

  /** Geo for table rendering - never triggers network calls. */
  cachedGeo(ip: string): IpApiData | null {
    const c = this.cacheGet<IpApiData>(ip, 'ipapi');
    return c?.ok && c.data ? c.data : this.offline(ip);
  }

  async lookup(ip: string, opts: { refresh?: boolean } = {}): Promise<IpIntel> {
    const key = `${ip}|${opts.refresh ? 1 : 0}`;
    const existing = this.inflight.get(key);
    if (existing) return existing;
    const p = this.doLookup(ip, !!opts.refresh).finally(() => this.inflight.delete(key));
    this.inflight.set(key, p);
    return p;
  }

  private async doLookup(ip: string, refresh: boolean): Promise<IpIntel> {
    const cfg = this.deps.getConfig();
    const cls = classifyIp(ip);
    const { local, network } = this.deps.resolveLocal(ip);
    const sources: IpIntel['sources'] = [];
    const isPublic = cls.scope === 'public';
    const own = isPublic && this.deps.isOwnAddress(ip);
    const live = isPublic && !own;

    const record = <T>(name: string, r: ProviderResult<T>) => {
      sources.push({ name, ok: r.ok, cached: r.cached, error: r.error, at: r.at });
      return r.data;
    };

    const tasks: Promise<unknown>[] = [];
    let rdns: string[] = [];
    let rdnsVerified: string[] = [];
    let geo: IpApiData | null = null;
    let rdap: RdapData | null = null;
    let idb: InternetDbData | null = null;
    let tor: boolean | null = null;
    let abuse: NonNullable<IpIntel['reputation']['abuseipdb']> | null = null;
    let grey: NonNullable<IpIntel['reputation']['greynoise']> | null = null;

    // Reverse DNS asks your DNS resolver, never the address itself.
    if (cls.scope !== 'invalid') {
      tasks.push(
        this.cached<RdnsData | string[]>(ip, 'rdns', refresh, () => this.rdns(ip)).then((r) => {
          const d = record('Reverse DNS (forward-confirmed)', r);
          const norm: RdnsData = Array.isArray(d) ? { names: d, verified: [] } : d ?? { names: [], verified: [] };
          rdns = norm.names;
          rdnsVerified = norm.verified;
        }),
      );
    }
    if (own) sources.push({ name: 'Your own public IP — not sent to any outside service', ok: true, cached: false, error: null, at: null });
    if (live) {
      const off = this.offline(ip);
      if (off) {
        geo = off;
        const st = this.deps.geoDb.status();
        sources.push({ name: `${st.edition ?? 'DB-IP Lite'} — offline, CC BY 4.0`, ok: true, cached: true, error: null, at: null });
      }
      if (cfg.intel.ipapi) {
        tasks.push(
          this.geoBatch([ip], refresh).then((m) => {
            const g = m.get(ip);
            const fromApi = g && g !== off;
            if (fromApi) geo = { ...(off ?? {}), ...g } as IpApiData;
            sources.push({ name: 'ip-api.com', ok: !!fromApi, cached: false, error: fromApi ? null : 'unavailable or rate limited', at: Date.now() });
          }),
        );
      }
      if (cfg.intel.rdap) tasks.push(this.cached(ip, 'rdap', refresh, () => this.rdap(ip)).then((r) => (rdap = record('RDAP (regional internet registry)', r))));
      if (cfg.intel.internetdb) tasks.push(this.cached(ip, 'internetdb', refresh, () => this.internetDb(ip)).then((r) => (idb = record('Shodan InternetDB', r))));
      if (cfg.intel.tor) {
        tasks.push(
          this.torList().then((t) => {
            tor = t ? t.set.has(ip) : null;
            sources.push({ name: 'Tor Project exit list', ok: !!t, cached: true, error: t ? null : 'unavailable', at: t?.at ?? null });
          }),
        );
      }
      if (cfg.abuseipdbKey) tasks.push(this.cached(ip, 'abuseipdb', refresh, () => this.abuseIpDb(ip, cfg.abuseipdbKey)).then((r) => (abuse = record('AbuseIPDB', r))));
      if (cfg.greynoiseKey) tasks.push(this.cached(ip, 'greynoise', refresh, () => this.greyNoise(ip, cfg.greynoiseKey)).then((r) => (grey = record('GreyNoise', r))));
    }
    await Promise.allSettled(tasks);

    const g = geo as IpApiData | null;
    const r = rdap ? { ...(rdap as RdapData), registrant: ownerName((rdap as RdapData).registrant) } : null;
    const asMatch = g?.as ? /^AS(\d+)\s*(.*)$/.exec(g.as) : null;
    const networkInfo: IpIntel['network'] = g
      ? { asn: asMatch ? Number(asMatch[1]) : null, asName: g.asname ?? asMatch?.[2] ?? null, org: g.org || r?.registrant || null, isp: g.isp, hosting: g.hosting, proxy: g.proxy, mobile: g.mobile }
      : r
        ? { asn: null, asName: null, org: r.registrant, isp: null, hosting: null, proxy: null, mobile: null }
        : null;
    if (g?.reverse && !rdns.includes(g.reverse)) rdns = [...rdns, g.reverse];

    const activity = this.deps.activity(ip);
    const blocking = this.deps.blocking(ip);
    const scanner = isPublic && !own ? knownScanner(rdnsVerified, [networkInfo?.org, networkInfo?.asName, networkInfo?.isp, r?.registrant, r?.name]) : null;

    const intel: IpIntel = {
      ip,
      version: cls.version,
      scope: cls.scope,
      scopeLabel: cls.label,
      local,
      insideNetwork: network,
      reverseDns: rdns,
      reverseDnsVerified: rdnsVerified,
      geo: g ? { country: g.country, countryCode: g.countryCode, region: g.regionName, city: g.city, lat: g.lat, lon: g.lon, timezone: g.timezone } : null,
      network: networkInfo,
      registration: r,
      exposure: idb,
      reputation: { tor, abuseipdb: abuse, greynoise: grey },
      knownScanner: scanner ? { name: scanner.name, description: scanner.description } : null,
      verdict: { level: 'unknown', score: 0, summary: '', reasons: [] },
      activity,
      blocking,
      sources,
      fetchedAt: Date.now(),
    };
    intel.verdict = computeVerdict(intel);
    return intel;
  }
}

export function computeVerdict(i: IpIntel): IpIntel['verdict'] {
  const reasons: string[] = [];
  if (i.local?.network === 'WAN') {
    if (i.activity.events) reasons.push(`Involved in ${i.activity.events} IPS detection(s) — usually attacks aimed at your public IP.`);
    return { level: 'internal', score: 0, summary: 'This is your own public IP address (your gateway’s WAN). It is never sent to outside lookup services.', reasons };
  }
  if (i.scope !== 'public') {
    const who = i.local?.name ? `${i.local.name}${i.insideNetwork ? ` on ${i.insideNetwork.name}` : ''}` : i.insideNetwork ? `an unknown device on ${i.insideNetwork.name}` : null;
    const summary =
      i.scope === 'private' || i.scope === 'cgnat'
        ? who
          ? `Internal address — ${who}.`
          : `${i.scopeLabel}. Not one of your known devices or networks.`
        : `${i.scopeLabel}.`;
    if (i.insideNetwork && !i.local?.known) reasons.push('Address is inside one of your networks but no known client uses it right now.');
    if (i.activity.events) reasons.push(`Involved in ${i.activity.events} IPS detection(s).`);
    return { level: 'internal', score: i.activity.events ? 20 : 0, summary, reasons };
  }

  let score = 0;
  const ab = i.reputation.abuseipdb;
  if (ab) {
    if (ab.score >= 75) {
      score += 60;
      reasons.push(`AbuseIPDB confidence ${ab.score}% (${ab.totalReports} reports).`);
    } else if (ab.score >= 25) {
      score += 35;
      reasons.push(`AbuseIPDB confidence ${ab.score}% (${ab.totalReports} reports).`);
    } else if (ab.totalReports > 0) {
      score += 10;
      reasons.push(`Reported ${ab.totalReports} time${ab.totalReports === 1 ? '' : 's'} on AbuseIPDB (low confidence ${ab.score}%).`);
    }
  }
  const gn = i.reputation.greynoise;
  if (gn) {
    if (gn.classification === 'malicious') {
      score += 40;
      reasons.push('GreyNoise classifies it as malicious.');
    } else if (gn.riot) {
      score -= 30;
      reasons.push(`GreyNoise: known business service${gn.name ? ` (${gn.name})` : ''}.`);
    } else if (gn.classification === 'benign') {
      score -= 15;
      reasons.push(`GreyNoise: benign${gn.name ? ` (${gn.name})` : ''}.`);
    } else if (gn.noise) {
      score += 10;
      reasons.push('GreyNoise: actively scanning the internet.');
    }
  }
  if (i.reputation.tor) {
    score += 20;
    reasons.push('Tor exit node — traffic is anonymised.');
  }
  const tags = i.exposure?.tags ?? [];
  if (tags.some((t) => /malware|c2|compromised|doublepulsar|botnet/i.test(t))) {
    score += 35;
    reasons.push(`Shodan tags: ${tags.join(', ')}.`);
  } else if (tags.some((t) => /proxy|vpn/i.test(t))) {
    score += 10;
    reasons.push(`Shodan tags: ${tags.join(', ')} (anonymising service).`);
  }
  if ((i.exposure?.vulns.length ?? 0) > 0) {
    score += 5;
    reasons.push(`Host itself exposes ${i.exposure!.vulns.length} known-vulnerable service(s) — often a sign it is compromised.`);
  }
  const act = i.activity;
  if (act.events > 0) {
    const worst = act.signatures[0]?.severity;
    const bump = worst === 'critical' ? 35 : worst === 'high' ? 25 : worst === 'medium' ? 15 : 8;
    score += bump + Math.min(15, Math.floor(Math.log2(act.events + 1) * 3));
    reasons.push(`Triggered your IPS ${act.events} time${act.events === 1 ? '' : 's'}${act.blocked ? ` (${act.blocked} blocked)` : ''}.`);
  }
  const hosting = i.network?.hosting || HOSTING_RE.test(`${i.network?.org ?? ''} ${i.network?.asName ?? ''} ${i.network?.isp ?? ''}`);
  if (hosting) reasons.push('Hosted in a data center / cloud provider (not a home or mobile connection).');
  if (i.network?.proxy) {
    score += 10;
    reasons.push('Flagged as a proxy / VPN exit.');
  }
  score = Math.max(0, Math.min(100, score));

  let level: IpVerdictLevel;
  if (i.knownScanner && score < 60) {
    level = 'scanner';
    reasons.unshift(`Known research scanner: ${i.knownScanner.name}.`);
  } else if (score >= 60) level = 'malicious';
  else if (score >= 30) level = 'suspicious';
  else if (gn?.riot || gn?.classification === 'benign') level = 'benign';
  else if (hosting) level = 'cloud';
  else level = 'unknown';

  const owner = i.network?.org || i.registration?.registrant || i.network?.isp || i.registration?.name;
  const place = [i.geo?.city, i.geo?.country].filter(Boolean).join(', ');
  const asn = i.network?.asn ? ` (AS${i.network.asn})` : '';
  const parts: string[] = [];
  // The registered owner is the ISP or hosting company, not necessarily who sent the traffic.
  if (owner) {
    const s = `Network owner: ${owner}${asn}${place ? `, located around ${place}` : ''}`;
    parts.push(s.endsWith('.') ? s : `${s}.`); // "Censys, Inc." must not become "Censys, Inc.."
  }
  else if (place) parts.push(`Located around ${place}.`);
  const levelText: Record<IpVerdictLevel, string> = {
    malicious: 'Strong signs this address is malicious.',
    suspicious: 'Some signs this address is up to no good.',
    scanner: `A known internet scanner (${i.knownScanner?.name}) — usually harmless reconnaissance.`,
    cloud: 'A rented cloud/data-center server — attackers often use these, but so do legitimate services.',
    benign: 'Appears to be a legitimate service.',
    unknown: 'No reputation data either way.',
    internal: '',
  };
  parts.push(levelText[level]);
  return { level, score, summary: parts.join(' '), reasons };
}
