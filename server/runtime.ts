// One environment at runtime: its controller connection, cached snapshot + analyses,
// background pollers, live stream, threat history and change log.

import fs from 'node:fs';
import path from 'node:path';
import type {
  AppStatus, BlockedTraffic, CapabilityReport, CertInfo, ChangePlan, ChangeRecord, ClientDetail, EnvSummary, EnvTls, ExposureItem, FirewallOverview, HygieneIssue, IpIntel, LiveClients, LiveRange,
  LiveTrend, NetworkRole,
  NetworkSummary, OverviewExtras, Posture, RiskAcceptance, SegmentationMatrix, TemplateStatus, ThreatQuery, ThreatSummary, UnifiDevice, UnifiDeviceDetail, WriteMode, ZoneSummary,
} from '../shared/types.ts';
import { NETWORK_ROLES } from '../shared/types.ts';
import { DATA_DIR, keyHint, type Config } from './config.ts';
import { openDb, type Db } from './db.ts';
import { isCloudUrl, type EnvRecord } from './environments.ts';
import { HttpError } from './errors.ts';
import { buildLiveClients, buildLiveSnapshot, ClientTraffic, findGateway, LiveHub, liveTrend, usageByMac } from './live.ts';
import { UniFiClient } from './unifi/client.ts';
import { collect, type RawSnapshot } from './unifi/collect.ts';
import { HttpTransport, type Transport } from './unifi/http.ts';
import { fetchThreats } from './unifi/threats.ts';
import type { GeoDb } from './security/geodb.ts';
import { analyzeHygiene } from './security/hygiene.ts';
import { IntelService } from './security/ipintel.ts';
import type { FwModel } from './security/model.ts';
import { buildModel, zoneMemberNames } from './security/normalize.ts';
import { analyzeExposure, computePosture } from './security/posture.ts';
import { analyzePath, buildMatrix, toRuleView } from './security/segmentation.ts';
import { fetchBlockedFlows, summarizeBlocked } from './security/blockedFlows.ts';
import { deviceIssues, newDevices, waysIn } from './overview.ts';
import { clientConnection, unifiDeviceDetail, unifiDevices } from './devices.ts';
import { identifyDevice } from './security/identify.ts';
import type { MakerDb } from './security/makers.ts';
import { AddrSet, ServiceSet, ST_NEW } from './security/sets.ts';
import { ThreatStore } from './security/threatStore.ts';
import { networkOf, resolveLocal, toThreatEvent, type Directory } from './security/threats.ts';
import { ChangeExecutor } from './security/hardening/executor.ts';
import { assessTemplates, buildPlan } from './security/hardening/planner.ts';
import { TEMPLATES } from './security/hardening/templates.ts';

type Obj = Record<string, unknown>;

interface Derived {
  raw: RawSnapshot;
  model: FwModel;
  dir: Directory;
  matrix?: SegmentationMatrix;
  hygiene?: HygieneIssue[];
  exposure?: ExposureItem[];
  templates?: TemplateStatus[];
  posture?: { at: number; value: Posture };
}

export interface Globals {
  /** Shared database: IP-intel cache, Tor list, settings. */
  globalDb: Db;
  geoDb: GeoDb;
  getConfig: () => Config;
  /** Saves the certificate a self-signed console presented the first time, and returns the updated record. */
  trustCert: (envId: string, cert: CertInfo) => EnvRecord;
  /** Offline register of who made a device, from its MAC address. */
  makers: MakerDb;
}

const LIVE_MS = 5_000;
const CLIENTS_MS = 15_000;
const THREATS_MS = 60_000;
const CONFIG_MS = 120_000;
const BACKFILL_DAYS = 7;

export class EnvRuntime {
  env: EnvRecord;
  readonly db: Db;
  readonly live: LiveHub;
  readonly threats: ThreatStore;
  readonly executor: ChangeExecutor;
  readonly intel: IntelService;
  client: UniFiClient | null = null;
  private readonly g: Globals;
  private snap: Derived | null = null;
  private connected = false;
  private lastError: string | null = null;
  /** The real transport, kept to report a refused (unpinned) certificate. */
  private http: HttpTransport | null = null;
  private lastRefresh: number | null = null;
  private timers: NodeJS.Timeout[] = [];
  private refreshing: Promise<void> | null = null;
  private liveClients: LiveClients | null = null;
  /** Remembers wired counters between polls, to turn them into live rates. */
  private readonly traffic = new ClientTraffic();
  /** Last-24-hour usage per device, refreshed every few minutes (the report is hourly anyway). */
  private usage24h: { at: number; byMac: Map<string, { rx: number; tx: number }> } | null = null;
  /** What the firewall blocked in the last day, per matrix cell; read again after a few minutes. */
  private blocked: { at: number; value: Promise<BlockedTraffic> } | null = null;
  private generation = 0;
  private threatSources: { name: string; ok: boolean; count: number; detail: string }[] = [];

  constructor(env: EnvRecord, g: Globals) {
    this.env = env;
    this.g = g;
    this.db = openDb(DATA_DIR, `env-${env.id}.db`);
    this.live = new LiveHub(this.db);
    this.threats = new ThreatStore(this.db);
    this.executor = new ChangeExecutor(this.db);
    this.intel = new IntelService({
      db: g.globalDb,
      geoDb: g.geoDb,
      getConfig: g.getConfig,
      isOwnAddress: (ip) => this.snap?.dir.wanIps.has(ip) ?? false,
      resolveLocal: (ip) => {
        if (!this.snap) return { local: null, network: null };
        const net = networkOf(this.snap.dir, ip);
        return { local: resolveLocal(this.snap.dir, ip), network: net ? { id: net.id, name: net.name, vlan: net.vlan } : null };
      },
      activity: (ip) => this.threats.activityFor(ip),
      blocking: (ip) => this.blockingFor(ip),
    });
  }

  // ---------------------------------------------------------------------------------
  // Lifecycle
  // ---------------------------------------------------------------------------------

  get configured(): boolean {
    return !!(this.env.url && this.env.apiKey);
  }

  get writeMode(): WriteMode {
    return this.env.writeMode;
  }

  start(): void {
    this.generation++;
    let transport: Transport | null = null;
    if (this.configured) {
      // A self-signed console is pinned: its certificate is trusted the first time and no other one afterwards.
      this.http = new HttpTransport({
        baseUrl: this.env.url,
        apiKey: this.env.apiKey,
        verifyTls: this.env.verifyTls,
        pin: this.env.tlsPin?.spki ?? null,
        trustOnFirstUse: true,
        onTrust: (cert) => {
          this.env = this.g.trustCert(this.env.id, cert);
        },
      });
      transport = this.http;
    }
    if (!transport) return;
    this.client = new UniFiClient(transport, this.env.site, isCloudUrl(this.env.url) ? 'cloud' : 'unifi-os');
    void this.connectLoop(this.generation);
  }

  async stop(): Promise<void> {
    this.generation++;
    for (const t of this.timers) clearInterval(t);
    this.timers = [];
    if (this.client) await this.client.transport.close().catch(() => undefined);
    this.client = null;
    this.http = null;
    this.connected = false;
  }

  /** Apply edited settings; reconnects only when connection details changed. */
  async update(next: EnvRecord): Promise<void> {
    const conn = (e: EnvRecord) => JSON.stringify([e.url, e.apiKey, e.site, e.verifyTls, e.tlsPin?.spki ?? null]);
    const reconnect = conn(next) !== conn(this.env);
    this.env = next;
    if (this.snap) this.snap.templates = undefined;
    if (reconnect) {
      await this.stop();
      this.snap = null;
      this.lastError = null;
      this.live.samples.length = 0;
      this.live.latest = null;
      this.start();
    }
  }

  /** Stop and delete this environment's local data. */
  async destroy(): Promise<void> {
    await this.stop();
    this.db.close();
    for (const suffix of ['', '-wal', '-shm']) fs.rmSync(path.join(DATA_DIR, `env-${this.env.id}.db${suffix}`), { force: true });
  }

  private async connectLoop(gen: number): Promise<void> {
    while (gen === this.generation && this.client && !this.connected) {
      try {
        await this.client.connect();
        if (gen !== this.generation) return;
        this.connected = true;
        this.lastError = null;
        await this.refresh(true);
        await this.pollClients();
        await this.pollLive();
        void this.pollThreats(true);
        this.schedule(gen);
        this.live.broadcast({ type: 'config-changed', data: { reason: 'connected' } });
      } catch (e) {
        this.lastError = e instanceof Error ? e.message : String(e);
        await new Promise((r) => setTimeout(r, 30_000).unref());
      }
    }
  }

  private schedule(gen: number): void {
    const every = (ms: number, fn: () => Promise<unknown>) => {
      const t = setInterval(() => {
        if (gen !== this.generation) return;
        fn().catch((e) => (this.lastError = e instanceof Error ? e.message : String(e)));
      }, ms);
      t.unref();
      this.timers.push(t);
    };
    // unifi.ui.com relays at most 100 requests a minute per console, so cloud consoles are polled about 4× less often.
    const slow = isCloudUrl(this.env.url) ? 4 : 1;
    every(LIVE_MS * slow, () => this.pollLive());
    every(CLIENTS_MS * slow, () => this.pollClients());
    every(THREATS_MS * slow, () => this.pollThreats(false));
    every(CONFIG_MS * slow, () => this.refresh(false));
    every(6 * 3600e3, async () => this.threats.prune(this.g.getConfig().threatRetentionDays));
  }

  // ---------------------------------------------------------------------------------
  // Snapshot
  // ---------------------------------------------------------------------------------

  private roles(): Map<string, NetworkRole> {
    const rows = this.db.prepare('SELECT network_id, role FROM network_roles').all() as { network_id: string; role: NetworkRole }[];
    return new Map(rows.map((r) => [r.network_id, r.role]));
  }

  private directory(raw: RawSnapshot, model: FwModel): Directory {
    const wanIps = new Set<string>();
    for (const h of raw.health) if (typeof h.wan_ip === 'string' && h.wan_ip) wanIps.add(h.wan_ip);
    const gw = findGateway(raw.devices);
    for (const k of ['wan1', 'wan2']) {
      const w = gw?.[k] as Obj | undefined;
      if (typeof w?.ip === 'string' && !model.internal.has(w.ip)) wanIps.add(w.ip);
    }
    const byIp: Directory['byIp'] = new Map();
    const byMac: Directory['byMac'] = new Map();
    const clients = raw.clients.length ? raw.clients : raw.iClients;
    for (const c of clients) {
      const ip = (c.ip ?? c.ipAddress) as string | undefined;
      const mac = String(c.mac ?? c.macAddress ?? '').toLowerCase() || null;
      const name = (c.name || c.hostname || null) as string | null;
      if (ip) byIp.set(ip, { mac, name, networkId: (c.network_id as string) ?? null });
      if (mac) byMac.set(mac, { ip: ip ?? null, name });
    }
    for (const d of raw.devices) {
      const ip = d.ip as string | undefined;
      if (ip && !wanIps.has(ip)) byIp.set(ip, { mac: (d.mac as string) ?? null, name: (d.name as string) ?? null, networkId: null });
    }
    return { networks: model.networks, wanIps, byIp, byMac };
  }

  async refresh(force: boolean): Promise<void> {
    if (!this.client || !this.connected) return;
    // After a change (or the Refresh button) near misses are worked out again against the new rules.
    if (force) this.blocked = null;
    if (this.refreshing) {
      // A forced refresh (after a change) must read the controller again: one already running may predate the change.
      if (!force) return this.refreshing;
      await this.refreshing.catch(() => undefined);
      return this.refresh(true);
    }
    if (!force && this.lastRefresh && Date.now() - this.lastRefresh < 20_000) return;
    this.refreshing = (async () => {
      try {
        const raw = await collect(this.client!);
        const model = buildModel(raw, this.roles());
        this.snap = { raw, model, dir: this.directory(raw, model) };
        this.lastRefresh = Date.now();
        this.lastError = raw.errors.length ? raw.errors.join('; ') : null;
      } finally {
        this.refreshing = null;
      }
    })();
    return this.refreshing;
  }

  private async ensure(): Promise<Derived> {
    if (!this.snap) {
      if (!this.client) throw new HttpError(503, `“${this.env.name}” has no URL or API key yet — edit it in Settings.`);
      if (!this.connected) throw new HttpError(503, this.lastError ? `“${this.env.name}”: ${this.lastError}` : `Connecting to “${this.env.name}”…`);
      await this.refresh(true);
    }
    if (!this.snap) throw new HttpError(503, this.lastError ?? 'No data from the controller yet.');
    return this.snap;
  }

  private get plannerCtx() {
    return {
      model: this.snap!.model,
      raw: this.snap!.raw,
      client: this.client!,
      testOnly: this.writeMode === 'test-network',
      // Local data only (offline database / cache) - planning never triggers lookups.
      ownerOf: (ip: string) => {
        const g = this.intel.cachedGeo(ip);
        return g?.org ?? g?.asname ?? g?.isp ?? null;
      },
    };
  }

  async matrix(): Promise<SegmentationMatrix> {
    const s = await this.ensure();
    return (s.matrix ??= buildMatrix(s.model));
  }

  /** Connections the firewall blocked in the last 24 hours, per matrix cell, from UniFi's traffic log. */
  async blockedTraffic(): Promise<BlockedTraffic> {
    if (this.blocked && Date.now() - this.blocked.at < 5 * 60e3) return this.blocked.value;
    const at = Date.now();
    const range = { from: at - 86400e3, to: at };
    const value = (async () => {
      const s = await this.ensure();
      if (!this.client) return { ...range, available: false, truncated: false, cells: {} };
      const res = await fetchBlockedFlows(this.client, range.from, range.to).catch(() => null);
      if (!res) return { ...range, available: false, truncated: false, cells: {} };
      return summarizeBlocked(s.model, res.flows, range, (ip) => s.dir.byIp.get(ip)?.name ?? null, res.truncated);
    })();
    // Concurrent callers share one read; a failed one is not kept.
    this.blocked = { at, value };
    value.catch(() => (this.blocked = null));
    return value;
  }

  async hygiene(): Promise<HygieneIssue[]> {
    const s = await this.ensure();
    return (s.hygiene ??= analyzeHygiene(s.model));
  }

  async exposure(): Promise<ExposureItem[]> {
    const s = await this.ensure();
    return (s.exposure ??= analyzeExposure(s.raw, s.model, (ip) => s.dir.byIp.get(ip)?.name ?? null));
  }

  /** The Overview's extra cards: ways in, devices that joined lately, this app's last changes, UniFi devices to check. */
  async overviewExtras(): Promise<OverviewExtras> {
    const s = await this.ensure();
    const from = Date.now() - 86400e3;
    const attacks = (ip: string) => this.threats.query({ from, ip, direction: ['inbound'], limit: 1 }).total;
    const nameOf = (ip: string) => this.threats.query({ ip, limit: 5 }).events.find((e) => e.localIp === ip && e.local?.name)?.local?.name ?? null;
    const changes = this.executor.list(50);
    return {
      doors: waysIn(s.raw, await this.exposure(), attacks, nameOf),
      upnp: s.raw.settings.usg ? s.raw.settings.usg.upnp_enabled === true : null,
      newDevices: newDevices(s.raw, Date.now()),
      changes: { recent: changes.slice(0, 3).map(({ id, ts, title, summary, status }) => ({ id, ts, title, summary, status })), total: changes.length },
      devices: deviceIssues(s.raw),
    };
  }

  liveTrend(range: LiveRange): LiveTrend {
    return liveTrend(this.db, range);
  }

  async templateStatus(): Promise<TemplateStatus[]> {
    const s = await this.ensure();
    const accepted = this.acceptedByKey();
    return (s.templates ??= assessTemplates(this.plannerCtx)).map((t) => ({ ...t, acceptance: accepted.get(`protection:${t.templateId}`) ?? null }));
  }

  async posture(): Promise<Posture> {
    const s = await this.ensure();
    if (s.posture && Date.now() - s.posture.at < 60_000) return s.posture.value;
    const value = computePosture({
      raw: s.raw,
      model: s.model,
      matrix: await this.matrix(),
      hygiene: await this.hygiene(),
      exposure: await this.exposure(),
      templates: await this.templateStatus(),
      threats7d: this.threatSummary({ from: Date.now() - 7 * 86400e3 }),
      accepted: this.acceptedByKey(),
    });
    s.posture = { at: Date.now(), value };
    return value;
  }

  /** Posture if it can be computed without waiting on the controller (fleet view). */
  cachedPosture(): Posture | null {
    return this.snap?.posture?.value ?? null;
  }

  // ---------------------------------------------------------------------------------
  // Risk acceptance: stored in this console only, nothing is sent to UniFi
  // ---------------------------------------------------------------------------------

  risks(): RiskAcceptance[] {
    const rows = this.db.prepare('SELECT key, kind, title, reason, accepted_at FROM risk_acceptances ORDER BY accepted_at DESC').all() as { key: string; kind: string; title: string; reason: string; accepted_at: number }[];
    return rows.map((r) => ({ key: r.key, kind: r.kind === 'protection' ? 'protection' : 'finding', title: r.title, reason: r.reason, acceptedAt: r.accepted_at }));
  }

  acceptRisk(input: Record<string, unknown>): RiskAcceptance {
    const key = String(input.key ?? '').trim();
    const title = String(input.title ?? '').trim();
    const reason = String(input.reason ?? '').trim();
    if (!key || !title || typeof input.key !== 'string' || !/^[A-Za-z0-9:._>-]{1,120}$/.test(key)) throw new HttpError(400, 'Say which issue or protection you are accepting.');
    if (reason.length < 10) throw new HttpError(400, 'Write a short reason (at least 10 characters), so you and others know why later.');
    const rec: RiskAcceptance = { key, kind: input.kind === 'protection' ? 'protection' : 'finding', title: title.slice(0, 200), reason: reason.slice(0, 1000), acceptedAt: Date.now() };
    this.db
      .prepare('INSERT INTO risk_acceptances (key, kind, title, reason, accepted_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(key) DO UPDATE SET kind = excluded.kind, title = excluded.title, reason = excluded.reason, accepted_at = excluded.accepted_at')
      .run(rec.key, rec.kind, rec.title, rec.reason, rec.acceptedAt);
    this.risksChanged();
    return rec;
  }

  revokeRisk(key: string): void {
    this.db.prepare('DELETE FROM risk_acceptances WHERE key = ?').run(key);
    this.risksChanged();
  }

  private acceptedByKey(): Map<string, RiskAcceptance> {
    return new Map(this.risks().map((r) => [r.key, r]));
  }

  private risksChanged(): void {
    if (this.snap) this.snap.posture = undefined;
    this.live.broadcast({ type: 'config-changed', data: { reason: 'risk-accepted' } });
  }

  // ---------------------------------------------------------------------------------
  // Pollers
  // ---------------------------------------------------------------------------------

  private async pollLive(): Promise<void> {
    if (!this.client || !this.connected) return;
    const raw = this.snap?.raw;
    let health: Obj[] = raw?.health ?? [];
    let devices: Obj[] = raw?.devices ?? [];
    let integrationStats: Obj | null = null;
    if (this.client.info.internal) {
      const [h, d] = await Promise.allSettled([this.client.v1<Obj>('GET', '/stat/health'), this.client.v1<Obj>('GET', '/stat/device')]);
      if (h.status === 'fulfilled') health = h.value;
      if (d.status === 'fulfilled') devices = d.value;
      if (raw) {
        raw.health = health;
        raw.devices = devices;
      }
    } else if (this.client.info.integration && raw) {
      const gw = raw.iDevices.find((d) => Array.isArray(d.features) && (d.features as string[]).includes('gateway'));
      if (gw) integrationStats = await this.client.integ<Obj>('GET', `/devices/${gw.id}/statistics/latest`).catch(() => null);
    }
    const day = this.threats.counts(Date.now() - 86400e3);
    const hour = this.threats.counts(Date.now() - 3600e3);
    const clients = raw?.clients.length ? raw.clients : raw?.iClients ?? [];
    this.live.push(buildLiveSnapshot({ health, devices, clients, threats: { lastHour: hour.total, last24h: day.total, blocked24h: day.blocked }, integrationStats }));
  }

  private async pollClients(): Promise<void> {
    if (!this.client || !this.connected || !this.snap) return;
    try {
      if (this.client.info.internal) this.snap.raw.clients = await this.client.v1<Obj>('GET', '/stat/sta');
      else if (this.client.info.integration) this.snap.raw.iClients = await this.client.integAll<Obj>('/clients');
      this.snap.dir = this.directory(this.snap.raw, this.snap.model);
      // Who is on a VPN server changes by the minute, so it is read with the clients rather than with the configuration.
      if (this.client.info.internal && this.snap.raw.vpnSessions) {
        this.snap.raw.vpnSessions = await this.client.v1<Obj>('GET', '/stat/remoteuservpn').catch(() => this.snap!.raw.vpnSessions);
      }
    } catch {
      /* keep previous */
    }
    if (this.client.info.internal && (!this.usage24h || Date.now() - this.usage24h.at > 5 * 60e3)) {
      const end = Date.now();
      // A query, despite the POST: UniFi's hourly per-client report for the last 24 hours, all devices at once.
      const rows = await this.client.v1<Obj>('POST', '/stat/report/hourly.user', { attrs: ['rx_bytes', 'tx_bytes', 'time', 'user'], start: end - 24 * 3600e3, end }).catch(() => null);
      this.usage24h = { at: end, byMac: rows ? usageByMac(rows) : (this.usage24h?.byMac ?? new Map()) };
    }
    this.liveClients = buildLiveClients(this.snap.raw.clients.length ? this.snap.raw.clients : this.snap.raw.iClients, this.snap.model.networks, this.usage24h?.byMac ?? null, this.traffic);
  }

  private async pollThreats(initial: boolean): Promise<void> {
    if (!this.client || !this.connected) return;
    await this.ensure().catch(() => undefined);
    if (!this.snap) return;
    const now = Date.now();
    const latest = this.threats.latestTs();
    const from = latest ? Math.max(latest - 10 * 60e3, now - BACKFILL_DAYS * 86400e3) : now - BACKFILL_DAYS * 86400e3;
    const res = await fetchThreats(this.client, from, now);
    this.threatSources = res.sources;
    const events = res.events.map((r) => toThreatEvent(r, this.snap!.dir));
    const fresh = this.threats.upsert(events);
    if (!initial && latest) {
      for (const e of fresh.sort((a, b) => a.ts - b.ts).slice(-25)) this.live.broadcast({ type: 'threat', data: e });
    }
    if (fresh.length && this.snap.posture) this.snap.posture = undefined;
    // Warm the local geo lookups for the most active external addresses (never blocks the poll).
    const ips = [...new Set(fresh.map((e) => e.remoteIp).filter((x): x is string => !!x))].slice(0, 100);
    if (ips.length) void this.intel.geoBatch(ips).catch(() => undefined);
  }

  // ---------------------------------------------------------------------------------
  // Queries used by routes
  // ---------------------------------------------------------------------------------

  summary(): EnvSummary {
    const info = this.client?.info ?? null;
    return {
      id: this.env.id,
      name: this.env.name,
      color: this.env.color,
      url: this.env.url || null,
      site: this.env.site,
      verifyTls: this.env.verifyTls,
      writeMode: this.env.writeMode,
      effectiveWriteMode: this.writeMode,
      apiKeySet: !!this.env.apiKey,
      apiKeyHint: keyHint(this.env.apiKey),
      connected: this.connected,
      version: info?.version ?? null,
      siteName: info?.siteName ?? null,
      firewallMode: this.snap?.raw.firewallMode ?? 'unknown',
      lastError: this.lastError,
      tls: this.tls(),
    };
  }

  private tls(): EnvTls | null {
    const mode: EnvTls['mode'] = !this.env.url.startsWith('https://') ? 'plain' : this.env.verifyTls || isCloudUrl(this.env.url) ? 'ca' : this.env.tlsPin ? 'pinned' : 'pending';
    return { mode, pin: mode === 'pinned' ? this.env.tlsPin : null, mismatch: mode === 'pinned' ? (this.http?.mismatch ?? null) : null };
  }

  /** The per-environment part of AppStatus. */
  status(): Omit<AppStatus, 'environments' | 'envId' | 'authRequired' | 'authenticated' | 'intel'> {
    const info = this.client?.info ?? null;
    const gw = this.snap ? findGateway(this.snap.raw.devices) : null;
    const caps: CapabilityReport[] = [
      ...(info
        ? [
            { key: 'api.integration', label: 'Official Network API', ok: info.integration, detail: info.integration ? 'reachable' : 'not available' },
            { key: 'api.internal', label: 'Internal API (API key)', ok: info.internal, detail: info.internal ? 'reachable' : 'not available — threats, settings and live stats are limited' },
          ]
        : []),
      ...(this.snap?.raw.capabilities ?? []),
      ...this.threatSources.map((s) => ({ key: `threats.${s.name}`, label: s.name, ok: s.ok, detail: s.detail })),
    ];
    return {
      configured: this.configured,
      connected: this.connected,
      readOnly: this.writeMode === 'read-only',
      writeMode: this.writeMode,
      controller: {
        url: this.env.url || null,
        version: info?.version ?? null,
        kind: info?.kind ?? null,
        site: info?.site ?? this.env.site,
        siteDescription: info?.siteName ?? null,
        firewallMode: this.snap?.raw.firewallMode ?? 'unknown',
        gatewayModel: (gw?.shortname as string) ?? (gw?.model as string) ?? null,
      },
      capabilities: caps,
      lastError: this.lastError,
      lastRefresh: this.lastRefresh,
    };
  }

  threatSummary(q: ThreatQuery): ThreatSummary {
    const s = this.threats.summary(q);
    for (const src of s.topSources) {
      if (src.country && src.org) continue;
      const g = this.intel.cachedGeo(src.ip);
      if (g) {
        src.country ??= g.countryCode;
        src.org ??= g.org ?? g.isp;
      }
    }
    if (!s.byCountry.length) {
      const m = new Map<string, number>();
      for (const src of s.topSources) if (src.country) m.set(src.country, (m.get(src.country) ?? 0) + src.count);
      s.byCountry = [...m.entries()].map(([country, count]) => ({ country, count })).sort((a, b) => b.count - a.count);
    }
    return s;
  }

  async firewallOverview(): Promise<FirewallOverview> {
    const s = await this.ensure();
    const m = s.model;
    const clientsPerNet = new Map<string, number>();
    for (const c of s.raw.clients) {
      const net = m.networks.find((n) => n.id === c.network_id || n.raw._legacyId === c.network_id);
      if (net) clientsPerNet.set(net.id, (clientsPerNet.get(net.id) ?? 0) + 1);
    }
    const networks: NetworkSummary[] = m.networks.map((n) => ({
      id: n.id,
      name: n.name,
      vlan: n.vlan,
      purpose: n.purpose,
      subnet: n.subnet,
      subnet6: n.subnet6,
      gatewayIp: n.gatewayIp,
      zoneId: n.zoneId,
      zoneName: m.zones.find((z) => z.id === n.zoneId)?.name ?? null,
      role: n.role,
      roleSource: n.roleSource,
      isolated: n.isolated,
      internetAccess: n.internetAccess,
      clientCount: clientsPerNet.get(n.id) ?? 0,
      dhcpDns: n.dhcpDns,
      enabled: n.enabled,
      isTest: n.isTest,
    }));
    const members = zoneMemberNames(m, s.raw);
    const zones: ZoneSummary[] = m.zones.map((z) => ({ id: z.id, name: z.name, key: z.key, networkIds: z.networkIds, networkNames: members.get(z.id) ?? [] }));
    const real = m.rules.filter((r) => !r.id.startsWith('synthetic:'));
    const rules = real.map((r) => toRuleView(m, r)).sort((a, b) => a.group.localeCompare(b.group) || Number(a.predefined) - Number(b.predefined) || a.index - b.index);
    return {
      firewallMode: m.mode,
      networks,
      zones,
      rules,
      hygiene: await this.hygiene(),
      exposure: await this.exposure(),
      counts: { total: real.length, custom: real.filter((r) => !r.predefined).length, enabled: real.filter((r) => r.enabled).length, managed: real.filter((r) => r.managed).length, predefined: real.filter((r) => r.predefined).length },
      warnings: m.warnings,
    };
  }

  async setRole(networkId: string, role: NetworkRole | null): Promise<void> {
    if (role && !NETWORK_ROLES.some((r) => r.value === role)) throw new HttpError(400, 'Unknown role');
    const s = await this.ensure();
    if (!s.model.networks.some((n) => n.id === networkId || n.raw._legacyId === networkId)) throw new HttpError(404, 'Network not found.');
    if (role) this.db.prepare('INSERT INTO network_roles (network_id, role) VALUES (?, ?) ON CONFLICT(network_id) DO UPDATE SET role = excluded.role').run(networkId, role);
    else this.db.prepare('DELETE FROM network_roles WHERE network_id = ?').run(networkId);
    if (this.snap) {
      const model = buildModel(this.snap.raw, this.roles());
      this.snap = { raw: this.snap.raw, model, dir: this.directory(this.snap.raw, model) };
    }
  }

  async templates() {
    const s = await this.ensure();
    const testNetwork = s.model.networks.find((n) => n.isTest);
    // Zone pickers list this site's zones (everything except the internet itself).
    const zoneOptions = s.model.zones.filter((z) => z.key !== 'external').map((z) => ({ value: z.id, label: z.name }));
    return {
      // Hidden templates (block an IP, close a port forward...) are not listed on Hardening, but their Fix buttons need them.
      templates: TEMPLATES.map((t) => (t.params.some((p) => p.key === 'zones') ? { ...t, params: t.params.map((p) => (p.key === 'zones' ? { ...p, options: zoneOptions } : p)) } : t)),
      status: await this.templateStatus(),
      readOnly: this.writeMode === 'read-only',
      writeMode: this.writeMode,
      testNetwork: testNetwork ? { id: testNetwork.id, name: testNetwork.name, subnet: testNetwork.subnet, vlan: testNetwork.vlan, zoneId: testNetwork.zoneId } : null,
    };
  }

  async plan(templateId: string, params: Record<string, unknown>, strategy?: string): Promise<ChangePlan> {
    await this.ensure();
    const plan = buildPlan(this.plannerCtx, templateId, params, strategy);
    plan.madeIn = this.writeMode;
    this.executor.remember(plan);
    return plan;
  }

  async apply(planId: string): Promise<ChangeRecord> {
    if (this.writeMode === 'read-only') throw new HttpError(403, `“${this.env.name}” is read-only. Change its "Change safety" level in Settings to make changes.`);
    await this.ensure();
    const plan = this.executor.getPlan(planId);
    if (!plan) throw new HttpError(410, 'This preview has expired. Please review the change again.');
    // The test-network guard ran when the plan was made; a plan from another safety level must be reviewed again.
    if (plan.madeIn !== this.writeMode) throw new HttpError(409, 'The change-safety level changed after this preview was made. Review the change again.');
    const refused = this.executor.refusal(plan);
    if (refused) throw new HttpError(refused === plan.blockedReason ? 403 : 409, refused);
    const rec = await this.executor.apply(planId, this.client!, this.writeMode);
    await this.refresh(true).catch(() => undefined);
    this.live.broadcast({ type: 'config-changed', data: { reason: 'change-applied' } });
    return rec;
  }

  /** Later changes that have to be undone before `id`, newest first. */
  undoDependents(id: string): ChangeRecord[] {
    return this.executor.dependents(id);
  }

  /** Undo a change; with `cascade`, later changes that depend on it are undone first (newest first). */
  async undo(id: string, cascade = false): Promise<ChangeRecord> {
    if (this.writeMode === 'read-only') throw new HttpError(403, `“${this.env.name}” is read-only. Change its "Change safety" level in Settings to undo changes.`);
    const existing = this.executor.get(id);
    if (!existing) throw new HttpError(404, 'Change not found.');
    const deps = this.executor.dependents(id);
    if (this.writeMode === 'test-network' && [existing, ...deps].some((r) => r.appliedMode !== 'test-network')) {
      throw new HttpError(403, 'Test-network mode can only undo changes that were made in test-network mode.');
    }
    if (deps.length && !cascade) {
      const list = deps.map((d) => `“${d.title}”`).join(', ');
      throw new HttpError(409, `${deps.length === 1 ? 'A later change uses' : `${deps.length} later changes use`} what this change created (${list}). Undo ${deps.length === 1 ? 'it' : 'them'} first, or confirm undoing them together.`);
    }
    await this.ensure();
    try {
      return await this.executor.undoCascade(id, this.client!);
    } catch (e) {
      throw new HttpError(502, e instanceof Error ? e.message : String(e));
    } finally {
      await this.refresh(true).catch(() => undefined);
      this.live.broadcast({ type: 'config-changed', data: { reason: 'change-undone' } });
    }
  }

  async intelFor(ip: string, refresh: boolean): Promise<IpIntel> {
    await this.ensure().catch(() => undefined);
    const result = await this.intel.lookup(ip, { refresh });
    if (!this.snap || result.scope === 'public') return result;
    // One of your devices: which port forwards open it to the internet, and what UniFi called it when it was attacked.
    const seenAs = result.local?.name ? null : (this.threats.query({ ip, limit: 5 }).events.find((e) => e.localIp === ip && e.local?.name)?.local?.name ?? null);
    return { ...result, exposedBy: await this.exposedBy(ip), seenAs };
  }

  /** Enabled port forwards that make one of your addresses reachable from the internet. */
  private async exposedBy(ip: string): Promise<NonNullable<IpIntel['exposedBy']>> {
    const raw = this.snap?.raw;
    if (!raw) return [];
    return (await this.exposure())
      .filter((e) => e.kind === 'port-forward' && e.enabled && String(raw.portForwards.find((p) => String(p._id) === e.id)?.fwd ?? '') === ip)
      .map((e) => ({ id: e.id, name: e.name, what: e.services.length ? e.services.join(', ') : `${e.protocol} ${e.externalPort}`, severity: e.severity, limited: !!e.sourceRestriction }));
  }

  /** Everything about one client: identity (with a best guess), connection, traffic and security. */
  async clientDetail(macIn: string): Promise<ClientDetail> {
    const s = await this.ensure();
    const mac = macIn.toLowerCase();
    const raw = s.raw.clients.find((c) => String(c.mac ?? '').toLowerCase() === mac) ?? s.raw.iClients.find((c) => String(c.macAddress ?? '').toLowerCase() === mac);
    if (!raw) throw new HttpError(404, 'This device is not connected right now.');
    const row = this.liveClients?.clients.find((c) => c.mac.toLowerCase() === mac) ?? buildLiveClients([raw], s.model.networks, this.usage24h?.byMac ?? null).clients[0];
    const net = s.model.networks.find((n) => n.id === row.networkId) ?? null;
    const now = Date.now();
    const internal = !!this.client?.info.internal;
    // Two small queries for just this device: its hourly traffic, and UniFi's fingerprint label.
    const [hourly, active] = await Promise.all([
      internal ? this.client!.v1<Obj>('POST', '/stat/report/hourly.user', { attrs: ['rx_bytes', 'tx_bytes', 'time'], start: now - 24 * 3600e3, end: now, macs: [mac] }).catch(() => [] as Obj[]) : Promise.resolve([] as Obj[]),
      internal ? this.client!.v2<Obj[]>('GET', '/clients/active').catch(() => [] as Obj[]) : Promise.resolve([] as Obj[]),
    ]);
    const fp = (Array.isArray(active) ? active : []).find((x) => String(x.mac ?? '').toLowerCase() === mac);
    const fpConf = Number((fp?.fingerprint as Obj | undefined)?.confidence);
    const ip = row.ip;
    const maker = typeof raw.oui === 'string' && raw.oui ? raw.oui : this.g.makers.lookup(mac);
    const month = now - 30 * 86400e3;
    const t = ip ? this.threatSummary({ ip, from: month }) : null;
    const matrix = net ? await this.matrix().catch(() => null) : null;
    const nameOf = (id: string) => matrix?.endpoints.find((e) => e.id === id)?.name ?? id;
    return {
      mac,
      name: row.name,
      hostname: typeof raw.hostname === 'string' ? raw.hostname : null,
      ip,
      ipv6: Array.isArray(raw.ipv6_addresses) ? (raw.ipv6_addresses as string[]) : [],
      network: { id: net?.id ?? null, name: row.network, vlan: row.vlan, role: net?.role ?? null },
      connection: clientConnection(raw),
      uptime: row.uptime,
      firstSeen: row.firstSeen,
      lastSeen: typeof raw.last_seen === 'number' ? raw.last_seen * 1000 : null,
      traffic: {
        downBps: row.rxBps,
        upBps: row.txBps,
        down24h: row.rx24h,
        up24h: row.tx24h,
        downSince: row.rxBytes,
        upSince: row.txBytes,
        hourly: hourly.map((h) => ({ t: Number(h.time), down: Number(h.rx_bytes ?? 0), up: Number(h.tx_bytes ?? 0) })).sort((a, b) => a.t - b.t),
      },
      identity: identifyDevice({
        mac,
        name: typeof raw.name === 'string' ? raw.name : null,
        hostname: typeof raw.hostname === 'string' ? raw.hostname : null,
        maker,
        makerSource: typeof raw.oui === 'string' && raw.oui ? 'unifi' : maker ? 'registry' : null,
        fingerprint: typeof fp?.model_name === 'string' ? fp.model_name : null,
        fingerprintConfidence: Number.isFinite(fpConf) ? fpConf : null,
        wired: row.wired,
        network: row.network,
      }),
      security: {
        suspect: !!ip && this.threatSummary({ from: now - 7 * 86400e3 }).suspects.some((x) => x.ip === ip),
        exposedBy: ip ? await this.exposedBy(ip) : [],
        threats: {
          total: t?.total ?? 0,
          blocked: t?.blocked ?? 0,
          alerted: t?.alerted ?? 0,
          aimedAt: t?.byDirection.inbound ?? 0,
          startedBy: (t?.byDirection.outbound ?? 0) + (t?.byDirection.internal ?? 0),
          recent: ip ? this.threats.query({ ip, from: month, limit: 15 }).events : [],
        },
        reach: matrix && net ? matrix.cells.filter((c) => c.from === net.id && c.verdict !== 'self').map((c) => ({ to: nameOf(c.to), verdict: c.verdict, risk: c.risk, summary: c.summary })) : [],
      },
    };
  }

  async unifiDevices(): Promise<UnifiDevice[]> {
    return unifiDevices((await this.ensure()).raw);
  }

  async unifiDevice(mac: string): Promise<UnifiDeviceDetail> {
    const d = unifiDeviceDetail((await this.ensure()).raw, mac);
    if (!d) throw new HttpError(404, 'That UniFi device is not on this site.');
    return d;
  }

  async geo(ips: string[]) {
    const m = await this.intel.geoBatch(ips.slice(0, 200));
    return Object.fromEntries([...m.entries()].map(([ip, g]) => [ip, { countryCode: g.countryCode, country: g.country, org: g.org ?? g.isp, city: g.city }]));
  }

  /** Is this external IP blocked by rules that name it specifically, inbound and outbound? */
  private blockingFor(ip: string): IpIntel['blocking'] {
    if (!this.snap) return null;
    const ipSet = AddrSet.parse(ip);
    const m = this.snap.model;
    if (!ipSet || m.internal.overlaps(ipSet) || m.mode === 'unknown') return null;
    const rules = new Map<string, { id: string; name: string; action: 'allow' | 'block' | 'reject' }>();
    const verdict = (dir: 'in' | 'out') => {
      let blocked = 0;
      let allowed = 0;
      for (const n of m.networks.filter((x) => x.enabled && !x.addrs.isEmpty())) {
        if (dir === 'in') {
          const ext = m.zones.find((z) => z.key === 'external');
          const chainRules = m.mode === 'zone' ? m.rules.filter((r) => r.chain === `${ext?.id}>${n.zoneId}`) : m.rules.filter((r) => r.chain === 'WAN_IN');
          const hit = chainRules.find((r) => !r.predefined && r.enabled && r.exact && r.space.some((b) => b.fam === 4 && b.src.contains(ipSet.v4)));
          if (hit) {
            rules.set(hit.id, { id: hit.id, name: hit.name, action: hit.action });
            if (hit.action === 'allow') allowed++;
            else blocked++;
          } else allowed++;
          continue;
        }
        const res = analyzePath(m, n, { kind: 'addrs', addrs: ipSet, label: ip, zoneKey: 'external' }, ServiceSet.ALL, ST_NEW);
        if (!res) continue;
        for (const seg of res.result.segments) {
          const specific = seg.rule && !seg.rule.predefined && !seg.rule.dstAny;
          if (specific) rules.set(seg.rule!.id, { id: seg.rule!.id, name: seg.rule!.name, action: seg.rule!.action });
          if (seg.verdict === 'block' && specific) blocked++;
          else allowed++;
        }
      }
      return blocked && !allowed ? ('blocked' as const) : blocked ? ('partial' as const) : ('allowed' as const);
    };
    return { inbound: verdict('in'), outbound: verdict('out'), rules: [...rules.values()] };
  }

  liveClientsView(): LiveClients {
    return this.liveClients ?? { t: Date.now(), clients: [], networks: [] };
  }

  async diagnostics() {
    const probes: { key: string; label: string; method: string; path: string; ok: boolean; status: number | null; detail: string; ms: number }[] = [];
    const c = this.client;
    if (c && this.connected) {
      const list: [string, string, 'GET' | 'POST', string, unknown?][] = [
        ['info', 'Application info', 'GET', c.fullPath('integration', '/info')],
        ['sites', 'Sites', 'GET', `${c.info.prefix}/integration/v1/sites`],
        ['zones', 'Firewall zones', 'GET', c.fullPath('integration', '/firewall/zones')],
        ['policies', 'Firewall policies', 'GET', c.fullPath('integration', '/firewall/policies')],
        ['health', 'Health', 'GET', c.fullPath('v1', '/stat/health')],
        ['settings', 'Settings', 'GET', c.fullPath('v1', '/get/setting')],
        ['flows', 'Traffic flows (IPS)', 'POST', c.fullPath('v2', '/traffic-flows'), { timestampFrom: Date.now() - 3600e3, timestampTo: Date.now(), pageNumber: 0, pageSize: 1, policy_type: ['INTRUSION_PREVENTION'] }],
        ['ipsEvents', 'IPS events (legacy)', 'POST', c.fullPath('v1', '/stat/ips/event'), { start: Date.now() - 3600e3, end: Date.now(), _limit: 1 }],
        ['threatAlerts', 'System log threat alerts', 'POST', c.fullPath('v2', '/system-log/threat-alert'), { timestampFrom: Date.now() - 3600e3, timestampTo: Date.now(), threatTypes: ['THREAT'], pageNumber: 0, pageSize: 1 }],
        ['v2policies', 'Firewall policies (internal)', 'GET', c.fullPath('v2', '/firewall-policies')],
      ];
      for (const [key, label, method, p, body] of list) {
        const t0 = Date.now();
        try {
          const res = await c.probe(method, p, body);
          const j = res.json as Obj | unknown[] | null;
          const n = Array.isArray(j) ? j.length : Array.isArray((j as Obj | null)?.data) ? ((j as Obj).data as unknown[]).length : null;
          probes.push({ key, label, method, path: p, ok: res.status >= 200 && res.status < 300, status: res.status, detail: res.status < 300 ? (n !== null ? `${n} item(s)` : 'ok') : res.text.slice(0, 160), ms: Date.now() - t0 });
        } catch (e) {
          probes.push({ key, label, method, path: p, ok: false, status: null, detail: e instanceof Error ? e.message : String(e), ms: Date.now() - t0 });
        }
      }
    }
    return probes;
  }
}
