// Application service: the registry of environments (one runtime each), plus the global
// settings shared by all of them (IP intelligence, retention, offline geo database).

import fs from 'node:fs';
import path from 'node:path';
import type { AppStatus, CertInfo, CloudConsole, EnvInput, EnvSummary, EnvTestResult, FleetRow, GeoDbStatus, SettingsUpdate, TlsPin } from '../shared/types.ts';
import { DATA_DIR, loadConfig, saveSettings, seedConfig, type Config } from './config.ts';
import { openDb, type Db } from './db.ts';
import { CLOUD_API, EnvStore, isCloudUrl, parseCloudHosts, type EnvRecord } from './environments.ts';
import { HttpError } from './errors.ts';
import { EnvRuntime, type Globals } from './runtime.ts';
import { GeoDb } from './security/geodb.ts';
import { MakerDb } from './security/makers.ts';
import { listCategories } from './security/threatKb.ts';
import { UniFiClient } from './unifi/client.ts';
import { collect } from './unifi/collect.ts';
import { fetchCert, HttpTransport } from './unifi/http.ts';

type Obj = Record<string, unknown>;

export class AppService {
  readonly settingsDb: Db;
  readonly geoDb: GeoDb;
  readonly makers: MakerDb;
  readonly store: EnvStore;
  cfg: Config;
  private readonly runtimes = new Map<string, EnvRuntime>();

  constructor() {
    this.settingsDb = openDb(DATA_DIR, 'app.db');
    this.cfg = loadConfig(this.settingsDb);
    this.geoDb = new GeoDb(DATA_DIR);
    this.makers = new MakerDb(DATA_DIR);
    this.store = new EnvStore(this.settingsDb);
  }

  private get globals(): Globals {
    return { globalDb: this.settingsDb, geoDb: this.geoDb, getConfig: () => this.cfg, trustCert: (id, cert) => this.store.setPin(id, { ...cert, pinnedAt: Date.now() }), makers: this.makers };
  }

  async start(): Promise<void> {
    // Older versions could add simulated environments; they and their data go.
    for (const id of this.store.removeSimulated()) {
      for (const suffix of ['', '-wal', '-shm']) fs.rmSync(path.join(DATA_DIR, `env-${id}.db${suffix}`), { force: true });
    }
    if (!this.store.list().length) {
      const seed = seedConfig(this.settingsDb);
      if (seed.unifiUrl && seed.apiKey) this.store.create({ name: 'Main', url: seed.unifiUrl, apiKey: seed.apiKey, site: seed.site, verifyTls: seed.verifyTls, writeMode: seed.writeMode });
    }
    for (const env of this.store.list()) this.launch(env);
  }

  async stop(): Promise<void> {
    await Promise.all([...this.runtimes.values()].map((r) => r.stop()));
  }

  private launch(env: EnvRecord): EnvRuntime {
    const rt = new EnvRuntime(env, this.globals);
    this.runtimes.set(env.id, rt);
    rt.start();
    return rt;
  }

  /** The runtime for an environment id (or the first environment when none is given). */
  rt(envId?: string | null): EnvRuntime {
    if (envId && this.runtimes.has(envId)) return this.runtimes.get(envId)!;
    if (envId) throw new HttpError(404, 'That environment no longer exists — pick another one.');
    const first = this.store.list()[0];
    if (!first) throw new HttpError(503, 'No environments yet — add your UniFi controller in Settings.');
    return this.runtimes.get(first.id)!;
  }

  environments(): EnvSummary[] {
    return this.store
      .list()
      .map((e) => this.runtimes.get(e.id)?.summary())
      .filter((x): x is EnvSummary => !!x);
  }

  status(envId: string | null, authRequired: boolean, authenticated: boolean): AppStatus {
    const environments = this.environments();
    const intel = { providers: this.cfg.intel, abuseipdb: !!this.cfg.abuseipdbKey, greynoise: !!this.cfg.greynoiseKey, geoDb: this.geoDb.available };
    const rt = environments.length ? (envId && this.runtimes.has(envId) ? this.runtimes.get(envId)! : this.rt(null)) : null;
    if (!rt) {
      return {
        environments,
        envId: null,
        configured: false,
        connected: false,
        readOnly: true,
        writeMode: 'read-only',
        authRequired,
        authenticated,
        controller: { url: null, version: null, kind: null, site: 'default', siteDescription: null, firewallMode: 'unknown', gatewayModel: null },
        capabilities: [],
        lastError: null,
        lastRefresh: null,
        intel,
      };
    }
    return { environments, envId: rt.env.id, authRequired, authenticated, intel, ...rt.status() };
  }

  // ---------------------------------------------------------------------------------
  // Environment management
  // ---------------------------------------------------------------------------------

  async addEnv(input: EnvInput): Promise<EnvSummary> {
    if (!input.url?.trim() || !input.apiKey?.trim()) throw new HttpError(400, 'Enter the console URL and an API key.');
    checkWriteMode(input);
    const next = withCloudTls(input);
    const env = this.store.create(next, await pinFor(next.url ?? '', !!next.verifyTls, input.trustCert));
    return this.launch(env).summary();
  }

  async updateEnv(id: string, input: EnvInput): Promise<EnvSummary> {
    const rt = this.runtimes.get(id);
    const stored = this.store.get(id);
    if (!rt || !stored) throw new HttpError(404, 'Environment not found');
    checkWriteMode(input);
    // A saved key is only ever sent to the address it was saved for.
    if (input.url && !sameOrigin(input.url, stored.url) && !input.apiKey?.trim()) throw new HttpError(400, 'Enter the API key again: it is only reused for the same console address.');
    const next = withCloudTls({ ...input, url: input.url ?? stored.url });
    const verifyTls = next.verifyTls ?? stored.verifyTls;
    // Same console, still pinned: keep the trusted certificate unless the owner approved a new one after testing.
    const keep = sameOrigin(next.url!, stored.url) && !verifyTls && !!stored.tlsPin && (!input.trustCert || input.trustCert === stored.tlsPin.spki);
    const env = this.store.update(id, next, keep ? undefined : await pinFor(next.url!, verifyTls, input.trustCert));
    await rt.update(env);
    return rt.summary();
  }

  /** Trust the certificate a console presents now, after the owner checked it (e.g. after replacing it). */
  async trustCert(id: string, spki: string): Promise<EnvSummary> {
    const rt = this.runtimes.get(id);
    const stored = this.store.get(id);
    if (!rt || !stored) throw new HttpError(404, 'Environment not found');
    if (stored.verifyTls || isCloudUrl(stored.url) || !stored.url.startsWith('https://')) throw new HttpError(400, 'This connection does not use a pinned certificate.');
    const pin = await pinFor(stored.url, false, spki);
    await rt.update(this.store.setPin(id, pin));
    return rt.summary();
  }

  async removeEnv(id: string): Promise<void> {
    const rt = this.runtimes.get(id);
    if (!rt) throw new HttpError(404, 'Environment not found');
    this.runtimes.delete(id);
    this.store.remove(id);
    await rt.destroy();
  }

  async testEnv(input: EnvInput & { id?: string }): Promise<EnvTestResult> {
    const stored = input.id ? this.store.get(input.id) : null;
    const url = (input.url ?? stored?.url ?? '').trim().replace(/\/+$/, '');
    // A saved key is only ever sent to the address it was saved for, never to a newly typed one.
    const key = input.apiKey?.trim() || (stored && sameOrigin(url, stored.url) ? stored.apiKey : '');
    if (!key && stored && url) return { ok: false, message: 'Enter the API key again: it is only reused for the same console address.', version: null, firewallMode: null, capabilities: [], sites: [] };
    const site = input.site?.trim() || stored?.site || 'default';
    const cloud = isCloudUrl(url);
    const verifyTls = cloud || (input.verifyTls ?? stored?.verifyTls ?? false);
    const fail = (message: string, sites: EnvTestResult['sites'] = []): EnvTestResult => ({ ok: false, message, version: null, firewallMode: null, capabilities: [], sites });
    if (!url || !key) return fail('Enter the console URL and an API key.');
    // Testing never trusts a new certificate by itself: it reports it, and saving pins the one the owner saw.
    const pin = stored?.tlsPin && sameOrigin(url, stored.url) && !verifyTls ? stored.tlsPin.spki : null;
    const transport = new HttpTransport({ baseUrl: url, apiKey: key, verifyTls, pin });
    const client = new UniFiClient(transport, site, cloud ? 'cloud' : 'unifi-os');
    const certOf = (): Pick<EnvTestResult, 'cert' | 'certChanged'> => (verifyTls || !url.startsWith('https://') ? {} : { cert: transport.mismatch ?? transport.seen, certChanged: !!transport.mismatch });
    let sites: EnvTestResult['sites'] = [];
    try {
      for (const prefix of cloud ? ['/network', '/proxy/network'] : ['/proxy/network', '']) {
        const res = await client.probe('GET', `${prefix}/integration/v1/sites?limit=200`).catch(() => null);
        if (res?.status === 200) {
          sites = (((res.json as Obj | null)?.data as Obj[]) ?? []).map((s) => ({ internalReference: String(s.internalReference ?? ''), name: String(s.name ?? s.internalReference ?? '') }));
          break;
        }
      }
      const info = await client.connect();
      const raw = await collect(client);
      const failed = raw.capabilities.filter((c) => !c.ok);
      return {
        ok: true,
        message: `Connected to UniFi Network ${info.version ?? '(unknown version)'}, site "${info.siteName ?? info.site}". ${raw.firewallMode === 'zone' ? 'Zone-based firewall detected.' : raw.firewallMode === 'legacy' ? 'Legacy firewall rules detected.' : 'Firewall mode could not be determined.'}${failed.length ? ` ${failed.length} optional data source(s) unavailable.` : ''}`,
        version: info.version,
        firewallMode: raw.firewallMode,
        capabilities: [
          { key: 'api.integration', label: 'Official Network API', ok: info.integration, detail: info.integration ? 'reachable' : 'not available' },
          { key: 'api.internal', label: 'Internal API (API key)', ok: info.internal, detail: info.internal ? 'reachable' : 'not available' },
          ...raw.capabilities,
        ],
        sites,
        ...certOf(),
      };
    } catch (e) {
      return { ...fail(e instanceof Error ? e.message : String(e), sites), ...certOf() };
    } finally {
      await transport.close().catch(() => undefined);
    }
  }

  /** Consoles a unifi.ui.com (Site Manager) API key can reach, so one can be added without a local address. */
  async cloudConsoles(input: { apiKey?: unknown; id?: unknown }): Promise<CloudConsole[]> {
    // A saved key is only used here when it is a unifi.ui.com key (a cloud environment's), never a console's local key.
    const saved = typeof input.id === 'string' ? this.store.get(input.id) : null;
    const key = String(input.apiKey ?? '').trim() || (saved && isCloudUrl(saved.url) ? saved.apiKey : '');
    if (!key) throw new HttpError(400, 'Paste an API key from unifi.ui.com first.');
    const transport = new HttpTransport({ baseUrl: CLOUD_API, apiKey: key, verifyTls: true });
    try {
      const out: CloudConsole[] = [];
      let next: string | undefined;
      for (let page = 0; page < 10; page++) {
        const res = await transport.send({ method: 'GET', path: '/v1/hosts', query: { pageSize: 100, nextToken: next }, timeoutMs: 20_000 });
        if (res.status === 401 || res.status === 403) throw new HttpError(400, 'unifi.ui.com rejected this API key. Create one at unifi.ui.com → Settings → API Keys.');
        if (res.status === 429) throw new HttpError(429, 'unifi.ui.com is rate-limiting requests. Try again in a minute.');
        if (res.status !== 200) throw new HttpError(502, `unifi.ui.com answered HTTP ${res.status}.`);
        const body = (res.json ?? {}) as { data?: Record<string, unknown>[]; nextToken?: string };
        out.push(...parseCloudHosts(body.data ?? []));
        next = body.nextToken || undefined;
        if (!next) break;
      }
      return out;
    } catch (e) {
      if (e instanceof HttpError) throw e;
      throw new HttpError(502, e instanceof Error ? e.message : String(e));
    } finally {
      await transport.close().catch(() => undefined);
    }
  }

  /** One row per environment for the cross-environment overview. */
  async fleet(): Promise<FleetRow[]> {
    const rows: FleetRow[] = [];
    for (const env of this.environments()) {
      const rt = this.runtimes.get(env.id)!;
      let posture = rt.cachedPosture();
      if (!posture && env.connected) posture = await Promise.race([rt.posture().catch(() => null), new Promise<null>((r) => setTimeout(() => r(null), 4000))]);
      const day = rt.threats.counts(Date.now() - 86400e3);
      const latest = rt.live.latest;
      rows.push({
        env,
        score: posture?.score ?? null,
        grade: posture?.grade ?? null,
        failed: posture?.failed ?? null,
        critical: posture ? posture.counts.critical + posture.counts.high : 0,
        threats24h: day.total,
        blocked24h: day.blocked,
        alerted24h: day.total - day.blocked,
        clients: latest?.clients.total ?? null,
        rxBps: latest?.wan?.rxBps ?? null,
        txBps: latest?.wan?.txBps ?? null,
      });
    }
    return rows;
  }

  // ---------------------------------------------------------------------------------
  // Global settings
  // ---------------------------------------------------------------------------------

  saveSettings(update: SettingsUpdate): void {
    saveSettings(this.settingsDb, update);
    this.cfg = loadConfig(this.settingsDb);
  }

  geoDbStatus(): GeoDbStatus {
    return this.geoDb.status();
  }

  downloadGeoDb(edition: 'country' | 'city'): Promise<GeoDbStatus> {
    return this.geoDb.download(edition);
  }

  removeGeoDb(): GeoDbStatus {
    return this.geoDb.remove();
  }

  threatCategories() {
    return listCategories();
  }
}

/** api.ui.com has a public certificate, so cloud consoles always verify TLS. */
function withCloudTls(input: EnvInput): EnvInput {
  return input.url && isCloudUrl(input.url.trim()) ? { ...input, verifyTls: true } : input;
}

const WRITE_MODES = new Set(['read-only', 'test-network', 'full']);

function checkWriteMode(input: EnvInput): void {
  if (input.writeMode !== undefined && !WRITE_MODES.has(input.writeMode)) throw new HttpError(400, 'Unknown change-safety level.');
}

/** Same scheme, host and port: the only place a saved API key may be sent. */
/**
 * The certificate to pin for a self-signed console (null when the connection is checked by certificate authorities or not
 * encrypted). When the owner tested the connection first, the console must still present exactly that certificate.
 */
async function pinFor(url: string, verifyTls: boolean, approved: string | undefined): Promise<TlsPin | null> {
  if (verifyTls || isCloudUrl(url) || !url.startsWith('https://')) return null;
  let cert: CertInfo;
  try {
    cert = await fetchCert(url);
  } catch (e) {
    // Unreachable right now: trust the first certificate at the next connection instead, unless one was approved.
    if (approved) throw new HttpError(502, e instanceof Error ? e.message : String(e));
    return null;
  }
  if (approved && cert.spki !== approved) throw new HttpError(409, 'The console now presents a different certificate than the one you checked. Test the connection again and compare the fingerprint.');
  return { ...cert, pinnedAt: Date.now() };
}

function sameOrigin(a: string, b: string): boolean {
  try {
    return new URL(a.trim()).origin === new URL(b.trim()).origin;
  } catch {
    return false;
  }
}
