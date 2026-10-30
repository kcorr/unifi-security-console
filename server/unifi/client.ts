// UniFi API client.
//
// Two API families are used, both authenticated with the same X-API-KEY header:
//  * the official Network API ("integration API"):  {prefix}/integration/v1/...
//    documented by Ubiquiti; used for networks, firewall zones/policies, traffic matching lists.
//  * the internal API the Network web UI uses:       {prefix}/api/s/{site}/...  and  {prefix}/v2/api/site/{site}/...
//    undocumented but the only source for IPS events, settings, port forwards, live stats.
// On UniFi OS consoles (and UniFi OS Server) {prefix} is "/proxy/network".

import type { HttpRequest, HttpResponse, Transport } from './http.ts';
import { UniFiHttpError } from './http.ts';

export interface ControllerInfo {
  /** 'cloud': reached through unifi.ui.com's connector, which adds the /proxy part of the path itself. */
  kind: 'unifi-os' | 'self-hosted' | 'cloud';
  prefix: string;
  version: string | null;
  site: string;
  siteId: string | null;
  siteName: string | null;
  integration: boolean;
  internal: boolean;
}

interface IntegrationPage<T> {
  offset: number;
  limit: number;
  count: number;
  totalCount: number;
  data: T[];
}

function errorMessage(res: HttpResponse): string {
  const j = res.json as Record<string, unknown> | null;
  if (j && typeof j === 'object') {
    const meta = j.meta as { msg?: string } | undefined;
    const err = j.error as { message?: string } | string | undefined;
    const parts = [j.code, j.message, meta?.msg, typeof err === 'string' ? err : err?.message, j.errorCode].filter((x) => typeof x === 'string' && x);
    if (parts.length) return [...new Set(parts as string[])].join(': ');
  }
  return res.text ? res.text.slice(0, 200) : `HTTP ${res.status}`;
}

export function apiErrorCode(e: unknown): string | null {
  if (!(e instanceof UniFiHttpError)) return null;
  try {
    const j = JSON.parse(e.body) as { code?: string; meta?: { msg?: string } };
    return j.code ?? j.meta?.msg ?? null;
  } catch {
    return null;
  }
}

export class UniFiClient {
  readonly transport: Transport;
  info: ControllerInfo;

  constructor(transport: Transport, site: string, kind: ControllerInfo['kind'] = 'unifi-os') {
    this.transport = transport;
    this.info = { kind, prefix: '/proxy/network', version: null, site: site || 'default', siteId: null, siteName: null, integration: false, internal: false };
  }

  private async raw(req: HttpRequest): Promise<HttpResponse> {
    return this.transport.send(req);
  }

  private async ok(req: HttpRequest): Promise<HttpResponse> {
    const res = await this.raw(req);
    if (res.status < 200 || res.status >= 300) {
      throw new UniFiHttpError(res.status, req.path, res.text, `${req.method} ${req.path} → ${res.status} ${errorMessage(res)}`);
    }
    // The v1 API reports some failures with HTTP 200 and meta.rc = "error".
    const meta = (res.json as { meta?: { rc?: string; msg?: string } } | null)?.meta;
    if (meta?.rc === 'error') throw new UniFiHttpError(400, req.path, res.text, `${req.method} ${req.path} → ${meta.msg ?? 'error'}`);
    return res;
  }

  /** Detect API prefix, controller version and site id. Throws a readable error on failure. */
  async connect(): Promise<ControllerInfo> {
    const cloud = this.info.kind === 'cloud';
    const attempts = cloud ? ['/network', '/proxy/network'] : ['/proxy/network', ''];
    let lastErr = '';
    for (const prefix of attempts) {
      let res: HttpResponse;
      try {
        res = await this.raw({ method: 'GET', path: `${prefix}/integration/v1/info`, timeoutMs: 12_000 });
      } catch (e) {
        throw e instanceof Error ? e : new Error(String(e));
      }
      if (res.status === 200) {
        this.info.prefix = prefix;
        this.info.integration = true;
        this.info.version = ((res.json as { applicationVersion?: string } | null)?.applicationVersion as string) ?? null;
        if (!cloud) this.info.kind = prefix ? 'unifi-os' : 'self-hosted';
        break;
      }
      if (res.status === 401 || res.status === 403) {
        throw new UniFiHttpError(
          res.status,
          res.text,
          res.text,
          cloud
            ? 'unifi.ui.com rejected the API key, or this console is not on the account. Use a key from unifi.ui.com (Settings → API Keys) created by an owner of this console.'
            : 'The controller rejected the API key (401). Check that the key is correct and was created on this console (Settings → Control Plane → Integrations).',
        );
      }
      if (cloud && res.status === 429) throw new UniFiHttpError(429, res.text, res.text, 'unifi.ui.com is rate-limiting requests to this console. Try again in a minute.');
      lastErr = `${prefix || '(no prefix)'}: HTTP ${res.status}`;
    }

    if (this.info.integration) {
      try {
        const sites = await this.integAll<{ id: string; internalReference: string; name: string }>('/sites');
        const match = sites.find((s) => s.internalReference === this.info.site) ?? sites.find((s) => s.name.toLowerCase() === this.info.site.toLowerCase()) ?? (sites.length === 1 ? sites[0] : undefined);
        if (match) {
          this.info.siteId = match.id;
          this.info.site = match.internalReference || this.info.site;
          this.info.siteName = match.name;
        } else if (sites.length) {
          throw new Error(`Site "${this.info.site}" not found. Available sites: ${sites.map((s) => `${s.internalReference} (${s.name})`).join(', ')}`);
        }
      } catch (e) {
        if (e instanceof Error && e.message.startsWith('Site ')) throw e;
      }
    }

    // Internal API reachable with the key?
    for (const prefix of this.info.integration ? [this.info.prefix] : cloud ? ['/network', '/proxy/network'] : ['/proxy/network', '']) {
      try {
        const res = await this.raw({ method: 'GET', path: `${prefix}/api/s/${this.info.site}/stat/health`, timeoutMs: 12_000 });
        if (res.status === 200) {
          this.info.internal = true;
          this.info.prefix = prefix;
          if (!this.info.integration && !cloud) this.info.kind = prefix ? 'unifi-os' : 'self-hosted';
          break;
        }
      } catch {
        /* ignore */
      }
    }
    if (!this.info.integration && !this.info.internal) {
      throw new Error(`Could not reach the UniFi Network API with this key (${lastErr || 'no response'}). API keys require a UniFi OS console or UniFi OS Server running Network 9.0 or newer.`);
    }
    if (this.info.internal && !this.info.version) {
      try {
        const sys = await this.v1<{ version?: string }>('GET', '/stat/sysinfo');
        this.info.version = sys[0]?.version ?? null;
      } catch {
        /* ignore */
      }
    }
    return this.info;
  }

  // ---------------------------------------------------------------------------------
  // Official integration API
  // ---------------------------------------------------------------------------------

  integPath(path: string): string {
    const p = path.startsWith('/sites/') || path === '/sites' || path.startsWith('/info') || path.startsWith('/dpi') || path.startsWith('/countries') ? path : `/sites/${this.info.siteId}${path}`;
    return `${this.info.prefix}/integration/v1${p}`;
  }

  async integ<T>(method: HttpRequest['method'], path: string, body?: unknown, query?: HttpRequest['query']): Promise<T> {
    const res = await this.ok({ method, path: this.integPath(path), body, query });
    return res.json as T;
  }

  async integAll<T>(path: string, query: HttpRequest['query'] = {}): Promise<T[]> {
    const out: T[] = [];
    let offset = 0;
    for (let i = 0; i < 100; i++) {
      const page = await this.integ<IntegrationPage<T>>('GET', path, undefined, { ...query, offset, limit: 200 });
      out.push(...(page.data ?? []));
      offset += page.count ?? page.data?.length ?? 0;
      if (!page.data?.length || offset >= (page.totalCount ?? 0)) break;
    }
    return out;
  }

  // ---------------------------------------------------------------------------------
  // Internal API
  // ---------------------------------------------------------------------------------

  async v1<T>(method: HttpRequest['method'], path: string, body?: unknown): Promise<T[]> {
    const res = await this.ok({ method, path: `${this.info.prefix}/api/s/${this.info.site}${path}`, body });
    const j = res.json as { data?: T[] } | T[] | null;
    if (Array.isArray(j)) return j;
    return j?.data ?? [];
  }

  async v2<T>(method: HttpRequest['method'], path: string, body?: unknown, query?: HttpRequest['query']): Promise<T> {
    const res = await this.ok({ method, path: `${this.info.prefix}/v2/api/site/${this.info.site}${path}`, body, query });
    return res.json as T;
  }

  /** Full path for an API family + sub path (used to show users the exact URL a change hits). */
  fullPath(kind: 'integration' | 'v1' | 'v2', sub: string): string {
    if (kind === 'integration') return this.integPath(sub);
    if (kind === 'v1') return `${this.info.prefix}/api/s/${this.info.site}${sub}`;
    return `${this.info.prefix}/v2/api/site/${this.info.site}${sub}`;
  }

  /** Request by full path; throws on HTTP / API errors and returns the parsed JSON. */
  async request<T = unknown>(method: HttpRequest['method'], fullPath: string, body?: unknown, query?: HttpRequest['query']): Promise<T> {
    const res = await this.ok({ method, path: fullPath, body, query });
    return res.json as T;
  }

  /** Low-level request used by diagnostics; never throws on HTTP errors. */
  async probe(method: HttpRequest['method'], fullPath: string, body?: unknown): Promise<HttpResponse> {
    return this.raw({ method, path: fullPath, body, timeoutMs: 15_000 });
  }
}
