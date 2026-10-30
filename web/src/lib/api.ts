import type {
  AppStatus, BlockedTraffic, ChangePlan, ChangeRecord, EnvInput, EnvSummary, EnvTestResult, FirewallOverview, FleetRow, GeoDbStatus, HardeningTemplate, IpIntel, LiveClients,
  LiveSample, LiveSnapshot, NetworkRole, Posture, SegmentationMatrix, SettingsUpdate, SettingsView, TemplateStatus, ThreatCategory, ThreatEvent, ThreatQuery,
  ThreatSummary, WriteMode, RiskAcceptance, CloudConsole, OverviewExtras, LiveRange, LiveTrend, ClientDetail, UnifiDevice, UnifiDeviceDetail, MakerDbStatus,
} from '@shared/types';
import { getEnv } from './env';

export class ApiError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

// Endpoints that are not scoped to one environment.
const GLOBAL = ['/login', '/logout', '/setup', '/account', '/settings', '/environments', '/fleet', '/threats/categories', '/intel/geodb'];

export function apiUrl(path: string): string {
  const env = getEnv();
  if (!env || GLOBAL.some((g) => path.startsWith(g))) return `/api${path}`;
  return `/api${path}${path.includes('?') ? '&' : '?'}env=${encodeURIComponent(env)}`;
}

async function call<T>(method: string, path: string, body?: unknown): Promise<T> {
  let res: Response;
  try {
    res = await fetch(apiUrl(path), {
      method,
      headers: { Accept: 'application/json', 'X-Requested-With': 'usc', ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}) },
      body: body !== undefined ? JSON.stringify(body) : undefined,
      credentials: 'same-origin',
    });
  } catch {
    // The browser never reached this app's own server (stopped, restarting or another port), so the request went
    // nowhere. A plain Error (no status) keeps query retries working.
    throw new Error('Cannot reach the Security Console server, so nothing was sent to UniFi. It may be stopped or restarting — check that its container is running in Docker Desktop, then try again.');
  }
  const text = await res.text();
  const json = text ? JSON.parse(text) : null;
  if (!res.ok) {
    if (res.status === 401 && !path.startsWith('/login') && !path.startsWith('/status')) window.dispatchEvent(new Event('usc:unauthorized'));
    throw new ApiError(res.status, (json && (json.error || json.message)) || `HTTP ${res.status}`);
  }
  return json as T;
}

function qs(q: object): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(q)) {
    if (v === undefined || v === null || v === '') continue;
    if (Array.isArray(v)) {
      if (v.length) p.set(k, v.join(','));
    } else p.set(k, String(v));
  }
  const s = p.toString();
  return s ? `?${s}` : '';
}

export interface OverviewData {
  posture: Posture;
  threats: ThreatSummary;
  live: LiveSnapshot | null;
  history: LiveSample[];
  matrix: SegmentationMatrix | null;
  recent: ThreatEvent[];
  extras: OverviewExtras;
}

export interface DiagnosticsData {
  status: AppStatus;
  probes: { key: string; label: string; method: string; path: string; ok: boolean; status: number | null; detail: string; ms: number }[];
}

export const api = {
  status: () => call<AppStatus>('GET', '/status'),
  login: (username: string, password: string) => call<{ ok: boolean }>('POST', '/login', { username, password }),
  /** Creates the sign-in account on the first visit, and signs in with it. */
  setup: (username: string, password: string) => call<{ ok: boolean }>('POST', '/setup', { username, password }),
  logout: () => call<{ ok: boolean }>('POST', '/logout'),
  updateAccount: (b: { currentPassword: string; username?: string; newPassword?: string }) => call<{ ok: boolean; username: string }>('PUT', '/account', b),
  settings: () => call<SettingsView>('GET', '/settings'),
  saveSettings: (s: SettingsUpdate) => call<SettingsView>('PUT', '/settings', s),
  refresh: () => call<{ ok: boolean }>('POST', '/refresh'),

  environments: () => call<EnvSummary[]>('GET', '/environments'),
  addEnvironment: (e: EnvInput) => call<EnvSummary>('POST', '/environments', e),
  updateEnvironment: (id: string, e: EnvInput) => call<EnvSummary>('PUT', `/environments/${encodeURIComponent(id)}`, e),
  removeEnvironment: (id: string) => call<{ ok: boolean }>('DELETE', `/environments/${encodeURIComponent(id)}`),
  testEnvironment: (e: EnvInput & { id?: string }) => call<EnvTestResult>('POST', '/environments/test', e),
  trustCert: (id: string, spki: string) => call<EnvSummary>('POST', `/environments/${encodeURIComponent(id)}/trust-cert`, { spki }),
  fleet: () => call<FleetRow[]>('GET', '/fleet'),
  diagnostics: () => call<DiagnosticsData>('GET', '/diagnostics'),

  overview: () => call<OverviewData>('GET', '/overview'),
  posture: () => call<Posture>('GET', '/posture'),

  threats: (q: ThreatQuery) => call<{ total: number; events: ThreatEvent[] }>('GET', `/threats${qs(q)}`),
  threatSummary: (q: ThreatQuery) => call<ThreatSummary>('GET', `/threats/summary${qs(q)}`),
  threatCategories: () => call<ThreatCategory[]>('GET', '/threats/categories'),
  threat: (id: string) => call<ThreatEvent>('GET', `/threats/${encodeURIComponent(id)}`),

  intel: (ip: string, refresh = false) => call<IpIntel>('GET', `/intel/${encodeURIComponent(ip)}${refresh ? '?refresh=1' : ''}`),
  geo: (ips: string[]) => call<Record<string, { countryCode: string | null; country: string | null; org: string | null; city: string | null }>>('POST', '/intel/geo', { ips }),

  firewall: () => call<FirewallOverview>('GET', '/firewall'),
  matrix: () => call<SegmentationMatrix>('GET', '/firewall/matrix'),
  /** What the firewall blocked in the last 24 hours, per matrix cell. */
  blockedTraffic: () => call<BlockedTraffic>('GET', '/firewall/blocked'),
  setRole: (networkId: string, role: NetworkRole | null) => call<{ ok: boolean }>('PUT', `/networks/${encodeURIComponent(networkId)}/role`, { role }),

  templates: () =>
    call<{ templates: HardeningTemplate[]; status: TemplateStatus[]; readOnly: boolean; writeMode: WriteMode; testNetwork: { id: string; name: string; subnet: string | null; vlan: number | null; zoneId: string | null } | null }>('GET', '/hardening/templates'),
  downloadGeoDb: (edition: 'country' | 'city') => call<GeoDbStatus>('POST', '/intel/geodb', { edition }),
  removeGeoDb: () => call<GeoDbStatus>('DELETE', '/intel/geodb'),
  plan: (templateId: string, params: Record<string, unknown>, strategy?: string) => call<ChangePlan>('POST', '/hardening/plan', { templateId, params, strategy }),
  apply: (planId: string) => call<ChangeRecord>('POST', '/hardening/apply', { planId }),
  changes: () => call<ChangeRecord[]>('GET', '/changes'),
  undo: (id: string, cascade = false) => call<ChangeRecord>('POST', `/changes/${encodeURIComponent(id)}/undo`, cascade ? { cascade: true } : undefined),
  /** Later changes that would be undone first (newest first). */
  undoDependents: (id: string) => call<ChangeRecord[]>('GET', `/changes/${encodeURIComponent(id)}/dependents`),
  /** Consoles reachable with a unifi.ui.com API key (the typed key, or the one saved for environment `id`). */
  cloudConsoles: (b: { apiKey?: string; id?: string }) => call<CloudConsole[]>('POST', '/environments/cloud-consoles', b),
  risks: () => call<RiskAcceptance[]>('GET', '/risks'),
  acceptRisk: (r: { key: string; kind: RiskAcceptance['kind']; title: string; reason: string }) => call<RiskAcceptance>('POST', '/risks', r),
  revokeRisk: (key: string) => call<{ ok: boolean }>('DELETE', `/risks/${encodeURIComponent(key)}`),

  liveSnapshot: () => call<LiveSnapshot>('GET', '/live/snapshot'),
  liveHistory: () => call<LiveSample[]>('GET', '/live/history'),
  liveTrend: (range: LiveRange) => call<LiveTrend>('GET', `/live/trend?range=${range}`),
  clientDetail: (mac: string) => call<ClientDetail>('GET', `/clients/${encodeURIComponent(mac)}`),
  unifiDevices: () => call<UnifiDevice[]>('GET', '/unifi-devices'),
  unifiDevice: (mac: string) => call<UnifiDeviceDetail>('GET', `/unifi-devices/${encodeURIComponent(mac)}`),
  makers: () => call<MakerDbStatus>('GET', '/intel/makers'),
  downloadMakers: () => call<MakerDbStatus>('POST', '/intel/makers'),
  removeMakers: () => call<MakerDbStatus>('DELETE', '/intel/makers'),
  liveClients: () => call<LiveClients>('GET', '/live/clients'),
};
