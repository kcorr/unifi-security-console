// Pulls configuration + state from the controller into one raw snapshot.
// Every call is optional: failures are recorded as capabilities instead of aborting.

import type { CapabilityReport, FirewallMode } from '../../shared/types.ts';
import type { UniFiClient } from './client.ts';
import { apiErrorCode } from './client.ts';
import { UniFiHttpError } from './http.ts';

type Obj = Record<string, unknown>;

export interface RawSnapshot {
  fetchedAt: number;
  firewallMode: FirewallMode;
  /** Where zones/policies came from. IDs inside the model are only consistent within one source. */
  firewallSource: 'integration' | 'internal-v2' | 'legacy' | 'none';
  iNetworks: Obj[];
  iZones: Obj[];
  iPolicies: Obj[];
  iLists: Obj[];
  iWifi: Obj[];
  iDevices: Obj[];
  iClients: Obj[];
  networkconf: Obj[];
  v2Zones: Obj[];
  v2Policies: Obj[];
  legacyRules: Obj[];
  firewallGroups: Obj[];
  trafficRules: Obj[];
  portForwards: Obj[];
  wlans: Obj[];
  settings: Record<string, Obj>;
  devices: Obj[];
  clients: Obj[];
  health: Obj[];
  /** Remote-access VPN sessions (WireGuard, OpenVPN, L2TP…); null when the controller doesn't report them. */
  vpnSessions: Obj[] | null;
  capabilities: CapabilityReport[];
  errors: string[];
}

function describeError(e: unknown): string {
  if (e instanceof UniFiHttpError) {
    if (e.status === 404) return 'not available on this controller version';
    if (e.status === 401 || e.status === 403) return 'not permitted for this API key';
    return e.message.slice(0, 200);
  }
  return e instanceof Error ? e.message.slice(0, 200) : String(e);
}

export async function collect(client: UniFiClient): Promise<RawSnapshot> {
  const caps: CapabilityReport[] = [];
  const errors: string[] = [];
  const info = client.info;
  const snap: RawSnapshot = {
    fetchedAt: Date.now(),
    firewallMode: 'unknown',
    firewallSource: 'none',
    iNetworks: [],
    iZones: [],
    iPolicies: [],
    iLists: [],
    iWifi: [],
    iDevices: [],
    iClients: [],
    networkconf: [],
    v2Zones: [],
    v2Policies: [],
    legacyRules: [],
    firewallGroups: [],
    trafficRules: [],
    portForwards: [],
    wlans: [],
    settings: {},
    devices: [],
    clients: [],
    health: [],
    vpnSessions: null,
    capabilities: caps,
    errors,
  };

  const attempt = async <T>(key: string, label: string, fn: () => Promise<T>, okDetail: (v: T) => string): Promise<T | null> => {
    try {
      const v = await fn();
      caps.push({ key, label, ok: true, detail: okDetail(v) });
      return v;
    } catch (e) {
      caps.push({ key, label, ok: false, detail: describeError(e) });
      if (!(e instanceof UniFiHttpError && (e.status === 404 || e.status === 400))) errors.push(`${label}: ${describeError(e)}`);
      return null;
    }
  };
  const count = (v: unknown[]) => `${v.length} item${v.length === 1 ? '' : 's'}`;

  const integ = info.integration && !!info.siteId;
  const internal = info.internal;

  // --- Firewall model source ---------------------------------------------------
  let zoneBasedNotConfigured = false;
  if (integ) {
    try {
      snap.iZones = await client.integAll<Obj>('/firewall/zones');
      caps.push({ key: 'integration.zones', label: 'Firewall zones (official API)', ok: true, detail: count(snap.iZones) });
    } catch (e) {
      if (apiErrorCode(e) === 'api.firewall.zone-based-firewall-not-configured') zoneBasedNotConfigured = true;
      caps.push({ key: 'integration.zones', label: 'Firewall zones (official API)', ok: false, detail: zoneBasedNotConfigured ? 'site still uses legacy firewall rules' : describeError(e) });
    }
    if (snap.iZones.length) {
      const pol = await attempt('integration.policies', 'Firewall policies (official API)', () => client.integAll<Obj>('/firewall/policies'), count);
      if (pol) {
        snap.iPolicies = pol;
        snap.firewallSource = 'integration';
        snap.firewallMode = 'zone';
      }
    }
  }
  if (snap.firewallSource === 'integration' && internal) {
    // Display only: the official API lists WAN / VPN zone members by ids it never resolves, while the internal zone
    // list uses networkconf ids, which name every member. Best effort, so no capability entry.
    try {
      const zones = await client.v2<Obj[] | { data: Obj[] }>('GET', '/firewall/zone');
      snap.v2Zones = Array.isArray(zones) ? zones : (zones.data ?? []);
    } catch {
      // Names fall back to "n other".
    }
  }
  if (snap.firewallSource === 'none' && internal && !zoneBasedNotConfigured) {
    const zones = await attempt('internal.zones', 'Firewall zones (internal API)', () => client.v2<Obj[] | { data: Obj[] }>('GET', '/firewall/zone'), (v) => count(Array.isArray(v) ? v : v.data ?? []));
    const zl = zones ? (Array.isArray(zones) ? zones : zones.data ?? []) : [];
    if (zl.length) {
      const pols = await attempt('internal.policies', 'Firewall policies (internal API)', () => client.v2<Obj[] | { data: Obj[] }>('GET', '/firewall-policies'), (v) => count(Array.isArray(v) ? v : v.data ?? []));
      if (pols) {
        snap.v2Zones = zl;
        snap.v2Policies = Array.isArray(pols) ? pols : pols.data ?? [];
        snap.firewallSource = 'internal-v2';
        snap.firewallMode = 'zone';
      }
    }
  }

  // --- Everything else, in parallel ----------------------------------------------
  const tasks: Promise<unknown>[] = [];
  if (integ) {
    if (snap.firewallSource === 'integration') {
      tasks.push(
        attempt('integration.networks', 'Networks (official API)', async () => {
          const list = await client.integAll<Obj>('/networks');
          // Details carry subnets / zone / isolation flags.
          const details = await Promise.all(list.map((n) => client.integ<Obj>('GET', `/networks/${n.id}`).catch(() => n)));
          return details;
        }, count).then((v) => v && (snap.iNetworks = v)),
      );
      tasks.push(attempt('integration.lists', 'Traffic matching lists (official API)', () => client.integAll<Obj>('/traffic-matching-lists'), count).then((v) => v && (snap.iLists = v)));
    }
    tasks.push(attempt('integration.wifi', 'WiFi broadcasts (official API)', () => client.integAll<Obj>('/wifi/broadcasts'), count).then((v) => v && (snap.iWifi = v)));
    tasks.push(attempt('integration.devices', 'Devices (official API)', () => client.integAll<Obj>('/devices'), count).then((v) => v && (snap.iDevices = v)));
    if (!internal) tasks.push(attempt('integration.clients', 'Clients (official API)', () => client.integAll<Obj>('/clients'), count).then((v) => v && (snap.iClients = v)));
  }
  if (internal) {
    tasks.push(attempt('internal.networkconf', 'Network configuration', () => client.v1<Obj>('GET', '/rest/networkconf'), count).then((v) => v && (snap.networkconf = v)));
    tasks.push(attempt('internal.firewallgroup', 'Firewall groups', () => client.v1<Obj>('GET', '/rest/firewallgroup'), count).then((v) => v && (snap.firewallGroups = v)));
    if (snap.firewallMode !== 'zone') {
      tasks.push(
        attempt('internal.firewallrule', 'Legacy firewall rules', () => client.v1<Obj>('GET', '/rest/firewallrule'), count).then((v) => {
          if (v) {
            snap.legacyRules = v;
            snap.firewallSource = 'legacy';
            snap.firewallMode = 'legacy';
          }
        }),
      );
    }
    tasks.push(attempt('internal.trafficrules', 'Traffic rules', () => client.v2<Obj[]>('GET', '/trafficrules'), (v) => count(Array.isArray(v) ? v : [])).then((v) => Array.isArray(v) && (snap.trafficRules = v)));
    tasks.push(attempt('internal.portforward', 'Port forwards', () => client.v1<Obj>('GET', '/rest/portforward'), count).then((v) => v && (snap.portForwards = v)));
    tasks.push(attempt('internal.wlanconf', 'WiFi networks', () => client.v1<Obj>('GET', '/rest/wlanconf'), count).then((v) => v && (snap.wlans = v)));
    tasks.push(
      attempt('internal.settings', 'Site settings (IPS, UPnP…)', () => client.v1<Obj>('GET', '/get/setting'), count).then((v) => {
        if (v) for (const s of v) if (typeof s.key === 'string') snap.settings[s.key] = s;
      }),
    );
    tasks.push(attempt('internal.devices', 'Devices (internal API)', () => client.v1<Obj>('GET', '/stat/device'), count).then((v) => v && (snap.devices = v)));
    tasks.push(attempt('internal.clients', 'Active clients', () => client.v1<Obj>('GET', '/stat/sta'), count).then((v) => v && (snap.clients = v)));
    tasks.push(attempt('internal.health', 'Site health', () => client.v1<Obj>('GET', '/stat/health'), count).then((v) => v && (snap.health = v)));
    // The health summary's VPN user count leaves out WireGuard; the session list has every remote-access VPN user.
    tasks.push(attempt('internal.vpnsessions', 'VPN sessions', () => client.v1<Obj>('GET', '/stat/remoteuservpn'), count).then((v) => v && (snap.vpnSessions = v)));
  }
  await Promise.all(tasks);
  return snap;
}
