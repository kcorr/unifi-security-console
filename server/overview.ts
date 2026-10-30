// The Overview's extra cards: the ways into your network from the internet, devices that joined recently, and UniFi
// devices that need attention. Pure functions over one snapshot, so they are easy to test.

import type { DeviceIssue, Door, ExposureItem, NewDevice } from '../shared/types.ts';
import type { RawSnapshot } from './unifi/collect.ts';
import { sevRank } from './security/threatKb.ts';

type Obj = Record<string, unknown>;
const DAY = 86400e3;
const str = (v: unknown) => (typeof v === 'string' && v.trim() ? v : null);
const num = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) ? v : typeof v === 'string' && v.trim() && Number.isFinite(Number(v)) ? Number(v) : null);

const VPN_NAME: [RegExp, string][] = [
  [/wireguard/i, 'WireGuard'],
  [/openvpn/i, 'OpenVPN'],
  [/l2tp/i, 'L2TP'],
  [/pptp/i, 'PPTP'],
  [/ipsec/i, 'IPsec'],
  [/teleport/i, 'Teleport'],
];
const vpnName = (type: unknown) => VPN_NAME.find(([re]) => re.test(String(type ?? '')))?.[1] ?? 'VPN';

/**
 * Every enabled way in: port forwards (with how often the device behind each was attacked), UPnP, and VPN servers
 * and site-to-site tunnels. Outgoing VPN clients are not ways in, so they are left out.
 */
export function waysIn(raw: RawSnapshot, exposure: ExposureItem[], attacks: (ip: string) => number, nameOf: (ip: string) => string | null = () => null): Door[] {
  const doors: Door[] = [];
  for (const e of exposure) {
    if (!e.enabled) continue;
    if (e.kind === 'port-forward') {
      const ip = str(raw.portForwards.find((p) => String(p._id) === e.id)?.fwd);
      // A device that is not connected right now can still be known by name from the detections that hit it.
      const name = e.internalName ?? (ip ? nameOf(ip) : null);
      const target = name ? `${name}${ip ? ` (${ip})` : ''}` : (ip ?? e.internalTarget);
      const what = e.services.length ? e.services.slice(0, 2).join(', ') : `${e.protocol} ${e.externalPort}`;
      doors.push({ id: e.id, kind: e.kind, name: e.name, detail: `${what} → ${target}`, severity: e.severity, limited: !!e.sourceRestriction, attacks: ip ? attacks(ip) : 0 });
    } else {
      doors.push({ id: e.id, kind: e.kind, name: e.name, detail: e.risk, severity: e.severity, limited: !!e.sourceRestriction, attacks: 0 });
    }
  }
  const vpn = raw.health.find((h) => h.subsystem === 'vpn');
  // Users connected to one VPN server: from the session list (which counts WireGuard users), else the site-wide summary.
  const usersOn = (serverId: string) => (raw.vpnSessions ? raw.vpnSessions.filter((s) => String(s.network_id) === serverId && s.up !== false).length : num(vpn?.remote_user_num_active));
  const up = num(vpn?.site_to_site_num_active);
  const down = num(vpn?.site_to_site_num_inactive);
  for (const n of raw.networkconf) {
    if (n.enabled === false) continue;
    if (n.purpose === 'remote-user-vpn') {
      const type = vpnName(n.vpn_type);
      const users = usersOn(String(n._id));
      doors.push({
        id: String(n._id),
        kind: 'vpn-server',
        name: str(n.name) ?? `${type} VPN server`,
        detail: `${type} server for remote access${users !== null ? ` · ${users} connected now` : ''}`,
        severity: 'info',
        limited: true,
        attacks: 0,
      });
    } else if (n.purpose === 'site-vpn') {
      const type = vpnName(n.vpn_type);
      doors.push({
        id: String(n._id),
        kind: 'site-vpn',
        name: str(n.name) ?? `${type} site-to-site VPN`,
        detail: `${type} tunnel to another site${up !== null && down !== null && up + down > 0 ? ` · ${up} of ${up + down} tunnels up` : ''}`,
        severity: 'info',
        limited: true,
        attacks: 0,
      });
    }
  }
  // The riskiest door first; among equals, the most attacked.
  return doors.sort((a, b) => sevRank(b.severity) - sevRank(a.severity) || b.attacks - a.attacks);
}

/** Devices connected now that the controller first saw within `days`, newest first. Null when client data is missing. */
export function newDevices(raw: RawSnapshot, now: number, days = 7): NewDevice[] | null {
  if (!raw.clients.length) return null;
  return raw.clients
    .map((c) => ({ c, first: num(c.first_seen) }))
    .filter((x): x is { c: Obj; first: number } => x.first !== null && now - x.first * 1000 < days * DAY && now - x.first * 1000 >= -DAY)
    .sort((a, b) => b.first - a.first)
    .map(({ c, first }) => ({
      name: str(c.name) ?? str(c.hostname),
      vendor: str(c.oui),
      ip: str(c.ip) ?? str(c.last_ip),
      network: str(c.network) ?? str(c.last_connection_network_name),
      firstSeen: first * 1000,
      wired: c.is_wired === true,
      guest: c.is_guest === true,
    }));
}

/** UniFi devices that are offline or have a firmware update waiting. Devices you disabled on purpose are left out. */
export function deviceIssues(raw: RawSnapshot): DeviceIssue[] {
  // The internal API has the detail (last seen, target version); the official API is the fallback.
  const list = raw.devices.length ? raw.devices : raw.iDevices;
  const out: DeviceIssue[] = [];
  for (const d of list) {
    if (d.disabled === true) continue;
    const name = str(d.name) ?? str(d.model) ?? str(d.mac) ?? str(d.macAddress) ?? 'UniFi device';
    const model = str(d.shortname) ?? str(d.model);
    const state = d.state;
    const lastSeen = num(d.last_seen);
    if (state === 0 || state === 6 || state === 'OFFLINE') {
      out.push({ name, model, issue: 'offline', detail: state === 6 ? 'Not responding' : 'Offline', since: lastSeen !== null ? lastSeen * 1000 : null });
    }
    if (d.upgradable === true || d.firmwareUpdatable === true) {
      const from = str(d.version) ?? str(d.firmwareVersion);
      const to = str(d.upgrade_to_firmware);
      out.push({ name, model, issue: 'update', detail: from || to ? `${from ?? 'current'} → ${to ?? 'newer firmware'}` : 'Firmware update available', since: null });
    }
  }
  return out;
}
