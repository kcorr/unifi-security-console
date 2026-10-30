// The Devices page and the device panels: UniFi's own devices (gateway, switches, access points) and how one client is
// connected. Pure functions over the controller's data, so they are easy to test.

import type { ClientDetail, UnifiDevice, UnifiDeviceDetail } from '../shared/types.ts';
import type { RawSnapshot } from './unifi/collect.ts';

type Obj = Record<string, unknown>;
const obj = (v: unknown): Obj => (v && typeof v === 'object' && !Array.isArray(v) ? (v as Obj) : {});
const arr = (v: unknown): Obj[] => (Array.isArray(v) ? (v as Obj[]) : []);
const str = (v: unknown) => (typeof v === 'string' && v.trim() ? v : null);
const num = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : typeof v === 'string' && v.trim() && Number.isFinite(Number(v)) ? Number(v) : null);
const round1 = (v: number | null) => (v === null ? null : Math.round(v * 10) / 10);
/** UniFi's 0–100 experience score; it reports -1 while there is nothing to measure. */
const score = (v: unknown): number | null => {
  const n = num(v);
  return n !== null && n >= 0 && n <= 100 ? n : null;
};

const GATEWAYS = new Set(['udm', 'ugw', 'uxg', 'udr', 'ucg', 'uxgpro']);
const BAND: Record<string, string> = { ng: '2.4 GHz', na: '5 GHz', '6e': '6 GHz', wifi6e: '6 GHz' };
const STANDARD: Record<string, string> = { be: 'Wi-Fi 7', ax: 'Wi-Fi 6', ac: 'Wi-Fi 5', n: 'Wi-Fi 4', g: 'Wi-Fi 3 (802.11g)', a: 'Wi-Fi 2 (802.11a)', b: 'Wi-Fi 1 (802.11b)' };

function kindOf(d: Obj): UnifiDevice['kind'] {
  const type = String(d.type ?? '').toLowerCase();
  if (GATEWAYS.has(type) || (Array.isArray(d.features) && (d.features as string[]).includes('gateway'))) return 'gateway';
  if (type === 'usw' || (Array.isArray(d.features) && (d.features as string[]).includes('switching'))) return 'switch';
  if (type === 'uap' || (Array.isArray(d.features) && (d.features as string[]).includes('accessPoint'))) return 'ap';
  return 'other';
}

function stateOf(d: Obj): UnifiDevice['state'] {
  if (d.disabled === true) return 'disabled';
  if (d.state === 'ONLINE') return 'online';
  if (d.state === 'OFFLINE') return 'offline';
  const s = num(d.state);
  if (s === 1) return 'online';
  if (s === 0 || s === 6) return 'offline';
  if (s === 4 || s === 5) return 'updating';
  if (s === 2 || s === 7) return 'adopting';
  return 'other';
}

function deviceOf(d: Obj): UnifiDevice {
  const sys = obj(d['system-stats']);
  const temps = arr(d.temperatures);
  const cpuTemp = temps.find((t) => /cpu/i.test(String(t.name ?? t.type))) ?? temps[0];
  const kind = kindOf(d);
  const up = obj(d.uplink);
  const uplink: UnifiDevice['uplink'] = !d.uplink
    ? null
    : up.type === 'wireless'
      ? { name: str(up.uplink_device_name), port: null, speedMbps: null, wireless: true }
      : kind === 'gateway'
        ? { name: 'Internet', port: num(up.port_idx), speedMbps: num(up.speed), wireless: false }
        : { name: str(up.uplink_device_name), port: num(up.uplink_remote_port), speedMbps: num(up.speed), wireless: false };
  const lastSeen = num(d.last_seen);
  return {
    mac: String(d.mac ?? d.macAddress ?? '').toLowerCase(),
    name: str(d.name) ?? str(d.shortname) ?? str(d.model) ?? 'UniFi device',
    model: str(d.shortname) ?? str(d.model),
    kind,
    state: stateOf(d),
    ip: str(d.ip) ?? str(d.ipAddress) ?? str(obj(d.config_network).ip),
    version: str(d.version) ?? str(d.firmwareVersion),
    update: d.upgradable === true || d.firmwareUpdatable === true ? (str(d.upgrade_to_firmware) ?? 'newer firmware') : null,
    endOfLife: d.model_in_eol === true,
    uptime: num(d.uptime),
    lastSeen: lastSeen !== null ? lastSeen * 1000 : null,
    clients: num(d.num_sta),
    cpu: round1(num(sys.cpu)),
    mem: round1(num(sys.mem)),
    tempC: round1(num(cpuTemp?.value) ?? num(d.general_temperature)),
    uplink,
  };
}

const ORDER: Record<UnifiDevice['kind'], number> = { gateway: 0, switch: 1, ap: 2, other: 3 };

/** All UniFi devices, gateway first, then switches and access points; within those by name. */
export function unifiDevices(raw: RawSnapshot): UnifiDevice[] {
  const list = raw.devices.length ? raw.devices : raw.iDevices;
  return list.map(deviceOf).sort((a, b) => ORDER[a.kind] - ORDER[b.kind] || a.name.localeCompare(b.name));
}

export function unifiDeviceDetail(raw: RawSnapshot, mac: string): UnifiDeviceDetail | null {
  const want = mac.toLowerCase();
  const d = (raw.devices.length ? raw.devices : raw.iDevices).find((x) => String(x.mac ?? x.macAddress ?? '').toLowerCase() === want);
  if (!d) return null;
  const base = deviceOf(d);
  const ports = arr(d.port_table)
    .map((p) => {
      const idx = num(p.port_idx) ?? 0;
      const up = p.up === true;
      // A port counts from the switch's side: what it sends goes down to the device behind it.
      const rate = (k: string) => (up ? Math.round((num(p[k]) ?? 0) * 8) : null);
      return {
        idx,
        name: str(p.name) ?? `Port ${idx}`,
        up,
        enabled: p.enable !== false,
        speedMbps: up ? num(p.speed) : null,
        fullDuplex: typeof p.full_duplex === 'boolean' ? p.full_duplex : null,
        poeWatts: p.poe_enable === true || p.port_poe === true ? round1(num(p.poe_power)) : null,
        uplink: p.is_uplink === true,
        devices: num(p.mac_table_count),
        downBps: rate('tx_bytes-r'),
        upBps: rate('rx_bytes-r'),
        errors: (num(p.rx_errors) ?? 0) + (num(p.tx_errors) ?? 0) || null,
      };
    })
    .sort((a, b) => a.idx - b.idx);
  const config = arr(d.radio_table);
  const radios = arr(d.radio_table_stats).map((r) => {
    const cfg = config.find((c) => c.name === r.name) ?? {};
    const band = String(r.radio ?? cfg.radio ?? '');
    return {
      band: BAND[band] ?? band,
      channel: num(r.channel) ?? num(cfg.channel),
      width: num(r.bw) ?? num(cfg.ht),
      txPower: num(r.tx_power) ?? num(cfg.tx_power),
      clients: num(r.num_sta),
      utilization: num(r.cu_total),
      experience: score(r.satisfaction),
      retriesPct: round1(num(r.tx_retries_pct)),
    };
  });
  const poeUsed = ports.reduce((a, p) => a + (p.poeWatts ?? 0), 0);
  const maxW = num(d.total_max_power);
  const connected = raw.clients
    .filter((c) => String(c.last_uplink_mac ?? c.sw_mac ?? c.ap_mac ?? '').toLowerCase() === want)
    .map((c) => ({
      mac: String(c.mac ?? ''),
      name: String(c.name || c.hostname || c.oui || c.mac || 'Unknown device'),
      ip: str(c.ip),
      wired: c.is_wired === true,
      port: c.is_wired === true ? num(c.sw_port) : null,
      ssid: str(c.essid),
    }))
    .sort((a, b) => (a.port ?? 999) - (b.port ?? 999) || a.name.localeCompare(b.name));
  return { ...base, ports, radios, poe: maxW !== null || poeUsed > 0 ? { usedW: round1(poeUsed), maxW } : null, connected };
}

/** How a client is connected, from its stat/sta record. */
export function clientConnection(c: Obj): ClientDetail['connection'] {
  const wired = c.is_wired === true;
  const nss = num(c.nss);
  const radio = String(c.radio ?? '');
  const proto = String(c.radio_proto ?? '');
  const kbps = (v: unknown) => (num(v) === null ? null : Math.round(num(v)! / 1000));
  return {
    wired,
    guest: c.is_guest === true,
    via: str(c.last_uplink_name),
    port: wired ? num(c.sw_port) : null,
    linkMbps: wired ? num(c.wired_rate_mbps) : null,
    ssid: wired ? null : str(c.essid),
    band: wired ? null : (BAND[radio] ?? (radio || null)),
    standard: wired ? null : (STANDARD[proto] ? `${STANDARD[proto]}${proto === 'ax' && radio === '6e' ? 'E' : ''}` : proto || null),
    channel: wired ? null : num(c.channel),
    channelWidth: wired ? null : num(c.channel_width),
    signal: wired ? null : num(c.signal),
    rxRateMbps: wired ? null : kbps(c.rx_rate),
    txRateMbps: wired ? null : kbps(c.tx_rate),
    streams: wired || !nss ? null : `${nss}x${nss}`,
    retriesPct: wired ? null : round1(num(c.wifi_tx_retries_percentage)),
    experience: score(c.satisfaction),
  };
}
