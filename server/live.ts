// Live statistics: ring buffer of samples + Server-Sent Events fan-out.

import type { ServerResponse } from 'node:http';
import type { ClientRow, LiveClients, LiveEvent, LiveRange, LiveSample, LiveSnapshot, LiveTrend, NetworkLoad } from '../shared/types.ts';
import type { Db } from './db.ts';
import type { NetInfo } from './security/model.ts';

type Obj = Record<string, unknown>;

const num = (v: unknown): number | null => {
  const x = typeof v === 'string' ? Number(v) : typeof v === 'number' ? v : NaN;
  return Number.isFinite(x) ? x : null;
};

/** Controllers report e.g. 70.10000000000001 °C. */
const round1 = (v: number | null): number | null => (v === null ? null : Math.round(v * 10) / 10);

const isOnline = (d: Obj) => num(d.state) === 1 || d.state === 'ONLINE';

const GATEWAY_TYPES = new Set(['udm', 'ugw', 'uxg', 'udr', 'ucg', 'uxgpro']);

export function findGateway(devices: Obj[]): Obj | null {
  return devices.find((d) => GATEWAY_TYPES.has(String(d.type)) || /^(UDM|UDR|UCG|UXG|USG)/i.test(String(d.model ?? ''))) ?? null;
}

export function buildLiveSnapshot(p: { health: Obj[]; devices: Obj[]; clients: Obj[]; threats: { lastHour: number; last24h: number; blocked24h: number }; integrationStats?: Obj | null }): LiveSnapshot {
  const wan = p.health.find((h) => h.subsystem === 'wan');
  const www = p.health.find((h) => h.subsystem === 'www');
  const gw = findGateway(p.devices);
  const sys = (gw?.['system-stats'] ?? {}) as Obj;
  const temp = Array.isArray(gw?.temperatures) ? ((gw!.temperatures as Obj[]).find((t) => String(t.type ?? t.name).toLowerCase().includes('cpu')) ?? (gw!.temperatures as Obj[])[0]) : null;
  const latency = num(www?.latency) ?? num(((wan?.uptime_stats as Obj | undefined)?.WAN as Obj | undefined)?.latency_average);
  const ist = p.integrationStats ?? null;
  const uplink = (ist?.uplink ?? {}) as Obj;
  const rxBps = wan ? (num(wan['rx_bytes-r']) ?? 0) * 8 : num(uplink.rxRateBps);
  const txBps = wan ? (num(wan['tx_bytes-r']) ?? 0) * 8 : num(uplink.txRateBps);
  const clients = p.clients;
  return {
    t: Date.now(),
    wan: wan || ist ? { rxBps, txBps, latencyMs: latency, ip: (wan?.wan_ip as string) ?? null, isp: (wan?.isp_name as string) ?? (wan?.isp_organization as string) ?? null, status: (wan?.status as string) ?? null, uptime: num(www?.uptime) ?? num(ist?.uptimeSec) } : null,
    gateway: gw || ist
      ? {
          name: (gw?.name as string) ?? null,
          // `shortname` is the product name ("UDR7"); `model` can be an internal code ("UDMA67A").
          model: (gw?.shortname as string) ?? (gw?.model as string) ?? null,
          version: (gw?.version as string) ?? null,
          cpu: round1(num(sys.cpu) ?? num(ist?.cpuUtilizationPct)),
          mem: round1(num(sys.mem) ?? num(ist?.memoryUtilizationPct)),
          tempC: temp ? round1(num(temp.value)) : null,
          uptime: num(gw?.uptime) ?? num(ist?.uptimeSec),
          upgradable: gw?.upgradable === true,
        }
      : null,
    clients: {
      total: clients.length,
      wired: clients.filter((c) => c.is_wired === true).length,
      wireless: clients.filter((c) => c.is_wired === false).length,
      guest: clients.filter((c) => c.is_guest === true).length,
      vpn: clients.filter((c) => String(c.type ?? '').toUpperCase() === 'VPN' || String(c.network ?? '').toLowerCase().includes('vpn')).length,
    },
    devices: {
      total: p.devices.length,
      online: p.devices.filter(isOnline).length,
      // A device switched off in UniFi ("disabled") is not a problem to report as offline.
      offline: p.devices.filter((d) => !isOnline(d) && d.disabled !== true).length,
      disabled: p.devices.filter((d) => !isOnline(d) && d.disabled === true).length,
      upgradable: p.devices.filter((d) => d.upgradable === true || d.firmwareUpdatable === true).length,
    },
    threats: p.threats,
  };
}

export function sampleOf(s: LiveSnapshot): LiveSample {
  return { t: s.t, rxBps: s.wan?.rxBps ?? null, txBps: s.wan?.txBps ?? null, latencyMs: s.wan?.latencyMs ?? null, clients: s.clients.total, cpu: s.gateway?.cpu ?? null, mem: s.gateway?.mem ?? null };
}

/** Bytes per device (by MAC) from UniFi's hourly per-client report rows. */
export function usageByMac(rows: Obj[]): Map<string, { rx: number; tx: number }> {
  const m = new Map<string, { rx: number; tx: number }>();
  for (const r of rows) {
    const mac = typeof r.user === 'string' ? r.user.toLowerCase() : '';
    if (!mac) continue;
    const u = m.get(mac) ?? { rx: 0, tx: 0 };
    u.rx += num(r.rx_bytes) ?? 0;
    u.tx += num(r.tx_bytes) ?? 0;
    m.set(mac, u);
  }
  return m;
}

/**
 * A client's traffic as download (rx) and upload (tx). Wi-Fi clients report it from the client's side. Wired clients
 * only have the switch port's counters, seen from the switch: what the port sends (tx) is the device's download.
 * Wired clients get no live rate from UniFi, so it is worked out from how much the counters grew since the last poll.
 */
export class ClientTraffic {
  private readonly last = new Map<string, { t: number; down: number; up: number }>();

  read(c: Obj, now = Date.now()): { down: number; up: number; downBps: number; upBps: number } {
    const mac = String(c.mac ?? c.macAddress ?? '').toLowerCase();
    if (c.is_wired !== true || c['wired-tx_bytes'] === undefined) {
      return { down: num(c.rx_bytes) ?? 0, up: num(c.tx_bytes) ?? 0, downBps: (num(c['rx_bytes-r']) ?? 0) * 8, upBps: (num(c['tx_bytes-r']) ?? 0) * 8 };
    }
    const down = num(c['wired-tx_bytes']) ?? 0;
    const up = num(c['wired-rx_bytes']) ?? 0;
    const prev = this.last.get(mac);
    this.last.set(mac, { t: now, down, up });
    const secs = prev ? (now - prev.t) / 1000 : 0;
    // A counter that went backwards means the device reconnected: no rate this time.
    const rate = (cur: number, before: number | undefined) => (prev && secs >= 1 && before !== undefined && cur >= before ? ((cur - before) * 8) / secs : 0);
    return { down, up, downBps: rate(down, prev?.down), upBps: rate(up, prev?.up) };
  }
}

export function buildLiveClients(clients: Obj[], networks: NetInfo[], usage24h: Map<string, { rx: number; tx: number }> | null = null, traffic = new ClientTraffic()): LiveClients {
  const rows: ClientRow[] = clients.map((c) => {
    const t = traffic.read(c);
    const vlan = num(c.vlan);
    const net = networks.find((n) => n.id === c.network_id || n.raw._legacyId === c.network_id) ?? (typeof c.ip === 'string' ? networks.find((n) => n.addrs.has(c.ip as string)) : undefined);
    return {
      mac: String(c.mac ?? c.macAddress ?? ''),
      name: String(c.name || c.hostname || c.oui || c.mac || 'Unknown device'),
      ip: (c.ip as string) ?? (c.ipAddress as string) ?? null,
      network: net?.name ?? (c.network as string) ?? null,
      networkId: net?.id ?? null,
      vlan: vlan ?? net?.vlan ?? null,
      wired: c.is_wired === true || c.type === 'WIRED',
      guest: c.is_guest === true,
      rxBps: t.downBps,
      txBps: t.upBps,
      rxBytes: t.down,
      txBytes: t.up,
      rx24h: usage24h?.get(String(c.mac ?? c.macAddress ?? '').toLowerCase())?.rx ?? null,
      tx24h: usage24h?.get(String(c.mac ?? c.macAddress ?? '').toLowerCase())?.tx ?? null,
      signal: num(c.signal),
      uptime: num(c.uptime),
      oui: (c.oui as string) ?? null,
      essid: (c.essid as string) ?? null,
      firstSeen: num(c.first_seen) ? num(c.first_seen)! * 1000 : null,
    };
  });
  const loads = new Map<string, NetworkLoad>();
  for (const n of networks) loads.set(n.id, { id: n.id, name: n.name, vlan: n.vlan, clients: 0, rxBps: 0, txBps: 0 });
  for (const r of rows) {
    const l = r.networkId ? loads.get(r.networkId) : undefined;
    if (!l) continue;
    l.clients++;
    l.rxBps += r.rxBps;
    l.txBps += r.txBps;
  }
  return { t: Date.now(), clients: rows.sort((a, b) => b.rxBps + b.txBps - (a.rxBps + a.txBps)), networks: [...loads.values()] };
}

/** Live samples are kept this long (a little over the longest range offered). */
const KEEP_MS = 31 * 86400e3;
const HOUR = 3600e3;
const RANGE_MS: Record<LiveRange, number> = { '5m': 5 * 60e3, '30m': 30 * 60e3, '1h': HOUR, '24h': 24 * HOUR, '7d': 7 * 24 * HOUR, '30d': 30 * 24 * HOUR };
const SAMPLE_MS = 5_000;

type Num = number | null;
const n = (v: unknown): Num => (typeof v === 'number' && Number.isFinite(v) ? v : null);

/** Samples over a range, averaged into at most ~720 points, plus the range's peaks, averages and data used. */
export function liveTrend(db: Db, range: LiveRange, now = Date.now()): LiveTrend {
  const to = now;
  const from = now - RANGE_MS[range];
  const bucketMs = Math.max(SAMPLE_MS, Math.ceil((to - from) / 720 / SAMPLE_MS) * SAMPLE_MS);
  const rows = db
    .prepare(
      `SELECT (t / ?) * ? AS t, AVG(rx) AS rx, MAX(rx) AS rxMax, AVG(tx) AS tx, MAX(tx) AS txMax, AVG(latency) AS latency, AVG(clients) AS clients, AVG(cpu) AS cpu, AVG(mem) AS mem
       FROM live_samples WHERE t >= ? AND t <= ? GROUP BY t / ? ORDER BY 1`,
    )
    .all(bucketMs, bucketMs, from, to, bucketMs) as Record<string, unknown>[];
  const points = rows.map((r) => {
    const round = (v: Num) => (v === null ? null : Math.round(v * 10) / 10);
    return { t: Number(r.t), rxBps: round(n(r.rx)), txBps: round(n(r.tx)), latencyMs: round(n(r.latency)), clients: round(n(r.clients)), cpu: round(n(r.cpu)), mem: round(n(r.mem)), rxMax: n(r.rxMax), txMax: n(r.txMax) };
  });
  const agg = db
    .prepare('SELECT MIN(t) AS since, AVG(latency) AS avgLatency, MAX(latency) AS maxLatency, AVG(cpu) AS avgCpu, MAX(cpu) AS maxCpu, MAX(clients) AS maxClients FROM live_samples WHERE t >= ? AND t <= ?')
    .get(from, to) as Record<string, unknown>;
  const peak = (col: 'rx' | 'tx') => {
    const r = db.prepare(`SELECT t, ${col} AS v FROM live_samples WHERE t >= ? AND t <= ? AND ${col} IS NOT NULL ORDER BY ${col} DESC LIMIT 1`).get(from, to) as { t: number; v: number } | undefined;
    return r ? { bps: r.v, t: r.t } : null;
  };
  // Data used: each sample's rate over the time until the next one, but never across a gap (the app was down).
  const used = db
    .prepare(
      `SELECT COALESCE(SUM(rx * dt), 0) / 8000.0 AS rxBytes, COALESCE(SUM(tx * dt), 0) / 8000.0 AS txBytes FROM (
         SELECT rx, tx, MIN(COALESCE(LEAD(t) OVER (ORDER BY t), t) - t, 60000) AS dt FROM live_samples WHERE t >= ? AND t <= ?)`,
    )
    .get(from, to) as { rxBytes: number; txBytes: number };
  return {
    range,
    from,
    to,
    bucketMs,
    points,
    summary: {
      since: n(agg.since),
      peakRx: peak('rx'),
      peakTx: peak('tx'),
      rxBytes: Math.round(used.rxBytes),
      txBytes: Math.round(used.txBytes),
      avgLatency: n(agg.avgLatency),
      maxLatency: n(agg.maxLatency),
      avgCpu: n(agg.avgCpu),
      maxCpu: n(agg.maxCpu),
      maxClients: n(agg.maxClients),
    },
  };
}

export class LiveHub {
  private readonly clients = new Set<ServerResponse>();
  readonly samples: LiveSample[] = [];
  latest: LiveSnapshot | null = null;
  private keepAlive: NodeJS.Timeout;
  private readonly db: Db | null;
  private writes = 0;

  /** With a database, samples are kept for 31 days and the last hour is back right after a restart. */
  constructor(db: Db | null = null) {
    this.db = db;
    if (db) {
      const rows = db.prepare('SELECT t, rx, tx, latency, clients, cpu, mem FROM live_samples WHERE t >= ? ORDER BY t').all(Date.now() - HOUR) as Record<string, unknown>[];
      for (const r of rows.slice(-720)) this.samples.push({ t: Number(r.t), rxBps: n(r.rx), txBps: n(r.tx), latencyMs: n(r.latency), clients: n(r.clients), cpu: n(r.cpu), mem: n(r.mem) });
    }
    this.keepAlive = setInterval(() => {
      for (const c of this.clients) c.write(': ping\n\n');
    }, 20_000);
    this.keepAlive.unref();
  }

  add(res: ServerResponse): void {
    this.clients.add(res);
    res.on('close', () => this.clients.delete(res));
    if (this.latest) res.write(`data: ${JSON.stringify({ type: 'snapshot', data: this.latest, sample: sampleOf(this.latest) } satisfies LiveEvent)}\n\n`);
  }

  push(snapshot: LiveSnapshot): void {
    this.latest = snapshot;
    const s = sampleOf(snapshot);
    this.samples.push(s);
    if (this.samples.length > 720) this.samples.splice(0, this.samples.length - 720);
    if (this.db) {
      this.db.prepare('INSERT OR REPLACE INTO live_samples (t, rx, tx, latency, clients, cpu, mem) VALUES (?, ?, ?, ?, ?, ?, ?)').run(s.t, s.rxBps, s.txBps, s.latencyMs, s.clients, s.cpu, s.mem);
      // Trim old samples now and then rather than on every write.
      if (++this.writes % 500 === 1) this.db.prepare('DELETE FROM live_samples WHERE t < ?').run(Date.now() - KEEP_MS);
    }
    this.broadcast({ type: 'snapshot', data: snapshot, sample: s });
  }

  broadcast(ev: LiveEvent): void {
    const msg = `data: ${JSON.stringify(ev)}\n\n`;
    for (const c of this.clients) c.write(msg);
  }

  get size(): number {
    return this.clients.size;
  }
}
