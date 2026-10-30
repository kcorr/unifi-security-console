// Threat history in SQLite + aggregations for the Threats page.

import type { Severity, ThreatDirection, ThreatEvent, ThreatQuery, ThreatSummary, IpIntel } from '../../shared/types.ts';
import { SEVERITIES } from '../../shared/types.ts';
import type { Db } from '../db.ts';
import { THREAT_CATEGORIES, maxSeverity, sevRank } from './threatKb.ts';

type SqlValue = string | number | null;

function where(q: ThreatQuery): { sql: string; args: SqlValue[] } {
  const parts: string[] = [];
  const args: SqlValue[] = [];
  if (q.from) {
    parts.push('ts >= ?');
    args.push(q.from);
  }
  if (q.to) {
    parts.push('ts <= ?');
    args.push(q.to);
  }
  const inList = (col: string, vals?: string[]) => {
    if (!vals?.length) return;
    parts.push(`${col} IN (${vals.map(() => '?').join(',')})`);
    args.push(...vals);
  };
  inList('severity', q.severity);
  inList('direction', q.direction);
  inList('action', q.action);
  inList('category', q.category);
  if (q.ip) {
    parts.push('(src_ip = ? OR dst_ip = ?)');
    args.push(q.ip, q.ip);
  }
  if (q.q) {
    parts.push('(signature LIKE ? OR src_ip LIKE ? OR dst_ip LIKE ? OR data LIKE ?)');
    const like = `%${q.q}%`;
    args.push(like, like, like, like);
  }
  return { sql: parts.length ? `WHERE ${parts.join(' AND ')}` : '', args };
}

function bucketFor(rangeMs: number): number {
  const h = 3600e3;
  if (rangeMs <= 2 * h) return 5 * 60e3;
  if (rangeMs <= 12 * h) return 15 * 60e3;
  if (rangeMs <= 2 * 24 * h) return h;
  if (rangeMs <= 8 * 24 * h) return 6 * h;
  return 24 * h;
}

export class ThreatStore {
  private readonly db: Db;

  constructor(db: Db) {
    this.db = db;
  }

  /** Insert new events; returns those that were not already stored. */
  upsert(events: ThreatEvent[]): ThreatEvent[] {
    if (!events.length) return [];
    const ins = this.db.prepare(
      `INSERT OR IGNORE INTO threats (id, ts, severity, action, direction, category, signature, src_ip, dst_ip, remote_ip, local_ip, data)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    );
    const fresh: ThreatEvent[] = [];
    this.db.exec('BEGIN');
    try {
      for (const e of events) {
        const r = ins.run(e.id, e.ts, e.severity, e.action, e.direction, e.categoryKey, e.signature, e.srcIp, e.dstIp, e.remoteIp, e.localIp, JSON.stringify(e));
        if (Number(r.changes) > 0) fresh.push(e);
      }
      this.db.exec('COMMIT');
    } catch (err) {
      this.db.exec('ROLLBACK');
      throw err;
    }
    return fresh;
  }

  latestTs(): number | null {
    const r = this.db.prepare('SELECT MAX(ts) AS m FROM threats').get() as { m: number | null };
    return r.m ?? null;
  }

  prune(retentionDays: number): number {
    const r = this.db.prepare('DELETE FROM threats WHERE ts < ?').run(Date.now() - retentionDays * 86400e3);
    return Number(r.changes);
  }

  clear(): void {
    this.db.exec('DELETE FROM threats');
  }

  query(q: ThreatQuery): { total: number; events: ThreatEvent[] } {
    const w = where(q);
    const total = (this.db.prepare(`SELECT COUNT(*) AS c FROM threats ${w.sql}`).get(...w.args) as { c: number }).c;
    const limit = Math.min(Math.max(q.limit ?? 100, 1), 1000);
    const offset = Math.max(q.offset ?? 0, 0);
    const rows = this.db.prepare(`SELECT data FROM threats ${w.sql} ORDER BY ts DESC LIMIT ? OFFSET ?`).all(...w.args, limit, offset) as { data: string }[];
    return { total, events: rows.map((r) => JSON.parse(r.data) as ThreatEvent) };
  }

  get(id: string): ThreatEvent | null {
    const r = this.db.prepare('SELECT data FROM threats WHERE id = ?').get(id) as { data: string } | undefined;
    return r ? (JSON.parse(r.data) as ThreatEvent) : null;
  }

  counts(sinceTs: number): { total: number; blocked: number } {
    const r = this.db.prepare(`SELECT COUNT(*) AS c, SUM(CASE WHEN action = 'blocked' THEN 1 ELSE 0 END) AS b FROM threats WHERE ts >= ?`).get(sinceTs) as { c: number; b: number | null };
    return { total: r.c, blocked: r.b ?? 0 };
  }

  private rows(q: ThreatQuery, cap = 50000): ThreatEvent[] {
    const w = where(q);
    return (this.db.prepare(`SELECT data FROM threats ${w.sql} ORDER BY ts DESC LIMIT ?`).all(...w.args, cap) as { data: string }[]).map((r) => JSON.parse(r.data) as ThreatEvent);
  }

  summary(q: ThreatQuery): ThreatSummary {
    const to = q.to ?? Date.now();
    const from = q.from ?? to - 24 * 3600e3;
    const events = this.rows({ ...q, from, to });
    const bucketMs = bucketFor(to - from);
    const start = Math.floor(from / bucketMs) * bucketMs;
    const nBuckets = Math.min(400, Math.ceil((to - start) / bucketMs));
    const timeline: ThreatSummary['timeline'] = Array.from({ length: nBuckets }, (_, i) => ({ t: start + i * bucketMs, total: 0, blocked: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 }));

    const bySeverity = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
    const byDirection: Record<ThreatDirection, number> = { inbound: 0, outbound: 0, internal: 0, unknown: 0 };
    const cats = new Map<string, { count: number; blocked: number; severity: Severity }>();
    const sigs = new Map<string, ThreatSummary['topSignatures'][number]>();
    const srcs = new Map<string, ThreatSummary['topSources'][number] & { cats: Set<string> }>();
    const targets = new Map<string, ThreatSummary['topTargets'][number]>();
    const countries = new Map<string, number>();
    const suspects = new Map<string, ThreatSummary['suspects'][number] & { cats: Set<string> }>();
    let blocked = 0;
    let alerted = 0;

    for (const e of events) {
      const n = e.count || 1;
      bySeverity[e.severity] += n;
      byDirection[e.direction] += n;
      if (e.action === 'blocked') blocked += n;
      else if (e.action === 'alerted') alerted += n;

      const bi = Math.floor((e.ts - start) / bucketMs);
      const b = timeline[bi];
      if (b) {
        b.total += n;
        b[e.severity] += n;
        if (e.action === 'blocked') b.blocked += n;
      }

      const c = cats.get(e.categoryKey) ?? { count: 0, blocked: 0, severity: 'info' as Severity };
      c.count += n;
      if (e.action === 'blocked') c.blocked += n;
      c.severity = maxSeverity(c.severity, e.severity);
      cats.set(e.categoryKey, c);

      const s = sigs.get(e.signature) ?? { signature: e.signature, headline: e.headline, categoryKey: e.categoryKey, count: 0, severity: e.severity, lastSeen: e.ts, blocked: 0 };
      s.count += n;
      if (e.action === 'blocked') s.blocked += n;
      s.severity = maxSeverity(s.severity, e.severity);
      s.lastSeen = Math.max(s.lastSeen, e.ts);
      sigs.set(e.signature, s);

      const actor = e.direction === 'inbound' ? e.remoteIp ?? e.srcIp : e.srcIp;
      if (actor) {
        const a = srcs.get(actor) ?? { ip: actor, count: 0, country: e.direction === 'inbound' ? e.remoteCountry : null, org: e.direction === 'inbound' ? e.remoteOrg : null, lastSeen: e.ts, severity: e.severity, blocked: 0, categories: [], direction: e.direction, cats: new Set<string>() };
        a.count += n;
        if (e.action === 'blocked') a.blocked += n;
        a.severity = maxSeverity(a.severity, e.severity);
        a.lastSeen = Math.max(a.lastSeen, e.ts);
        a.cats.add(e.categoryKey);
        srcs.set(actor, a);
      }

      if (e.local && e.direction === 'inbound') {
        const t = targets.get(e.local.ip) ?? { ip: e.local.ip, name: e.local.name, network: e.local.network, count: 0, severity: e.severity };
        t.count += n;
        t.severity = maxSeverity(t.severity, e.severity);
        targets.set(e.local.ip, t);
      }

      if (e.remoteCountry) countries.set(e.remoteCountry, (countries.get(e.remoteCountry) ?? 0) + n);

      // Internal devices behaving badly (outbound / lateral malicious categories).
      const fam = THREAT_CATEGORIES[e.categoryKey]?.family ?? 'other';
      if ((e.direction === 'outbound' || e.direction === 'internal') && e.local && !['policy', 'info', 'protocol', 'other'].includes(fam) && sevRank(e.severity) >= sevRank('medium')) {
        const sp = suspects.get(e.local.ip) ?? { ip: e.local.ip, name: e.local.name, network: e.local.network, count: 0, categories: [], severity: e.severity, lastSeen: e.ts, cats: new Set<string>() };
        sp.count += n;
        sp.cats.add(e.categoryKey);
        sp.severity = maxSeverity(sp.severity, e.severity);
        sp.lastSeen = Math.max(sp.lastSeen, e.ts);
        suspects.set(e.local.ip, sp);
      }
    }

    const sortCount = <T extends { count: number }>(xs: T[]) => xs.sort((a, b) => b.count - a.count);
    return {
      range: { from, to },
      total: events.reduce((acc, e) => acc + (e.count || 1), 0),
      blocked,
      alerted,
      uniqueSources: srcs.size,
      bySeverity,
      byDirection,
      byCategory: sortCount(
        [...cats.entries()].map(([key, v]) => ({ key, name: THREAT_CATEGORIES[key]?.name ?? key, family: THREAT_CATEGORIES[key]?.family ?? 'other', count: v.count, blocked: v.blocked, severity: v.severity })),
      ),
      topSignatures: sortCount([...sigs.values()]).slice(0, 25),
      topSources: sortCount([...srcs.values()])
        .slice(0, 50)
        .map(({ cats: cs, ...rest }) => ({ ...rest, categories: [...cs] })),
      topTargets: sortCount([...targets.values()]).slice(0, 25),
      byCountry: [...countries.entries()].map(([country, count]) => ({ country, count })).sort((a, b) => b.count - a.count),
      timeline,
      bucketMs,
      suspects: sortCount([...suspects.values()]).map(({ cats: cs, ...rest }) => ({ ...rest, categories: [...cs] })),
    };
  }

  activityFor(ip: string): IpIntel['activity'] {
    const events = this.rows({ ip }, 5000);
    const directions: Record<ThreatDirection, number> = { inbound: 0, outbound: 0, internal: 0, unknown: 0 };
    const sigs = new Map<string, IpIntel['activity']['signatures'][number]>();
    const peers = new Map<string, { ip: string; name: string | null; count: number }>();
    let blocked = 0;
    let total = 0;
    for (const e of events) {
      const n = e.count || 1;
      total += n;
      directions[e.direction] += n;
      if (e.action === 'blocked') blocked += n;
      const s = sigs.get(e.signature) ?? { signature: e.signature, headline: e.headline, categoryKey: e.categoryKey, count: 0, severity: e.severity };
      s.count += n;
      s.severity = maxSeverity(s.severity, e.severity);
      sigs.set(e.signature, s);
      const peerIp = e.srcIp === ip ? e.dstIp : e.srcIp;
      const peerName = e.local && e.local.ip === peerIp ? e.local.name : null;
      const p = peers.get(peerIp) ?? { ip: peerIp, name: peerName, count: 0 };
      p.count += n;
      peers.set(peerIp, p);
    }
    return {
      events: total,
      blocked,
      firstSeen: events.length ? events[events.length - 1].ts : null,
      lastSeen: events.length ? events[0].ts : null,
      directions,
      signatures: [...sigs.values()].sort((a, b) => sevRank(b.severity) - sevRank(a.severity) || b.count - a.count).slice(0, 20),
      peers: [...peers.values()].sort((a, b) => b.count - a.count).slice(0, 20),
      recent: events.slice(0, 25),
    };
  }
}
