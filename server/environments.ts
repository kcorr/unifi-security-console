// Environments: one UniFi site each, with its own connection, API key and write mode.
// API keys are encrypted at rest (AES-256-GCM).

import { createCipheriv, createDecipheriv, createHash, randomBytes, randomUUID } from 'node:crypto';
import type { CloudConsole, EnvInput, TlsPin, WriteMode } from '../shared/types.ts';
import type { Db } from './db.ts';
import { kvGet, kvSet } from './db.ts';

export interface EnvRecord {
  id: string;
  name: string;
  url: string;
  apiKey: string;
  site: string;
  verifyTls: boolean;
  color: string;
  writeMode: WriteMode;
  sort: number;
  createdAt: number;
  /** The trusted certificate of a self-signed console (see unifi/http.ts). */
  tlsPin: TlsPin | null;
}

export const ENV_COLORS = ['#22d3ee', '#a78bfa', '#34d399', '#f59e0b', '#f472b6', '#60a5fa', '#fb7185', '#a3e635'];

// Consoles reached through Ubiquiti's cloud (unifi.ui.com) use the Site Manager API's connector: requests to
// <CLOUD_API>/v1/connector/consoles/<id>/<path> are relayed to /proxy/<path> on that console.
export const CLOUD_API = 'https://api.ui.com';
const HOST_ID = /^[A-Za-z0-9:._-]+$/;
const CLOUD_CONSOLE = /^https:\/\/api\.ui\.com\/v1\/connector\/consoles\/[A-Za-z0-9:._-]+$/;

export function cloudConsoleUrl(hostId: string): string {
  // Host ids look like "70A7…:1261206302"; ':' is valid in a path segment, anything else unusual is refused.
  if (!HOST_ID.test(hostId)) throw new Error('Not a valid unifi.ui.com console id.');
  return `${CLOUD_API}/v1/connector/consoles/${hostId}`;
}

export function isCloudUrl(url: string): boolean {
  return CLOUD_CONSOLE.test(url.replace(/\/+$/, ''));
}

/** The consoles in a Site Manager GET /v1/hosts response. */
export function parseCloudHosts(data: Record<string, unknown>[]): CloudConsole[] {
  return data
    .filter((h) => typeof h.id === 'string' && HOST_ID.test(h.id) && h.isBlocked !== true)
    .map((h) => {
      const rs = (h.reportedState ?? {}) as Record<string, unknown>;
      const hw = (rs.hardware ?? {}) as Record<string, unknown>;
      const apps = ((h.userData ?? {}) as Record<string, unknown>).controllers;
      const state = typeof rs.state === 'string' ? rs.state.toLowerCase() : null;
      const text = (v: unknown) => (typeof v === 'string' && v ? v : null);
      return {
        id: String(h.id),
        url: cloudConsoleUrl(String(h.id)),
        name: text(rs.name) ?? text(rs.hostname) ?? text(hw.name) ?? text(h.ipAddress) ?? String(h.id),
        model: text(hw.name) ?? text(hw.shortname) ?? text(h.type),
        version: text(rs.version),
        online: state === null ? null : state === 'connected',
        owner: h.owner === true,
        hasNetwork: Array.isArray(apps) ? apps.includes('network') : null,
      };
    })
    .sort((a, b) => Number(b.hasNetwork === true) - Number(a.hasNetwork === true) || a.name.localeCompare(b.name));
}

interface Row {
  id: string;
  name: string;
  kind: string;
  url: string;
  api_key: string;
  site: string;
  verify_tls: number;
  color: string;
  write_mode: string;
  sort: number;
  created_at: number;
  tls_pin: string;
}

function parsePin(v: string): TlsPin | null {
  try {
    const p = v ? (JSON.parse(v) as TlsPin) : null;
    return p && typeof p.spki === 'string' && p.spki ? p : null;
  } catch {
    return null;
  }
}

export class EnvStore {
  private readonly db: Db;
  private readonly key: Buffer;

  constructor(db: Db) {
    this.db = db;
    // APP_SECRET (if set) keeps keys decryptable only with that secret; otherwise a random key
    // stored next to the data protects against casual reads of the database file.
    const secret = process.env.APP_SECRET;
    if (secret) this.key = createHash('sha256').update(secret).digest();
    else {
      let k = kvGet<string>(db, 'env-secret')?.value;
      if (!k) {
        k = randomBytes(32).toString('hex');
        kvSet(db, 'env-secret', k);
      }
      this.key = Buffer.from(k, 'hex');
    }
  }

  private encrypt(plain: string): string {
    if (!plain) return '';
    const iv = randomBytes(12);
    const c = createCipheriv('aes-256-gcm', this.key, iv);
    const ct = Buffer.concat([c.update(plain, 'utf8'), c.final()]);
    return `v1:${iv.toString('base64')}:${c.getAuthTag().toString('base64')}:${ct.toString('base64')}`;
  }

  private decrypt(stored: string): string {
    if (!stored) return '';
    const [v, iv, tag, ct] = stored.split(':');
    if (v !== 'v1') return '';
    try {
      const d = createDecipheriv('aes-256-gcm', this.key, Buffer.from(iv, 'base64'));
      d.setAuthTag(Buffer.from(tag, 'base64'));
      return Buffer.concat([d.update(Buffer.from(ct, 'base64')), d.final()]).toString('utf8');
    } catch {
      return '';
    }
  }

  private fromRow(r: Row): EnvRecord {
    return {
      id: r.id,
      name: r.name,
      url: r.url,
      apiKey: this.decrypt(r.api_key),
      site: r.site || 'default',
      verifyTls: !!r.verify_tls,
      color: r.color,
      writeMode: (['read-only', 'test-network', 'full'].includes(r.write_mode) ? r.write_mode : 'read-only') as WriteMode,
      sort: r.sort,
      createdAt: r.created_at,
      tlsPin: parsePin(r.tls_pin),
    };
  }

  list(): EnvRecord[] {
    return (this.db.prepare("SELECT * FROM environments WHERE kind = 'unifi' ORDER BY sort, created_at").all() as unknown as Row[]).map((r) => this.fromRow(r));
  }

  get(id: string): EnvRecord | null {
    const r = this.db.prepare("SELECT * FROM environments WHERE id = ? AND kind = 'unifi'").get(id) as unknown as Row | undefined;
    return r ? this.fromRow(r) : null;
  }

  /** Removes simulated environments that older versions created; returns their ids so their data can go too. */
  removeSimulated(): string[] {
    const ids = (this.db.prepare("SELECT id FROM environments WHERE kind <> 'unifi'").all() as { id: string }[]).map((r) => r.id);
    this.db.prepare("DELETE FROM environments WHERE kind <> 'unifi'").run();
    return ids;
  }

  create(input: EnvInput, tlsPin: TlsPin | null = null): EnvRecord {
    const all = this.list();
    const rec: EnvRecord = {
      id: randomUUID().slice(0, 8),
      name: (input.name ?? '').trim() || `Environment ${all.length + 1}`,
      url: (input.url ?? '').trim().replace(/\/+$/, ''),
      apiKey: (input.apiKey ?? '').trim(),
      site: (input.site ?? 'default').trim() || 'default',
      verifyTls: !!input.verifyTls,
      color: input.color || ENV_COLORS[all.length % ENV_COLORS.length],
      writeMode: input.writeMode ?? 'read-only',
      sort: all.length,
      createdAt: Date.now(),
      tlsPin,
    };
    this.db
      .prepare('INSERT INTO environments (id, name, kind, url, api_key, site, verify_tls, color, write_mode, sort, created_at, tls_pin) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
      .run(rec.id, rec.name, 'unifi', rec.url, this.encrypt(rec.apiKey), rec.site, rec.verifyTls ? 1 : 0, rec.color, rec.writeMode, rec.sort, rec.createdAt, tlsPin ? JSON.stringify(tlsPin) : '');
    return rec;
  }

  /** `tlsPin` undefined keeps the current pin; null clears it. */
  update(id: string, input: EnvInput, tlsPin?: TlsPin | null): EnvRecord {
    const cur = this.get(id);
    if (!cur) throw new Error('Environment not found');
    const next: EnvRecord = {
      ...cur,
      name: input.name !== undefined ? input.name.trim() || cur.name : cur.name,
      url: input.url !== undefined ? input.url.trim().replace(/\/+$/, '') : cur.url,
      apiKey: input.apiKey ? input.apiKey.trim() : cur.apiKey,
      site: input.site !== undefined ? input.site.trim() || 'default' : cur.site,
      verifyTls: input.verifyTls ?? cur.verifyTls,
      color: input.color ?? cur.color,
      writeMode: input.writeMode ?? cur.writeMode,
      tlsPin: tlsPin === undefined ? cur.tlsPin : tlsPin,
    };
    this.db
      .prepare('UPDATE environments SET name = ?, url = ?, api_key = ?, site = ?, verify_tls = ?, color = ?, write_mode = ?, tls_pin = ? WHERE id = ?')
      .run(next.name, next.url, this.encrypt(next.apiKey), next.site, next.verifyTls ? 1 : 0, next.color, next.writeMode, next.tlsPin ? JSON.stringify(next.tlsPin) : '', id);
    return next;
  }

  /** Saves the trusted certificate without touching anything else. */
  setPin(id: string, tlsPin: TlsPin | null): EnvRecord {
    this.db.prepare('UPDATE environments SET tls_pin = ? WHERE id = ?').run(tlsPin ? JSON.stringify(tlsPin) : '', id);
    const rec = this.get(id);
    if (!rec) throw new Error('Environment not found');
    return rec;
  }

  remove(id: string): void {
    this.db.prepare('DELETE FROM environments WHERE id = ?').run(id);
  }
}
