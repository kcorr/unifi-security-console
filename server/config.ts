// Configuration. Global settings (IP intelligence, retention) come from environment
// variables and can be changed on the Settings page (stored in the app database, which wins).
// Controller connections live on environments (see environments.ts); the UNIFI_* variables only
// seed the first environment.

import type { GeoDbStatus, IntelProviderSettings, SettingsUpdate, SettingsView, WriteMode } from '../shared/types.ts';
import type { Db } from './db.ts';

export interface Config {
  intel: IntelProviderSettings;
  abuseipdbKey: string;
  greynoiseKey: string;
  threatRetentionDays: number;
}

export interface SeedConfig {
  unifiUrl: string;
  apiKey: string;
  site: string;
  verifyTls: boolean;
  writeMode: WriteMode;
}

export const APP_PORT = Number(process.env.PORT ?? 8787);
export const DATA_DIR = process.env.DATA_DIR ?? './data';
// Create the sign-in account at startup instead of on the first visit (used once, while there is no account).
export const APP_USERNAME = process.env.APP_USERNAME ?? '';
export const APP_PASSWORD = process.env.APP_PASSWORD ?? '';

function envBool(name: string, def: boolean): boolean {
  const v = process.env[name];
  if (v === undefined || v === '') return def;
  return /^(1|true|yes|on)$/i.test(v.trim());
}

function envWriteMode(): WriteMode {
  const v = (process.env.WRITE_MODE ?? '').trim().toLowerCase();
  if (v === 'full' || v === 'test-network' || v === 'read-only') return v;
  // Safe default: a real controller is read-only until you choose otherwise.
  return 'read-only';
}

/** Connection seed for the first environment: env vars, overridden by pre-environment saved settings. */
export function seedConfig(db: Db): SeedConfig {
  const seed: SeedConfig = {
    unifiUrl: (process.env.UNIFI_URL ?? '').trim().replace(/\/+$/, ''),
    apiKey: (process.env.UNIFI_API_KEY ?? '').trim(),
    site: (process.env.UNIFI_SITE ?? 'default').trim() || 'default',
    verifyTls: envBool('UNIFI_VERIFY_TLS', false),
    writeMode: envWriteMode(),
  };
  const legacy: Record<string, keyof SeedConfig> = { unifiUrl: 'unifiUrl', apiKey: 'apiKey', unifiSite: 'site', verifyTls: 'verifyTls', writeMode: 'writeMode' };
  const rows = db.prepare('SELECT key, value FROM settings').all() as { key: string; value: string }[];
  const target = seed as unknown as Record<string, unknown>;
  for (const { key, value } of rows) if (legacy[key]) target[legacy[key]] = JSON.parse(value);
  return seed;
}

function envConfig(): Config {
  return {
    intel: {
      rdap: envBool('INTEL_RDAP', true),
      tor: envBool('INTEL_TOR_LIST', true),
      ipapi: envBool('INTEL_IPAPI', false),
      internetdb: envBool('INTEL_INTERNETDB', false),
    },
    abuseipdbKey: (process.env.ABUSEIPDB_API_KEY ?? '').trim(),
    greynoiseKey: (process.env.GREYNOISE_API_KEY ?? '').trim(),
    threatRetentionDays: Math.max(1, Number(process.env.THREAT_RETENTION_DAYS ?? 30) || 30),
  };
}

const KEYS: (keyof SettingsUpdate)[] = ['intel', 'abuseipdbKey', 'greynoiseKey', 'threatRetentionDays'];

export function loadConfig(db: Db): Config {
  const cfg = envConfig();
  const rows = db.prepare('SELECT key, value FROM settings').all() as { key: string; value: string }[];
  const target = cfg as unknown as Record<string, unknown>;
  for (const { key, value } of rows) {
    if (!(key in cfg)) continue;
    const v = JSON.parse(value);
    target[key] = key === 'intel' ? { ...cfg.intel, ...v } : v;
  }
  return cfg;
}

export function saveSettings(db: Db, update: SettingsUpdate): void {
  const stmt = db.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value');
  for (const key of KEYS) {
    let value: unknown = update[key];
    if (value === undefined) continue;
    if (typeof value === 'string') value = value.trim();
    if (key === 'threatRetentionDays') value = Math.max(1, Math.min(365, Number(value) || 30));
    if (key === 'intel') {
      const current = db.prepare("SELECT value FROM settings WHERE key = 'intel'").get() as { value: string } | undefined;
      value = { ...(current ? JSON.parse(current.value) : {}), ...(value as object) };
    }
    stmt.run(key, JSON.stringify(value));
  }
}

export function keyHint(secret: string): string | null {
  if (!secret) return null;
  return secret.length <= 8 ? '••••' : `${secret.slice(0, 4)}…${secret.slice(-4)}`;
}

export function settingsView(cfg: Config, geoDb: GeoDbStatus): SettingsView {
  return {
    intel: cfg.intel,
    abuseipdbKeySet: !!cfg.abuseipdbKey,
    greynoiseKeySet: !!cfg.greynoiseKey,
    threatRetentionDays: cfg.threatRetentionDays,
    geoDb,
  };
}
