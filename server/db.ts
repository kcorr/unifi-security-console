// Local persistence (Node's built-in SQLite): settings, threat history, IP-intel cache,
// change log for undo, and user overrides such as network roles.

import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import path from 'node:path';

export type Db = DatabaseSync;

const MIGRATIONS: string[] = [
  `CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
   CREATE TABLE IF NOT EXISTS intel_cache (
     ip TEXT NOT NULL, provider TEXT NOT NULL, ok INTEGER NOT NULL, data TEXT, error TEXT, fetched_at INTEGER NOT NULL,
     PRIMARY KEY (ip, provider));
   CREATE TABLE IF NOT EXISTS threats (
     id TEXT PRIMARY KEY, ts INTEGER NOT NULL, severity TEXT NOT NULL, action TEXT NOT NULL, direction TEXT NOT NULL,
     category TEXT NOT NULL, signature TEXT NOT NULL, src_ip TEXT, dst_ip TEXT, remote_ip TEXT, local_ip TEXT, data TEXT NOT NULL);
   CREATE INDEX IF NOT EXISTS threats_ts ON threats (ts);
   CREATE INDEX IF NOT EXISTS threats_remote ON threats (remote_ip, ts);
   CREATE INDEX IF NOT EXISTS threats_local ON threats (local_ip, ts);
   CREATE TABLE IF NOT EXISTS changes (id TEXT PRIMARY KEY, ts INTEGER NOT NULL, data TEXT NOT NULL);
   CREATE TABLE IF NOT EXISTS network_roles (network_id TEXT PRIMARY KEY, role TEXT NOT NULL);
   CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL);`,
  `CREATE TABLE IF NOT EXISTS environments (
     id TEXT PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL, url TEXT NOT NULL DEFAULT '', api_key TEXT NOT NULL DEFAULT '',
     site TEXT NOT NULL DEFAULT 'default', verify_tls INTEGER NOT NULL DEFAULT 0, color TEXT NOT NULL, write_mode TEXT NOT NULL,
     sort INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL);`,
  `CREATE TABLE IF NOT EXISTS risk_acceptances (
     key TEXT PRIMARY KEY, kind TEXT NOT NULL, title TEXT NOT NULL, reason TEXT NOT NULL, accepted_at INTEGER NOT NULL);`,
  `ALTER TABLE environments ADD COLUMN tls_pin TEXT NOT NULL DEFAULT '';`,
  `CREATE TABLE IF NOT EXISTS live_samples (t INTEGER PRIMARY KEY, rx REAL, tx REAL, latency REAL, clients REAL, cpu REAL, mem REAL);`,
];

export function openDb(dataDir: string, name: string): Db {
  fs.mkdirSync(dataDir, { recursive: true });
  const db = new DatabaseSync(path.join(dataDir, name));
  db.exec('PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA foreign_keys = ON;');
  db.exec('CREATE TABLE IF NOT EXISTS schema_version (v INTEGER NOT NULL)');
  const row = db.prepare('SELECT v FROM schema_version').get() as { v: number } | undefined;
  let v = row?.v ?? 0;
  if (!row) db.prepare('INSERT INTO schema_version (v) VALUES (0)').run();
  while (v < MIGRATIONS.length) {
    db.exec(MIGRATIONS[v]);
    v++;
    db.prepare('UPDATE schema_version SET v = ?').run(v);
  }
  return db;
}

export function kvGet<T>(db: Db, key: string): { value: T; updatedAt: number } | null {
  const row = db.prepare('SELECT value, updated_at FROM kv WHERE key = ?').get(key) as { value: string; updated_at: number } | undefined;
  if (!row) return null;
  return { value: JSON.parse(row.value) as T, updatedAt: row.updated_at };
}

export function kvSet(db: Db, key: string, value: unknown): void {
  db.prepare('INSERT INTO kv (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at').run(
    key,
    JSON.stringify(value),
    Date.now(),
  );
}
