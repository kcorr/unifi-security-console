// Offline register of who made a network device, from the first half of its MAC address: the IEEE registry
// (MA-L, MA-M and MA-S blocks). Downloaded only when the owner asks for it; afterwards every lookup is local, so no
// device address is ever sent anywhere to identify it.

import fs from 'node:fs';
import path from 'node:path';
import type { MakerDbStatus } from '../../shared/types.ts';

const UA = 'unifi-security-console/0.1 (+self-hosted)';
const SOURCES = ['https://standards-oui.ieee.org/oui/oui.csv', 'https://standards-oui.ieee.org/oui28/mam.csv', 'https://standards-oui.ieee.org/oui36/oui36.csv'];

/** Fields of one CSV line, honouring quotes ("a, b" and doubled "" inside them). */
export function csvFields(line: string): string[] {
  const out: string[] = [];
  let cur = '';
  let quoted = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (quoted) {
      if (ch === '"' && line[i + 1] === '"') {
        cur += '"';
        i++;
      } else if (ch === '"') quoted = false;
      else cur += ch;
    } else if (ch === '"') quoted = true;
    else if (ch === ',') {
      out.push(cur);
      cur = '';
    } else cur += ch;
  }
  out.push(cur);
  return out;
}

/** Prefix (hex, upper case) → organisation, from the registry CSVs. */
export function parseRegistry(csv: string, into: Record<string, string> = {}): Record<string, string> {
  for (const line of csv.split(/\r?\n/).slice(1)) {
    const [, assignment, org] = csvFields(line);
    if (assignment && org && /^[0-9A-F]{6,9}$/i.test(assignment)) into[assignment.toUpperCase()] = org.trim();
  }
  return into;
}

/** The maker of a MAC address: the most specific block wins (36-bit, then 28-bit, then 24-bit prefixes). */
export function makerOf(entries: Record<string, string>, mac: string): string | null {
  const hex = mac.replace(/[^0-9a-f]/gi, '').toUpperCase();
  if (hex.length < 6) return null;
  return entries[hex.slice(0, 9)] ?? entries[hex.slice(0, 7)] ?? entries[hex.slice(0, 6)] ?? null;
}

export class MakerDb {
  private readonly file: string;
  private entries: Record<string, string> | null = null;
  private meta: { downloadedAt: number; count: number } | null = null;
  private downloading = false;
  private lastError: string | null = null;

  constructor(dataDir: string) {
    this.file = path.join(dataDir, 'makers.json');
    try {
      const j = JSON.parse(fs.readFileSync(this.file, 'utf8')) as { downloadedAt: number; entries: Record<string, string> };
      this.entries = j.entries;
      this.meta = { downloadedAt: j.downloadedAt, count: Object.keys(j.entries).length };
    } catch {
      // Not downloaded yet.
    }
  }

  lookup(mac: string): string | null {
    return this.entries ? makerOf(this.entries, mac) : null;
  }

  status(): MakerDbStatus {
    return { installed: !!this.entries, entries: this.meta?.count ?? null, downloadedAt: this.meta?.downloadedAt ?? null, downloading: this.downloading, error: this.lastError };
  }

  async download(): Promise<MakerDbStatus> {
    if (this.downloading) return this.status();
    this.downloading = true;
    this.lastError = null;
    try {
      const entries: Record<string, string> = {};
      for (const url of SOURCES) {
        const res = await fetch(url, { headers: { 'User-Agent': UA }, signal: AbortSignal.timeout(120_000) });
        if (!res.ok) throw new Error(`IEEE registry download failed: HTTP ${res.status} for ${url}`);
        parseRegistry(await res.text(), entries);
      }
      // A truncated download must never replace a good register.
      if (Object.keys(entries).length < 10_000) throw new Error('The IEEE registry looked incomplete; kept the previous copy.');
      fs.mkdirSync(path.dirname(this.file), { recursive: true });
      const downloadedAt = Date.now();
      fs.writeFileSync(this.file, JSON.stringify({ downloadedAt, entries }));
      this.entries = entries;
      this.meta = { downloadedAt, count: Object.keys(entries).length };
    } catch (e) {
      this.lastError = (e as Error).message;
    } finally {
      this.downloading = false;
    }
    return this.status();
  }

  remove(): MakerDbStatus {
    fs.rmSync(this.file, { force: true });
    this.entries = null;
    this.meta = null;
    return this.status();
  }
}
