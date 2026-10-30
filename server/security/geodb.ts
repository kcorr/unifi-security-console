// Offline IP geolocation / ASN database: DB-IP "Lite" (CC BY 4.0, https://db-ip.com).
// Downloaded only when the user asks for it; afterwards every lookup is local, so investigated
// IPs are never sent anywhere for geolocation.

import fs from 'node:fs';
import path from 'node:path';
import { gunzipSync } from 'node:zlib';
import { Reader } from 'mmdb-lib';
import type { GeoDbStatus } from '../../shared/types.ts';

type Rec = Record<string, unknown>;

export interface GeoAsn {
  country: string | null;
  countryCode: string | null;
  region: string | null;
  city: string | null;
  lat: number | null;
  lon: number | null;
  asn: number | null;
  asOrg: string | null;
}

const UA = 'unifi-security-console/0.1 (+self-hosted)';

function monthStr(d: Date): string {
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}`;
}

export class GeoDb {
  private readonly dir: string;
  private geo: Reader<Rec> | null = null;
  private asn: Reader<Rec> | null = null;
  private meta: { edition: string; month: string; sizeBytes: number; downloadedAt: number } | null = null;
  private downloading = false;
  private lastError: string | null = null;

  constructor(dataDir: string) {
    this.dir = path.join(dataDir, 'geo');
    this.load();
  }

  private load(): void {
    try {
      const metaFile = path.join(this.dir, 'meta.json');
      if (!fs.existsSync(metaFile)) return;
      this.meta = JSON.parse(fs.readFileSync(metaFile, 'utf8'));
      this.geo = new Reader<Rec>(fs.readFileSync(path.join(this.dir, 'geo.mmdb')));
      const asnFile = path.join(this.dir, 'asn.mmdb');
      this.asn = fs.existsSync(asnFile) ? new Reader<Rec>(fs.readFileSync(asnFile)) : null;
    } catch (e) {
      this.geo = null;
      this.asn = null;
      this.lastError = `Could not load the geo database: ${(e as Error).message}`;
    }
  }

  status(): GeoDbStatus {
    return {
      installed: !!this.geo,
      edition: this.meta ? `DB-IP ${this.meta.edition} Lite (${this.meta.month})` : null,
      builtAt: this.meta?.month ?? null,
      sizeBytes: this.meta?.sizeBytes ?? null,
      downloading: this.downloading,
      error: this.lastError,
    };
  }

  get available(): boolean {
    return !!this.geo;
  }

  lookup(ip: string): GeoAsn | null {
    if (!this.geo) return null;
    try {
      const g = (this.geo.get(ip) ?? {}) as Rec;
      const a = (this.asn?.get(ip) ?? {}) as Rec;
      const en = (o: unknown) => ((o as Rec | undefined)?.names as Rec | undefined)?.en as string | undefined;
      const country = g.country as Rec | undefined;
      const loc = g.location as Rec | undefined;
      const sub = Array.isArray(g.subdivisions) ? (g.subdivisions as Rec[])[0] : undefined;
      if (!country && !a.autonomous_system_number) return null;
      return {
        country: en(country) ?? null,
        countryCode: (country?.iso_code as string) ?? null,
        region: en(sub) ?? null,
        city: en(g.city) ?? null,
        lat: typeof loc?.latitude === 'number' ? loc.latitude : null,
        lon: typeof loc?.longitude === 'number' ? loc.longitude : null,
        asn: typeof a.autonomous_system_number === 'number' ? a.autonomous_system_number : null,
        asOrg: (a.autonomous_system_organization as string) ?? null,
      };
    } catch {
      return null;
    }
  }

  /** Download the current monthly release (falls back to last month early in a month). */
  async download(edition: 'country' | 'city'): Promise<GeoDbStatus> {
    if (this.downloading) return this.status();
    this.downloading = true;
    this.lastError = null;
    try {
      fs.mkdirSync(this.dir, { recursive: true });
      const now = new Date();
      const months = [monthStr(now), monthStr(new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - 1, 1)))];
      let used: string | null = null;
      let geoBuf: Buffer | null = null;
      for (const m of months) {
        const res = await fetch(`https://download.db-ip.com/free/dbip-${edition}-lite-${m}.mmdb.gz`, { headers: { 'User-Agent': UA }, signal: AbortSignal.timeout(600_000) });
        if (res.status === 404) continue;
        if (!res.ok) throw new Error(`DB-IP download failed: HTTP ${res.status}`);
        geoBuf = gunzipSync(Buffer.from(await res.arrayBuffer()));
        used = m;
        break;
      }
      if (!geoBuf || !used) throw new Error('No DB-IP release found for this or last month.');
      const asnRes = await fetch(`https://download.db-ip.com/free/dbip-asn-lite-${used}.mmdb.gz`, { headers: { 'User-Agent': UA }, signal: AbortSignal.timeout(600_000) });
      const asnBuf = asnRes.ok ? gunzipSync(Buffer.from(await asnRes.arrayBuffer())) : null;
      // Validate before replacing the current files.
      new Reader<Rec>(geoBuf).get('8.8.8.8');
      if (asnBuf) new Reader<Rec>(asnBuf).get('8.8.8.8');
      fs.writeFileSync(path.join(this.dir, 'geo.mmdb'), geoBuf);
      if (asnBuf) fs.writeFileSync(path.join(this.dir, 'asn.mmdb'), asnBuf);
      fs.writeFileSync(path.join(this.dir, 'meta.json'), JSON.stringify({ edition: edition === 'city' ? 'City' : 'Country', month: used, sizeBytes: geoBuf.length + (asnBuf?.length ?? 0), downloadedAt: Date.now() }));
      this.load();
    } catch (e) {
      this.lastError = (e as Error).message;
    } finally {
      this.downloading = false;
    }
    return this.status();
  }

  remove(): GeoDbStatus {
    for (const f of ['geo.mmdb', 'asn.mmdb', 'meta.json']) fs.rmSync(path.join(this.dir, f), { force: true });
    this.geo = null;
    this.asn = null;
    this.meta = null;
    return this.status();
  }
}
