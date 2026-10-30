// Which host names may address the dashboard.
//
// The check stops DNS rebinding: a hostile web page that points its own domain at this server so the visitor's
// browser talks to the dashboard. Such requests always carry the attacker's domain name, so names that can't be
// registered in public DNS are safe to accept with no setup at all: IP addresses (http://192.168.1.20:8787),
// single-word names (http://dockerhost:8787) and private-use suffixes (.lan, .local, .home.arpa, .internal...).
// Any other name, such as a domain behind a reverse proxy, has to be listed in ALLOWED_HOSTS; "*" turns the check off.

import { isIP } from 'node:net';

const PRIVATE_SUFFIXES = ['.localhost', '.local', '.localdomain', '.lan', '.home', '.home.arpa', '.internal', '.corp'];

export function parseAllowedHosts(value: string | undefined): Set<string> {
  return new Set((value ?? '').split(',').map((h) => h.trim().toLowerCase().replace(/\.$/, '')).filter(Boolean));
}

/** The name in a Host header, without its port, IPv6 brackets or a trailing dot. */
export function hostName(header: string | undefined): string {
  const h = (header ?? '').trim().toLowerCase();
  const v6 = /^\[([^\]]+)\](:\d+)?$/.exec(h);
  if (v6) return v6[1];
  return h.replace(/:\d+$/, '').replace(/\.$/, '');
}

export function hostAllowed(header: string | undefined, allowed: Set<string>): boolean {
  if (allowed.has('*')) return true;
  const name = hostName(header);
  if (!name) return false;
  if (allowed.has(name) || isIP(name)) return true;
  if (!name.includes('.')) return true;
  return PRIVATE_SUFFIXES.some((s) => name.endsWith(s));
}
