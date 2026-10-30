// HTTP server: JSON API, live event stream and the web UI.
// Data endpoints take ?env=<environment id> (default: the first environment).

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Fastify, { type FastifyReply, type FastifyRequest } from 'fastify';
import fastifyStatic from '@fastify/static';
import type { EnvInput, NetworkRole, Severity, SettingsUpdate, ThreatDirection, ThreatQuery } from '../shared/types.ts';
import { APP_PASSWORD, APP_PORT, APP_USERNAME, settingsView } from './config.ts';
import { Auth, LoginThrottle } from './auth.ts';
import { hostAllowed, hostName, parseAllowedHosts } from './hosts.ts';
import { HttpError } from './errors.ts';
import { LIVE_RANGES, type LiveRange } from '../shared/types.ts';
import { AppService } from './service.ts';
import { parseIp } from './security/sets.ts';
import { getTemplate } from './security/hardening/templates.ts';

const here = path.dirname(fileURLToPath(import.meta.url));
const webDist = path.resolve(here, '../web/dist');

const service = new AppService();
const auth = new Auth(service.settingsDb);
const app = Fastify({ logger: { level: process.env.LOG_LEVEL ?? 'info' }, bodyLimit: 1024 * 1024 });
const seeded = await auth.seed(APP_USERNAME, APP_PASSWORD);
if (seeded) app.log.info(seeded);

// Everything else needs a signed-in session, and before the account exists nobody has one.
const OPEN_ROUTES = new Set(['/api/health', '/api/status', '/api/setup', '/api/login', '/api/logout']);

// IP addresses and local names always work; public-looking names must be listed (see hosts.ts).
const ALLOWED_HOSTS = parseAllowedHosts(process.env.ALLOWED_HOSTS);

app.addHook('onRequest', async (req, reply) => {
  if (!hostAllowed(req.headers.host, ALLOWED_HOSTS)) {
    const name = hostName(req.headers.host) || 'none';
    return reply
      .code(403)
      .type('text/plain')
      .send(`The name "${name}" is not allowed, to protect against DNS rebinding. Open the dashboard by its IP address or a local name instead, or add "${name}" to ALLOWED_HOSTS.`);
  }
  // Decide on the route that actually matched, not on the raw URL: the router decodes "%61pi" and ignores an
  // absolute-form host, so checking the URL text could be walked around.
  const route = req.routeOptions.url;
  if (!route?.startsWith('/api/')) return;
  if (req.method !== 'GET' && req.method !== 'HEAD' && req.headers['x-requested-with'] !== 'usc') {
    return reply.code(403).send({ error: 'Missing X-Requested-With header' });
  }
  if (OPEN_ROUTES.has(route)) return;
  if (!auth.verify(auth.tokenFrom(req.headers.cookie))) return reply.code(401).send({ error: 'Login required' });
});

app.addHook('onSend', async (_req, reply, payload) => {
  // The UI loads nothing from other origins; inline style attributes come from React.
  reply.header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
  reply.header('X-Content-Type-Options', 'nosniff');
  reply.header('X-Frame-Options', 'DENY');
  reply.header('Referrer-Policy', 'no-referrer');
  return payload;
});

app.setErrorHandler((err: unknown, _req, reply) => {
  const status = err instanceof HttpError ? err.status : ((err as { statusCode?: number }).statusCode ?? 500);
  // 503 means "still connecting" or "controller unreachable": expected, and already shown in the UI.
  if (status >= 500 && status !== 503) app.log.error(err);
  reply.code(status).send({ error: err instanceof Error ? err.message : String(err) });
});

const list = <T extends string>(v: unknown): T[] | undefined => (typeof v === 'string' && v ? (v.split(',') as T[]) : undefined);
const num = (v: unknown): number | undefined => (v === undefined || v === '' ? undefined : Number.isFinite(Number(v)) ? Number(v) : undefined);
/** A whole number clamped to [min, max], or undefined when absent or not a number. */
const int = (v: unknown, min: number, max: number): number | undefined => {
  const n = num(v);
  return n === undefined ? undefined : Math.min(max, Math.max(min, Math.floor(n)));
};
const envOf = (req: FastifyRequest): string | null => {
  const q = req.query as { env?: unknown };
  if (!('env' in q)) return null;
  // Present but not a single non-empty id (repeated, empty…): never fall back to another environment.
  if (typeof q.env !== 'string' || !q.env) throw new HttpError(404, 'That environment no longer exists — pick another one.');
  return q.env;
};
const rt = (req: FastifyRequest) => service.rt(envOf(req));

function threatQuery(q: Record<string, unknown>): ThreatQuery {
  return {
    from: num(q.from),
    to: num(q.to),
    severity: list<Severity>(q.severity),
    direction: list<ThreatDirection>(q.direction),
    action: list<'blocked' | 'alerted' | 'unknown'>(q.action),
    category: list<string>(q.category),
    ip: typeof q.ip === 'string' && q.ip ? q.ip : undefined,
    q: typeof q.q === 'string' && q.q ? q.q : undefined,
    limit: int(q.limit, 1, 1000),
    offset: int(q.offset, 0, 1_000_000),
  };
}

// ---------------------------------------------------------------------------------
// Auth, status, settings
// ---------------------------------------------------------------------------------

app.get('/api/health', async () => ({ ok: true }));

app.get('/api/status', async (req) => {
  // Before signing in, say only that a sign-in (or creating the account) is needed: no environments, addresses or key hints.
  if (!auth.verify(auth.tokenFrom(req.headers.cookie))) return { authRequired: true, authenticated: false, setupRequired: !auth.hasAccount };
  return { ...service.status(envOf(req), true, true), username: auth.username };
});

const throttle = new LoginThrottle();
const strings = (body: unknown) => (body && typeof body === 'object' ? (body as Record<string, unknown>) : {});
const text = (v: unknown) => (typeof v === 'string' ? v : '');

/** Refuses while too many wrong passwords came from this address. */
function throttled(req: FastifyRequest, reply: FastifyReply): void {
  const wait = throttle.retryAfter(req.ip);
  if (!wait) return;
  reply.header('Retry-After', String(wait));
  throw new HttpError(429, `Too many wrong passwords. Try again in ${Math.ceil(wait / 60)} minute${wait > 60 ? 's' : ''}.`);
}

async function wrongPassword(req: FastifyRequest): Promise<void> {
  throttle.fail(req.ip);
  await new Promise((r) => setTimeout(r, 600));
}

// The first visit creates the account (refused once it exists) and signs in with it.
app.post('/api/setup', async (req, reply) => {
  const b = strings(req.body);
  await auth.create(text(b.username), text(b.password));
  app.log.info('The sign-in account was created');
  reply.header('Set-Cookie', auth.cookie(auth.issue()));
  return { ok: true };
});

app.post('/api/login', async (req, reply) => {
  const b = strings(req.body);
  throttled(req, reply);
  if (!(await auth.check(text(b.username), text(b.password)))) {
    await wrongPassword(req);
    throw new HttpError(401, 'Wrong username or password.');
  }
  throttle.succeed(req.ip);
  reply.header('Set-Cookie', auth.cookie(auth.issue()));
  return { ok: true };
});

// Changing the username or the password needs the current password, and ends every other session.
app.put('/api/account', async (req, reply) => {
  const b = strings(req.body);
  throttled(req, reply);
  try {
    await auth.update(text(b.currentPassword), { username: typeof b.username === 'string' ? b.username : undefined, password: text(b.newPassword) || undefined });
  } catch (e) {
    if (e instanceof HttpError && e.status === 403) await wrongPassword(req);
    throw e;
  }
  throttle.succeed(req.ip);
  reply.header('Set-Cookie', auth.cookie(auth.issue()));
  return { ok: true, username: auth.username };
});

app.post('/api/logout', async (_req, reply) => {
  auth.revokeAll();
  reply.header('Set-Cookie', auth.clearCookie());
  return { ok: true };
});

app.get('/api/settings', async () => settingsView(service.cfg, service.geoDbStatus()));

app.put('/api/settings', async (req) => {
  service.saveSettings((req.body ?? {}) as SettingsUpdate);
  return settingsView(service.cfg, service.geoDbStatus());
});

// Offline geolocation database: downloaded only on explicit request.
app.post('/api/intel/geodb', async (req) => {
  const { edition } = (req.body ?? {}) as { edition?: string };
  return service.downloadGeoDb(edition === 'city' ? 'city' : 'country');
});
app.delete('/api/intel/geodb', async () => service.removeGeoDb());

// ---------------------------------------------------------------------------------
// Environments
// ---------------------------------------------------------------------------------

app.get('/api/environments', async () => service.environments());
app.post('/api/environments', async (req) => service.addEnv((req.body ?? {}) as EnvInput));
app.post('/api/environments/test', async (req) => service.testEnv((req.body ?? {}) as EnvInput & { id?: string }));
app.post('/api/environments/:id/trust-cert', async (req) => {
  const spki = (req.body as { spki?: unknown } | null)?.spki;
  if (typeof spki !== 'string' || !/^[A-Za-z0-9+/=]{20,100}$/.test(spki)) throw new HttpError(400, 'Missing certificate key.');
  return service.trustCert((req.params as { id: string }).id, spki);
});

app.post('/api/environments/cloud-consoles', async (req) => service.cloudConsoles((req.body ?? {}) as { apiKey?: unknown; id?: unknown }));
app.put('/api/environments/:id', async (req) => service.updateEnv((req.params as { id: string }).id, (req.body ?? {}) as EnvInput));
app.delete('/api/environments/:id', async (req) => {
  await service.removeEnv((req.params as { id: string }).id);
  return { ok: true };
});
app.get('/api/fleet', async () => service.fleet());

app.post('/api/refresh', async (req) => {
  await rt(req).refresh(true);
  return { ok: true };
});

app.get('/api/diagnostics', async (req) => ({ status: service.status(envOf(req), true, true), probes: await rt(req).diagnostics() }));

// ---------------------------------------------------------------------------------
// Overview / posture
// ---------------------------------------------------------------------------------

app.get('/api/overview', async (req) => {
  const r = rt(req);
  const posture = await r.posture();
  return {
    posture,
    threats: r.threatSummary({ from: Date.now() - 86400e3 }),
    live: r.live.latest,
    history: r.live.samples,
    matrix: await r.matrix().catch(() => null),
    recent: r.threats.query({ limit: 8 }).events,
    extras: await r.overviewExtras(),
  };
});

app.get('/api/posture', async (req) => rt(req).posture());

// ---------------------------------------------------------------------------------
// Threats & intel
// ---------------------------------------------------------------------------------

app.get('/api/threats', async (req) => rt(req).threats.query(threatQuery(req.query as Record<string, unknown>)));
app.get('/api/threats/summary', async (req) => rt(req).threatSummary(threatQuery(req.query as Record<string, unknown>)));
app.get('/api/threats/categories', async () => service.threatCategories());
app.get('/api/threats/:id', async (req) => {
  const e = rt(req).threats.get((req.params as { id: string }).id);
  if (!e) throw new HttpError(404, 'Threat not found');
  return e;
});

app.get('/api/intel/:ip', async (req) => {
  const ip = decodeURIComponent((req.params as { ip: string }).ip).trim();
  if (!parseIp(ip)) throw new HttpError(400, `"${ip}" is not a valid IP address`);
  return rt(req).intelFor(ip, (req.query as { refresh?: string }).refresh === '1');
});

app.post('/api/intel/geo', async (req) => {
  const ips = (req.body as { ips?: unknown })?.ips;
  if (!Array.isArray(ips)) throw new HttpError(400, 'Send {"ips": [...]}.');
  return rt(req).geo(ips.filter((x): x is string => typeof x === 'string' && !!parseIp(x)));
});

// ---------------------------------------------------------------------------------
// Firewall & hardening
// ---------------------------------------------------------------------------------

app.get('/api/firewall', async (req) => rt(req).firewallOverview());
app.get('/api/firewall/matrix', async (req) => rt(req).matrix());
app.get('/api/firewall/blocked', async (req) => rt(req).blockedTraffic());

app.put('/api/networks/:id/role', async (req) => {
  const { role } = (req.body ?? {}) as { role?: NetworkRole | null };
  await rt(req).setRole((req.params as { id: string }).id, role ?? null);
  return { ok: true };
});

app.get('/api/hardening/templates', async (req) => rt(req).templates());

app.post('/api/hardening/plan', async (req) => {
  const { templateId, params, strategy } = (req.body ?? {}) as { templateId?: unknown; params?: unknown; strategy?: unknown };
  if (typeof templateId !== 'string' || !getTemplate(templateId)) throw new HttpError(400, 'Unknown hardening action.');
  const p = params && typeof params === 'object' && !Array.isArray(params) ? (params as Record<string, unknown>) : {};
  return rt(req).plan(templateId, p, typeof strategy === 'string' ? strategy : undefined);
});

app.post('/api/hardening/apply', async (req) => {
  const { planId } = (req.body ?? {}) as { planId?: string };
  if (!planId) throw new HttpError(400, 'planId is required');
  return rt(req).apply(planId);
});

app.get('/api/changes', async (req) => rt(req).executor.list());
app.get('/api/risks', async (req) => rt(req).risks());
app.post('/api/risks', async (req) => rt(req).acceptRisk((req.body ?? {}) as Record<string, unknown>));
app.delete('/api/risks/:key', async (req) => {
  rt(req).revokeRisk((req.params as { key: string }).key);
  return { ok: true };
});
app.get('/api/changes/:id/dependents', async (req) => rt(req).undoDependents((req.params as { id: string }).id));
app.post('/api/changes/:id/undo', async (req) => rt(req).undo((req.params as { id: string }).id, (req.body as { cascade?: unknown } | undefined)?.cascade === true));

// ---------------------------------------------------------------------------------
// Live
// ---------------------------------------------------------------------------------

app.get('/api/live/snapshot', async (req) => rt(req).live.latest);
app.get('/api/live/history', async (req) => rt(req).live.samples);
const MAC = /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/i;
app.get('/api/clients/:mac', async (req) => {
  const mac = (req.params as { mac: string }).mac;
  if (!MAC.test(mac)) throw new HttpError(400, 'Not a MAC address.');
  return rt(req).clientDetail(mac);
});
app.get('/api/unifi-devices', async (req) => rt(req).unifiDevices());
app.get('/api/unifi-devices/:mac', async (req) => {
  const mac = (req.params as { mac: string }).mac;
  if (!MAC.test(mac)) throw new HttpError(400, 'Not a MAC address.');
  return rt(req).unifiDevice(mac);
});
app.get('/api/intel/makers', async () => service.makers.status());
app.post('/api/intel/makers', async () => service.makers.download());
app.delete('/api/intel/makers', async () => service.makers.remove());
app.get('/api/live/trend', async (req) => {
  const range = (req.query as { range?: unknown }).range;
  if (!LIVE_RANGES.includes(range as LiveRange)) throw new HttpError(400, `range must be one of ${LIVE_RANGES.join(', ')}`);
  return rt(req).liveTrend(range as LiveRange);
});
app.get('/api/live/clients', async (req) => rt(req).liveClientsView());

app.get('/api/live/stream', (req: FastifyRequest, reply: FastifyReply) => {
  const hub = rt(req).live;
  reply.hijack();
  reply.raw.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  reply.raw.write(': connected\n\n');
  hub.add(reply.raw);
  req.raw.on('close', () => reply.raw.end());
});

// ---------------------------------------------------------------------------------
// Web UI
// ---------------------------------------------------------------------------------

if (fs.existsSync(webDist)) {
  await app.register(fastifyStatic, { root: webDist, prefix: '/', wildcard: false });
  app.setNotFoundHandler((req, reply) => {
    if (req.url.startsWith('/api/')) return reply.code(404).send({ error: 'Not found' });
    // A missing bundle file is a plain 404; answering with the app page makes the browser fail with a MIME error.
    if (req.url.startsWith('/assets/')) return reply.code(404).type('text/plain').send('Not found');
    return reply.type('text/html').sendFile('index.html');
  });
} else {
  app.get('/', async () => ({ message: 'API is running. Build the web UI with "npm run build" (or use "npm run dev:web" during development).' }));
}

const shutdown = async () => {
  await service.stop().catch(() => undefined);
  await app.close();
  process.exit(0);
};
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

// Local by default; the container sets HOST=0.0.0.0 and Docker publishes the port on 127.0.0.1 only.
await app.listen({ port: APP_PORT, host: process.env.HOST ?? '127.0.0.1' });
await service.start();
const envs = service.environments();
app.log.info(envs.length ? `Environments: ${envs.map((e) => `${e.name} (${e.url})`).join(', ')}` : 'No environments yet - open the UI to connect a UniFi controller');
if (!auth.hasAccount) {
  // Whoever opens the dashboard first creates the account, which matters most once a console is already connected.
  if (envs.length) app.log.warn('No sign-in account yet although a UniFi console is connected: create it now, or set APP_USERNAME / APP_PASSWORD');
  else app.log.info('No sign-in account yet - open the dashboard to create one');
}
