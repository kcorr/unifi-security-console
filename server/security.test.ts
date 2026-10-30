// Starts a real server (no UniFi console; an account created from APP_PASSWORD) and attacks its front door.

import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, type ChildProcess } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';

const PORT = 18000 + Math.floor(Math.random() * 1000);
let server: ChildProcess;
let dir: string;

function request(o: { path: string; method?: string; host?: string; headers?: Record<string, string>; body?: unknown; port?: number }): Promise<{ status: number; body: string; headers: http.IncomingHttpHeaders }> {
  const port = o.port ?? PORT;
  return new Promise((resolve, reject) => {
    const body = o.body === undefined ? undefined : JSON.stringify(o.body);
    const req = http.request(
      {
        host: '127.0.0.1',
        port,
        method: o.method ?? 'GET',
        path: o.path,
        headers: { host: o.host ?? `localhost:${port}`, ...(body ? { 'content-type': 'application/json', 'x-requested-with': 'usc' } : {}), ...o.headers },
      },
      (res) => {
        let data = '';
        res.on('data', (c) => (data += c));
        res.on('end', () => resolve({ status: res.statusCode ?? 0, body: data, headers: res.headers }));
      },
    );
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

const cookieOf = (res: { headers: http.IncomingHttpHeaders }) => String(res.headers['set-cookie']?.[0] ?? '').split(';')[0];

async function login(): Promise<string> {
  const res = await request({ path: '/api/login', method: 'POST', body: { username: 'admin', password: 'correct horse' } });
  assert.equal(res.status, 200, res.body);
  return cookieOf(res);
}

async function startServer(port: number, dataDir: string, env: Record<string, string>): Promise<ChildProcess> {
  const child = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', 'server/index.ts'], {
    env: { ...process.env, PORT: String(port), HOST: '127.0.0.1', DATA_DIR: dataDir, LOG_LEVEL: 'error', ...env },
    stdio: 'ignore',
  });
  for (let i = 0; i < 150; i++) {
    try {
      if ((await request({ path: '/api/health', port })).status === 200) return child;
    } catch {
      // not listening yet
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error('test server did not start');
}

async function stopServer(child: ChildProcess, dataDir: string): Promise<void> {
  // Wait for the server to exit: on Windows its database files stay locked until then.
  if (child.exitCode === null) await new Promise<void>((resolve) => child.once('exit', () => resolve()).kill());
  fs.rmSync(dataDir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
}

before(async () => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'usc-security-'));
  server = await startServer(PORT, dir, { APP_USERNAME: '', APP_PASSWORD: 'correct horse' });
});

after(() => stopServer(server, dir));

test('the password cannot be walked around with encoded or absolute URLs', async () => {
  assert.equal((await request({ path: '/api/environments' })).status, 401);
  assert.equal((await request({ path: '/%61pi/environments' })).status, 401);
  assert.equal((await request({ path: `http://x/api/environments` })).status, 401);
  assert.equal((await request({ path: '/%61pi/environments', method: 'POST', headers: { 'x-requested-with': 'usc', 'content-type': 'application/json' } })).status, 401);
});

test('public-looking host names are refused (DNS rebinding); IP addresses and local names work', async () => {
  assert.equal((await request({ path: '/api/health', host: 'evil.example:8787' })).status, 403);
  assert.equal((await request({ path: '/', host: 'evil.example' })).status, 403);
  assert.equal((await request({ path: '/api/health', host: '127.0.0.1' })).status, 200);
  assert.equal((await request({ path: '/api/health', host: '192.168.1.20:8787' })).status, 200, 'a Docker server opened by its LAN address');
  assert.equal((await request({ path: '/api/health', host: 'dockerhost.lan:8787' })).status, 200);
});

test('before signing in, status only says that a sign-in is needed', async () => {
  const res = await request({ path: '/api/status' });
  assert.deepEqual(JSON.parse(res.body), { authRequired: true, authenticated: false, setupRequired: false });
  assert.match(String(res.headers['content-security-policy']), /frame-ancestors 'none'/);
});

test('the first visit creates the account: nothing is open before that, and it only works once', async () => {
  const port = PORT + 1;
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'usc-setup-'));
  const child = await startServer(port, dataDir, { APP_USERNAME: '', APP_PASSWORD: '' });
  try {
    assert.deepEqual(JSON.parse((await request({ port, path: '/api/status' })).body), { authRequired: true, authenticated: false, setupRequired: true });
    assert.equal((await request({ port, path: '/api/environments' })).status, 401);
    assert.equal((await request({ port, path: '/api/setup', method: 'POST', body: { username: 'alex', password: 'too short' } })).status, 400);
    const res = await request({ port, path: '/api/setup', method: 'POST', body: { username: 'alex', password: 'correct horse battery' } });
    assert.equal(res.status, 200, res.body);
    const cookie = cookieOf(res);
    assert.equal(JSON.parse((await request({ port, path: '/api/status', headers: { cookie } })).body).username, 'alex');
    assert.equal((await request({ port, path: '/api/environments', headers: { cookie } })).status, 200);

    const again = await request({ port, path: '/api/setup', method: 'POST', body: { username: 'mallory', password: 'my own long password' } });
    assert.equal(again.status, 409, 'once the account exists, nobody can create another');
    assert.equal(JSON.parse((await request({ port, path: '/api/status' })).body).setupRequired, false);

    const wrong = await request({ port, path: '/api/account', method: 'PUT', headers: { cookie }, body: { currentPassword: 'not my password', newPassword: 'a brand new password' } });
    assert.equal(wrong.status, 403);
    const changed = await request({ port, path: '/api/account', method: 'PUT', headers: { cookie }, body: { currentPassword: 'correct horse battery', newPassword: 'a brand new password' } });
    assert.equal(changed.status, 200, changed.body);
    assert.equal((await request({ port, path: '/api/environments', headers: { cookie } })).status, 401, 'a new password ends the old sessions');
    assert.equal((await request({ port, path: '/api/environments', headers: { cookie: cookieOf(changed) } })).status, 200, 'and this browser gets a new one');
  } finally {
    await stopServer(child, dataDir);
  }
});

test('a saved API key is never sent to a different address', async () => {
  const cookie = await login();
  const env = await request({ path: '/api/environments', method: 'POST', headers: { cookie }, body: { name: 'Remote', url: 'https://192.0.2.10', apiKey: 'saved-secret-key' } });
  assert.equal(env.status, 200, env.body);
  const id = JSON.parse(env.body).id as string;
  const t = await request({ path: '/api/environments/test', method: 'POST', headers: { cookie }, body: { id, url: 'http://127.0.0.1:9/steal' } });
  assert.match(JSON.parse(t.body).message, /Enter the API key again/);
  const u = await request({ path: `/api/environments/${id}`, method: 'PUT', headers: { cookie }, body: { url: 'http://127.0.0.1:9/steal' } });
  assert.equal(u.status, 400);
  const c = await request({ path: '/api/environments/cloud-consoles', method: 'POST', headers: { cookie }, body: { id } });
  assert.equal(c.status, 400, 'a local console key is never sent to unifi.ui.com');
  const w = await request({ path: `/api/environments/${id}`, method: 'PUT', headers: { cookie }, body: { writeMode: 'Read-Only' } });
  assert.equal(w.status, 400, 'unknown safety levels are refused');
});

test('signing out ends the session', async () => {
  const cookie = await login();
  assert.equal((await request({ path: '/api/environments', headers: { cookie } })).status, 200);
  await request({ path: '/api/logout', method: 'POST', headers: { cookie, 'x-requested-with': 'usc' } });
  assert.equal((await request({ path: '/api/environments', headers: { cookie } })).status, 401);
});

test('wrong passwords are throttled', async () => {
  for (let i = 0; i < 5; i++) assert.equal((await request({ path: '/api/login', method: 'POST', body: { username: 'admin', password: 'guess' } })).status, 401);
  const res = await request({ path: '/api/login', method: 'POST', body: { username: 'admin', password: 'correct horse' } });
  assert.equal(res.status, 429, 'even the right password waits once the limit is hit');
  assert.ok(Number(res.headers['retry-after']) > 0);
});
