import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import https from 'node:https';
import type { AddressInfo } from 'node:net';
import { X509Certificate } from 'node:crypto';
import type { CertInfo } from '../../shared/types.ts';
import { certInfo, fetchCert, HttpTransport } from './http.ts';

// Two throwaway self-signed "consoles" on 127.0.0.1 (see fixtures/README.txt).
const fixture = (name: string) => fs.readFileSync(new URL(`./fixtures/${name}`, import.meta.url));
const consoles = {
  a: { key: fixture('console-a.key'), cert: fixture('console-a.crt'), keysSeen: [] as string[], url: '' },
  b: { key: fixture('console-b.key'), cert: fixture('console-b.crt'), keysSeen: [] as string[], url: '' },
};
const servers: https.Server[] = [];
const spkiOf = (pem: Buffer) => certInfo(new X509Certificate(pem).raw).spki;

before(async () => {
  for (const c of Object.values(consoles)) {
    const server = https.createServer({ key: c.key, cert: c.cert }, (req, res) => {
      c.keysSeen.push(String(req.headers['x-api-key'] ?? ''));
      res.setHeader('Content-Type', 'application/json');
      res.end('{"ok":true}');
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    c.url = `https://127.0.0.1:${(server.address() as AddressInfo).port}`;
    servers.push(server);
  }
});

after(async () => {
  for (const s of servers) {
    s.closeAllConnections();
    await new Promise((resolve) => s.close(resolve));
  }
});

test('the first certificate is trusted and reported, so it can be saved', async () => {
  let trusted: CertInfo | null = null;
  const t = new HttpTransport({ baseUrl: consoles.a.url, apiKey: 'key-a', verifyTls: false, trustOnFirstUse: true, onTrust: (c) => (trusted = c) });
  const res = await t.send({ method: 'GET', path: '/x' });
  await t.close();
  assert.equal(res.status, 200);
  assert.equal(trusted!.spki, spkiOf(consoles.a.cert));
  assert.equal(trusted!.selfSigned, true);
  assert.match(trusted!.sha256, /^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);
});

test('a different certificate is refused before any request, so the API key never reaches it', async () => {
  const before = consoles.b.keysSeen.length;
  const t = new HttpTransport({ baseUrl: consoles.b.url, apiKey: 'secret-key', verifyTls: false, pin: spkiOf(consoles.a.cert), trustOnFirstUse: true });
  await assert.rejects(t.send({ method: 'GET', path: '/x' }), /Refused to connect.*API key was not sent/);
  assert.equal(t.mismatch?.spki, spkiOf(consoles.b.cert), 'the refused certificate is reported for review');
  await t.close();
  assert.equal(consoles.b.keysSeen.length, before, 'no request reached the impostor');

  const ok = new HttpTransport({ baseUrl: consoles.a.url, apiKey: 'key-a', verifyTls: false, pin: spkiOf(consoles.a.cert) });
  assert.equal((await ok.send({ method: 'GET', path: '/x' })).status, 200, 'the trusted console still works');
  await ok.close();
});

test('reading a certificate for review sends no request at all', async () => {
  const before = consoles.a.keysSeen.length;
  const cert = await fetchCert(consoles.a.url);
  assert.equal(cert.spki, spkiOf(consoles.a.cert));
  assert.equal(consoles.a.keysSeen.length, before);
});

test('certificate-authority checking still refuses a self-signed console', async () => {
  const t = new HttpTransport({ baseUrl: consoles.a.url, apiKey: 'key-a', verifyTls: true });
  await assert.rejects(t.send({ method: 'GET', path: '/x' }), /certificate/i);
  await t.close();
});
