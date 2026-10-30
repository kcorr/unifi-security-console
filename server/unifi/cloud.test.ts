import { test } from 'node:test';
import assert from 'node:assert/strict';
import { UniFiClient } from './client.ts';
import type { HttpRequest, HttpResponse, Transport } from './http.ts';
import { cloudConsoleUrl, isCloudUrl, parseCloudHosts } from '../environments.ts';

test('cloud consoles are reached through the unifi.ui.com connector', async () => {
  const seen: string[] = [];
  // The connector adds "/proxy" itself, so the Network API sits under /network/… on the cloud side.
  const transport: Transport = {
    async send(req: HttpRequest): Promise<HttpResponse> {
      seen.push(req.path);
      if (req.path === '/network/integration/v1/info') return { status: 200, json: { applicationVersion: '10.6.101' }, text: '' };
      if (req.path === '/network/integration/v1/sites') return { status: 200, json: { offset: 0, limit: 200, count: 1, totalCount: 1, data: [{ id: 'site-1', internalReference: 'default', name: 'Default' }] }, text: '' };
      if (req.path === '/network/api/s/default/stat/health') return { status: 200, json: { meta: { rc: 'ok' }, data: [] }, text: '' };
      return { status: 404, json: null, text: '' };
    },
    async close() {},
  };
  const info = await new UniFiClient(transport, 'default', 'cloud').connect();
  assert.equal(seen[0], '/network/integration/v1/info');
  assert.deepEqual([info.kind, info.prefix, info.integration, info.internal, info.siteId], ['cloud', '/network', true, true, 'site-1']);
});

test('cloud console addresses and the list of consoles on an account', () => {
  const url = cloudConsoleUrl('70A7419783ED:1261206302');
  assert.equal(url, 'https://api.ui.com/v1/connector/consoles/70A7419783ED:1261206302');
  assert.ok(isCloudUrl(url));
  assert.ok(!isCloudUrl('https://192.168.1.1'));
  assert.ok(!isCloudUrl('https://api.ui.com.evil.example/v1/connector/consoles/x'));
  assert.throws(() => cloudConsoleUrl('../../v1/hosts'));

  const list = parseCloudHosts([
    { id: 'b:2', type: 'ucore', owner: false, isBlocked: false, userData: { controllers: ['protect'] }, reportedState: {} },
    { id: 'a:1', type: 'udm', owner: true, isBlocked: false, userData: { controllers: ['network', 'protect'] }, reportedState: { name: 'Home UDR7', state: 'connected', version: '5.1.33', hardware: { name: 'UniFi Dream Router 7' } } },
    { id: 'c:3', isBlocked: true },
  ]);
  assert.deepEqual(list.map((c) => c.id), ['a:1', 'b:2'], 'consoles running Network first; blocked ones left out');
  assert.deepEqual(list[0], { id: 'a:1', url: 'https://api.ui.com/v1/connector/consoles/a:1', name: 'Home UDR7', model: 'UniFi Dream Router 7', version: '5.1.33', online: true, owner: true, hasNetwork: true });
  assert.deepEqual([list[1].name, list[1].online, list[1].hasNetwork], ['b:2', null, false]);
});
