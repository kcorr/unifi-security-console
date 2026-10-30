import { test } from 'node:test';
import assert from 'node:assert/strict';
import { hostAllowed, hostName, parseAllowedHosts } from './hosts.ts';

test('IP addresses and local names work without any setup; public-looking names need ALLOWED_HOSTS', () => {
  const none = parseAllowedHosts(undefined);
  for (const ok of ['localhost:8787', '127.0.0.1:8787', '[::1]:8787', '192.168.1.20:8787', '[fd00::20]:8787', 'dockerhost:8787', 'nas.lan', 'usc.home.arpa:8787', 'console.local', 'app.internal']) {
    assert.equal(hostAllowed(ok, none), true, ok);
  }
  for (const no of ['evil.example:8787', 'usc.example.com', '', undefined, 'lan.evil.example', '192.168.1.20.nip.io']) {
    assert.equal(hostAllowed(no, none), false, String(no));
  }
  const listed = parseAllowedHosts(' USC.Example.com , other.example. ');
  assert.equal(hostAllowed('usc.example.com:443', listed), true, 'listed names, case and trailing dot ignored');
  assert.equal(hostAllowed('other.example', listed), true);
  assert.equal(hostAllowed('evil.example', listed), false);
  assert.equal(hostAllowed('evil.example', parseAllowedHosts('*')), true, '"*" turns the check off');
  assert.equal(hostName('[FD00::20]:8787'), 'fd00::20');
});
