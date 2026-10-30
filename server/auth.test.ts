import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { Auth } from './auth.ts';

function db() {
  const d = new DatabaseSync(':memory:');
  d.exec('CREATE TABLE kv (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL)');
  return d;
}

test('the first visit creates the account, once, and nothing is open before that', async () => {
  const auth = new Auth(db(), '');
  assert.equal(auth.hasAccount, false);
  assert.equal(auth.verify(undefined), false);
  assert.equal(await auth.check('admin', 'any password at all'), false);
  await assert.rejects(auth.create('alex', 'too short'), /at least 12/);
  await assert.rejects(auth.create('alex', 'alex-and-more-words'), /must not contain the username/);
  await assert.rejects(auth.create('alex smith', 'a long enough passphrase'), /letters, digits/);
  await assert.rejects(auth.create('alex', 'aaaaaaaaaaaaaaaa'), /too few different/);
  await auth.create('  Alex ', 'correct horse battery');
  assert.equal(auth.username, 'Alex');
  await assert.rejects(auth.create('sam', 'another long password'), /already been created/);

  const race = new Auth(db(), '');
  const results = await Promise.allSettled([race.create('alex', 'first long password'), race.create('sam', 'second long password')]);
  assert.deepEqual(results.map((r) => r.status).sort(), ['fulfilled', 'rejected'], 'of two set-ups at the same moment, only one wins');
  assert.match(String((results.find((r) => r.status === 'rejected') as PromiseRejectedResult).reason), /already been created/);
});

test('signing in checks the username and the password, which is stored only as a scrypt hash', async () => {
  const d = db();
  const auth = new Auth(d, '');
  await auth.create('Alex', 'correct horse battery');
  assert.equal(await auth.check('alex', 'correct horse battery'), true, 'the username is not case-sensitive');
  assert.equal(await auth.check('alex', 'correct horse batter'), false);
  assert.equal(await auth.check('sam', 'correct horse battery'), false);
  const stored = (d.prepare("SELECT value FROM kv WHERE key = 'account'").get() as { value: string }).value;
  assert.ok(!stored.includes('correct horse'), 'the password itself is never stored');

  const token = auth.issue();
  assert.equal(auth.verify(token), true);
  assert.equal(new Auth(d, '').verify(token), true, 'sessions survive a restart');
  assert.equal(auth.verify(`${token}0`), false);
});

test('changing the password or the username needs the current password and ends every session', async () => {
  const auth = new Auth(db(), '');
  await auth.create('alex', 'correct horse battery');
  const first = auth.issue();
  await assert.rejects(auth.update('not my password', { password: 'a brand new password' }), /current password is wrong/);
  await assert.rejects(auth.update('correct horse battery', { password: 'short' }), /at least 12/);
  assert.equal(auth.verify(first), true, 'a refused change changes nothing');

  await auth.update('correct horse battery', { password: 'a brand new password' });
  assert.equal(auth.verify(first), false);
  assert.equal(await auth.check('alex', 'correct horse battery'), false);
  assert.equal(await auth.check('alex', 'a brand new password'), true);

  const second = auth.issue();
  await auth.update('a brand new password', { username: 'sam' });
  assert.equal(auth.verify(second), false);
  assert.equal(await auth.check('sam', 'a brand new password'), true);

  const third = auth.issue();
  auth.reset();
  assert.equal(auth.hasAccount, false, 'the reset command brings back the set-up page');
  assert.equal(auth.verify(third), false);
});

test('APP_USERNAME and APP_PASSWORD create the account once, and only with a good password', async () => {
  const auth = new Auth(db(), '');
  assert.equal(await auth.seed('', ''), null);
  assert.match((await auth.seed('', 'short')) ?? '', /was not used: Use at least 12/);
  assert.equal(auth.hasAccount, false);
  assert.match((await auth.seed('', 'a long seeded password')) ?? '', /"admin"/);
  assert.equal(await auth.check('admin', 'a long seeded password'), true);
  assert.match((await auth.seed('', 'another long password')) ?? '', /ignored/);
  assert.equal(await auth.check('admin', 'a long seeded password'), true);
});

test('with APP_SECRET set, no session secret is stored in the database', async () => {
  const d = db();
  const auth = new Auth(d, 'my-app-secret');
  await auth.create('alex', 'correct horse battery');
  const token = auth.issue();
  assert.equal((d.prepare("SELECT COUNT(*) AS c FROM kv WHERE key = 'session-secret'").get() as { c: number }).c, 0);
  assert.equal(new Auth(d, 'my-app-secret').verify(token), true, 'the same secret keeps sessions valid across restarts');
  assert.equal(new Auth(d, 'another-secret').verify(token), false);
});
