// Signing in to the dashboard: one account (a username and a password), created on the first visit, or from
// APP_USERNAME / APP_PASSWORD before that. Sessions are HMAC-signed cookies.
//
// The password is kept only as a salted scrypt hash, so a copied database can't be used to guess it at speed.
// Sessions are signed with a key derived from the session secret and that hash, so changing the password or the
// username, or resetting the account, ends every session. With APP_SECRET set, the session secret is derived from
// it instead of being stored in the database.

import { createHash, createHmac, randomBytes, scrypt, timingSafeEqual } from 'node:crypto';
import { PASSWORD_MIN_LENGTH } from '../shared/types.ts';
import type { Db } from './db.ts';
import { kvGet, kvSet } from './db.ts';
import { HttpError } from './errors.ts';

const COOKIE = 'usc_session';
const TTL_MS = 30 * 86400e3;
// About 50–100 ms and 32 MiB per guess: unnoticeable when signing in, very slow for anyone guessing offline.
const SCRYPT = { N: 2 ** 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
const ACCOUNT_KEY = 'account';
const TAKEN = 'The account has already been created. Sign in instead.';

interface Account {
  username: string;
  /** scrypt salt and hash of the password, hex. */
  salt: string;
  hash: string;
  createdAt: number;
  changedAt: number;
}

function stretch(password: string, salt: Buffer): Promise<Buffer> {
  // The same password typed on another keyboard or system can arrive in another Unicode form.
  return new Promise((resolve, reject) => scrypt(password.normalize('NFKC'), salt, 32, SCRYPT, (err, key) => (err ? reject(err) : resolve(key))));
}

async function hashed(username: string, password: string): Promise<Account> {
  const salt = randomBytes(16);
  const now = Date.now();
  return { username, salt: salt.toString('hex'), hash: (await stretch(password, salt)).toString('hex'), createdAt: now, changedAt: now };
}

const cleanUsername = (u: string) => u.normalize('NFKC').trim();
const sameUser = (a: string, b: string) => cleanUsername(a).toLowerCase() === cleanUsername(b).toLowerCase();

/** Why a username can't be used, or null. */
export function usernameProblem(username: string): string | null {
  if (!username) return 'Enter a username.';
  if (username.length > 64) return 'Use at most 64 characters for the username.';
  if (!/^[\p{L}\p{N}._@-]+$/u.test(username)) return 'Use only letters, digits and . _ - @ in the username (no spaces).';
  return null;
}

/** Why a password can't be used, or null. */
export function passwordProblem(password: string, username: string): string | null {
  const length = [...password].length;
  if (length < PASSWORD_MIN_LENGTH) return `Use at least ${PASSWORD_MIN_LENGTH} characters. A few unrelated words make a long password that is easy to remember.`;
  if (length > 256) return 'Use at most 256 characters for the password.';
  const name = username.toLowerCase();
  if (name.length >= 4 && password.toLowerCase().includes(name)) return 'The password must not contain the username.';
  if (new Set(password).size < 5) return 'This password uses too few different characters to be safe.';
  return null;
}

export class Auth {
  private readonly db: Db;
  private readonly secret: Buffer;

  constructor(db: Db, appSecret = process.env.APP_SECRET) {
    this.db = db;
    if (appSecret) this.secret = createHmac('sha256', createHash('sha256').update(appSecret).digest()).update('session-secret').digest();
    else {
      let s = kvGet<string>(db, 'session-secret')?.value;
      if (!s) {
        s = randomBytes(32).toString('hex');
        kvSet(db, 'session-secret', s);
      }
      this.secret = Buffer.from(s, 'hex');
    }
  }

  /** Read each time, so a reset from the command line (reset-login.ts) takes effect at once. */
  private account(): Account | null {
    return kvGet<Account>(this.db, ACCOUNT_KEY)?.value ?? null;
  }

  /** False until the first visit (or APP_PASSWORD) has created the account. */
  get hasAccount(): boolean {
    return this.account() !== null;
  }

  get username(): string | null {
    return this.account()?.username ?? null;
  }

  /** Creates the account. Refused once one exists, so nobody can redo the first visit. */
  async create(username: string, password: string): Promise<void> {
    const name = cleanUsername(username);
    const problem = usernameProblem(name) ?? passwordProblem(password, name);
    if (problem) throw new HttpError(400, problem);
    if (this.hasAccount) throw new HttpError(409, TAKEN);
    const record = await hashed(name, password);
    // Checked again after hashing: of two set-ups racing each other, only the first may win.
    if (this.hasAccount) throw new HttpError(409, TAKEN);
    kvSet(this.db, ACCOUNT_KEY, record);
  }

  /** Whether the username (not case-sensitive) and the password are right. */
  async check(username: string, password: string): Promise<boolean> {
    const a = this.account();
    // Without an account the password is still hashed, so the answer takes as long either way.
    const got = await stretch(password, a ? Buffer.from(a.salt, 'hex') : this.secret.subarray(0, 16));
    return a !== null && timingSafeEqual(got, Buffer.from(a.hash, 'hex')) && sameUser(a.username, username);
  }

  /** Changes the username and/or the password after checking the current password. Ends every session. */
  async update(currentPassword: string, next: { username?: string; password?: string }): Promise<void> {
    const a = this.account();
    if (!a) throw new HttpError(409, 'There is no account yet.');
    if (!(await this.check(a.username, currentPassword))) throw new HttpError(403, 'The current password is wrong.');
    const name = next.username === undefined ? a.username : cleanUsername(next.username);
    const problem = usernameProblem(name) ?? (next.password === undefined ? null : passwordProblem(next.password, name));
    if (problem) throw new HttpError(400, problem);
    const record = next.password === undefined ? { ...a, username: name } : await hashed(name, next.password);
    kvSet(this.db, ACCOUNT_KEY, { ...record, createdAt: a.createdAt, changedAt: Date.now() });
  }

  /** Removes the account, so the next visit shows the set-up page again. Everything else is kept. */
  reset(): void {
    this.db.prepare('DELETE FROM kv WHERE key = ?').run(ACCOUNT_KEY);
    this.revokeAll();
  }

  /** APP_USERNAME / APP_PASSWORD create the account at startup while there is none. Returns a line for the log. */
  async seed(username: string, password: string): Promise<string | null> {
    if (!password) return null;
    if (this.hasAccount) return 'APP_PASSWORD is ignored because the account already exists. Change the password in Settings → Account.';
    const name = cleanUsername(username) || 'admin';
    try {
      await this.create(name, password);
      return `Created the sign-in account "${name}" from APP_PASSWORD.`;
    } catch (e) {
      return `APP_PASSWORD was not used: ${e instanceof Error ? e.message : String(e)} Create the account in the browser instead.`;
    }
  }

  issue(): string {
    const a = this.account();
    if (!a) throw new HttpError(409, 'There is no account yet.');
    const iat = Date.now();
    const exp = iat + TTL_MS;
    return `${iat}.${exp}.${this.sign(a, `${iat}.${exp}`)}`;
  }

  verify(token: string | undefined): boolean {
    const a = this.account();
    if (!a || !token) return false;
    const [iat, exp, sig] = token.split('.');
    if (!iat || !exp || !sig || Number(exp) < Date.now()) return false;
    // Sessions issued before the last sign-out are no longer valid.
    if (Number(iat) < (kvGet<number>(this.db, 'session-valid-after')?.value ?? 0)) return false;
    const expect = this.sign(a, `${iat}.${exp}`);
    return expect.length === sig.length && timingSafeEqual(Buffer.from(expect), Buffer.from(sig));
  }

  /** Signs out every session (single-user app: signing out means everywhere). */
  revokeAll(): void {
    kvSet(this.db, 'session-valid-after', Date.now());
  }

  cookie(token: string): string {
    return `${COOKIE}=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${TTL_MS / 1000}`;
  }

  clearCookie(): string {
    return `${COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`;
  }

  tokenFrom(cookieHeader: string | undefined): string | undefined {
    if (!cookieHeader) return undefined;
    for (const part of cookieHeader.split(';')) {
      const [k, ...v] = part.trim().split('=');
      if (k === COOKIE) return v.join('=');
    }
    return undefined;
  }

  private sign(a: Account, payload: string): string {
    // Keyed by the password hash and the username too, so changing either ends every session.
    const key = createHmac('sha256', this.secret).update(`${a.hash}:${a.username}:session`).digest();
    return createHmac('sha256', key).update(payload).digest('hex');
  }
}

// ---------------------------------------------------------------------------------
// Login throttling: wrong passwords per address and in total, so guessing in parallel doesn't help.
// ---------------------------------------------------------------------------------

const WINDOW_MS = 10 * 60e3;
const PER_ADDRESS = 5;
const OVERALL = 30;

export class LoginThrottle {
  private readonly failures = new Map<string, number[]>();

  /** Seconds to wait before another attempt from `ip`, or 0. */
  retryAfter(ip: string, now = Date.now()): number {
    const mine = this.recent(ip, now);
    const all = [...this.failures.keys()].reduce((n, k) => n + this.recent(k, now).length, 0);
    const blockedUntil = mine.length >= PER_ADDRESS ? mine[mine.length - PER_ADDRESS] + WINDOW_MS : all >= OVERALL ? now + 60e3 : 0;
    return blockedUntil > now ? Math.ceil((blockedUntil - now) / 1000) : 0;
  }

  fail(ip: string, now = Date.now()): void {
    this.failures.set(ip, [...this.recent(ip, now), now]);
  }

  succeed(ip: string): void {
    this.failures.delete(ip);
  }

  private recent(ip: string, now: number): number[] {
    const list = (this.failures.get(ip) ?? []).filter((t) => now - t < WINDOW_MS);
    if (list.length) this.failures.set(ip, list);
    else this.failures.delete(ip);
    return list;
  }
}
