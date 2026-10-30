// Applies change plans to the controller, records them, and undoes them.

import { randomUUID } from 'node:crypto';
import type { ChangePlan, ChangeRecord, PlanOperation, WriteMode } from '../../../shared/types.ts';
import type { Db } from '../../db.ts';
import type { UniFiClient } from '../../unifi/client.ts';
import { UniFiHttpError } from '../../unifi/http.ts';

type Obj = Record<string, unknown>;
type OpResult = ChangeRecord['operations'][number];

const VOLATILE = new Set(['last_alert_id', 'last_honeypot_id', 'last_nmap_id', 'utm_token', 'site_id', 'hits', 'last_hit', 'index', 'reportFlowEnabled', 'report_flow', 'metadata', 'id', '_id']);
const PLAN_TTL_MS = 30 * 60e3;

// Records saved before summaries were kept in the past tense still say what "will" happen. These are the exact phrases
// the planner used then; anything else (every newer record) passes through unchanged.
const FIREWALL_PARTS: [RegExp, string][] = [
  [/^(.+) will get a new rule$/, '$1 got a new rule'],
  [/^(.+) will be handled by updating existing rules$/, 'existing rules were updated to cover $1'],
  [/^(.+) is already protected$/, '$1 was already protected'],
  [/^(.+) are already protected$/, '$1 were already protected'],
];
const WHOLE: [RegExp, string][] = [
  [/^Switch Intrusion Prevention to (.+)$/, 'Switched Intrusion Prevention to $1'],
  [/^Disable UPnP so only port forwards you create are exposed$/, 'Disabled UPnP, so only port forwards you create are exposed'],
  [/^Enable client isolation on (.+)$/, 'Enabled client isolation on $1'],
  [/^Disable port forward (.+)$/, 'Disabled port forward $1'],
  [/^Restrict port forward (.+)$/, 'Restricted port forward $1'],
  [/^Block new connections from (.+)$/, 'Blocked new connections from $1'],
  [/^Create an empty “(.+?)” network to try hardening actions on, without touching your real networks\. Remove it from the Change Log when you are done$/, 'Created the empty “$1” network for trying hardening actions. Remove it from the Change Log when you are done'],
  [/^(.+) will be added to your managed blocklist\. .*$/, 'Added $1 to your managed blocklist'],
  [/^(.+) will be blocked with a managed blocklist and (\d+ rules?)\. .*$/, 'Blocked $1 with a managed blocklist and $2'],
];
export function pastTense(summary: string): string {
  const body = summary.replace(/\.$/, '');
  for (const [re, to] of WHOLE) if (re.test(body)) return `${body.replace(re, to)}.`;
  const parts = body.split('; ');
  if (!parts.some((x) => FIREWALL_PARTS.some(([re]) => re.test(x)))) return summary;
  const out = parts.map((x) => FIREWALL_PARTS.reduce((acc, [re, to]) => acc.replace(re, to), x)).join('; ');
  return `${out.charAt(0).toUpperCase()}${out.slice(1)}.`;
}
const readRecord = (data: string): ChangeRecord => {
  const r = JSON.parse(data) as ChangeRecord;
  return { ...r, summary: pastTense(r.summary) };
};

function substitute<T>(v: T, created: Map<string, string>): T {
  if (typeof v === 'string') {
    if (v.startsWith('$created:')) return (created.get(v.slice(9)) ?? v) as T;
    return v.replace(/\$created:([A-Za-z0-9-]+)/g, (m, id: string) => created.get(id) ?? m) as T;
  }
  if (Array.isArray(v)) return v.map((x) => substitute(x, created)) as T;
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v as Obj).map(([k, x]) => [k, substitute(x, created)])) as T;
  return v;
}

function normalize(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(normalize);
  if (v && typeof v === 'object') {
    return Object.fromEntries(
      Object.entries(v as Obj)
        .filter(([k]) => !VOLATILE.has(k))
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([k, x]) => [k, normalize(x)]),
    );
  }
  return v;
}

function sameDoc(a: unknown, b: unknown): boolean {
  return JSON.stringify(normalize(a)) === JSON.stringify(normalize(b));
}

function extractId(res: unknown): string | null {
  if (!res || typeof res !== 'object') return null;
  const r = res as Obj;
  if (typeof r.id === 'string') return r.id;
  if (typeof r._id === 'string') return r._id;
  if (Array.isArray(r.data) && r.data[0] && typeof (r.data[0] as Obj)._id === 'string') return (r.data[0] as Obj)._id as string;
  if (Array.isArray(res) && res[0] && typeof (res[0] as Obj)._id === 'string') return (res[0] as Obj)._id as string;
  return null;
}

function unwrap(res: unknown): Obj | null {
  if (!res || typeof res !== 'object') return null;
  const r = res as Obj;
  if (Array.isArray(r.data)) return (r.data[0] as Obj) ?? null;
  if (Array.isArray(res)) return (res[0] as Obj) ?? null;
  return r;
}

function settingKey(path: string): string | null {
  return /\/rest\/setting\/([^/]+)\//.exec(path)?.[1] ?? null;
}

/**
 * Ids of the objects a change created or modified that it is still responsible for. A later change touching any of
 * them depends on it: undoing the earlier one first would wipe the later one out.
 */
function touchedIds(rec: ChangeRecord): string[] {
  return rec.operations
    .filter((o) => o.status === 'ok' && !isOrdering(o))
    .map((o) => (o.kind === 'create' ? o.resultId : o.targetId))
    .filter((id): id is string => !!id);
}

function notFound(e: unknown): boolean {
  return e instanceof UniFiHttpError && e.status === 404;
}

function isOrdering(op: { path: string }): boolean {
  return op.path.includes('/ordering') || op.path.includes('batch-reorder');
}

/** Everything in `expected` is also in `actual` (the controller may add fields of its own). */
function contains(actual: unknown, expected: unknown): boolean {
  if (Array.isArray(expected)) {
    if (!Array.isArray(actual) || actual.length !== expected.length) return false;
    // Lists are sets here (ports, networks, addresses), and UniFi stores them in its own order: sent 53, 853 comes back
    // as 853, 53. Each expected item just needs its own matching item.
    const left = [...actual];
    return expected.every((x) => {
      const i = left.findIndex((a) => contains(a, x));
      if (i >= 0) left.splice(i, 1);
      return i >= 0;
    });
  }
  if (expected && typeof expected === 'object') {
    if (!actual || typeof actual !== 'object') return false;
    return Object.entries(expected as Obj).every(([k, v]) => VOLATILE.has(k) || contains((actual as Obj)[k], v));
  }
  // Region Blocking keeps its countries as text ("RU,KP,CN"): a set as well.
  if (typeof expected === 'string' && typeof actual === 'string' && CODE_LIST.test(expected) && CODE_LIST.test(actual)) return expected.split(',').sort().join() === actual.split(',').sort().join();
  return actual === expected || (expected === null && actual === undefined);
}
const CODE_LIST = /^[A-Z]{2}(,[A-Z]{2})+$/;

export class ChangeExecutor {
  private readonly db: Db;
  private readonly plans = new Map<string, ChangePlan>();
  /** Counts applies and undos; a preview made before the latest one may no longer match reality. */
  private changes = 0;
  /** Pause between retries while UniFi finishes removing a network (shorter in tests). */
  retryDelayMs = 3000;
  private readonly madeAt = new Map<string, number>();

  constructor(db: Db) {
    this.db = db;
  }

  /** Why a remembered preview can't be applied as it is, or null when it can. */
  refusal(plan: ChangePlan): string | null {
    if (this.madeAt.get(plan.id) !== this.changes) return 'Something was changed after this preview was made. Review the change again.';
    if (plan.blockedReason) return plan.blockedReason;
    if (!plan.operations.length) return 'There is nothing to change.';
    return null;
  }

  remember(plan: ChangePlan): void {
    const now = Date.now();
    for (const [id, p] of this.plans) {
      if (now - p.createdAt <= PLAN_TTL_MS) continue;
      this.plans.delete(id);
      this.madeAt.delete(id);
    }
    this.plans.set(plan.id, plan);
    this.madeAt.set(plan.id, this.changes);
  }

  getPlan(id: string): ChangePlan | null {
    const p = this.plans.get(id);
    if (!p || Date.now() - p.createdAt > PLAN_TTL_MS) return null;
    return p;
  }

  list(limit = 200): ChangeRecord[] {
    return (this.db.prepare('SELECT data FROM changes ORDER BY ts DESC LIMIT ?').all(limit) as { data: string }[]).map((r) => readRecord(r.data));
  }

  get(id: string): ChangeRecord | null {
    const r = this.db.prepare('SELECT data FROM changes WHERE id = ?').get(id) as { data: string } | undefined;
    return r ? readRecord(r.data) : null;
  }

  private save(rec: ChangeRecord): void {
    this.db.prepare('INSERT INTO changes (id, ts, data) VALUES (?, ?, ?) ON CONFLICT(id) DO UPDATE SET data = excluded.data').run(rec.id, rec.ts, JSON.stringify(rec));
  }

  /** Current state of the object an update targets (null when it cannot be read). */
  private async current(client: UniFiClient, op: PlanOperation): Promise<Obj | null> {
    try {
      const key = settingKey(op.path);
      if (key) {
        const rows = await client.request<{ data?: Obj[] }>('GET', op.path.replace(/\/rest\/setting\/.*$/, '/get/setting'));
        return rows.data?.find((s) => s.key === key) ?? null;
      }
      if (op.path.includes('/ordering') || op.path.includes('batch-reorder')) return null;
      return unwrap(await client.request('GET', op.path));
    } catch {
      return null;
    }
  }

  async apply(planId: string, client: UniFiClient, mode?: WriteMode): Promise<ChangeRecord> {
    const plan = this.getPlan(planId);
    if (!plan) throw new Error('This preview has expired. Please review the change again.');
    // Each preview applies once (a double-click must not create every rule twice), and never once it is stale.
    this.plans.delete(planId);
    const refused = this.refusal(plan);
    this.madeAt.delete(planId);
    if (refused) throw new Error(refused);
    const rec: ChangeRecord = {
      appliedMode: mode,
      id: randomUUID(),
      ts: Date.now(),
      planId: plan.id,
      templateId: plan.templateId,
      title: plan.title,
      summary: plan.doneSummary ?? plan.summary,
      status: 'applied',
      operations: [],
      undoable: true,
      undoneAt: null,
      error: null,
    };
    const created = new Map<string, string>();
    let failed = false;
    for (const op of plan.operations) {
      if (failed) {
        rec.operations.push({ ...op, status: 'skipped' });
        continue;
      }
      let body = substitute(op.body, created) as Obj | undefined;
      // What the Change Log keeps: for settings only the changed fields, never the whole document with its secrets.
      let logged = body;
      const path = substitute(op.path, created);
      try {
        if (op.kind === 'update' && op.objectType === 'setting') {
          // Re-base the change on the freshest settings document; without one, a partial PUT could wipe fields.
          const cur = await this.current(client, op);
          if (!cur) throw new Error('Could not read the current settings from UniFi, so nothing was changed. Try again.');
          const changes = Object.fromEntries(Object.entries(body ?? {}).filter(([k, v]) => JSON.stringify((op.before as Obj | undefined)?.[k]) !== JSON.stringify(v)));
          // A field edited in UniFi after the preview would be overwritten (Region Blocking's list is one field).
          if (Object.keys(changes).some((k) => !sameDoc(cur[k] ?? null, (op.before as Obj | undefined)?.[k] ?? null))) {
            throw new Error('This setting changed in UniFi since this preview was made. Close this dialog and review the change again.');
          }
          body = { ...cur, ...changes };
          logged = changes;
        } else if (op.kind === 'update' && op.before && op.targetId) {
          const cur = await this.current(client, op);
          if (cur) {
            if (op.objectType === 'wlan') {
              // Partial update - nothing to compare.
            } else {
              const comparable = op.api === 'integration' ? Object.fromEntries(Object.entries(cur).filter(([k]) => !['id', 'index', 'metadata'].includes(k))) : cur;
              if (!sameDoc(comparable, op.before)) throw new Error('The object changed in UniFi since this preview was made. Close this dialog and review the change again.');
            }
          }
        }
        let res: unknown;
        try {
          res = await client.request(op.method, path, body);
        } catch (err) {
          // Per-id DELETE is not available on every firmware for v2 policies; batch-delete is.
          if (op.kind === 'delete' && /\/firewall-policies\/[^/]+$/.test(path)) res = await client.request('POST', path.replace(/\/[^/]+$/, '/batch-delete'), [op.targetId]);
          else throw err;
        }
        const newId = op.kind === 'create' ? extractId(res) : null;
        if (op.kind === 'create') {
          if (!newId) throw new Error('The controller did not return the id of the created object.');
          created.set(op.id, newId);
        }
        rec.operations.push({ ...op, path, body: logged, status: 'ok', resultId: newId ?? op.targetId });
      } catch (e) {
        failed = true;
        const msg = e instanceof Error ? e.message : String(e);
        rec.operations.push({ ...op, path, body: logged, status: 'failed', error: msg });
        rec.error = msg;
      }
    }
    if (failed) {
      // Roll the earlier steps back, so a half-applied change can't leave something blocked or ineffective.
      const done = rec.operations.filter((o) => o.status === 'ok');
      const problems: string[] = [];
      for (const op of [...done].reverse()) {
        try {
          await this.undoOne(client, op);
          op.status = 'undone';
        } catch (e) {
          problems.push(`${op.description}: ${e instanceof Error ? e.message : String(e)}`);
        }
      }
      rec.status = problems.length ? 'partial' : 'failed';
      if (done.length) rec.error = problems.length ? `${rec.error} Rolling back the earlier steps also failed (${problems.join('; ')}); undo it from the Change Log.` : `${rec.error} The steps that had already run were rolled back, so nothing changed.`;
    }
    rec.undoable = rec.operations.some((o) => o.status === 'ok');
    if (rec.operations.some((o) => o.status === 'ok' || o.status === 'undone')) this.changes++;
    this.save(rec);
    return rec;
  }

  /**
   * Later changes that still use or modify something this change created or modified (rules in a test network's
   * zone, another update to the same rule or setting, a widen of a rule it created…), newest first: they have to be
   * undone before this one, or undoing it would silently wipe them out.
   */
  dependents(id: string): ChangeRecord[] {
    const row = this.db.prepare('SELECT rowid AS n, data FROM changes WHERE id = ?').get(id) as { n: number; data: string } | undefined;
    if (!row) return [];
    const ids = new Set(touchedIds(JSON.parse(row.data) as ChangeRecord));
    if (!ids.size) return [];
    const deps: ChangeRecord[] = [];
    // rowid is insertion order (saves update in place), so this also orders changes applied within one millisecond.
    for (const r of this.db.prepare('SELECT data FROM changes WHERE rowid > ? ORDER BY rowid').all(row.n) as { data: string }[]) {
      const rec = JSON.parse(r.data) as ChangeRecord;
      if (rec.status !== 'applied' && rec.status !== 'partial') continue;
      // Ordering steps list every rule of a zone pair, so they would make unrelated changes look dependent.
      const text = JSON.stringify(rec.operations.filter((o) => !isOrdering(o)));
      if (![...ids].some((x) => text.includes(x))) continue;
      deps.push(rec);
      for (const x of touchedIds(rec)) ids.add(x);
    }
    return deps.reverse();
  }

  /** Undo a change after first undoing every later change that depends on it, newest first. Stops at the first failure. */
  async undoCascade(id: string, client: UniFiClient): Promise<ChangeRecord> {
    for (const d of this.dependents(id)) {
      const r = await this.undo(d.id, client);
      if (r.status !== 'undone') throw new Error(`Stopped while undoing “${d.title}”: ${r.error ?? 'unknown error'}. Older changes were left as they are.`);
    }
    return this.undo(id, client);
  }

  async undo(id: string, client: UniFiClient): Promise<ChangeRecord> {
    const rec = this.get(id);
    if (!rec) throw new Error('Change not found.');
    if (rec.status === 'undone') return rec;
    const errors: string[] = [];
    const ops = [...rec.operations].reverse();
    for (const op of ops) {
      if (op.status !== 'ok') continue;
      try {
        await this.undoOne(client, op);
        op.status = 'undone';
      } catch (e) {
        // Stop here, like apply: undoing later steps on top of a failed one (e.g. deleting a DNS exception while the
        // widened block stays) can leave things worse than either state.
        errors.push(`${op.description}: ${e instanceof Error ? e.message : String(e)}`);
        break;
      }
    }
    rec.operations = ops.reverse();
    if (rec.operations.some((o) => o.status === 'undone')) this.changes++;
    if (errors.length) {
      rec.error = `Undo incomplete: ${errors.join('; ')}`;
    } else {
      rec.status = 'undone';
      rec.undoneAt = Date.now();
      rec.undoable = false;
      rec.error = null;
    }
    this.save(rec);
    return rec;
  }

  private async undoOne(client: UniFiClient, op: OpResult): Promise<void> {
    if (op.kind === 'create') {
      if (!op.resultId) throw new Error('missing id of created object');
      const base = op.path.replace(/\?.*$/, '');
      try {
        if (base.endsWith('/firewall-policies')) {
          try {
            await client.request('DELETE', `${base}/${op.resultId}`);
          } catch {
            await client.request('POST', `${base}/batch-delete`, [op.resultId]);
          }
          return;
        }
        // Right after its network is deleted, UniFi still counts the network in its zone for a few seconds and refuses
        // to delete the zone ("network-does-not-exist"); waiting a moment is enough.
        for (let attempt = 0; ; attempt++) {
          try {
            await client.request('DELETE', `${base}/${op.resultId}`);
            break;
          } catch (e) {
            if (!(base.endsWith('/firewall/zones') && attempt < 5 && e instanceof UniFiHttpError && e.status === 422 && /network-does-not-exist/.test(e.message))) throw e;
            await new Promise((r) => setTimeout(r, this.retryDelayMs));
          }
        }
      } catch (e) {
        // Already gone (deleted in UniFi, or by another change): nothing left to undo.
        if (!notFound(e)) throw e;
      }
      return;
    }
    if (op.kind === 'delete') {
      if (!op.before) throw new Error('no copy of the deleted object was recorded');
      await client.request('POST', op.path.replace(/\/[^/]+$/, ''), op.before);
      return;
    }
    if (op.kind === 'update') {
      // Rule ordering only moved our own new rules; deleting them restores the previous order.
      if (isOrdering(op)) return;
      if (op.before === undefined) throw new Error('no previous state recorded');
      const before = op.before as Obj;
      const after = (op.body ?? {}) as Obj;
      let cur: Obj | null;
      try {
        cur = op.objectType === 'setting' ? await this.current(client, op) : unwrap(await client.request('GET', op.path));
      } catch (e) {
        if (notFound(e)) return; // deleted in UniFi since: nothing left to restore
        throw e;
      }
      if (!cur) throw new Error('could not read its current state from UniFi');
      // Revert only what this change set, on top of the current object, and only while those fields still hold the
      // values it set: otherwise undoing would silently overwrite edits made in UniFi since.
      const changed = Object.keys(after).filter((k) => !VOLATILE.has(k) && JSON.stringify(normalize(before[k])) !== JSON.stringify(normalize(after[k])));
      const edited = changed.filter((k) => !contains(cur![k], after[k]));
      if (edited.length) throw new Error(`it was changed in UniFi after this change (${edited.join(', ')}), so undoing it would overwrite those edits`);
      const restore = Object.fromEntries(changed.map((k) => [k, before[k]]));
      const base = op.api === 'integration' ? Object.fromEntries(Object.entries(cur).filter(([k]) => !['id', 'index', 'metadata'].includes(k))) : cur;
      await client.request('PUT', op.path, op.objectType === 'wlan' ? restore : { ...base, ...restore });
    }
  }
}
