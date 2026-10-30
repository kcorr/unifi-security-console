import { useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import clsx from 'clsx';
import {
  ArrowRight, Check, CircleCheck, CircleDashed, CircleX, Code2, GitMerge, ListChecks, LockKeyhole, Plus, ShieldCheck, Sparkles, TriangleAlert, Undo2, Wrench, X,
} from 'lucide-react';
import countries from 'i18n-iso-countries';
import { countryName } from '../lib/format';
import type { ChangePlan, ChangeRecord, FixAction, HardeningTemplate, NetworkSummary, PlanAnalysisItem, TemplateParamSpec } from '@shared/types';
import { NETWORK_ROLES } from '@shared/types';
import { api } from '../lib/api';
import { Badge, Button, Callout, ErrorBox, Modal, Spinner, Toggle } from './ui';
import { hasRuleDetails, RuleDetailsWindow } from './RuleDetails';

const STATUS_META: Record<PlanAnalysisItem['status'], { icon: React.ReactNode; tone: string; label: string }> = {
  'already-covered': { icon: <CircleCheck className="h-4 w-4 text-emerald-400" />, tone: 'text-emerald-300', label: 'Already in place' },
  'will-extend': { icon: <GitMerge className="h-4 w-4 text-cyan-300" />, tone: 'text-cyan-200', label: 'Extend existing rule' },
  'will-create': { icon: <Plus className="h-4 w-4 text-cyan-300" />, tone: 'text-cyan-200', label: 'New rule' },
  'will-update': { icon: <Wrench className="h-4 w-4 text-cyan-300" />, tone: 'text-cyan-200', label: 'Update' },
  conflict: { icon: <TriangleAlert className="h-4 w-4 text-amber-400" />, tone: 'text-amber-200', label: 'Conflict' },
  exception: { icon: <CircleDashed className="h-4 w-4 text-sky-300" />, tone: 'text-sky-200', label: 'Exception kept' },
  skipped: { icon: <CircleX className="h-4 w-4 text-ink-3" />, tone: 'text-ink-3', label: 'Skipped' },
  info: { icon: <Sparkles className="h-4 w-4 text-ink-3" />, tone: 'text-ink-2', label: 'Note' },
};

export function FixFlow({ fix, onClose }: { fix: FixAction | null; onClose: () => void }) {
  const open = !!fix;
  const qc = useQueryClient();
  const templates = useQuery({ queryKey: ['templates'], queryFn: api.templates, enabled: open });
  const firewall = useQuery({ queryKey: ['firewall'], queryFn: api.firewall, enabled: open });
  const template = templates.data?.templates.find((t) => t.id === fix?.templateId) ?? null;
  const readOnly = templates.data?.readOnly ?? false;

  const [params, setParams] = useState<Record<string, unknown>>({});
  const [strategy, setStrategy] = useState<string | undefined>(undefined);
  const [result, setResult] = useState<ChangeRecord | null>(null);
  const [showJson, setShowJson] = useState(false);
  // The fix whose parameters are set up; only then is a plan requested (and a reload after applying keeps the result).
  const [paramsFor, setParamsFor] = useState<FixAction | null>(null);

  useEffect(() => {
    if (!fix) setParamsFor(null);
  }, [fix]);
  useEffect(() => {
    if (!fix || !templates.data || paramsFor === fix) return;
    const next: Record<string, unknown> = { ...fix.params };
    // Test-network mode: rules may only start from the test network, so every fix starts there instead of on the real
    // networks the suggestion named; otherwise the preview could never be applied.
    const testNet = templates.data.writeMode === 'test-network' ? templates.data.testNetwork : null;
    const spec = templates.data.templates.find((t) => t.id === fix.templateId);
    if (testNet && spec?.kind === 'firewall') {
      for (const p of spec.params) {
        if (p.type === 'networks' && (p.key === 'networks' || p.key === 'sources')) next[p.key] = [testNet.id];
        if (p.key === 'zones' && testNet.zoneId) next[p.key] = [testNet.zoneId];
      }
    }
    setParams(next);
    setStrategy(undefined);
    setResult(null);
    setShowJson(false);
    setParamsFor(fix);
  }, [fix, templates.data, paramsFor]);

  const paramKey = JSON.stringify(params);
  const plan = useQuery({
    queryKey: ['plan', fix?.templateId, paramKey, strategy],
    queryFn: () => api.plan(fix!.templateId, params, strategy),
    enabled: open && !!template && !result && paramsFor === fix,
    staleTime: 0,
    gcTime: 0,
    retry: false,
  });

  const apply = useMutation({
    mutationFn: (p: ChangePlan) => api.apply(p.id),
    onSuccess: (rec) => {
      setResult(rec);
      void qc.invalidateQueries();
    },
  });

  const undo = useMutation({
    mutationFn: (id: string) => api.undo(id),
    onSuccess: (rec) => {
      setResult(rec);
      void qc.invalidateQueries();
    },
  });

  const p = plan.data;
  const canApply = !!p && !p.noop && !readOnly && !p.blockedReason && !apply.isPending;

  return (
    <Modal
      open={open}
      onClose={onClose}
      size="lg"
      title={
        <span className="flex items-center gap-2">
          <ShieldCheck className="h-4 w-4 text-cyan-300" />
          {template?.title ?? fix?.label ?? 'Apply fix'}
        </span>
      }
      subtitle={template?.summary}
      footer={
        result ? (
          <>
            {result.undoable && result.status !== 'undone' && (
              <Button variant="ghost" icon={<Undo2 className="h-4 w-4" />} loading={undo.isPending} onClick={() => undo.mutate(result.id)}>
                Undo
              </Button>
            )}
            <Button variant="primary" onClick={onClose}>
              Done
            </Button>
          </>
        ) : p?.noop && p.state !== 'needs-input' && !plan.isFetching ? (
          // Already in place, or can't be done here: nothing to confirm, so just close.
          <Button variant="primary" onClick={onClose}>
            Close
          </Button>
        ) : (
          <>
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button variant="primary" disabled={!canApply} loading={apply.isPending} onClick={() => p && apply.mutate(p)} icon={readOnly || p?.blockedReason ? <LockKeyhole className="h-4 w-4" /> : <Check className="h-4 w-4" />}>
              {readOnly ? 'Read-only mode' : p?.blockedReason ? 'Not allowed in test-network mode' : p?.state === 'needs-input' ? 'Choose what to change' : p?.noop ? 'Nothing to change' : `Apply ${p ? plural(p.operations.length, 'change') : ''}`}
            </Button>
          </>
        )
      }
    >
      {(templates.isLoading || firewall.isLoading) && (
        <div className="flex items-center gap-2 py-6 text-sm text-ink-3">
          <Spinner /> Loading…
        </div>
      )}
      {templates.error && <ErrorBox error={templates.error} />}
      {templates.data && fix && !template && (
        <Callout tone="warn" icon={<CircleX className="h-4 w-4" />} title="This fix isn't available">
          The app doesn't know the action “{fix.templateId}”. Reload the page and try again.
        </Callout>
      )}
      {template && !result && (
        <div className="space-y-5">
          <p className="text-sm leading-relaxed text-ink-2">{template.why}</p>
          {template.params.length > 0 && <ParamEditor template={template} networks={firewall.data?.networks ?? []} params={params} onChange={setParams} analysis={p?.analysis ?? []} />}

          {readOnly && (
            <Callout tone="info" icon={<LockKeyhole className="h-4 w-4" />} title="Preview only — read-only mode">
              Nothing will be sent to UniFi. To apply changes, pick “Test network only” or “Full access” under{' '}
              <Link to="/settings#change-safety" className="underline">
                Settings → Change safety
              </Link>
              .
            </Callout>
          )}
          {p?.blockedReason && (
            <Callout tone="warn" icon={<LockKeyhole className="h-4 w-4" />} title="Not allowed in test-network mode">
              {p.blockedReason}
            </Callout>
          )}
          <div>
            <div className="mb-2 flex items-center justify-between">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-ink-3">What will happen</h3>
              {plan.isFetching && <Spinner />}
            </div>
            {plan.error && <ErrorBox error={plan.error} onRetry={() => void plan.refetch()} />}
            {p && <PlanBody plan={p} strategy={strategy} onStrategy={setStrategy} showJson={showJson} onToggleJson={() => setShowJson((s) => !s)} />}
          </div>

          {template.caveats.length > 0 && (
            <div className="rounded-lg border border-line bg-surface-2/50 p-3 text-xs text-ink-3">
              <div className="mb-1 font-medium text-ink-2">Good to know</div>
              <ul className="ml-4 list-disc space-y-0.5">
                {template.caveats.map((c) => (
                  <li key={c}>{c}</li>
                ))}
              </ul>
            </div>
          )}
          {apply.error && <ErrorBox error={apply.error} />}
        </div>
      )}
      {result && <ApplyResult record={result} />}
    </Modal>
  );
}

function plural(n: number, w: string) {
  return `${n} ${w}${n === 1 ? '' : 's'}`;
}

export function PlanBody({ plan, strategy, onStrategy, showJson, onToggleJson }: { plan: ChangePlan; strategy?: string; onStrategy?: (s: string) => void; showJson: boolean; onToggleJson: () => void }) {
  // undefined: closed; null: open at the top; an operation id: open at that rule.
  const [details, setDetails] = useState<string | null | undefined>(undefined);
  return (
    <div className="space-y-3">
      <RuleDetailsWindow ops={plan.operations} open={details !== undefined} focus={details ?? null} onClose={() => setDetails(undefined)} />
      {plan.noop && plan.state === 'needs-input' ? (
        <Callout tone="info" icon={<Sparkles className="h-4 w-4" />}>
          {plan.summary}
        </Callout>
      ) : plan.noop && plan.state === 'unavailable' ? (
        <Callout tone="warn" icon={<CircleX className="h-4 w-4" />} title="This can't be done here">
          {plan.summary}
        </Callout>
      ) : plan.noop ? (
        <Callout tone="success" icon={<CircleCheck className="h-4 w-4" />} title="Already in place — nothing to change">
          {plan.summary} Changes made with this app can be undone from the{' '}
          <Link to="/activity" className="underline">
            Change Log
          </Link>
          .
        </Callout>
      ) : (
        <p className="text-sm text-ink">{plan.summary}</p>
      )}

      {plan.analysis.length > 0 && (
        <ul className="divide-y divide-line/60 rounded-lg border border-line bg-surface-2/40">
          {plan.analysis.map((a, i) => {
            const meta = STATUS_META[a.status];
            return (
              <li key={i} className="flex items-start gap-3 px-3 py-2.5">
                <div className="mt-0.5">{meta.icon}</div>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-sm font-medium text-ink">{a.target}</span>
                    <span className={clsx('text-xs', meta.tone)}>{meta.label}</span>
                  </div>
                  <div className="mt-0.5 text-xs leading-relaxed text-ink-2">{a.message}</div>
                  {a.rules.length > 0 && (
                    <div className="mt-1.5 flex flex-wrap gap-1">
                      {a.rules.map((r) => (
                        <Link key={r.id} to={`/firewall/rules?rule=${encodeURIComponent(r.id)}`} className="rounded bg-surface-3 px-1.5 py-0.5 text-[11px] text-ink-2 hover:text-cyan-200">
                          {r.name}
                        </Link>
                      ))}
                    </div>
                  )}
                </div>
              </li>
            );
          })}
        </ul>
      )}

      {plan.alternatives.length > 0 && onStrategy && (
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <span className="text-ink-3">Strategy:</span>
          {plan.alternatives.map((alt) => (
            <button
              key={alt.strategy}
              title={alt.description}
              aria-pressed={(strategy ?? plan.strategy) === alt.strategy}
              onClick={() => onStrategy(alt.strategy)}
              className={clsx(
                'rounded-md border px-2 py-1 transition-colors',
                (strategy ?? plan.strategy) === alt.strategy ? 'border-cyan-500/50 bg-cyan-500/10 text-cyan-200' : 'border-line text-ink-2 hover:bg-surface-3',
              )}
            >
              {alt.label}
            </button>
          ))}
        </div>
      )}

      {plan.warnings.map((w) => (
        <Callout key={w} tone="warn" icon={<TriangleAlert className="h-4 w-4" />}>
          {w}
        </Callout>
      ))}

      {plan.operations.length > 0 && (
        <div className="rounded-lg border border-line">
          <div className="flex items-center justify-between border-b border-line px-3 py-2">
            <span className="text-xs font-semibold uppercase tracking-wider text-ink-3">Changes sent to UniFi</span>
            <span className="flex items-center gap-3">
              {hasRuleDetails(plan.operations) && (
                <button type="button" onClick={() => setDetails(null)} className="inline-flex items-center gap-1 text-xs font-medium text-cyan-300 hover:text-cyan-200">
                  <ListChecks className="h-3.5 w-3.5" /> See the rules in detail
                </button>
              )}
              <button onClick={onToggleJson} className="inline-flex items-center gap-1 text-xs text-ink-3 hover:text-cyan-200">
                <Code2 className="h-3.5 w-3.5" /> {showJson ? 'Hide' : 'Show'} API calls
              </button>
            </span>
          </div>
          <ol className="divide-y divide-line/60">
            {plan.operations.map((op, i) => (
              <li key={op.id} className="px-3 py-2.5">
                <div className="flex items-start gap-2">
                  <span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-surface-3 text-[11px] text-ink-2">{i + 1}</span>
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2 text-sm text-ink">
                      <Badge tone={op.kind === 'create' ? 'cyan' : op.kind === 'delete' ? 'red' : 'violet'}>{op.kind}</Badge>
                      {op.description}
                      {(op.detail || op.order) && (
                        <button type="button" onClick={() => setDetails(op.id)} className="text-xs text-cyan-300 hover:text-cyan-200">
                          Details →
                        </button>
                      )}
                    </div>
                    {op.sentence && <div className="mt-1 text-xs text-ink-2">“{op.sentence}”</div>}
                    {showJson && (
                      <pre className="mono mt-2 max-h-64 overflow-auto rounded-md bg-black/40 p-2 text-[11px] leading-relaxed text-slate-300">
                        {`${op.method} ${op.path}\n`}
                        {op.body !== undefined ? JSON.stringify(op.body, null, 2) : ''}
                      </pre>
                    )}
                  </div>
                </div>
              </li>
            ))}
          </ol>
        </div>
      )}
    </div>
  );
}

function ApplyResult({ record }: { record: ChangeRecord }) {
  const ok = record.status === 'applied';
  return (
    <div className="space-y-3">
      {record.status === 'undone' ? (
        <Callout tone="info" icon={<Undo2 className="h-4 w-4" />} title="Change undone">
          Everything this change created or modified was rolled back.
        </Callout>
      ) : ok ? (
        <Callout tone="success" icon={<CircleCheck className="h-4 w-4" />} title="Applied successfully">
          {record.summary} You can undo this at any time from the <Link to="/activity" className="underline">Change Log</Link>.
        </Callout>
      ) : (
        <Callout tone="danger" icon={<CircleX className="h-4 w-4" />} title={record.status === 'partial' ? 'Partially applied' : 'Failed'}>
          {record.error ?? 'Some operations failed.'} {record.status === 'partial' && 'Successful operations can be undone from the Change Log.'}
        </Callout>
      )}
      <ul className="space-y-1.5 text-sm">
        {record.operations.map((op) => (
          <li key={op.id} className="flex items-start gap-2">
            {op.status === 'ok' ? (
              <CircleCheck className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400" />
            ) : op.status === 'undone' ? (
              <Undo2 className="mt-0.5 h-4 w-4 shrink-0 text-sky-300" />
            ) : op.status === 'skipped' ? (
              <CircleDashed className="mt-0.5 h-4 w-4 shrink-0 text-ink-3" />
            ) : (
              <CircleX className="mt-0.5 h-4 w-4 shrink-0 text-rose-400" />
            )}
            <div>
              <div className="text-ink">{op.description}</div>
              {op.error && <div className="text-xs text-rose-300">{op.error}</div>}
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}

// ---------------------------------------------------------------------------------
// Parameter editor
// ---------------------------------------------------------------------------------

function ParamEditor(props: { template: HardeningTemplate; networks: NetworkSummary[]; params: Record<string, unknown>; onChange: (p: Record<string, unknown>) => void; analysis: PlanAnalysisItem[] }) {
  const { template, networks, params, onChange } = props;
  const [showAdvanced, setShowAdvanced] = useState(false);
  const set = (k: string, v: unknown) => onChange({ ...params, [k]: v });
  const visible = template.params.filter((s) => s.type !== 'text' || s.key !== 'portForwardId');
  const hasAdvanced = visible.some((s) => s.advanced);
  return (
    <div className="space-y-4 rounded-xl border border-line bg-surface-2/30 p-4">
      {visible
        .filter((s) => showAdvanced || !s.advanced)
        .map((spec) => (
          <ParamField key={spec.key} spec={spec} value={params[spec.key] ?? spec.default} onChange={(v) => set(spec.key, v)} networks={networks} analysis={props.analysis} />
        ))}
      {hasAdvanced && (
        <button className="text-xs text-ink-3 hover:text-cyan-200" onClick={() => setShowAdvanced((s) => !s)}>
          {showAdvanced ? 'Hide' : 'Show'} advanced options
        </button>
      )}
    </div>
  );
}

function ParamField({ spec, value, onChange, networks, analysis }: { spec: TemplateParamSpec; value: unknown; onChange: (v: unknown) => void; networks: NetworkSummary[]; analysis: PlanAnalysisItem[] }) {
  const label = (
    <div className="mb-1.5">
      <div className="text-xs font-medium text-ink-2">{spec.label}</div>
      {spec.help && <div className="text-[11px] text-ink-3">{spec.help}</div>}
    </div>
  );
  if (spec.type === 'networks') {
    const selected = new Set(Array.isArray(value) ? (value as string[]) : []);
    const status = new Map(analysis.map((a) => [a.target, a.status]));
    return (
      <div>
        {label}
        <div className="flex flex-wrap gap-1.5">
          {networks.map((n) => {
            const on = selected.has(n.id);
            const st = status.get(n.name);
            return (
              <button
                key={n.id}
                type="button"
                aria-pressed={on}
                onClick={() => {
                  const next = new Set(selected);
                  if (on) next.delete(n.id);
                  else next.add(n.id);
                  onChange([...next]);
                }}
                className={clsx(
                  'inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-xs transition-colors',
                  on ? 'border-cyan-500/50 bg-cyan-500/10 text-ink' : 'border-line bg-surface-2 text-ink-3 hover:text-ink-2',
                )}
              >
                <span className={clsx('flex h-3.5 w-3.5 items-center justify-center rounded border', on ? 'border-cyan-400 bg-cyan-400 text-slate-950' : 'border-slate-600')}>
                  {on && <Check className="h-2.5 w-2.5" />}
                </span>
                <span className="font-medium">{n.name}</span>
                {n.isTest && <span className="rounded bg-violet-500/20 px-1 text-[10px] font-semibold text-violet-200">TEST</span>}
                {n.vlan !== null && <span className="text-ink-3">VLAN {n.vlan}</span>}
                <span className="text-[10px] uppercase tracking-wide text-ink-3">{NETWORK_ROLES.find((r) => r.value === n.role)?.label}</span>
                {on && st === 'already-covered' && <CircleCheck className="h-3.5 w-3.5 text-emerald-400" />}
              </button>
            );
          })}
        </div>
      </div>
    );
  }
  if (spec.type === 'boolean') {
    return <Toggle checked={value === undefined ? !!spec.default : !!value} onChange={onChange} label={spec.label} description={spec.help} />;
  }
  if (spec.type === 'select') {
    const multi = Array.isArray(spec.default);
    if (multi) {
      const sel = new Set(Array.isArray(value) ? (value as string[]) : []);
      return (
        <div>
          {label}
          <div className="grid gap-1.5 sm:grid-cols-2">
            {spec.options?.map((o) => (
              <label key={o.value} className="flex cursor-pointer items-center gap-2 rounded-lg border border-line bg-surface-2 px-2.5 py-1.5 text-xs text-ink-2">
                <input
                  type="checkbox"
                  className="accent-cyan-400"
                  checked={sel.has(o.value)}
                  onChange={() => {
                    const next = new Set(sel);
                    if (next.has(o.value)) next.delete(o.value);
                    else next.add(o.value);
                    onChange([...next]);
                  }}
                />
                {o.label}
              </label>
            ))}
          </div>
        </div>
      );
    }
    return (
      <div>
        {label}
        <div className="flex flex-wrap gap-1.5">
          {spec.options?.map((o) => (
            <button
              key={o.value}
              type="button"
              onClick={() => onChange(o.value)}
              className={clsx('rounded-lg border px-2.5 py-1.5 text-xs', value === o.value ? 'border-cyan-500/50 bg-cyan-500/10 text-ink' : 'border-line bg-surface-2 text-ink-3 hover:text-ink-2')}
            >
              {o.label}
            </button>
          ))}
        </div>
      </div>
    );
  }
  if (spec.type === 'ips') {
    return <ListInput label={label} value={Array.isArray(value) ? (value as string[]) : []} onChange={onChange} placeholder="e.g. 192.168.1.5, 203.0.113.0/24" />;
  }
  if (spec.type === 'countries') {
    return <CountryPicker label={label} value={Array.isArray(value) ? (value as string[]) : []} onChange={onChange} />;
  }
  return (
    <div>
      {label}
      <input
        value={typeof value === 'string' ? value : value === undefined || value === null ? '' : String(value)}
        onChange={(e) => onChange(e.target.value)}
        className="h-9 w-full rounded-lg border border-line-2 bg-surface-2 px-3 text-sm text-ink focus:border-cyan-500/60 focus:outline-none"
      />
    </div>
  );
}

const ALL_COUNTRIES = Object.keys(countries.getAlpha2Codes())
  .map((code) => ({ code, name: countryName(code) }))
  .sort((a, b) => a.name.localeCompare(b.name));

/** Search-and-pick list of countries, with the countries recent attacks came from as quick picks. */
function CountryPicker({ label, value, onChange }: { label: React.ReactNode; value: string[]; onChange: (v: unknown) => void }) {
  const [q, setQ] = useState('');
  const seen = useQuery({ queryKey: ['threat-summary', '7d'], queryFn: () => api.threatSummary({ from: Date.now() - 7 * 86400e3 }), staleTime: 60_000 });
  const selected = new Set(value);
  const toggle = (code: string) => onChange(selected.has(code) ? value.filter((c) => c !== code) : [...value, code]);
  const ql = q.trim().toLowerCase();
  const matches = ql ? ALL_COUNTRIES.filter((c) => c.name.toLowerCase().includes(ql) || c.code.toLowerCase() === ql).slice(0, 10) : [];
  const recent = (seen.data?.byCountry ?? []).filter((c) => !selected.has(c.country)).slice(0, 6);
  const chip = 'inline-flex items-center gap-1 rounded-lg border px-2 py-1 text-xs transition-colors';
  return (
    <div>
      {label}
      {value.length > 0 && (
        <div className="mb-2 flex flex-wrap gap-1.5">
          {value.map((code) => (
            <button key={code} type="button" title="Remove" onClick={() => toggle(code)} className={clsx(chip, 'border-cyan-500/50 bg-cyan-500/10 text-ink')}>
              {countryName(code)} <span className="text-ink-3">{code}</span> <X className="h-3 w-3" />
            </button>
          ))}
        </div>
      )}
      <input
        value={q}
        onChange={(e) => setQ(e.target.value)}
        placeholder="Search for a country…"
        aria-label="Search for a country"
        className="h-9 w-full rounded-lg border border-line-2 bg-surface-2 px-3 text-sm text-ink placeholder:text-ink-3 focus:border-cyan-500/60 focus:outline-none"
      />
      {matches.length > 0 && (
        <div className="mt-1.5 flex flex-wrap gap-1.5">
          {matches.map((c) => (
            <button
              key={c.code}
              type="button"
              onClick={() => {
                toggle(c.code);
                setQ('');
              }}
              className={clsx(chip, selected.has(c.code) ? 'border-cyan-500/50 bg-cyan-500/10 text-ink' : 'border-line bg-surface-2 text-ink-2 hover:text-ink')}
            >
              {c.name}
            </button>
          ))}
        </div>
      )}
      {!ql && recent.length > 0 && (
        <div className="mt-2 text-[11px] text-ink-3">
          Attacks in the last 7 days came from:{' '}
          {recent.map((c) => (
            <button key={c.country} type="button" onClick={() => toggle(c.country)} className="mr-2 text-cyan-300 hover:text-cyan-200">
              {countryName(c.country)} ({c.count})
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

function ListInput({ label, value, onChange, placeholder }: { label: React.ReactNode; value: string[]; onChange: (v: string[]) => void; placeholder?: string }) {
  const [text, setText] = useState(value.join(', '));
  useEffect(() => setText(value.join(', ')), [value.join(',')]); // eslint-disable-line react-hooks/exhaustive-deps
  const commit = () =>
    onChange(
      text
        .split(/[\s,;]+/)
        .map((s) => s.trim())
        .filter(Boolean),
    );
  return (
    <div>
      {label}
      <input
        value={text}
        placeholder={placeholder}
        onChange={(e) => setText(e.target.value)}
        onBlur={commit}
        onKeyDown={(e) => e.key === 'Enter' && commit()}
        className="mono h-9 w-full rounded-lg border border-line-2 bg-surface-2 px-3 text-sm text-ink placeholder:text-ink-3 focus:border-cyan-500/60 focus:outline-none"
      />
    </div>
  );
}

/** `onClosed` runs when the preview is closed (cancelled or done), e.g. to return to the list it was opened from. */
export function useFix(onClosed?: () => void) {
  const [fix, setFix] = useState<FixAction | null>(null);
  const closed = useRef(onClosed);
  closed.current = onClosed;
  const node = useMemo(
    () => (
      <FixFlow
        fix={fix}
        onClose={() => {
          setFix(null);
          closed.current?.();
        }}
      />
    ),
    [fix],
  );
  return { open: setFix, node };
}

export function FixButton({ fix, onOpen, size = 'sm', variant = 'primary' }: { fix: FixAction; onOpen: (f: FixAction) => void; size?: 'xs' | 'sm' | 'md'; variant?: 'primary' | 'secondary' }) {
  return (
    <Button size={size} variant={variant} icon={<ArrowRight className="h-3.5 w-3.5" />} onClick={() => onOpen(fix)}>
      {fix.label}
    </Button>
  );
}
