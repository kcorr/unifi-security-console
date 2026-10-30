import { useEffect, useState } from 'react';
import { useLocation, useNavigate, useSearchParams } from 'react-router';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import clsx from 'clsx';
import {
  CircleCheck, CircleX, Database, FlaskConical, Globe, KeyRound, Layers, LockKeyhole, LogOut, Pencil, Plus, PlugZap, Settings as SettingsIcon, ShieldCheck, Stethoscope, Trash2,
  UserRound,
} from 'lucide-react';
import { PASSWORD_MIN_LENGTH, TEST_NETWORK_PREFIX, type CertInfo, type CloudConsole, type EnvInput, type EnvSummary, type EnvTestResult, type IntelProviderSettings, type SettingsUpdate, type SettingsView, type TlsPin, type WriteMode } from '@shared/types';
import { api } from '../lib/api';
import { timeAgo } from '../lib/format';
import { setEnv, useEnv } from '../lib/env';
import { Badge, Button, Callout, Card, ErrorBox, Loading, PageHeader, Segmented, TextInput, Toggle } from '../components/ui';
import { useSignOut } from '../components/TopNav';

/** Consoles added through unifi.ui.com are reached via its connector address. */
const isCloud = (url: string | null | undefined) => !!url && url.startsWith('https://api.ui.com/v1/connector/consoles/');

/** The server only reuses a saved key for the same scheme, host and port. */
function sameAddress(a: string | null | undefined, b: string | null | undefined): boolean {
  try {
    return new URL(a ?? '').origin === new URL(b ?? '').origin;
  } catch {
    return false;
  }
}

const SECTIONS = [
  ['environments', 'Environments'],
  ['change-safety', 'Change safety'],
  ['intel', 'IP intelligence'],
  ['data', 'Data'],
  ['account', 'Account'],
  ['diagnostics', 'Diagnostics'],
] as const;

const COLORS = ['#22d3ee', '#a78bfa', '#34d399', '#f59e0b', '#f472b6', '#60a5fa', '#fb7185', '#a3e635'];

export function SettingsPage() {
  const [sp] = useSearchParams();
  const qc = useQueryClient();
  const settings = useQuery({ queryKey: ['settings'], queryFn: api.settings });
  const status = useQuery({ queryKey: ['status'], queryFn: api.status });
  const save = useMutation({ mutationFn: (u: SettingsUpdate) => api.saveSettings(u), onSuccess: () => void qc.invalidateQueries() });
  const envs = status.data?.environments ?? [];
  const setup = sp.get('setup') === '1' || (!!status.data && envs.length === 0);
  const envId = useEnv();
  const current = envs.find((e) => e.id === envId) ?? envs[0] ?? null;
  const loading = settings.isLoading || status.isLoading;
  // Links such as /settings#intel land on that section once it has rendered.
  const { hash } = useLocation();
  useEffect(() => {
    if (!hash || loading) return;
    const t = setTimeout(() => document.getElementById(decodeURIComponent(hash.slice(1)))?.scrollIntoView({ block: 'start' }), 50);
    return () => clearTimeout(t);
  }, [hash, loading]);

  if (loading) return <Loading />;
  const s = settings.data;

  return (
    <div className="space-y-5">
      <PageHeader
        icon={<SettingsIcon className="h-5 w-5" />}
        title={setup ? 'Connect your UniFi network' : 'Settings'}
        subtitle={setup ? 'Two minutes: create an API key in UniFi, paste it here, done. Nothing leaves your machine except calls to your own console.' : 'Environments, change safety, IP intelligence and diagnostics.'}
      />

      {!setup && (
        <nav aria-label="Settings sections" className="flex flex-wrap gap-1.5 text-xs">
          {SECTIONS.map(([id, label]) => (
            <a key={id} href={`#${id}`} className="rounded-md border border-line bg-surface-2 px-2.5 py-1 text-ink-2 hover:border-cyan-500/40 hover:text-cyan-200">
              {label}
            </a>
          ))}
        </nav>
      )}
      {setup && <SetupIntro />}
      <EnvironmentsCard envs={envs} currentId={current?.id ?? null} setup={setup} />

      {!setup && current && <ChangeSafety env={current} />}
      {!setup && s && <IntelSettings s={s} onSave={(u) => save.mutate(u)} />}
      {!setup && s && (
        <Card id="data" title="Data">
          <div className="flex flex-wrap items-end gap-3">
            <RetentionField days={s.threatRetentionDays} onSave={(d, done) => save.mutate({ threatRetentionDays: d }, { onSuccess: done })} />
            <p className="pb-2 text-xs text-ink-3">Threats are stored locally per environment, so history survives controller log rotation.</p>
          </div>
        </Card>
      )}
      {!setup && status.data?.username && <AccountCard username={status.data.username} />}
      {!setup && current && <Diagnostics env={current} />}
    </div>
  );
}

function AccountCard({ username }: { username: string }) {
  const qc = useQueryClient();
  const signOut = useSignOut();
  const [name, setName] = useState(username);
  const [next, setNext] = useState('');
  const [repeat, setRepeat] = useState('');
  const [current, setCurrent] = useState('');
  const save = useMutation({
    mutationFn: () => api.updateAccount({ currentPassword: current, username: name.trim() === username ? undefined : name, newPassword: next || undefined }),
    onSuccess: (r) => {
      setName(r.username);
      setNext('');
      setRepeat('');
      setCurrent('');
      void qc.invalidateQueries({ queryKey: ['status'] });
    },
  });
  const changed = name.trim() !== username || next !== '';
  const mismatch = next !== '' && repeat !== next;

  return (
    <Card
      id="account"
      title="Account"
      icon={<UserRound className="h-4 w-4" />}
      subtitle="The username and password that protect this dashboard. Saving a change signs out every other browser; this one stays signed in."
      actions={
        <Button size="sm" variant="ghost" icon={<LogOut className="h-3.5 w-3.5" />} onClick={() => void signOut()}>
          Sign out
        </Button>
      }
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          save.mutate();
        }}
        onChange={() => save.reset()}
        className="grid max-w-3xl gap-3 sm:grid-cols-2"
      >
        <TextInput label="Username" autoComplete="username" autoCapitalize="none" spellCheck={false} required value={name} onChange={(e) => setName(e.target.value)} />
        <TextInput label="Current password" type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} hint="Needed to save any change." />
        <TextInput
          label="New password"
          type="password"
          autoComplete="new-password"
          minLength={PASSWORD_MIN_LENGTH}
          value={next}
          onChange={(e) => setNext(e.target.value)}
          hint={`Leave empty to keep your password. At least ${PASSWORD_MIN_LENGTH} characters.`}
        />
        <TextInput
          label="Repeat new password"
          type="password"
          autoComplete="new-password"
          value={repeat}
          onChange={(e) => setRepeat(e.target.value)}
          hint={mismatch && repeat !== '' ? <span className="text-rose-300">The two new passwords are different.</span> : undefined}
        />
        <div className="flex flex-wrap items-center gap-3 sm:col-span-2">
          <Button type="submit" variant="primary" loading={save.isPending} disabled={!changed || !current || mismatch}>
            Save changes
          </Button>
          {save.isSuccess && (
            <span className="flex items-center gap-1.5 text-xs text-emerald-300">
              <CircleCheck className="h-3.5 w-3.5" /> Saved. Other browsers were signed out.
            </span>
          )}
        </div>
      </form>
      {save.error && (
        <div className="mt-3">
          <ErrorBox error={save.error} />
        </div>
      )}
    </Card>
  );
}

/** Short form of a fingerprint for a line of text; the full one is in the tooltip. */
const shortPrint = (sha256: string) => `${sha256.split(':').slice(0, 6).join(':')}…`;

function TlsLine({ tls }: { tls: NonNullable<EnvSummary['tls']> }) {
  if (tls.mode === 'plain') return <div className="mt-0.5 text-xs text-amber-300">Not encrypted (http): the API key travels in the clear. Use https if the console supports it.</div>;
  if (tls.mode === 'ca') return <div className="mt-0.5 text-xs text-ink-3">Certificate checked by a certificate authority.</div>;
  if (tls.mode === 'pending') return <div className="mt-0.5 text-xs text-ink-3">The console's certificate is trusted at the next connection.</div>;
  return (
    <div className="mt-0.5 flex items-center gap-1 text-xs text-ink-3" title={`SHA-256 ${tls.pin?.sha256}\nIssued to ${tls.pin?.subject}\nValid until ${tls.pin?.validTo}`}>
      <LockKeyhole className="h-3 w-3 shrink-0 text-emerald-400" />
      <span className="truncate">
        Certificate pinned{tls.pin ? ` · ${shortPrint(tls.pin.sha256)} · trusted ${timeAgo(tls.pin.pinnedAt)}` : ''}
      </span>
    </div>
  );
}

/** The console presented another certificate: nothing is sent until the owner checks it and trusts it. */
function CertChanged({ env }: { env: EnvSummary }) {
  const qc = useQueryClient();
  const tls = env.tls!;
  const trust = useMutation({ mutationFn: () => api.trustCert(env.id, tls.mismatch!.spki), onSuccess: () => void qc.invalidateQueries() });
  return (
    <div className="mt-2 rounded-lg border border-rose-500/40 bg-rose-500/5 p-3 text-xs leading-relaxed text-ink-2">
      <div className="mb-1 font-medium text-rose-200">The console's certificate changed, so the app stopped connecting</div>
      If you replaced the console's certificate, reset the console or changed its address, trust the new one. If not, someone may be intercepting the connection: don't trust it.
      <dl className="mt-2 space-y-0.5">
        <div>
          <dt className="inline text-ink-3">Trusted: </dt>
          <dd className="mono inline break-all text-[11px]">{tls.pin?.sha256}</dd>
        </div>
        <div>
          <dt className="inline text-ink-3">Now: </dt>
          <dd className="mono inline break-all text-[11px]">{tls.mismatch!.sha256}</dd>
        </div>
      </dl>
      <div className="mt-2">
        <Button size="xs" variant="secondary" loading={trust.isPending} onClick={() => confirm('Trust the new certificate? Do this only if you know why it changed.') && trust.mutate()}>
          Trust the new certificate
        </Button>
      </div>
      {trust.error && <ErrorBox error={trust.error} />}
    </div>
  );
}

/** The certificate a self-signed console presented during the test, before saving trusts it. */
function CertCheck({ cert, changed, trusted }: { cert: CertInfo; changed: boolean; trusted: TlsPin | null }) {
  return (
    <Callout tone={changed ? 'warn' : 'info'} icon={<LockKeyhole className="h-4 w-4" />} title={changed ? 'This is not the certificate you trusted before' : "The console's certificate"}>
      <p>
        {changed
          ? `You trusted a different certificate ${trusted ? timeAgo(trusted.pinnedAt) : 'before'}. Save only if you replaced the console's certificate or reset the console; saving trusts this one instead.`
          : `${cert.selfSigned ? 'Self-signed' : `Issued by ${cert.issuer}`}, for ${cert.subject}. Saving trusts only this certificate for this console; the app refuses any other one afterwards.`}
      </p>
      <p className="mono mt-1.5 break-all text-[11px] text-ink-2">SHA-256 {cert.sha256}</p>
      <p className="mt-1 text-[11px] text-ink-3">To double-check, open the console in your browser and compare this with the certificate fingerprint it shows.</p>
    </Callout>
  );
}

/** Out-of-range values snap to 1–365, and the field says what was actually saved. */
function RetentionField({ days, onSave }: { days: number; onSave: (days: number, done: () => void) => void }) {
  const [value, setValue] = useState(String(days));
  const [note, setNote] = useState<string | null>(null);
  const commit = () => {
    const typed = Math.round(Number(value));
    const v = Number.isFinite(typed) && value.trim() !== '' ? Math.min(365, Math.max(1, typed)) : days;
    setValue(String(v));
    const adjusted = v !== typed ? `Set to ${v} days: the range is 1 to 365.` : null;
    if (v === days) return setNote(adjusted);
    onSave(v, () => setNote(adjusted ?? 'Saved.'));
  };
  return (
    <TextInput
      label="Keep threat history for (days)"
      type="number"
      min={1}
      max={365}
      value={value}
      onChange={(e) => setValue(e.target.value)}
      onBlur={commit}
      onKeyDown={(e) => e.key === 'Enter' && commit()}
      hint={note ?? undefined}
      className="w-32"
    />
  );
}

function SetupIntro() {
  return (
    <Card title="1 · Create an API key in UniFi" icon={<KeyRound className="h-4 w-4" />}>
        <ol className="ml-4 list-decimal space-y-2 text-sm leading-relaxed text-ink-2">
          <li>Open your UniFi Network application (your console's web UI).</li>
          <li>
            Go to <strong className="text-ink">Settings → Control Plane → Integrations</strong>.
          </li>
          <li>
            Click <strong className="text-ink">Create API Key</strong>, give it a name (e.g. “Security Console”) and copy the key — it is shown only once.
          </li>
          <li>
            The key has the permissions of the admin who creates it. Every environment starts <strong className="text-ink">read-only</strong> — nothing is changed until you choose a different “Change safety” level.
          </li>
        </ol>
        <p className="mt-3 text-xs text-ink-3">Requires a UniFi OS console (UDM, UCG, UDR, UX, Cloud Key Gen2+) or UniFi OS Server with Network 9.0 or newer. The classic self-hosted Network application does not support API keys.</p>
    </Card>
  );
}

// ---------------------------------------------------------------------------------
// Environments
// ---------------------------------------------------------------------------------

function EnvironmentsCard({ envs, currentId, setup }: { envs: EnvSummary[]; currentId: string | null; setup: boolean }) {
  const qc = useQueryClient();
  const [editing, setEditing] = useState<string | 'new' | null>(setup && envs.length === 0 ? 'new' : null);
  const remove = useMutation({ mutationFn: (id: string) => api.removeEnvironment(id), onSuccess: () => void qc.invalidateQueries() });

  return (
    <Card
      id="environments"
      title={setup ? '2 · Connect' : 'Environments'}
      icon={setup ? <PlugZap className="h-4 w-4" /> : <Layers className="h-4 w-4" />}
      subtitle={setup ? undefined : 'Each environment is one UniFi site with its own API key and change-safety level. Switch between them from the top bar.'}
      actions={
        !setup && (
          <Button size="sm" variant="primary" icon={<Plus className="h-3.5 w-3.5" />} onClick={() => setEditing('new')}>
            Add environment
          </Button>
        )
      }
      padded={false}
    >
      {envs.length > 0 && (
        <ul className="divide-y divide-line/60">
          {envs.map((e) =>
            editing === e.id ? (
              <li key={e.id} className="p-4">
                <EnvForm initial={e} onDone={() => setEditing(null)} />
              </li>
            ) : (
              <li key={e.id} className="flex flex-wrap items-center gap-3 px-4 py-3">
                <span className="h-3 w-3 shrink-0 rounded-full" style={{ background: e.color }} />
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-medium text-ink">{e.name}</span>
                    {e.id === currentId && <Badge tone="cyan">viewing</Badge>}
                    {e.connected ? <Badge tone="green">connected</Badge> : <Badge tone="red">{e.lastError ? 'cannot connect' : 'connecting'}</Badge>}
                    <Badge tone="slate">{e.effectiveWriteMode === 'read-only' ? 'read-only' : e.effectiveWriteMode === 'test-network' ? 'test network only' : 'full access'}</Badge>
                  </div>
                  <div className="truncate text-xs text-ink-3">
                    {`${isCloud(e.url) ? 'Through unifi.ui.com' : e.url} · site “${e.site}”`}
                    {e.version ? ` · Network ${e.version}` : ''}
                    {e.apiKeyHint ? ` · key ${e.apiKeyHint}` : ''}
                  </div>
                  {e.tls && <TlsLine tls={e.tls} />}
                  {!e.connected && e.lastError && !e.tls?.mismatch && <div className="mt-0.5 text-xs text-rose-300">{e.lastError}</div>}
                  {e.tls?.mismatch && <CertChanged env={e} />}
                </div>
                <div className="flex shrink-0 gap-1.5">
                  {e.id !== currentId && (
                    <Button size="xs" variant="secondary" onClick={() => setEnv(e.id)}>
                      View
                    </Button>
                  )}
                  <Button size="xs" variant="ghost" icon={<Pencil className="h-3 w-3" />} onClick={() => setEditing(e.id)}>
                    Edit
                  </Button>
                  <Button
                    size="xs"
                    variant="ghost"
                    icon={<Trash2 className="h-3 w-3" />}
                    loading={remove.isPending && remove.variables === e.id}
                    onClick={() => confirm(`Remove “${e.name}”? Its locally stored threat history and change log are deleted. Nothing is changed on the controller.`) && remove.mutate(e.id)}
                  >
                    Remove
                  </Button>
                </div>
              </li>
            ),
          )}
        </ul>
      )}
      {editing === 'new' && (
        <div className={clsx('p-4', envs.length > 0 && 'border-t border-line')}>
          <EnvForm onDone={() => setEditing(null)} first={envs.length === 0} />
        </div>
      )}
      {remove.error && (
        <div className="p-4">
          <ErrorBox error={remove.error} />
        </div>
      )}
    </Card>
  );
}

function EnvForm({ initial, onDone, first }: { initial?: EnvSummary; onDone: () => void; first?: boolean }) {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [form, setForm] = useState<EnvInput>({
    name: initial?.name ?? (first ? 'Main' : ''),
    url: initial?.url ?? '',
    site: initial?.site ?? 'default',
    verifyTls: initial?.verifyTls ?? false,
    color: initial?.color ?? COLORS[Math.floor(Math.random() * COLORS.length)],
    writeMode: initial?.writeMode ?? 'read-only',
  });
  const [apiKey, setApiKey] = useState('');
  const [pickedSites, setPickedSites] = useState<string[]>([]);
  // Local: the console's own address and a key from its Integrations page. Cloud: a unifi.ui.com key and a picked console.
  const [via, setVia] = useState<'local' | 'cloud'>(isCloud(initial?.url) ? 'cloud' : 'local');
  const test = useMutation({
    mutationFn: () => api.testEnvironment({ ...form, ...(apiKey ? { apiKey } : {}), id: initial?.id }),
    onSuccess: (r: EnvTestResult) => setPickedSites(r.sites.length > 1 ? [form.site ?? 'default'] : []),
  });
  const save = useMutation({
    mutationFn: async () => {
      const body = { ...form, ...(apiKey ? { apiKey } : {}), ...(test.data?.cert && !form.verifyTls ? { trustCert: test.data.cert.spki } : {}) };
      if (initial) return [await api.updateEnvironment(initial.id, body)];
      const sites = test.data?.sites ?? [];
      if (pickedSites.length > 1) {
        const created: EnvSummary[] = [];
        for (const ref of pickedSites) {
          const site = sites.find((x) => x.internalReference === ref);
          created.push(await api.addEnvironment({ ...body, site: ref, name: `${form.name || 'UniFi'} · ${site?.name ?? ref}`, color: COLORS[(COLORS.indexOf(form.color ?? '') + created.length + 1) % COLORS.length] }));
        }
        return created;
      }
      return [await api.addEnvironment({ ...body, site: pickedSites[0] ?? form.site })];
    },
    onSuccess: async (created) => {
      if (!initial && created[0]) setEnv(created[0].id);
      await qc.invalidateQueries();
      onDone();
      if (first) navigate('/');
    },
  });
  const set = (p: Partial<EnvInput>) => setForm((f) => ({ ...f, ...p }));
  const sites = test.data?.sites ?? [];

  return (
    <div className="space-y-4">
      <div>
        <span className="mb-1 block text-xs font-medium text-ink-2">Connect through</span>
        <Segmented
          value={via}
          onChange={(v) => {
            setVia(v);
            set({ url: v === 'cloud' ? '' : isCloud(form.url) ? '' : form.url });
            test.reset();
          }}
          options={[
            { value: 'local', label: 'Local address' },
            { value: 'cloud', label: 'Through unifi.ui.com' },
          ]}
        />
        <span className="mt-1 block text-xs text-ink-3">
          {via === 'local' ? 'This app talks to the console directly, e.g. on your LAN or over a VPN.' : 'For consoles you can’t reach directly. Requests are relayed by Ubiquiti’s cloud, which limits how often the app can refresh.'}
        </span>
      </div>
      <div className="grid gap-4 md:grid-cols-2 [&>*]:min-w-0">
        <TextInput label="Name" placeholder="e.g. Home, Office, Mom's house" value={form.name ?? ''} onChange={(e) => set({ name: e.target.value })} />
        <div>
          <span className="mb-1 block text-xs font-medium text-ink-2">Color</span>
          <div className="flex h-9 items-center gap-2">
            {COLORS.map((c) => (
              <button key={c} type="button" aria-label={`Color ${c}`} onClick={() => set({ color: c })} className={clsx('h-6 w-6 rounded-full ring-offset-2 ring-offset-[#0c1220]', form.color === c && 'ring-2 ring-white/70')} style={{ background: c }} />
            ))}
          </div>
        </div>
        {via === 'local' && (
          <TextInput label="Console URL" placeholder="https://192.168.1.1" value={form.url ?? ''} onChange={(e) => set({ url: e.target.value })} hint="UniFi OS console: https://<console-ip>. UniFi OS Server: https://<host>:11443" />
        )}
        <TextInput
          label={via === 'local' ? 'API key' : 'unifi.ui.com API key'}
          type="password"
          placeholder={
            initial?.apiKeySet && sameAddress(form.url, initial.url) ? `Saved (${initial.apiKeyHint}) — leave empty to keep` : initial?.apiKeySet ? 'Enter the key again for the new address' : 'Paste your API key'
          }
          value={apiKey}
          onChange={(e) => setApiKey(e.target.value)}
          autoComplete="off"
          hint={
            via === 'local'
              ? "Created on the console: Settings → Control Plane → Integrations. Stored encrypted in the app's data volume."
              : 'Created at unifi.ui.com → Settings → API Keys. It can reach every console on your account, so it is stored encrypted and new environments start read-only.'
          }
        />
        {via === 'cloud' && <CloudConsolePicker apiKey={apiKey} envId={initial?.id} value={form.url ?? ''} onPick={(c) => set({ url: c.url, name: form.name || c.name })} />}
        <TextInput label="Site" value={form.site ?? 'default'} onChange={(e) => set({ site: e.target.value })} hint='Usually "default": the short name in the UniFi address (…/network/default/…), not the display name. Test connection lists every site.' />
        <div>
          <span className="mb-1 block text-xs font-medium text-ink-2">Change safety</span>
          <select
            value={form.writeMode}
            onChange={(e) => set({ writeMode: e.target.value as WriteMode })}
            className="h-9 w-full rounded-lg border border-line-2 bg-surface-2 px-2 text-sm text-ink focus:border-cyan-500/50 focus:outline-none"
          >
            {MODES.map((m) => (
              <option key={m.value} value={m.value}>
                {m.title}
              </option>
            ))}
          </select>
          <span className="mt-1 block text-xs text-ink-3">{MODES.find((m) => m.value === form.writeMode)?.text}</span>
        </div>
      </div>
      {via === 'local' && (
        <Toggle
          checked={!!form.verifyTls}
          onChange={(v) => set({ verifyTls: v })}
          label="Check the certificate with a certificate authority"
          description="Only for consoles with a certificate from a public authority (for example on your own domain). Off: the app trusts this console's own certificate the first time and refuses any other certificate afterwards."
        />
      )}

      {test.data && (
        <div className="space-y-3">
          <Callout tone={test.data.ok ? 'success' : 'danger'} icon={test.data.ok ? <CircleCheck className="h-4 w-4" /> : <CircleX className="h-4 w-4" />} title={test.data.ok ? 'Connection works' : 'Connection failed'}>
            {test.data.message}
          </Callout>
          {!initial && sites.length > 1 && (
            <div className="rounded-lg border border-line bg-surface-2/40 p-3">
              <div className="text-sm font-medium text-ink">This controller has {sites.length} sites</div>
              <div className="mb-2 text-xs text-ink-3">Each selected site becomes its own environment (same URL and key).</div>
              <div className="grid gap-1.5 sm:grid-cols-2">
                {sites.map((site) => (
                  <label key={site.internalReference} className="flex cursor-pointer items-center gap-2 text-sm text-ink-2">
                    <input
                      type="checkbox"
                      className="accent-cyan-400"
                      checked={pickedSites.includes(site.internalReference)}
                      onChange={() => setPickedSites((p) => (p.includes(site.internalReference) ? p.filter((x) => x !== site.internalReference) : [...p, site.internalReference]))}
                    />
                    {site.name} <span className="mono text-xs text-ink-3">{site.internalReference}</span>
                  </label>
                ))}
              </div>
            </div>
          )}
          {test.data.cert && <CertCheck cert={test.data.cert} changed={!!test.data.certChanged} trusted={initial?.tls?.pin ?? null} />}
          {test.data.capabilities.length > 0 && <CapabilityList caps={test.data.capabilities} />}
        </div>
      )}
      {(test.error || save.error) && <ErrorBox error={test.error ?? save.error} />}

      <div className="flex flex-wrap items-center gap-2">
        <Button variant="secondary" loading={test.isPending} disabled={!form.url || (!apiKey && !initial?.apiKeySet)} onClick={() => test.mutate()}>
          Test connection
        </Button>
        <Button variant="primary" loading={save.isPending} disabled={!form.url || (!apiKey && !initial?.apiKeySet) || (sites.length > 1 && !initial && pickedSites.length === 0)} onClick={() => save.mutate()}>
          {initial ? 'Save' : pickedSites.length > 1 ? `Add ${pickedSites.length} environments` : 'Save & connect'}
        </Button>
        {!first && (
          <Button variant="ghost" onClick={onDone}>
            Cancel
          </Button>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------------
// Change safety (per environment)
// ---------------------------------------------------------------------------------

const MODES: { value: WriteMode; title: string; text: string; icon: React.ReactNode }[] = [
  { value: 'read-only', title: 'Read-only', text: 'Never sends any change to UniFi. Every hardening plan can still be previewed in full.', icon: <LockKeyhole className="h-4 w-4" /> },
  {
    value: 'test-network',
    title: 'Test network only',
    text: `Hardening buttons may only create new rules that start from a dedicated test network (named “${TEST_NETWORK_PREFIX}…”, created from the Hardening page). Existing rules and site settings are never modified.`,
    icon: <FlaskConical className="h-4 w-4" />,
  },
  { value: 'full', title: 'Full access', text: 'Hardening may create rules, extend or widen your existing rules and change settings — always after showing you the exact changes.', icon: <ShieldCheck className="h-4 w-4" /> },
];

function ChangeSafety({ env }: { env: EnvSummary }) {
  const qc = useQueryClient();
  const save = useMutation({ mutationFn: (m: WriteMode) => api.updateEnvironment(env.id, { writeMode: m }), onSuccess: () => void qc.invalidateQueries() });
  return (
    <Card
      id="change-safety"
      title={
        <span className="flex items-center gap-2">
          Change safety <span className="h-2 w-2 rounded-full" style={{ background: env.color }} /> <span className="font-normal text-ink-2">{env.name}</span>
        </span>
      }
      icon={<ShieldCheck className="h-4 w-4" />}
      subtitle="How much this console may change on this environment's UniFi controller."
    >
      <div className="grid gap-3 md:grid-cols-3">
        {MODES.map((m) => (
          <button
            key={m.value}
            type="button"
            disabled={save.isPending}
            onClick={() => save.mutate(m.value)}
            className={clsx('rounded-xl border p-4 text-left transition-colors', env.writeMode === m.value ? 'border-cyan-500/50 bg-cyan-500/10' : 'border-line bg-surface-2/40 hover:bg-surface-2')}
          >
            <div className="flex items-center gap-2 text-sm font-medium text-ink">
              <span className={env.writeMode === m.value ? 'text-cyan-300' : 'text-ink-3'}>{m.icon}</span>
              {m.title}
              {env.writeMode === m.value && <Badge tone="cyan">current</Badge>}
            </div>
            <p className="mt-1.5 text-xs leading-relaxed text-ink-3">{m.text}</p>
          </button>
        ))}
      </div>
      {save.error && (
        <div className="mt-3">
          <ErrorBox error={save.error} />
        </div>
      )}
    </Card>
  );
}

// ---------------------------------------------------------------------------------
// IP intelligence (global)
// ---------------------------------------------------------------------------------

const PROVIDERS: { key: keyof IntelProviderSettings; title: string; sends: string; terms: string; link: string }[] = [
  {
    key: 'rdap',
    title: 'Regional internet registries (RDAP)',
    sends: 'Asks the registry responsible for the address (ARIN, RIPE NCC, APNIC, LACNIC or AFRINIC — found via IANA’s bootstrap list) who it is registered to and its abuse contact.',
    terms: 'Public registry service. Results are cached for 14 days and requests are spaced out.',
    link: 'https://www.iana.org/help/rdap-faq',
  },
  {
    key: 'tor',
    title: 'Tor Project exit-node list',
    sends: 'Downloads the public list of Tor exit nodes every 6 hours. No IP addresses are sent.',
    terms: 'Published openly by the Tor Project.',
    link: 'https://check.torproject.org/torbulkexitlist',
  },
  {
    key: 'ipapi',
    title: 'ip-api.com',
    sends: 'Sends public IPs (over plain HTTP) to get ISP, ASN and hosting / proxy / mobile flags.',
    terms: 'Free tier is for non-commercial use only, max 45 requests per minute.',
    link: 'https://ip-api.com/docs/legal',
  },
  {
    key: 'internetdb',
    title: 'Shodan InternetDB',
    sends: 'Sends public IPs to see which ports and known vulnerabilities Shodan’s own scans have observed.',
    terms: 'Free API from Shodan; check Shodan’s terms before commercial use.',
    link: 'https://internetdb.shodan.io/',
  },
];

/** The offline IEEE register of device makers (the first half of a MAC address), used to identify devices. */
function MakersRegister() {
  const qc = useQueryClient();
  const status = useQuery({ queryKey: ['makers'], queryFn: api.makers });
  const download = useMutation({ mutationFn: api.downloadMakers, onSuccess: () => void qc.invalidateQueries({ queryKey: ['makers'] }) });
  const remove = useMutation({ mutationFn: api.removeMakers, onSuccess: () => void qc.invalidateQueries({ queryKey: ['makers'] }) });
  const m = download.data ?? status.data;
  if (!m) return null;
  return (
    <div className="rounded-xl border border-line bg-surface-2/40 p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 text-sm font-medium text-ink">
            <Database className="h-4 w-4 text-ink-3" /> Device makers register
            {m.installed ? <Badge tone="green">installed</Badge> : <Badge tone="slate">not installed</Badge>}
          </div>
          <p className="mt-1 text-xs leading-relaxed text-ink-3">
            Names the maker of a device from the first half of its MAC address, for devices UniFi doesn’t recognise. It is the public IEEE register, downloaded from
            standards-oui.ieee.org only when you click below (about 5 MB); every lookup then happens on this machine.
          </p>
          {m.installed && (
            <p className="mt-1 text-xs text-ink-2">
              {m.entries?.toLocaleString()} address blocks{m.downloadedAt ? ` · downloaded ${timeAgo(m.downloadedAt)}` : ''}
            </p>
          )}
          {m.error && <p className="mt-1 text-xs text-rose-300">{m.error}</p>}
        </div>
        <div className="flex flex-wrap gap-2">
          <Button size="sm" variant="secondary" loading={download.isPending || m.downloading} onClick={() => download.mutate()}>
            {m.installed ? 'Update' : 'Download'}
          </Button>
          {m.installed && (
            <Button size="sm" variant="ghost" loading={remove.isPending} onClick={() => remove.mutate()}>
              Remove
            </Button>
          )}
        </div>
      </div>
    </div>
  );
}

function IntelSettings({ s, onSave }: { s: SettingsView; onSave: (u: SettingsUpdate) => void }) {
  const qc = useQueryClient();
  const download = useMutation({ mutationFn: (e: 'country' | 'city') => api.downloadGeoDb(e), onSuccess: () => void qc.invalidateQueries({ queryKey: ['settings'] }) });
  const remove = useMutation({ mutationFn: () => api.removeGeoDb(), onSuccess: () => void qc.invalidateQueries({ queryKey: ['settings'] }) });
  const g = s.geoDb;
  return (
    <Card
      id="intel"
      title="IP intelligence"
      icon={<Globe className="h-4 w-4" />}
      subtitle="Applies to all environments. Lookups are passive: the investigated address itself is never contacted (no ping, scan or connection). Private addresses are classified locally and never leave this machine."
    >
      <div className="space-y-5">
        <div className="rounded-xl border border-line bg-surface-2/40 p-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2 text-sm font-medium text-ink">
                <Database className="h-4 w-4 text-ink-3" /> Offline location & network database
                {g.installed ? <Badge tone="green">installed</Badge> : <Badge tone="slate">not installed</Badge>}
              </div>
              <p className="mt-1 text-xs leading-relaxed text-ink-3">
                Country / city and network owner (ASN) for any public IP, looked up locally — nothing is sent anywhere. Uses the free DB-IP Lite database (
                <a className="text-cyan-300 hover:text-cyan-200" href="https://db-ip.com/db/lite.php" target="_blank" rel="noreferrer">
                  IP Geolocation by DB-IP
                </a>
                , CC BY 4.0). It is downloaded from download.db-ip.com only when you click below; refresh it monthly.
              </p>
              {g.installed && (
                <p className="mt-1 text-xs text-ink-2">
                  {g.edition}
                  {g.sizeBytes ? ` · ${(g.sizeBytes / 1e6).toFixed(0)} MB` : ''}
                </p>
              )}
              {(g.error || download.error) && <p className="mt-1 text-xs text-rose-300">{g.error ?? String(download.error)}</p>}
            </div>
            <div className="flex flex-wrap gap-2">
              <Button size="sm" variant="secondary" loading={download.isPending && download.variables === 'country'} disabled={download.isPending} onClick={() => download.mutate('country')}>
                {g.installed ? 'Update' : 'Download'} (country)
              </Button>
              <Button size="sm" variant="secondary" loading={download.isPending && download.variables === 'city'} disabled={download.isPending} onClick={() => download.mutate('city')}>
                {g.installed ? 'Update' : 'Download'} (city, larger)
              </Button>
              {g.installed && (
                <Button size="sm" variant="ghost" loading={remove.isPending} onClick={() => remove.mutate()}>
                  Remove
                </Button>
              )}
            </div>
          </div>
        </div>

        <MakersRegister />

        <div className="space-y-3">
          {PROVIDERS.map((p) => (
            <div key={p.key} className="flex items-start gap-3">
              <Toggle checked={s.intel[p.key]} onChange={(v) => onSave({ intel: { [p.key]: v } })} ariaLabel={p.title} />
              <div className="min-w-0 text-xs leading-relaxed">
                <div className="text-sm text-ink">{p.title}</div>
                <div className="text-ink-2">{p.sends}</div>
                <div className="text-ink-3">
                  {p.terms}{' '}
                  <a className="text-cyan-300 hover:text-cyan-200" href={p.link} target="_blank" rel="noreferrer">
                    Terms / details
                  </a>
                </div>
              </div>
            </div>
          ))}
        </div>

        <div className="space-y-4 border-t border-line pt-4">
          <p className="text-xs text-ink-3">Optional reputation services with your own free API key. They only run when a key is set; nothing is ever reported to them and nothing is blocked automatically.</p>
          <KeyField label="AbuseIPDB API key" set={s.abuseipdbKeySet} hint="Community abuse reports and a confidence score. Free tier: 1,000 checks/day — see abuseipdb.com/legal." onSave={(v) => onSave({ abuseipdbKey: v })} />
          <KeyField label="GreyNoise API key" set={s.greynoiseKeySet} hint="Whether an IP is a mass scanner or a known business service. Free community key — see greynoise.io terms." onSave={(v) => onSave({ greynoiseKey: v })} />
        </div>
      </div>
    </Card>
  );
}

function KeyField({ label, set, hint, onSave }: { label: string; set: boolean; hint: string; onSave: (v: string) => void }) {
  const [v, setV] = useState('');
  return (
    <div className="flex flex-wrap items-end gap-2">
      <div className="min-w-[280px] flex-1">
        <TextInput label={label} type="password" value={v} onChange={(e) => setV(e.target.value)} placeholder={set ? 'Saved — enter a new key to replace' : 'Not set'} hint={hint} autoComplete="off" />
      </div>
      <Button
        size="md"
        variant="secondary"
        className="mb-5"
        disabled={!v}
        onClick={() => {
          onSave(v);
          setV('');
        }}
      >
        Save
      </Button>
      {set && (
        <Button size="md" variant="ghost" className="mb-5" onClick={() => onSave('')}>
          Remove
        </Button>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------------
// Diagnostics (per environment)
// ---------------------------------------------------------------------------------

function CapabilityList({ caps }: { caps: { key: string; label: string; ok: boolean; detail: string }[] }) {
  return (
    <ul className="grid gap-1.5 sm:grid-cols-2">
      {caps.map((c) => (
        <li key={c.key} className="flex items-start gap-2 rounded-lg border border-line/70 bg-surface-2/40 px-3 py-2 text-xs">
          {c.ok ? <CircleCheck className="mt-px h-3.5 w-3.5 shrink-0 text-emerald-400" /> : <CircleX className="mt-px h-3.5 w-3.5 shrink-0 text-ink-3" />}
          <div className="min-w-0">
            <div className="text-ink">{c.label}</div>
            <div className="break-words text-ink-3">{c.detail}</div>
          </div>
        </li>
      ))}
    </ul>
  );
}

function Diagnostics({ env }: { env: EnvSummary }) {
  const status = useQuery({ queryKey: ['status'], queryFn: api.status });
  const [run, setRun] = useState(false);
  const diag = useQuery({ queryKey: ['diagnostics'], queryFn: api.diagnostics, enabled: run });
  return (
    <Card
      id="diagnostics"
      title={
        <span className="flex items-center gap-2">
          Diagnostics <span className="h-2 w-2 rounded-full" style={{ background: env.color }} /> <span className="font-normal text-ink-2">{env.name}</span>
        </span>
      }
      icon={<Stethoscope className="h-4 w-4" />}
      subtitle="Which UniFi data sources work with this controller and key."
      actions={
        <Button size="sm" variant="secondary" loading={diag.isFetching} onClick={() => (run ? void diag.refetch() : setRun(true))}>
          Probe endpoints
        </Button>
      }
    >
      {status.data && <CapabilityList caps={status.data.capabilities} />}
      {status.data?.lastError && (
        <div className="mt-3">
          <ErrorBox error={status.data.lastError} />
        </div>
      )}
      {diag.data && (
        <div className="mt-4 overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-line text-left text-ink-3">
                <th className="py-2 pr-3 font-medium">Endpoint</th>
                <th className="py-2 pr-3 font-medium">Request</th>
                <th className="py-2 pr-3 font-medium">Result</th>
                <th className="py-2 font-medium">Time</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line/50">
              {diag.data.probes.map((p) => (
                <tr key={p.key}>
                  <td className="py-2 pr-3 text-ink">{p.label}</td>
                  <td className="mono py-2 pr-3 text-ink-3">
                    {p.method} {p.path}
                  </td>
                  <td className="py-2 pr-3">
                    <Badge tone={p.ok ? 'green' : 'slate'}>{p.status ?? 'error'}</Badge> <span className="text-ink-3">{p.detail}</span>
                  </td>
                  <td className="py-2 text-ink-3">{p.ms} ms</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

/** Lists the consoles a unifi.ui.com key can reach and lets the owner pick one. */
function CloudConsolePicker({ apiKey, envId, value, onPick }: { apiKey: string; envId?: string; value: string; onPick: (c: CloudConsole) => void }) {
  const find = useMutation({ mutationFn: () => api.cloudConsoles({ ...(apiKey ? { apiKey } : {}), ...(envId ? { id: envId } : {}) }) });
  const consoles = find.data ?? [];
  const picked = consoles.find((c) => c.url === value);
  return (
    <div className="md:col-span-2">
      <span className="mb-1 block text-xs font-medium text-ink-2">Console</span>
      <div className="flex flex-wrap items-center gap-2">
        <Button size="sm" variant="secondary" loading={find.isPending} disabled={!apiKey && !envId} onClick={() => find.mutate()}>
          Find my consoles
        </Button>
        <span className="text-xs text-ink-3">{picked ? `Selected: ${picked.name}` : value ? 'A console is selected.' : 'Paste the key, then pick the console to add.'}</span>
      </div>
      {find.error && (
        <div className="mt-2">
          <ErrorBox error={find.error} />
        </div>
      )}
      {find.data && !consoles.length && <p className="mt-2 text-xs text-ink-3">No consoles were found on this account.</p>}
      {consoles.length > 0 && (
        <div className="mt-2 grid gap-1.5 sm:grid-cols-2">
          {consoles.map((c) => (
            <button
              key={c.id}
              type="button"
              disabled={c.hasNetwork === false}
              onClick={() => onPick(c)}
              className={clsx(
                'rounded-lg border px-3 py-2 text-left transition-colors disabled:cursor-not-allowed disabled:opacity-50',
                value === c.url ? 'border-cyan-500/50 bg-cyan-500/10' : 'border-line bg-surface-2 hover:bg-surface-3',
              )}
            >
              <span className="flex items-center gap-2 text-sm font-medium text-ink">
                <span className={clsx('h-2 w-2 shrink-0 rounded-full', c.online === false ? 'bg-slate-500' : c.online ? 'bg-emerald-400' : 'bg-slate-400')} />
                <span className="truncate">{c.name}</span>
              </span>
              <span className="mt-0.5 block truncate text-xs text-ink-3">
                {[c.model, c.version && `v${c.version}`, c.online === false ? 'offline' : null, c.hasNetwork === false ? 'no UniFi Network' : null, c.owner ? null : 'shared with you'].filter(Boolean).join(' · ')}
              </span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
