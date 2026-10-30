import { useState, type FormEvent } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { ShieldCheck } from 'lucide-react';
import { PASSWORD_MIN_LENGTH } from '@shared/types';
import { api } from '../lib/api';
import { Button, ErrorBox, TextInput } from '../components/ui';

/** Signing in, or on the very first visit, creating the account that protects the dashboard. */
export function LoginPage({ setup }: { setup: boolean }) {
  const qc = useQueryClient();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [repeat, setRepeat] = useState('');
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const mismatch = setup && repeat !== '' && repeat !== password;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      if (setup) await api.setup(username, password);
      else await api.login(username, password);
      await qc.invalidateQueries();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex h-full items-center justify-center overflow-y-auto p-4">
      <form onSubmit={submit} className="w-full max-w-sm rounded-2xl border border-line bg-surface p-6 shadow-2xl">
        <div className="mb-5 flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-cyan-400 to-indigo-500 text-slate-950">
            <ShieldCheck className="h-5 w-5" />
          </div>
          <div>
            <div className="font-semibold text-ink">Security Console</div>
            <div className="text-xs text-ink-3">{setup ? 'Create your account' : 'Sign in to continue'}</div>
          </div>
        </div>
        {setup && (
          <p className="mb-4 text-xs leading-relaxed text-ink-3">
            This is the first start, so there is no account yet. The username and password you choose protect this dashboard, which can change your firewall.
            You can change them later in Settings.
          </p>
        )}
        <div className="space-y-3">
          <TextInput
            label="Username"
            autoComplete="username"
            autoCapitalize="none"
            spellCheck={false}
            autoFocus
            required
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
          <TextInput
            label="Password"
            type="password"
            autoComplete={setup ? 'new-password' : 'current-password'}
            required
            minLength={setup ? PASSWORD_MIN_LENGTH : undefined}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            hint={setup ? `At least ${PASSWORD_MIN_LENGTH} characters. A few unrelated words are easy to remember and hard to guess.` : undefined}
          />
          {setup && (
            <TextInput
              label="Repeat password"
              type="password"
              autoComplete="new-password"
              required
              value={repeat}
              onChange={(e) => setRepeat(e.target.value)}
              hint={mismatch ? <span className="text-rose-300">The two passwords are different.</span> : undefined}
            />
          )}
        </div>
        {error !== null && (
          <div className="mt-3">
            <ErrorBox error={error} />
          </div>
        )}
        <Button type="submit" variant="primary" className="mt-4 w-full" loading={busy} disabled={setup && (mismatch || repeat === '')}>
          {setup ? 'Create account and sign in' : 'Sign in'}
        </Button>
        {!setup && (
          <details className="mt-4 text-xs text-ink-3">
            <summary className="cursor-pointer select-none hover:text-ink-2">Forgot your password?</summary>
            <p className="mt-2 leading-relaxed">
              On the computer that runs the console, open a terminal and run the command below. It removes the account, so the next visit lets you
              create a new one. Your environments, keys and history are kept.
            </p>
            <code className="mt-2 block break-all rounded-lg border border-line bg-surface-2 p-2 font-mono text-[11px] text-ink-2">
              docker exec unifi-security-console node --disable-warning=ExperimentalWarning server/reset-login.ts
            </code>
          </details>
        )}
      </form>
    </div>
  );
}
