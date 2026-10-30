import { useEffect, useId, useRef, useState, type ButtonHTMLAttributes, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import { Link } from 'react-router';
import clsx from 'clsx';
import { Check, CircleAlert, Copy, Info, LoaderCircle, X } from 'lucide-react';
import type { IpVerdictLevel, ReachVerdict, Severity, ThreatDirection, ThreatEvent } from '@shared/types';
import { countryName } from '../lib/format';

// ---------------------------------------------------------------------------------
// Layout primitives
// ---------------------------------------------------------------------------------

export function Card(props: {
  title?: ReactNode;
  subtitle?: ReactNode;
  icon?: ReactNode;
  actions?: ReactNode;
  children?: ReactNode;
  className?: string;
  bodyClassName?: string;
  padded?: boolean;
  /** Anchor for links such as /settings#intel. */
  id?: string;
}) {
  const { title, subtitle, icon, actions, children, className, bodyClassName, padded = true } = props;
  return (
    <section id={props.id} className={clsx('scroll-mt-4 rounded-xl border border-line bg-surface/80 shadow-[0_1px_0_0_rgba(255,255,255,0.03)_inset]', className)}>
      {(title || actions) && (
        // On narrow screens the actions wrap below the title instead of squeezing it to a single letter.
        <header className="flex flex-wrap items-start justify-between gap-x-3 gap-y-2 border-b border-line/70 px-4 py-3">
          <div className="flex min-w-0 flex-1 basis-56 items-start gap-2.5">
            {icon && <div className="mt-0.5 text-ink-3">{icon}</div>}
            <div className="min-w-0">
              <h2 className="truncate text-sm font-semibold text-ink">{title}</h2>
              {subtitle && <p className="mt-0.5 text-xs text-ink-3">{subtitle}</p>}
            </div>
          </div>
          {actions && <div className="flex max-w-full flex-wrap items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={clsx(padded && 'p-4', bodyClassName)}>{children}</div>
    </section>
  );
}

export function PageHeader(props: { title: ReactNode; subtitle?: ReactNode; actions?: ReactNode; icon?: ReactNode }) {
  return (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div className="flex items-center gap-3">
        {props.icon && <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-line bg-surface-2 text-brand">{props.icon}</div>}
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-ink">{props.title}</h1>
          {props.subtitle && <p className="mt-0.5 max-w-3xl text-sm text-ink-3">{props.subtitle}</p>}
        </div>
      </div>
      {props.actions && <div className="flex flex-wrap items-center gap-2">{props.actions}</div>}
    </div>
  );
}

// ---------------------------------------------------------------------------------
// Buttons & inputs
// ---------------------------------------------------------------------------------

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: 'primary' | 'secondary' | 'ghost' | 'danger' | 'success';
  size?: 'xs' | 'sm' | 'md';
  icon?: ReactNode;
  loading?: boolean;
};

export function Button({ variant = 'secondary', size = 'md', icon, loading, className, children, disabled, ...rest }: ButtonProps) {
  return (
    <button
      {...rest}
      disabled={disabled || loading}
      className={clsx(
        'inline-flex items-center justify-center gap-1.5 whitespace-nowrap rounded-lg font-medium transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-brand/60 disabled:cursor-not-allowed disabled:opacity-50',
        size === 'xs' && 'h-6 px-2 text-xs',
        size === 'sm' && 'h-8 px-3 text-xs',
        size === 'md' && 'h-9 px-3.5 text-sm',
        variant === 'primary' && 'bg-cyan-500 text-slate-950 hover:bg-cyan-400',
        variant === 'secondary' && 'border border-line-2 bg-surface-2 text-ink hover:bg-surface-3',
        variant === 'ghost' && 'text-ink-2 hover:bg-surface-3 hover:text-ink',
        variant === 'danger' && 'bg-rose-500/90 text-white hover:bg-rose-500',
        variant === 'success' && 'bg-emerald-500 text-slate-950 hover:bg-emerald-400',
        className,
      )}
    >
      {loading ? <LoaderCircle className="h-4 w-4 animate-spin" /> : icon}
      {children}
    </button>
  );
}

export function Toggle(props: { checked: boolean; onChange: (v: boolean) => void; label?: ReactNode; description?: ReactNode; disabled?: boolean; ariaLabel?: string }) {
  return (
    <label className={clsx('flex cursor-pointer items-start gap-3', props.disabled && 'cursor-not-allowed opacity-60')}>
      <button
        type="button"
        role="switch"
        aria-checked={props.checked}
        aria-label={props.ariaLabel}
        disabled={props.disabled}
        onClick={() => props.onChange(!props.checked)}
        className={clsx('relative mt-0.5 inline-flex h-5 w-9 shrink-0 items-center rounded-full transition-colors', props.checked ? 'bg-cyan-500' : 'bg-slate-700')}
      >
        <span className={clsx('inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform', props.checked ? 'translate-x-4' : 'translate-x-0.5')} />
      </button>
      {(props.label || props.description) && (
        <span className="min-w-0">
          {props.label && <span className="block text-sm text-ink">{props.label}</span>}
          {props.description && <span className="block text-xs text-ink-3">{props.description}</span>}
        </span>
      )}
    </label>
  );
}

export function Segmented<T extends string>(props: { options: { value: T; label: ReactNode }[]; value: T; onChange: (v: T) => void; size?: 'sm' | 'md' }) {
  return (
    <div className="inline-flex rounded-lg border border-line bg-surface-2 p-0.5">
      {props.options.map((o) => (
        <button
          key={o.value}
          type="button"
          aria-pressed={props.value === o.value}
          onClick={() => props.onChange(o.value)}
          className={clsx(
            'rounded-md font-medium transition-colors',
            props.size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-3 py-1 text-xs',
            props.value === o.value ? 'bg-surface-3 text-ink shadow' : 'text-ink-3 hover:text-ink',
          )}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function TextInput(props: React.InputHTMLAttributes<HTMLInputElement> & { label?: ReactNode; hint?: ReactNode }) {
  const { label, hint, className, ...rest } = props;
  return (
    <label className="block">
      {label && <span className="mb-1 block text-xs font-medium text-ink-2">{label}</span>}
      <input
        {...rest}
        className={clsx(
          'h-9 w-full rounded-lg border border-line-2 bg-surface-2 px-3 text-sm text-ink placeholder:text-ink-3 focus:border-cyan-500/60 focus:outline-none focus:ring-2 focus:ring-cyan-500/20',
          className,
        )}
      />
      {hint && <span className="mt-1 block text-xs text-ink-3">{hint}</span>}
    </label>
  );
}

// ---------------------------------------------------------------------------------
// Badges
// ---------------------------------------------------------------------------------

export type Tone = 'neutral' | 'red' | 'orange' | 'amber' | 'green' | 'blue' | 'cyan' | 'violet' | 'slate';

const TONES: Record<Tone, string> = {
  neutral: 'bg-slate-500/10 text-slate-300 ring-slate-500/25',
  slate: 'bg-slate-500/10 text-slate-400 ring-slate-500/20',
  red: 'bg-rose-500/12 text-rose-300 ring-rose-500/30',
  orange: 'bg-orange-500/12 text-orange-300 ring-orange-500/30',
  amber: 'bg-amber-500/12 text-amber-300 ring-amber-500/30',
  green: 'bg-emerald-500/12 text-emerald-300 ring-emerald-500/30',
  blue: 'bg-sky-500/12 text-sky-300 ring-sky-500/30',
  cyan: 'bg-cyan-500/12 text-cyan-300 ring-cyan-500/30',
  violet: 'bg-violet-500/12 text-violet-300 ring-violet-500/30',
};

export function Badge(props: { tone?: Tone; children: ReactNode; className?: string; icon?: ReactNode; title?: string }) {
  return (
    <span title={props.title} className={clsx('inline-flex items-center gap-1 whitespace-nowrap rounded-md px-1.5 py-0.5 text-[11px] font-medium ring-1 ring-inset', TONES[props.tone ?? 'neutral'], props.className)}>
      {props.icon}
      {props.children}
    </span>
  );
}

export const SEVERITY_TONE: Record<Severity, Tone> = { critical: 'red', high: 'orange', medium: 'amber', low: 'blue', info: 'slate' };
export const SEVERITY_HEX: Record<Severity, string> = { critical: '#f43f5e', high: '#f97316', medium: '#f59e0b', low: '#38bdf8', info: '#64748b' };

export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  return (
    <Badge tone={SEVERITY_TONE[severity]} className={clsx('capitalize', className)}>
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: SEVERITY_HEX[severity] }} />
      {severity}
    </Badge>
  );
}

export function ActionBadge({ action }: { action: 'blocked' | 'alerted' | 'unknown' }) {
  if (action === 'blocked') return <Badge tone="green">Blocked</Badge>;
  if (action === 'alerted') return <Badge tone="amber" title='Detected but allowed through (IPS in "Notify" mode)'>Allowed</Badge>;
  return <Badge tone="slate">Unknown</Badge>;
}

export function DirectionBadge({ direction }: { direction: ThreatDirection }) {
  const map: Record<ThreatDirection, { tone: Tone; label: string; title: string }> = {
    inbound: { tone: 'slate', label: 'Inbound', title: 'From the internet towards your network' },
    outbound: { tone: 'violet', label: 'Outbound', title: 'Started by a device on your network' },
    internal: { tone: 'orange', label: 'Internal', title: 'Between devices on your own networks' },
    unknown: { tone: 'slate', label: 'Unknown', title: '' },
  };
  const m = map[direction];
  return (
    <Badge tone={m.tone} title={m.title}>
      {m.label}
    </Badge>
  );
}

export function VerdictBadge({ level }: { level: IpVerdictLevel }) {
  const map: Record<IpVerdictLevel, { tone: Tone; label: string }> = {
    malicious: { tone: 'red', label: 'Malicious' },
    suspicious: { tone: 'orange', label: 'Suspicious' },
    scanner: { tone: 'blue', label: 'Research scanner' },
    cloud: { tone: 'violet', label: 'Cloud / hosting' },
    benign: { tone: 'green', label: 'Benign' },
    unknown: { tone: 'slate', label: 'No reputation data' },
    internal: { tone: 'cyan', label: 'Internal' },
  };
  return <Badge tone={map[level].tone}>{map[level].label}</Badge>;
}

export const REACH_STYLE: Record<ReachVerdict, { tone: Tone; label: string }> = {
  allowed: { tone: 'red', label: 'Allowed' },
  blocked: { tone: 'green', label: 'Blocked' },
  partial: { tone: 'amber', label: 'Partially' },
  self: { tone: 'slate', label: '—' },
  unknown: { tone: 'slate', label: 'Unknown' },
};

/** One legend for every segmentation grid, so a colour means the same thing on every page. */
export const MATRIX_LEGEND = [
  { cls: 'bg-emerald-500/50', label: 'Blocked' },
  { cls: 'bg-slate-500/40', label: 'Allowed (fine for these roles)' },
  { cls: 'bg-amber-400/70', label: 'Partly open — check' },
  { cls: 'bg-rose-500/70', label: 'Open, but should be blocked' },
];

export function MatrixLegend({ className }: { className?: string }) {
  return (
    <div className={clsx('flex flex-wrap gap-x-4 gap-y-1.5', className)}>
      {MATRIX_LEGEND.map((l) => (
        <span key={l.label} className="flex items-center gap-1.5">
          <span className={clsx('inline-block h-2.5 w-2.5 shrink-0 rounded-sm', l.cls)} />
          {l.label}
        </span>
      ))}
    </div>
  );
}

/** A matrix cell's label; "partial" says which way it leans, since "Partially" alone reads both ways. */
export function reachLabel(c: { verdict: ReachVerdict; summary: string }): string {
  if (c.verdict !== 'partial') return REACH_STYLE[c.verdict].label;
  return c.summary.startsWith('Mostly blocked') ? 'Mostly blocked' : 'Mostly open';
}

/** One side of a detection: your device by name, or the outside address with its country. Works for both directions. */
export function EventEnd({ e, ip }: { e: ThreatEvent; ip: string }) {
  if (e.local?.name && ip === e.localIp) return <span className="min-w-0 truncate">{e.local.name}</span>;
  return (
    <span className="flex min-w-0 items-center gap-1">
      {ip === e.remoteIp && e.remoteCountry && <CountryTag code={e.remoteCountry} />}
      <span className="mono truncate">{ip}</span>
    </span>
  );
}

export function CountryTag({ code, showName = false }: { code: string | null | undefined; showName?: boolean }) {
  if (!code) return <span className="text-ink-3">—</span>;
  return (
    <span className="inline-flex items-center gap-1.5" title={countryName(code)}>
      <span className="mono rounded bg-slate-700/60 px-1 py-px text-[10px] font-semibold tracking-wider text-slate-200">{code.toUpperCase()}</span>
      {showName && <span className="truncate text-ink-2">{countryName(code)}</span>}
    </span>
  );
}

export function IpLink({ ip, name, className }: { ip: string | null | undefined; name?: string | null; className?: string }) {
  if (!ip) return <span className="text-ink-3">—</span>;
  return (
    <Link to={`/investigate/${encodeURIComponent(ip)}`} className={clsx('group inline-flex min-w-0 items-baseline gap-1.5 hover:text-cyan-300', className)} onClick={(e) => e.stopPropagation()}>
      {name ? (
        <>
          <span className="truncate font-medium text-ink group-hover:text-cyan-300">{name}</span>
          <span className="mono shrink-0 text-[11px] text-ink-3">{ip}</span>
        </>
      ) : (
        <span className="mono truncate text-[13px]">{ip}</span>
      )}
    </Link>
  );
}

// ---------------------------------------------------------------------------------
// Feedback states
// ---------------------------------------------------------------------------------

export function Spinner({ className }: { className?: string }) {
  return <LoaderCircle className={clsx('h-4 w-4 animate-spin text-ink-3', className)} />;
}

export function Loading({ label = 'Loading…', className }: { label?: string; className?: string }) {
  return (
    <div className={clsx('flex items-center justify-center gap-2 py-10 text-sm text-ink-3', className)}>
      <Spinner /> {label}
    </div>
  );
}

export function ErrorBox({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const msg = error instanceof Error ? error.message : String(error);
  return (
    <div className="flex items-start gap-3 rounded-lg border border-rose-500/30 bg-rose-500/5 p-3 text-sm text-rose-200">
      <CircleAlert className="mt-0.5 h-4 w-4 shrink-0 text-rose-400" />
      <div className="min-w-0 flex-1 break-words">{msg}</div>
      {onRetry && (
        <Button size="xs" variant="ghost" onClick={onRetry}>
          Retry
        </Button>
      )}
    </div>
  );
}

export function EmptyState(props: { icon?: ReactNode; title: ReactNode; children?: ReactNode; action?: ReactNode; className?: string }) {
  return (
    <div className={clsx('flex flex-col items-center justify-center px-6 py-10 text-center', props.className)}>
      {props.icon && <div className="mb-3 text-ink-3">{props.icon}</div>}
      <div className="text-sm font-medium text-ink">{props.title}</div>
      {props.children && <div className="mt-1 max-w-md text-xs text-ink-3">{props.children}</div>}
      {props.action && <div className="mt-4">{props.action}</div>}
    </div>
  );
}

export function Callout(props: { tone?: 'info' | 'warn' | 'danger' | 'success'; title?: ReactNode; children?: ReactNode; icon?: ReactNode; className?: string }) {
  const tone = props.tone ?? 'info';
  return (
    <div
      className={clsx(
        'flex gap-3 rounded-lg border p-3 text-sm',
        tone === 'info' && 'border-sky-500/25 bg-sky-500/5 text-sky-100',
        tone === 'warn' && 'border-amber-500/30 bg-amber-500/5 text-amber-100',
        tone === 'danger' && 'border-rose-500/30 bg-rose-500/5 text-rose-100',
        tone === 'success' && 'border-emerald-500/30 bg-emerald-500/5 text-emerald-100',
        props.className,
      )}
    >
      <div
        className={clsx(
          'mt-0.5 shrink-0',
          tone === 'info' && 'text-sky-400',
          tone === 'warn' && 'text-amber-400',
          tone === 'danger' && 'text-rose-400',
          tone === 'success' && 'text-emerald-400',
        )}
      >
        {props.icon ?? <Info className="h-4 w-4" />}
      </div>
      <div className="min-w-0 flex-1">
        {props.title && <div className="font-medium">{props.title}</div>}
        {props.children && <div className={clsx('text-[13px] opacity-90', props.title && 'mt-0.5')}>{props.children}</div>}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------------
// Overlays
// ---------------------------------------------------------------------------------

// Open windows, oldest first: Escape closes only the last one, so a window opened from another leaves that one open.
const escapeStack: object[] = [];

function useEscape(open: boolean, onClose: () => void) {
  const close = useRef(onClose);
  close.current = onClose;
  useEffect(() => {
    if (!open) return;
    const me = {};
    escapeStack.push(me);
    const h = (e: KeyboardEvent) => e.key === 'Escape' && escapeStack[escapeStack.length - 1] === me && close.current();
    window.addEventListener('keydown', h);
    return () => {
      window.removeEventListener('keydown', h);
      escapeStack.splice(escapeStack.indexOf(me), 1);
    };
  }, [open]);
}

export function Drawer(props: { open: boolean; onClose: () => void; title?: ReactNode; subtitle?: ReactNode; children?: ReactNode; footer?: ReactNode; width?: string }) {
  const titleId = useId();
  useEscape(props.open, props.onClose);
  if (!props.open) return null;
  return createPortal(
    <div className="fixed inset-0 z-50 flex justify-end">
      <div className="fade-in absolute inset-0 bg-black/50 backdrop-blur-[1px]" onClick={props.onClose} />
      <aside role="dialog" aria-modal="true" aria-labelledby={titleId} className={clsx('slide-in relative flex h-full w-full flex-col border-l border-line bg-[#0c1220] shadow-2xl', props.width ?? 'max-w-2xl')}>
        <header className="flex items-start justify-between gap-3 border-b border-line px-5 py-4">
          <div className="min-w-0">
            <div id={titleId} className="text-base font-semibold text-ink">{props.title}</div>
            {props.subtitle && <div className="mt-0.5 text-xs text-ink-3">{props.subtitle}</div>}
          </div>
          <button onClick={props.onClose} className="rounded-md p-1 text-ink-3 hover:bg-surface-3 hover:text-ink" aria-label="Close">
            <X className="h-5 w-5" />
          </button>
        </header>
        <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">{props.children}</div>
        {props.footer && <footer className="border-t border-line px-5 py-3">{props.footer}</footer>}
      </aside>
    </div>,
    document.body,
  );
}

export function Modal(props: { open: boolean; onClose: () => void; title?: ReactNode; subtitle?: ReactNode; children?: ReactNode; footer?: ReactNode; size?: 'md' | 'lg' | 'xl' }) {
  const titleId = useId();
  useEscape(props.open, props.onClose);
  if (!props.open) return null;
  return createPortal(
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto p-4 sm:p-8">
      <div className="fade-in fixed inset-0 bg-black/60 backdrop-blur-[1px]" onClick={props.onClose} />
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        className={clsx(
          'fade-in relative w-full rounded-2xl border border-line bg-[#0c1220] shadow-2xl',
          props.size === 'xl' ? 'max-w-5xl' : props.size === 'lg' ? 'max-w-3xl' : 'max-w-xl',
        )}
      >
        <header className="flex items-start justify-between gap-3 border-b border-line px-5 py-4">
          <div className="min-w-0">
            <div id={titleId} className="text-base font-semibold text-ink">{props.title}</div>
            {props.subtitle && <div className="mt-0.5 text-xs text-ink-3">{props.subtitle}</div>}
          </div>
          <button onClick={props.onClose} className="rounded-md p-1 text-ink-3 hover:bg-surface-3 hover:text-ink" aria-label="Close">
            <X className="h-5 w-5" />
          </button>
        </header>
        <div className="px-5 py-4">{props.children}</div>
        {props.footer && <footer className="flex items-center justify-end gap-2 border-t border-line px-5 py-3">{props.footer}</footer>}
      </div>
    </div>,
    document.body,
  );
}

export function InfoTip({ children, className, wide }: { children: ReactNode; className?: string; wide?: boolean }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLSpanElement>(null);
  const [pos, setPos] = useState<{ left: number; top: number } | null>(null);
  useEffect(() => {
    if (!open || !ref.current) return;
    const r = ref.current.getBoundingClientRect();
    const w = wide ? 380 : 280;
    setPos({ left: Math.min(Math.max(8, r.left + r.width / 2 - w / 2), window.innerWidth - w - 8), top: r.bottom + 8 });
  }, [open, wide]);
  return (
    <span ref={ref} className={clsx('inline-flex', className)} onMouseEnter={() => setOpen(true)} onMouseLeave={() => setOpen(false)} onFocus={() => setOpen(true)} onBlur={() => setOpen(false)}>
      <Info className="h-3.5 w-3.5 cursor-help text-ink-3 hover:text-cyan-300" tabIndex={0} />
      {open &&
        pos &&
        createPortal(
          <div
            className="fade-in pointer-events-none fixed z-[60] rounded-lg border border-line-2 bg-[#111a2e] p-3 text-xs leading-relaxed text-ink-2 shadow-xl"
            style={{ left: pos.left, top: pos.top, width: wide ? 380 : 280 }}
          >
            {children}
          </div>,
          document.body,
        )}
    </span>
  );
}

// ---------------------------------------------------------------------------------
// Misc
// ---------------------------------------------------------------------------------

export function Tabs<T extends string>(props: { tabs: { id: T; label: ReactNode; count?: number | null; icon?: ReactNode }[]; value: T; onChange: (id: T) => void; className?: string }) {
  return (
    <div className={clsx('flex gap-1 overflow-x-auto border-b border-line', props.className)}>
      {props.tabs.map((t) => (
        <button
          key={t.id}
          onClick={() => props.onChange(t.id)}
          className={clsx(
            '-mb-px inline-flex items-center gap-2 whitespace-nowrap border-b-2 px-3 py-2.5 text-sm font-medium transition-colors',
            props.value === t.id ? 'border-cyan-400 text-ink' : 'border-transparent text-ink-3 hover:text-ink-2',
          )}
        >
          {t.icon}
          {t.label}
          {t.count !== undefined && t.count !== null && (
            <span className={clsx('rounded-full px-1.5 py-px text-[10px] font-semibold', props.value === t.id ? 'bg-cyan-500/20 text-cyan-200' : 'bg-slate-700/60 text-ink-3')}>{t.count}</span>
          )}
        </button>
      ))}
    </div>
  );
}

export function KV({ k, v, mono }: { k: ReactNode; v: ReactNode; mono?: boolean }) {
  return (
    <div className="flex items-baseline justify-between gap-4 border-b border-line/50 py-1.5 text-sm last:border-0">
      <dt className="shrink-0 text-ink-3">{k}</dt>
      <dd className={clsx('min-w-0 break-words text-right text-ink', mono && 'mono text-[13px]')}>{v ?? <span className="text-ink-3">—</span>}</dd>
    </div>
  );
}

export function CopyButton({ text, className }: { text: string; className?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      className={clsx('rounded p-1 text-ink-3 hover:bg-surface-3 hover:text-ink', className)}
      title="Copy"
      onClick={(e) => {
        e.stopPropagation();
        void navigator.clipboard?.writeText(text).then(() => {
          setDone(true);
          setTimeout(() => setDone(false), 1200);
        });
      }}
    >
      {done ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
    </button>
  );
}

export function Stat(props: { label: ReactNode; value: ReactNode; sub?: ReactNode; icon?: ReactNode; tone?: Tone; className?: string; children?: ReactNode }) {
  return (
    <div className={clsx('rounded-xl border border-line bg-surface/80 p-4', props.className)}>
      <div className="flex items-center justify-between gap-2 text-xs font-medium text-ink-3">
        <span className="flex items-center gap-1.5">{props.label}</span>
        {props.icon && <span className={clsx(props.tone && TONES[props.tone].split(' ')[1])}>{props.icon}</span>}
      </div>
      <div className="mt-2 text-2xl font-semibold tracking-tight text-ink">{props.value}</div>
      {props.sub && <div className="mt-1 text-xs text-ink-3">{props.sub}</div>}
      {props.children}
    </div>
  );
}

export function Bar({ value, max, color = '#22d3ee', className }: { value: number; max: number; color?: string; className?: string }) {
  const pct = max > 0 ? Math.max(2, Math.min(100, (value / max) * 100)) : 0;
  return (
    <div className={clsx('h-1.5 w-full overflow-hidden rounded-full bg-slate-800', className)}>
      <div className="h-full rounded-full" style={{ width: `${pct}%`, background: color }} />
    </div>
  );
}

export function gradeColor(grade: string): string {
  return grade === 'A' ? '#34d399' : grade === 'B' ? '#a3e635' : grade === 'C' ? '#fbbf24' : grade === 'D' ? '#fb923c' : '#f43f5e';
}

export function ScoreRing({ score, grade, size = 132 }: { score: number; grade: string; size?: number }) {
  const r = (size - 14) / 2;
  const c = 2 * Math.PI * r;
  const color = gradeColor(grade);
  return (
    <div className="relative" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} stroke="#1e293b" strokeWidth={10} fill="none" />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          stroke={color}
          strokeWidth={10}
          fill="none"
          strokeLinecap="round"
          strokeDasharray={`${(c * Math.max(0, Math.min(100, score))) / 100} ${c}`}
          style={{ transition: 'stroke-dasharray 0.6s ease' }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <div className="text-4xl font-bold leading-none" style={{ color }}>
          {grade}
        </div>
        <div className="mt-1 text-xs text-ink-3">{score}/100</div>
      </div>
    </div>
  );
}
