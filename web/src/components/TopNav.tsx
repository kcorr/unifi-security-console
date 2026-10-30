import { useCallback, useEffect, useLayoutEffect, useRef, useState, type FormEvent, type ReactNode } from 'react';
import { NavLink, useLocation, useNavigate } from 'react-router';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import clsx from 'clsx';
import {
  Activity, BookOpen, Check, Router, ChevronDown, CircleHelp, CircleUserRound, Flame, History, Keyboard, KeyRound, Layers, LayoutDashboard, LockKeyhole, LogOut, Menu, Radar,
  RefreshCw, ScanSearch, Search, Settings as SettingsIcon, ShieldCheck, Stethoscope, Wrench, X, type LucideIcon,
} from 'lucide-react';
import { version as APP_VERSION } from '../../../package.json';
import { api } from '../lib/api';
import { setEnv, useEnv } from '../lib/env';
import { useLive } from '../lib/live';
import { timeAgo } from '../lib/format';

type NavItem = { to: string; label: string; short?: string; icon: LucideIcon; end?: boolean };

// In priority order. The bar shows as many links as fit beside the right-hand controls (measured, so a long
// environment name or the wider search box on big screens never pushes a link underneath them) and the rest go
// into "More". Below lg everything is in the mobile menu.
const NAV: NavItem[] = [
  { to: '/', label: 'Overview', icon: LayoutDashboard, end: true },
  { to: '/threats', label: 'Threats', icon: Flame },
  { to: '/hardening', label: 'Hardening', icon: Wrench },
  { to: '/firewall', label: 'Firewall & Segmentation', short: 'Firewall', icon: Radar },
  { to: '/live', label: 'Live Activity', short: 'Live', icon: Activity },
  { to: '/devices', label: 'UniFi Devices', short: 'Devices', icon: Router },
  { to: '/activity', label: 'Change Log', icon: History },
  // Also reachable from the search box and the Help menu, so these are the first to move into "More".
  { to: '/investigate', label: 'Investigate IP', short: 'Investigate', icon: ScanSearch },
  { to: '/learn', label: 'Threat Encyclopedia', short: 'Encyclopedia', icon: BookOpen },
];
const SETTINGS: NavItem = { to: '/settings', label: 'Settings', icon: SettingsIcon };

const ITEM_SHAPE = 'flex h-8 shrink-0 items-center whitespace-nowrap rounded-lg px-3 text-sm font-medium';
const ITEM_IDLE = 'text-ink-2 hover:bg-surface-3/60 hover:text-ink';
const ITEM_ACTIVE = 'bg-cyan-500/10 text-cyan-200 ring-1 ring-inset ring-cyan-500/20';
const ICON_BUTTON = 'flex h-9 w-9 shrink-0 items-center justify-center rounded-lg transition-colors';
const NAV_GAP = 2; // gap-0.5 between links
const NAV_CLEARANCE = 12; // space kept free before the right-hand controls

export function TopNav() {
  const { pathname } = useLocation();
  const { navRef, measureRef, count } = useNavFit(pathname);
  const overflow = NAV.slice(count);

  return (
    <header className="relative z-30 flex h-14 shrink-0 items-center gap-2 border-b border-line bg-[#0b1120]/90 px-3 backdrop-blur sm:px-4 xl:px-6">
      <MobileMenu />
      <NavLink to="/" title="Security Console for UniFi Network" className="flex shrink-0 items-center gap-2.5">
        <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-gradient-to-br from-cyan-400 to-indigo-500 text-slate-950 shadow-lg shadow-cyan-500/10">
          <ShieldCheck className="h-[18px] w-[18px]" />
        </span>
        <span className="hidden leading-tight 2xl:block">
          <span className="block text-sm font-semibold text-ink">Security Console</span>
          <span className="block text-[11px] text-ink-3">for UniFi Network</span>
        </span>
      </NavLink>
      <nav ref={navRef} aria-label="Main" className="ml-2 hidden min-w-0 flex-1 items-center gap-0.5 lg:flex xl:ml-4">
        {NAV.slice(0, count).map((n) => (
          <NavLink
            key={n.to}
            to={n.to}
            end={n.end}
            title={n.short ? n.label : undefined}
            className={({ isActive }) => clsx(ITEM_SHAPE, 'transition-colors', isActive ? ITEM_ACTIVE : ITEM_IDLE)}
          >
            {n.short ?? n.label}
          </NavLink>
        ))}
        {overflow.length > 0 && <MoreMenu items={overflow} />}
      </nav>
      {/* Invisible copies of the links, and of "More" with every label it can show, for useNavFit to measure. */}
      <div aria-hidden className="pointer-events-none invisible absolute left-0 top-0 h-0 w-0 overflow-hidden">
        <div ref={measureRef} className="flex w-max">
          {NAV.map((n) => (
            <span key={n.to} className={ITEM_SHAPE}>
              {n.short ?? n.label}
            </span>
          ))}
          {['More', ...NAV.map((n) => n.short ?? n.label)].map((label, i) => (
            <span key={i} className={clsx(ITEM_SHAPE, 'gap-1')}>
              {label}
              <ChevronDown className="h-3.5 w-3.5" />
            </span>
          ))}
        </div>
      </div>
      <div className="ml-auto flex min-w-0 flex-1 items-center justify-end gap-1 sm:gap-1.5 lg:flex-none">
        <EnvSwitcher />
        <SearchBox />
        <ConnectionMenu />
        <RefreshButton />
        <NavLink to={SETTINGS.to} title="Settings" aria-label="Settings" className={({ isActive }) => clsx(ICON_BUTTON, 'hidden sm:flex', isActive ? ITEM_ACTIVE : ITEM_IDLE)}>
          <SettingsIcon className="h-4 w-4" />
        </NavLink>
        <AccountMenu />
        <HelpMenu />
      </div>
    </header>
  );
}

/** Signs out (everywhere: it is a one-account app) and goes back to the sign-in page. */
export function useSignOut() {
  const qc = useQueryClient();
  return async () => {
    await api.logout();
    await qc.resetQueries();
  };
}

/** How many NAV links fit in the bar; the rest go into "More", whose label depends on the current page. */
function useNavFit(pathname: string) {
  const navRef = useRef<HTMLElement>(null);
  const measureRef = useRef<HTMLDivElement>(null);
  const [count, setCount] = useState(NAV.length);
  useLayoutEffect(() => {
    const nav = navRef.current;
    const row = measureRef.current;
    if (!nav || !row) return;
    const current = NAV.findIndex((n) => isCurrent(n, pathname));
    const fit = () => {
      const room = nav.clientWidth - NAV_CLEARANCE;
      if (room <= 0) return; // the bar is hidden below lg
      const w = Array.from(row.children, (c) => (c as HTMLElement).offsetWidth);
      // Width of "More" while links k.. are in it: it shows the current page's label when that page is inside.
      const more = (k: number) => (k === NAV.length ? 0 : w[NAV.length + 1 + (current >= k ? current : -1)]);
      let k = NAV.length;
      let used = w.slice(0, k).reduce((sum, x) => sum + x + NAV_GAP, 0);
      while (k > 0 && used + more(k) > room) used -= w[--k] + NAV_GAP;
      setCount(k);
    };
    fit();
    const observer = new ResizeObserver(fit);
    observer.observe(nav);
    observer.observe(row); // fonts finishing loading change the link widths
    return () => observer.disconnect();
  }, [pathname]);
  return { navRef, measureRef, count };
}

function Dropdown(props: {
  trigger: (state: { open: boolean; toggle: () => void }) => ReactNode;
  children: (close: () => void) => ReactNode;
  align?: 'left' | 'right';
  panelClass?: string;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const close = useCallback(() => setOpen(false), []);
  const { pathname } = useLocation();
  useEffect(close, [pathname, close]);
  useEffect(() => {
    if (!open) return;
    const onPointer = (e: PointerEvent) => {
      if (!ref.current?.contains(e.target as Node)) close();
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') close();
    };
    document.addEventListener('pointerdown', onPointer);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('pointerdown', onPointer);
      document.removeEventListener('keydown', onKey);
    };
  }, [open, close]);

  return (
    <div ref={ref} className="relative">
      {props.trigger({ open, toggle: () => setOpen((o) => !o) })}
      {open && (
        <div
          className={clsx(
            'fade-in absolute top-full z-50 mt-2.5 rounded-xl border border-line-2 bg-[#0f1729] p-1.5 shadow-2xl shadow-black/40',
            props.align === 'left' ? 'left-0' : 'right-0',
            props.panelClass,
          )}
        >
          {props.children(close)}
        </div>
      )}
    </div>
  );
}

function MenuLink({ item, hint, onClick }: { item: NavItem; hint?: string; onClick?: () => void }) {
  return (
    <NavLink
      to={item.to}
      end={item.end}
      onClick={onClick}
      className={({ isActive }) => clsx('flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors', isActive ? 'bg-cyan-500/10 text-cyan-200' : ITEM_IDLE)}
    >
      <item.icon className="h-4 w-4 shrink-0" />
      <span className="min-w-0">
        <span className="block truncate">{item.label}</span>
        {hint && <span className="block truncate text-xs text-ink-3">{hint}</span>}
      </span>
    </NavLink>
  );
}

function isCurrent(item: NavItem, pathname: string): boolean {
  return item.end ? pathname === item.to : pathname === item.to || pathname.startsWith(`${item.to}/`);
}

function MoreMenu({ items }: { items: NavItem[] }) {
  const { pathname } = useLocation();
  const current = items.find((n) => isCurrent(n, pathname));
  return (
    <Dropdown
      align="left"
      panelClass="w-64"
      trigger={({ open, toggle }) => (
        <button
          type="button"
          onClick={toggle}
          aria-haspopup="true"
          aria-expanded={open}
          className={clsx(ITEM_SHAPE, 'gap-1 transition-colors', current ? ITEM_ACTIVE : open ? 'bg-surface-3/60 text-ink' : ITEM_IDLE)}
        >
          {current ? (current.short ?? current.label) : 'More'}
          <ChevronDown className={clsx('h-3.5 w-3.5 transition-transform', open && 'rotate-180')} />
        </button>
      )}
    >
      {(close) => items.map((n) => <MenuLink key={n.to} item={n} onClick={close} />)}
    </Dropdown>
  );
}

function MobileMenu() {
  return (
    <div className="lg:hidden">
      <Dropdown
        align="left"
        panelClass="w-72"
        trigger={({ open, toggle }) => (
          <button type="button" onClick={toggle} aria-label="Menu" aria-haspopup="true" aria-expanded={open} className={clsx(ICON_BUTTON, ITEM_IDLE)}>
            {open ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
          </button>
        )}
      >
        {(close) => [...NAV, SETTINGS].map((n) => <MenuLink key={n.to} item={n} onClick={close} />)}
      </Dropdown>
    </div>
  );
}

function EnvSwitcher() {
  const { data: s } = useQuery({ queryKey: ['status'], queryFn: api.status });
  const env = useEnv();
  const envs = s?.environments ?? [];
  if (!envs.length) return null;
  const cur = envs.find((e) => e.id === env) ?? envs[0];
  const stateOf = (e: (typeof envs)[number]) => (e.connected ? `UniFi Network ${e.version ?? ''}`.trim() : e.lastError ? 'Cannot connect' : 'Connecting…');
  return (
    <Dropdown
      panelClass="w-80"
      trigger={({ open, toggle }) => (
        <button
          type="button"
          onClick={toggle}
          aria-haspopup="true"
          aria-expanded={open}
          title={`Environment: ${cur.name} — click to switch`}
          className={clsx(
            'flex h-9 max-w-[12rem] shrink-0 items-center gap-2 rounded-lg border px-2.5 text-xs font-medium transition-colors',
            open ? 'border-line-2 bg-surface-3/60 text-ink' : 'border-line bg-surface-2/60 text-ink-2 hover:text-ink',
          )}
        >
          <span className="h-2.5 w-2.5 shrink-0 rounded-full" style={{ background: cur.color }} />
          <span className="hidden truncate xl:inline">{cur.name}</span>
          <ChevronDown className={clsx('h-3.5 w-3.5 shrink-0 text-ink-3 transition-transform', open && 'rotate-180')} />
        </button>
      )}
    >
      {(close) => (
        <div>
          <div className="px-3 pb-1.5 pt-1 text-[11px] font-semibold uppercase tracking-wider text-ink-3">Environment</div>
          {envs.map((e) => (
            <button
              key={e.id}
              type="button"
              onClick={() => {
                setEnv(e.id);
                close();
              }}
              className={clsx('flex w-full items-center gap-3 rounded-lg px-3 py-2 text-left text-sm transition-colors', e.id === cur.id ? 'bg-cyan-500/10 text-cyan-100' : ITEM_IDLE)}
            >
              <span className="h-2.5 w-2.5 shrink-0 rounded-full" style={{ background: e.color }} />
              <span className="min-w-0 flex-1">
                <span className="block truncate">{e.name}</span>
                <span className={clsx('block truncate text-xs', !e.connected && e.lastError ? 'text-rose-300' : 'text-ink-3')}>{stateOf(e)}</span>
              </span>
              {e.id === cur.id && <Check className="h-4 w-4 shrink-0 text-cyan-300" />}
            </button>
          ))}
          <div className="my-1.5 border-t border-line" />
          {envs.length > 1 && <MenuLink item={{ to: '/fleet', label: 'All environments', icon: Layers }} hint="Compare security across environments" onClick={close} />}
          <MenuLink item={{ ...SETTINGS, label: 'Manage environments' }} hint="Add a controller or another site" onClick={close} />
        </div>
      )}
    </Dropdown>
  );
}

function SearchBox() {
  const navigate = useNavigate();
  const [q, setQ] = useState('');
  const input = useRef<HTMLInputElement>(null);

  // "/" jumps to the search box from anywhere that isn't already a text field.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== '/' || e.ctrlKey || e.metaKey || e.altKey) return;
      const t = e.target as HTMLElement | null;
      if (t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName))) return;
      e.preventDefault();
      input.current?.focus();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const v = q.trim();
    if (!v) return;
    if (/^[0-9a-f:.]+$/i.test(v) && (v.includes('.') || v.includes(':'))) navigate(`/investigate/${encodeURIComponent(v)}`);
    else navigate(`/threats?q=${encodeURIComponent(v)}`);
    setQ('');
    input.current?.blur();
  };

  return (
    <form onSubmit={submit} role="search" className="relative min-w-0 flex-1 lg:w-44 lg:flex-none xl:w-56 2xl:w-72">
      <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-ink-3" />
      <input
        ref={input}
        value={q}
        onChange={(e) => setQ(e.target.value)}
        placeholder="Search IP or threat…"
        aria-label="Investigate an IP address or search threats"
        title="Investigate an IP, or search threats (press / to focus)"
        className="peer h-9 w-full rounded-lg border border-line bg-surface-2/80 pl-9 pr-3 text-sm text-ink placeholder:text-ink-3 focus:border-cyan-500/50 focus:outline-none focus:ring-2 focus:ring-cyan-500/15 xl:pr-8"
      />
      {!q && (
        <kbd className="pointer-events-none absolute right-2 top-1/2 hidden -translate-y-1/2 rounded border border-line-2 px-1.5 font-mono text-[10px] leading-4 text-ink-3 xl:block xl:peer-focus:hidden">
          /
        </kbd>
      )}
    </form>
  );
}

function ConnectionMenu() {
  const { data: s } = useQuery({ queryKey: ['status'], queryFn: api.status });
  const live = useLive();
  if (!s) return null;

  const failing = !!s.lastError;
  const state = failing
    ? { label: 'Controller error', dot: 'bg-rose-400' }
    : s.connected
      ? { label: 'Connected', dot: 'bg-emerald-400' }
      : { label: 'Offline', dot: 'bg-slate-500' };
  const firewall = s.controller.firewallMode === 'zone' ? 'Zone-based' : s.controller.firewallMode === 'legacy' ? 'Legacy rules' : 'Unknown';
  const rows: [string, ReactNode][] = [
    ['Controller', s.controller.url ?? 'Not configured'],
    ['Site', s.controller.siteDescription ? `${s.controller.siteDescription} (${s.controller.site})` : s.controller.site],
    ['Network', s.controller.version ? `UniFi Network ${s.controller.version}` : 'Unknown version'],
    ['Firewall', firewall],
    ...(s.controller.gatewayModel ? [['Gateway', s.controller.gatewayModel] as [string, ReactNode]] : []),
    ['Live data', live.connected ? 'Streaming' : 'Disconnected'],
    ['Last sync', s.lastRefresh ? timeAgo(s.lastRefresh) : 'Not yet'],
  ];

  return (
    <Dropdown
      panelClass="w-80"
      trigger={({ open, toggle }) => (
        <button
          type="button"
          onClick={toggle}
          aria-haspopup="true"
          aria-expanded={open}
          title={`${state.label}${s.readOnly ? ' · read-only' : ''} · live updates ${live.connected ? 'on' : 'off'}`}
          className={clsx(
            'flex h-9 shrink-0 items-center gap-2 rounded-lg border px-2.5 text-xs font-medium transition-colors',
            failing ? 'border-rose-500/30 bg-rose-500/10 text-rose-200' : open ? 'border-line-2 bg-surface-3/60 text-ink' : 'border-line bg-surface-2/60 text-ink-2 hover:text-ink',
          )}
        >
          <span className={clsx('relative inline-block h-2 w-2 rounded-full', state.dot, live.connected && 'live-dot')} />
          <span className="hidden whitespace-nowrap xl:inline">{state.label}</span>
          {s.readOnly && <LockKeyhole className="h-3.5 w-3.5 text-amber-300" />}
          <ChevronDown className={clsx('hidden h-3.5 w-3.5 text-ink-3 transition-transform sm:block', open && 'rotate-180')} />
        </button>
      )}
    >
      {() => (
        <div className="p-1.5 text-xs">
          <div className="mb-2 flex items-center gap-2">
            <span className={clsx('inline-block h-2 w-2 rounded-full', state.dot)} />
            <span className="text-sm font-medium text-ink">{state.label}</span>
          </div>
          <dl className="space-y-1.5">
            {rows.map(([k, v]) => (
              <div key={k} className="flex gap-3">
                <dt className="w-20 shrink-0 text-ink-3">{k}</dt>
                <dd className="min-w-0 break-words text-ink-2">{v}</dd>
              </div>
            ))}
          </dl>
          {s.readOnly && (
            <div className="mt-3 flex items-start gap-2 rounded-lg border border-amber-500/25 bg-amber-500/10 p-2 text-amber-200">
              <LockKeyhole className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              Read-only mode: hardening changes are disabled.
            </div>
          )}
          {failing && <div className="mt-3 break-words rounded-lg border border-rose-500/25 bg-rose-500/10 p-2 text-rose-200">{s.lastError}</div>}
        </div>
      )}
    </Dropdown>
  );
}

function RefreshButton() {
  const qc = useQueryClient();
  const [busy, setBusy] = useState(false);
  const refresh = async () => {
    setBusy(true);
    try {
      await api.refresh();
      await qc.invalidateQueries();
    } finally {
      setBusy(false);
    }
  };
  return (
    <button type="button" onClick={refresh} disabled={busy} title="Refresh data from the controller" aria-label="Refresh" className={clsx(ICON_BUTTON, ITEM_IDLE, 'hidden disabled:opacity-60 sm:flex')}>
      <RefreshCw className={clsx('h-4 w-4', busy && 'animate-spin')} />
    </button>
  );
}

function AccountMenu() {
  const { data: s } = useQuery({ queryKey: ['status'], queryFn: api.status });
  const signOut = useSignOut();
  if (!s?.username) return null;
  return (
    <Dropdown
      panelClass="w-64"
      trigger={({ open, toggle }) => (
        <button
          type="button"
          onClick={toggle}
          aria-haspopup="true"
          aria-expanded={open}
          aria-label="Account"
          title={`Signed in as ${s.username}`}
          className={clsx(ICON_BUTTON, open ? 'bg-surface-3/60 text-ink' : ITEM_IDLE)}
        >
          <CircleUserRound className="h-4 w-4" />
        </button>
      )}
    >
      {(close) => (
        <>
          <div className="truncate px-3 pb-2 pt-1.5 text-xs text-ink-3">
            Signed in as <span className="font-medium text-ink">{s.username}</span>
          </div>
          <MenuLink item={{ to: '/settings#account', label: 'Username & password', icon: KeyRound }} hint="Change how you sign in" onClick={close} />
          <button
            type="button"
            onClick={() => {
              close();
              void signOut();
            }}
            className={clsx('flex w-full items-center gap-3 rounded-lg px-3 py-2 text-left text-sm transition-colors', ITEM_IDLE)}
          >
            <LogOut className="h-4 w-4 shrink-0" />
            Sign out
          </button>
        </>
      )}
    </Dropdown>
  );
}

function HelpMenu() {
  const { data: s } = useQuery({ queryKey: ['status'], queryFn: api.status });
  return (
    <Dropdown
      panelClass="w-72"
      trigger={({ open, toggle }) => (
        <button
          type="button"
          onClick={toggle}
          aria-haspopup="true"
          aria-expanded={open}
          title={`Help · Security Console v${APP_VERSION}`}
          className={clsx('flex h-10 shrink-0 items-center gap-2 rounded-lg px-2 text-left transition-colors', open ? 'bg-surface-3/60 text-ink' : ITEM_IDLE)}
        >
          <CircleHelp className="h-4 w-4 shrink-0" />
          <span className="hidden flex-col leading-none sm:flex">
            <span className="text-sm font-medium">Help</span>
            <span className="mt-1 font-mono text-[10px] text-ink-3">v{APP_VERSION}</span>
          </span>
        </button>
      )}
    >
      {(close) => (
        <>
          <MenuLink item={{ to: '/learn', label: 'Threat Encyclopedia', icon: BookOpen }} hint="What each threat type means" onClick={close} />
          <MenuLink item={{ ...SETTINGS, label: 'Settings & diagnostics', icon: Stethoscope }} hint="Connection, API key and endpoint checks" onClick={close} />
          <div className="flex items-center gap-3 px-3 py-2 text-sm text-ink-2">
            <Keyboard className="h-4 w-4 shrink-0" />
            <span>
              Press <kbd className="rounded border border-line-2 px-1.5 font-mono text-[11px] text-ink">/</kbd> to search
            </span>
          </div>
          <div className="mt-1.5 space-y-1 border-t border-line px-3 pb-1.5 pt-2.5 text-xs">
            <div className="flex justify-between gap-3">
              <span className="text-ink-3">Security Console</span>
              <span className="font-mono text-ink-2">v{APP_VERSION}</span>
            </div>
            {s?.controller.version && (
              <div className="flex justify-between gap-3">
                <span className="text-ink-3">UniFi Network</span>
                <span className="font-mono text-ink-2">{s.controller.version}</span>
              </div>
            )}
          </div>
        </>
      )}
    </Dropdown>
  );
}
