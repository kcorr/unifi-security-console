import { Area, AreaChart, Bar, BarChart, CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import type { LiveSample, Severity, ThreatSummary } from '@shared/types';
import { fmtBps, fmtBytes, fmtNum, fmtTime } from '../lib/format';
import { SEVERITY_HEX } from './ui';

const AXIS = { fill: '#6f7a93', fontSize: 11 };
const GRID = '#1b2438';

function TooltipBox({ title, rows }: { title: string; rows: { label: string; value: string; color?: string }[] }) {
  return (
    <div className="rounded-lg border border-line-2 bg-[#0f1729] px-3 py-2 text-xs shadow-xl">
      <div className="mb-1 font-medium text-ink-2">{title}</div>
      {rows.map((r) => (
        <div key={r.label} className="flex items-center justify-between gap-4">
          <span className="flex items-center gap-1.5 text-ink-3">
            {r.color && <span className="h-2 w-2 rounded-full" style={{ background: r.color }} />}
            {r.label}
          </span>
          <span className="mono text-ink">{r.value}</span>
        </div>
      ))}
    </div>
  );
}

export function ThroughputChart({ samples, height = 260, tickFormat = (t: number) => fmtTime(t, false) }: { samples: LiveSample[]; height?: number; tickFormat?: (t: number) => string }) {
  const data = samples.map((s) => ({ t: s.t, rx: s.rxBps ?? 0, tx: s.txBps ?? 0 }));
  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: 0 }}>
        <defs>
          <linearGradient id="rxFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#22d3ee" stopOpacity={0.35} />
            <stop offset="100%" stopColor="#22d3ee" stopOpacity={0} />
          </linearGradient>
          <linearGradient id="txFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#a78bfa" stopOpacity={0.3} />
            <stop offset="100%" stopColor="#a78bfa" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid stroke={GRID} vertical={false} />
        <XAxis dataKey="t" type="number" domain={['dataMin', 'dataMax']} tickFormatter={tickFormat} tick={AXIS} axisLine={false} tickLine={false} minTickGap={40} />
        <YAxis tickFormatter={(v) => fmtBps(v)} tick={AXIS} axisLine={false} tickLine={false} width={72} />
        <Tooltip
          content={({ active, payload, label }) =>
            active && payload?.length ? (
              <TooltipBox
                title={fmtTime(label as number)}
                rows={[
                  { label: 'Download', value: fmtBps(payload.find((p) => p.dataKey === 'rx')?.value as number), color: '#22d3ee' },
                  { label: 'Upload', value: fmtBps(payload.find((p) => p.dataKey === 'tx')?.value as number), color: '#a78bfa' },
                ]}
              />
            ) : null
          }
        />
        <Area type="monotone" dataKey="rx" stroke="#22d3ee" strokeWidth={1.8} fill="url(#rxFill)" isAnimationActive={false} />
        <Area type="monotone" dataKey="tx" stroke="#a78bfa" strokeWidth={1.8} fill="url(#txFill)" isAnimationActive={false} />
      </AreaChart>
    </ResponsiveContainer>
  );
}

export function MetricLine({ samples, dataKey, color, format, height = 160, domain, seriesName, tickFormat = (t: number) => fmtTime(t, false) }: { samples: LiveSample[]; dataKey: keyof LiveSample; color: string; format: (v: number) => string; height?: number; domain?: [number, number]; seriesName?: string; tickFormat?: (t: number) => string }) {
  const data = samples.map((s) => ({ t: s.t, v: s[dataKey] as number | null }));
  return (
    <ResponsiveContainer width="100%" height={height}>
      <LineChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: 0 }}>
        <CartesianGrid stroke={GRID} vertical={false} />
        <XAxis dataKey="t" type="number" domain={['dataMin', 'dataMax']} tickFormatter={tickFormat} tick={AXIS} axisLine={false} tickLine={false} minTickGap={40} />
        <YAxis tickFormatter={(v) => format(v)} tick={AXIS} axisLine={false} tickLine={false} width={52} domain={domain ?? ['auto', 'auto']} />
        <Tooltip
          content={({ active, payload, label }) =>
            active && payload?.length ? <TooltipBox title={fmtTime(label as number)} rows={[{ label: seriesName ?? String(dataKey), value: format(payload[0].value as number), color }]} /> : null
          }
        />
        <Line type="monotone" dataKey="v" stroke={color} strokeWidth={1.8} dot={false} isAnimationActive={false} connectNulls />
      </LineChart>
    </ResponsiveContainer>
  );
}

export function Sparkline({ values, color = '#22d3ee', height = 36 }: { values: number[]; color?: string; height?: number }) {
  const data = values.map((v, i) => ({ i, v }));
  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={data} margin={{ top: 2, right: 0, bottom: 0, left: 0 }}>
        <defs>
          <linearGradient id={`spark-${color.slice(1)}`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={color} stopOpacity={0.35} />
            <stop offset="100%" stopColor={color} stopOpacity={0} />
          </linearGradient>
        </defs>
        <Area type="monotone" dataKey="v" stroke={color} strokeWidth={1.5} fill={`url(#spark-${color.slice(1)})`} isAnimationActive={false} />
      </AreaChart>
    </ResponsiveContainer>
  );
}

/** Traffic of one device per hour: download and upload stacked. */
export function HourlyUsage({ hours, height = 140 }: { hours: { t: number; down: number; up: number }[]; height?: number }) {
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={hours} margin={{ top: 8, right: 8, bottom: 0, left: -8 }} barCategoryGap={1}>
        <CartesianGrid stroke={GRID} vertical={false} />
        <XAxis dataKey="t" tickFormatter={(t) => fmtTime(t, false)} tick={AXIS} axisLine={false} tickLine={false} minTickGap={36} />
        <YAxis tickFormatter={(v) => fmtBytes(v)} tick={AXIS} axisLine={false} tickLine={false} width={60} />
        <Tooltip
          cursor={{ fill: 'rgba(148,163,184,0.06)' }}
          content={({ active, payload, label }) =>
            active && payload?.length ? (
              <TooltipBox
                title={fmtTime(label as number)}
                rows={[
                  { label: 'Download', value: fmtBytes(payload.find((p) => p.dataKey === 'down')?.value as number), color: '#22d3ee' },
                  { label: 'Upload', value: fmtBytes(payload.find((p) => p.dataKey === 'up')?.value as number), color: '#a78bfa' },
                ]}
              />
            ) : null
          }
        />
        <Bar dataKey="down" stackId="a" fill="#22d3ee" isAnimationActive={false} />
        <Bar dataKey="up" stackId="a" fill="#a78bfa" isAnimationActive={false} />
      </BarChart>
    </ResponsiveContainer>
  );
}

const SEV_KEYS: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];

export function ThreatTimeline({ summary, height = 220 }: { summary: ThreatSummary; height?: number }) {
  const bucketHours = summary.bucketMs / 3600e3;
  const fmt = (t: number) => (bucketHours >= 24 ? new Date(t).toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) : fmtTime(t, false));
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={summary.timeline} margin={{ top: 8, right: 8, bottom: 0, left: -8 }} barCategoryGap={1}>
        <CartesianGrid stroke={GRID} vertical={false} />
        <XAxis dataKey="t" tickFormatter={fmt} tick={AXIS} axisLine={false} tickLine={false} minTickGap={36} />
        <YAxis tick={AXIS} axisLine={false} tickLine={false} allowDecimals={false} width={40} />
        <Tooltip
          cursor={{ fill: 'rgba(148,163,184,0.06)' }}
          content={({ active, payload, label }) =>
            active && payload?.length ? (
              <TooltipBox
                title={`${fmtTime(label as number)}`}
                rows={[
                  ...SEV_KEYS.slice()
                    .reverse()
                    .map((k) => ({ label: k, value: fmtNum(payload.find((p) => p.dataKey === k)?.value as number), color: SEVERITY_HEX[k] }))
                    .filter((r) => r.value !== '0'),
                  { label: 'blocked', value: fmtNum((payload[0].payload as { blocked: number }).blocked) },
                ]}
              />
            ) : null
          }
        />
        {SEV_KEYS.map((k) => (
          <Bar key={k} dataKey={k} stackId="s" fill={SEVERITY_HEX[k]} isAnimationActive={false} />
        ))}
      </BarChart>
    </ResponsiveContainer>
  );
}

export function HBarList({ items, color = '#22d3ee', format = fmtNum, onClick }: { items: { key: string; label: React.ReactNode; value: number; sub?: React.ReactNode; color?: string }[]; color?: string; format?: (n: number) => string; onClick?: (key: string) => void }) {
  const max = Math.max(1, ...items.map((i) => i.value));
  return (
    <ul className="space-y-2">
      {items.map((it) => (
        <li key={it.key} className={onClick ? 'cursor-pointer rounded-md hover:bg-surface-3/40' : undefined} onClick={onClick ? () => onClick(it.key) : undefined}>
          <div className="flex items-baseline justify-between gap-3 text-sm">
            <span className="min-w-0 truncate text-ink-2">{it.label}</span>
            <span className="mono shrink-0 text-xs text-ink">{format(it.value)}</span>
          </div>
          <div className="mt-1 h-1.5 w-full overflow-hidden rounded-full bg-slate-800/80">
            <div className="h-full rounded-full" style={{ width: `${Math.max(2, (it.value / max) * 100)}%`, background: it.color ?? color }} />
          </div>
          {it.sub && <div className="mt-0.5 text-[11px] text-ink-3">{it.sub}</div>}
        </li>
      ))}
    </ul>
  );
}
