import { useQuery } from '@tanstack/react-query';
import clsx from 'clsx';
import { CircleArrowUp, PowerOff, WifiOff } from 'lucide-react';
import { api } from '../lib/api';
import { fmtBps, fmtDuration, fmtTime, plural, timeAgo } from '../lib/format';
import { Badge, Callout, Drawer, ErrorBox, KV, Loading } from './ui';
import { KIND_LABEL, STATE, uplinkText } from '../pages/Devices';

const speed = (mbps: number | null) => (mbps === null ? '—' : mbps >= 1000 ? `${mbps / 1000} G` : `${mbps} M`);

/** One UniFi device in detail: status and firmware, health, ports, radios and who is connected through it. */
export function UnifiDevicePanel({ mac, onClose, onClient }: { mac: string | null; onClose: () => void; onClient: (mac: string) => void }) {
  const q = useQuery({ queryKey: ['unifi-device', mac], queryFn: () => api.unifiDevice(mac!), enabled: !!mac, refetchInterval: 10_000, retry: false });
  const d = q.data;
  return (
    <Drawer open={!!mac} onClose={onClose} title={d?.name ?? 'UniFi device'} subtitle={d ? [KIND_LABEL[d.kind], d.model, d.ip, d.mac].filter(Boolean).join(' · ') : undefined}>
      {q.isLoading && <Loading />}
      {q.error && <ErrorBox error={q.error} />}
      {d && (
        <div className="space-y-6">
          <div className="space-y-2">
            {d.state === 'offline' && (
              <Callout tone="warn" icon={<WifiOff className="h-4 w-4" />} title="Offline">
                {d.lastSeen ? `Last seen ${fmtTime(d.lastSeen)} (${timeAgo(d.lastSeen)}). ` : ''}Check its power and cable{d.uplink?.name && !d.uplink.wireless ? ` (${uplinkText(d)})` : ''}, or remove it in UniFi if it is retired.
              </Callout>
            )}
            {d.state === 'disabled' && (
              <Callout tone="info" icon={<PowerOff className="h-4 w-4" />} title="Disabled in UniFi">
                It is switched off on purpose, so it isn’t counted as a problem.
              </Callout>
            )}
            {d.update && (
              <Callout tone="warn" icon={<CircleArrowUp className="h-4 w-4" />} title={`Firmware ${d.update} is available`}>
                It runs {d.version ?? 'an older version'}. Install the update from the UniFi app (Devices → {d.name} → Update); this console never installs firmware.
              </Callout>
            )}
            {d.endOfLife && (
              <Callout tone="warn" title="No more firmware updates">
                Ubiquiti has marked this model as end of life, so security fixes will stop. Plan to replace it.
              </Callout>
            )}
          </div>

          <section>
            <h3 className="mb-1 text-xs font-semibold uppercase tracking-wider text-ink-3">Status</h3>
            <dl>
              <KV k="State" v={<span className="inline-flex items-center gap-1.5"><span className={clsx('h-2 w-2 rounded-full', STATE[d.state].dot)} />{STATE[d.state].label}</span>} />
              <KV k="Firmware" v={<span className="mono text-[13px]">{d.version ?? '—'}{d.update ? ` → ${d.update}` : ''}</span>} />
              {d.uptime !== null && <KV k="Up for" v={fmtDuration(d.uptime)} />}
              {d.clients !== null && <KV k="Clients" v={String(d.clients)} />}
              {d.cpu !== null && <KV k="CPU" v={`${d.cpu}%`} />}
              {d.mem !== null && <KV k="Memory" v={`${d.mem}%`} />}
              {d.tempC !== null && <KV k="Temperature" v={`${d.tempC}°C`} />}
              {uplinkText(d) && <KV k={d.kind === 'gateway' ? 'Internet' : 'Connected to'} v={uplinkText(d)} />}
              {d.poe && <KV k="PoE power" v={`${d.poe.usedW ?? 0} W used${d.poe.maxW ? ` of ${d.poe.maxW} W` : ''}`} />}
            </dl>
          </section>

          {d.ports.length > 0 && (
            <section>
              <h3 className="mb-1 text-xs font-semibold uppercase tracking-wider text-ink-3">Ports</h3>
              <div className="overflow-x-auto rounded-lg border border-line">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-line text-left text-ink-3">
                      <th className="px-3 py-1.5 font-medium">#</th>
                      <th className="px-2 py-1.5 font-medium">Name</th>
                      <th className="px-2 py-1.5 font-medium">Link</th>
                      <th className="px-2 py-1.5 text-right font-medium">PoE</th>
                      <th className="px-2 py-1.5 text-right font-medium" title="Addresses the port has seen">Devices</th>
                      <th className="px-3 py-1.5 text-right font-medium" title="To the device behind the port / from it">Traffic now</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-line/50">
                    {d.ports.map((p) => (
                      <tr key={p.idx} className={clsx(!p.up && 'text-ink-3')}>
                        <td className="mono px-3 py-1.5">{p.idx}</td>
                        <td className="px-2 py-1.5">
                          {p.name}
                          {p.uplink && <Badge tone="slate" className="ml-1.5">uplink</Badge>}
                          {!p.enabled && <Badge tone="slate" className="ml-1.5">off</Badge>}
                        </td>
                        <td className="px-2 py-1.5">{p.up ? <span className="text-emerald-300">{speed(p.speedMbps)}{p.fullDuplex === false ? ' half' : ''}</span> : 'down'}{p.errors ? <span className="ml-1 text-amber-300">· {p.errors} errors</span> : null}</td>
                        <td className="px-2 py-1.5 text-right">{p.poeWatts !== null && p.poeWatts > 0 ? `${p.poeWatts} W` : ''}</td>
                        <td className="px-2 py-1.5 text-right">{p.devices ?? ''}</td>
                        <td className="mono px-3 py-1.5 text-right">{p.up && (p.downBps || p.upBps) ? `↓ ${fmtBps(p.downBps)} ↑ ${fmtBps(p.upBps)}` : ''}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}

          {d.radios.length > 0 && (
            <section>
              <h3 className="mb-1 text-xs font-semibold uppercase tracking-wider text-ink-3">Radios</h3>
              <div className="grid gap-2 sm:grid-cols-2">
                {d.radios.map((r, i) => (
                  <div key={`${r.band}-${i}`} className="rounded-lg border border-line bg-surface-2/40 p-3 text-xs">
                    <div className="mb-1 font-medium text-ink">{r.band}</div>
                    <dl className="space-y-0.5 text-ink-2">
                      <div>Channel {r.channel ?? '—'}{r.width ? ` · ${r.width} MHz` : ''}{r.txPower !== null ? ` · ${r.txPower} dBm` : ''}</div>
                      <div>{plural(r.clients ?? 0, 'client')}{r.experience !== null ? ` · experience ${r.experience}%` : ''}</div>
                      {r.utilization !== null && <div className={clsx(r.utilization > 70 && 'text-amber-300')}>Channel busy {r.utilization}% of the time{r.utilization > 70 ? ' (crowded)' : ''}</div>}
                      {r.retriesPct !== null && <div>Retries {r.retriesPct}%</div>}
                    </dl>
                  </div>
                ))}
              </div>
            </section>
          )}

          {d.connected.length > 0 && (
            <section>
              <h3 className="mb-1 text-xs font-semibold uppercase tracking-wider text-ink-3">Connected through it ({d.connected.length})</h3>
              <ul className="divide-y divide-line/50 rounded-lg border border-line">
                {d.connected.map((c) => (
                  <li key={c.mac}>
                    <button type="button" onClick={() => onClient(c.mac)} className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs hover:bg-surface-2/60">
                      <span className="min-w-0 flex-1 truncate text-ink">{c.name}</span>
                      <span className="mono text-ink-3">{c.ip ?? ''}</span>
                      <span className="w-20 text-right text-ink-3">{c.wired ? (c.port !== null ? `port ${c.port}` : 'wired') : (c.ssid ?? 'Wi-Fi')}</span>
                    </button>
                  </li>
                ))}
              </ul>
            </section>
          )}
        </div>
      )}
    </Drawer>
  );
}
