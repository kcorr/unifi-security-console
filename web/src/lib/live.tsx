import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import type { LiveEvent, LiveSample, LiveSnapshot, ThreatEvent } from '@shared/types';
import { api, apiUrl } from './api';
import { useEnv } from './env';

interface LiveState {
  connected: boolean;
  snapshot: LiveSnapshot | null;
  samples: LiveSample[];
  threats: ThreatEvent[];
  /** ids of threats that arrived while this tab was open (for highlight animations) */
  freshIds: Set<string>;
}

const LiveContext = createContext<LiveState>({ connected: false, snapshot: null, samples: [], threats: [], freshIds: new Set() });

const MAX_SAMPLES = 720; // 1h at 5s

export function LiveProvider({ children, enabled }: { children: ReactNode; enabled: boolean }) {
  const qc = useQueryClient();
  const env = useEnv();
  const [state, setState] = useState<LiveState>({ connected: false, snapshot: null, samples: [], threats: [], freshIds: new Set() });
  const esRef = useRef<EventSource | null>(null);

  useEffect(() => {
    if (!enabled) return;
    let cancelled = false;
    setState({ connected: false, snapshot: null, samples: [], threats: [], freshIds: new Set() });
    api
      .liveHistory()
      .then((h) => !cancelled && setState((s) => ({ ...s, samples: mergeSamples(h, s.samples) })))
      .catch(() => undefined);
    api
      .threats({ limit: 30 })
      .then((r) => !cancelled && setState((s) => ({ ...s, threats: r.events })))
      .catch(() => undefined);

    const es = new EventSource(apiUrl('/live/stream'));
    esRef.current = es;
    es.onopen = () => setState((s) => ({ ...s, connected: true }));
    es.onerror = () => setState((s) => ({ ...s, connected: false }));
    es.onmessage = (msg) => {
      let ev: LiveEvent;
      try {
        ev = JSON.parse(msg.data) as LiveEvent;
      } catch {
        return;
      }
      if (ev.type === 'snapshot') {
        setState((s) => ({ ...s, connected: true, snapshot: ev.data, samples: [...s.samples, ev.sample].slice(-MAX_SAMPLES) }));
      } else if (ev.type === 'threat') {
        setState((s) => {
          const fresh = new Set(s.freshIds);
          fresh.add(ev.data.id);
          return { ...s, threats: [ev.data, ...s.threats.filter((t) => t.id !== ev.data.id)].slice(0, 100), freshIds: fresh };
        });
        void qc.invalidateQueries({ queryKey: ['threats'] });
        void qc.invalidateQueries({ queryKey: ['overview'] });
      } else if (ev.type === 'config-changed') {
        void qc.invalidateQueries();
      }
    };
    return () => {
      cancelled = true;
      es.close();
      esRef.current = null;
    };
  }, [enabled, qc, env]);

  return <LiveContext.Provider value={state}>{children}</LiveContext.Provider>;
}

function mergeSamples(history: LiveSample[], current: LiveSample[]): LiveSample[] {
  const last = history[history.length - 1]?.t ?? 0;
  return [...history, ...current.filter((s) => s.t > last)].slice(-MAX_SAMPLES);
}

export function useLive(): LiveState {
  return useContext(LiveContext);
}
