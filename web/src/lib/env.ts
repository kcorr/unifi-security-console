// The environment the UI is looking at. Kept in localStorage (and ?env= in the URL, so
// links can point at a specific environment). Every API call is scoped to it.

import { useSyncExternalStore } from 'react';

const KEY = 'usc.env';
const listeners = new Set<() => void>();

function initial(): string | null {
  try {
    const fromUrl = new URL(window.location.href).searchParams.get('env');
    if (fromUrl) return fromUrl;
    return window.localStorage.getItem(KEY);
  } catch {
    return null;
  }
}

let current: string | null = initial();

export function getEnv(): string | null {
  return current;
}

export function setEnv(id: string | null): void {
  if (id === current) return;
  current = id;
  try {
    if (id) window.localStorage.setItem(KEY, id);
    else window.localStorage.removeItem(KEY);
  } catch {
    /* storage unavailable - selection lasts for this tab only */
  }
  const url = new URL(window.location.href);
  if (url.searchParams.has('env')) {
    if (id) url.searchParams.set('env', id);
    else url.searchParams.delete('env');
    window.history.replaceState(window.history.state, '', url);
  }
  for (const l of listeners) l();
}

function subscribe(l: () => void): () => void {
  listeners.add(l);
  return () => listeners.delete(l);
}

export function useEnv(): string | null {
  return useSyncExternalStore(subscribe, getEnv);
}
