import { useEffect } from 'react';
import { Navigate, Route, Routes, useLocation } from 'react-router';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from './lib/api';
import { setEnv, useEnv } from './lib/env';
import { LiveProvider } from './lib/live';
import { FleetPage } from './pages/Fleet';
import { Spinner } from './components/ui';
import { TopNav } from './components/TopNav';
import { OverviewPage } from './pages/Overview';
import { ThreatsPage } from './pages/Threats';
import { ThreatTypesPage } from './pages/ThreatTypes';
import { InvestigatePage } from './pages/Investigate';
import { FirewallPage } from './pages/Firewall';
import { HardeningPage } from './pages/Hardening';
import { LivePage } from './pages/Live';
import { DevicesPage } from './pages/Devices';
import { ActivityPage } from './pages/Activity';
import { SettingsPage } from './pages/Settings';
import { LoginPage } from './pages/Login';

export function App() {
  const env = useEnv();
  const status = useQuery({ queryKey: ['status'], queryFn: api.status, refetchInterval: 30_000 });
  const location = useLocation();
  const qc = useQueryClient();

  useEffect(() => {
    const h = () => void qc.invalidateQueries({ queryKey: ['status'] });
    window.addEventListener('usc:unauthorized', h);
    return () => window.removeEventListener('usc:unauthorized', h);
  }, [qc]);

  // No selection yet, or the selected environment was removed: follow the server's default.
  const serverEnv = status.data?.envId ?? null;
  useEffect(() => {
    if (serverEnv && serverEnv !== env) setEnv(serverEnv);
  }, [serverEnv, env]);

  if (status.isLoading) {
    return (
      <div className="flex h-full items-center justify-center gap-2 text-sm text-ink-3">
        <Spinner /> Starting…
      </div>
    );
  }
  const s = status.data;
  if (s?.authRequired && !s.authenticated) {
    return <LoginPage setup={!!s.setupRequired} />;
  }
  const needsSetup = s && !s.configured;
  if (needsSetup && location.pathname !== '/settings') return <Navigate to="/settings?setup=1" replace />;

  return (
    <LiveProvider enabled={!!s && s.configured}>
      <div className="flex h-full flex-col">
        <TopNav />
        <main className="min-h-0 flex-1 overflow-y-auto">
          {/* Keyed by environment so every page starts fresh after switching. */}
          <div key={env ?? 'none'} className="px-4 py-5 sm:px-6 2xl:px-8">
            <Routes>
              <Route path="/" element={<OverviewPage />} />
              <Route path="/fleet" element={<FleetPage />} />
              <Route path="/threats" element={<ThreatsPage />} />
              <Route path="/learn" element={<ThreatTypesPage />} />
              <Route path="/learn/:key" element={<ThreatTypesPage />} />
              <Route path="/investigate" element={<InvestigatePage />} />
              <Route path="/investigate/:ip" element={<InvestigatePage />} />
              <Route path="/firewall" element={<FirewallPage />} />
              <Route path="/firewall/:tab" element={<FirewallPage />} />
              <Route path="/hardening" element={<HardeningPage />} />
              <Route path="/live" element={<LivePage />} />
              <Route path="/devices" element={<DevicesPage />} />
              <Route path="/activity" element={<ActivityPage />} />
              <Route path="/settings" element={<SettingsPage />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </div>
        </main>
      </div>
    </LiveProvider>
  );
}
