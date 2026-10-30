import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { App } from './App';
import { getEnv } from './lib/env';
import './styles.css';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // Cache entries are per environment, so switching never shows another environment's data.
      queryKeyHashFn: (key) => JSON.stringify([getEnv(), key]),
      staleTime: 15_000,
      refetchOnWindowFocus: false,
      retry: (count, err) => count < 2 && !(err && typeof err === 'object' && 'status' in err && (err as { status: number }).status < 500),
    },
  },
});

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <App />
      </BrowserRouter>
    </QueryClientProvider>
  </StrictMode>,
);
