import { Component, Suspense, lazy, useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider, QueryCache } from '@tanstack/react-query';
import toast, { Toaster } from 'react-hot-toast';

const queryClient = new QueryClient({
  queryCache: new QueryCache({
    onError: (error) => {
      // Show toast for query errors (API down, 500, etc.) — but not for 401 (handled by interceptor)
      const status = (error as { response?: { status?: number } })?.response?.status;
      if (status !== 401) {
        toast.error('Failed to load data. Check API connection.', { id: 'query-error', duration: 3000 });
      }
    },
  }),
  defaultOptions: {
    queries: {
      staleTime: 60_000,
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});
import { Layout } from './components/layout/Layout';
import { GlobalSearch } from './components/GlobalSearch';
import { Login } from './pages/Login';
import { SetupWizard } from './components/SetupWizard';
import { api } from './lib/api';

// Lazy-loaded page components for code splitting
const Dashboard = lazy(() => import('./pages/Dashboard').then(m => ({ default: m.Dashboard })));
const Blacklists = lazy(() => import('./pages/Blacklists').then(m => ({ default: m.Blacklists })));
const Logs = lazy(() => import('./pages/Logs').then(m => ({ default: m.Logs })));
const Settings = lazy(() => import('./pages/Settings').then(m => ({ default: m.Settings })));
const ThreatIntel = lazy(() => import('./pages/ThreatIntel').then(m => ({ default: m.ThreatIntel })));

class ErrorBoundary extends Component<{ children: React.ReactNode }, { error: Error | null }> {
  constructor(props: { children: React.ReactNode }) {
    super(props);
    this.state = { error: null };
  }
  static getDerivedStateFromError(error: Error) {
    return { error };
  }
  render() {
    if (this.state.error) {
      return (
        <div className="flex items-center justify-center h-screen bg-background text-foreground">
          <div className="text-center space-y-3 max-w-md px-4">
            <p className="text-lg font-semibold text-destructive">Something went wrong</p>
            <p className="text-sm text-muted-foreground font-mono">{this.state.error.message}</p>
            <button
              type="button"
              onClick={() => this.setState({ error: null })}
              className="mt-4 px-4 py-2 bg-secondary rounded-md text-sm font-medium hover:bg-secondary/80 transition-colors"
            >
              Try again
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

function PageLoader() {
  return (
    <div className="flex items-center justify-center h-64">
      <div className="animate-spin w-6 h-6 border-2 border-primary border-t-transparent rounded-full" />
    </div>
  );
}

function NotFound() {
  return (
    <div className="flex flex-col items-center justify-center h-full text-center gap-2 py-24">
      <span className="text-5xl font-bold text-muted-foreground/30">404</span>
      <p className="text-sm text-muted-foreground">Page not found</p>
    </div>
  );
}

function App() {
  const handleLogout = () => {
    localStorage.removeItem('auth_token');
    setIsAuthenticated(false);
    queryClient.clear();
  };

  const [isAuthenticated, setIsAuthenticated] = useState(() => {
    const token = localStorage.getItem('auth_token');
    if (!token) return false;
    // Check JWT expiry on mount — clear stale tokens
    try {
      const parts = token.split('.');
      if (parts.length === 3) {
        const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
        if (payload.exp && payload.exp * 1000 < Date.now()) {
          localStorage.removeItem('auth_token');
          return false;
        }
      }
    } catch { /* malformed token — treat as valid, API will 401 */ }
    return true;
  });

  const [wizardDone, setWizardDone] = useState<boolean | null>(null);

  // Listen for session expiry warning from API interceptor
  useEffect(() => {
    const handler = () => {
      toast('Session expiring soon — save your work', { icon: '⏳', duration: 10000, id: 'session-warn' });
    };
    window.addEventListener('session-expiring', handler);
    return () => window.removeEventListener('session-expiring', handler);
  }, []);

  // Check wizard status after login
  useEffect(() => {
    if (!isAuthenticated) return;
    api.get('settings').then(res => {
      const settings = res.data?.data || [];
      const wizardSetting = Array.isArray(settings)
        ? settings.find((s: { setting_name: string }) => s.setting_name === 'wizard_completed')
        : null;
      setWizardDone(wizardSetting?.setting_value === 'true');
    }).catch(() => setWizardDone(true)); // If API fails, skip wizard
  }, [isAuthenticated]);

  if (!isAuthenticated) {
    return <Login onLogin={() => setIsAuthenticated(true)} />;
  }

  // Loading — checking wizard status
  if (wizardDone === null) {
    return (
      <div className="flex items-center justify-center h-screen bg-background">
        <div className="animate-spin w-6 h-6 border-2 border-primary border-t-transparent rounded-full" />
      </div>
    );
  }

  // Show wizard if not completed
  if (wizardDone === false) {
    return <SetupWizard onComplete={() => setWizardDone(true)} />;
  }

  return (
    <>
      <QueryClientProvider client={queryClient}>
        <BrowserRouter>
          <GlobalSearch />
          <ErrorBoundary>
            <Suspense fallback={<PageLoader />}>
              <Routes>
                <Route path="/" element={<Layout onLogout={handleLogout} />}>
                  <Route index element={<ErrorBoundary><Dashboard /></ErrorBoundary>} />
                  <Route path="blacklists" element={<ErrorBoundary><Blacklists /></ErrorBoundary>} />
                  <Route path="threats" element={<ErrorBoundary><ThreatIntel /></ErrorBoundary>} />
                  <Route path="logs" element={<ErrorBoundary><Logs /></ErrorBoundary>} />
                  <Route path="settings" element={<ErrorBoundary><Settings /></ErrorBoundary>} />
                  <Route path="*" element={<NotFound />} />
                </Route>
              </Routes>
            </Suspense>
          </ErrorBoundary>
        </BrowserRouter>
      </QueryClientProvider>
      <Toaster
        position="bottom-right"
        toastOptions={{
          style: {
            background: '#1e293b',
            color: '#fff',
            border: '1px solid #334155',
          },
          success: {
            iconTheme: {
              primary: '#10b981',
              secondary: '#fff',
            },
          },
        }}
      />
    </>
  );
}

export default App;
