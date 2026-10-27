import { Component, Suspense, lazy, useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router';
import { QueryClient, QueryClientProvider, QueryCache, useQuery } from '@tanstack/react-query';
import toast, { Toaster } from 'react-hot-toast';
import { Layout } from './components/layout/Layout';
import { Button } from './components/ui/Button';
import { Notice } from './components/ui/Notice';
import { getErrorMessage, isTokenExpired, signOut } from './lib/api';
import { settingsQuery } from './lib/queries';
import { ThemeProvider } from './components/ThemeProvider';
import { SettingsDraftsProvider } from './components/settings/SettingsDrafts';

function createAppQueryClient() {
  return new QueryClient({
    queryCache: new QueryCache({
      onError: (error, query) => {
        // Pages render their own inline error states; only show a global toast
        // when a query explicitly opts in via meta.toastOnError.
        if (!query.meta?.toastOnError) return;
        const status = (error as { response?: { status?: number } })?.response?.status;
        if (status === 401) return;
        const msg = typeof status === 'number'
          ? getErrorMessage(error, `Request failed (${status}).`)
          : 'Could not reach the backend.';
        toast.error(msg, { id: 'query-error', duration: 3000 });
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
}

// Lazy-loaded page components for code splitting
const Login = lazy(() => import('./pages/Login').then(m => ({ default: m.Login })));
const SetupWizard = lazy(() => import('./components/SetupWizard').then(m => ({ default: m.SetupWizard })));
const GlobalSearch = lazy(() => import('./components/GlobalSearch').then(m => ({ default: m.GlobalSearch })));
const Dashboard = lazy(() => import('./pages/Dashboard').then(m => ({ default: m.Dashboard })));
const Blacklists = lazy(() => import('./pages/Blacklists').then(m => ({ default: m.Blacklists })));
const Logs = lazy(() => import('./pages/Logs').then(m => ({ default: m.Logs })));
const Settings = lazy(() => import('./pages/Settings').then(m => ({ default: m.Settings })));
const Analytics = lazy(() => import('./pages/Analytics').then(m => ({ default: m.Analytics })));
const Audit = lazy(() => import('./pages/Audit').then(m => ({ default: m.Audit })));
const Clients = lazy(() => import('./pages/Clients').then(m => ({ default: m.Clients })));
const EgressAllowlist = lazy(() => import('./pages/EgressAllowlist').then(m => ({ default: m.EgressAllowlist })));

class ErrorBoundary extends Component<{ children: React.ReactNode; silent?: boolean }, { error: Error | null }> {
  constructor(props: { children: React.ReactNode; silent?: boolean }) {
    super(props);
    this.state = { error: null };
  }
  static getDerivedStateFromError(error: Error) {
    return { error };
  }
  render() {
    if (this.state.error) {
      if (this.props.silent) return null;
      return (
        <div className="flex items-center justify-center h-screen bg-ground text-ink">
          <div className="text-center space-y-3 max-w-md px-4">
            <p className="text-lg font-semibold text-danger">Something went wrong</p>
            <p className="text-sm text-ink-muted font-mono">{this.state.error.message}</p>
            <Button
              onClick={() => this.setState({ error: null })}
              className="mt-4"
            >
              Try again
            </Button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

function PageLoader() {
  return (
    <div className="flex items-center justify-center h-64" role="status" aria-live="polite">
      <div className="animate-spin w-6 h-6 border-2 border-accent border-t-transparent rounded-full" aria-hidden="true" />
      <span className="sr-only">Loading…</span>
    </div>
  );
}

function NotFound() {
  return (
    <div className="flex flex-col items-center justify-center h-full text-center gap-2 py-24">
      <span className="text-5xl font-bold text-ink-subtle">404</span>
      <p className="text-sm text-ink-muted">Page not found</p>
    </div>
  );
}

function AppContent({ queryClient }: { queryClient: QueryClient }) {
  const handleLogout = async () => {
    await signOut();
    setIsAuthenticated(false);
    setWizardCompletedOverride(false);
    queryClient.clear();
  };

  const [isAuthenticated, setIsAuthenticated] = useState(() => {
    const token = localStorage.getItem('auth_token');
    if (!token) return false;
    // Clear stale tokens on mount via the shared JWT helper. A malformed or
    // exp-less token is kept (isTokenExpired → false) and the API will 401.
    if (isTokenExpired(token)) {
      localStorage.removeItem('auth_token');
      return false;
    }
    return true;
  });

  const [wizardCompletedOverride, setWizardCompletedOverride] = useState(false);

  // Listen for session expiry warning from API interceptor
  useEffect(() => {
    const handler = () => {
      toast('Session expiring soon: save your work', { icon: '⏳', duration: 10000, id: 'session-warn' });
    };
    window.addEventListener('session-expiring', handler);
    return () => window.removeEventListener('session-expiring', handler);
  }, []);

  // Read wizard_completed through settingsQuery so the page that mounts next
  // reuses the cached GET /api/settings response instead of fetching it twice.
  const settings = useQuery({
    ...settingsQuery,
    enabled: isAuthenticated,
    retry: false,
  });

  if (!isAuthenticated) {
    // Lazy screens sit inside a boundary: a chunk that fails to load (a tab
    // left open across an upgrade) shows an error instead of a blank page.
    return (
      <ErrorBoundary>
        <Suspense fallback={<PageLoader />}>
          <Login onLogin={() => setIsAuthenticated(true)} />
        </Suspense>
      </ErrorBoundary>
    );
  }

  // Only a first load that failed blocks the app: a later refetch that fails
  // (after a save, say) keeps the cached rows, the page and its drafts.
  if (settings.isError && settings.data === undefined && !wizardCompletedOverride) {
    const wizardError = getErrorMessage(
      settings.error,
      'The backend did not answer. Check that the backend container is running.',
    );
    return (
      <main className="flex items-center justify-center min-h-screen bg-ground text-ink px-4">
        <div className="w-full max-w-md">
          <Notice
            tone="danger"
            title="Could not load settings"
            action={
              <Button
                variant="secondary"
                size="sm"
                onClick={() => {
                  void settings.refetch();
                }}
              >
                Try again
              </Button>
            }
          >
            {wizardError}
          </Notice>
        </div>
      </main>
    );
  }

  // Loading: checking wizard status
  if (settings.isPending && !wizardCompletedOverride) {
    return (
      <div className="flex items-center justify-center h-screen bg-ground" role="status" aria-live="polite">
        <div className="animate-spin w-6 h-6 border-2 border-accent border-t-transparent rounded-full" aria-hidden="true" />
        <span className="sr-only">Loading…</span>
      </div>
    );
  }

  const wizardSetting = Array.isArray(settings.data)
    ? settings.data.find((s) => s.setting_name === 'wizard_completed')
    : null;
  const wizardDone = wizardCompletedOverride || wizardSetting?.setting_value === 'true';

  // Show wizard if not completed
  if (!wizardDone) {
    return (
      <ErrorBoundary>
        <Suspense fallback={<PageLoader />}>
          <SetupWizard onComplete={() => setWizardCompletedOverride(true)} />
        </Suspense>
      </ErrorBoundary>
    );
  }

  return (
    <BrowserRouter>
      {/* Unsaved Settings drafts outlive a visit to another page, not the session. */}
      <SettingsDraftsProvider>
        {/* Search failing to load leaves the page usable, so its boundary shows nothing. */}
        <ErrorBoundary silent>
          <Suspense fallback={null}>
            <GlobalSearch />
          </Suspense>
        </ErrorBoundary>
        <ErrorBoundary>
          <Suspense fallback={<PageLoader />}>
            <Routes>
              <Route path="/" element={<Layout onLogout={handleLogout} />}>
                <Route index element={<ErrorBoundary><Dashboard /></ErrorBoundary>} />
                <Route path="blacklists" element={<ErrorBoundary><Blacklists /></ErrorBoundary>} />
                <Route path="analytics" element={<ErrorBoundary><Analytics /></ErrorBoundary>} />
                {/* The Threat Intel page is now Analytics; old links and bookmarks still land on it. */}
                <Route path="threats" element={<Navigate to="/analytics" replace />} />
                <Route path="clients" element={<ErrorBoundary><Clients /></ErrorBoundary>} />
                <Route path="logs" element={<ErrorBoundary><Logs /></ErrorBoundary>} />
                <Route path="audit" element={<ErrorBoundary><Audit /></ErrorBoundary>} />
                <Route path="egress" element={<ErrorBoundary><EgressAllowlist /></ErrorBoundary>} />
                {/* One section per URL; /settings opens the first one. */}
                <Route path="settings" element={<Navigate to="/settings/overview" replace />} />
                <Route path="settings/:section" element={<ErrorBoundary><Settings /></ErrorBoundary>} />
                <Route path="*" element={<NotFound />} />
              </Route>
            </Routes>
          </Suspense>
        </ErrorBoundary>
      </SettingsDraftsProvider>
    </BrowserRouter>
  );
}

function App() {
  const [queryClient] = useState(createAppQueryClient);
  return (
    <ThemeProvider>
      <QueryClientProvider client={queryClient}>
        <AppContent queryClient={queryClient} />
        <Toaster
          position="bottom-right"
          toastOptions={{
            style: {
              background: 'var(--ds-surface)',
              color: 'var(--ds-text)',
              border: '1px solid var(--ds-border)',
            },
            success: {
              iconTheme: {
                primary: 'var(--ds-success-strong)',
                secondary: 'var(--ds-surface)',
              },
            },
          }}
        />
      </QueryClientProvider>
    </ThemeProvider>
  );
}

export default App;
