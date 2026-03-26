import { Component, useState } from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Toaster } from 'react-hot-toast';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 10_000,
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});
import { Layout } from './components/layout/Layout';
import { GlobalSearch } from './components/GlobalSearch';
import { Dashboard } from './pages/Dashboard';
import { Blacklists } from './pages/Blacklists';
import { Logs } from './pages/Logs';
import { Settings } from './pages/Settings';
import { ThreatIntel } from './pages/ThreatIntel';
import { Login } from './pages/Login';

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

function NotFound() {
  return (
    <div className="flex flex-col items-center justify-center h-full text-center gap-2 py-24">
      <span className="text-5xl font-bold text-muted-foreground/30">404</span>
      <p className="text-sm text-muted-foreground">Page not found</p>
    </div>
  );
}

function App() {
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

  if (!isAuthenticated) {
    return <Login onLogin={() => setIsAuthenticated(true)} />;
  }

  return (
    <>
      <QueryClientProvider client={queryClient}>
        <BrowserRouter>
          <GlobalSearch />
          <ErrorBoundary>
            <Routes>
              <Route path="/" element={<Layout />}>
                <Route index element={<ErrorBoundary><Dashboard /></ErrorBoundary>} />
                <Route path="blacklists" element={<ErrorBoundary><Blacklists /></ErrorBoundary>} />
                <Route path="threats" element={<ErrorBoundary><ThreatIntel /></ErrorBoundary>} />
                <Route path="logs" element={<ErrorBoundary><Logs /></ErrorBoundary>} />
                <Route path="settings" element={<ErrorBoundary><Settings /></ErrorBoundary>} />
                <Route path="*" element={<NotFound />} />
              </Route>
            </Routes>
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
