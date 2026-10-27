import { useState } from 'react';
import { signIn } from '../lib/api';
import { Button } from '../components/ui/Button';
import { PasswordInput } from '../components/settings/ChangePassword';

interface Props {
  onLogin: () => void;
}

const INPUT =
  'h-9 w-full rounded-control border border-line-strong bg-surface px-3 text-sm text-ink ' +
  'focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-accent';

function describeLoginError(err: unknown): string {
  const response = (err as {
    response?: {
      status?: number;
      data?: { detail?: string; message?: string };
      headers?: Record<string, string | undefined>;
    };
  })?.response;
  const status = response?.status;
  if (status === 401 || (status !== undefined && status >= 400 && status < 500 && status !== 429)) {
    return 'Invalid username or password';
  }
  if (status === 429) {
    const detail = response?.data?.detail || response?.data?.message || 'Too many failed attempts, try again later';
    const retryAfter = response?.headers?.['retry-after'] || response?.headers?.['Retry-After'];
    return retryAfter ? `${detail} (retry after ${retryAfter}s)` : detail;
  }
  return 'The backend did not answer. Check that the backend container is running and healthy.';
}

export function Login({ onLogin }: Props) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      // The backend keeps the token in an HttpOnly cookie; the page never sees it.
      await signIn(username, password);
      onLogin();
    } catch (err) {
      setError(describeLoginError(err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="min-h-screen bg-ground text-ink flex items-center justify-center px-4">
      <div className="w-full max-w-sm rounded-panel border border-line bg-surface p-6 space-y-6 page-enter">
        <div className="text-center space-y-2">
          <div className="flex justify-center">
            <div className="w-12 h-12 rounded-panel border border-line bg-surface-muted flex items-center justify-center">
              <img src="/logo.svg" alt="Secure Proxy Manager" className="w-7 h-7" />
            </div>
          </div>
          <h1 className="text-xl font-semibold tracking-tight text-ink">
            Secure Proxy Manager
          </h1>
          <p className="text-sm text-ink-muted">Sign in to continue</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="flex flex-col gap-1.5">
            <label htmlFor="username" className="text-sm font-medium text-ink">Username</label>
            <input
              id="username"
              type="text"
              autoComplete="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              className={INPUT}
            />
          </div>
          <PasswordInput
            id="password"
            label="Password"
            value={password}
            onChange={setPassword}
            autoComplete="current-password"
            reveal
            required
          />

          {error && (
            <p role="alert" className="rounded-control border border-danger-line bg-danger-subtle px-3 py-2 text-sm text-danger animate-fade-in-up">
              {error}
            </p>
          )}

          <Button type="submit" variant="primary" disabled={loading} className="w-full">
            {loading ? (
              <span className="flex items-center justify-center gap-2">
                <span className="w-4 h-4 border-2 border-accent-foreground/30 border-t-accent-foreground rounded-full animate-spin" aria-hidden="true" />
                Signing in...
              </span>
            ) : 'Sign in'}
          </Button>
        </form>
      </div>
    </main>
  );
}
