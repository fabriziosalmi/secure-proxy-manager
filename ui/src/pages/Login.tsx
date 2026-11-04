import { useEffect, useState } from 'react';
import { OIDC_LOGIN_PATH, oidcStatus, signIn, type OIDCStatus } from '../lib/api';
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
  if (status === 403) {
    return 'Password sign-in is turned off here. Sign in with the identity provider.';
  }
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

// What a failed OIDC sign-in comes back with (?oidc_error=, handlers/oidc.go).
const OIDC_ERRORS: Record<string, string> = {
  state: 'The sign-in expired or was started in another browser. Try again.',
  provider: 'The identity provider refused the sign-in.',
  exchange: 'The identity provider\'s answer could not be verified. Try again; if it happens again, check the OIDC settings.',
  token: 'The identity provider\'s answer could not be verified. Try again; if it happens again, check the OIDC settings.',
  not_allowed: 'Your account is not allowed to sign in here. An admin can add your email or group to OIDC_ALLOWED_EMAILS or OIDC_ALLOWED_GROUPS.',
  unverified_email: 'Your email address is not verified at the identity provider.',
  no_email: 'The identity provider sent no email address: the client needs the email scope.',
  unavailable: 'The identity provider could not be reached.',
};

function oidcErrorText(code: string): string {
  return OIDC_ERRORS[code] ?? 'Single sign-on failed.';
}

const SSO_LINK =
  'inline-flex h-9 w-full items-center justify-center rounded-control border border-line-strong bg-surface px-3.5 ' +
  'text-sm font-semibold text-ink-secondary transition-colors hover:bg-surface-muted hover:text-ink ' +
  'focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2 focus-visible:ring-offset-surface';

export function Login({ onLogin }: Props) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [oidc, setOidc] = useState<OIDCStatus>({ enabled: false, passwordLogin: true });
  const [ssoError] = useState(() => new URLSearchParams(window.location.search).get('oidc_error') ?? '');

  useEffect(() => {
    let live = true;
    void oidcStatus().then((s) => { if (live) setOidc(s); });
    return () => { live = false; };
  }, []);

  // The reason is shown once; a reload does not show it again.
  useEffect(() => {
    if (!ssoError) return;
    const url = new URL(window.location.href);
    url.searchParams.delete('oidc_error');
    window.history.replaceState(null, '', url.pathname + url.search + url.hash);
  }, [ssoError]);

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

  const passwordForm = !oidc.enabled || oidc.passwordLogin;
  const alert = (error || ssoError) && (
    <p role="alert" className="rounded-control border border-danger-line bg-danger-subtle px-3 py-2 text-sm text-danger animate-fade-in-up">
      {error || oidcErrorText(ssoError)}
    </p>
  );

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

        {passwordForm && (
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

            {alert}

            <Button type="submit" variant="primary" disabled={loading} className="w-full">
              {loading ? (
                <span className="flex items-center justify-center gap-2">
                  <span className="w-4 h-4 border-2 border-accent-foreground/30 border-t-accent-foreground rounded-full animate-spin" aria-hidden="true" />
                  Signing in...
                </span>
              ) : 'Sign in'}
            </Button>
          </form>
        )}

        {oidc.enabled && (
          <div className="space-y-4">
            {passwordForm ? (
              <div className="flex items-center gap-3 text-xs text-ink-muted" aria-hidden="true">
                <span className="h-px flex-1 bg-line" />or<span className="h-px flex-1 bg-line" />
              </div>
            ) : alert}
            <a href={OIDC_LOGIN_PATH} className={SSO_LINK}>Sign in with {oidc.label || 'single sign-on'}</a>
          </div>
        )}
      </div>
    </main>
  );
}
