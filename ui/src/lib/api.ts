import axios from 'axios';
import type { AxiosResponse, AxiosRequestConfig } from 'axios';

export const api = axios.create({
  baseURL: '/api',
  timeout: 120000,
});

/**
 * Unwrap the backend's `{ status, data }` envelope, coalescing a missing `data`
 * to `null`. React Query forbids a queryFn resolving to `undefined`; a data-less
 * response (error envelope, empty body, or a 304 Not Modified) would otherwise
 * throw inside the queryFn and crash the page. Always route queryFns through
 * this (or `getData`) instead of reaching for `r.data.data` directly.
 */
export function unwrapData<T = unknown>(r: AxiosResponse): T {
  return (r?.data?.data ?? null) as T;
}

/** GET a path and unwrap the `{ status, data }` envelope (never resolves to undefined). */
export function getData<T = unknown>(path: string, config?: AxiosRequestConfig): Promise<T> {
  return api.get(path, config).then((r) => unwrapData<T>(r));
}

/*
 * The browser session lives in an HttpOnly cookie (spm_session) that the
 * backend sets at sign-in, so script in the page, an injected one included,
 * cannot read the token. The UI knows only when the session expires
 * (expires_at, from the sign-in answer or GET /api/session), to warn five
 * minutes before and to end it on time. Every request carries
 * X-Requested-With: spm, which the backend requires on a state-changing
 * request that the cookie authenticates (CSRF protection).
 */
api.defaults.headers.common['X-Requested-With'] = 'spm';

let sessionActive = false;
let sessionExpiresAt: number | null = null; // milliseconds; null: no expiry known
let expiryWarningShown = false;
let sessionEndSignalled = false;

/** The signed-in session, as GET /api/session reports it. */
export interface Session {
  username: string;
  via: 'cookie' | 'bearer' | 'basic' | string;
  /** Unix seconds; null for a credential that does not expire. */
  expires_at: number | null;
}

/** Record a started session and its expiry (Unix seconds), re-arming the warning. */
export function startSession(expiresAt: number | null | undefined): void {
  sessionActive = true;
  sessionExpiresAt = typeof expiresAt === 'number' ? expiresAt * 1000 : null;
  expiryWarningShown = false;
  sessionEndSignalled = false;
}

function endSession(): void {
  sessionActive = false;
  sessionExpiresAt = null;
}

// The app listens for this and shows the sign-in screen.
function signalSessionEnded(): void {
  if (!sessionActive || sessionEndSignalled) return;
  sessionEndSignalled = true;
  endSession();
  window.dispatchEvent(new CustomEvent('session-ended'));
}

/**
 * The current session, or null when there is none (401). Any other failure
 * (backend down) is thrown, so the caller can tell the two apart.
 */
export async function loadSession(): Promise<Session | null> {
  try {
    const res = await api.get('session');
    const s = (res.data?.data ?? null) as Session | null;
    if (!s) return null;
    startSession(s.expires_at);
    return s;
  } catch (err) {
    if (axios.isAxiosError(err) && err.response?.status === 401) return null;
    throw err;
  }
}

/**
 * Sign in with a session cookie: the backend answers with the expiry only,
 * never the token.
 */
export async function signIn(username: string, password: string): Promise<void> {
  const res = await api.post<{ expires_at?: number }>('auth/login', { username, password }, {
    headers: { 'X-SPM-Session': 'cookie' },
  });
  startSession(res.data?.expires_at);
}

/**
 * Sign out: the backend revokes the token and clears the cookie. A failed
 * revocation must not keep the user signed in, so its error is swallowed and
 * the local session ends regardless.
 */
export async function signOut(): Promise<void> {
  try {
    if (sessionActive) await api.post('logout');
  } catch {
    /* the local sign-out below still happens */
  }
  endSession();
}

// Earlier versions kept the token in localStorage, where any script in the
// page could read it. A token left there is revoked once and forgotten.
function retireStoredToken(): void {
  let stored: string | null;
  try {
    stored = localStorage.getItem('auth_token');
    localStorage.removeItem('auth_token');
  } catch {
    return; // storage blocked: nothing was stored either
  }
  if (stored) {
    void api.post('logout', {}, { headers: { Authorization: `Bearer ${stored}` } }).catch(() => {});
  }
}
retireStoredToken();

api.interceptors.request.use((config) => {
  if (sessionActive && sessionExpiresAt !== null) {
    const now = Date.now();
    if (now >= sessionExpiresAt) {
      signalSessionEnded();
    } else if (!expiryWarningShown && now >= sessionExpiresAt - 5 * 60_000) {
      expiryWarningShown = true;
      window.dispatchEvent(new CustomEvent('session-expiring'));
    }
  }
  return config;
});

// A 401 on a signed-in session means it ended (expired, revoked, or the
// password changed elsewhere): the app returns to the sign-in screen once.
api.interceptors.response.use(
  (response) => response,
  (error: unknown) => {
    if (axios.isAxiosError(error) && error.response?.status === 401) {
      const url = error.config?.url ?? '';
      if (!url.startsWith('auth/') && url !== 'session') signalSessionEnded();
    }
    return Promise.reject(error);
  }
);

/** Extract a human-readable message from an Axios error, with a fallback. */
export function getErrorMessage(err: unknown, fallback: string): string {
  if (axios.isAxiosError(err)) {
    return (
      (err.response?.data as { message?: string; detail?: string })?.message ??
      (err.response?.data as { message?: string; detail?: string })?.detail ??
      fallback
    );
  }
  return fallback;
}
