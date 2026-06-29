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

/** Decode JWT payload without a library (base64url → JSON). */
function decodeJwtPayload(token: string): { exp?: number } | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const payload = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(atob(payload));
  } catch {
    return null;
  }
}

/** Check if a JWT token is expired (with 60s grace period). */
export function isTokenExpired(token: string): boolean {
  const payload = decodeJwtPayload(token);
  if (!payload?.exp) return false; // No exp claim = never expires
  return payload.exp * 1000 < Date.now() - 60_000;
}

// Attach JWT Bearer token from localStorage to every request.
// If token is expired, clear it and skip the header.
let reloadScheduled = false;
let expiryWarningShown = false;

/**
 * Persist a JWT and reset the expiry-tracking flags.
 *
 * Always use this helper instead of calling localStorage.setItem('auth_token', …)
 * directly — otherwise the "session expiring" warning won't re-arm after a fresh
 * login, and the once-per-load reload guard may stay tripped.
 */
export function setAuthToken(token: string): void {
  expiryWarningShown = false;
  reloadScheduled = false;
  localStorage.setItem('auth_token', token);
}

/** Check if token expires within N minutes. */
function tokenExpiresSoon(token: string, minutes: number): boolean {
  const payload = decodeJwtPayload(token);
  if (!payload?.exp) return false;
  return payload.exp * 1000 < Date.now() + minutes * 60_000;
}

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('auth_token');
  if (token) {
    if (isTokenExpired(token)) {
      localStorage.removeItem('auth_token');
      if (!reloadScheduled) {
        reloadScheduled = true;
        window.location.reload();
      }
      return config;
    }
    // Warn 5 minutes before expiry
    if (!expiryWarningShown && tokenExpiresSoon(token, 5)) {
      expiryWarningShown = true;
      window.dispatchEvent(new CustomEvent('session-expiring'));
    }
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// On 401, clear the stale token and reload ONCE.
// Guard: only reload if we had a token and haven't already scheduled a reload.
api.interceptors.response.use(
  (response) => response,
  (error: unknown) => {
    if (axios.isAxiosError(error) && error.response?.status === 401) {
      if (localStorage.getItem('auth_token') && !reloadScheduled) {
        reloadScheduled = true;
        localStorage.removeItem('auth_token');
        window.location.reload();
      }
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
