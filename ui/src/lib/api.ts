import axios from 'axios';

export const api = axios.create({
  baseURL: '/api',
  timeout: 120000,
});

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

// Reset warning flag when a new token is stored (e.g. after re-login)
const _origSetItem = localStorage.setItem.bind(localStorage);
localStorage.setItem = function (key: string, value: string) {
  if (key === 'auth_token') {
    expiryWarningShown = false;
    reloadScheduled = false;
  }
  return _origSetItem(key, value);
};

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
