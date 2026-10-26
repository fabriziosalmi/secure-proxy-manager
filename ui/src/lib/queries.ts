import { api, getData } from './api';
import type { ProxyAuthStatus, SettingRow } from '../types';

// Queries that more than one component reads. One definition per key, so two
// components never cache different shapes under the same key.

/** GET /api/status (authenticated): the proxy probe, version, update check. */
export interface StatusData {
  proxy_status?: string;
  proxy_host?: string;
  proxy_port?: string;
  version?: string;
  requests_count?: number;
  /** Squid's version as the proxy reported it; absent until it has. */
  squid_version?: string;
  update_available?: string;
  update_url?: string;
  /** What the proxy last did about proxy login; absent until it has recorded it. */
  proxy_auth?: ProxyAuthStatus;
}

export type { ProxyAuthStatus };

export const statusQuery = {
  queryKey: ['status'] as const,
  queryFn: () => getData<StatusData>('status'),
};

/**
 * How many entries the egress allowlist holds: GET /api/egress-allowlist
 * with limit=1 answers meta.total (writeList in backend-go). Under the
 * ['egress-allowlist'] key, so the Egress page's changes refresh it.
 */
export const egressTotalQuery = {
  queryKey: ['egress-allowlist', 'total'] as const,
  queryFn: () =>
    api.get('egress-allowlist', { params: { limit: 1 } }).then((r) => {
      const total = r.data?.meta?.total ?? r.data?.total;
      return typeof total === 'number' ? total : null;
    }),
};

/**
 * GET /api/settings: every setting row. The key and the shape are the ones
 * the Settings page caches, so a save there refreshes every reader.
 */
export const settingsQuery = {
  queryKey: ['settings'] as const,
  queryFn: () => getData<SettingRow[]>('settings'),
};

/** GET /api/health (public): the backend's version and runtime. */
export interface HealthData {
  status?: string;
  version?: string;
  runtime?: string;
}

export const healthQuery = {
  queryKey: ['health'] as const,
  // Not wrapped in { data }: /api/health answers with a bare object.
  queryFn: () => api.get<HealthData>('health').then((r) => r.data ?? null),
};
