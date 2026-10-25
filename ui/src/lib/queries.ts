import { api, getData } from './api';

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
}

export const statusQuery = {
  queryKey: ['status'] as const,
  queryFn: () => getData<StatusData>('status'),
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
