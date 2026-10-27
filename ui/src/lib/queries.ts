import { useQuery } from '@tanstack/react-query';
import { api, getData } from './api';
import { formatCount } from './format';
import type { EgressProvider, ProxyAuthStatus, SettingRow } from '../types';

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
  squid_cves?: number;
  cves_checked?: boolean;
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
 * GET /api/egress-providers: catalog and custom URL provider lists and their
 * counts.
 */
export const egressProvidersQuery = {
  queryKey: ['egress-providers'] as const,
  queryFn: (): Promise<EgressProvider[]> =>
    api.get('egress-providers').then((r) => (Array.isArray(r.data?.data) ? (r.data.data as EgressProvider[]) : [])),
};

export interface EgressSummary {
  /** Combined manual + enabled provider entries; null when either read failed, undefined while loading. */
  total: number | null | undefined;
  /** Manual entries count; null when reading manual entries failed, undefined while loading. */
  manual: number | null | undefined;
  /** Entries across enabled provider lists; null when reading providers failed, undefined while loading. */
  providerEntries: number | null | undefined;
  /** Enabled provider lists count; null when reading providers failed, undefined while loading. */
  providerCount: number | null | undefined;
  manualFailed: boolean;
  providersFailed: boolean;
  isPending: boolean;
  isError: boolean;
}

export function formatEgressBreakdown(manual: number, providerEntries: number, providerCount: number): string {
  const manualPart = `${formatCount(manual)} manual ${manual === 1 ? 'entry' : 'entries'}`;
  const providerPart = `${formatCount(providerEntries)} from ${formatCount(providerCount)} ${providerCount === 1 ? 'provider list' : 'provider lists'}`;
  return `${manualPart} and ${providerPart}`;
}

export interface EgressSummaryOptions {
  enabled?: boolean;
  manualQuery?: {
    data: number | null | undefined;
    isPending: boolean;
    isError: boolean;
  };
}

export function useEgressSummary(options?: EgressSummaryOptions): EgressSummary {
  const enabled = options?.enabled ?? true;
  const manualOverride = options?.manualQuery;
  const manualQ = useQuery({ ...egressTotalQuery, enabled: enabled && !manualOverride });
  const providersQ = useQuery({ ...egressProvidersQuery, enabled });

  const m = manualOverride ?? manualQ;
  const manualFailed = m.isError || (!m.isPending && m.data === null);
  const providersFailed = providersQ.isError;
  const isPending = m.isPending || providersQ.isPending;
  const isError = manualFailed || providersFailed;

  const manual = manualFailed ? null : m.data;
  const enabledProviders = !providersFailed && providersQ.data ? providersQ.data.filter((p) => p.enabled) : undefined;
  const providerCount = providersFailed ? null : enabledProviders?.length;
  const providerEntries = providersFailed
    ? null
    : enabledProviders?.reduce((sum, p) => sum + p.v4_count + p.v6_count, 0);

  let total: number | null | undefined;
  if (isError) {
    total = null;
  } else if (typeof manual === 'number' && typeof providerEntries === 'number') {
    total = manual + providerEntries;
  } else {
    total = undefined;
  }

  return {
    total,
    manual,
    providerEntries,
    providerCount,
    manualFailed,
    providersFailed,
    isPending,
    isError,
  };
}

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
