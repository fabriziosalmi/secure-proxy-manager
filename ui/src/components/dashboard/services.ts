/**
 * The Services rows: what the backend reports about each service, and
 * nothing it does not. GET /api/status answers for the backend itself and
 * for the proxy (proxy_status is the backend's probe of Squid);
 * dashboard/summary says whether the WAF's management API answered
 * (waf_status); cache/statistics gives the proxy's last collection of
 * Squid's cache statistics and whether it is current (lib/cacheStats.ts).
 * A service with no data is "unknown", never "running".
 */
import type { CacheStats, DashboardSummary } from '../../types';
import type { StatusData } from '../../lib/queries';
import { formatCount } from '../../lib/format';
import { cacheCollected, cacheSummary } from '../../lib/cacheStats';

export type Health = 'ok' | 'down' | 'unknown';

export interface ServiceRow {
  name: string;
  health: Health;
  state: string;
  detail: string;
}

type Load<T> = { data?: T | null; isPending: boolean; isError: boolean };

/** The WAF line: why there are no statistics when there are none. */
export function wafRow(summary: Load<DashboardSummary>): ServiceRow {
  const name = 'WAF';
  if (summary.isPending) return { name, health: 'unknown', state: 'checking', detail: 'Waiting for the dashboard summary' };
  const s = summary.data;
  if (summary.isError || !s) return { name, health: 'unknown', state: 'unknown', detail: 'The dashboard summary did not load' };
  switch (s.waf_status) {
    case 'ok': {
      const n = s.waf?.total_requests;
      return { name, health: 'ok', state: 'reporting', detail: typeof n === 'number' ? `${formatCount(n)} requests inspected` : 'Inspected count not reported' };
    }
    case 'auth_failed':
      return { name, health: 'down', state: 'refusing the backend', detail: 'Set INTERNAL_ALERT_TOKEN to the same value on the waf and backend services' };
    case 'unreachable':
      return { name, health: 'down', state: 'not reachable', detail: 'The WAF management API is not reachable' };
    case 'error':
      return { name, health: 'down', state: 'error', detail: 'The WAF management API returned an error' };
    default:
      return { name, health: 'unknown', state: 'not reported', detail: 'This backend does not report the WAF state' };
  }
}

function statusRows(status: Load<StatusData>): ServiceRow[] {
  const st = status.data;
  if (status.isPending) {
    return [
      { name: 'Backend', health: 'unknown', state: 'checking', detail: 'Waiting for /api/status' },
      { name: 'Proxy', health: 'unknown', state: 'checking', detail: 'Waiting for /api/status' },
    ];
  }
  if (status.isError || !st) {
    return [
      { name: 'Backend', health: 'down', state: 'not answering', detail: '/api/status failed' },
      { name: 'Proxy', health: 'unknown', state: 'unknown', detail: 'The backend probes the proxy; it did not answer' },
    ];
  }
  const backend: ServiceRow = { name: 'Backend', health: 'ok', state: 'running', detail: st.version ? `v${st.version.replace(/^v/, '')}` : 'Version not reported' };
  const port = st.proxy_port ? `port ${st.proxy_port}` : 'port not reported';
  const squid = st.squid_version ? `Squid ${st.squid_version}, ` : '';
  let proxy: ServiceRow;
  if (st.proxy_status === 'running') proxy = { name: 'Proxy', health: 'ok', state: 'running', detail: `${squid}${port}` };
  else if (st.proxy_status) proxy = { name: 'Proxy', health: 'down', state: 'not answering', detail: `The backend's probe of Squid failed (${port})` };
  else proxy = { name: 'Proxy', health: 'unknown', state: 'not reported', detail: 'The backend did not report the proxy' };
  return [backend, proxy];
}

function cacheRow(cache: Load<CacheStats>): ServiceRow {
  const name = 'Cache statistics';
  const c = cache.data;
  if (cache.isPending) return { name, health: 'unknown', state: 'checking', detail: 'Waiting for cache/statistics' };
  switch (c?.state) {
    case 'current':
      return { name, health: 'ok', state: 'collected', detail: cacheSummary(c) };
    case 'stale':
      // The watchdog or Squid stopped answering: the numbers describe the past.
      return { name, health: 'down', state: 'out of date', detail: cacheCollected(c) ?? 'No collection time reported' };
    case 'not_collected':
      return { name, health: 'unknown', state: 'not collected', detail: 'The proxy has not written cache statistics yet' };
    case 'unreadable':
      return { name, health: 'unknown', state: 'unreadable', detail: "The backend cannot read the proxy's cache statistics" };
    default:
      return { name, health: 'unknown', state: 'not reported', detail: 'cache/statistics did not answer' };
  }
}

export function serviceRows(status: Load<StatusData>, summary: Load<DashboardSummary>, cache: Load<CacheStats>): ServiceRow[] {
  return [...statusRows(status), wafRow(summary), cacheRow(cache)];
}
