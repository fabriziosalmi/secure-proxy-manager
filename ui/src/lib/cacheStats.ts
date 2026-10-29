/**
 * What the Overview's Services line and the Settings tile say about Squid's
 * cache, from GET /api/cache/statistics. The proxy's watchdog reads Squid's
 * cache manager once a minute; the backend says whether that record is
 * current, stale (no collection for three intervals), not collected (no
 * record) or unreadable. Only a current record's numbers are shown as the
 * cache's state; a stale one says when it was last collected.
 */
import type { CacheStats } from '../types';
import { formatAge, formatDateTime, formatHourMinute, formatKilobytes, formatPercent } from './format';

const HOUR_S = 3600;
const MINUTE_S = 60;

/**
 * The window of Squid's "60min" hit ratio. Until Squid has run for an hour
 * it covers the time since it started, so the label says so.
 */
export function cacheHitWindow(c: CacheStats): string {
  const uptime = c.uptime_s;
  if (uptime === null || uptime === undefined || uptime >= HOUR_S) return 'last hour';
  return `last ${Math.max(1, Math.floor(uptime / MINUTE_S))} min, since Squid started`;
}

/** "64.7%", Squid's request hit ratio over its 60 minute window; null in its first minute, when it has measured nothing. */
export function cacheHitPercent(c: CacheStats): string | null {
  const pct = c.request_hit_ratio_60min_pct;
  return pct === null || pct === undefined ? null : formatPercent(pct);
}

/** "Hit ratio 64.7% (last hour)"; null in Squid's first minute. */
export function cacheHitRatio(c: CacheStats): string | null {
  const pct = cacheHitPercent(c);
  return pct === null ? null : `Hit ratio ${pct} (${cacheHitWindow(c)})`;
}

/** "252 KB of 50.0 MB on disk", or "252 KB on disk" without the capacity; null without either. */
export function cacheDisk(c: CacheStats): string | null {
  if (c.disk_used_kb === null || c.disk_used_kb === undefined) return null;
  const of = c.disk_capacity_kb === null || c.disk_capacity_kb === undefined ? '' : ` of ${formatKilobytes(c.disk_capacity_kb)}`;
  return `${formatKilobytes(c.disk_used_kb)}${of} on disk`;
}

/** "collected 12:15" for a current record, "Last collected 2026-10-25 12:15:28 (25 min ago)" otherwise. */
export function cacheCollected(c: CacheStats): string | null {
  if (!c.collected_at) return null;
  if (c.state === 'current') return `collected ${formatHourMinute(c.collected_at)}`;
  const ago = typeof c.age_s === 'number' ? ` (${formatAge(c.age_s)} ago)` : '';
  return `Last collected ${formatDateTime(c.collected_at)}${ago}`;
}

/** The current record in one line: hit ratio, disk, collection time. */
export function cacheSummary(c: CacheStats): string {
  const hit = cacheHitRatio(c) ?? "Hit ratio not measured yet (Squid's first minute)";
  return [hit, cacheDisk(c), cacheCollected(c)].filter(Boolean).join(' · ');
}
