/**
 * The pure part of "What the cache did, per day": which outcomes are drawn
 * together, what each day's bar is made of, the axis in bytes, the summary
 * and the chart's text alternative. Every number comes from GET
 * /api/analytics/cache-by-day.
 */
import type { CacheByDay, CacheCounts, CacheDay, CacheOutcome } from '../../types';
import { formatBytes, formatCount, formatShare } from '../../lib/format';
import { axisMax } from '../dashboard/hourly';
import { dayName, type SeriesColor } from './days';

export type CacheMeasure = 'requests' | 'bytes';

/** One stack of the chart, bottom first. */
export interface CacheGroup {
  key: string;
  label: string;
  color: SeriesColor;
  outcomes: CacheOutcome[];
}

// A hit and a revalidated copy both left the cache: one colour, told apart in
// the table. The other outcomes have one each.
const GROUPS: readonly { key: string; color: SeriesColor; outcomes: CacheOutcome[]; label?: string }[] = [
  { key: 'cache', color: 'series-1', outcomes: ['hit', 'revalidated'], label: 'From the cache' },
  { key: 'miss', color: 'series-2', outcomes: ['miss'] },
  { key: 'tunnel', color: 'series-3', outcomes: ['tunnel'] },
  { key: 'refused', color: 'series-4', outcomes: ['refused'] },
  { key: 'other', color: 'neutral', outcomes: ['other'] },
];

/** The stacks, every one of them, with the API's label where a stack is one outcome. */
export function cacheGroups(data: Pick<CacheByDay, 'outcomes'>): CacheGroup[] {
  const label = new Map(data.outcomes.map((o) => [o.outcome, o.label]));
  return GROUPS.map((g) => ({
    key: g.key,
    color: g.color,
    outcomes: g.outcomes,
    label: g.label ?? label.get(g.outcomes[0]) ?? g.key,
  }));
}

export function sumOf(counts: CacheCounts, outcomes: readonly CacheOutcome[]): number {
  return outcomes.reduce((n, o) => n + (counts[o] ?? 0), 0);
}

const ALL: readonly CacheOutcome[] = ['hit', 'revalidated', 'miss', 'tunnel', 'refused', 'other'];

export function dayTotal(day: CacheDay, measure: CacheMeasure): number {
  return sumOf(day[measure], ALL);
}

/** A day's bar, bottom first: every stack with its value that day, zeros included. */
export function cacheSegments(day: CacheDay, groups: readonly CacheGroup[], measure: CacheMeasure) {
  return groups.map((g) => ({ group: g, value: sumOf(day[measure], g.outcomes) }));
}

const KIB = 1024;

/**
 * The top of the axis: a round count of requests, or a round number of the
 * byte unit the peak is written in (2.0 GB rather than 1.9 GB), so the labels
 * formatBytes writes are round too.
 */
export function cacheAxisMax(days: readonly CacheDay[], measure: CacheMeasure): number {
  const peak = Math.max(0, ...days.map((d) => dayTotal(d, measure)));
  if (peak <= 0) return 0;
  if (measure === 'requests') return axisMax([{ time: '', total: peak, blocked: 0 }]);
  let unit = 1;
  while (peak / unit >= KIB && unit < KIB ** 4) unit *= KIB;
  return axisMax([{ time: '', total: peak / unit, blocked: 0 }]) * unit;
}

export function formatMeasure(v: number, measure: CacheMeasure): string {
  return measure === 'bytes' ? formatBytes(v) : formatCount(v);
}

/**
 * What the week comes to. cacheable is what the cache could have answered:
 * hits, revalidated copies and misses; a tunnel's bytes are never readable
 * and a refused request is never fetched, so neither is in it. share is the
 * part of cacheable that came from the cache, null when nothing was
 * cacheable.
 */
export function cacheSummary(data: CacheByDay) {
  const r = data.totals.requests;
  const b = data.totals.bytes;
  const fromCache = ['hit', 'revalidated'] as const;
  const cacheable = ['hit', 'revalidated', 'miss'] as const;
  return {
    requests: sumOf(r, ALL),
    cacheable: sumOf(r, cacheable),
    fromCache: sumOf(r, fromCache),
    revalidated: r.revalidated,
    share: formatShare(sumOf(r, fromCache), sumOf(r, cacheable)),
    byteShare: formatShare(sumOf(b, fromCache), sumOf(b, cacheable)),
    tunnelShare: formatShare(r.tunnel, sumOf(r, ALL)),
    tunnelByteShare: formatShare(b.tunnel, sumOf(b, ALL)),
  };
}

/** The chart's text alternative: every day with traffic, by stack, then the others in one phrase. */
export function describeCacheDays(data: CacheByDay, measure: CacheMeasure): string {
  const lead = `What the cache did per day, ${measure === 'bytes' ? 'bytes sent' : 'requests'}, today and the 6 days before:`;
  const groups = cacheGroups(data);
  const busy = data.days.filter((d) => dayTotal(d, measure) > 0);
  if (busy.length === 0) return `${lead} no client requests.`;
  const last = data.days[data.days.length - 1]?.date;
  const parts = busy.map((d) => {
    const segs = cacheSegments(d, groups, measure).filter((s) => s.value > 0);
    const name = d.date === last ? 'today' : dayName(d.date);
    return `${name} ${segs.map((s) => `${formatMeasure(s.value, measure)} ${s.group.label}`).join(', ')}`;
  });
  const idle = data.days.length - busy.length;
  const rest = idle > 0 ? `; none on the other ${idle === 1 ? 'day' : `${idle} days`}` : '';
  return `${lead} ${parts.join('; ')}${rest}.`;
}
