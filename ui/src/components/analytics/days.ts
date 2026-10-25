/**
 * The pure part of "Blocked requests per day, by rule": which colour each
 * rule gets, what each day's bar is made of, and the chart's text
 * alternative. Every count comes from GET /api/analytics/blocked-by-day.
 */
import type { BlockedDay, ReasonCount } from '../../types';
import { formatCount } from '../../lib/format';

export type SeriesColor = 'series-1' | 'series-2' | 'series-3' | 'series-4' | 'neutral';

/** The fill class of each colour: design tokens, stepped in lightness (tokens.test.ts). */
export const SERIES_BG: Record<SeriesColor, string> = {
  'series-1': 'bg-series-1',
  'series-2': 'bg-series-2',
  'series-3': 'bg-series-3',
  'series-4': 'bg-series-4',
  neutral: 'bg-chart-neutral',
};

/** One stack of the chart: a rule, or the rules folded into one when there are more rules than colours. */
export interface Series {
  key: string;
  /** The API's label, or "Other rules" for the fold. */
  label: string;
  color: SeriesColor;
  /** The block reasons it counts. */
  reasons: string[];
  /** The API labels of the reasons it counts, for the fold. */
  labels: string[];
}

// The rules in the order they take colours: the ones a self-hoster sets up
// first. A reason the UI does not know comes after, by name.
const ORDER = [
  'domain_blacklist_dns', 'domain_blacklist_dns_reconstructed', 'domain_blacklist', 'ip_blacklist', 'waf', 'direct_ip', 'egress_policy', 'proxy_auth',
  'time_restriction', 'content_filter', 'source_gate', 'port_policy', 'protocol_policy', 'other',
];
const COLORS = ['series-1', 'series-2', 'series-3', 'series-4'] as const;

function rank(reason: string): number {
  const i = ORDER.indexOf(reason);
  return i < 0 ? ORDER.length : i;
}

function byOrder(a: ReasonCount, b: ReasonCount): number {
  return rank(a.reason) - rank(b.reason) || a.reason.localeCompare(b.reason);
}

function single(r: ReasonCount, color: SeriesColor): Series {
  return { key: r.reason, label: r.label, color, reasons: [r.reason], labels: [r.label] };
}

/**
 * The stacks, bottom first, for the reasons that blocked something in the
 * window (the API's totals). Each rule keeps one colour for the whole chart,
 * taken in ORDER, so the same rules are always drawn the same way. Rows with
 * no recorded reason are the neutral bar, on top. Four colours stay apart in
 * lightness; with more than four rules in a week, the three that blocked the
 * most keep theirs and the rest are folded into "Other rules", named in the
 * legend and counted one by one in the table.
 */
export function seriesFor(totals: readonly ReasonCount[]): Series[] {
  const present = totals.filter((r) => r.count > 0);
  const rules = present.filter((r) => r.reason !== 'unclassified');
  const out: Series[] = [];
  if (rules.length <= COLORS.length) {
    [...rules].sort(byOrder).forEach((r, i) => out.push(single(r, COLORS[i])));
  } else {
    const keep = [...rules].sort((a, b) => b.count - a.count || byOrder(a, b)).slice(0, COLORS.length - 1);
    const rest = rules.filter((r) => !keep.includes(r)).sort(byOrder);
    keep.sort(byOrder).forEach((r, i) => out.push(single(r, COLORS[i])));
    out.push({
      key: 'other-rules',
      label: 'Other rules',
      color: COLORS[COLORS.length - 1],
      reasons: rest.map((r) => r.reason),
      labels: rest.map((r) => r.label),
    });
  }
  const unclassified = present.find((r) => r.reason === 'unclassified');
  if (unclassified) out.push(single(unclassified, 'neutral'));
  return out;
}

/** One series' part of one day's bar. */
export interface Segment {
  series: Series;
  count: number;
}

/** A day's bar, bottom first: every series with its count that day, zeros included. */
export function daySegments(day: BlockedDay, series: readonly Series[]): Segment[] {
  const counts = new Map(day.reasons.map((r) => [r.reason, r.count]));
  return series.map((s) => ({ series: s, count: s.reasons.reduce((n, r) => n + (counts.get(r) ?? 0), 0) }));
}

const WEEKDAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];

/**
 * "Sun 25" for "2026-10-25". The date is already the viewer's calendar day
 * (the backend counted in their zone), so it is read as a date, not a moment.
 */
export function dayLabel(date: string): { weekday: string; day: string } {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(date);
  if (!m) return { weekday: '', day: date };
  const wd = new Date(Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]))).getUTCDay();
  return { weekday: WEEKDAYS[wd], day: String(Number(m[3])) };
}

/** "Sun 25". */
export function dayName(date: string): string {
  const { weekday, day } = dayLabel(date);
  return weekday ? `${weekday} ${day}` : day;
}

/** "2 Domain blacklist (DNS), 1 WAF": a day's blocks by rule, largest first, every rule by its API label. */
export function reasonsText(reasons: readonly ReasonCount[]): string {
  return [...reasons]
    .filter((r) => r.count > 0)
    .sort((a, b) => b.count - a.count || a.reason.localeCompare(b.reason))
    .map((r) => `${formatCount(r.count)} ${r.label}`)
    .join(', ');
}

/** The chart's text alternative: every day that had blocks, by rule, then the others in one phrase. */
export function describeDays(days: readonly BlockedDay[]): string {
  const lead = 'Blocked requests per day, today and the 6 days before:';
  const busy = days.filter((d) => d.blocked > 0);
  if (busy.length === 0) return `${lead} none.`;
  const last = days[days.length - 1]?.date;
  const parts = busy.map((d) => `${d.date === last ? 'today' : dayName(d.date)} ${formatCount(d.blocked)} (${reasonsText(d.reasons)})`);
  const idle = days.length - busy.length;
  const rest = idle > 0 ? `; none on the other ${idle === 1 ? 'day' : `${idle} days`}` : '';
  return `${lead} ${parts.join(', ')}${rest}.`;
}

/** The viewer's IANA time zone, as the browser reports it; UTC when it reports none. */
export function viewerTimeZone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
  } catch {
    return 'UTC';
  }
}
