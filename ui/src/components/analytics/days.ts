/**
 * The pure part of "Blocked requests per day, by rule": which colour each
 * rule gets, what each day's bar is made of, and the chart's text
 * alternative. Every count comes from GET /api/analytics/blocked-by-day.
 */
import type { BlockedDay, ReasonCount } from '../../types';
import { formatCount } from '../../lib/format';

export type SeriesColor = 'series-1' | 'series-2' | 'series-3' | 'series-4' | 'neutral';

/** The fill class of each colour: design tokens told apart with any colour vision (tokens.test.ts). */
export const SERIES_BG: Record<SeriesColor, string> = {
  'series-1': 'bg-series-1',
  'series-2': 'bg-series-2',
  'series-3': 'bg-series-3',
  'series-4': 'bg-series-4',
  neutral: 'bg-chart-neutral',
};

/** One stack of the chart: one rule, or the rules of one colour group when several of them blocked. */
export interface Series {
  key: string;
  /** The API's label, or the group's name when the series counts more than one rule. */
  label: string;
  color: SeriesColor;
  /** The block reasons it counts. */
  reasons: string[];
  /** The API labels of the reasons it counts. */
  labels: string[];
}

type RuleColor = Exclude<SeriesColor, 'neutral'>;

// Each rule always has the same colour, whatever else blocked that week: the
// two domain blacklists one each, the address and network rules one, the WAF
// and every other rule one. Colours used to be handed out in order to the
// rules present, so the WAF was series-1 one week and series-2 the next.
const RULE_COLOR: Record<string, RuleColor> = {
  domain_blacklist: 'series-1',
  domain_blacklist_dns: 'series-2',
  domain_blacklist_dns_reconstructed: 'series-2',
  ip_blacklist: 'series-3',
  direct_ip: 'series-3',
  egress_policy: 'series-3',
  port_policy: 'series-3',
  protocol_policy: 'series-3',
  source_gate: 'series-3',
};

/** The colour of a block reason; a rule the UI does not know is drawn with the other rules. */
export function ruleColor(reason: string): RuleColor {
  return RULE_COLOR[reason] ?? 'series-4';
}

// What a colour is called when more than one of its rules blocked in the week.
const GROUP_LABEL: Record<RuleColor, string> = {
  'series-1': 'Domain blacklist (proxy)',
  'series-2': 'Domain blacklist (DNS sinkhole)',
  'series-3': 'Address and network rules',
  'series-4': 'WAF and other rules',
};

const COLORS: readonly RuleColor[] = ['series-1', 'series-2', 'series-3', 'series-4'];

// Within a group, the rules in the order a self-hoster sets them up; a reason
// the UI does not know comes after, by name.
const ORDER = [
  'domain_blacklist_dns', 'domain_blacklist_dns_reconstructed', 'domain_blacklist', 'ip_blacklist', 'waf', 'direct_ip', 'egress_policy', 'proxy_auth',
  'proxy_auth_unset', 'time_restriction', 'content_filter', 'source_gate', 'port_policy', 'protocol_policy', 'lists_unverified', 'other',
];

function rank(reason: string): number {
  const i = ORDER.indexOf(reason);
  return i < 0 ? ORDER.length : i;
}

function byOrder(a: ReasonCount, b: ReasonCount): number {
  return rank(a.reason) - rank(b.reason) || a.reason.localeCompare(b.reason);
}

/**
 * The stacks, bottom first, for the reasons that blocked something in the
 * window (the API's totals): one per colour group that blocked, in colour
 * order, then rows with no recorded reason as the neutral bar on top. A
 * group with one rule is named by its API label; with more, by the group's
 * name, its rules listed in the legend and counted one by one in the table.
 */
export function seriesFor(totals: readonly ReasonCount[]): Series[] {
  const present = totals.filter((r) => r.count > 0);
  const out: Series[] = [];
  for (const color of COLORS) {
    const rules = present.filter((r) => r.reason !== 'unclassified' && ruleColor(r.reason) === color).sort(byOrder);
    if (rules.length === 0) continue;
    out.push({
      key: rules.length === 1 ? rules[0].reason : `group-${color}`,
      label: rules.length === 1 ? rules[0].label : GROUP_LABEL[color],
      color,
      reasons: rules.map((r) => r.reason),
      labels: rules.map((r) => r.label),
    });
  }
  const unclassified = present.find((r) => r.reason === 'unclassified');
  if (unclassified) {
    out.push({ key: unclassified.reason, label: unclassified.label, color: 'neutral', reasons: [unclassified.reason], labels: [unclassified.label] });
  }
  return out;
}

/**
 * The height of a day's whole bar. A day with blocks stays visible at 4 px;
 * the rules share the bar by their counts. The floor used to apply to each
 * rule, so a day of 10 blocks over 3 rules drew 12 px, as tall as a day of
 * hundreds on a scale of thousands.
 */
export function barHeight(total: number, max: number): string {
  return total > 0 ? `max(4px, ${(total / max) * 100}%)` : '0';
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
