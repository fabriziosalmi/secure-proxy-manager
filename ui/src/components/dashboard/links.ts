import { NO_FILTERS, writeFilters, type LogFilters } from '../../lib/accessLog';

/**
 * The access log filtered to blocked requests, and to a host (q) or a rule
 * when given: where a figure on the Overview can be read row by row. The
 * Overview counts the last 24 hours; the log lists every row it keeps,
 * newest first.
 */
export function blockedLogsLink(f: Partial<Pick<LogFilters, 'q' | 'rule'>> = {}): string {
  return `/logs?${writeFilters({ ...NO_FILTERS, ...f, outcome: 'blocked' }).toString()}`;
}
