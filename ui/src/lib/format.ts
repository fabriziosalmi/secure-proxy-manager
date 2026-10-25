import { parseUtc } from './utils';

// The one way the UI writes a count. toLocaleString() follows the browser
// locale, so the same page showed "1328" in one place and "50.772" in another
// (an Italian browser groups with a dot, raw numbers are not grouped at all).
// A fixed locale gives 1,328 and 50,772 everywhere, whoever opens the page.
const COUNT = new Intl.NumberFormat('en-US', { maximumFractionDigits: 0 });

/** A whole-number count with en-US grouping: 1328 -> "1,328". */
export function formatCount(n: number): string {
  return COUNT.format(n);
}

/**
 * The position of a page in a list: "1 to 50 of 50,772" for the first 50
 * rows of 50,772 (offset 0, 50 shown). "No entries" when there is nothing
 * to page through.
 */
export function formatRange(offset: number, shown: number, total: number): string {
  if (total <= 0 || shown <= 0) return 'No entries';
  const first = offset + 1;
  const last = Math.min(offset + shown, total);
  return `${formatCount(first)} to ${formatCount(last)} of ${formatCount(total)}`;
}

// The one way the UI writes a backend timestamp. The backend stores UTC as
// "2026-07-01 09:00:00", with no zone marker; new Date() reads that as local
// time, so the Dashboard, Threat Intel, Logs and Blacklists showed every
// time shifted by the viewer's UTC offset. parseUtc reads it as UTC, and the
// result is written in the viewer's time zone in one fixed, locale-free shape.
const pad = (n: number) => String(n).padStart(2, '0');

function parsed(ts: string): Date | null {
  if (!ts) return null;
  const d = parseUtc(ts);
  return Number.isNaN(d.getTime()) ? null : d;
}

/** "2026-07-01" in the viewer's time zone; the input when unparseable. */
export function formatDate(ts: string): string {
  const d = parsed(ts);
  return d ? `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}` : ts;
}

/** "11:00:00" in the viewer's time zone; the input when unparseable. */
export function formatTime(ts: string): string {
  const d = parsed(ts);
  return d ? `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}` : ts;
}

/** "2026-07-01 11:00:00" in the viewer's time zone; the input when unparseable. */
export function formatDateTime(ts: string): string {
  return parsed(ts) ? `${formatDate(ts)} ${formatTime(ts)}` : ts;
}
