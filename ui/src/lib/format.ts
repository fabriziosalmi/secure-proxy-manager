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

/** "11:00" in the viewer's time zone, for a backend timestamp; the input when unparseable. */
export function formatHourMinute(ts: string): string {
  const d = parsed(ts);
  return d ? `${pad(d.getHours())}:${pad(d.getMinutes())}` : ts;
}

/** "11:00" in the viewer's time zone, for a moment in the browser (a Date or epoch milliseconds). */
export function formatClock(at: Date | number): string {
  const d = typeof at === 'number' ? new Date(at) : at;
  return `${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

const SHARE = new Intl.NumberFormat('en-US', { minimumFractionDigits: 1, maximumFractionDigits: 1 });

/** part as a share of total with one decimal: (908, 1180) -> "77.0%". Null when total is not positive. */
export function formatShare(part: number, total: number): string | null {
  if (!(total > 0)) return null;
  return `${SHARE.format((part / total) * 100)}%`;
}

/** A percentage the backend already computed, with one decimal: 64.7 -> "64.7%", 0 -> "0.0%". */
export function formatPercent(pct: number): string {
  // -0.0 (Squid prints it for an idle byte hit ratio) is written as 0.0.
  return `${SHARE.format(pct === 0 ? 0 : pct)}%`;
}

const SIZE_UNITS = ['KB', 'MB', 'GB', 'TB'];
const SIZE_SMALL = new Intl.NumberFormat('en-US', { maximumFractionDigits: 1 });

/**
 * A size Squid reports in KB (1024 bytes) in the largest unit that keeps it
 * at 1 or more: 252 -> "252 KB", 51200 -> "50 MB", 1258291 -> "1.2 GB".
 * One decimal below 100 of a unit, none above.
 */
export function formatKilobytes(kb: number): string {
  let v = kb;
  let unit = 0;
  while (Math.abs(v) >= 1024 && unit < SIZE_UNITS.length - 1) {
    v /= 1024;
    unit += 1;
  }
  return `${Math.abs(v) >= 100 ? COUNT.format(v) : SIZE_SMALL.format(v)} ${SIZE_UNITS[unit]}`;
}

/**
 * A size in bytes (an access-log row's): "205 B" under 1 KB, then as
 * formatKilobytes writes it: 6758 -> "6.6 KB", 1258291 -> "1.2 MB".
 */
export function formatBytes(bytes: number): string {
  if (Math.abs(bytes) < 1024) return `${COUNT.format(bytes)} B`;
  return formatKilobytes(bytes / 1024);
}

/** "45s", "12 min", "3 h", "2 d": how long ago something was, from its age in seconds. */
export function formatAge(seconds: number): string {
  const s = Math.max(0, Math.round(seconds));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} min`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h} h`;
  return `${Math.floor(h / 24)} d`;
}
