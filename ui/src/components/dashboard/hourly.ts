import type { TimelineEntry } from '../../types';
import { formatCount, formatHourMinute } from '../../lib/format';

/** One hour of the Requests per hour chart. */
export interface HourSlot {
  /**
   * When the hour begins, as a backend timestamp ("2026-10-25 07:00:00",
   * UTC), so the format helpers show it at the viewer time. In a zone with a
   * half-hour offset it reads "...06:30:00" and shows as 12:00 in Kolkata.
   */
  time: string;
  /** When the hour begins, epoch milliseconds. */
  start: number;
  total: number;
  blocked: number;
  /**
   * The part of the hour inside the window, epoch milliseconds, when the
   * window covers only part of it: the first hour starts at now minus 24
   * hours, the last ends now. Absent for a whole hour.
   */
  partial?: { from: number; to: number };
}

const HOUR = 3_600_000;
const pad = (n: number) => String(n).padStart(2, '0');

/** The backend timestamp, UTC, of epoch milliseconds. */
function utcStamp(ms: number): string {
  const d = new Date(ms);
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:00`;
}

/**
 * The start of the viewer's hour that contains ms. Subtracted, not set:
 * setMinutes(0) on the second 02:00 of a night that leaves summer time
 * resolves to the first one, an hour earlier, and the walk never ended.
 */
function hourStart(ms: number): number {
  const d = new Date(ms);
  return ms - (d.getMinutes() * 60_000 + d.getSeconds() * 1000 + d.getMilliseconds());
}

/**
 * Where an entry's hour begins: start (epoch seconds), which the backend
 * sends for logs/timeline?tz=; an older backend sends only time, a UTC hour.
 */
function entryStart(e: TimelineEntry): number {
  return typeof e.start === 'number' ? e.start * 1000 : Date.parse(`${e.time.replace(' ', 'T')}Z`);
}

/**
 * Every hour of the window logs/timeline covers, oldest first, with the
 * hours the backend did not return set to zero. The backend returns only
 * the hours that have rows, so three busy hours used to be drawn as three
 * adjacent bars, as if the day had three hours.
 *
 * The hours are the viewer's: the page asks logs/timeline?tz= for its zone,
 * so in Asia/Kolkata an hour runs from 12:00 to 13:00, not from 12:30. The
 * window is rows since now minus `hours` hours, from the hour containing that
 * moment to the hour containing now (the first and last partial). An entry
 * outside it (a clock that disagrees) is kept, in order, not dropped: every
 * bar comes from the API.
 */
export function hourlySlots(entries: readonly TimelineEntry[], now: number, hours = 24): HourSlot[] {
  const byStart = new Map<number, HourSlot>();
  const from = now - hours * HOUR;
  for (let t = hourStart(from); t <= now; t = hourStart(t + HOUR)) {
    byStart.set(t, { time: utcStamp(t), start: t, total: 0, blocked: 0 });
  }
  for (const e of entries) {
    const at = entryStart(e);
    if (Number.isNaN(at)) continue;
    const slot = byStart.get(at) ?? { time: utcStamp(at), start: at, total: 0, blocked: 0 };
    slot.total += e.total || 0;
    slot.blocked += e.blocked || 0;
    byStart.set(at, slot);
  }
  const out = [...byStart.values()].sort((a, b) => a.start - b.start);
  const first = byStart.get(hourStart(from));
  if (first && from !== first.start) first.partial = { from, to: hourStart(first.start + HOUR) };
  const last = byStart.get(hourStart(now));
  if (last && now !== last.start) last.partial = { from: last.start, to: now };
  return out;
}

const WEEKDAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const two = (n: number) => String(n).padStart(2, '0');
/** "08:52" in the viewer's zone for epoch milliseconds. */
const clock = (ms: number) => { const d = new Date(ms); return `${two(d.getHours())}:${two(d.getMinutes())}`; };

/**
 * The x axis labels, by slot index: the first is where the window starts
 * ("Wed 08:52", yesterday), the last "Now", and every 3rd hour between, so
 * no label is written twice. The axis used to read 08:00 at both ends, the
 * first 08:00 covering 8 minutes of yesterday.
 */
export function axisLabels(slots: readonly HourSlot[]): Map<number, string> {
  const labels = new Map<number, string>();
  if (slots.length === 0) return labels;
  const first = slots[0];
  const startMs = first.partial?.from ?? first.start;
  const d = new Date(startMs);
  labels.set(0, `${WEEKDAYS[d.getDay()]} ${clock(startMs)}`);
  const lastIdx = slots.length - 1;
  labels.set(lastIdx, 'Now');
  for (let i = 3; i < lastIdx - 1; i += 3) labels.set(i, formatHourMinute(slots[i].time));
  return labels;
}

/** "08:52 to 09:00 only": the minutes of a partial hour inside the window. */
export function partialText(slot: HourSlot): string | null {
  return slot.partial ? `${clock(slot.partial.from)} to ${clock(slot.partial.to)} only` : null;
}

const STEPS = [1, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10];

/** The top of the y axis: the busiest hour rounded up to a round number (1,146 -> 1,500). 0 when every hour is empty. */
export function axisMax(slots: readonly Pick<HourSlot, 'time' | 'total' | 'blocked'>[]): number {
  const peak = Math.max(0, ...slots.map((s) => s.total));
  if (peak <= 0) return 0;
  const p = 10 ** Math.floor(Math.log10(peak));
  const step = STEPS.find((m) => m * p >= peak) ?? 10;
  return Math.max(1, Math.round(step * p));
}

/** The chart's text alternative: every hour that had requests, at the viewer time, then the rest in one phrase. */
export function describeHours(slots: readonly HourSlot[]): string {
  const busy = slots.filter((s) => s.total > 0);
  if (busy.length === 0) return 'Requests per hour, last 24 hours: no client requests.';
  const parts = busy.map((s) => {
    const at = `${formatCount(s.total)} at ${formatHourMinute(s.time)}`;
    return s.blocked > 0 ? `${at} of which ${formatCount(s.blocked)} blocked` : at;
  });
  const rest = busy.length < slots.length ? '; no requests in the other hours' : '';
  return `Requests per hour, last 24 hours: ${parts.join(', ')}${rest}.`;
}

/** The y axis labels, top first: the maximum, its half when it is a whole number, and 0. */
export function axisTicks(max: number): number[] {
  if (max <= 0) return [0];
  return Number.isInteger(max / 2) ? [max, max / 2, 0] : [max, 0];
}
