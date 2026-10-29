import type { TimelineEntry } from '../../types';
import { formatCount, formatHourMinute } from '../../lib/format';

/** One hour of the Requests per hour chart. */
export interface HourSlot {
  /** The hour bucket as the backend writes it: "2026-10-25 07:00:00", UTC. */
  time: string;
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

/** The backend's hour key for the UTC hour that contains ms. */
function hourKey(ms: number): string {
  const d = new Date(Math.floor(ms / HOUR) * HOUR);
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:00:00`;
}

/**
 * Every hour of the window logs/timeline covers, oldest first, with the
 * hours the backend did not return set to zero. The backend returns only
 * the hours that have rows, so three busy hours used to be drawn as three
 * adjacent bars, as if the day had three hours.
 *
 * The window is the backend's: rows since now minus `hours` hours, bucketed
 * by UTC hour, so it spans from the hour containing now minus `hours` to the
 * hour containing now (hours + 1 buckets, the first and last partial). An
 * entry outside that range (a clock that disagrees) is kept, in order, not
 * dropped: every bar comes from the API.
 */
export function hourlySlots(entries: readonly TimelineEntry[], now: number, hours = 24): HourSlot[] {
  const byTime = new Map<string, HourSlot>();
  for (let t = now - hours * HOUR; ; t += HOUR) {
    const key = hourKey(t);
    byTime.set(key, { time: key, total: 0, blocked: 0 });
    if (key === hourKey(now)) break;
  }
  for (const e of entries) {
    const slot = byTime.get(e.time) ?? { time: e.time, total: 0, blocked: 0 };
    slot.total += e.total || 0;
    slot.blocked += e.blocked || 0;
    byTime.set(e.time, slot);
  }
  // Same fixed-width shape for every key, so text order is time order.
  const out = [...byTime.values()].sort((a, b) => a.time.localeCompare(b.time));
  const start = now - hours * HOUR;
  const first = out.find((s) => s.time === hourKey(start));
  if (first && start % HOUR !== 0) first.partial = { from: start, to: Math.floor(start / HOUR) * HOUR + HOUR };
  const last = out.find((s) => s.time === hourKey(now));
  if (last && now % HOUR !== 0) last.partial = { from: Math.floor(now / HOUR) * HOUR, to: now };
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
  const startMs = first.partial?.from ?? Date.parse(first.time.replace(' ', 'T') + 'Z');
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
export function axisMax(slots: readonly HourSlot[]): number {
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
