import { describe, it, expect, vi, afterEach } from 'vitest'
import { axisLabels, axisMax, axisTicks, hourlySlots } from './hourly'

// 2026-10-25 09:21:40 UTC, the moment the test deployment's screenshot was taken.
const NOW = Date.UTC(2026, 9, 25, 9, 21, 40)

const TEST_DEPLOYMENT = [
  { time: '2026-10-25 07:00:00', total: 26, blocked: 0 },
  { time: '2026-10-25 08:00:00', total: 1146, blocked: 908 },
  { time: '2026-10-25 09:00:00', total: 8, blocked: 0 },
]

describe('hourlySlots', () => {
  // logs/timeline returns only the hours with rows; three busy hours were
  // drawn as three adjacent bars, as if the day had three hours.
  it('fills every hour of the window, the empty ones with zero', () => {
    const slots = hourlySlots(TEST_DEPLOYMENT, NOW)
    // now - 24h is in the 09:00 hour of the day before: 25 hour buckets,
    // the first and the last partial, as the backend buckets them.
    expect(slots).toHaveLength(25)
    expect(slots[0].time).toBe('2026-10-24 09:00:00')
    expect(slots[24].time).toBe('2026-10-25 09:00:00')
    expect(slots.filter((s) => s.total > 0).map((s) => s.time)).toEqual(TEST_DEPLOYMENT.map((e) => e.time))
    expect(slots.find((s) => s.time === '2026-10-25 08:00:00')).toEqual({ time: '2026-10-25 08:00:00', start: Date.UTC(2026, 9, 25, 8), total: 1146, blocked: 908 })
    expect(slots.find((s) => s.time === '2026-10-24 20:00:00')).toEqual({ time: '2026-10-24 20:00:00', start: Date.UTC(2026, 9, 24, 20), total: 0, blocked: 0 })
  })

  it('keeps every count the API sent, even an hour outside the window', () => {
    const skewed = [...TEST_DEPLOYMENT, { time: '2026-10-25 10:00:00', total: 3, blocked: 1 }]
    const slots = hourlySlots(skewed, NOW)
    expect(slots.reduce((n, s) => n + s.total, 0)).toBe(26 + 1146 + 8 + 3)
    expect(slots[slots.length - 1]).toEqual({ time: '2026-10-25 10:00:00', start: Date.UTC(2026, 9, 25, 10), total: 3, blocked: 1 })
  })

  it('is all zeros when the API returned no hour', () => {
    const slots = hourlySlots([], NOW)
    expect(slots).toHaveLength(25)
    expect(slots.every((s) => s.total === 0 && s.blocked === 0)).toBe(true)
  })
})

// The chart grouped by UTC hour, so in a zone with a half-hour offset every
// label read half past: 12:30 15:30 18:30 in Asia/Kolkata, 04:30 07:30 in
// America/St_Johns. The page now asks logs/timeline?tz= for the viewer's
// hours, and the slots are those hours.
describe('hourlySlots in a zone with a half-hour offset', () => {
  afterEach(() => { vi.unstubAllEnvs() })
  // 2026-10-29 07:52:30 UTC: 13:22 in Kolkata (UTC+05:30), 05:22 in St John's (UTC-02:30).
  const AT = Date.UTC(2026, 9, 29, 7, 52, 30)

  it.each([
    ['Asia/Kolkata', '13:00 16:00 19:00 22:00 01:00 04:00 07:00 10:00 13:00'],
    ['America/St_Johns', '05:00 08:00 11:00 14:00 17:00 20:00 23:00 02:00 05:00'],
  ])('%s: every hour begins on the hour of the zone', (zone, every3rd) => {
    vi.stubEnv('TZ', zone)
    const slots = hourlySlots([], AT)
    const clock = (ms: number) => new Intl.DateTimeFormat('en-GB', { timeZone: zone, hour: '2-digit', minute: '2-digit', hourCycle: 'h23' }).format(ms)
    expect(slots.filter((_, i) => i % 3 === 0).map((s) => clock(s.start)).join(' ')).toBe(every3rd)
    // The labels between the ends are those hours.
    const labels = axisLabels(slots)
    expect(labels.get(3)).toBe(clock(slots[3].start))
    expect(labels.get(3)).toMatch(/:00$/)
  })

  it('puts an hour the backend counted in the zone into the slot of that hour', () => {
    vi.stubEnv('TZ', 'Asia/Kolkata')
    // 12:00 to 13:00 in Kolkata is 06:30 to 07:30 UTC.
    const start = Date.UTC(2026, 9, 29, 6, 30) / 1000
    const slots = hourlySlots([{ time: '2026-10-29 12:00:00', start, total: 5, blocked: 2 }], AT)
    expect(slots.filter((s) => s.total > 0)).toEqual([{ time: '2026-10-29 06:30:00', start: start * 1000, total: 5, blocked: 2 }])
  })

  it('walks through the night summer time ends without stopping', () => {
    vi.stubEnv('TZ', 'Europe/Rome')
    // 25 October 2026: 03:00 CEST becomes 02:00 CET; the day has 25 hours.
    const slots = hourlySlots([], Date.UTC(2026, 9, 25, 12, 0, 0))
    expect(slots).toHaveLength(25)
    expect(new Set(slots.map((s) => s.start)).size).toBe(25)
  })
})

describe('axisMax / axisTicks', () => {
  it('rounds the busiest hour up to a round number', () => {
    expect(axisMax(hourlySlots(TEST_DEPLOYMENT, NOW))).toBe(1500)
    expect(axisMax([{ time: 'x', total: 7, blocked: 0 }])).toBe(8)
    expect(axisMax([{ time: 'x', total: 1, blocked: 1 }])).toBe(1)
    expect(axisMax([{ time: 'x', total: 100, blocked: 0 }])).toBe(100)
  })

  it('has no axis when nothing was requested', () => {
    expect(axisMax(hourlySlots([], NOW))).toBe(0)
  })

  it('labels whole numbers only', () => {
    expect(axisTicks(1500)).toEqual([1500, 750, 0])
    expect(axisTicks(1)).toEqual([1, 0])
    expect(axisTicks(0)).toEqual([0])
  })
})
