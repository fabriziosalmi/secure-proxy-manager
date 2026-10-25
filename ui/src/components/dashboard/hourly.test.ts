import { describe, it, expect } from 'vitest'
import { axisMax, axisTicks, hourlySlots } from './hourly'

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
    expect(slots.find((s) => s.time === '2026-10-25 08:00:00')).toEqual({ time: '2026-10-25 08:00:00', total: 1146, blocked: 908 })
    expect(slots.find((s) => s.time === '2026-10-24 20:00:00')).toEqual({ time: '2026-10-24 20:00:00', total: 0, blocked: 0 })
  })

  it('keeps every count the API sent, even an hour outside the window', () => {
    const skewed = [...TEST_DEPLOYMENT, { time: '2026-10-25 10:00:00', total: 3, blocked: 1 }]
    const slots = hourlySlots(skewed, NOW)
    expect(slots.reduce((n, s) => n + s.total, 0)).toBe(26 + 1146 + 8 + 3)
    expect(slots[slots.length - 1]).toEqual({ time: '2026-10-25 10:00:00', total: 3, blocked: 1 })
  })

  it('is all zeros when the API returned no hour', () => {
    const slots = hourlySlots([], NOW)
    expect(slots).toHaveLength(25)
    expect(slots.every((s) => s.total === 0 && s.blocked === 0)).toBe(true)
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
