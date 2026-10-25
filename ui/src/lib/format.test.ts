import { describe, it, expect, vi, afterEach, beforeAll, afterAll } from 'vitest'
import { formatClock, formatCount, formatDate, formatDateTime, formatHourMinute, formatRange, formatShare, formatTime } from './format'
import { simulateItalianLocale, setRomeTimeZone } from '../test/helpers'

describe('formatRange', () => {
  afterEach(() => { vi.restoreAllMocks() })

  it('writes the first page of a long list with grouped counts', () => {
    expect(formatRange(0, 50, 50772)).toBe('1 to 50 of 50,772')
  })

  it('writes a later page and a short last page', () => {
    expect(formatRange(50, 50, 50772)).toBe('51 to 100 of 50,772')
    expect(formatRange(50750, 22, 50772)).toBe('50,751 to 50,772 of 50,772')
  })

  it('never runs past the total', () => {
    expect(formatRange(0, 50, 7)).toBe('1 to 7 of 7')
  })

  it('says there is nothing rather than "1 to 0 of 0"', () => {
    expect(formatRange(0, 0, 0)).toBe('No entries')
  })

  it('does not follow the browser locale', () => {
    simulateItalianLocale()
    expect(formatRange(1000, 50, 50772)).toBe('1,001 to 1,050 of 50,772')
  })
})

describe('formatCount', () => {
  afterEach(() => { vi.restoreAllMocks() })

  it('groups thousands with a comma', () => {
    expect(formatCount(0)).toBe('0')
    expect(formatCount(999)).toBe('999')
    expect(formatCount(1328)).toBe('1,328')
    expect(formatCount(50772)).toBe('50,772')
    expect(formatCount(1234567)).toBe('1,234,567')
  })

  it('writes a count as a whole number', () => {
    expect(formatCount(1327.6)).toBe('1,328')
  })

  // The point of the module: an Italian (or any other) browser locale must not
  // turn 50,772 into 50.772 on one card and leave 1328 bare on the next.
  it('does not follow the browser locale', async () => {
    simulateItalianLocale()
    expect((50772).toLocaleString()).toBe('50.772')
    // Re-import so the module builds its formatter under the simulated locale.
    vi.resetModules()
    const fresh = await import('./format')
    expect(fresh.formatCount(50772)).toBe('50,772')
  })
})

// The backend writes UTC as "2026-07-01 09:00:00" with no zone marker.
describe('formatDate / formatTime / formatDateTime', () => {
  let restoreTz: () => void
  beforeAll(() => { restoreTz = setRomeTimeZone() })
  afterAll(() => { restoreTz() })

  it('reads a backend timestamp as UTC and writes it in the viewer time zone', () => {
    expect(formatTime('2026-07-01 09:00:00')).toBe('11:00:00')
    expect(formatDateTime('2026-07-01 09:00:00')).toBe('2026-07-01 11:00:00')
    expect(formatDateTime('2026-01-15 09:05:07')).toBe('2026-01-15 10:05:07')
  })

  it('moves the date when the zone offset crosses midnight', () => {
    expect(formatDate('2026-01-01 23:30:00')).toBe('2026-01-02')
  })

  it('accepts an ISO timestamp that already carries its zone', () => {
    expect(formatDateTime('2026-07-01T09:00:00Z')).toBe('2026-07-01 11:00:00')
  })

  it('returns what it was given when it cannot parse it', () => {
    expect(formatDateTime('not a date')).toBe('not a date')
    expect(formatTime('')).toBe('')
  })

  it('writes hours and minutes of a backend timestamp in the viewer time zone', () => {
    expect(formatHourMinute('2026-07-01 09:00:00')).toBe('11:00')
    expect(formatHourMinute('2026-01-15 23:59:59')).toBe('00:59')
    expect(formatHourMinute('nope')).toBe('nope')
  })

  // "updated HH:MM" is a moment in the browser, not a backend string.
  it('writes a browser moment as hours and minutes in the viewer time zone', () => {
    const at = Date.UTC(2026, 6, 1, 9, 21, 40)
    expect(formatClock(at)).toBe('11:21')
    expect(formatClock(new Date(at))).toBe('11:21')
  })
})

describe('formatShare', () => {
  afterEach(() => { vi.restoreAllMocks() })

  it('writes a share with one decimal', () => {
    expect(formatShare(908, 1180)).toBe('76.9%')
    expect(formatShare(23, 1235)).toBe('1.9%')
    expect(formatShare(0, 10)).toBe('0.0%')
    expect(formatShare(10, 10)).toBe('100.0%')
  })

  // No requests is not a 0% block rate.
  it('has no share of nothing', () => {
    expect(formatShare(0, 0)).toBeNull()
  })

  it('does not follow the browser locale', async () => {
    simulateItalianLocale()
    vi.resetModules()
    const fresh = await import('./format')
    expect(fresh.formatShare(1, 3)).toBe('33.3%')
  })
})
