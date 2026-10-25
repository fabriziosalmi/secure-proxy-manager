import { describe, it, expect, vi, afterEach, beforeAll, afterAll } from 'vitest'
import { formatCount, formatDate, formatDateTime, formatTime } from './format'
import { simulateItalianLocale, setRomeTimeZone } from '../test/helpers'

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
})
