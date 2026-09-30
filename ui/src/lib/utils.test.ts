import { describe, it, expect, vi, afterEach } from 'vitest'
import { parseUtc, relative } from './utils'

describe('parseUtc', () => {
  it('reads a zone-less SQLite timestamp as UTC', () => {
    expect(parseUtc('2026-06-04 14:30:00').toISOString()).toBe('2026-06-04T14:30:00.000Z')
  })
  it('leaves an ISO string that already has a zone alone', () => {
    expect(parseUtc('2026-06-04T14:30:00+02:00').toISOString()).toBe('2026-06-04T12:30:00.000Z')
  })
})

describe('relative', () => {
  afterEach(() => vi.useRealTimers())
  const at = (now: string, ts: string) => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date(now))
    return relative(ts)
  }
  it('picks the unit', () => {
    const now = '2026-06-04T15:00:00Z'
    expect(at(now, '2026-06-04 14:59:30')).toBe('30s ago')
    expect(at(now, '2026-06-04 14:55:00')).toBe('5m ago')
    expect(at(now, '2026-06-04 12:00:00')).toBe('3h ago')
    expect(at(now, '2026-06-02 15:00:00')).toBe('2d ago')
  })
  it('never goes negative for a timestamp slightly in the future', () => {
    expect(at('2026-06-04T15:00:00Z', '2026-06-04 15:00:05')).toBe('0s ago')
  })
  it('shows a dash for empty and echoes what it cannot parse', () => {
    expect(relative('')).toBe('—')
    expect(relative('not a date')).toBe('not a date')
  })
})
