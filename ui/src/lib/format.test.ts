import { describe, it, expect, vi, afterEach } from 'vitest'
import { formatCount } from './format'
import { simulateItalianLocale } from '../test/helpers'

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
