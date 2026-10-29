import { describe, it, expect, afterEach, beforeEach } from 'vitest'
import { cacheCollected, cacheDisk, cacheHitRatio, cacheHitWindow, cacheSummary } from './cacheStats'
import { currentCacheStats, staleCacheStats } from '../test/cacheStats'
import { setRomeTimeZone } from '../test/helpers'

describe('cache statistics text', () => {
  let restoreTz: () => void
  beforeEach(() => { restoreTz = setRomeTimeZone() })
  afterEach(() => { restoreTz() })

  it("says the current record's hit ratio, disk use and collection time", () => {
    // 12:15:28 UTC is 13:15 in Rome on 2026-10-25 (CET).
    expect(cacheSummary({ ...currentCacheStats, uptime_s: 7200 }))
      .toBe('Hit ratio 64.7% (last hour) · 252 KB of 50.0 MB on disk · collected 13:15')
  })

  // Squid's 60 minute window covers the time since it started until it has
  // run for an hour: 210 s of uptime is not "the last hour".
  it('names the window Squid measured over', () => {
    expect(cacheHitWindow(currentCacheStats)).toBe('last 3 min, since Squid started')
    expect(cacheHitWindow({ ...currentCacheStats, uptime_s: 3600 })).toBe('last hour')
    expect(cacheHitRatio(currentCacheStats)).toBe('Hit ratio 64.7% (last 3 min, since Squid started)')
  })

  // Squid prints 0.0% before its first sample; the watchdog records null.
  it('never writes an absent hit ratio as 0%', () => {
    const first = { ...currentCacheStats, request_hit_ratio_60min_pct: null, uptime_s: 8.4 }
    expect(cacheHitRatio(first)).toBeNull()
    expect(cacheSummary(first)).toMatch(/^Hit ratio not measured yet \(Squid's first minute\) · /)
    expect(cacheSummary(first)).not.toContain('0.0%')
    expect(cacheHitRatio({ ...currentCacheStats, request_hit_ratio_60min_pct: 0, uptime_s: 7200 })).toBe('Hit ratio 0.0% (last hour)')
  })

  it('writes the disk use with its capacity when Squid reported one', () => {
    expect(cacheDisk({ ...currentCacheStats, disk_used_kb: 1258291, disk_capacity_kb: 10485760 })).toBe('1.2 GB of 10.0 GB on disk')
    expect(cacheDisk({ ...currentCacheStats, disk_capacity_kb: null })).toBe('252 KB on disk')
    expect(cacheDisk({ ...currentCacheStats, disk_used_kb: null })).toBeNull()
  })

  it('dates a stale record and says how old it is', () => {
    expect(cacheCollected(staleCacheStats)).toBe('Last collected 2026-10-25 13:15:28 (25 min ago)')
  })
})
