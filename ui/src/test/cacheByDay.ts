/**
 * A GET /api/analytics/cache-by-day body as analytics_cache.go writes it:
 * seven days of Europe/Rome, every outcome present. The week's mix is the
 * one measured on a deployment without HTTPS inspection: tunnels carry
 * nearly every byte, and the cache answers a small share of the rest.
 */
import type { CacheByDay, CacheCounts } from '../types'

const zero = (): CacheCounts => ({ hit: 0, revalidated: 0, miss: 0, tunnel: 0, refused: 0, other: 0 })

export const CACHE_DAYS = ['19', '20', '21', '22', '23', '24', '25']

export function cacheByDayFixture(): CacheByDay {
  const days = CACHE_DAYS.map((d, i) => ({
    date: `2026-10-${d}`,
    start: 1792360800 + i * 86400,
    end: 1792360800 + (i + 1) * 86400,
    requests: zero(),
    bytes: zero(),
  }))
  // Monday 19 has nothing; Sunday 25 (today) has every kind.
  Object.assign(days[1].requests, { miss: 40, tunnel: 900 })
  Object.assign(days[1].bytes, { miss: 4 * 1024 * 1024, tunnel: 900 * 1024 * 1024 })
  Object.assign(days[6].requests, { hit: 2, revalidated: 127, miss: 417, tunnel: 7074, refused: 928, other: 16 })
  Object.assign(days[6].bytes, { hit: 2048, revalidated: 56 * 1024 * 1024, miss: 96 * 1024 * 1024, tunnel: 5 * 1024 ** 3, refused: 4 * 1024 * 1024, other: 0 })
  const totals = { requests: zero(), bytes: zero() }
  for (const day of days) {
    for (const k of Object.keys(totals.requests) as (keyof CacheCounts)[]) {
      totals.requests[k] += day.requests[k]
      totals.bytes[k] += day.bytes[k]
    }
  }
  return {
    tz: 'Europe/Rome',
    outcomes: [
      { outcome: 'hit', label: 'From the cache' },
      { outcome: 'revalidated', label: 'From the cache, checked with the server' },
      { outcome: 'miss', label: 'Fetched from the server' },
      { outcome: 'tunnel', label: 'HTTPS tunnel (not cacheable)' },
      { outcome: 'refused', label: 'Refused by the proxy' },
      { outcome: 'other', label: 'Other' },
    ],
    days,
    totals,
    internal_sources: 2,
  }
}
