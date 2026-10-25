import type { CacheStats } from '../types'

/**
 * GET /api/cache/statistics as the backend answers for the record the
 * watchdog wrote from the Squid 7.7 pages in tests/python/fixtures
 * (backend-go/internal/handlers/cache_stats_test.go), 42 s after it.
 */
export const currentCacheStats: CacheStats = {
  state: 'current',
  collected_at: '2026-10-25 12:15:28',
  age_s: 42,
  interval_s: 60,
  stale_after_s: 180,
  request_hit_ratio_5min_pct: 64.7,
  request_hit_ratio_60min_pct: 64.7,
  byte_hit_ratio_5min_pct: 91.6,
  byte_hit_ratio_60min_pct: 91.6,
  disk_used_kb: 252,
  disk_capacity_kb: 51200,
  disk_used_pct: 0.5,
  memory_used_kb: 468,
  memory_used_pct: 0.2,
  uptime_s: 210.475,
  store_entries: 64,
  memory_objects: 11,
  disk_objects: 11,
}

const NO_VALUES = {
  collected_at: null, age_s: null, interval_s: null, stale_after_s: null,
  request_hit_ratio_5min_pct: null, request_hit_ratio_60min_pct: null,
  byte_hit_ratio_5min_pct: null, byte_hit_ratio_60min_pct: null,
  disk_used_kb: null, disk_capacity_kb: null, disk_used_pct: null,
  memory_used_kb: null, memory_used_pct: null, uptime_s: null,
  store_entries: null, memory_objects: null, disk_objects: null,
}

/** No cache_stats.json on the proxy. */
export const notCollectedCacheStats: CacheStats = { state: 'not_collected', ...NO_VALUES }

/** The same record 25 minutes later: three intervals missed long ago. */
export const staleCacheStats: CacheStats = { ...currentCacheStats, state: 'stale', age_s: 1500 }
