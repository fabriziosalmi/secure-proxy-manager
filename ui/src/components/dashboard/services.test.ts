import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { serviceRows } from './services'
import type { CacheStats, DashboardSummary } from '../../types'
import type { StatusData } from '../../lib/queries'
import { currentCacheStats, notCollectedCacheStats, staleCacheStats } from '../../test/cacheStats'
import { setRomeTimeZone } from '../../test/helpers'

type Load<T> = { data?: T | null; isPending: boolean; isError: boolean }
const ok = <T>(data: T): Load<T> => ({ data, isPending: false, isError: false })
const pending: Load<never> = { isPending: true, isError: false }
const failed: Load<never> = { isPending: false, isError: true }

const summary = (s: Partial<DashboardSummary>) => ok(s as DashboardSummary)

function byName(rows: ReturnType<typeof serviceRows>) {
  return Object.fromEntries(rows.map((r) => [r.name, r]))
}

describe('serviceRows', () => {
  it('reports what /api/status, the summary and cache/statistics say', () => {
    const rows = byName(serviceRows(
      ok<StatusData>({ proxy_status: 'running', proxy_port: '3128', version: '3.14.3', squid_version: '7.7' }),
      summary({ waf_status: 'ok', waf: { total_requests: 30 } as DashboardSummary['waf'] }),
      ok<CacheStats>(notCollectedCacheStats),
    ))
    expect(rows.Backend).toMatchObject({ health: 'ok', state: 'running', detail: 'v3.14.3' })
    expect(rows.Proxy).toMatchObject({ health: 'ok', state: 'running', detail: 'Squid 7.7, port 3128' })
    expect(rows.WAF).toMatchObject({ health: 'ok', state: 'reporting', detail: '30 requests inspected' })
    // No cache_stats.json on the proxy: not a 0% hit rate.
    expect(rows['Cache statistics']).toMatchObject({ health: 'unknown', state: 'not collected', detail: 'The proxy has not written cache statistics yet' })
  })

  it('shows Not checked for Squid 7.x when cves_checked is false, and the CVE count when checked', () => {
    const unchecked = byName(serviceRows(
      ok<StatusData>({ proxy_status: 'running', proxy_port: '3128', squid_version: '7.7', squid_cves: 0, cves_checked: false }),
      pending,
      pending,
    ))
    expect(unchecked.Proxy.detail).toBe('Squid 7.7, port 3128 · Not checked for Squid 7.x')

    const checked = byName(serviceRows(
      ok<StatusData>({ proxy_status: 'running', proxy_port: '3128', squid_version: '5.9', squid_cves: 10, cves_checked: true }),
      pending,
      pending,
    ))
    expect(checked.Proxy.detail).toBe('Squid 5.9, port 3128 · 10 known CVEs')
  })

  describe('cache statistics', () => {
    let restoreTz: () => void
    beforeEach(() => { restoreTz = setRomeTimeZone() })
    afterEach(() => { restoreTz() })
    const cacheRow = (c: CacheStats) => byName(serviceRows(pending, pending, ok(c)))['Cache statistics']

    it("shows the proxy's current record: hit ratio, disk use and when it was collected", () => {
      expect(cacheRow({ ...currentCacheStats, uptime_s: 7200 })).toEqual({
        name: 'Cache statistics', health: 'ok', state: 'collected',
        detail: 'Hit ratio 64.7% (last hour) · 252 KB of 50.0 MB on disk · collected 13:15',
      })
    })

    // Three missed collections: the numbers describe the past, so they are not shown as the cache's state.
    it('says a stale record is out of date and when it was last collected', () => {
      const row = cacheRow(staleCacheStats)
      expect(row).toMatchObject({ health: 'down', state: 'out of date', detail: 'Last collected 2026-10-25 13:15:28 (25 min ago)' })
      expect(row.detail).not.toContain('64.7%')
    })

    it('says a record the backend cannot read is unreadable, with no numbers', () => {
      expect(cacheRow({ ...notCollectedCacheStats, state: 'unreadable' })).toMatchObject({ health: 'unknown', state: 'unreadable' })
    })
  })

  // No data is not "running".
  it('never shows a service as running without data', () => {
    for (const status of [pending, failed]) {
      const rows = serviceRows(status, pending, pending)
      expect(rows.filter((r) => r.health === 'ok')).toEqual([])
      expect(rows.some((r) => r.state === 'running')).toBe(false)
    }
    const noProxy = byName(serviceRows(ok<StatusData>({ version: '3.14.3' }), failed, failed))
    expect(noProxy.Proxy).toMatchObject({ health: 'unknown', state: 'not reported' })
    expect(noProxy.WAF.health).toBe('unknown')
    expect(noProxy['Cache statistics']).toMatchObject({ health: 'unknown', state: 'not reported' })
  })

  it('says why the proxy and the WAF are down', () => {
    const rows = byName(serviceRows(
      ok<StatusData>({ proxy_status: 'error', proxy_port: '3128' }),
      summary({ waf_status: 'auth_failed', waf: null }),
      ok<CacheStats>(currentCacheStats),
    ))
    expect(rows.Proxy).toMatchObject({ health: 'down', state: 'not answering' })
    expect(rows.WAF).toMatchObject({ health: 'down', state: 'refusing the backend' })
    expect(rows.WAF.detail).toContain('INTERNAL_ALERT_TOKEN')
    expect(rows['Cache statistics']).toMatchObject({ health: 'ok', state: 'collected' })
    expect(byName(serviceRows(failed, summary({ waf_status: 'unreachable' }), failed)).WAF.state).toBe('not reachable')
  })
})
