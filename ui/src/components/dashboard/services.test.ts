import { describe, it, expect } from 'vitest'
import { serviceRows } from './services'
import type { CacheStats, DashboardSummary } from '../../types'
import type { StatusData } from '../../lib/queries'

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
      ok<CacheStats>({ simulated: true, hit_rate: 0, byte_hit_rate: 0, cache_size: 'N/A', objects_cached: 0 }),
    ))
    expect(rows.Backend).toMatchObject({ health: 'ok', state: 'running', detail: 'v3.14.3' })
    expect(rows.Proxy).toMatchObject({ health: 'ok', state: 'running', detail: 'Squid 7.7, port 3128' })
    expect(rows.WAF).toMatchObject({ health: 'ok', state: 'reporting', detail: '30 requests inspected' })
    // simulated: nothing wrote cache_stats.txt, so the zeros are not a 0% hit rate.
    expect(rows['Cache statistics']).toMatchObject({ health: 'unknown', state: 'not collected' })
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
      ok<CacheStats>({ hit_rate: 0.423, byte_hit_rate: 0, cache_size: '1 KB', objects_cached: 1 }),
    ))
    expect(rows.Proxy).toMatchObject({ health: 'down', state: 'not answering' })
    expect(rows.WAF).toMatchObject({ health: 'down', state: 'refusing the backend' })
    expect(rows.WAF.detail).toContain('INTERNAL_ALERT_TOKEN')
    expect(rows['Cache statistics']).toMatchObject({ health: 'ok', detail: 'Hit rate 42.3% (5 minutes)' })
    expect(byName(serviceRows(failed, summary({ waf_status: 'unreachable' }), failed)).WAF.state).toBe('not reachable')
  })
})
