import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import { renderWithProviders, setRomeTimeZone, simulateItalianLocale } from '../../test/helpers'
import { currentCacheStats, notCollectedCacheStats, staleCacheStats } from '../../test/cacheStats'
import { api } from '../../lib/api'
import { proxyAddress } from '../../lib/utils'
import { ServiceStatus } from './ServiceStatus'

// Bodies as the backend sends them. Only api.get is stubbed, so the panel's
// own envelope handling is what is under test.
const bodies: Record<string, unknown> = {
  status: {
    status: 'success',
    data: { proxy_status: 'running', proxy_host: 'proxy', proxy_port: '3128', version: '3.4.0', requests_count: 50772 },
  },
  'dashboard/summary': { status: 'success', data: { today_blocked: 1328 } },
  'cache/statistics': { status: 'success', data: notCollectedCacheStats },
  'clients/statistics': {
    status: 'success',
    data: [{ ip_address: '192.168.0.109', requests: 1172, blocked: 8, last_seen: '2026-10-25 09:00:00', status: 'Active' }],
    meta: { total: 3, limit: 1, offset: 0 },
    total: 3,
  },
}

/** The value line of the tile whose label is `label`. */
function tileValue(label: string): string {
  return screen.getByText(label).nextElementSibling?.textContent ?? ''
}

/** The detail line under a tile's value, '' when it has none. */
function tileDetail(label: string): string {
  return screen.getByText(label).nextElementSibling?.nextElementSibling?.textContent ?? ''
}

function serveCache(data: unknown) {
  vi.mocked(api.get).mockImplementation((url: string) =>
    Promise.resolve({ data: url === 'cache/statistics' ? { status: 'success', data } : bodies[url] ?? { status: 'success', data: null } }))
}

describe('ServiceStatus', () => {
  beforeEach(() => {
    vi.spyOn(api, 'get').mockImplementation((url: string) =>
      Promise.resolve({ data: bodies[url] ?? { status: 'success', data: null } }))
  })
  afterEach(() => { vi.restoreAllMocks() })

  it('shows the client count the backend reports in meta', async () => {
    renderWithProviders(<ServiceStatus />)
    await waitFor(() => { expect(tileValue('Clients')).toBe('3') })
  })

  // requests_count counts rows since the start of the day and today_blocked
  // since UTC midnight: neither is a rolling 24 hours.
  it('labels the request counts as today, which is the window the backend counts', async () => {
    simulateItalianLocale()
    renderWithProviders(<ServiceStatus />)
    await waitFor(() => { expect(tileValue('Requests today')).toBe('50,772') })
    expect(tileValue('Blocked today')).toBe('1,328')
    expect(screen.queryByText(/24h/)).not.toBeInTheDocument()
  })

  // proxy_host is the compose service name, reachable only inside the compose
  // network. The tile showed "proxy:3128"; the Dashboard showed the address a
  // client can use. Both read proxyAddress() now.
  it('shows the reachable proxy address, the same one the Dashboard shows', async () => {
    renderWithProviders(<ServiceStatus />)
    await waitFor(() => { expect(tileValue('Listen')).toBe(`${window.location.hostname}:3128`) })
    expect(tileValue('Listen')).toBe(proxyAddress())
    expect(tileValue('Listen')).not.toContain('proxy:')
  })

  // No cache_stats.json on the proxy: the tile used to render zeros as a
  // measured "0.0%" hit rate.
  it('says the cache hit ratio is not collected when the proxy has written no record', async () => {
    renderWithProviders(<ServiceStatus />)
    await waitFor(() => { expect(tileValue('Cache hit')).toBe('Not collected') })
    expect(tileDetail('Cache hit')).toBe('')
  })

  describe('with cache statistics from the proxy', () => {
    let restoreTz: () => void
    beforeEach(() => { restoreTz = setRomeTimeZone() })
    afterEach(() => { restoreTz() })

    it("shows Squid's hit ratio, its window, the disk use and when it was collected", async () => {
      serveCache({ ...currentCacheStats, uptime_s: 7200 })
      renderWithProviders(<ServiceStatus />)
      await waitFor(() => { expect(tileValue('Cache hit')).toBe('64.7%') })
      expect(tileDetail('Cache hit')).toBe('last hour · 252 KB of 50 MB on disk · collected 13:15')
      // The tile is narrow and cuts the line: its title holds all of it.
      expect(screen.getByTitle('last hour · 252 KB of 50 MB on disk · collected 13:15')).toBeInTheDocument()
    })

    // Squid prints 0.0% in its first minute; the record holds null.
    it('says the hit ratio is not measured yet rather than 0.0% in Squid\'s first minute', async () => {
      serveCache({ ...currentCacheStats, request_hit_ratio_60min_pct: null, uptime_s: 8.4 })
      renderWithProviders(<ServiceStatus />)
      await waitFor(() => { expect(tileValue('Cache hit')).toBe('Not measured yet') })
      expect(tileDetail('Cache hit')).toBe("Squid's first minute · 252 KB of 50 MB on disk · collected 13:15")
    })

    it('says a stale record is out of date, with when it was last collected', async () => {
      serveCache(staleCacheStats)
      renderWithProviders(<ServiceStatus />)
      await waitFor(() => { expect(tileValue('Cache hit')).toBe('Out of date') })
      expect(tileDetail('Cache hit')).toBe('Last collected 2026-10-25 13:15:28 (25 min ago)')
    })
  })

  it('says a value is not reported instead of showing a bare placeholder', async () => {
    vi.mocked(api.get).mockImplementation((url: string) =>
      Promise.resolve({ data: url === 'status' ? { status: 'success', data: { proxy_status: 'running' } } : { status: 'success', data: null } }))
    renderWithProviders(<ServiceStatus />)
    await waitFor(() => { expect(tileValue('Version')).toBe('Not reported') })
    expect(tileValue('Clients')).toBe('Not reported')
    expect(tileValue('Requests today')).toBe('Not reported')
    expect(tileValue('Blocked today')).toBe('Not reported')
    expect(tileValue('Cache hit')).toBe('Not reported')
  })
})
