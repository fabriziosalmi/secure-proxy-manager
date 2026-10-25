import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import { renderWithProviders, simulateItalianLocale } from '../../test/helpers'
import { api } from '../../lib/api'
import { ServiceStatus } from './ServiceStatus'

// Bodies as the backend sends them. Only api.get is stubbed, so the panel's
// own envelope handling is what is under test.
const bodies: Record<string, unknown> = {
  status: {
    status: 'success',
    data: { proxy_status: 'running', proxy_host: 'proxy', proxy_port: '3128', version: '3.4.0', requests_count: 50772 },
  },
  'dashboard/summary': { status: 'success', data: { today_blocked: 1328 } },
  'cache/statistics': {
    status: 'success',
    data: { hit_rate: 0, byte_hit_rate: 0, cache_size: 'N/A', objects_cached: 0, hits: 0, misses: 0, requests: 0, simulated: true },
  },
  'clients/statistics': {
    status: 'success',
    data: [{ ip_address: '192.168.0.109', requests: 1172, blocked: 8, last_seen: '2026-10-25 09:00:00', status: 'Active' }],
    meta: { total: 3, limit: 1, offset: 0 },
    total: 3,
  },
}

/** The value line of the tile whose label is `label`. */
function tileValue(label: string): string {
  const labelEl = screen.getByText(label)
  return labelEl.parentElement?.lastElementChild?.textContent ?? ''
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

  // cache_stats.txt is never written (poll_once in proxy/blacklist_watchdog.py
  // collects no cache statistics), so the backend answers simulated: true with
  // zeros. The tile rendered those zeros as a measured "0.0%" hit rate.
  it('says the cache hit rate is not collected when the backend reports simulated', async () => {
    renderWithProviders(<ServiceStatus />)
    await waitFor(() => { expect(tileValue('Cache hit')).toBe('Not collected') })
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
