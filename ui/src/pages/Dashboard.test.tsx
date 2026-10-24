import { describe, it, expect, vi, beforeEach } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import { renderWithProviders } from '../test/helpers'
import { Dashboard } from './Dashboard'

vi.mock('../lib/api', () => {
  const get = vi.fn()
  return {
    api: {
      get,
      post: vi.fn(),
      interceptors: { request: { use: vi.fn() }, response: { use: vi.fn() } },
    },
    // getData wraps the (mocked) api.get and unwraps the { data } envelope, so
    // the same mockImplementation drives both api.get and getData call sites.
    getData: (path: string) =>
      get(path).then((r: { data?: { data?: unknown } }) => r?.data?.data ?? null),
    getErrorMessage: (_e: unknown, f: string) => f,
  }
})

vi.mock('../hooks/useAnimatedNumber', () => ({
  useAnimatedNumber: (v: number) => v,
}))

import { api } from '../lib/api'

const summaryData = {
  total_requests: 5000,
  blocked_requests: 200,
  today_requests: 350,
  today_blocked: 15,
  ip_blacklist_count: 1200,
  domain_blacklist_count: 45000,
  top_blocked: [{ dest: 'malware.com', count: 50 }],
  top_clients: [{ ip: '192.168.1.10', count: 100 }],
  threat_categories: [{ category: 'Malware', count: 30 }],
  recent_blocks: [],
  waf: null,
}

describe('Dashboard', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url.includes('dashboard/summary')) return Promise.resolve({ data: { data: summaryData } })
      if (url.includes('logs/timeline')) return Promise.resolve({ data: { data: [] } })
      if (url.includes('security/score')) return Promise.resolve({ data: { data: { score: 75, max_score: 100, recommendations: [] } } })
      if (url.includes('cache/statistics')) return Promise.resolve({ data: { data: { hit_rate: 0.85 } } })
      return Promise.resolve({ data: { data: null } })
    })
  })

  it('renders dashboard title', async () => {
    renderWithProviders(<Dashboard />)
    expect(screen.getByText(/dashboard/i)).toBeInTheDocument()
  })

  it('shows loading skeleton initially', () => {
    vi.mocked(api.get).mockImplementation(() => new Promise(() => {}))
    renderWithProviders(<Dashboard />)
    const skeletons = document.querySelectorAll('.skeleton-shimmer')
    expect(skeletons.length).toBeGreaterThan(0)
  })

  it('displays today requests count', async () => {
    renderWithProviders(<Dashboard />)
    await waitFor(() => {
      expect(screen.getByText('350')).toBeInTheDocument()
    })
  })

  // The WAF cards used to be hidden whenever waf was null, so a WAF that
  // refused every management call looked like a deployment without one.
  it('keeps the WAF card and says why its statistics are missing', async () => {
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url.includes('dashboard/summary')) return Promise.resolve({ data: { data: { ...summaryData, waf: null, waf_status: 'auth_failed' } } })
      return Promise.resolve({ data: { data: null } })
    })
    renderWithProviders(<Dashboard />)
    await waitFor(() => {
      expect(screen.getByText('WAF Intelligence')).toBeInTheDocument()
    })
    expect(screen.getByText(/refused the backend credential.*INTERNAL_ALERT_TOKEN/)).toBeInTheDocument()
  })

  it('reports an unreachable WAF as such', async () => {
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url.includes('dashboard/summary')) return Promise.resolve({ data: { data: { ...summaryData, waf: null, waf_status: 'unreachable' } } })
      return Promise.resolve({ data: { data: null } })
    })
    renderWithProviders(<Dashboard />)
    await waitFor(() => {
      expect(screen.getByText(/management API is not reachable/)).toBeInTheDocument()
    })
  })

  it('displays security score', async () => {
    renderWithProviders(<Dashboard />)
    await waitFor(() => {
      expect(screen.getByText('75')).toBeInTheDocument()
    })
  })
})
