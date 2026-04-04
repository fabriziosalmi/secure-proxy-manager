import { describe, it, expect, vi, beforeEach } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import { renderWithProviders } from '../test/helpers'
import { Dashboard } from './Dashboard'

vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(),
    interceptors: { request: { use: vi.fn() }, response: { use: vi.fn() } },
  },
  getErrorMessage: (_e: unknown, f: string) => f,
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
    const skeletons = document.querySelectorAll('.animate-pulse')
    expect(skeletons.length).toBeGreaterThan(0)
  })

  it('displays today requests count', async () => {
    renderWithProviders(<Dashboard />)
    await waitFor(() => {
      expect(screen.getByText('350')).toBeInTheDocument()
    })
  })

  it('displays security score', async () => {
    renderWithProviders(<Dashboard />)
    await waitFor(() => {
      expect(screen.getByText('75')).toBeInTheDocument()
    })
  })
})
