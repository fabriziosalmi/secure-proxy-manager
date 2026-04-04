import { describe, it, expect, vi, beforeEach } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import { renderWithProviders } from '../test/helpers'
import { Logs } from './Logs'

vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(),
    delete: vi.fn(),
    interceptors: { request: { use: vi.fn() }, response: { use: vi.fn() } },
  },
  getErrorMessage: (_e: unknown, f: string) => f,
}))

import { api } from '../lib/api'

const mockLogs = {
  data: {
    data: [
      {
        id: 1,
        timestamp: '2026-04-04 12:00:00',
        client_ip: '192.168.1.10',
        method: 'CONNECT',
        destination: 'example.com:443',
        status: 'TCP_TUNNEL/200',
        bytes: 1234,
      },
      {
        id: 2,
        timestamp: '2026-04-04 12:01:00',
        client_ip: '192.168.1.10',
        method: 'GET',
        destination: 'malware.com',
        status: 'TCP_DENIED/403',
        bytes: 0,
      },
    ],
    total: 2,
  },
}

describe('Logs', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url.includes('logs')) return Promise.resolve(mockLogs)
      if (url.includes('ws-token')) return Promise.resolve({ data: { token: 'ws-tok' } })
      return Promise.resolve({ data: {} })
    })
  })

  it('renders logs page with title', async () => {
    renderWithProviders(<Logs />)
    expect(screen.getByText(/access logs/i)).toBeInTheDocument()
  })

  it('displays log entries from API', async () => {
    renderWithProviders(<Logs />)
    await waitFor(() => {
      expect(screen.getByText('example.com:443')).toBeInTheDocument()
      expect(screen.getByText('malware.com')).toBeInTheDocument()
    })
  })

  it('shows client IP in log entries', async () => {
    renderWithProviders(<Logs />)
    await waitFor(() => {
      const ips = screen.getAllByText('192.168.1.10')
      expect(ips.length).toBeGreaterThan(0)
    })
  })

  it('has search input', () => {
    renderWithProviders(<Logs />)
    const searchInputs = screen.getAllByRole('textbox')
    expect(searchInputs.length).toBeGreaterThan(0)
  })
})
