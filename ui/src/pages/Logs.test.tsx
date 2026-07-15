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

// Capture WebSocket constructor calls so we can assert on the protocols argument.
const mockWebSocketInstances: Array<{ url: string; protocols?: string | string[] }> = []

vi.stubGlobal('WebSocket', class MockWebSocket {
  url: string
  protocols?: string | string[]
  onopen: (() => void) | null = null
  onmessage: ((e: MessageEvent) => void) | null = null
  onclose: (() => void) | null = null
  onerror: (() => void) | null = null
  readyState = 0 // CONNECTING

  constructor(url: string, protocols?: string | string[]) {
    this.url = url
    this.protocols = protocols
    mockWebSocketInstances.push({ url, protocols })
  }

  close() {}
})

describe('Logs', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockWebSocketInstances.length = 0
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

  it('passes token via Sec-WebSocket-Protocol subprotocol, not query string', async () => {
    renderWithProviders(<Logs />)

    // Wait for the ws-token API call and WebSocket construction.
    await waitFor(() => {
      expect(mockWebSocketInstances.length).toBeGreaterThan(0)
    })

    const instance = mockWebSocketInstances[0]

    // Token MUST appear in the protocols array as "spm-ws-token.<token>".
    const protocols = Array.isArray(instance.protocols)
      ? instance.protocols
      : [instance.protocols ?? '']
    const hasSubprotocol = protocols.some((p) => p === 'spm-ws-token.ws-tok')
    expect(hasSubprotocol).toBe(true)

    // Token MUST NOT appear in the URL query string.
    expect(instance.url).not.toContain('token=')
    expect(instance.url).not.toContain('ws-tok')
  })
})

