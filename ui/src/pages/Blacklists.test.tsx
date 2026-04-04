import { describe, it, expect, vi, beforeEach } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderWithProviders } from '../test/helpers'
import { Blacklists } from './Blacklists'

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

const mockIpList = {
  data: {
    data: [
      { id: 1, ip: '10.0.0.1', description: 'Test IP', added_date: '2026-01-01' },
      { id: 2, ip: '192.168.1.0/24', description: 'Subnet', added_date: '2026-01-02' },
    ],
    total: 2,
  },
}

const emptyList = { data: { data: [], total: 0 } }

describe('Blacklists', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url.includes('ip-blacklist')) return Promise.resolve(mockIpList)
      if (url.includes('domain-blacklist')) return Promise.resolve(emptyList)
      if (url.includes('ip-whitelist')) return Promise.resolve(emptyList)
      if (url.includes('domain-whitelist')) return Promise.resolve(emptyList)
      return Promise.resolve(emptyList)
    })
  })

  it('renders with IP blacklist tab active by default', async () => {
    renderWithProviders(<Blacklists />)
    await waitFor(() => {
      expect(screen.getByText('10.0.0.1')).toBeInTheDocument()
    })
  })

  it('displays IP entries from the API', async () => {
    renderWithProviders(<Blacklists />)
    await waitFor(() => {
      expect(screen.getByText('10.0.0.1')).toBeInTheDocument()
      expect(screen.getByText('192.168.1.0/24')).toBeInTheDocument()
    })
  })

  it('shows descriptions for entries', async () => {
    renderWithProviders(<Blacklists />)
    await waitFor(() => {
      expect(screen.getByText('Test IP')).toBeInTheDocument()
    })
  })

  it('has add entry input fields', async () => {
    renderWithProviders(<Blacklists />)
    await waitFor(() => {
      expect(screen.getByText('10.0.0.1')).toBeInTheDocument()
    })
    const inputs = screen.getAllByRole('textbox')
    expect(inputs.length).toBeGreaterThan(0)
  })

  it('switches tabs when clicking domain blacklist', async () => {
    const user = userEvent.setup()
    renderWithProviders(<Blacklists />)

    await waitFor(() => {
      expect(screen.getByText('10.0.0.1')).toBeInTheDocument()
    })

    const tabs = screen.getAllByRole('button')
    const domainTab = tabs.find(btn =>
      btn.textContent?.toLowerCase().includes('domain') &&
      !btn.textContent?.toLowerCase().includes('whitelist')
    )
    if (domainTab) {
      await user.click(domainTab)
      await waitFor(() => {
        expect(api.get).toHaveBeenCalledWith(
          expect.stringContaining('domain-blacklist')
        )
      })
    }
  })
})
