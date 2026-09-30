import { describe, it, expect, vi, beforeEach } from 'vitest'
import { screen, waitFor, fireEvent } from '@testing-library/react'
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
  // #219 M8 + M10b. Both were real: a second click fired a second POST and
  // imported twice, and the inline country parser filtered on length alone, so
  // "12" reached the API as a country code.
  describe('geo import guards', () => {
    const openGeoPanel = async (user: ReturnType<typeof userEvent.setup>) => {
      await waitFor(() => expect(screen.getByText('10.0.0.1')).toBeInTheDocument())
      await user.click(screen.getByRole('button', { name: /geo-block/i }))
      return screen.getByPlaceholderText(/e\.g\. CN, RU, KP/i)
    }

    it('rejects a country code that is two characters but not two letters', async () => {
      const user = userEvent.setup()
      renderWithProviders(<Blacklists />)
      const input = await openGeoPanel(user)
      await user.type(input, '12')
      await user.click(screen.getByRole('button', { name: /download & block ips/i }))
      // parseGeoCountries drops it, so the handler returns before any request.
      expect(api.post).not.toHaveBeenCalledWith('blacklists/import-geo', expect.anything())
    })

    it('does not submit twice when the button is clicked twice', async () => {
      const user = userEvent.setup()
      let resolve!: (v: unknown) => void
      vi.mocked(api.post).mockReturnValueOnce(new Promise(r => { resolve = r }) as never)
      renderWithProviders(<Blacklists />)
      const input = await openGeoPanel(user)
      await user.type(input, 'CN')
      const btn = screen.getByRole('button', { name: /download & block ips/i })
      await user.click(btn)
      await waitFor(() => expect(btn).toBeDisabled())
      await user.click(btn)
      const geoCalls = vi.mocked(api.post).mock.calls.filter(c => c[0] === 'blacklists/import-geo')
      expect(geoCalls).toHaveLength(1)
      resolve({ data: { data: { imported: 1 } } })
    })

    // The test above passes on the disabled attribute alone, so it would still
    // pass with the handler's own guard removed. This one submits the form
    // directly, which is the path a disabled button cannot cover — and the one
    // that matters if the attribute is ever dropped from the markup.
    it('the handler itself refuses a second submit while one is in flight', async () => {
      const user = userEvent.setup()
      let resolve!: (v: unknown) => void
      vi.mocked(api.post).mockReturnValueOnce(new Promise(r => { resolve = r }) as never)
      renderWithProviders(<Blacklists />)
      const input = await openGeoPanel(user)
      await user.type(input, 'CN')
      const form = input.closest('form')!
      fireEvent.submit(form)
      fireEvent.submit(form)
      const geoCalls = vi.mocked(api.post).mock.calls.filter(c => c[0] === 'blacklists/import-geo')
      expect(geoCalls).toHaveLength(1)
      resolve({ data: { data: { imported: 1 } } })
    })
  })

})
