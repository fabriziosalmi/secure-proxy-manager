import { describe, it, expect, vi, beforeEach } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderWithProviders } from '../test/helpers'
import { GlobalSearch } from './GlobalSearch'

vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn().mockResolvedValue({ data: { data: [] } }),
    post: vi.fn(),
    interceptors: { request: { use: vi.fn() }, response: { use: vi.fn() } },
  },
}))

describe('GlobalSearch', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('opens with Cmd+K', async () => {
    const user = userEvent.setup()
    renderWithProviders(<GlobalSearch />)

    // Modal should not be visible initially
    expect(screen.queryByPlaceholderText(/search/i)).not.toBeInTheDocument()

    // Press Cmd+K
    await user.keyboard('{Meta>}k{/Meta}')

    await waitFor(() => {
      expect(screen.getByPlaceholderText(/search/i)).toBeInTheDocument()
    })
  })

  it('closes with Escape', async () => {
    const user = userEvent.setup()
    renderWithProviders(<GlobalSearch />)

    await user.keyboard('{Meta>}k{/Meta}')
    await waitFor(() => expect(screen.getByPlaceholderText(/search/i)).toBeInTheDocument())

    await user.keyboard('{Escape}')
    await waitFor(() => {
      expect(screen.queryByPlaceholderText(/search/i)).not.toBeInTheDocument()
    })
  })

  it('shows page results when typing', async () => {
    const user = userEvent.setup()
    renderWithProviders(<GlobalSearch />)

    await user.keyboard('{Meta>}k{/Meta}')
    await waitFor(() => expect(screen.getByPlaceholderText(/search/i)).toBeInTheDocument())

    await user.type(screen.getByPlaceholderText(/search/i), 'dash')

    await waitFor(() => {
      expect(screen.getByText('Dashboard')).toBeInTheDocument()
    })
  })

  it('finds a Settings section by what it holds and opens its URL', async () => {
    const user = userEvent.setup()
    window.history.pushState({}, '', '/')
    renderWithProviders(<GlobalSearch />)

    await user.keyboard('{Meta>}k{/Meta}')
    await waitFor(() => expect(screen.getByPlaceholderText(/search/i)).toBeInTheDocument())
    await user.type(screen.getByPlaceholderText(/search/i), 'telegram')

    const hit = await screen.findByText('Settings: Alerts')
    await user.click(hit)
    expect(window.location.pathname).toBe('/settings/alerts')
  })
})
