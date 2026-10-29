import { describe, it, expect, vi, beforeEach } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderWithProviders } from '../test/helpers'
import { GlobalSearch } from './GlobalSearch'
import { NAV_GROUPS } from './layout/nav'

vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn().mockResolvedValue({ data: { data: [] } }),
    post: vi.fn(),
    interceptors: { request: { use: vi.fn() }, response: { use: vi.fn() } },
  },
}))

describe('GlobalSearch', () => {
  beforeEach(async () => {
    vi.clearAllMocks()
    const { api } = await import('../lib/api')
    vi.mocked(api.get).mockResolvedValue({ data: { data: [] } })
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
      // The old menu name finds the page by its new one.
      expect(screen.getByText('Overview')).toBeInTheDocument()
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

  // It sent ?search=, which /api/logs never read: the five newest rows came
  // back as "matches" for anything typed. The access log searches
  // destinations with q, and a log result opens the log on that search.
  it('searches the access log by destination and opens it filtered', async () => {
    const { api } = await import('../lib/api')
    vi.mocked(api.get).mockImplementation((url: string) => Promise.resolve({
      data: { data: url.startsWith('logs?') ? [{ method: 'GET', destination: 'http://ads.example.com/', source_ip: '192.168.1.10', status: 'TCP_DENIED/403' }] : [] },
    }))
    const user = userEvent.setup()
    renderWithProviders(<GlobalSearch />)
    await user.keyboard('{Meta>}k{/Meta}')
    await user.type(await screen.findByPlaceholderText(/search/i), 'ads')
    const hit = await screen.findByText('GET http://ads.example.com/')
    const call = vi.mocked(api.get).mock.calls.map(([u]) => String(u)).find((u) => u.startsWith('logs?'))!
    expect(new URLSearchParams(call.split('?')[1]).get('q')).toBe('ads')
    await user.click(hit)
    expect(window.location.pathname + window.location.search).toBe('/logs?q=ads')
  })

  // Quick navigation had a list of its own: five pages, no Clients, Egress or
  // Audit log, Analytics drawn with a shield. It now follows the sidebar.
  it('offers every sidebar page in the sidebar order, in a dialog on document.body', async () => {
    const user = userEvent.setup()
    renderWithProviders(<GlobalSearch />)
    await user.keyboard('{Meta>}k{/Meta}')
    const dialog = await screen.findByRole('dialog', { name: 'Global search' })
    expect(dialog.parentElement).toBe(document.body)
    const labels = NAV_GROUPS.flatMap((g) => g.items).map((i) => i.label)
    const buttons = within(dialog).getAllByRole('button').filter((b) => /^\D.*\d+$/.test(b.textContent ?? ''))
    expect(buttons.map((b) => b.textContent)).toEqual(labels.map((l, i) => `${l}${i + 1}`))
    expect(labels).toEqual(expect.arrayContaining(['Clients', 'Egress allowlist', 'Audit log']))
  })

  it('asks each list for five entries with the parameter the backend reads', async () => {
    const { api } = await import('../lib/api')
    const user = userEvent.setup()
    renderWithProviders(<GlobalSearch />)
    await user.keyboard('{Meta>}k{/Meta}')
    await user.type(await screen.findByPlaceholderText(/search/i), 'goo')
    await waitFor(() => expect(vi.mocked(api.get).mock.calls.some(([u]) => String(u).startsWith('egress-allowlist?'))).toBe(true))
    for (const list of ['ip-blacklist', 'domain-blacklist', 'ip-whitelist', 'domain-whitelist', 'egress-allowlist']) {
      const call = String(vi.mocked(api.get).mock.calls.map(([u]) => u).filter((u) => String(u).startsWith(`${list}?`)).at(-1))
      const p = new URLSearchParams(call.split('?')[1])
      expect(p.get('limit'), list).toBe('5')
      expect(p.has('page_size'), list).toBe(false)
    }
  })

  it('opens the matching Blacklists tab or Egress allowlist with the searched term pre-filled in ?q=', async () => {
    const { api } = await import('../lib/api')
    vi.mocked(api.get).mockImplementation((url: string) => {
      const u = String(url)
      if (u.startsWith('ip-blacklist?')) return Promise.resolve({ data: { data: [{ ip: '203.0.113.9', description: 'Bad host' }] } })
      if (u.startsWith('domain-blacklist?')) return Promise.resolve({ data: { data: [{ domain: 'ads.example.org', description: 'Ad tracker' }] } })
      if (u.startsWith('domain-whitelist?')) return Promise.resolve({ data: { data: [{ domain: 'ok.example.org', description: 'Trusted' }] } })
      if (u.startsWith('egress-allowlist?')) return Promise.resolve({ data: { data: [{ entry: 'api.example.org', type: 'domain', description: 'Partner' }] } })
      return Promise.resolve({ data: { data: [] } })
    })
    const user = userEvent.setup()
    window.history.pushState({}, '', '/')
    renderWithProviders(<GlobalSearch />)

    await user.keyboard('{Meta>}k{/Meta}')
    await user.type(await screen.findByPlaceholderText(/search/i), 'example')
    await user.click(await screen.findByText('ads.example.org'))
    expect(window.location.pathname + window.location.search).toBe('/blacklists?tab=blocked-domains&q=example')

    await user.keyboard('{Meta>}k{/Meta}')
    await user.type(await screen.findByPlaceholderText(/search/i), '203.0')
    await user.click(await screen.findByText('203.0.113.9'))
    expect(window.location.pathname + window.location.search).toBe('/blacklists?tab=blocked-ips&q=203.0')

    await user.keyboard('{Meta>}k{/Meta}')
    await user.type(await screen.findByPlaceholderText(/search/i), 'ok.ex')
    await user.click(await screen.findByText('ok.example.org'))
    expect(window.location.pathname + window.location.search).toBe('/blacklists?tab=allowed-domains&q=ok.ex')

    await user.keyboard('{Meta>}k{/Meta}')
    await user.type(await screen.findByPlaceholderText(/search/i), 'api.ex')
    await user.click(await screen.findByText('api.example.org'))
    expect(window.location.pathname + window.location.search).toBe('/egress?q=api.ex')
  })

  it('exposes a keyboard combobox with aria-activedescendant, polite count announcements, and focus restoration on Escape', async () => {
    const user = userEvent.setup()
    renderWithProviders(
      <>
        <button type="button">Trigger before search</button>
        <GlobalSearch />
      </>,
    )
    const trigger = screen.getByRole('button', { name: 'Trigger before search' })
    trigger.focus()
    expect(document.activeElement).toBe(trigger)

    await user.keyboard('{Meta>}k{/Meta}')
    const combobox = await screen.findByRole('combobox', { name: /search ips, domains, requests, pages/i })
    expect(combobox).toHaveAttribute('aria-expanded', 'false')

    await user.type(combobox, 'al')
    await waitFor(() => expect(screen.getAllByRole('option').length).toBeGreaterThanOrEqual(2))
    const options = screen.getAllByRole('option')
    expect(combobox).toHaveAttribute('aria-expanded', 'true')
    const listboxId = combobox.getAttribute('aria-controls')
    expect(listboxId).toBeTruthy()
    expect(document.getElementById(listboxId!)).toHaveAttribute('role', 'listbox')

    expect(combobox).toHaveAttribute('aria-activedescendant', options[0].id)
    expect(options[0]).toHaveAttribute('aria-selected', 'true')

    await user.keyboard('{ArrowDown}')
    expect(combobox).toHaveAttribute('aria-activedescendant', options[1].id)
    expect(options[1]).toHaveAttribute('aria-selected', 'true')

    await user.keyboard('{ArrowUp}')
    expect(combobox).toHaveAttribute('aria-activedescendant', options[0].id)

    const polite = document.querySelector('[aria-live="polite"]')
    expect(polite).toHaveTextContent(`${options.length} results available`)

    await user.clear(combobox)
    await user.type(combobox, 'zzzznonexistent')
    await waitFor(() => expect(polite).toHaveTextContent('No results for "zzzznonexistent"'))

    await user.keyboard('{Escape}')
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(document.activeElement).toBe(trigger)
  })
})
