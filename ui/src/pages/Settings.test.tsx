import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { screen, waitFor, fireEvent, within } from '@testing-library/react'
import { Routes, Route, useLocation } from 'react-router'
import { renderWithProviders } from '../test/helpers'
import { expectNoAxeViolations } from '../test/axe'
import { DESKTOP_QUERY } from '../hooks/useMediaQuery'
import { Settings } from './Settings'

vi.mock('../lib/api', () => {
  const api = {
    get: vi.fn(),
    post: vi.fn(),
    interceptors: { request: { use: vi.fn() }, response: { use: vi.fn() } },
  }
  return {
    api,
    // The real unwrapping, over the mocked client.
    getData: (path: string) => api.get(path).then((r: { data?: { data?: unknown } }) => r?.data?.data ?? null),
    getErrorMessage: (_e: unknown, f: string) => f,
  }
})

import { api } from '../lib/api'

// Rows as GET /api/settings returns them (GetAll in
// backend-go/internal/handlers/settings.go): secrets carry no value.
const rows = [
  { setting_name: 'proxy_port', setting_value: '3128' },
  { setting_name: 'cache_size', setting_value: '1000' },
  { setting_name: 'memory_cache', setting_value: '256' },
  { setting_name: 'log_retention_days', setting_value: '30' },
  { setting_name: 'enable_notifications', setting_value: 'true' },
  { setting_name: 'gotify_token', setting_value: '', secret: true, is_set: true, decrypt_failed: true },
  { setting_name: 'telegram_bot_token', setting_value: '', secret: true, is_set: true },
  { setting_name: 'webhook_url', setting_value: '', secret: true },
  { setting_name: 'default_password_changed', setting_value: 'true' },
  { setting_name: 'wizard_completed', setting_value: 'true' },
]

function setViewport(desktop: boolean) {
  Object.defineProperty(window, 'matchMedia', {
    configurable: true,
    writable: true,
    value: (query: string) => ({
      matches: desktop && query === DESKTOP_QUERY,
      media: query,
      onchange: null,
      addEventListener: () => {},
      removeEventListener: () => {},
      addListener: () => {},
      removeListener: () => {},
      dispatchEvent: () => false,
    }),
  })
}

function Where() {
  return <p data-testid="where">{useLocation().pathname}</p>
}

function renderAt(path: string) {
  window.history.pushState({}, '', path)
  return renderWithProviders(
    <Routes>
      <Route path="/settings/:section" element={<><Settings /><Where /></>} />
    </Routes>,
  )
}

const sectionNav = () => screen.getByRole('navigation', { name: 'Settings sections' })

describe('Settings', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    setViewport(true)
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url === 'settings') return Promise.resolve({ data: { status: 'success', data: rows } })
      return Promise.resolve({ data: { status: 'success', data: null } })
    })
    vi.mocked(api.post).mockResolvedValue({ data: { status: 'success' } })
  })
  afterEach(() => { vi.restoreAllMocks() })

  describe('sections', () => {
    it('lists the eight sections in task order and marks the one in the URL', async () => {
      const { container } = renderAt('/settings/access')
      const links = within(sectionNav()).getAllByRole('link')
      expect(links.map((a) => [a.textContent, a.getAttribute('href')])).toEqual([
        ['Overview', '/settings/overview'],
        ['Clients and access', '/settings/access'],
        ['Filtering', '/settings/filtering'],
        ['Inspection', '/settings/inspection'],
        ['Alerts', '/settings/alerts'],
        ['Logs and privacy', '/settings/logs'],
        ['Admin and backup', '/settings/admin'],
        ['Proxy engine', '/settings/engine'],
      ])
      expect(within(sectionNav()).getByRole('link', { name: 'Clients and access' })).toHaveAttribute('aria-current', 'page')
      expect(within(sectionNav()).getByRole('link', { name: 'Overview' })).not.toHaveAttribute('aria-current')
      expect(screen.getByRole('heading', { level: 1, name: 'Settings' })).toBeInTheDocument()
      expect(screen.getByRole('heading', { level: 2, name: 'Clients and access' })).toBeInTheDocument()
      await expectNoAxeViolations(container)
    })

    it('opens a deep link on its section, with the values from the API', async () => {
      renderAt('/settings/engine')
      expect(screen.getByRole('heading', { level: 2, name: 'Proxy engine' })).toBeInTheDocument()
      await waitFor(() => expect(screen.getByLabelText('Cache Size (MB)')).toHaveValue(1000))
    })

    it('sends an unknown section to Overview', async () => {
      renderAt('/settings/nope')
      await waitFor(() => expect(screen.getByTestId('where')).toHaveTextContent('/settings/overview'))
      expect(screen.getByRole('heading', { level: 2, name: 'Overview' })).toBeInTheDocument()
    })

    it('keeps what was typed when moving to another section and back', async () => {
      renderAt('/settings/engine')
      const cache = await screen.findByLabelText('Cache Size (MB)')
      await waitFor(() => expect(cache).toHaveValue(1000))
      fireEvent.change(cache, { target: { value: '4000' } })
      fireEvent.click(within(sectionNav()).getByRole('link', { name: 'Logs and privacy' }))
      expect(screen.getByTestId('where')).toHaveTextContent('/settings/logs')
      expect(screen.getByLabelText('Log Retention (days)')).toHaveValue(30)
      fireEvent.click(within(sectionNav()).getByRole('link', { name: 'Proxy engine' }))
      expect(screen.getByLabelText('Cache Size (MB)')).toHaveValue(4000)
    })

    it('keeps the headings in order', async () => {
      renderAt('/settings/alerts')
      await screen.findByText('Cannot be read, re-enter it')
      const levels = screen.getAllByRole('heading').map((h) => Number(h.tagName.slice(1)))
      expect(levels[0]).toBe(1)
      for (let i = 1; i < levels.length; i++) expect(levels[i] - levels[i - 1]).toBeLessThanOrEqual(1)
    })
  })

  describe('below lg', () => {
    beforeEach(() => setViewport(false))

    it('collapses the sections into one switcher that names the current one', async () => {
      const { container } = renderAt('/settings/filtering')
      const toggle = within(sectionNav()).getByRole('button', { name: /Section: Filtering/ })
      expect(toggle).toHaveAttribute('aria-expanded', 'false')
      expect(within(sectionNav()).queryByRole('link')).not.toBeInTheDocument()
      fireEvent.click(toggle)
      expect(toggle).toHaveAttribute('aria-expanded', 'true')
      const list = document.getElementById(toggle.getAttribute('aria-controls')!)!
      expect(within(list).getByRole('link', { name: 'Filtering' })).toHaveAttribute('aria-current', 'page')
      await expectNoAxeViolations(container)
      fireEvent.click(within(list).getByRole('link', { name: 'Alerts' }))
      expect(screen.getByTestId('where')).toHaveTextContent('/settings/alerts')
      expect(within(sectionNav()).getByRole('button', { name: /Section: Alerts/ })).toHaveAttribute('aria-expanded', 'false')
    })
  })

  it('never sends back a secret the operator did not retype, and names one removed in clear', async () => {
    renderAt('/settings/alerts')
    expect(await screen.findByText('Cannot be read, re-enter it')).toBeInTheDocument()
    const save = () => fireEvent.click(screen.getByRole('button', { name: /Save Changes/ }))
    const lastSettingsPost = () => vi.mocked(api.post).mock.calls.filter(([url]) => url === 'settings').at(-1)!

    save()
    await waitFor(() => expect(vi.mocked(api.post).mock.calls.some(([url]) => url === 'settings')).toBe(true))
    let [, body, config] = lastSettingsPost()
    expect(body).toMatchObject({ log_retention_days: '30' })
    expect(body).not.toHaveProperty('gotify_token')
    expect(body).not.toHaveProperty('telegram_bot_token')
    expect(body).not.toHaveProperty('webhook_url')
    expect(config?.params).toBeUndefined()

    fireEvent.change(screen.getByLabelText('App token'), { target: { value: 'retyped' } })
    fireEvent.click(screen.getByRole('button', { name: 'Remove Bot token' }))
    vi.mocked(api.post).mockClear()
    save()
    await waitFor(() => expect(vi.mocked(api.post).mock.calls.some(([url]) => url === 'settings')).toBe(true));
    [, body, config] = lastSettingsPost()
    expect(body).toMatchObject({ gotify_token: 'retyped' })
    expect(body).not.toHaveProperty('telegram_bot_token')
    expect(config?.params).toEqual({ clear: 'telegram_bot_token' })
  })
})
