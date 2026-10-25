import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { screen, waitFor, fireEvent, within } from '@testing-library/react'
import { Routes, Route, Link, useLocation } from 'react-router'
import { AxiosError } from 'axios'
import { renderWithProviders } from '../test/helpers'
import { expectNoAxeViolations } from '../test/axe'
import { DESKTOP_QUERY } from '../hooks/useMediaQuery'
import { Settings } from './Settings'
import { SettingsDraftsProvider } from '../components/settings/SettingsDrafts'

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

let current = rows

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
    current = rows
    setViewport(true)
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url === 'settings') return Promise.resolve({ data: { status: 'success', data: current } })
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
      await waitFor(() => expect(screen.getByLabelText('Disk cache (MB)')).toHaveValue('1000'))
    })

    it('sends an unknown section to Overview', async () => {
      renderAt('/settings/nope')
      await waitFor(() => expect(screen.getByTestId('where')).toHaveTextContent('/settings/overview'))
      expect(screen.getByRole('heading', { level: 2, name: 'Overview' })).toBeInTheDocument()
    })

    it('keeps what was typed when moving to another section and back', async () => {
      renderAt('/settings/engine')
      const cache = await screen.findByLabelText('Disk cache (MB)')
      await waitFor(() => expect(cache).toHaveValue('1000'))
      fireEvent.change(cache, { target: { value: '4000' } })
      fireEvent.click(within(sectionNav()).getByRole('link', { name: 'Logs and privacy' }))
      expect(screen.getByTestId('where')).toHaveTextContent('/settings/logs')
      expect(screen.getByLabelText('Keep logs for (days)')).toHaveValue('30')
      fireEvent.click(within(sectionNav()).getByRole('link', { name: /^Proxy engine/ }))
      expect(screen.getByLabelText('Disk cache (MB)')).toHaveValue('4000')
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

  describe('save model', () => {
    const settingsPosts = () => vi.mocked(api.post).mock.calls.filter(([url]) => url === 'settings')
    const reloads = () => vi.mocked(api.post).mock.calls.filter(([url]) => url === 'maintenance/reload-config')
    const bar = () => screen.getByTestId('save-bar')

    // A backend that stores what it accepts, so the refetch after a save
    // reads the saved values back.
    function answerPosts(reload: () => Promise<unknown>, save: () => Promise<unknown> = () => Promise.resolve({ data: { status: 'success', message: 'Settings updated', data: { kept: [] } } })) {
      vi.mocked(api.post).mockImplementation((url: string, body?: unknown) => {
        if (url === 'settings') {
          return save().then((res) => {
            current = current.map((r) => {
              const v = (body as Record<string, string>)[r.setting_name]
              return v === undefined || 'secret' in r ? r : { ...r, setting_value: v }
            })
            return res
          })
        }
        if (url === 'maintenance/reload-config') return reload()
        return Promise.resolve({ data: { status: 'success' } })
      })
    }

    async function editCache(value: string) {
      renderAt('/settings/engine')
      const cache = await screen.findByLabelText('Disk cache (MB)')
      await waitFor(() => expect(cache).toHaveValue('1000'))
      fireEvent.change(cache, { target: { value } })
      return cache
    }

    it('shows nothing to save until a field changes, then a dot in the nav and the count', async () => {
      await editCache('2000')
      expect(within(bar()).getByRole('status')).toHaveTextContent('1 unsaved change')
      expect(screen.getByTestId('dirty-engine')).toBeInTheDocument()
      expect(within(sectionNav()).getByRole('link', { name: /Proxy engine, 1 unsaved change/ })).toBeInTheDocument()
      fireEvent.change(screen.getByLabelText('Memory cache (MB)'), { target: { value: '512' } })
      expect(within(bar()).getByRole('status')).toHaveTextContent('2 unsaved changes')
      // Typing the stored value back is no change.
      fireEvent.change(screen.getByLabelText('Memory cache (MB)'), { target: { value: '256' } })
      expect(within(bar()).getByRole('status')).toHaveTextContent('1 unsaved change')
    })

    it('Discard puts the stored values back and removes the bar', async () => {
      const cache = await editCache('2000')
      fireEvent.click(within(bar()).getByRole('button', { name: 'Discard' }))
      expect(cache).toHaveValue('1000')
      expect(screen.queryByTestId('save-bar')).not.toBeInTheDocument()
      expect(screen.queryByTestId('dirty-engine')).not.toBeInTheDocument()
    })

    it('sends every key of the section that has a value and nothing else, then says the proxy applied it', async () => {
      answerPosts(() => Promise.resolve({ data: { status: 'success', message: 'Proxy reloaded' } }))
      await editCache('2000')
      fireEvent.click(within(bar()).getByRole('button', { name: 'Save section' }))
      expect(await screen.findByText(/^Applied to the proxy at \d\d:\d\d\.$/)).toBeInTheDocument()
      expect(settingsPosts()).toHaveLength(1)
      const [, body, config] = settingsPosts()[0]
      // proxy_port is shown, not sent: this page does not change it.
      expect(body).toEqual({ cache_size: '2000', memory_cache: '256' })
      expect(config?.params).toBeUndefined()
      expect(reloads()).toHaveLength(1)
      expect(screen.queryByTestId('save-bar')).not.toBeInTheDocument()
      expect(screen.getByLabelText('Disk cache (MB)')).toHaveValue('2000')
    })

    it('says so when the proxy did not confirm, and Apply again asks it again', async () => {
      answerPosts(() => Promise.resolve({ data: { status: 'pending', message: 'reload requested, but the proxy did not acknowledge it in time' } }))
      await editCache('2000')
      fireEvent.click(within(bar()).getByRole('button', { name: 'Save section' }))
      expect(await screen.findByText('Saved. The proxy did not confirm within 8 seconds: check that the proxy container is running.')).toBeInTheDocument()
      expect(screen.queryByText(/Applied to the proxy/)).not.toBeInTheDocument()
      answerPosts(() => Promise.resolve({ data: { status: 'success' } }))
      fireEvent.click(screen.getByRole('button', { name: 'Apply again' }))
      expect(await screen.findByText(/^Applied to the proxy at \d\d:\d\d\.$/)).toBeInTheDocument()
      expect(reloads()).toHaveLength(2)
    })

    it('says so when the proxy refused the new configuration and kept the previous one', async () => {
      answerPosts(() => Promise.reject(new AxiosError('refused', 'ERR_BAD_RESPONSE', undefined, undefined, {
        status: 500,
        data: { status: 'error', code: 'reload_failed', detail: 'the proxy refused the new configuration and kept the previous one', data: { generator_rc: 1, reconfigure_rc: null } },
      } as never)))
      await editCache('2000')
      fireEvent.click(within(bar()).getByRole('button', { name: 'Save section' }))
      expect(await screen.findByText('Saved, but the proxy refused the new configuration and kept the previous one (generator exit code 1).')).toBeInTheDocument()
    })

    it('names the files the backend could not write', async () => {
      answerPosts(
        () => Promise.resolve({ data: { status: 'success' } }),
        () => Promise.resolve({ data: { status: 'partial', message: 'settings saved, but some proxy configuration files could not be written', data: { failed: ['squid_settings.env'], kept: [] } } }),
      )
      await editCache('2000')
      fireEvent.click(within(bar()).getByRole('button', { name: 'Save section' }))
      expect(await screen.findByText('These proxy configuration files could not be written, so the proxy still uses the previous ones: squid_settings.env.')).toBeInTheDocument()
    })

    it('puts the field the backend refused in front of the operator and keeps the draft', async () => {
      answerPosts(
        () => Promise.resolve({ data: { status: 'success' } }),
        () => Promise.reject(new AxiosError('bad', 'ERR_BAD_REQUEST', undefined, undefined, {
          status: 400,
          data: { status: 'error', detail: 'cache_size: must be a non-negative number' },
        } as never)),
      )
      await editCache('2000')
      fireEvent.click(within(bar()).getByRole('button', { name: 'Save section' }))
      expect(await within(bar()).findByText('Not saved: Disk cache (MB) needs attention')).toBeInTheDocument()
      expect(screen.getByLabelText('Disk cache (MB)')).toHaveAccessibleDescription(/Must be a non-negative number/)
      expect(screen.getByLabelText('Disk cache (MB)')).toHaveValue('2000')
      expect(reloads()).toHaveLength(0)
    })

    it('checks the generator limits before sending', async () => {
      await editCache('12345678')
      fireEvent.click(within(bar()).getByRole('button', { name: 'Save section' }))
      expect(await screen.findByText('Must be a whole number of megabytes, from 1 to 9999999')).toBeInTheDocument()
      expect(screen.getByLabelText('Disk cache (MB)')).toHaveAttribute('aria-invalid', 'true')
      expect(settingsPosts()).toHaveLength(0)
    })

    it('never sends back a secret the operator did not retype, and names one removed in clear', async () => {
      renderAt('/settings/alerts')
      expect(await screen.findByText('Cannot be read, re-enter it')).toBeInTheDocument()
      expect(screen.queryByTestId('save-bar')).not.toBeInTheDocument()
      fireEvent.change(screen.getByLabelText('App token'), { target: { value: 'retyped' } })
      fireEvent.click(screen.getByRole('button', { name: 'Remove Bot token' }))
      expect(within(bar()).getByRole('status')).toHaveTextContent('2 unsaved changes')
      fireEvent.click(within(bar()).getByRole('button', { name: 'Save section' }))
      expect(await screen.findByText(/^Saved at \d\d:\d\d\.$/)).toBeInTheDocument()
      expect(screen.getByText('Read on every use: in effect as soon as it is saved.')).toBeInTheDocument()
      const [, body, config] = settingsPosts()[0]
      // The section's keys only: no internal key, nothing from another section,
      // no secret nobody retyped.
      expect(body).toEqual({ enable_notifications: 'true', gotify_token: 'retyped' })
      expect(config?.params).toEqual({ clear: 'telegram_bot_token' })
      // Nothing here needs the proxy.
      expect(reloads()).toHaveLength(0)
    })

    it('keeps a draft while the operator visits another page', async () => {
      window.history.pushState({}, '', '/settings/engine')
      renderWithProviders(
        <SettingsDraftsProvider>
          <Routes>
            <Route path="/settings/:section" element={<Settings />} />
            <Route path="/logs" element={<Link to="/settings/engine">Back to settings</Link>} />
          </Routes>
          <Link to="/logs">Go to logs</Link>
        </SettingsDraftsProvider>,
      )
      const cache = await screen.findByLabelText('Disk cache (MB)')
      await waitFor(() => expect(cache).toHaveValue('1000'))
      fireEvent.change(cache, { target: { value: '2000' } })
      fireEvent.click(screen.getByRole('link', { name: 'Go to logs' }))
      expect(screen.queryByLabelText('Disk cache (MB)')).not.toBeInTheDocument()
      // Closing the tab now asks first.
      const leave = new Event('beforeunload', { cancelable: true })
      window.dispatchEvent(leave)
      expect(leave.defaultPrevented).toBe(true)
      fireEvent.click(screen.getByRole('link', { name: 'Back to settings' }))
      expect(await screen.findByLabelText('Disk cache (MB)')).toHaveValue('2000')
      expect(within(bar()).getByRole('status')).toHaveTextContent('1 unsaved change')
    })

    it('lets the tab close without asking when nothing is unsaved', async () => {
      renderAt('/settings/engine')
      await screen.findByLabelText('Disk cache (MB)')
      const leave = new Event('beforeunload', { cancelable: true })
      window.dispatchEvent(leave)
      expect(leave.defaultPrevented).toBe(false)
    })
  })
})
