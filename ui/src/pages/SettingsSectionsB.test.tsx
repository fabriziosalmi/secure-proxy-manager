import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { screen, waitFor, fireEvent, within } from '@testing-library/react'
import { Routes, Route } from 'react-router'
import { AxiosError } from 'axios'
import { renderWithProviders } from '../test/helpers'
import { expectNoAxeViolations } from '../test/axe'
import { currentCacheStats } from '../test/cacheStats'
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
    getData: (path: string) => api.get(path).then((r: { data?: { data?: unknown } }) => r?.data?.data ?? null),
    getErrorMessage: (e: unknown, f: string) => (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail ?? f,
    setAuthToken: vi.fn(),
  }
})

import { api } from '../lib/api'

type Row = { setting_name: string; setting_value: string; secret?: boolean; is_set?: boolean; decrypt_failed?: boolean }

// What GET /api/settings returns on an install seeded by this version
// (seedDefaultSettings): the heuristics are stored, sequence validation off.
const rows: Row[] = [
  { setting_name: 'proxy_port', setting_value: '3128' },
  { setting_name: 'cache_size', setting_value: '1000' },
  { setting_name: 'memory_cache', setting_value: '256' },
  { setting_name: 'extra_ssl_ports', setting_value: '' },
  { setting_name: 'cache_bypass_domains', setting_value: '' },
  { setting_name: 'aggressive_caching_enabled', setting_value: 'false' },
  { setting_name: 'enable_offline_mode', setting_value: 'false' },
  { setting_name: 'ssl_bump_enabled', setting_value: 'false' },
  { setting_name: 'waf_h_entropy', setting_value: 'true' },
  { setting_name: 'waf_h_beaconing', setting_value: 'true' },
  { setting_name: 'waf_h_pii', setting_value: 'true' },
  { setting_name: 'waf_h_sharding', setting_value: 'true' },
  { setting_name: 'waf_h_ghosting', setting_value: 'true' },
  { setting_name: 'waf_h_sequence', setting_value: 'false' },
  { setting_name: 'enable_notifications', setting_value: 'false' },
  { setting_name: 'notify_group_window_minutes', setting_value: '10' },
  { setting_name: 'notify_max_per_hour', setting_value: '20' },
  { setting_name: 'notify_waf_block', setting_value: 'true' },
  { setting_name: 'notify_login_failure', setting_value: 'true' },
  { setting_name: 'notify_min_level', setting_value: 'info' },
  { setting_name: 'webhook_url', setting_value: '', secret: true, is_set: true },
  { setting_name: 'gotify_url', setting_value: '', secret: true },
  { setting_name: 'gotify_token', setting_value: '', secret: true },
  { setting_name: 'log_retention_days', setting_value: '30' },
  { setting_name: 'gdpr_mode', setting_value: 'false' },
  { setting_name: 'default_password_changed', setting_value: 'true' },
]

let heuristics: unknown = { available: true, running: { waf_h_entropy: true, waf_h_beaconing: true, waf_h_pii: true, waf_h_sharding: true, waf_h_ghosting: true, waf_h_sequence: true } }

function setViewport(desktop: boolean) {
  Object.defineProperty(window, 'matchMedia', {
    configurable: true,
    writable: true,
    value: (query: string) => ({
      matches: desktop && query === DESKTOP_QUERY, media: query, onchange: null,
      addEventListener: () => {}, removeEventListener: () => {}, addListener: () => {}, removeListener: () => {}, dispatchEvent: () => false,
    }),
  })
}

function renderAt(path: string) {
  window.history.pushState({}, '', path)
  return renderWithProviders(
    <Routes>
      <Route path="/settings/:section" element={<Settings />} />
    </Routes>,
  )
}

const settingsPosts = () => vi.mocked(api.post).mock.calls.filter(([url]) => url === 'settings')
const bar = () => screen.getByTestId('save-bar')
const save = () => fireEvent.click(within(bar()).getByRole('button', { name: 'Save section' }))
const headingsInOrder = () => {
  const levels = screen.getAllByRole('heading').map((h) => Number(h.tagName.slice(1)))
  expect(levels[0]).toBe(1)
  for (let i = 1; i < levels.length; i++) expect(levels[i] - levels[i - 1]).toBeLessThanOrEqual(1)
}
const badRequest = (data: unknown) => Promise.reject(new AxiosError('bad', 'ERR_BAD_REQUEST', undefined, undefined, { status: 400, data } as never))

describe('Settings sections, part B', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    setViewport(true)
    heuristics = { available: true, running: { waf_h_entropy: true, waf_h_beaconing: true, waf_h_pii: true, waf_h_sharding: true, waf_h_ghosting: true, waf_h_sequence: true } }
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url === 'settings') return Promise.resolve({ data: { status: 'success', data: rows } })
      if (url === 'waf/heuristics') return Promise.resolve({ data: { status: 'success', data: heuristics } })
      if (url === 'waf/categories') return Promise.resolve({ data: { status: 'ok', data: [{ name: 'SQL_INJECTION', rules: 40, enabled: true }, { name: 'CUSTOM_USER_RULES', rules: 2, enabled: true }] } })
      if (url === 'cache/statistics') return Promise.resolve({ data: { status: 'success', data: currentCacheStats } })
      return Promise.resolve({ data: { status: 'success', data: null } })
    })
    vi.mocked(api.post).mockImplementation((url: string) => {
      if (url === 'maintenance/reload-config') return Promise.resolve({ data: { status: 'success' } })
      return Promise.resolve({ data: { status: 'success', data: { kept: [] } } })
    })
  })
  afterEach(() => { vi.restoreAllMocks() })

  describe('Inspection', () => {
    it('shows the stored heuristics, what the WAF runs, and where they differ', async () => {
      const { container } = renderAt('/settings/inspection')
      const sequence = await screen.findByRole('switch', { name: 'Sequence validation' })
      // Stored off: shown off, not on as an absent key used to be.
      expect(sequence).toHaveAttribute('aria-checked', 'false')
      expect(await screen.findByText(/, not as saved here/)).toHaveTextContent('The WAF runs it on, not as saved here.')
      expect(screen.getByText('The WAF loaded 2 custom patterns.')).toBeInTheDocument()
      expect(document.getElementById('waf_h_sequence-label')!.parentElement!.querySelector('[data-apply]')).toHaveTextContent(/^WAF/)
      headingsInOrder()
      await expectNoAxeViolations(container)
    })

    it('says why the WAF could not be asked', async () => {
      heuristics = { available: false, reason: 'INTERNAL_ALERT_TOKEN is not set, and the WAF refuses management calls without it' }
      renderAt('/settings/inspection')
      expect(await screen.findByText('The running WAF could not be asked what it applies')).toBeInTheDocument()
      expect(screen.getByText(/INTERNAL_ALERT_TOKEN is not set/)).toBeInTheDocument()
    })

    it('reports that the WAF refused the toggle, with the reason the backend gave', async () => {
      vi.mocked(api.post).mockImplementation((url: string) => {
        if (url === 'settings') {
          return Promise.resolve({ data: { status: 'success', data: { kept: [], waf: { pushed: [], failed: [{ key: 'waf_h_sequence', reason: 'INTERNAL_ALERT_TOKEN is not set' }] } } } })
        }
        return Promise.resolve({ data: { status: 'success' } })
      })
      renderAt('/settings/inspection')
      fireEvent.click(await screen.findByRole('switch', { name: 'Sequence validation' }))
      save()
      const result = await screen.findByTestId('save-result')
      expect(result).toHaveTextContent('Saved, but the running WAF did not take Sequence validation: INTERNAL_ALERT_TOKEN is not set.')
      expect(result).toHaveTextContent('The backend sends the stored values again every 30 seconds until the WAF takes them.')
      expect(settingsPosts()[0][1]).toMatchObject({ waf_h_sequence: 'true', ssl_bump_enabled: 'false' })
    })

    it('says the WAF took the toggle when it did', async () => {
      vi.mocked(api.post).mockImplementation((url: string) => {
        if (url === 'settings') return Promise.resolve({ data: { status: 'success', data: { kept: [], waf: { pushed: ['waf_h_pii'], failed: [] } } } })
        return Promise.resolve({ data: { status: 'success' } })
      })
      renderAt('/settings/inspection')
      fireEvent.click(await screen.findByRole('switch', { name: 'Personal data in responses' }))
      save()
      expect(await screen.findByText('Applied to the running WAF (1 heuristic).')).toBeInTheDocument()
    })

    it('says the CA does not exist yet instead of blaming the switch', async () => {
      vi.mocked(api.get).mockImplementation((url: string) => {
        if (url === 'security/download-ca') return Promise.reject(new AxiosError('nf', 'ERR_BAD_REQUEST', undefined, undefined, { status: 404, data: {} } as never))
        if (url === 'settings') return Promise.resolve({ data: { status: 'success', data: rows } })
        return Promise.resolve({ data: { status: 'success', data: null } })
      })
      renderAt('/settings/inspection')
      fireEvent.click(await screen.findByRole('button', { name: 'Download the CA certificate (.pem)' }))
      expect(await screen.findByText(/has not created its certificate authority yet/)).toBeInTheDocument()
      expect(screen.queryByText(/Ensure HTTPS filtering is enabled/)).not.toBeInTheDocument()
      expect(screen.getByText('macOS')).toBeInTheDocument()
      expect(screen.getByText('Android')).toBeInTheDocument()
    })

    it('warns before inspection is turned on', async () => {
      renderAt('/settings/inspection')
      fireEvent.click(await screen.findByRole('switch', { name: 'Inspect HTTPS traffic' }))
      expect(screen.getByText("Every device must trust the proxy's CA before you save")).toBeInTheDocument()
    })
  })

  describe('Alerts', () => {
    it('keeps every channel setting write-only, with the bearer token among them', async () => {
      const { container } = renderAt('/settings/alerts')
      const token = await screen.findByLabelText('Bearer token')
      expect(token).toHaveAttribute('type', 'password')
      expect(token).toHaveValue('')
      expect(screen.getByLabelText('Webhook URL')).toHaveAttribute('type', 'password')
      expect(screen.getByText(/without one, anybody who learns the URL can post alerts/)).toBeInTheDocument()
      headingsInOrder()
      await expectNoAxeViolations(container)
    })

    it('shows the stored limits, the event switches and the minimum level, and says a crash loses the counts', async () => {
      const { container } = renderAt('/settings/alerts')
      const groupWindow = await screen.findByLabelText('Group window (minutes)')
      await waitFor(() => expect(groupWindow).toHaveValue('10'))
      expect(groupWindow).toHaveAccessibleDescription(/The first alert from an address is sent at once.*From 1 to 1440/)
      expect(screen.getByLabelText('Alerts per channel per hour')).toHaveValue('20')
      expect(screen.getByLabelText('Alerts per channel per hour')).toHaveAccessibleDescription(/summaries included.*From 1 to 1000/)
      expect(screen.getByRole('switch', { name: 'WAF blocks' })).toHaveAttribute('aria-checked', 'true')
      expect(screen.getByRole('switch', { name: 'Failed sign-ins' })).toHaveAttribute('aria-checked', 'true')
      const level = screen.getByRole('group', { name: 'Minimum level' })
      expect(within(level).getByRole('button', { name: 'All' })).toHaveAttribute('aria-pressed', 'true')
      expect(document.getElementById('notify_min_level-label')!.parentElement!.querySelector('[data-apply]')).toHaveTextContent(/^Live/)
      expect(screen.getByTestId('limits-memory')).toHaveTextContent(
        'The counts are kept in memory: a restart sends the pending summaries first, a crash loses them.',
      )
      expect(screen.getByText(/outside the limits\./)).toBeInTheDocument()
      headingsInOrder()
      await expectNoAxeViolations(container)
    })

    it('saves the limits with the section', async () => {
      renderAt('/settings/alerts')
      fireEvent.change(await screen.findByLabelText('Group window (minutes)'), { target: { value: '30' } })
      fireEvent.click(within(screen.getByRole('group', { name: 'Minimum level' })).getByRole('button', { name: 'Errors only' }))
      fireEvent.click(screen.getByRole('switch', { name: 'WAF blocks' }))
      save()
      await waitFor(() => expect(settingsPosts()).toHaveLength(1))
      expect(settingsPosts()[0][1]).toMatchObject({
        notify_group_window_minutes: '30', notify_max_per_hour: '20', notify_min_level: 'error',
        notify_waf_block: 'false', notify_login_failure: 'true',
      })
    })

    it('refuses limits out of range under their fields, before sending', async () => {
      renderAt('/settings/alerts')
      fireEvent.change(await screen.findByLabelText('Group window (minutes)'), { target: { value: '0' } })
      fireEvent.change(screen.getByLabelText('Alerts per channel per hour'), { target: { value: '1001' } })
      save()
      expect(screen.getByLabelText('Group window (minutes)')).toHaveAccessibleDescription(/Must be a whole number of minutes, from 1 to 1440/)
      expect(screen.getByLabelText('Alerts per channel per hour')).toHaveAccessibleDescription(/Must be a whole number of alerts, from 1 to 1000/)
      expect(settingsPosts()).toHaveLength(0)
      fireEvent.change(screen.getByLabelText('Group window (minutes)'), { target: { value: '1440' } })
      fireEvent.change(screen.getByLabelText('Alerts per channel per hour'), { target: { value: '1' } })
      save()
      await waitFor(() => expect(settingsPosts()).toHaveLength(1))
    })

    it('refuses a URL the backend would refuse, under its field, before sending', async () => {
      renderAt('/settings/alerts')
      fireEvent.change(await screen.findByLabelText('Gotify URL'), { target: { value: 'file:///etc/passwd' } })
      save()
      expect(screen.getByLabelText('Gotify URL')).toHaveAccessibleDescription(/Must be an http or https URL/)
      expect(settingsPosts()).toHaveLength(0)
    })

    it('puts every field the backend refused under its own field', async () => {
      vi.mocked(api.post).mockImplementation((url: string) => (url === 'settings'
        ? badRequest({ status: 'error', detail: 'gotify_url: must not point at this host', errors: { gotify_url: 'must not point at this host', webhook_url: 'must be an http or https URL' } })
        : Promise.resolve({ data: {} })))
      renderAt('/settings/alerts')
      fireEvent.change(await screen.findByLabelText('Gotify URL'), { target: { value: 'https://gotify.lan' } })
      fireEvent.change(screen.getByLabelText('Webhook URL'), { target: { value: 'https://hook.example/x' } })
      save()
      await waitFor(() => expect(screen.getByLabelText('Gotify URL')).toHaveAccessibleDescription(/Must not point at this host/))
      expect(screen.getByLabelText('Webhook URL')).toHaveAccessibleDescription(/Must be an http or https URL/)
      expect(within(bar()).getByRole('status')).toHaveTextContent('Not saved: 2 fields need attention')
    })

    it('tests the saved channels and shows what each one answered', async () => {
      vi.mocked(api.post).mockImplementation((url: string) => {
        if (url === 'notifications/test') {
          return Promise.resolve({ data: {
            status: 'success', message: 'Delivered to 1 of 2 configured channels', waf_alerts_delivered: false,
            warning: 'WAF block alerts are NOT being delivered: INTERNAL_ALERT_TOKEN is not set.',
            data: { notifications_enabled: false, channels: [
              { channel: 'webhook', delivered: true, status: 200 },
              { channel: 'gotify', delivered: false, status: 401, error: 'the server refused the credentials (HTTP 401)' },
            ] },
          } })
        }
        return Promise.resolve({ data: { status: 'success' } })
      })
      renderAt('/settings/alerts')
      const test = await screen.findByRole('button', { name: 'Send a test alert' })
      // Unsaved changes: the test would not use them.
      fireEvent.click(screen.getByRole('switch', { name: 'Send alerts' }))
      expect(test).toBeDisabled()
      fireEvent.click(within(bar()).getByRole('button', { name: 'Discard' }))
      expect(test).toBeEnabled()
      fireEvent.click(test)
      const results = await screen.findByRole('list', { name: 'Test results' })
      expect(results).toHaveTextContent('DeliveredWebhookHTTP 200')
      expect(results).toHaveTextContent('Not deliveredGotifythe server refused the credentials (HTTP 401)')
      expect(screen.getByText('Delivered to 1 of 2 configured channels')).toBeInTheDocument()
      expect(screen.getByText('Alerts are off')).toBeInTheDocument()
      expect(screen.getByText(/INTERNAL_ALERT_TOKEN is not set/)).toBeInTheDocument()
    })
  })

  describe('Logs and privacy', () => {
    it('says what retention deletes and what client IP masking covers and leaves out', async () => {
      const { container } = renderAt('/settings/logs')
      const days = await screen.findByLabelText('Keep logs for (days)')
      expect(days).toHaveAccessibleDescription(/every 24 hours, requests older than this are deleted.*The audit log is kept for 365 days/)
      expect(screen.getByRole('switch', { name: 'Mask client IPs' })).toHaveAccessibleDescription(/everywhere they leave the backend.*MCP.*alerts.*\/64.*\/api\/database\/export/)
      expect(screen.queryByText(/GDPR Mode/)).not.toBeInTheDocument()
      headingsInOrder()
      await expectNoAxeViolations(container)
    })
  })

  describe('Admin and backup', () => {
    it('lays out the password, backup and maintenance with their results in place, and notes unmasked addresses in database export', async () => {
      const { container } = renderAt('/settings/admin')
      expect(await screen.findByRole('button', { name: 'Change password' })).toBeDisabled()
      expect(screen.getByRole('button', { name: 'Download a backup' })).toBeInTheDocument()
      expect(screen.getByText(/holds the full, unmasked client addresses/)).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Empty disk and memory cache' })).toBeInTheDocument()
      headingsInOrder()
      await expectNoAxeViolations(container)
    })
  })

  describe('Proxy engine', () => {
    it('shows the port without a control, the cache statistics and why HTTPS is not cached', async () => {
      const { container } = renderAt('/settings/engine')
      await waitFor(() => expect(screen.getByTestId('proxy-port')).toHaveTextContent('3128'))
      expect(screen.queryByRole('textbox', { name: /^proxy port/i })).not.toBeInTheDocument()
      expect(document.getElementById('proxy_port')).toBeNull()
      expect(screen.getByText(/docker compose up -d/)).toBeInTheDocument()
      expect(await screen.findByText('Hit ratio 64.7% (last 3 min, since Squid started)')).toBeInTheDocument()
      expect(screen.getByText(/HTTPS inspection is off, and most sites are HTTPS, so a hit ratio near 0% is expected/)).toBeInTheDocument()
      expect(screen.getByLabelText('Extra HTTPS ports')).toHaveAccessibleDescription(/Applied when the proxy reloads/)
      expect(screen.queryByText(/Requires proxy restart/)).not.toBeInTheDocument()
      for (const gone of [/Allowed Networks/, /Tailscale/, /Dynamic DNS/]) expect(screen.queryByText(gone)).not.toBeInTheDocument()
      headingsInOrder()
      await expectNoAxeViolations(container)
    })

    it('warns before offline mode, and checks the bypass list before sending', async () => {
      renderAt('/settings/engine')
      fireEvent.click(await screen.findByRole('switch', { name: 'Offline mode' }))
      expect(screen.getByText("Clients may get outdated and other users' pages")).toBeInTheDocument()
      fireEvent.change(screen.getByLabelText('Never cache these domains'), { target: { value: 'bank.example.com, not a domain' } })
      save()
      expect(screen.getByLabelText('Never cache these domains')).toHaveAccessibleDescription(/"not a domain" is not a domain name/)
      expect(settingsPosts()).toHaveLength(0)
    })
  })

  describe('below lg', () => {
    beforeEach(() => setViewport(false))
    for (const section of ['inspection', 'alerts', 'logs', 'admin', 'engine']) {
      it(`/settings/${section} passes the accessibility gate on a phone`, async () => {
        const { container } = renderAt(`/settings/${section}`)
        await screen.findAllByRole('heading', { level: 3 })
        await expectNoAxeViolations(container)
      })
    }
  })
})
