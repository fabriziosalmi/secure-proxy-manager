import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { screen, waitFor, fireEvent, within } from '@testing-library/react'
import { Routes, Route } from 'react-router'
import { AxiosError } from 'axios'
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
    getData: (path: string) => api.get(path).then((r: { data?: { data?: unknown } }) => r?.data?.data ?? null),
    getErrorMessage: (e: unknown, f: string) => (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail ?? f,
  }
})

import { api } from '../lib/api'

type Row = { setting_name: string; setting_value: string; secret?: boolean; is_set?: boolean; decrypt_failed?: boolean }

// A fresh install as GET /api/settings returns it (seedDefaultSettings),
// with the access and filtering keys a running install has.
const base: Row[] = [
  { setting_name: 'proxy_port', setting_value: '3128' },
  { setting_name: 'ssl_bump_enabled', setting_value: 'false' },
  { setting_name: 'egress_default_deny', setting_value: 'false' },
  { setting_name: 'enable_content_filtering', setting_value: 'false' },
  { setting_name: 'enable_notifications', setting_value: 'false' },
  { setting_name: 'auto_refresh_enabled', setting_value: 'false' },
  { setting_name: 'auto_refresh_hours', setting_value: '24' },
  { setting_name: 'default_password_changed', setting_value: 'false' },
  { setting_name: 'enable_bandwidth_limits', setting_value: 'false' },
  { setting_name: 'bandwidth_limit_mbps', setting_value: '100' },
  { setting_name: 'webhook_url', setting_value: '', secret: true },
  { setting_name: 'wizard_completed', setting_value: 'true' },
]

let rows: Row[] = base
let egressTotal = 0
let proxyStatus = 'running'

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

function renderAt(path: string) {
  window.history.pushState({}, '', path)
  return renderWithProviders(
    <Routes>
      <Route path="/settings/:section" element={<Settings />} />
    </Routes>,
  )
}

const settingsPosts = () => vi.mocked(api.post).mock.calls.filter(([url]) => url === 'settings')
const reloads = () => vi.mocked(api.post).mock.calls.filter(([url]) => url === 'maintenance/reload-config')
const bar = () => screen.getByTestId('save-bar')
const save = () => fireEvent.click(within(bar()).getByRole('button', { name: 'Save section' }))
const headingsInOrder = () => {
  const levels = screen.getAllByRole('heading').map((h) => Number(h.tagName.slice(1)))
  expect(levels[0]).toBe(1)
  for (let i = 1; i < levels.length; i++) expect(levels[i] - levels[i - 1]).toBeLessThanOrEqual(1)
}

describe('Settings sections', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    rows = base
    egressTotal = 0
    proxyStatus = 'running'
    setViewport(true)
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url === 'settings') return Promise.resolve({ data: { status: 'success', data: rows } })
      if (url === 'status') return Promise.resolve({ data: { status: 'success', data: { proxy_status: proxyStatus } } })
      if (url === 'egress-allowlist') return Promise.resolve({ data: { status: 'success', data: [], meta: { total: egressTotal, limit: 1, offset: 0 }, total: egressTotal } })
      return Promise.resolve({ data: { status: 'success', data: null } })
    })
    vi.mocked(api.post).mockImplementation((url: string) => {
      if (url === 'maintenance/reload-config') return Promise.resolve({ data: { status: 'success', message: 'Proxy reloaded' } })
      return Promise.resolve({ data: { status: 'success', data: { kept: [] } } })
    })
  })
  afterEach(() => { vi.restoreAllMocks() })

  describe('Clients and access', () => {
    it('says who may connect without offering a control that does nothing', async () => {
      const { container } = renderAt('/settings/access')
      const who = screen.getByRole('region', { name: 'Who may connect' })
      expect(who).toHaveTextContent('Devices on private networks can use the proxy: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7, fe80::/10.')
      expect(who).toHaveTextContent('This page cannot read .env, so it does not show which ones are set.')
      expect(within(who).queryByRole('textbox')).not.toBeInTheDocument()
      expect(screen.queryByLabelText(/Allowed Networks/)).not.toBeInTheDocument()
      expect(screen.queryByLabelText(/Auth Method/)).not.toBeInTheDocument()
      await screen.findByRole('switch', { name: 'Limit bandwidth' })
      headingsInOrder()
      await expectNoAxeViolations(container)
    })

    it('says the login is the .env credential, and warns before every device must sign in', async () => {
      renderAt('/settings/access')
      const auth = await screen.findByRole('switch', { name: 'Require proxy login' })
      expect(auth).toHaveAccessibleDescription(/BASIC_AUTH_USERNAME and BASIC_AUTH_PASSWORD from \.env .* not your dashboard password/)
      expect(document.getElementById('enable_proxy_auth-label')!.parentElement!.querySelector('[data-apply]')).toHaveTextContent(/^Proxy reload/)
      fireEvent.click(auth)
      expect(screen.getByText('Every device must sign in after you save')).toBeInTheDocument()
    })

    it('shows the stored values, says which are missing, and checks the window before sending', async () => {
      renderAt('/settings/access')
      fireEvent.click(await screen.findByRole('switch', { name: 'Limit bandwidth' }))
      expect(screen.getByLabelText('Whole network (Mbps)')).toHaveValue('100')
      expect(screen.getByLabelText('Each client (kbps)')).toHaveValue('')
      expect(screen.getByLabelText('Each client (kbps)')).toHaveAccessibleDescription(/No value is stored for this yet\./)

      fireEvent.click(screen.getByRole('switch', { name: 'Limit to a time window' }))
      fireEvent.change(screen.getByLabelText('From'), { target: { value: '18:00' } })
      fireEvent.change(screen.getByLabelText('Until'), { target: { value: '08:00' } })
      fireEvent.change(screen.getByLabelText('Each client (kbps)'), { target: { value: '500' } })
      save()
      const until = screen.getByLabelText('Until')
      expect(until).toHaveAttribute('aria-invalid', 'true')
      expect(until).toHaveAccessibleDescription(/Must be later than the start time/)
      expect(within(bar()).getByRole('status')).toHaveTextContent('Not saved: Until needs attention')
      expect(settingsPosts()).toHaveLength(0)

      fireEvent.change(until, { target: { value: '19:00' } })
      expect(until).not.toHaveAttribute('aria-invalid')
      save()
      expect(await screen.findByText(/^Applied to the proxy at \d\d:\d\d\.$/)).toBeInTheDocument()
      expect(settingsPosts()[0][1]).toEqual({
        enable_time_restrictions: 'true',
        time_restriction_start: '18:00',
        time_restriction_end: '19:00',
        enable_bandwidth_limits: 'true',
        bandwidth_limit_mbps: '100',
        bandwidth_limit_per_user_kbps: '500',
      })
      expect(reloads()).toHaveLength(1)
    })

    it('puts the backend refusal under the field it names', async () => {
      vi.mocked(api.post).mockImplementation((url: string) => {
        if (url === 'settings') {
          return Promise.reject(new AxiosError('bad', 'ERR_BAD_REQUEST', undefined, undefined, {
            status: 400, data: { status: 'error', detail: 'bandwidth_limit_mbps: must be a positive number' },
          } as never))
        }
        return Promise.resolve({ data: { status: 'success' } })
      })
      renderAt('/settings/access')
      fireEvent.click(await screen.findByRole('switch', { name: 'Limit bandwidth' }))
      fireEvent.change(screen.getByLabelText('Each client (kbps)'), { target: { value: '0' } })
      save()
      const total = screen.getByLabelText('Whole network (Mbps)')
      await waitFor(() => expect(total).toHaveAttribute('aria-invalid', 'true'))
      expect(total).toHaveAccessibleDescription('Must be a positive number')
      await waitFor(() => expect(document.activeElement).toBe(total))
      expect(screen.queryByRole('list', { name: 'Fields that need attention' })).not.toBeInTheDocument()
    })
  })

  describe('Filtering', () => {
    it('refuses to turn on default-deny over an empty allowlist', async () => {
      const { container } = renderAt('/settings/filtering')
      expect(await screen.findByText('The egress allowlist holds 0 entries.')).toBeInTheDocument()
      expect(screen.getByRole('link', { name: 'Edit the allowlist' })).toHaveAttribute('href', '/egress')
      fireEvent.click(screen.getByRole('switch', { name: 'Only allowlisted destinations' }))
      expect(screen.getByText('The allowlist is empty')).toBeInTheDocument()
      save()
      expect(screen.getByRole('switch', { name: 'Only allowlisted destinations' })).toHaveAccessibleDescription(/The egress allowlist is empty, so every destination would be refused/)
      expect(settingsPosts()).toHaveLength(0)
      headingsInOrder()
      await expectNoAxeViolations(container)
    })

    it('saves default-deny once the allowlist has entries', async () => {
      egressTotal = 4
      renderAt('/settings/filtering')
      expect(await screen.findByText('The egress allowlist holds 4 entries.')).toBeInTheDocument()
      fireEvent.click(screen.getByRole('switch', { name: 'Only allowlisted destinations' }))
      save()
      expect(await screen.findByText(/^Applied to the proxy at/)).toBeInTheDocument()
      expect(settingsPosts()[0][1]).toMatchObject({ egress_default_deny: 'true' })
    })

    it('shows the patterns the proxy will match, and refuses what is not an extension', async () => {
      renderAt('/settings/filtering')
      fireEvent.click(await screen.findByRole('switch', { name: 'Block risky downloads' }))
      const list = screen.getByLabelText('Blocked extensions')
      save()
      expect(list).toHaveAccessibleDescription(/List at least one extension: with an empty list the proxy blocks nothing/)
      fireEvent.change(list, { target: { value: 'EXE, .msi, *' } })
      expect(screen.getByText('The proxy matches:')).toHaveTextContent('\\.exe$ \\.msi$ \\.*$')
      save()
      expect(list).toHaveAccessibleDescription(/"\*" is not a file extension/)
      fireEvent.change(list, { target: { value: 'exe, msi' } })
      save()
      await waitFor(() => expect(settingsPosts()).toHaveLength(1))
      expect(settingsPosts()[0][1]).toMatchObject({ enable_content_filtering: 'true', blocked_file_types: 'exe, msi' })
    })

    it('a DNS-only change does not reload the proxy and says where it takes effect', async () => {
      renderAt('/settings/filtering')
      fireEvent.click(await screen.findByRole('switch', { name: 'SafeSearch' }))
      save()
      expect(await screen.findByText(/^Saved at \d\d:\d\d\.$/)).toBeInTheDocument()
      expect(screen.getByText('The DNS service restarts within about 2 seconds of the save. Devices may keep cached answers for a while.')).toBeInTheDocument()
      expect(reloads()).toHaveLength(0)
    })
  })

  describe('Overview', () => {
    it('lists what needs attention from the API, links each item to its section and counts the warnings in the nav', async () => {
      proxyStatus = 'stopped'
      const { container } = renderAt('/settings/overview')
      const list = await screen.findByRole('region', { name: 'Needs attention' })
      await within(list).findByText('The proxy is not running')
      expect(within(list).getByText('The admin password was never changed here')).toBeInTheDocument()
      expect(within(list).getByRole('link', { name: 'Admin and backup' })).toHaveAttribute('href', '/settings/admin')
      const nav = screen.getByRole('navigation', { name: 'Settings sections' })
      expect(within(nav).getByRole('link', { name: /^Overview/ })).toHaveTextContent('2 items need attention')
      headingsInOrder()
      await expectNoAxeViolations(container)
    })

    it('previews a profile, names the risky changes, applies it and reports what the proxy did', async () => {
      renderAt('/settings/overview')
      fireEvent.click(await screen.findByRole('button', { name: /^Paranoid/ }))
      const preview = await screen.findByRole('heading', { level: 4, name: /^Paranoid changes \d+ settings$/ })
      const box = preview.parentElement!
      expect(box).toHaveTextContent('Require proxy login: not set to on')
      expect(box).toHaveTextContent('Every device must sign in with the .env credential, or gets 407.')
      expect(box).toHaveTextContent('HTTPS Inspection (SSL Bump): off to on')
      fireEvent.click(within(box).getByRole('button', { name: 'Apply Paranoid' }))
      expect(await screen.findByText('Paranoid saved.')).toBeInTheDocument()
      expect(screen.getByText(/^Applied to the proxy at/)).toBeInTheDocument()
      const [, body] = settingsPosts()[0]
      expect(body).toMatchObject({ ssl_bump_enabled: 'true', enable_proxy_auth: 'true', blocked_file_types: expect.stringContaining('exe') })
      expect(body).not.toHaveProperty('waf_block_threshold')
      expect(body).not.toHaveProperty('enable_offline_mode')
      expect(reloads()).toHaveLength(1)
    })

    it('will not apply a profile over unsaved changes in a section it touches', async () => {
      renderAt('/settings/filtering')
      fireEvent.click(await screen.findByRole('switch', { name: 'SafeSearch' }))
      fireEvent.click(screen.getByRole('link', { name: /^Overview/ }))
      fireEvent.click(await screen.findByRole('button', { name: /^Family/ }))
      expect(await screen.findByText('Save or discard the unsaved changes in Filtering first.')).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Apply Family' })).toBeDisabled()
    })

    it('opens the device steps, and reports what the DNS scan found', async () => {
      vi.mocked(api.post).mockImplementation((url: string) => {
        if (url === 'dns/detect') return Promise.resolve({ data: { status: 'success', data: { subnet: '192.168.1', scanned: 8, found: [{ ip: '192.168.1.2', type: 'pihole', name: 'Pi-hole @ 192.168.1.2' }] } } })
        return Promise.resolve({ data: { status: 'success' } })
      })
      renderAt('/settings/overview')
      const steps = await screen.findByRole('button', { name: /^Step-by-step/ })
      expect(steps).toHaveAttribute('aria-expanded', 'false')
      fireEvent.click(steps)
      expect(steps).toHaveAttribute('aria-expanded', 'true')
      expect(screen.getByText('Connect Your Devices')).toBeInTheDocument()
      fireEvent.click(screen.getByRole('button', { name: 'Look for Pi-hole or AdGuard Home' }))
      expect(await screen.findByText('Pi-hole @ 192.168.1.2')).toBeInTheDocument()
      expect(screen.getByText('DNS_UPSTREAM_1=192.168.1.2')).toBeInTheDocument()
    })
  })
})
