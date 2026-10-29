import { describe, it, expect, vi, beforeEach, afterEach, onTestFinished } from 'vitest'
import { screen, waitFor, fireEvent, within } from '@testing-library/react'
import { renderWithProviders, simulateItalianLocale, setRomeTimeZone } from '../test/helpers'
import { expectNoAxeViolations } from '../test/axe'
import { api } from '../lib/api'
import { DESKTOP_QUERY } from '../hooks/useMediaQuery'
import { Clients, SHOW_INTERNAL_KEY } from './Clients'

// The body GET /api/clients/statistics really returns (writeList in
// backend-go/internal/handlers/helpers.go, ClientStats in analytics.go): the
// clients with the most requests, then the internal sources, marked. Only
// api.get is stubbed, so the page's own unwrapping runs as in production.
const clientsBody = {
  status: 'success',
  data: [
    { ip_address: '192.168.0.109', requests: 1180, blocked: 908, last_seen: '2026-07-01 09:00:00', status: 'Active', internal: false, kind: 'Private network address' },
    { ip_address: '172.20.5.9', requests: 30, blocked: 0, last_seen: '2026-07-01 08:00:00', status: 'Active', internal: false, kind: 'Private network address' },
    { ip_address: '172.18.0.2', requests: 17, blocked: 0, last_seen: '2026-07-01 09:10:00', status: 'Active', internal: true, kind: 'Internal: the backend' },
    { ip_address: '172.18.0.1', requests: 16, blocked: 10, last_seen: '2026-07-01 09:00:00', status: 'Active', internal: true, kind: 'Internal: this host' },
    { ip_address: '127.0.0.1', requests: 2, blocked: 0, last_seen: '2026-07-01 07:00:00', status: 'Active', internal: true, kind: 'Internal: loopback, from inside the proxy container' },
  ],
  meta: { total: 2, limit: 50, offset: 0, internal: 3 },
  total: 2,
  limit: 50,
  offset: 0,
}

// /api/clients/{ip}/details for the LAN client: every request on record
// (1,300, more than the table's 7 days), 8 of its blocks from before reasons
// were recorded.
const detailBody = (ip: string) => ({
  status: 'success',
  data: {
    ip_address: ip,
    internal: false,
    kind: 'Private network address',
    total_requests: 1300,
    blocked: 908,
    first_seen: '2026-06-28 07:59:00',
    last_seen: '2026-07-01 09:21:00',
    top_domains: [
      { destination: 'ads.example.test', requests: 700, blocked: 700 },
      { destination: 'news.example.test', requests: 300, blocked: 0 },
    ],
    recent: [
      { timestamp: '2026-07-01 09:21:00', method: 'CONNECT', destination: 'ads.example.test:443', status: 'TCP_DENIED/403', bytes: 0, blocked: true, reason: 'domain_blacklist', reason_label: 'Domain blacklist' },
      { timestamp: '2026-07-01 09:20:00', method: 'GET', destination: 'http://news.example.test/', status: 'TCP_MISS/403', bytes: 10, blocked: false, reason: 'none', reason_label: 'Not blocked' },
      { timestamp: '2026-06-28 08:00:00', method: 'GET', destination: 'http://old.test/', status: 'NONE_NONE/403', bytes: 0, blocked: true, reason: 'unclassified', reason_label: 'Unclassified (no reason recorded)' },
    ],
    blocked_by_reason: [
      { reason: 'domain_blacklist', label: 'Domain blacklist', count: 900 },
      { reason: 'unclassified', label: 'Unclassified (no reason recorded)', count: 8 },
    ],
  },
})

let body: unknown = clientsBody
const detailCalls: string[] = []
const detailWindows: string[] = []

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

const tableRows = () => within(screen.getByRole('table', { name: 'Clients in the last 7 days' })).getAllByRole('row').slice(1)
const ips = () => tableRows().map((r) => within(r).getAllByRole('button')[0].textContent)

describe('Clients', () => {
  beforeEach(() => {
    body = clientsBody
    detailCalls.length = 0
    detailWindows.length = 0
    window.localStorage.clear()
    setViewport(false)
    vi.spyOn(api, 'get').mockImplementation((url: string) => {
      if (url.includes('clients/statistics')) return Promise.resolve({ data: body })
      // clients/<ip>/details: the address is the path segment in between.
      const detail = url.match(/clients\/([^/]+)\/details/)
      if (detail) {
        const ip = decodeURIComponent(detail[1])
        detailCalls.push(ip)
        // The backend answers with the window it counted (?window=, default all).
        const span = new URLSearchParams(url.split('?')[1] ?? '').get('window') ?? 'all'
        detailWindows.push(span)
        const b = detailBody(ip)
        return Promise.resolve({ data: { ...b, data: { ...b.data, window: span } } })
      }
      return Promise.resolve({ data: { status: 'success', data: null } })
    })
  })
  afterEach(() => { vi.restoreAllMocks() })

  it('shows the header from the mockup, and Connect a device opens the device setup', async () => {
    renderWithProviders(<Clients />)
    expect(screen.getByRole('heading', { level: 1, name: 'Clients' })).toBeInTheDocument()
    expect(screen.getByText('Traffic')).toBeInTheDocument()
    expect(screen.getByText('Devices that sent traffic through the proxy in the last 7 days.')).toBeInTheDocument()
    const connect = screen.getByRole('button', { name: 'Connect a device' })
    expect(connect).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByRole('tablist', { name: 'Operating system' })).not.toBeInTheDocument()
    fireEvent.click(connect)
    expect(connect).toHaveAttribute('aria-expanded', 'true')
    expect(screen.getByRole('tablist', { name: 'Operating system' })).toBeInTheDocument()
  })

  it('hides the internal addresses until the viewer shows them, and says how many it hides', async () => {
    renderWithProviders(<Clients />)
    await waitFor(() => expect(ips()).toEqual(['192.168.0.109', '172.20.5.9']))
    const toggle = screen.getByRole('switch', { name: 'Show internal addresses (3)' })
    expect(toggle).toHaveAttribute('aria-checked', 'false')
    expect(screen.getByText('2 clients shown. 3 internal addresses are hidden and not counted in any statistic.')).toBeInTheDocument()

    fireEvent.click(toggle)
    expect(toggle).toHaveAttribute('aria-checked', 'true')
    expect(ips()).toEqual(['192.168.0.109', '172.20.5.9', '172.18.0.2', '172.18.0.1', '127.0.0.1'])
    expect(screen.getByText('Internal: this host')).toBeInTheDocument()
    expect(screen.getByText('5 addresses shown, 3 of them internal. Internal traffic is not counted in any statistic.')).toBeInTheDocument()
    expect(window.localStorage.getItem(SHOW_INTERNAL_KEY)).toBe('true')
  })

  it('remembers the choice per viewer, and works when storage is blocked', async () => {
    window.localStorage.setItem(SHOW_INTERNAL_KEY, 'true')
    const { unmount } = renderWithProviders(<Clients />)
    await waitFor(() => expect(ips()).toHaveLength(5))
    unmount()

    vi.spyOn(window.localStorage, 'getItem').mockImplementation(() => { throw new Error('SecurityError') })
    vi.spyOn(window.localStorage, 'setItem').mockImplementation(() => { throw new Error('SecurityError') })
    renderWithProviders(<Clients />)
    await waitFor(() => expect(ips()).toHaveLength(2))
    fireEvent.click(screen.getByRole('switch', { name: 'Show internal addresses (3)' }))
    expect(ips()).toHaveLength(5)
  })

  it('sorts by requests, most first, and re-sorts on Requests and Blocked', async () => {
    window.localStorage.setItem(SHOW_INTERNAL_KEY, 'true')
    renderWithProviders(<Clients />)
    await waitFor(() => expect(ips()).toHaveLength(5))
    expect(screen.getByRole('columnheader', { name: /Requests/ })).toHaveAttribute('aria-sort', 'descending')
    fireEvent.click(screen.getByRole('button', { name: 'Requests' }))
    expect(screen.getByRole('columnheader', { name: /Requests/ })).toHaveAttribute('aria-sort', 'ascending')
    expect(ips()).toEqual(['127.0.0.1', '172.18.0.1', '172.18.0.2', '172.20.5.9', '192.168.0.109'])
    fireEvent.click(screen.getByRole('button', { name: 'Blocked' }))
    expect(ips().slice(0, 2)).toEqual(['192.168.0.109', '172.18.0.1'])
  })

  // "Share blocked" could not be sorted: a client with few requests, nearly
  // all blocked, sat at the bottom under clients with large counts.
  it('sorts by share blocked, largest first', async () => {
    const client = (ip_address: string, requests: number, blocked: number) => (
      { ip_address, requests, blocked, last_seen: '2026-07-01 08:00:00', status: 'Active', internal: false, kind: 'Private network address' })
    body = { ...clientsBody, data: [client('10.20.0.1', 1180, 908), client('10.20.0.2', 30, 0), client('10.20.0.3', 10, 9)], meta: { ...clientsBody.meta, internal: 0 } }
    renderWithProviders(<Clients />)
    await waitFor(() => expect(ips()).toHaveLength(3))
    fireEvent.click(screen.getByRole('button', { name: 'Share blocked' }))
    expect(screen.getByRole('columnheader', { name: /Share blocked/ })).toHaveAttribute('aria-sort', 'descending')
    // 90%, 76.9%, 0%; by requests they were 1,180, 30, 10.
    expect(ips()).toEqual(['10.20.0.3', '10.20.0.1', '10.20.0.2'])
  })

  it('writes counts, the share blocked and the last request from the API, in the viewer time zone', async () => {
    const restoreTz = setRomeTimeZone()
    try {
      simulateItalianLocale()
      renderWithProviders(<Clients />)
      await waitFor(() => expect(ips()).toHaveLength(2))
      const row = tableRows()[0]
      expect(row).toHaveTextContent('1,180')
      expect(row).not.toHaveTextContent('1.180')
      expect(row).toHaveTextContent('908')
      // 908 of 1,180, one decimal.
      expect(row).toHaveTextContent('76.9%')
      // 09:00 UTC on 1 July is 11:00 in Rome; not today, so with its date.
      expect(row).toHaveTextContent('2026-07-01 11:00')
    } finally {
      restoreTz()
    }
  })

  it('filters by IP address', async () => {
    renderWithProviders(<Clients />)
    await waitFor(() => expect(ips()).toHaveLength(2))
    fireEvent.change(screen.getByRole('searchbox', { name: 'Filter clients by IP address' }), { target: { value: '172.20' } })
    expect(ips()).toEqual(['172.20.5.9'])
    expect(screen.getByText(/^1 client matches the filter\./)).toBeInTheDocument()
    fireEvent.change(screen.getByRole('searchbox', { name: 'Filter clients by IP address' }), { target: { value: '10.9' } })
    expect(screen.getByText('No client matches "10.9"')).toBeInTheDocument()
  })

  it('says when only internal addresses sent traffic, and offers device setup when nothing did', async () => {
    body = { ...clientsBody, data: clientsBody.data.filter((c) => c.internal), meta: { total: 0, limit: 50, offset: 0, internal: 3 } }
    const { unmount } = renderWithProviders(<Clients />)
    expect(await screen.findByText('No devices in the last 7 days')).toBeInTheDocument()
    expect(screen.getByText(/Only internal addresses sent requests \(3\)/)).toBeInTheDocument()
    unmount()

    body = { ...clientsBody, data: [], meta: { total: 0, limit: 50, offset: 0, internal: 0 } }
    renderWithProviders(<Clients />)
    expect(await screen.findByText('No client traffic in the last 7 days')).toBeInTheDocument()
    expect(screen.getAllByRole('button', { name: 'Connect a device' })).toHaveLength(2)
  })

  describe('on a wide screen', () => {
    beforeEach(() => { setViewport(true) })

    it('shows the selected client in a panel next to the table, with the row marked selected', async () => {
      const restoreTz = setRomeTimeZone()
      onTestFinished(restoreTz)
      const { container } = renderWithProviders(<Clients />)
      // The first row is selected until another is picked.
      const panel = await screen.findByRole('region', { name: '192.168.0.109' })
      const first = screen.getByRole('button', { name: '192.168.0.109' })
      expect(first).toHaveAttribute('aria-pressed', 'true')
      expect(first.closest('tr')).toHaveAttribute('data-selected', 'true')
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument()

      await within(panel).findByText('1,300')
      // One row each, so a date never wraps away from its time.
      const firstSeen = within(panel).getByText('First request').nextElementSibling!
      const lastSeen = within(panel).getByText('Last request').nextElementSibling!
      expect(firstSeen).toHaveTextContent(/^2026-06-28 09:59$/)
      expect(lastSeen).toHaveTextContent(/^2026-07-01 11:21$/)
      expect(firstSeen).toHaveClass('whitespace-nowrap')
      expect(lastSeen).toHaveAttribute('title', '2026-07-01 11:21:00 (Europe/Rome)')
      expect(within(panel).getByText('908')).toBeInTheDocument()
      // 908 of 1,300.
      expect(within(panel).getByText('69.8%')).toBeInTheDocument()
      // The detail counts the table's 7 days and says so.
      expect(detailWindows).toEqual(['7d'])
      expect(within(panel).getByText('These counts cover the last 7 days, as the table does.')).toBeInTheDocument()
      expect(within(panel).getByText('8 of the 908 blocked requests were logged before the proxy recorded why it blocked a request, so the rule is not known.')).toBeInTheDocument()
      const dest = within(panel).getByRole('table', { name: 'Top destinations of 192.168.0.109' })
      expect(within(dest).getByText('ads.example.test')).toBeInTheDocument()
      expect(within(dest).getAllByText('700')).toHaveLength(2)
      expect(within(panel).getByText('Domain blacklist')).toBeInTheDocument()
      // "Not blocked" here, "Allowed" in the access log: one word now.
      expect(within(panel).getByText('Allowed')).toHaveAttribute('data-tone', 'success')
      // A recent request from another day carries its date, in the viewer's zone.
      expect(within(panel).getByText('2026-06-28 10:00')).toBeInTheDocument()
      // The access log filters by client now: the panel links to this
      // client's requests (and only to them, not to the unfiltered log).
      const links = within(panel).getAllByRole('link')
      expect(links).toHaveLength(1)
      expect(links[0]).toHaveAccessibleName("Show this client's requests in the access log")
      expect(links[0]).toHaveAttribute('href', '/logs?client=192.168.0.109')

      fireEvent.click(screen.getByRole('button', { name: '172.20.5.9' }))
      expect(await screen.findByRole('region', { name: '172.20.5.9' })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: '172.20.5.9' })).toHaveAttribute('aria-pressed', 'true')
      expect(first).toHaveAttribute('aria-pressed', 'false')
      await waitFor(() => expect(detailCalls).toContain('172.20.5.9'))
      await expectNoAxeViolations(container)
    })

    it('keeps the headings in order', async () => {
      renderWithProviders(<Clients />)
      await screen.findByRole('heading', { name: 'Top destinations' })
      const levels = screen.getAllByRole('heading').map((h) => Number(h.tagName.slice(1)))
      expect(levels[0]).toBe(1)
      for (let i = 1; i < levels.length; i++) expect(levels[i] - levels[i - 1]).toBeLessThanOrEqual(1)
    })

    it('groups rows by network CIDR when GDPR mode is on, fetches detail by CIDR and links to ?client=<CIDR>', async () => {
      body = {
        status: 'success',
        data: [
          { ip_address: '192.168.0.x', network: '192.168.0.0/24', addresses: 3, requests: 1180, blocked: 908, last_seen: '2026-07-01 09:00:00', status: 'Active', internal: false, kind: 'Private network address' },
          { ip_address: '2001:db8:1:2::x', network: '2001:db8:1:2::/64', addresses: 2, requests: 40, blocked: 5, last_seen: '2026-07-01 08:30:00', status: 'Active', internal: false, kind: 'mixed', classification: 'mixed' },
        ],
        meta: { total: 2, limit: 50, offset: 0, internal: 0 },
      }
      renderWithProviders(<Clients />)
      const panel = await screen.findByRole('region', { name: '192.168.0.0/24' })
      expect(detailCalls).toContain('192.168.0.0/24')
      expect(screen.getByText(/192\.168\.0\.0\/24 · 3 addresses/)).toBeInTheDocument()
      expect(screen.getByText(/2001:db8:1:2::\/64 · 2 addresses · mixed/)).toBeInTheDocument()
      const link = await within(panel).findByRole('link', { name: 'Show requests from this network in the access log' })
      expect(link).toHaveAttribute('href', '/logs?client=192.168.0.0%2F24')
      expect(within(panel).getByText('These counts cover the last 7 days, as the table does.')).toBeInTheDocument()
      // All time on request, said as such.
      fireEvent.click(within(panel).getByRole('button', { name: 'All time' }))
      expect(await within(panel).findByText('These counts cover every request logged for this network; the table counts the last 7 days.')).toBeInTheDocument()
      expect(detailWindows).toEqual(['7d', 'all'])
      expect(screen.getByRole('searchbox', { name: 'Filter clients by network or IP address' })).toHaveAttribute('placeholder', 'Filter by network or IP address')
    })
  })

  describe('below lg', () => {
    it('opens the detail in a drawer outside the page, directly in document.body', async () => {
      renderWithProviders(<Clients />)
      const button = await screen.findByRole('button', { name: '192.168.0.109' })
      expect(button).toHaveAttribute('aria-haspopup', 'dialog')
      expect(screen.queryByRole('region', { name: '192.168.0.109' })).not.toBeInTheDocument()
      fireEvent.click(button)
      const drawer = await screen.findByRole('dialog', { name: '192.168.0.109' })
      expect(drawer.parentElement).toBe(document.body)
      await within(drawer).findByText('1,300')
      expect(within(drawer).getByRole('link', { name: "Show this client's requests in the access log" })).toHaveAttribute('href', '/logs?client=192.168.0.109')
      await expectNoAxeViolations(drawer)
      fireEvent.click(within(drawer).getByRole('button', { name: 'Close' }))
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    })
  })
})
