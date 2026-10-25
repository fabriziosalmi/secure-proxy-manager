import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { renderWithProviders, setRomeTimeZone } from '../test/helpers'
import { expectNoAxeViolations } from '../test/axe'
import { api } from '../lib/api'
import { DESKTOP_QUERY } from '../hooks/useMediaQuery'
import { Logs, PAGE_SIZE, SHOW_INTERNAL_TRAFFIC_KEY } from './Logs'
import type { LogEntry } from '../types'

// Rows as GET /api/logs returns them (logRow.wire in
// backend-go/internal/handlers/logs.go): reason, reason_label, internal and
// kind on every row, meta.internal counting the matching rows hidden as
// internal. Only api.get and api.post are stubbed, so the page's own request
// building and unwrapping run as in production.
const row = (over: Partial<LogEntry> & { id: number }): LogEntry => ({
  timestamp: '2026-04-04 12:00:00',
  source_ip: '192.168.1.10',
  method: 'CONNECT',
  destination: 'example.com:443',
  status: 'TCP_TUNNEL/200',
  bytes: 1234,
  blocked: false,
  reason: 'none',
  reason_label: 'Not blocked',
  internal: false,
  kind: 'Private network address',
  ...over,
})

const allowed = row({ id: 3 })
const dnsBlock = row({
  id: 2, method: 'GET', destination: 'http://ads.example.net/pixel', status: 'TCP_DENIED/403', bytes: 4900,
  blocked: true, reason: 'domain_blacklist_dns', reason_label: 'Domain blacklist (DNS)',
})
const wafBlock = row({
  id: 1, timestamp: '2026-04-04 12:01:00', method: 'POST', destination: 'http://shop.example.org/login', status: 'NONE_NONE/403', bytes: 205,
  blocked: true, reason: 'waf', reason_label: 'WAF', source_ip: '192.168.1.20',
})
const oldBlock = row({ id: 0, destination: 'old.example.com:443', status: 'TCP_DENIED/403', blocked: true, reason: 'unclassified', reason_label: 'Unclassified (no reason recorded)' })

const page = (data: LogEntry[], meta: Record<string, number> = {}) => ({
  status: 'success',
  data,
  meta: { total: data.length, limit: PAGE_SIZE, offset: 0, internal: 2880, ...meta },
})

const clientsBody = {
  status: 'success',
  data: [
    { ip_address: '192.168.1.10', requests: 30, blocked: 2, last_seen: '2026-04-04 12:00:00', status: 'Active', internal: false, kind: 'Private network address' },
    { ip_address: '192.168.1.20', requests: 3, blocked: 1, last_seen: '2026-04-04 12:00:00', status: 'Active', internal: false, kind: 'Private network address' },
    { ip_address: '172.18.0.1', requests: 16, blocked: 0, last_seen: '2026-04-04 12:00:00', status: 'Active', internal: true, kind: 'Internal: this host' },
  ],
  meta: { total: 2, limit: 50, offset: 0, internal: 1 },
}
const statsBody = {
  status: 'success',
  data: {
    blocked_by_reason: [
      { reason: 'domain_blacklist_dns', label: 'Domain blacklist (DNS)', count: 900 },
      { reason: 'waf', label: 'WAF', count: 3 },
    ],
  },
}

let logsBody: (url: string) => unknown = () => page([allowed, dnsBlock, wafBlock, oldBlock])
const logCalls = () => vi.mocked(api.get).mock.calls.map(([u]) => String(u)).filter((u) => u.startsWith('logs?'))
const lastLogParams = () => new URLSearchParams(logCalls().at(-1)!.split('?')[1])

// Capture WebSocket constructor calls so we can assert on the protocols argument.
const mockWebSocketInstances: Array<{ url: string; protocols?: string | string[] }> = []
const mockSockets: Array<{ onmessage: ((e: MessageEvent) => void) | null; onopen: (() => void) | null; closed: boolean; readyState: number }> = []

vi.stubGlobal('WebSocket', class MockWebSocket {
  static OPEN = 1
  static CONNECTING = 0
  url: string
  protocols?: string | string[]
  onopen: (() => void) | null = null
  onmessage: ((e: MessageEvent) => void) | null = null
  onclose: (() => void) | null = null
  onerror: (() => void) | null = null
  readyState = 0 // CONNECTING
  closed = false

  constructor(url: string, protocols?: string | string[]) {
    this.url = url
    this.protocols = protocols
    mockWebSocketInstances.push({ url, protocols })
    mockSockets.push(this)
  }

  close() { this.closed = true }
})

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

const table = () => screen.getByRole('table', { name: 'Access log requests' })
const bodyRows = () => within(table()).getAllByRole('row').slice(1)
const destinations = () => bodyRows().map((r) => within(r).getAllByRole('button')[0].textContent)

async function openSocket() {
  await waitFor(() => expect(mockSockets.length).toBeGreaterThan(0))
  const sock = mockSockets[mockSockets.length - 1]
  await waitFor(() => expect(sock.onmessage).toBeTruthy())
  act(() => { sock.readyState = 1; sock.onopen?.() })
  return sock
}

const send = (sock: { onmessage: ((e: MessageEvent) => void) | null }, msg: unknown) =>
  act(() => { sock.onmessage!({ data: JSON.stringify(msg) } as MessageEvent) })

describe('Logs', () => {
  beforeEach(() => {
    mockWebSocketInstances.length = 0
    mockSockets.length = 0
    window.localStorage.clear()
    window.history.replaceState({}, '', '/logs')
    setViewport(true)
    logsBody = () => page([allowed, dnsBlock, wafBlock, oldBlock])
    vi.spyOn(api, 'get').mockImplementation((url: string) => {
      if (url.startsWith('logs?')) return Promise.resolve({ data: logsBody(url) })
      if (url.startsWith('logs/stats')) return Promise.resolve({ data: statsBody })
      if (url.startsWith('logs/export')) return Promise.resolve({ data: new Blob(['id\n']) })
      if (url.includes('clients/statistics')) return Promise.resolve({ data: clientsBody })
      if (url.includes('ws-token')) return Promise.resolve({ data: { token: 'ws-tok' } })
      return Promise.resolve({ data: { status: 'success', data: null } })
    })
    vi.spyOn(api, 'post').mockResolvedValue({ data: { status: 'success' } })
  })
  afterEach(() => { vi.restoreAllMocks(); vi.useRealTimers() })

  it('shows the header from the mockup, with the live toggle and the export', async () => {
    renderWithProviders(<Logs />)
    expect(screen.getByRole('heading', { level: 1, name: 'Access logs' })).toBeInTheDocument()
    expect(screen.getByText('Traffic')).toBeInTheDocument()
    expect(screen.getByText('Every request the proxy handled, newest first, with the rule that blocked it.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Export CSV' })).toBeInTheDocument()
    // The headings run in order: the page's h1, then its sections' h2.
    const levels = screen.getAllByRole('heading').map((h) => Number(h.tagName.slice(1)))
    expect(levels[0]).toBe(1)
    expect(levels.slice(1).every((l) => l === 2)).toBe(true)
  })

  it('asks the server for the newest page in id order, leaving internal traffic out by default', async () => {
    renderWithProviders(<Logs />)
    await waitFor(() => expect(logCalls().length).toBeGreaterThan(0))
    const p = lastLogParams()
    expect(p.get('limit')).toBe(String(PAGE_SIZE))
    expect(p.get('sort')).toBe('id')
    expect(p.get('order')).toBe('desc')
    expect(p.has('include_internal')).toBe(false)
  })

  it('draws each row as the mockup does: client and kind, method and destination, result, rule, size', async () => {
    renderWithProviders(<Logs />)
    await waitFor(() => expect(bodyRows()).toHaveLength(4))
    const [a, dns, waf, old] = bodyRows()
    expect(within(a).getByText('192.168.1.10')).toBeInTheDocument()
    expect(within(a).getByText('Private network address')).toBeInTheDocument()
    expect(within(a).getByText('CONNECT')).toBeInTheDocument()
    expect(within(a).getByRole('button', { name: 'example.com:443' })).toHaveAttribute('title', 'example.com:443')
    expect(within(a).getByText('200')).toHaveClass('text-success')
    expect(within(a).getByText('TCP_TUNNEL')).toBeInTheDocument()
    expect(within(a).getByText('Allowed')).toHaveAttribute('data-tone', 'success')
    expect(within(a).getByText('1.2 KB')).toBeInTheDocument()

    expect(within(dns).getByText('403')).toHaveClass('text-danger')
    expect(within(dns).getByText('Domain blacklist (DNS)')).toHaveAttribute('data-tone', 'danger')
    expect(within(waf).getByText('WAF')).toHaveAttribute('data-tone', 'danger')
    expect(within(waf).getByText('205 B')).toBeInTheDocument()
    expect(within(old).getByText('Unclassified (no reason recorded)')).toHaveAttribute('data-tone', 'neutral')
  })

  // The table read the zone-less UTC timestamp as local time.
  it('shows each entry at the viewer time, not at the UTC wall-clock time', async () => {
    const restoreTz = setRomeTimeZone()
    try {
      renderWithProviders(<Logs />)
      expect(await screen.findAllByText('2026-04-04 14:00:00')).not.toHaveLength(0)
    } finally { restoreTz() }
  })

  it('says how many requests it shows and how many internal ones it hides', async () => {
    logsBody = () => page([allowed, dnsBlock], { total: 250 })
    renderWithProviders(<Logs />)
    expect(await screen.findByText(
      '2 of 250 requests shown, newest first. 2,880 requests from internal sources (the stack\'s own traffic) are hidden.',
    )).toBeInTheDocument()
  })

  it('reads its filters from the URL, so a link opens the same view', async () => {
    window.history.replaceState({}, '', '/logs?client=192.168.1.20&outcome=blocked&rule=waf&q=shop')
    renderWithProviders(<Logs />)
    await waitFor(() => expect(logCalls().length).toBeGreaterThan(0))
    const p = lastLogParams()
    expect(p.get('source_ip')).toBe('192.168.1.20')
    expect(p.get('outcome')).toBe('blocked')
    expect(p.get('reason')).toBe('waf')
    expect(p.get('q')).toBe('shop')
    expect(screen.getByRole('searchbox', { name: 'Search destinations' })).toHaveValue('shop')
    expect(screen.getByRole('button', { name: 'Blocked' })).toHaveAttribute('aria-pressed', 'true')
    await waitFor(() => expect(screen.getByRole('combobox', { name: 'Client' })).toHaveValue('192.168.1.20'))
    await waitFor(() => expect(screen.getByRole('combobox', { name: 'Rule' })).toHaveValue('waf'))
  })

  it('writes a filter change to the URL and asks the server again', async () => {
    renderWithProviders(<Logs />)
    await waitFor(() => expect(logCalls().length).toBe(1))
    fireEvent.click(screen.getByRole('button', { name: 'Blocked' }))
    await waitFor(() => expect(lastLogParams().get('outcome')).toBe('blocked'))
    expect(window.location.search).toBe('?outcome=blocked')

    await waitFor(() => expect(screen.getByRole('option', { name: 'WAF' })).toBeInTheDocument())
    fireEvent.change(screen.getByRole('combobox', { name: 'Rule' }), { target: { value: 'waf' } })
    await waitFor(() => expect(lastLogParams().get('reason')).toBe('waf'))
    fireEvent.change(screen.getByRole('combobox', { name: 'Client' }), { target: { value: '192.168.1.10' } })
    await waitFor(() => expect(lastLogParams().get('source_ip')).toBe('192.168.1.10'))
    expect(new URLSearchParams(window.location.search).get('client')).toBe('192.168.1.10')
  })

  it('searches the destination once typing stops, not on every key', async () => {
    renderWithProviders(<Logs />)
    await waitFor(() => expect(logCalls().length).toBe(1))
    const box = screen.getByRole('searchbox', { name: 'Search destinations' })
    fireEvent.change(box, { target: { value: 'a' } })
    fireEvent.change(box, { target: { value: 'ads' } })
    expect(logCalls().length).toBe(1)
    await waitFor(() => expect(lastLogParams().get('q')).toBe('ads'))
    expect(logCalls().filter((u) => u.includes('q=a&') || u.endsWith('q=a'))).toHaveLength(0)
  })

  it('lists devices only in the client filter until internal traffic is shown', async () => {
    renderWithProviders(<Logs />)
    const client = screen.getByRole('combobox', { name: 'Client' })
    await waitFor(() => expect(within(client).getByRole('option', { name: '192.168.1.20' })).toBeInTheDocument())
    expect(within(client).queryByRole('option', { name: /172\.18\.0\.1/ })).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('switch', { name: 'Show internal traffic' }))
    expect(within(client).getByRole('option', { name: '172.18.0.1 (internal: this host)' })).toBeInTheDocument()
  })

  it('shows internal traffic on request, and remembers the choice for this viewer', async () => {
    renderWithProviders(<Logs />)
    const sw = screen.getByRole('switch', { name: 'Show internal traffic' })
    expect(sw).toHaveAttribute('aria-checked', 'false')
    fireEvent.click(sw)
    await waitFor(() => expect(lastLogParams().get('include_internal')).toBe('true'))
    expect(window.localStorage.getItem(SHOW_INTERNAL_TRAFFIC_KEY)).toBe('true')
  })

  it('starts with internal traffic shown when the viewer chose it, and works when storage is blocked', async () => {
    window.localStorage.setItem(SHOW_INTERNAL_TRAFFIC_KEY, 'true')
    const { unmount } = renderWithProviders(<Logs />)
    expect(screen.getByRole('switch', { name: 'Show internal traffic' })).toHaveAttribute('aria-checked', 'true')
    unmount()
    vi.spyOn(window.localStorage, 'getItem').mockImplementation(() => { throw new Error('blocked') })
    vi.spyOn(window.localStorage, 'setItem').mockImplementation(() => { throw new Error('blocked') })
    renderWithProviders(<Logs />)
    const sw = screen.getByRole('switch', { name: 'Show internal traffic' })
    expect(sw).toHaveAttribute('aria-checked', 'false')
    fireEvent.click(sw)
    expect(sw).toHaveAttribute('aria-checked', 'true')
  })

  it('loads older rows with the cursor of the last row shown', async () => {
    const first = Array.from({ length: PAGE_SIZE }, (_, i) => row({ id: 1000 - i, destination: `p1-${i}.example.com:443` }))
    logsBody = (url) => (url.includes('before_id=901')
      ? page([row({ id: 900, destination: 'older.example.com:443' })], { total: 101 })
      : page(first, { total: 101 }))
    renderWithProviders(<Logs />)
    const more = await screen.findByRole('button', { name: 'Load older' })
    fireEvent.click(more)
    await waitFor(() => expect(destinations()).toContain('older.example.com:443'))
    expect(lastLogParams().get('before_id')).toBe('901')
    expect(destinations()).toHaveLength(PAGE_SIZE + 1)
    // The second page was short: there is nothing older.
    expect(screen.queryByRole('button', { name: 'Load older' })).not.toBeInTheDocument()
  })

  it('has no Load older when the first page holds everything', async () => {
    renderWithProviders(<Logs />)
    await waitFor(() => expect(bodyRows()).toHaveLength(4))
    expect(screen.queryByRole('button', { name: 'Load older' })).not.toBeInTheDocument()
  })

  // The hub also carries {"type":"login_failure", ...} events, which anyone can
  // cause by failing a login. They were added to the table as blank rows dated
  // "Invalid Date" and pushed real traffic out of the buffer.
  it('keeps only log rows from the live feed', async () => {
    renderWithProviders(<Logs />)
    await waitFor(() => expect(bodyRows()).toHaveLength(4))
    const sock = await openSocket()
    send(sock, { type: 'login_failure', data: { username: 'x', client_ip: '203.0.113.5' } })
    send(sock, { timestamp: new Date().toISOString(), client_ip: '192.168.1.77', method: 'GET', destination: 'fresh.example.org', status: 'TCP_MISS/200', bytes: 10 })
    await waitFor(() => expect(screen.getByText('fresh.example.org')).toBeInTheDocument())
    expect(screen.queryByText(/invalid date/i)).not.toBeInTheDocument()
    expect(bodyRows()).toHaveLength(5)
  })

  // Live rows used to be prepended whatever the page showed: a filtered view
  // filled with rows it did not select.
  it('prepends a live row only when it matches the filters on screen', async () => {
    window.history.replaceState({}, '', '/logs?outcome=blocked')
    renderWithProviders(<Logs />)
    await waitFor(() => expect(bodyRows()).toHaveLength(4))
    const sock = await openSocket()
    send(sock, { id: 50, timestamp: '2026-04-04 12:05:00', source_ip: '192.168.1.10', method: 'GET', destination: 'live-allowed.example.com', status: 'TCP_MISS/200', bytes: 1, blocked: 0, reason: 'none', internal: false })
    send(sock, { id: 51, timestamp: '2026-04-04 12:05:01', source_ip: '172.18.0.1', method: 'GET', destination: 'live-internal.example.com', status: 'TCP_DENIED/403', bytes: 1, blocked: 1, reason: 'domain_blacklist', internal: true, kind: 'Internal: this host' })
    send(sock, { id: 52, timestamp: '2026-04-04 12:05:02', source_ip: '192.168.1.10', method: 'GET', destination: 'live-blocked.example.com', status: 'TCP_DENIED/403', bytes: 1, blocked: 1, reason: 'domain_blacklist', reason_label: 'Domain blacklist', internal: false })
    await waitFor(() => expect(destinations()[0]).toBe('live-blocked.example.com'))
    expect(screen.queryByText('live-allowed.example.com')).not.toBeInTheDocument()
    expect(screen.queryByText('live-internal.example.com')).not.toBeInTheDocument()
    // A row the page already holds is not listed twice.
    send(sock, { ...dnsBlock, blocked: 1 })
    expect(destinations().filter((d) => d === dnsBlock.destination)).toHaveLength(1)
  })

  it('pauses the live feed: the button reads Paused and the socket is closed', async () => {
    renderWithProviders(<Logs />)
    const sock = await openSocket()
    const toggle = await screen.findByRole('button', { name: 'Live' })
    expect(toggle).toHaveAttribute('aria-pressed', 'true')
    fireEvent.click(toggle)
    expect(screen.getByRole('button', { name: 'Paused' })).toHaveAttribute('aria-pressed', 'false')
    expect(sock.closed).toBe(true)
    fireEvent.click(screen.getByRole('button', { name: 'Paused' }))
    await waitFor(() => expect(mockSockets.length).toBe(2))
  })

  it('details the selected request below the table, with why it was blocked', async () => {
    renderWithProviders(<Logs />)
    await waitFor(() => expect(bodyRows()).toHaveLength(4))
    expect(screen.queryByRole('heading', { name: 'Request details' })).not.toBeInTheDocument()
    const pick = screen.getByRole('button', { name: dnsBlock.destination })
    fireEvent.click(pick)
    expect(pick).toHaveAttribute('aria-pressed', 'true')
    const details = screen.getByRole('region', { name: 'Request details' })
    expect(within(details).getByText('The name is on the domain blacklist; the DNS sinkhole answered it with 0.0.0.0 and the proxy refused the request.')).toBeInTheDocument()
    expect(within(details).getByText('TCP_DENIED/403')).toBeInTheDocument()
    expect(within(details).getByRole('button', { name: 'Allow this domain' })).toBeInTheDocument()
    await expectNoAxeViolations()
  })

  it('offers Allow this domain only for a rule a domain whitelist overrides', async () => {
    renderWithProviders(<Logs />)
    await waitFor(() => expect(bodyRows()).toHaveLength(4))
    for (const r of [wafBlock, allowed, oldBlock]) {
      fireEvent.click(screen.getByRole('button', { name: r.destination }))
      const details = screen.getByRole('region', { name: 'Request details' })
      expect(within(details).queryByRole('button', { name: 'Allow this domain' })).not.toBeInTheDocument()
    }
  })

  it('allows the domain through the whitelist endpoint, after a confirmation that names it and what it overrides', async () => {
    renderWithProviders(<Logs />)
    await waitFor(() => expect(bodyRows()).toHaveLength(4))
    fireEvent.click(screen.getByRole('button', { name: dnsBlock.destination }))
    fireEvent.click(screen.getByRole('button', { name: 'Allow this domain' }))
    const dialog = await screen.findByRole('alertdialog', { name: 'Allow ads.example.net?' })
    expect(dialog).toHaveTextContent('domain whitelist')
    expect(dialog).toHaveTextContent('"Domain blacklist (DNS)" no longer blocks it')
    expect(api.post).not.toHaveBeenCalled()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Allow domain' }))
    await waitFor(() => expect(api.post).toHaveBeenCalledWith('domain-whitelist', { domain: 'ads.example.net', description: 'Allowed from the access log' }))
  })

  it("filters to the selected request's client", async () => {
    renderWithProviders(<Logs />)
    await waitFor(() => expect(bodyRows()).toHaveLength(4))
    fireEvent.click(screen.getByRole('button', { name: wafBlock.destination }))
    fireEvent.click(screen.getByRole('button', { name: "Show this client's requests" }))
    await waitFor(() => expect(lastLogParams().get('source_ip')).toBe('192.168.1.20'))
    expect(new URLSearchParams(window.location.search).get('client')).toBe('192.168.1.20')
  })

  it('opens the detail in a drawer on a phone', async () => {
    setViewport(false)
    renderWithProviders(<Logs />)
    await waitFor(() => expect(bodyRows()).toHaveLength(4))
    const pick = screen.getByRole('button', { name: wafBlock.destination })
    expect(pick).toHaveAttribute('aria-haspopup', 'dialog')
    fireEvent.click(pick)
    const drawer = screen.getByRole('dialog', { name: 'Request details' })
    expect(drawer.parentElement).toBe(document.body)
    expect(within(drawer).getByText('The WAF matched one of its rules in the request or the response and blocked it.')).toBeInTheDocument()
    await expectNoAxeViolations()
    fireEvent.click(within(drawer).getByRole('button', { name: 'Close' }))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('exports the rows the filters select', async () => {
    window.history.replaceState({}, '', '/logs?outcome=blocked&q=ads')
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    Object.assign(URL, { createObjectURL: vi.fn(() => 'blob:x'), revokeObjectURL: vi.fn() })
    renderWithProviders(<Logs />)
    fireEvent.click(screen.getByRole('button', { name: 'Export CSV' }))
    await waitFor(() => expect(click).toHaveBeenCalled())
    const call = vi.mocked(api.get).mock.calls.find(([u]) => String(u).startsWith('logs/export'))!
    expect(new URLSearchParams(String(call[0]).split('?')[1]).toString()).toBe('q=ads&outcome=blocked')
    expect(call[1]).toEqual({ responseType: 'blob' })
  })

  it('says what is missing when nothing matches, and clears the filters', async () => {
    window.history.replaceState({}, '', '/logs?q=nothing')
    logsBody = () => page([], { internal: 0 })
    renderWithProviders(<Logs />)
    expect(await screen.findByText('No request matches these filters')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Clear filters' }))
    await waitFor(() => expect(window.location.search).toBe(''))
    expect(screen.getByRole('searchbox', { name: 'Search destinations' })).toHaveValue('')
  })

  it('says when only internal traffic was logged', async () => {
    logsBody = () => page([], { internal: 12 })
    renderWithProviders(<Logs />)
    expect(await screen.findByText('No requests from devices')).toBeInTheDocument()
    expect(screen.getByText(/Only internal sources sent requests \(12 requests/)).toBeInTheDocument()
  })

  it('has no accessibility violations', async () => {
    renderWithProviders(<Logs />)
    await waitFor(() => expect(bodyRows()).toHaveLength(4))
    await expectNoAxeViolations()
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
    // The fixed protocol the server selects; without it a browser closes the socket.
    expect(protocols[0]).toBe('spm.v1')

    // Token MUST NOT appear in the URL query string.
    expect(instance.url).not.toContain('token=')
    expect(instance.url).not.toContain('ws-tok')
  })

  // The feed used to give up after ten failed attempts (about three minutes of
  // backoff) and stay frozen until the page was reloaded: a tab left open
  // through a backend restart, which is when someone is watching it.
  describe('reconnecting', () => {
    const tokenCalls = () => vi.mocked(api.get).mock.calls.filter(([u]) => String(u).includes('ws-token')).length

    beforeEach(() => {
      vi.useFakeTimers({ shouldAdvanceTime: true })
      vi.mocked(api.get).mockImplementation((url: string) => {
        if (url.includes('ws-token')) return Promise.reject(new Error('backend down'))
        if (url.startsWith('logs?')) return Promise.resolve({ data: page([allowed]) })
        return Promise.resolve({ data: { status: 'success', data: null } })
      })
    })
    afterEach(() => { vi.useRealTimers() })

    it('keeps retrying after more than ten failures, at a capped delay', async () => {
      renderWithProviders(<Logs />)
      // 1 + 2 + 4 + 8 + 16 s, then 30 s each: 15 attempts fit in ten minutes.
      for (let i = 0; i < 40; i++) {
        await act(async () => { await vi.advanceTimersByTimeAsync(30_000) })
      }
      expect(tokenCalls()).toBeGreaterThan(15)
    })

    it('reconnects at once when the tab becomes visible again, instead of waiting out the backoff', async () => {
      renderWithProviders(<Logs />)
      for (let i = 0; i < 12; i++) {
        await act(async () => { await vi.advanceTimersByTimeAsync(30_000) })
      }
      await act(async () => { await vi.advanceTimersByTimeAsync(0) })
      const before = tokenCalls()
      await act(async () => {
        document.dispatchEvent(new Event('visibilitychange'))
        await vi.advanceTimersByTimeAsync(0)
      })
      expect(tokenCalls()).toBe(before + 1)
    })
  })
})
