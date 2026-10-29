import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import { renderWithProviders, simulateItalianLocale, setRomeTimeZone } from '../test/helpers'
import { expectNoAxeViolations } from '../test/axe'
import { Dashboard } from './Dashboard'
import { currentCacheStats, notCollectedCacheStats } from '../test/cacheStats'

vi.mock('../lib/api', () => {
  const get = vi.fn()
  return {
    api: {
      get,
      post: vi.fn(),
      interceptors: { request: { use: vi.fn() }, response: { use: vi.fn() } },
    },
    // getData wraps the (mocked) api.get and unwraps the { data } envelope, so
    // the same mockImplementation drives both api.get and getData call sites.
    getData: (path: string) =>
      get(path).then((r: { data?: { data?: unknown } }) => r?.data?.data ?? null),
    getErrorMessage: (_e: unknown, f: string) => f,
  }
})

import { api } from '../lib/api'

// The test deployment's summary, in the shape the backend sends.
const summaryData = {
  total_requests: 1234,
  blocked_requests: 23,
  today_requests: 1234,
  today_blocked: 23,
  last_24h_requests: 1180,
  last_24h_blocked: 908,
  last_24h_clients: 1,
  last_request_at: '2026-07-01 07:21:05',
  ip_blacklist_count: 50772,
  domain_blacklist_count: 640929,
  top_blocked: [
    { dest: 'dpm.demdex.net', count: 74, reasons: [{ reason: 'domain_blacklist_dns', label: 'Domain blacklist (DNS)', count: 74 }] },
    { dest: 'example.com', count: 11, reasons: [{ reason: 'unclassified', label: 'Unclassified (no reason recorded)', count: 11 }] },
  ],
  top_clients: [{ ip: '192.168.0.109', count: 1180 }],
  threat_categories: [],
  blocked_by_reason_24h: [
    { reason: 'domain_blacklist_dns', label: 'Domain blacklist (DNS)', count: 900 },
    { reason: 'domain_blacklist', label: 'Domain blacklist', count: 8 },
  ],
  recent_blocks: [
    {
      timestamp: '2026-07-01 07:04:12', source_ip: '192.168.0.109', method: 'CONNECT',
      destination: 'static.chartbeat.com:443', host: 'static.chartbeat.com', status: 'TCP_DENIED/403',
      reason: 'domain_blacklist_dns', reason_label: 'Domain blacklist (DNS)',
    },
  ],
  squid_domain_acl: null,
  waf: { total_requests: 30, total_blocked: 1, avg_url_entropy: 3.98, requests_last_minute: 0, top_blocked_categories: [] },
  waf_status: 'ok',
}

const timeline = [{ time: '2026-07-01 06:00:00', total: 1146, blocked: 908 }]

type Routes = Record<string, unknown>
function serve(routes: Routes) {
  vi.mocked(api.get).mockImplementation((url: string) => {
    for (const [path, data] of Object.entries(routes)) {
      if (url.startsWith(path)) {
        if (data instanceof Error) return Promise.reject(data)
        return Promise.resolve({ data: { data } })
      }
    }
    return Promise.resolve({ data: { data: null } })
  })
}

const DEFAULT_ROUTES: Routes = {
  'dashboard/summary': summaryData,
  'logs/timeline': timeline,
  status: { proxy_status: 'running', proxy_port: '3128', version: '3.14.3' },
  'cache/statistics': notCollectedCacheStats,
}

function card(label: string): HTMLElement {
  const el = screen.getByText(label, { selector: 'p' }).parentElement
  if (!el) throw new Error(`no card ${label}`)
  return el
}

describe('Dashboard (Overview)', () => {
  let restoreTz: () => void
  beforeEach(() => {
    vi.clearAllMocks()
    restoreTz = setRomeTimeZone()
    serve(DEFAULT_ROUTES)
  })
  afterEach(() => {
    restoreTz()
    vi.restoreAllMocks()
  })

  it('is the Overview of the last 24 hours, with the time it was updated', async () => {
    renderWithProviders(<Dashboard />)
    expect(screen.getByRole('heading', { level: 1, name: 'Overview' })).toBeInTheDocument()
    expect(await screen.findByText(/^Last 24 hours · updated \d\d:\d\d$/)).toBeInTheDocument()
  })

  it('shows each card from its API field', async () => {
    renderWithProviders(<Dashboard />)
    await waitFor(() => { expect(card('Client requests')).toHaveTextContent('1,180') })
    expect(card('Client requests')).toHaveTextContent('from 1 client')
    expect(card('Blocked')).toHaveTextContent('908')
    expect(card('Blocked')).toHaveTextContent('76.9% of requests')
    // One client: its address, and the newest request at the viewer time (UTC+2 in July).
    expect(card('Active clients')).toHaveTextContent('1192.168.0.109, last request 09:21')
    expect(card('Rules in force')).toHaveTextContent('691,701')
    expect(card('Rules in force')).toHaveTextContent('50,772 IPs, 640,929 domains')
  })

  // It read "1 IPs" on a deployment with one blocked network.
  it('counts one rule in the singular', async () => {
    serve({ ...DEFAULT_ROUTES, 'dashboard/summary': { ...summaryData, ip_blacklist_count: 1, domain_blacklist_count: 1 } })
    renderWithProviders(<Dashboard />)
    await waitFor(() => { expect(card('Rules in force')).toHaveTextContent('1 IP, 1 domain') })
    expect(card('Rules in force')).not.toHaveTextContent('IPs')
  })

  // The backend leaves the stack's own addresses out of every count and
  // says how many it left out; the Active clients card repeats it.
  it('says how many internal addresses the counts leave out', async () => {
    serve({ ...DEFAULT_ROUTES, 'dashboard/summary': { ...summaryData, last_24h_internal_sources: 3, last_24h_internal_requests: 40 } })
    renderWithProviders(<Dashboard />)
    await waitFor(() => { expect(card('Active clients')).toHaveTextContent('3 internal addresses not counted') })
    expect(card('Active clients')).toHaveTextContent('192.168.0.109, last request 09:21')
    expect(card('Active clients')).toHaveTextContent(/^Active clients1/)
  })

  it('says nothing about internal addresses when none were left out', async () => {
    serve({ ...DEFAULT_ROUTES, 'dashboard/summary': { ...summaryData, last_24h_internal_sources: 0 } })
    renderWithProviders(<Dashboard />)
    await waitFor(() => { expect(card('Active clients')).toHaveTextContent('1192.168.0.109') })
    expect(card('Active clients')).not.toHaveTextContent('internal')
  })

  // The old header said TODAY 1,235 next to TOTAL 1,234; the cards now read
  // one window, the last 24 hours, and an older backend's missing field is
  // said, not drawn as 0.
  it('says Not reported for a figure an older backend does not send', async () => {
    const old: Record<string, unknown> = { ...summaryData }
    delete old.last_24h_requests
    delete old.last_24h_blocked
    delete old.last_24h_clients
    serve({ ...DEFAULT_ROUTES, 'dashboard/summary': old })
    renderWithProviders(<Dashboard />)
    await waitFor(() => { expect(card('Rules in force')).toHaveTextContent('691,701') })
    for (const label of ['Client requests', 'Blocked', 'Active clients']) {
      expect(card(label).querySelector('[data-state="not-reported"]')).toHaveTextContent('Not reported')
    }
  })

  it('has no score, WAF rate, entropy or reset on the overview', async () => {
    renderWithProviders(<Dashboard />)
    await waitFor(() => { expect(card('Client requests')).toHaveTextContent('1,180') })
    expect(screen.queryByText('Score')).toBeNull()
    expect(screen.queryByText(/\/100|\/min|entropy/i)).toBeNull()
    expect(screen.queryByRole('button', { name: /reset/i })).toBeNull()
    expect(vi.mocked(api.get).mock.calls.map((c) => c[0])).not.toContain('security/score')
  })

  // On the test deployment the Recent Blocks list said WAF next to a domain
  // blacklist block: the badge was hard-coded from the 403 status.
  it('labels each latest block with the rule the backend recorded', async () => {
    renderWithProviders(<Dashboard />)
    const latest = await screen.findByRole('region', { name: 'Latest blocks' })
    await waitFor(() => { expect(within(latest).getByText('static.chartbeat.com')).toBeInTheDocument() })
    const row = within(latest).getByText('static.chartbeat.com').closest('li')!
    expect(row).toHaveTextContent('Domain blacklist (DNS)')
    expect(row).toHaveTextContent('192.168.0.109')
    expect(row).not.toHaveTextContent('WAF')
  })

  // recent_blocks timestamps are UTC without a zone marker.
  it('shows a recent block at the viewer time, not at the UTC wall-clock time', async () => {
    vi.useFakeTimers({ toFake: ['Date'], now: Date.UTC(2026, 6, 1, 12, 0, 0) })
    try {
      renderWithProviders(<Dashboard />)
      const latest = await screen.findByRole('region', { name: 'Latest blocks' })
      expect(await within(latest).findByText('09:04:12')).toBeInTheDocument()
    } finally { vi.useRealTimers() }
  })

  it('lists the most blocked destinations as hosts with their rule', async () => {
    renderWithProviders(<Dashboard />)
    const table = await screen.findByRole('table', { name: 'Most blocked destinations in the last 24 hours' })
    await waitFor(() => { expect(within(table).getByText('dpm.demdex.net')).toBeInTheDocument() })
    const rows = within(table).getAllByRole('row').slice(1)
    expect(rows.map((r) => r.textContent)).toEqual([
      'dpm.demdex.netDomain blacklist (DNS)74',
      'example.comUnclassified (no reason recorded)11',
    ])
  })

  it('shows the blocked-by-rule card from blocked_by_reason_24h', async () => {
    renderWithProviders(<Dashboard />)
    const region = await screen.findByRole('region', { name: 'Blocked by rule' })
    await waitFor(() => { expect(within(region).getByText('Domain blacklist (DNS)')).toBeInTheDocument() })
    expect(within(region).getByText('900')).toBeInTheDocument()
    expect(within(region).getByText(/the IP blacklist, the WAF, the direct-IP rule or the egress policy\.$/)).toBeInTheDocument()
  })

  describe('notices', () => {
    // Notice renders role="status" with data-tone; nothing else on the page does.
    const shownNotices = () => [...document.querySelectorAll('[role="status"][data-tone]')]

    it('shows none when the state calls for none', async () => {
      renderWithProviders(<Dashboard />)
      await waitFor(() => { expect(card('Client requests')).toHaveTextContent('1,180') })
      expect(shownNotices()).toEqual([])
    })

    // Only from the proxy's record: no record, no notice.
    it('says the blacklist is blocked at DNS only when the proxy recorded that Squid does not hold it', async () => {
      serve({ ...DEFAULT_ROUTES, 'dashboard/summary': { ...summaryData, squid_domain_acl: { names: 473936, limit: 250000, held: false, written_at: 1 } } })
      renderWithProviders(<Dashboard />)
      const title = await screen.findByText('Blacklisted domains are blocked at DNS only')
      const notice = title.closest('[role="status"]')!
      expect(notice).toHaveTextContent('The list has 473,936 names, above the proxy\'s limit of 250,000 (SPM_SQUID_DOMAIN_ACL_MAX)')
      expect(within(notice as HTMLElement).getByRole('link', { name: 'Open blacklists' })).toHaveAttribute('href', '/blacklists')
    })

    it('shows no DNS-only notice when Squid holds the list', async () => {
      serve({ ...DEFAULT_ROUTES, 'dashboard/summary': { ...summaryData, squid_domain_acl: { names: 12, limit: 250000, held: true, written_at: 1 } } })
      renderWithProviders(<Dashboard />)
      await waitFor(() => { expect(card('Client requests')).toHaveTextContent('1,180') })
      expect(shownNotices()).toEqual([])
    })

    it('says Squid could not load its copy when the proxy recorded a list under the limit as not held', async () => {
      serve({ ...DEFAULT_ROUTES, 'dashboard/summary': { ...summaryData, squid_domain_acl: { names: 12, limit: 250000, held: false, written_at: 1 } } })
      renderWithProviders(<Dashboard />)
      expect(await screen.findByText('Squid could not load its copy of the domain blacklist')).toBeInTheDocument()
      expect(screen.queryByText(/blocked at DNS only/)).toBeNull()
      expect(shownNotices()).toHaveLength(1)
    })

    it('says the WAF refuses the backend credential', async () => {
      serve({ ...DEFAULT_ROUTES, 'dashboard/summary': { ...summaryData, waf: null, waf_status: 'auth_failed' } })
      renderWithProviders(<Dashboard />)
      expect(await screen.findByText('The WAF refuses the backend')).toBeInTheDocument()
      expect(screen.getAllByText(/INTERNAL_ALERT_TOKEN/).length).toBeGreaterThan(0)
    })

    it('says the overview could not be loaded when the summary fails', async () => {
      serve({ ...DEFAULT_ROUTES, 'dashboard/summary': new Error('502') })
      renderWithProviders(<Dashboard />)
      expect(await screen.findByText('The overview could not be loaded')).toBeInTheDocument()
      expect(card('Client requests')).toHaveTextContent('Not reported')
    })
  })

  it('reports the services from the APIs, cache statistics as not collected', async () => {
    renderWithProviders(<Dashboard />)
    const services = await screen.findByRole('region', { name: 'Services' })
    await waitFor(() => { expect(services).toHaveTextContent('Proxy · running') })
    expect(services).toHaveTextContent('Backend · running')
    expect(services).toHaveTextContent('WAF · reporting30 requests inspected')
    expect(services).toHaveTextContent('Cache statistics · not collected')
  })

  it("shows the cache statistics the proxy collected, with when it collected them", async () => {
    serve({ ...DEFAULT_ROUTES, 'cache/statistics': { ...currentCacheStats, uptime_s: 7200 } })
    renderWithProviders(<Dashboard />)
    const services = await screen.findByRole('region', { name: 'Services' })
    await waitFor(() => {
      expect(services).toHaveTextContent('Cache statistics · collectedHit ratio 64.7% (last hour) · 252 KB of 50.0 MB on disk · collected 13:15')
    })
  })

  // toLocaleString followed the browser (50.772 in Italian).
  it('writes every count with en-US grouping in any browser locale', async () => {
    simulateItalianLocale()
    renderWithProviders(<Dashboard />)
    await waitFor(() => { expect(card('Rules in force')).toHaveTextContent('50,772 IPs, 640,929 domains') })
    expect(card('Client requests')).toHaveTextContent('1,180')
  })

  // The Settings Listen tile reads the same helper.
  it('shows the reachable proxy address', async () => {
    renderWithProviders(<Dashboard />)
    expect(await screen.findByText(`${window.location.hostname}:3128`)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Copy proxy address' })).toBeInTheDocument()
  })

  it('has its headings in order and passes axe', async () => {
    const { container } = renderWithProviders(<Dashboard />)
    await waitFor(() => { expect(card('Client requests')).toHaveTextContent('1,180') })
    await screen.findByRole('img', { name: /Requests per hour/ })
    const levels = [...container.querySelectorAll('h1, h2, h3, h4')].map((h) => Number(h.tagName[1]))
    expect(levels[0]).toBe(1)
    for (let i = 1; i < levels.length; i++) expect(levels[i] - levels[i - 1]).toBeLessThanOrEqual(1)
    expect(levels.filter((l) => l === 1)).toHaveLength(1)
    await expectNoAxeViolations(container)
  })
})
