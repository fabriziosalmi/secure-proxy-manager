import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import { renderWithProviders, simulateItalianLocale, setRomeTimeZone } from '../test/helpers'
import { expectNoAxeViolations } from '../test/axe'
import { api } from '../lib/api'
import type { BlockedByDay, Coverage } from '../types'
import { Analytics } from './Analytics'

// The bodies the endpoints really return (backend-go/internal/handlers:
// analytics_daily.go, analytics_coverage.go, analytics.go). Only api.get is
// stubbed, so the page's own unwrapping runs as in production.
const DAYS = ['19', '20', '21', '22', '23', '24', '25']
const blockedByDay: BlockedByDay = {
  tz: 'Europe/Rome',
  days: DAYS.map((d, i) => ({
    date: `2026-10-${d}`,
    start: 1792360800 + i * 86400,
    end: 1792360800 + (i + 1) * 86400,
    blocked: d === '25' ? 1323 : 0,
    reasons: d === '25'
      ? [
          { reason: 'unclassified', label: 'Unclassified (no reason recorded)', count: 1300 },
          { reason: 'domain_blacklist_dns', label: 'Domain blacklist (DNS)', count: 22 },
          { reason: 'waf', label: 'WAF', count: 1 },
        ]
      : [],
  })),
  reasons: [
    { reason: 'unclassified', label: 'Unclassified (no reason recorded)', count: 1300 },
    { reason: 'domain_blacklist_dns', label: 'Domain blacklist (DNS)', count: 22 },
    { reason: 'waf', label: 'WAF', count: 1 },
  ],
  internal_sources: 2,
}

const coverage: Coverage = {
  domain_blacklist: { entries: 640929, squid_acl: null },
  ip_blacklist: { entries: 50772, squid_acl: { entries: 50772, networks: 48000, dropped: 0, written_at: 1 } },
  waf: { status: 'ok', categories: 4, categories_enabled: 4, rules: 31, rules_enabled: 31 },
  https_inspection: false,
  proxy_login: false,
  alerts: { enabled: false, channels: 0, waf_alerts_delivered: true },
}

const summary = {
  waf_status: 'ok',
  waf: { total_requests: 1030, total_blocked: 1, avg_url_entropy: 2, high_entropy_count: 0, requests_last_minute: 0, top_blocked_categories: [{ key: 'SQL injection', count: 1 }] },
  top_blocked: [{ dest: 'malware.example', count: 1328, reasons: [] }],
  recent_blocks: [{ timestamp: '2026-10-25 09:00:00', destination: 'live-feed.example', host: 'live-feed.example' }],
}

const bodies: Record<string, unknown> = {
  'analytics/blocked-by-day': blockedByDay,
  'analytics/coverage': coverage,
  'dashboard/summary': summary,
  'analytics/shadow-it': [{ name: 'Facebook', domain: 'facebook.com', requests: 1328, category: 'Social' }],
  'analytics/user-agents': { methods: [], service_types: [{ name: 'Other', count: 50772 }, { name: 'CDN', count: 230 }] },
  'analytics/file-extensions': { extensions: [{ ext: '.js', count: 12 }, { ext: '.png', count: 3 }], categories: [{ category: 'Web', count: 12 }, { category: 'Images', count: 3 }], examined: 40, limit: 10000 },
}

let failing = new Set<string>()
const calls: string[] = []

function serve() {
  vi.spyOn(api, 'get').mockImplementation((url: string) => {
    calls.push(url)
    const key = url.split('?')[0]
    if (failing.has(key)) return Promise.reject(new Error('Network Error'))
    return Promise.resolve({ data: { status: 'success', data: bodies[key] ?? null } })
  })
}

const region = (name: string) => screen.getByRole('region', { name })

describe('Analytics', () => {
  let restoreTz: () => void
  beforeEach(() => {
    failing = new Set()
    calls.length = 0
    restoreTz = setRomeTimeZone()
    serve()
  })
  afterEach(() => {
    vi.restoreAllMocks()
    restoreTz()
  })

  it('shows the sections of the mockup, headings in order, and nothing the Overview already has', async () => {
    renderWithProviders(<Analytics />)
    expect(screen.getByRole('heading', { level: 1, name: 'Analytics' })).toBeInTheDocument()
    expect(screen.getByText('Last 7 days, client traffic only. Times are your local time.')).toBeInTheDocument()
    await waitFor(() => { expect(screen.getByRole('img', { name: /^Blocked requests per day/ })).toBeInTheDocument() })
    expect(screen.getAllByRole('heading', { level: 2 }).map((h) => h.textContent)).toEqual([
      'Blocked requests per day, by rule',
      'Protection coverage',
      'WAF categories',
      'Cloud services in use',
      'Traffic by kind of service',
      'Downloads by file type',
    ])
    // The Overview's lists, the word cloud, the old cards and the playground are gone.
    for (const gone of ['Top Blocked', 'Live Feed', 'Top Domains', 'Regex Playground', 'Shadow IT', 'Threat Timeline (72h)', 'Score', 'Entropy Alerts']) {
      expect(screen.queryByText(gone)).toBeNull()
    }
    expect(screen.queryByText('malware.example')).toBeNull()
    expect(screen.queryByText('live-feed.example')).toBeNull()
    expect(calls).not.toContain('analytics/top-domains')
    expect(calls).not.toContain('security/score')
    expect(screen.getByRole('link', { name: 'Last 24 hours: Overview' })).toHaveAttribute('href', '/')
    expect(screen.getByRole('link', { name: 'Every request: Access logs' })).toHaveAttribute('href', '/logs')
  })

  it('asks for the days of the viewer time zone and draws every day, the empty ones as zero', async () => {
    renderWithProviders(<Analytics />)
    await waitFor(() => { expect(screen.getByTestId('day-bars')).toBeInTheDocument() })
    expect(calls).toContain('analytics/blocked-by-day?tz=Europe%2FRome')
    const days = [...screen.getByTestId('day-bars').querySelectorAll('[data-day]')]
    expect(days.map((d) => d.getAttribute('data-day'))).toEqual(DAYS.map((d) => `2026-10-${d}`))
    for (const d of days.slice(0, 6)) expect(d.querySelectorAll('[data-series]')).toHaveLength(0)
    // Bottom first: the rules in their fixed order, then the rows with no reason.
    const today = [...days[6].querySelectorAll('[data-series]')]
    expect(today.map((s) => [s.getAttribute('data-series'), s.getAttribute('data-count')])).toEqual([
      ['domain_blacklist_dns', '22'], ['waf', '1'], ['unclassified', '1300'],
    ])
    expect(today.map((s) => s.className.match(/bg-[a-z0-9-]+/)?.[0])).toEqual(['bg-series-1', 'bg-series-2', 'bg-chart-neutral'])
    const chart = region('Blocked requests per day, by rule')
    // The legend names each rule by the API label.
    for (const label of ['Domain blacklist (DNS)', 'WAF', 'Unclassified (no reason recorded)']) expect(within(chart).getAllByText(label).length).toBeGreaterThan(0)
    expect(screen.getByRole('img', { name: /^Blocked requests per day/ })).toHaveAccessibleName(
      'Blocked requests per day, today and the 6 days before: today 1,323 (1,300 Unclassified (no reason recorded), 22 Domain blacklist (DNS), 1 WAF); none on the other 6 days.',
    )
    expect(within(chart).getByText(/midnight to midnight in your time zone \(Europe\/Rome\)\. 1,323 blocked in all\. Requests from 2 internal addresses are not counted\./)).toBeInTheDocument()
    // The table has every day, the empty ones as None.
    const rows = within(within(chart).getByRole('table', { name: 'Blocked requests on each of the last 7 days' })).getAllByRole('row').slice(1)
    expect(rows).toHaveLength(7)
    expect(rows[0]).toHaveTextContent('Mon 19 2026-10-19None0')
    expect(rows[6]).toHaveTextContent('Sun 25 2026-10-251,300 Unclassified (no reason recorded), 22 Domain blacklist (DNS), 1 WAF1,323')
  })

  it('says what is switched on from analytics/coverage, each line linking to its setting', async () => {
    renderWithProviders(<Analytics />)
    const cov = region('Protection coverage')
    await waitFor(() => { expect(within(cov).getAllByRole('listitem')).toHaveLength(6) })
    expect(within(cov).getByText("Domain blacklist: 640,929 entries, blocked at the DNS sinkhole; the proxy has not reported whether it holds its own copy")).toBeInTheDocument()
    expect(within(cov).getByText('IP blacklist: 50,772 entries, enforced by the proxy as 48,000 networks')).toBeInTheDocument()
    expect(within(cov).getByText('WAF: 31 request rules in 4 categories, inspecting plain HTTP only')).toBeInTheDocument()
    expect(within(cov).getByText('Alerts: off, blocks are not reported anywhere')).toBeInTheDocument()
    const blacklistLinks = within(cov).getAllByRole('link', { name: 'Blacklists' })
    expect(blacklistLinks[0]).toHaveAttribute('href', '/blacklists?tab=blocked-domains')
    expect(blacklistLinks[1]).toHaveAttribute('href', '/blacklists')
    expect(within(cov).getByRole('link', { name: 'Alerts' })).toHaveAttribute('href', '/settings/alerts')
  })

  it('shows the WAF counters with their window, and the three 7-day sections with what they count', async () => {
    renderWithProviders(<Analytics />)
    const waf = region('WAF categories')
    await waitFor(() => { expect(within(waf).getByText('Since the WAF last started or its counters were reset, 1,030 requests inspected.')).toBeInTheDocument() })
    expect(within(waf).getByText('SQL injection')).toBeInTheDocument()
    expect(within(waf).getByText(/No other category matched\. 1 of the inspected requests were blocked\./)).toBeInTheDocument()

    const svc = region('Cloud services in use')
    expect(svc).toHaveTextContent('Client requests in the last 7 days to services recognised by their host name.')
    await waitFor(() => { expect(within(svc).getByRole('table', { name: 'Cloud services in use in the last 7 days' })).toHaveTextContent('FacebookSocial1,328') })

    const kinds = region('Traffic by kind of service')
    expect(kinds).toHaveTextContent(/Client requests in the last 7 days, grouped by words in the host name/)
    await waitFor(() => { expect(within(kinds).getByRole('list', { name: 'Client requests by kind of service' })).toHaveTextContent('Other50,772CDN230') })

    const files = region('Downloads by file type')
    expect(files).toHaveTextContent('HTTPS that is not inspected shows no URL to the proxy and is not counted.')
    await waitFor(() => { expect(within(files).getByText('15 downloads.')).toBeInTheDocument() })
    expect(within(files).getByText('Extensions: .js 12, .png 3.')).toBeInTheDocument()
  })

  it('says which part is missing when an endpoint does not answer, or the WAF refuses the backend', async () => {
    failing = new Set(['analytics/blocked-by-day', 'analytics/coverage', 'analytics/user-agents'])
    bodies['dashboard/summary'] = { ...summary, waf: null, waf_status: 'auth_failed' }
    try {
      renderWithProviders(<Analytics />)
      await waitFor(() => { expect(within(region('Blocked requests per day, by rule')).getByRole('alert')).toHaveTextContent('Could not load the daily counts (analytics/blocked-by-day).') })
      await waitFor(() => { expect(within(region('Protection coverage')).getByRole('alert')).toHaveTextContent('Not reported: analytics/coverage did not answer.') })
      await waitFor(() => { expect(within(region('Traffic by kind of service')).getByRole('alert')).toHaveTextContent('Not reported: analytics/user-agents did not answer.') })
      await waitFor(() => { expect(within(region('WAF categories')).getByRole('alert')).toHaveTextContent('Not available: the WAF refuses the backend credential.') })
    } finally {
      bodies['dashboard/summary'] = summary
    }
  })

  // The backend used to send null lists for a window with no file request,
  // and the page fell into its error boundary (reduce of null).
  it('says there was no request for a file when the lists are empty or null', async () => {
    const saved = bodies['analytics/file-extensions']
    bodies['analytics/file-extensions'] = { extensions: null, categories: null, examined: 0, limit: 10000 }
    try {
      renderWithProviders(<Analytics />)
      await waitFor(() => { expect(within(region('Downloads by file type')).getByText('No request for a file in the last 7 days.')).toBeInTheDocument() })
      expect(screen.getByRole('heading', { level: 2, name: 'Protection coverage' })).toBeInTheDocument()
    } finally {
      bodies['analytics/file-extensions'] = saved
    }
  })

  it('writes every count with en-US grouping in any browser locale', async () => {
    simulateItalianLocale()
    renderWithProviders(<Analytics />)
    await waitFor(() => { expect(within(region('Protection coverage')).getByText('IP blacklist: 50,772 entries, enforced by the proxy as 48,000 networks')).toBeInTheDocument() })
    await waitFor(() => { expect(within(region('Cloud services in use')).getByRole('table')).toHaveTextContent('1,328') })
  })

  it('has no axe violations', async () => {
    const { container } = renderWithProviders(<Analytics />)
    await waitFor(() => { expect(screen.getByTestId('day-bars')).toBeInTheDocument() })
    await waitFor(() => { expect(within(region('Protection coverage')).getAllByRole('listitem')).toHaveLength(6) })
    await waitFor(() => { expect(within(region('Downloads by file type')).getByText('15 downloads.')).toBeInTheDocument() })
    await expectNoAxeViolations(container)
  })
})
