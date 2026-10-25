import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { screen, waitFor, fireEvent, within } from '@testing-library/react'
import { AxiosError, AxiosHeaders } from 'axios'
import { renderWithProviders, setRomeTimeZone } from '../test/helpers'
import { expectNoAxeViolations } from '../test/axe'
import { api } from '../lib/api'
import { checkDestination, egressEntryKind } from '../lib/egress'
import { EgressAllowlist } from './EgressAllowlist'

// The bodies the backend returns: writeList (data + meta) for the list, and
// the settings as rows. Only api.get, api.post and api.delete are stubbed.
const listBody = (data: unknown[], total: number) => ({
  status: 'success', data, meta: { total, limit: 50, offset: 0 }, total: 0, limit: 50, offset: 0,
})

const rows = [
  { id: 3, entry: 'acme-v02.api.letsencrypt.org', type: 'domain', description: 'certificate renewals', added_date: '2026-07-01 09:00:00' },
  { id: 2, entry: '.debian.org', type: 'domain', description: '', added_date: '2026-07-01 08:00:00' },
  { id: 1, entry: '203.0.113.0/24', type: 'cidr', description: null, added_date: '2026-07-01 07:00:00' },
]

let deny: string
let entries: unknown[]
let settingsFail: boolean
const getCalls: { url: string; params?: Record<string, unknown> }[] = []

function routeGet(url: string, config?: { params?: Record<string, unknown> }) {
  getCalls.push({ url, params: config?.params })
  if (url === 'settings') {
    if (settingsFail) return Promise.reject(new Error('down'))
    return Promise.resolve({ data: { status: 'success', data: [{ setting_name: 'egress_default_deny', setting_value: deny }, { setting_name: 'proxy_port', setting_value: '3128' }] } })
  }
  if (url === 'egress-allowlist') {
    if (config?.params?.limit === 1) return Promise.resolve({ data: listBody([], entries.length) })
    return Promise.resolve({ data: listBody(entries, entries.length) })
  }
  return Promise.resolve({ data: { status: 'success', data: null } })
}

const badRequest = (detail: string) => new AxiosError('400', 'ERR_BAD_REQUEST', undefined, undefined, {
  status: 400, statusText: 'Bad Request', data: { status: 'error', detail }, headers: {}, config: { headers: new AxiosHeaders() },
})

describe('EgressAllowlist', () => {
  beforeEach(() => {
    deny = 'false'
    entries = rows
    settingsFail = false
    getCalls.length = 0
    vi.spyOn(api, 'get').mockImplementation(((url: string, config?: { params?: Record<string, unknown> }) => routeGet(url, config)) as never)
    vi.spyOn(api, 'post').mockResolvedValue({ data: { status: 'success' } } as never)
    vi.spyOn(api, 'delete').mockResolvedValue({ data: { status: 'success' } } as never)
  })
  afterEach(() => { vi.restoreAllMocks() })

  it('shows the header, the add form and the list from the mockup, headings in order, with no axe violation', async () => {
    const restoreTz = setRomeTimeZone()
    const { container } = renderWithProviders(<EgressAllowlist />)
    expect(screen.getByRole('heading', { level: 1, name: 'Egress allowlist' })).toBeInTheDocument()
    expect(screen.getByText('With default deny on, clients may reach only the destinations listed here.')).toBeInTheDocument()
    const table = await screen.findByRole('table', { name: 'Allowed destinations' })
    expect(screen.getAllByRole('heading').map((h) => `${h.tagName}:${h.textContent}`)).toEqual([
      'H1:Egress allowlist', 'H2:Add a destination', 'H2:Allowed destinations',
    ])
    // Labels on every field.
    expect(screen.getByLabelText('Kind')).toHaveValue('domain')
    expect(screen.getByLabelText('Destination')).toBeInTheDocument()
    expect(screen.getByLabelText('Note (optional)')).toBeInTheDocument()
    // What each entry allows, the note under it, the time in the viewer's zone.
    const acme = (await within(table).findByText('acme-v02.api.letsencrypt.org')).closest('tr')!
    expect(within(acme).getByText('Exact domain')).toBeInTheDocument()
    expect(within(acme).getByText('certificate renewals')).toBeInTheDocument()
    expect(within(acme).getByText('2026-07-01 11:00:00')).toBeInTheDocument()
    expect(within(within(table).getByText('.debian.org').closest('tr')!).getByText('Domain and its subdomains')).toBeInTheDocument()
    expect(within(within(table).getByText('203.0.113.0/24').closest('tr')!).getByText('Network')).toBeInTheDocument()
    restoreTz()
    await expectNoAxeViolations(container)
  })

  it('says what the domain entries match, as the proxy reads them', () => {
    renderWithProviders(<EgressAllowlist />)
    expect(screen.getByText(/A domain allows that exact name only: example\.com does not cover www\.example\.com\. Start it with a dot, as in \.example\.com,/)).toBeInTheDocument()
  })

  it('with default deny off, says the list has no effect and links to Filtering', async () => {
    renderWithProviders(<EgressAllowlist />)
    const notice = await screen.findByText('Default deny is off, so this list has no effect')
    const box = notice.closest('[role="status"]') as HTMLElement
    expect(within(box).getByRole('link', { name: 'Open Filtering' })).toHaveAttribute('href', '/settings/filtering')
  })

  it('with default deny on and an empty list, says only LAN destinations are reachable, and the empty state says so too', async () => {
    deny = 'true'
    entries = []
    renderWithProviders(<EgressAllowlist />)
    const title = await screen.findByText('Default deny is on and this list is empty: clients reach only LAN destinations')
    const box = title.closest('[role="status"]') as HTMLElement
    expect(box).toHaveAttribute('data-tone', 'danger')
    expect(box).toHaveTextContent('Every destination outside 10.0.0.0/8 and 192.168.0.0/16 is refused, except the addresses on Allowed IPs.')
    expect(await screen.findByText('No destination yet')).toBeInTheDocument()
    expect(screen.getByText(/Default deny is on, so every client reaches only LAN destinations/)).toBeInTheDocument()
  })

  it('with default deny off and an empty list, warns about turning it on before adding destinations', async () => {
    entries = []
    renderWithProviders(<EgressAllowlist />)
    expect(await screen.findByText('No destination yet')).toBeInTheDocument()
    expect(screen.getByText('If you turn default deny on with an empty list, every client loses access to everything except the LAN. Add what your clients need first.')).toBeInTheDocument()
  })

  it('with default deny on, counts the destinations from meta.total', async () => {
    deny = 'true'
    renderWithProviders(<EgressAllowlist />)
    expect(await screen.findByText('Default deny is on: clients reach only these 3 destinations')).toBeInTheDocument()
  })

  it('says what is missing when the settings do not load', async () => {
    settingsFail = true
    renderWithProviders(<EgressAllowlist />)
    expect(await screen.findByText('Whether default deny is on could not be read')).toBeInTheDocument()
  })

  it('adds a destination with its note, and checks the kind at the field before sending', async () => {
    renderWithProviders(<EgressAllowlist />)
    const dest = screen.getByLabelText('Destination')
    fireEvent.change(dest, { target: { value: '203.0.113.7' } })
    fireEvent.click(screen.getByRole('button', { name: 'Add' }))
    expect(await screen.findByText('This is an address: choose IP or network as the kind.')).toBeInTheDocument()
    expect(dest).toHaveAttribute('aria-invalid', 'true')
    expect(dest).toHaveAccessibleDescription('This is an address: choose IP or network as the kind.')
    expect(api.post).not.toHaveBeenCalled()

    fireEvent.change(screen.getByLabelText('Kind'), { target: { value: 'ip' } })
    fireEvent.change(screen.getByLabelText('Note (optional)'), { target: { value: 'office VPN' } })
    fireEvent.click(screen.getByRole('button', { name: 'Add' }))
    await waitFor(() => expect(api.post).toHaveBeenCalledWith('egress-allowlist', { entry: '203.0.113.7', description: 'office VPN' }))
    await waitFor(() => expect(dest).toHaveValue(''))
  })

  it('shows the backend refusal at the field it concerns', async () => {
    vi.mocked(api.post).mockRejectedValueOnce(badRequest('entry already in allowlist'))
    renderWithProviders(<EgressAllowlist />)
    const dest = screen.getByLabelText('Destination')
    fireEvent.change(dest, { target: { value: 'acme-v02.api.letsencrypt.org' } })
    fireEvent.click(screen.getByRole('button', { name: 'Add' }))
    expect(await screen.findByText('entry already in allowlist')).toBeInTheDocument()
    expect(dest).toHaveAccessibleDescription('entry already in allowlist')

    vi.mocked(api.post).mockRejectedValueOnce(badRequest('description: must be at most 500 characters'))
    fireEvent.click(screen.getByRole('button', { name: 'Add' }))
    expect(await screen.findByText('description: must be at most 500 characters')).toBeInTheDocument()
    expect(screen.getByLabelText('Note (optional)')).toHaveAttribute('aria-invalid', 'true')
  })

  it('removes an entry after a confirmation that names it', async () => {
    deny = 'true'
    renderWithProviders(<EgressAllowlist />)
    await screen.findByText('Default deny is on: clients reach only these 3 destinations')
    fireEvent.click(await screen.findByRole('button', { name: 'Remove 203.0.113.0/24' }))
    const dialog = await screen.findByRole('alertdialog')
    expect(within(dialog).getByText('Remove 203.0.113.0/24?')).toBeInTheDocument()
    expect(within(dialog).getByText(/clients can no longer reach 203\.0\.113\.0\/24/)).toBeInTheDocument()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Remove' }))
    await waitFor(() => expect(api.delete).toHaveBeenCalledWith('egress-allowlist/1'))
  })

  it('searches on the backend', async () => {
    renderWithProviders(<EgressAllowlist />)
    fireEvent.change(screen.getByRole('searchbox', { name: 'Search the egress allowlist' }), { target: { value: 'debian' } })
    await waitFor(() => expect(getCalls.some((c) => c.url === 'egress-allowlist' && c.params?.search === 'debian')).toBe(true))
  })
})

describe('checkDestination', () => {
  it('accepts what the backend accepts for each kind and names the mistake otherwise', () => {
    expect(checkDestination('domain', 'Example.COM')).toBeNull()
    expect(checkDestination('domain', '.example.com')).toBeNull()
    expect(checkDestination('domain', '*.example.com')).toMatch(/^Write \.example\.com, with a leading dot/)
    expect(checkDestination('domain', '10.0.0.1')).toBe('This is an address: choose IP or network as the kind.')
    expect(checkDestination('domain', 'bad name')).toMatch(/is not a domain name/)
    expect(checkDestination('ip', '203.0.113.0/24')).toBeNull()
    expect(checkDestination('ip', '2001:db8::/32')).toBeNull()
    expect(checkDestination('ip', 'example.com')).toBe('This is a domain name: choose Domain as the kind.')
    expect(checkDestination('ip', '300.1.1.1')).toMatch(/is not an IP address or network/)
    expect(checkDestination('ip', '  ')).toBe('Enter a destination.')
  })

  it('names what an entry allows', () => {
    expect(egressEntryKind({ entry: 'a.example', type: 'domain' })).toBe('Exact domain')
    expect(egressEntryKind({ entry: '.a.example', type: 'domain' })).toBe('Domain and its subdomains')
    expect(egressEntryKind({ entry: '192.0.2.1', type: 'cidr' })).toBe('IP address')
  })
})
