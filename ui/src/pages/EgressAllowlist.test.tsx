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
let refreshHours: string
let entries: unknown[]
let manualTotalOverride: number | null
let providers: unknown[]
let settingsFail: boolean
let providersFail: boolean
const getCalls: { url: string; params?: Record<string, unknown> }[] = []

function routeGet(url: string, config?: { params?: Record<string, unknown> }) {
  getCalls.push({ url, params: config?.params })
  if (url === 'settings') {
    if (settingsFail) return Promise.reject(new Error('down'))
    return Promise.resolve({
      data: {
        status: 'success',
        data: [
          { setting_name: 'egress_default_deny', setting_value: deny },
          { setting_name: 'egress_provider_refresh_hours', setting_value: refreshHours },
          { setting_name: 'proxy_port', setting_value: '3128' },
        ],
      },
    })
  }
  if (url === 'egress-allowlist') {
    const total = manualTotalOverride ?? entries.length
    if (config?.params?.limit === 1) return Promise.resolve({ data: listBody([], total) })
    return Promise.resolve({ data: listBody(entries, total) })
  }
  if (url === 'egress-providers') {
    if (providersFail) return Promise.reject(new Error('providers down'))
    return Promise.resolve({ data: { status: 'success', data: providers } })
  }
  return Promise.resolve({ data: { status: 'success', data: null } })
}

const badRequest = (detail: string) => new AxiosError('400', 'ERR_BAD_REQUEST', undefined, undefined, {
  status: 400, statusText: 'Bad Request', data: { status: 'error', detail }, headers: {}, config: { headers: new AxiosHeaders() },
})

const conflictError = (detail: string) => new AxiosError('409', 'ERR_BAD_REQUEST', undefined, undefined, {
  status: 409, statusText: 'Conflict', data: { status: 'error', detail }, headers: {}, config: { headers: new AxiosHeaders() },
})

describe('EgressAllowlist', () => {
  beforeEach(() => {
    deny = 'false'
    refreshHours = '24'
    entries = rows
    manualTotalOverride = null
    providers = []
    settingsFail = false
    providersFail = false
    getCalls.length = 0
    vi.spyOn(api, 'get').mockImplementation(((url: string, config?: { params?: Record<string, unknown> }) => routeGet(url, config)) as never)
    vi.spyOn(api, 'post').mockResolvedValue({ data: { status: 'success' } } as never)
    vi.spyOn(api, 'put').mockResolvedValue({ data: { status: 'success' } } as never)
    vi.spyOn(api, 'delete').mockResolvedValue({ data: { status: 'success' } } as never)
  })
  afterEach(() => {
    document.documentElement.classList.remove('dark')
    vi.restoreAllMocks()
  })

  it('shows the header, the add form and the list from the mockup, headings in order, with no axe violation', async () => {
    const restoreTz = setRomeTimeZone()
    const { container } = renderWithProviders(<EgressAllowlist />)
    expect(screen.getByRole('heading', { level: 1, name: 'Egress allowlist' })).toBeInTheDocument()
    expect(screen.getByText('With default deny on, clients may reach only the destinations listed here.')).toBeInTheDocument()
    const table = await screen.findByRole('table', { name: 'Allowed destinations' })
    expect(screen.getAllByRole('heading').map((h) => `${h.tagName}:${h.textContent}`)).toEqual([
      'H1:Egress allowlist', 'H2:Add a destination', 'H2:Provider lists', 'H2:Allowed destinations',
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

  it('renders provider lists with catalog metadata, GitHub Actions note, commit link, refresh button and no axe violations in light and dark themes', async () => {
    const restoreTz = setRomeTimeZone()
    refreshHours = '12'
    providers = [
      {
        id: 1, kind: 'catalog', name: 'github', url: '', source: 'api.github.com/meta',
        enabled: true, shared_network: true, v4_count: 512, v6_count: 140,
        ipv4_covered: 42949673, ipv6_64_covered: 140,
        last_refresh: '2026-07-01 09:00:00', last_commit: 'd03d319a255c8899',
        last_error: '', held: null,
      },
      {
        id: 2, kind: 'catalog', name: 'telegram', url: '', source: 'core.telegram.org/resources/cidr.txt',
        enabled: true, shared_network: false, v4_count: 15, v6_count: 8,
        ipv4_covered: 18432, ipv6_64_covered: 8,
        last_refresh: '2026-07-01 09:00:00', last_commit: 'd03d319a255c8899',
        last_error: '', held: null,
      },
      {
        id: 9, kind: 'url', name: 'partner-feed', url: 'https://feeds.example.com/cidr.txt',
        enabled: true, shared_network: false, v4_count: 4, v6_count: 1,
        ipv4_covered: 1024, ipv6_64_covered: 1,
        last_refresh: '2026-07-01 09:00:00', last_commit: '9f86d081884c7d65',
        last_error: '', held: null,
      },
    ]
    const { container } = renderWithProviders(<EgressAllowlist />)
    const pTable = await screen.findByRole('table', { name: 'Provider lists' })
    expect(screen.getByText(/lord-alfred\/ipranges/)).toBeInTheDocument()
    expect(await screen.findByText(/every 12 hours/)).toBeInTheDocument()

    const ghRow = (await within(pTable).findByText('github')).closest('tr')!
    expect(within(ghRow).getByText('Shared network')).toBeInTheDocument()
    expect(within(ghRow).getByText(/GitHub Actions/)).toBeInTheDocument()
    expect(within(ghRow).getByText('42,949,673 (1.0% of IPv4)')).toBeInTheDocument()
    const commitLink = within(ghRow).getByRole('link', { name: 'd03d319' })
    expect(commitLink).toHaveAttribute('href', 'https://github.com/lord-alfred/ipranges/commit/d03d319a255c8899')

    const urlRow = within(pTable).getByText('partner-feed').closest('tr')!
    expect(within(urlRow).getByText('URL')).toBeInTheDocument()
    expect(within(urlRow).getByText('https://feeds.example.com/cidr.txt')).toBeInTheDocument()

    fireEvent.click(within(ghRow).getByRole('button', { name: 'Refresh now: github' }))
    await waitFor(() => expect(api.post).toHaveBeenCalledWith('egress-providers/github/refresh'))

    await expectNoAxeViolations(container)
    document.documentElement.classList.add('dark')
    await expectNoAxeViolations(container)
    restoreTz()
  })

  it('requires confirmation before enabling shared_network providers and uses a danger dialog with IPv4 space percentage for all', async () => {
    providers = [
      {
        id: 0, kind: 'catalog', name: 'amazon', url: '', source: 'ip-ranges.amazonaws.com',
        enabled: false, shared_network: true, v4_count: 0, v6_count: 0,
        ipv4_covered: 100663296, ipv6_64_covered: 0,
        last_refresh: '', last_commit: '', last_error: '', held: null,
      },
      {
        id: 0, kind: 'catalog', name: 'all', url: '', source: 'all upstream directories',
        enabled: false, shared_network: true, v4_count: 0, v6_count: 0,
        ipv4_covered: 429496730, ipv6_64_covered: 0,
        last_refresh: '', last_commit: '', last_error: '', held: null,
      },
      {
        id: 0, kind: 'catalog', name: 'telegram', url: '', source: 'core.telegram.org/resources/cidr.txt',
        enabled: false, shared_network: false, v4_count: 0, v6_count: 0,
        ipv4_covered: 0, ipv6_64_covered: 0,
        last_refresh: '', last_commit: '', last_error: '', held: null,
      },
    ]
    renderWithProviders(<EgressAllowlist />)
    await screen.findByText('amazon')

    // Non-shared provider enables immediately without a dialog.
    fireEvent.click(screen.getByRole('switch', { name: 'Enable telegram' }))
    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument()
    await waitFor(() => expect(api.put).toHaveBeenCalledWith('egress-providers/telegram', { enabled: true }))
    vi.mocked(api.put).mockClear()

    // Shared network provider opens a confirmation dialog; cancelling sends nothing.
    fireEvent.click(screen.getByRole('switch', { name: 'Enable amazon' }))
    const amazonDialog = await screen.findByRole('alertdialog')
    expect(within(amazonDialog).getByText(/100,663,296 IPv4 addresses/)).toBeInTheDocument()
    fireEvent.click(within(amazonDialog).getByRole('button', { name: 'Cancel' }))
    expect(api.put).not.toHaveBeenCalled()

    // Confirming amazon sends confirm_shared: true.
    fireEvent.click(screen.getByRole('switch', { name: 'Enable amazon' }))
    const amazonDialog2 = await screen.findByRole('alertdialog')
    fireEvent.click(within(amazonDialog2).getByRole('button', { name: 'Enable amazon' }))
    await waitFor(() => expect(api.put).toHaveBeenCalledWith('egress-providers/amazon', { enabled: true, confirm_shared: true }))
    vi.mocked(api.put).mockClear()

    // Enabling "all" opens a danger dialog reporting the percentage of the IPv4 space.
    fireEvent.click(screen.getByRole('switch', { name: 'Enable all' }))
    const allDialog = await screen.findByRole('alertdialog')
    expect(within(allDialog).getByText(/10\.0% of the IPv4 address space/)).toBeInTheDocument()
    const confirmBtn = within(allDialog).getByRole('button', { name: 'Enable all' })
    expect(confirmBtn.className).toMatch(/text-danger/)
    fireEvent.click(confirmBtn)
    await waitFor(() => expect(api.put).toHaveBeenCalledWith('egress-providers/all', { enabled: true, confirm_shared: true }))
  })

  it('shows Not downloaded yet instead of 0 / 0, 0.0%, Never, or None when last_refresh is empty, and describes all before first download without invented numbers', async () => {
    providers = [
      {
        id: 0, kind: 'catalog', name: 'all', url: '', source: 'all upstream directories',
        enabled: false, shared_network: true, v4_count: 0, v6_count: 0,
        ipv4_covered: 0, ipv6_64_covered: 0,
        last_refresh: '', last_commit: '', last_error: '', held: null,
      },
    ]
    renderWithProviders(<EgressAllowlist />)
    const pTable = await screen.findByRole('table', { name: 'Provider lists' })
    const allRow = (await within(pTable).findByText('all')).closest('tr')!
    expect(within(allRow).getAllByText('Not downloaded yet').length).toBeGreaterThanOrEqual(1)
    expect(within(allRow).queryByText('0 / 0')).not.toBeInTheDocument()
    expect(within(allRow).queryByText('0 (0.0% of IPv4)')).not.toBeInTheDocument()
    expect(within(allRow).queryByText('Never')).not.toBeInTheDocument()
    expect(within(allRow).queryByText('None')).not.toBeInTheDocument()

    fireEvent.click(within(allRow).getByRole('switch', { name: 'Enable all' }))
    const allDialog = await screen.findByRole('alertdialog')
    expect(within(allDialog).getByText(/after the first download/i)).toBeInTheDocument()
    expect(within(allDialog).getByText(/25%/)).toBeInTheDocument()
    expect(within(allDialog).queryByText(/350 million/i)).not.toBeInTheDocument()
    expect(within(allDialog).queryByText(/8% to 10%/i)).not.toBeInTheDocument()
    fireEvent.click(within(allDialog).getByRole('button', { name: 'Cancel' }))
  })

  it('shows last_error, refresh_error on initial enable, and held updates with confirmation on Apply update', async () => {
    providers = [
      {
        id: 1, kind: 'catalog', name: 'cloudflare', url: '', source: 'cloudflare.com/ips',
        enabled: true, shared_network: true, v4_count: 15, v6_count: 7,
        ipv4_covered: 1048576, ipv6_64_covered: 7,
        last_refresh: '2026-07-01 09:00:00', last_commit: 'aaaa1111',
        last_error: '',
        held: {
          commit: 'bbbb2222', v4_count: 25, v6_count: 7,
          ipv4_covered: 1572864, ipv6_64_covered: 7,
          growth_pct: 50.0, reason: 'IPv4 covered addresses grew by 50.0% (from 1048576 to 1572864)',
          held_at: '2026-07-01 10:00:00',
        },
      },
      {
        id: 2, kind: 'catalog', name: 'oracle', url: '', source: 'public_ip_ranges.json',
        enabled: true, shared_network: true, v4_count: 10, v6_count: 0,
        ipv4_covered: 65536, ipv6_64_covered: 0,
        last_refresh: '2026-07-01 08:00:00', last_commit: 'cccc3333',
        last_error: 'HTTP 503 from raw.githubusercontent.com', held: null,
      },
      {
        id: 0, kind: 'catalog', name: 'telegram', url: '', source: 'core.telegram.org/resources/cidr.txt',
        enabled: false, shared_network: false, v4_count: 0, v6_count: 0,
        ipv4_covered: 0, ipv6_64_covered: 0,
        last_refresh: '', last_commit: '', last_error: '', held: null,
      },
    ]
    renderWithProviders(<EgressAllowlist />)
    expect(await screen.findByText(/HTTP 503 from raw\.githubusercontent\.com/)).toBeInTheDocument()
    expect(screen.getByText(/IPv4 covered addresses grew by 50\.0%/)).toBeInTheDocument()

    // Clicking "Apply update" asks for confirmation first (with before/after numbers) before calling apply-held.
    fireEvent.click(screen.getByRole('button', { name: 'Apply update for cloudflare' }))
    expect(api.post).not.toHaveBeenCalled()
    const holdDialog = await screen.findByRole('alertdialog')
    expect(within(holdDialog).getByText(/50\.0%/)).toBeInTheDocument()
    expect(within(holdDialog).getByText(/1,048,576/)).toBeInTheDocument()
    expect(within(holdDialog).getByText(/1,572,864/)).toBeInTheDocument()
    fireEvent.click(within(holdDialog).getByRole('button', { name: 'Apply update' }))
    await waitFor(() => expect(api.post).toHaveBeenCalledWith('egress-providers/cloudflare/apply-held'))

    // Initial enable returning refresh_error shows a row notice while keeping the provider enabled.
    vi.mocked(api.put).mockResolvedValueOnce({
      data: {
        status: 'success',
        data: {
          id: 3, kind: 'catalog', name: 'telegram', url: '', source: 'core.telegram.org/resources/cidr.txt',
          enabled: true, shared_network: false, v4_count: 0, v6_count: 0,
          ipv4_covered: 0, ipv6_64_covered: 0,
          last_refresh: '', last_commit: '', last_error: '', held: null,
        },
        held: false,
        refresh_error: 'upstream feed timed out',
      },
    } as never)
    fireEvent.click(screen.getByRole('switch', { name: 'Enable telegram' }))
    expect(await screen.findByText(/upstream feed timed out/)).toBeInTheDocument()
  })

  it('adds and deletes custom URL provider lists and shows 400 and 409 errors under the relevant field', async () => {
    providers = [
      {
        id: 11, kind: 'url', name: 'existing-feed', url: 'https://feeds.example.com/ips.txt',
        enabled: true, shared_network: false, v4_count: 3, v6_count: 0,
        ipv4_covered: 768, ipv6_64_covered: 0,
        last_refresh: '2026-07-01 09:00:00', last_commit: '1234567890abcdef',
        last_error: '', held: null,
      },
    ]
    renderWithProviders(<EgressAllowlist />)
    await screen.findByText('existing-feed')

    const labelInput = screen.getByLabelText('List label')
    const urlInput = screen.getByLabelText('List URL')
    const addBtn = screen.getByRole('button', { name: 'Add list' })

    // 400 SSRF error under the URL field.
    vi.mocked(api.post).mockRejectedValueOnce(badRequest('url resolves to a private or disallowed address'))
    fireEvent.change(labelInput, { target: { value: 'internal-feed' } })
    fireEvent.change(urlInput, { target: { value: 'http://127.0.0.1/ips.txt' } })
    fireEvent.click(addBtn)
    expect(await screen.findByText('url resolves to a private or disallowed address')).toBeInTheDocument()
    expect(urlInput).toHaveAttribute('aria-invalid', 'true')
    expect(urlInput).toHaveAccessibleDescription('url resolves to a private or disallowed address')

    // 409 duplicate error under the URL field.
    vi.mocked(api.post).mockRejectedValueOnce(conflictError('a URL provider with that label or URL already exists'))
    fireEvent.change(urlInput, { target: { value: 'https://feeds.example.com/ips.txt' } })
    fireEvent.click(addBtn)
    expect(await screen.findByText('a URL provider with that label or URL already exists')).toBeInTheDocument()
    expect(urlInput).toHaveAttribute('aria-invalid', 'true')

    // Successful creation.
    vi.mocked(api.post).mockResolvedValueOnce({ data: { status: 'success' } } as never)
    fireEvent.change(labelInput, { target: { value: 'partner-cidr' } })
    fireEvent.change(urlInput, { target: { value: 'https://feeds.example.com/partner.txt' } })
    fireEvent.click(addBtn)
    await waitFor(() => expect(api.post).toHaveBeenCalledWith('egress-providers/url', {
      label: 'partner-cidr',
      url: 'https://feeds.example.com/partner.txt',
    }))

    // Deleting a URL provider asks for confirmation first.
    fireEvent.click(screen.getByRole('button', { name: 'Remove existing-feed' }))
    const delDialog = await screen.findByRole('alertdialog')
    fireEvent.click(within(delDialog).getByRole('button', { name: 'Remove' }))
    await waitFor(() => expect(api.delete).toHaveBeenCalledWith('egress-providers/url/11'))
  })

  it('uses the combined manual + provider count in StateNotice and reports when provider reading fails', async () => {
    deny = 'true'
    entries = []
    manualTotalOverride = 12
    providers = [
      {
        id: 1, kind: 'catalog', name: 'telegram', url: '', source: 'core.telegram.org/resources/cidr.txt',
        enabled: true, shared_network: false, v4_count: 5000, v6_count: 200,
        ipv4_covered: 18432, ipv6_64_covered: 8,
        last_refresh: '2026-07-01 09:00:00', last_commit: 'aaaa', last_error: '', held: null,
      },
      {
        id: 2, kind: 'catalog', name: 'cloudflare', url: '', source: 'cloudflare.com/ips',
        enabled: true, shared_network: true, v4_count: 90, v6_count: 5,
        ipv4_covered: 1048576, ipv6_64_covered: 5,
        last_refresh: '2026-07-01 09:00:00', last_commit: 'bbbb', last_error: '', held: null,
      },
    ]
    const { unmount } = renderWithProviders(<EgressAllowlist />)
    expect(await screen.findByText('Default deny is on: clients reach only these 5,307 destinations')).toBeInTheDocument()
    expect(screen.getByText(/12 manual entries and 5,295 from 2 provider lists/)).toBeInTheDocument()
    expect(screen.queryByText(/this list is empty/)).not.toBeInTheDocument()
    unmount()

    // When egress-providers fails to load with 0 manual entries, never claim the allowlist is empty.
    manualTotalOverride = 0
    providersFail = true
    renderWithProviders(<EgressAllowlist />)
    expect(await screen.findByText('Default deny is on, and the size of this list could not be read')).toBeInTheDocument()
    expect(screen.queryByText(/this list is empty/)).not.toBeInTheDocument()
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
