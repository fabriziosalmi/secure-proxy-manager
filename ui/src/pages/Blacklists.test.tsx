import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { screen, waitFor, fireEvent, within, act } from '@testing-library/react'
import { AxiosError, AxiosHeaders } from 'axios'
import { renderWithProviders, simulateItalianLocale, setRomeTimeZone } from '../test/helpers'
import { expectNoAxeViolations } from '../test/axe'
import toast from 'react-hot-toast'
import { api } from '../lib/api'
import { Blacklists } from './Blacklists'

// The bodies the backend really returns: writeList (data + meta) for the
// lists and their sources, writeOK for the enforcement record. Only api.get,
// api.post and api.delete are stubbed, so the page's unwrapping runs as in
// production.
type Body = Record<string, unknown>
const listBody = (data: unknown[], total: number): Body => ({
  status: 'success', data, meta: { total, limit: 50, offset: 0 }, total: 0, limit: 50, offset: 0,
})

const ipEntries = [
  { id: 1, ip: '10.0.0.1', description: 'Imported on 2026-10-25', added_date: '2026-10-25 08:00:00', source_id: null, source_kind: null, source: null, source_label: null },
  { id: 2, ip: '198.51.100.0/24', description: 'scanner seen at the edge', added_date: '2026-10-25 09:00:00', source_id: 3, source_kind: 'manual', source: '', source_label: '' },
  { id: 3, ip: '203.0.113.0/24', description: '', added_date: '2026-10-25 10:00:00', source_id: 7, source_kind: 'url', source: 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset', source_label: 'Firehol Level 1' },
  { id: 4, ip: '2.32.0.0/16', description: '', added_date: '2026-10-25 11:00:00', source_id: 8, source_kind: 'geo', source: 'CN', source_label: '' },
  { id: 5, ip: '192.0.2.9', description: '', added_date: '2026-10-25 12:00:00', source_id: 9, source_kind: 'paste', source: '', source_label: '' },
]
const ipSources = [
  { id: 7, kind: 'url', source: 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset', label: 'Firehol Level 1', entries: 4521, first_added: '2026-10-25 10:00:00', last_added: '2026-10-25 10:02:00' },
  { id: 3, kind: 'manual', source: '', label: '', entries: 1, first_added: '2026-10-25 09:00:00', last_added: '2026-10-25 09:00:00' },
  { id: null, kind: 'unrecorded', source: '', label: '', entries: 50772, first_added: '2026-10-25 08:00:00', last_added: '2026-10-25 08:02:00' },
]
const enforcementBody = {
  dns_blocklist_limit: 1000000,
  domain_blacklist_entries: 640929,
  domain_blacklist_on_allowed: 3,
  squid_domain_acl: { names: 473936, limit: 250000, held: false, written_at: 1792900000 },
  squid_ip_blacklist: { entries: 50772, networks: 32215, dropped: 0, written_at: 1792900000 },
  squid_ip_whitelist: null,
}

let counts: Record<string, number>
let entries: Record<string, unknown[]>
let sources: Record<string, unknown[]>
let enforcement: Body | null
const getCalls: string[] = []

function routeGet(url: string) {
  getCalls.push(url)
  if (url === 'blacklists/enforcement') return Promise.resolve({ data: { status: 'success', data: enforcement } })
  const m = url.match(/^(ip-blacklist|domain-blacklist|ip-whitelist|domain-whitelist)(\/sources|\/export)?(\?.*)?$/)
  if (!m) return Promise.resolve({ data: { status: 'success', data: null } })
  const [, path, sub, qs] = m
  if (sub === '/sources') return Promise.resolve({ data: listBody(sources[path] ?? [], (sources[path] ?? []).length) })
  if (sub === '/export') return Promise.resolve({ data: '10.0.0.1\n198.51.100.0/24\n' })
  if (qs?.includes('limit=1&') || qs === '?limit=1') return Promise.resolve({ data: listBody([], counts[path] ?? 0) })
  return Promise.resolve({ data: listBody(entries[path] ?? [], counts[path] ?? 0) })
}

function go(search: string) {
  window.history.replaceState(null, '', `/blacklists${search}`)
}

describe('Blacklists', () => {
  beforeEach(() => {
    counts = { 'ip-blacklist': 5, 'domain-blacklist': 0, 'ip-whitelist': 0, 'domain-whitelist': 0 }
    entries = { 'ip-blacklist': ipEntries }
    sources = { 'ip-blacklist': ipSources }
    enforcement = enforcementBody
    getCalls.length = 0
    go('')
    vi.spyOn(api, 'get').mockImplementation(((url: string) => routeGet(url)) as never)
    vi.spyOn(api, 'post').mockResolvedValue({ data: { status: 'success', data: { added: 2, skipped: 0 } } } as never)
    vi.spyOn(api, 'delete').mockResolvedValue({ data: { status: 'success', data: { removed: 4521 } } } as never)
  })
  afterEach(() => { vi.restoreAllMocks() })

  it('shows the header from the mockup, four tabs and the sections, with headings in order', async () => {
    renderWithProviders(<Blacklists />)
    expect(screen.getByRole('heading', { level: 1, name: 'Blacklists' })).toBeInTheDocument()
    expect(screen.getByText('Protection')).toBeInTheDocument()
    expect(screen.getAllByRole('tab').map((t) => t.textContent?.replace(/[\d,]/g, ''))).toEqual(['Blocked IPs', 'Blocked domains', 'Allowed IPs', 'Allowed domains'])
    expect(screen.getByRole('tab', { name: /Blocked IPs/ })).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByRole('tabpanel')).toHaveAttribute('aria-labelledby', 'bl-tab-blocked-ips')
    await screen.findByText('10.0.0.1')
    const levels = screen.getAllByRole('heading').map((h) => Number(h.tagName.slice(1)))
    expect(levels[0]).toBe(1)
    expect(levels.slice(1).every((l) => l === 2)).toBe(true)
    expect(screen.getAllByRole('heading', { level: 2 }).map((h) => h.textContent)).toEqual([
      'Enforcement', 'Where the entries came from', 'Entries', 'Remove every entry on this list',
    ])
    expect(screen.getByRole('button', { name: 'Add entries' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Export' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Popular lists' })).toBeInTheDocument()
  })

  it('counts each tab from meta.total, in en-US grouping in any browser locale', async () => {
    simulateItalianLocale()
    counts = { 'ip-blacklist': 50772, 'domain-blacklist': 640929, 'ip-whitelist': 2, 'domain-whitelist': 0 }
    renderWithProviders(<Blacklists />)
    await waitFor(() => expect(screen.getByRole('tab', { name: /Blocked IPs/ })).toHaveTextContent('50,772'))
    expect(screen.getByRole('tab', { name: /Blocked domains/ })).toHaveTextContent('640,929')
    expect(screen.getByRole('tab', { name: /Allowed IPs/ })).toHaveTextContent('2')
    // The deprecated top-level total is 0 in every body here: it is not read.
    expect(screen.getByRole('tab', { name: /Allowed domains/ })).toHaveTextContent('0')
  })

  it('keeps the tab in the URL, so a link opens it and Back returns to the one before', async () => {
    go('?tab=blocked-domains')
    renderWithProviders(<Blacklists />)
    expect(screen.getByRole('tab', { name: /Blocked domains/ })).toHaveAttribute('aria-selected', 'true')
    await waitFor(() => expect(getCalls).toContain('domain-blacklist/sources'))

    fireEvent.click(screen.getByRole('tab', { name: /Allowed IPs/ }))
    expect(window.location.search).toBe('?tab=allowed-ips')
    expect(screen.getByRole('tab', { name: /Allowed IPs/ })).toHaveAttribute('aria-selected', 'true')

    await act(async () => {
      window.history.back()
      await new Promise((r) => setTimeout(r, 50))
    })
    await waitFor(() => expect(screen.getByRole('tab', { name: /Blocked domains/ })).toHaveAttribute('aria-selected', 'true'))
  })

  it('moves between tabs with the arrow keys', () => {
    renderWithProviders(<Blacklists />)
    const first = screen.getByRole('tab', { name: /Blocked IPs/ })
    fireEvent.keyDown(first, { key: 'ArrowRight' })
    expect(screen.getByRole('tab', { name: /Blocked domains/ })).toHaveAttribute('aria-selected', 'true')
    expect(document.activeElement).toBe(screen.getByRole('tab', { name: /Blocked domains/ }))
    fireEvent.keyDown(document.activeElement!, { key: 'End' })
    expect(screen.getByRole('tab', { name: /Allowed domains/ })).toHaveAttribute('aria-selected', 'true')
  })

  it('lists each entry with its kind, its source and when it was added, in the viewer time zone', async () => {
    const restoreTz = setRomeTimeZone()
    try {
      renderWithProviders(<Blacklists />)
      const table = await screen.findByRole('table', { name: 'Blocked IPs entries' })
      await within(table).findByText('10.0.0.1')
      const row = (value: string) => within(table).getByText(value).closest('tr')!
      // An entry is set in mono; a typed description shows under it, the old
      // "Imported on <date>" stamp (the date column again) does not.
      expect(within(table).getByText('10.0.0.1').tagName).toBe('CODE')
      expect(within(table).queryByText('Imported on 2026-10-25')).not.toBeInTheDocument()
      expect(within(row('198.51.100.0/24')).getByText('scanner seen at the edge')).toBeInTheDocument()

      expect(within(row('10.0.0.1')).getByText('IP')).toBeInTheDocument()
      expect(within(row('198.51.100.0/24')).getByText('Network /24')).toBeInTheDocument()

      expect(within(row('10.0.0.1')).getByText('Source not recorded')).toBeInTheDocument()
      expect(within(row('198.51.100.0/24')).getByText('Manual')).toBeInTheDocument()
      expect(within(row('203.0.113.0/24')).getByText('Firehol Level 1')).toBeInTheDocument()
      expect(within(row('2.32.0.0/16')).getByText('GeoIP: CN')).toBeInTheDocument()
      expect(within(row('192.0.2.9')).getByText('Pasted list')).toBeInTheDocument()

      // Rome leaves summer time at 01:00 UTC on 25 October 2026, so 08:00 UTC
      // is 09:00 there.
      expect(within(row('10.0.0.1')).getByText('2026-10-25 09:00')).toBeInTheDocument()
      expect(within(table).getAllByRole('button', { name: /^Remove / }).map((b) => b.getAttribute('aria-label'))).toEqual([
        'Remove 10.0.0.1', 'Remove 198.51.100.0/24', 'Remove 203.0.113.0/24', 'Remove 2.32.0.0/16', 'Remove 192.0.2.9',
      ])
      expect(screen.getByText('1 to 5 of 5')).toBeInTheDocument()
    } finally { restoreTz() }
  })

  it('searches the list on the backend from a search field with the search icon', async () => {
    const { container } = renderWithProviders(<Blacklists />)
    const box = screen.getByRole('searchbox', { name: 'Search Blocked IPs' })
    expect(box).toHaveAttribute('placeholder', 'Search IPs and networks')
    expect(container.querySelector('label svg.lucide-search')).not.toBeNull()
    expect(container.querySelector('svg.lucide-ban')).toBeNull()
    fireEvent.change(box, { target: { value: '203.0' } })
    await waitFor(() => expect(getCalls).toContain('ip-blacklist?limit=50&offset=0&search=203.0'))
  })

  it('pages through the list 50 at a time: "1 to 50 of 50,772"', async () => {
    counts['ip-blacklist'] = 50772
    entries['ip-blacklist'] = Array.from({ length: 50 }, (_, i) => ({ ...ipEntries[0], id: 100 + i, ip: `203.0.113.${i}` }))
    renderWithProviders(<Blacklists />)
    expect(await screen.findByText('1 to 50 of 50,772')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Next' }))
    await waitFor(() => expect(getCalls).toContain('ip-blacklist?limit=50&offset=50&search='))
  })

  describe('Enforcement', () => {
    it('blocked domains: the DNS sinkhole holds every name, and whether Squid holds its own copy is the proxy record', async () => {
      go('?tab=blocked-domains')
      counts['domain-blacklist'] = 640929
      renderWithProviders(<Blacklists />)
      const section = (await screen.findByRole('heading', { name: 'Enforcement' })).closest('section')!
      await within(section).findByText('640,929')
      expect(within(section).getByText('473,936')).toBeInTheDocument()
      expect(within(section).getByText('Every entry but the 3 on Allowed domains')).toBeInTheDocument()
      expect(within(section).getByText('No copy: 473,936 names is over its limit of 250,000 (SPM_SQUID_DOMAIN_ACL_MAX)')).toBeInTheDocument()
      expect(within(section).getByText('1,000,000 entries (SPM_DNS_BLOCKLIST_MAX_DOMAINS)')).toBeInTheDocument()
      // The semantics db.go (EnforcedDomain) and the watchdog implement: "*."
      // and a leading dot are dropped, the exact name is blocked.
      expect(within(section).getByText(/"\*\.example\.com" and "\.example\.com" each block example\.com itself, in the DNS sinkhole and in Squid alike/)).toBeInTheDocument()
    })

    it('blocked domains: a held copy, and no record at all, are each said as they are', async () => {
      go('?tab=blocked-domains')
      enforcement = { ...enforcementBody, domain_blacklist_on_allowed: 0, squid_domain_acl: { names: 12, limit: 250000, held: true, written_at: 1 } }
      const { unmount } = renderWithProviders(<Blacklists />)
      expect(await screen.findByText('Its own copy of all 12 names')).toBeInTheDocument()
      expect(screen.getByText('Every entry')).toBeInTheDocument()
      unmount()
      enforcement = { ...enforcementBody, squid_domain_acl: null }
      renderWithProviders(<Blacklists />)
      expect(await screen.findByText('Not reported: the proxy has not written domain_acl_status.json')).toBeInTheDocument()
      expect(screen.queryByText('Distinct names')).not.toBeInTheDocument()
    })

    it('blocked IPs: the networks Squid loads after merging come from the proxy record, never a guess', async () => {
      renderWithProviders(<Blacklists />)
      const section = (await screen.findByRole('heading', { name: 'Enforcement' })).closest('section')!
      expect(await within(section).findByText('32,215')).toBeInTheDocument()
      expect(within(section).getByText(/merged from 50,772 entries, recorded/)).toBeInTheDocument()
      expect(within(section).getByText(/Squid checks this list before Allowed IPs, so an address on both stays blocked/)).toBeInTheDocument()
    })

    it('says "Not reported" when the proxy has written no IP record', async () => {
      enforcement = { ...enforcementBody, squid_ip_blacklist: null }
      renderWithProviders(<Blacklists />)
      expect(await screen.findByText('Not reported: the proxy has not written ip_blacklist_acl_status.json')).toBeInTheDocument()
    })

    it('allowed domains: says which blocked forms a name takes out, as the exporter does', async () => {
      go('?tab=allowed-domains')
      renderWithProviders(<Blacklists />)
      // db.go loadWhitelistSet compares EnforcedDomain of both sides.
      expect(await screen.findByText(/example\.com also takes out \*\.example\.com and \.example\.com, which block example\.com itself\. It does not cover subdomains/)).toBeInTheDocument()
    })

    it('allowed IPs: says the blocked lists are checked first', async () => {
      go('?tab=allowed-ips')
      renderWithProviders(<Blacklists />)
      expect(await screen.findByText(/It checks Blocked IPs and Blocked domains first, so an entry here does not override them/)).toBeInTheDocument()
      expect(screen.getByText('Not reported: the proxy has not written ip_whitelist_acl_status.json')).toBeInTheDocument()
    })
  })

  describe('Where the entries came from', () => {
    it('lists each source with its entries and when they were added', async () => {
      const restoreTz = setRomeTimeZone()
      try {
        renderWithProviders(<Blacklists />)
        const table = await screen.findByRole('table', { name: 'Sources of Blocked IPs' })
        await within(table).findByText('Firehol Level 1')
        const row = (name: string) => within(table).getByText(name).closest('tr')!
        expect(within(row('Firehol Level 1')).getByText('https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset')).toBeInTheDocument()
        expect(within(row('Firehol Level 1')).getByText('4,521')).toBeInTheDocument()
        // The Added column (the range is also under the name, for a phone).
        expect(row('Firehol Level 1').cells[2]).toHaveTextContent(/^2026-10-25 11:00 to 11:02$/)
        expect(row('Manual').cells[2]).toHaveTextContent(/^2026-10-25 10:00$/)
        expect(within(row('Source not recorded')).getByText('Added before sources were recorded')).toBeInTheDocument()
        expect(within(row('Source not recorded')).getByText('50,772')).toBeInTheDocument()
      } finally { restoreTz() }
    })

    it('tells two pasted lists of the same size apart by when they were pasted', async () => {
      const restoreTz = setRomeTimeZone()
      try {
        sources['ip-blacklist'] = [
          { id: 12, kind: 'paste', source: '', label: '', entries: 3, first_added: '2026-10-25 12:53:40', last_added: '2026-10-25 12:53:40' },
          { id: 11, kind: 'paste', source: '', label: '', entries: 3, first_added: '2026-10-25 12:53:10', last_added: '2026-10-25 12:53:10' },
        ]
        renderWithProviders(<Blacklists />)
        expect(await screen.findByText('Pasted 2026-10-25 13:53:40')).toBeInTheDocument()
        expect(screen.getByRole('button', { name: 'Remove batch: Pasted list, 3 entries, pasted 2026-10-25 13:53:40' })).toBeInTheDocument()
        expect(screen.getByRole('button', { name: 'Remove batch: Pasted list, 3 entries, pasted 2026-10-25 13:53:10' })).toBeInTheDocument()
      } finally { restoreTz() }
    })

    it('removes a whole source after a confirmation that names how many entries go', async () => {
      renderWithProviders(<Blacklists />)
      const btn = await screen.findByRole('button', { name: 'Remove batch: Firehol Level 1, 4,521 entries' })
      fireEvent.click(btn)
      const dialog = await screen.findByRole('alertdialog')
      expect(within(dialog).getByText('Remove 4,521 entries from Firehol Level 1?')).toBeInTheDocument()
      expect(within(dialog).getByText(/Clients can reach them again once the proxy reloads the list/)).toBeInTheDocument()
      fireEvent.click(within(dialog).getByRole('button', { name: 'Remove 4,521 entries' }))
      await waitFor(() => expect(api.delete).toHaveBeenCalledWith('ip-blacklist/sources/7'))
    })

    it('removes the entries whose source was not recorded through "unrecorded", and does nothing on Cancel', async () => {
      renderWithProviders(<Blacklists />)
      fireEvent.click(await screen.findByRole('button', { name: 'Remove batch: Source not recorded, 50,772 entries' }))
      fireEvent.click(within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Cancel' }))
      await waitFor(() => expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument())
      expect(api.delete).not.toHaveBeenCalled()

      fireEvent.click(screen.getByRole('button', { name: 'Remove batch: Source not recorded, 50,772 entries' }))
      fireEvent.click(within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Remove 50,772 entries' }))
      await waitFor(() => expect(api.delete).toHaveBeenCalledWith('ip-blacklist/sources/unrecorded'))
    })
  })

  it('removes one entry after a confirmation naming it', async () => {
    renderWithProviders(<Blacklists />)
    fireEvent.click(await screen.findByRole('button', { name: 'Remove 198.51.100.0/24' }))
    const dialog = await screen.findByRole('alertdialog')
    expect(within(dialog).getByText('Remove 198.51.100.0/24?')).toBeInTheDocument()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Remove' }))
    await waitFor(() => expect(api.delete).toHaveBeenCalledWith('ip-blacklist/2'))
  })

  it('keeps Remove all in a danger zone whose confirmation names the count and the consequence', async () => {
    counts['ip-blacklist'] = 50772
    renderWithProviders(<Blacklists />)
    const zone = (await screen.findByRole('heading', { name: 'Remove every entry on this list' })).closest('section')!
    await within(zone).findByText(/^50,772 blocked IPs and networks\./)
    fireEvent.click(within(zone).getByRole('button', { name: 'Remove all' }))
    const dialog = await screen.findByRole('alertdialog')
    expect(within(dialog).getByText('Remove all 50,772 blocked IPs and networks?')).toBeInTheDocument()
    expect(within(dialog).getByText(/Clients can reach them again once the proxy reloads the list\. This cannot be undone/)).toBeInTheDocument()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Remove all 50,772' }))
    await waitFor(() => expect(api.delete).toHaveBeenCalledWith('ip-blacklist/clear-all'))
  })

  it('has no danger zone and no Popular lists on an allowed list', async () => {
    go('?tab=allowed-domains')
    renderWithProviders(<Blacklists />)
    await screen.findByRole('heading', { name: 'Where the entries came from' })
    expect(screen.queryByRole('heading', { name: 'Remove every entry on this list' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Popular lists' })).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Add entries' }))
    expect(within(screen.getByRole('group', { name: 'How to add' })).getAllByRole('button').map((b) => b.textContent)).toEqual(['Single entry', 'Paste a list'])
  })

  it('exports the whole list from the backend, not the page on screen', async () => {
    const createObjectURL = vi.fn(() => 'blob:x')
    const revokeObjectURL = vi.fn()
    Object.assign(URL, { createObjectURL, revokeObjectURL })
    renderWithProviders(<Blacklists />)
    fireEvent.click(screen.getByRole('button', { name: 'Export' }))
    await waitFor(() => expect(getCalls).toContain('ip-blacklist/export'))
    await waitFor(() => expect(createObjectURL).toHaveBeenCalled())
  })

  describe('Add entries', () => {
    const open = (method?: string) => {
      fireEvent.click(screen.getByRole('button', { name: 'Add entries' }))
      if (method) fireEvent.click(within(screen.getByRole('group', { name: 'How to add' })).getByRole('button', { name: method }))
    }

    it('offers every way to add to a blocked IP list, Geo-block included', () => {
      renderWithProviders(<Blacklists />)
      open()
      expect(within(screen.getByRole('group', { name: 'How to add' })).getAllByRole('button').map((b) => b.textContent))
        .toEqual(['Single entry', 'Paste a list', 'Import from URL', 'Popular lists', 'Geo-block'])
    })

    it('adds a single entry with its description', async () => {
      renderWithProviders(<Blacklists />)
      open()
      fireEvent.change(screen.getByLabelText('IP address or network'), { target: { value: '203.0.113.77' } })
      fireEvent.change(screen.getByLabelText('Description (optional)'), { target: { value: 'port scanner' } })
      fireEvent.click(screen.getByRole('button', { name: 'Add entry' }))
      await waitFor(() => expect(api.post).toHaveBeenCalledWith('ip-blacklist', { ip: '203.0.113.77', description: 'port scanner' }))
    })

    it('refuses an address the shared validator rejects, and says why', async () => {
      renderWithProviders(<Blacklists />)
      open()
      fireEvent.change(screen.getByLabelText('IP address or network'), { target: { value: '300.1.1.1' } })
      fireEvent.click(screen.getByRole('button', { name: 'Add entry' }))
      expect(await screen.findByRole('alert')).toHaveTextContent('"300.1.1.1" is not an IPv4 address or network')
      expect(api.post).not.toHaveBeenCalled()
    })

    it('shows the domain limit as the backend words it when an import would pass it', async () => {
      go('?tab=blocked-domains')
      const detail = 'import refused: the domain blacklist would hold 1000002 entries; the domain blacklist is limited to 1000000 entries (SPM_DNS_BLOCKLIST_MAX_DOMAINS)'
      vi.mocked(api.post).mockRejectedValueOnce(new AxiosError('413', 'ERR_BAD_REQUEST', undefined, undefined, {
        status: 413, statusText: 'Request Entity Too Large', data: { status: 'error', detail }, headers: {}, config: { headers: new AxiosHeaders() },
      }))
      renderWithProviders(<Blacklists />)
      open('Paste a list')
      fireEvent.change(screen.getByLabelText('Entries, one per line'), { target: { value: 'a.example\nb.example' } })
      fireEvent.click(screen.getByRole('button', { name: 'Add pasted entries' }))
      expect(await screen.findByRole('alert')).toHaveTextContent(detail)
      expect(api.post).toHaveBeenCalledWith('blacklists/import', { type: 'domain', content: 'a.example\nb.example' })
    })

    it('says the domain blacklist is full when it holds the limit', async () => {
      go('?tab=blocked-domains')
      counts['domain-blacklist'] = 1000000
      renderWithProviders(<Blacklists />)
      expect(await screen.findByText('The domain blacklist is full')).toBeInTheDocument()
    })

    it('imports a URL into the blocked list', async () => {
      renderWithProviders(<Blacklists />)
      open('Import from URL')
      fireEvent.change(screen.getByLabelText('List URL'), { target: { value: 'https://lists.example/ips.txt' } })
      fireEvent.click(screen.getByRole('button', { name: 'Import list' }))
      await waitFor(() => expect(api.post).toHaveBeenCalledWith('blacklists/import', { type: 'ip', url: 'https://lists.example/ips.txt' }))
    })

    it('imports a Popular list under its name, so the source shows the name', async () => {
      go('?tab=blocked-domains')
      renderWithProviders(<Blacklists />)
      fireEvent.click(screen.getByRole('button', { name: 'Popular lists' }))
      fireEvent.click(screen.getByRole('button', { name: 'Import StevenBlack Unified' }))
      await waitFor(() => expect(api.post).toHaveBeenCalledWith('blacklists/import', {
        type: 'domain', url: 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts', name: 'StevenBlack Unified',
      }))
    })

    // A pasted list on an allowed tab used to post to blacklists/import, which
    // feeds the BLOCKED tables: an address meant to be allowed was blocked.
    // Then it posted each line to the single add, which recorded every entry
    // as Manual. It goes to the allowed list's own import, one paste source.
    describe.each([
      ['allowed-ips', 'ip-whitelist', 'Allowed IPs', '203.0.113.7\n198.51.100.0/24'],
      ['allowed-domains', 'domain-whitelist', 'Allowed domains', 'trusted.example.com\nok.example.org'],
    ])('a pasted list on %s', (tab, endpoint, label, text) => {
      it('goes to the allowed list\'s own import in one request, never to a blocked one', async () => {
        go(`?tab=${tab}`)
        vi.spyOn(toast, 'success')
        renderWithProviders(<Blacklists />)
        open('Paste a list')
        fireEvent.change(screen.getByLabelText('Entries, one per line'), { target: { value: text } })
        fireEvent.click(screen.getByRole('button', { name: 'Add pasted entries' }))
        await waitFor(() => expect(api.post).toHaveBeenCalledWith(`${endpoint}/import`, { content: text }))
        expect(api.post).toHaveBeenCalledTimes(1)
        await waitFor(() => expect(toast.success).toHaveBeenCalledWith(`Added 2 entries to ${label}`, expect.anything()))
      })
    })

    it('names each refused line of an allowed paste with its reason', async () => {
      go('?tab=allowed-domains')
      vi.mocked(api.post).mockResolvedValueOnce({ data: { status: 'success', data: {
        added: 1, skipped: 1, refused: 2, refusals: [
          { entry: '.dot.example', reason: '".dot.example" is not an exact name: write dot.example. An allowed name takes that same name off Blocked domains, however it is written there, and covers no name under it' },
          { entry: 'bad name', reason: '"bad name" is not a domain name: labels of letters, digits and hyphens separated by dots' },
        ] } } } as never)
      renderWithProviders(<Blacklists />)
      open('Paste a list')
      fireEvent.change(screen.getByLabelText('Entries, one per line'), { target: { value: 'ok.example\nok.example\n.dot.example\nbad name' } })
      fireEvent.click(screen.getByRole('button', { name: 'Add pasted entries' }))
      expect(await screen.findByRole('alert')).toHaveTextContent(
        'Added 1 entry to Allowed domains, 1 already listed; 2 refused: ".dot.example" is not an exact name: write dot.example. ' +
        'An allowed name takes that same name off Blocked domains, however it is written there, and covers no name under it; ' +
        '"bad name" is not a domain name: labels of letters, digits and hyphens separated by dots.')
    })

    it('says the name to write for a leading dot on Allowed domains, before any request', async () => {
      go('?tab=allowed-domains')
      renderWithProviders(<Blacklists />)
      open()
      fireEvent.change(screen.getByLabelText('Domain'), { target: { value: '.github.com' } })
      fireEvent.click(screen.getByRole('button', { name: 'Add entry' }))
      expect(await screen.findByRole('alert')).toHaveTextContent('".github.com" is not an exact name: write github.com.')
      expect(api.post).not.toHaveBeenCalled()
    })

    // #219 M8 + M10b. Both were real: a second click fired a second POST and
    // imported twice, and an inline country parser filtered on length alone, so
    // "12" reached the API as a country code.
    describe('geo-block guards', () => {
      const openGeo = () => {
        open('Geo-block')
        return screen.getByPlaceholderText(/e\.g\. CN, RU, KP/i)
      }

      it('rejects a country code that is two characters but not two letters', async () => {
        renderWithProviders(<Blacklists />)
        fireEvent.change(openGeo(), { target: { value: '12' } })
        fireEvent.click(screen.getByRole('button', { name: /download and block ips/i }))
        expect(await screen.findByRole('alert')).toHaveTextContent('Enter two-letter ISO country codes')
        expect(api.post).not.toHaveBeenCalledWith('blacklists/import-geo', expect.anything())
      })

      it('does not submit twice when the button is clicked twice', async () => {
        let resolve!: (v: unknown) => void
        vi.mocked(api.post).mockReturnValueOnce(new Promise((r) => { resolve = r }) as never)
        renderWithProviders(<Blacklists />)
        fireEvent.change(openGeo(), { target: { value: 'CN' } })
        const btn = screen.getByRole('button', { name: /download and block ips/i })
        fireEvent.click(btn)
        await waitFor(() => expect(screen.getByRole('button', { name: /importing/i })).toBeDisabled())
        fireEvent.click(screen.getByRole('button', { name: /importing/i }))
        expect(vi.mocked(api.post).mock.calls.filter((c) => c[0] === 'blacklists/import-geo')).toHaveLength(1)
        await act(async () => { resolve({ data: { data: { imported: 1, countries_imported: 1, countries_requested: 1 } } }) })
      })

      // The test above passes on the disabled attribute alone. This one
      // submits the form directly, the path a disabled button cannot cover.
      it('the handler itself refuses a second submit while one is in flight', async () => {
        let resolve!: (v: unknown) => void
        vi.mocked(api.post).mockReturnValueOnce(new Promise((r) => { resolve = r }) as never)
        renderWithProviders(<Blacklists />)
        const input = openGeo()
        fireEvent.change(input, { target: { value: 'CN' } })
        const form = input.closest('form')!
        fireEvent.submit(form)
        fireEvent.submit(form)
        expect(vi.mocked(api.post).mock.calls.filter((c) => c[0] === 'blacklists/import-geo')).toHaveLength(1)
        await act(async () => { resolve({ data: { data: { imported: 1, countries_imported: 1, countries_requested: 1 } } }) })
      })
    })
  })

  it('has no accessibility violations, with the add panel closed and open', async () => {
    const { container } = renderWithProviders(<Blacklists />)
    await screen.findByText('10.0.0.1')
    await screen.findByRole('button', { name: /^Remove batch: Firehol Level 1/ })
    await expectNoAxeViolations(container)
    fireEvent.click(screen.getByRole('button', { name: 'Add entries' }))
    await expectNoAxeViolations(container)
    fireEvent.click(within(screen.getByRole('group', { name: 'How to add' })).getByRole('button', { name: 'Popular lists' }))
    await expectNoAxeViolations(container)
  })

  it('makes 6 GET requests on /blacklists instead of 7 (reusing meta.total of the active tab instead of ?limit=1) and pre-fills the search filter from ?q=', async () => {
    const { unmount } = renderWithProviders(<Blacklists />)
    await screen.findByText('10.0.0.1')
    const urls = vi.mocked(api.get).mock.calls.map(([u]) => String(u))
    expect(urls).not.toContain('ip-blacklist?limit=1')
    expect(urls).toHaveLength(6)
    await waitFor(() => expect(within(screen.getByRole('tab', { name: /^Blocked IPs/ })).getByText('5')).toBeInTheDocument())
    unmount()

    vi.mocked(api.get).mockClear()
    go('?tab=blocked-domains&q=ads.example')
    renderWithProviders(<Blacklists />)
    const searchbox = await screen.findByRole('searchbox', { name: 'Search Blocked domains' })
    expect(searchbox).toHaveValue('ads.example')
    expect(screen.getByRole('tab', { name: /^Blocked domains/ })).toHaveAttribute('aria-selected', 'true')
  })

  it('opened from search with ?q=, counts the whole active list in its tab and in the danger zone', async () => {
    counts['ip-blacklist'] = 50772
    vi.mocked(api.get).mockImplementation(((url: string) => {
      if (/^ip-blacklist\?.*search=10\.0\.0\.1/.test(url)) {
        getCalls.push(url)
        return Promise.resolve({ data: listBody([ipEntries[0]], 1) })
      }
      return routeGet(url)
    }) as never)
    go('?tab=blocked-ips&q=10.0.0.1')
    renderWithProviders(<Blacklists />)
    expect(await screen.findByRole('searchbox', { name: 'Search Blocked IPs' })).toHaveValue('10.0.0.1')
    await waitFor(() => expect(screen.getByRole('tab', { name: /^Blocked IPs/ })).toHaveTextContent('50,772'))
    const zone = screen.getByRole('heading', { name: 'Remove every entry on this list' }).closest('section')!
    await within(zone).findByText(/^50,772 blocked IPs and networks\./)
  })
})
