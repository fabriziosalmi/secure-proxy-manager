import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { screen, fireEvent } from '@testing-library/react'
import { renderWithProviders } from '../../test/helpers'
import { expectNoAxeViolations } from '../../test/axe'
import { api } from '../../lib/api'
import { BlockDoh, EssentialWhitelist } from './QuickLists'

// GET {list}/presets and POST {list}/presets/{id} as backend-go/internal/
// handlers/presets.go answers them.
const allowedPresets = [
  { id: 'github', name: 'GitHub', domains: ['github.com', 'raw.githubusercontent.com', 'api.github.com', 'gist.github.com', 'objects.githubusercontent.com'], listed: ['github.com'] },
  { id: 'cloudflare', name: 'Cloudflare', domains: ['cloudflare.com', 'dash.cloudflare.com'], listed: [] },
]
const blockedPresets = [
  { id: 'doh', name: 'DNS-over-HTTPS resolvers', domains: Array.from({ length: 14 }, (_, i) => `doh${i}.example`), listed: ['doh0.example'] },
]

describe('QuickLists', () => {
  beforeEach(() => {
    vi.spyOn(api, 'get').mockImplementation(((url: string) => {
      if (url === 'domain-whitelist/presets') return Promise.resolve({ data: { status: 'success', data: allowedPresets } })
      if (url === 'domain-blacklist/presets') return Promise.resolve({ data: { status: 'success', data: blockedPresets } })
      return Promise.reject(new Error(`unexpected GET ${url}`))
    }) as never)
    vi.spyOn(api, 'post').mockImplementation(((url: string) => {
      if (url === 'domain-whitelist/presets/github') {
        return Promise.resolve({ data: { status: 'success', data: { preset: 'github', name: 'GitHub', added: ['raw.githubusercontent.com', 'api.github.com', 'gist.github.com', 'objects.githubusercontent.com'], already: 1 } } })
      }
      if (url === 'domain-blacklist/presets/doh') {
        return Promise.resolve({ data: { status: 'success', data: { preset: 'doh', name: 'DNS-over-HTTPS resolvers', added: Array.from({ length: 13 }, (_, i) => `doh${i + 1}.example`), already: 1 } } })
      }
      return Promise.reject(new Error(`unexpected POST ${url}`))
    }) as never)
  })
  afterEach(() => { vi.restoreAllMocks() })

  // One click used to be one POST per domain plus a DNS reload: five Manual
  // entries and five audit rows for "+ GitHub".
  it('adds a common service with one request to its preset, and says what was already listed', async () => {
    const { container } = renderWithProviders(<EssentialWhitelist />)
    fireEvent.click(await screen.findByRole('button', { name: '+ GitHub' }))
    expect(await screen.findByText('GitHub: 4 added, 1 already listed. The lists are being sent to the proxy and the DNS sinkhole.')).toBeInTheDocument()
    expect(api.post).toHaveBeenCalledTimes(1)
    expect(api.post).toHaveBeenCalledWith('domain-whitelist/presets/github')
    expect(screen.getByRole('button', { name: '+ Cloudflare' })).toHaveAttribute('title', 'cloudflare.com, dash.cloudflare.com')
    await expectNoAxeViolations(container)
  })

  it('blacklists the DoH resolvers with one request, naming how many the preset holds', async () => {
    const { container } = renderWithProviders(<BlockDoh />)
    expect(await screen.findByText(/^Blacklists 14 public DoH resolvers/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Block DoH resolvers' }))
    expect(await screen.findByText('DNS-over-HTTPS resolvers: 13 added, 1 already listed. The lists are being sent to the proxy and the DNS sinkhole.')).toBeInTheDocument()
    expect(api.post).toHaveBeenCalledTimes(1)
    await expectNoAxeViolations(container)
  })

  it('says so when the presets cannot be read', async () => {
    vi.mocked(api.get).mockImplementation((() => Promise.reject(new Error('down'))) as never)
    renderWithProviders(<EssentialWhitelist />)
    expect(await screen.findByRole('alert')).toHaveTextContent('The presets could not be read')
  })
})
