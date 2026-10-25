import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { screen, fireEvent } from '@testing-library/react'
import { AxiosError } from 'axios'
import { renderWithProviders } from '../../test/helpers'
import { expectNoAxeViolations } from '../../test/axe'
import { api } from '../../lib/api'
import { BlockDoh, EssentialWhitelist } from './QuickLists'

// The answer the list endpoints give for a duplicate (AddDomainWhitelist and
// AddDomain in backend-go/internal/handlers/blacklists.go).
const already = (what: string) => new AxiosError('dup', 'ERR_BAD_REQUEST', undefined, undefined, {
  status: 400, data: { status: 'error', detail: `domain already in ${what}` },
} as never)

describe('QuickLists', () => {
  beforeEach(() => {
    vi.spyOn(api, 'post').mockImplementation((url: string, body?: unknown) => {
      const domain = (body as { domain?: string })?.domain
      if (url === 'domain-whitelist' && domain === 'github.com') return Promise.reject(already('whitelist'))
      if (url === 'domain-blacklist' && domain === 'dns.google') return Promise.reject(already('blacklist'))
      return Promise.resolve({ data: { status: 'success' } })
    })
  })
  afterEach(() => { vi.restoreAllMocks() })

  it('whitelists a service, counts what was already there, and reloads DNS', async () => {
    const { container } = renderWithProviders(<EssentialWhitelist />)
    fireEvent.click(screen.getByRole('button', { name: '+ GitHub' }))
    expect(await screen.findByText('GitHub: 4 added, 1 already listed. DNS reloaded.')).toBeInTheDocument()
    expect(api.post).toHaveBeenCalledWith('maintenance/reload-dns')
    expect(screen.getByRole('button', { name: '+ Cloudflare' })).toHaveAttribute('title', 'cloudflare.com, dash.cloudflare.com')
    await expectNoAxeViolations(container)
  })

  it('tells a domain the list refused apart from one already listed', async () => {
    vi.mocked(api.post).mockImplementation((_url: string, body?: unknown) => {
      if ((body as { domain?: string })?.domain === 'hub.docker.com') {
        return Promise.reject(new AxiosError('bad', 'ERR_BAD_REQUEST', undefined, undefined, { status: 400, data: { status: 'error', detail: 'invalid domain' } } as never))
      }
      return Promise.resolve({ data: { status: 'success' } })
    })
    renderWithProviders(<EssentialWhitelist />)
    fireEvent.click(screen.getByRole('button', { name: '+ Docker' }))
    expect(await screen.findByText('Docker: 4 added, 1 refused by the list. DNS reloaded.')).toBeInTheDocument()
  })

  it('blacklists the DoH resolvers and says when DNS could not be reloaded', async () => {
    vi.mocked(api.post).mockImplementation((url: string, body?: unknown) => {
      if (url === 'maintenance/reload-dns') return Promise.reject(new Error('down'))
      if ((body as { domain?: string })?.domain === 'dns.google') return Promise.reject(already('blacklist'))
      return Promise.resolve({ data: { status: 'success' } })
    })
    const { container } = renderWithProviders(<BlockDoh />)
    fireEvent.click(screen.getByRole('button', { name: 'Block DoH resolvers' }))
    expect(await screen.findByText('DoH resolvers: 13 added, 1 already listed. DNS was not reloaded: use Reload DNS.')).toBeInTheDocument()
    await expectNoAxeViolations(container)
  })
})
