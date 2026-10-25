import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { screen, waitFor, fireEvent } from '@testing-library/react'
import { renderWithProviders, simulateItalianLocale } from '../test/helpers'
import { api } from '../lib/api'
import { Clients } from './Clients'

// The body GET /api/clients/statistics really returns (writeList in
// backend-go/internal/handlers/helpers.go). Only api.get is stubbed, so the
// page's own unwrapping runs exactly as in production: reading data.data off
// an already unwrapped array left the page empty against a backend that had
// reported a client.
const clientsBody = {
  status: 'success',
  data: [
    { ip_address: '192.168.0.109', requests: 1172, blocked: 8, last_seen: '2026-10-25 09:00:00', status: 'Active' },
  ],
  meta: { total: 1, limit: 1, offset: 0 },
  total: 1,
  limit: 1,
  offset: 0,
}

describe('Clients', () => {
  beforeEach(() => {
    vi.spyOn(api, 'get').mockImplementation((url: string) => {
      if (url.includes('clients/statistics')) return Promise.resolve({ data: clientsBody })
      return Promise.resolve({ data: { status: 'success', data: null } })
    })
  })
  afterEach(() => { vi.restoreAllMocks() })

  it('lists the client the backend reports', async () => {
    renderWithProviders(<Clients />)
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'View details for 192.168.0.109' })).toBeInTheDocument()
    })
    expect(screen.queryByText(/No client traffic/)).not.toBeInTheDocument()
  })

  it('opens the client detail drawer outside the page, directly in document.body', async () => {
    renderWithProviders(<Clients />)
    fireEvent.click(await screen.findByRole('button', { name: 'View details for 192.168.0.109' }))
    const drawer = await screen.findByRole('dialog')
    expect(drawer.parentElement).toBe(document.body)
  })

  it('writes the request count with en-US grouping in any browser locale', async () => {
    simulateItalianLocale()
    renderWithProviders(<Clients />)
    const row = (await screen.findByRole('button', { name: 'View details for 192.168.0.109' })).closest('tr') as HTMLElement
    expect(row).toHaveTextContent('1,172')
    expect(row).not.toHaveTextContent('1.172')
  })
})
