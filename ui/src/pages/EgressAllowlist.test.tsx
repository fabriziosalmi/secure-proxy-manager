import { describe, it, expect, vi, afterEach } from 'vitest'
import { screen } from '@testing-library/react'
import { renderWithProviders } from '../test/helpers'
import { api } from '../lib/api'
import { EgressAllowlist } from './EgressAllowlist'

describe('EgressAllowlist', () => {
  afterEach(() => { vi.restoreAllMocks() })

  it('links to the Settings section that turns the allowlist on', () => {
    vi.spyOn(api, 'get').mockResolvedValue({ data: { status: 'success', data: [], meta: { total: 0, limit: 50, offset: 0 } } })
    renderWithProviders(<EgressAllowlist />)
    expect(screen.getByRole('link', { name: 'Settings, Filtering' })).toHaveAttribute('href', '/settings/filtering')
    expect(screen.getByText(/Turning it on or off reloads the proxy configuration\./)).toBeInTheDocument()
  })
})
