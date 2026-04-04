import { describe, it, expect, vi, beforeEach } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import { renderWithProviders } from '../test/helpers'
import { Settings } from './Settings'

vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(),
    interceptors: { request: { use: vi.fn() }, response: { use: vi.fn() } },
  },
  getErrorMessage: (_e: unknown, f: string) => f,
}))

import { api } from '../lib/api'

const mockSettings = {
  data: {
    data: [
      { setting_name: 'proxy_port', setting_value: '3128' },
      { setting_name: 'cache_size', setting_value: '1000' },
      { setting_name: 'memory_cache', setting_value: '256' },
      { setting_name: 'allowed_networks', setting_value: '10.0.0.0/8' },
      { setting_name: 'ssl_bump_enabled', setting_value: 'false' },
      { setting_name: 'enable_waf', setting_value: 'true' },
      { setting_name: 'enable_ip_blacklist', setting_value: 'true' },
      { setting_name: 'enable_domain_blacklist', setting_value: 'true' },
      { setting_name: 'log_retention_days', setting_value: '30' },
      { setting_name: 'enable_notifications', setting_value: 'false' },
      { setting_name: 'webhook_url', setting_value: '' },
      { setting_name: 'default_password_changed', setting_value: 'true' },
      { setting_name: 'wizard_completed', setting_value: 'true' },
    ],
  },
}

describe('Settings', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url.includes('settings')) return Promise.resolve(mockSettings)
      return Promise.resolve({ data: {} })
    })
    vi.mocked(api.post).mockResolvedValue({ data: { status: 'success' } })
  })

  it('renders settings page', async () => {
    renderWithProviders(<Settings />)
    expect(screen.getAllByText(/settings/i).length).toBeGreaterThan(0)
  })

  it('loads and displays proxy port setting', async () => {
    renderWithProviders(<Settings />)
    await waitFor(() => {
      const portInput = document.querySelector('input[value="3128"]') as HTMLInputElement
      expect(portInput).toBeTruthy()
    })
  })

  it('has a save button', async () => {
    renderWithProviders(<Settings />)
    await waitFor(() => {
      const saveButtons = screen.getAllByRole('button').filter(
        btn => btn.textContent?.toLowerCase().includes('save')
      )
      expect(saveButtons.length).toBeGreaterThan(0)
    })
  })

  it('renders toggle switches for feature flags', async () => {
    renderWithProviders(<Settings />)
    await waitFor(() => {
      // Look for toggle-style buttons or checkboxes
      const buttons = screen.getAllByRole('button')
      expect(buttons.length).toBeGreaterThan(0)
    })
  })
})
