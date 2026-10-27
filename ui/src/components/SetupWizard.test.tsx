import { describe, it, expect, vi, beforeEach } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import { renderWithProviders } from '../test/helpers'
import { expectNoAxeViolations } from '../test/axe'
import { SetupWizard } from './SetupWizard'
import wizardSource from './SetupWizard.tsx?raw'

vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn().mockResolvedValue({ data: { data: [] } }),
    post: vi.fn().mockResolvedValue({ data: { status: 'success' } }),
    interceptors: { request: { use: vi.fn() }, response: { use: vi.fn() } },
  },
  getErrorMessage: (_e: unknown, f: string) => f,
}))

import { api } from '../lib/api'

describe('SetupWizard', () => {
  const onComplete = vi.fn()

  beforeEach(() => {
    vi.clearAllMocks()
    toast.remove()
  })

  it('contains no emoji characters in SetupWizard.tsx source', () => {
    expect(wizardSource).not.toMatch(/\p{Extended_Pictographic}/u)
  })

  it('renders step 0 with environment options and removes the fake devices step', async () => {
    const user = userEvent.setup()
    renderWithProviders(<SetupWizard onComplete={onComplete} />)
    expect(screen.getByText('Homelab')).toBeInTheDocument()
    expect(screen.getByText('Family')).toBeInTheDocument()
    expect(screen.getByText('Small Business')).toBeInTheDocument()
    expect(screen.getByText('Advanced')).toBeInTheDocument()

    await user.click(screen.getByText('Homelab'))
    await user.click(screen.getByRole('button', { name: /^next$/i }))

    // Goes directly to strictness without a devices step
    expect(screen.queryByText(/what devices use this proxy/i)).not.toBeInTheDocument()
    expect(screen.getByText('Relaxed')).toBeInTheDocument()
    expect(screen.getByText('Balanced')).toBeInTheDocument()
    expect(screen.getByText('Strict')).toBeInTheDocument()
    // Strict option lists the extra archive and script extensions it blocks
    for (const ext of ['zip', '7z', 'rar', 'tar', 'iso', 'sh', 'py', 'rb']) {
      expect(screen.getByText(new RegExp(`\\b${ext}\\b`))).toBeInTheDocument()
    }
  })

  it('advanced environment shows Skip Wizard button and skips', async () => {
    const user = userEvent.setup()
    renderWithProviders(<SetupWizard onComplete={onComplete} />)

    await user.click(screen.getByText('Advanced'))
    const skipBtns = screen.getAllByRole('button').filter(b =>
      b.textContent?.trim().startsWith('Skip Wizard')
    )
    await user.click(skipBtns[0])

    await waitFor(() => {
      expect(api.post).toHaveBeenCalledWith('settings', { wizard_completed: 'true' })
      expect(onComplete).toHaveBeenCalled()
    })
  })

  it.each([
    {
      envLabel: 'Homelab',
      strictLabel: 'Relaxed',
      expected: {
        waf_h_entropy: 'true',
        waf_h_beaconing: 'true',
        waf_h_pii: 'false',
        waf_h_sharding: 'false',
        waf_h_ghosting: 'false',
        enable_safesearch: 'false',
        enable_youtube_restricted: 'false',
        enable_content_filtering: 'false',
        enable_bandwidth_limits: 'false',
        aggressive_caching_enabled: 'false',
      },
    },
    {
      envLabel: 'Homelab',
      strictLabel: 'Balanced',
      expected: {
        waf_h_entropy: 'true',
        waf_h_beaconing: 'true',
        waf_h_pii: 'false',
        waf_h_sharding: 'false',
        waf_h_ghosting: 'true',
        enable_safesearch: 'false',
        enable_youtube_restricted: 'false',
        enable_content_filtering: 'false',
        enable_bandwidth_limits: 'false',
        aggressive_caching_enabled: 'false',
      },
    },
    {
      envLabel: 'Homelab',
      strictLabel: 'Strict',
      expected: {
        waf_h_entropy: 'true',
        waf_h_beaconing: 'true',
        waf_h_pii: 'true',
        waf_h_sharding: 'true',
        waf_h_ghosting: 'true',
        enable_safesearch: 'false',
        enable_youtube_restricted: 'false',
        enable_content_filtering: 'true',
        blocked_file_types: 'exe,bat,cmd,dll,msi,scr,ps1,vbs,sh,py,rb,zip,7z,rar,tar,iso',
        enable_bandwidth_limits: 'false',
        aggressive_caching_enabled: 'false',
      },
    },
    {
      envLabel: 'Family',
      strictLabel: 'Relaxed',
      expected: {
        waf_h_entropy: 'true',
        waf_h_beaconing: 'true',
        waf_h_pii: 'false',
        waf_h_sharding: 'false',
        waf_h_ghosting: 'false',
        enable_safesearch: 'true',
        enable_youtube_restricted: 'true',
        enable_content_filtering: 'true',
        blocked_file_types: 'exe,bat,cmd,dll,msi,scr,ps1,vbs',
        enable_bandwidth_limits: 'false',
        aggressive_caching_enabled: 'false',
      },
    },
    {
      envLabel: 'Family',
      strictLabel: 'Balanced',
      expected: {
        waf_h_entropy: 'true',
        waf_h_beaconing: 'true',
        waf_h_pii: 'false',
        waf_h_sharding: 'false',
        waf_h_ghosting: 'true',
        enable_safesearch: 'true',
        enable_youtube_restricted: 'true',
        enable_content_filtering: 'true',
        blocked_file_types: 'exe,bat,cmd,dll,msi,scr,ps1,vbs',
        enable_bandwidth_limits: 'false',
        aggressive_caching_enabled: 'false',
      },
    },
    {
      envLabel: 'Family',
      strictLabel: 'Strict',
      expected: {
        waf_h_entropy: 'true',
        waf_h_beaconing: 'true',
        waf_h_pii: 'true',
        waf_h_sharding: 'true',
        waf_h_ghosting: 'true',
        enable_safesearch: 'true',
        enable_youtube_restricted: 'true',
        enable_content_filtering: 'true',
        blocked_file_types: 'exe,bat,cmd,dll,msi,scr,ps1,vbs,sh,py,rb,zip,7z,rar,tar,iso',
        enable_bandwidth_limits: 'false',
        aggressive_caching_enabled: 'false',
      },
    },
    {
      envLabel: 'Small Business',
      strictLabel: 'Relaxed',
      expected: {
        waf_h_entropy: 'true',
        waf_h_beaconing: 'true',
        waf_h_pii: 'true',
        waf_h_sharding: 'true',
        waf_h_ghosting: 'true',
        enable_safesearch: 'false',
        enable_youtube_restricted: 'false',
        enable_content_filtering: 'true',
        blocked_file_types: 'exe,bat,cmd,dll,msi,scr,ps1,vbs',
        enable_bandwidth_limits: 'false',
        aggressive_caching_enabled: 'false',
      },
    },
    {
      envLabel: 'Small Business',
      strictLabel: 'Balanced',
      expected: {
        waf_h_entropy: 'true',
        waf_h_beaconing: 'true',
        waf_h_pii: 'true',
        waf_h_sharding: 'true',
        waf_h_ghosting: 'true',
        enable_safesearch: 'false',
        enable_youtube_restricted: 'false',
        enable_content_filtering: 'true',
        blocked_file_types: 'exe,bat,cmd,dll,msi,scr,ps1,vbs',
        enable_bandwidth_limits: 'false',
        aggressive_caching_enabled: 'false',
      },
    },
    {
      envLabel: 'Small Business',
      strictLabel: 'Strict',
      expected: {
        waf_h_entropy: 'true',
        waf_h_beaconing: 'true',
        waf_h_pii: 'true',
        waf_h_sharding: 'true',
        waf_h_ghosting: 'true',
        enable_safesearch: 'false',
        enable_youtube_restricted: 'false',
        enable_content_filtering: 'true',
        blocked_file_types: 'exe,bat,cmd,dll,msi,scr,ps1,vbs,sh,py,rb,zip,7z,rar,tar,iso',
        enable_bandwidth_limits: 'false',
        aggressive_caching_enabled: 'false',
      },
    },
  ])('writes exact settings matching the option descriptions for $envLabel + $strictLabel', async ({ envLabel, strictLabel, expected }) => {
    const user = userEvent.setup()
    renderWithProviders(<SetupWizard onComplete={onComplete} />)

    await user.click(screen.getByText(envLabel))
    await user.click(screen.getByRole('button', { name: /^next$/i }))

    await user.click(screen.getByText(strictLabel))
    await user.click(screen.getByRole('button', { name: /apply/i }))

    await waitFor(() => {
      const settingsCall = vi.mocked(api.post).mock.calls.find(([url]) => url === 'settings')
      expect(settingsCall).toBeDefined()
      const settings = settingsCall![1] as Record<string, string>
      expect(settings).toMatchObject({ ...expected, wizard_completed: 'true' })
      for (const dead of ['block_direct_ip', 'waf_block_threshold', 'enable_offline_mode']) {
        expect(settings).not.toHaveProperty(dead)
      }
    })
  })

  it('does not claim the proxy is live when reload-config responds pending, and points to Settings, Admin and backup, Reload the proxy', async () => {
    const user = userEvent.setup()
    const toastSuccessSpy = vi.spyOn(toast, 'success')
    vi.mocked(api.post).mockImplementation((url: string) => {
      if (url === 'maintenance/reload-config') {
        return Promise.resolve({ data: { status: 'pending' } })
      }
      return Promise.resolve({ data: { status: 'success' } })
    })

    const { container } = renderWithProviders(<SetupWizard onComplete={onComplete} />)

    await user.click(screen.getByText('Homelab'))
    await user.click(screen.getByRole('button', { name: /^next$/i }))
    await user.click(screen.getByRole('button', { name: /apply/i }))

    await waitFor(() => {
      expect(screen.getByText(/did not confirm within 8 seconds/i)).toBeInTheDocument()
    })
    expect(screen.getByText(/Settings, Admin and backup, Reload the proxy/i)).toBeInTheDocument()
    expect(container.textContent).not.toMatch(/proxy is live/i)
    expect(toastSuccessSpy).not.toHaveBeenCalled()
    toastSuccessSpy.mockRestore()
  })

  it('invalidates the settings query cache after saving and reports failed reload outcomes truthfully', async () => {
    const user = userEvent.setup()
    vi.mocked(api.post).mockImplementation((url: string) => {
      if (url === 'maintenance/reload-config') {
        return Promise.reject(Object.assign(new Error('500'), {
          isAxiosError: true,
          response: { status: 500, data: { code: 'trigger_write_failed', detail: 'Config exported, but the reload trigger could not be written; apply manually' } },
        }))
      }
      return Promise.resolve({ data: { status: 'success' } })
    })

    const invalidateSpy = vi.spyOn(QueryClient.prototype, 'invalidateQueries')
    renderWithProviders(<SetupWizard onComplete={onComplete} />)

    await user.click(screen.getByText('Homelab'))
    await user.click(screen.getByRole('button', { name: /^next$/i }))
    await user.click(screen.getByRole('button', { name: /apply/i }))

    await waitFor(() => {
      expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['settings'] })
      expect(screen.getByText(/Could not reload the proxy/i)).toBeInTheDocument()
    })
    expect(screen.getByText(/Settings, Admin and backup, Reload the proxy/i)).toBeInTheDocument()
    invalidateSpy.mockRestore()
  })

  it.each(['light', 'dark'] as const)('passes axe accessibility checks on every wizard step in %s theme', async (theme) => {
    document.documentElement.classList.toggle('dark', theme === 'dark')
    try {
      const user = userEvent.setup()
      const { container } = renderWithProviders(<SetupWizard onComplete={onComplete} />)

      // Step 0: Environment
      await expectNoAxeViolations(container)
      await user.click(screen.getByText('Homelab'))
      await expectNoAxeViolations(container)
      await user.click(screen.getByRole('button', { name: /^next$/i }))

      // Step 1: Strictness
      await waitFor(() => expect(screen.getByText('Balanced')).toBeInTheDocument())
      await expectNoAxeViolations(container)
      await user.click(screen.getByRole('button', { name: /apply/i }))

      // Step 2: Connect your devices (ClientSetup)
      await waitFor(() => expect(screen.getByRole('tablist', { name: 'Operating system' })).toBeInTheDocument())
      await expectNoAxeViolations(container)
    } finally {
      document.documentElement.classList.remove('dark')
    }
  })
})
