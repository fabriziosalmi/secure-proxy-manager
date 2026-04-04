import { describe, it, expect, vi, beforeEach } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderWithProviders } from '../test/helpers'
import { SetupWizard } from './SetupWizard'

vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn().mockResolvedValue({ data: { status: 'success' } }),
    interceptors: { request: { use: vi.fn() }, response: { use: vi.fn() } },
  },
}))

import { api } from '../lib/api'

describe('SetupWizard', () => {
  const onComplete = vi.fn()

  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders step 0 with environment options', () => {
    renderWithProviders(<SetupWizard onComplete={onComplete} />)
    expect(screen.getByText('Homelab')).toBeInTheDocument()
    expect(screen.getByText('Family')).toBeInTheDocument()
    expect(screen.getByText('Small Business')).toBeInTheDocument()
    expect(screen.getByText('Advanced')).toBeInTheDocument()
  })

  it('advanced environment shows Skip Wizard button and skips', async () => {
    const user = userEvent.setup()
    renderWithProviders(<SetupWizard onComplete={onComplete} />)

    await user.click(screen.getByText('Advanced'))
    // The "Skip Wizard" nav button (not the option card which contains "skip wizard" too)
    const skipBtns = screen.getAllByRole('button').filter(b =>
      b.textContent?.trim().startsWith('Skip Wizard')
    )
    await user.click(skipBtns[0])

    await waitFor(() => {
      expect(api.post).toHaveBeenCalledWith('settings', { wizard_completed: 'true' })
      expect(onComplete).toHaveBeenCalled()
    })
  })

  it('navigates step 0 → 1 → 2 via Next buttons', async () => {
    const user = userEvent.setup()
    renderWithProviders(<SetupWizard onComplete={onComplete} />)

    // Step 0: select Homelab, click Next
    await user.click(screen.getByText('Homelab'))
    await user.click(screen.getByText(/^next$/i))

    // Step 1: devices
    await waitFor(() => expect(screen.getByText('PCs / Laptops')).toBeInTheDocument())
    await user.click(screen.getByText(/^next$/i))

    // Step 2: strictness
    await waitFor(() => {
      expect(screen.getByText('Relaxed')).toBeInTheDocument()
      expect(screen.getByText('Balanced')).toBeInTheDocument()
      expect(screen.getByText('Strict')).toBeInTheDocument()
    })
  })

  it('family + balanced submits correct settings', async () => {
    const user = userEvent.setup()
    renderWithProviders(<SetupWizard onComplete={onComplete} />)

    // Step 0: Family
    await user.click(screen.getByText('Family'))
    await user.click(screen.getByText(/^next$/i))

    // Step 1: skip devices
    await waitFor(() => expect(screen.getByText('PCs / Laptops')).toBeInTheDocument())
    await user.click(screen.getByText(/^next$/i))

    // Step 2: default is balanced, click Apply
    await waitFor(() => expect(screen.getByText(/apply/i)).toBeInTheDocument())
    await user.click(screen.getByText(/apply/i))

    await waitFor(() => {
      expect(api.post).toHaveBeenCalled()
      const settings = vi.mocked(api.post).mock.calls[0][1] as Record<string, string>
      expect(settings.enable_safesearch).toBe('true')
      expect(settings.enable_content_filtering).toBe('true')
      expect(settings.enable_youtube_restricted).toBe('true')
      expect(settings.block_direct_ip).toBe('true')
      expect(settings.wizard_completed).toBe('true')
      // balanced strictness overrides
      expect(settings.waf_block_threshold).toBe('8')
    })
  })
})
