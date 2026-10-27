import { describe, it, expect, vi, beforeEach } from 'vitest'
import { screen, fireEvent, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import toast from 'react-hot-toast'
import { renderWithProviders } from '../test/helpers'
import { expectNoAxeViolations } from '../test/axe'
import { ClientSetup } from './ClientSetup'

vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn().mockResolvedValue({ data: { data: [] } }),
    post: vi.fn(),
    interceptors: { request: { use: vi.fn() }, response: { use: vi.fn() } },
  },
}))

import { api } from '../lib/api'

describe('ClientSetup', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    toast.remove()
  })

  it.each(['light', 'dark'] as const)('renders OS tabs without duplicate Connect Your Devices heading, switches panels with keyboard and mouse, and passes axe in %s theme', async (theme) => {
    document.documentElement.classList.toggle('dark', theme === 'dark')
    try {
      const { container } = renderWithProviders(<ClientSetup />)
      expect(screen.queryByRole('heading', { name: /connect your devices/i })).not.toBeInTheDocument()
      await expectNoAxeViolations(container)

      const winTab = screen.getByRole('tab', { name: 'Windows' })
      expect(winTab).toHaveAttribute('aria-selected', 'true')
      fireEvent.keyDown(winTab, { key: 'ArrowRight' })

      const macTab = screen.getByRole('tab', { name: 'macOS' })
      expect(macTab).toHaveAttribute('aria-selected', 'true')
      await expectNoAxeViolations(container)

      fireEvent.click(screen.getByRole('tab', { name: 'iOS' }))
      expect(screen.getByRole('tab', { name: 'iOS' })).toHaveAttribute('aria-selected', 'true')
      await expectNoAxeViolations(container)
    } finally {
      document.documentElement.classList.remove('dark')
    }
  })

  it('does not show Copied when clipboard writeText rejects, and shows an error toast instead', async () => {
    const user = userEvent.setup()
    const successSpy = vi.spyOn(toast, 'success')
    const errorSpy = vi.spyOn(toast, 'error')
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText: vi.fn().mockRejectedValueOnce(new Error('NotAllowedError')) },
    })

    renderWithProviders(<ClientSetup />)
    await user.click(screen.getByRole('button', { name: 'Copy proxy' }))

    await waitFor(() => {
      expect(errorSpy).toHaveBeenCalled()
    })
    expect(successSpy).not.toHaveBeenCalled()
    successSpy.mockRestore()
    errorSpy.mockRestore()
  })

  it('shows Authentication: Username and password on iOS when enable_proxy_auth is true', async () => {
    const user = userEvent.setup()
    vi.mocked(api.get).mockResolvedValueOnce({
      data: {
        data: [{ setting_name: 'enable_proxy_auth', setting_value: 'true' }],
      },
    })

    renderWithProviders(<ClientSetup />)
    await user.click(screen.getByRole('tab', { name: 'iOS' }))

    expect(await screen.findByText(/Authentication: Username and password/i)).toBeInTheDocument()
    expect(screen.queryByText(/Authentication: Off/i)).not.toBeInTheDocument()
  })
})
