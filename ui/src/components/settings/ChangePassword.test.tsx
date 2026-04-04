import { describe, it, expect, vi, beforeEach } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderWithProviders } from '../../test/helpers'
import { ChangePassword } from './ChangePassword'

vi.mock('../../lib/api', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(),
    interceptors: { request: { use: vi.fn() }, response: { use: vi.fn() } },
  },
}))

import { api } from '../../lib/api'

describe('ChangePassword', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders all password fields', () => {
    renderWithProviders(<ChangePassword />)
    expect(screen.getByText('Current Password')).toBeInTheDocument()
    expect(screen.getByText('New Password')).toBeInTheDocument()
    expect(screen.getByText('Confirm New Password')).toBeInTheDocument()
  })

  it('submit button is disabled when form is empty', () => {
    renderWithProviders(<ChangePassword />)
    const btn = screen.getByRole('button', { name: /change password/i })
    expect(btn).toBeDisabled()
  })

  it('shows validation indicators when typing new password', async () => {
    const user = userEvent.setup()
    renderWithProviders(<ChangePassword />)

    const inputs = screen.getAllByDisplayValue('')
    // New password is the 2nd input
    await user.type(inputs[1], 'short')

    await waitFor(() => {
      expect(screen.getByText(/8\+ chars/)).toBeInTheDocument()
      expect(screen.getByText(/number/)).toBeInTheDocument()
      expect(screen.getByText(/special/)).toBeInTheDocument()
    })
  })

  it('shows mismatch error when passwords differ', async () => {
    const user = userEvent.setup()
    renderWithProviders(<ChangePassword />)

    const inputs = screen.getAllByDisplayValue('')
    await user.type(inputs[1], 'NewPass1!')
    await user.type(inputs[2], 'Different1!')

    await waitFor(() => {
      expect(screen.getByText(/passwords do not match/i)).toBeInTheDocument()
    })
  })

  it('enables submit when all criteria met', async () => {
    const user = userEvent.setup()
    renderWithProviders(<ChangePassword />)

    const inputs = screen.getAllByDisplayValue('')
    await user.type(inputs[0], 'oldpassword')
    await user.type(inputs[1], 'NewPass1!')
    await user.type(inputs[2], 'NewPass1!')

    const btn = screen.getByRole('button', { name: /change password/i })
    expect(btn).not.toBeDisabled()
  })

  it('calls API with correct payload on submit', async () => {
    const user = userEvent.setup()
    vi.mocked(api.post).mockResolvedValueOnce({ data: {} })
    renderWithProviders(<ChangePassword />)

    const inputs = screen.getAllByDisplayValue('')
    await user.type(inputs[0], 'oldpassword')
    await user.type(inputs[1], 'NewPass1!')
    await user.type(inputs[2], 'NewPass1!')

    await user.click(screen.getByRole('button', { name: /change password/i }))

    await waitFor(() => {
      expect(api.post).toHaveBeenCalledWith('change-password', {
        current_password: 'oldpassword',
        new_password: 'NewPass1!',
      })
    })
  })

  it('clears form on successful password change', async () => {
    const user = userEvent.setup()
    vi.mocked(api.post).mockResolvedValueOnce({ data: {} })
    renderWithProviders(<ChangePassword />)

    const inputs = screen.getAllByDisplayValue('')
    await user.type(inputs[0], 'oldpassword')
    await user.type(inputs[1], 'NewPass1!')
    await user.type(inputs[2], 'NewPass1!')
    await user.click(screen.getByRole('button', { name: /change password/i }))

    await waitFor(() => {
      const allInputs = screen.getAllByDisplayValue('')
      expect(allInputs.length).toBeGreaterThanOrEqual(3)
    })
  })

  it('keeps button disabled with short password', async () => {
    const user = userEvent.setup()
    renderWithProviders(<ChangePassword />)

    const inputs = screen.getAllByDisplayValue('')
    await user.type(inputs[0], 'old')
    await user.type(inputs[1], 'Sh1!')     // too short
    await user.type(inputs[2], 'Sh1!')

    const btn = screen.getByRole('button', { name: /change password/i })
    expect(btn).toBeDisabled()
  })

  it('keeps button disabled without special char', async () => {
    const user = userEvent.setup()
    renderWithProviders(<ChangePassword />)

    const inputs = screen.getAllByDisplayValue('')
    await user.type(inputs[0], 'old')
    await user.type(inputs[1], 'LongPass1')   // no special
    await user.type(inputs[2], 'LongPass1')

    const btn = screen.getByRole('button', { name: /change password/i })
    expect(btn).toBeDisabled()
  })
})
