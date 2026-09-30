import { describe, it, expect, vi, beforeEach } from 'vitest'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderWithProviders } from '../../test/helpers'
import { ChangePassword } from './ChangePassword'

vi.mock('../../lib/api', () => ({
  api: { post: vi.fn(() => Promise.resolve({ data: {} })) },
  getErrorMessage: (_e: unknown, f: string) => f,
}))
import { api } from '../../lib/api'

async function fill(current: string, next: string, confirm: string) {
  await userEvent.type(screen.getByLabelText('Current Password'), current)
  await userEvent.type(screen.getByLabelText('New Password'), next)
  await userEvent.type(screen.getByLabelText('Confirm New Password'), confirm)
}

describe('ChangePassword uses the shared password rule', () => {
  beforeEach(() => vi.clearAllMocks())

  it('shows which requirements are met', async () => {
    renderWithProviders(<ChangePassword />)
    await userEvent.type(screen.getByLabelText('New Password'), 'abcdefgh')
    expect(screen.getByText(/✓ 8\+ chars/)).toBeInTheDocument()
    expect(screen.getByText(/✗ number/)).toBeInTheDocument()
    expect(screen.getByText(/✗ special/)).toBeInTheDocument()
  })

  it('does not submit a password without a special character', async () => {
    renderWithProviders(<ChangePassword />)
    await fill('old-pass', 'abcdefg1', 'abcdefg1')
    await userEvent.click(screen.getByRole('button', { name: /change password|update|save/i }))
    expect(api.post).not.toHaveBeenCalled()
  })

  it('submits a password that meets every requirement', async () => {
    renderWithProviders(<ChangePassword />)
    await fill('old-pass', 'abcdef1!', 'abcdef1!')
    await userEvent.click(screen.getByRole('button', { name: /change password|update|save/i }))
    expect(api.post).toHaveBeenCalledWith('change-password', { current_password: 'old-pass', new_password: 'abcdef1!' })
  })
})
