import { describe, it, expect, vi, beforeEach } from 'vitest'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderWithProviders } from '../../test/helpers'
import { ChangePassword } from './ChangePassword'

vi.mock('../../lib/api', () => ({
  api: { post: vi.fn(() => Promise.resolve({ data: {} })) },
  setAuthToken: vi.fn(),
  getErrorMessage: (e: unknown, f: string) => (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail ?? f,
}))
import { api, setAuthToken } from '../../lib/api'

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
    const rules = screen.getByRole('list', { name: 'Password rules' })
    expect(rules).toHaveTextContent('Has at least 8 characters')
    expect(rules).toHaveTextContent('Missing a number')
    expect(rules).toHaveTextContent('Missing a special character')
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

  // The change ends every earlier session, including this one; the backend
  // returns a fresh token and the page must keep it or it is signed out.
  it('keeps the session going with the token the change returns', async () => {
    vi.mocked(api.post).mockResolvedValueOnce({ data: { status: 'success', access_token: 'fresh-token' } })
    renderWithProviders(<ChangePassword />)
    await fill('old-pass', 'abcdef1!', 'abcdef1!')
    await userEvent.click(screen.getByRole('button', { name: /change password|update|save/i }))
    await vi.waitFor(() => expect(setAuthToken).toHaveBeenCalledWith('fresh-token'))
    expect(await screen.findByText('Password changed. Every other session was signed out; this one continues.')).toBeInTheDocument()
  })

  // The backend's refusal is shown under the form, not in a toast.
  it('shows why the backend refused the change', async () => {
    vi.mocked(api.post).mockRejectedValueOnce({ response: { data: { detail: 'current password is incorrect' } } })
    renderWithProviders(<ChangePassword />)
    await fill('wrong-pass', 'abcdef1!', 'abcdef1!')
    await userEvent.click(screen.getByRole('button', { name: 'Change Password' }))
    expect(await screen.findByRole('status')).toHaveTextContent('Not changed: current password is incorrect.')
  })
})
