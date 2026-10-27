import { describe, it, expect, vi, beforeEach } from 'vitest'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderWithProviders } from '../../test/helpers'
import { ChangePassword, PasswordInput } from './ChangePassword'

vi.mock('../../lib/api', () => ({
  api: { post: vi.fn(() => Promise.resolve({ data: {} })) },
  startSession: vi.fn(),
  getErrorMessage: (e: unknown, f: string) => (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail ?? f,
}))
import { api, startSession } from '../../lib/api'

async function fill(current: string, next: string, confirm: string) {
  await userEvent.type(screen.getByLabelText('Current password'), current)
  await userEvent.type(screen.getByLabelText('New password'), next)
  await userEvent.type(screen.getByLabelText('Confirm new password'), confirm)
}

describe('ChangePassword uses the shared password rule', () => {
  beforeEach(() => vi.clearAllMocks())

  it('shows which requirements are met', async () => {
    renderWithProviders(<ChangePassword />)
    await userEvent.type(screen.getByLabelText('New password'), 'abcdefgh')
    const rules = screen.getByRole('list', { name: 'Password rules' })
    expect(rules).toHaveTextContent('Has at least 8 characters')
    expect(rules).toHaveTextContent('Missing a number')
    expect(rules).toHaveTextContent('Missing a special character')
  })

  it('does not submit a password without a special character', async () => {
    renderWithProviders(<ChangePassword />)
    await fill('old-pass', 'abcdefg1', 'abcdefg1')
    await userEvent.click(screen.getByRole('button', { name: 'Change password' }))
    expect(api.post).not.toHaveBeenCalled()
  })

  it('submits a password that meets every requirement', async () => {
    renderWithProviders(<ChangePassword />)
    await fill('old-pass', 'abcdef1!', 'abcdef1!')
    await userEvent.click(screen.getByRole('button', { name: 'Change password' }))
    expect(api.post).toHaveBeenCalledWith('change-password', { current_password: 'old-pass', new_password: 'abcdef1!' })
  })

  // The change ends every earlier session, including this one; the backend
  // returns a fresh token and the page must keep it or it is signed out.
  it('keeps the session going: the backend renews the cookie and the page re-plans the expiry it returns', async () => {
    vi.mocked(api.post).mockResolvedValueOnce({ data: { status: 'success', expires_at: 1900000000 } })
    renderWithProviders(<ChangePassword />)
    await fill('old-pass', 'abcdef1!', 'abcdef1!')
    await userEvent.click(screen.getByRole('button', { name: 'Change password' }))
    await vi.waitFor(() => expect(startSession).toHaveBeenCalledWith(1900000000))
    expect(await screen.findByText('Password changed. Every other session was signed out; this one continues.')).toBeInTheDocument()
  })

  // The backend's refusal is shown under the form, not in a toast.
  it('shows why the backend refused the change', async () => {
    vi.mocked(api.post).mockRejectedValueOnce({ response: { data: { detail: 'current password is incorrect' } } })
    renderWithProviders(<ChangePassword />)
    await fill('wrong-pass', 'abcdef1!', 'abcdef1!')
    await userEvent.click(screen.getByRole('button', { name: 'Change password' }))
    expect(await screen.findByRole('status')).toHaveTextContent('Not changed: current password is incorrect.')
  })

  it('provides sentence-case labels and a reveal button on all three password inputs including Confirm new password', async () => {
    renderWithProviders(<ChangePassword />)
    expect(screen.getByRole('button', { name: 'Show current password' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Show new password' })).toBeInTheDocument()
    const confirmReveal = screen.getByRole('button', { name: 'Show confirm new password' })
    expect(confirmReveal).toBeInTheDocument()
    const confirmInput = screen.getByLabelText('Confirm new password')
    expect(confirmInput).toHaveAttribute('type', 'password')
    await userEvent.click(confirmReveal)
    expect(confirmInput).toHaveAttribute('type', 'text')
  })

  it('positions the reveal toggle inside a full-width relative wrapper with aria-pressed and Tab order after the input', async () => {
    const user = userEvent.setup()
    renderWithProviders(
      <div>
        <PasswordInput id="plain-pwd" label="Plain password" value="" onChange={() => {}} autoComplete="current-password" />
        <PasswordInput id="reveal-pwd" label="Reveal password" value="" onChange={() => {}} autoComplete="current-password" reveal />
      </div>,
    )
    const plainInput = screen.getByLabelText('Plain password')
    const revealInput = screen.getByLabelText('Reveal password')
    const revealBtn = screen.getByRole('button', { name: 'Show reveal password' })

    expect(plainInput.className).toMatch(/\bw-full\b/)
    expect(revealInput.className).toMatch(/\bw-full\b/)
    expect(revealInput.className).toMatch(/\bpr-10\b/)
    expect(revealInput.parentElement).toBe(revealBtn.parentElement)
    expect(revealInput.parentElement?.className).toMatch(/\brelative\b/)
    expect(revealInput.parentElement?.className).not.toMatch(/\bflex\b/)
    expect(revealBtn.className).toMatch(/\babsolute\b/)
    expect(revealBtn).toHaveAttribute('aria-pressed', 'false')

    revealInput.focus()
    expect(document.activeElement).toBe(revealInput)
    await user.tab()
    expect(document.activeElement).toBe(revealBtn)

    await user.click(revealBtn)
    expect(revealBtn).toHaveAttribute('aria-pressed', 'true')
    expect(revealBtn).toHaveAccessibleName('Show reveal password')
    expect(revealInput).toHaveAttribute('type', 'text')
  })
})
