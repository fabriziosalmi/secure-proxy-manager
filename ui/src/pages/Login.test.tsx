import { describe, it, expect, vi, beforeEach } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderWithProviders } from '../test/helpers'
import { Login } from './Login'

vi.mock('../lib/api', () => ({
  api: {
    post: vi.fn(),
    get: vi.fn(),
    interceptors: { request: { use: vi.fn() }, response: { use: vi.fn() } },
  },
  // Mirrors the real helper: persist the token so the existing assertions
  // on localStorage.getItem('auth_token') keep working after Login.tsx
  // switched from a direct setItem to setAuthToken().
  setAuthToken: (token: string) => localStorage.setItem('auth_token', token),
}))

import { api } from '../lib/api'

describe('Login', () => {
  const onLogin = vi.fn()

  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.removeItem('auth_token')
  })

  it('renders login form with username and password fields', () => {
    renderWithProviders(<Login onLogin={onLogin} />)
    expect(screen.getByLabelText(/username/i)).toBeInTheDocument()
    expect(screen.getByLabelText(/password/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /sign in/i })).toBeInTheDocument()
    expect(screen.getByText(/secure proxy manager/i)).toBeInTheDocument()
  })

  it('calls API and stores token on successful login', async () => {
    const user = userEvent.setup()
    vi.mocked(api.post).mockResolvedValueOnce({
      data: { access_token: 'test-jwt-token' },
    })

    renderWithProviders(<Login onLogin={onLogin} />)

    await user.type(screen.getByLabelText(/username/i), 'admin')
    await user.type(screen.getByLabelText(/password/i), 'secret')
    await user.click(screen.getByRole('button', { name: /sign in/i }))

    await waitFor(() => {
      expect(api.post).toHaveBeenCalledWith('auth/login', {
        username: 'admin',
        password: 'secret',
      })
      expect(localStorage.getItem('auth_token')).toBe('test-jwt-token')
      expect(onLogin).toHaveBeenCalled()
    })
  })

  it('shows error message on failed login', async () => {
    const user = userEvent.setup()
    vi.mocked(api.post).mockRejectedValueOnce(new Error('401'))

    renderWithProviders(<Login onLogin={onLogin} />)

    await user.type(screen.getByLabelText(/username/i), 'admin')
    await user.type(screen.getByLabelText(/password/i), 'wrong')
    await user.click(screen.getByRole('button', { name: /sign in/i }))

    await waitFor(() => {
      expect(screen.getByText(/invalid username or password/i)).toBeInTheDocument()
    })
    expect(onLogin).not.toHaveBeenCalled()
  })

  it('shows loading state while submitting', async () => {
    const user = userEvent.setup()
    let resolveLogin: (v: unknown) => void
    vi.mocked(api.post).mockImplementationOnce(
      () => new Promise((resolve) => { resolveLogin = resolve })
    )

    renderWithProviders(<Login onLogin={onLogin} />)

    await user.type(screen.getByLabelText(/username/i), 'admin')
    await user.type(screen.getByLabelText(/password/i), 'pass')
    await user.click(screen.getByRole('button', { name: /sign in/i }))

    expect(screen.getByText(/signing in/i)).toBeInTheDocument()
    expect(screen.getByRole('button')).toBeDisabled()

    resolveLogin!({ data: { access_token: 'tok' } })
    await waitFor(() => expect(onLogin).toHaveBeenCalled())
  })

  it('accepts token from alternate field name', async () => {
    const user = userEvent.setup()
    vi.mocked(api.post).mockResolvedValueOnce({
      data: { token: 'alt-token' },
    })

    renderWithProviders(<Login onLogin={onLogin} />)

    await user.type(screen.getByLabelText(/username/i), 'u')
    await user.type(screen.getByLabelText(/password/i), 'p')
    await user.click(screen.getByRole('button', { name: /sign in/i }))

    await waitFor(() => {
      expect(localStorage.getItem('auth_token')).toBe('alt-token')
    })
  })

  it('shows error when API returns no token at all', async () => {
    const user = userEvent.setup()
    vi.mocked(api.post).mockResolvedValueOnce({
      data: { status: 'success' }, // no access_token or token field
    })

    renderWithProviders(<Login onLogin={onLogin} />)

    await user.type(screen.getByLabelText(/username/i), 'admin')
    await user.type(screen.getByLabelText(/password/i), 'pass')
    await user.click(screen.getByRole('button', { name: /sign in/i }))

    await waitFor(() => {
      expect(screen.getByText(/invalid username or password/i)).toBeInTheDocument()
    })
    expect(onLogin).not.toHaveBeenCalled()
  })

  it('does not expose backend error details', async () => {
    const user = userEvent.setup()
    const axiosError = new Error('Request failed')
    Object.assign(axiosError, {
      response: { data: { detail: 'SQL injection attempt detected' } },
    })
    vi.mocked(api.post).mockRejectedValueOnce(axiosError)

    renderWithProviders(<Login onLogin={onLogin} />)

    await user.type(screen.getByLabelText(/username/i), 'admin')
    await user.type(screen.getByLabelText(/password/i), 'pass')
    await user.click(screen.getByRole('button', { name: /sign in/i }))

    await waitFor(() => {
      // Should show generic error, NOT the backend detail
      expect(screen.getByText(/invalid username or password/i)).toBeInTheDocument()
      expect(screen.queryByText(/SQL injection/i)).not.toBeInTheDocument()
    })
  })

  it('has required attribute on both inputs', () => {
    renderWithProviders(<Login onLogin={onLogin} />)
    expect(screen.getByLabelText(/username/i)).toBeRequired()
    expect(screen.getByLabelText(/password/i)).toBeRequired()
  })

  it('has correct autocomplete attributes', () => {
    renderWithProviders(<Login onLogin={onLogin} />)
    expect(screen.getByLabelText(/username/i)).toHaveAttribute('autocomplete', 'username')
    expect(screen.getByLabelText(/password/i)).toHaveAttribute('autocomplete', 'current-password')
  })
})
