import { describe, it, expect, vi, beforeEach } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderWithProviders } from '../test/helpers'
import { expectNoAxeViolations } from '../test/axe'
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

  it('renders login form with username and password fields and a password reveal toggle', async () => {
    const user = userEvent.setup()
    renderWithProviders(<Login onLogin={onLogin} />)
    expect(screen.getByLabelText('Username')).toBeInTheDocument()
    const pwd = screen.getByLabelText('Password')
    expect(pwd).toBeInTheDocument()
    expect(pwd).toHaveAttribute('type', 'password')
    expect(screen.getByRole('button', { name: /sign in/i })).toBeInTheDocument()
    expect(screen.getByText(/secure proxy manager/i)).toBeInTheDocument()

    const revealBtn = screen.getByRole('button', { name: 'Show password' })
    await user.click(revealBtn)
    expect(pwd).toHaveAttribute('type', 'text')
    await user.click(screen.getByRole('button', { name: 'Hide password' }))
    expect(pwd).toHaveAttribute('type', 'password')
  })

  it('calls API and stores token on successful login', async () => {
    const user = userEvent.setup()
    vi.mocked(api.post).mockResolvedValueOnce({
      data: { access_token: 'test-jwt-token' },
    })

    renderWithProviders(<Login onLogin={onLogin} />)

    await user.type(screen.getByLabelText('Username'), 'admin')
    await user.type(screen.getByLabelText('Password'), 'secret')
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

  it('shows Invalid username or password on 401', async () => {
    const user = userEvent.setup()
    const err401 = Object.assign(new Error('Unauthorized'), {
      isAxiosError: true,
      response: { status: 401, data: { detail: 'incorrect username or password' } },
    })
    vi.mocked(api.post).mockRejectedValueOnce(err401)

    renderWithProviders(<Login onLogin={onLogin} />)

    await user.type(screen.getByLabelText('Username'), 'admin')
    await user.type(screen.getByLabelText('Password'), 'wrong')
    await user.click(screen.getByRole('button', { name: /sign in/i }))

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent('Invalid username or password')
    })
    expect(onLogin).not.toHaveBeenCalled()
  })

  it('shows the backend rate-limit detail on 429 instead of Invalid username or password', async () => {
    const user = userEvent.setup()
    const err429 = Object.assign(new Error('Too Many Requests'), {
      isAxiosError: true,
      response: {
        status: 429,
        data: { detail: 'too many failed attempts, try again later' },
      },
    })
    vi.mocked(api.post).mockRejectedValueOnce(err429)

    renderWithProviders(<Login onLogin={onLogin} />)

    await user.type(screen.getByLabelText('Username'), 'admin')
    await user.type(screen.getByLabelText('Password'), 'secret')
    await user.click(screen.getByRole('button', { name: /sign in/i }))

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent(/too many failed attempts, try again later/i)
    expect(alert).not.toHaveTextContent(/invalid username or password/i)
    expect(onLogin).not.toHaveBeenCalled()
  })

  it('shows The backend did not answer on 500 or when there is no response', async () => {
    const user = userEvent.setup()
    const err500 = Object.assign(new Error('Internal Server Error'), {
      isAxiosError: true,
      response: { status: 500, data: { detail: 'database locked' } },
    })
    vi.mocked(api.post).mockRejectedValueOnce(err500)

    renderWithProviders(<Login onLogin={onLogin} />)

    await user.type(screen.getByLabelText('Username'), 'admin')
    await user.type(screen.getByLabelText('Password'), 'secret')
    await user.click(screen.getByRole('button', { name: /sign in/i }))

    const alert500 = await screen.findByRole('alert')
    expect(alert500).toHaveTextContent(/The backend did not answer/i)
    expect(alert500).toHaveTextContent(/backend container/i)
    expect(alert500).not.toHaveTextContent(/invalid username or password/i)

    // Network failure (no response at all)
    vi.mocked(api.post).mockRejectedValueOnce(new Error('Network Error'))
    await user.click(screen.getByRole('button', { name: /sign in/i }))
    const alertNet = await screen.findByRole('alert')
    expect(alertNet).toHaveTextContent(/The backend did not answer/i)
    expect(alertNet).not.toHaveTextContent(/invalid username or password/i)
  })

  it('shows loading state while submitting', async () => {
    const user = userEvent.setup()
    let resolveLogin: (v: unknown) => void
    vi.mocked(api.post).mockImplementationOnce(
      () => new Promise((resolve) => { resolveLogin = resolve })
    )

    renderWithProviders(<Login onLogin={onLogin} />)

    await user.type(screen.getByLabelText('Username'), 'admin')
    await user.type(screen.getByLabelText('Password'), 'pass')
    await user.click(screen.getByRole('button', { name: /sign in/i }))

    expect(screen.getByText(/signing in/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /signing in/i })).toBeDisabled()

    resolveLogin!({ data: { access_token: 'tok' } })
    await waitFor(() => expect(onLogin).toHaveBeenCalled())
  })

  it('accepts token from alternate field name', async () => {
    const user = userEvent.setup()
    vi.mocked(api.post).mockResolvedValueOnce({
      data: { token: 'alt-token' },
    })

    renderWithProviders(<Login onLogin={onLogin} />)

    await user.type(screen.getByLabelText('Username'), 'u')
    await user.type(screen.getByLabelText('Password'), 'p')
    await user.click(screen.getByRole('button', { name: /sign in/i }))

    await waitFor(() => {
      expect(localStorage.getItem('auth_token')).toBe('alt-token')
    })
  })

  it('shows a distinct error when API returns no token at all', async () => {
    const user = userEvent.setup()
    vi.mocked(api.post).mockResolvedValueOnce({
      data: { status: 'success' }, // no access_token or token field
    })

    renderWithProviders(<Login onLogin={onLogin} />)

    await user.type(screen.getByLabelText('Username'), 'admin')
    await user.type(screen.getByLabelText('Password'), 'pass')
    await user.click(screen.getByRole('button', { name: /sign in/i }))

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent(/no token received/i)
    expect(alert).not.toHaveTextContent(/invalid username or password/i)
    expect(onLogin).not.toHaveBeenCalled()
  })

  it('does not expose arbitrary backend error details on 400/401', async () => {
    const user = userEvent.setup()
    const axiosError = Object.assign(new Error('Request failed'), {
      isAxiosError: true,
      response: { status: 400, data: { detail: 'SQL injection attempt detected' } },
    })
    vi.mocked(api.post).mockRejectedValueOnce(axiosError)

    renderWithProviders(<Login onLogin={onLogin} />)

    await user.type(screen.getByLabelText('Username'), 'admin')
    await user.type(screen.getByLabelText('Password'), 'pass')
    await user.click(screen.getByRole('button', { name: /sign in/i }))

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent('Invalid username or password')
      expect(screen.queryByText(/SQL injection/i)).not.toBeInTheDocument()
    })
  })

  it('has required attribute on both inputs', () => {
    renderWithProviders(<Login onLogin={onLogin} />)
    expect(screen.getByLabelText('Username')).toBeRequired()
    expect(screen.getByLabelText('Password')).toBeRequired()
  })

  it('has correct autocomplete attributes', () => {
    renderWithProviders(<Login onLogin={onLogin} />)
    expect(screen.getByLabelText('Username')).toHaveAttribute('autocomplete', 'username')
    expect(screen.getByLabelText('Password')).toHaveAttribute('autocomplete', 'current-password')
  })

  it.each(['light', 'dark'] as const)('passes axe accessibility checks in %s theme (including error state)', async (theme) => {
    document.documentElement.classList.toggle('dark', theme === 'dark')
    try {
      const user = userEvent.setup()
      vi.mocked(api.post).mockRejectedValueOnce(Object.assign(new Error('401'), {
        isAxiosError: true,
        response: { status: 401 },
      }))
      const { container } = renderWithProviders(<Login onLogin={onLogin} />)
      await expectNoAxeViolations(container)

      await user.type(screen.getByLabelText('Username'), 'admin')
      await user.type(screen.getByLabelText('Password'), 'wrong')
      await user.click(screen.getByRole('button', { name: /sign in/i }))
      await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument())
      await expectNoAxeViolations(container)
    } finally {
      document.documentElement.classList.remove('dark')
    }
  })
})
