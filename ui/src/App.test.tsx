import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import App from './App'

vi.mock('./lib/api', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(),
    interceptors: { request: { use: vi.fn() }, response: { use: vi.fn() } },
  },
  isTokenExpired: vi.fn(() => false),
  getErrorMessage: (_e: unknown, f: string) => f,
}))

import { api, isTokenExpired } from './lib/api'

function clearStorage() {
  localStorage.removeItem('auth_token')
}

describe('App', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    clearStorage()
  })

  it('shows login page when not authenticated', () => {
    render(<App />)
    expect(screen.getByText(/sign in to continue/i)).toBeInTheDocument()
    expect(screen.getByLabelText(/username/i)).toBeInTheDocument()
  })

  it('shows loading spinner when authenticated and checking wizard', () => {
    const payload = btoa(JSON.stringify({ sub: 'admin', exp: Math.floor(Date.now() / 1000) + 3600 }))
    const fakeToken = `eyJhbGciOiJIUzI1NiJ9.${payload}.signature`
    localStorage.setItem('auth_token', fakeToken)

    vi.mocked(api.get).mockImplementation(() => new Promise(() => {}))

    render(<App />)
    const spinner = document.querySelector('.animate-spin')
    expect(spinner).toBeTruthy()
  })

  it('shows dashboard after auth and wizard check', async () => {
    const payload = btoa(JSON.stringify({ sub: 'admin', exp: Math.floor(Date.now() / 1000) + 3600 }))
    const fakeToken = `eyJhbGciOiJIUzI1NiJ9.${payload}.signature`
    localStorage.setItem('auth_token', fakeToken)

    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url === 'settings') {
        return Promise.resolve({
          data: {
            data: [{ setting_name: 'wizard_completed', setting_value: 'true' }],
          },
        })
      }
      return Promise.resolve({ data: { data: [] } })
    })

    render(<App />)
    await waitFor(() => {
      expect(screen.getAllByText(/dashboard/i).length).toBeGreaterThan(0)
    })
  })

  // Threat Intel became Analytics: an old link or bookmark to /threats must
  // still land on the page, under its new address and name.
  it('sends /threats to /analytics, the renamed Threat Intel page', async () => {
    const payload = btoa(JSON.stringify({ sub: 'admin', exp: Math.floor(Date.now() / 1000) + 3600 }))
    localStorage.setItem('auth_token', `eyJhbGciOiJIUzI1NiJ9.${payload}.signature`)
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url === 'settings') {
        return Promise.resolve({ data: { data: [{ setting_name: 'wizard_completed', setting_value: 'true' }] } })
      }
      return Promise.resolve({ data: { data: [] } })
    })
    window.history.pushState({}, '', '/threats')
    try {
      render(<App />)
      expect(await screen.findByRole('heading', { level: 1, name: 'Analytics' }, { timeout: 5000 })).toBeInTheDocument()
      expect(window.location.pathname).toBe('/analytics')
      expect(screen.getByRole('link', { name: 'Analytics' })).toHaveAttribute('aria-current', 'page')
    } finally {
      window.history.pushState({}, '', '/')
    }
  })

  it('clears expired token on mount', () => {
    const payload = btoa(JSON.stringify({ sub: 'admin', exp: Math.floor(Date.now() / 1000) - 120 }))
    const fakeToken = `eyJhbGciOiJIUzI1NiJ9.${payload}.signature`
    localStorage.setItem('auth_token', fakeToken)
    // App delegates expiry detection to the shared isTokenExpired helper
    // (unit-tested in lib/api.test.ts); here we assert App acts on its verdict.
    vi.mocked(isTokenExpired).mockReturnValue(true)

    render(<App />)
    expect(screen.getByText(/sign in to continue/i)).toBeInTheDocument()
    expect(localStorage.getItem('auth_token')).toBeNull()
  })
})
