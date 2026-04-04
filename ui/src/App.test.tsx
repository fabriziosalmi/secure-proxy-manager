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

import { api } from './lib/api'

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

  it('clears expired token on mount', () => {
    const payload = btoa(JSON.stringify({ sub: 'admin', exp: Math.floor(Date.now() / 1000) - 120 }))
    const fakeToken = `eyJhbGciOiJIUzI1NiJ9.${payload}.signature`
    localStorage.setItem('auth_token', fakeToken)

    render(<App />)
    expect(screen.getByText(/sign in to continue/i)).toBeInTheDocument()
    expect(localStorage.getItem('auth_token')).toBeNull()
  })
})
