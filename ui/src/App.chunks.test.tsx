import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import App from './App'

// A tab left open across an upgrade asks for chunk names the new build no
// longer serves, so the dynamic import of a lazy screen rejects.
vi.mock('./pages/Login', () => {
  throw new Error('Failed to fetch dynamically imported module')
})

vi.mock('./lib/api', () => ({
  api: { get: vi.fn(), post: vi.fn(), interceptors: { request: { use: vi.fn() }, response: { use: vi.fn() } } },
  getData: vi.fn(),
  loadSession: vi.fn(() => Promise.resolve(null)),
  getErrorMessage: (_e: unknown, f: string) => f,
  signOut: vi.fn(() => Promise.resolve()),
}))

describe('App lazy screens', () => {
  it('shows an error with Try again, not a blank page, when the sign-in screen fails to load', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    localStorage.removeItem('auth_token')
    render(<App />)
    expect(await screen.findByText('Something went wrong')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Try again' })).toBeInTheDocument()
  })
})
