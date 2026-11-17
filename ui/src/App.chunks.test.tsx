import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import App, { ErrorBoundary } from './App'
import { browser } from './lib/api'
import { isChunkLoadError } from './lib/chunkLoad'

// A tab left open across an upgrade asks for chunk names the new build no
// longer serves, so the dynamic import of a lazy screen rejects. The getter
// rejects the lazy import with the browser's own message; a factory that
// throws would reach the boundary as Vitest's mocking error instead.
vi.mock('./pages/Login', () => ({
  get Login() {
    throw new Error('Failed to fetch dynamically imported module: https://spm.example/assets/Login-abc.js')
  },
}))

vi.mock('./lib/api', () => ({
  api: { get: vi.fn(), post: vi.fn(), interceptors: { request: { use: vi.fn() }, response: { use: vi.fn() } } },
  getData: vi.fn(),
  loadSession: vi.fn(() => Promise.resolve(null)),
  getErrorMessage: (_e: unknown, f: string) => f,
  signOut: vi.fn(() => Promise.resolve()),
  browser: { assign: vi.fn(), reload: vi.fn() },
}))

describe('App lazy screens', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.spyOn(console, 'error').mockImplementation(() => {})
    localStorage.removeItem('auth_token')
  })

  it('shows an error, not a blank page, when the sign-in screen fails to load', async () => {
    render(<App />)
    expect(await screen.findByText('Something went wrong')).toBeInTheDocument()
  })

  // React.lazy keeps the rejected import and throws it again on every
  // render, so resetting the boundary brings back the same screen: only a
  // reload fetches the new build's chunks.
  it('reloads the page from the error screen when a chunk failed to load', async () => {
    render(<App />)
    await screen.findByText('Something went wrong')
    await userEvent.click(screen.getByRole('button'))
    expect(browser.reload).toHaveBeenCalledTimes(1)
    expect(screen.getByText(/new version/)).toBeInTheDocument()
  })
})

function Throws({ message }: { message: string }): never {
  throw new Error(message)
}

describe('ErrorBoundary', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.spyOn(console, 'error').mockImplementation(() => {})
  })

  it('keeps Try again, and does not reload, for an error that is not a chunk load', async () => {
    render(<ErrorBoundary><Throws message="Cannot read properties of undefined" /></ErrorBoundary>)
    expect(screen.queryByText(/new version/)).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Try again' }))
    expect(browser.reload).not.toHaveBeenCalled()
  })

  it.each([
    ['Chrome', 'Failed to fetch dynamically imported module: https://spm.example/assets/Logs-abc.js'],
    ['Firefox', 'error loading dynamically imported module: https://spm.example/assets/Logs-abc.js'],
    ['Safari', 'Importing a module script failed.'],
    ['Vite CSS preload', 'Unable to preload CSS for /assets/Logs-abc.css'],
  ])('recognises a failed chunk load from %s', (_from, message) => {
    expect(isChunkLoadError(new Error(message))).toBe(true)
  })
})
