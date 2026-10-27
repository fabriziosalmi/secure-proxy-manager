import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import toast from 'react-hot-toast'
import App from './App'

vi.mock('./lib/api', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(),
    interceptors: { request: { use: vi.fn() }, response: { use: vi.fn() } },
  },
  getData: (path: string) => (api.get(path) as Promise<{ data?: { data?: unknown } }>).then((r) => r?.data?.data ?? null),
  loadSession: vi.fn(() => Promise.resolve(null)),
  getErrorMessage: (_e: unknown, f: string) => f,
  signOut: vi.fn(() => Promise.resolve()),
}))

import { api, loadSession } from './lib/api'

// GET /api/session answers for a signed-in admin (the cookie is HttpOnly:
// the page learns of the session only from the backend).
function signedIn() {
  vi.mocked(loadSession).mockResolvedValue({ username: 'admin', via: 'cookie', expires_at: Math.floor(Date.now() / 1000) + 3600 })
}

function clearStorage() {
  vi.mocked(loadSession).mockResolvedValue(null)
}

describe('App', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    clearStorage()
  })

  it('shows login page when not authenticated', async () => {
    render(<App />)
    expect(await screen.findByText(/sign in to continue/i)).toBeInTheDocument()
    expect(screen.getByLabelText(/username/i)).toBeInTheDocument()
  })

  it('shows loading spinner when authenticated and checking wizard', () => {
    signedIn()

    vi.mocked(api.get).mockImplementation(() => new Promise(() => {}))

    render(<App />)
    const spinner = document.querySelector('.animate-spin')
    expect(spinner).toBeTruthy()
  })

  it('does not skip the wizard when GET /api/settings fails on first load, and shows an error with Try again', async () => {
    const user = userEvent.setup()
    signedIn()

    let attempts = 0
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url === 'settings') {
        attempts += 1
        if (attempts === 1) {
          return Promise.reject(new Error('500 Internal Server Error'))
        }
        return Promise.resolve({
          data: {
            data: [{ setting_name: 'wizard_completed', setting_value: 'false' }],
          },
        })
      }
      return Promise.resolve({ data: { data: [] } })
    })

    render(<App />)

    const retryBtn = await screen.findByRole('button', { name: /try again/i })
    expect(retryBtn).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: /overview|dashboard/i })).not.toBeInTheDocument()
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()

    await user.click(retryBtn)
    expect(await screen.findByRole('heading', { name: /welcome to secure proxy manager/i })).toBeInTheDocument()
  })

  it('shows dashboard after auth and wizard check', async () => {
    signedIn()

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
    signedIn()
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

  it('shows the sign-in screen when GET /api/session has no session, and never reads localStorage for one', async () => {
    localStorage.setItem('auth_token', 'left-by-an-old-version')
    render(<App />)
    expect(await screen.findByText(/sign in to continue/i)).toBeInTheDocument()
    expect(loadSession).toHaveBeenCalled()
    localStorage.removeItem('auth_token')
  })

  it('returns to the sign-in screen when the session ends under the page', async () => {
    signedIn()
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url === 'settings') return Promise.resolve({ data: { data: [{ setting_name: 'wizard_completed', setting_value: 'true' }] } })
      return Promise.resolve({ data: { data: [] } })
    })
    render(<App />)
    expect(await screen.findByRole('navigation', { name: 'Main' }, { timeout: 5000 })).toBeInTheDocument()
    vi.mocked(loadSession).mockResolvedValue(null)
    window.dispatchEvent(new CustomEvent('session-ended'))
    expect(await screen.findByText(/sign in to continue/i)).toBeInTheDocument()
  })

  it('makes 3 GET requests (1 settings, 1 status, 1 health) after GET /api/session, instead of 6, when mounting /settings/access inside App', async () => {
    signedIn()
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url === 'settings') {
        return Promise.resolve({
          data: {
            data: [
              { setting_name: 'wizard_completed', setting_value: 'true' },
              { setting_name: 'egress_default_deny', setting_value: 'false' },
            ],
          },
        })
      }
      if (url === 'status') return Promise.resolve({ data: { data: { proxy_status: 'running', version: '3.14.3' } } })
      if (url === 'health') return Promise.resolve({ data: { status: 'healthy', version: '3.14.3', runtime: 'go' } })
      return Promise.resolve({ data: { data: [], meta: { total: 0 } } })
    })

    window.history.pushState({}, '', '/settings/access')
    try {
      render(<App />)
      expect(await screen.findByRole('heading', { level: 2, name: 'Clients and access' }, { timeout: 5000 })).toBeInTheDocument()
      await screen.findByText('Backend and proxy running')
      const urls = vi.mocked(api.get).mock.calls.map(([u]) => String(u))
      expect(urls.filter((u) => u === 'settings')).toHaveLength(1)
      expect(urls).toHaveLength(3)
    } finally {
      window.history.pushState({}, '', '/')
    }
  })

  it('keeps the app and its unsaved drafts when a settings refetch fails after the first load', async () => {
    signedIn()
    let settingsDown = false
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url === 'settings') {
        if (settingsDown) return Promise.reject(Object.assign(new Error('502'), { response: { status: 502 } }))
        return Promise.resolve({ data: { data: [{ setting_name: 'wizard_completed', setting_value: 'true' }] } })
      }
      return Promise.resolve({ data: { data: [], meta: { total: 0 } } })
    })
    vi.mocked(api.post).mockResolvedValue({ data: { status: 'success', data: {} } })

    window.history.pushState({}, '', '/settings/access')
    try {
      render(<App />)
      fireEvent.click(await screen.findByRole('switch', { name: 'Require proxy login' }, { timeout: 5000 }))
      fireEvent.change(screen.getByLabelText('Proxy username'), { target: { value: 'office' } })
      fireEvent.change(screen.getByLabelText('Proxy password'), { target: { value: 'correct-horse-battery' } })
      settingsDown = true
      fireEvent.click(within(screen.getByTestId('save-bar')).getByRole('button', { name: 'Save section' }))
      await waitFor(() => expect(vi.mocked(api.get).mock.calls.filter(([u]) => u === 'settings').length).toBeGreaterThan(1))
      // Past the default retry (1 retry after about 1 s), so the refetch has settled as failed.
      await new Promise((r) => setTimeout(r, 2500))
      expect(screen.queryByText(/The backend did not answer/)).not.toBeInTheDocument()
      expect(screen.getByRole('heading', { level: 2, name: 'Clients and access' })).toBeInTheDocument()
    } finally {
      window.history.pushState({}, '', '/')
    }
  }, 15000)

  it('does not open a duplicate global toast when a page with an inline error receives a 500 response', async () => {
    const toastErrorSpy = vi.spyOn(toast, 'error')
    signedIn()
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url === 'settings') {
        return Promise.resolve({ data: { data: [{ setting_name: 'wizard_completed', setting_value: 'true' }] } })
      }
      if (url.startsWith('audit')) {
        return Promise.reject(Object.assign(new Error('500 Internal Server Error'), { response: { status: 500 } }))
      }
      return Promise.resolve({ data: { data: [] } })
    })

    window.history.pushState({}, '', '/audit')
    try {
      render(<App />)
      expect(await screen.findByText(/could not load audit events/i, {}, { timeout: 5000 })).toBeInTheDocument()
      expect(toastErrorSpy).not.toHaveBeenCalled()
    } finally {
      toastErrorSpy.mockRestore()
      window.history.pushState({}, '', '/')
    }
  })
})
