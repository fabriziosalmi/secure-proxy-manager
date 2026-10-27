import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, within, waitFor, fireEvent, act } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Routes, Route, Link, useLocation } from 'react-router'
import { QueryClientProvider } from '@tanstack/react-query'
import { ThemeProvider } from '../ThemeProvider'
import { GlobalSearch } from '../GlobalSearch'
import { Layout } from './Layout'
import { isActivePath, summarizeHealth, NAV_GROUPS } from './nav'
import { createTestQueryClient } from '../../test/helpers'
import { expectNoAxeViolations } from '../../test/axe'
import { DESKTOP_QUERY } from '../../hooks/useMediaQuery'
import { useEffect } from 'react'
import { SettingsDraftsProvider } from '../settings/SettingsDrafts'
import { useSettingsDrafts } from '../../hooks/useSettingsDrafts'

const get = vi.fn()

vi.mock('../../lib/api', () => ({
  api: {
    get: (...a: unknown[]) => get(...a),
    post: vi.fn(),
    interceptors: { request: { use: vi.fn() }, response: { use: vi.fn() } },
  },
  getData: (path: string) => get(path).then((r: { data?: { data?: unknown } }) => r?.data?.data ?? null),
  getErrorMessage: (_e: unknown, f: string) => f,
}))

type Status = { proxy_status?: string; version?: string } | 'fail'

function answer(status: Status = { proxy_status: 'running', version: '3.14.3' }) {
  get.mockImplementation((url: string) => {
    if (url === 'status') return status === 'fail' ? Promise.reject(new Error('down')) : Promise.resolve({ data: { status: 'success', data: status } })
    if (url === 'health') return Promise.resolve({ data: { status: 'healthy', version: '3.14.3', runtime: 'go' } })
    return Promise.resolve({ data: { data: [] } })
  })
}

function setViewport(desktop: boolean) {
  Object.defineProperty(window, 'matchMedia', {
    configurable: true,
    writable: true,
    value: (query: string) => ({
      matches: desktop && query === DESKTOP_QUERY,
      media: query,
      onchange: null,
      addEventListener: () => {},
      removeEventListener: () => {},
      addListener: () => {},
      removeListener: () => {},
      dispatchEvent: () => false,
    }),
  })
}

function Where() {
  return <p data-testid="where">{useLocation().pathname}</p>
}

function shell(path = '/', onLogout = vi.fn()) {
  const client = createTestQueryClient()
  const utils = render(
    <QueryClientProvider client={client}>
      <ThemeProvider>
        <MemoryRouter initialEntries={[path]}>
          <GlobalSearch />
          <Routes>
            <Route path="/" element={<Layout onLogout={onLogout} />}>
              <Route index element={<h1>Dashboard page</h1>} />
              <Route path="*" element={<><h1>Other page</h1><Where /></>} />
            </Route>
          </Routes>
        </MemoryRouter>
      </ThemeProvider>
    </QueryClientProvider>,
  )
  return { ...utils, onLogout }
}

const sidebar = () => document.getElementById('app-sidebar') as HTMLElement
const mainNav = () => within(sidebar()).getByRole('navigation', { name: 'Main' })

// jsdom has no layout, so every offsetParent is null and useModal would find
// nothing to focus. Give elements a parent, as a browser does for visible ones.
const offsetParent = Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'offsetParent')

beforeEach(() => {
  localStorage.clear()
  answer()
  Object.defineProperty(HTMLElement.prototype, 'offsetParent', { configurable: true, get() { return this.parentNode } })
})

afterEach(() => {
  vi.restoreAllMocks()
  if (offsetParent) Object.defineProperty(HTMLElement.prototype, 'offsetParent', offsetParent)
  document.documentElement.classList.remove('dark')
})

describe('active item', () => {
  it('matches by first path segment', () => {
    expect(isActivePath('/', '/')).toBe(true)
    expect(isActivePath('/logs', '/')).toBe(false)
    expect(isActivePath('/settings', '/settings')).toBe(true)
    expect(isActivePath('/settings/alerts', '/settings')).toBe(true)
    expect(isActivePath('/settingsx', '/settings')).toBe(false)
    expect(isActivePath('/analytics', '/settings')).toBe(false)
  })
})

describe('service health line', () => {
  it('is healthy only when the status says the proxy is running', () => {
    // /api/status answers for the backend and the proxy only, so the line
    // names those two and claims nothing about the other services.
    expect(summarizeHealth({ proxy_status: 'running' }, 'success')).toMatchObject({ tone: 'success', text: 'Backend and proxy running' })
    expect(summarizeHealth({ proxy_status: 'error' }, 'success')).toMatchObject({ tone: 'warning', text: 'Proxy not running', down: ['Proxy'] })
  })

  it('never says healthy while loading or after a failure', () => {
    expect(summarizeHealth(undefined, 'pending')).toMatchObject({ tone: 'unknown', text: 'Checking the backend and proxy' })
    expect(summarizeHealth(undefined, 'error')).toMatchObject({ tone: 'unknown', text: 'Backend not reachable', down: ['Backend'] })
    expect(summarizeHealth(null, 'success')).toMatchObject({ tone: 'unknown', text: 'Status unknown' })
  })
})

describe('shell on a wide screen', () => {
  beforeEach(() => setViewport(true))

  it('groups the navigation as approved and marks the current page', async () => {
    const { container } = shell('/')
    const groups = within(mainNav()).getAllByRole('list')
    const byGroup = Object.fromEntries(groups.map((ul) => [
      ul.getAttribute('aria-labelledby') && document.getElementById(ul.getAttribute('aria-labelledby')!)?.textContent,
      within(ul).getAllByRole('link').map((a) => [a.getAttribute('aria-label'), a.getAttribute('href')]),
    ]))
    expect(byGroup).toEqual({
      Overview: [['Dashboard', '/'], ['Analytics', '/analytics']],
      Traffic: [['Access logs', '/logs'], ['Clients', '/clients']],
      Protection: [['Blacklists', '/blacklists'], ['Egress allowlist', '/egress']],
      System: [['Settings', '/settings'], ['Audit log', '/audit']],
    })
    const dash = within(mainNav()).getByRole('link', { name: 'Dashboard' })
    expect(dash).toHaveAttribute('aria-current', 'page')
    expect(dash.className).toMatch(/bg-accent-subtle/)
    expect(dash.className).toMatch(/text-accent/)
    expect(within(mainNav()).getByRole('link', { name: 'Analytics' })).not.toHaveAttribute('aria-current')
    await screen.findByText('Backend and proxy running')
    await expectNoAxeViolations(container)
  })

  it('keeps Settings active on a settings sub-page', () => {
    shell('/settings/alerts')
    expect(within(mainNav()).getByRole('link', { name: 'Settings' })).toHaveAttribute('aria-current', 'page')
    expect(within(mainNav()).getByRole('link', { name: 'Dashboard' })).not.toHaveAttribute('aria-current')
  })

  it('keeps the page mounted between its sections and mounts a new page fresh', async () => {
    const user = userEvent.setup()
    function Sections() {
      return (
        <>
          <input aria-label="Draft" />
          <Link to="/settings/b">Section b</Link>
          <Link to="/logs">Logs</Link>
        </>
      )
    }
    const client = createTestQueryClient()
    render(
      <QueryClientProvider client={client}>
        <ThemeProvider>
          <MemoryRouter initialEntries={['/settings/a']}>
            <Routes>
              <Route path="/" element={<Layout />}>
                <Route path="settings/:section" element={<Sections />} />
                <Route path="logs" element={<Sections />} />
              </Route>
            </Routes>
          </MemoryRouter>
        </ThemeProvider>
      </QueryClientProvider>,
    )
    await user.type(screen.getByLabelText('Draft'), 'typed')
    const page = screen.getByLabelText('Draft').closest('.page-enter')
    await user.click(screen.getByRole('link', { name: 'Section b' }))
    expect(screen.getByLabelText('Draft')).toHaveValue('typed')
    expect(screen.getByLabelText('Draft').closest('.page-enter')).toBe(page)
    await user.click(screen.getByRole('link', { name: 'Logs' }))
    expect(screen.getByLabelText('Draft')).toHaveValue('')
    expect(screen.getByLabelText('Draft').closest('.page-enter')).not.toBe(page)
  })

  it('shows the product, the host and the backend version', async () => {
    shell('/')
    expect(within(sidebar()).getByText('Secure Proxy Manager')).toBeInTheDocument()
    expect(await within(sidebar()).findByText('v3.14.3')).toBeInTheDocument()
    expect(sidebar()).toHaveTextContent(window.location.hostname)
  })

  it('collapses to icons, keeps every link named, and remembers the choice', async () => {
    const { container, unmount } = shell('/logs')
    const toggle = within(sidebar()).getByRole('button', { name: 'Collapse sidebar' })
    expect(toggle).toHaveAttribute('aria-expanded', 'true')
    expect(toggle).toHaveAttribute('aria-controls', 'app-sidebar')
    await userEvent.click(toggle)

    const expand = within(sidebar()).getByRole('button', { name: 'Expand sidebar' })
    expect(expand).toHaveAttribute('aria-expanded', 'false')
    expect(sidebar().firstElementChild?.className).toMatch(/w-\[72px\]/)
    const logs = within(mainNav()).getByRole('link', { name: 'Access logs' })
    expect(logs).toHaveAttribute('title', 'Access logs')
    expect(logs).toHaveAttribute('aria-current', 'page')
    expect(logs).not.toHaveTextContent('Access logs')
    expect(localStorage.getItem('spm.sidebar.collapsed')).toBe('1')
    await screen.findByText('Backend and proxy running')
    await expectNoAxeViolations(container)

    unmount()
    shell('/logs')
    expect(within(sidebar()).getByRole('button', { name: 'Expand sidebar' })).toBeInTheDocument()
    await userEvent.click(within(sidebar()).getByRole('button', { name: 'Expand sidebar' }))
    expect(localStorage.getItem('spm.sidebar.collapsed')).toBe('0')
  })

  it('works when storage throws on every read and write', async () => {
    vi.spyOn(localStorage, 'getItem').mockImplementation(() => { throw new Error('SecurityError') })
    vi.spyOn(localStorage, 'setItem').mockImplementation(() => { throw new Error('QuotaExceededError') })
    shell('/')
    await userEvent.click(within(sidebar()).getByRole('button', { name: 'Collapse sidebar' }))
    expect(within(sidebar()).getByRole('button', { name: 'Expand sidebar' })).toHaveAttribute('aria-expanded', 'false')
  })

  it('has no drawer on a wide screen: not a dialog, not inert', () => {
    shell('/')
    expect(sidebar()).not.toHaveAttribute('role')
    expect(sidebar()).not.toHaveAttribute('inert')
  })

  it('opens the global search from the Search button', async () => {
    shell('/')
    await userEvent.click(within(sidebar()).getByRole('button', { name: 'Search' }))
    expect(await screen.findByRole('dialog', { name: 'Global search' })).toBeInTheDocument()
  })

  // The theme is chosen in Settings, Appearance: the shell has no control
  // for it, expanded or collapsed.
  it('has no theme control, expanded or collapsed', async () => {
    const { unmount } = shell('/')
    expect(within(sidebar()).queryByRole('group', { name: 'Theme' })).not.toBeInTheDocument()
    expect(within(sidebar()).queryByRole('button', { name: /theme/i })).not.toBeInTheDocument()
    await userEvent.click(within(sidebar()).getByRole('button', { name: 'Collapse sidebar' }))
    expect(within(sidebar()).queryByRole('button', { name: /theme/i })).not.toBeInTheDocument()
    unmount()
  })

  it('shows the product mark from logo.svg in the header, not a lucide shield', () => {
    shell('/')
    const mark = within(sidebar()).getByTestId('brand-mark')
    expect(mark.tagName).toBe('IMG')
    expect(mark).toHaveAttribute('src', '/logo.svg')
    expect(mark).toHaveAttribute('aria-hidden', 'true')
    expect(mark).toHaveAttribute('width', '32')
    expect(sidebar().querySelector('svg.lucide-shield-check, svg.lucide-shield')).toBeNull()
  })

  it('signs out from the footer', async () => {
    const { onLogout } = shell('/')
    await userEvent.click(within(sidebar()).getByRole('button', { name: 'Sign out' }))
    expect(onLogout).toHaveBeenCalledTimes(1)
  })

  it('asks before signing out over unsaved Settings changes, naming how many and where', async () => {
    function Drafts() {
      const d = useSettingsDrafts()
      useEffect(() => {
        d.setEdit('access', 'enable_time_restrictions', 'true')
        d.setEdit('access', 'time_restriction_start', '08:00')
        d.setEdit('alerts', 'enable_notifications', 'true')
        // eslint-disable-next-line react-hooks/exhaustive-deps
      }, [])
      return null
    }
    const onLogout = vi.fn()
    render(
      <QueryClientProvider client={createTestQueryClient()}>
        <ThemeProvider>
          <MemoryRouter initialEntries={['/']}>
            <SettingsDraftsProvider>
              <Drafts />
              <Routes>
                <Route path="/" element={<Layout onLogout={onLogout} />}>
                  <Route index element={<h1>Dashboard page</h1>} />
                </Route>
              </Routes>
            </SettingsDraftsProvider>
          </MemoryRouter>
        </ThemeProvider>
      </QueryClientProvider>,
    )
    await userEvent.click(within(sidebar()).getByRole('button', { name: 'Sign out' }))
    const dialog = await screen.findByRole('alertdialog')
    expect(within(dialog).getByText('Sign out and lose 3 unsaved changes?')).toBeInTheDocument()
    expect(within(dialog).getByText(/Clients and access and Alerts/)).toBeInTheDocument()
    await userEvent.click(within(dialog).getByRole('button', { name: 'Keep editing' }))
    expect(onLogout).not.toHaveBeenCalled()
    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument()

    await userEvent.click(within(sidebar()).getByRole('button', { name: 'Sign out' }))
    await userEvent.click(within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Sign out' }))
    expect(onLogout).toHaveBeenCalledTimes(1)
  })

  it('reports a proxy that is down in amber with the count', async () => {
    answer({ proxy_status: 'error', version: '3.14.3' })
    shell('/')
    const line = await within(sidebar()).findByText('Proxy not running')
    const status = line.closest('[role="status"]') as HTMLElement
    expect(status.className).toMatch(/text-warning/)
    expect(status).toHaveAttribute('title', 'Down: Proxy')
    expect(status.querySelector('[data-tone]')).toHaveAttribute('data-tone', 'warning')
  })

  it('says the backend is not reachable when the status request fails, not running', async () => {
    answer('fail')
    shell('/')
    expect(await within(sidebar()).findByText('Backend not reachable')).toBeInTheDocument()
    expect(within(sidebar()).queryByText(/running|healthy/)).not.toBeInTheDocument()
  })
})

describe('shell on a small screen', () => {
  beforeEach(() => setViewport(false))

  it('keeps the closed drawer out of the tab order and offers no collapse button', () => {
    shell('/')
    expect(sidebar()).toHaveAttribute('inert')
    expect(within(sidebar()).queryByRole('button', { name: /collapse sidebar/i })).not.toBeInTheDocument()
  })

  it('opens a modal drawer from a 44px menu button and moves focus into it', async () => {
    const { container } = shell('/')
    const menu = screen.getByRole('button', { name: 'Open navigation menu' })
    expect(menu.className).toMatch(/h-11 w-11/)
    await userEvent.click(menu)

    const dialog = screen.getByRole('dialog', { name: 'Navigation' })
    expect(dialog).toBe(sidebar())
    expect(dialog).toHaveAttribute('aria-modal', 'true')
    expect(dialog).not.toHaveAttribute('inert')
    expect(screen.getByRole('button', { name: 'Close navigation menu' })).toHaveAttribute('aria-expanded', 'true')
    expect(dialog.contains(document.activeElement)).toBe(true)
    // The drawer is always expanded, with names visible.
    expect(within(dialog).getByRole('link', { name: 'Access logs' })).toHaveTextContent('Access logs')
    await within(dialog).findByText('Backend and proxy running')
    await expectNoAxeViolations(container)
  })

  it('closes on Escape and gives focus back to the menu button', async () => {
    shell('/')
    const menu = screen.getByRole('button', { name: 'Open navigation menu' })
    menu.focus()
    await userEvent.click(menu)
    expect(screen.getByRole('dialog', { name: 'Navigation' })).toBeInTheDocument()
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(screen.queryByRole('dialog', { name: 'Navigation' })).not.toBeInTheDocument()
    expect(sidebar()).toHaveAttribute('inert')
    expect(document.activeElement).toBe(screen.getByRole('button', { name: 'Open navigation menu' }))
  })

  it('closes when the backdrop or the close button is pressed', async () => {
    shell('/')
    await userEvent.click(screen.getByRole('button', { name: 'Open navigation menu' }))
    fireEvent.click(screen.getByTestId('drawer-backdrop'))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: 'Open navigation menu' }))
    await userEvent.click(within(sidebar()).getByRole('button', { name: 'Close navigation' }))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('closes when the route changes', async () => {
    shell('/')
    await userEvent.click(screen.getByRole('button', { name: 'Open navigation menu' }))
    await act(async () => {
      fireEvent.click(within(sidebar()).getByRole('link', { name: 'Clients' }))
    })
    await waitFor(() => expect(screen.getByTestId('where')).toHaveTextContent('/clients'))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(sidebar()).toHaveAttribute('inert')
  })

  it('closes when the route changes from outside the drawer (a quick-nav key)', async () => {
    shell('/')
    await userEvent.click(screen.getByRole('button', { name: 'Open navigation menu' }))
    expect(screen.getByRole('dialog', { name: 'Navigation' })).toBeInTheDocument()
    // GlobalSearch maps the number keys to the sidebar's pages in its order.
    const second = NAV_GROUPS.flatMap((g) => g.items)[1].to
    fireEvent.keyDown(window, { key: '2' })
    await waitFor(() => expect(screen.getByTestId('where')).toHaveTextContent(second))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('names the current page in the top bar', () => {
    shell('/blacklists')
    const topBar = screen.getByRole('button', { name: 'Open navigation menu' }).parentElement as HTMLElement
    expect(within(topBar).getByText('Blacklists')).toBeInTheDocument()
  })
})
