import { describe, it, expect, vi, beforeEach } from 'vitest'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderWithProviders } from './test/helpers'
import { Clients } from './pages/Clients'
import { Audit } from './pages/Audit'
import { EgressAllowlist } from './pages/EgressAllowlist'
import { Blacklists } from './pages/Blacklists'
import { RegexPlayground } from './components/RegexPlayground'
import { ClientSetup } from './components/ClientSetup'
import { Layout } from './components/layout/Layout'

vi.mock('./lib/api', () => ({
  api: {
    get: vi.fn(() => Promise.resolve({ data: { data: [], total: 0, entries: [], clients: [] } })),
    post: vi.fn(),
    delete: vi.fn(),
    interceptors: { request: { use: vi.fn() }, response: { use: vi.fn() } },
  },
  getErrorMessage: (_e: unknown, f: string) => f,
}))

// A placeholder is not an accessible name (WCAG 1.3.1 / 4.1.2): a screen reader
// may skip it once the field has a value, and it disappears on input. These
// controls are found by role AND name, which fails for an unnamed field.
describe('controls have an accessible name', () => {
  beforeEach(() => vi.clearAllMocks())

  it('Clients filter', () => {
    renderWithProviders(<Clients />)
    expect(screen.getByRole('textbox', { name: /filter clients by ip/i })).toBeInTheDocument()
  })

  it('Audit filter', () => {
    renderWithProviders(<Audit />)
    expect(screen.getByRole('textbox', { name: /filter audit entries/i })).toBeInTheDocument()
  })

  it('EgressAllowlist inputs', () => {
    renderWithProviders(<EgressAllowlist />)
    expect(screen.getByRole('textbox', { name: /destination to allow/i })).toBeInTheDocument()
    expect(screen.getByRole('textbox', { name: /description/i })).toBeInTheDocument()
    expect(screen.getByRole('textbox', { name: /search the allowlist/i })).toBeInTheDocument()
  })

  it('Blacklists search', () => {
    renderWithProviders(<Blacklists />)
    expect(screen.getByRole('textbox', { name: /search this list/i })).toBeInTheDocument()
  })

  it('RegexPlayground regex field and period select', () => {
    renderWithProviders(<RegexPlayground />)
    expect(screen.getByRole('textbox', { name: /regular expression/i })).toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: /period/i })).toBeInTheDocument()
  })

  it('ClientSetup icon-only copy buttons', () => {
    renderWithProviders(<ClientSetup />)
    expect(screen.getByRole('button', { name: 'Copy proxy' })).toBeInTheDocument()
  })
})

describe('mobile menu toggle', () => {
  it('names itself and reports and controls the sidebar', async () => {
    renderWithProviders(<Layout />)
    const toggle = screen.getByRole('button', { name: /open navigation menu/i })
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
    const controls = toggle.getAttribute('aria-controls')
    expect(controls).toBeTruthy()
    expect(document.getElementById(controls!)).not.toBeNull()

    await userEvent.click(toggle)
    const open = screen.getByRole('button', { name: /close navigation menu/i })
    expect(open).toHaveAttribute('aria-expanded', 'true')
  })
})
