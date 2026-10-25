import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { screen, fireEvent } from '@testing-library/react'
import { renderWithProviders } from '../../../test/helpers'
import { expectNoAxeViolations } from '../../../test/axe'
import { AppearanceSection } from './AppearanceSection'

let systemDark = false
const listeners = new Set<() => void>()

function mockSystem() {
  Object.defineProperty(window, 'matchMedia', {
    configurable: true,
    writable: true,
    value: (query: string) => ({
      get matches() { return query === '(prefers-color-scheme: dark)' && systemDark },
      media: query, onchange: null,
      addEventListener: (_: string, l: () => void) => listeners.add(l),
      removeEventListener: (_: string, l: () => void) => listeners.delete(l),
      addListener: () => {}, removeListener: () => {}, dispatchEvent: () => false,
    }),
  })
}

const html = () => document.documentElement

describe('Appearance', () => {
  beforeEach(() => {
    systemDark = false
    listeners.clear()
    mockSystem()
    localStorage.clear()
    html().classList.remove('dark')
  })
  afterEach(() => { vi.restoreAllMocks() })

  it('starts on System, says where the choice lives, and passes the accessibility gate', async () => {
    const { container } = renderWithProviders(<AppearanceSection />)
    expect(screen.getByRole('radio', { name: /^System/ })).toBeChecked()
    expect(screen.getByText('Saved in this browser only.')).toBeInTheDocument()
    await expectNoAxeViolations(container)
  })

  it('Dark sets the theme and survives a reload; System removes the override and follows the device live', () => {
    const first = renderWithProviders(<AppearanceSection />)
    fireEvent.click(screen.getByRole('radio', { name: /^Dark/ }))
    expect(html()).toHaveClass('dark')
    expect(localStorage.getItem('theme')).toBe('dark')
    first.unmount()

    // A reload: a fresh provider reads the stored choice.
    html().classList.remove('dark')
    renderWithProviders(<AppearanceSection />)
    expect(screen.getByRole('radio', { name: /^Dark/ })).toBeChecked()
    expect(html()).toHaveClass('dark')

    fireEvent.click(screen.getByRole('radio', { name: /^System/ }))
    expect(html()).not.toHaveClass('dark')
    expect(localStorage.getItem('theme')).toBe('auto')
    systemDark = true
    listeners.forEach((l) => l())
    expect(html()).toHaveClass('dark')
  })

  it('still switches when the browser blocks storage', () => {
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new DOMException('blocked', 'SecurityError') })
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => { throw new DOMException('blocked', 'SecurityError') })
    renderWithProviders(<AppearanceSection />)
    fireEvent.click(screen.getByRole('radio', { name: /^Dark/ }))
    expect(html()).toHaveClass('dark')
  })
})
