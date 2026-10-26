import { describe, it, expect } from 'vitest'
import { screen, fireEvent } from '@testing-library/react'
import { renderWithProviders } from '../test/helpers'
import { expectNoAxeViolations } from '../test/axe'
import { ClientSetup } from './ClientSetup'

describe('ClientSetup', () => {
  it.each(['light', 'dark'] as const)('renders OS tabs, switches panels with keyboard and mouse, and passes axe in %s theme', async (theme) => {
    document.documentElement.classList.toggle('dark', theme === 'dark')
    try {
      const { container } = renderWithProviders(<ClientSetup />)
      expect(screen.getByRole('heading', { level: 3, name: 'Connect Your Devices' })).toBeInTheDocument()
      await expectNoAxeViolations(container)

      const winTab = screen.getByRole('tab', { name: 'Windows' })
      expect(winTab).toHaveAttribute('aria-selected', 'true')
      fireEvent.keyDown(winTab, { key: 'ArrowRight' })

      const macTab = screen.getByRole('tab', { name: 'macOS' })
      expect(macTab).toHaveAttribute('aria-selected', 'true')
      await expectNoAxeViolations(container)

      fireEvent.click(screen.getByRole('tab', { name: 'iOS' }))
      expect(screen.getByRole('tab', { name: 'iOS' })).toHaveAttribute('aria-selected', 'true')
      await expectNoAxeViolations(container)
    } finally {
      document.documentElement.classList.remove('dark')
    }
  })
})
