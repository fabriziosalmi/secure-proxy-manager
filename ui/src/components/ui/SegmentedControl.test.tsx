import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { Sun, Moon } from 'lucide-react'
import { SegmentedControl } from './SegmentedControl'
import { expectNoAxeViolations } from '../../test/axe'

const RANGES = [
  { value: '1h', label: '1h' },
  { value: '24h', label: '24h' },
  { value: '7d', label: '7d' },
] as const

describe('SegmentedControl', () => {
  it('is a named group whose options report aria-pressed', async () => {
    const { container } = render(<SegmentedControl label="Time range" options={RANGES} value="24h" onChange={() => {}} />)
    expect(screen.getByRole('group', { name: 'Time range' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '24h' })).toHaveAttribute('aria-pressed', 'true')
    expect(screen.getByRole('button', { name: '1h' })).toHaveAttribute('aria-pressed', 'false')
    expect(screen.getByRole('button', { name: '7d' })).toHaveAttribute('aria-pressed', 'false')
    await expectNoAxeViolations(container)
  })

  it('reports the picked value', () => {
    const onChange = vi.fn()
    render(<SegmentedControl label="Time range" options={RANGES} value="24h" onChange={onChange} />)
    fireEvent.click(screen.getByRole('button', { name: '7d' }))
    expect(onChange).toHaveBeenCalledWith('7d')
  })

  it('names icon-only options by their aria-label', async () => {
    const { container } = render(
      <SegmentedControl
        label="Theme"
        options={[
          { value: 'light', icon: <Sun />, ariaLabel: 'Light theme' },
          { value: 'dark', icon: <Moon />, ariaLabel: 'Dark theme' },
        ]}
        value="dark"
        onChange={() => {}}
      />,
    )
    expect(screen.getByRole('button', { name: 'Dark theme' })).toHaveAttribute('aria-pressed', 'true')
    expect(screen.getByRole('button', { name: 'Light theme' })).toHaveAttribute('title', 'Light theme')
    await expectNoAxeViolations(container)
  })
})
