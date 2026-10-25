import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { Switch } from './Switch'
import { expectNoAxeViolations } from '../../test/axe'

describe('Switch', () => {
  it('is a role=switch whose aria-checked follows the state', async () => {
    const { rerender, container } = render(<Switch checked={false} onChange={() => {}} label="Require proxy login" />)
    const sw = screen.getByRole('switch', { name: 'Require proxy login' })
    expect(sw).toHaveAttribute('aria-checked', 'false')
    await expectNoAxeViolations(container)
    rerender(<Switch checked onChange={() => {}} label="Require proxy login" />)
    expect(sw).toHaveAttribute('aria-checked', 'true')
    expect(sw.className).toMatch(/bg-accent-solid/)
  })

  it('emits the next state', () => {
    const onChange = vi.fn()
    render(<Switch checked onChange={onChange} label="WAF" />)
    fireEvent.click(screen.getByRole('switch', { name: 'WAF' }))
    expect(onChange).toHaveBeenCalledWith(false)
  })

  it('can be named by the visible label already on the page', async () => {
    const { container } = render(
      <div>
        <span id="t-auth">Require proxy login</span>
        <Switch checked={false} onChange={() => {}} labelledBy="t-auth" />
      </div>,
    )
    const sw = screen.getByRole('switch', { name: 'Require proxy login' })
    expect(sw).not.toHaveAttribute('aria-label')
    await expectNoAxeViolations(container)
  })

  it('reads the text that explains it after its name', () => {
    render(
      <div>
        <span id="t-hours">Allowed hours</span>
        <p id="t-hours-help">Outside these hours every request is refused.</p>
        <Switch checked={false} onChange={() => {}} labelledBy="t-hours" describedBy="t-hours-help" />
      </div>,
    )
    expect(screen.getByRole('switch', { name: 'Allowed hours' })).toHaveAccessibleDescription('Outside these hours every request is refused.')
  })

  it('does not flip when disabled', () => {
    const onChange = vi.fn()
    render(<Switch checked={false} onChange={onChange} label="WAF" disabled />)
    fireEvent.click(screen.getByRole('switch', { name: 'WAF' }))
    expect(onChange).not.toHaveBeenCalled()
  })
})
