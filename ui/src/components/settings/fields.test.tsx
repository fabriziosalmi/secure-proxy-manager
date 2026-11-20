import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { ChoiceRow, TextField, ToggleRow } from './fields'
import type { SectionForm } from './sectionForm'

function form(values: Record<string, string> = {}): SectionForm {
  return {
    values,
    stored: values,
    formData: values,
    set: vi.fn(),
    setFormData: vi.fn(),
    handleChange: vi.fn(),
    secretProps: () => ({ state: { kind: 'unset' } as never, onEdit: vi.fn() }),
    error: () => undefined,
  } as unknown as SectionForm
}

// The rows stretched across the card: a switch sat 886 px from its label at
// 1512 px. Each row is held to max-w-3xl, the control by its text.
describe('settings rows', () => {
  it('holds a toggle row (label, help, switch) to the readable width', () => {
    render(<ToggleRow form={form({ enable_x: 'false' })} setting="enable_x" label="Block risky downloads" help="Refuses any URL whose path ends in one of these." />)
    const row = screen.getByRole('switch', { name: 'Block risky downloads' }).parentElement!
    expect(row).toHaveClass('max-w-3xl')
    expect(row).toContainElement(screen.getByText('Block risky downloads'))
  })

  it('holds a choice row to the readable width', () => {
    render(<ChoiceRow form={form({ mode: 'a' })} setting="mode" label="Mode" help="Which one." options={[{ value: 'a', label: 'A' }, { value: 'b', label: 'B' }]} />)
    const row = screen.getByRole('group', { name: 'Mode' }).parentElement!
    expect(row).toHaveClass('max-w-3xl')
  })

  // The help under a 240 px field was cut to 240 px, in 12 px type.
  it('writes field help in the size of every other description, across the row, whatever the field width', () => {
    render(
      <>
        <ToggleRow form={form({ enable_x: 'true' })} setting="enable_x" label="Egress" help="A toggle's help." />
        <TextField form={form({ hours: '24' })} setting="hours" label="Refresh provider lists every (hours)" inputWidth="sm:max-w-[240px]" hint="From 6 to 168." />
      </>,
    )
    const toggleHelp = screen.getByText("A toggle's help.")
    const fieldHelp = screen.getByText('From 6 to 168.')
    expect(fieldHelp.className).toBe(toggleHelp.className)
    const input = screen.getByLabelText('Refresh provider lists every (hours)')
    // The width applies to the label and the input, not to the help under them.
    expect(input.closest('.sm\\:max-w-\\[240px\\]')).not.toBeNull()
    expect(fieldHelp.closest('.sm\\:max-w-\\[240px\\]')).toBeNull()
    expect(fieldHelp.closest('.max-w-3xl')).not.toBeNull()
  })
})
