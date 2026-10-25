import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { Plus, Trash2 } from 'lucide-react'
import { Button, IconButton } from './Button'
import { expectNoAxeViolations } from '../../test/axe'

describe('Button', () => {
  it('is type="button" by default, so it never submits a form by accident', () => {
    const onSubmit = vi.fn((e: React.FormEvent) => e.preventDefault())
    render(<form onSubmit={onSubmit}><Button>Export</Button></form>)
    const btn = screen.getByRole('button', { name: 'Export' })
    expect(btn).toHaveAttribute('type', 'button')
    fireEvent.click(btn)
    expect(onSubmit).not.toHaveBeenCalled()
  })

  it('submits when asked to', () => {
    const onSubmit = vi.fn((e: React.FormEvent) => e.preventDefault())
    render(<form onSubmit={onSubmit}><Button type="submit" variant="primary">Save</Button></form>)
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(onSubmit).toHaveBeenCalledTimes(1)
  })

  it('draws each variant from the tokens, red only for danger-outline', () => {
    render(
      <>
        <Button variant="primary">Add entries</Button>
        <Button variant="secondary">Export</Button>
        <Button variant="danger-outline">Remove all</Button>
        <Button variant="ghost">More</Button>
      </>,
    )
    expect(screen.getByRole('button', { name: 'Add entries' }).className).toMatch(/bg-accent-solid/)
    expect(screen.getByRole('button', { name: 'Export' }).className).toMatch(/border-line-strong/)
    expect(screen.getByRole('button', { name: 'Remove all' }).className).toMatch(/text-danger/)
    for (const name of ['Add entries', 'Export', 'More']) {
      expect(screen.getByRole('button', { name }).className).not.toMatch(/danger/)
    }
  })

  it('hides its icon from assistive technology and keeps the text as the name', async () => {
    const { container } = render(<Button variant="primary" icon={<Plus />}>Add entries</Button>)
    expect(screen.getByRole('button', { name: 'Add entries' })).toBeInTheDocument()
    expect(container.querySelector('svg')?.closest('[aria-hidden="true"]')).not.toBeNull()
    await expectNoAxeViolations(container)
  })

  it('does not fire when disabled', () => {
    const onClick = vi.fn()
    render(<Button disabled onClick={onClick}>Previous</Button>)
    fireEvent.click(screen.getByRole('button', { name: 'Previous' }))
    expect(onClick).not.toHaveBeenCalled()
  })
})

describe('IconButton', () => {
  it('is named by its aria-label, which is also its tooltip', async () => {
    const onClick = vi.fn()
    const { container } = render(<IconButton aria-label="Remove 192.0.2.1" icon={<Trash2 />} onClick={onClick} />)
    const btn = screen.getByRole('button', { name: 'Remove 192.0.2.1' })
    expect(btn).toHaveAttribute('title', 'Remove 192.0.2.1')
    fireEvent.click(btn)
    expect(onClick).toHaveBeenCalledTimes(1)
    await expectNoAxeViolations(container)
  })

  it('cannot be written without an aria-label', () => {
    // @ts-expect-error aria-label is required: an icon is not a name.
    const el = <IconButton icon={<Trash2 />} />
    expect(el).toBeTruthy()
  })
})
