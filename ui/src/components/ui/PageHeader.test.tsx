import { describe, it, expect } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { PageHeader } from './PageHeader'
import { Button } from './Button'
import { expectNoAxeViolations } from '../../test/axe'

describe('PageHeader', () => {
  it('renders the eyebrow, the title as the page h1, the description and the actions', async () => {
    const { container } = render(
      <PageHeader
        eyebrow="Protection"
        title="Blacklists"
        description="Destinations the proxy refuses, and the exceptions that override them."
        actions={<Button variant="primary">Add entries</Button>}
      />,
    )
    expect(screen.getByRole('heading', { level: 1, name: 'Blacklists' })).toBeInTheDocument()
    expect(screen.getByText('Protection')).toBeInTheDocument()
    expect(screen.getByText(/Destinations the proxy refuses/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Add entries' })).toBeInTheDocument()
    await expectNoAxeViolations(container)
  })

  it('renders only the title when nothing else is given', () => {
    const { container } = render(<PageHeader title="Settings" />)
    expect(screen.getByRole('heading', { level: 1, name: 'Settings' })).toBeInTheDocument()
    expect(container.querySelectorAll('p')).toHaveLength(0)
    expect(screen.queryByRole('button')).not.toBeInTheDocument()
  })

  it('puts the description in the tooltip of an info button, shown on hover and on keyboard focus and closed by Escape', async () => {
    const user = userEvent.setup()
    const { container } = render(<PageHeader title="Access logs" description="Every request the proxy handled, newest first." />)
    const info = screen.getByRole('button', { name: 'About Access logs' })
    expect(info).toHaveAccessibleDescription('Every request the proxy handled, newest first.')
    const tip = screen.getByRole('tooltip', { hidden: true })
    expect(tip).toHaveTextContent('Every request the proxy handled, newest first.')
    expect(tip).toHaveAttribute('data-state', 'closed')

    await user.hover(info)
    expect(tip).toHaveAttribute('data-state', 'open')
    await user.unhover(info)
    expect(tip).toHaveAttribute('data-state', 'closed')

    await user.tab()
    expect(info).toHaveFocus()
    expect(tip).toHaveAttribute('data-state', 'open')
    fireEvent.keyDown(info, { key: 'Escape' })
    expect(tip).toHaveAttribute('data-state', 'closed')
    await expectNoAxeViolations(container)
  })

  it('writes an inline description as a visible line, with no info button', () => {
    render(<PageHeader title="Overview" describe="inline" description="Last 24 hours · updated 08:52" />)
    expect(screen.getByText('Last 24 hours · updated 08:52').tagName).toBe('P')
    expect(screen.queryByRole('button', { name: /^About/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('tooltip', { hidden: true })).not.toBeInTheDocument()
  })
})
