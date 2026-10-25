import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
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
  })
})
