import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { Section } from './Section'
import { expectNoAxeViolations } from '../../test/axe'

describe('Section', () => {
  it('is a region named by its heading, with the description and an action link', async () => {
    const { container } = render(
      <MemoryRouter>
        <Section title="Most blocked destinations" description="Last 24 hours" action={{ label: 'View all', to: '/analytics' }}>
          <p>rows</p>
        </Section>
      </MemoryRouter>,
    )
    const region = screen.getByRole('region', { name: 'Most blocked destinations' })
    expect(region).toContainElement(screen.getByText('rows'))
    expect(screen.getByRole('heading', { level: 2, name: 'Most blocked destinations' })).toBeInTheDocument()
    expect(screen.getByText('Last 24 hours')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'View all' })).toHaveAttribute('href', '/analytics')
    await expectNoAxeViolations(container)
  })

  it('uses an h3 inside another section', () => {
    render(<MemoryRouter><Section title="Top destinations" level={3} /></MemoryRouter>)
    expect(screen.getByRole('heading', { level: 3, name: 'Top destinations' })).toBeInTheDocument()
  })

  it('draws a danger zone with the danger border only when asked', () => {
    render(
      <MemoryRouter>
        <Section title="Plain" />
        <Section title="Remove every entry on this list" tone="danger" />
      </MemoryRouter>,
    )
    expect(screen.getByRole('region', { name: 'Plain' }).className).not.toMatch(/danger/)
    expect(screen.getByRole('region', { name: 'Remove every entry on this list' }).className).toMatch(/border-danger-line/)
  })
})
