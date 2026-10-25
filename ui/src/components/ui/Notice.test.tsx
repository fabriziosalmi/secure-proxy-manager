import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { Notice } from './Notice'
import { expectNoAxeViolations } from '../../test/axe'

describe('Notice', () => {
  it('is a polite status with its title, body and action', async () => {
    const { container } = render(
      <Notice tone="warning" title="Blacklisted domains are blocked at DNS only" action={<a href="/settings">Review limit</a>}>
        The list has 473,936 names, above the limit of 250,000.
      </Notice>,
    )
    const status = screen.getByRole('status')
    expect(status).toHaveAttribute('data-tone', 'warning')
    expect(status).toHaveTextContent('Blacklisted domains are blocked at DNS only')
    expect(status).toHaveTextContent('473,936 names')
    expect(screen.getByRole('link', { name: 'Review limit' })).toBeInTheDocument()
    await expectNoAxeViolations(container)
  })

  it('hides its icon from screen readers', () => {
    const { container } = render(<Notice title="Info" />)
    expect(container.querySelector('svg')).toHaveAttribute('aria-hidden', 'true')
  })

  it.each([
    ['info', /bg-accent-subtle/],
    ['warning', /bg-warning-subtle/],
    ['danger', /bg-danger-subtle/],
  ] as const)('draws the %s tone from its tokens', (tone, cls) => {
    render(<Notice tone={tone} title={tone} />)
    expect(screen.getByRole('status').className).toMatch(cls)
  })
})
