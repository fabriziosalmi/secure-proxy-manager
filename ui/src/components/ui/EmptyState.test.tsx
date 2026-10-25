import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { EmptyState } from './EmptyState'
import { Button } from './Button'
import { expectNoAxeViolations } from '../../test/axe'

describe('EmptyState', () => {
  it('says what is missing, what to do, and offers the action', async () => {
    const { container } = render(
      <EmptyState
        title="No allowed domains yet"
        description="An entry on this list is allowed even when a blacklist names it."
        action={<Button>Add a domain</Button>}
      />,
    )
    expect(screen.getByText('No allowed domains yet')).toBeInTheDocument()
    expect(screen.getByText(/allowed even when a blacklist names it/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Add a domain' })).toBeInTheDocument()
    expect(container.querySelector('svg')?.closest('[aria-hidden="true"]')).not.toBeNull()
    await expectNoAxeViolations(container)
  })
})
