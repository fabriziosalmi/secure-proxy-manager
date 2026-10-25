import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { Badge } from './Badge'
import { expectNoAxeViolations } from '../../test/axe'

describe('Badge', () => {
  it('is neutral unless a tone is asked for', () => {
    render(<Badge>Import</Badge>)
    expect(screen.getByText('Import')).toHaveAttribute('data-tone', 'neutral')
  })

  it.each([
    ['danger', /text-danger/],
    ['warning', /text-warning/],
    ['success', /text-success/],
    ['accent', /text-accent/],
  ] as const)('draws the %s tone from its tokens', (tone, cls) => {
    render(<Badge tone={tone}>{tone}</Badge>)
    expect(screen.getByText(tone).className).toMatch(cls)
  })

  it('passes axe in every tone', async () => {
    const { container } = render(
      <p>
        <Badge>Import</Badge>
        <Badge tone="danger">Domain blacklist</Badge>
        <Badge tone="warning">2</Badge>
        <Badge tone="success">On</Badge>
        <Badge tone="accent">Selected</Badge>
      </p>,
    )
    await expectNoAxeViolations(container)
  })
})
