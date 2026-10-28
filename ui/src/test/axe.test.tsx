import { describe, it, expect } from 'vitest'
import { render } from '@testing-library/react'
import { expectNoAxeViolations } from './axe'

// The gate itself: if the helper stopped failing, every component test that
// relies on it would pass whatever the markup.
describe('expectNoAxeViolations', () => {
  it('passes accessible markup', async () => {
    const { container } = render(<button type="button">Save</button>)
    await expectNoAxeViolations(container)
  })

  it('fails a button with no accessible name and names the rule', async () => {
    const { container } = render(<button type="button"><svg aria-hidden="true" /></button>)  // slopless-disable-line VBC-035 -- deliberately unnamed button: the test proves the axe gate rejects it
    await expect(expectNoAxeViolations(container)).rejects.toThrow(/button-name/)
  })

  it('fails an input with no label', async () => {
    const { container } = render(<input type="text" />)
    await expect(expectNoAxeViolations(container)).rejects.toThrow(/label/)
  })
})
