import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { Unavailable } from './Unavailable'
import { expectNoAxeViolations } from '../../test/axe'

describe('Unavailable', () => {
  // "Not reported: analytics/coverage did not answer." led with a path.
  it('says what is missing first, and the request that failed as a detail under it', async () => {
    const { container } = render(<Unavailable endpoint="analytics/coverage">What protection is on could not be read.</Unavailable>)
    const alert = screen.getByRole('alert')
    const [sentence, detail] = alert.querySelectorAll('p')
    expect(sentence).toHaveTextContent(/^What protection is on could not be read\.$/)
    expect(detail).toHaveTextContent('Detail: GET /api/analytics/coverage did not answer.')
    expect(detail.className).toContain('text-xs')
    await expectNoAxeViolations(container)
  })
})
