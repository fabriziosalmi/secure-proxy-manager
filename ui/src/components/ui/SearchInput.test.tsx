import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { SearchInput } from './SearchInput'
import { expectNoAxeViolations } from '../../test/axe'

describe('SearchInput', () => {
  it('is a search field named by a visually hidden label, not by its placeholder', async () => {
    const { container } = render(
      <SearchInput label="Filter clients by IP address" placeholder="Filter by IP address" value="" onChange={() => {}} />,
    )
    const box = screen.getByRole('searchbox', { name: 'Filter clients by IP address' })
    expect(box).toHaveAttribute('type', 'search')
    expect(screen.getByText('Filter clients by IP address')).toHaveClass('sr-only')
    expect(container.querySelector('svg')).toHaveAttribute('aria-hidden', 'true')
    await expectNoAxeViolations(container)
  })

  it('reports the typed value', () => {
    const onChange = vi.fn()
    render(<SearchInput label="Search entries" value="" onChange={onChange} />)
    fireEvent.change(screen.getByRole('searchbox', { name: 'Search entries' }), { target: { value: '192.0.2' } })
    expect(onChange).toHaveBeenCalledWith('192.0.2')
  })
})
