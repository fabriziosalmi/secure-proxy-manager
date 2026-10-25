import { describe, it, expect, afterEach, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { StatCard } from './StatCard'
import { expectNoAxeViolations } from '../../test/axe'
import { simulateItalianLocale } from '../../test/helpers'

describe('StatCard', () => {
  afterEach(() => { vi.restoreAllMocks() })

  it('writes a number through formatCount, in every browser locale', async () => {
    simulateItalianLocale()
    const { container } = render(<StatCard label="Blocked IPs" value={50772} sub="from 3 lists" />)
    expect(screen.getByText('50,772')).toBeInTheDocument()
    expect(screen.getByText('50,772').className).toMatch(/tabular-nums/)
    expect(screen.getByText('from 3 lists')).toBeInTheDocument()
    await expectNoAxeViolations(container)
  })

  it('shows a string value as given', () => {
    render(<StatCard label="Rules in force" value="50,772 IPs, 640,929 domains" />)
    expect(screen.getByText('50,772 IPs, 640,929 domains')).toBeInTheDocument()
  })

  it('shows a real zero as 0', () => {
    render(<StatCard label="Blocked" value={0} />)
    expect(screen.getByText('0')).toBeInTheDocument()
  })

  it.each([
    ['not-collected', 'Not collected'],
    ['not-reported', 'Not reported'],
  ] as const)('says "%s" instead of a number, even when a 0 is passed', (unavailable, text) => {
    render(<StatCard label="Cache hit rate" value={0} unavailable={unavailable} />)
    expect(screen.getByText(text)).toBeInTheDocument()
    expect(screen.queryByText('0')).not.toBeInTheDocument()
  })

  it('says "Not reported" when the value is missing, never 0', () => {
    render(<StatCard label="Requests today" value={undefined} />)
    expect(screen.getByText('Not reported')).toBeInTheDocument()
    expect(screen.queryByText('0')).not.toBeInTheDocument()
  })

  it('treats NaN as missing', () => {
    render(<StatCard label="Requests today" value={Number.NaN} />)
    expect(screen.getByText('Not reported')).toBeInTheDocument()
  })

  it('colours the value with its tone', () => {
    render(<StatCard label="Blocked" value={908} tone="danger" />)
    expect(screen.getByText('908').className).toMatch(/text-danger/)
  })

  it('shows a skeleton and tells screen readers it is loading', async () => {
    const { container } = render(<StatCard label="Blocked" value={undefined} loading />)
    expect(screen.getByText('Loading')).toHaveClass('sr-only')
    expect(screen.queryByText('Not reported')).not.toBeInTheDocument()
    await expectNoAxeViolations(container)
  })
})
