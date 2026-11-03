import { describe, it, expect, vi, afterEach } from 'vitest'
import { screen, within, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderWithProviders } from '../../test/helpers'
import { expectNoAxeViolations } from '../../test/axe'
import { api } from '../../lib/api'
import type { WafTrajectory, WafTrajectoryDetail } from '../../types'
import { Trajectories } from './Trajectories'

const ROW: WafTrajectory = {
  id: 7,
  client_ip: '192.0.2.7',
  rule: 'order',
  start: '2026-11-03T10:00:00Z',
  closed: '2026-11-03T10:15:00Z',
  end: '2026-11-03T11:00:00Z',
  phases: ['arrival', 'contact', 'action'],
  categories: ['TYPOSQUATTING', 'HEURISTIC_BEACONING', 'CLOUD_SECRETS'],
  hosts: ['paypa1.com', 'c2.example.net'],
  signals: 3,
}

const DETAIL: WafTrajectoryDetail = {
  trajectory: ROW,
  truncated: false,
  signals: [
    { at: '2026-11-03T10:00:00Z', category: 'TYPOSQUATTING', phase: 'arrival', host: 'paypa1.com', rule: 'ML-TYPO-001', observed: false, blocked: false, event_id: 'e1' },
    { at: '2026-11-03T10:15:00Z', category: 'HEURISTIC_BEACONING', phase: 'contact', host: 'c2.example.net', rule: 'H2-BEACON', observed: false, blocked: false, event_id: 'e2' },
    { at: '2026-11-03T11:00:00Z', category: 'CLOUD_SECRETS', phase: 'action', host: 'c2.example.net', rule: 'SEC-AWS-1', observed: true, blocked: false, event_id: 'e3' },
  ],
}

function render(props: Partial<Parameters<typeof Trajectories>[0]> = {}) {
  return renderWithProviders(
    <Trajectories rows={[ROW]} loading={false} error={false} onRetry={() => {}} gdpr={false} {...props} />,
  )
}

afterEach(() => { vi.restoreAllMocks() })

describe('Trajectories', () => {
  it('lists each client with its stages and signals in words', () => {
    render()
    const table = screen.getByRole('table', { name: /Client trajectories in the last 7 days/ })
    const row = within(table).getAllByRole('row')[1]
    expect(within(row).getByText('192.0.2.7')).toBeInTheDocument()
    expect(within(row).getByText('arrival')).toBeInTheDocument()
    expect(within(row).getByText('action')).toBeInTheDocument()
    // Category names, not the WAF's identifiers.
    expect(row.textContent).not.toContain('CLOUD_SECRETS')
  })

  it('opens the client signals of that day, in order, marking what was Log only, and closes on Escape', async () => {
    const get = vi.spyOn(api, 'get').mockResolvedValue({ data: { status: 'success', data: DETAIL } })
    render()
    await userEvent.click(screen.getByRole('button', { name: 'Signals of 192.0.2.7' }))
    const dialog = await screen.findByRole('dialog', { name: '192.0.2.7' })
    expect(get).toHaveBeenCalledWith('waf/trajectories/7', undefined)
    await waitFor(() => { expect(within(dialog).getAllByRole('listitem')).toHaveLength(3) })
    const items = within(dialog).getAllByRole('listitem')
    expect(items[0].textContent).toContain('paypa1.com')
    expect(items[2].textContent).toContain('Log only')
    expect(within(dialog).getByText('One stage followed another')).toBeInTheDocument()
    await expectNoAxeViolations(document.body)
    await userEvent.keyboard('{Escape}')
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  it('says why none are read in GDPR mode', () => {
    render({ rows: [], gdpr: true })
    expect(screen.getByText('Not read in GDPR mode')).toBeInTheDocument()
    expect(screen.getByText('No client trajectory in the last 7 days')).toBeInTheDocument()
  })

  it('says which call failed', () => {
    render({ rows: null, error: true })
    expect(screen.getByText(/waf\/trajectories did not answer/)).toBeInTheDocument()
  })

  it('has no accessibility violations', async () => {
    const { container } = render()
    await expectNoAxeViolations(container)
  })
})
