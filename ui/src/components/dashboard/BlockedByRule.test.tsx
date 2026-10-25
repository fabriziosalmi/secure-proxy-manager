import { describe, it, expect } from 'vitest'
import { screen, within } from '@testing-library/react'
import { renderWithProviders } from '../../test/helpers'
import { expectNoAxeViolations } from '../../test/axe'
import { BlockedByRule } from './BlockedByRule'
import { idleRulesSentence } from './rules'

// The test deployment's last 24 hours, as blocked_by_reason_24h sends them.
const REASONS = [
  { reason: 'unclassified', label: 'Unclassified (no reason recorded)', count: 20 },
  { reason: 'domain_blacklist_dns', label: 'Domain blacklist (DNS)', count: 2 },
  { reason: 'waf', label: 'WAF', count: 1 },
]

describe('BlockedByRule', () => {
  it('names each rule with the label the API sent, legacy rows included', () => {
    renderWithProviders(<BlockedByRule reasons={REASONS} />)
    const items = screen.getAllByRole('listitem')
    expect(items.map((li) => li.textContent)).toEqual([
      'Unclassified (no reason recorded)20',
      'Domain blacklist (DNS)2',
      'WAF1',
    ])
  })

  // A rule that blocked nothing is said, in one sentence, not left out.
  it('names the main rules that blocked nothing in one sentence', () => {
    renderWithProviders(<BlockedByRule reasons={REASONS} />)
    expect(screen.getByText(
      'No client request was blocked in the last 24 hours by the domain blacklist at the proxy, the IP blacklist, the direct-IP rule or the egress policy.',
    )).toBeInTheDocument()
  })

  it('has no idle sentence when every main rule blocked something', () => {
    const all = ['domain_blacklist_dns', 'domain_blacklist', 'ip_blacklist', 'waf', 'direct_ip', 'egress_policy']
      .map((reason) => ({ reason, label: reason, count: 1 }))
    expect(idleRulesSentence(all)).toBeNull()
    expect(idleRulesSentence([{ reason: 'waf', label: 'WAF', count: 0 }])).toContain('the WAF')
  })

  it('says nothing was blocked instead of drawing empty bars', () => {
    renderWithProviders(<BlockedByRule reasons={[]} />)
    expect(screen.getByText('No blocked requests in the last 24 hours')).toBeInTheDocument()
    expect(screen.queryByRole('listitem')).toBeNull()
  })

  // An older backend without the field: the card says what is missing.
  it('says the figure is not reported when the backend did not send it', () => {
    renderWithProviders(<BlockedByRule reasons={undefined} />)
    const region = screen.getByRole('region', { name: 'Blocked by rule' })
    expect(within(region).getByText(/Not reported/)).toBeInTheDocument()
  })

  it('passes axe', async () => {
    const { container } = renderWithProviders(<BlockedByRule reasons={REASONS} />)
    await expectNoAxeViolations(container)
  })
})
