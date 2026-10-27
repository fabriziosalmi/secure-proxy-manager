import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { expectNoAxeViolations } from '../../test/axe'
import { ApplyBadge } from './ApplyBadge'

describe('ApplyBadge', () => {
  it('names how each kind of setting takes effect', async () => {
    const { container } = render(
      <ul>
        <li><ApplyBadge setting="enable_proxy_auth" /></li>
        <li><ApplyBadge setting="enable_safesearch" /></li>
        <li><ApplyBadge setting="enable_notifications" /></li>
        <li><ApplyBadge setting="log_retention_days" /></li>
        <li><ApplyBadge setting="auto_refresh_hours" /></li>
      </ul>,
    )
    const badges = [...container.querySelectorAll('[data-apply]')].map((b) => [b.getAttribute('data-apply'), b.firstChild?.textContent])
    expect(badges).toEqual([
      ['reload', 'Proxy reload'],
      ['dns', 'DNS'],
      ['live', 'Live'],
      ['daily', 'Daily'],
      ['cycle', 'Next cycle'],
    ])
    expect(screen.getByText('Proxy reload')).toHaveAttribute('title', 'Saving regenerates the proxy configuration and reloads it.')
    await expectNoAxeViolations(container)
  })

  it('draws nothing for a key the map does not know', () => {
    const { container } = render(<ApplyBadge setting="tailscale_enabled" />)
    expect(container).toBeEmptyDOMElement()
  })

  it('gives egress_provider_refresh_hours its own worker description instead of the blocklist refresh worker text', () => {
    render(<ApplyBadge setting="egress_provider_refresh_hours" />)
    const badge = screen.getByText('Next cycle')
    expect(badge).toHaveAttribute('data-apply', 'provider_cycle')
    expect(badge.getAttribute('title')).toMatch(/egress provider refresh worker/i)
    expect(badge.getAttribute('title')).not.toMatch(/blocklist refresh worker|within 30 minutes/i)
  })
})
