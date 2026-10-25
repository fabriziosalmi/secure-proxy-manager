import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import { renderWithProviders, simulateItalianLocale } from '../test/helpers'
import { api } from '../lib/api'
import { ThreatIntel } from './ThreatIntel'

vi.mock('../hooks/useAnimatedNumber', () => ({ useAnimatedNumber: (v: number) => v }))

const summary = {
  total_requests: 50772,
  blocked_requests: 1328,
  today_requests: 350,
  today_blocked: 15,
  ip_blacklist_count: 0,
  domain_blacklist_count: 0,
  top_blocked: [],
  top_clients: [],
  threat_categories: [],
  recent_blocks: [],
  waf: null,
  waf_status: 'unreachable',
}

function serve(body: unknown) {
  vi.spyOn(api, 'get').mockImplementation((url: string) =>
    Promise.resolve({ data: { status: 'success', data: url === 'dashboard/summary' ? body : null } }))
}

/** The metric card whose caption is `label`. */
function card(label: string): HTMLElement {
  return screen.getByText(label).parentElement as HTMLElement
}

describe('ThreatIntel', () => {
  beforeEach(() => { serve(summary) })
  afterEach(() => { vi.restoreAllMocks() })

  // Without WAF statistics the two WAF cards drew 0, which reads as a WAF
  // that inspected traffic and blocked nothing.
  it('says the WAF figures are not available when the backend has no WAF statistics', async () => {
    renderWithProviders(<ThreatIntel />)
    await waitFor(() => { expect(card('Total Blocks')).toHaveTextContent('1,328') })
    expect(card('WAF Blocks')).toHaveTextContent('Not available')
    expect(card('Entropy Alerts')).toHaveTextContent('Not available')
  })

  it('writes every count with en-US grouping in any browser locale', async () => {
    simulateItalianLocale()
    serve({ ...summary, blocked_requests: 50772, top_blocked: [{ dest: 'malware.example', count: 1328 }] })
    renderWithProviders(<ThreatIntel />)
    await waitFor(() => { expect(card('Total Blocks')).toHaveTextContent('50,772') })
    expect(screen.getByTitle('malware.example').parentElement).toHaveTextContent('1,328')
  })
})
