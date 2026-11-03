import { describe, it, expect, vi, afterEach } from 'vitest'
import { screen, within } from '@testing-library/react'
import { renderWithProviders } from '../../../test/helpers'
import { api } from '../../../lib/api'
import { WafRunning } from './WafRunning'
import { wafRunningRows } from '../../../lib/wafRunning'

const ok = { status: 'ok' as const, categories: 21, categories_enabled: 20, categories_observed: 3, rules: 190, rules_enabled: 180, rules_observed: 12 }
const running = { engine: 'hybrid', threshold: 10, regex_engine: 'go', regex_shadow: true, heuristics: 5, policy_mode: 'block', policy_exceptions: 2, policy_reload_failed: false }

function serve(data: unknown) {
  vi.spyOn(api, 'get').mockResolvedValue({ data: { data } })
}

describe('WafRunning', () => {
  afterEach(() => vi.restoreAllMocks())

  it('lists what the WAF reports, not what the compose ships', () => {
    expect(wafRunningRows(ok, running)).toEqual([
      ['Engine', 'SPM rules plus the OWASP Core Rule Set'],
      // The threshold scores the SPM rules; the Core Rule Set blocks at its own.
      ['SPM rules block at', 'a score of 10 (WAF_BLOCK_THRESHOLD)'],
      ['Core Rule Set blocks at', 'its own anomaly score of 5'],
      ['Request rules', '180 on, in 20 categories; 3 categories only logged'],
      ['Regular expressions', "Go's regexp decides; the other engine runs beside it and the WAF logs any disagreement"],
      ['Heuristics on', '5'],
      ['Policy', 'Block, 2 exceptions'],
    ])
    const legacy = wafRunningRows({ ...ok, categories_observed: 0 }, { ...running, engine: 'legacy', threshold: 7, regex_engine: 're2', regex_shadow: false, policy_mode: '' })
    expect(legacy).toEqual([
      ['Engine', 'SPM rules only, without the OWASP Core Rule Set'],
      ['SPM rules block at', 'a score of 7 (WAF_BLOCK_THRESHOLD)'],
      ['Request rules', '180 on, in 20 categories'],
      ['Regular expressions', 'RE2'],
      ['Heuristics on', '5'],
    ])
    // Rules the policy makes log-only are counted with the categories.
    expect(wafRunningRows({ ...ok, categories_observed: 1 }, { ...running, policy_observe_rules: 2 })).toContainEqual(
      ['Request rules', '180 on, in 20 categories; 1 category and 2 single rules only logged'],
    )
  })

  it('warns that Log only blocks nothing', async () => {
    serve({ ...ok, running: { ...running, policy_mode: 'observe' } })
    renderWithProviders(<WafRunning />)
    expect(await screen.findByText('Log only: the WAF blocks nothing')).toBeInTheDocument()
    expect(screen.getByText('Log only: blocks nothing, 2 exceptions')).toBeInTheDocument()
  })

  it('says why it is not known', async () => {
    serve({ status: 'unreachable', categories: null, categories_enabled: null, rules: null, rules_enabled: null })
    renderWithProviders(<WafRunning />)
    expect(await screen.findByText('Not known. The backend cannot reach the WAF.')).toBeInTheDocument()
  })

  // The categories the coverage counts, each with whether it scores, only
  // logs or is off, so a category the policy observes can be seen.
  it('lists the rule categories and what each does', async () => {
    vi.spyOn(api, 'get').mockImplementation(((url: string) => Promise.resolve({ data: url === 'waf/categories'
      ? { status: 'ok', data: [
        { name: 'XSS_ATTACKS', rules: 72, enabled: true, observe: false },
        { name: 'CLOUD_SECRETS', rules: 30, enabled: true, observe: true },
        { name: 'SQL_INJECTION', rules: 100, enabled: false, observe: false },
      ] }
      : { data: { ...ok, running } } })) as never)
    renderWithProviders(<WafRunning />)
    const summary = await screen.findByText('Rule categories: 3 (1 only logged, 1 off)')
    const table = within(summary.closest('details') as HTMLElement).getByRole('table')
    const rows = within(table).getAllByRole('row').slice(1).map((r) => r.textContent)
    expect(rows).toEqual(['Cloud secrets30Only logged', 'Cross-site scripting72Scores', 'SQL injection100Off'])
  })
})
