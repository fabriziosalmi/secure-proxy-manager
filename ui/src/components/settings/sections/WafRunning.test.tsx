import { describe, it, expect, vi, afterEach } from 'vitest'
import { screen } from '@testing-library/react'
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
      ['Blocks at', 'a score of 10 (WAF_BLOCK_THRESHOLD)'],
      ['Request rules', '180 on, in 20 categories, 3 of them only logged'],
      ['Regular expressions', "Go's regexp decides; the other engine runs beside it and the WAF logs any disagreement"],
      ['Heuristics on', '5'],
      ['Policy', 'Block, 2 exceptions'],
    ])
    const legacy = wafRunningRows({ ...ok, categories_observed: 0 }, { ...running, engine: 'legacy', threshold: 7, regex_engine: 're2', regex_shadow: false, policy_mode: '' })
    expect(legacy).toEqual([
      ['Engine', 'SPM rules only, without the OWASP Core Rule Set'],
      ['Blocks at', 'a score of 7 (WAF_BLOCK_THRESHOLD)'],
      ['Request rules', '180 on, in 20 categories'],
      ['Regular expressions', 'RE2'],
      ['Heuristics on', '5'],
    ])
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
})
