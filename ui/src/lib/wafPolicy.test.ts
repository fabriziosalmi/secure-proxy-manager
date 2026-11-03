import { describe, it, expect, vi, afterEach } from 'vitest'
import { QueryClient } from '@tanstack/react-query'
import { refreshWafState } from './wafPolicy'

// A policy write must reach every page that shows the WAF's state: Log only
// read as Block until the page was reloaded.
describe('refreshWafState', () => {
  afterEach(() => { vi.useRealTimers() })

  const keys = (qc: QueryClient) => vi.mocked(qc.invalidateQueries).mock.calls.map((c) => JSON.stringify(c[0]?.queryKey))

  it('reads the policy, the WAF status and the categories again, once when the WAF reloaded', () => {
    vi.useFakeTimers()
    const qc = new QueryClient()
    vi.spyOn(qc, 'invalidateQueries')
    refreshWafState(qc, { reloaded: true })
    vi.advanceTimersByTime(10_000)
    expect(keys(qc)).toEqual(['["waf","policy"]', '["waf","status"]', '["waf","categories"]'])
  })

  it('reads them again after the WAF has had the time to pick the file up when the reload was not confirmed', () => {
    vi.useFakeTimers()
    const qc = new QueryClient()
    const spy = vi.spyOn(qc, 'invalidateQueries')
    refreshWafState(qc, { reloaded: false, detail: 'the WAF did not answer' })
    expect(spy).toHaveBeenCalledTimes(3)
    vi.advanceTimersByTime(5_999)
    expect(spy).toHaveBeenCalledTimes(3)
    vi.advanceTimersByTime(1)
    expect(keys(qc)).toEqual(['["waf","policy"]', '["waf","status"]', '["waf","categories"]', '["waf","policy"]', '["waf","status"]', '["waf","categories"]'])
  })
})
