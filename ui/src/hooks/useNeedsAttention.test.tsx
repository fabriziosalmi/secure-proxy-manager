import { describe, it, expect, vi, afterEach } from 'vitest'
import { act, renderHook, waitFor } from '@testing-library/react'
import { QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { createTestQueryClient } from '../test/helpers'
import { api } from '../lib/api'
import { useNeedsAttention } from './useNeedsAttention'

// Settings calls the hook with no interval. A channel that starts failing
// while the page is open must still reach Needs attention, so the delivery
// status is polled anyway, and only with alerts on.
describe('useNeedsAttention', () => {
  afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks() })

  const run = (alertsOn: boolean) => {
    let failing = false
    vi.spyOn(api, 'get').mockImplementation(((url: string) => {
      if (url === 'settings') return Promise.resolve({ data: { data: [
        { setting_name: 'enable_notifications', setting_value: alertsOn ? 'true' : 'false' },
        { setting_name: 'webhook_url', secret: true, is_set: true },
      ] } })
      if (url === 'notifications/status') return Promise.resolve({ data: { data: { since: 't', channels: { webhook: {
        last_attempt: 't', last_delivered: null, last_error: 'the server answered HTTP 500', last_error_at: 't', last_failed: failing, delivered: 0, failed: failing ? 1 : 0,
      } } } } })
      return Promise.resolve({ data: { data: null } })
    }) as never)
    const client = createTestQueryClient()
    const wrapper = ({ children }: { children: ReactNode }) => <QueryClientProvider client={client}>{children}</QueryClientProvider>
    const hook = renderHook(() => useNeedsAttention(), { wrapper })
    return { hook, fail: () => { failing = true }, statusCalls: () => vi.mocked(api.get).mock.calls.filter(([u]) => u === 'notifications/status').length }
  }

  it('polls the deliveries with no interval given, and reports a channel that starts failing', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    const { hook, fail, statusCalls } = run(true)
    await waitFor(() => expect(statusCalls()).toBe(1))
    expect(hook.result.current.items.map((a) => a.id)).not.toContain('alerts-failing')
    fail()
    await act(async () => { await vi.advanceTimersByTimeAsync(31_000) })
    await waitFor(() => expect(hook.result.current.items.map((a) => a.id)).toContain('alerts-failing'))
  })

  it('does not read the deliveries with alerts off', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    const { hook, statusCalls } = run(false)
    await waitFor(() => expect(hook.result.current.settingsLoaded).toBe(true))
    await act(async () => { await vi.advanceTimersByTimeAsync(31_000) })
    expect(statusCalls()).toBe(0)
  })
})
