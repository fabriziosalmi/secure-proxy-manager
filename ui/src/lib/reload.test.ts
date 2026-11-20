import { describe, it, expect, vi, afterEach } from 'vitest'

import { api } from './api'
import { applyToProxy, describeApply } from './reload'

afterEach(() => {
  vi.restoreAllMocks()
})

describe('applyToProxy', () => {
  it('reads 200 success as applied', async () => {
    vi.spyOn(api, 'post').mockResolvedValue({ data: { status: 'success', message: 'Proxy reloaded' } })
    expect((await applyToProxy()).kind).toBe('applied')
  })

  // The backend reloads the proxy even when exporting the lists failed, and
  // answers status partial with code export_failed. That is neither applied
  // nor a reload that could not be requested.
  it('reads partial export_failed as a reload with the previous lists', async () => {
    vi.spyOn(api, 'post').mockResolvedValue({
      data: { status: 'partial', code: 'export_failed', message: 'Proxy reloaded, but the lists could not be exported' },
    })
    const o = await applyToProxy()
    expect(o.kind).toBe('listsNotExported')
    const d = describeApply(o, 'Saved')
    expect(d.tone).toBe('warning')
    expect(d.text).toContain('The proxy reloaded')
    expect(d.text).toContain('the lists could not be exported')
    expect(d.text).not.toContain('could not be requested')
  })
})
