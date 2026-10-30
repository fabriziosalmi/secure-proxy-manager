import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { renderWithProviders } from '../../../test/helpers'
import { expectNoAxeViolations } from '../../../test/axe'
import { api } from '../../../lib/api'
import { WafPolicySection } from './WafPolicySection'
import type { WafPolicyState } from '../../../lib/wafPolicy'

// GET /api/waf/policy as the backend answers it (handlers/waf_policy.go).
const state = (over: Partial<WafPolicyState> = {}): WafPolicyState => ({
  path: '/config/waf_policy.json', exists: true, sha256: 'abc123',
  policy: {
    version: 1,
    observe_rules: ['XSS-003'],
    exceptions: [
      { rule: 'CRS-942290', host: 'shop.example', target: 'ARGS:pwd', comment: 'login form' },
      { rule: 'SQLi-015', host: '.search.example', path: '/api/' },
    ],
  },
  waf: { mode: 'block', exceptions: 2, sha256: 'abc123' }, in_force: true,
  ...over,
})

let current: WafPolicyState = state()

describe('WafPolicySection', () => {
  beforeEach(() => {
    current = state()
    vi.spyOn(api, 'get').mockImplementation((url: string) => (url === 'waf/policy'
      ? Promise.resolve({ data: { status: 'success', data: current } })
      : Promise.reject(new Error(url))) as never)
    vi.spyOn(api, 'put').mockResolvedValue({ data: { status: 'success', data: { sha256: 'def456', waf: { reloaded: true } } } })
  })
  afterEach(() => vi.restoreAllMocks())

  it('lists the exceptions and the rules left to log only', async () => {
    const { container } = renderWithProviders(<WafPolicySection />)
    expect(await screen.findByText('on shop.example, ARGS:pwd')).toBeInTheDocument()
    expect(screen.getByText('on search.example and the names under it, path /api/')).toBeInTheDocument()
    expect(screen.getByText('login form')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Block again: XSS-003' })).toBeInTheDocument()
    await expectNoAxeViolations(container)
  })

  it('removes one exception with a PUT of the whole file and the digest it read', async () => {
    renderWithProviders(<WafPolicySection />)
    fireEvent.click(await screen.findByRole('button', { name: 'Remove the exception for SQLi-015 on search.example and the names under it, path /api/' }))
    const dialog = await screen.findByRole('alertdialog', { name: 'Remove the exception for SQLi-015?' })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Remove' }))
    await waitFor(() => expect(api.put).toHaveBeenCalledWith('waf/policy', {
      sha256: 'abc123',
      policy: { version: 1, observe_rules: ['XSS-003'], exceptions: [{ rule: 'CRS-942290', host: 'shop.example', target: 'ARGS:pwd', comment: 'login form' }] },
    }))
  })

  it('switches to log only after a confirmation, and back without the mode field', async () => {
    renderWithProviders(<WafPolicySection />)
    fireEvent.click(await screen.findByRole('button', { name: 'Log only' }))
    fireEvent.click(within(await screen.findByRole('alertdialog', { name: 'Log only, block nothing?' })).getByRole('button', { name: 'Log only' }))
    await waitFor(() => expect(vi.mocked(api.put).mock.calls[0][1]).toMatchObject({ policy: { mode: 'observe' } }))
  })

  it('offers a reset when the file does not parse, and says why', async () => {
    current = state({ policy: null, file_error: 'the policy file does not parse: unexpected EOF' })
    renderWithProviders(<WafPolicySection />)
    expect(await screen.findByText(/unexpected EOF/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Reset to an empty policy' }))
    fireEvent.click(within(await screen.findByRole('alertdialog', { name: 'Reset the policy file?' })).getByRole('button', { name: 'Reset' }))
    await waitFor(() => expect(api.put).toHaveBeenCalledWith('waf/policy', { policy: { version: 1 }, sha256: 'abc123' }))
  })

  it('says when the WAF cannot be asked and when it has not applied the file yet', async () => {
    current = state({ waf: null, in_force: undefined, waf_error: 'the WAF could not be reached' })
    const { unmount } = renderWithProviders(<WafPolicySection />)
    expect(await screen.findByText('The running WAF could not be asked which policy it applies')).toBeInTheDocument()
    unmount()
    current = state({ in_force: false, waf: { sha256: 'old', last_error: 'exception 2: unknown rule' } })
    renderWithProviders(<WafPolicySection />)
    expect(await screen.findByText('The WAF has not applied this file yet')).toBeInTheDocument()
    expect(screen.getByText(/Its last attempt failed: exception 2: unknown rule/)).toBeInTheDocument()
  })
})
