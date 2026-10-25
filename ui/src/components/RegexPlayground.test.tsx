import { describe, it, expect, vi, beforeEach } from 'vitest'
import { screen, fireEvent } from '@testing-library/react'
import { AxiosError } from 'axios'
import { renderWithProviders } from '../test/helpers'
import { expectNoAxeViolations } from '../test/axe'
import { RegexPlayground } from './RegexPlayground'

vi.mock('../lib/api', () => ({
  api: { post: vi.fn() },
  getErrorMessage: (e: unknown, f: string) => (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail ?? f,
}))
import { api } from '../lib/api'

const test = (pattern: string) => {
  fireEvent.change(screen.getByRole('textbox', { name: 'Pattern' }), { target: { value: pattern } })
  fireEvent.click(screen.getByRole('button', { name: 'Test' }))
}

describe('RegexPlayground', () => {
  beforeEach(() => vi.clearAllMocks())

  it('sends the pattern as the WAF compiles it and lists what it matched', async () => {
    vi.mocked(api.post).mockResolvedValue({ data: { status: 'success', data: {
      regex: '(?i)\\.torrent$', hours: 24, scanned: 812, matched: 2, would_block: true,
      examples: ['http://files.example/a.torrent', 'http://files.example/B.TORRENT'],
    } } })
    const { container } = renderWithProviders(<RegexPlayground />)
    test('\\.torrent$')
    expect(await screen.findByRole('status')).toHaveTextContent('Matches 2 of 812 requests in the last 24 hours.')
    expect(screen.getByRole('list', { name: 'Matching URLs' })).toHaveTextContent('http://files.example/B.TORRENT')
    // Case-insensitive, as waf-go/internal/engine/customrules.go compiles it.
    expect(api.post).toHaveBeenCalledWith('waf/test-rule', { regex: '(?i)\\.torrent$', hours: 24 })
    // A match is not a verdict: nothing claims the WAF would block.
    expect(screen.getByRole('status')).not.toHaveTextContent(/block|safe to deploy/i)
    await expectNoAxeViolations(container)
  })

  it('says when a limit of the backend was reached', async () => {
    vi.mocked(api.post).mockResolvedValue({ data: { data: { regex: 'x', hours: 168, scanned: 10000, matched: 50, examples: [] } } })
    renderWithProviders(<RegexPlayground />)
    test('x')
    expect(await screen.findByRole('status')).toHaveTextContent('Matches at least 50 of 10,000 requests (the most one test reads) in the last 7 days.')
  })

  // Go's regexp, not JavaScript's, decides: (?i) is valid Go and invalid JS,
  // so the page sends the pattern and shows the backend's refusal.
  it('shows the backend error for a pattern Go cannot compile, without the flag the page added', async () => {
    vi.mocked(api.post).mockRejectedValue(new AxiosError('bad', 'ERR_BAD_REQUEST', undefined, undefined, {
      status: 400, data: { status: 'error', detail: 'invalid regex: error parsing regexp: missing closing ): `(?i)(abc`' },
    } as never))
    renderWithProviders(<RegexPlayground />)
    test('(abc')
    expect(await screen.findByText('The pattern was not tested')).toBeInTheDocument()
    expect(screen.getByText('invalid regex: error parsing regexp: missing closing ): `(abc`')).toBeInTheDocument()
  })
})
