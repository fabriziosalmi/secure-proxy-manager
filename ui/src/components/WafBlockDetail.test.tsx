import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { AxiosError, AxiosHeaders } from 'axios'
import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { renderWithProviders } from '../test/helpers'
import { expectNoAxeViolations } from '../test/axe'
import { api } from '../lib/api'
import { WafBlockDetail } from './WafBlockDetail'
import type { WafEvent } from '../lib/wafPolicy'

// A Core Rule Set block as GET /api/waf/events/{id} returns it
// (database.WAFEvent): DLP-001 is an observe-only match, in rules but not in
// scoring_rules, so no exception is offered for it.
const crsBlock: WafEvent = {
  event_id: 'dmi3z8mpcz74-1', timestamp: '2026-10-30 10:42:19', client_ip: '192.168.1.20',
  host: 'shop.example', path: '/tienda1/publico/autenticar.jsp', url: 'http://shop.example/tienda1/publico/autenticar.jsp?pwd=x',
  source: 'URL', blocked_by: 'crs', score: 0, crs_score: 5,
  rules: ['CRS-942290', 'DLP-001'], scoring_rules: ['CRS-942290'], categories: ['CRS_SQLI', 'DATA_LEAK_PREVENTION'],
  crs_targets: [{ rule: 'CRS-942290', target: 'ARGS:pwd' }],
}

let event: () => Promise<unknown> = () => Promise.resolve({ data: { status: 'success', data: crsBlock } })

describe('WafBlockDetail', () => {
  beforeEach(() => {
    event = () => Promise.resolve({ data: { status: 'success', data: crsBlock } })
    vi.spyOn(api, 'get').mockImplementation((url: string) => (url.startsWith('waf/events/') ? event() : Promise.reject(new Error(url))) as never)
    vi.spyOn(api, 'post').mockResolvedValue({ data: { status: 'success', data: { added: true, waf: { reloaded: true } } } })
  })
  afterEach(() => vi.restoreAllMocks())

  it('names what blocked and offers exceptions for the scoring rules only', async () => {
    const { container } = renderWithProviders(<WafBlockDetail eventId="dmi3z8mpcz74-1" />)
    expect(await screen.findByText(/The OWASP Core Rule Set blocked it, with an anomaly score of 5/)).toBeInTheDocument()
    expect(api.get).toHaveBeenCalledWith('waf/events/dmi3z8mpcz74-1', undefined)
    expect(screen.getByText('CRS-942290')).toBeInTheDocument()
    expect(screen.queryByText('DLP-001')).not.toBeInTheDocument()
    for (const name of ['Exception for shop.example', 'Only this path', 'Only ARGS:pwd', 'Log only, every host']) {
      expect(screen.getByRole('button', { name })).toBeInTheDocument()
    }
    await expectNoAxeViolations(container)
  })

  it('adds the argument exception after a confirmation, with the event in the comment', async () => {
    renderWithProviders(<WafBlockDetail eventId="dmi3z8mpcz74-1" />)
    fireEvent.click(await screen.findByRole('button', { name: 'Only ARGS:pwd' }))
    const dialog = await screen.findByRole('alertdialog', { name: 'Add an exception for CRS-942290?' })
    expect(dialog).toHaveTextContent('ARGS:pwd on shop.example')
    expect(api.post).not.toHaveBeenCalled()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Add exception' }))
    await waitFor(() => expect(api.post).toHaveBeenCalledWith('waf/policy/exceptions', {
      rule: 'CRS-942290', host: 'shop.example', target: 'ARGS:pwd', comment: 'Added from the access log (event dmi3z8mpcz74-1)',
    }))
  })

  it('leaves a rule to log only after a confirmation that says it no longer blocks anywhere', async () => {
    renderWithProviders(<WafBlockDetail eventId="dmi3z8mpcz74-1" />)
    fireEvent.click(await screen.findByRole('button', { name: 'Log only, every host' }))
    const dialog = await screen.findByRole('alertdialog', { name: 'Log CRS-942290 only, on every host?' })
    expect(dialog).toHaveTextContent('no longer blocks anything, anywhere')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Log only' }))
    await waitFor(() => expect(api.post).toHaveBeenCalledWith('waf/policy/observe-rules', { rule: 'CRS-942290' }))
  })

  it('says the details are not kept when the event is gone', async () => {
    event = () => Promise.reject(new AxiosError('nf', 'ERR_BAD_REQUEST', undefined, undefined, {
      status: 404, statusText: 'Not Found', headers: {}, config: { headers: new AxiosHeaders() }, data: { status: 'error', detail: 'no WAF event' },
    }))
    renderWithProviders(<WafBlockDetail eventId="gone-1" />)
    expect(await screen.findByText("The WAF's details of this block are not kept")).toBeInTheDocument()
    expect(screen.queryByRole('button')).not.toBeInTheDocument()
  })

  it('offers every rule when an older backend sends no scoring_rules', async () => {
    event = () => Promise.resolve({ data: { status: 'success', data: { ...crsBlock, scoring_rules: undefined, blocked_by: 'spm', score: 12, rules: ['SQLi-006', 'SQLi-017'], crs_targets: [] } } })
    renderWithProviders(<WafBlockDetail eventId="dmi3z8mpcz74-1" />)
    expect(await screen.findByText('The built-in rules blocked it, with a score of 12.')).toBeInTheDocument()
    expect(screen.getAllByRole('button', { name: 'Exception for shop.example' })).toHaveLength(2)
    expect(screen.queryByRole('button', { name: /^Only ARGS/ })).not.toBeInTheDocument()
  })
})
