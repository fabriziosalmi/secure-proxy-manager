import { describe, it, expect } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderWithProviders } from '../../test/helpers'
import { expectNoAxeViolations } from '../../test/axe'
import { CACHE_DAYS, cacheByDayFixture } from '../../test/cacheByDay'
import type { CacheByDay } from '../../types'
import { CachePerDay } from './CachePerDay'
import { cacheAxisMax, cacheSummary } from './cache'

describe('CachePerDay', () => {
  it('draws every day, bottom first from the cache, and says what the week comes to', async () => {
    const { container } = renderWithProviders(<CachePerDay data={cacheByDayFixture()} />)
    const bars = screen.getByTestId('cache-bars')
    const days = [...bars.querySelectorAll('[data-day]')]
    expect(days.map((d) => d.getAttribute('data-day'))).toEqual(CACHE_DAYS.map((d) => `2026-10-${d}`))
    expect(days[0].querySelectorAll('[data-group]')).toHaveLength(0)
    const today = [...days[6].querySelectorAll('[data-group]')]
    // A hit and a revalidated copy share one stack (2 + 127).
    expect(today.map((s) => [s.getAttribute('data-group'), s.getAttribute('data-value')])).toEqual([
      ['cache', '129'], ['miss', '417'], ['tunnel', '7074'], ['refused', '928'], ['other', '16'],
    ])
    expect(today.map((s) => s.className.match(/bg-[a-z0-9-]+/)?.[0])).toEqual(['bg-series-1', 'bg-series-2', 'bg-series-3', 'bg-series-4', 'bg-chart-neutral'])
    // 129 of 586 cacheable requests; 7974 tunnels of 9504 requests.
    expect(screen.getByTestId('cache-summary')).toHaveTextContent(
      'The cache answered 22.0% of the 586 requests it could have answered (35.9% of their bytes), 127 of them after checking with the server. 83.9% of the requests (97.4% of the bytes) were HTTPS tunnels',
    )
    expect(screen.getByRole('img', { name: /^What the cache did per day, requests/ })).toHaveAccessibleName(
      'What the cache did per day, requests, today and the 6 days before: Tue 20 40 Fetched from the server, 900 HTTPS tunnel (not cacheable); today 129 From the cache, 417 Fetched from the server, 7,074 HTTPS tunnel (not cacheable), 928 Refused by the proxy, 16 Other; none on the other 5 days.',
    )
    expect(screen.getByText(/Requests from 2 internal addresses in these 7 days are not counted/)).toBeInTheDocument()
    await expectNoAxeViolations(container)
  })

  it('switches to bytes, with an axis in round units, and the table follows', async () => {
    renderWithProviders(<CachePerDay data={cacheByDayFixture()} />)
    expect(screen.getByRole('button', { name: 'Requests' })).toHaveAttribute('aria-pressed', 'true')
    await userEvent.click(screen.getByRole('button', { name: 'Bytes' }))
    expect(screen.getByRole('button', { name: 'Bytes' })).toHaveAttribute('aria-pressed', 'true')
    const today = [...screen.getByTestId('cache-bars').querySelectorAll('[data-day="2026-10-25"] [data-group]')]
    expect(today.map((s) => s.getAttribute('data-value'))).toEqual([String(2048 + 56 * 1024 * 1024), String(96 * 1024 * 1024), String(5 * 1024 ** 3), String(4 * 1024 * 1024)])
    await userEvent.click(screen.getByText('Show the numbers'))
    const table = screen.getByRole('table', { name: 'What the cache did on each of the last 7 days, bytes sent' })
    const row = within(table).getAllByRole('row').find((r) => r.textContent?.startsWith('Sun 25'))
    expect(row?.textContent).toBe('Sun 25 2026-10-252.0 KB56.0 MB96.0 MB5.0 GB4.0 MB0 B5.2 GB')
  })

  it('says so when nothing was cacheable, and when nothing was logged', () => {
    const data = cacheByDayFixture()
    for (const d of data.days) Object.assign(d.requests, { hit: 0, revalidated: 0, miss: 0 })
    Object.assign(data.totals.requests, { hit: 0, revalidated: 0, miss: 0 })
    const { unmount } = renderWithProviders(<CachePerDay data={data} />)
    expect(screen.getByTestId('cache-summary')).toHaveTextContent('No request the cache could have answered in these 7 days.')
    unmount()
    const empty: CacheByDay = { ...cacheByDayFixture(), days: cacheByDayFixture().days.map((d) => ({ ...d, requests: { hit: 0, revalidated: 0, miss: 0, tunnel: 0, refused: 0, other: 0 } })) }
    renderWithProviders(<CachePerDay data={empty} />)
    expect(screen.getByText('No client requests in the last 7 days')).toBeInTheDocument()
  })

  it('says which call failed', () => {
    renderWithProviders(<CachePerDay error />)
    expect(screen.getByRole('alert')).toHaveTextContent('Could not load the daily counts (analytics/cache-by-day).')
  })
})

describe('cache', () => {
  it('rounds the byte axis in the unit of the peak', () => {
    const data = cacheByDayFixture()
    // Today sends 5.15 GiB: the axis tops at 6 GiB, not at a decimal 6,000,000,000.
    expect(cacheAxisMax(data.days, 'bytes')).toBe(6 * 1024 ** 3)
    expect(cacheAxisMax(data.days, 'requests')).toBe(10000)
  })

  it('leaves tunnels and refusals out of the cacheable share', () => {
    const s = cacheSummary(cacheByDayFixture())
    expect([s.cacheable, s.fromCache, s.share]).toEqual([586, 129, '22.0%'])
  })
})
