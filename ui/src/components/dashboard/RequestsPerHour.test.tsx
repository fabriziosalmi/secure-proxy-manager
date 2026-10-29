import { describe, it, expect, afterEach, beforeEach } from 'vitest'
import { screen } from '@testing-library/react'
import { renderWithProviders, setRomeTimeZone } from '../../test/helpers'
import { expectNoAxeViolations } from '../../test/axe'
import { RequestsPerHour } from './RequestsPerHour'

const NOW = Date.UTC(2026, 9, 25, 9, 21, 40)
const TEST_DEPLOYMENT = [
  { time: '2026-10-25 07:00:00', total: 26, blocked: 0 },
  { time: '2026-10-25 08:00:00', total: 1146, blocked: 908 },
  { time: '2026-10-25 09:00:00', total: 8, blocked: 0 },
]

function bars() {
  return [...document.querySelectorAll<HTMLElement>('[data-hour]')]
}

describe('RequestsPerHour', () => {
  let restoreTz: () => void
  beforeEach(() => { restoreTz = setRomeTimeZone() })
  afterEach(() => { restoreTz() })

  it('draws one bar per hour of the window, the empty hours at zero height', () => {
    renderWithProviders(<RequestsPerHour entries={TEST_DEPLOYMENT} now={NOW} />)
    const all = bars()
    expect(all).toHaveLength(25)
    const empty = all.filter((b) => [...b.children].every((c) => (c as HTMLElement).style.height === '0px' || (c as HTMLElement).style.height === '0'))
    expect(empty).toHaveLength(22)
  })

  // Blocked is a part of the hour's requests: stacked on the allowed part, on
  // the one axis, so 908 of 1,146 is 908 of 1,146 and not a second scale.
  it('stacks blocked on allowed for the same hour, on one axis', () => {
    renderWithProviders(<RequestsPerHour entries={TEST_DEPLOYMENT} now={NOW} />)
    const busy = bars().find((b) => b.dataset.hour === '2026-10-25 08:00:00')!
    const blocked = busy.querySelector<HTMLElement>('[data-series="blocked"]')!
    const allowed = busy.querySelector<HTMLElement>('[data-series="allowed"]')!
    // The axis tops at 1,500: 908 / 1,500 and 238 / 1,500 of the height.
    expect(blocked.style.height).toBe(`max(1px, ${(908 / 1500) * 100}%)`)
    expect(allowed.style.height).toBe(`max(1px, ${(238 / 1500) * 100}%)`)
    expect(blocked.className).toContain('bg-danger-strong')
    expect(allowed.className).toContain('bg-chart-neutral')
    // 2026-10-25 is the day Rome leaves summer time: UTC+1 after 01:00 UTC.
    expect(busy.title).toBe('09:00: 1,146 requests, 908 blocked')
  })

  it('says the same numbers as text, at the viewer time', () => {
    renderWithProviders(<RequestsPerHour entries={TEST_DEPLOYMENT} now={NOW} />)
    expect(screen.getByRole('img', {
      name: 'Requests per hour, last 24 hours: 26 at 08:00, 1,146 at 09:00 of which 908 blocked, 8 at 10:00; no requests in the other hours.',
    })).toBeInTheDocument()
  })

  it('says there were no requests instead of drawing an empty axis', () => {
    renderWithProviders(<RequestsPerHour entries={[]} now={NOW} />)
    expect(screen.getByText('No client requests in the last 24 hours')).toBeInTheDocument()
    expect(bars()).toHaveLength(0)
  })

  it('says the timeline is missing when the request failed', () => {
    renderWithProviders(<RequestsPerHour entries={null} now={NOW} error />)
    expect(screen.getByRole('alert')).toHaveTextContent('Could not load the hourly timeline')
  })

  // The axis read 08:00 at both ends: 25 hourly buckets for 24 hours, the
  // first covering only the minutes from now minus 24 hours to the next hour.
  it('marks the partial first and last hours and writes no label twice', () => {
    renderWithProviders(<RequestsPerHour entries={TEST_DEPLOYMENT} now={NOW} />)
    const all = bars()
    expect(all[0].dataset.partial).toBe('true')
    expect(all[all.length - 1].dataset.partial).toBe('true')
    expect(all.slice(1, -1).every((b) => b.dataset.partial === undefined)).toBe(true)
    // 24 hours before 10:21:40 in Rome (UTC+1 now, UTC+2 the day before) is 11:21 on Saturday.
    expect(all[0].title).toBe('11:21 to 12:00 only: 0 requests, 0 blocked')
    expect(all[all.length - 1].title).toBe('10:00 to 10:21 only: 8 requests, 0 blocked')
    const labels = [...document.querySelectorAll<HTMLElement>('[data-label]')].map((l) => l.dataset.label)
    expect(new Set(labels).size).toBe(labels.length)
    expect(labels[0]).toBe('Sat 11:21')
    expect(labels[labels.length - 1]).toBe('Now')
  })

  it('treats a window that starts on the hour as whole hours', () => {
    const onTheHour = Date.UTC(2026, 9, 25, 9, 0, 0)
    renderWithProviders(<RequestsPerHour entries={TEST_DEPLOYMENT} now={onTheHour} />)
    expect(bars().filter((b) => b.dataset.partial)).toHaveLength(0)
  })

  it('passes axe', async () => {
    const { container } = renderWithProviders(<RequestsPerHour entries={TEST_DEPLOYMENT} now={NOW} />)
    await expectNoAxeViolations(container)
  })
})
