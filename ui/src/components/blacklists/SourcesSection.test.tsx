import { describe, it, expect, vi, afterEach } from 'vitest'
import { screen, within } from '@testing-library/react'
import { renderWithProviders } from '../../test/helpers'
import type { ListSource } from '../../types'
import { SourcesSection } from './SourcesSection'
import { LISTS } from './lists'

// jsdom has no layout, so these pin the classes the layout rests on; the
// boxes themselves are measured in Chromium (tests/e2e/selfhoster.spec.ts,
// "keeps Remove batch inside its card"). Finding 29: a long URL widened the
// source column and the Remove batch button ended 240 px past the card's
// right edge at 1440 px, out of sight in the table's scroll box.

const LONG = 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/a/very/long/path/to/the/list/firehol_level1.netset'
const sources: ListSource[] = [
  { id: 1, kind: 'url', source: LONG, label: 'A Popular list with a name long enough to need cutting', entries: 50772, first_added: '2026-10-25 08:00:00', last_added: '2026-10-26 09:00:00' },
  { id: 2, kind: 'manual', source: '', label: '', entries: 3, first_added: '2026-10-25 08:00:00', last_added: '2026-10-25 08:00:00' },
]

function renderSources() {
  renderWithProviders(
    <SourcesSection list={LISTS[0]} sources={sources} loading={false} error={false} onRetry={() => {}} onRemove={() => {}} />,
  )
  return screen.getByRole('table', { name: 'Sources of Blocked IPs' })
}

const classes = (el: Element | null) => (el?.getAttribute('class') ?? '').split(/\s+/)

describe('SourcesSection layout', () => {
  it('cuts a long name and URL to the width left over, with the whole text in the title', () => {
    const table = renderSources()
    const name = within(table).getByText('A Popular list with a name long enough to need cutting')
    const url = within(table).getByText(LONG)
    for (const el of [name, url]) {
      expect(classes(el)).toEqual(expect.arrayContaining(['block', 'truncate']))
      expect(el).toHaveAttribute('title', el.textContent)
    }
    // The cell takes what the other columns leave and no more: without
    // max-w-0 the text's own width decides the column's.
    expect(classes(name.closest('td'))).toEqual(expect.arrayContaining(['w-full', 'max-w-0']))
  })

  it('keeps the action column as wide as its button, never narrower', () => {
    const table = renderSources()
    const btn = within(table).getByRole('button', { name: /^Remove batch: A Popular list/ })
    expect(classes(btn.closest('td'))).toEqual(expect.arrayContaining(['w-px', 'whitespace-nowrap']))
  })

  afterEach(() => { vi.useRealTimers() })

  it('lets a date range break only before "to"', () => {
    vi.useFakeTimers({ toFake: ['Date'], now: Date.UTC(2026, 9, 29, 7, 52, 30) })
    const table = renderSources()
    const row = within(table).getAllByRole('row')[1]
    const pieces = within(row).getAllByText(/^(Sun 25 \d\d:\d\d|to Mon 26 \d\d:\d\d)$/)
    // Once in the Added column and once under the name for a phone.
    expect(pieces).toHaveLength(4)
    for (const p of pieces) expect(classes(p)).toContain('whitespace-nowrap')
  })
})
