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
  it('cuts a long name to the width left over, and lets its URL run onto more lines as a link, with the whole text in the title', () => {
    const table = renderSources()
    const name = within(table).getByText('A Popular list with a name long enough to need cutting')
    const url = within(table).getByText(LONG)
    expect(classes(name)).toEqual(expect.arrayContaining(['block', 'truncate']))
    expect(name).toHaveAttribute('title', name.textContent)
    // An ellipsis on the first line hid most of every feed URL.
    expect(classes(url)).toEqual(expect.arrayContaining(['line-clamp-3', 'break-all']))
    expect(classes(url)).not.toContain('truncate')
    expect(url.tagName).toBe('A')
    expect(url).toHaveAttribute('href', LONG)
    expect(url).toHaveAttribute('rel', 'noopener noreferrer')
    expect(url).toHaveAttribute('title', LONG)
    // The cell takes what the other columns leave and no more: without
    // max-w-0 the text's own width decides the column's.
    expect(classes(name.closest('td'))).toEqual(expect.arrayContaining(['w-full', 'max-w-0']))
  })

  // "Remove" and " batch" were two flex items of the button, 6 px apart
  // (a space is 2.8 px at 13 px): "Remove  batch".
  it('writes Remove batch as one piece of text, so its space is a space', () => {
    const table = renderSources()
    const btn = within(table).getByRole('button', { name: /^Remove batch: A Popular list/ })
    expect(btn.children).toHaveLength(1)
    expect(btn.firstElementChild).toHaveTextContent('Remove batch')
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

  // What the last refresh of each url source came to: a source that stopped
  // downloading, or came back short, is seen where the source is.
  it('says what the last refresh of each url source came to', () => {
    const at = '2026-11-03 10:00:00'
    renderWithProviders(
      <SourcesSection
        list={LISTS[0]}
        sources={[
          { ...sources[0], id: 1, refreshed_at: at, refresh_status: 'ok', refresh_detail: 'listed 50,772 entries' },
          { ...sources[0], id: 3, source: 'https://b.test/l', refreshed_at: at, refresh_status: 'held', refresh_detail: 'listed 30 entries, fewer than half of the 1,200 it added: they are kept' },
          { ...sources[0], id: 4, source: 'https://c.test/l', refreshed_at: at, refresh_status: 'failed', refresh_detail: 'not downloaded: the server answered HTTP 410' },
          sources[1],
        ]}
        loading={false}
        error={false}
        onRetry={() => {}}
        onRemove={() => {}}
      />,
    )
    const notes = [...document.querySelectorAll('[data-refresh]')].map((n) => [n.getAttribute('data-refresh'), n.textContent])
    expect(notes).toHaveLength(3)
    expect(notes[0][1]).toMatch(/^Refreshed .+: listed 50,772 entries$/)
    expect(notes[1][1]).toMatch(/^Held .+: listed 30 entries, fewer than half of the 1,200 it added: they are kept$/)
    expect(notes[2][1]).toMatch(/^Not refreshed .+: not downloaded: the server answered HTTP 410$/)
    expect(document.querySelector('[data-refresh="held"]')?.className).toContain('text-warning')
    expect(document.querySelector('[data-refresh="failed"]')?.className).toContain('text-danger')
  })
})
