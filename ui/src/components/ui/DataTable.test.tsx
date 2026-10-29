import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent, within } from '@testing-library/react'
import { DataTable, type Column, type SortState } from './DataTable'
import { expectNoAxeViolations } from '../../test/axe'
import { formatCount } from '../../lib/format'

interface Client { ip: string; requests: number; blocked: number }

const ROWS: Client[] = [
  { ip: '192.168.1.109', requests: 1180, blocked: 908 },
  { ip: '172.18.0.4', requests: 128, blocked: 128 },
]

const COLUMNS: Column<Client>[] = [
  { id: 'ip', header: 'Client', cell: (c) => <code>{c.ip}</code> },
  { id: 'requests', header: 'Requests', align: 'right', sortable: true, firstSort: 'descending', cell: (c) => formatCount(c.requests) },
  { id: 'blocked', header: 'Blocked', align: 'right', sortable: true, firstSort: 'descending', cell: (c) => formatCount(c.blocked) },
  { id: 'actions', header: 'Actions', headerHidden: true, cell: (c) => <button type="button">Remove {c.ip}</button> },
]

const EMPTY = { title: 'No clients yet', description: 'Devices appear here once they use the proxy.' }

function table(props: Partial<React.ComponentProps<typeof DataTable<Client>>> = {}) {
  return render(
    <DataTable<Client> caption="Clients" columns={COLUMNS} rows={ROWS} rowKey={(c) => c.ip} empty={EMPTY} {...props} />,
  )
}

describe('DataTable', () => {
  it('renders a named table inside a focusable scroll box that is a group, not a landmark region', async () => {
    const { container } = table()
    const t = screen.getByRole('table', { name: 'Clients' })
    expect(within(t).getAllByRole('row')).toHaveLength(3)
    expect(within(t).getByText('1,180')).toBeInTheDocument()
    const scrollBox = screen.getByRole('group', { name: 'Clients' })
    expect(scrollBox).toBe(t.parentElement)
    expect(scrollBox).toHaveAttribute('tabindex', '0')
    expect(scrollBox.className).toMatch(/overflow-x-auto/)
    expect(screen.queryByRole('region', { name: 'Clients' })).toBeNull()
    // The actions header stays for screen readers only.
    expect(screen.getByRole('columnheader', { name: 'Actions' }).querySelector('.sr-only')).not.toBeNull()
    await expectNoAxeViolations(container)
  })

  it('marks the sorted column with aria-sort and only that one', async () => {
    const { container } = table({ sort: { columnId: 'requests', direction: 'descending' }, onSortChange: () => {} })
    expect(screen.getByRole('columnheader', { name: /Requests/ })).toHaveAttribute('aria-sort', 'descending')
    expect(screen.getByRole('columnheader', { name: /Blocked/ })).not.toHaveAttribute('aria-sort')
    expect(screen.getByRole('columnheader', { name: 'Client' })).not.toHaveAttribute('aria-sort')
    await expectNoAxeViolations(container)
  })

  it('sorts a new column in its first direction and flips the current one', () => {
    const onSortChange = vi.fn<(s: SortState) => void>()
    table({ sort: { columnId: 'requests', direction: 'descending' }, onSortChange })
    fireEvent.click(screen.getByRole('button', { name: 'Blocked' }))
    expect(onSortChange).toHaveBeenLastCalledWith({ columnId: 'blocked', direction: 'descending' })
    fireEvent.click(screen.getByRole('button', { name: 'Requests' }))
    expect(onSortChange).toHaveBeenLastCalledWith({ columnId: 'requests', direction: 'ascending' })
  })

  it('has no sort buttons when nobody handles sorting', () => {
    table()
    expect(screen.queryByRole('button', { name: 'Requests' })).not.toBeInTheDocument()
  })

  it('paginates as "1 to 50 of 50,772" with Previous disabled on the first page', async () => {
    const onChange = vi.fn()
    const many = Array.from({ length: 50 }, (_, i) => ({ ip: `10.0.0.${i}`, requests: i, blocked: 0 }))
    const { container } = table({ rows: many, pagination: { offset: 0, limit: 50, total: 50772, onChange } })
    const nav = screen.getByRole('navigation', { name: 'Clients pages' })
    expect(within(nav).getByText('1 to 50 of 50,772')).toBeInTheDocument()
    expect(within(nav).getByRole('button', { name: 'Previous' })).toBeDisabled()
    fireEvent.click(within(nav).getByRole('button', { name: 'Next' }))
    expect(onChange).toHaveBeenCalledWith(50)
    await expectNoAxeViolations(container)
  })

  it('names the page buttons as the list asks, newest first reading Newer and Older', () => {
    const onChange = vi.fn()
    table({ pagination: { offset: 50, limit: 50, total: 120, onChange, previousLabel: 'Newer', nextLabel: 'Older' } })
    fireEvent.click(screen.getByRole('button', { name: 'Older' }))
    expect(onChange).toHaveBeenLastCalledWith(100)
    fireEvent.click(screen.getByRole('button', { name: 'Newer' }))
    expect(onChange).toHaveBeenLastCalledWith(0)
    expect(screen.queryByRole('button', { name: 'Previous' })).toBeNull()
  })

  it('disables Next on the last page', () => {
    table({ pagination: { offset: 50, limit: 50, total: 52, onChange: () => {} } })
    expect(screen.getByText('51 to 52 of 52')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Previous' })).toBeEnabled()
  })

  it('shows skeleton rows while loading, marked busy, and says so to screen readers', async () => {
    const { container } = table({ rows: [], loading: true, skeletonRows: 3, pagination: { offset: 0, limit: 50, total: 0, onChange: () => {} } })
    expect(screen.getByRole('table', { name: 'Clients' })).toHaveAttribute('aria-busy', 'true')
    expect(screen.getByRole('status')).toHaveTextContent('Loading clients')
    expect(container.querySelectorAll('tbody tr[aria-hidden="true"]')).toHaveLength(3)
    expect(screen.queryByText('No clients yet')).not.toBeInTheDocument()
    expect(screen.queryByRole('navigation')).not.toBeInTheDocument()
    await expectNoAxeViolations(container)
  })

  it('says what is missing and what to do when there are no rows', async () => {
    const { container } = table({ rows: [] })
    expect(screen.getByText('No clients yet')).toBeInTheDocument()
    expect(screen.getByText('Devices appear here once they use the proxy.')).toBeInTheDocument()
    await expectNoAxeViolations(container)
  })

  it('shows what failed, as an alert, with a Retry that works', async () => {
    const onRetry = vi.fn()
    const { container } = table({ rows: [], error: 'The backend did not answer.', onRetry })
    const alert = screen.getByRole('alert')
    expect(alert).toHaveTextContent('Could not load clients')
    expect(alert).toHaveTextContent('The backend did not answer.')
    fireEvent.click(within(alert).getByRole('button', { name: 'Retry' }))
    expect(onRetry).toHaveBeenCalledTimes(1)
    expect(screen.queryByText('No clients yet')).not.toBeInTheDocument()
    await expectNoAxeViolations(container)
  })

  it('makes the header sticky inside a bounded scroll box when asked', () => {
    table({ stickyHeader: true, maxHeight: '320px' })
    const scrollBox = screen.getByRole('table', { name: 'Clients' }).parentElement as HTMLElement
    expect(scrollBox).toHaveStyle({ maxHeight: '320px' })
    for (const th of screen.getAllByRole('columnheader')) expect(th.className).toMatch(/sticky top-0/)
  })

  it('draws the selected row in the accent tint, and only that row', () => {
    table({ isRowSelected: (c) => c.ip === '172.18.0.4' })
    const selected = screen.getByText('172.18.0.4').closest('tr') as HTMLElement
    const other = screen.getByText('192.168.1.109').closest('tr') as HTMLElement
    expect(selected).toHaveAttribute('data-selected', 'true')
    expect(selected.className).toMatch(/bg-accent-subtle/)
    expect(other).not.toHaveAttribute('data-selected')
    expect(other.className).not.toMatch(/bg-accent-subtle/)
  })

  it('aligns number columns right in tabular figures', () => {
    table()
    const cell = screen.getByText('1,180').closest('td')
    expect(cell?.className).toMatch(/text-right/)
    expect(cell?.className).toMatch(/tabular-nums/)
  })
})
