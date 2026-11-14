import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { screen, fireEvent, waitFor, within } from '@testing-library/react'
import { renderWithProviders } from '../../test/helpers'
import { expectNoAxeViolations } from '../../test/axe'
import { api } from '../../lib/api'
import { ConfigHistory } from './ConfigHistory'
import type { SnapshotDiff } from '../../lib/snapshots'

// GET /api/config/snapshots and .../diff as handlers/config_snapshots.go answers.
const snapshots = [
  { id: 7, created_at: 1794682000, username: 'admin', reason: 'before a settings save', sha256: 'b', current: true },
  { id: 6, created_at: 1794681000, username: 'admin', reason: 'taken by hand: known good', sha256: 'a', current: false },
]
const diff: SnapshotDiff = {
  settings: [
    { key: 'log_retention_days', from: '7', to: '30' },
    { key: 'webhook_url', from: null, to: null, secret: true },
  ],
  groups_added: ['Kids'], groups_removed: ['Guests'], groups_changed: [],
  waf_policy: null, egress_allowlist_added: [], egress_allowlist_removed: ['api.example.com'], same: false,
}
let currentDiff: SnapshotDiff = diff

describe('ConfigHistory', () => {
  beforeEach(() => {
    currentDiff = diff
    vi.spyOn(api, 'get').mockImplementation((url: string) => {
      if (url === 'config/snapshots') return Promise.resolve({ data: { status: 'success', data: snapshots } })
      if (url === 'config/snapshots/6/diff') return Promise.resolve({ data: { status: 'success', data: currentDiff } })
      return Promise.resolve({ data: { status: 'success', data: null } })
    })
    vi.spyOn(api, 'post').mockImplementation((url: string) => {
      if (url === 'config/snapshots') return Promise.resolve({ data: { status: 'success', data: { id: 8, created: true } } })
      if (url === 'config/snapshots/6/restore') {
        return Promise.resolve({ data: { status: 'success', data: { restored: 6, undo_snapshot: 8, skipped_groups: [], skipped_settings: [], failed_files: [], waf_policy: null } } })
      }
      if (url === 'maintenance/reload-config') return Promise.resolve({ data: { status: 'success', message: 'Proxy reloaded' } })
      return Promise.resolve({ data: { status: 'success' } })
    })
  })
  afterEach(() => { vi.restoreAllMocks() })

  it('lists the snapshots, newest first, and marks the one in force', async () => {
    const { container } = renderWithProviders(<ConfigHistory />)
    const list = await screen.findByRole('list', { name: 'Snapshots, newest first' })
    const rows = within(list).getAllByRole('listitem')
    expect(rows[0]).toHaveTextContent('#7')
    expect(rows[0]).toHaveTextContent('In force')
    expect(within(rows[0]).getByRole('button', { name: 'Restore' })).toBeDisabled()
    expect(rows[1]).toHaveTextContent('taken by hand: known good, by admin')
    await expectNoAxeViolations(container)
  })

  it('takes a snapshot with a note', async () => {
    renderWithProviders(<ConfigHistory />)
    fireEvent.change(await screen.findByLabelText('Note for a snapshot taken now'), { target: { value: 'before the office move' } })
    fireEvent.click(screen.getByRole('button', { name: 'Take a snapshot now' }))
    expect(await screen.findByText('Snapshot taken.')).toBeInTheDocument()
    expect(api.post).toHaveBeenCalledWith('config/snapshots', { note: 'before the office move' })
  })

  it('says what restoring would change, naming a secret without its value', async () => {
    renderWithProviders(<ConfigHistory />)
    const rows = within(await screen.findByRole('list', { name: 'Snapshots, newest first' })).getAllByRole('listitem')
    fireEvent.click(within(rows[1]).getByRole('button', { name: 'Compare with now' }))
    expect(await within(rows[1]).findByText('log_retention_days: 7 becomes 30')).toBeInTheDocument()
    expect(within(rows[1]).getByText('webhook_url: the secret changes')).toBeInTheDocument()
    expect(within(rows[1]).getByText('Client groups that come back: Kids')).toBeInTheDocument()
    expect(within(rows[1]).getByText('Client groups that go: Guests')).toBeInTheDocument()
    expect(within(rows[1]).getByText('Default-deny allowlist entries that go: api.example.com')).toBeInTheDocument()
  })

  it('restores after a confirmation that lists the changes, and says how to undo it', async () => {
    renderWithProviders(<ConfigHistory />)
    const rows = within(await screen.findByRole('list', { name: 'Snapshots, newest first' })).getAllByRole('listitem')
    fireEvent.click(within(rows[1]).getByRole('button', { name: 'Restore' }))
    const dialog = await screen.findByRole('alertdialog')
    expect(within(dialog).getByText('log_retention_days: 7 becomes 30')).toBeInTheDocument()
    expect(within(dialog).getByText(/A snapshot of the configuration in force is taken first/)).toBeInTheDocument()
    await expectNoAxeViolations(dialog)
    fireEvent.click(within(dialog).getByRole('button', { name: 'Restore' }))
    expect(await screen.findByText(/^Restored\. To undo, restore snapshot 8, taken just before\./)).toBeInTheDocument()
    expect(api.post).toHaveBeenCalledWith('config/snapshots/6/restore', {})
    await waitFor(() => expect(api.post).toHaveBeenCalledWith('maintenance/reload-config', {}))
  })

  it('does not ask to restore a snapshot that is the configuration in force', async () => {
    currentDiff = { ...diff, settings: [], groups_added: [], groups_removed: [], egress_allowlist_removed: [], same: true }
    renderWithProviders(<ConfigHistory />)
    const rows = within(await screen.findByRole('list', { name: 'Snapshots, newest first' })).getAllByRole('listitem')
    fireEvent.click(within(rows[1]).getByRole('button', { name: 'Restore' }))
    expect(await screen.findByText('This snapshot is the configuration in force: there is nothing to restore.')).toBeInTheDocument()
    expect(screen.queryByRole('alertdialog')).toBeNull()
    expect(api.post).not.toHaveBeenCalledWith('config/snapshots/6/restore', expect.anything())
  })
})
