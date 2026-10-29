import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { screen, fireEvent, waitFor, within } from '@testing-library/react'
import { QueryClient } from '@tanstack/react-query'
import { renderWithProviders } from '../../test/helpers'
import { expectNoAxeViolations } from '../../test/axe'
import { AxiosError, AxiosHeaders } from 'axios'
import { api } from '../../lib/api'
import { Maintenance } from './Maintenance'

// The body GET /api/maintenance/backup-config returns (BackupConfig in
// backend-go/internal/handlers/maintenance.go).
const envelope = {
  backup_version: 2,
  app_version: '3.14.3',
  exported_at: '2026-10-20T12:00:00Z',
  settings: { log_retention_days: '14', enable_safesearch: 'true', default_password_changed: 'true' },
  lists: {
    ip_blacklist: [{ value: '203.0.113.9', description: 'bad host' }],
    ip_whitelist: [],
    domain_blacklist: [],
    domain_whitelist: [],
    dst_allowlist: [],
  },
}

// What RestoreConfig answers for that file.
const restoreAnswer = {
  status: 'success',
  restored_settings: 2,
  restored_entries: 1,
  skipped_settings: [{ key: 'default_password_changed', reason: 'managed by the application, not restored from a file' }],
  skipped_entries: 0,
  failed_files: [],
  restored: 3,
  skipped: 1,
}

let downloaded: Blob[] = []

function chooseFile(text: string, name = 'proxy-backup-2026-10-20.json') {
  const input = screen.getByLabelText('Backup file to restore') as HTMLInputElement
  const file = new File([text], name, { type: 'application/json' })
  fireEvent.change(input, { target: { files: [file] } })
}

describe('Maintenance', () => {
  beforeEach(() => {
    downloaded = []
    Object.defineProperty(window.URL, 'createObjectURL', {
      configurable: true,
      value: (b: Blob) => { downloaded.push(b); return 'blob:test' },
    })
    Object.defineProperty(window.URL, 'revokeObjectURL', { configurable: true, value: () => {} })
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    vi.spyOn(api, 'get').mockImplementation((url: string) => {
      if (url === 'maintenance/backup-config') return Promise.resolve({ data: { status: 'success', data: envelope } })
      return Promise.resolve({ data: { status: 'success', data: {} } })
    })
    vi.spyOn(api, 'post').mockImplementation((url: string) => {
      if (url === 'maintenance/restore-config') return Promise.resolve({ data: restoreAnswer })
      if (url === 'maintenance/reload-config') return Promise.resolve({ data: { status: 'success', message: 'Proxy reloaded' } })
      return Promise.resolve({ data: { status: 'success' } })
    })
  })
  afterEach(() => { vi.restoreAllMocks() })

  it('backs up through the restorable endpoint, and restores the same file back', async () => {
    const { container } = renderWithProviders(<Maintenance />)
    fireEvent.click(screen.getByRole('button', { name: 'Download a backup' }))
    await waitFor(() => expect(downloaded).toHaveLength(1))
    expect(api.get).toHaveBeenCalledWith('maintenance/backup-config')
    expect(api.get).not.toHaveBeenCalledWith('database/export', expect.anything())
    const file = await downloaded[0].text()
    expect(JSON.parse(file)).toEqual(envelope)

    chooseFile(file)
    const dialog = await screen.findByRole('alertdialog', { name: 'Restore proxy-backup-2026-10-20.json?' })
    expect(within(dialog).getByText('The 3 settings in the file replace the current values.')).toBeInTheDocument()
    expect(within(dialog).getByText('IP blacklist: 1')).toBeInTheDocument()
    expect(within(dialog).getByText('Nothing is removed: settings and entries that are not in the file stay as they are.')).toBeInTheDocument()
    expect(within(dialog).getByText(/by version 3\.14\.3\./)).toBeInTheDocument()
    await expectNoAxeViolations(dialog)
    fireEvent.click(within(dialog).getByRole('button', { name: 'Restore' }))

    expect(await screen.findByText('Restored 2 settings and 1 list entries.')).toBeInTheDocument()
    expect(api.post).toHaveBeenCalledWith('maintenance/restore-config', envelope)
    expect(api.post).toHaveBeenCalledWith('maintenance/reload-config', {})
    expect(screen.getByText('default_password_changed')).toBeInTheDocument()
    expect(screen.getByText(/managed by the application, not restored from a file/)).toBeInTheDocument()
    expect(screen.getByText(/^Applied to the proxy at \d\d:\d\d\.$/)).toBeInTheDocument()
    await expectNoAxeViolations(container)
  })

  it('says when the proxy did not take the restored configuration', async () => {
    vi.mocked(api.post).mockImplementation((url: string) => {
      if (url === 'maintenance/restore-config') return Promise.resolve({ data: restoreAnswer })
      if (url === 'maintenance/reload-config') return Promise.resolve({ data: { status: 'pending' } })
      return Promise.resolve({ data: {} })
    })
    renderWithProviders(<Maintenance />)
    chooseFile(JSON.stringify(envelope))
    fireEvent.click(await screen.findByRole('button', { name: 'Restore' }))
    expect(await screen.findByText('Restored. The proxy did not confirm within 8 seconds: check that the proxy container is running.')).toBeInTheDocument()
  })

  it('restores nothing when the dialog is cancelled', async () => {
    renderWithProviders(<Maintenance />)
    chooseFile(JSON.stringify(envelope))
    fireEvent.click(await screen.findByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument())
    expect(api.post).not.toHaveBeenCalledWith('maintenance/restore-config', expect.anything())
  })

  it('says what emptying the cache does before it runs, and what the proxy did after', async () => {
    vi.mocked(api.post).mockImplementation((url: string) => {
      if (url === 'maintenance/clear-cache') return Promise.resolve({ data: { status: 'success', data: { objects_removed: 1234 } } })
      return Promise.resolve({ data: {} })
    })
    renderWithProviders(<Maintenance />)
    fireEvent.click(screen.getByRole('button', { name: 'Empty disk and memory cache' }))
    const dialog = await screen.findByRole('alertdialog', { name: 'Empty the proxy cache?' })
    expect(dialog).toHaveTextContent('Stops the proxy, deletes every object in its disk cache and starts it again, which also empties its memory cache.')
    expect(dialog).toHaveTextContent('Requests in progress are cut off, and new ones are refused until it is back')
    expect(dialog).not.toHaveTextContent('objects cached on disk stay')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Empty the cache' }))
    expect(await screen.findByText(/^Emptied at \d\d:\d\d: 1,234 objects removed from disk, and the proxy is running again\.$/)).toBeInTheDocument()
    expect(api.post).toHaveBeenCalledWith('maintenance/clear-cache')
  })

  it('does not call a clear the proxy did not confirm, or refused, a success', async () => {
    const refused = new AxiosError('500', 'ERR_BAD_RESPONSE', undefined, undefined, {
      status: 500, statusText: 'Internal Server Error', headers: {}, config: { headers: new AxiosHeaders() },
      data: { status: 'error', code: 'clear_cache_failed', detail: 'refused, nothing was removed: cache_dir /etc resolves to /etc, outside /var/spool/squid' },
    })
    vi.mocked(api.post).mockImplementationOnce(() => Promise.resolve({ data: { status: 'pending' } }))
      .mockImplementationOnce(() => Promise.reject(refused))
    renderWithProviders(<Maintenance />)
    const clear = async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Empty disk and memory cache' }))
      const dialog = await screen.findByRole('alertdialog', { name: 'Empty the proxy cache?' })
      fireEvent.click(within(dialog).getByRole('button', { name: 'Empty the cache' }))
    }
    await clear()
    expect(await screen.findByText('The proxy did not confirm within 45 seconds: check that the proxy container is running.')).toBeInTheDocument()
    await clear()
    expect(await screen.findByText(/^It failed: refused, nothing was removed: cache_dir \/etc resolves to \/etc, outside \/var\/spool\/squid\.?$/)).toBeInTheDocument()
    expect(screen.queryByText(/^Emptied at/)).not.toBeInTheDocument()
  })

  it('refuses a database export, which restore cannot read, without asking', async () => {
    renderWithProviders(<Maintenance />)
    chooseFile(JSON.stringify({ status: 'success', data: { settings: [{ id: 1, setting_name: 'a' }], proxy_logs: [] } }), 'database_export.json')
    expect(await screen.findByText('This is a database export, which cannot be restored. Use a file made by Download a backup.')).toBeInTheDocument()
    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument()
    expect(api.post).not.toHaveBeenCalled()
  })

  it('reports each maintenance action under its own button, from what the backend answered', async () => {
    let size = 2_000_000
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url === 'database/size') { const n = size; size = 1_000_000; return Promise.resolve({ data: { status: 'success', data: { size_bytes: n } } }) }
      return Promise.resolve({ data: { status: 'success', data: {} } })
    })
    vi.mocked(api.post).mockImplementation((url: string) => {
      if (url === 'counters/reset') return Promise.resolve({ data: { status: 'success', data: { logs_cleared: 1234, waf_reset: false } } })
      if (url === 'maintenance/reload-dns') return Promise.resolve({ data: { status: 'success', data: { domains: 42, left_out: 3 } } })
      return Promise.resolve({ data: { status: 'success' } })
    })
    const { container } = renderWithProviders(<Maintenance />)

    fireEvent.click(screen.getByRole('button', { name: 'Send the lists again' }))
    expect(await screen.findByText('42 domain entries went to the DNS sinkhole, 3 left out by Allowed domains. The DNS sinkhole and the proxy reread them within a few seconds; this page cannot confirm it.')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Reset statistics' }))
    const ask = await screen.findByRole('alertdialog', { name: 'Delete every logged request?' })
    fireEvent.click(within(ask).getByRole('button', { name: 'Delete and reset' }))
    expect(await screen.findByText('Deleted 1,234 logged requests. The WAF did not reset its counters: it did not answer, or refused the backend.')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Empty disk and memory cache' }))
    const empty = await screen.findByRole('alertdialog', { name: 'Empty the proxy cache?' })
    fireEvent.click(within(empty).getByRole('button', { name: 'Empty the cache' }))
    expect(await screen.findByText(/^Emptied at \d\d:\d\d: the disk cache was emptied, and the proxy is running again\.$/)).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Optimize' }))
    expect(await screen.findByText(/^Optimized \(VACUUM and REINDEX\)\. Size 1\.9 MB before, 977 KB after\.$/)).toBeInTheDocument()
    await expectNoAxeViolations(container)
  })

  it('does nothing destructive when the confirmation is cancelled', async () => {
    renderWithProviders(<Maintenance />)
    fireEvent.click(screen.getByRole('button', { name: 'Reset statistics' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument())
    expect(api.post).not.toHaveBeenCalledWith('counters/reset')
  })

  it('describes egress providers in Backup help, confirms 8 list entries and 1 egress provider, reports background download, and invalidates queries', async () => {
    const backupWithProvider = {
      backup_version: 2,
      app_version: '3.15.0',
      exported_at: '2026-10-27T12:00:00Z',
      settings: { log_retention_days: '14', enable_safesearch: 'true' },
      lists: {
        ip_blacklist: [
          { value: '203.0.113.1' },
          { value: '203.0.113.2' },
          { value: '203.0.113.3' },
          { value: '203.0.113.4' },
        ],
        domain_blacklist: [
          { value: 'bad1.example.test' },
          { value: 'bad2.example.test' },
          { value: 'bad3.example.test' },
          { value: 'bad4.example.test' },
        ],
      },
      egress_providers: [
        { kind: 'catalog', name: 'telegram', url: '', enabled: true },
      ],
    }
    vi.mocked(api.post).mockImplementation((url: string) => {
      if (url === 'maintenance/restore-config') {
        return Promise.resolve({
          data: {
            status: 'success',
            restored_settings: 2,
            restored_entries: 8,
            restored_egress_providers: 1,
            egress_providers_refreshing: true,
            skipped_settings: [],
            skipped_entries: 0,
            failed_files: [],
            restored: 11,
            skipped: 0,
          },
        })
      }
      if (url === 'maintenance/reload-config') return Promise.resolve({ data: { status: 'success', message: 'Proxy reloaded' } })
      return Promise.resolve({ data: { status: 'success' } })
    })

    const invalidateSpy = vi.spyOn(QueryClient.prototype, 'invalidateQueries')
    renderWithProviders(<Maintenance />)

    expect(screen.getByText(/enabled egress providers and custom URLs.*not their downloaded entries/i)).toBeInTheDocument()

    chooseFile(JSON.stringify(backupWithProvider), 'proxy-backup-2026-10-27.json')
    const dialog = await screen.findByRole('alertdialog', { name: 'Restore proxy-backup-2026-10-27.json?' })
    expect(within(dialog).getByText(/8 list entries and 1 egress provider/)).toBeInTheDocument()

    fireEvent.click(within(dialog).getByRole('button', { name: 'Restore' }))
    expect(await screen.findByText('Restored 2 settings, 8 list entries, and 1 egress provider.')).toBeInTheDocument()
    expect(screen.getByText(/downloading in the background/i)).toBeInTheDocument()
    expect(invalidateSpy).toHaveBeenCalled()
  })
})
