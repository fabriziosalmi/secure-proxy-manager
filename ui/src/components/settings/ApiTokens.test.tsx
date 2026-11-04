import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderWithProviders } from '../../test/helpers'
import { expectNoAxeViolations } from '../../test/axe'
import { api } from '../../lib/api'
import { ApiTokens, type ApiToken } from './ApiTokens'

const day = 24 * 3600 * 1000
const iso = (ms: number) => new Date(ms).toISOString()

// The rows GET /api/tokens answers (database.APIToken).
const tokens: ApiToken[] = [
  { id: 'aaaaaaaaaaaa', name: 'grafana', scope: 'read', created_by: 'admin', created_at: iso(Date.now() - 10 * day), expires_at: iso(Date.now() + 80 * day), last_used_at: iso(Date.now() - day), revoked_at: null },
  { id: 'bbbbbbbbbbbb', name: 'old-ci', scope: 'write', created_by: 'admin', created_at: iso(Date.now() - 100 * day), expires_at: iso(Date.now() - 10 * day), last_used_at: null, revoked_at: null },
  { id: 'cccccccccccc', name: 'laptop', scope: 'write', created_by: 'admin', created_at: iso(Date.now() - 50 * day), expires_at: null, last_used_at: null, revoked_at: iso(Date.now() - 5 * day) },
]

describe('ApiTokens', () => {
  beforeEach(() => {
    vi.spyOn(api, 'get').mockResolvedValue({ data: { status: 'success', data: tokens } })
  })
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it.each(['light', 'dark'] as const)('lists each token with its state and passes axe in %s theme', async (theme) => {
    document.documentElement.classList.toggle('dark', theme === 'dark')
    try {
      const { container } = renderWithProviders(<ApiTokens />)
      const table = await screen.findByRole('table', { name: 'API tokens' })
      await within(table).findByText('grafana')
      const row = (name: string) => within(table).getByText(name).closest('tr') as HTMLElement
      expect(within(row('grafana')).getByText('Active')).toBeInTheDocument()
      expect(within(row('old-ci')).getByText('Expired')).toBeInTheDocument()
      expect(within(row('laptop')).getByText(/^Revoked /)).toBeInTheDocument()
      // A revoked token has nothing left to revoke.
      expect(within(row('laptop')).queryByRole('button', { name: /revoke/i })).not.toBeInTheDocument()
      expect(within(row('grafana')).getByRole('button', { name: 'Revoke grafana' })).toBeInTheDocument()
      // No expiry and never used.
      expect(within(row('laptop')).getAllByText('Never')).toHaveLength(2)
      expect(within(row('grafana')).queryByText('Never')).not.toBeInTheDocument()
      await expectNoAxeViolations(container)
    } finally {
      document.documentElement.classList.remove('dark')
    }
  })

  it('creates a token with 90 days by default and shows its value once', async () => {
    const user = userEvent.setup()
    const post = vi.spyOn(api, 'post').mockResolvedValue({
      data: { status: 'success', data: { token: 'spm_dddddddddddd_secretvalue', id: 'dddddddddddd', name: 'backup' } },
    })
    renderWithProviders(<ApiTokens />)
    await user.type(screen.getByLabelText('Name'), '  backup ')
    await user.click(screen.getByRole('button', { name: 'Create token' }))

    expect(post).toHaveBeenCalledWith('tokens', { name: 'backup', scope: 'read', expires_in_days: 90 })
    expect(await screen.findByLabelText('New token')).toHaveTextContent('spm_dddddddddddd_secretvalue')
    expect(screen.getByText(/it is not shown again/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Done' }))
    expect(screen.queryByLabelText('New token')).not.toBeInTheDocument()
  })

  it('asks for no expiry only when Never is chosen, and a write scope when Write is', async () => {
    const user = userEvent.setup()
    const post = vi.spyOn(api, 'post').mockResolvedValue({ data: { status: 'success', data: { token: 'spm_x_y', name: 'mcp' } } })
    renderWithProviders(<ApiTokens />)
    await user.type(screen.getByLabelText('Name'), 'mcp')
    await user.click(screen.getByRole('button', { name: 'Write' }))
    await user.click(screen.getByRole('button', { name: 'Never' }))
    expect(screen.getByText(/works until it is revoked/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Create token' }))
    expect(post).toHaveBeenCalledWith('tokens', { name: 'mcp', scope: 'write', no_expiry: true })
  })

  it('refuses a name the backend would refuse, before sending it', async () => {
    const user = userEvent.setup()
    const post = vi.spyOn(api, 'post')
    renderWithProviders(<ApiTokens />)
    await user.type(screen.getByLabelText('Name'), 'x<script>')
    expect(screen.getByLabelText('Name')).toHaveAttribute('aria-invalid', 'true')
    expect(screen.getByRole('button', { name: 'Create token' })).toBeDisabled()
    expect(post).not.toHaveBeenCalled()
  })

  it('revokes a token after confirmation', async () => {
    const user = userEvent.setup()
    const del = vi.spyOn(api, 'delete').mockResolvedValue({ data: { status: 'success' } })
    renderWithProviders(<ApiTokens />)
    await user.click(await screen.findByRole('button', { name: 'Revoke grafana' }))
    const dialog = await screen.findByRole('alertdialog')
    await user.click(within(dialog).getByRole('button', { name: 'Revoke' }))
    await waitFor(() => expect(del).toHaveBeenCalledWith('tokens/aaaaaaaaaaaa'))
  })
})
