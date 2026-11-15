import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { screen, fireEvent, waitFor, within } from '@testing-library/react'
import { renderWithProviders } from '../../test/helpers'
import { expectNoAxeViolations } from '../../test/axe'
import { api } from '../../lib/api'
import { SignInLimits } from './SignInLimits'

// GET /api/security/rate-limits as handlers/security.go answers it: blocked
// first, then by address (auth.RateLimitSnapshot).
const now = Math.floor(Date.now() / 1000)
let rows = [
  { ip: '192.0.2.7', attempts: 5, blocked: true, last_attempt: now - 60, until: now + 600 },
  { ip: '2001:db8::1', attempts: 2, blocked: false, last_attempt: now - 120 },
]

describe('SignInLimits', () => {
  beforeEach(() => {
    vi.spyOn(api, 'get').mockImplementation(() =>
      Promise.resolve({ data: { status: 'success', data: rows, meta: { max_attempts: 5, window_seconds: 900 } } }))
    vi.spyOn(api, 'delete').mockResolvedValue({ data: { status: 'success' } })
  })
  afterEach(() => { vi.restoreAllMocks() })

  it('states the rule from the backend and lists the addresses, the refused one with when it may sign in again', async () => {
    const { container } = renderWithProviders(<SignInLimits />)
    expect(await screen.findByText(/fails to sign in 5 times within 15 minutes is refused until the oldest of those attempts is 15 minutes old/)).toBeInTheDocument()
    const list = screen.getByRole('list', { name: 'Addresses with failed sign-ins, refused first' })
    const items = within(list).getAllByRole('listitem')
    expect(items.map((li) => li.querySelector('.font-mono')?.textContent)).toEqual(['192.0.2.7', '2001:db8::1'])
    expect(within(items[0]).getByText(/^Refused until \d\d:\d\d$/)).toBeInTheDocument()
    expect(within(items[0]).getByText(/5 of 5 failed, the last at/)).toBeInTheDocument()
    expect(within(items[1]).queryByText(/Refused/)).toBeNull()
    await expectNoAxeViolations(container)
  })

  it('lets an address sign in again, with the address encoded in the path, and says so', async () => {
    renderWithProviders(<SignInLimits />)
    const list = await screen.findByRole('list', { name: 'Addresses with failed sign-ins, refused first' })
    fireEvent.click(within(within(list).getAllByRole('listitem')[1]).getByRole('button', { name: 'Let it sign in again' }))
    await waitFor(() => expect(api.delete).toHaveBeenCalledWith('security/rate-limits/2001%3Adb8%3A%3A1'))
    expect(await screen.findByText('2001:db8::1 can sign in again.')).toBeInTheDocument()
  })

  it('says when no address failed within the window', async () => {
    const saved = rows
    rows = []
    renderWithProviders(<SignInLimits />)
    expect(await screen.findByText('No address has failed to sign in within the last 15 minutes.')).toBeInTheDocument()
    rows = saved
  })

  it('says a failed clear and the reason', async () => {
    vi.mocked(api.delete).mockRejectedValueOnce({ isAxiosError: true, response: { status: 404, data: { detail: 'no active rate limit for IP 192.0.2.7' } } })
    renderWithProviders(<SignInLimits />)
    const list = await screen.findByRole('list', { name: 'Addresses with failed sign-ins, refused first' })
    fireEvent.click(within(within(list).getAllByRole('listitem')[0]).getByRole('button', { name: 'Let it sign in again' }))
    expect(await screen.findByText(/^192\.0\.2\.7 is still limited: /)).toBeInTheDocument()
  })
})
