import { describe, it, expect, vi, beforeEach } from 'vitest'
import { screen, fireEvent, waitFor, within } from '@testing-library/react'
import { AxiosError } from 'axios'
import { renderWithProviders } from '../../test/helpers'
import { expectNoAxeViolations } from '../../test/axe'
import { ClientGroups } from './ClientGroups'
import type { ClientGroup, ListSource } from '../../types'

vi.mock('../../lib/api', () => {
  const api = { get: vi.fn(), post: vi.fn(), put: vi.fn(), delete: vi.fn(), interceptors: { request: { use: vi.fn() }, response: { use: vi.fn() } } }
  const getData = (path: string) => api.get(path).then((r: { data?: { data?: unknown } }) => r?.data?.data)
  const getErrorMessage = (err: unknown, fallback: string) =>
    (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail ?? fallback
  return { api, getData, getErrorMessage }
})

import { api } from '../../lib/api'

const games: ListSource = { id: 7, kind: 'url', source: 'https://lists.example/games.txt', label: 'Games', entries: 120, first_added: '2026-11-05 10:00:00', last_added: '2026-11-05 10:00:00', scope: 'groups' }
const ads: ListSource = { id: 3, kind: 'url', source: 'https://lists.example/ads.txt', label: 'Ads', entries: 900, first_added: '2026-11-01 10:00:00', last_added: '2026-11-01 10:00:00', scope: 'global' }
const kids: ClientGroup = {
  id: 4, name: 'kids', description: "the children's tablets", members: ['192.168.1.20/32', '192.168.1.21/32', '192.168.50.0/24'],
  lists: [7], schedule: { days: 'MTWHF', start: '07:00', end: '21:00' }, allowlist_only: true,
}

function serve(groups: ClientGroup[], domainSources: ListSource[] = [games, ads]) {
  vi.mocked(api.get).mockImplementation((url: string) => Promise.resolve({
    data: { data: url === 'client-groups' ? groups : url === 'domain-blacklist/sources' ? domainSources : [] },
  }) as never)
}

describe('ClientGroups', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('says how to get a list for groups only when there is none, and passes axe', async () => {
    serve([], [ads])
    const { container } = renderWithProviders(<ClientGroups />)
    expect(await screen.findByText('No client groups')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'New group' }))
    const form = screen.getByRole('form', { name: 'New client group' })
    expect(within(form).getByText(/No list applies to groups only yet/)).toBeInTheDocument()
    expect(within(form).getByRole('link', { name: 'Blacklists' })).toHaveAttribute('href', '/blacklists')
    await expectNoAxeViolations(container)
  })

  it('creates a group with the body the backend validates', async () => {
    serve([])
    vi.mocked(api.post).mockResolvedValueOnce({ data: { status: 'success', data: kids } } as never)
    renderWithProviders(<ClientGroups />)
    fireEvent.click(await screen.findByRole('button', { name: 'New group' }))
    const form = screen.getByRole('form', { name: 'New client group' })
    fireEvent.change(within(form).getByLabelText('Name'), { target: { value: ' kids ' } })
    fireEvent.change(within(form).getByLabelText('Members'), { target: { value: '192.168.1.20\n192.168.50.0/24, 192.168.1.21\n' } })
    // Only the source set to groups only is offered.
    expect(within(form).queryByText('Ads')).toBeNull()
    fireEvent.click(await within(form).findByRole('checkbox', { name: /Games/ }))
    fireEvent.click(within(form).getByRole('switch', { name: 'Only during set hours' }))
    fireEvent.click(within(form).getByRole('checkbox', { name: 'Friday' }))
    fireEvent.click(within(form).getByRole('checkbox', { name: 'Saturday' }))
    fireEvent.click(within(form).getByRole('switch', { name: 'Only the destinations on the allowlist' }))
    fireEvent.click(within(form).getByRole('button', { name: 'Create group' }))
    await waitFor(() => expect(api.post).toHaveBeenCalledWith('client-groups', {
      name: 'kids', description: '', members: ['192.168.1.20', '192.168.50.0/24', '192.168.1.21'], lists: [7],
      schedule: { days: 'MTWHA', start: '07:00', end: '21:00' }, allowlist_only: true,
    }))
    await waitFor(() => expect(screen.queryByRole('form')).toBeNull())
  })

  it('refuses a name and a window the backend would refuse, before sending', async () => {
    serve([])
    renderWithProviders(<ClientGroups />)
    fireEvent.click(await screen.findByRole('button', { name: 'New group' }))
    const form = screen.getByRole('form', { name: 'New client group' })
    fireEvent.change(within(form).getByLabelText('Name'), { target: { value: '-bad' } })
    expect(within(form).getByText(/starting with a letter or digit/)).toBeInTheDocument()
    expect(within(form).getByRole('button', { name: 'Create group' })).toBeDisabled()
    fireEvent.change(within(form).getByLabelText('Name'), { target: { value: 'night' } })
    fireEvent.click(within(form).getByRole('switch', { name: 'Only during set hours' }))
    fireEvent.change(within(form).getByLabelText('From'), { target: { value: '21:00' } })
    fireEvent.change(within(form).getByLabelText('to'), { target: { value: '07:00' } })
    expect(within(form).getByText(/21:00 to 07:00 is not one window/)).toBeInTheDocument()
    expect(within(form).getByRole('button', { name: 'Create group' })).toBeDisabled()
  })

  it('shows the backend refusal', async () => {
    serve([])
    vi.mocked(api.post).mockRejectedValueOnce(new AxiosError('bad', 'ERR_BAD_REQUEST', undefined, undefined,
      { status: 400, data: { detail: '"10.0.0.300" is not an IP address or network' } } as never))
    renderWithProviders(<ClientGroups />)
    fireEvent.click(await screen.findByRole('button', { name: 'New group' }))
    const form = screen.getByRole('form', { name: 'New client group' })
    fireEvent.change(within(form).getByLabelText('Name'), { target: { value: 'kids' } })
    fireEvent.change(within(form).getByLabelText('Members'), { target: { value: '10.0.0.300' } })
    fireEvent.click(within(form).getByRole('button', { name: 'Create group' }))
    expect(await within(form).findByRole('alert')).toHaveTextContent('Not saved: "10.0.0.300" is not an IP address or network.')
  })

  it.each([
    ['MWF', 'Mon, Wed, Fri, 07:00 to 21:00'],
    ['SMTWHFA', 'Every day, 07:00 to 21:00'],
    ['FAS', 'Fri to Sun, 07:00 to 21:00'],
    ['MTHF', 'Mon, Tue, Thu, Fri, 07:00 to 21:00'],
  ])('writes the days %s as "%s"', async (days, text) => {
    serve([{ ...kids, schedule: { days, start: '07:00', end: '21:00' } }])
    renderWithProviders(<ClientGroups />)
    expect(await screen.findByText(text)).toBeInTheDocument()
  })

  it('lists a group with what restricts it, edits it in place and deletes it after a confirmation', async () => {
    serve([kids])
    vi.mocked(api.put).mockResolvedValueOnce({ data: { status: 'success', data: kids } } as never)
    vi.mocked(api.delete).mockResolvedValueOnce({ data: { status: 'success' } } as never)
    renderWithProviders(<ClientGroups />)
    const row = (await screen.findByText('kids')).closest('tr')!
    expect(within(row).getByText('192.168.1.20/32, 192.168.1.21/32 and 1 more')).toBeInTheDocument()
    expect(await within(row).findByText('Games')).toBeInTheDocument()
    expect(within(row).getByText('Mon to Fri, 07:00 to 21:00')).toBeInTheDocument()
    expect(within(row).getByText('Allowlist only')).toBeInTheDocument()

    fireEvent.click(within(row).getByRole('button', { name: 'Edit kids' }))
    const form = screen.getByRole('form', { name: 'Edit kids' })
    expect(within(form).getByLabelText('Members')).toHaveValue('192.168.1.20/32\n192.168.1.21/32\n192.168.50.0/24')
    fireEvent.click(within(form).getByRole('button', { name: 'Save group' }))
    await waitFor(() => expect(api.put).toHaveBeenCalledWith('client-groups/4', expect.objectContaining({ name: 'kids', lists: [7], allowlist_only: true })))

    fireEvent.click(await screen.findByRole('button', { name: 'Delete kids' }))
    const dialog = await screen.findByRole('alertdialog')
    expect(within(dialog).getByText('Delete the group "kids"?')).toBeInTheDocument()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Delete group' }))
    await waitFor(() => expect(api.delete).toHaveBeenCalledWith('client-groups/4'))
  })
})
