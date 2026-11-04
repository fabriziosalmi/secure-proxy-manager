import { describe, it, expect, vi, beforeEach } from 'vitest'
import { screen, fireEvent, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import toast from 'react-hot-toast'
import { renderWithProviders } from '../test/helpers'
import { expectNoAxeViolations } from '../test/axe'
import { ClientSetup } from './ClientSetup'

vi.mock('../lib/api', () => {
  const api = {
    get: vi.fn().mockResolvedValue({ data: { data: [] } }),
    post: vi.fn(),
    interceptors: { request: { use: vi.fn() }, response: { use: vi.fn() } },
  }
  // The status query reads through getData, as the app does.
  const getData = (path: string) => api.get(path).then((r: { data?: { data?: unknown } }) => r?.data?.data)
  return { api, getData }
})

import { api } from '../lib/api'

describe('ClientSetup', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    toast.remove()
  })

  it.each(['light', 'dark'] as const)('renders OS tabs without duplicate Connect Your Devices heading, switches panels with keyboard and mouse, and passes axe in %s theme', async (theme) => {
    document.documentElement.classList.toggle('dark', theme === 'dark')
    try {
      const { container } = renderWithProviders(<ClientSetup />)
      expect(screen.queryByRole('heading', { name: /connect your devices/i })).not.toBeInTheDocument()
      await expectNoAxeViolations(container)

      const winTab = screen.getByRole('tab', { name: 'Windows' })
      expect(winTab).toHaveAttribute('aria-selected', 'true')
      fireEvent.keyDown(winTab, { key: 'ArrowRight' })

      const macTab = screen.getByRole('tab', { name: 'macOS' })
      expect(macTab).toHaveAttribute('aria-selected', 'true')
      await expectNoAxeViolations(container)

      fireEvent.click(screen.getByRole('tab', { name: 'iOS' }))
      expect(screen.getByRole('tab', { name: 'iOS' })).toHaveAttribute('aria-selected', 'true')
      await expectNoAxeViolations(container)
    } finally {
      document.documentElement.classList.remove('dark')
    }
  })

  it('does not show Copied when clipboard writeText rejects, and shows an error toast instead', async () => {
    const user = userEvent.setup()
    const successSpy = vi.spyOn(toast, 'success')
    const errorSpy = vi.spyOn(toast, 'error')
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText: vi.fn().mockRejectedValueOnce(new Error('NotAllowedError')) },
    })

    renderWithProviders(<ClientSetup />)
    await user.click(screen.getByRole('button', { name: 'Copy proxy' }))

    await waitFor(() => {
      expect(errorSpy).toHaveBeenCalled()
    })
    expect(successSpy).not.toHaveBeenCalled()
    successSpy.mockRestore()
    errorSpy.mockRestore()
  })

  it('gives a Linux server the environment, apt, Docker and systemd settings, each with its own copy button', async () => {
    const user = userEvent.setup()
    renderWithProviders(<ClientSetup />)
    await user.click(screen.getByRole('tab', { name: 'Linux server' }))
    const panel = screen.getByRole('tabpanel')

    for (const file of ['/etc/environment', '/etc/apt/apt.conf.d/95proxy', '/etc/systemd/system/docker.service.d/http-proxy.conf', 'sudo systemctl edit <service>']) {
      expect(within(panel).getByText(file)).toBeInTheDocument()
    }
    const env = within(panel).getByText(/^http_proxy=http:\/\//)
    // /etc/environment takes NAME=value lines: no export, and both cases.
    expect(env.textContent).not.toMatch(/export/)
    expect(env.textContent).toMatch(/^HTTPS_PROXY=http:\/\/[^\n]+:3128$/m)
    expect(within(panel).getByText(/^Acquire::http::Proxy "http:\/\/[^"]+:3128";/)).toBeInTheDocument()
    expect(within(panel).getAllByRole('button', { name: /^Copy .* configuration$/ })).toHaveLength(4)
    expect(within(panel).queryByText(/USER:PASSWORD/)).not.toBeInTheDocument()
  })

  it('tells a Linux server to put the proxy login in the URL when it is on', async () => {
    const user = userEvent.setup()
    vi.mocked(api.get).mockImplementation((url: string) => Promise.resolve({
      data: { data: url === 'settings' ? [{ setting_name: 'enable_proxy_auth', setting_value: 'true' }] : {} },
    }) as never)
    renderWithProviders(<ClientSetup />)
    await user.click(screen.getByRole('tab', { name: 'Linux server' }))
    expect(await screen.findByText(/http:\/\/USER:PASSWORD@/)).toBeInTheDocument()
  })

  it('does not offer export lines for /etc/environment on the Linux tab', async () => {
    const user = userEvent.setup()
    renderWithProviders(<ClientSetup />)
    await user.click(screen.getByRole('tab', { name: 'Linux' }))
    expect(screen.getByRole('tabpanel')).not.toHaveTextContent('/etc/environment')
    expect(screen.getByText(/^export http_proxy=/)).toBeInTheDocument()
  })

  it('shows Authentication: Username and password on iOS when enable_proxy_auth is true', async () => {
    const user = userEvent.setup()
    vi.mocked(api.get).mockImplementation((url: string) => Promise.resolve({
      data: { data: url === 'settings' ? [{ setting_name: 'enable_proxy_auth', setting_value: 'true' }] : {} },
    }) as never)

    renderWithProviders(<ClientSetup />)
    await user.click(screen.getByRole('tab', { name: 'iOS' }))

    expect(await screen.findByText(/Authentication: Username and password/i)).toBeInTheDocument()
    expect(screen.queryByText(/Authentication: Off/i)).not.toBeInTheDocument()
  })

  // The page runs on localhost here: with no PROXY_IP the address shown is
  // localhost, which no other device can reach, and the page says so; with
  // PROXY_IP the address and the PAC URL are the server's.
  it('warns on localhost and shows the PAC URL', async () => {
    renderWithProviders(<ClientSetup />)
    expect(await screen.findByText('Other devices cannot reach this address')).toBeInTheDocument()
    expect(screen.getByText('http://localhost/wpad.dat')).toBeInTheDocument()
  })

  it('uses PROXY_IP from the status for the address and the PAC URL', async () => {
    vi.mocked(api.get).mockImplementation((url: string) =>
      Promise.resolve({ data: { data: url === 'status' ? { proxy_ip: '192.0.2.10' } : [] } }) as never)
    renderWithProviders(<ClientSetup />)
    expect(await screen.findByText('192.0.2.10:3128')).toBeInTheDocument()
    expect(screen.getByText('http://192.0.2.10/wpad.dat')).toBeInTheDocument()
    expect(screen.queryByText('Other devices cannot reach this address')).toBeNull()
  })
})
