import { describe, it, expect, vi, afterEach } from 'vitest'
import { parseUtc, relative, proxyAddress, isLoopbackHost } from './utils'

describe('parseUtc', () => {
  it('reads a zone-less SQLite timestamp as UTC', () => {
    expect(parseUtc('2026-06-04 14:30:00').toISOString()).toBe('2026-06-04T14:30:00.000Z')
  })
  it('leaves an ISO string that already has a zone alone', () => {
    expect(parseUtc('2026-06-04T14:30:00+02:00').toISOString()).toBe('2026-06-04T12:30:00.000Z')
  })
})

describe('relative', () => {
  afterEach(() => vi.useRealTimers())
  const at = (now: string, ts: string) => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date(now))
    return relative(ts)
  }
  it('picks the unit', () => {
    const now = '2026-06-04T15:00:00Z'
    expect(at(now, '2026-06-04 14:59:30')).toBe('30s ago')
    expect(at(now, '2026-06-04 14:55:00')).toBe('5m ago')
    expect(at(now, '2026-06-04 12:00:00')).toBe('3h ago')
    expect(at(now, '2026-06-02 15:00:00')).toBe('2d ago')
  })
  it('never goes negative for a timestamp slightly in the future', () => {
    expect(at('2026-06-04T15:00:00Z', '2026-06-04 15:00:05')).toBe('0s ago')
  })
  it('shows a dash for empty and echoes what it cannot parse', () => {
    expect(relative('')).toBe('not recorded')
    expect(relative('not a date')).toBe('not a date')
  })
})

// The address a device configures: the server's LAN address (PROXY_IP) when
// the server names one, else the host the UI was opened on.
describe('proxy address', () => {
  it('prefers the server address and brackets IPv6', () => {
    expect(proxyAddress('192.0.2.10')).toBe('192.0.2.10:3128')
    expect(proxyAddress(' 192.0.2.10 ')).toBe('192.0.2.10:3128')
    expect(proxyAddress('2001:db8::10')).toBe('[2001:db8::10]:3128')
    expect(proxyAddress('')).toBe(`${window.location.hostname}:3128`)
    expect(proxyAddress(undefined)).toBe(`${window.location.hostname}:3128`)
  })

  it('knows the hosts no other device can reach', () => {
    for (const h of ['localhost', 'app.localhost', '127.0.0.1', '127.1.2.3', '::1', '[::1]', '0.0.0.0', 'LOCALHOST']) {
      expect(isLoopbackHost(h), h).toBe(true)
    }
    for (const h of ['192.168.0.157', 'proxy.lan', '10.0.0.1', '2001:db8::1', 'localhost.example']) {
      expect(isLoopbackHost(h), h).toBe(false)
    }
  })
})
