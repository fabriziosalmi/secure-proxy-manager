import { describe, it, expect } from 'vitest'
import { LISTS, entryKind } from './lists'

const ips = LISTS.find((l) => l.key === 'blocked-ips')!
const domains = LISTS.find((l) => l.key === 'blocked-domains')!

describe('entryKind', () => {
  // "Network /22" repeated the prefix shown in the Entry column.
  it('says how many addresses a network covers, not its prefix again', () => {
    expect(entryKind(ips, '220.158.216.0/22')).toBe('Network, 1,024 addresses')
    expect(entryKind(ips, '10.0.0.0/8')).toBe('Network, 16,777,216 addresses')
    expect(entryKind(ips, '192.0.2.9')).toBe('IP')
    expect(entryKind(ips, '192.0.2.9/32')).toBe('IP')
    expect(entryKind(ips, '2001:db8::/120')).toBe('IPv6 network, 256 addresses')
    expect(entryKind(ips, '2001:db8::/64')).toBe('IPv6 network')
    expect(entryKind(domains, 'ads.example.com')).toBe('Domain')
  })
})
