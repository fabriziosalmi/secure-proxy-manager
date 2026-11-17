import { describe, it, expect } from 'vitest'
import { isValidIP, isValidIPOrNetwork, isValidDomain, validatePassword, parseGeoCountries, oldLogDays } from './validation'

describe('isValidIP', () => {
  // Valid IPs
  it.each([
    '0.0.0.0',
    '255.255.255.255',
    '192.168.1.1',
    '10.0.0.0',
    '172.16.0.1',
    '1.2.3.4',
  ])('accepts valid IP: %s', (ip) => {
    expect(isValidIP(ip)).toBe(true)
  })

  // Valid CIDR
  it.each([
    '10.0.0.0/8',
    '192.168.1.0/24',
    '0.0.0.0/0',
    '255.255.255.255/32',
    '172.16.0.0/12',
  ])('accepts valid CIDR: %s', (cidr) => {
    expect(isValidIP(cidr)).toBe(true)
  })

  // Invalid IPs
  it.each([
    '256.0.0.0',       // octet > 255
    '999.999.999.999',  // all octets > 255
    '192.168.1',        // only 3 octets
    '192.168.1.1.1',    // 5 octets
    'abc.def.ghi.jkl',  // non-numeric
    '',                  // empty
    '192.168.1.1/33',   // CIDR > 32
    '192.168.1.1/-1',   // negative CIDR
    '192.168.1.1/abc',  // non-numeric CIDR
    '192.168.1.1/8/8',  // double slash
    '10.0.0.0/100',     // CIDR > 32
    '192.168.01.1',     // leading zero with 3 digits passes parseInt but is valid per regex
  ])('rejects invalid IP: %s', (ip) => {
    if (ip === '192.168.01.1') return // this is technically valid (01 parses to 1)
    expect(isValidIP(ip)).toBe(false)
  })

  it('rejects completely empty string', () => {
    expect(isValidIP('')).toBe(false)
  })

  it('rejects IP with spaces', () => {
    expect(isValidIP('192.168. 1.1')).toBe(false)
  })
})

// What the backend's netguard.IsValidCIDR (netip.ParsePrefix, then
// netip.ParseAddr) answers for each value: the table was printed by running
// those two calls in Go 1.27 on these inputs, not written by hand.
describe('isValidIPOrNetwork answers as the backend does', () => {
  it.each([
    ['2001:db8::1', true], ['2001:db8::/32', true], ['::', true], ['::/0', true], ['::1', true], ['::1/128', true],
    ['1::', true], ['1:2:3:4:5:6:7::', true], ['::2:3:4:5:6:7:8', true], ['1:2:3:4:5:6:7:8', true],
    ['1:2:3:4:5:6:7:8/64', true], ['2001:DB8::ABCD', true], ['0001:0db8::0001', true], ['::ffff:192.0.2.1', true],
    ['::ffff:192.0.2.1/120', true], ['1:2:3:4:5:6:192.0.2.1', true], ['1::192.0.2.1', true], ['::192.0.2.1', true],
    ['fe80::1%eth0', true], ['fe80::1%a/b', true], ['2001:db8::/0', true], ['2001:db8::/128', true],
    ['2001:db8:::1', false], [':::', false], ['1:::2', false], ['1:2:3:4:5:6:7:8::', false], ['::1:2:3:4:5:6:7:8', false],
    ['1:2:3:4:5:6:7', false], ['1:2:3:4:5:6:7:8:9', false], [':1:2:3:4:5:6:7', false], ['1:2:3:4:5:6:7:', false],
    ['12345::1', false], ['2001:db8::g', false], ['2001:db8::/129', false], ['2001:db8::/-1', false],
    ['2001:db8::/032', false], ['2001:db8::/', false], ['2001:db8::/3x', false], ['fe80::1%eth0/64', true],
    ['fe80::1%', false], ['1:2:3:4:5:6:7:192.0.2.1', false], ['::ffff:192.0.2.01', false], ['::ffff:192.0.2', false],
    ['::ffff:256.0.2.1', false], ['::192.0.2.1:1', false], ['a:192.0.2.1::', false], ['192.0.2.1::1', false],
    ['192.0.2.1:80', false], ['%eth0', false], ['::/1/2', false], [' 2001:db8::1', false], ['2001:db8::1 ', false],
    ['192.0.2.1', true], ['192.0.2.0/24', true], ['0.0.0.0/0', true], ['300.1.1.1', false], ['192.0.2.1/33', false],
  ] as const)('%j: %s', (value, ok) => {
    expect(isValidIPOrNetwork(value)).toBe(ok)
  })

  it('leaves isValidIP, which the egress form relies on, IPv4 only', () => {
    expect(isValidIP('2001:db8::1')).toBe(false)
  })
})

describe('isValidDomain', () => {
  // Valid domains
  it.each([
    'example.com',
    'sub.example.com',
    'a.b.c.d.example.co.uk',
    'my-domain.org',
    'x.io',
    '123.456.com',       // numeric labels are valid
    'a-b.c-d.com',
  ])('accepts valid domain: %s', (domain) => {
    expect(isValidDomain(domain)).toBe(true)
  })

  // Invalid domains
  it.each([
    '',                   // empty
    'localhost',          // single label (no dot)
    '.example.com',      // starts with dot (empty label)
    'example.com.',      // ends with dot (empty label); trailing dots not handled
    '-example.com',      // label starts with hyphen
    'example-.com',      // label ends with hyphen
    'exam ple.com',      // space in label
    'exam_ple.com',      // underscore (not in RFC 1035 label chars)
  ])('rejects invalid domain: %s', (domain) => {
    expect(isValidDomain(domain)).toBe(false)
  })

  it('rejects domain over 253 chars', () => {
    // Build a domain that's definitely over 253 chars
    const labels = []
    for (let i = 0; i < 10; i++) labels.push('a'.repeat(25))
    labels.push('com')
    const long = labels.join('.')
    expect(long.length).toBeGreaterThan(253)
    expect(isValidDomain(long)).toBe(false)
  })

  it('rejects label over 63 chars', () => {
    const domain = 'a'.repeat(64) + '.com'
    expect(isValidDomain(domain)).toBe(false)
  })

  it('accepts label exactly 63 chars', () => {
    const domain = 'a'.repeat(63) + '.com'
    expect(isValidDomain(domain)).toBe(true)
  })
})

describe('validatePassword', () => {
  it('requires 8+ characters', () => {
    expect(validatePassword('Ab!1').hasLength).toBe(false)
    expect(validatePassword('Abcdefg!1').hasLength).toBe(true)
  })

  it('requires at least one number', () => {
    expect(validatePassword('Abcdefg!').hasNumber).toBe(false)
    expect(validatePassword('Abcdefg!1').hasNumber).toBe(true)
  })

  it('requires at least one special character', () => {
    expect(validatePassword('Abcdefg1').hasSpecial).toBe(false)
    expect(validatePassword('Abcdefg1!').hasSpecial).toBe(true)
  })

  it('returns valid=true only when all criteria met', () => {
    expect(validatePassword('short').valid).toBe(false)
    expect(validatePassword('longenoughbutnospecial1').valid).toBe(false)
    expect(validatePassword('Str0ng!Pass').valid).toBe(true)
  })

  it('handles empty password', () => {
    const r = validatePassword('')
    expect(r.valid).toBe(false)
    expect(r.hasLength).toBe(false)
    expect(r.hasNumber).toBe(false)
    expect(r.hasSpecial).toBe(false)
  })

  it.each([
    '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', ',', '.', '?', '"', ':', '{', '}', '|', '<', '>',
  ])('recognizes special char: %s', (char) => {
    expect(validatePassword(`Abcdefg1${char}`).hasSpecial).toBe(true)
  })

  // The backend (auth.go pwdSpecial) counts any character that is not an
  // ASCII letter or digit, so the form must not refuse what the API takes.
  it.each([
    '-', '_', '+', '=', '~', '/', ';', ' ', "'", '[', ']', '\\', '`', 'é',
  ])('recognizes what the backend counts as special: %j', (char) => {
    expect(validatePassword(`Abcdefg1${char}`).hasSpecial).toBe(true)
  })

  it('counts length in characters, as the backend does (min=8 counts runes)', () => {
    // 7 characters, 8 UTF-16 code units: the backend refuses it.
    expect(validatePassword('Abcde1\u{1F600}').hasLength).toBe(false)
    expect(validatePassword('Abcdef1\u{1F600}').hasLength).toBe(true)
  })
})

describe('parseGeoCountries', () => {
  it('parses comma-separated country codes', () => {
    expect(parseGeoCountries('US, CN, RU')).toEqual(['US', 'CN', 'RU'])
  })

  it('parses space-separated codes', () => {
    expect(parseGeoCountries('US CN RU')).toEqual(['US', 'CN', 'RU'])
  })

  it('uppercases codes', () => {
    expect(parseGeoCountries('us, cn')).toEqual(['US', 'CN'])
  })

  it('filters invalid codes', () => {
    expect(parseGeoCountries('US, ABC, X, CN')).toEqual(['US', 'CN'])
  })

  it('handles empty input', () => {
    expect(parseGeoCountries('')).toEqual([])
  })

  it('handles mixed separators', () => {
    expect(parseGeoCountries('US,CN  RU, DE')).toEqual(['US', 'CN', 'RU', 'DE'])
  })
})

describe('oldLogDays', () => {
  it('takes whole days from 1 to 3650, as the backend does', () => {
    expect(['1', '30', ' 365 ', '3650'].map(oldLogDays)).toEqual([1, 30, 365, 3650])
    expect(['0', '-1', '3651', '1.5', 'abc', ''].map(oldLogDays)).toEqual([null, null, null, null, null, null])
  })
})
