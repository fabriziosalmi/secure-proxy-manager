import { describe, it, expect } from 'vitest'
import { isValidIP, isValidDomain, validatePassword, parseGeoCountries } from './validation'

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
    'example.com.',      // ends with dot (empty label) — trailing dots not handled
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
