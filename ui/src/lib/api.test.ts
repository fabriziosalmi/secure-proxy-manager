import { describe, it, expect } from 'vitest'

// Import after setup.ts has polyfilled localStorage
import { isTokenExpired, getErrorMessage } from './api'

describe('isTokenExpired', () => {
  function makeToken(exp: number): string {
    const header = btoa(JSON.stringify({ alg: 'HS256' }))
    const payload = btoa(JSON.stringify({ sub: 'admin', exp }))
    return `${header}.${payload}.signature`
  }

  it('returns false for token expiring in the future', () => {
    const token = makeToken(Math.floor(Date.now() / 1000) + 3600)
    expect(isTokenExpired(token)).toBe(false)
  })

  it('returns true for token expired more than 60s ago', () => {
    const token = makeToken(Math.floor(Date.now() / 1000) - 120)
    expect(isTokenExpired(token)).toBe(true)
  })

  it('returns false for token expired less than 60s ago (grace period)', () => {
    const token = makeToken(Math.floor(Date.now() / 1000) - 30)
    expect(isTokenExpired(token)).toBe(false)
  })

  it('returns false for token without exp claim', () => {
    const header = btoa(JSON.stringify({ alg: 'HS256' }))
    const payload = btoa(JSON.stringify({ sub: 'admin' }))
    expect(isTokenExpired(`${header}.${payload}.sig`)).toBe(false)
  })

  it('returns false for malformed token', () => {
    expect(isTokenExpired('not-a-jwt')).toBe(false)
  })
})

describe('getErrorMessage', () => {
  it('returns fallback for non-axios errors', () => {
    expect(getErrorMessage(new Error('test'), 'fallback')).toBe('fallback')
  })

  it('returns fallback for undefined errors', () => {
    expect(getErrorMessage(undefined, 'oops')).toBe('oops')
  })
})
