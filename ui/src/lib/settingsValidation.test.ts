import { describe, it, expect } from 'vitest'
import { checkProxyPassword, checkProxyUsername, validateProxyLogin, validateSecrets, validateSection } from './settingsValidation'

// The same domains as validProxyUsername and validProxyPassword in
// backend-go/internal/handlers/proxy_login.go, with the same messages.
describe('proxy login checks', () => {
  it('accepts a username the password file and Basic auth can carry, and nothing else', () => {
    for (const ok of ['', 'office', 'first.last@example.org', 'a+b_c-d', 'u'.repeat(64)]) expect(checkProxyUsername(ok), ok).toBeUndefined()
    for (const bad of ['user:name', 'two words', 'line\nbreak', '#comment', 'u'.repeat(65)]) {
      expect(checkProxyUsername(bad), bad).toBe('must be 1 to 64 letters, digits or the characters . _ @ + -, with no spaces or colons')
    }
  })

  it('asks for at least 12 characters on one line, and at most the 72 bytes bcrypt reads', () => {
    expect(checkProxyPassword('')).toBeUndefined()
    expect(checkProxyPassword('twelve-chars')).toBeUndefined()
    expect(checkProxyPassword('eleven-char')).toBe('must be at least 12 characters')
    expect(checkProxyPassword('line-one-long\nline-two')).toBe('must be on one line')
    expect(checkProxyPassword('p'.repeat(72))).toBeUndefined()
    expect(checkProxyPassword('p'.repeat(73))).toMatch(/^must be at most 72 bytes/)
    // Characters, not bytes, for the minimum; bytes for the maximum.
    expect(checkProxyPassword('è'.repeat(12))).toBeUndefined()
    expect(checkProxyPassword('è'.repeat(37))).toMatch(/^must be at most 72 bytes/)
  })

  it('checks a typed proxy password with the section secrets', () => {
    expect(validateSecrets('access', { proxy_auth_password: 'short' })).toEqual({ proxy_auth_password: 'must be at least 12 characters' })
    expect(validateSecrets('access', { proxy_auth_password: 'long-enough-pass' })).toEqual({})
  })

  it('needs both credentials while login is on, and nothing while it is off', () => {
    const msg = ': with proxy login on and no credentials the proxy refuses every client'
    expect(validateProxyLogin({ enable_proxy_auth: 'true' }, false)).toEqual({
      proxy_auth_username: `set the username devices sign in with${msg}`,
      proxy_auth_password: `set the password devices sign in with${msg}`,
    })
    expect(validateProxyLogin({ enable_proxy_auth: 'true', proxy_auth_username: 'office' }, true)).toEqual({})
    expect(validateProxyLogin({ enable_proxy_auth: 'false' }, false)).toEqual({})
  })

  it('validates egress_provider_refresh_hours from 6 to 168 hours', () => {
    expect(validateSection('filtering', { egress_provider_refresh_hours: '6' })).toEqual({})
    expect(validateSection('filtering', { egress_provider_refresh_hours: '24' })).toEqual({})
    expect(validateSection('filtering', { egress_provider_refresh_hours: '168' })).toEqual({})
    expect(validateSection('filtering', { egress_provider_refresh_hours: '5' })).toEqual({
      egress_provider_refresh_hours: 'must be a whole number from 6 to 168 (hours)',
    })
    expect(validateSection('filtering', { egress_provider_refresh_hours: '169' })).toEqual({
      egress_provider_refresh_hours: 'must be a whole number from 6 to 168 (hours)',
    })
    expect(validateSection('filtering', { egress_provider_refresh_hours: 'abc' })).toEqual({
      egress_provider_refresh_hours: 'must be a whole number from 6 to 168 (hours)',
    })
  })
})
