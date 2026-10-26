import { describe, it, expect } from 'vitest'
import { rowsAfterSave, sectionRequest } from './settingsSave'

describe('the proxy password is write-only in the page too', () => {
  it('is sent only when typed, and only as a secret', () => {
    const stored = { enable_proxy_auth: 'true', proxy_auth_username: 'office' }
    const untouched = sectionRequest('access', stored, {}, {})
    expect(untouched.body).not.toHaveProperty('proxy_auth_password')
    const typed = sectionRequest('access', stored, {}, { proxy_auth_password: { kind: 'replace', value: 'correct-horse-battery' } })
    expect(typed.body).toMatchObject({ proxy_auth_password: 'correct-horse-battery', proxy_auth_username: 'office' })
    expect(typed.sent).not.toContain('proxy_auth_password')
    expect(typed.modes).toEqual(['reload'])
    const removed = sectionRequest('access', stored, {}, { proxy_auth_password: { kind: 'clear' } })
    expect(removed.clear).toEqual(['proxy_auth_password'])
  })

  it('never keeps the typed password in the cached settings after a save', () => {
    const rows = [
      { setting_name: 'proxy_auth_username', setting_value: 'office' },
      { setting_name: 'proxy_auth_password', setting_value: '', secret: true, is_set: false },
    ]
    const next = rowsAfterSave(rows, { body: { proxy_auth_password: 'correct-horse-battery' }, clear: [] })
    const row = next.find((r) => r.setting_name === 'proxy_auth_password')!
    expect(row).toMatchObject({ setting_value: '', secret: true, is_set: true })
    expect(JSON.stringify(next)).not.toContain('correct-horse-battery')
  })
})
