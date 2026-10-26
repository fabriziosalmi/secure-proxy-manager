import { describe, it, expect } from 'vitest'
import { PROFILES, matchingProfile, profileChanges } from './profiles'
import { sectionOfKey } from './settingsMeta'

describe('profiles', () => {
  it('set only keys that are enforced and that a section saves', () => {
    const dead = ['waf_block_threshold', 'block_direct_ip', 'auth_method', 'kiosk_mode', 'enable_offline_mode', 'aggressive_caching_enabled', 'enable_waf', 'enable_ip_blacklist']
    for (const p of PROFILES) {
      for (const key of Object.keys(p.values)) {
        expect(dead, `${p.name} sets ${key}`).not.toContain(key)
        expect(sectionOfKey(key), `${p.name} sets ${key}, which no section owns`).toBeDefined()
      }
    }
  })

  it('never block .js, which every web page loads', () => {
    for (const p of PROFILES) {
      const list = (p.values.blocked_file_types ?? '').split(',').map((s) => s.trim())
      expect(list, p.name).not.toContain('js')
    }
  })

  it('carry the parameters of every toggle they turn on', () => {
    for (const p of PROFILES) {
      const v = p.values
      if (v.enable_content_filtering === 'true') expect(v.blocked_file_types, p.name).toBeTruthy()
      if (v.enable_bandwidth_limits === 'true') expect([v.bandwidth_limit_mbps, v.bandwidth_limit_per_user_kbps].every(Boolean), p.name).toBe(true)
      if (v.enable_time_restrictions === 'true') expect([v.time_restriction_start, v.time_restriction_end].every(Boolean), p.name).toBe(true)
    }
  })

  it('preview only what changes, in section order, with the risky ones marked', () => {
    const paranoid = PROFILES.find((p) => p.id === 'paranoid')!
    const stored = { ...paranoid.values, enable_proxy_auth: 'false', ssl_bump_enabled: 'false', enable_safesearch: 'false' }
    const changes = profileChanges(paranoid, stored)
    expect(changes.map((c) => [c.section, c.key, c.from, c.to])).toEqual([
      ['access', 'enable_proxy_auth', 'false', 'true'],
      ['filtering', 'enable_safesearch', 'false', 'true'],
      ['inspection', 'ssl_bump_enabled', 'false', 'true'],
    ])
    expect(changes[0].warning).toBe('Every device must sign in with the proxy username and password set under Clients and access, or gets 407. Without them every client is refused.')
    expect(changes[1].warning).toBeUndefined()
  })

  it('recognise the profile the stored values match', () => {
    const family = PROFILES.find((p) => p.id === 'family')!
    expect(matchingProfile({ ...family.values, proxy_port: '3128' })?.id).toBe('family')
    expect(matchingProfile({ ...family.values, enable_safesearch: 'false' })).toBeUndefined()
  })
})
