import { describe, it, expect } from 'vitest'
import type { Coverage } from '../../types'
import { coverageLines } from './coverage'

// The body GET /api/analytics/coverage returns for a deployment with lists,
// a WAF that answers, and everything else off (analytics_coverage.go).
const coverageBody: Coverage = {
  domain_blacklist: { entries: 640929, squid_acl: { names: 640929, limit: 100000, held: false, written_at: 1 } },
  ip_blacklist: { entries: 50772, squid_acl: { entries: 50772, networks: 50770, dropped: 2, written_at: 1 } },
  waf: { status: 'ok', categories: 3, categories_enabled: 3, rules: 9, rules_enabled: 9 },
  https_inspection: false,
  proxy_login: false,
  alerts: { enabled: false, channels: 0, waf_alerts_delivered: true },
}

function lines(c: Coverage) {
  return Object.fromEntries(coverageLines(c).map((l) => [l.id, l]))
}

describe('coverageLines', () => {
  it('says each protection with the numbers the API sent', () => {
    const l = lines(coverageBody)
    expect(Object.keys(l)).toEqual(['domain', 'ip', 'waf', 'https', 'login', 'alerts'])
    expect(l.domain).toMatchObject({ state: 'attention', text: "Domain blacklist: 640,929 entries, blocked at the DNS sinkhole only: 640,929 names are above the proxy's limit of 100,000" })
    expect(l.ip).toMatchObject({ state: 'on', text: 'IP blacklist: 50,772 entries, enforced by the proxy as 50,770 networks; 2 lines are not an address and not loaded' })
    // The WAF's own count, not a number written into the UI.
    expect(l.waf).toMatchObject({ state: 'on', text: 'WAF: 9 request rules in 3 categories, inspecting plain HTTP only' })
    expect(l.https).toMatchObject({ state: 'off', text: 'HTTPS inspection: off, so the WAF does not see inside HTTPS' })
    expect(l.login).toMatchObject({ state: 'off', text: 'Proxy login: off, any device on an allowed network can use the proxy' })
    expect(l.alerts).toMatchObject({ state: 'attention', text: 'Alerts: off, blocks are not reported anywhere' })
    expect(l.domain.link).toEqual({ label: 'Blacklists', to: '/blacklists?tab=blocked-domains' })
    expect(l.ip.link).toEqual({ label: 'Blacklists', to: '/blacklists' })
    expect(l.waf.link).toEqual({ label: 'Inspection', to: '/settings/inspection' })
    expect(l.login.link).toEqual({ label: 'Access', to: '/settings/access' })
  })

  it('says when the proxy holds its own copy, and when rules are partly off', () => {
    const l = lines({
      ...coverageBody,
      domain_blacklist: { entries: 2, squid_acl: { names: 2, limit: 100000, held: true, written_at: 1 } },
      waf: { status: 'ok', categories: 12, categories_enabled: 11, rules: 172, rules_enabled: 160 },
      https_inspection: true,
      proxy_login: true,
      alerts: { enabled: true, channels: 2, waf_alerts_delivered: true },
    })
    expect(l.domain.text).toBe("Domain blacklist: 2 entries, blocked at the DNS sinkhole and by the proxy's own copy")
    expect(l.waf.text).toBe('WAF: 160 of 172 request rules on, in 11 of 12 categories, inspecting plain HTTP and inspected HTTPS')
    expect(l.https.state).toBe('on')
    expect(l.login.text).toBe('Proxy login: on, a device signs in to use the proxy')
    // The proxy's own record: login on with no user refuses every client.
    expect(lines({ ...coverageBody, proxy_login: true, proxy_login_status: { state: 'no_credentials', users: 0, written_at: 1 } }).login).toMatchObject({
      state: 'attention',
      text: 'Proxy login: on, but no proxy credentials are set: every client is refused until you set them',
    })
    expect(lines({ ...coverageBody, proxy_login: true, proxy_login_status: { state: 'enforced', users: 1, written_at: 1 } }).login.state).toBe('on')
    expect(l.alerts).toMatchObject({ state: 'on', text: 'Alerts: on, sent to 2 channels' })
  })

  it('says what is missing instead of showing it as off', () => {
    const l = lines({
      domain_blacklist: { entries: null, squid_acl: null },
      ip_blacklist: { entries: null, squid_acl: null },
      waf: { status: 'auth_failed', categories: null, categories_enabled: null, rules: null, rules_enabled: null },
      https_inspection: null,
      proxy_login: null,
      alerts: { enabled: true, channels: 1, waf_alerts_delivered: false },
    })
    for (const id of ['domain', 'ip', 'https', 'login'] as const) expect(l[id].state, id).toBe('unknown')
    expect(l.domain.text).toBe('Domain blacklist: the backend could not count its entries')
    expect(l.waf).toMatchObject({ state: 'attention', text: 'WAF: refuses the backend credential, so its rules are not reported (INTERNAL_ALERT_TOKEN must match)' })
    expect(l.alerts.text).toBe('Alerts: on, sent to 1 channel, but WAF block alerts do not arrive: INTERNAL_ALERT_TOKEN is not set')
    expect(lines({ ...coverageBody, waf: { ...coverageBody.waf, status: 'unreachable' } }).waf.text).toBe('WAF: did not answer the backend, so its rules are not reported')
    expect(lines({ ...coverageBody, alerts: { enabled: true, channels: 0, waf_alerts_delivered: true } }).alerts.text).toBe('Alerts: on, but no channel is set up, so they go nowhere')
    expect(lines({ ...coverageBody, ip_blacklist: { entries: 3, squid_acl: null } }).ip.text).toBe('IP blacklist: 3 entries; the proxy has not reported loading them')
    expect(lines({ ...coverageBody, domain_blacklist: { entries: 0, squid_acl: null } }).domain).toMatchObject({ state: 'off', text: 'Domain blacklist: empty, no domain is blocked' })
  })
})
