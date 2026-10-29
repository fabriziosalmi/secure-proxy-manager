import { describe, it, expect } from 'vitest'
import type { Coverage } from '../types'
import { coverageLines } from '../components/analytics/coverage'
import { needsAttention } from './attention'
import { SHARED_SEVERITY } from './posture'

// One install: alerts off, HTTPS not inspected, proxy login off.
const coverage: Coverage = {
  domain_blacklist: { entries: 10, squid_acl: null },
  ip_blacklist: { entries: 10, squid_acl: null },
  waf: { status: 'ok', categories: 1, categories_enabled: 1, rules: 1, rules_enabled: 1 },
  https_inspection: false,
  proxy_login: false,
  alerts: { enabled: false, channels: 0, waf_alerts_delivered: true },
}
const values = { ssl_bump_enabled: 'false', enable_notifications: 'false', enable_proxy_auth: 'false', default_password_changed: 'true', proxy_port: '3128' }

const lineState = (c: Coverage, id: string) => coverageLines(c).find((l) => l.id === id)?.state
const itemPosture = (v: Record<string, string>, id: string) =>
  needsAttention({ values: v, secrets: {}, proxyStatus: 'running', egressTotal: 0 }).find((a) => a.id === id)?.posture

// Alerts off were an orange "attention" in Analytics and a grey item "for
// information" in Settings: the same condition judged twice.
describe('one severity for a condition on both pages', () => {
  it('alerts off', () => {
    expect(lineState(coverage, 'alerts')).toBe(SHARED_SEVERITY.alertsOff)
    expect(itemPosture(values, 'alerts-off')).toBe(SHARED_SEVERITY.alertsOff)
  })
  it('HTTPS not inspected', () => {
    expect(lineState(coverage, 'https')).toBe(SHARED_SEVERITY.httpsOff)
    expect(itemPosture(values, 'https-off')).toBe(SHARED_SEVERITY.httpsOff)
  })
  it('proxy login off', () => {
    expect(lineState(coverage, 'login')).toBe(SHARED_SEVERITY.proxyLoginOff)
    expect(itemPosture(values, 'no-login')).toBe(SHARED_SEVERITY.proxyLoginOff)
  })
  it('alerts on with no channel', () => {
    expect(lineState({ ...coverage, alerts: { enabled: true, channels: 0, waf_alerts_delivered: true } }, 'alerts')).toBe(SHARED_SEVERITY.alertsWithoutChannel)
    expect(itemPosture({ ...values, enable_notifications: 'true' }, 'alerts-no-channel')).toBe(SHARED_SEVERITY.alertsWithoutChannel)
  })
  it('alerts off is worth knowing, not needing attention', () => {
    expect(SHARED_SEVERITY.alertsOff).toBe('worth-knowing')
  })
})
