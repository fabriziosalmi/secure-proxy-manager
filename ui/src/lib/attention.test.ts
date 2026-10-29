import { describe, it, expect } from 'vitest'
import { needsAttention, configuredChannels, type AttentionInput } from './attention'

// The values seedDefaultSettings stores on a fresh install
// (backend-go/internal/database/db.go), as GET /api/settings returns them.
const fresh: Record<string, string> = {
  proxy_port: '3128',
  ssl_bump_enabled: 'false',
  egress_default_deny: 'false',
  enable_content_filtering: 'false',
  enable_notifications: 'false',
  default_password_changed: 'false',
}

const input = (over: Partial<AttentionInput> = {}): AttentionInput => ({
  values: fresh,
  secrets: {},
  proxyStatus: 'running',
  egressTotal: 0,
  ...over,
})

const ids = (i: AttentionInput) => needsAttention(i).map((a) => `${a.posture}:${a.id}`)

describe('needsAttention', () => {
  it('on a fresh install: the password, and three choices worth knowing', () => {
    expect(ids(input())).toEqual(['needs-attention:password', 'worth-knowing:https-off', 'worth-knowing:alerts-off', 'worth-knowing:no-login'])
  })

  it('says nothing about what it does not know yet', () => {
    expect(ids(input({ values: {}, proxyStatus: undefined, egressTotal: undefined }))).toEqual(['worth-knowing:no-login'])
  })

  it('reports a proxy that is not running, and a status it could not read', () => {
    expect(needsAttention(input({ proxyStatus: 'error' }))[0]).toMatchObject({ id: 'proxy-down', body: 'The backend reports the proxy as "error". Clients cannot browse until the proxy container runs.' })
    expect(ids(input({ proxyStatus: null }))[0]).toBe('needs-attention:proxy-unknown')
  })

  it('warns when default-deny egress meets an empty allowlist, and only then', () => {
    const on = { ...fresh, egress_default_deny: 'true' }
    expect(ids(input({ values: on, egressTotal: 0 }))).toContain('needs-attention:egress-empty')
    expect(ids(input({ values: on, egressTotal: 3 }))).not.toContain('needs-attention:egress-empty')
    expect(ids(input({ values: on, egressTotal: null }))).toContain('needs-attention:egress-unknown')
    expect(ids(input({ values: fresh, egressTotal: 0 }))).not.toContain('needs-attention:egress-empty')
    // What stays reachable, from the generator's rule order (lib/egress.ts):
    // local_dst and ip_whitelist are allowed before the egress deny.
    const item = needsAttention(input({ values: on, egressTotal: 0 })).find((a) => a.id === 'egress-empty')!
    expect(item.title).toBe('Clients reach only LAN destinations and Allowed IPs')
    expect(item.body).toContain('With default deny on and an empty list, clients reach only LAN destinations and the addresses on Allowed IPs.')
    expect(item.body).not.toMatch(/every destination/i)
    // Provider lists count toward the effective allowlist: 0 manual entries + enabled provider entries is not empty.
    expect(ids(input({ values: on, egressTotal: 0, egressProviderEntries: 5295 }))).not.toContain('needs-attention:egress-empty')
    // When reading provider lists fails, report egress-unknown rather than egress-empty.
    expect(ids(input({ values: on, egressTotal: 0, egressProviderEntries: null }))).not.toContain('needs-attention:egress-empty')
    expect(ids(input({ values: on, egressTotal: 0, egressProviderEntries: null }))).toContain('needs-attention:egress-unknown')
  })

  it('warns when download blocking is on with no extension', () => {
    expect(ids(input({ values: { ...fresh, enable_content_filtering: 'true', blocked_file_types: ' , ' } }))).toContain('needs-attention:downloads-empty')
    expect(ids(input({ values: { ...fresh, enable_content_filtering: 'true', blocked_file_types: 'exe' } }))).not.toContain('needs-attention:downloads-empty')
  })

  it('warns about an unreadable secret, and alerts that go nowhere', () => {
    const items = needsAttention(input({
      values: { ...fresh, enable_notifications: 'true' },
      secrets: { gotify_url: 'set', gotify_token: 'unreadable' },
    }))
    expect(items.map((a) => a.id)).toEqual(expect.arrayContaining(['secrets-unreadable', 'alerts-no-channel']))
    expect(items.find((a) => a.id === 'secrets-unreadable')).toMatchObject({ title: 'An alert setting cannot be read', section: 'alerts' })
  })

  it('counts a channel only when every key it needs is stored', () => {
    expect(configuredChannels({ telegram_bot_token: 'set' })).toEqual([])
    expect(configuredChannels({ telegram_bot_token: 'set', telegram_chat_id: 'set', webhook_url: 'set' })).toEqual(['Telegram', 'Webhook'])
  })

  it('warns about a proxy port the compose file does not publish', () => {
    expect(needsAttention(input({ values: { ...fresh, proxy_port: '8080' } })).find((a) => a.id === 'port')).toMatchObject({
      title: 'The proxy is set to listen on 8080',
      section: 'engine',
    })
  })

  it('puts proxy login with no credentials first, from the settings or from the proxy itself', () => {
    const on = { ...fresh, enable_proxy_auth: 'true' }
    const title = 'Proxy login is on but no proxy credentials are set: every client is refused until you set them'
    // As an upgraded install has it: login on, nothing stored.
    const first = needsAttention(input({ values: on }))[0]
    expect(first).toMatchObject({ id: 'proxy-login-no-credentials', posture: 'needs-attention', title, section: 'access', action: 'Clients and access' })
    // Half the credentials is none.
    expect(ids(input({ values: { ...on, proxy_auth_username: 'office' } }))[0]).toBe('needs-attention:proxy-login-no-credentials')
    expect(ids(input({ values: on, secrets: { proxy_auth_password: 'set' } }))[0]).toBe('needs-attention:proxy-login-no-credentials')
    // Both stored: nothing to say.
    const both = input({ values: { ...on, proxy_auth_username: 'office' }, secrets: { proxy_auth_password: 'set' } })
    expect(ids(both)).not.toContain('needs-attention:proxy-login-no-credentials')
    // The proxy's own record wins: it has no user, whatever the settings say.
    expect(ids({ ...both, proxyAuth: { state: 'no_credentials', users: 0, written_at: 1 } })[0]).toBe('needs-attention:proxy-login-no-credentials')
    expect(ids({ ...both, proxyAuth: { state: 'enforced', users: 1, written_at: 1 } })).not.toContain('needs-attention:proxy-login-no-credentials')
    // Login off: no warning, the information item instead.
    expect(ids(input())).not.toContain('needs-attention:proxy-login-no-credentials')
  })

  it('tells an unreadable proxy password apart from an alert setting', () => {
    const items = needsAttention(input({ values: { ...fresh, enable_proxy_auth: 'true', proxy_auth_username: 'office' }, secrets: { proxy_auth_password: 'unreadable' } }))
    expect(items.map((a) => a.id)).toContain('proxy-password-unreadable')
    expect(items.map((a) => a.id)).not.toContain('secrets-unreadable')
    // Stored, if unreadable: the proxy keeps the file it has, so login is not without credentials.
    expect(items.map((a) => a.id)).not.toContain('proxy-login-no-credentials')
    expect(items.find((a) => a.id === 'proxy-password-unreadable')).toMatchObject({ section: 'access' })
  })

  it('says HTTPS inspection needs the CA when it is on', () => {
    expect(ids(input({ values: { ...fresh, ssl_bump_enabled: 'true' } }))).toContain('worth-knowing:https-on')
  })
})
