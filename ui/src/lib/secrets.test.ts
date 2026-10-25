import { describe, it, expect } from 'vitest'
import { parseSettings, secretPayload } from './secrets'

describe('parseSettings', () => {
  it('keeps plain values and only the state of each secret', () => {
    const { values, secrets } = parseSettings([
      { setting_name: 'proxy_port', setting_value: '3128' },
      { setting_name: 'gotify_token', setting_value: '', secret: true, is_set: true },
      { setting_name: 'telegram_bot_token', setting_value: '', secret: true, is_set: true, decrypt_failed: true },
      { setting_name: 'webhook_url', setting_value: '', secret: true },
    ])
    expect(values).toEqual({ proxy_port: '3128' })
    expect(secrets).toEqual({ gotify_token: 'set', telegram_bot_token: 'unreadable', webhook_url: 'unset' })
  })

  it('treats a secret from an older backend, which returned the plaintext, as a secret', () => {
    const { values, secrets } = parseSettings([{ setting_name: 'ntfy_topic', setting_value: 'my-topic' }])
    expect(values).toEqual({})
    expect(secrets).toEqual({ ntfy_topic: 'set' })
  })
})

describe('secretPayload', () => {
  it('sends a typed value, names a removed secret, and leaves the rest out', () => {
    expect(secretPayload({
      gotify_token: { kind: 'replace', value: 'new' },
      webhook_url: { kind: 'clear' },
      telegram_bot_token: undefined,
      ntfy_url: { kind: 'replace', value: '' },
    })).toEqual({ body: { gotify_token: 'new' }, clear: ['webhook_url'] })
  })
})
