import { describe, it, expect } from 'vitest'
import { describeAudit } from './auditEvents'
import type { AuditEntry } from '../types'

const row = (action: string, target: string | null = null, details: string | null = null): AuditEntry => ({
  id: 1, username: 'admin', action, target, details, timestamp: '2026-10-25 09:00:00',
})

describe('describeAudit', () => {
  it('writes the list changes the backend records as sentences, with their counts', () => {
    const cases: [AuditEntry, string, string | null][] = [
      [row('clear_domain_blacklist', '', '{"removed":640929}'), 'Removed all 640,929 blocked domains', null],
      [row('import_domain_blacklist', 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts', '{"added":71140,"from":"url","name":"StevenBlack Unified","skipped":12}'),
        'Imported 71,140 domains from StevenBlack Unified',
        'From https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts. 12 skipped (already listed or not valid)'],
      [row('import_ip_blacklist', 'https://lists.example/ips.txt', '{"added":50772,"bogon_skipped":3,"from":"url","skipped":3}'),
        'Imported 50,772 IPs from https://lists.example/ips.txt', '3 skipped (already listed or not valid). 3 private or LAN ranges left out'],
      [row('import_ip_blacklist', '', '{"added":1,"from":"paste","skipped":0}'), 'Added 1 IP to Blocked IPs from a pasted list', null],
      [row('add_egress_allowlist', 'acme-v02.api.letsencrypt.org', 'certificate renewals'), 'Added acme-v02.api.letsencrypt.org to the egress allowlist', 'Note: certificate renewals'],
      [row('add_ip_whitelist', '198.51.100.7', ''), 'Added 198.51.100.7 to Allowed IPs', null],
      [row('remove_domain_whitelist', 'good.example'), 'Removed good.example from Allowed domains', null],
      [row('bulk_remove_ip_blacklist', '', '{"removed":2}'), 'Removed 2 blocked IPs', 'A selection removed at once'],
      [row('clear_egress_allowlist', '', '{"removed":1}'), 'Removed the only egress destination', null],
      [row('geo_block', 'CN,RU', '{"added":8123,"countries":1,"failed":["RU: no data"],"requested":2}'), 'Blocked 8,123 address blocks of CN, RU', 'Not imported: RU: no data'],
      [row('remove_source_ip_blacklist', 'https://lists.example/f.netset', '{"kind":"url","name":"Firehol Level 1","removed":4521}'),
        'Removed 4,521 blocked IPs from Firehol Level 1', 'From https://lists.example/f.netset'],
      [row('remove_source_domain_blacklist', '', '{"kind":"paste","removed":3}'), 'Removed 3 blocked domains from a pasted list', null],
      [row('remove_source_ip_blacklist', 'CN', '{"kind":"geo","removed":10}'), 'Removed 10 blocked IPs of CN', null],
      [row('remove_source_ip_blacklist', '', '{"kind":"unrecorded","removed":50772}'), 'Removed 50,772 blocked IPs whose source was not recorded', null],
      [row('restore_domain_blacklist', '', '{"added":2,"skipped":1}'), 'Restored 2 blocked domains from a backup', '1 not valid or over the limit, not restored'],
    ]
    for (const [e, event, details] of cases) {
      const d = describeAudit(e)
      expect(d.event, e.action).toBe(event)
      expect(d.details, e.action).toBe(details)
      expect(d.kind, e.action).toBe('change')
    }
  })

  // One click on "+ Docker" wrote five rows "Added <domain> to Allowed domains".
  it('writes a preset as one event naming what it added', () => {
    expect(describeAudit(row('add_preset_domain_whitelist', 'Docker', '{"preset":"docker","added":4,"already":1,"domains":["docker.com","registry.docker.io","auth.docker.io","production.cloudflare.docker.com"]}'))).toEqual({
      event: 'Added Docker (4 domains) to Allowed domains',
      details: 'docker.com, registry.docker.io, auth.docker.io, production.cloudflare.docker.com. 1 already listed',
      kind: 'change',
    })
    expect(describeAudit(row('remove_source_domain_whitelist', 'docker', '{"removed":4,"kind":"preset","name":"Common services: Docker"}')).event)
      .toBe('Removed 4 allowed domains of Common services: Docker')
  })

  it('describes a refresh run of the worker, which writes as system', () => {
    const d = describeAudit({ ...row('refresh_blacklists', '', '{"domain_blacklist":{"added":71140,"fetched":2,"failed":0,"not_added":5},"ip_blacklist":{"added":0,"fetched":1,"failed":1}}'), username: 'system' })
    expect(d.event).toBe('Auto-refresh added 0 blocked IPs and 71,140 blocked domains')
    expect(d.details).toBe('3 of 4 lists read, 1 could not be fetched. 5 domains not added: the domain blacklist is at its limit')
  })

  it('describes the upgrade step that rewrote *.name egress entries', () => {
    const d = describeAudit({ ...row('rewrite_egress_wildcards', 'egress_allowlist', '{"dropped":2,"entries":["*.a.example > .a.example"],"rewritten":1}'), username: 'system' })
    expect(d.event).toBe('The upgrade rewrote 1 egress entry from *.name to .name')
    expect(d.details).toBe('*.a.example > .a.example. 2 entries removed: already listed as .name, or a bare *.')
    expect(d.kind).toBe('change')
    const capped = describeAudit(row('rewrite_egress_wildcards', 'egress_allowlist', '{"dropped":0,"entries":["*.a > .a"],"rewritten":51}'))
    expect(capped.details).toBe('*.a > .a, and 50 more')
    // A shape this module does not know is shown as recorded.
    expect(describeAudit(row('rewrite_egress_wildcards', 'egress_allowlist', 'text')).event).toBe('rewrite_egress_wildcards')
  })

  it('names the sign-ins and keeps a failed one apart', () => {
    // Recorded before 3.15.0: no address.
    expect(describeAudit(row('login'))).toEqual({ event: 'Signed in', details: 'Address not recorded', kind: 'signin' })
    expect(describeAudit(row('login', '198.51.100.23'))).toEqual({ event: 'Signed in', details: 'From 198.51.100.23', kind: 'signin' })
    expect(describeAudit(row('logout', '198.51.100.23'))).toEqual({ event: 'Signed out', details: 'From 198.51.100.23', kind: 'signin' })
    expect(describeAudit(row('logout')).kind).toBe('signin')
    expect(describeAudit(row('login_failed', '203.0.113.5', 'invalid credentials'))).toEqual({
      event: 'Sign-in failed', details: 'From 203.0.113.5. invalid credentials', kind: 'signin-failed',
    })
  })

  it('reads the rows recorded before this change', () => {
    expect(describeAudit(row('delete_ip', 'id=42', 'dst_allowlist')).event).toBe('Removed entry 42 from the egress allowlist')
    expect(describeAudit(row('delete_domain', 'id=7', 'domain_blacklist')).event).toBe('Removed entry 7 from Blocked domains')
    // #426 wrote the source removal as text.
    expect(describeAudit(row('remove_source_ip_blacklist', 'source=3', '4 entries removed'))).toEqual({
      event: 'Removed a source from Blocked IPs', details: 'source=3. 4 entries removed', kind: 'change',
    })
    expect(describeAudit(row('update_settings', 'log_retention_days,enable_waf'))).toMatchObject({ event: 'Changed 2 settings', details: 'log_retention_days, enable_waf' })
    expect(describeAudit(row('reload_config', 'proxy')).event).toBe('Reloaded the proxy configuration')
  })

  it('shows a key it does not know verbatim, with what was recorded', () => {
    expect(describeAudit(row('rotate_keys', 'waf', 'manual'))).toEqual({ event: 'rotate_keys', details: 'waf. manual', kind: 'change' })
    // A known key whose details are not what the backend writes is not guessed at.
    expect(describeAudit(row('clear_ip_blacklist', '', 'Cleared some'))).toEqual({ event: 'clear_ip_blacklist', details: 'Cleared some', kind: 'change' })
  })
})
