import { describe, it, expect } from 'vitest'
import {
  allowableDomain, apiParams, matchesFilters, readFilters, requestHost, splitStatus, statusTone, whyText, writeFilters, NO_FILTERS,
} from './accessLog'
import type { LogEntry } from '../types'

const entry = (over: Partial<LogEntry> = {}): LogEntry => ({
  timestamp: '2026-04-04 12:00:00', source_ip: '192.168.1.10', method: 'GET', destination: 'http://Example.com/a',
  status: 'TCP_MISS/200', bytes: 1, blocked: 0, reason: 'none', internal: false, ...over,
})

describe('filters in the URL', () => {
  it('round-trips, leaving defaults out', () => {
    const f = { q: 'ads', outcome: 'blocked' as const, client: '192.168.1.10', rule: 'waf' }
    expect(writeFilters(f).toString()).toBe('q=ads&outcome=blocked&client=192.168.1.10&rule=waf')
    expect(readFilters(writeFilters(f))).toEqual(f)
    expect(writeFilters(NO_FILTERS).toString()).toBe('')
  })

  it('ignores an outcome it does not know', () => {
    expect(readFilters(new URLSearchParams('outcome=denied')).outcome).toBe('all')
  })

  it('names the API parameters', () => {
    const p = apiParams({ q: 'x', outcome: 'allowed', client: '10.0.0.1', rule: 'waf' }, true)
    expect(p.toString()).toBe('q=x&outcome=allowed&source_ip=10.0.0.1&reason=waf&include_internal=true')
    expect(apiParams(NO_FILTERS, false).toString()).toBe('')
  })
})

describe('matchesFilters (live rows)', () => {
  it('applies each filter as the server does', () => {
    expect(matchesFilters(entry(), NO_FILTERS, false)).toBe(true)
    expect(matchesFilters(entry(), { ...NO_FILTERS, client: '192.168.1.1' }, false)).toBe(false)
    expect(matchesFilters(entry(), { ...NO_FILTERS, outcome: 'blocked' }, false)).toBe(false)
    expect(matchesFilters(entry({ blocked: 1, reason: 'waf' }), { ...NO_FILTERS, outcome: 'blocked' }, false)).toBe(true)
    expect(matchesFilters(entry({ blocked: true, reason: 'waf' }), { ...NO_FILTERS, outcome: 'allowed' }, false)).toBe(false)
    expect(matchesFilters(entry({ blocked: 1, reason: 'waf' }), { ...NO_FILTERS, rule: 'waf' }, false)).toBe(true)
    expect(matchesFilters(entry({ blocked: 1, reason: 'ip_blacklist' }), { ...NO_FILTERS, rule: 'waf' }, false)).toBe(false)
    expect(matchesFilters(entry(), { ...NO_FILTERS, q: 'example.COM' }, false)).toBe(true)
    expect(matchesFilters(entry(), { ...NO_FILTERS, q: 'other' }, false)).toBe(false)
  })

  it('hides internal rows unless shown or named', () => {
    const internal = entry({ source_ip: '172.18.0.2', internal: true })
    expect(matchesFilters(internal, NO_FILTERS, false)).toBe(false)
    expect(matchesFilters(internal, NO_FILTERS, true)).toBe(true)
    expect(matchesFilters(internal, { ...NO_FILTERS, client: '172.18.0.2' }, false)).toBe(true)
    // An older backend sends no classification: the row is not known to be internal.
    expect(matchesFilters(entry({ internal: undefined }), NO_FILTERS, false)).toBe(true)
  })
})

describe('row facts', () => {
  it('splits the Squid result from the HTTP code', () => {
    expect(splitStatus('TCP_TUNNEL/200')).toEqual({ squid: 'TCP_TUNNEL', code: '200' })
    expect(splitStatus('weird')).toEqual({ squid: 'weird', code: '' })
    expect(splitStatus(undefined)).toEqual({ squid: '', code: '' })
  })

  it('finds the host a destination names, and no host in an address literal', () => {
    expect(requestHost('ads.example.com:443')).toBe('ads.example.com')
    expect(requestHost('http://Ads.Example.com:8080/x?y')).toBe('ads.example.com')
    expect(requestHost('https://ads.example.com/')).toBe('ads.example.com')
    expect(requestHost('sink.example.org')).toBe('sink.example.org')
    expect(requestHost('8.8.8.8:443')).toBeNull()
    expect(requestHost('http://8.8.8.8/')).toBeNull()
    expect(requestHost('[2001:db8::1]:443')).toBeNull()
    expect(requestHost('http://[2001:db8::1]/')).toBeNull()
    expect(requestHost('/')).toBeNull()
    expect(requestHost('error:transaction-end-before-headers')).toBeNull()
  })

  it('offers the whitelist only for the rules it overrides', () => {
    expect(allowableDomain(entry({ blocked: 1, reason: 'domain_blacklist', destination: 'ads.example.com:443' }))).toBe('ads.example.com')
    expect(allowableDomain(entry({ blocked: 1, reason: 'domain_blacklist_dns', destination: 'http://ads.example.com/' }))).toBe('ads.example.com')
    // #424: a block from before reasons were recorded, reconstructed as a DNS sinkhole block.
    expect(allowableDomain(entry({ blocked: 1, reason: 'domain_blacklist_dns_reconstructed', destination: 'ads.example.com:443' }))).toBe('ads.example.com')
    for (const reason of ['waf', 'ip_blacklist', 'direct_ip', 'egress_policy', 'lists_unverified', 'unclassified', 'other']) {
      expect(allowableDomain(entry({ blocked: 1, reason, destination: 'ads.example.com:443' }))).toBeNull()
    }
    expect(allowableDomain(entry({ blocked: 0, reason: 'domain_blacklist' }))).toBeNull()
  })

  it('says why in a sentence, for every rule and for one it does not know', () => {
    expect(whyText(entry())).toBe('Allowed: no rule blocked it.')
    for (const reason of ['domain_blacklist', 'domain_blacklist_dns', 'domain_blacklist_dns_reconstructed', 'ip_blacklist', 'direct_ip', 'egress_policy', 'waf', 'proxy_auth',
      'time_restriction', 'content_filter', 'source_gate', 'port_policy', 'protocol_policy', 'lists_unverified', 'other', 'unclassified']) {
      expect(whyText(entry({ blocked: 1, reason }))).toMatch(/\.$/)
    }
    expect(whyText(entry({ blocked: 1, reason: 'new_rule', reason_label: 'New rule' }))).toBe('Blocked by the rule "New rule".')
    expect(whyText(entry({ blocked: 1, reason: 'domain_blacklist_dns_reconstructed' }))).toMatch(/^Logged before the proxy recorded why/)
    // The fail-closed lists gate has its own sentence, not the generic "the proxy did not name".
    expect(whyText(entry({ blocked: 1, reason: 'lists_unverified', reason_label: 'Lists not verified' })))
      .toMatch(/^A blocklist did not match the manifest .* until a verified copy was loaded\.$/)
  })
})

describe('statusTone', () => {
  it('reads a block as danger whatever its code', () => {
    expect(statusTone('403', true)).toBe('danger')
    expect(statusTone('200', true)).toBe('danger')
  })
  it('reads a failure the proxy let through as warning, never as success', () => {
    expect(statusTone('503', false)).toBe('warning') // a name that does not resolve
    expect(statusTone('404', false)).toBe('warning')
    expect(statusTone('000', false)).toBe('warning') // the client went away
    expect(statusTone('', false)).toBe('warning')
  })
  it('reads 2xx and 3xx as success', () => {
    expect(statusTone('200', false)).toBe('success')
    expect(statusTone('304', false)).toBe('success')
  })
})
