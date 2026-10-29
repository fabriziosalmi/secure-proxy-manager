import { describe, it, expect, afterEach } from 'vitest'
import type { BlockedDay, ReasonCount } from '../../types'
import { barHeight, daySegments, dayLabel, describeDays, ruleColor, seriesFor } from './days'
import { setRomeTimeZone } from '../../test/helpers'

const r = (reason: string, label: string, count: number): ReasonCount => ({ reason, label, count })

const DNS = r('domain_blacklist_dns', 'Domain blacklist (DNS)', 2)
const WAF = r('waf', 'WAF', 1)
const UNC = r('unclassified', 'Unclassified (no reason recorded)', 20)

function day(date: string, reasons: ReasonCount[]): BlockedDay {
  return { date, start: 0, end: 0, blocked: reasons.reduce((n, x) => n + x.count, 0), reasons }
}

describe('seriesFor', () => {
  // Colours were handed out in order to the rules present: the WAF was
  // series-1 in a week without domain blocks and series-2 in a week with them.
  it('gives each rule the same colour whatever else blocked, and the neutral bar to rows with no reason', () => {
    const s = seriesFor([UNC, DNS, WAF])
    expect(s.map((x) => [x.key, x.color])).toEqual([
      ['domain_blacklist_dns', 'series-2'],
      ['waf', 'series-4'],
      ['unclassified', 'neutral'],
    ])
    expect(seriesFor([r('waf', 'WAF', 9)]).map((x) => [x.key, x.color])).toEqual([['waf', 'series-4']])
    expect(seriesFor([r('domain_blacklist', 'Domain blacklist', 3), DNS]).map((x) => [x.key, x.color])).toEqual([
      ['domain_blacklist', 'series-1'],
      ['domain_blacklist_dns', 'series-2'],
    ])
  })

  it('maps every rule to its colour, and a rule the UI does not know to the other rules', () => {
    expect(['domain_blacklist', 'domain_blacklist_dns', 'domain_blacklist_dns_reconstructed', 'ip_blacklist', 'direct_ip', 'egress_policy', 'port_policy', 'protocol_policy', 'source_gate', 'waf', 'proxy_auth', 'lists_unverified', 'other', 'brand_new_rule'].map(ruleColor))
      .toEqual(['series-1', 'series-2', 'series-2', 'series-3', 'series-3', 'series-3', 'series-3', 'series-3', 'series-3', 'series-4', 'series-4', 'series-4', 'series-4', 'series-4'])
  })

  it('leaves out a reason with no blocks and keeps the API label', () => {
    const s = seriesFor([r('ip_blacklist', 'IP blacklist', 0), WAF])
    expect(s).toHaveLength(1)
    expect(s[0]).toMatchObject({ key: 'waf', label: 'WAF', color: 'series-4' })
  })

  it('draws the rules of one colour as one stack, named by the group and listing its rules', () => {
    const s = seriesFor([
      r('direct_ip', 'Direct IP', 50), r('waf', 'WAF', 40), r('egress_policy', 'Egress policy', 30),
      r('domain_blacklist', 'Domain blacklist', 2), r('proxy_auth', 'Proxy authentication', 1), r('lists_unverified', 'Lists not verified', 9), UNC,
    ])
    expect(s.map((x) => [x.key, x.label, x.color])).toEqual([
      ['domain_blacklist', 'Domain blacklist', 'series-1'],
      ['group-series-3', 'Address and network rules', 'series-3'],
      ['group-series-4', 'WAF and other rules', 'series-4'],
      ['unclassified', 'Unclassified (no reason recorded)', 'neutral'],
    ])
    expect(s[1].labels).toEqual(['Direct IP', 'Egress policy'])
    expect(s[2].reasons).toEqual(['waf', 'proxy_auth', 'lists_unverified'])
  })
})

describe('daySegments', () => {
  it('gives every series its count that day, zero included, and sums a group', () => {
    const series = seriesFor([
      r('direct_ip', 'Direct IP', 50), r('waf', 'WAF', 40), r('egress_policy', 'Egress policy', 30),
      r('domain_blacklist', 'Domain blacklist', 2), r('proxy_auth', 'Proxy authentication', 1),
    ])
    const segs = daySegments(day('2026-10-25', [r('waf', 'WAF', 4), r('domain_blacklist', 'Domain blacklist', 2), r('proxy_auth', 'Proxy authentication', 1)]), series)
    expect(segs.map((x) => [x.series.key, x.count])).toEqual([['domain_blacklist', 2], ['group-series-3', 0], ['group-series-4', 5]])
  })
})

describe('barHeight', () => {
  // The 4 px floor was on each rule: 10 blocks over 3 rules drew 12 px.
  it('floors the whole day at 4 px, not each rule, and draws nothing for a day without blocks', () => {
    expect(barHeight(10, 1000)).toBe('max(4px, 1%)')
    expect(barHeight(500, 1000)).toBe('max(4px, 50%)')
    expect(barHeight(0, 1000)).toBe('0')
  })
})

describe('dayLabel', () => {
  let restore: (() => void) | undefined
  afterEach(() => { restore?.() })

  it('reads the date as the viewer day, not as a UTC moment', () => {
    restore = setRomeTimeZone()
    expect(dayLabel('2026-10-25')).toEqual({ weekday: 'Sun', day: '25' })
    expect(dayLabel('2026-10-19')).toEqual({ weekday: 'Mon', day: '19' })
  })
})

describe('describeDays', () => {
  it('names every day that had blocks, by rule, and counts the rest', () => {
    const days = ['19', '20', '21', '22', '23', '24'].map((d) => day(`2026-10-${d}`, []))
    days.push(day('2026-10-25', [UNC, DNS, WAF]))
    expect(describeDays(days)).toBe(
      'Blocked requests per day, today and the 6 days before: today 23 (20 Unclassified (no reason recorded), 2 Domain blacklist (DNS), 1 WAF); none on the other 6 days.',
    )
    expect(describeDays(days.slice(0, 6))).toBe('Blocked requests per day, today and the 6 days before: none.')
  })
})
