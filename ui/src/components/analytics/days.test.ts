import { describe, it, expect, afterEach } from 'vitest'
import type { BlockedDay, ReasonCount } from '../../types'
import { daySegments, dayLabel, describeDays, seriesFor } from './days'
import { setRomeTimeZone } from '../../test/helpers'

const r = (reason: string, label: string, count: number): ReasonCount => ({ reason, label, count })

const DNS = r('domain_blacklist_dns', 'Domain blacklist (DNS)', 2)
const WAF = r('waf', 'WAF', 1)
const UNC = r('unclassified', 'Unclassified (no reason recorded)', 20)

function day(date: string, reasons: ReasonCount[]): BlockedDay {
  return { date, start: 0, end: 0, blocked: reasons.reduce((n, x) => n + x.count, 0), reasons }
}

describe('seriesFor', () => {
  it('gives each rule a colour in a fixed order, whatever the counts, and the neutral bar to rows with no reason', () => {
    // The API sends the totals largest first: unclassified, DNS, WAF.
    const s = seriesFor([UNC, DNS, WAF])
    expect(s.map((x) => [x.key, x.color])).toEqual([
      ['domain_blacklist_dns', 'series-1'],
      ['waf', 'series-2'],
      ['unclassified', 'neutral'],
    ])
    // Swapping the counts does not repaint them.
    expect(seriesFor([r('waf', 'WAF', 9), r('domain_blacklist_dns', 'Domain blacklist (DNS)', 1)]).map((x) => [x.key, x.color])).toEqual([
      ['domain_blacklist_dns', 'series-1'],
      ['waf', 'series-2'],
    ])
  })

  it('keeps the lists gate a rule of its own, before other, with the API label', () => {
    // Alphabetical order would put "lists_unverified" first, ahead of the
    // configured rules; it is ranked just before other.
    const s = seriesFor([r('other', 'Other', 5), r('lists_unverified', 'Lists not verified', 9), WAF])
    expect(s.map((x) => [x.key, x.label, x.color])).toEqual([
      ['waf', 'WAF', 'series-1'],
      ['lists_unverified', 'Lists not verified', 'series-2'],
      ['other', 'Other', 'series-3'],
    ])
  })

  it('leaves out a reason with no blocks and keeps the API label', () => {
    const s = seriesFor([r('ip_blacklist', 'IP blacklist', 0), WAF])
    expect(s).toHaveLength(1)
    expect(s[0]).toMatchObject({ key: 'waf', label: 'WAF', color: 'series-1' })
  })

  it('folds the rules beyond four colours into Other rules, keeping the three that blocked the most', () => {
    const s = seriesFor([
      r('direct_ip', 'Direct IP', 50), r('waf', 'WAF', 40), r('egress_policy', 'Egress policy', 30),
      r('domain_blacklist', 'Domain blacklist', 2), r('proxy_auth', 'Proxy authentication', 1), UNC,
    ])
    expect(s.map((x) => [x.key, x.color])).toEqual([
      ['waf', 'series-1'], ['direct_ip', 'series-2'], ['egress_policy', 'series-3'],
      ['other-rules', 'series-4'], ['unclassified', 'neutral'],
    ])
    expect(s[3].labels).toEqual(['Domain blacklist', 'Proxy authentication'])
    expect(s[3].reasons).toEqual(['domain_blacklist', 'proxy_auth'])
  })
})

describe('daySegments', () => {
  it('gives every series its count that day, zero included, and sums a fold', () => {
    const series = seriesFor([
      r('direct_ip', 'Direct IP', 50), r('waf', 'WAF', 40), r('egress_policy', 'Egress policy', 30),
      r('domain_blacklist', 'Domain blacklist', 2), r('proxy_auth', 'Proxy authentication', 1),
    ])
    const segs = daySegments(day('2026-10-25', [r('waf', 'WAF', 4), r('domain_blacklist', 'Domain blacklist', 2), r('proxy_auth', 'Proxy authentication', 1)]), series)
    expect(segs.map((x) => [x.series.key, x.count])).toEqual([['waf', 4], ['direct_ip', 0], ['egress_policy', 0], ['other-rules', 3]])
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
