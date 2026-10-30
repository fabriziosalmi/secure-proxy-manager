import { describe, expect, it } from 'vitest'
import { wafCategoryLabel } from './wafCategories'

describe('wafCategoryLabel', () => {
  it('names a request rule category in words', () => {
    expect(wafCategoryLabel('SQL_INJECTION')).toEqual({ label: 'SQL injection', kind: 'rule' })
  })
  it('tells heuristics and domain reputation apart from rule categories', () => {
    expect(wafCategoryLabel('HEURISTIC_BEACONING').kind).toBe('heuristic')
    expect(wafCategoryLabel('DGA_DOMAIN')).toEqual({ label: 'Generated domain name (DGA)', kind: 'domain reputation' })
    expect(wafCategoryLabel('TYPOSQUATTING').kind).toBe('domain reputation')
    expect(wafCategoryLabel('BODY_OVERSIZE').kind).toBe('size limit')
  })
  // The Core Rule Set's families, as waf-go/internal/crs/crs.go names them
  // (families) plus CRS for a rule outside them. Written from its key,
  // CRS_SQLI read "Crs sqli".
  it('names every Core Rule Set family the WAF reports', () => {
    const families = ['CRS', 'CRS_METHOD', 'CRS_SCANNER', 'CRS_PROTOCOL', 'CRS_PROTOCOL_ATTACK', 'CRS_MULTIPART', 'CRS_LFI',
      'CRS_RFI', 'CRS_RCE', 'CRS_PHP', 'CRS_GENERIC', 'CRS_XSS', 'CRS_SQLI', 'CRS_SESSION', 'CRS_JAVA']
    for (const f of families) {
      expect(wafCategoryLabel(f).label, f).toMatch(/Core Rule Set/)
    }
    expect(wafCategoryLabel('CRS_SQLI').label).toBe('SQL injection (Core Rule Set)')
  })
  it('writes an unknown key in words, keeping acronyms', () => {
    expect(wafCategoryLabel('XSS_EXTRA_CHECK')).toEqual({ label: 'XSS extra check', kind: 'rule' })
    expect(wafCategoryLabel('HEURISTIC_NEW_THING')).toEqual({ label: 'Heuristic new thing', kind: 'heuristic' })
  })
})
