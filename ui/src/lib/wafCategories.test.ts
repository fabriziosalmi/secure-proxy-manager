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
  it('writes an unknown key in words, keeping acronyms', () => {
    expect(wafCategoryLabel('CRS_SQLI_EXTRA')).toEqual({ label: 'CRS sqli extra', kind: 'rule' })
    expect(wafCategoryLabel('HEURISTIC_NEW_THING')).toEqual({ label: 'Heuristic new thing', kind: 'heuristic' })
  })
})
