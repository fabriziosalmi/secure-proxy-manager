import { describe, it, expect } from 'vitest'
import { tableKind } from './clientKind'

describe('tableKind', () => {
  it('leaves out the kind every LAN client has, and says the others', () => {
    expect(tableKind('Private network address')).toBeUndefined()
    expect(tableKind('Public address')).toBe('Public address')
    expect(tableKind('Internal: this host')).toBe('Internal: this host')
    expect(tableKind('')).toBeUndefined()
    expect(tableKind(undefined)).toBeUndefined()
  })
})
