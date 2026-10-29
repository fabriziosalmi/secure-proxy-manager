import { describe, it, expect } from 'vitest'
import { describeListResend } from './listResend'

describe('describeListResend', () => {
  it('says what went to the DNS sinkhole and what Domain exceptions left out', () => {
    expect(describeListResend({ domains: 640926, left_out: 3 })).toBe('640,926 domain entries went to the DNS sinkhole, 3 left out by Domain exceptions.')
    expect(describeListResend({ domains: 1, left_out: 0 })).toBe('1 domain entry went to the DNS sinkhole.')
  })

  it('names no count it was not given', () => {
    expect(describeListResend(undefined)).toBe('The lists were written again.')
    expect(describeListResend({})).toBe('The lists were written again.')
  })
})
