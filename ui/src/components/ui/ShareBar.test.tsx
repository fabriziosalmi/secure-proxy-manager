import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { ShareBar } from './ShareBar'
import { fillWidth, shareText } from '../../lib/share'

describe('ShareBar', () => {
  // 145 of 6,539 is 2.2%: on an 80 px track the fill was 1.75 px, clipped
  // by the rounded track into a "(".
  it('draws any share above zero at least two pixels wide', () => {
    expect(fillWidth(145, 6539)).toBe('max(2px, 2.217464444104603%)')
    render(<ShareBar part={145} total={6539} />)
    expect(screen.getByTestId('share-fill').style.width).toBe('max(2px, 2.217464444104603%)')
    expect(screen.getByText('2.2%')).toBeInTheDocument()
  })

  it('draws no track at exactly zero, and writes 0% rather than a rounded 0.0%', () => {
    render(<ShareBar part={0} total={400} />)
    expect(screen.queryByTestId('share-track')).toBeNull()
    expect(screen.getByText('0%')).toBeInTheDocument()
    expect(shareText(0, 400)).toBe('0%')
    expect(shareText(1, 100000)).toBe('0.0%')
  })

  it('says there were no requests when the total is zero', () => {
    render(<ShareBar part={0} total={0} />)
    expect(screen.getByText('No requests')).toBeInTheDocument()
  })

  it('never draws past the end of its track', () => {
    expect(fillWidth(5, 4)).toBe('max(2px, 100%)')
  })
})
