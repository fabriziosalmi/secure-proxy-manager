import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'
import { renderWithProviders } from '../../test/helpers'
import { api } from '../../lib/api'
import type { TimelineEntry } from '../../types'

// Rendered, not grepped. jsdom has no layout, so recharts' ResponsiveContainer
// measures 0x0 and draws nothing; the series primitives are replaced by
// recorders that keep the props each page passes them, and the containers by
// pass-throughs. What is asserted is therefore the real JSX of the Dashboard
// and Threat Intel timelines, whatever component they go through.
const series: { kind: string; props: Record<string, unknown> }[] = []

vi.mock('recharts', () => {
  const pass = ({ children }: { children?: ReactNode }) => <div>{children}</div>
  const none = () => null
  const recorder = (kind: string) => (props: Record<string, unknown>) => {
    series.push({ kind, props })
    return null
  }
  return {
    ResponsiveContainer: pass, ComposedChart: pass, BarChart: pass, AreaChart: pass, LineChart: pass, PieChart: pass,
    Area: recorder('Area'), Bar: recorder('Bar'), Line: recorder('Line'),
    XAxis: none, YAxis: none, Tooltip: none, Legend: none, Cell: none, Pie: none, CartesianGrid: none,
  }
})

vi.mock('../../hooks/useAnimatedNumber', () => ({ useAnimatedNumber: (v: number) => v }))

import DashboardCharts from './DashboardCharts'
import { ThreatIntel } from '../../pages/ThreatIntel'

// Three hourly buckets, the case that used to be drawn as a smooth bell.
const hours: TimelineEntry[] = [
  { time: '2026-10-25 07:00:00', total: 120, blocked: 3 },
  { time: '2026-10-25 08:00:00', total: 1328, blocked: 41 },
  { time: '2026-10-25 09:00:00', total: 90, blocked: 0 },
]

// Interpolations that invent values between measured hours.
const CURVED = /monotone|natural|basis|cardinal|catmull|bump/i

function timelineSeries() {
  return series.filter((s) => s.props.dataKey === 'total' || s.props.dataKey === 'blocked')
}

function expectHourlyCountsNotCurved() {
  const found = timelineSeries()
  expect(found.map((s) => s.props.dataKey).sort()).toEqual(['blocked', 'total'])
  for (const s of found) {
    // Bars per hour, or a straight/step line: never an area through a curve.
    expect(['Bar', 'Line'], `${String(s.props.dataKey)} is drawn as ${s.kind}`).toContain(s.kind)
    if (s.kind === 'Line') expect(String(s.props.type ?? 'linear')).toMatch(/^(linear|step|stepBefore|stepAfter)$/)
    expect(String(s.props.type ?? '')).not.toMatch(CURVED)
  }
  // One y axis for both series: a second, unlabelled scale made a handful of
  // blocks as tall as a thousand requests.
  expect(new Set(found.map((s) => String(s.props.yAxisId ?? 0))).size).toBe(1)
}

describe('hourly timeline charts', () => {
  beforeEach(() => { series.length = 0 })
  afterEach(() => { vi.restoreAllMocks() })

  it('Dashboard draws hourly counts as bars on one axis', () => {
    render(<DashboardCharts chart={hours} />)
    expectHourlyCountsNotCurved()
  })

  it('Threat Intel draws hourly counts as bars on one axis', async () => {
    vi.spyOn(api, 'get').mockImplementation((url: string) =>
      Promise.resolve({ data: { status: 'success', data: url.startsWith('logs/timeline') ? hours : null } }))
    renderWithProviders(<ThreatIntel />)
    await waitFor(() => { expect(timelineSeries().length).toBeGreaterThan(0) })
    expectHourlyCountsNotCurved()
  })
})
