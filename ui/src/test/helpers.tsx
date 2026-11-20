import { vi, expect } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { BrowserRouter } from 'react-router'
import { render } from '@testing-library/react'
import type { ReactElement } from 'react'
import { ThemeProvider } from '../components/ThemeProvider'

export function createTestQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0 },
      mutations: { retry: false },
    },
  })
}

export function renderWithProviders(ui: ReactElement) {
  const queryClient = createTestQueryClient()
  return render(
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <BrowserRouter>{ui}</BrowserRouter>
      </ThemeProvider>
    </QueryClientProvider>
  )
}

/**
 * Run in the Europe/Rome time zone (UTC+2 in July, UTC+1 in January) until
 * the returned function is called. Backend timestamps are UTC with no zone
 * marker, so a page that reads them as local time is off by those hours.
 */
export function setRomeTimeZone(): () => void {
  vi.stubEnv('TZ', 'Europe/Rome')
  return () => { vi.unstubAllEnvs() }
}

/**
 * Run as in an Italian browser: any number or Intl formatter that names no
 * locale groups thousands with a dot (50.772). A page that writes counts
 * through lib/format still shows 50,772. Undone by vi.restoreAllMocks().
 */
export function simulateItalianLocale() {
  type Locales = Intl.LocalesArgument
  const real = Intl.NumberFormat
  vi.spyOn(Intl, 'NumberFormat').mockImplementation(function (locale?: Locales, opts?: Intl.NumberFormatOptions) {
    return new real(locale ?? 'it-IT', opts)
  } as unknown as typeof Intl.NumberFormat)
  vi.spyOn(Number.prototype, 'toLocaleString').mockImplementation(function (this: number, locale?: Locales, opts?: Intl.NumberFormatOptions) {
    return new real(locale ?? 'it-IT', opts).format(this)
  })
}

// A length the components write as `max(<floor>px, <percent>%)`, read back
// from an element's style. jsdom 31 serializes the percentage to six
// significant digits (60.5333%, not 60.53333333333333%), so the percentage is
// compared as a number, to three decimals, and the floor exactly.
export function expectMaxLength(value: string, floorPx: number, percent: number) {
  const m = /^max\((\d+(?:\.\d+)?)px, (\d+(?:\.\d+)?)%\)$/.exec(value)
  expect(m, `"${value}" is not max(<n>px, <n>%)`).not.toBeNull()
  expect(Number(m![1])).toBe(floorPx)
  expect(Number(m![2])).toBeCloseTo(percent, 3)
}
