import { vi } from 'vitest'
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
