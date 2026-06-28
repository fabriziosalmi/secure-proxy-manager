import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { BrowserRouter } from 'react-router-dom'
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
