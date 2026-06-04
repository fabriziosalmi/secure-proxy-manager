import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:5001', // Local backend for dev
        changeOrigin: true,
      }
    }
  },
  build: {
    modulePreload: {
      // recharts (vendor-charts, ~110KB gzip) is only used by the lazy Dashboard
      // and ThreatIntel routes. Vite would otherwise <link rel=modulepreload> it
      // from the entry HTML, pulling it onto EVERY first paint (Logs, Settings,
      // Audit…) and defeating the lazy boundary. Drop it from the preload set so
      // those routes fetch it on demand; the chunk stays shared and cacheable.
      resolveDependencies: (_filename: string, deps: string[]) =>
        deps.filter((dep) => !dep.includes('vendor-charts')),
    },
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes('node_modules/react-router-dom')) return 'vendor-react';
          if (id.includes('node_modules/react-dom')) return 'vendor-react';
          if (id.includes('node_modules/react')) return 'vendor-react';
          if (id.includes('node_modules/recharts')) return 'vendor-charts';
          if (id.includes('node_modules/@tanstack/react-query')) return 'vendor-query';
        },
      },
    },
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: './src/test/setup.ts',
    css: true,
    include: ['src/**/*.test.{ts,tsx}'],
  }
})
