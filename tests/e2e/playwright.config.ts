import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: '.',
  testMatch: '**/*.spec.ts',
  timeout: 60_000,
  expect: { timeout: 15_000 },
  retries: process.env.CI ? 1 : 0,
  workers: 1, // serial — tests share DB state

  reporter: [
    ['list'],
    ['html', { open: 'never', outputFolder: '/test-results/html' }],
    ['json', { outputFile: '/test-results/results.json' }],
  ],

  use: {
    baseURL: process.env.BASE_URL ?? 'https://localhost:8443',
    // The web serves only HTTPS (HTTP 8011 301-redirects everything except
    // /health); accept its self-signed cert.
    ignoreHTTPSErrors: true,
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
    trace: 'on-first-retry',
  },

  // No globalSetup / storageState: auth is injected per-test via addInitScript
  // into localStorage (where the app reads the JWT).

  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],

  outputDir: '/test-results/artifacts',
});
