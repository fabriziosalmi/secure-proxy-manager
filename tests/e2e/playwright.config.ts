import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: '.',
  testMatch: '**/*.spec.ts',
  timeout: 60_000,
  expect: { timeout: 15_000 },
  retries: process.env.CI ? 2 : 1,
  workers: 1, // serial — tests share DB state

  reporter: [
    ['list'],
    ['html', { open: 'never', outputFolder: '/test-results/html' }],
    ['json', { outputFile: '/test-results/results.json' }],
  ],

  use: {
    baseURL: process.env.BASE_URL ?? 'http://localhost:8011',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
    trace: 'on-first-retry',
    // allow clipboard API in insecure origins (http)
    launchOptions: {
      args: ['--unsafely-treat-insecure-origin-as-secure=http://web:8011,http://localhost:8011'],
    },
  },

  // No globalSetup / storageState: auth is injected per-test via addInitScript
  // (Playwright storageState only persists localStorage, not sessionStorage,
  //  and the app uses sessionStorage for the JWT token)

  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],

  outputDir: '/test-results/artifacts',
});
