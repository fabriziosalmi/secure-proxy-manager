/**
 * The layout suite (tests-layout/): the UI from the Vite dev server, every
 * /api request answered by tests-layout/fixtures.ts, at the widths the pages
 * are used at. It measures what jsdom cannot (alignment, line breaks,
 * overflow), so a layout fix has a test that fails without it. No backend
 * is needed; tests-e2e/ is the suite that runs against a live stack.
 */
import { defineConfig, devices } from '@playwright/test';
import { TIME_ZONE } from './tests-layout/fixtures';

const PORT = 5199;

export default defineConfig({
  testDir: './tests-layout',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: 0,
  workers: process.env.CI ? 2 : undefined,
  reporter: process.env.CI ? [['list'], ['html', { open: 'never', outputFolder: 'playwright-report-layout' }]] : 'list',
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    timezoneId: TIME_ZONE,
    locale: 'it-IT',
    colorScheme: 'light',
    trace: 'retain-on-failure',
  },
  webServer: {
    command: `npm run dev -- --port ${PORT} --strictPort --host 127.0.0.1`,
    url: `http://127.0.0.1:${PORT}`,
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
  },
  projects: [
    { name: 'desktop-1440', use: { ...devices['Desktop Chrome'], viewport: { width: 1440, height: 1000 } } },
    { name: 'laptop-1250', use: { ...devices['Desktop Chrome'], viewport: { width: 1250, height: 900 } } },
    { name: 'phone-390', use: { ...devices['Desktop Chrome'], viewport: { width: 390, height: 844 } } },
  ],
});
