/**
 * Global setup: performs one login via API + UI to capture the sessionStorage token
 * into a storageState snapshot. All tests reuse this snapshot so they start
 * already authenticated without repeating the login flow.
 */
import { chromium, type FullConfig } from '@playwright/test';

export default async function globalSetup(config: FullConfig) {
  const baseURL = config.projects[0].use.baseURL ?? 'http://localhost:8011';
  const username = process.env.TEST_USERNAME ?? 'testadmin';
  const password = process.env.TEST_PASSWORD ?? 'TestP@ss123!';

  const browser = await chromium.launch();
  const context = await browser.newContext({
    baseURL,
    launchOptions: {
      args: [`--unsafely-treat-insecure-origin-as-secure=${baseURL}`],
    },
  } as Parameters<typeof browser.newContext>[0]);
  const page = await context.newPage();

  // 1. Obtain a token via the API (fast — no UI interaction needed)
  const res = await page.request.post(`${baseURL}/api/auth/login`, {
    data: { username, password },
  });

  if (!res.ok()) {
    const body = await res.text();
    await browser.close();
    throw new Error(
      `Global setup: login failed (${res.status()}): ${body}\n` +
      `Make sure TEST_USERNAME / TEST_PASSWORD env vars are set correctly.`
    );
  }

  const { token } = (await res.json()) as { token: string };

  // 2. Open the app and inject the token into sessionStorage
  await page.goto('/');
  await page.evaluate((t: string) => sessionStorage.setItem('auth_token', t), token);

  // 3. Reload so the React app picks up the token and renders the main layout
  await page.reload();
  await page.waitForSelector('text=Configure your device', { timeout: 20_000 });

  // 4. Save the storage state (includes sessionStorage) for test reuse
  await context.storageState({ path: '/tmp/e2e-auth.json' });

  await browser.close();
  console.log('\n[global-setup] Auth state saved to /tmp/e2e-auth.json\n');
}
