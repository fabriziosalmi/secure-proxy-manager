import { test, expect } from '@playwright/test';

const USERNAME = process.env.BASIC_AUTH_USERNAME || 'admin';
const PASSWORD = process.env.BASIC_AUTH_PASSWORD || 'admin-12345';

// The SPA renders the Dashboard at the index route ("/") after authentication;
// there is no "/dashboard" route, and a successful login swaps the component tree
// in place without a URL change. Assertions therefore key off visible headings
// and the post-login routes that actually exist (see ui/src/App.tsx).
test.describe('Secure Proxy Manager E2E', () => {
  test('logs in and navigates the main sections', async ({ page }) => {
    await page.goto('/');

    // Unauthenticated: the Login page is shown in place at "/".
    const passwordField = page.locator('#password');
    await expect(passwordField).toBeVisible();
    await expect(page.locator('#username')).toBeVisible();

    await page.locator('#username').fill(USERNAME);
    await passwordField.fill(PASSWORD);
    await page.getByRole('button', { name: /sign in/i }).click();

    // Auth succeeds: login fields disappear and the Dashboard renders at "/".
    await expect(passwordField).toBeHidden();
    await expect(page).toHaveURL(/:\/\/[^/]+\/?$/);
    await expect(
      page.getByRole('heading', { level: 1, name: 'Dashboard' }).first(),
    ).toBeVisible();

    // Sidebar navigation -> Clients ("/clients").
    await page.getByRole('link', { name: 'Clients' }).click();
    await expect(page).toHaveURL(/\/clients\/?$/);
    await expect(page.getByRole('heading', { level: 1, name: 'Clients' })).toBeVisible();

    // Sidebar navigation -> Settings ("/settings").
    await page.getByRole('link', { name: 'Settings' }).click();
    await expect(page).toHaveURL(/\/settings\/?$/);
    await expect(page.getByRole('heading', { level: 1, name: 'Settings' })).toBeVisible();

    // Back to the Dashboard via the sidebar.
    await page.getByRole('link', { name: 'Dashboard' }).click();
    await expect(page).toHaveURL(/:\/\/[^/]+\/?$/);
    await expect(
      page.getByRole('heading', { level: 1, name: 'Dashboard' }).first(),
    ).toBeVisible();
  });
});
