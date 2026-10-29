/**
 * A time is never broken across lines: the Overview's latest blocks wrote
 * "2026-10-28" over "23:51" in a 72 px column, and the client detail split
 * "2026-10-29" from "08:51:30" at the end of a sentence.
 */
import { expect, test } from '@playwright/test';
import { mockApi } from './fixtures';
import { lineCount } from './measure';

test('every latest block time is on one line', async ({ page }) => {
  await mockApi(page);
  await page.goto('/');
  const latest = page.getByRole('region', { name: 'Latest blocks' });
  const times = latest.locator('li > span.font-mono');
  await expect(times).toHaveCount(3);
  for (const t of await times.all()) {
    expect(await lineCount(t), `"${await t.textContent()}" is broken across lines`).toBe(1);
  }
});

test('the first and the last request of a client are each on one line', async ({ page }, info) => {
  test.skip(info.project.name === 'phone-390', 'the detail opens in a drawer only when a client is picked');
  await mockApi(page);
  await page.goto('/clients');
  const panel = page.getByRole('region', { name: '10.20.0.109' });
  for (const label of ['First request', 'Last request']) {
    const value = panel.getByText(label, { exact: true }).locator('xpath=following-sibling::*[1]');
    await expect(value).toBeVisible();
    expect(await lineCount(value), `${label} is broken across lines`).toBe(1);
  }
});
