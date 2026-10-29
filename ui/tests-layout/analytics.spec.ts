/**
 * The four smaller Analytics cards fill their rows: at 1440 px three fitted
 * on a row and "Downloads by file type" stood alone on the next.
 */
import { expect, test } from '@playwright/test';
import { mockApi } from './fixtures';

const CARDS = ['WAF rule matches', 'Cloud services in use', 'Traffic by kind of service', 'Downloads by file type'];

test('no row of the four smaller cards holds a card alone', async ({ page }, info) => {
  test.skip(info.project.name === 'phone-390', 'one card per row on a phone');
  await mockApi(page);
  await page.goto('/analytics');
  // The charts above the grid load on their own and push it down. Measured
  // one card at a time, a card read before that shift and its neighbour read
  // after it sat on two rows, so the cards are read once every section has
  // loaded, in one pass over the same layout.
  for (const name of CARDS) await expect(page.getByRole('region', { name })).toBeVisible();
  await expect(page.getByRole('status').filter({ hasText: /^Loading/ })).toHaveCount(0);
  const tops = await page.evaluate((names) => names.map((name) => {
    const heading = [...document.querySelectorAll('h2, h3')].find((h) => h.textContent === name);
    const card = heading?.closest('section');
    return card ? Math.round(card.getBoundingClientRect().top) : null;
  }), CARDS);
  expect(tops, 'each card is found by its heading').not.toContain(null);
  const rows = new Map<number, string[]>();
  CARDS.forEach((name, i) => rows.set(tops[i]!, [...(rows.get(tops[i]!) ?? []), name]));
  for (const names of rows.values()) expect(names.length, `a row holds ${names.join(', ')} alone`).toBeGreaterThan(1);
});
