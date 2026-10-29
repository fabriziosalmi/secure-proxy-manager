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
  const rows = new Map<number, string[]>();
  for (const name of CARDS) {
    const box = (await page.getByRole('region', { name }).boundingBox())!;
    const top = Math.round(box.y);
    rows.set(top, [...(rows.get(top) ?? []), name]);
  }
  for (const names of rows.values()) expect(names.length, `a row holds ${names.join(', ')} alone`).toBeGreaterThan(1);
});
