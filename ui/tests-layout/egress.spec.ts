/**
 * The egress provider table fits its card: at 1250 px its seven columns
 * scrolled sideways inside the card and cut "Refresh now" at the edge.
 */
import { expect, test } from '@playwright/test';
import { mockApi } from './fixtures';

test('the provider table fits its card, actions included', async ({ page }, info) => {
  test.skip(info.project.name === 'phone-390', 'on a phone a table scrolls inside its own box by design');
  await mockApi(page);
  await page.goto('/egress');
  const table = page.getByRole('table', { name: 'Provider lists' });
  await expect(table.getByText('amazon', { exact: true })).toBeVisible();
  const overflow = await table.evaluate((el) => {
    const box = el.parentElement!;
    return box.scrollWidth - box.clientWidth;
  });
  expect(overflow, 'px the table runs past its card').toBeLessThanOrEqual(0);
  const card = page.getByRole('region', { name: 'Provider lists' });
  const cardBox = (await card.boundingBox())!;
  for (const b of await table.getByRole('button').all()) {
    const box = (await b.boundingBox())!;
    expect(box.x + box.width, `${await b.getAttribute('aria-label')} ends inside the card`).toBeLessThanOrEqual(cardBox.x + cardBox.width);
  }
});
