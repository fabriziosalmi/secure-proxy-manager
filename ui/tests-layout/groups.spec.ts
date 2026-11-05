/**
 * Client groups on the Clients page: the table fits its card at every width,
 * with the longest fixture group (a long name, an IPv6 member, every
 * restriction), so Edit and Delete are on screen without scrolling the table.
 * At 390 px it scrolled sideways inside the card: the schedule badge did not
 * wrap and the members column took the room.
 */
import { expect, test } from '@playwright/test';
import { mockApi } from './fixtures';

test('the client groups table fits its card', async ({ page }) => {
  await mockApi(page);
  await page.goto('/clients');
  const section = page.getByRole('region', { name: 'Client groups' });
  const table = section.getByRole('table', { name: 'Client groups' });
  await expect(table.getByText('Kids tablets and the shared family laptop')).toBeVisible();
  const fit = await table.evaluate((el) => ({ scroll: el.parentElement!.scrollWidth, client: el.parentElement!.clientWidth }));
  expect(fit.scroll, `the table is ${fit.scroll} px wide in ${fit.client} px`).toBeLessThanOrEqual(fit.client);
  const card = (await section.boundingBox())!;
  const del = (await section.getByRole('button', { name: 'Delete Kids tablets and the shared family laptop' }).boundingBox())!;
  expect(del.x + del.width, 'Delete ends past the card').toBeLessThanOrEqual(card.x + card.width);
});
