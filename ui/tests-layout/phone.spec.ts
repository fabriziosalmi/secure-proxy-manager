/**
 * On a phone, what a page is for stays on the screen. The four Blacklists
 * tabs went onto three lines, and the access log put each request's outcome
 * past the right edge, reachable only by scrolling the table.
 */
import { expect, test } from '@playwright/test';
import { mockApi } from './fixtures';

const phoneOnly = (project: string) => test.skip(project !== 'phone-390', 'a phone-width defect');

test('the Blacklists tabs stay on one line', async ({ page }, info) => {
  phoneOnly(info.project.name);
  await mockApi(page);
  await page.goto('/blacklists');
  const tabs = page.getByRole('tab');
  await expect(tabs).toHaveCount(4);
  const tops = new Set<number>();
  for (const t of await tabs.all()) tops.add(Math.round((await t.boundingBox())!.y));
  expect([...tops], 'the tabs sit on more than one line').toHaveLength(1);
  // The selected tab is in view; the others scroll within the tab list.
  const selected = page.getByRole('tab', { selected: true });
  const box = (await selected.boundingBox())!;
  expect(box.x).toBeGreaterThanOrEqual(0);
  expect(box.x + box.width).toBeLessThanOrEqual(390);
});

test('the selected Blacklists tab is scrolled into view', async ({ page }, info) => {
  phoneOnly(info.project.name);
  await mockApi(page);
  await page.goto('/blacklists?tab=allowed-domains');
  const box = (await page.getByRole('tab', { selected: true }).boundingBox())!;
  expect(box.x).toBeGreaterThanOrEqual(0);
  expect(box.x + box.width, 'the selected tab ends past the screen').toBeLessThanOrEqual(390);
});

test('each access log row shows its destination and its outcome without scrolling', async ({ page }, info) => {
  phoneOnly(info.project.name);
  await mockApi(page);
  await page.goto('/logs');
  const table = page.getByRole('table').first();
  const rows = table.getByRole('row');
  await expect(rows.nth(1)).toBeVisible();
  const rowList = (await rows.all()).slice(1);
  expect(rowList.length).toBeGreaterThan(1);
  for (const row of rowList) {
    // The destination is the row's button; the outcome is its badge, the
    // rule that blocked it or "Allowed".
    const destination = row.getByRole('button').first();
    const outcome = row.locator('[data-tone]').filter({ visible: true }).first();
    for (const [what, el] of [['destination', destination], ['outcome', outcome]] as const) {
      await expect(el).toBeVisible();
      const b = (await el.boundingBox())!;
      expect(b.x, `the ${what} starts off the screen`).toBeGreaterThanOrEqual(0);
      expect(b.x + b.width, `the ${what} ends past the screen`).toBeLessThanOrEqual(390);
    }
    const scroller = table.locator('xpath=..');
    expect(await scroller.evaluate((el) => el.scrollWidth - el.clientWidth), 'the table scrolls sideways').toBe(0);
  }
});
