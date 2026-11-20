/**
 * The access log's filters fit on one row at the widths the page is read at:
 * "Until" used to wrap alone onto a second row with the internal-traffic
 * switch. With Custom range picked, the two times take a row of their own
 * below, inside the page.
 */
import { expect, test, type Locator, type Page } from '@playwright/test';
import { mockApi } from './fixtures';

function controls(page: Page): [string, Locator][] {
  const bar = page.getByRole('region', { name: 'Filters' });
  return [
    ['search', bar.getByRole('searchbox', { name: 'Search destinations' })],
    ['outcome', bar.getByRole('group', { name: 'Outcome' })],
    ['client', bar.getByRole('combobox', { name: 'Client' })],
    ['rule', bar.getByRole('combobox', { name: 'Rule' })],
    ['time range', bar.getByRole('combobox', { name: 'Time range' })],
    ['internal traffic', bar.getByRole('switch', { name: 'Show internal traffic' })],
  ];
}

for (const viewport of [{ width: 1512, height: 805 }, { width: 1280, height: 800 }]) {
  test.describe(`${viewport.width}x${viewport.height}`, () => {
    test.use({ viewport });
    test.beforeEach(async ({ page }, info) => {
      test.skip(info.project.name !== 'desktop-1440', 'the viewport is set here, once');
      await mockApi(page);
      await page.goto('/logs');
      await expect(page.getByRole('table', { name: 'Access log requests' })).toBeVisible();
      await page.waitForLoadState('networkidle');
    });

    test('the filters sit on one row and nothing overflows', async ({ page }) => {
      const bar = page.getByRole('region', { name: 'Filters' });
      const barBox = (await bar.boundingBox())!;
      const rows = new Set<number>();
      for (const [name, el] of controls(page)) {
        await expect(el, name).toBeVisible();
        const b = (await el.boundingBox())!;
        rows.add(Math.round(b.y + b.height / 2));
        expect(b.x + b.width, `${name} ends past the filter bar`).toBeLessThanOrEqual(barBox.x + barBox.width + 0.5);
      }
      expect([...rows], 'the filters sit on more than one row').toHaveLength(1);
      expect(await bar.evaluate((el) => el.scrollWidth - el.clientWidth), 'the filter bar scrolls sideways').toBeLessThanOrEqual(0);
    });

    test('a custom range puts its two times on a row of their own, inside the page', async ({ page }) => {
      await page.getByRole('combobox', { name: 'Time range' }).selectOption('custom');
      const from = page.getByLabel('From');
      const until = page.getByLabel('Until');
      await expect(from).toBeVisible();
      const fromBox = (await from.boundingBox())!;
      const untilBox = (await until.boundingBox())!;
      const rangeBox = (await page.getByRole('combobox', { name: 'Time range' }).boundingBox())!;
      expect(Math.round(fromBox.y + fromBox.height / 2), 'From and Until on one row').toBe(Math.round(untilBox.y + untilBox.height / 2));
      expect(fromBox.y, 'the times are below the filter row').toBeGreaterThan(rangeBox.y + rangeBox.height);
      const main = (await page.locator('main').boundingBox())!;
      expect(untilBox.x + untilBox.width).toBeLessThanOrEqual(main.x + main.width);
    });
  });
}
