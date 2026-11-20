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
    ['outcome', bar.getByRole('combobox', { name: 'Outcome' })],
    ['client', bar.getByRole('combobox', { name: 'Client' })],
    ['rule', bar.getByRole('combobox', { name: 'Rule' })],
    ['time range', bar.getByRole('combobox', { name: 'Time range' })],
    ['internal traffic', bar.getByRole('switch', { name: 'Show internal traffic' })],
  ];
}

/**
 * What the shown option of a select needs and what the select has: the
 * browser measures a copy of the select holding only that option, at its
 * natural width.
 */
function fitOf(select: Locator): Promise<{ text: string; need: number; has: number }> {
  return select.evaluate((el) => {
    const s = el as HTMLSelectElement;
    const copy = s.cloneNode(false) as HTMLSelectElement;
    copy.appendChild(s.options[s.selectedIndex].cloneNode(true));
    copy.style.width = 'auto';
    copy.style.maxWidth = 'none';
    copy.style.position = 'absolute';
    s.parentElement!.appendChild(copy);
    const need = copy.getBoundingClientRect().width;
    copy.remove();
    return { text: s.options[s.selectedIndex].text, need, has: s.getBoundingClientRect().width };
  });
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

    // "Search host or U" at 1280: the native clear button of a search field
    // takes part of its width, so the placeholder is typed in and measured
    // with that button shown.
    test('the search box shows its whole placeholder', async ({ page }) => {
      const box = page.getByRole('searchbox', { name: 'Search destinations' });
      const placeholder = (await box.getAttribute('placeholder'))!;
      await box.fill(placeholder);
      const fit = await box.evaluate((el) => ({ scroll: el.scrollWidth, client: el.clientWidth }));
      expect(fit.scroll, `"${placeholder}" needs ${fit.scroll} px, the box has ${fit.client}`).toBeLessThanOrEqual(fit.client);
    });

    // "Any outco…": a select is compact while it shows its own name, and
    // that name must still fit.
    test('with nothing chosen, each select shows its whole name', async ({ page }) => {
      const bar = page.getByRole('region', { name: 'Filters' });
      for (const [name, want] of [['Outcome', 'Any outcome'], ['Client', 'All clients'], ['Rule', 'Any rule'], ['Time range', 'Any time']]) {
        const fit = await fitOf(bar.getByRole('combobox', { name }));
        expect(fit.text).toBe(want);
        expect(fit.has, `"${fit.text}" needs ${Math.round(fit.need)} px, the ${name} select has ${Math.round(fit.has)}`).toBeGreaterThanOrEqual(fit.need - 0.5);
      }
    });

    // "10.20.0.1…" and "Domain b…": a chosen client or rule was cut to the
    // compact width that fits the select's own name.
    test('a chosen outcome, client and rule show their whole value', async ({ page }) => {
      await page.goto('/logs?outcome=upstream_error&client=10.20.0.109&rule=domain_blacklist');
      await expect(page.getByRole('table', { name: 'Access log requests' })).toBeVisible();
      await page.waitForLoadState('networkidle');
      const bar = page.getByRole('region', { name: 'Filters' });
      const values: Record<string, string> = { Outcome: 'upstream_error', Client: '10.20.0.109', Rule: 'domain_blacklist' };
      for (const [name, want] of [['Outcome', 'Upstream error'], ['Client', '10.20.0.109'], ['Rule', 'Domain blacklist (proxy)']]) {
        const select = bar.getByRole('combobox', { name });
        await expect(select).toHaveValue(values[name]);
        const fit = await fitOf(select);
        expect(fit.text).toBe(want);
        expect(fit.has, `"${fit.text}" needs ${Math.round(fit.need)} px, the ${name} select has ${Math.round(fit.has)}`).toBeGreaterThanOrEqual(fit.need - 0.5);
      }
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
