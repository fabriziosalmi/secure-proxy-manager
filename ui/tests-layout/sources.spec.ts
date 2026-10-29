/**
 * "Where the entries came from": a source's URL or explanation is shown
 * whole, not cut with an ellipsis (2 of 3 URLs at 1440 px, all 3 at 1250,
 * and "Added before this release recorded where entries com..."), and
 * "Remove batch" has one space, not the 6 px flex gap between two pieces.
 */
import { expect, test } from '@playwright/test';
import { mockApi } from './fixtures';

for (const tab of ['blocked-ips', 'blocked-domains']) {
  test(`${tab}: every source detail is shown whole`, async ({ page }, info) => {
    test.skip(info.project.name === 'phone-390', 'on a phone a long URL takes its three lines and keeps the rest in its title');
    await mockApi(page);
    await page.goto(`/blacklists?tab=${tab}`);
    const table = page.getByRole('table', { name: /^Sources of / });
    const details = table.locator('td:first-child :is(a, span.text-xs):not(.sm\\:hidden)');
    await expect(details.first()).toBeVisible();
    for (const d of await details.all()) {
      const cut = await d.evaluate((el) => el.scrollHeight > el.clientHeight + 1 || el.scrollWidth > el.clientWidth + 1);
      expect(cut, `"${await d.textContent()}" is cut`).toBe(false);
    }
  });
}

test('Remove batch is written with one ordinary space', async ({ page }, info) => {
  test.skip(info.project.name === 'phone-390', 'on a phone the button reads Remove');
  await mockApi(page);
  await page.goto('/blacklists?tab=blocked-domains');
  const btn = page.getByRole('button', { name: /^Remove batch: StevenBlack/ });
  const gap = await btn.evaluate((el) => {
    const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT);
    const rects: DOMRect[] = [];
    for (let n = walker.nextNode(); n; n = walker.nextNode()) {
      const text = n.textContent ?? '';
      const r = document.createRange();
      // The visible letters of each piece: "Remove", then "batch" after its space.
      const start = text.length - text.trimStart().length;
      r.setStart(n, start);
      r.setEnd(n, text.length);
      rects.push(r.getBoundingClientRect());
    }
    return rects.length === 2 ? rects[1].left - rects[0].right : null;
  });
  const space = await btn.evaluate((el) => {
    const c = document.createElement('canvas').getContext('2d')!;
    c.font = getComputedStyle(el).font;
    return c.measureText(' ').width;
  });
  expect(gap, 'the gap between "Remove" and "batch"').not.toBeNull();
  // The flex gap was 6 px, more than twice a space; a space renders a little wider than measureText says.
  expect(gap!).toBeLessThan(space * 1.5);
});
