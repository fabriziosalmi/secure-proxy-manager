/**
 * A host name in monospace wraps only after a dot: the client detail's top
 * destinations broke "gsp57-ssl-background.ls.apple.c" from "om" (break-all),
 * and a source URL on Blacklists split its names the same way.
 */
import { expect, test, type Locator } from '@playwright/test';
import { mockApi } from './fixtures';

/** The text of each line an element is laid out on. */
async function lines(el: Locator): Promise<string[]> {
  return el.evaluate((node) => {
    const out: { top: number; text: string }[] = [];
    const walker = document.createTreeWalker(node, NodeFilter.SHOW_TEXT);
    for (let n = walker.nextNode(); n; n = walker.nextNode()) {
      const text = n.textContent ?? '';
      for (let i = 0; i < text.length; i++) {
        const r = document.createRange();
        r.setStart(n, i);
        r.setEnd(n, i + 1);
        const rect = r.getClientRects()[0];
        if (!rect) continue;
        const top = Math.round(rect.top);
        const last = out[out.length - 1];
        if (last && Math.abs(last.top - top) <= 2) last.text += text[i];
        else out.push({ top, text: text[i] });
      }
    }
    return out.map((l) => l.text);
  });
}

test.use({ viewport: { width: 1512, height: 805 } });

test.beforeEach(async ({ page }, info) => {
  test.skip(info.project.name !== 'desktop-1440', 'the viewport is set here, once');
  await mockApi(page);
});

test('no top destination of a client breaks inside a label', async ({ page }) => {
  await page.goto('/clients');
  const table = page.getByRole('table', { name: 'Top destinations of 10.20.0.109' });
  await expect(table).toBeVisible();
  const names = table.locator('tbody td:first-child');
  await expect(names.first()).toBeVisible();
  let wrapped = 0;
  for (const cell of await names.all()) {
    const parts = await lines(cell);
    if (parts.length > 1) wrapped += 1;
    for (const line of parts.slice(0, -1)) {
      expect(line, `"${parts.join('|')}" breaks inside a label`).toMatch(/\.$/);
    }
  }
  // The fixture's longest name does not fit on one line: the check above saw a wrap.
  expect(wrapped, 'no name wrapped, so nothing was checked').toBeGreaterThan(0);
});

test('a source URL on Blacklists breaks only after a dot or a slash', async ({ page }) => {
  await page.goto('/blacklists?tab=blocked-domains');
  const table = page.getByRole('table', { name: /^Sources of / });
  const urls = table.locator('td:first-child a');
  await expect(urls.first()).toBeVisible();
  for (const url of await urls.all()) {
    const parts = await lines(url);
    for (const line of parts.slice(0, -1)) {
      expect(line, `"${parts.join('|')}" breaks inside a name`).toMatch(/[./]$/);
    }
  }
});
