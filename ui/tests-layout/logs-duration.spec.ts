/**
 * The access log's Duration column (elapsed_ms) at 1280 px, the laptop width
 * it was added for, with its widest values in the rows ("Not recorded",
 * "45.3 s", "1.2 h"): the page does not scroll sideways, the table scrolls
 * inside its own box, and no duration is cut or wrapped.
 */
import { expect, test } from '@playwright/test';
import { mockApi } from './fixtures';
import { isCut, lineCount, pageOverflow } from './measure';

test.use({ viewport: { width: 1280, height: 900 } });

test('the Duration column fits its values at 1280 px without the page scrolling sideways', async ({ page }) => {
  const unknown = await mockApi(page);
  await page.goto('/logs');
  await expect(page.getByRole('heading', { level: 1, name: 'Access logs' })).toBeVisible();
  const table = page.getByRole('table');
  await expect(table.getByRole('columnheader', { name: 'Duration' })).toBeAttached();

  for (const text of ['12 ms', '850 ms', '2.4 s', '45.3 s', '1.2 h', '3.5 min', 'Not recorded']) {
    const cell = table.getByRole('cell', { name: text, exact: true });
    await cell.scrollIntoViewIfNeeded();
    await expect(cell).toBeVisible();
    expect(await isCut(cell), `${text} is cut`).toBe(false);
    expect(await lineCount(cell), `${text} wraps`).toBe(1);
  }

  const { scrollWidth, clientWidth } = await pageOverflow(page);
  expect(scrollWidth, `the page is ${scrollWidth} px wide in a ${clientWidth} px box`).toBeLessThanOrEqual(clientWidth);
  expect([...unknown], 'API paths the fixtures do not answer').toEqual([]);
});
