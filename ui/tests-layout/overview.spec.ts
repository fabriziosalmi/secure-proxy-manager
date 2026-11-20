/**
 * The Overview's four cards are alike: each is one link to the page that
 * lists what it counts, with the same hover and focus, and no card's label is
 * underlined like a text link (Blocked was, under the pointer, and Client
 * requests linked nowhere). With nothing blocked in the window, one line says
 * so instead of three empty cards, and the chart has the row to itself.
 */
import { expect, test, type Page } from '@playwright/test';
import { answer, mockApi } from './fixtures';

test.use({ viewport: { width: 1512, height: 805 } });

test.beforeEach(async ({ page }, info) => {
  test.skip(info.project.name !== 'desktop-1440', 'the viewport is set here, once');
  // The hover and focus styles are read as they end, not mid-transition.
  await page.emulateMedia({ reducedMotion: 'reduce' });
});

const CARDS = ['Client requests', 'Blocked', 'Active clients', 'Blacklist entries'];

async function cardStyle(page: Page, label: string) {
  return page.getByRole('region', { name: 'Last 24 hours at a glance' }).getByRole('link', { name: label }).evaluate((a) => {
    const card = a.closest('p')!.parentElement!;
    return {
      underline: getComputedStyle(a).textDecorationLine,
      border: getComputedStyle(card).borderColor,
      ring: getComputedStyle(a, '::after').boxShadow,
    };
  });
}

test('the four cards link alike: no underlined label, the same hover and the same focus ring', async ({ page }) => {
  await mockApi(page);
  await page.goto('/');
  const glance = page.getByRole('region', { name: 'Last 24 hours at a glance' });
  await expect(glance.getByRole('link')).toHaveCount(4);
  await page.waitForLoadState('networkidle');
  const rest = await cardStyle(page, 'Client requests');
  const hovered: string[] = [];
  for (const label of CARDS) {
    const link = glance.getByRole('link', { name: label });
    const box = (await link.locator('xpath=ancestor::p/..').boundingBox())!;
    // The middle of the card, away from its label: the whole card is the target.
    await page.mouse.move(box.x + box.width / 2, box.y + box.height - 12);
    await expect.poll(async () => (await cardStyle(page, label)).border, { message: `${label}: no hover state` }).not.toBe(rest.border);
    const s = await cardStyle(page, label);
    expect(s.underline, `${label}: label underlined on hover`).toBe('none');
    hovered.push(s.border);
    await page.mouse.move(1, 800);
  }
  expect(new Set(hovered).size, 'the cards hover differently').toBe(1);

  // A 2 px ring in a colour, around the card (the link's ::after covers it).
  const RING = /rgb\(\d+, \d+, \d+\) 0px 0px 0px 2px/;
  const rings: string[] = [];
  for (const label of CARDS) {
    const link = glance.getByRole('link', { name: label });
    await link.focus();
    await page.keyboard.press('Shift+Tab');
    await page.keyboard.press('Tab');
    await expect(link, `${label}: the keyboard did not reach the card`).toBeFocused();
    await expect.poll(async () => (await cardStyle(page, label)).ring, { message: `${label}: no focus ring around the card` }).toMatch(RING);
    rings.push((await cardStyle(page, label)).ring);
  }
  expect(new Set(rings).size, `the cards show different focus rings: ${rings.join(' | ')}`).toBe(1);
});

test('with nothing blocked, one line replaces the three blocked cards and the chart takes the row', async ({ page }) => {
  await mockApi(page);
  const base = answer(new URL('http://x/api/dashboard/summary')) as { status: string; data: Record<string, unknown> };
  await page.route('**/api/dashboard/summary', (route) => route.fulfill({
    json: { ...base, data: { ...base.data, last_24h_blocked: 0, top_blocked: [], recent_blocks: [], blocked_by_reason_24h: [] } },
  }));
  await page.goto('/');
  const quiet = page.getByRole('region', { name: 'Blocked requests' });
  await expect(quiet).toBeVisible();
  for (const gone of ['Blocked by rule', 'Most blocked destinations', 'Latest blocks']) {
    await expect(page.getByRole('region', { name: gone })).toHaveCount(0);
  }
  const chart = (await page.getByRole('region', { name: 'Requests per hour' }).boundingBox())!;
  const glance = (await page.getByRole('region', { name: 'Last 24 hours at a glance' }).boundingBox())!;
  expect(Math.abs(chart.width - glance.width), 'the chart is narrower than the row').toBeLessThanOrEqual(1);
  // One compact line, not a tall empty card.
  expect((await quiet.boundingBox())!.height).toBeLessThan(120);
});
