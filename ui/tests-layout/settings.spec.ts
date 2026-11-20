/**
 * Settings rows read as one line of sight: a switch sat at x 1427 while its
 * label started at x 561 on a 1512 px screen. Each row (label, description,
 * control) is held to a readable width, the same in every section. The help
 * under a narrow field ("Refresh provider lists every (hours)", "Keep logs
 * for (days)") was squeezed to the field's 240 px in 12 px type, while every
 * other description spans its row in 14 px: one rule now.
 */
import { expect, test } from '@playwright/test';
import { mockApi } from './fixtures';

const SECTIONS = ['overview', 'access', 'filtering', 'inspection', 'alerts', 'logs', 'admin', 'engine', 'appearance'];
/** max-w-3xl: the readable width of a settings row. */
const ROW = 768;

test.use({ viewport: { width: 1512, height: 805 } });

test.beforeEach(async ({ page }, info) => {
  test.skip(info.project.name !== 'desktop-1440', 'the viewport is set here, once');
  await mockApi(page);
});

test('every switch sits within a readable row of its label, at the same x in every section', async ({ page }) => {
  test.setTimeout(60_000);
  const rights = new Map<string, number>();
  let seen = 0;
  for (const s of SECTIONS) {
    await page.goto(`/settings/${s}`);
    await expect(page.getByRole('heading', { level: 2 }).first()).toBeVisible();
    await page.waitForLoadState('networkidle');
    const rows = await page.locator('main [role="switch"][aria-labelledby]').evaluateAll((switches) => switches.map((sw) => {
      const label = document.getElementById(sw.getAttribute('aria-labelledby')!.split(' ')[0])!;
      const card = sw.closest('section')!.getBoundingClientRect();
      const b = sw.getBoundingClientRect();
      return { name: label.textContent ?? '', labelLeft: label.getBoundingClientRect().left, right: b.right, cardLeft: card.left, visible: b.width > 0 };
    }));
    for (const r of rows.filter((x) => x.visible)) {
      seen += 1;
      expect(r.right - r.labelLeft, `${s}: "${r.name}" switch is ${Math.round(r.right - r.labelLeft)} px from its label`).toBeLessThanOrEqual(ROW + 0.5);
      // Rows of one depth line up: the switch's offset from the card it is in.
      rights.set(`${s}: ${r.name}`, Math.round(r.right - r.cardLeft));
    }
  }
  expect(seen, 'no switch was measured').toBeGreaterThan(10);
  const offsets = new Set(rights.values());
  expect(offsets.size, `switch offsets: ${[...rights].map(([k, v]) => `${k}=${v}`).join(', ')}`).toBe(1);
});

for (const [section, field] of [['filtering', 'Refresh provider lists every (hours)'], ['logs', 'Keep logs for (days)']] as const) {
  test(`${section}: the help under "${field}" spans its row in the size of every other description`, async ({ page }) => {
    await page.goto(`/settings/${section}`);
    const input = page.getByLabel(field, { exact: true });
    await expect(input).toBeVisible();
    const hintId = (await input.getAttribute('aria-describedby'))!.split(' ')[0];
    const hint = page.locator(`[id="${hintId}"]`);
    const toggleHelp = page.locator('main [role="switch"]').first().evaluate((sw) => {
      const help = document.getElementById(sw.getAttribute('aria-describedby')!.split(' ')[0])!;
      return getComputedStyle(help).fontSize;
    });
    const hintBox = (await hint.boundingBox())!;
    const inputBox = (await input.boundingBox())!;
    expect(await hint.evaluate((el) => getComputedStyle(el).fontSize)).toBe(await toggleHelp);
    expect(hintBox.width, `the help is ${hintBox.width} px wide under a ${inputBox.width} px field`).toBeGreaterThan(inputBox.width + 200);
    expect(hintBox.width).toBeLessThanOrEqual(ROW + 0.5);
  });
}

// Investigated, not a defect: a second section looked selected only while
// the pointer was on it (its hover ground) or while the keyboard focus was
// on it. Once the pointer leaves, one section is highlighted.
test('after picking a section with the pointer, only that section is highlighted once the pointer leaves', async ({ page }) => {
  await page.goto('/settings/filtering');
  const nav = page.getByRole('navigation', { name: 'Settings sections' });
  await nav.getByRole('link', { name: 'Alerts' }).click();
  await page.mouse.move(900, 700);
  await expect(nav.getByRole('link', { name: 'Alerts' })).toHaveAttribute('aria-current', 'page');
  await expect.poll(() => nav.locator('a').evaluateAll((links) => links
    .filter((a) => getComputedStyle(a).backgroundColor !== 'rgba(0, 0, 0, 0)' || a.matches(':focus-visible'))
    .map((a) => a.textContent))).toEqual(['Alerts']);
});
