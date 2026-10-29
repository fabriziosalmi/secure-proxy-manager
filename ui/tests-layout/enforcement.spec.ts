/**
 * Every value of the Enforcement card starts on its term's line and ends at
 * the card's right edge. A value with an explanation under it ("Networks
 * Squid loads 32,215, merged from ...") or a long one ("Limit 1,000,000
 * entries (SPM_DNS_...)") wrapped under its term and stopped short of the
 * edge: 93 px at 1440, 30 at 1250 and 46 at 390 for 32,215.
 */
import { expect, test } from '@playwright/test';
import { mockApi } from './fixtures';
import { rightGap } from './measure';

for (const tab of ['blocked-ips', 'blocked-domains', 'allowed-domains']) {
  test(`${tab}: every Enforcement value sits on its term's line and ends at the right edge`, async ({ page }) => {
    await mockApi(page);
    await page.goto(`/blacklists?tab=${tab}`);
    const card = page.getByRole('region', { name: 'Enforcement' });
    const dl = card.locator('dl');
    await expect(dl).toBeVisible();
    // The value cells only: a note spans both columns and is left-aligned.
    const values = dl.locator('dt + dd');
    const n = await values.count();
    expect(n).toBeGreaterThan(1);
    for (let i = 0; i < n; i += 1) {
      const dd = values.nth(i);
      const term = await dd.evaluate((el) => el.previousElementSibling?.textContent ?? '');
      expect(await rightGap(dd, dl), `"${term}" ends short of the right edge`).toBeLessThanOrEqual(1);
      const drop = await dd.evaluate((el) => Math.round(el.getBoundingClientRect().top - (el.previousElementSibling?.getBoundingClientRect().top ?? 0)));
      expect(drop, `"${term}" drops under its term`).toBeLessThanOrEqual(2);
    }
  });
}
