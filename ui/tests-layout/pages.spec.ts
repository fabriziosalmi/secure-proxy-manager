/**
 * Every page renders against the fixed API answers at each width of the
 * suite, without asking for an API the fixtures do not answer and without
 * the page itself scrolling sideways (a table may scroll inside its own box).
 * Checks for one defect go in a spec of their own, next to this one.
 */
import { expect, test } from '@playwright/test';
import { mockApi } from './fixtures';
import { pageOverflow } from './measure';

const PAGES: { path: string; heading: string }[] = [
  { path: '/', heading: 'Overview' },
  { path: '/analytics', heading: 'Analytics' },
  { path: '/logs', heading: 'Access logs' },
  { path: '/clients', heading: 'Clients' },
  { path: '/blacklists', heading: 'Blacklists' },
  { path: '/blacklists?tab=blocked-domains', heading: 'Blacklists' },
  { path: '/blacklists?tab=allowed-domains', heading: 'Blacklists' },
  { path: '/egress', heading: 'Default-deny allowlist' },
  { path: '/settings/overview', heading: 'Settings' },
  { path: '/audit', heading: 'Audit log' },
];

for (const { path, heading } of PAGES) {
  test(`${path} renders and the page does not scroll sideways`, async ({ page }) => {
    const unknown = await mockApi(page);
    await page.goto(path);
    await expect(page.getByRole('heading', { level: 1, name: heading })).toBeVisible();
    await page.waitForLoadState('networkidle');
    const { scrollWidth, clientWidth } = await pageOverflow(page);
    expect(scrollWidth, `the page is ${scrollWidth} px wide in a ${clientWidth} px box`).toBeLessThanOrEqual(clientWidth);
    expect([...unknown], 'API paths the fixtures do not answer').toEqual([]);
  });
}
