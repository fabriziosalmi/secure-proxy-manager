/**
 * The page band: the strip across the top of the main column that holds the
 * nav group, the page's h1 and its actions. Its bottom border continues the
 * line under the sidebar's brand header (same y, same height, same colour),
 * the h1 starts where the page's content starts, it stays at the top while
 * the page scrolls, and the content does not move sideways from one page to
 * the next, including onto a page too short to scroll (the 4 px scrollbar
 * used to make such a page 4 px wider). Measured at the two widths the pages
 * are reviewed at, with the sidebar expanded and collapsed.
 */
import { expect, test, type Page } from '@playwright/test';
import { mockApi } from './fixtures';

// Headless Chromium hides scrollbars (--hide-scrollbars), so a page that
// scrolls is as wide as one that does not and the shift this file guards
// against cannot be seen. Here the scrollbars take their room, as on a
// desktop browser with a mouse.
test.use({ launchOptions: { ignoreDefaultArgs: ['--hide-scrollbars'] } });

const SECTIONS = ['overview', 'access', 'filtering', 'inspection', 'alerts', 'logs', 'admin', 'engine', 'appearance'];
const ROUTES = ['/', '/analytics', '/logs', '/clients', '/blacklists', '/egress', ...SECTIONS.map((s) => `/settings/${s}`), '/audit'];

interface Measured {
  route: string;
  bandTop: number;
  bandBottom: number;
  bandHeight: number;
  bandBorder: string;
  brandBottom: number;
  brandBorder: string;
  h1Left: number;
  contentLeft: number;
  contentRight: number;
  firstBlockLeft: number;
  firstCardLeft: number | null;
  firstCard: string;
}

async function measure(page: Page, route: string): Promise<Measured> {
  await page.goto(route);
  const band = page.getByTestId('page-band');
  await expect(band.getByRole('heading', { level: 1 })).toBeVisible();
  await page.waitForLoadState('networkidle');
  // The entrance animation moves the page up 8 px; measure where it settles.
  await page.waitForTimeout(450);
  return page.evaluate((r) => {
    const rect = (el: Element) => el.getBoundingClientRect();
    const band = document.querySelector('[data-testid="page-band"]')!;
    const brand = document.querySelector('[data-testid="brand-mark"]')!.parentElement!;
    const content = document.querySelector('[data-testid="page-content"]') as HTMLElement;
    const root = content.firstElementChild!;
    const visible = (el: Element) => { const b = rect(el); return b.width > 0 && b.height > 0; };
    const firstBlock = [...root.children].find(visible)!;
    // The first card of the page in reading order: the first rounded box with
    // a border or a ring (a notice, a Section, a search field, the selected
    // Settings section).
    const card = [...content.querySelectorAll('*')].find((el) => {
      const s = getComputedStyle(el);
      const edged = parseFloat(s.borderLeftWidth) >= 1 || s.boxShadow !== 'none';
      return visible(el) && edged && parseFloat(s.borderTopLeftRadius) >= 8;
    });
    const cs = getComputedStyle(content);
    const c = rect(content);
    return {
      route: r,
      bandTop: rect(band).top,
      bandBottom: rect(band).bottom,
      bandHeight: rect(band).height,
      bandBorder: getComputedStyle(band).borderBottomColor,
      brandBottom: rect(brand).bottom,
      brandBorder: getComputedStyle(brand).borderBottomColor,
      h1Left: rect(band.querySelector('h1')!).left,
      contentLeft: c.left + parseFloat(cs.paddingLeft),
      contentRight: c.right - parseFloat(cs.paddingRight),
      firstBlockLeft: rect(firstBlock).left,
      firstCardLeft: card ? rect(card).left : null,
      firstCard: card ? `${card.tagName.toLowerCase()} "${(card.textContent ?? '').trim().slice(0, 40)}"` : 'none',
    };
  }, route);
}

for (const viewport of [{ width: 1512, height: 805 }, { width: 1280, height: 800 }]) {
  for (const collapsed of [false, true]) {
    const name = `${viewport.width}x${viewport.height}, sidebar ${collapsed ? 'collapsed' : 'expanded'}`;
    test.describe(name, () => {
      test.use({ viewport, colorScheme: 'light' });
      test.beforeEach(async ({ page }, info) => {
        test.skip(info.project.name !== 'desktop-1440', 'the viewport is set here, once');
        await page.addInitScript((c) => { window.localStorage.setItem('spm.sidebar.collapsed', c ? '1' : '0'); }, collapsed);
        await mockApi(page);
      });

      test('the band continues the sidebar header line and lines up with the content on every page', async ({ page }) => {
        test.setTimeout(90_000);
        const all: Measured[] = [];
        for (const route of ROUTES) {
          const m = await measure(page, route);
          all.push(m);
          expect(Math.abs(m.bandBottom - m.brandBottom), `${route}: band bottom ${m.bandBottom}, sidebar header bottom ${m.brandBottom}`).toBeLessThanOrEqual(0.5);
          expect(m.bandHeight, `${route}: band height`).toBe(64);
          expect(m.bandBorder, `${route}: band border colour`).toBe(m.brandBorder);
          expect(Math.abs(m.h1Left - m.contentLeft), `${route}: h1 at ${m.h1Left}, content at ${m.contentLeft}`).toBeLessThanOrEqual(0.5);
          expect(Math.abs(m.firstBlockLeft - m.contentLeft), `${route}: first block at ${m.firstBlockLeft}, content at ${m.contentLeft}`).toBeLessThanOrEqual(0.5);
          expect(m.firstCardLeft, `${route}: no card found`).not.toBeNull();
          expect(Math.abs(m.firstCardLeft! - m.h1Left), `${route}: first card ${m.firstCard} at ${m.firstCardLeft}, h1 at ${m.h1Left}`).toBeLessThanOrEqual(0.5);
        }
        // No sideways shift between pages, a page that does not scroll included.
        const lefts = new Set(all.map((m) => m.contentLeft));
        const rights = new Set(all.map((m) => m.contentRight));
        expect([...lefts], `content left edges: ${all.map((m) => `${m.route}=${m.contentLeft}`).join(', ')}`).toHaveLength(1);
        expect([...rights], `content right edges: ${all.map((m) => `${m.route}=${m.contentRight}`).join(', ')}`).toHaveLength(1);
      });

      test('the band stays at the top while the page scrolls', async ({ page }) => {
        test.setTimeout(60_000);
        for (const route of ['/', '/analytics', '/blacklists', '/settings/filtering']) {
          await page.goto(route);
          await expect(page.getByTestId('page-band').getByRole('heading', { level: 1 })).toBeVisible();
          await page.waitForLoadState('networkidle');
          const scrolled = await page.locator('main').evaluate((el) => { el.scrollTop = 600; return el.scrollTop; });
          expect(scrolled, `${route} scrolls`).toBeGreaterThan(0);
          const top = await page.getByTestId('page-band').evaluate((el) => el.getBoundingClientRect().top);
          expect(top, `${route}: band top after scrolling ${scrolled} px`).toBe(0);
          await expect(page.getByTestId('page-band').getByRole('heading', { level: 1 })).toBeInViewport();
          if (route.startsWith('/settings/')) {
            // The section list stays in view below the band, not under it.
            const nav = await page.getByRole('navigation', { name: 'Settings sections' }).boundingBox();
            expect(nav!.y, 'the Settings section list slid under the band').toBeGreaterThanOrEqual(64);
          }
        }
      });
    });
  }
}

// The description of a page whose sentence is not about its numbers is the
// tooltip of the info button by the title: it opens on hover and on keyboard
// focus, Escape closes it, and it stays inside the window at every width.
for (const route of ['/logs', '/blacklists', '/egress', '/audit']) {
  test(`${route}: the info tooltip opens on hover and on focus and stays in the window`, async ({ page }) => {
    await mockApi(page);
    await page.goto(route);
    const info = page.getByTestId('page-band').getByRole('button', { name: /^About / });
    const tip = page.getByRole('tooltip');
    await expect(info).toBeVisible();
    await expect(tip).toBeHidden();

    await info.hover();
    await expect(tip).toBeVisible();
    const width = page.viewportSize()!.width;
    const box = (await tip.boundingBox())!;
    expect(box.x, 'the tooltip starts off the screen').toBeGreaterThanOrEqual(0);
    expect(box.x + box.width, 'the tooltip ends past the screen').toBeLessThanOrEqual(width);
    // Below the title, over the content, not cut by the top of the window.
    expect(box.y).toBeGreaterThan((await info.boundingBox())!.y);
    await page.keyboard.press('Escape');
    await expect(tip).toBeHidden();

    await page.mouse.move(0, page.viewportSize()!.height - 1);
    await info.focus();
    await expect(tip).toBeVisible();
    await info.blur();
    await expect(tip).toBeHidden();
  });
}

// On a phone the band's row wraps: the actions go under the title and must
// wrap inside the band. They could not shrink, so on /analytics the four
// related-page links stayed one 365 px line and the page scrolled sideways
// (by 2 px at 390 in CI's fonts, by 25 px at 360). Measured at 360, a common
// Android width, so the margin does not depend on the fonts installed.
test.describe('360x780', () => {
  test.use({ viewport: { width: 360, height: 780 } });
  // One test per page: the 16 pages in one test ran past its 30 s under the full suite.
  for (const route of ROUTES) {
    test(`${route}: on a phone the band holds its title and actions, and the page does not scroll sideways`, async ({ page }, info) => {
      test.skip(info.project.name !== 'desktop-1440', 'the viewport is set here, once');
      await mockApi(page);
      await page.goto(route);
      await expect(page.getByTestId('page-band').getByRole('heading', { level: 1 })).toBeVisible();
      await page.waitForLoadState('networkidle');
      const m = await page.evaluate(() => {
        const row = document.querySelector('[data-testid="page-band"] > div') as HTMLElement;
        const right = row.getBoundingClientRect().right - parseFloat(getComputedStyle(row).paddingRight);
        const past = Math.max(0, ...[...row.children].map((k) => k.getBoundingClientRect().right - right));
        const main = document.querySelector('main')!;
        return { past: Math.round(past), scroll: main.scrollWidth - main.clientWidth };
      });
      expect(m.past, 'band content past its edge (px)').toBeLessThanOrEqual(0);
      expect(m.scroll, 'page wider than the screen (px)').toBeLessThanOrEqual(0);
    });
  }
});
