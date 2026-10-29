/**
 * Measurements the layout suite asserts on, taken from the rendered page:
 * what jsdom cannot tell (widths, line breaks, alignment, overflow).
 */
import type { Locator, Page } from '@playwright/test';

/**
 * Whether the page scrolls sideways: the document wider than the window, or
 * the main column (Layout's <main>, which scrolls on its own) wider than its
 * box. The larger overflow of the two is returned.
 */
export async function pageOverflow(page: Page): Promise<{ scrollWidth: number; clientWidth: number }> {
  return page.evaluate(() => {
    const boxes = [document.documentElement, document.querySelector('main')].filter((el): el is HTMLElement => el !== null);
    const worst = boxes.reduce((a, b) => (b.scrollWidth - b.clientWidth > a.scrollWidth - a.clientWidth ? b : a));
    return { scrollWidth: worst.scrollWidth, clientWidth: worst.clientWidth };
  });
}

/** How many lines the text of an element is laid out on. */
export async function lineCount(el: Locator): Promise<number> {
  return el.evaluate((node) => {
    const range = document.createRange();
    range.selectNodeContents(node);
    return new Set([...range.getClientRects()].filter((r) => r.width > 0).map((r) => Math.round(r.top))).size;
  });
}

/** The gap in pixels between the right edge of an element's text and the right edge of container. */
export async function rightGap(el: Locator, container: Locator): Promise<number> {
  const box = await container.boundingBox();
  const textRight = await el.evaluate((node) => {
    const range = document.createRange();
    range.selectNodeContents(node);
    return Math.max(...[...range.getClientRects()].map((r) => r.right));
  });
  if (!box) throw new Error('container is not rendered');
  return Math.round(box.x + box.width - textRight);
}

/** Whether an element's content is cut: wider than the box that shows it. */
export async function isCut(el: Locator): Promise<boolean> {
  return el.evaluate((node) => (node as HTMLElement).scrollWidth > (node as HTMLElement).clientWidth);
}
