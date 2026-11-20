/**
 * The page band's slot: Layout draws the band across the top of the main
 * column and hands its inner row to PageHeader through this context, so a
 * page keeps writing <PageHeader title actions /> where it always did and its
 * title and buttons appear in the band. eyebrow is the nav group of the
 * route. Outside Layout (a page rendered on its own in a test) there is no
 * band, and PageHeader draws itself in place.
 */
import { createContext } from 'react';

export interface PageBand {
  /** The band's inner row, once it is mounted. */
  slot: HTMLElement | null;
  /** The nav group of the current route, from nav.ts. */
  eyebrow: string | undefined;
}

export const PageBandContext = createContext<PageBand | null>(null);
