/**
 * PageHeader: the top of every page. Inside Layout it is drawn in the page
 * band, the strip across the top of the main column that continues the line
 * under the sidebar's brand: the eyebrow is the page's nav group (from
 * nav.ts, so a page cannot name another), the title is the page's only h1,
 * and actions holds the page's buttons (at most one primary), on the right.
 *
 * The description says in one sentence what the page is for. By default it
 * is the tooltip of an info icon next to the title. A sentence that says
 * what the page's numbers count, or over which time window, is written
 * inline instead: a visible line at the top of the content, where it is read
 * with the numbers (describe="inline").
 *
 * Rendered outside Layout (a page on its own in a test) there is no band:
 * the header is drawn in place, with the eyebrow passed to it.
 */
import { useContext, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import { PageBandContext } from '../layout/pageBand';
import { InfoTip } from './InfoTip';
import { cn } from '../../lib/utils';

export type DescribeAs = 'tooltip' | 'inline';

export interface PageHeaderProps {
  title: string;
  /** Shown only where there is no band; in the band the eyebrow is the route's nav group. */
  eyebrow?: string;
  description?: ReactNode;
  /** tooltip (default): behind an info icon by the title. inline: a visible line at the top of the content. */
  describe?: DescribeAs;
  actions?: ReactNode;
  className?: string;
}

export function PageHeader({ title, eyebrow, description, describe = 'tooltip', actions, className }: PageHeaderProps) {
  const band = useContext(PageBandContext);
  const group = band ? band.eyebrow : eyebrow;
  const row = (
    <>
      <div className="flex min-w-0 flex-auto flex-col">
        {group && <p data-testid="page-eyebrow" className="text-xs leading-4 text-ink-muted">{group}</p>}
        <div className="flex min-w-0 items-center gap-1">
          <h1 className="min-w-0 truncate text-xl font-semibold leading-7 tracking-[-0.01em] text-ink">{title}</h1>
          {description && describe === 'tooltip' && <InfoTip label={`About ${title}`}>{description}</InfoTip>}
        </div>
      </div>
      {/* On a wide screen the actions keep their width beside the title; on a
          phone they go under it and wrap inside the band (min-w-0), or a row
          of links ran past the screen. */}
      {actions && <div className="flex min-w-0 flex-wrap items-center gap-2 lg:shrink-0">{actions}</div>}
    </>
  );
  const inline = description && describe === 'inline'
    ? <p data-testid="page-description" className={cn('text-sm text-ink-muted', band && className)}>{description}</p>
    : null;
  if (band) {
    return (
      <>
        {band.slot && createPortal(row, band.slot)}
        {inline}
      </>
    );
  }
  return (
    <header className={cn('flex flex-col gap-1', className)}>
      <div className="flex flex-wrap items-center justify-between gap-4">{row}</div>
      {inline}
    </header>
  );
}
