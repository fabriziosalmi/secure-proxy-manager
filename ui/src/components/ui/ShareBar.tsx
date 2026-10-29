/**
 * ShareBar: a part of a total as a thin bar and its percentage, the one way
 * the UI draws "share blocked".
 *
 * - The fill is at least 2 px wide for any part above zero, with a square
 *   left end: a 2.2% fill used to be 1.75 px clipped by a rounded track,
 *   which drew a "(" rather than a bar.
 * - At exactly zero there is no track and the text is a muted "0%": an empty
 *   track on every row of a table is noise, and 0.0% would read as rounded.
 * - The bar repeats the number, so it is hidden from assistive technology;
 *   it can be left out (bar={false}) where the text is enough.
 */
import { fillWidth, shareText } from '../../lib/share';
import { cn } from '../../lib/utils';

export interface ShareBarProps {
  part: number;
  total: number;
  /** Words after the percentage, e.g. "of requests". */
  suffix?: string;
  /** Draw the bar (it is hidden on a phone either way); false for the text alone. */
  bar?: boolean;
  /** Width of the bar's track. */
  trackClassName?: string;
  /** Width and alignment of the percentage, so a column of them lines up. */
  textClassName?: string;
  className?: string;
}

export function ShareBar({ part, total, suffix, bar = true, trackClassName, textClassName, className }: ShareBarProps) {
  const text = shareText(part, total);
  if (!text) return <span className={cn('text-[13px] text-ink-muted', className)}>No requests</span>;
  const zero = part === 0;
  return (
    <span className={cn('flex items-center gap-2', className)}>
      {bar && (zero ? (
        // The track's room, empty, so a column of percentages stays aligned.
        <span aria-hidden="true" className={cn('hidden flex-1 sm:block', trackClassName)} />
      ) : (
        <span aria-hidden="true" data-testid="share-track" className={cn('hidden h-1.5 flex-1 overflow-hidden rounded-r-full bg-line-subtle sm:block', trackClassName)}>
          <span data-testid="share-fill" className="block h-1.5 rounded-r-full bg-danger-strong" style={{ width: fillWidth(part, total) }} />
        </span>
      ))}
      <span className={cn('shrink-0 tabular-nums', zero ? 'text-ink-subtle' : 'text-ink-muted', textClassName)}>
        {text}
        {suffix ? ` ${suffix}` : ''}
      </span>
    </span>
  );
}
