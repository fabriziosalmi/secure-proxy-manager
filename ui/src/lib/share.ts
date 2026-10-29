/** The share helpers of components/ui/ShareBar, kept apart so the component file exports components only. */
import { formatShare } from './format';

/**
 * The share as text: "2.2%", "0%" when the part is exactly zero (0.0% would
 * read as a rounded small share), null when the total is not positive.
 */
export function shareText(part: number, total: number): string | null {
  const share = formatShare(part, total);
  if (!share) return null;
  return part === 0 ? '0%' : share;
}

/** The fill's CSS width for a share: at least 2 px when above zero. */
export function fillWidth(part: number, total: number): string {
  if (!(total > 0) || !(part > 0)) return '0';
  return `max(2px, ${Math.min(100, (part / total) * 100)}%)`;
}
