/**
 * Badge: a short status label in a pill ("Domain blacklist", "On", "2").
 *
 * Tones carry meaning: danger for blocked or destructive, warning for
 * something that needs attention, success for on or healthy, accent for the
 * current selection, neutral for everything else. Pick neutral when unsure:
 * colour without meaning is noise. The text must say the state on its own,
 * colour only repeats it.
 */
import type { HTMLAttributes } from 'react';
import { cn } from '../../lib/utils';

export type BadgeTone = 'neutral' | 'danger' | 'warning' | 'success' | 'accent';

const TONES: Record<BadgeTone, string> = {
  neutral: 'bg-line-subtle text-ink-muted',
  danger: 'bg-danger-subtle text-danger',
  warning: 'bg-warning-subtle text-warning',
  success: 'bg-success-subtle text-success',
  accent: 'bg-accent-subtle text-accent',
};

export interface BadgeProps extends HTMLAttributes<HTMLSpanElement> {
  tone?: BadgeTone;
}

export function Badge({ tone = 'neutral', className, ...rest }: BadgeProps) {
  return (
    <span
      data-tone={tone}
      className={cn('inline-flex items-center whitespace-nowrap rounded-full px-2 py-0.5 text-xs font-medium tabular-nums', TONES[tone], className)}
      {...rest}
    />
  );
}
