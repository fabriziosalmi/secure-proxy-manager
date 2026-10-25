/**
 * SegmentedControl: pick one of a few options that change what a view shows
 * (time range 1h / 24h / 7d, theme). A named group of toggle buttons: each
 * option is a button with aria-pressed, so a screen reader hears which one
 * is on. An icon-only option must carry an ariaLabel.
 *
 * Use tabs (role="tablist") instead when the options switch between panels
 * of different content.
 */
import type { ReactNode } from 'react';
import { cn } from '../../lib/utils';

export type SegmentOption<V extends string> =
  | { value: V; label: string; icon?: ReactNode; ariaLabel?: string }
  | { value: V; label?: undefined; icon: ReactNode; ariaLabel: string };

export interface SegmentedControlProps<V extends string> {
  /** Accessible name of the group ("Time range"). */
  label: string;
  options: readonly SegmentOption<V>[];
  value: V;
  onChange: (value: V) => void;
  size?: 'sm' | 'md';
  className?: string;
}

export function SegmentedControl<V extends string>({ label, options, value, onChange, size = 'md', className }: SegmentedControlProps<V>) {
  return (
    <div
      role="group"
      aria-label={label}
      className={cn(
        'inline-flex items-center gap-0.5 rounded-control border border-line bg-surface p-[3px]',
        size === 'md' ? 'h-9' : 'h-8',
        className,
      )}
    >
      {options.map((o) => {
        const on = o.value === value;
        return (
          <button
            key={o.value}
            type="button"
            aria-pressed={on}
            aria-label={o.ariaLabel}
            title={o.label ? undefined : o.ariaLabel}
            onClick={() => onChange(o.value)}
            className={cn(
              'inline-flex h-full items-center justify-center gap-1.5 rounded-[6px] text-[13px] transition-colors',
              'focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-accent',
              o.label ? 'px-3' : 'aspect-square px-0',
              on ? 'bg-ink font-semibold text-surface' : 'text-ink-secondary hover:bg-surface-muted',
            )}
          >
            {o.icon && <span aria-hidden="true" className="inline-flex [&>svg]:h-3.5 [&>svg]:w-3.5">{o.icon}</span>}
            {o.label}
          </button>
        );
      })}
    </div>
  );
}
