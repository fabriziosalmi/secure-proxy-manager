/**
 * StatCard: one headline number with its label and an optional sub-line.
 *
 * A number goes through formatCount (50,772 in every locale) in tabular
 * figures; a string is shown as given. A value the backend did not send is
 * never drawn as 0: pass unavailable="not-collected" (nothing gathers it) or
 * "not-reported" (the source did not send it), and a missing value with no
 * reason says "Not reported" too. While loading, the value is a skeleton and
 * screen readers hear "Loading".
 *
 * tone colours the value only: danger for blocked counts, warning for a
 * number that needs attention, success for a healthy one.
 */
import type { ReactNode } from 'react';
import { cn } from '../../lib/utils';
import { formatCount } from '../../lib/format';

export type StatTone = 'default' | 'danger' | 'warning' | 'success';
export type Unavailable = 'not-collected' | 'not-reported';

const TONES: Record<StatTone, string> = {
  default: 'text-ink',
  danger: 'text-danger',
  warning: 'text-warning',
  success: 'text-success',
};

const UNAVAILABLE_TEXT: Record<Unavailable, string> = {
  'not-collected': 'Not collected',
  'not-reported': 'Not reported',
};

export interface StatCardProps {
  label: string;
  value?: number | string | null;
  tone?: StatTone;
  sub?: ReactNode;
  unavailable?: Unavailable;
  loading?: boolean;
  className?: string;
}

export function StatCard({ label, value, tone = 'default', sub, unavailable, loading, className }: StatCardProps) {
  const missing = unavailable ?? (value === null || value === undefined || (typeof value === 'number' && !Number.isFinite(value)) ? 'not-reported' : null);
  let body: ReactNode;
  if (loading) {
    body = (
      <p className="h-9 flex items-center">
        <span aria-hidden="true" className="block h-6 w-20 rounded-md bg-line-subtle animate-pulse" />
        <span className="sr-only">Loading</span>
      </p>
    );
  } else if (missing) {
    body = <p data-state={missing} className="text-base font-medium leading-9 text-ink-muted">{UNAVAILABLE_TEXT[missing]}</p>;
  } else {
    body = (
      <p className={cn('text-[30px] font-semibold leading-9 tabular-nums', TONES[tone])}>
        {typeof value === 'number' ? formatCount(value) : value}
      </p>
    );
  }
  return (
    <div className={cn('flex min-w-0 flex-col gap-2 rounded-panel border border-line bg-surface p-5', className)}>
      <p className="text-[13px] font-medium text-ink-muted">{label}</p>
      {body}
      {sub && <div className="text-[13px] text-ink-muted">{sub}</div>}
    </div>
  );
}
