/**
 * Section: a titled card, the block every page is built from. The title is a
 * heading (h2 by default) that also names the region, the optional
 * description says what the block shows, and the optional action is a link
 * to where the full data lives ("View all", "Open access logs").
 *
 * The body is padded; pass flush for a table or list that runs edge to edge.
 */
import { useId, type ReactNode } from 'react';
import { Link } from 'react-router';
import { cn } from '../../lib/utils';

export interface SectionAction {
  label: string;
  /** An in-app route. */
  to: string;
}

export interface SectionProps {
  title: string;
  description?: ReactNode;
  action?: SectionAction;
  /** Heading level of the title: 2 on a page, 3 inside another section. */
  level?: 2 | 3;
  /** Drop the body padding, for a table or list that runs edge to edge. */
  flush?: boolean;
  /** Danger zone: a red border, for the block that holds a destructive action. */
  tone?: 'default' | 'danger';
  className?: string;
  children?: ReactNode;
}

export function Section({ title, description, action, level = 2, flush, tone = 'default', className, children }: SectionProps) {
  const id = useId();
  const Heading = level === 2 ? 'h2' : 'h3';
  return (
    <section
      aria-labelledby={id}
      className={cn(
        'min-w-0 overflow-hidden rounded-panel border bg-surface text-ink',
        tone === 'danger' ? 'border-danger-line' : 'border-line',
        className,
      )}
    >
      <div className={cn('flex flex-wrap items-start justify-between gap-3 px-5 pt-4', flush ? 'pb-3' : 'pb-0')}>
        <div className="flex min-w-0 flex-col gap-1">
          <Heading id={id} className={cn('font-semibold text-ink', level === 2 ? 'text-base' : 'text-sm')}>{title}</Heading>
          {description && <p className="text-[13px] text-ink-muted">{description}</p>}
        </div>
        {action && (
          <Link
            to={action.to}
            className="rounded-sm text-sm font-semibold text-accent hover:underline focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-accent"
          >
            {action.label}
          </Link>
        )}
      </div>
      <div className={flush ? '' : 'px-5 pb-5 pt-4'}>{children}</div>
    </section>
  );
}
