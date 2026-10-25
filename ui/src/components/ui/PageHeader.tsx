/**
 * PageHeader: the top of every page. An optional eyebrow names the
 * navigation group the page belongs to ("Traffic", "Protection"), the title
 * is the page's only h1, the description says in one sentence what the page
 * is for, and actions holds the page's buttons (at most one primary).
 */
import type { ReactNode } from 'react';
import { cn } from '../../lib/utils';

export interface PageHeaderProps {
  title: string;
  eyebrow?: string;
  description?: ReactNode;
  actions?: ReactNode;
  className?: string;
}

export function PageHeader({ title, eyebrow, description, actions, className }: PageHeaderProps) {
  return (
    <header className={cn('flex flex-wrap items-end justify-between gap-4', className)}>
      <div className="flex min-w-0 flex-col gap-1">
        {eyebrow && <p className="text-[13px] text-ink-muted">{eyebrow}</p>}
        <h1 className="text-2xl font-semibold leading-8 tracking-[-0.01em] text-ink">{title}</h1>
        {description && <p className="text-sm text-ink-muted">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </header>
  );
}
