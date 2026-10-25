/**
 * EmptyState: what a list or chart shows when it has nothing to show. The
 * title says what is missing ("No blocked requests today"), the description
 * says why or what to do next ("Requests appear here once a device uses the
 * proxy"), and the optional action is the button or link that does it.
 * Never an empty box or a lone "No data".
 */
import type { ReactNode } from 'react';
import { Inbox } from 'lucide-react';
import { cn } from '../../lib/utils';

export interface EmptyStateProps {
  title: string;
  description: ReactNode;
  action?: ReactNode;
  icon?: ReactNode;
  className?: string;
}

export function EmptyState({ title, description, action, icon, className }: EmptyStateProps) {
  return (
    <div className={cn('flex flex-col items-center gap-2 px-6 py-10 text-center', className)}>
      <span aria-hidden="true" className="mb-1 flex h-10 w-10 items-center justify-center rounded-full bg-line-subtle text-ink-subtle [&>svg]:h-5 [&>svg]:w-5">
        {icon ?? <Inbox strokeWidth={1.75} />}
      </span>
      <p className="text-sm font-semibold text-ink">{title}</p>
      <div className="max-w-md text-sm text-ink-muted">{description}</div>
      {action && <div className="mt-2">{action}</div>}
    </div>
  );
}
