/**
 * Unavailable: what could not be shown, in words, with the request that
 * failed as a detail under it. Error states used to lead with the endpoint
 * ("Not reported: analytics/coverage did not answer."), which names a path
 * a reader cannot act on before saying what is missing.
 */
import type { ReactNode } from 'react';
import { cn } from '../../lib/utils';

export interface UnavailableProps {
  /** What is missing and what that means, as a sentence. */
  children: ReactNode;
  /** The API path that did not answer, without /api/ ("analytics/coverage"). */
  endpoint: string;
  className?: string;
}

export function Unavailable({ children, endpoint, className }: UnavailableProps) {
  return (
    <div role="alert" className={cn('flex flex-col gap-0.5 text-sm text-ink-muted', className)}>
      <p>{children}</p>
      <p className="text-xs text-ink-subtle">
        Detail: <code className="font-mono">GET /api/{endpoint}</code> did not answer.
      </p>
    </div>
  );
}
