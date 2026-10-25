/**
 * Protection coverage: what is switched on and enforced now, one line per
 * protection, each linking to where it is changed (coverageLines, from GET
 * /api/analytics/coverage). It takes the place the security score had: the
 * score added points for settings, some of which nothing reads.
 */
import { Link } from 'react-router';
import type { Coverage } from '../../types';
import { cn } from '../../lib/utils';
import { Section } from '../ui/Section';
import { coverageLines, type CoverageState } from './coverage';

// The dot repeats what the text says; it is never the only signal.
const DOT: Record<CoverageState, string> = {
  on: 'bg-success-strong',
  off: 'bg-chart-neutral',
  attention: 'bg-warning-strong',
  unknown: 'bg-line-strong',
};

export interface ProtectionCoverageProps {
  data?: Coverage | null;
  loading?: boolean;
  error?: boolean;
}

export function ProtectionCoverage({ data, loading, error }: ProtectionCoverageProps) {
  let body;
  if (loading) {
    body = (
      <div className="space-y-3">
        <span aria-hidden="true" className="block h-40 rounded-md bg-line-subtle animate-pulse" />
        <span role="status" className="sr-only">Loading protection coverage</span>
      </div>
    );
  } else if (error || !data) {
    body = <p role="alert" className="text-sm text-ink-muted">Not reported: analytics/coverage did not answer.</p>;
  } else {
    body = (
      <ul className="flex flex-col gap-2.5 text-sm">
        {coverageLines(data).map((l) => (
          <li key={l.id} data-line={l.id} data-state={l.state} className="flex items-start gap-2.5">
            <span aria-hidden="true" className={cn('mt-1.5 h-2 w-2 flex-none rounded-full', DOT[l.state])} />
            <span className="min-w-0 flex-1 text-ink [overflow-wrap:anywhere]">{l.text}</span>
            <Link
              to={l.link.to}
              className="shrink-0 whitespace-nowrap rounded-sm text-[13px] font-semibold text-accent hover:underline focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-accent"
            >
              {l.link.label}
            </Link>
          </li>
        ))}
      </ul>
    );
  }
  return (
    <Section
      title="Protection coverage"
      description="What is switched on and enforced right now. Each line links to the setting."
      className="flex-[1_1_300px]"
    >
      {body}
    </Section>
  );
}
