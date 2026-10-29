/**
 * Protection coverage: what is switched on and enforced now, one line per
 * protection, each linking to where it is changed (coverageLines, from GET
 * /api/analytics/coverage). It takes the place the security score had: the
 * score added points for settings, some of which nothing reads.
 */
import { Link } from 'react-router';
import type { Coverage } from '../../types';
import { POSTURE_WORD, type Posture } from '../../lib/posture';
import { Section } from '../ui/Section';
import { PostureMark } from '../ui/PostureMark';
import { coverageLines } from './coverage';

/** The marks of the states the lines show, in a fixed order, for the legend. */
const LEGEND_ORDER: Posture[] = ['on', 'worth-knowing', 'needs-attention', 'unknown'];

// Inline elements only: it sits in a paragraph-free list footer.
function Legend({ states }: { states: Posture[] }) {
  return (
    <p className="flex flex-wrap gap-x-4 gap-y-1 border-t border-line-subtle pt-3 text-xs text-ink-muted">
      {LEGEND_ORDER.filter((p) => states.includes(p)).map((p) => (
        <span key={p} className="inline-flex items-center gap-1.5" aria-hidden="true">
          <PostureMark posture={p} />
          {POSTURE_WORD[p]}
        </span>
      ))}
    </p>
  );
}

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
    const lines = coverageLines(data);
    body = (
      <div className="flex flex-col gap-3">
        <ul className="flex flex-col gap-2.5 text-sm">
          {lines.map((l) => (
            <li key={l.id} data-line={l.id} data-state={l.state} className="flex items-start gap-2.5">
              <PostureMark posture={l.state} className="mt-0.5" />
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
        <Legend states={lines.map((l) => l.state)} />
      </div>
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
