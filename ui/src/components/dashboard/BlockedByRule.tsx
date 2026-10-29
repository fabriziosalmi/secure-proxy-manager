/**
 * Blocked by rule: the last 24 hours of blocked client requests, by the rule
 * that blocked them (blocked_by_reason_24h). Each rule is named by the label
 * the API sends, "Unclassified (no reason recorded)" included. The main rules
 * that blocked nothing are named in one sentence, so a zero is said rather
 * than left out.
 */
import { ShieldCheck } from 'lucide-react';
import type { ReasonCount } from '../../types';
import { formatCount } from '../../lib/format';
import { Section } from '../ui/Section';
import { EmptyState } from '../ui/EmptyState';
import { idleRulesSentence } from './rules';

export interface BlockedByRuleProps {
  reasons?: ReasonCount[] | null;
  loading?: boolean;
}

export function BlockedByRule({ reasons, loading }: BlockedByRuleProps) {
  let body;
  if (loading) {
    body = (
      <div className="space-y-3">
        <span aria-hidden="true" className="block h-12 rounded-md bg-line-subtle animate-pulse" />
        <span role="status" className="sr-only">Loading blocked requests by rule</span>
      </div>
    );
  } else if (!reasons) {
    // Not a failed request: an answer without the field, from an older backend.
    body = <p className="text-sm text-ink-muted">Not reported: this backend does not count blocks by rule. Updating it adds them.</p>;
  } else {
    const shown = reasons.filter((r) => r.count > 0);
    const total = shown.reduce((s, r) => s + r.count, 0);
    const idle = idleRulesSentence(shown);
    body = total === 0 ? (
      <EmptyState
        icon={<ShieldCheck strokeWidth={1.75} />}
        title="No blocked requests in the last 24 hours"
        description="No rule blocked a client request in this window."
      />
    ) : (
      <div className="flex flex-col gap-4">
        <ul className="flex flex-col gap-3">
          {shown.map((r) => (
            <li key={r.reason} className="flex flex-col gap-1.5">
              <div className="flex items-baseline justify-between gap-3 text-sm">
                <span className="min-w-0 font-medium text-ink">{r.label}</span>
                <span className="font-semibold tabular-nums text-ink">{formatCount(r.count)}</span>
              </div>
              <div aria-hidden="true" className="h-2 overflow-hidden rounded-full bg-line-subtle">
                <div className="h-2 bg-danger-strong" style={{ width: `${(r.count / total) * 100}%` }} />
              </div>
            </li>
          ))}
        </ul>
        {idle && <p className="border-t border-line-subtle pt-3 text-[13px] leading-5 text-ink-muted">{idle}</p>}
      </div>
    );
  }
  return (
    <Section title="Blocked by rule" action={{ label: 'Open analytics', to: '/analytics' }} className="flex-[1_1_300px]">
      {body}
    </Section>
  );
}
