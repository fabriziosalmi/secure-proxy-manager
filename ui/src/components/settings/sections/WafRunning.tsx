/**
 * What the WAF runs, as it reports it (GET /api/waf/status): the engine,
 * the score that blocks, the rules, the regular-expression engine and the
 * policy's mode. Before it, the page said "10 in the shipped compose" and
 * nothing showed whether the OWASP Core Rule Set or Log only was in force.
 */
import { useQuery } from '@tanstack/react-query';
import { wafStatusQuery } from '../../../lib/queries';
import { wafRunningRows, wafUnknownReason } from '../../../lib/wafRunning';
import { Section } from '../../ui/Section';
import { Notice } from '../../ui/Notice';

export function WafRunning() {
  const q = useQuery({ ...wafStatusQuery, staleTime: 10_000 });
  const w = q.data;
  const run = w?.status === 'ok' ? w.running : undefined;

  let body;
  if (q.isPending) body = <p className="text-sm text-ink-muted">Asking the WAF what it runs...</p>;
  else if (!w || w.status !== 'ok') body = <p className="text-sm text-ink-muted">Not known. {wafUnknownReason(w?.status)}</p>;
  else if (!run) body = <p className="text-sm text-ink-muted">The WAF answered for its rules but not for its /health, so its engine and threshold are not known.</p>;
  else {
    body = (
      <>
        {run.policy_mode === 'observe' && (
          <Notice tone="warning" title="Log only: the WAF blocks nothing" className="mb-3">
            It records what it would block. Switch the WAF policy below back to Block when you are done.
          </Notice>
        )}
        {run.policy_reload_failed && (
          <Notice tone="warning" title="The WAF could not reload its policy" className="mb-3">
            It still runs the policy it had before. The WAF policy below shows why.
          </Notice>
        )}
        <dl className="grid grid-cols-1 gap-x-6 gap-y-2 text-sm sm:grid-cols-[max-content_1fr]">
          {wafRunningRows(w, run).map(([k, v]) => (
            <div key={k} className="contents">
              <dt className="text-ink-muted">{k}</dt>
              <dd className="text-ink [overflow-wrap:anywhere]">{v}</dd>
            </div>
          ))}
        </dl>
      </>
    );
  }
  return (
    <Section level={3} title="What the WAF runs" description="As the WAF reports it now. The engine, the threshold and the regex engine are set in .env.">
      {body}
    </Section>
  );
}
