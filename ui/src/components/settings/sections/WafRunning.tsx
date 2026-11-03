/**
 * What the WAF runs, as it reports it (GET /api/waf/status): the engine,
 * the score that blocks, the rules, the regular-expression engine and the
 * policy's mode. Before it, the page said "10 in the shipped compose" and
 * nothing showed whether the OWASP Core Rule Set or Log only was in force.
 */
import { useQuery } from '@tanstack/react-query';
import { wafCategoriesQuery, wafStatusQuery } from '../../../lib/queries';
import { wafCategoryLabel } from '../../../lib/wafCategories';
import { formatCount } from '../../../lib/format';
import { wafRunningRows, wafUnknownReason } from '../../../lib/wafRunning';
import { Section } from '../../ui/Section';
import { Notice } from '../../ui/Notice';

/**
 * The rule categories, each with its rules and whether it scores, only logs
 * or is off: Protection coverage counts them, and the policy can make one
 * log-only, but nothing listed them.
 */
function WafCategories() {
  const q = useQuery(wafCategoriesQuery);
  const cats = q.data;
  if (q.isPending || !cats) return null;
  const sorted = [...cats].sort((a, b) => wafCategoryLabel(a.name).label.localeCompare(wafCategoryLabel(b.name).label));
  const logged = cats.filter((c) => c.enabled && c.observe).length;
  const off = cats.filter((c) => !c.enabled).length;
  const counts = [logged ? `${formatCount(logged)} only logged` : '', off ? `${formatCount(off)} off` : ''].filter(Boolean).join(', ');
  return (
    <details className="mt-4 rounded-control border border-line px-3 py-2">
      <summary className="cursor-pointer text-sm font-semibold text-ink">
        Rule categories: {formatCount(cats.length)}{counts ? ` (${counts})` : ''}
      </summary>
      <table className="mt-2 w-full text-sm">
        <caption className="sr-only">The WAF&apos;s rule categories</caption>
        <thead>
          <tr className="text-left text-xs text-ink-muted">
            <th scope="col" className="py-1 pr-3 font-medium">Category</th>
            <th scope="col" className="py-1 pr-3 text-right font-medium">Rules</th>
            <th scope="col" className="py-1 font-medium">State</th>
          </tr>
        </thead>
        <tbody>
          {sorted.map((c) => (
            <tr key={c.name} className="border-t border-line-subtle">
              <td className="py-1 pr-3 text-ink [overflow-wrap:anywhere]">{wafCategoryLabel(c.name).label}</td>
              <td className="py-1 pr-3 text-right tabular-nums text-ink-secondary">{formatCount(c.rules)}</td>
              <td className="py-1 text-ink-secondary">{!c.enabled ? 'Off' : c.observe ? 'Only logged' : 'Scores'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </details>
  );
}

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
        <WafCategories />
      </>
    );
  }
  return (
    <Section level={3} title="What the WAF runs" description="As the WAF reports it now. The engine, the threshold and the regex engine are set in .env.">
      {body}
    </Section>
  );
}
