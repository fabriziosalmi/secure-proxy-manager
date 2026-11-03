/**
 * Services: one line per service, from serviceRows (services.ts). The dot
 * repeats the state the text already says and is hidden from screen readers.
 */
import { cn } from '../../lib/utils';
import type { SquidCve } from '../../types';
import { Section } from '../ui/Section';
import type { Health, ServiceRow } from './services';

const DOT: Record<Health, string> = {
  ok: 'bg-success',
  down: 'bg-danger',
  unknown: 'bg-ink-subtle',
};

/**
 * The advisories behind the proxy's CVE count, under its line: the count
 * alone said there were some, not which, nor whether they apply (several
 * need a feature this proxy does not turn on).
 */
function CveList({ cves }: { cves: SquidCve[] }) {
  return (
    <details className="mt-1 text-[13px]">
      <summary className="cursor-pointer text-ink-secondary">Which {cves.length === 1 ? 'advisory' : `${cves.length} advisories`}</summary>
      <ul className="mt-1 flex flex-col gap-1">
        {cves.map((c) => (
          <li key={c.id} className="text-ink-muted [overflow-wrap:anywhere]">
            <a href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(c.id)}`} target="_blank" rel="noreferrer noopener" className="font-mono text-ink underline-offset-2 hover:underline">
              {c.id}
            </a>{' '}
            ({c.severity}): {c.summary}
          </li>
        ))}
      </ul>
    </details>
  );
}

export function ServicesPanel({ rows, proxyCves }: { rows: ServiceRow[]; proxyCves?: SquidCve[] }) {
  return (
    <Section title="Services">
      <ul className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {rows.map((r) => (
          <li key={r.name} className="flex min-w-0 items-start gap-2.5">
            <span aria-hidden="true" className={cn('mt-1.5 h-2 w-2 shrink-0 rounded-full', DOT[r.health])} />
            <div className="flex min-w-0 flex-col gap-0.5">
              <span className="text-sm font-medium text-ink">
                {r.name} <span className="font-normal text-ink-muted">· {r.state}</span>
              </span>
              <span className="text-[13px] text-ink-muted [overflow-wrap:anywhere]">{r.detail}</span>
              {r.name === 'Proxy' && proxyCves && proxyCves.length > 0 && <CveList cves={proxyCves} />}
            </div>
          </li>
        ))}
      </ul>
    </Section>
  );
}
