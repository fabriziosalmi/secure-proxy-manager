/**
 * Services: one line per service, from serviceRows (services.ts). The dot
 * repeats the state the text already says and is hidden from screen readers.
 */
import { cn } from '../../lib/utils';
import { Section } from '../ui/Section';
import type { Health, ServiceRow } from './services';

const DOT: Record<Health, string> = {
  ok: 'bg-success',
  down: 'bg-danger',
  unknown: 'bg-ink-subtle',
};

export function ServicesPanel({ rows }: { rows: ServiceRow[] }) {
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
            </div>
          </li>
        ))}
      </ul>
    </Section>
  );
}
