/**
 * SettingsNav: the list of Settings sections, one link per section URL
 * (/settings/<id>). On wide screens it is a vertical list beside the
 * section. Below lg it collapses into one sticky button that names the
 * current section and opens the same list; following a link closes it.
 *
 * The current section carries aria-current="page". A section with unsaved
 * changes shows a dot (and says so to a screen reader); Overview shows how
 * many items need attention.
 */
import { useId, useState } from 'react';
import { Link } from 'react-router';
import { ChevronDown } from 'lucide-react';
import { SECTIONS, sectionPath, type SectionId } from '../../lib/settingsMeta';
import { useMediaQuery, DESKTOP_QUERY } from '../../hooks/useMediaQuery';
import { cn } from '../../lib/utils';

export interface SettingsNavProps {
  current: SectionId;
  /** Unsaved changes per section. */
  dirty?: Partial<Record<SectionId, number>>;
  /** Items that need attention, shown on Overview; undefined while unknown. */
  attention?: number;
}

function unsavedText(n: number) {
  return n === 1 ? '1 unsaved change' : `${n} unsaved changes`;
}

function SectionList({ current, dirty = {}, attention, onPick, id }: SettingsNavProps & { onPick?: () => void; id?: string }) {
  return (
    <ul id={id} className="flex flex-col gap-0.5">
      {SECTIONS.map((s) => {
        const active = s.id === current;
        const changes = dirty[s.id] ?? 0;
        const badge = s.id === 'overview' && attention ? attention : 0;
        // One name, built here: browsers join the parts of a flex link with
        // different spacing, so the dot and badge only repeat it visually.
        let name = s.label;
        if (changes > 0) name += `, ${unsavedText(changes)}`;
        if (badge > 0) name += `, ${badge} ${badge === 1 ? 'item needs' : 'items need'} attention`;
        return (
          <li key={s.id}>
            <Link
              to={sectionPath(s.id)}
              onClick={onPick}
              aria-current={active ? 'page' : undefined}
              aria-label={name}
              className={cn(
                'flex h-9 items-center gap-2 rounded-control px-3 text-sm transition-colors',
                'focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-accent',
                active ? 'bg-surface font-semibold text-ink shadow-[0_0_0_1px_var(--color-line)]' : 'font-medium text-ink-muted hover:bg-surface-muted hover:text-ink',
              )}
            >
              <span className="min-w-0 flex-1 truncate">{s.label}</span>
              {changes > 0 && (
                <span aria-hidden="true" data-testid={`dirty-${s.id}`} className="h-2 w-2 flex-none rounded-full bg-accent-solid" />
              )}
              {badge > 0 && (
                <span aria-hidden="true" className="flex-none rounded-full bg-warning-subtle px-2 text-xs font-semibold text-warning">{badge}</span>
              )}
            </Link>
          </li>
        );
      })}
    </ul>
  );
}

export function SettingsNav(props: SettingsNavProps) {
  const isDesktop = useMediaQuery(DESKTOP_QUERY);
  const listId = useId();
  // Open only on the section it was opened on, so following a link (or the
  // back button) closes it without an effect.
  const [openOn, setOpenOn] = useState<SectionId | null>(null);
  const open = openOn === props.current;

  if (isDesktop) {
    return (
      <nav aria-label="Settings sections" className="sticky top-0 w-[220px] flex-none self-start pt-1">
        <SectionList {...props} />
      </nav>
    );
  }

  const current = SECTIONS.find((s) => s.id === props.current);
  const total = Object.values(props.dirty ?? {}).reduce((a, b) => a + (b ?? 0), 0);
  return (
    <nav aria-label="Settings sections" className="sticky top-14 z-20 -mx-4 border-b border-line bg-ground/95 px-4 py-2 backdrop-blur">
      <button
        type="button"
        aria-expanded={open}
        aria-controls={listId}
        onClick={() => setOpenOn(open ? null : props.current)}
        className="flex h-11 w-full items-center gap-2 rounded-control border border-line-strong bg-surface px-3 text-left text-sm text-ink focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-accent"
      >
        <span className="min-w-0 flex-1 truncate">
          <span className="text-ink-muted">Section:</span>{' '}
          <span className="font-semibold">{current?.label}</span>
        </span>
        {total > 0 && <span className="flex-none text-xs text-accent">{unsavedText(total)}</span>}
        <ChevronDown aria-hidden="true" className={cn('h-4 w-4 flex-none transition-transform', open && 'rotate-180')} />
      </button>
      {open && (
        <div className="mt-2 rounded-control border border-line bg-surface-muted p-1">
          <SectionList {...props} id={listId} onPick={() => setOpenOn(null)} />
        </div>
      )}
    </nav>
  );
}
