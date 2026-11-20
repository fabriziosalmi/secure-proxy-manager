/**
 * InfoTip: an info icon that explains what sits next to it. The text is the
 * button's accessible description (aria-describedby), so a screen reader
 * reads it with the button, and it shows as a tooltip while the pointer is on
 * the icon or the tooltip, and while the icon has keyboard focus. Escape
 * closes it until the pointer leaves or the focus moves (WCAG 1.4.13: the
 * tooltip can be hovered, dismissed, and stays until then).
 *
 * The tooltip opens below the icon, so in the page band it lies over the top
 * of the content instead of being cut by the top of the window. Closed, it
 * takes no room (a hidden box still widened a phone's page); open, it is
 * moved left as far as needed to stay inside the window.
 */
import { useEffect, useId, useLayoutEffect, useRef, useState, type ReactNode } from 'react';
import { Info } from 'lucide-react';
import { cn } from '../../lib/utils';

export interface InfoTipProps {
  /** The button's name, such as "About Access logs". */
  label: string;
  children: ReactNode;
  className?: string;
}

/** The space kept between an open tooltip and the right edge of the window. */
const EDGE = 8;

export function InfoTip({ label, children, className }: InfoTipProps) {
  const id = useId();
  const tipRef = useRef<HTMLSpanElement>(null);
  const [hovered, setHovered] = useState(false);
  const [focused, setFocused] = useState(false);
  const [dismissed, setDismissed] = useState(false);
  const open = (hovered || focused) && !dismissed;

  // Escape closes it wherever the focus is: hovering does not move the focus to the icon.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setDismissed(true); };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [open]);

  useLayoutEffect(() => {
    const tip = tipRef.current;
    if (!tip || !open) return;
    tip.style.left = '0px';
    const past = tip.getBoundingClientRect().right - (document.documentElement.clientWidth - EDGE);
    if (past > 0) tip.style.left = `${-Math.ceil(past)}px`;
  }, [open]);

  return (
    <span
      className={cn('relative inline-flex shrink-0', className)}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => { setHovered(false); setDismissed(false); }}
    >
      <button
        type="button"
        aria-label={label}
        aria-describedby={id}
        onFocus={() => setFocused(true)}
        onBlur={() => { setFocused(false); setDismissed(false); }}
        className="flex h-7 w-7 items-center justify-center rounded-control text-ink-subtle transition-colors hover:bg-surface-muted hover:text-ink focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-accent"
      >
        <Info aria-hidden="true" className="h-4 w-4" strokeWidth={1.75} />
      </button>
      {/* The top padding bridges the gap to the icon, so the pointer can move onto the text. */}
      <span
        ref={tipRef}
        role="tooltip"
        id={id}
        data-state={open ? 'open' : 'closed'}
        className={cn('absolute left-0 top-full z-30 pt-1.5', open ? 'block' : 'hidden')}
      >
        <span className="block w-max max-w-[min(20rem,calc(100vw-2rem))] rounded-control border border-line bg-surface px-3 py-2 text-[13px] font-normal leading-5 text-ink-secondary shadow-[0_8px_16px_rgba(16,24,40,0.12)]">
          {children}
        </span>
      </span>
    </span>
  );
}
