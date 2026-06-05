import { useEffect, useRef } from 'react';

const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

/**
 * Wires modal accessibility onto a dialog container: focuses the first focusable
 * element on open, traps Tab/Shift+Tab within it, closes on Escape, and restores
 * focus to whatever was focused before it opened (WCAG 2.4.3 / 2.1.2).
 *
 * Attach the returned ref to the dialog's content element. Pass `onClose` to
 * enable Escape-to-close; omit it for a non-dismissible gate (e.g. first-run
 * wizard) — focus is still trapped, Escape just does nothing.
 */
export function useModal<T extends HTMLElement>(isOpen: boolean, onClose?: () => void) {
  const ref = useRef<T>(null);
  const restoreRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (!isOpen) return;
    const container = ref.current;
    restoreRef.current = (document.activeElement as HTMLElement) ?? null;

    const focusable = () =>
      container
        ? Array.from(container.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(
            (el) => el.offsetParent !== null,
          )
        : [];

    focusable()[0]?.focus();

    // Listen on document so Escape closes the open modal regardless of where
    // focus sits (and the Tab trap can pull focus back if it ever escapes the
    // container), rather than relying on the event bubbling up from inside.
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        if (onClose) {
          e.preventDefault();
          onClose();
        }
        return;
      }
      if (e.key !== 'Tab' || !container) return;
      const items = focusable();
      if (items.length === 0) return;
      const first = items[0];
      const last = items[items.length - 1];
      if (!container.contains(document.activeElement)) {
        e.preventDefault();
        first.focus();
      } else if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    };

    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('keydown', onKeyDown);
      restoreRef.current?.focus?.();
    };
  }, [isOpen, onClose]);

  return ref;
}
