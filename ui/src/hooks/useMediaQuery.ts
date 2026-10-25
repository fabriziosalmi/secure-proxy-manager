import { useCallback, useSyncExternalStore } from 'react';

/**
 * Whether a CSS media query matches, kept in sync as the window changes.
 * False where matchMedia is missing, so a test or an old browser gets the
 * small-screen layout rather than an exception.
 */
export function useMediaQuery(query: string): boolean {
  const subscribe = useCallback(
    (notify: () => void) => {
      if (typeof window === 'undefined' || !window.matchMedia) return () => {};
      const mql = window.matchMedia(query);
      mql.addEventListener?.('change', notify);
      return () => mql.removeEventListener?.('change', notify);
    },
    [query],
  );
  const read = () => (typeof window !== 'undefined' && window.matchMedia ? window.matchMedia(query).matches : false);
  return useSyncExternalStore(subscribe, read, () => false);
}

/** Tailwind's lg breakpoint: the sidebar is static at this width and up. */
export const DESKTOP_QUERY = '(min-width: 1024px)';
