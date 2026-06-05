import { useEffect, useState } from 'react';

const QUERY = '(prefers-reduced-motion: reduce)';

/**
 * Returns true when the user has asked the OS to reduce motion. Components use it
 * to skip JS-driven animation (e.g. the rAF number counter, recharts mount
 * animations). Purely CSS animations are neutralized globally in index.css; this
 * hook covers the cases CSS can't reach.
 */
export function useReducedMotion(): boolean {
  const [reduced, setReduced] = useState<boolean>(() => {
    if (typeof window === 'undefined' || !window.matchMedia) return false;
    return window.matchMedia(QUERY).matches;
  });

  useEffect(() => {
    if (typeof window === 'undefined' || !window.matchMedia) return;
    // The initial value comes from the useState initializer (client-only SPA);
    // the effect only registers the change listener, so there's no synchronous
    // setState here.
    const mql = window.matchMedia(QUERY);
    const onChange = () => setReduced(mql.matches);
    mql.addEventListener('change', onChange);
    return () => mql.removeEventListener('change', onChange);
  }, []);

  return reduced;
}
