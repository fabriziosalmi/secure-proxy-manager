import { useEffect, useRef, useState } from 'react';

/**
 * Animates a number from its previous value to a new target.
 * Uses requestAnimationFrame for smooth 60fps interpolation.
 */
export function useAnimatedNumber(target: number, duration = 600): number {
  const [display, setDisplay] = useState(target);
  const prev = useRef(target);
  const raf = useRef(0);

  useEffect(() => {
    const from = prev.current;
    const delta = target - from;
    if (delta === 0) return;

    const start = performance.now();
    const step = (now: number) => {
      const elapsed = now - start;
      const progress = Math.min(elapsed / duration, 1);
      // ease-out cubic
      const eased = 1 - Math.pow(1 - progress, 3);
      const current = from + delta * eased;
      setDisplay(Math.round(current));
      if (progress < 1) {
        raf.current = requestAnimationFrame(step);
      } else {
        prev.current = target;
      }
    };

    raf.current = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf.current);
  }, [target, duration]);

  return display;
}
