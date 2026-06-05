import { renderHook } from '@testing-library/react';
import { describe, it, expect, vi, afterEach } from 'vitest';
import { useAnimatedNumber } from './useAnimatedNumber';

function setReducedMotion(matches: boolean) {
  (globalThis as { matchMedia: unknown }).matchMedia = (query: string) => ({
    matches,
    media: query,
    onchange: null,
    addEventListener: () => {},
    removeEventListener: () => {},
    addListener: () => {},
    removeListener: () => {},
    dispatchEvent: () => false,
  });
}

afterEach(() => setReducedMotion(false));

describe('useAnimatedNumber', () => {
  it('snaps straight to the target under reduced motion, with no rAF', () => {
    setReducedMotion(true);
    const rafSpy = vi.spyOn(globalThis, 'requestAnimationFrame');

    const { result, rerender } = renderHook(({ t }) => useAnimatedNumber(t), {
      initialProps: { t: 0 },
    });
    rerender({ t: 100 });

    expect(result.current).toBe(100);
    expect(rafSpy).not.toHaveBeenCalled();
    rafSpy.mockRestore();
  });
});
