/**
 * PostureMark: the mark of a lib/posture state, told apart by shape as well
 * as colour, with the state in words for screen readers.
 *
 * - on: a filled green circle;
 * - worth-knowing: a hollow grey circle;
 * - needs-attention: an orange triangle;
 * - unknown: a dashed grey circle.
 *
 * The colours are the text tokens (success, warning, ink-subtle), each at
 * 3:1 or more on the surface; the *-strong tokens the dots used were 2.62:1
 * and 2.35:1 on white.
 */
import { TriangleAlert } from 'lucide-react';
import { POSTURE_WORD, type Posture } from '../../lib/posture';
import { cn } from '../../lib/utils';

export function PostureMark({ posture, className }: { posture: Posture; className?: string }) {
  return (
    <span data-posture={posture} className={cn('inline-flex h-3.5 w-3.5 flex-none items-center justify-center', className)}>
      {posture === 'needs-attention' ? (
        <TriangleAlert aria-hidden="true" className="h-3.5 w-3.5 text-warning" strokeWidth={2.5} />
      ) : (
        <span
          aria-hidden="true"
          className={cn(
            'block h-2.5 w-2.5 rounded-full',
            posture === 'on' && 'bg-success',
            posture === 'worth-knowing' && 'border-2 border-ink-subtle',
            posture === 'unknown' && 'border border-dashed border-ink-subtle',
          )}
        />
      )}
      <span className="sr-only">{POSTURE_WORD[posture]}: </span>
    </span>
  );
}
