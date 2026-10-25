/**
 * SecretField: a write-only setting (an alert channel token or URL). The
 * backend never returns the value, so the field shows only what is known:
 * Set, Not set, or Cannot be read (a stored value the backend cannot decrypt
 * with its current key). Typing replaces the stored value on save; Remove
 * clears it on save; Undo drops either change. A field left alone is not
 * sent at all, so saving never overwrites a secret nobody retyped.
 */
import { useId } from 'react';
import { Badge, type BadgeTone } from '../ui/Badge';
import { Button } from '../ui/Button';
import { cn } from '../../lib/utils';
import type { SecretEdit, SecretState } from '../../lib/secrets';

const STATE: Record<SecretState, { text: string; tone: BadgeTone }> = {
  set: { text: 'Set', tone: 'success' },
  unset: { text: 'Not set', tone: 'neutral' },
  unreadable: { text: 'Cannot be read, re-enter it', tone: 'warning' },
};

export interface SecretFieldProps {
  label: string;
  state: SecretState;
  edit?: SecretEdit;
  onEdit: (edit: SecretEdit | undefined) => void;
  /** Example shown in an empty field that has no stored value. */
  placeholder?: string;
  /** A message from the backend about this field. */
  error?: string;
  /** id for the input; one is generated when omitted. */
  id?: string;
}

export function SecretField({ label, state, edit, onEdit, placeholder, error, id }: SecretFieldProps) {
  const auto = useId();
  const inputId = id ?? `${auto}-input`;
  const hintId = `${inputId}-hint`;
  const errorId = `${inputId}-error`;
  const s = STATE[state];
  const clearing = edit?.kind === 'clear';
  const typed = edit?.kind === 'replace' ? edit.value : '';

  let hint: string;
  if (clearing) hint = 'Will be removed when you save.';
  else if (typed) hint = 'Replaces the stored value when you save.';
  else if (state === 'set') hint = 'A value is stored. It is never shown; type a new one to replace it.';
  else if (state === 'unreadable') hint = 'A value is stored but the backend cannot decrypt it with its current key. Type it again, or remove it.';
  else hint = 'No value stored.';

  return (
    <div className="flex flex-col gap-1.5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <label htmlFor={inputId} className="text-sm font-medium text-ink">{label}</label>
        <Badge tone={s.tone}>{s.text}</Badge>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <input
          id={inputId}
          type="password"
          autoComplete="new-password"
          spellCheck={false}
          value={typed}
          disabled={clearing}
          placeholder={state === 'unset' ? placeholder : 'Type a new value'}
          aria-describedby={error ? `${hintId} ${errorId}` : hintId}
          aria-invalid={error ? true : undefined}
          onChange={(e) => onEdit(e.target.value === '' ? undefined : { kind: 'replace', value: e.target.value })}
          className={cn(
            'h-9 min-w-0 flex-1 rounded-control border bg-surface px-3 text-sm text-ink placeholder:text-ink-subtle',
            'focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-accent disabled:opacity-60',
            error ? 'border-danger-line' : 'border-line-strong',
          )}
        />
        {state !== 'unset' && !edit && (
          <Button size="sm" variant="ghost" onClick={() => onEdit({ kind: 'clear' })} aria-label={`Remove ${label}`}>
            Remove
          </Button>
        )}
        {edit && (
          <Button size="sm" variant="ghost" onClick={() => onEdit(undefined)} aria-label={`Undo the change to ${label}`}>
            Undo
          </Button>
        )}
      </div>
      <p id={hintId} className="text-xs text-ink-muted">{hint}</p>
      {error && <p id={errorId} className="text-xs text-danger">{error}</p>}
    </div>
  );
}
