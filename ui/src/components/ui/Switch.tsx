/**
 * Switch: an on/off setting that applies as soon as it is flipped, or that a
 * section's Save applies. A real button with role="switch" and aria-checked,
 * so Space and Enter work natively and a screen reader hears "on" or "off".
 *
 * Name it with label (sets aria-label) or, when the visible label is already
 * on the page, with labelledBy (the id of that element), so the name is read
 * from the text the user sees.
 */
import { cn } from '../../lib/utils';

type SwitchName =
  | { label: string; labelledBy?: undefined }
  | { labelledBy: string; label?: undefined };

export type SwitchProps = SwitchName & {
  checked: boolean;
  onChange: (next: boolean) => void;
  /** Optional form-field name, kept on the element as data-name. */
  name?: string;
  size?: 'sm' | 'md';
  disabled?: boolean;
  className?: string;
};

export function Switch({ checked, onChange, label, labelledBy, name, size = 'sm', disabled, className }: SwitchProps) {
  const track = size === 'md' ? 'h-[22px] w-10' : 'h-[18px] w-8';
  const knob = size === 'md' ? 'h-[18px] w-[18px]' : 'h-3.5 w-3.5';
  const travel = size === 'md' ? 'translate-x-[18px]' : 'translate-x-3.5';
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      aria-labelledby={labelledBy}
      data-name={name}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={cn(
        'relative inline-flex shrink-0 cursor-pointer items-center rounded-full p-0.5 transition-colors',
        'focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2 focus-visible:ring-offset-surface',
        'disabled:cursor-not-allowed disabled:opacity-50',
        track,
        checked ? 'bg-accent-solid' : 'bg-line-strong',
        className,
      )}
    >
      <span
        aria-hidden="true"
        className={cn(
          'pointer-events-none block rounded-full bg-white shadow-[0_1px_2px_rgba(16,24,40,0.2)] transition-transform',
          knob,
          checked ? travel : 'translate-x-0',
        )}
      />
    </button>
  );
}
