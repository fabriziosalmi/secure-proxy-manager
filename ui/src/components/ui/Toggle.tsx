interface ToggleProps {
  /** Controlled on/off state. */
  checked: boolean;
  /** Called with the next boolean state when toggled. */
  onChange: (next: boolean) => void;
  /** Accessible name — the switch's visible label usually sits beside it as a
   *  sibling, so it isn't programmatically associated without this. */
  label: string;
  /** Optional form-field name, preserved for parity with the old checkbox markup. */
  name?: string;
  size?: 'sm' | 'md';
  className?: string;
}

/**
 * Accessible on/off switch: a real `role="switch"` with `aria-checked`, a visible
 * keyboard focus ring, and native button keyboard handling (Space/Enter). Replaces
 * the ad-hoc `sr-only peer` checkbox toggles, which announced as checkboxes and had
 * no (or an explicitly suppressed) focus indicator.
 */
export function Toggle({ checked, onChange, label, name, size = 'sm', className }: ToggleProps) {
  const track = size === 'md' ? 'w-11 h-6' : 'w-9 h-5';
  const thumb = size === 'md' ? 'h-5 w-5' : 'h-4 w-4';
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      data-name={name}
      onClick={() => onChange(!checked)}
      className={`relative inline-flex ${track} shrink-0 cursor-pointer items-center rounded-full transition-colors
        focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/60 focus-visible:ring-offset-2 focus-visible:ring-offset-background
        ${checked ? 'bg-primary' : 'bg-secondary'} ${className ?? ''}`}
    >
      <span
        className={`pointer-events-none absolute top-[2px] left-[2px] ${thumb} rounded-full bg-white transition-transform ${
          checked ? 'translate-x-full' : 'translate-x-0'
        }`}
      />
    </button>
  );
}
