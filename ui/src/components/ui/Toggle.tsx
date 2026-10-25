import { Switch } from './Switch';

interface ToggleProps {
  /** Controlled on/off state. */
  checked: boolean;
  /** Called with the next boolean state when toggled. */
  onChange: (next: boolean) => void;
  /** Accessible name: the switch's visible label usually sits beside it as a
   *  sibling, so it isn't programmatically associated without this. */
  label: string;
  /** Optional form-field name, preserved for parity with the old checkbox markup. */
  name?: string;
  size?: 'sm' | 'md';
  className?: string;
}

/**
 * The switch the existing pages use, now drawn by the shared Switch (same
 * role="switch", aria-checked and keyboard handling, new tokens). New code
 * should import Switch directly; this name stays so the pages need no change
 * until they are rebuilt.
 */
export function Toggle(props: ToggleProps) {
  return <Switch {...props} />;
}
