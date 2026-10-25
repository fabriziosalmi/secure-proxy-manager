/**
 * Appearance: the dashboard's theme. A preference of this browser (the
 * ThemeProvider keeps it in localStorage, guarded for blocked storage), not
 * a proxy setting, so it applies at once and has no Save. System follows the
 * operating system's light or dark setting as it changes.
 */
import { useId } from 'react';
import { useTheme, type Theme } from '../../ThemeProvider';
import { Section } from '../../ui/Section';
import { cn } from '../../../lib/utils';

const OPTIONS: { value: Theme; label: string; help: string }[] = [
  { value: 'auto', label: 'System', help: "Follows the device's light or dark setting, also when it changes." },
  { value: 'light', label: 'Light', help: 'Always light.' },
  { value: 'dark', label: 'Dark', help: 'Always dark.' },
];

export function AppearanceSection() {
  const { theme, setTheme } = useTheme();
  const id = useId();
  return (
    <Section level={3} title="Theme">
      <fieldset className="flex flex-col gap-3" aria-describedby={`${id}-note`}>
        <legend className="sr-only">Theme</legend>
        {OPTIONS.map((o) => (
          <label
            key={o.value}
            className={cn(
              'flex cursor-pointer items-start gap-3 rounded-control border px-3 py-2.5',
              theme === o.value ? 'border-accent-line bg-accent-subtle' : 'border-line hover:bg-surface-muted',
            )}
          >
            <input
              type="radio"
              name={`${id}-theme`}
              value={o.value}
              checked={theme === o.value}
              onChange={() => setTheme(o.value)}
              aria-describedby={`${id}-${o.value}`}
              className="mt-1 h-4 w-4 accent-[var(--color-accent-solid)]"
            />
            <span className="flex flex-col">
              <span className="text-sm font-semibold text-ink">{o.label}</span>
              <span id={`${id}-${o.value}`} className="text-sm text-ink-muted">{o.help}</span>
            </span>
          </label>
        ))}
      </fieldset>
      <p id={`${id}-note`} className="mt-3 text-sm text-ink-muted">Saved in this browser only.</p>
    </Section>
  );
}
