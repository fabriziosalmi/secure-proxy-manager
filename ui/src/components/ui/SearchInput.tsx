/**
 * SearchInput: a search or filter field with a search icon. The label is
 * required and visually hidden: a placeholder is not an accessible name (it
 * disappears once the field has a value), so the field is always named by a
 * real <label>. type="search" gives the native clear button and Escape.
 */
import { forwardRef, type InputHTMLAttributes } from 'react';
import { Search } from 'lucide-react';
import { cn } from '../../lib/utils';

export interface SearchInputProps extends Omit<InputHTMLAttributes<HTMLInputElement>, 'type' | 'onChange' | 'value'> {
  /** Accessible name, read by screen readers; not shown. */
  label: string;
  value: string;
  onChange: (value: string) => void;
}

export const SearchInput = forwardRef<HTMLInputElement, SearchInputProps>(function SearchInput(
  { label, value, onChange, className, ...rest },
  ref,
) {
  return (
    <label
      className={cn(
        'flex h-9 min-w-0 items-center gap-2 rounded-control border border-line-strong bg-surface px-3 text-ink-subtle',
        'focus-within:border-accent focus-within:ring-2 focus-within:ring-accent/30',
        className,
      )}
    >
      <Search aria-hidden="true" className="h-4 w-4 shrink-0" strokeWidth={1.75} />
      <span className="sr-only">{label}</span>
      <input
        ref={ref}
        type="search"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="h-full min-w-0 flex-1 bg-transparent text-sm text-ink outline-hidden placeholder:text-ink-subtle"
        {...rest}
      />
    </label>
  );
});
