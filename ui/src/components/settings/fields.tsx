/**
 * The rows the rebuilt Settings sections are made of. Each one is bound to
 * a setting key: its value comes from the section draft, its apply badge
 * from the static map, and a message the last save refused for that key is
 * shown under it with aria-invalid on the control. The input id is the key,
 * so a refused field can be focused by name.
 */
import type { ReactNode } from 'react';
import { Switch } from '../ui/Switch';
import { SegmentedControl } from '../ui/SegmentedControl';
import { ApplyBadge } from './ApplyBadge';
import { SecretField } from './SecretField';
import { cn } from '../../lib/utils';
import type { SectionForm } from './sectionForm';

/** The backend's messages start in lower case ("must be a positive number"). */
const sentence = (msg: string) => msg.charAt(0).toUpperCase() + msg.slice(1);

export interface ToggleRowProps {
  form: SectionForm;
  setting: string;
  label: string;
  help: ReactNode;
  /** Shown under the row while the switch is on (the toggle's parameters). */
  children?: ReactNode;
}

export function ToggleRow({ form, setting, label, help, children }: ToggleRowProps) {
  const on = form.values[setting] === 'true';
  const labelId = `${setting}-label`;
  const helpId = `${setting}-help`;
  const error = form.error(setting);
  return (
    <div className="flex flex-col gap-3 border-t border-line-subtle py-4 first:border-t-0 first:pt-0 last:pb-0">
      <div className="flex items-start gap-4">
        <div className="flex min-w-0 flex-1 flex-col gap-0.5">
          <div className="flex flex-wrap items-center gap-2">
            <span id={labelId} className="text-sm font-semibold text-ink">{label}</span>
            <ApplyBadge setting={setting} />
          </div>
          <p id={helpId} className="text-sm leading-5 text-ink-muted">{help}</p>
        </div>
        <Switch
          size="md"
          name={setting}
          labelledBy={labelId}
          describedBy={error ? `${helpId} ${setting}-error` : helpId}
          checked={on}
          onChange={(next) => form.set(setting, next ? 'true' : 'false')}
          className="mt-0.5"
        />
      </div>
      {error && <p id={`${setting}-error`} className="text-sm text-danger">{sentence(error)}</p>}
      {on && children && <div className="flex flex-col gap-4">{children}</div>}
    </div>
  );
}

export interface ChoiceRowProps<V extends string> {
  form: SectionForm;
  setting: string;
  label: string;
  help: ReactNode;
  options: readonly { value: V; label: string }[];
}

/**
 * One of a few values, as a row like ToggleRow: the label, the apply badge
 * and the help on the left, the choices on the right. The group is named by
 * the label.
 */
export function ChoiceRow<V extends string>({ form, setting, label, help, options }: ChoiceRowProps<V>) {
  const labelId = `${setting}-label`;
  const error = form.error(setting);
  const value = form.values[setting] ?? '';
  return (
    <div className="flex flex-col gap-3 border-t border-line-subtle py-4 first:border-t-0 first:pt-0 last:pb-0">
      <div className="flex flex-wrap items-start gap-4">
        <div className="flex min-w-0 flex-1 basis-60 flex-col gap-0.5">
          <div className="flex flex-wrap items-center gap-2">
            <span id={labelId} className="text-sm font-semibold text-ink">{label}</span>
            <ApplyBadge setting={setting} />
          </div>
          <p id={`${setting}-help`} className="text-sm leading-5 text-ink-muted">{help}</p>
        </div>
        <SegmentedControl
          label={label}
          options={options}
          value={value as V}
          onChange={(next) => form.set(setting, next)}
        />
      </div>
      {error && <p id={`${setting}-error`} className="text-sm text-danger">{sentence(error)}</p>}
    </div>
  );
}

export interface SecretRowProps {
  form: SectionForm;
  setting: string;
  label: string;
  placeholder?: string;
}

/**
 * A write-only setting (lib/secrets), bound to the section draft: its id is
 * the key, so a refused value can be focused by name, and the refusal shows
 * under it.
 */
export function SecretRow({ form, setting, label, placeholder }: SecretRowProps) {
  const error = form.error(setting);
  return (
    <SecretField
      id={setting}
      label={label}
      placeholder={placeholder}
      error={error ? sentence(error) : undefined}
      {...form.secretProps(setting)}
    />
  );
}

export interface TextFieldProps {
  form: SectionForm;
  setting: string;
  label: string;
  hint?: ReactNode;
  type?: 'text' | 'time';
  inputMode?: 'numeric' | 'text';
  placeholder?: string;
  className?: string;
}

export function TextField({ form, setting, label, hint, type = 'text', inputMode, placeholder, className }: TextFieldProps) {
  const error = form.error(setting);
  const hintId = `${setting}-hint`;
  const errorId = `${setting}-error`;
  const value = form.values[setting] ?? '';
  const stored = setting in form.stored;
  const describedBy = [hint || !stored ? hintId : '', error ? errorId : ''].filter(Boolean).join(' ') || undefined;
  return (
    <div className={cn('flex min-w-0 flex-col gap-1.5', className)}>
      <label htmlFor={setting} className="text-sm font-medium text-ink">{label}</label>
      <input
        id={setting}
        name={setting}
        type={type}
        inputMode={inputMode}
        placeholder={placeholder}
        value={value}
        onChange={(e) => form.set(setting, e.target.value)}
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy}
        className={cn(
          'h-9 w-full min-w-0 rounded-control border bg-surface px-3 text-sm text-ink placeholder:text-ink-subtle',
          'focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-accent',
          error ? 'border-danger-line' : 'border-line-strong',
        )}
      />
      {(hint || !stored) && (
        <p id={hintId} className="text-xs text-ink-muted">
          {hint}
          {!stored && value === '' && <>{hint ? ' ' : ''}No value is stored for this yet.</>}
        </p>
      )}
      {error && <p id={errorId} className="text-sm text-danger">{sentence(error)}</p>}
    </div>
  );
}
