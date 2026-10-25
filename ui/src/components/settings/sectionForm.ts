import type { ChangeEvent } from 'react';
import type { SecretEdit, SecretState } from '../../lib/secrets';

/**
 * What a Settings section reads and writes. values is the draft (the stored
 * values with the unsaved changes on top), stored is what the backend has.
 */
export interface SectionForm {
  values: Record<string, string>;
  stored: Record<string, string>;
  /** The same draft as values, for code that still names it formData. */
  formData: Record<string, string>;
  set: (key: string, value: string) => void;
  setFormData: (update: (prev: Record<string, string>) => Record<string, string>) => void;
  handleChange: (e: ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) => void;
  secretProps: (key: string) => { state: SecretState; edit?: SecretEdit; onEdit: (edit: SecretEdit | undefined) => void };
  /** The message for a field the last save refused, if any. */
  error: (key: string) => string | undefined;
}
