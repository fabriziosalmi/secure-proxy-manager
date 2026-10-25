import type { LegacyForm } from './LegacySections';

/**
 * What a Settings section reads and writes. values is the draft (the stored
 * values with the unsaved changes on top), stored is what the backend has.
 */
export interface SectionForm extends LegacyForm {
  values: Record<string, string>;
  stored: Record<string, string>;
  set: (key: string, value: string) => void;
  /** The message for a field the last save refused, if any. */
  error: (key: string) => string | undefined;
}
