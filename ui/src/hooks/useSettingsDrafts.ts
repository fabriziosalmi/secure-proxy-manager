import { createContext, useContext } from 'react';
import type { SectionId } from '../lib/settingsMeta';
import type { SecretEdit } from '../lib/secrets';
import type { SaveResult } from '../lib/settingsSave';

type PerSection<T> = Partial<Record<SectionId, T>>;

export interface DraftState {
  edits: PerSection<Record<string, string>>;
  secretEdits: PerSection<Record<string, SecretEdit>>;
  errors: PerSection<Record<string, string>>;
  results: PerSection<SaveResult>;
}

/** The unsaved state of the Settings page (components/settings/SettingsDrafts). */
export interface SettingsDrafts extends DraftState {
  /** Record a changed value; undefined drops the change. */
  setEdit: (section: SectionId, key: string, value: string | undefined) => void;
  setSecretEdit: (section: SectionId, key: string, edit: SecretEdit | undefined) => void;
  setErrors: (section: SectionId, errors: Record<string, string> | undefined) => void;
  setResult: (section: SectionId, result: SaveResult | undefined) => void;
  /** Forget every change in a section. */
  discard: (section: SectionId) => void;
  /** Whether any section holds a change. */
  anyDirty: boolean;
}

export const SettingsDraftsContext = createContext<SettingsDrafts | null>(null);

/** The drafts, or null outside a provider. */
export function useSettingsDraftsOptional(): SettingsDrafts | null {
  return useContext(SettingsDraftsContext);
}

export function useSettingsDrafts(): SettingsDrafts {
  const ctx = useContext(SettingsDraftsContext);
  if (!ctx) throw new Error('useSettingsDrafts needs a SettingsDraftsProvider');
  return ctx;
}
