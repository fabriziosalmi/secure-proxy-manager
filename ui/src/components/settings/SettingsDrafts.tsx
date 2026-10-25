/**
 * The unsaved state of the Settings page: per section, the values the
 * operator changed, the secrets typed or removed, the field errors and the
 * result of the last save. It lives above the routes, so leaving Settings
 * for another page and coming back keeps a draft, and it ends with the
 * session (the provider unmounts on sign-out). While any section holds a
 * draft, closing or reloading the tab asks for confirmation.
 */
import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react';
import type { SectionId } from '../../lib/settingsMeta';
import type { SecretEdit } from '../../lib/secrets';
import type { SaveResult } from '../../lib/settingsSave';
import { SettingsDraftsContext, type DraftState, type SettingsDrafts } from '../../hooks/useSettingsDrafts';

const EMPTY: DraftState = { edits: {}, secretEdits: {}, errors: {}, results: {} };

function without<T>(map: Record<string, T> | undefined, key: string): Record<string, T> {
  const next = { ...(map ?? {}) };
  delete next[key];
  return next;
}

export function SettingsDraftsProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<DraftState>(EMPTY);

  const setEdit = useCallback((section: SectionId, key: string, value: string | undefined) => {
    setState((s) => {
      const current = s.edits[section];
      const next = value === undefined ? without(current, key) : { ...(current ?? {}), [key]: value };
      // Editing a field takes back its error and the last save's result.
      return {
        ...s,
        edits: { ...s.edits, [section]: next },
        errors: { ...s.errors, [section]: without(s.errors[section], key) },
        results: { ...s.results, [section]: undefined },
      };
    });
  }, []);

  const setSecretEdit = useCallback((section: SectionId, key: string, edit: SecretEdit | undefined) => {
    setState((s) => {
      const current = s.secretEdits[section];
      const next = edit === undefined ? without(current, key) : { ...(current ?? {}), [key]: edit };
      return {
        ...s,
        secretEdits: { ...s.secretEdits, [section]: next },
        errors: { ...s.errors, [section]: without(s.errors[section], key) },
        results: { ...s.results, [section]: undefined },
      };
    });
  }, []);

  const setErrors = useCallback((section: SectionId, errors: Record<string, string> | undefined) => {
    setState((s) => ({ ...s, errors: { ...s.errors, [section]: errors } }));
  }, []);

  const setResult = useCallback((section: SectionId, result: SaveResult | undefined) => {
    setState((s) => ({ ...s, results: { ...s.results, [section]: result } }));
  }, []);

  const discard = useCallback((section: SectionId) => {
    setState((s) => ({
      edits: { ...s.edits, [section]: {} },
      secretEdits: { ...s.secretEdits, [section]: {} },
      errors: { ...s.errors, [section]: {} },
      results: { ...s.results, [section]: undefined },
    }));
  }, []);

  const anyDirty = useMemo(
    () => Object.values(state.edits).some((e) => e && Object.keys(e).length > 0)
      || Object.values(state.secretEdits).some((e) => e && Object.keys(e).length > 0),
    [state],
  );

  // The browser's own "leave site?" prompt; its text cannot be set.
  useEffect(() => {
    if (!anyDirty) return;
    const warn = (e: BeforeUnloadEvent) => {
      e.preventDefault();
      e.returnValue = '';
    };
    window.addEventListener('beforeunload', warn);
    return () => window.removeEventListener('beforeunload', warn);
  }, [anyDirty]);

  const value = useMemo<SettingsDrafts>(
    () => ({ ...state, setEdit, setSecretEdit, setErrors, setResult, discard, anyDirty }),
    [state, setEdit, setSecretEdit, setErrors, setResult, discard, anyDirty],
  );
  return <SettingsDraftsContext.Provider value={value}>{children}</SettingsDraftsContext.Provider>;
}
