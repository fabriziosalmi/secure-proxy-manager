/**
 * Settings: one section at a time, at /settings/<section> (lib/settingsMeta
 * lists the sections in task order). /settings and an unknown section go to
 * Overview. The section nav sits beside the section on wide screens and
 * collapses into a switcher below lg.
 *
 * Save model: each section has its own draft (SettingsDrafts), a dot in the
 * nav while it holds changes, and a sticky bar with Discard and Save
 * section. A Save sends every key of the section that has a value and
 * nothing else, then reports what happened: whether the proxy applied it,
 * did not confirm in time or refused it, which files could not be written,
 * and where else the change takes effect. A 400 that names a field is shown
 * under that field.
 */
import axios from 'axios';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useMemo, useRef, useState } from 'react';
import { Navigate, useParams } from 'react-router';
import type { SettingRow } from '../types';
import { api, getData, getErrorMessage } from '../lib/api';
import { PageHeader } from '../components/ui/PageHeader';
import { Notice } from '../components/ui/Notice';
import { SettingsNav } from '../components/settings/SettingsNav';
import { SaveBar } from '../components/settings/SaveBar';
import { SettingsDraftsProvider } from '../components/settings/SettingsDrafts';
import { useSettingsDrafts, useSettingsDraftsOptional } from '../hooks/useSettingsDrafts';
import { LegacyAdmin, LegacyAlerts, LegacyEngine, LegacyInspection, LegacyLogs } from '../components/settings/LegacySections';
import { OverviewSection } from '../components/settings/sections/OverviewSection';
import { AccessSection } from '../components/settings/sections/AccessSection';
import { FilteringSection } from '../components/settings/sections/FilteringSection';
import { needsAttention, type AttentionItem } from '../lib/attention';
import { egressTotalQuery, statusQuery } from '../lib/queries';
import type { SectionForm } from '../components/settings/sectionForm';
import { parseSettings, secretStateOf } from '../lib/secrets';
import { applyToProxy } from '../lib/reload';
import { rowsAfterSave, sectionRequest } from '../lib/settingsSave';
import { parseFieldError, validateSection } from '../lib/settingsValidation';
import {
  DEFAULT_SECTION, SECTIONS, SECTION_KEYS, fieldLabel, sectionById, sectionOfKey, sectionPath,
  type SectionDef, type SectionId,
} from '../lib/settingsMeta';
import { useMediaQuery, DESKTOP_QUERY } from '../hooks/useMediaQuery';

const SETTINGS_KEY = ['settings'] as const;

// Sections that show a refused value's message under the field itself. The
// others (their controls are rebuilt in part B) list the messages after the
// section, each one moving focus to its field.
const INLINE_ERRORS: SectionId[] = ['access', 'filtering'];

interface BodyProps {
  section: SectionDef;
  form: SectionForm;
  rows: SettingRow[] | undefined;
  attention: AttentionItem[];
  attentionLoading: boolean;
  dirty: Record<SectionId, number>;
}

function SectionBody({ section, form, rows, attention, attentionLoading, dirty }: BodyProps) {
  switch (section.id) {
    case 'overview': return <OverviewSection form={form} rows={rows} attention={attention} attentionLoading={attentionLoading} dirty={dirty} />;
    case 'access': return <AccessSection form={form} />;
    case 'filtering': return <FilteringSection form={form} />;
    case 'inspection': return <LegacyInspection form={form} />;
    case 'alerts': return <LegacyAlerts form={form} />;
    case 'logs': return <LegacyLogs form={form} />;
    case 'admin': return <LegacyAdmin />;
    case 'engine': return <LegacyEngine form={form} />;
  }
}

function SettingsPage() {
  const { section: sectionParam } = useParams<{ section: string }>();
  const section = sectionById(sectionParam);
  const isDesktop = useMediaQuery(DESKTOP_QUERY);
  const queryClient = useQueryClient();
  const drafts = useSettingsDrafts();
  const settings = useQuery<SettingRow[]>({
    queryKey: SETTINGS_KEY,
    queryFn: () => getData<SettingRow[]>('settings'),
  });
  const rows = settings.data;
  const status = useQuery({ ...statusQuery, staleTime: 10_000 });
  const egress = useQuery(egressTotalQuery);
  const parsed = useMemo(() => parseSettings(rows), [rows]);
  const [saving, setSaving] = useState<SectionId | null>(null);
  // Synchronous latch against a double click posting twice.
  const savingRef = useRef(false);

  // The draft of every section on top of the stored values. Each key belongs
  // to one section, so the drafts never overlap.
  const values = useMemo(() => {
    const merged = { ...parsed.values };
    for (const e of Object.values(drafts.edits)) Object.assign(merged, e);
    return merged;
  }, [parsed.values, drafts.edits]);

  // The Overview's list, and its count on the nav. The stored values, not
  // the drafts: it describes what is running.
  const attention = useMemo(() => needsAttention({
    values: parsed.values,
    secrets: parsed.secrets,
    proxyStatus: status.isError ? null : status.data ? (status.data.proxy_status ?? 'unknown') : undefined,
    egressTotal: egress.isError ? null : egress.data,
  }), [parsed, status.isError, status.data, egress.isError, egress.data]);
  const warnings = attention.filter((a) => a.tone === 'warning').length;

  const changesIn = (id: SectionId) =>
    Object.keys(drafts.edits[id] ?? {}).length + Object.keys(drafts.secretEdits[id] ?? {}).length;
  const dirty = Object.fromEntries(SECTIONS.map((s) => [s.id, changesIn(s.id)])) as Record<SectionId, number>;

  if (!section) return <Navigate to={sectionPath(DEFAULT_SECTION)} replace />;
  const id = section.id;

  // A change is filed under the section that owns the key, wherever it was
  // made (a profile on Overview changes several sections). A value equal to
  // the stored one is no change.
  const setValue = (key: string, value: string) => {
    const owner = sectionOfKey(key);
    if (!owner) return;
    drafts.setEdit(owner, key, value === (parsed.values[key] ?? '') ? undefined : value);
  };

  const form: SectionForm = {
    values,
    stored: parsed.values,
    formData: values,
    set: setValue,
    setFormData: (update) => {
      const next = update(values);
      for (const k of new Set([...Object.keys(next), ...Object.keys(values)])) {
        if (next[k] !== values[k]) setValue(k, next[k] ?? '');
      }
    },
    handleChange: (e) => setValue(e.target.name, e.target.value),
    secretProps: (key) => {
      const owner = sectionOfKey(key) ?? id;
      return {
        state: secretStateOf(parsed.secrets, key),
        edit: drafts.secretEdits[owner]?.[key],
        onEdit: (edit) => drafts.setSecretEdit(owner, key, edit),
      };
    },
    error: (key) => drafts.errors[id]?.[key],
  };

  const focusField = (key: string) => {
    requestAnimationFrame(() => document.getElementById(key)?.focus());
  };

  const save = async () => {
    if (savingRef.current) return;
    const req = sectionRequest(id, parsed.values, drafts.edits[id] ?? {}, drafts.secretEdits[id] ?? {});
    const errors = validateSection(id, values, req.sent);
    // An empty allowlist with default-deny on leaves only LAN destinations
    // and Allowed IPs reachable (lib/egress).
    if (id === 'filtering' && values.egress_default_deny === 'true' && egress.data === 0) {
      errors.egress_default_deny = 'the egress allowlist is empty, so clients would reach only LAN destinations and the addresses on Allowed IPs: add destinations first';
    }
    if (Object.keys(errors).length) {
      drafts.setErrors(id, errors);
      drafts.setResult(id, { kind: 'invalid', fields: Object.keys(errors) });
      focusField(Object.keys(errors)[0]);
      return;
    }
    savingRef.current = true;
    setSaving(id);
    try {
      const res = await api.post('settings', req.body, {
        params: req.clear.length ? { clear: req.clear.join(',') } : undefined,
      });
      const failedFiles: string[] = res.data?.status === 'partial' ? (res.data?.data?.failed ?? []) : [];
      const apply = req.modes.includes('reload') ? await applyToProxy() : undefined;
      queryClient.setQueryData<SettingRow[]>(SETTINGS_KEY, (old) => rowsAfterSave(old, req));
      drafts.discard(id);
      drafts.setResult(id, { kind: 'saved', at: new Date(), modes: req.modes, apply, failedFiles });
      void queryClient.invalidateQueries({ queryKey: SETTINGS_KEY });
    } catch (err) {
      const status = axios.isAxiosError(err) ? err.response?.status : undefined;
      const field = status === 400 && axios.isAxiosError(err) ? parseFieldError(err.response?.data?.detail) : null;
      if (field && SECTION_KEYS[id].includes(field.key)) {
        drafts.setErrors(id, { [field.key]: field.message });
        drafts.setResult(id, { kind: 'invalid', fields: [field.key] });
        focusField(field.key);
      } else if (field) {
        drafts.setResult(id, { kind: 'invalid', fields: [], outside: `${fieldLabel(field.key)}: ${field.message}` });
      } else {
        drafts.setResult(id, { kind: 'error', message: getErrorMessage(err, 'the backend did not answer') });
      }
    } finally {
      savingRef.current = false;
      setSaving(null);
    }
  };

  const retryApply = async () => {
    const last = drafts.results[id];
    if (last?.kind !== 'saved') return;
    const apply = await applyToProxy();
    drafts.setResult(id, { ...last, apply });
  };

  const fieldErrors = drafts.errors[id] ?? {};

  return (
    <div className="flex flex-col gap-6">
      <PageHeader eyebrow="System" title="Settings" />
      <div className={isDesktop ? 'flex items-start gap-8' : 'flex flex-col gap-4'}>
        <SettingsNav current={id} dirty={dirty} attention={settings.isSuccess ? warnings : undefined} />
        <section aria-labelledby="settings-section-title" className="flex min-w-0 flex-1 flex-col gap-4">
          <header className="flex flex-col gap-1">
            <h2 id="settings-section-title" className="text-lg font-semibold text-ink">{section.label}</h2>
            <p className="text-sm text-ink-muted">{section.purpose}</p>
          </header>
          {settings.isError && (
            <Notice tone="danger" title="The settings could not be loaded">
              GET /api/settings failed, so the values below are missing and nothing here can be saved safely.
            </Notice>
          )}
          <SectionBody
            section={section}
            form={form}
            rows={rows}
            attention={attention}
            attentionLoading={settings.isPending}
            dirty={dirty}
          />
          {!INLINE_ERRORS.includes(id) && Object.keys(fieldErrors).length > 0 && (
            <ul aria-label="Fields that need attention" className="flex flex-col gap-1 rounded-panel border border-danger-line bg-danger-subtle px-4 py-3 text-sm text-danger">
              {Object.entries(fieldErrors).map(([key, msg]) => (
                <li key={key}>
                  <button type="button" className="text-left underline-offset-2 hover:underline" onClick={() => focusField(key)}>
                    {fieldLabel(key)}: {msg}
                  </button>
                </li>
              ))}
            </ul>
          )}
          <SaveBar
            changes={changesIn(id)}
            saving={saving === id}
            result={drafts.results[id]}
            labelOf={fieldLabel}
            onSave={() => void save()}
            onDiscard={() => drafts.discard(id)}
            onRetryApply={() => void retryApply()}
          />
        </section>
      </div>
    </div>
  );
}

export function Settings() {
  // The drafts live above the routes in the app; a page rendered on its own
  // (a test, a story) brings its own.
  const drafts = useSettingsDraftsOptional();
  if (!drafts) return <SettingsDraftsProvider><SettingsPage /></SettingsDraftsProvider>;
  return <SettingsPage />;
}
