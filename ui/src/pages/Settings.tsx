/**
 * Settings: one section at a time, at /settings/<section> (lib/settingsMeta
 * lists the sections in task order). /settings and an unknown section go to
 * Overview. The section nav sits beside the section on wide screens and
 * collapses into a switcher below lg.
 *
 * The form is held here, so switching sections keeps what was typed (the
 * Layout keeps this page mounted across /settings/* paths).
 */
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useState, useEffect, useRef } from 'react';
import { Navigate, useParams } from 'react-router';
import { Save } from 'lucide-react';
import toast from 'react-hot-toast';
import type { SettingRow } from '../types';
import { api, getData } from '../lib/api';
import { PageHeader } from '../components/ui/PageHeader';
import { Button } from '../components/ui/Button';
import { SettingsNav } from '../components/settings/SettingsNav';
import {
  LegacyAccess, LegacyAdmin, LegacyAlerts, LegacyEngine, LegacyFiltering, LegacyInspection, LegacyLogs, LegacyOverview,
  type LegacyForm,
} from '../components/settings/LegacySections';
import { parseSettings, secretPayload, secretStateOf, type SecretEdit, type SecretState } from '../lib/secrets';
import { DEFAULT_SECTION, sectionById, sectionPath, type SectionDef } from '../lib/settingsMeta';
import { useMediaQuery, DESKTOP_QUERY } from '../hooks/useMediaQuery';

function SectionBody({ section, form }: { section: SectionDef; form: LegacyForm }) {
  switch (section.id) {
    case 'overview': return <LegacyOverview form={form} />;
    case 'access': return <LegacyAccess form={form} />;
    case 'filtering': return <LegacyFiltering form={form} />;
    case 'inspection': return <LegacyInspection form={form} />;
    case 'alerts': return <LegacyAlerts form={form} />;
    case 'logs': return <LegacyLogs form={form} />;
    case 'admin': return <LegacyAdmin />;
    case 'engine': return <LegacyEngine form={form} />;
  }
}

export function Settings() {
  const { section: sectionParam } = useParams<{ section: string }>();
  const section = sectionById(sectionParam);
  const isDesktop = useMediaQuery(DESKTOP_QUERY);
  const { data: settingsData, isLoading: loading, error } = useQuery<SettingRow[]>({
    queryKey: ['settings'],
    queryFn: () => getData<SettingRow[]>('settings'),
  });
  const queryClient = useQueryClient();
  const [formData, setFormData] = useState<Record<string, string>>({});
  // Secrets are write-only: the page knows only whether each one is stored,
  // and sends one only when the operator typed or removed it.
  const [secrets, setSecrets] = useState<Record<string, SecretState>>({});
  const [secretEdits, setSecretEdits] = useState<Record<string, SecretEdit | undefined>>({});
  const [isSaving, setIsSaving] = useState(false);
  // Synchronous latch against a double click posting twice.
  const savingRef = useRef(false);

  useEffect(() => {
    if (!loading && !error && Array.isArray(settingsData)) {
      const parsed = parseSettings(settingsData);
      // Seeding an editable form from fetched data: a deliberate mirror of
      // query data into state (issue #192).
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setFormData(parsed.values);
      setSecrets(parsed.secrets);
    }
  }, [settingsData, loading, error]);

  const form: LegacyForm = {
    formData,
    setFormData,
    handleChange: (e) => setFormData((prev) => ({ ...prev, [e.target.name]: e.target.value })),
    secretProps: (key) => ({
      state: secretStateOf(secrets, key),
      edit: secretEdits[key],
      onEdit: (edit) => setSecretEdits((prev) => ({ ...prev, [key]: edit })),
    }),
  };

  const handleSave = async () => {
    if (savingRef.current) return;
    savingRef.current = true;
    setIsSaving(true);
    const loadingToast = toast.loading('Saving settings...');
    try {
      const secret = secretPayload(secretEdits);
      await api.post('settings', { ...formData, ...secret.body }, {
        params: secret.clear.length ? { clear: secret.clear.join(',') } : undefined,
      });
      toast.success('Settings saved successfully!', { id: loadingToast });
      setSecretEdits({});
      queryClient.invalidateQueries({ queryKey: ['settings'] });
      toast.promise(api.post('maintenance/reload-config', {}), {
        loading: 'Applying new configuration to Proxy...',
        success: 'Proxy reloaded with new configuration.',
        error: 'Failed to apply configuration.',
      });
    } catch {
      toast.error('Failed to save settings', { id: loadingToast });
    } finally {
      savingRef.current = false;
      setIsSaving(false);
    }
  };

  if (!section) return <Navigate to={sectionPath(DEFAULT_SECTION)} replace />;

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        eyebrow="System"
        title="Settings"
        actions={(
          <Button variant="primary" icon={<Save />} onClick={handleSave} disabled={isSaving}>
            {isSaving ? 'Saving...' : 'Save Changes'}
          </Button>
        )}
      />
      <div className={isDesktop ? 'flex items-start gap-8' : 'flex flex-col gap-4'}>
        <SettingsNav current={section.id} />
        <section aria-labelledby="settings-section-title" className="flex min-w-0 flex-1 flex-col gap-4">
          <header className="flex flex-col gap-1">
            <h2 id="settings-section-title" className="text-lg font-semibold text-ink">{section.label}</h2>
            <p className="text-sm text-ink-muted">{section.purpose}</p>
          </header>
          <SectionBody section={section} form={form} />
        </section>
      </div>
    </div>
  );
}
