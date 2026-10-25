/**
 * Overview: what needs attention (worked out from the API, lib/attention),
 * how to connect a device, profiles that set several sections at once with
 * a preview of every change, and the upstream DNS finder.
 */
import { useId, useState } from 'react';
import { Link } from 'react-router';
import { useQueryClient } from '@tanstack/react-query';
import type { SettingRow } from '../../../types';
import { api, getErrorMessage } from '../../../lib/api';
import { Section } from '../../ui/Section';
import { Button } from '../../ui/Button';
import { Notice } from '../../ui/Notice';
import { ClientSetup } from '../../ClientSetup';
import { proxyAddress, cn } from '../../../lib/utils';
import { formatCount } from '../../../lib/format';
import { applyToProxy } from '../../../lib/reload';
import { describeSave, rowsAfterSave, type SaveResult } from '../../../lib/settingsSave';
import { APPLY_MODE, SECTIONS, sectionPath, type ApplyMode, type SectionId } from '../../../lib/settingsMeta';
import { PROFILES, matchingProfile, profileChanges, showValue, type Profile } from '../../../lib/profiles';
import type { AttentionItem } from '../../../lib/attention';
import type { SectionForm } from '../sectionForm';

const DOT = { warning: 'bg-warning-strong', info: 'bg-chart-neutral' };

function NeedsAttention({ items, loading }: { items: AttentionItem[]; loading: boolean }) {
  return (
    <Section level={3} title="Needs attention" description="Worked out from the running configuration, not from a checklist you tick." flush>
      {loading ? (
        <p className="px-5 pb-4 text-sm text-ink-muted">Reading the configuration...</p>
      ) : items.length === 0 ? (
        <p className="px-5 pb-4 text-sm text-ink-muted">Nothing needs attention.</p>
      ) : (
        <ul>
          {items.map((a) => (
            <li key={a.id} data-tone={a.tone} className="flex flex-wrap items-start gap-3 border-t border-line-subtle px-5 py-4">
              <span aria-hidden="true" className={cn('mt-1.5 h-2.5 w-2.5 flex-none rounded-full', DOT[a.tone])} />
              <div className="flex min-w-0 flex-1 flex-col gap-0.5">
                <p className="text-sm font-semibold text-ink">
                  {a.title}
                  <span className="sr-only">{a.tone === 'warning' ? ' (needs attention)' : ' (for information)'}</span>
                </p>
                <p className="text-sm leading-5 text-ink-muted">{a.body}</p>
              </div>
              {a.section && a.action && (
                <Link to={sectionPath(a.section)} className="flex-none text-sm font-semibold text-accent hover:underline focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-accent">
                  {a.action}
                </Link>
              )}
            </li>
          ))}
        </ul>
      )}
    </Section>
  );
}

function ConnectDevice() {
  const [open, setOpen] = useState(false);
  const panelId = useId();
  return (
    <Section level={3} title="Connect a device">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <p className="text-sm text-ink-secondary">
          Set the device's HTTP and HTTPS proxy to{' '}
          <code className="rounded bg-surface-muted px-1 font-mono text-[13px] text-ink">{proxyAddress()}</code>.{' '}
          <Link to="/clients" className="font-semibold text-accent hover:underline">Clients</Link> lists the devices that sent traffic.
        </p>
        <Button aria-expanded={open} aria-controls={panelId} onClick={() => setOpen(!open)}>
          Step-by-step for Windows, macOS, Linux, iOS, Android
        </Button>
      </div>
      {open && <div id={panelId} className="mt-4"><ClientSetup /></div>}
    </Section>
  );
}

const sectionLabel = (id: SectionId) => SECTIONS.find((s) => s.id === id)?.label ?? id;

function ApplyProfile({ stored, rows, dirty }: { stored: Record<string, string>; rows: SettingRow[] | undefined; dirty: Partial<Record<SectionId, number>> }) {
  const queryClient = useQueryClient();
  const [picked, setPicked] = useState<Profile | null>(null);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ profile: string; save: SaveResult } | null>(null);
  const active = matchingProfile(stored);
  const changes = picked ? profileChanges(picked, stored) : [];
  const touched = [...new Set(changes.map((c) => c.section))];
  const blocking = touched.filter((s) => (dirty[s] ?? 0) > 0);
  const previewId = useId();

  const apply = async () => {
    if (!picked || busy) return;
    setBusy(true);
    const body = { ...picked.values };
    const modes = [...new Set(changes.map((c) => APPLY_MODE[c.key]).filter((m): m is ApplyMode => !!m))];
    try {
      const res = await api.post('settings', body);
      const failedFiles: string[] = res.data?.status === 'partial' ? (res.data?.data?.failed ?? []) : [];
      const apply = modes.includes('reload') ? await applyToProxy() : undefined;
      queryClient.setQueryData<SettingRow[]>(['settings'], (old) => rowsAfterSave(old ?? rows, { body, clear: [] }));
      void queryClient.invalidateQueries({ queryKey: ['settings'] });
      setResult({ profile: picked.name, save: { kind: 'saved', at: new Date(), modes, apply, failedFiles } });
      setPicked(null);
    } catch (err) {
      setResult({ profile: picked.name, save: { kind: 'error', message: getErrorMessage(err, 'the backend did not answer') } });
    } finally {
      setBusy(false);
    }
  };

  const d = result ? describeSave(result.save) : null;
  return (
    <Section level={3} title="Apply a profile" description="Sets several sections at once. Every change is listed before anything is saved.">
      <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
        {PROFILES.map((p) => (
          <button
            key={p.id}
            type="button"
            aria-pressed={picked?.id === p.id}
            aria-controls={previewId}
            onClick={() => { setPicked(picked?.id === p.id ? null : p); setResult(null); }}
            className={cn(
              'flex flex-col items-start gap-1 rounded-control border px-3 py-2.5 text-left transition-colors',
              'focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-accent',
              picked?.id === p.id ? 'border-accent-line bg-accent-subtle' : 'border-line hover:bg-surface-muted',
            )}
          >
            <span className="flex items-center gap-2 text-sm font-semibold text-ink">
              {p.name}
              {active?.id === p.id && <span className="rounded-full bg-success-subtle px-2 text-xs font-medium text-success">Current</span>}
            </span>
            <span className="text-xs leading-4 text-ink-muted">{p.summary}</span>
          </button>
        ))}
      </div>

      <div id={previewId} aria-live="polite">
        {picked && (
          <div className="mt-4 flex flex-col gap-3 rounded-control border border-line bg-surface-muted p-4">
            <h4 className="text-sm font-semibold text-ink">
              {changes.length === 0 ? `Your settings already match ${picked.name}` : `${picked.name} changes ${changes.length === 1 ? '1 setting' : `${formatCount(changes.length)} settings`}`}
            </h4>
            {touched.map((s) => (
              <div key={s}>
                <p className="text-xs font-semibold uppercase tracking-[0.04em] text-ink-subtle">{sectionLabel(s)}</p>
                <ul className="mt-1 flex flex-col gap-1">
                  {changes.filter((c) => c.section === s).map((c) => (
                    <li key={c.key} className={cn('text-sm', c.warning ? 'text-warning-ink' : 'text-ink-secondary')}>
                      {c.label}: {showValue(c.from)} to <span className="font-semibold">{showValue(c.to)}</span>
                      {c.warning && <span className="block text-xs">{c.warning}</span>}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
            {blocking.length > 0 && (
              <Notice tone="warning" title="Unsaved changes in the way">
                Save or discard the unsaved changes in {blocking.map(sectionLabel).join(', ')} first.
              </Notice>
            )}
            {changes.length > 0 && (
              <div className="flex flex-wrap gap-2">
                <Button variant="primary" disabled={busy || blocking.length > 0} onClick={() => void apply()}>
                  {busy ? 'Applying...' : `Apply ${picked.name}`}
                </Button>
                <Button onClick={() => setPicked(null)} disabled={busy}>Cancel</Button>
              </div>
            )}
          </div>
        )}
        {d && result && (
          <div role="status" className={cn('mt-4 flex flex-col gap-1 rounded-control border px-4 py-3 text-sm',
            d.tone === 'success' ? 'border-success-subtle bg-success-subtle text-success' : d.tone === 'warning' ? 'border-warning-line bg-warning-subtle text-warning-ink' : 'border-danger-line bg-danger-subtle text-danger')}>
            <p className="font-medium">{result.save.kind === 'saved' ? `${result.profile} saved.` : `${result.profile} not applied.`}</p>
            {d.lines.map((l, i) => <p key={i}>{l}</p>)}
          </div>
        )}
      </div>
    </Section>
  );
}

interface Detected { ip: string; type: string; name: string }

function UpstreamDns() {
  const [state, setState] = useState<{ kind: 'idle' | 'busy' } | { kind: 'done'; found: Detected[]; scanned?: number; subnet?: string } | { kind: 'failed'; message: string }>({ kind: 'idle' });
  const scan = async () => {
    setState({ kind: 'busy' });
    try {
      const res = await api.post('dns/detect', {});
      const data = res.data?.data ?? {};
      setState({ kind: 'done', found: Array.isArray(data.found) ? data.found : [], scanned: data.scanned, subnet: data.subnet });
    } catch (err) {
      setState({ kind: 'failed', message: getErrorMessage(err, 'the scan did not answer') });
    }
  };
  return (
    <Section level={3} title="Upstream DNS">
      <p className="text-sm text-ink-secondary">
        The DNS service forwards to the servers in <code className="font-mono text-[12px]">DNS_UPSTREAM_1</code> to{' '}
        <code className="font-mono text-[12px]">DNS_UPSTREAM_3</code> in <code className="font-mono text-[12px]">.env</code>, which this page cannot read.
        A Pi-hole or AdGuard Home on the LAN can be one of them.
      </p>
      <div className="mt-3">
        <Button onClick={() => void scan()} disabled={state.kind === 'busy'}>
          {state.kind === 'busy' ? 'Looking...' : 'Look for Pi-hole or AdGuard Home'}
        </Button>
      </div>
      <div role="status" className="mt-3 text-sm text-ink-secondary">
        {state.kind === 'failed' && <p className="text-danger">The scan failed: {state.message}.</p>}
        {state.kind === 'done' && state.found.length === 0 && (
          <p>None found{state.scanned ? ` among the ${state.scanned} addresses checked${state.subnet ? ` in ${state.subnet}.x` : ''}` : ''}.</p>
        )}
        {state.kind === 'done' && state.found.length > 0 && (
          <>
            <ul className="list-disc pl-5">{state.found.map((f) => <li key={f.ip}>{f.name}</li>)}</ul>
            <p className="mt-1">
              To use one, set <code className="font-mono text-[12px]">DNS_UPSTREAM_1={state.found[0].ip}</code> in .env, then run{' '}
              <code className="font-mono text-[12px]">docker compose up -d</code> so the dns container picks it up.
            </p>
          </>
        )}
      </div>
    </Section>
  );
}

export interface OverviewSectionProps {
  form: SectionForm;
  rows: SettingRow[] | undefined;
  attention: AttentionItem[];
  attentionLoading: boolean;
  dirty: Partial<Record<SectionId, number>>;
}

export function OverviewSection({ form, rows, attention, attentionLoading, dirty }: OverviewSectionProps) {
  return (
    <div className="flex flex-col gap-4">
      <NeedsAttention items={attention} loading={attentionLoading} />
      <ConnectDevice />
      <ApplyProfile stored={form.stored} rows={rows} dirty={dirty} />
      <UpstreamDns />
    </div>
  );
}
