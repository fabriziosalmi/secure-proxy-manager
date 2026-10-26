import { useId, useRef, useState, type FormEvent, type ReactNode } from 'react';
import { Link } from 'react-router';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { isAxiosError } from 'axios';
import { Trash2 } from 'lucide-react';
import { api, getErrorMessage } from '../../lib/api';
import { formatCount, formatDateTime } from '../../lib/format';
import { egressProvidersQuery } from '../../lib/queries';
import { cn } from '../../lib/utils';
import { useConfirm } from '../../hooks/useConfirm';
import type { EgressProvider } from '../../types';
import { Section } from '../ui/Section';
import { DataTable, type Column } from '../ui/DataTable';
import { Switch } from '../ui/Switch';
import { Badge } from '../ui/Badge';
import { Notice } from '../ui/Notice';
import { Button, IconButton } from '../ui/Button';

const IPV4_SPACE = 4_294_967_296;

const FIELD =
  'h-9 w-full min-w-0 rounded-control border border-line-strong bg-surface px-3 text-sm text-ink placeholder:text-ink-subtle ' +
  'focus:border-accent focus:outline-hidden focus:ring-2 focus:ring-accent/30 aria-invalid:border-danger';

function formatIpv4Coverage(covered: number): { count: string; pct: string; summary: string } {
  const count = formatCount(covered);
  if (!(covered > 0)) {
    return { count: '0', pct: '0.0%', summary: '0 (0.0% of IPv4)' };
  }
  const rawPct = (covered / IPV4_SPACE) * 100;
  let pct: string;
  if (rawPct < 0.01) pct = '<0.01%';
  else if (rawPct < 1) pct = `${rawPct.toFixed(2)}%`;
  else pct = `${rawPct.toFixed(1)}%`;
  return { count, pct, summary: `${count} (${pct} of IPv4)` };
}

function Field({ id, label, error, className, children }: {
  id: string; label: string; error?: string | null; className?: string; children: ReactNode;
}) {
  return (
    <div className={cn('flex min-w-0 flex-col gap-1.5', className)}>
      <label htmlFor={id} className="text-[13px] font-medium text-ink-secondary">{label}</label>
      {children}
      {error && <p id={`${id}-error`} className="text-xs font-medium text-danger">{error}</p>}
    </div>
  );
}

export function ProviderListsSection({ refreshHours, onChanged }: { refreshHours?: string; onChanged?: () => void }) {
  const qc = useQueryClient();
  const ids = useId();
  const { confirm, dialog } = useConfirm();
  const providers = useQuery(egressProvidersQuery);

  const [busyRow, setBusyRow] = useState<string | null>(null);
  const [rowErrors, setRowErrors] = useState<Record<string, string>>({});

  const [label, setLabel] = useState('');
  const [url, setUrl] = useState('');
  const [labelError, setLabelError] = useState<string | null>(null);
  const [urlError, setUrlError] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [addingUrl, setAddingUrl] = useState(false);
  const inFlight = useRef(false);
  const labelRef = useRef<HTMLInputElement>(null);
  const urlRef = useRef<HTMLInputElement>(null);

  const hours = refreshHours && /^[0-9]+$/.test(refreshHours) ? refreshHours : '24';

  const invalidateAll = () => {
    void qc.invalidateQueries({ queryKey: ['egress-providers'] });
    void qc.invalidateQueries({ queryKey: ['egress-allowlist'] });
    onChanged?.();
  };

  const toggleProvider = async (p: EgressProvider, next: boolean) => {
    if (busyRow) return;
    if (next && p.shared_network) {
      const cov = formatIpv4Coverage(p.ipv4_covered);
      const isAll = p.name === 'all';
      const ok = await confirm({
        title: isAll ? 'Enable all provider lists?' : `Enable shared network ${p.name}?`,
        body: isAll
          ? p.ipv4_covered > 0
            ? `Enabling "all" merges every catalog provider into one allowlist (${cov.count} IPv4 addresses, ${cov.pct} of the IPv4 address space). Clients will reach any website or workload hosted across all listed cloud and CDN providers.`
            : `Enabling "all" merges every catalog provider into one allowlist (${cov.pct} of the IPv4 address space before first fetch; typically over 350 million IPv4 addresses, around 8% to 10% of the public IPv4 address space). Clients will reach any website or workload hosted across all listed cloud and CDN providers.`
          : p.ipv4_covered > 0
            ? `${p.name} is a shared cloud, CDN, or hosting network (${cov.count} IPv4 addresses, ${cov.pct} of the IPv4 address space). Clients will reach every third-party site or workload hosted on ${p.name}, not only ${p.name}'s own services.`
            : `${p.name} is a shared cloud, CDN, or hosting network spanning millions of public IPv4 addresses where third-party sites and workloads run. Clients will reach every site or service hosted on ${p.name}, not only ${p.name}'s own services.`,
        confirmLabel: isAll ? 'Enable all' : `Enable ${p.name}`,
        destructive: isAll,
      });
      if (!ok) return;
    }

    setBusyRow(p.name);
    setRowErrors((prev) => {
      const copy = { ...prev };
      delete copy[p.name];
      return copy;
    });
    try {
      const payload = next && p.shared_network ? { enabled: true, confirm_shared: true } : { enabled: next };
      const res = await api.put(`egress-providers/${encodeURIComponent(p.name)}`, payload);
      const refreshErr = typeof res.data?.refresh_error === 'string' ? res.data.refresh_error : '';
      if (refreshErr) {
        setRowErrors((prev) => ({ ...prev, [p.name]: refreshErr }));
        toast.error(`Enabled ${p.name}, but initial refresh failed: ${refreshErr}`);
      } else {
        toast.success(`${next ? 'Enabled' : 'Disabled'} ${p.name}`);
      }
    } catch (err) {
      const msg = getErrorMessage(err, `Could not update ${p.name}`);
      setRowErrors((prev) => ({ ...prev, [p.name]: msg }));
      toast.error(msg);
    } finally {
      setBusyRow(null);
      invalidateAll();
    }
  };

  const refreshNow = async (p: EgressProvider) => {
    if (busyRow) return;
    setBusyRow(p.name);
    setRowErrors((prev) => {
      const copy = { ...prev };
      delete copy[p.name];
      return copy;
    });
    try {
      const res = await api.post(`egress-providers/${encodeURIComponent(p.name)}/refresh`);
      if (res.data?.held) {
        toast(`Update for ${p.name} was held for review`);
      } else {
        toast.success(`Refreshed ${p.name}`);
      }
    } catch (err) {
      const msg = getErrorMessage(err, `Could not refresh ${p.name}`);
      setRowErrors((prev) => ({ ...prev, [p.name]: msg }));
      toast.error(msg);
    } finally {
      setBusyRow(null);
      invalidateAll();
    }
  };

  const applyHeld = async (p: EgressProvider) => {
    if (!p.held || busyRow) return;
    const h = p.held;
    const ok = await confirm({
      title: `Apply held update for ${p.name}?`,
      body: `${h.reason} (+${h.growth_pct.toFixed(1)}%). Current list: ${formatCount(p.v4_count)} IPv4 / ${formatCount(p.v6_count)} IPv6 prefixes (${formatCount(p.ipv4_covered)} IPv4 addresses). Candidate list: ${formatCount(h.v4_count)} IPv4 / ${formatCount(h.v6_count)} IPv6 prefixes (${formatCount(h.ipv4_covered)} IPv4 addresses).`,
      confirmLabel: 'Apply update',
    });
    if (!ok) return;
    setBusyRow(p.name);
    try {
      await api.post(`egress-providers/${encodeURIComponent(p.name)}/apply-held`);
      toast.success(`Applied held update for ${p.name}`);
    } catch (err) {
      toast.error(getErrorMessage(err, `Could not apply held update for ${p.name}`));
    } finally {
      setBusyRow(null);
      invalidateAll();
    }
  };

  const removeUrl = async (p: EgressProvider) => {
    if (busyRow) return;
    const ok = await confirm({
      title: `Remove ${p.name}?`,
      body: `Removes the custom URL list ${p.name} (${p.url}) and its ${formatCount(p.v4_count + p.v6_count)} prefixes from the egress allowlist.`,
      confirmLabel: 'Remove',
      destructive: true,
    });
    if (!ok) return;
    setBusyRow(p.name);
    try {
      await api.delete(`egress-providers/url/${p.id}`);
      toast.success(`Removed ${p.name}`);
    } catch (err) {
      toast.error(getErrorMessage(err, `Could not remove ${p.name}`));
    } finally {
      setBusyRow(null);
      invalidateAll();
    }
  };

  const submitUrl = async (e: FormEvent) => {
    e.preventDefault();
    if (inFlight.current) return;
    setLabelError(null);
    setUrlError(null);
    setFormError(null);

    const trimmedLabel = label.trim();
    const trimmedUrl = url.trim();
    if (!trimmedLabel) {
      setLabelError('label must be between 1 and 100 characters');
      labelRef.current?.focus();
      return;
    }
    if (!trimmedUrl) {
      setUrlError('url must be a valid http or https URL');
      urlRef.current?.focus();
      return;
    }

    inFlight.current = true;
    setAddingUrl(true);
    try {
      await api.post('egress-providers/url', { label: trimmedLabel, url: trimmedUrl });
      toast.success(`Added provider list ${trimmedLabel}`);
      setLabel('');
      setUrl('');
      invalidateAll();
    } catch (err) {
      const msg = getErrorMessage(err, 'Could not add the provider list');
      const status = isAxiosError(err) ? err.response?.status : undefined;
      if (status === 400 || status === 409) {
        if (/^label|reserved catalog/i.test(msg)) {
          setLabelError(msg);
          labelRef.current?.focus();
        } else {
          setUrlError(msg);
          urlRef.current?.focus();
        }
      } else {
        setFormError(msg);
      }
    } finally {
      inFlight.current = false;
      setAddingUrl(false);
    }
  };

  const columns: Column<EgressProvider>[] = [
    {
      id: 'provider',
      header: 'Provider',
      className: 'min-w-[14rem]',
      cell: (p) => {
        const errText = rowErrors[p.name] || p.last_error;
        return (
          <div className="flex min-w-0 flex-col gap-1">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-[13px] font-semibold text-ink">{p.name}</span>
              {p.kind === 'url' && <Badge tone="neutral">URL</Badge>}
              {p.shared_network && <Badge tone="warning">Shared network</Badge>}
            </div>
            <span className="text-xs text-ink-muted [overflow-wrap:anywhere]">
              {p.kind === 'url' ? p.url : p.source}
            </span>
            {p.name === 'github' && (
              <span className="text-xs text-ink-muted">
                Includes GitHub Actions runner addresses, where any public workflow can run.
              </span>
            )}
            {errText && (
              <Notice tone="warning" title={`Refresh failed for ${p.name}`} className="mt-1">
                {errText}
              </Notice>
            )}
            {p.held && (
              <Notice
                tone="warning"
                title={`Update held for ${p.name}`}
                className="mt-1"
                action={
                  <Button
                    size="sm"
                    aria-label={`Apply update for ${p.name}`}
                    disabled={busyRow === p.name}
                    onClick={() => { void applyHeld(p); }}
                  >
                    Apply update
                  </Button>
                }
              >
                <p>{p.held.reason} (+{p.held.growth_pct.toFixed(1)}%).</p>
                <p className="mt-0.5 text-xs">
                  Current: {formatCount(p.v4_count)} IPv4 / {formatCount(p.v6_count)} IPv6 ({formatCount(p.ipv4_covered)} IPv4 addresses).
                  Candidate: {formatCount(p.held.v4_count)} IPv4 / {formatCount(p.held.v6_count)} IPv6 ({formatCount(p.held.ipv4_covered)} IPv4 addresses).
                </p>
              </Notice>
            )}
          </div>
        );
      },
    },
    {
      id: 'enabled',
      header: 'Enabled',
      cell: (p) => (
        <Switch
          label={`Enable ${p.name}`}
          checked={p.enabled}
          disabled={busyRow === p.name}
          onChange={(next) => { void toggleProvider(p, next); }}
        />
      ),
    },
    {
      id: 'counts',
      header: 'Prefixes (v4 / v6)',
      align: 'right',
      className: 'whitespace-nowrap text-ink-secondary',
      cell: (p) => `${formatCount(p.v4_count)} / ${formatCount(p.v6_count)}`,
    },
    {
      id: 'coverage',
      header: 'IPv4 covered',
      align: 'right',
      className: 'whitespace-nowrap text-ink-secondary',
      cell: (p) => formatIpv4Coverage(p.ipv4_covered).summary,
    },
    {
      id: 'refresh',
      header: 'Last refresh',
      hideOnPhone: true,
      className: 'whitespace-nowrap text-ink-muted',
      cell: (p) => (p.last_refresh ? formatDateTime(p.last_refresh) : 'Never'),
    },
    {
      id: 'commit',
      header: 'Commit',
      hideOnPhone: true,
      className: 'whitespace-nowrap',
      cell: (p) => {
        if (!p.last_commit) return <span className="text-ink-muted">None</span>;
        const short = p.last_commit.slice(0, 7);
        if (p.kind === 'catalog') {
          return (
            <a
              href={`https://github.com/lord-alfred/ipranges/commit/${p.last_commit}`}
              target="_blank"
              rel="noopener noreferrer"
              className="font-mono text-xs text-accent hover:underline"
            >
              {short}
            </a>
          );
        }
        return (
          <code className="font-mono text-xs text-ink-muted" title={`SHA-256: ${p.last_commit}`}>
            {short}
          </code>
        );
      },
    },
    {
      id: 'actions',
      header: 'Actions',
      headerHidden: true,
      align: 'right',
      className: 'whitespace-nowrap',
      cell: (p) => (
        <div className="inline-flex items-center justify-end gap-1.5">
          <Button
            size="sm"
            aria-label={`Refresh ${p.name} now`}
            disabled={busyRow === p.name}
            onClick={() => { void refreshNow(p); }}
          >
            Refresh now
          </Button>
          {p.kind === 'url' && (
            <IconButton
              size="sm"
              variant="danger-outline"
              aria-label={`Remove ${p.name}`}
              disabled={busyRow === p.name}
              icon={<Trash2 />}
              onClick={() => { void removeUrl(p); }}
            />
          )}
        </div>
      ),
    },
  ];

  return (
    <Section title="Provider lists" flush>
      <div className="flex flex-col gap-4 px-5 pb-4">
        <p className="text-sm text-ink-secondary">
          Built-in catalog lists are fetched from{' '}
          <code className="rounded bg-surface-muted px-1 py-px font-mono text-[12px] text-ink">lord-alfred/ipranges</code>{' '}
          pinned to the latest commit on <code className="rounded bg-surface-muted px-1 py-px font-mono text-[12px] text-ink">main</code>.{' '}
          <span>{`Enabled lists refresh every ${hours} ${hours === '1' ? 'hour' : 'hours'}`}</span> (change this in{' '}
          <Link to="/settings/filtering" className="font-semibold text-accent hover:underline">Settings, Filtering</Link>).
        </p>

        <form onSubmit={(e) => { void submitUrl(e); }} noValidate className="flex flex-col gap-3 rounded-control border border-line-subtle bg-surface-muted/40 p-3.5">
          {formError && (
            <p role="alert" className="rounded-control border border-danger-line bg-danger-subtle px-3 py-2 text-sm text-danger">
              {formError}
            </p>
          )}
          <div className="flex flex-col gap-3 sm:flex-row sm:flex-wrap sm:items-start">
            <Field id={`${ids}-url-label`} label="List label" error={labelError} className="sm:w-52">
              <input
                id={`${ids}-url-label`}
                ref={labelRef}
                value={label}
                onChange={(e) => { setLabel(e.target.value); if (labelError) setLabelError(null); }}
                placeholder="partner-cidr-feed"
                maxLength={100}
                autoComplete="off"
                spellCheck={false}
                aria-invalid={labelError ? true : undefined}
                aria-describedby={labelError ? `${ids}-url-label-error` : undefined}
                className={cn(FIELD, 'font-mono text-[13px]')}
              />
            </Field>
            <Field id={`${ids}-url-address`} label="List URL" error={urlError} className="sm:flex-[1_1_280px]">
              <input
                id={`${ids}-url-address`}
                ref={urlRef}
                value={url}
                onChange={(e) => { setUrl(e.target.value); if (urlError) setUrlError(null); }}
                placeholder="https://feeds.example.com/allowlist.txt"
                autoComplete="off"
                spellCheck={false}
                aria-invalid={urlError ? true : undefined}
                aria-describedby={urlError ? `${ids}-url-address-error` : undefined}
                className={cn(FIELD, 'font-mono text-[13px]')}
              />
            </Field>
            <Button type="submit" disabled={addingUrl} className="sm:mt-[26px]">
              {addingUrl ? 'Adding...' : 'Add list'}
            </Button>
          </div>
        </form>
      </div>

      <DataTable<EgressProvider>
        caption="Provider lists"
        columns={columns}
        rows={providers.data ?? []}
        rowKey={(p) => `${p.kind}:${p.name}`}
        loading={providers.isPending}
        error={providers.isError ? 'The egress provider lists did not answer.' : null}
        onRetry={() => { void providers.refetch(); }}
        empty={{
          title: 'No provider lists loaded',
          description: 'Catalog provider lists are returned by GET /api/egress-providers.',
        }}
      />
      {dialog}
    </Section>
  );
}
