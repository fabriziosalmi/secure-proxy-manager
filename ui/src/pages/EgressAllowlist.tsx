/**
 * Egress allowlist (route /egress, Egress.dc.html): the destinations a client
 * may reach when default deny is on.
 *
 * - A notice says what the list does right now, from the egress_default_deny
 *   setting (GET /api/settings) and the size of the list (meta.total of
 *   GET /api/egress-allowlist): no effect while default deny is off; with it
 *   on and the list empty, only LAN destinations are reachable.
 * - Add a destination: a domain or an IP/network, with an optional note.
 *   What the backend refuses is shown at the field it concerns.
 * - Allowed destinations: the list, 50 a page, searched on the backend,
 *   each removed after a confirmation that names it.
 *
 * What the proxy does with an entry is read from proxy/generate_squid_conf.sh:
 * the domains are a dstdomain ACL and the addresses a dst ACL, and the deny
 * for every other destination comes after `allow ip_whitelist` and
 * `allow local_dst` (10.0.0.0/8, 192.168.0.0/16), so those stay reachable.
 */
import { useId, useRef, useState, type FormEvent, type ReactNode } from 'react';
import { Link } from 'react-router';
import { keepPreviousData, useQuery, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { isAxiosError } from 'axios';
import { Trash2 } from 'lucide-react';
import { api, getErrorMessage } from '../lib/api';
import { formatCount, formatDateTime } from '../lib/format';
import { formatEgressBreakdown, settingsQuery, useEgressSummary, type EgressSummary } from '../lib/queries';
import { parseSettings } from '../lib/secrets';
import { checkDestination, egressEntryKind, type EgressKind, LAN_DESTINATIONS } from '../lib/egress';
import { cn } from '../lib/utils';
import { useConfirm } from '../hooks/useConfirm';
import { useDebounced } from '../hooks/useDebounced';
import type { EgressEntry } from '../types';
import { PageHeader } from '../components/ui/PageHeader';
import { Notice } from '../components/ui/Notice';
import { Section } from '../components/ui/Section';
import { DataTable, type Column } from '../components/ui/DataTable';
import { SearchInput } from '../components/ui/SearchInput';
import { Button, IconButton } from '../components/ui/Button';
import { ProviderListsSection } from '../components/egress/ProviderListsSection';

const PAGE_SIZE = 50;

/** The destinations local_dst lets through before the egress deny. */
// One source with Settings: what proxy/generate_squid_conf.sh's local_dst holds.
const LAN = LAN_DESTINATIONS.join(' and ');

const FIELD =
  'h-9 w-full min-w-0 rounded-control border border-line-strong bg-surface px-3 text-sm text-ink placeholder:text-ink-subtle ' +
  'focus:border-accent focus:outline-hidden focus:ring-2 focus:ring-accent/30 aria-invalid:border-danger';

function Field({ id, label, error, hint, className, children }: {
  id: string; label: string; error?: string | null; hint?: ReactNode; className?: string; children: ReactNode;
}) {
  return (
    <div className={cn('flex min-w-0 flex-col gap-1.5', className)}>
      <label htmlFor={id} className="text-[13px] font-medium text-ink-secondary">{label}</label>
      {children}
      {error && <p id={`${id}-error`} className="text-xs font-medium text-danger">{error}</p>}
      {hint && !error && <p id={`${id}-hint`} className="text-xs text-ink-muted">{hint}</p>}
    </div>
  );
}

function StateNotice({ denyOn, settingsFailed, summary }: { denyOn: boolean | undefined; settingsFailed: boolean; summary: EgressSummary }) {
  const open = <Link to="/settings/filtering" className="text-accent hover:underline">Open Filtering</Link>;
  if (settingsFailed) {
    return (
      <Notice tone="warning" title="Whether default deny is on could not be read" action={open}>
        The settings did not load, so this page cannot say whether this list is in force.
      </Notice>
    );
  }
  if (denyOn === undefined) return null;
  const total = summary.total;
  const hasProviders = !summary.isError && (summary.providerCount ?? 0) > 0;
  const breakdown = hasProviders
    ? `The allowlist holds ${formatEgressBreakdown(summary.manual ?? 0, summary.providerEntries ?? 0, summary.providerCount ?? 0)}. `
    : '';
  if (!denyOn) {
    return (
      <Notice title="Default deny is off, so this list has no effect" action={open}>
        {breakdown}Clients can reach any destination that no blacklist names. Turn it on in Settings, Filtering, after adding the destinations your clients need.
      </Notice>
    );
  }
  if (total === 0) {
    return (
      <Notice tone="danger" title="Default deny is on and this list is empty: clients reach only LAN destinations" action={open}>
        Every destination outside {LAN} is refused, except the addresses on Allowed IPs. Add the destinations your clients need, or turn default deny off in Settings, Filtering.
      </Notice>
    );
  }
  if (typeof total !== 'number') {
    return (
      <Notice tone="warning" title="Default deny is on, and the size of this list could not be read" action={open}>
        Clients reach only the destinations listed here, LAN destinations ({LAN}) and the addresses on Allowed IPs.
      </Notice>
    );
  }
  return (
    <Notice title={`Default deny is on: clients reach only these ${formatCount(total)} ${total === 1 ? 'destination' : 'destinations'}`} action={open}>
      {breakdown}LAN destinations ({LAN}) and the addresses on Allowed IPs stay reachable too. Everything else is refused.
    </Notice>
  );
}

function AddDestination({ onAdded }: { onAdded: () => void }) {
  const ids = useId();
  const [kind, setKind] = useState<EgressKind>('domain');
  const [value, setValue] = useState('');
  const [note, setNote] = useState('');
  const [entryError, setEntryError] = useState<string | null>(null);
  const [noteError, setNoteError] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const inFlight = useRef(false);
  const entryRef = useRef<HTMLInputElement>(null);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (inFlight.current) return;
    setFormError(null);
    setNoteError(null);
    const problem = checkDestination(kind, value);
    setEntryError(problem);
    if (problem) {
      entryRef.current?.focus();
      return;
    }
    const entry = value.trim().toLowerCase();
    inFlight.current = true;
    setBusy(true);
    try {
      await api.post('egress-allowlist', { entry, description: note.trim() });
      toast.success(`Added ${entry} to the egress allowlist`);
      setValue('');
      setNote('');
      onAdded();
    } catch (err) {
      const msg = getErrorMessage(err, 'The destination could not be added');
      // A refusal (400) is about one of the two fields: the backend names
      // the description when it is the note; anything else is the entry.
      if (isAxiosError(err) && err.response?.status === 400) {
        if (/^description/i.test(msg)) setNoteError(msg);
        else {
          setEntryError(msg);
          entryRef.current?.focus();
        }
      } else {
        setFormError(msg);
      }
    } finally {
      inFlight.current = false;
      setBusy(false);
    }
  };

  return (
    <Section title="Add a destination">
      <form onSubmit={(e) => { void submit(e); }} noValidate className="flex flex-col gap-3">
        {formError && <p role="alert" className="rounded-control border border-danger-line bg-danger-subtle px-3 py-2 text-sm text-danger">{formError}</p>}
        <div className="flex flex-col gap-3 sm:flex-row sm:flex-wrap sm:items-start">
          <Field id={`${ids}-kind`} label="Kind" className="sm:w-44">
            <select
              id={`${ids}-kind`}
              value={kind}
              onChange={(e) => { setKind(e.target.value as EgressKind); setEntryError(null); }}
              className={FIELD}
            >
              <option value="domain">Domain</option>
              <option value="ip">IP or network</option>
            </select>
          </Field>
          <Field id={`${ids}-entry`} label="Destination" error={entryError} className="sm:flex-[1_1_260px]">
            <input
              id={`${ids}-entry`}
              ref={entryRef}
              value={value}
              onChange={(e) => { setValue(e.target.value); if (entryError) setEntryError(null); }}
              placeholder={kind === 'domain' ? 'acme-v02.api.letsencrypt.org' : '203.0.113.0/24'}
              autoComplete="off"
              spellCheck={false}
              aria-invalid={entryError ? true : undefined}
              aria-describedby={entryError ? `${ids}-entry-error` : undefined}
              className={cn(FIELD, 'font-mono text-[13px]')}
            />
          </Field>
          <Field id={`${ids}-note`} label="Note (optional)" error={noteError} className="sm:flex-[1_1_260px]">
            <input
              id={`${ids}-note`}
              value={note}
              onChange={(e) => { setNote(e.target.value); if (noteError) setNoteError(null); }}
              placeholder="What needs it"
              maxLength={500}
              aria-invalid={noteError ? true : undefined}
              aria-describedby={noteError ? `${ids}-note-error` : undefined}
              className={FIELD}
            />
          </Field>
          <Button type="submit" variant="primary" disabled={busy} className="sm:mt-[26px]">{busy ? 'Adding...' : 'Add'}</Button>
        </div>
        <p className="text-[13px] text-ink-muted">
          A domain allows that exact name only: example.com does not cover www.example.com. Start it with a dot, as in .example.com,
          to allow the domain and every name under it. A network such as 203.0.113.0/24 allows every address in it, and any name
          that resolves into it.
        </p>
      </form>
    </Section>
  );
}

export function EgressAllowlist() {
  const qc = useQueryClient();
  const { confirm, dialog } = useConfirm();
  const [search, setSearch] = useState('');
  const query = useDebounced(search.trim(), 300);
  const [offset, setOffset] = useState(0);

  const settings = useQuery(settingsQuery);
  const summary = useEgressSummary();
  const entries = useQuery({
    queryKey: ['egress-allowlist', 'entries', offset, query],
    queryFn: () =>
      api.get('egress-allowlist', { params: { limit: PAGE_SIZE, offset, search: query } })
        .then((r) => ({ rows: (r.data?.data ?? []) as EgressEntry[], total: (r.data?.meta?.total ?? 0) as number })),
    placeholderData: keepPreviousData,
  });

  const parsedSettings = settings.data ? parseSettings(settings.data).values : undefined;
  const denyOn = parsedSettings ? parsedSettings.egress_default_deny === 'true' : undefined;
  const refreshHours = parsedSettings?.egress_provider_refresh_hours;
  const refresh = () => { void qc.invalidateQueries({ queryKey: ['egress-allowlist'] }); };

  const remove = async (e: EgressEntry) => {
    const ok = await confirm({
      title: `Remove ${e.entry}?`,
      body: denyOn
        ? `Default deny is on: clients can no longer reach ${e.entry} once the proxy has the new list.`
        : 'Default deny is off, so nothing changes for clients until it is turned on.',
      confirmLabel: 'Remove',
      destructive: true,
    });
    if (!ok) return;
    try {
      await api.delete(`egress-allowlist/${e.id}`);
      toast.success(`Removed ${e.entry} from the egress allowlist`);
    } catch (err) {
      toast.error(getErrorMessage(err, `Could not remove ${e.entry}`));
    } finally {
      refresh();
    }
  };

  const columns: Column<EgressEntry>[] = [
    {
      id: 'entry',
      header: 'Destination',
      className: 'min-w-[11rem]',
      cell: (e) => (
        <div className="flex min-w-0 flex-col gap-0.5">
          <code className="font-mono text-[13px] text-ink [overflow-wrap:anywhere]">{e.entry}</code>
          {e.description && <span className="text-xs text-ink-muted">{e.description}</span>}
        </div>
      ),
    },
    { id: 'kind', header: 'Allows', className: 'whitespace-nowrap text-ink-muted', cell: egressEntryKind },
    { id: 'added', header: 'Added', className: 'whitespace-nowrap text-ink-muted', cell: (e) => formatDateTime(e.added_date) },
    {
      id: 'actions',
      header: 'Actions',
      headerHidden: true,
      align: 'right',
      cell: (e) => <IconButton size="sm" aria-label={`Remove ${e.entry}`} icon={<Trash2 />} onClick={() => { void remove(e); }} />,
    },
  ];

  const empty = query
    ? { title: `No destination matches "${query}"`, description: 'The search looks in the destinations and their notes. Clear it to see the whole list.' }
    : {
        title: 'No destination yet',
        description: denyOn
          ? (summary.providerEntries ?? 0) > 0
            ? `No manual destinations yet. Clients reach the ${formatCount(summary.providerEntries ?? 0)} entries from ${formatCount(summary.providerCount ?? 0)} ${(summary.providerCount ?? 0) === 1 ? 'provider list' : 'provider lists'}, LAN destinations (${LAN}) and the addresses on Allowed IPs.`
            : `Default deny is on, so every client reaches only LAN destinations (${LAN}) and the addresses on Allowed IPs. Add what your clients need.`
          : 'If you turn default deny on with an empty list, every client loses access to everything except the LAN. Add what your clients need first.',
      };

  return (
    <div className="flex flex-col gap-5">
      <PageHeader
        eyebrow="Protection"
        title="Egress allowlist"
        description="With default deny on, clients may reach only the destinations listed here."
      />

      <StateNotice denyOn={denyOn} settingsFailed={settings.isError} summary={summary} />

      <AddDestination onAdded={refresh} />

      <ProviderListsSection refreshHours={refreshHours} onChanged={refresh} />

      <Section title="Allowed destinations" flush>
        <div className="px-5 pb-3">
          <SearchInput
            label="Search the egress allowlist"
            placeholder="Search destinations and notes"
            value={search}
            onChange={(v) => { setSearch(v); setOffset(0); }}
            className="w-full sm:max-w-[360px]"
          />
        </div>
        <DataTable<EgressEntry>
          caption="Allowed destinations"
          columns={columns}
          rows={entries.data?.rows ?? []}
          rowKey={(e) => String(e.id)}
          loading={entries.isPending}
          error={entries.isError ? 'The egress allowlist did not answer.' : null}
          onRetry={() => { void entries.refetch(); }}
          empty={empty}
          pagination={{ offset, limit: PAGE_SIZE, total: entries.data?.total ?? 0, onChange: setOffset }}
        />
      </Section>
      {dialog}
    </div>
  );
}
