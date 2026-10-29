/**
 * Blacklists (route /blacklists, Blacklists.dc.html): the four lists the
 * proxy enforces, one tab each, with the tab in ?tab= so a link opens it and
 * the back button returns to the one before.
 *
 * For the list on screen:
 * - Enforcement: what really enforces it, from blacklists/enforcement (the
 *   proxy's own records of what Squid holds, the domain limit, the blocked
 *   names the allowed list removes) and the list's count (meta.total);
 * - Where the entries came from: {list}/sources, one row per source with
 *   the entries it added, and the removal of a whole source;
 * - Entries: {list}, 50 a page, searched on the backend, each with its
 *   source; removed one at a time after a confirmation;
 * - for a blocked list, a danger zone that removes every entry.
 *
 * Add entries (single, pasted, URL, Popular lists, Geo-block) and Export
 * (the whole list, from {list}/export) are the page's actions.
 */
import { useEffect, useRef, useState, type KeyboardEvent, type ReactNode } from 'react';
import { useSearchParams } from 'react-router';
import { keepPreviousData, useQueries, useQuery, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { Download, Plus, Trash2 } from 'lucide-react';
import { api, getData, getErrorMessage } from '../lib/api';
import { formatCount } from '../lib/format';
import { describeListResend, RESEND_UNCONFIRMED } from '../lib/listResend';
import { cn } from '../lib/utils';
import { useConfirm } from '../hooks/useConfirm';
import type { Enforcement, ListEntry, ListSource } from '../types';
import { PageHeader } from '../components/ui/PageHeader';
import { Section } from '../components/ui/Section';
import { DataTable, type Column } from '../components/ui/DataTable';
import { SearchInput } from '../components/ui/SearchInput';
import { Button, IconButton } from '../components/ui/Button';
import { Badge } from '../components/ui/Badge';
import { Notice } from '../components/ui/Notice';
import { AddEntries } from '../components/blacklists/AddEntries';
import { EnforcementSection } from '../components/blacklists/EnforcementSection';
import { SourcesSection } from '../components/blacklists/SourcesSection';
import { BlockDoh, EssentialWhitelist } from '../components/blacklists/QuickLists';
import {
  LISTS, DEFAULT_LIST, listByKey, entryKind, methodsFor, shownDescription, shortDateTime, sourceName, sourceTitle,
  type AddMethod, type ListDef, type ListKey,
} from '../components/blacklists/lists';

const PAGE_SIZE = 50;

const entriesWord = (n: number) => `${formatCount(n)} ${n === 1 ? 'entry' : 'entries'}`;

interface EntryPage {
  rows: ListEntry[];
  total: number;
}

function useDebounced(value: string, ms: number): string {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return v;
}

function ListTabs({ active, counts, onSelect }: {
  active: ListKey;
  counts: { data?: number | null; isError: boolean }[];
  onSelect: (k: ListKey) => void;
}) {
  const refs = useRef<(HTMLButtonElement | null)[]>([]);
  const onKey = (e: KeyboardEvent<HTMLDivElement>) => {
    const i = LISTS.findIndex((l) => l.key === active);
    let next = -1;
    if (e.key === 'ArrowRight') next = (i + 1) % LISTS.length;
    else if (e.key === 'ArrowLeft') next = (i - 1 + LISTS.length) % LISTS.length;
    else if (e.key === 'Home') next = 0;
    else if (e.key === 'End') next = LISTS.length - 1;
    if (next < 0) return;
    e.preventDefault();
    onSelect(LISTS[next].key);
    refs.current[next]?.focus();
  };
  return (
    <div role="tablist" aria-label="Lists" onKeyDown={onKey} className="flex flex-wrap gap-1 border-b border-line">
      {LISTS.map((l, i) => {
        const sel = l.key === active;
        const c = counts[i];
        let count: ReactNode = null;
        if (c?.isError) count = <Badge tone="neutral">Not reported</Badge>;
        else if (typeof c?.data === 'number') count = <Badge tone={sel ? 'accent' : 'neutral'}>{formatCount(c.data)}</Badge>;
        return (
          <button
            key={l.key}
            ref={(el) => { refs.current[i] = el; }}
            type="button"
            role="tab"
            id={`bl-tab-${l.key}`}
            aria-selected={sel}
            aria-controls={`bl-panel-${l.key}`}
            tabIndex={sel ? 0 : -1}
            onClick={() => onSelect(l.key)}
            className={cn(
              '-mb-px flex h-11 items-center gap-2 border-b-2 px-3 text-sm transition-colors sm:px-3.5',
              'focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent',
              sel ? 'border-accent font-semibold text-accent' : 'border-transparent font-medium text-ink-muted hover:text-ink',
            )}
          >
            {l.label}
            {count}
          </button>
        );
      })}
    </div>
  );
}

// The count is read from meta (writeList); the top-level total beside it is
// deprecated and goes away in the next contract version.
function countQuery(l: ListDef) {
  return {
    queryKey: ['lists', l.path, 'count'],
    queryFn: () => api.get(`${l.path}?limit=1`).then((r) => (r.data?.meta?.total ?? null) as number | null),
    staleTime: 60_000,
  };
}

export function Blacklists() {
  const [params, setParams] = useSearchParams();
  const list = listByKey(params.get('tab'));
  const initialSearch = params.get('q') ?? params.get('search') ?? '';
  const qc = useQueryClient();
  const { confirm, dialog } = useConfirm();
  const [addOpen, setAddOpen] = useState(false);
  const [method, setMethod] = useState<AddMethod>('single');
  // The active tab is not fetched here: ListBody writes its count from
  // meta.total of the unfiltered page it downloads anyway, and fetches it
  // only while a search filters that page (see ListBody).
  const counts = useQueries({
    queries: LISTS.map((l) => ({ ...countQuery(l), enabled: l.key !== list.key })),
  });
  const total = counts[LISTS.indexOf(list)]?.data ?? undefined;

  const enforcement = useQuery<Enforcement | null>({
    queryKey: ['lists', 'enforcement'],
    queryFn: () => getData<Enforcement>('blacklists/enforcement'),
  });

  const refresh = () => { void qc.invalidateQueries({ queryKey: ['lists'] }); };

  const selectTab = (k: ListKey) => {
    if (k === list.key) return;
    const next = listByKey(k);
    if (!methodsFor(next).includes(method)) setMethod('single');
    setParams(k === DEFAULT_LIST ? {} : { tab: k });
  };

  const openAdd = (m: AddMethod) => {
    setMethod(m);
    setAddOpen(true);
  };

  const exportList = async () => {
    try {
      const r = await api.get(`${list.path}/export`, { responseType: 'text', transformResponse: (d: unknown) => d });
      const text = typeof r.data === 'string' ? r.data : '';
      const n = text ? text.split('\n').filter(Boolean).length : 0;
      const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
      const a = document.createElement('a');
      a.href = url;
      a.download = `${list.path}-${new Date().toISOString().slice(0, 10)}.txt`;
      a.click();
      URL.revokeObjectURL(url);
      toast.success(`Exported ${entriesWord(n)} of ${list.label}`);
    } catch (err) {
      toast.error(getErrorMessage(err, `Could not export ${list.label}`));
    }
  };

  const domainLimit = enforcement.data?.dns_blocklist_limit;
  const domainsFull = list.key === 'blocked-domains' && typeof domainLimit === 'number' && typeof total === 'number' && total >= domainLimit;

  return (
    <div className="flex flex-col gap-5">
      <PageHeader
        eyebrow="Protection"
        title="Blacklists"
        description="Destinations the proxy refuses, and the ones it lets through."
        actions={
          <>
            {!list.allowed && <Button onClick={() => openAdd('popular')}>Popular lists</Button>}
            <Button icon={<Download />} onClick={() => { void exportList(); }}>Export</Button>
            <Button variant="primary" icon={<Plus />} aria-expanded={addOpen} onClick={() => (addOpen ? setAddOpen(false) : openAdd(method))}>
              Add entries
            </Button>
          </>
        }
      />

      <ListTabs active={list.key} counts={counts} onSelect={selectTab} />

      <div role="tabpanel" id={`bl-panel-${list.key}`} aria-labelledby={`bl-tab-${list.key}`} className="flex flex-col gap-5">
        {addOpen && (
          <AddEntries list={list} method={method} onMethodChange={setMethod} onChanged={refresh} onClose={() => setAddOpen(false)} />
        )}

        {domainsFull && (
          <Notice tone="warning" title="The domain blacklist is full">
            It holds {formatCount(total)} entries, the limit set by SPM_DNS_BLOCKLIST_MAX_DOMAINS ({formatCount(domainLimit)}), so the backend refuses new
            entries and any import that would pass it. Remove entries, or raise the limit together with the dns container&apos;s memory.
          </Notice>
        )}

        <ListBody
          key={`${list.key}:${initialSearch}`}
          list={list}
          initialSearch={initialSearch}
          total={total}
          enforcement={enforcement}
          confirm={confirm}
          onChanged={refresh}
        />
      </div>
      {dialog}
    </div>
  );
}

function ListBody({ list, initialSearch = '', total, enforcement, confirm, onChanged }: {
  list: ListDef;
  initialSearch?: string;
  total?: number | null;
  enforcement: { data?: Enforcement | null; isPending: boolean; isError: boolean };
  confirm: ReturnType<typeof useConfirm>['confirm'];
  onChanged: () => void;
}) {
  const qc = useQueryClient();
  const [search, setSearch] = useState(initialSearch);
  const query = useDebounced(search.trim(), 300);
  const [offset, setOffset] = useState(0);
  const onSearch = (v: string) => {
    setSearch(v);
    setOffset(0);
  };

  const entries = useQuery<EntryPage>({
    queryKey: ['lists', list.path, 'entries', offset, query],
    queryFn: () =>
      api.get(`${list.path}?limit=${PAGE_SIZE}&offset=${offset}&search=${encodeURIComponent(query)}`)
        .then((r) => {
          const total = typeof r.data?.meta?.total === 'number' ? (r.data.meta.total as number) : null;
          // Unfiltered, meta.total is the whole list: it is the tab's count.
          if (!query) qc.setQueryData(countQuery(list).queryKey, total);
          return { rows: (r.data?.data ?? []) as ListEntry[], total: total ?? 0 };
        }),
    placeholderData: keepPreviousData,
  });
  // Filtered (a search, or a link from the global search with ?q=), the page
  // counts only its matches, so the whole list's count is read on its own.
  useQuery({ ...countQuery(list), enabled: query !== '' });
  const sources = useQuery<ListSource[] | null>({
    queryKey: ['lists', list.path, 'sources'],
    queryFn: () => getData<ListSource[]>(`${list.path}/sources`),
  });

  const removeEntry = async (e: ListEntry) => {
    const value = e[list.field] ?? '';
    const ok = await confirm({
      title: `Remove ${value}?`,
      body: `It leaves ${list.label}. ${list.consequence('it')}`,
      confirmLabel: 'Remove',
      destructive: true,
    });
    if (!ok) return;
    try {
      await api.delete(`${list.path}/${e.id}`);
      toast.success(`Removed ${value} from ${list.label}`);
    } catch (err) {
      toast.error(getErrorMessage(err, `Could not remove ${value}`));
    } finally {
      onChanged();
    }
  };

  const removeSource = async (s: ListSource) => {
    const name = sourceTitle(s);
    const ok = await confirm({
      title: `Remove ${entriesWord(s.entries)} from ${name}?`,
      body: `Every entry this source added leaves ${list.label}. ${list.consequence('them')} Entries another source added stay.`,
      confirmLabel: `Remove ${entriesWord(s.entries)}`,
      destructive: true,
    });
    if (!ok) return;
    try {
      const r = await api.delete(`${list.path}/sources/${s.id ?? 'unrecorded'}`);
      toast.success(`Removed ${entriesWord(r.data?.data?.removed ?? 0)} from ${list.label}`);
    } catch (err) {
      toast.error(getErrorMessage(err, `Could not remove ${name}`));
    } finally {
      onChanged();
    }
  };

  const removeAll = async () => {
    if (typeof total !== 'number') return;
    const ok = await confirm({
      title: `Remove all ${formatCount(total)} ${list.plural}?`,
      body: `${list.consequence('them')} This cannot be undone; export the list first to keep a copy.`,
      confirmLabel: `Remove all ${formatCount(total)}`,
      destructive: true,
    });
    if (!ok) return;
    try {
      await api.delete(`${list.path}/clear-all`);
      toast.success(`Removed every entry from ${list.label}`);
    } catch (err) {
      toast.error(getErrorMessage(err, `Could not empty ${list.label}`));
    } finally {
      onChanged();
    }
  };

  const reloadDns = async () => {
    try {
      const r = await api.post('maintenance/reload-dns');
      toast.success(`Lists sent again. ${describeListResend(r.data?.data)} ${RESEND_UNCONFIRMED}`);
    } catch (err) {
      toast.error(getErrorMessage(err, 'Could not send the lists again'));
    }
  };

  const columns: Column<ListEntry>[] = [
    {
      id: 'entry',
      header: 'Entry',
      // Wide enough for an address or network on one line; a long domain
      // still breaks rather than widening the table without end.
      className: 'min-w-[11rem]',
      cell: (e) => {
        const desc = shownDescription(e);
        return (
          <div className="flex min-w-0 flex-col gap-0.5">
            <code className="font-mono text-[13px] text-ink [overflow-wrap:anywhere]">{e[list.field]}</code>
            {desc && <span className="text-xs text-ink-muted">{desc}</span>}
          </div>
        );
      },
    },
    { id: 'kind', header: 'Kind', className: 'whitespace-nowrap text-ink-muted', cell: (e) => entryKind(list, e[list.field] ?? '') },
    {
      id: 'source',
      header: 'Source',
      className: 'text-ink-muted',
      cell: (e) => (
        <span title={e.source_kind === 'url' ? e.source ?? undefined : undefined}>
          {sourceName(e.source_kind, e.source, e.source_label)}
        </span>
      ),
    },
    { id: 'added', header: 'Added', className: 'whitespace-nowrap text-ink-muted', cell: (e) => shortDateTime(e.added_date) },
    {
      id: 'actions',
      header: 'Actions',
      headerHidden: true,
      align: 'right',
      cell: (e) => (
        <IconButton size="sm" aria-label={`Remove ${e[list.field]}`} icon={<Trash2 />} onClick={() => { void removeEntry(e); }} />
      ),
    },
  ];

  const empty = query
    ? { title: `No entry matches "${query}"`, description: 'The search looks in the entries and their descriptions. Clear it to see the whole list.' }
    : { title: `No ${list.plural}`, description: 'Entries appear here once they are added or imported with Add entries.' };

  return (
    <>
      <div className="flex flex-wrap items-start gap-4">
        <EnforcementSection
          list={list}
          total={total ?? undefined}
          data={enforcement.data}
          loading={enforcement.isPending}
          error={enforcement.isError}
          onReloadDns={list.key === 'blocked-domains' ? () => { void reloadDns(); } : undefined}
          className="flex-[1_1_320px]"
        />
        <SourcesSection
          list={list}
          sources={sources.data}
          loading={sources.isPending}
          error={sources.isError}
          onRetry={() => { void sources.refetch(); }}
          onRemove={(s) => { void removeSource(s); }}
          className="flex-[2_1_520px]"
        />
      </div>

      {/* One-click additions for the list on screen (moved here from Settings in #425). */}
      {list.key === 'blocked-domains' && <BlockDoh />}
      {list.key === 'allowed-domains' && <EssentialWhitelist />}

      <Section title="Entries" flush>
        <div className="px-5 pb-3">
          <SearchInput
            label={`Search ${list.label}`}
            placeholder={list.searchPlaceholder}
            value={search}
            onChange={onSearch}
            className="w-full sm:max-w-[360px]"
          />
        </div>
        <DataTable<ListEntry>
          caption={`${list.label} entries`}
          // With one source or none, the source is the same on every row and
          // the sources card above says it: "Source not recorded" was
          // repeated on all 50 rows.
          columns={(sources.data?.length ?? 0) > 1 ? columns : columns.filter((c) => c.id !== 'source')}
          rows={entries.data?.rows ?? []}
          rowKey={(e) => String(e.id)}
          loading={entries.isPending}
          error={entries.isError ? `${list.path} did not answer.` : null}
          onRetry={() => { void entries.refetch(); }}
          empty={empty}
          pagination={{ offset, limit: PAGE_SIZE, total: entries.data?.total ?? 0, onChange: setOffset }}
        />
      </Section>

      {!list.allowed && (
        <Section
          title="Remove every entry on this list"
          tone="danger"
          description={typeof total === 'number'
            ? (total > 0 ? `${formatCount(total)} ${list.plural}. ${list.consequence('them')}` : 'This list is empty.')
            : 'The count of this list is not reported.'}
        >
          <Button variant="danger-outline" disabled={!total} onClick={() => { void removeAll(); }}>Remove all</Button>
        </Section>
      )}
    </>
  );
}
